"""Single-process, memory-only job coordinator. Start exactly one uvicorn worker."""
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import signal
import sys
import time
from collections import Counter
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from .models import Credentials, EventPoll, Login, MESSAGES, Receipt, ProxyPoolInput, SlotRequest
from .core import retry_kind
from .admission import AdmissionQueue
from .proxy_pool import ProxyError, ProxyPools, parse_proxy
from .proxy_test import failed as proxy_test_failed, safe_result as proxy_test_result

ROOT = Path(__file__).resolve().parents[1]
MODE = os.getenv("MFA_MODE", "disabled")
ORIGIN = os.getenv("MFA_ORIGIN", "http://127.0.0.1:8790").rstrip("/")
LOCAL = os.getenv("MFA_LOCAL_DEV") == "1" and ORIGIN in {"http://127.0.0.1:8790", "http://localhost:8790"}
SECURE = ORIGIN.startswith("https://")
ACCESS = os.getenv("MFA_ACCESS_KEY", "")
TTL = 900
COOKIE = "mfa_session"
MAX_CONCURRENT = max(1, min(10, int(os.getenv("MFA_MAX_CONCURRENT", "10"))))
GLOBAL_MAX_CONCURRENT = max(1, min(30, int(os.getenv("MFA_GLOBAL_MAX_CONCURRENT", "30"))))


@dataclass
class Job:
    id: str
    owner: str
    operation: str
    key: str
    events: list = field(default_factory=list)
    process: object = None
    task: object = None
    state: str = "unchanged"
    done: bool = False
    ended: float = 0
    pending_receipt: str = ""
    accepted_receipt: str = ""
    started: float = field(default_factory=time.monotonic)
    last_contact: float = field(default_factory=time.monotonic)
    connected: int = 0
    cancelled: bool = False
    attached: bool = False
    action: str = "rotate"
    proxy_key: str = field(default="", repr=False)

    def emit(self, event):
        self.state = event.get("state", self.state)
        event = {**event, "seq": len(self.events) + 1, "state": self.state}
        event["message"] = MESSAGES.get(event.get("code"), "")
        if event["type"] == "secret":
            self.pending_receipt = event["receipt"]
        if event["type"] == "done":
            event.setdefault("stage", "stopped")
            event["outcome"] = "success" if self.state == "verified" else (
                "cancelled" if event.get("code") in {"cancelled", "verification_cancelled"} else "failed")
            event["retry"] = retry_kind(self.state)
            self.done = True
            self.ended = time.monotonic()
        self.events.append(event)


class Memory:
    def __init__(self):
        self.sessions = {}
        self.jobs = {}
        self.limits = {}
        self.completed_operations = {}
        self.key = secrets.token_bytes(32)
        self.proxies = ProxyPools(self.key)
        self.proxy_tests = {}
        self.admission = AdmissionQueue()
        self.stopping = False

    def cleanup(self):
        now = time.monotonic()
        for jid, job in list(self.jobs.items()):
            if job.done and now - job.ended > TTL:
                self.completed_operations[(job.owner, job.operation)] = now
                del self.jobs[jid]
        live_owners = {j.owner for j in self.jobs.values()}
        for sid, session in list(self.sessions.items()):
            if now - session["created"] > 7200 and sid not in live_owners:
                del self.sessions[sid]
        self.proxies.prune(set(self.sessions))
        self.admission.cleanup(set(self.sessions))
        self.limits = {k: v for k, v in self.limits.items() if now - v[0] < 60}
        self.completed_operations = {k: v for k, v in self.completed_operations.items() if now - v < 7200}

    def throttle(self, key, maximum):
        self.cleanup()
        first, count = self.limits.get(key, (time.monotonic(), 0))
        if count >= maximum or len(self.limits) > 4096:
            raise HTTPException(429, "rate_limited")
        self.limits[key] = (first, count + 1)


memory = Memory()


def occupied(job):
    # A terminal event precedes process cleanup. Do not release its slot early.
    return not job.done or (job.task is not None and not job.task.done())


async def send(job, command):
    if job.process and job.process.stdin and job.process.returncode is None:
        try:
            job.process.stdin.write((json.dumps(command) + "\n").encode())
            await job.process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def terminate(job):
    if job.process and job.process.returncode is None:
        try:
            if os.name != "nt":
                os.killpg(job.process.pid, signal.SIGKILL)
            else:
                job.process.kill()
        except ProcessLookupError:
            pass
        await job.process.wait()


async def execute(job, credentials):
    try:
        # Do not touch the account until a result channel is attached.
        for _ in range(40):
            if job.connected or job.attached or job.cancelled:
                break
            await asyncio.sleep(.25)
        if not (job.connected or job.attached) or job.cancelled:
            job.emit({"type": "done", "code": "verification_cancelled" if job.action == "verify" else "cancelled"})
            return
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
        job.process = await asyncio.create_subprocess_exec(sys.executable, "-B", "-m", "app.worker",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            cwd=str(ROOT), env=env, start_new_session=os.name != "nt", limit=65536)
        await send(job, credentials)
        credentials.clear()
        while True:
            try:
                line = await asyncio.wait_for(job.process.stdout.readline(), timeout=1)
            except asyncio.TimeoutError:
                if time.monotonic() - job.started > 600:
                    job.emit({"type": "done", "code": "deadline"})
                    break
                if not job.connected and time.monotonic() - job.last_contact > 20 and (job.state == "unchanged" or job.action == "verify"):
                    job.cancelled = True
                    await send(job, {"type": "cancel"})
                continue
            if not line:
                break
            try:
                event = json.loads(line)
                if event.get("type") not in {"stage", "secret", "done"}:
                    raise ValueError()
                job.emit(event)
            except Exception:
                job.emit({"type": "done", "code": "worker_failed"})
                break
            if job.done:
                break
        if not job.done:
            job.emit({"type": "done", "code": "worker_failed"})
    except Exception:
        if not job.done:
            job.emit({"type": "done", "code": "worker_failed"})
    finally:
        credentials.clear()
        await terminate(job)
        memory.proxies.release(job.proxy_key, job.id)


@asynccontextmanager
async def lifespan(app):
    async def expire():
        while True:
            await asyncio.sleep(15)
            memory.cleanup()
    sweeper = asyncio.create_task(expire())
    yield
    sweeper.cancel()
    memory.stopping = True
    tasks = [j.task for j in memory.jobs.values() if j.task and not j.task.done()]
    if tasks:
        _, pending = await asyncio.wait(tasks, timeout=610)
        for task in pending:
            task.cancel()
    for job in memory.jobs.values():
        await terminate(job)
    for process in list(memory.proxy_tests.values()):
        if process and process.returncode is None:
            with suppress(ProcessLookupError): process.kill()
            await process.wait()
    memory.proxy_tests.clear()
    memory.admission.waiting.clear()
    memory.admission.leases.clear()
    await memory.proxies.close()
    memory.jobs.clear()
    memory.sessions.clear()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def owner(request, writing=False):
    memory.cleanup()
    sid = request.cookies.get(COOKIE, "")
    session = memory.sessions.get(sid)
    if not session:
        raise HTTPException(401, "session_expired")
    if writing and not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session["csrf"]):
        raise HTTPException(403, "csrf_rejected")
    return sid


def get_job(request, job_id, writing=False):
    sid = owner(request, writing)
    job = memory.jobs.get(job_id)
    if not job or job.owner != sid:
        raise HTTPException(404, "job_not_found")
    return job


@app.middleware("http")
async def security(request, call_next):
    if request.url.path.startswith("/api/"):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("origin") != ORIGIN:
                return JSONResponse({"code": "origin_rejected"}, 403)
            if MODE not in {"live", "demo"} or not (SECURE or LOCAL):
                return JSONResponse({"code": "disabled", "message": MESSAGES["disabled"]}, 503)
            if "application/json" not in request.headers.get("content-type", ""):
                return JSONResponse({"code": "invalid_content_type"}, 415)
            try:
                declared = int(request.headers.get("content-length", "-1"))
            except ValueError:
                declared = -1
            large_proxy_body = (request.method == "PUT" and request.url.path == "/api/proxy-pool") or (request.method == "POST" and request.url.path == "/api/proxy-pool/test")
            body_limit = 65536 if large_proxy_body else 8192
            if not 0 <= declared <= body_limit:
                return JSONResponse({"code": "body_too_large"}, 413)
            chunks = []
            received = 0
            async for chunk in request.stream():
                received += len(chunk)
                if received > body_limit:
                    return JSONResponse({"code": "body_too_large"}, 413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
    response = await call_next(request)
    response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Pydantic's default `input` field can leak submitted credentials.
    message = "代理格式不正确，请检查输入。" if request.url.path.startswith("/api/proxy-pool") else "输入格式不正确，请检查邮箱、密码和 Base32 密钥。"
    return JSONResponse({"code": "invalid_input", "message": message}, 422)


@app.exception_handler(ProxyError)
async def proxy_error(request, exc):
    status = 409 if exc.code in {"proxy_required", "proxy_pool_changed"} else 422
    message = MESSAGES.get(exc.code, "代理不可用")
    if exc.line is not None:
        message = f"第 {exc.line} 行：{message}"
    return JSONResponse({"code": exc.code, "message": message}, status)


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    message = MESSAGES.get(exc.detail, "请求未完成，请检查权限或刷新页面。")
    if exc.detail == "rate_limited" and request.url.path.startswith("/api/proxy-pool"):
        message = "操作过于频繁，请稍后重试"
    return JSONResponse({"code": exc.detail, "message": message}, exc.status_code)


@app.get("/api/health")
async def health():
    return {"status": "ok", "mode": MODE}


@app.get("/api/capabilities")
async def capabilities():
    memory.cleanup()
    active_count = sum(occupied(j) for j in memory.jobs.values())
    return {"enabled": MODE in {"live", "demo"} and (SECURE or LOCAL) and bool(ACCESS),
            "mode": MODE, "secure_required": True, "max_batch": 50,
            "max_concurrent": min(MAX_CONCURRENT, GLOBAL_MAX_CONCURRENT), "active_count": active_count,
            "global_max_concurrent": GLOBAL_MAX_CONCURRENT,
            "reserved_count": len(memory.admission.leases), "waiting_sessions": len(memory.admission.waiting),
            "max_waiting_sessions": memory.admission.maximum_waiters,
            "available": active_count + len(memory.admission.leases) < GLOBAL_MAX_CONCURRENT,
            "persistence": "memory-only",
            "routing": {"allow_direct": LOCAL, "default_mode": "direct" if LOCAL else "pool", "max_proxies": 50}}


def request_slot(sid):
    active = Counter(job.owner for job in memory.jobs.values() if occupied(job))
    try:
        return memory.admission.request(sid, active, GLOBAL_MAX_CONCURRENT, MAX_CONCURRENT)
    except OverflowError:
        raise HTTPException(429, "admission_queue_full") from None


@app.post("/api/job-slots")
async def job_slot(body: SlotRequest, request: Request):
    sid = owner(request, True)
    # This endpoint accepts no task data; the only retained queue entry is the session ID and expiry.
    if memory.stopping:
        raise HTTPException(409, "busy")
    memory.throttle(("admission", sid), 120)
    return request_slot(sid)


@app.delete("/api/job-slots/{token}")
async def release_slot(token: str, request: Request):
    sid = owner(request, True)
    memory.admission.release(token, sid)
    return {"ok": True}


def require_pool_idle(sid):
    if any(job.owner == sid and occupied(job) for job in memory.jobs.values()):
        raise HTTPException(409, "proxy_pool_busy")


@app.get("/api/proxy-pool")
async def proxy_pool_state(request: Request):
    return memory.proxies.snapshot(owner(request))


@app.put("/api/proxy-pool")
async def proxy_pool_save(body: ProxyPoolInput, request: Request):
    sid = owner(request, True)
    async with memory.proxies.lock(sid):
        require_pool_idle(sid)
        memory.throttle(("proxy-save", sid), 30)
        return await memory.proxies.replace(sid, [value.get_secret_value() for value in body.proxies], LOCAL)


@app.delete("/api/proxy-pool")
async def proxy_pool_clear(request: Request):
    sid = owner(request, True)
    async with memory.proxies.lock(sid):
        require_pool_idle(sid)
        await memory.proxies.remove(sid)
        return memory.proxies.snapshot(sid)


async def run_proxy_test(route, sid):
    process = None
    try:
        process = await asyncio.create_subprocess_exec(sys.executable, "-B", "-m", "app.proxy_test",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            cwd=str(ROOT), env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, limit=65536)
        memory.proxy_tests[sid] = process
        payload = json.dumps(route).encode() + b"\n"
        route.clear()
        try:
            output, _ = await asyncio.wait_for(process.communicate(payload), timeout=30)
        finally:
            payload = b""
        if process.returncode != 0 or len(output) > 4096:
            return proxy_test_failed("proxy_test_failed")
        try: return proxy_test_result(json.loads(output))
        except (ValueError, TypeError): return proxy_test_failed("proxy_test_response")
    except asyncio.TimeoutError:
        return proxy_test_failed("proxy_test_timeout")
    except Exception:
        return proxy_test_failed("proxy_test_failed")
    finally:
        route.clear()
        if process and process.returncode is None:
            with suppress(ProcessLookupError): process.kill()
            await process.wait()


@app.post("/api/proxy-pool/test")
async def proxy_pool_test(body: ProxyPoolInput, request: Request):
    sid = owner(request, True)
    require_pool_idle(sid)
    if memory.stopping or sid in memory.proxy_tests or len(memory.proxy_tests) >= 3:
        raise HTTPException(409, "proxy_test_busy")
    memory.throttle(("proxy-test", sid), 10)
    entries, seen = [], set()
    for line, value in enumerate(body.proxies, 1):
        entry = parse_proxy(value.get_secret_value(), memory.key, line, LOCAL)
        if entry.key not in seen:
            seen.add(entry.key)
            entries.append(entry)
    chosen = secrets.choice(entries)
    route = {"mode": "pool", "local": LOCAL, "proxy_url": chosen.url}
    selected = int(chosen.id)
    # This temporary test never replaces the account-task pool or its version.
    memory.proxy_tests[sid] = None
    try:
        result = await run_proxy_test(route, sid)
        return {**result, "selected": selected}
    finally:
        memory.proxy_tests.pop(sid, None)


@app.post("/api/session")
async def session_start(body: Login, request: Request):
    memory.throttle(("login", request.client.host), 10)
    if not ACCESS or not secrets.compare_digest(body.access_key.get_secret_value(), ACCESS):
        raise HTTPException(401, "access_denied")
    if len(memory.sessions) >= 100:
        raise HTTPException(503, "busy")
    sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    memory.sessions[sid] = {"csrf": csrf, "created": time.monotonic()}
    response = JSONResponse({"csrf": csrf})
    response.set_cookie(COOKIE, sid, httponly=True, secure=SECURE, samesite="strict", max_age=7200)
    return response


@app.get("/api/session")
async def session_current(request: Request):
    sid = owner(request)
    return {"csrf": memory.sessions[sid]["csrf"]}


@app.post("/api/jobs")
async def create_job(body: Credentials, request: Request):
    sid = owner(request, True)
    async with memory.proxies.lock(sid):
        return create_job_locked(body, sid)


def create_job_locked(body, sid):
    if sid in memory.proxy_tests:
        raise HTTPException(409, "proxy_test_busy")
    if (sid, body.operation_id) in memory.completed_operations:
        raise HTTPException(409, "operation_already_completed")
    for job in memory.jobs.values():
        if job.owner == sid and job.operation == body.operation_id:
            memory.admission.release(body.slot_token, sid)
            return {"id": job.id, "duplicate": True}
    if body.action == "verify" and not body.factor_id:
        raise HTTPException(422, "invalid_input")
    key = hmac.new(memory.key, body.email.casefold().encode(), hashlib.sha256).hexdigest()
    if any(occupied(job) and job.key == key for job in memory.jobs.values()):
        raise HTTPException(409, "account_busy")
    active = [job for job in memory.jobs.values() if occupied(job)]
    # This admission/reservation path has no await, so all sessions share an atomic
    # limit in the single API event loop. Keep exactly one uvicorn worker.
    if (memory.stopping or len(active) >= GLOBAL_MAX_CONCURRENT
            or sum(job.owner == sid for job in active) >= MAX_CONCURRENT or len(memory.jobs) >= 200):
        raise HTTPException(409, "busy")
    token = body.slot_token
    if not token:
        # Older/direct API clients join the same fair queue, never bypass it.
        memory.throttle(("admission", sid), 120)
        admission = request_slot(sid)
        if admission["status"] != "ready":
            raise HTTPException(409, "busy")
        token = admission["token"]
    if not memory.admission.consume(token, sid):
        raise HTTPException(409, "slot_expired")
    memory.throttle(("jobs", sid), 100)
    job = Job(secrets.token_urlsafe(24), sid, body.operation_id, key)
    network_mode = body.network_mode or ("direct" if LOCAL else "pool")
    if network_mode == "direct":
        if not LOCAL:
            raise HTTPException(422, "direct_forbidden")
        route = {"mode": "direct", "local": LOCAL}
    else:
        job.proxy_key, route = memory.proxies.acquire(sid, body.proxy_pool_version, job.id)
        route["local"] = LOCAL
    job.action = body.action
    if body.action == "verify":
        job.state = body.initial_state
    memory.jobs[job.id] = job
    credentials = {"email": body.email, "password": body.password.get_secret_value(),
                   "totp_secret": body.totp_secret.get_secret_value(), "action": body.action,
                   "factor_id": body.factor_id, "initial_state": job.state, "network": route}
    job.task = asyncio.create_task(execute(job, credentials))
    return {"id": job.id}


@app.post("/api/jobs/{job_id}/retry")
async def retry_job(job_id: str, body: Credentials, request: Request):
    previous = get_job(request, job_id, True)
    expected_key = hmac.new(memory.key, body.email.casefold().encode(), hashlib.sha256).hexdigest()
    action = retry_kind(previous.state)
    if not previous.done or action == "none" or body.action != action or expected_key != previous.key:
        raise HTTPException(409, "unsafe_retry")
    if occupied(previous):
        raise HTTPException(409, "busy")
    if action == "verify":
        body = body.model_copy(update={"initial_state": previous.state})
        delivered = next((e for e in reversed(previous.events) if e["type"] == "secret"), None)
        if delivered and (body.factor_id != delivered["factor_id"] or not secrets.compare_digest(body.totp_secret.get_secret_value(), delivered["new_secret"])):
            raise HTTPException(409, "unsafe_retry")
    return await create_job(body, request)


@app.get("/api/operations/{operation_id}")
async def lookup_operation(operation_id: str, request: Request):
    sid = owner(request)
    for job in memory.jobs.values():
        if job.owner == sid and job.operation == operation_id:
            return {"id": job.id}
    raise HTTPException(404, "job_not_found")


@app.post("/api/job-events")
async def poll_events(body: EventPoll, request: Request):
    sid = owner(request, True)
    result = {}
    # One bounded response for all active jobs avoids the browser's HTTP/1
    # connection limit starving receipt/cancel requests during ten-way execution.
    for jid, cursor in body.cursors.items():
        job = memory.jobs.get(jid)
        if not job or job.owner != sid:
            result[jid] = {"error": "job_not_found"}
        elif cursor > len(job.events):
            result[jid] = {"error": "invalid_cursor"}
        else:
            job.attached = True
            job.last_contact = time.monotonic()
            result[jid] = {"events": job.events[cursor:], "done": job.done}
    return {"jobs": result}


@app.get("/api/jobs/{job_id}/events")
async def events(job_id: str, request: Request):
    job = get_job(request, job_id)
    try:
        cursor = max(0, int(request.headers.get("last-event-id", "0")))
    except ValueError:
        raise HTTPException(400, "invalid_cursor")
    if job.connected >= 2:
        raise HTTPException(429, "rate_limited")
    async def stream():
        nonlocal cursor
        job.connected += 1
        try:
            while True:
                job.last_contact = time.monotonic()
                if await request.is_disconnected():
                    break
                for event in job.events[cursor:]:
                    cursor = event["seq"]
                    yield f"id: {cursor}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
                if job.done:
                    break
                yield ": heartbeat\n\n"
                await asyncio.sleep(1)
        finally:
            job.connected -= 1
            job.last_contact = time.monotonic()
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


@app.post("/api/jobs/{job_id}/receipt")
async def acknowledge(job_id: str, body: Receipt, request: Request):
    job = get_job(request, job_id, True)
    if body.receipt == job.accepted_receipt:
        return {"ok": True}
    if not job.pending_receipt or not secrets.compare_digest(body.receipt, job.pending_receipt):
        raise HTTPException(409, "receipt_mismatch")
    job.accepted_receipt = body.receipt
    await send(job, {"type": "receipt", "receipt": body.receipt})
    return {"ok": True}


@app.post("/api/jobs/{job_id}/cancel")
async def cancel(job_id: str, request: Request):
    job = get_job(request, job_id, True)
    if job.done:
        return {"deferred": False, "done": True}
    job.cancelled = True
    await send(job, {"type": "cancel"})
    return {"deferred": job.action == "rotate" and job.state != "unchanged", "done": False}


@app.delete("/api/jobs/{job_id}")
async def forget(job_id: str, request: Request):
    job = get_job(request, job_id, True)
    if job.done and job.task is not None and not job.task.done():
        # Wait only for completed-worker cleanup, never interrupt a running mutation.
        await asyncio.wait({job.task}, timeout=2)
    if occupied(job):
        raise HTTPException(409, "job_active")
    memory.completed_operations[(job.owner, job.operation)] = time.monotonic()
    del memory.jobs[job_id]
    return {"ok": True}


DIST = ROOT / "frontend" / "dist"
if (DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    icon = DIST / "favicon.ico"
    if not icon.is_file():
        raise HTTPException(404, "icon_not_found")
    return FileResponse(icon, media_type="image/x-icon")


@app.get("/")
async def index():
    if not (DIST / "index.html").is_file():
        raise HTTPException(503, "frontend_not_built")
    return FileResponse(DIST / "index.html")
