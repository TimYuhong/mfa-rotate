"""QuickJS-driven Sentinel token generator.

Adapted from
https://github.com/zc-zhangchen/any-auto-register
platforms/chatgpt/sentinel_browser.py:`_get_sentinel_token_via_quickjs`
+ scripts/js/openai_sentinel_quickjs.js (MIT License).

Why this exists:
  Pure-Python `sentinel.py` computes a synthetic PoW that *passes* OpenAI's
  surface validation (200 OK on `/sentinel/req`, `/authorize/continue`, etc.)
  but the OTP-dispatch service runs the actual sentinel SDK JS server-side
  to verify the token. Our synthetic token fails the deeper check → email
  silent-drop. To pass, we must run OpenAI's real `sdk.js` (downloaded from
  `sentinel.openai.com/sentinel/<ver>/sdk.js`) inside a JS VM and emit the
  same token the real browser would.

Implementation:
  - 常驻 node 进程（默认）：`node openai_sentinel_quickjs.js --server` 按行 JSON
    协议处理多次 requirements/solve 请求，进程内复用 sdk.js patch 与 vm 编译产物，
    每个请求按当前指纹重建 VM 上下文后执行 action；启动失败/崩溃/超时自动回退
    一次性 spawn（`OPENAI_SENTINEL_QUICKJS_MODE=oneshot` 可整体关闭常驻模式）
  - 一次性 spawn 回退：`node openai_sentinel_quickjs.js`（stdin 读一次 JSON、
    stdout 写一次 JSON，与旧行为一致）
  - Wrapper loads OpenAI's sdk.js + `openai_sentinel_quickjs.js` (a thin
    adapter that exposes `requirements`/`solve` actions over stdin/stdout)
  - Two passes: action=requirements → `request_p`, then `/sentinel/req` →
    challenge, then action=solve → `final_p` + `t`
  - Returns the same JSON-string shape `{p, t, c, id, flow}` as our
    pure-Python `build_sentinel_token`, so callers don't need to change

Public API:
  - `get_sentinel_token_via_quickjs(session, device_id, flow, ...) -> str | None`
"""
from __future__ import annotations

import atexit
import collections
import hashlib
import json
import logging
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


SENTINEL_VERSION = "20260219f9f6"
SENTINEL_SDK_URL = f"https://sentinel.openai.com/sentinel/{SENTINEL_VERSION}/sdk.js"
SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"

# ─── SDK 版本发现链 ───────────────────────────────────────────────────────────
# 线上实际版本会轮换（2026-09-20 观测到 20260810913b 与 20260219f9f6 先后出现），
# 所以不能只认内置常量：优先从发现链 /backend-api/sentinel/sdk.js 解析当前版本，
# 进程内带 TTL 缓存；发现失败时回退到 SENTINEL_VERSION（fail-soft）。
DISCOVERY_SDK_URL = "https://sentinel.openai.com/backend-api/sentinel/sdk.js"
_DISCOVERY_VERSION_RE = re.compile(r"sentinel/([0-9a-zA-Z]{6,})/sdk\.js")
_DISCOVERY_CACHE_TTL_S = 1800.0
_DISCOVERY_OFF_VALUES = {"0", "off", "false", "no", "disable", "disabled", "none"}
_discovery_lock = threading.Lock()
_discovery_cache: dict[str, tuple[float, str]] = {}

# 实际执行过的 SDK 版本计数：磁盘缓存存在 ≠ 执行过，这里只记真正产出了 token 的版本。
_USED_SDK_VERSIONS: "collections.Counter[str]" = collections.Counter()
_USED_SDK_EVIDENCE: list[dict[str, Any]] = []
_used_sdk_lock = threading.Lock()


def parse_sdk_version_from_discovery(text: str) -> str:
    """从发现链 JS 文本里解析版本号（形如 sentinel/<ver>/sdk.js）；解析不到返回空串。"""
    try:
        match = _DISCOVERY_VERSION_RE.search(str(text or ""))
    except Exception:
        return ""
    return str(match.group(1)).strip() if match else ""


def discover_sentinel_version(
    session,
    *,
    timeout_ms: int = 15000,
    log=None,
    force: bool = False,
    accept_language: str = "en-US,en;q=0.9",
    referer: str = "https://auth.openai.com/",
    user_agent: str = "",
) -> str:
    """GET 发现链解析当前 SDK 版本；任何异常返回空串（不抛）。"""
    now = time.time()
    ttl = _DISCOVERY_CACHE_TTL_S
    try:
        ttl = max(0.0, float((os.getenv("OPENAI_SENTINEL_DISCOVERY_TTL", "") or "").strip() or _DISCOVERY_CACHE_TTL_S))
    except ValueError:
        ttl = _DISCOVERY_CACHE_TTL_S
    with _discovery_lock:
        hit = _discovery_cache.get("default")
        if hit and not force and (now - hit[0]) < ttl and hit[1]:
            return hit[1]
    try:
        resp = session.get(
            DISCOVERY_SDK_URL,
            headers={
                "accept": "*/*",
                "accept-language": str(accept_language or "en-US,en;q=0.9"),
                "referer": str(referer or "https://auth.openai.com/"),
                "sec-fetch-dest": "script",
                "sec-fetch-mode": "no-cors",
                "sec-fetch-site": "same-site",
                **({"user-agent": str(user_agent)} if str(user_agent or "").strip() else {}),
            },
            timeout=max(5, int(timeout_ms / 1000)),
        )
        if getattr(resp, "status_code", 0) != 200:
            return ""
        version = parse_sdk_version_from_discovery(getattr(resp, "text", "") or "")
    except Exception:
        return ""
    if version:
        with _discovery_lock:
            _discovery_cache["default"] = (now, version)
        if callable(log):
            try:
                log(f"[sentinel] 发现链版本: {version}")
            except Exception:
                pass
    return version


def resolve_sentinel_version(
    session=None,
    explicit: str = "",
    *,
    timeout_ms: int = 15000,
    log=None,
    accept_language: str = "en-US,en;q=0.9",
    referer: str = "https://auth.openai.com/",
    user_agent: str = "",
) -> str:
    """显式指定 > 进程环境 OPENAI_SENTINEL_VERSION > 发现链 > 内置默认。"""
    value = str(explicit or "").strip()
    if value:
        return value
    env_value = (os.getenv("OPENAI_SENTINEL_VERSION", "") or "").strip()
    if env_value:
        return env_value
    if (os.getenv("OPENAI_SENTINEL_DISCOVERY", "") or "").strip().lower() in _DISCOVERY_OFF_VALUES:
        return SENTINEL_VERSION
    if session is not None:
        discovered = discover_sentinel_version(
            session,
            timeout_ms=timeout_ms,
            log=log,
            accept_language=accept_language,
            referer=referer,
            user_agent=user_agent,
        )
        if discovered:
            return discovered
    return SENTINEL_VERSION


def _record_sdk_use(version: str) -> None:
    value = str(version or "").strip() or "unknown"
    with _used_sdk_lock:
        _USED_SDK_VERSIONS[value] += 1


def used_sdk_versions() -> dict:
    """本进程内实际产出过 token 的 SDK 版本计数快照。"""
    with _used_sdk_lock:
        return dict(_USED_SDK_VERSIONS)


def used_sdk_evidence() -> list[dict[str, Any]]:
    """Sanitized proof for SDK content that actually produced a token."""
    with _used_sdk_lock:
        return [dict(item) for item in _USED_SDK_EVIDENCE]


def _sdk_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _record_sdk_evidence(evidence: dict[str, Any]) -> None:
    row = dict(evidence or {})
    with _used_sdk_lock:
        _USED_SDK_EVIDENCE.append(row)
        if len(_USED_SDK_EVIDENCE) > 256:
            del _USED_SDK_EVIDENCE[:-256]


def _resolve_node_binary() -> str:
    return (os.getenv("OPENAI_SENTINEL_NODE_PATH", "") or "").strip() or "node"


def _quickjs_script_path() -> Path:
    return Path(__file__).resolve().parent / "openai_sentinel_quickjs.js"


def _hidden_process_kwargs() -> dict[str, Any]:
    """Keep the per-token Node worker invisible on Windows."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


_sdk_file_cache: dict[tuple[str, str], Path] = {}


def _ensure_sdk_file(
    session: Any,
    timeout_ms: int,
    *,
    sentinel_version: str = SENTINEL_VERSION,
    sdk_url: str = SENTINEL_SDK_URL,
    sdk_referer: str = "https://auth.openai.com/",
    accept_language: str = "en-US,en;q=0.9",
) -> tuple[Path, bool]:
    """Download OpenAI's actual sdk.js to /tmp cache (one-shot per version)."""
    version = str(sentinel_version or SENTINEL_VERSION).strip()
    resolved_sdk_url = str(sdk_url or SENTINEL_SDK_URL).strip()
    cache_key = (version, resolved_sdk_url)
    cached = _sdk_file_cache.get(cache_key)
    if cached and cached.exists():
        return cached, True

    cache_dir = Path(tempfile.gettempdir()) / "openai-sentinel-demo" / version
    cache_dir.mkdir(parents=True, exist_ok=True)
    sdk_file = cache_dir / "sdk.js"
    if sdk_file.exists() and sdk_file.stat().st_size > 0:
        _sdk_file_cache[cache_key] = sdk_file
        return sdk_file, True

    resp = session.get(
        resolved_sdk_url,
        headers={
            "accept": "*/*",
            "accept-language": accept_language,
            "referer": sdk_referer,
            "sec-fetch-dest": "script",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-site": "same-site",
        },
        timeout=max(10, int(timeout_ms / 1000)),
    )
    if getattr(resp, "status_code", 0) != 200:
        raise RuntimeError(f"下载 sdk.js 失败: HTTP {resp.status_code}")
    content = getattr(resp, "content", b"") or (resp.text or "").encode()
    if not content:
        raise RuntimeError("下载 sdk.js 失败: 响应为空")
    sdk_file.write_bytes(content)
    _sdk_file_cache[cache_key] = sdk_file
    return sdk_file, False


def _run_quickjs_action(
    *,
    action: str,
    sdk_file: Path,
    quickjs_script: Path,
    payload: dict,
    timeout_ms: int,
) -> dict:
    body = dict(payload)
    body["action"] = action
    proc = subprocess.run(
        [_resolve_node_binary(), str(quickjs_script)],
        input=json.dumps(body, ensure_ascii=False),
        text=True,
        capture_output=True,
        timeout=max(10, int(timeout_ms / 1000) + 5),
        env={
            **os.environ,
            "OPENAI_SENTINEL_SDK_FILE": str(sdk_file),
        },
        **_hidden_process_kwargs(),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"QuickJS 执行失败: {(proc.stderr or proc.stdout or 'unknown').strip()[:300]}")
    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError("QuickJS 返回空输出")
    data = json.loads(out)
    if not isinstance(data, dict):
        raise RuntimeError("QuickJS 输出不是 JSON 对象")
    return data


# ─── 常驻 Node 进程（进程内复用 sdk.js patch / vm 编译产物，省去每次 spawn） ─────
#
# 一次性 `_run_quickjs_action` 每次都要重新启动 node、读取 sdk.js 并重新编译；
# 常驻模式起一个 `node openai_sentinel_quickjs.js --server` 进程，用按行 JSON
# 协议处理多次 requirements/solve 请求：进程内只保留 sdk 文本 patch 与
# `vm.Script` 编译结果，每个请求按当前指纹重建 VM 上下文后执行 action，
# 语义与一次性模式一致。基础设施故障（启动失败/崩溃/超时）自动回退一次性
# spawn；action 级错误按旧语义直接抛出，不回退。

QUICKJS_SERVER_MODE_ENV = "OPENAI_SENTINEL_QUICKJS_MODE"
QUICKJS_SERVER_WORKERS_ENV = "OPENAI_SENTINEL_QUICKJS_WORKERS"
QUICKJS_SERVER_IDLE_TTL_ENV = "OPENAI_SENTINEL_QUICKJS_IDLE_TTL"
_DEFAULT_SERVER_WORKERS = 20
_DEFAULT_SERVER_IDLE_TTL_S = 900.0
_SERVER_FAIL_COOLDOWN_S = 30.0
_SERVER_REQUEST_TIMEOUT_FLOOR_S = 10.0
_ONESHOT_MODES = {"oneshot", "one-shot", "off", "0", "false", "disabled", "disable"}


def _quickjs_server_enabled() -> bool:
    mode = (os.getenv(QUICKJS_SERVER_MODE_ENV, "") or "").strip().lower()
    return mode not in _ONESHOT_MODES


def _quickjs_server_max_workers() -> int:
    try:
        value = int((os.getenv(QUICKJS_SERVER_WORKERS_ENV, "") or "").strip())
    except ValueError:
        value = _DEFAULT_SERVER_WORKERS
    # 与换绑页允许的最大账号并发一致；进程池仍按需创建 worker，不会在空闲时
    # 一次性启动 20 个 Node。用户配置 6/7/…/20 时，Sentinel 阶段不再被旧的
    # 4-worker 内部瓶颈压成“只有约 5 条进度在移动”。
    return max(1, min(20, value))


def _quickjs_server_idle_ttl() -> float:
    try:
        value = float((os.getenv(QUICKJS_SERVER_IDLE_TTL_ENV, "") or "").strip())
    except ValueError:
        value = _DEFAULT_SERVER_IDLE_TTL_S
    return max(0.0, value)


_server_stats_lock = threading.Lock()
_server_stats: dict[str, int] = {
    "spawns": 0,
    "requests": 0,
    "fallbacks": 0,
    "timeouts": 0,
    "crashes": 0,
    "start_failures": 0,
    "action_errors": 0,
}


def _server_stat_inc(name: str, delta: int = 1) -> None:
    with _server_stats_lock:
        _server_stats[name] = _server_stats.get(name, 0) + delta


def _server_stats_snapshot() -> dict[str, int]:
    with _server_stats_lock:
        return dict(_server_stats)


class _QuickJSServerError(RuntimeError):
    """常驻进程基础设施故障（启动/崩溃/超时）：可回退一次性 spawn。"""


class _QuickJSServerActionError(RuntimeError):
    """常驻进程返回的 action 级错误：与一次性失败语义一致，直接抛出。"""


def _popen_quickjs_server(node: str, script: Path, sdk_file: Path) -> "subprocess.Popen[str]":
    return subprocess.Popen(
        [node, str(script), "--server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env={**os.environ, "OPENAI_SENTINEL_SDK_FILE": str(sdk_file)},
        **_hidden_process_kwargs(),
    )


class _QuickJSWorker:
    """单个常驻 `node openai_sentinel_quickjs.js --server` 进程。"""

    def __init__(
        self,
        *,
        node: str,
        script: Path,
        sdk_file: Path,
        ready_timeout_s: float = 20.0,
    ) -> None:
        self._node = node
        self._script = script
        self._sdk_file = sdk_file
        self._lock = threading.Lock()
        self._stdout: "queue.Queue[Optional[str]]" = queue.Queue()
        self._stderr_tail: "collections.deque[str]" = collections.deque(maxlen=40)
        self._proc: Optional[subprocess.Popen[str]] = None
        self._spawn(max(2.0, float(ready_timeout_s)))

    @property
    def alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def _spawn(self, ready_timeout_s: float) -> None:
        try:
            proc = _popen_quickjs_server(self._node, self._script, self._sdk_file)
        except OSError as exc:
            _server_stat_inc("start_failures")
            raise _QuickJSServerError(f"无法启动常驻 Sentinel 进程: {exc}") from exc
        self._proc = proc
        threading.Thread(
            target=self._pump_stdout, args=(proc,), name="sentinel-json-out", daemon=True
        ).start()
        threading.Thread(
            target=self._pump_stderr, args=(proc,), name="sentinel-json-err", daemon=True
        ).start()
        try:
            line = self._read_line(ready_timeout_s)
        except queue.Empty:
            self.stop()
            _server_stat_inc("start_failures")
            raise _QuickJSServerError(
                f"常驻 Sentinel 进程 {ready_timeout_s:.0f}s 内未就绪: {self._stderr_text()}"
            ) from None
        if line is None:
            self.stop()
            _server_stat_inc("start_failures")
            raise _QuickJSServerError(f"常驻 Sentinel 进程启动即退出: {self._stderr_text()}")
        try:
            hello = json.loads(line)
        except ValueError:
            hello = None
        if not (isinstance(hello, dict) and hello.get("ready")):
            self.stop()
            _server_stat_inc("start_failures")
            raise _QuickJSServerError(f"常驻 Sentinel 进程就绪响应异常: {line[:200]}")

    def _pump_stdout(self, proc: "subprocess.Popen[str]") -> None:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                self._stdout.put(str(line).rstrip("\r\n"))
        except Exception:
            pass
        finally:
            self._stdout.put(None)

    def _pump_stderr(self, proc: "subprocess.Popen[str]") -> None:
        try:
            assert proc.stderr is not None
            for line in proc.stderr:
                self._stderr_tail.append(str(line).rstrip("\r\n"))
        except Exception:
            pass

    def _stderr_text(self) -> str:
        tail = [line for line in list(self._stderr_tail)[-4:] if line]
        return " | ".join(tail)[:400] or "无 stderr 输出"

    def _read_line(self, timeout_s: float) -> Optional[str]:
        deadline = time.monotonic() + max(0.05, float(timeout_s))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise queue.Empty
            line = self._stdout.get(timeout=remaining)
            if line is None:
                return None
            if line.strip():
                return line

    def request(self, payload: dict, timeout_s: float) -> dict:
        with self._lock:
            proc = self._proc
            if proc is None or proc.poll() is not None:
                self.stop()
                _server_stat_inc("crashes")
                raise _QuickJSServerError(f"常驻 Sentinel 进程已退出: {self._stderr_text()}")
            try:
                assert proc.stdin is not None
                proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
                proc.stdin.flush()
            except Exception as exc:  # noqa: BLE001
                self.stop()
                _server_stat_inc("crashes")
                raise _QuickJSServerError(f"向常驻 Sentinel 进程写入失败: {exc}") from exc
            try:
                raw = self._read_line(timeout_s)
            except queue.Empty:
                self.stop()
                _server_stat_inc("timeouts")
                raise _QuickJSServerError(
                    f"常驻 Sentinel 进程 {timeout_s:.0f}s 内无响应（已终止）"
                ) from None
            if raw is None:
                self.stop()
                _server_stat_inc("crashes")
                raise _QuickJSServerError(f"常驻 Sentinel 进程响应前退出: {self._stderr_text()}")
            try:
                data = json.loads(raw)
            except ValueError as exc:
                self.stop()
                _server_stat_inc("crashes")
                raise _QuickJSServerError(f"常驻 Sentinel 响应非 JSON: {raw[:200]}") from exc
            if not isinstance(data, dict):
                self.stop()
                _server_stat_inc("crashes")
                raise _QuickJSServerError(f"常驻 Sentinel 响应不是对象: {raw[:200]}")
            if data.get("ok") is not True:
                _server_stat_inc("action_errors")
                raise _QuickJSServerActionError(
                    "QuickJS 执行失败: "
                    + str(data.get("error") or "unknown")[:400]
                    + f" (stage={data.get('stage')})"
                )
            result = data.get("result")
            return result if isinstance(result, dict) else {}

    def stop(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


class _QuickJSWorkerPool:
    """按 sdk/脚本维度复用常驻进程；并发请求按需扩到 max_workers。"""

    def __init__(
        self,
        *,
        node: str,
        script: Path,
        sdk_file: Path,
        max_workers: int,
        idle_ttl_s: float,
    ) -> None:
        self._node = node
        self._script = script
        self._sdk_file = sdk_file
        self._max = max(1, int(max_workers))
        self._idle_ttl = max(0.0, float(idle_ttl_s))
        self._cond = threading.Condition()
        self._idle: "collections.deque[tuple[_QuickJSWorker, float]]" = collections.deque()
        self._workers: "set[_QuickJSWorker]" = set()
        self._pending = 0
        self._busy = 0
        self._closed = False
        self._reaper: Optional[threading.Thread] = None
        if self._idle_ttl > 0:
            self._reaper = threading.Thread(
                target=self._reap_loop, name="sentinel-reaper", daemon=True
            )
            self._reaper.start()

    def acquire(self, timeout_s: float) -> _QuickJSWorker:
        deadline = time.monotonic() + max(0.1, float(timeout_s))
        with self._cond:
            while True:
                while self._idle:
                    worker, _ts = self._idle.popleft()
                    if worker.alive:
                        self._busy += 1
                        return worker
                    self._workers.discard(worker)
                    worker.stop()
                if self._closed:
                    raise _QuickJSServerError("Sentinel 常驻进程池已关闭")
                if len(self._workers) + self._pending < self._max:
                    self._pending += 1
                    self._busy += 1
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _QuickJSServerError("等待 Sentinel 常驻进程空闲超时")
                self._cond.wait(remaining)
        try:
            worker = _QuickJSWorker(node=self._node, script=self._script, sdk_file=self._sdk_file)
        except Exception:
            with self._cond:
                self._pending -= 1
                self._busy = max(0, self._busy - 1)
                self._cond.notify_all()
            raise
        with self._cond:
            self._pending -= 1
            self._workers.add(worker)
            self._cond.notify_all()
        _server_stat_inc("spawns")
        return worker

    def release(self, worker: _QuickJSWorker, *, healthy: bool) -> None:
        drop = False
        with self._cond:
            self._busy = max(0, self._busy - 1)
            if healthy and worker.alive and not self._closed:
                self._idle.append((worker, time.monotonic()))
            else:
                drop = True
                self._workers.discard(worker)
            self._cond.notify_all()
        if drop:
            worker.stop()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            workers = list(self._workers)
            self._workers.clear()
            self._idle.clear()
            self._cond.notify_all()
        for worker in workers:
            worker.stop()

    def _reap_loop(self) -> None:
        while True:
            with self._cond:
                if self._closed:
                    return
                self._cond.wait(30.0)
                if self._closed:
                    return
                now = time.monotonic()
                keep: "collections.deque[tuple[_QuickJSWorker, float]]" = collections.deque()
                expired: list[_QuickJSWorker] = []
                while self._idle:
                    worker, ts = self._idle.popleft()
                    if now - ts > self._idle_ttl:
                        expired.append(worker)
                        self._workers.discard(worker)
                    else:
                        keep.append((worker, ts))
                self._idle = keep
            for worker in expired:
                worker.stop()


_pools_lock = threading.RLock()
_pools: dict[tuple[str, str, str], _QuickJSWorkerPool] = {}
_server_fail_lock = threading.Lock()
_server_fail_until: dict[tuple[str, str], float] = {}
_atexit_registered = False


def _register_atexit_shutdown() -> None:
    global _atexit_registered
    with _pools_lock:
        if _atexit_registered:
            return
        _atexit_registered = True
    atexit.register(_shutdown_quickjs_servers)


def _get_server_pool(node: str, script: Path, sdk_file: Path) -> _QuickJSWorkerPool:
    key = (str(node), str(script), str(sdk_file))
    with _pools_lock:
        pool = _pools.get(key)
        if pool is None:
            pool = _QuickJSWorkerPool(
                node=node,
                script=script,
                sdk_file=sdk_file,
                max_workers=_quickjs_server_max_workers(),
                idle_ttl_s=_quickjs_server_idle_ttl(),
            )
            _pools[key] = pool
            _register_atexit_shutdown()
        return pool


def _shutdown_quickjs_servers() -> None:
    """关闭所有常驻进程（服务退出/测试清理用）。"""
    with _pools_lock:
        pools = list(_pools.values())
        _pools.clear()
    for pool in pools:
        try:
            pool.close()
        except Exception:
            pass


def _server_fail_key(script: Path, sdk_file: Path) -> tuple[str, str]:
    return (str(script), str(sdk_file))


def _server_cooling_down(key: tuple[str, str]) -> bool:
    with _server_fail_lock:
        until = _server_fail_until.get(key, 0.0)
        if not until:
            return False
        if until <= time.monotonic():
            _server_fail_until.pop(key, None)
            return False
        return True


def _mark_server_failure(key: tuple[str, str]) -> None:
    with _server_fail_lock:
        _server_fail_until[key] = time.monotonic() + _SERVER_FAIL_COOLDOWN_S


def _run_quickjs_action_dispatch(
    *,
    action: str,
    sdk_file: Path,
    quickjs_script: Path,
    payload: dict,
    timeout_ms: int,
) -> dict:
    """优先走常驻 node 进程；不可用时回退一次性 spawn（与旧行为一致）。"""
    body = dict(payload)
    body["action"] = action

    def _oneshot(reason: str) -> dict:
        if reason:
            _server_stat_inc("fallbacks")
            logger.info("Sentinel QuickJS 回退一次性 node（%s）", reason)
        return _run_quickjs_action(
            action=action,
            sdk_file=sdk_file,
            quickjs_script=quickjs_script,
            payload=payload,
            timeout_ms=timeout_ms,
        )

    if not _quickjs_server_enabled():
        return _oneshot("")
    sdk_path = Path(sdk_file)
    if not sdk_path.exists():
        # 测试/异常场景：SDK 文件缺失时保持一次性路径。
        return _oneshot("")
    script_path = Path(quickjs_script)
    key = _server_fail_key(script_path, sdk_path)
    if _server_cooling_down(key):
        return _oneshot("冷却中")

    timeout_s = max(_SERVER_REQUEST_TIMEOUT_FLOOR_S, float(int(timeout_ms)) / 1000.0 + 5.0)
    deadline = time.monotonic() + timeout_s
    worker: Optional[_QuickJSWorker] = None
    pool: Optional[_QuickJSWorkerPool] = None
    healthy = True
    try:
        pool = _get_server_pool(_resolve_node_binary(), script_path, sdk_path)
        worker = pool.acquire(timeout_s)
        remaining = max(1.0, deadline - time.monotonic())
        result = worker.request(body, remaining)
    except _QuickJSServerActionError:
        raise
    except _QuickJSServerError as exc:
        healthy = False
        _mark_server_failure(key)
        logger.warning("Sentinel 常驻进程不可用: %s；本次回退一次性 node", exc)
        return _oneshot("常驻失败")
    finally:
        if worker is not None and pool is not None:
            pool.release(worker, healthy=healthy)
    _server_stat_inc("requests")
    return result


def _fetch_sentinel_challenge(
    session: Any,
    *,
    device_id: str,
    flow: str,
    request_p: str,
    timeout_ms: int,
    req_url: str = SENTINEL_REQ_URL,
    origin: str = "https://sentinel.openai.com",
    referer: str = f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_VERSION}",
    accept_language: str = "zh-CN,zh;q=0.9",
) -> dict:
    body = {"p": request_p, "id": device_id, "flow": flow}
    resp = session.post(
        req_url,
        data=json.dumps(body, separators=(",", ":")),
        headers={
            "origin": origin,
            "referer": referer,
            "content-type": "text/plain;charset=UTF-8",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": accept_language,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        },
        timeout=max(10, int(timeout_ms / 1000)),
    )
    if getattr(resp, "status_code", 0) != 200:
        raise RuntimeError(f"/sentinel/req HTTP {resp.status_code}")
    payload = resp.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Sentinel challenge 响应不是 JSON 对象")
    return payload


def get_sentinel_token_via_quickjs(
    session: Any,
    device_id: str,
    *,
    flow: str = "authorize_continue",
    sentinel_sid: str = "",
    request_p: str = "",
    sentinel_context: str = "top_level",
    requirements_only: bool = False,
    timeout_ms: int = 45000,
    log: Optional[Callable[[str], None]] = None,
    user_agent: str = "",
    screen: str = "",
    screen_width: int = 0,
    screen_height: int = 0,
    screen_avail_width: int = 0,
    screen_avail_height: int = 0,
    inner_width: int = 0,
    inner_height: int = 0,
    outer_width: int = 0,
    outer_height: int = 0,
    color_depth: int = 24,
    lang: str = "",
    lang_full: str = "",
    browser_type: str = "",
    sec_ch_ua: str = "",
    sec_ch_ua_platform: str = "",
    sec_ch_ua_mobile: str = "",
    platform: str = "",
    vendor: Optional[str] = None,
    hardware_concurrency: int = 0,
    device_memory: Optional[int] = None,
    max_touch_points: int = 0,
    device_pixel_ratio: float = 0.0,
    js_heap_size_limit: int = 0,
    navigator_languages: Optional[list[str]] = None,
    timezone: str = "",  # IANA 时区名（如 Asia/Tokyo）
    # Client Hints 全套（QuickJS 路径不直接用，但为了签名统一接收）
    sec_ch_ua_full_version_list: str = "",
    sec_ch_ua_arch: str = "",
    sec_ch_ua_bitness: str = "",
    sec_ch_ua_model: str = "",
    sec_ch_ua_platform_version: str = "",
    require_so_token: bool = True,
    sentinel_version: str = "",
    sentinel_sdk_url: str = "",
    sentinel_req_url: str = SENTINEL_REQ_URL,
    sentinel_origin: str = "https://sentinel.openai.com",
    sentinel_referer: str = "",
    page_url: str = "https://auth.openai.com/",
    sdk_evidence_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    version_resolved: bool = False,
) -> Optional[tuple[str, str]]:
    """Try the QuickJS path. Return JSON string on success, None on any failure.

    Caller is expected to fall back to pure-Python sentinel on None.

    指纹一致性：``platform`` / ``vendor`` / ``hardware_concurrency`` 等按调用方
    传入的浏览器家族画像喂给 sdk.js 的 navigator，避免 UA 说 Windows Chrome 但
    navigator 报 MacIntel/Apple 的硬伤。未传时按 UA 推断合理默认值。
    """
    log = log or (lambda m: logger.info(m))
    quickjs_script = _quickjs_script_path()
    if not quickjs_script.exists():
        log(f"Sentinel QuickJS 脚本不存在: {quickjs_script}")
        return None

    did = str(device_id or uuid.uuid4())
    # The server request keeps the canonical registration device id. The SDK
    # VM may use a context-specific Sentinel SID so top-level auth and the
    # password iframe do not collapse into one browser context.
    sid = str(sentinel_sid or did)

    screen_w, screen_h = "1920", "1080"
    if screen and "x" in screen:
        parts = screen.split("x", 1)
        screen_w, screen_h = parts[0], parts[1]
    screen_w = str(int(screen_width or screen_w or 1920))
    screen_h = str(int(screen_height or screen_h or 1080))
    screen_w_i, screen_h_i = int(screen_w), int(screen_h)
    avail_w_i = int(screen_avail_width or screen_w_i)
    avail_h_i = int(screen_avail_height or max(0, screen_h_i - 40))
    inner_w_i = int(inner_width or max(320, screen_w_i - 17))
    inner_h_i = int(inner_height or max(240, screen_h_i - 111))
    outer_w_i = int(outer_width or screen_w_i)
    outer_h_i = int(outer_height or screen_h_i)

    lang_primary = lang or "en-US"
    languages = [str(x).strip() for x in (navigator_languages or []) if str(x).strip()]
    if not languages:
        languages = [lang_primary]
    if lang_full and not navigator_languages:
        for part in lang_full.split(","):
            tag = part.split(";")[0].strip()
            if tag and tag not in languages:
                languages.append(tag)

    # ── 指纹一致性：platform / vendor 未显式传入时按 UA 推断，绝不写死 MacIntel ──
    ua_l = (user_agent or "").lower()
    if not platform:
        if "iphone" in ua_l:
            platform = "iPhone"
        elif "windows" in ua_l:
            platform = "Win32"
        elif "mac" in ua_l:
            platform = "MacIntel"
        else:
            platform = "Win32"
    if vendor is None:
        if "firefox" in ua_l:
            vendor = ""                       # Firefox navigator.vendor 为空串
        elif "chrome" in ua_l:
            vendor = "Google Inc."
        else:
            vendor = "Apple Computer, Inc."   # Safari / iOS
    hw_conc = int(hardware_concurrency) if hardware_concurrency else 8

    # 版本优先级：显式 > 环境变量 > 发现链 > 内置常量（见 resolve_sentinel_version）
    resolved_version = (
        str(sentinel_version or SENTINEL_VERSION).strip()
        if version_resolved
        else resolve_sentinel_version(
            session,
            sentinel_version,
            timeout_ms=timeout_ms,
            log=log,
            accept_language=lang_full or lang_primary,
            referer=str(page_url or "https://auth.openai.com/"),
            user_agent=user_agent,
        )
    )
    resolved_sdk_url = str(sentinel_sdk_url or "").strip() or (
        f"https://sentinel.openai.com/sentinel/{resolved_version}/sdk.js"
    )
    resolved_origin = str(sentinel_origin or "https://sentinel.openai.com").rstrip("/")
    resolved_referer = str(sentinel_referer or "").strip() or (
        f"{resolved_origin}/backend-api/sentinel/frame.html?sv={resolved_version}"
    )
    resolved_page_url = str(page_url or "https://auth.openai.com/").strip()
    env_payload = {
        "device_id": did,
        "sentinel_sid": sid,
        "screen_width": screen_w_i,
        "screen_height": screen_h_i,
        "screen_avail_width": avail_w_i,
        "screen_avail_height": avail_h_i,
        "inner_width": inner_w_i,
        "inner_height": inner_h_i,
        "outer_width": outer_w_i,
        "outer_height": outer_h_i,
        "color_depth": int(color_depth or 24),
        "js_heap_size_limit": int(js_heap_size_limit or 4294967296),
        "user_agent": user_agent or "Mozilla/5.0",
        "language": lang_primary,
        "languages": languages,
        "platform": platform,
        "vendor": vendor,
        "hardware_concurrency": hw_conc,
        "browser_type": browser_type or "",
        "sec_ch_ua": sec_ch_ua or "",
        "sec_ch_ua_platform": sec_ch_ua_platform or "",
        "sec_ch_ua_mobile": sec_ch_ua_mobile or "",
        "device_pixel_ratio": float(device_pixel_ratio) if device_pixel_ratio else 1.0,
        "max_touch_points": int(max_touch_points),
        "timezone": timezone or "UTC",  # IANA 时区名
        "page_url": resolved_page_url,
        "page_origin": resolved_origin,
        "sdk_url": resolved_sdk_url,
    }
    # deviceMemory 仅 Chromium 暴露；None 时不下发该键，JS 侧保持 undefined
    if device_memory is not None:
        env_payload["device_memory"] = int(device_memory)

    try:
        ensured = _ensure_sdk_file(
            session,
            timeout_ms,
            sentinel_version=resolved_version,
            sdk_url=resolved_sdk_url,
            sdk_referer=resolved_referer,
            accept_language=lang_full or lang_primary,
        )
        if isinstance(ensured, tuple):
            sdk_file, sdk_cache_hit = ensured
        else:
            # Compatibility for test doubles and older embeddings.
            sdk_file, sdk_cache_hit = Path(ensured), False
        sdk_digest = _sdk_sha256(sdk_file)

        request_p = str(request_p or "").strip()
        if not request_p:
            requirements = _run_quickjs_action_dispatch(
                action="requirements",
                sdk_file=sdk_file,
                quickjs_script=quickjs_script,
                payload=env_payload,
                timeout_ms=timeout_ms,
            )
            request_p = str(requirements.get("request_p") or "").strip()
        if not request_p:
            log("Sentinel QuickJS 失败: requirements 未返回 request_p")
            return None
        try:
            request_p_cache = getattr(session, "_open_protocol_sentinel_request_p", None)
            if not isinstance(request_p_cache, dict):
                request_p_cache = {}
                setattr(session, "_open_protocol_sentinel_request_p", request_p_cache)
            request_p_cache[str(sentinel_context or "top_level")] = request_p
        except Exception:
            pass
        if requirements_only:
            log(
                f"Sentinel QuickJS requirements OK (len={len(request_p)}, "
                f"sdk={resolved_version}, sha256={sdk_digest[:12]}, "
                f"cache={'Y' if sdk_cache_hit else 'N'})"
            )
            return (request_p, "")

        challenge = _fetch_sentinel_challenge(
            session,
            device_id=did,
            flow=flow,
            request_p=request_p,
            timeout_ms=timeout_ms,
            req_url=str(sentinel_req_url or SENTINEL_REQ_URL),
            origin=resolved_origin,
            referer=resolved_referer,
            accept_language=lang_full or lang_primary,
        )
        c_value = str(challenge.get("token") or "").strip()
        if not c_value:
            log("Sentinel QuickJS 失败: challenge token 为空")
            return None

        solve_payload = dict(env_payload)
        solve_payload.update({
            "request_p": request_p,
            "challenge": challenge,
            "flow": flow,
        })
        solved = _run_quickjs_action_dispatch(
            action="solve",
            sdk_file=sdk_file,
            quickjs_script=quickjs_script,
            payload=solve_payload,
            timeout_ms=timeout_ms,
        )

        so_token_raw = str(solved.get("so_token") or "").strip()

        sdk_token = str(solved.get("token") or "").strip()
        if sdk_token and (so_token_raw or not require_so_token):
            _record_sdk_use(resolved_version)
            evidence = {
                "version": resolved_version,
                "sha256": sdk_digest,
                "sdk_url": resolved_sdk_url,
                "frame_url": (
                    f"{resolved_origin}/backend-api/sentinel/frame.html?sv={resolved_version}"
                ),
                "referer": resolved_referer,
                "accept_language": lang_full or lang_primary,
                "cache_hit": bool(sdk_cache_hit),
                "execution_mode": (
                    "server" if _quickjs_server_enabled() else "oneshot"
                ),
                "flow": flow,
                "at": time.time(),
            }
            _record_sdk_evidence(evidence)
            if callable(sdk_evidence_callback):
                try:
                    sdk_evidence_callback(dict(evidence))
                except Exception:
                    logger.debug("SDK evidence callback failed", exc_info=True)
            log(
                f"Sentinel QuickJS OK (len={len(sdk_token)}, "
                f"so={'Y' if so_token_raw else 'N'}, require_so={'Y' if require_so_token else 'N'}, "
                f"sdk={resolved_version}, sha256={sdk_digest[:12]}, "
                f"cache={'Y' if sdk_cache_hit else 'N'})"
            )
            return (sdk_token, so_token_raw)
        if sdk_token:
            log("Sentinel QuickJS 失败: 主 token 有但 SO token 为空，中止以避免封号")
        else:
            log("Sentinel QuickJS 失败: SDK token 为空，中止以避免封号")
        return None
    except Exception as e:
        log(f"Sentinel QuickJS 异常: {e}")
        message = str(e).lower()
        network_markers = (
            "curl: (97)", "curl: (35)", "connection to proxy closed",
            "tls connect error", "wrong_version_number", "proxyerror",
            "connection reset", "connection aborted", "timed out", "timeout",
        )
        if any(marker in message for marker in network_markers):
            raise RuntimeError(f"Sentinel QuickJS 网络失败: {e}") from e
        return None


def get_sentinel_requirements_via_quickjs(
    session: Any,
    device_id: str,
    **kwargs: Any,
) -> Optional[str]:
    """Generate only the SDK requirements p for ChatGPT bootstrap endpoints."""
    result = get_sentinel_token_via_quickjs(
        session,
        device_id,
        requirements_only=True,
        require_so_token=False,
        **kwargs,
    )
    if not result:
        return None
    return str(result[0] or "") or None
