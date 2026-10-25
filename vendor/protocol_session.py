"""Commit one protocol registration callback without replaying its OAuth code.

Only redacted metadata leaves this module. A callback address, HTTP 302, or
cookie-shaped text is not a confirmed login: the same session must hold a
properly scoped cookie AND receive a valid Session/AT response.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urljoin, urlsplit


BASES = ("__Secure-next-auth.session-token", "next-auth.session-token")
SESSION_URL = "https://chatgpt.com/api/auth/session"
CALLBACK_PATH = "/api/auth/callback/openai"


def _session_cookie_name(name):
    return any(name == base or re.fullmatch(re.escape(base) + r"\.\d+", name)
               for base in BASES)


def _error_code(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value) else "unknown"


def _target(url):
    try:
        parsed = urlsplit(str(url or ""))
    except ValueError:
        return {"host": "invalid", "path": "invalid"}
    # No arbitrary path/query text: these may contain PII or credentials.
    paths = {"/", CALLBACK_PATH, "/api/auth/session", "/api/auth/error", "/auth/error", "/auth/login"}
    return {"host": "chatgpt.com" if parsed.hostname == "chatgpt.com" else "other",
            "path": parsed.path if parsed.path in paths else "other"}


def _allowed(url):
    try:
        p = urlsplit(url)
        return p.scheme == "https" and p.hostname == "chatgpt.com" and p.port in (None, 443) and not p.username and not p.password
    except (ValueError, TypeError):
        return False


def cookie_state(session):
    """Return private token plus metadata; reject mixed-scope/incomplete chunks."""
    try:
        jar = list(session.cookies.jar)
    except Exception:
        return "", {"status": "unavailable", "names": [], "eligible_names": []}
    groups, names, eligible = {}, set(), set()
    session_path = "/api/auth/session"
    for c in jar:
        name = str(c.name or "")
        if not _session_cookie_name(name):
            continue
        names.add(name)
        path = c.path or "/"
        if (str(c.domain or "").lstrip(".").lower() != "chatgpt.com"
                or c.is_expired() or not c.value
                or not (path == session_path or (session_path.startswith(path)
                        and (path.endswith("/") or session_path[len(path):].startswith("/"))))):
            continue
        groups.setdefault((c.domain, path), {})[name] = c.value
        eligible.add(name)
    candidates, incomplete = set(), False
    for values in groups.values():
        for base in BASES:
            if values.get(base):
                candidates.add(values[base])
            chunks = {int(k[len(base) + 1:]): v for k, v in values.items()
                      if k.startswith(base + ".") and k[len(base) + 1:].isdigit()}
            if chunks:
                indexes = sorted(chunks)
                if indexes != list(range(len(indexes))):
                    incomplete = True
                else:
                    candidates.add("".join(chunks[i] for i in indexes))
    state = "ambiguous" if len(candidates) > 1 else "incomplete" if incomplete else "present" if candidates else "missing"
    return (next(iter(candidates)) if state == "present" else ""), {"status": state, "names": sorted(names), "eligible_names": sorted(eligible)}


def response_evidence(response, url, session):
    """Status, destinations, known cookie names, and error enums, never bodies."""
    row = {"target": _target(url), "status": int(response.status_code),
           "cookie_jar": cookie_state(session)[1], "set_session_cookies": []}
    headers = response.headers
    getter = getattr(headers, "get_list", None) or getattr(headers, "getlist", None)
    try:
        values = getter("Set-Cookie") if callable(getter) else [headers.get("Set-Cookie", "")]
    except Exception:
        values = []
    for value in values or []:
        parsed = SimpleCookie()
        try:
            parsed.load(str(value))
        except Exception:
            continue
        for name, morsel in parsed.items():
            if _session_cookie_name(name):
                row["set_session_cookies"].append({"name": name, "has_value": bool(morsel.value),
                                                  "max_age_zero": morsel["max-age"] == "0"})
    location = headers.get("Location", "")
    if location:
        try:
            destination = urljoin(url, location)
            row["redirect"] = _target(destination)
            query = parse_qs(urlsplit(destination).query)
            if "error" in query:
                row["error_code"] = _error_code(query["error"][0])
        except ValueError:
            row["redirect"] = {"host": "invalid", "path": "invalid"}
    request_headers = getattr(getattr(response, "request", None), "headers", None)
    cookie_header = None
    if request_headers is not None:
        cookie_header = next((v for k, v in request_headers.items() if str(k).lower() == "cookie"), None)
    row["request_cookie_header_observed"] = cookie_header is not None
    if cookie_header is not None:
        row["request_session_cookie_names"] = sorted({
            field.split("=", 1)[0].strip() for field in str(cookie_header).split(";")
            if _session_cookie_name(field.split("=", 1)[0].strip())
        })
    try:
        data = response.json()
        row["json_object"] = isinstance(data, dict)
        if isinstance(data, dict):
            error = data.get("error")
            if error:
                row["error_code"] = _error_code(error.get("code") if isinstance(error, dict) else error)
            row["access_token_present"] = bool(data.get("accessToken") or data.get("access_token"))
    except Exception:
        row["json_object"] = False
    return row


class RegistrationSessionError(RuntimeError):
    """Terminal for this attempt; partial credentials must not override it."""
    def __init__(self, reason, evidence):
        evidence["outcome"] = "failed"
        evidence["reason"] = reason
        steps = evidence.get("steps") or []
        last = steps[-1] if steps else {}
        status = last.get("status", 0)
        detail = f"; HTTP={status}" if status else ""
        if last.get("error_code"):
            detail += f"; error_code={last['error_code']}"
        self.error_category = "network" if reason.endswith("transport_error") or status == 429 or status >= 500 else "unknown"
        labels = {
            "callback_http_error": "回调返回异常 HTTP 状态",
            "callback_oauth_error": "回调返回认证错误",
            "callback_redirected_to_auth_error": "回调跳回登录或错误页",
            "session_cookie_not_issued": "回调链结束但未取得 Session Cookie",
            "session_cookie_not_stored": "响应下发了 Session Cookie，但 Cookie 容器中没有可用值",
            "session_cookie_incomplete": "Session Cookie 分片不完整",
            "session_cookie_ambiguous": "Session Cookie 存在多组冲突值",
            "session_access_token_missing": "Cookie 已存在，但 Session 接口未返回 AT",
            "callback_state_mismatch": "回调 state 与本轮授权不匹配",
        }
        label = labels.get(reason, "回调或 Session 校验未通过")
        super().__init__(f"协议会话未建立: {reason}（{label}）{detail}；保留已确认密码和 MFA，未重复提交授权码")


def establish_registration_session(flow, callback_url, expected_state):
    session = flow.session
    context_id = str(flow._ensure_registration_context().context_id)
    evidence = {"outcome": "pending", "steps": [], "cookie_before": cookie_state(session)[1]}
    flow.registration_session_evidence = evidence
    def fail(reason):
        flow.registration_session_evidence = evidence
        raise RegistrationSessionError(reason, evidence)
    if not _allowed(callback_url) or urlsplit(callback_url).path != CALLBACK_PATH:
        fail("invalid_callback_target")
    query = parse_qs(urlsplit(callback_url).query)
    if "error" in query:
        evidence["steps"].append({"phase": "callback", "error_code": _error_code(query['error'][0])})
        fail("callback_oauth_error")
    if len(query.get("code", [])) != 1 or len(query.get("state", [])) != 1 or not expected_state:
        fail("callback_parameters_missing")
    evidence["state_match"] = hmac.compare_digest(query["state"][0].encode(), str(expected_state).encode())
    if not evidence["state_match"]:
        fail("callback_state_mismatch")
    # Store only a digest and mark BEFORE sending: uncertain transport outcomes
    # must not replay a potentially already-consumed code.
    key = hashlib.sha256((context_id + "\0" + query["code"][0]).encode()).hexdigest()
    attempted = getattr(flow, "_registration_callback_attempts", None)
    if attempted is None:
        attempted = flow._registration_callback_attempts = set()
    if key in attempted:
        fail("callback_already_attempted")
    attempted.add(key)
    flow.result.session_token = flow.result.access_token = ""
    current = callback_url
    issued_cookie = False
    expected_cookie_names = set()
    for hop in range(8):
        try:
            response = session.get(current, headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://auth.openai.com/", "User-Agent": flow._ua,
            }, timeout=30, allow_redirects=False)
        except Exception as exc:
            evidence["steps"].append({"phase": "callback", "exception_type": type(exc).__name__})
            fail("callback_transport_error")
        row = response_evidence(response, current, session)
        row.update(phase="callback", hop=hop + 1)
        evidence["steps"].append(row)
        if flow.session is not session or str(flow._ensure_registration_context().context_id) != context_id:
            fail("callback_context_changed")
        issued_cookie |= any(x["has_value"] and not x["max_age_zero"] for x in row["set_session_cookies"])
        for item in row["set_session_cookies"]:
            if item["has_value"] and not item["max_age_zero"]:
                expected_cookie_names.add(item["name"])
            else:
                expected_cookie_names.discard(item["name"])
        if response.status_code >= 400:
            fail("callback_http_error")
        if row.get("error_code"):
            fail("callback_oauth_error")
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            if not location:
                fail("callback_redirect_missing")
            try:
                destination = urljoin(current, location)
            except ValueError:
                fail("callback_redirect_invalid")
            if not _allowed(destination):
                fail("callback_redirect_outside_origin")
            path = urlsplit(destination).path
            if path in ("/api/auth/error", "/auth/error", "/auth/login"):
                fail("callback_redirected_to_auth_error")
            if path.startswith("/api/auth/callback"):
                fail("callback_redirect_loop")
            if cookie_state(session)[0]:
                break  # A Session probe, not another homepage visit, validates it.
            current = destination
            continue
        if 200 <= response.status_code < 300:
            break
        fail("callback_unexpected_status")
    else:
        fail("callback_redirect_limit")
    token, cookie = cookie_state(session)
    evidence["cookie_after"] = cookie
    if expected_cookie_names - set(cookie["eligible_names"]):
        fail("session_cookie_not_stored")
    if not token:
        if cookie["status"] in ("ambiguous", "incomplete"):
            fail("session_cookie_" + cookie["status"])
        fail("session_cookie_not_stored" if issued_cookie else "session_cookie_not_issued")
    # Retry only the idempotent Session GET once after a successful callback;
    # never retry callback, OTP, password, MFA, or non-2xx responses.
    for attempt in range(2):
        row = {"phase": "session", "attempt": attempt + 1}
        evidence["steps"].append(row)
        flow.result.access_token = flow.result.session_token = ""
        try:
            _, access = flow.get_auth_session(observation=row)
        except Exception as exc:
            row["exception_type"] = type(exc).__name__
            fail("session_http_error" if row.get("status") else "session_transport_error")
        if flow.session is not session or str(flow._ensure_registration_context().context_id) != context_id:
            fail("session_context_changed")
        token, state = cookie_state(session)
        row["cookie_jar"] = state
        if not token:
            fail("session_cookie_lost")
        if row.get("error_code"):
            fail("session_response_error")
        if access:
            flow.result.session_token = token
            evidence["outcome"] = "ready"
            return
        if attempt == 0:
            time.sleep(0.5)
    fail("session_access_token_missing")
