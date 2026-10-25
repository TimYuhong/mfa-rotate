"""ChatGPT（NextAuth）session-token cookie 解析工具。

背景（「注册结果」session 列为空的原因）：
    ChatGPT 的 `__Secure-next-auth.session-token` 是 JWE，长度会超过单个
    cookie 的 4096 字节上限，Chromium 会把同一个 cookie 拆成
    `__Secure-next-auth.session-token.0`、`.1` … 分片下发（Set-Cookie 分片）。
    只按整名匹配 cookie 时，这类账号取到的 session token 是空串，于是：
      * 注册结果列表 session 列显示 “—”；
      * 复制 session_token / 复制 Session JSON / 导出 bundle 都是空；
      * 用 Cookie 刷新 AT 时也判定「未发现 session_token」。

本模块只做纯字符串解析（不依赖第三方库），供三条链路共用：
    * auth_flow.py（协议注册 / Cookie 刷新）
    * webui.browser_registration、webui.credential_browser_login（浏览器链路）
    * webui.db（落库前的兜底补齐）

分片还原规则：整名 cookie 优先；没有整名时按 `.0`、`.1` … 的数字下标顺序
首尾拼接，得到服务端实际看到的完整 session token。
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

# 精确名在前，兼容旧域名写法在后。
SESSION_COOKIE_BASE_NAMES: tuple[str, ...] = (
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
)

_SESSION_JSON_KEYS = ("sessionToken", "session_token", "session-token")


def _split_chunk_prefix(name: str) -> tuple[str, int] | None:
    """把 `xxx.0` 形式的 cookie 名拆成 (基础名, 分片下标)；不匹配返回 None。"""
    for base in SESSION_COOKIE_BASE_NAMES:
        if not name.startswith(base + "."):
            continue
        suffix = name[len(base) + 1:]
        if suffix.isdigit():
            return base, int(suffix)
    return None


def session_token_from_cookie_pairs(pairs: Iterable[Any]) -> str:
    """从 (name, value) 序列里取 session token：整名优先，其次拼接 .0/.1 分片。"""
    single: dict[str, str] = {}
    chunks: dict[str, dict[int, str]] = {}
    for item in pairs or ():
        try:
            name, value = item
        except Exception:
            continue
        name = str(name or "").strip()
        if not name:
            continue
        text = "" if value is None else str(value)
        if not text:
            continue
        if name in SESSION_COOKIE_BASE_NAMES:
            single.setdefault(name, text)
            continue
        parsed = _split_chunk_prefix(name)
        if parsed is None:
            continue
        base, index = parsed
        chunks.setdefault(base, {}).setdefault(index, text)

    for base in SESSION_COOKIE_BASE_NAMES:
        if base in single:
            return single[base]
    for base in SESSION_COOKIE_BASE_NAMES:
        parts = chunks.get(base)
        if not parts:
            continue
        joined = "".join(parts[index] for index in sorted(parts))
        if joined:
            return joined
    return ""


def cookie_pairs_from_header(header: Any) -> list[tuple[str, str]]:
    """把 `a=1; b=2` 形式的 Cookie 头拆成 (name, value) 列表。"""
    text = "" if header is None else str(header)
    pairs: list[tuple[str, str]] = []
    for item in text.split(";"):
        if "=" not in item:
            continue
        name, value = item.split("=", 1)
        name = name.strip()
        if name:
            pairs.append((name, value.strip()))
    return pairs


def session_token_from_cookie_header(header: Any) -> str:
    """从 Cookie 头文本里取 session token（含分片拼接）。"""
    return session_token_from_cookie_pairs(cookie_pairs_from_header(header))


def session_token_from_storage_state(state: Any) -> str:
    """从 Playwright storage_state（JSON 文本 / dict / cookies 列表）里取 session token。"""
    if not state:
        return ""
    if isinstance(state, (bytes, bytearray)):
        try:
            state = state.decode("utf-8", "ignore")
        except Exception:
            return ""
    if isinstance(state, str):
        text = state.strip()
        if not text:
            return ""
        try:
            state = json.loads(text)
        except Exception:
            # 不是 JSON 时按 Cookie 头兜底解析。
            return session_token_from_cookie_header(text)
    if isinstance(state, Mapping):
        cookies = state.get("cookies")
    elif isinstance(state, (list, tuple)):
        cookies = state
    else:
        return ""
    if not isinstance(cookies, (list, tuple)):
        return ""
    pairs: list[tuple[Any, Any]] = []
    for item in cookies:
        if isinstance(item, Mapping):
            pairs.append((item.get("name"), item.get("value")))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            pairs.append((item[0], item[1]))
    return session_token_from_cookie_pairs(pairs)


def session_token_from_session_json(payload: Any) -> str:
    """从 /api/auth/session 的 JSON 里找 sessionToken（JWT session 策略时才有）。"""
    if not payload:
        return ""
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = payload.decode("utf-8", "ignore")
        except Exception:
            return ""
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return ""
        try:
            payload = json.loads(text)
        except Exception:
            return ""
    stack: list[Any] = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key in _SESSION_JSON_KEYS:
                value = current.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            stack.extend(current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return ""


def resolve_session_token(
    *,
    session_token: Any = "",
    storage_state_json: Any = "",
    cookie_header: Any = "",
    session_json: Any = "",
) -> str:
    """按「已有值 → storage_state → cookie 头 → session JSON」的顺序解析 session token。"""
    existing = "" if session_token is None else str(session_token).strip()
    if existing:
        return existing
    for candidate in (
        session_token_from_storage_state(storage_state_json),
        session_token_from_cookie_header(cookie_header),
        session_token_from_session_json(session_json),
    ):
        if candidate:
            return candidate
    return ""


def session_token_shape(value: Any) -> dict:
    """给日志用的形态描述：长度、分片拼接标志、JWE 段数。"""
    text = "" if value is None else str(value).strip()
    return {
        "length": len(text),
        "segments": text.count(".") + 1 if text else 0,
        "looks_like_jwe": bool(text) and text.count(".") >= 4 and len(text) >= 100,
    }
