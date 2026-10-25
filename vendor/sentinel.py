"""
OpenAI Sentinel Token 生成入口。

唯一有效路径：QuickJS（Node 子进程跑 OpenAI 真实 sdk.js），
同时返回主 token 和 SO token。

公开 API：
  get_sentinel_token(session, device_id, flow, ...) -> (sentinel_token, so_token)
  失败时抛 RuntimeError，调用方应终止当前注册流程。
"""

from __future__ import annotations

import logging
from typing import Callable

logger = logging.getLogger(__name__)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

_SENTINEL_FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html"


def _maybe_prime_sentinel_frame(
    session,
    *,
    frame_url: str = _SENTINEL_FRAME_URL,
    user_agent: str = "",
    lang: str = "",
    lang_full: str = "",
    referer: str = "",
    log=None,
) -> bool:
    """信号层开启时，像浏览器一样预载 Sentinel frame.html（fail-soft，默认关闭）。"""
    try:
        from signal_runtime import config as _signal_config

        if not _signal_config.feature_enabled("FRAME_LOAD"):
            return False
    except Exception:
        return False
    try:
        headers = {
            "accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "accept-language": lang_full or lang or "en-US,en;q=0.9",
            "referer": referer or "https://auth.openai.com/",
            "user-agent": user_agent or DEFAULT_UA,
            "sec-fetch-dest": "iframe",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
        }
        resp = session.get(frame_url, headers=headers, timeout=8)
        ok = int(getattr(resp, "status_code", 0) or 0) == 200
        if callable(log):
            try:
                log(
                    "[sentinel] frame.html 预载 "
                    + ("OK" if ok else "HTTP %s" % getattr(resp, "status_code", 0))
                )
            except Exception:
                pass
        return ok
    except Exception as exc:
        if callable(log):
            try:
                log(f"[sentinel] frame.html 预载失败（忽略）: {exc}")
            except Exception:
                pass
        return False


def get_sentinel_token(
    session,
    device_id: str,
    flow: str = "authorize_continue",
    user_agent: str = DEFAULT_UA,
    sec_ch_ua: str = "",
    sec_ch_ua_platform: str = "",
    sec_ch_ua_mobile: str = "",
    sec_ch_ua_full_version_list: str = "",
    sec_ch_ua_arch: str = "",
    sec_ch_ua_bitness: str = "",
    sec_ch_ua_model: str = "",
    sec_ch_ua_platform_version: str = "",
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
    navigator_platform: str = "",
    navigator_vendor: str | None = None,
    hardware_concurrency: int = 0,
    device_memory: int | None = None,
    max_touch_points: int = 0,
    device_pixel_ratio: float = 0.0,
    js_heap_size_limit: int = 0,
    navigator_languages: list[str] | None = None,
    timezone: str = "",
    require_so_token: bool = True,
    sentinel_version: str = "",
    sentinel_sdk_url: str = "",
    sentinel_req_url: str = "",
    sentinel_origin: str = "",
    sentinel_referer: str = "",
    page_url: str = "",
    sentinel_sid: str = "",
    request_p: str = "",
    sentinel_context: str = "top_level",
    log: Callable[[str], None] | None = None,
    sdk_evidence_callback: Callable[[dict], None] | None = None,
) -> tuple[str, str]:
    """返回 (sentinel_token, so_token) 元组。失败抛 RuntimeError。"""
    emit = log or (lambda message: logger.info(message))
    # Version must be resolved before either frame.html or sdk.js is loaded so
    # the frame, SDK, challenge referer, and execution evidence name one build.
    from sentinel_quickjs import (
        get_sentinel_token_via_quickjs,
        resolve_sentinel_version,
    )

    resolved_version = resolve_sentinel_version(
        session,
        sentinel_version,
        log=emit,
        accept_language=lang_full or lang or "en-US,en;q=0.9",
        referer=str(page_url or sentinel_referer or "https://auth.openai.com/"),
        user_agent=user_agent or DEFAULT_UA,
    )
    resolved_origin = str(sentinel_origin or "https://sentinel.openai.com").rstrip("/")
    resolved_frame_url = (
        f"{resolved_origin}/backend-api/sentinel/frame.html?sv={resolved_version}"
    )
    resolved_sdk_url = str(sentinel_sdk_url or "").strip() or (
        f"{resolved_origin}/sentinel/{resolved_version}/sdk.js"
    )
    resolved_page_url = str(page_url or sentinel_referer or "https://auth.openai.com/")
    # Each browser-side Sentinel context loads frame.html once. The top-level
    # auth context and password iframe context intentionally have different SID
    # values, while repeated flows inside one context reuse the same frame.
    frame_contexts = getattr(session, "_open_protocol_sentinel_frame_contexts", None)
    if not isinstance(frame_contexts, set):
        frame_contexts = set()
        try:
            setattr(session, "_open_protocol_sentinel_frame_contexts", frame_contexts)
        except Exception:
            pass
    frame_key = f"{str(sentinel_context or 'top_level')}:{resolved_version}:{str(sentinel_sid or device_id or '')}"
    if frame_key not in frame_contexts:
        primed = _maybe_prime_sentinel_frame(
            session,
            frame_url=resolved_frame_url,
            user_agent=user_agent,
            lang=lang,
            lang_full=lang_full,
            referer=resolved_page_url,
            log=emit,
        )
        if primed:
            frame_contexts.add(frame_key)
    try:
        qresult = get_sentinel_token_via_quickjs(
            session,
            device_id=device_id,
            flow=flow,
            sentinel_sid=str(sentinel_sid or device_id or ""),
            request_p=str(request_p or ""),
            sentinel_context=str(sentinel_context or "top_level"),
            log=emit,
            user_agent=user_agent,
            screen=screen,
            screen_width=screen_width,
            screen_height=screen_height,
            screen_avail_width=screen_avail_width,
            screen_avail_height=screen_avail_height,
            inner_width=inner_width,
            inner_height=inner_height,
            outer_width=outer_width,
            outer_height=outer_height,
            color_depth=color_depth,
            lang=lang,
            lang_full=lang_full,
            browser_type=browser_type,
            sec_ch_ua=sec_ch_ua,
            sec_ch_ua_platform=sec_ch_ua_platform,
            sec_ch_ua_mobile=sec_ch_ua_mobile,
            platform=navigator_platform,
            vendor=navigator_vendor,
            hardware_concurrency=hardware_concurrency,
            device_memory=device_memory,
            max_touch_points=max_touch_points,
            device_pixel_ratio=device_pixel_ratio,
            js_heap_size_limit=js_heap_size_limit,
            navigator_languages=navigator_languages,
            timezone=timezone,
            sec_ch_ua_full_version_list=sec_ch_ua_full_version_list,
            sec_ch_ua_arch=sec_ch_ua_arch,
            sec_ch_ua_bitness=sec_ch_ua_bitness,
            sec_ch_ua_model=sec_ch_ua_model,
            sec_ch_ua_platform_version=sec_ch_ua_platform_version,
            require_so_token=require_so_token,
            sentinel_version=resolved_version,
            sentinel_sdk_url=resolved_sdk_url,
            **({"sentinel_req_url": sentinel_req_url} if sentinel_req_url else {}),
            **({"sentinel_origin": sentinel_origin} if sentinel_origin else {}),
            sentinel_referer=resolved_frame_url,
            page_url=resolved_page_url,
            version_resolved=True,
            **(
                {"sdk_evidence_callback": sdk_evidence_callback}
                if callable(sdk_evidence_callback) else {}
            ),
        )
        if qresult:
            return qresult
        required = "主 Token 和 SO Token" if require_so_token else "主 Token"
        raise RuntimeError(f"Sentinel QuickJS 失败（未取得{required}）")
    except ImportError as e:
        raise RuntimeError(f"Sentinel QuickJS 模块缺失: {e}")
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Sentinel QuickJS 异常: {e}")
