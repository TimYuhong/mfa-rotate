"""Canonical context for one protocol registration transaction.

The protocol path must not invent a second browser identity for headers,
Sentinel, telemetry, or post-registration checks.  ``RegistrationContext`` is
the single owner of transport, browser, locale, device, and correlation state.
Only sanitized metadata is serialized; cookie values and bearer credentials
never leave the live session.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from fingerprint import generate_fingerprint


SCHEMA_VERSION = 1
_COOKIE_DOMAINS = ("chatgpt.com", "auth.openai.com")
_FINGERPRINT_KEYS = (
    "browser_type",
    "impersonate",
    "fallback_impersonates",
    "user_agent",
    "sec_ch_ua",
    "sec_ch_ua_platform",
    "sec_ch_ua_mobile",
    "sec_ch_ua_full_version_list",
    "sec_ch_ua_arch",
    "sec_ch_ua_bitness",
    "sec_ch_ua_model",
    "sec_ch_ua_platform_version",
    "screen",
    "lang",
    "lang_full",
    "timezone",
    "navigator_platform",
    "navigator_vendor",
    "hardware_concurrency",
    "device_memory",
    "max_touch_points",
    "device_pixel_ratio",
)


def _uuid() -> str:
    return str(uuid.uuid4())


def _fingerprint_payload(fingerprint: dict[str, Any], tls_target: str) -> dict[str, Any]:
    return {
        "tls_target": str(tls_target or fingerprint.get("impersonate") or ""),
        **{
            key: copy.deepcopy(fingerprint.get(key))
            for key in _FINGERPRINT_KEYS
        },
    }


def fingerprint_hash(fingerprint: dict[str, Any], tls_target: str = "") -> str:
    raw = json.dumps(
        _fingerprint_payload(fingerprint, tls_target),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass
class RegistrationContext:
    fingerprint: dict[str, Any]
    country_code: str = ""
    context_reason: str = "registration"
    context_id: str = field(default_factory=_uuid)
    device_id: str = field(default_factory=_uuid)
    session_id: str = field(default_factory=_uuid)
    navigation_id: str = field(default_factory=_uuid)
    auth_session_logging_id: str = field(default_factory=_uuid)
    route_type: str = "unknown"
    created_at: float = field(default_factory=time.time)
    supersedes_context_id: str = ""
    tls_fallback_history: list[dict[str, Any]] = field(default_factory=list)
    cookie_change_summary: list[dict[str, Any]] = field(default_factory=list)
    request_ledger: list[dict[str, Any]] = field(default_factory=list)
    sdk_executions: list[dict[str, Any]] = field(default_factory=list)
    _cookie_state: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)

    @classmethod
    def create(
        cls,
        *,
        country_code: str = "",
        reason: str = "registration",
        impersonate: str = "",
    ) -> "RegistrationContext":
        fp = generate_fingerprint(
            country_code=str(country_code or "").strip().upper(),
            impersonate=str(impersonate or "").strip(),
        )
        return cls(
            fingerprint=fp,
            country_code=str(country_code or "").strip().upper(),
            context_reason=str(reason or "registration"),
        )

    @property
    def tls_target(self) -> str:
        return str(self.fingerprint.get("impersonate") or "")

    @property
    def user_agent(self) -> str:
        return str(self.fingerprint.get("user_agent") or "")

    def rebuild_for_tls(self, impersonate: str) -> "RegistrationContext":
        """Create a new complete OAuth transaction for a TLS fallback target."""
        rebuilt = self.create(
            country_code=self.country_code,
            reason=f"{self.context_reason}:tls_transaction_rebuild",
            impersonate=str(impersonate or "").strip(),
        )
        rebuilt.supersedes_context_id = self.context_id
        rebuilt.tls_fallback_history = [
            *copy.deepcopy(self.tls_fallback_history),
            {
                "from_context_id": self.context_id,
                "from_tls_target": self.tls_target,
                "to_context_id": rebuilt.context_id,
                "to_tls_target": rebuilt.tls_target,
                "at": time.time(),
                "mode": "full_oauth_transaction_rebuild",
            },
        ]
        return rebuilt

    def fork(self, *, reason: str, route_type: str = "") -> "RegistrationContext":
        """Start an explicitly related transaction without inventing a new device.

        Follow-up login, cookie refresh, or MFA recovery needs fresh correlation
        IDs, but it must not silently become a different browser/device.  A fork
        therefore keeps the canonical fingerprint and authoritative DID while
        rotating transaction-scoped IDs and recording the parent context.
        """
        derived = RegistrationContext(
            fingerprint=copy.deepcopy(self.fingerprint),
            country_code=self.country_code,
            context_reason=str(reason or "followup_context"),
            device_id=self.device_id,
            route_type=str(route_type or "unknown"),
            supersedes_context_id=self.context_id,
            tls_fallback_history=copy.deepcopy(self.tls_fallback_history),
        )
        derived.request_ledger.append({
            "event": "context_forked",
            "reason": derived.context_reason,
            "from_context_id": self.context_id,
            "at": time.time(),
            "source": "explicit_context_transition",
        })
        return derived

    def bind_device_id(self, device_id: str, *, source: str = "") -> str:
        value = str(device_id or "").strip()
        if not value:
            return self.device_id
        if value != self.device_id:
            self.request_ledger.append({
                "event": "device_id_update",
                "source": str(source or "server_cookie"),
                "at": time.time(),
            })
        self.device_id = value
        return value

    def set_route(self, route_type: str) -> None:
        self.route_type = str(route_type or "unknown").strip() or "unknown"

    def rotate_navigation(self, *, reason: str = "") -> str:
        self.navigation_id = _uuid()
        self.request_ledger.append({
            "event": "navigation_rotated",
            "reason": str(reason or "explicit_navigation"),
            "at": time.time(),
        })
        return self.navigation_id

    @staticmethod
    def _cookie_domain(cookie: Any) -> str:
        raw = str(getattr(cookie, "domain", "") or "").lower().lstrip(".")
        for domain in _COOKIE_DOMAINS:
            if raw == domain or raw.endswith("." + domain):
                return domain
        return ""

    def capture_cookies(self, session: Any, phase: str) -> list[dict[str, Any]]:
        """Record name-only cookie deltas for both auth domains."""
        current: dict[str, dict[str, str]] = {domain: {} for domain in _COOKIE_DOMAINS}
        try:
            cookies = list(getattr(getattr(session, "cookies", None), "jar", session.cookies))
        except Exception:
            cookies = []
        for cookie in cookies:
            domain = self._cookie_domain(cookie)
            name = str(getattr(cookie, "name", "") or "").strip()
            if not domain or not name:
                continue
            value = str(getattr(cookie, "value", "") or "")
            current[domain][name] = hashlib.sha256(value.encode("utf-8")).hexdigest()

        rows: list[dict[str, Any]] = []
        for domain in _COOKIE_DOMAINS:
            previous = self._cookie_state.get(domain, {})
            now = current[domain]
            prev_names, now_names = set(previous), set(now)
            row = {
                "phase": str(phase or "unknown"),
                "domain": domain,
                "count": len(now),
                "present_names": sorted(now_names),
                "added": sorted(now_names - prev_names),
                "removed": sorted(prev_names - now_names),
                "changed": sorted(
                    name for name in now_names & prev_names if now[name] != previous[name]
                ),
                "at": time.time(),
            }
            self.cookie_change_summary.append(row)
            rows.append(row)
        self._cookie_state = current
        return rows

    def record_request(
        self,
        *,
        method: str,
        url: str,
        status: int = 0,
        duration_ms: float = 0.0,
        error: bool = False,
        header_names: list[str] | None = None,
    ) -> None:
        try:
            parsed = urlsplit(str(url or ""))
            target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            target = str(url or "").split("?", 1)[0]
        row = {
            "method": str(method or "GET").upper(),
            "url": target,
            "status": int(status or 0),
            "duration_ms": round(max(0.0, float(duration_ms or 0.0)), 3),
            "error": bool(error),
            "at": time.time(),
            "source": "observed_http",
        }
        if isinstance(header_names, list):
            row["header_names"] = sorted({
                str(name or "").strip().lower()
                for name in header_names
                if str(name or "").strip()
            })
        self.request_ledger.append(row)
        if len(self.request_ledger) > 160:
            del self.request_ledger[:-160]

    def record_sdk_execution(self, evidence: dict[str, Any]) -> None:
        if not isinstance(evidence, dict):
            return
        row = {
            key: evidence.get(key)
            for key in (
                "version", "sha256", "sdk_url", "frame_url", "referer",
                "accept_language", "cache_hit", "execution_mode", "flow",
            )
            if evidence.get(key) not in (None, "")
        }
        row["at"] = float(evidence.get("at") or time.time())
        self.sdk_executions.append(row)
        if len(self.sdk_executions) > 32:
            del self.sdk_executions[:-32]

    def signal_profile(self) -> dict[str, Any]:
        """Return the minimal signal/header profile derived from this context."""
        fp = self.fingerprint
        screen_text = str(fp.get("screen") or "1920x1080")
        try:
            width, height = (int(value) for value in screen_text.lower().split("x", 1))
        except Exception:
            width, height = 1920, 1080
        sec_ch = str(fp.get("sec_ch_ua") or "")
        languages = [
            part.split(";", 1)[0].strip()
            for part in str(fp.get("lang_full") or fp.get("lang") or "").split(",")
            if part.split(";", 1)[0].strip()
        ]
        return {
            "mode": "registration_context",
            "profile_id": self.context_id,
            "device_id": self.device_id,
            "transport_impersonate": self.tls_target,
            "browser_type": str(fp.get("browser_type") or ""),
            "user_agent": self.user_agent,
            "sec_ch_ua": sec_ch,
            "sec_ch_ua_mobile": str(fp.get("sec_ch_ua_mobile") or ""),
            "sec_ch_ua_platform": str(fp.get("sec_ch_ua_platform") or ""),
            "language": str(fp.get("lang") or ""),
            "languages": languages,
            "accept_language": str(fp.get("lang_full") or fp.get("lang") or ""),
            "timezone": str(fp.get("timezone") or ""),
            "platform": str(fp.get("navigator_platform") or ""),
            "vendor": fp.get("navigator_vendor"),
            "hardware_concurrency": int(fp.get("hardware_concurrency") or 0),
            "device_memory": fp.get("device_memory"),
            "max_touch_points": int(fp.get("max_touch_points") or 0),
            "screen": {
                "width": width,
                "height": height,
                "availWidth": width,
                "availHeight": height,
                "innerWidth": width,
                "innerHeight": height,
                "outerWidth": width,
                "outerHeight": height,
                "devicePixelRatio": float(fp.get("device_pixel_ratio") or 1.0),
            },
            "navigator": {
                "userAgent": self.user_agent,
                "language": str(fp.get("lang") or ""),
                "languages": languages,
                "platform": str(fp.get("navigator_platform") or ""),
                "vendor": fp.get("navigator_vendor"),
                "hardwareConcurrency": int(fp.get("hardware_concurrency") or 0),
                "deviceMemory": fp.get("device_memory"),
                "maxTouchPoints": int(fp.get("max_touch_points") or 0),
                "webdriver": False,
            },
        }

    def snapshot(self) -> dict[str, Any]:
        fp = _fingerprint_payload(self.fingerprint, self.tls_target)
        return {
            "schema_version": SCHEMA_VERSION,
            "context_id": self.context_id,
            "context_reason": self.context_reason,
            "created_at": self.created_at,
            "country_code": self.country_code,
            "route_type": self.route_type,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "navigation_id": self.navigation_id,
            "auth_session_logging_id": self.auth_session_logging_id,
            "tls_target": self.tls_target,
            "fingerprint": fp,
            "fingerprint_hash": fingerprint_hash(self.fingerprint, self.tls_target),
            "supersedes_context_id": self.supersedes_context_id,
            "tls_fallback_history": copy.deepcopy(self.tls_fallback_history),
            "cookie_change_summary": copy.deepcopy(self.cookie_change_summary),
            "request_ledger": copy.deepcopy(self.request_ledger[-96:]),
            "sdk_executions": copy.deepcopy(self.sdk_executions),
        }

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> "RegistrationContext":
        if not isinstance(snapshot, dict):
            raise ValueError("registration_context_missing")
        if int(snapshot.get("schema_version") or 0) != SCHEMA_VERSION:
            raise ValueError("registration_context_schema_invalid")
        fp = snapshot.get("fingerprint")
        if not isinstance(fp, dict):
            raise ValueError("registration_context_fingerprint_missing")
        tls_target = str(snapshot.get("tls_target") or fp.get("tls_target") or fp.get("impersonate") or "")
        clean_fp = {key: copy.deepcopy(fp.get(key)) for key in _FINGERPRINT_KEYS}
        clean_fp["impersonate"] = tls_target
        expected = str(snapshot.get("fingerprint_hash") or "")
        actual = fingerprint_hash(clean_fp, tls_target)
        if not expected or expected != actual:
            raise ValueError("registration_context_hash_mismatch")
        required = {
            "device_id": snapshot.get("device_id"),
            "session_id": snapshot.get("session_id"),
            "context_id": snapshot.get("context_id"),
        }
        if any(not str(value or "").strip() for value in required.values()):
            raise ValueError("registration_context_identity_missing")
        return cls(
            fingerprint=clean_fp,
            country_code=str(snapshot.get("country_code") or ""),
            context_reason=str(snapshot.get("context_reason") or "registration"),
            context_id=str(snapshot["context_id"]),
            device_id=str(snapshot["device_id"]),
            session_id=str(snapshot["session_id"]),
            navigation_id=str(snapshot.get("navigation_id") or _uuid()),
            auth_session_logging_id=str(snapshot.get("auth_session_logging_id") or _uuid()),
            route_type=str(snapshot.get("route_type") or "unknown"),
            created_at=float(snapshot.get("created_at") or time.time()),
            supersedes_context_id=str(snapshot.get("supersedes_context_id") or ""),
            tls_fallback_history=copy.deepcopy(snapshot.get("tls_fallback_history") or []),
            cookie_change_summary=copy.deepcopy(snapshot.get("cookie_change_summary") or []),
            request_ledger=copy.deepcopy(snapshot.get("request_ledger") or []),
            sdk_executions=copy.deepcopy(snapshot.get("sdk_executions") or []),
        )
