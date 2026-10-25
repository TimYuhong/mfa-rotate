"""Uses audited local authentication core; no account database or raw logging."""
import json
import logging
import os
import re
import sys
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urljoin
from .core import FlowError

logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vendor"))
for key in list(os.environ):
    if key.startswith(("AUTH_TRACE", "AUTH_HTTP_TRACE", "SIGNAL_", "OAUTH_")):
        os.environ.pop(key, None)
os.environ.update({"AUTH_HTTP_TRACE": "0", "AUTH_TRACE_DUMP": "0",
                   "OAUTH_CODEX_RT_EXCHANGE": "0", "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
                   "OAUTH_EXCHANGE_BEFORE_CALLBACK": "0", "OAUTH_REFRESH_ONLY": "0",
                   "OPENAI_SENTINEL_QUICKJS_MODE": "oneshot"})
from auth_flow import AuthFlow, _totp_now  # noqa: E402
from config import Config  # noqa: E402

BASE = "https://chatgpt.com"
ALLOWED_HOSTS = {"chatgpt.com", "auth.openai.com", "sentinel.openai.com"}


class OriginGuard:
    """Validate redirects before sending; do not forward bearer across origins."""
    def __init__(self, session):
        object.__setattr__(self, "wrapped", session)

    def __getattr__(self, name):
        return getattr(self.wrapped, name)

    def __setattr__(self, name, value):
        setattr(self.wrapped, name, value)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def request(self, method, url, **kwargs):
        follow = kwargs.pop("allow_redirects", True)
        for _ in range(12):
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
                raise FlowError("upstream_error")
            response = self.wrapped.request(method, url, allow_redirects=False, **kwargs)
            if not follow or response.status_code not in (301, 302, 303, 307, 308) or not response.headers.get("Location"):
                return response
            next_url = urljoin(url, response.headers["Location"])
            if urlsplit(next_url).netloc != parsed.netloc:
                if method.upper() != "GET" and response.status_code in (307, 308):
                    raise FlowError("upstream_error")
                kwargs["headers"] = {k: v for k, v in kwargs.get("headers", {}).items()
                    if k.lower() not in {"authorization", "cookie", "proxy-authorization"}}
            if response.status_code in (301, 302, 303) and method.upper() != "GET":
                method = "GET"
                kwargs.pop("json", None)
                kwargs.pop("data", None)
                kwargs["headers"] = {k: v for k, v in kwargs.get("headers", {}).items() if k.lower() != "content-type"}
            kwargs.pop("params", None)
            url = next_url
        raise FlowError("upstream_error")


def classify(exc):
    text = str(exc).lower()
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if "邮箱" in text or "email_otp" in text:
        return FlowError("email_required")
    if status == 429 or "429" in text:
        return FlowError("rate_limited")
    if status == 403 or "403" in text or "challenge" in text or "sentinel" in text:
        return FlowError("challenge_required")
    if isinstance(exc, (TimeoutError, ConnectionError)) or getattr(exc, "code", None) in {5, 6, 7, 28, 35, 52, 55, 56, 60, 67, 97}:
        return FlowError("network_error")
    if any(part in text for part in ("timed out", "timeout", "tls", "握手失败", "connection reset", "could not resolve", "failed to connect")):
        return FlowError("network_error")
    if "csrf" in text:
        return FlowError("auth_entry_failed")
    if any(part in text for part in ("invalid_credentials", "invalid_totp_code", "密码登录失败", "totp 验证失败")):
        return FlowError("login_failed")
    return FlowError("upstream_error")


class PrivacyFlow(AuthFlow):
    def __setattr__(self, name, value):
        if name == "session" and value is not None and not isinstance(value, OriginGuard):
            value = OriginGuard(value)
        super().__setattr__(name, value)

    def check_proxy(self):
        return True

    def _reset_authorization_session(self, email):
        previous = self.result
        context = self._ensure_registration_context().fork(reason="rotation_oauth_retry")
        self._replace_registration_context(context, preserve_email=email or previous.email,
            preserve_password=previous.password, preserve_totp_secret=previous.totp_secret)
        self.cookie_refresh_validation = {}
        self._is_existing_account = True
        self._existing_page_type = ""
        self._existing_email_verification_mode = ""
        self._captured_login_verifier = ""
        self._oauth_state = ""
        self._oauth_auth_url = ""


    def _trace_http(self, step, response, extra_request=None):
        """Keep bounded request metadata in memory. Never keep headers or bodies."""
        parsed = urlsplit(str(getattr(response, "url", "")))
        path = parsed.path
        if path.startswith("/mfa-challenge/"):
            path = "/mfa-challenge/<id>"
        allowed = {"/", "/log-in", "/log-in/password", "/email-verification",
                   "/api/auth/csrf", "/api/auth/signin/openai", "/api/auth/session",
                   "/api/auth/callback/openai", "/api/accounts/authorize/continue",
                   "/api/accounts/password/verify", "/api/accounts/mfa/verify",
                   "/mfa-challenge/<id>"}
        entry = {"step": step if re.fullmatch(r"[a-z0-9_]{1,80}", step) else "other",
                 "host": parsed.hostname if parsed.hostname in ALLOWED_HOSTS else "other",
                 "path": path if path in allowed else "other",
                 "status": int(getattr(response, "status_code", 0))}
        retry = str(response.headers.get("Retry-After", "")).strip()
        if retry:
            try:
                seconds = int(retry) if retry.isdigit() else int(parsedate_to_datetime(retry).timestamp() - time.time())
                entry["retry_after"] = max(1, min(seconds, 86400))
            except (ValueError, TypeError, OverflowError):
                pass
        try:
            body = response.json()
            error = body.get("error", {}) if isinstance(body, dict) else {}
            code = error.get("code", "") if isinstance(error, dict) else ""
            if code in {"rate_limit_exceeded", "too_many_requests", "invalid_state",
                        "invalid_credentials", "wrong_email_otp_code", "reauth_required",
                        "recent_auth_required", "invalid_totp_code"}:
                entry["upstream_code"] = code
        except Exception:
            pass
        observations = getattr(self, "observations", None)
        if observations is None:
            self.observations = observations = []
        observations.append(entry)
        del observations[:-32]
        if step == "auth_oauth_init":
            self._auth_entry_url = str(getattr(response, "url", ""))
        if entry["status"] == 429:
            raise FlowError("rate_limited")

    def _continue_existing_login_authorization(self, email, auth_url, sentinel_token, check_stopped=None):
        # login_hint can already establish the username and render the password
        # page. The real browser then submits the password directly; posting the
        # username a second time is unnecessary and can invalidate/throttle it.
        current = urlsplit(getattr(self, "_auth_entry_url", ""))
        if current.scheme == "https" and current.hostname == "auth.openai.com":
            if current.path == "/log-in/password":
                return auth_url, sentinel_token, {
                    "page": {"type": "login_password"},
                    "continue_url": "https://auth.openai.com/log-in/password",
                }
            if current.path == "/email-verification":
                raise FlowError("email_required")
        return super()._continue_existing_login_authorization(email, auth_url, sentinel_token, check_stopped)

    def get_auth_url(self, csrf_token, email=""):
        if not getattr(self, "rotation_reauth", False):
            return super().get_auth_url(csrf_token, email=email)
        params = {"login_hint": email, "reauth": "password", "max_age": "0",
                  "ext-oai-did": self._ensure_device_id(), "connection": "password",
                  "prompt": "login", "screen_hint": "login"}
        response = self.session.post(BASE + "/api/auth/signin/openai?" + urlencode(params),
            headers={**self._common_headers(BASE + "/"),
                     "Content-Type": "application/x-www-form-urlencoded",
                     "x-auth-return-redirect": "1"},
            data={"csrfToken": csrf_token, "callbackUrl": BASE + "/settings/security", "json": "true"},
            timeout=30, allow_redirects=False)
        self._trace_http("reauth_signin", response)
        if response.status_code != 200:
            raise RuntimeError("reauth_http_" + str(response.status_code))
        target = response.json().get("url", "")
        if urlsplit(target).scheme != "https" or urlsplit(target).hostname != "auth.openai.com":
            raise RuntimeError("invalid_authorization_origin")
        self._remember_oauth_params(target)
        return target


class ProtocolAdapter:
    def __init__(self, cancelled=lambda: False, network_route=None):
        self.flow = None
        self.flows = []
        self.access_token = ""
        self.account_id = ""
        self.cancelled = cancelled
        self.network_route = network_route or {"mode": "direct"}

    def _login(self, credentials, secret=None, reauth=False):
        context = self.flow.registration_context_snapshot() if self.flow else None
        flow = PrivacyFlow(Config(proxy=self.network_route.get("proxy_url"), pre_proxy="off",
            proxy_resolve=tuple(self.network_route.get("resolve", []))), env_overrides={"OAUTH_CODEX_RT_EXCHANGE": "0",
            "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0", "OAUTH_EXCHANGE_BEFORE_CALLBACK": "0"},
            registration_context=context,
            context_reason="rotation_reauth" if reauth else "rotation_login")
        flow.rotation_reauth = reauth
        self.flows.append(flow)
        flow.result.totp_secret = secret or credentials["totp_secret"]
        try:
            result = flow.run_protocol_login(None, credentials["email"],
                                             credentials["password"], credentials_only=True,
                                             should_stop=self.cancelled)
            if not result.access_token or not result.session_token:
                raise FlowError("login_failed")
            session = json.loads(result.session_json or "{}")
            if session.get("user", {}).get("email", "").casefold() != credentials["email"].casefold():
                raise FlowError("identity_mismatch")
            account_id = session.get("account", {}).get("id", "")
            if not account_id:
                raise FlowError("identity_mismatch")
            return flow, result.access_token, account_id
        except FlowError:
            raise
        except Exception as exc:
            if self.cancelled():
                raise FlowError("cancelled") from None
            raise classify(exc) from None

    def login(self, credentials):
        # Perform the explicit recent-auth login once. It verifies the password
        # and old TOTP and obtains a fresh web session before reading factors.
        self.flow, self.access_token, self.account_id = self._login(credentials, reauth=True)

    def reauthenticate(self, credentials):
        observations = getattr(self.flow, "observations", [])
        passed = {row["step"] for row in observations if row["status"] == 200}
        if getattr(self.flow, "rotation_reauth", False) and {
            "login_password_verify", "submit_mfa_totp", "chatgpt_auth_session"
        }.issubset(passed):
            return
        old_account = self.account_id
        self.flow, self.access_token, self.account_id = self._login(credentials, reauth=True)
        if self.account_id != old_account:
            raise FlowError("identity_mismatch")

    def diagnostics(self):
        return [item for flow in self.flows for item in getattr(flow, "observations", [])][-48:]

    def request(self, path, payload=None):
        try:
            headers = {**self.flow._common_headers(BASE + "/settings/security"),
                       "Authorization": "Bearer " + self.access_token,
                       "ChatGPT-Account-ID": self.account_id,
                       "oai-did": self.flow.result.device_id}
            response = self.flow.session.request("GET" if payload is None else "POST", BASE + path,
                headers=headers, **({} if payload is None else {"json": payload}),
                timeout=25, allow_redirects=False)
        except Exception:
            raise FlowError("network_error") from None
        if response.status_code == 429:
            raise FlowError("rate_limited")
        if response.status_code == 403:
            raise FlowError("challenge_required")
        if response.status_code != 200:
            raise FlowError("upstream_error")
        try:
            return response.json()
        except Exception:
            raise FlowError("upstream_error") from None

    def factors(self):
        info = self.request("/backend-api/accounts/mfa_info")
        factors = (info.get("factors") or {}).get("totp") or []
        if not isinstance(factors, list):
            raise FlowError()
        return factors

    def old_factor(self):
        factors = self.factors()
        if len(factors) != 1 or not factors[0].get("id"):
            raise FlowError("factor_ambiguous")
        return factors[0]["id"]

    def has_factor(self, factor_id):
        return any(f.get("id") == factor_id for f in self.factors())

    def disable(self, factor_id):
        self.request("/backend-api/accounts/mfa/user/disable_in_house", {"factor_id": factor_id})

    def enroll(self):
        body = self.request("/backend-api/accounts/mfa/enroll", {"factor_type": "totp", "source": "settings"})
        if not all([body.get("secret"), body.get("session_id"), (body.get("factor") or {}).get("id")]):
            raise FlowError()
        return {"secret": body["secret"], "session_id": body["session_id"], "factor_id": body["factor"]["id"]}

    def activate(self, new):
        remaining = 30 - time.time() % 30
        if remaining < 3:
            time.sleep(remaining + .2)
        body = self.request("/backend-api/accounts/mfa/user/activate_enrollment",
            {"factor_type": "totp", "source": "settings", "session_id": new["session_id"],
             "code": _totp_now(new["secret"])})
        if body.get("success") is not True:
            raise FlowError()

    def verify_new(self, credentials, new):
        flow, token, account = self._login(credentials, secret=new["secret"])
        if account != self.account_id:
            raise FlowError("identity_mismatch")

    def verify_current(self, credentials, new):
        # A fresh adapter owns a fresh device context and cookie jar. This path
        # performs authentication and a factor read, never a factor mutation.
        self.flow, self.access_token, self.account_id = self._login(credentials, secret=new["secret"])
        if not self.has_factor(new["factor_id"]):
            raise FlowError("factor_ambiguous")

    def close(self):
        for flow in self.flows:
            try:
                flow.session.close()
            except Exception:
                pass
