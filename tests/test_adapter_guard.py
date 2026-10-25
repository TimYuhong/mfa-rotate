from types import SimpleNamespace
from app.adapter import OriginGuard, classify, ProtocolAdapter
from app.core import FlowError
import pytest


def test_redirect_external_host_rejected_before_send():
    calls = []
    def request(method, url, **kwargs):
        calls.append(url)
        return SimpleNamespace(status_code=302, headers={"Location": "https://attacker.invalid/"})
    with pytest.raises(FlowError):
        OriginGuard(SimpleNamespace(request=request)).get("https://chatgpt.com/", headers={"Authorization": "canary"})
    assert calls == ["https://chatgpt.com/"]


def test_allowed_cross_origin_removes_bearer():
    calls = []
    def request(method, url, **kwargs):
        calls.append(kwargs.get("headers", {}))
        return SimpleNamespace(status_code=302 if len(calls) == 1 else 200, headers={"Location": "https://auth.openai.com/log-in"})
    OriginGuard(SimpleNamespace(request=request)).get("https://chatgpt.com/", headers={"Authorization": "canary"})
    assert not calls[1]


@pytest.mark.parametrize("url", ["http://chatgpt.com/", "https://chatgpt.com:444/", "https://user@chatgpt.com/", "https://127.0.0.1/"])
def test_unsafe_target_rejected(url):
    with pytest.raises(FlowError):
        OriginGuard(None).get(url)


@pytest.mark.parametrize("error,code", [
    (TimeoutError("fixture timeout"), "network_error"),
    (RuntimeError("chatgpt.com TLS 握手失败，无法连接 csrf"), "network_error"),
    (RuntimeError("CSRF Token 获取失败"), "auth_entry_failed"),
    (RuntimeError("HTTP 403"), "challenge_required"),
    (RuntimeError("HTTP 429"), "rate_limited"),
    (RuntimeError("invalid_credentials"), "login_failed"),
    (RuntimeError("invalid_totp_code"), "login_failed"),
    (RuntimeError("unexpected authentication response"), "upstream_error"),
])
def test_network_or_entry_errors_are_not_reported_as_wrong_credentials(error, code):
    assert classify(error).code == code


def test_curl_timeout_and_http_error_are_classified_from_structured_details():
    from curl_cffi.requests.exceptions import Timeout, HTTPError
    assert classify(Timeout("fixture", code=28)).code == "network_error"
    assert classify(HTTPError("fixture", response=SimpleNamespace(status_code=403))).code == "challenge_required"


def test_login_transport_failure_remains_before_mutation(monkeypatch):
    from app import adapter
    from app.core import rotate
    class FailedFlow:
        def __init__(self, *args, **kwargs):
            self.result = SimpleNamespace(totp_secret="")
            self.session = SimpleNamespace(close=lambda: None)
        def run_protocol_login(self, *args, **kwargs): raise TimeoutError("fixture")
    monkeypatch.setattr(adapter, "PrivacyFlow", FailedFlow)
    events = []
    rotate(ProtocolAdapter(), {"email": "fixture@example.com", "password": "fake", "totp_secret": "fixture"},
        events.append, lambda token: False, lambda: False)
    assert events[-1]["state"] == "unchanged" and events[-1]["code"] == "network_error"
