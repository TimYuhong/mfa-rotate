from app.adapter import OriginGuard, PrivacyFlow
from config import Config
from types import SimpleNamespace
from unittest.mock import Mock
from app.core import FlowError
import pytest


def test_oauth_retry_keeps_guard_and_device_and_credentials():
    flow = PrivacyFlow(Config())
    old_id = flow.result.device_id
    old_context = flow._ensure_registration_context().context_id
    flow.result.password = "fixture-password"
    flow.result.totp_secret = "JBSWY3DPEHPK3PXP"
    flow._reset_authorization_session("fixture@example.com")
    assert isinstance(flow.session, OriginGuard)
    assert flow.result.device_id == old_id
    assert flow._ensure_registration_context().context_id != old_context
    assert flow.result.password == "fixture-password"
    assert flow.result.totp_secret == "JBSWY3DPEHPK3PXP"
    assert not flow._trace_dump_enabled
    flow.session.close()


def test_password_page_does_not_resubmit_username():
    flow = PrivacyFlow(Config())
    flow._auth_entry_url = "https://auth.openai.com/log-in/password"
    flow.authorize_continue = Mock(side_effect=AssertionError("duplicate username submission"))
    _, _, result = flow._continue_existing_login_authorization("fixture@example.com", "https://auth.openai.com/oauth/authorize", "fixture-token")
    assert result["page"]["type"] == "login_password"
    flow.authorize_continue.assert_not_called()
    flow.session.close()


def test_diagnostics_exclude_tokens_email_and_query():
    flow = PrivacyFlow(Config())
    response = SimpleNamespace(url="https://auth.openai.com/mfa-challenge/fixture?secret=CANARY",
        status_code=200, headers={}, json=lambda: {"accessToken": "CANARY", "email": "private@example.com"})
    flow._trace_http("submit_mfa_totp", response)
    text = str(flow.observations)
    assert "CANARY" not in text and "private@example.com" not in text
    assert flow.observations[-1]["path"] == "/mfa-challenge/<id>"
    flow.session.close()


def test_rate_limit_is_terminal_and_retains_retry_after():
    flow = PrivacyFlow(Config())
    response = SimpleNamespace(url="https://auth.openai.com/api/accounts/password/verify",
        status_code=429, headers={"Retry-After": "120"}, json=lambda: {})
    with pytest.raises(FlowError, match="rate_limited"):
        flow._trace_http("login_password_verify", response)
    assert flow.observations[-1]["retry_after"] == 120
    flow.session.close()
