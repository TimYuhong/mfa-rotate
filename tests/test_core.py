from app.core import DemoAdapter, FlowError, rotate


def run(adapter=None, receipt=True, cancelled=False):
    records = []
    rotate(adapter or DemoAdapter(), {"email": "test@example.com"}, records.append,
           lambda token: receipt, lambda: cancelled)
    return records


def test_success_requires_receipt_and_verification():
    events = run()
    assert events[-1]["state"] == "verified"
    assert next(e for e in events if e["type"] == "secret")["state"] == "enrollment_pending"


def test_failed_receipt_does_not_activate():
    adapter = DemoAdapter()
    events = run(adapter, receipt=False)
    assert events[-1]["code"] == "receipt_timeout"
    assert events[-1]["state"] == "enrollment_pending"
    assert not adapter.factors


def test_cancel_before_removal():
    adapter = DemoAdapter()
    events = run(adapter, cancelled=True)
    assert adapter.factors == {"demo-old"}
    assert events[-1]["state"] == "unchanged"


def test_disable_response_lost_but_state_confirms():
    class Adapter(DemoAdapter):
        def disable(self, factor_id):
            super().disable(factor_id)
            raise FlowError("network_error")
    assert run(Adapter())[-1]["state"] == "verified"


def test_disable_unknown_does_not_enroll():
    class Adapter(DemoAdapter):
        def disable(self, factor_id):
            raise FlowError("network_error")
        def has_factor(self, factor_id):
            raise FlowError("network_error")
        def enroll(self):
            assert False, "must not enroll"
    assert run(Adapter())[-1]["state"] == "removal_unknown"


def test_enroll_failure_reports_removed_state():
    class Adapter(DemoAdapter):
        def enroll(self):
            raise FlowError("rate_limited")
    events = run(Adapter())
    assert events[-1]["state"] == "old_factor_removed"
    assert events[-1]["code"] == "rate_limited"


def test_activate_lost_response_recovers_by_read():
    class Adapter(DemoAdapter):
        def activate(self, new):
            super().activate(new)
            raise FlowError("network_error")
    assert run(Adapter())[-1]["state"] == "verified"


def test_post_activation_login_failure_is_not_unmodified():
    class Adapter(DemoAdapter):
        def verify_new(self, credentials, new):
            raise FlowError("email_required")
    events = run(Adapter())
    assert events[-1]["state"] == "enabled_unverified"
    assert events[-1]["code"] == "email_required"


def test_exception_text_never_reaches_output():
    class Adapter(DemoAdapter):
        def login(self, credentials):
            raise ValueError("CANARY_SECRET_PASSWORD")
    assert "CANARY_SECRET_PASSWORD" not in str(run(Adapter()))
