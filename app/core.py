"""Explicit non-atomic rotation state machine, transport injected for tests."""
import secrets
import time


class FlowError(Exception):
    def __init__(self, code="upstream_error"):
        self.code = code
        super().__init__(code)


def retry_kind(state):
    if state == "unchanged":
        return "rotate"
    if state in {"enabled_unverified", "activation_unknown"}:
        return "verify"
    return "none"


def verify_only(adapter, credentials, emit, cancelled):
    """Read-only recovery: never disable, enroll or activate any factor."""
    state = credentials.get("initial_state", "activation_unknown")
    try:
        if cancelled():
            raise FlowError("verification_cancelled")
        emit({"type": "stage", "stage": "verifying", "state": state})
        adapter.verify_current(credentials, {"secret": credentials["totp_secret"], "factor_id": credentials["factor_id"]})
        state = "verified"
        emit({"type": "done", "stage": "complete", "state": state, "code": "verified"})
    except FlowError as exc:
        code = "verification_cancelled" if exc.code == "cancelled" else exc.code
        emit({"type": "done", "stage": "stopped", "state": state, "code": code})
    except Exception:
        emit({"type": "done", "stage": "stopped", "state": state, "code": "worker_failed"})
    finally:
        adapter.close()


def rotate(adapter, credentials, emit, receipt, cancelled):
    state = "unchanged"
    new = None

    def stage(name):
        emit({"type": "stage", "stage": name, "state": state})

    def done(code, stage_name):
        event = {"type": "done", "stage": stage_name, "state": state, "code": code}
        diagnostics = getattr(adapter, "diagnostics", None)
        if callable(diagnostics):
            event["diagnostics"] = diagnostics()
        emit(event)

    try:
        if cancelled():
            raise FlowError("cancelled")
        stage("authenticating")
        adapter.login(credentials)
        if cancelled():
            raise FlowError("cancelled")
        stage("checking")
        old_id = adapter.old_factor()
        if cancelled():
            raise FlowError("cancelled")
        stage("reauthenticating")
        adapter.reauthenticate(credentials)
        if cancelled():
            raise FlowError("cancelled")
        # Announce the uncertain boundary BEFORE sending a mutation.
        state = "removal_unknown"
        stage("removing")
        try:
            adapter.disable(old_id)
        except FlowError:
            if adapter.has_factor(old_id):
                state = "unchanged"
                raise
        if adapter.has_factor(old_id):
            state = "unchanged"
            raise FlowError()
        state = "old_factor_removed"
        stage("enrolling")
        new = adapter.enroll()
        state = "enrollment_pending"
        token = secrets.token_urlsafe(24)
        emit({"type": "secret", "stage": "awaiting_receipt", "state": state,
              "new_secret": new["secret"], "factor_id": new["factor_id"], "receipt": token})
        if not receipt(token):
            raise FlowError("receipt_timeout")
        # Client has committed the new secret locally. Continue to protect the
        # account even if a cancel request arrives after the destructive boundary.
        state = "activation_unknown"
        stage("activating")
        try:
            adapter.activate(new)
        except FlowError:
            if not adapter.has_factor(new["factor_id"]):
                raise
        if not adapter.has_factor(new["factor_id"]) or adapter.has_factor(old_id):
            raise FlowError()
        state = "enabled_unverified"
        if cancelled():
            raise FlowError("verification_cancelled")
        stage("verifying")
        adapter.verify_new(credentials, new)
        state = "verified"
        done("verified", "complete")
    except FlowError as exc:
        code = "verification_cancelled" if exc.code == "cancelled" and state != "unchanged" else exc.code
        done(code, "stopped")
    except Exception:
        done("worker_failed", "stopped")
    finally:
        adapter.close()


class DemoAdapter:
    """Offline-only fixture, never contacts a real service."""
    def __init__(self):
        self.factors = {"demo-old"}

    def login(self, credentials):
        time.sleep(.1)
    def old_factor(self):
        return "demo-old"
    def reauthenticate(self, credentials):
        time.sleep(.1)
    def disable(self, factor_id):
        self.factors.remove(factor_id)
    def has_factor(self, factor_id):
        return factor_id in self.factors
    def enroll(self):
        import base64
        return {"secret": base64.b32encode(secrets.token_bytes(20)).decode(),
                "factor_id": secrets.token_hex(16), "session_id": secrets.token_hex(16)}
    def activate(self, new):
        self.factors.add(new["factor_id"])
    def verify_new(self, credentials, new):
        time.sleep(.1)
    def verify_current(self, credentials, new):
        time.sleep(.1)
    def close(self):
        pass
