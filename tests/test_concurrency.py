import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from app import server
from app.core import DemoAdapter, FlowError, rotate, verify_only
from app.adapter import PrivacyFlow
from config import Config


@pytest.fixture
def client(monkeypatch):
    server.memory = server.Memory()
    monkeypatch.setattr(server, "MODE", "demo")
    monkeypatch.setattr(server, "LOCAL", True)
    monkeypatch.setattr(server, "ACCESS", "fixture-access")
    monkeypatch.setattr(server, "MAX_CONCURRENT", 10)
    with TestClient(server.app, base_url=server.ORIGIN) as client:
        response = client.post("/api/session", json={"access_key": "fixture-access"}, headers={"origin": server.ORIGIN})
        client.headers.update({"origin": server.ORIGIN, "x-csrf-token": response.json()["csrf"]})
        try:
            yield client
        finally:
            # These are isolated offline fixtures, never real account jobs.
            for job in server.memory.jobs.values():
                job.cancelled = True
                if job.process:
                    client.portal.call(server.terminate, job)


def body(index=0, **extra):
    return {"email": f"fixture-{index}@example.com", "password": "fake-password", "totp_secret": "JBSWY3DPEHPK3PXP",
            "operation_id": f"operation_fixture_{index}", "storage_ready": True, "authorized": True, **extra}


async def reserve_only(job, credentials):
    credentials.clear()


def test_ten_slots_and_eleventh_rejected(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    ids = [client.post("/api/jobs", json=body(i)).json()["id"] for i in range(10)]
    assert len(set(ids)) == 10
    assert client.post("/api/jobs", json=body(10)).json()["code"] == "busy"
    assert client.get("/api/capabilities").json()["max_concurrent"] == 10
    assert not client.get("/api/capabilities").json()["available"]


def test_same_account_mutex_and_idempotency(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    first = client.post("/api/jobs", json=body()).json()
    assert client.post("/api/jobs", json=body()).json()["id"] == first["id"]
    assert client.post("/api/jobs", json=body(operation_id="different_operation_123")).json()["code"] == "account_busy"


def test_single_cancel_does_not_change_other_jobs(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    ids = [client.post("/api/jobs", json=body(i)).json()["id"] for i in range(3)]
    assert client.post(f"/api/jobs/{ids[1]}/cancel", json={}).status_code == 200
    assert [server.memory.jobs[jid].cancelled for jid in ids] == [False, True, False]


def test_retry_enforces_mutation_boundary(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    jid = client.post("/api/jobs", json=body()).json()["id"]
    job = server.memory.jobs[jid]
    job.emit({"type": "secret", "state": "enrollment_pending", "new_secret": "JBSWY3DPEHPK3PXP", "factor_id": "new-factor", "receipt": "fixture-receipt"})
    job.emit({"type": "done", "state": "enabled_unverified", "code": "login_failed"})
    retry = body(operation_id="retry_operation_123")
    assert client.post(f"/api/jobs/{jid}/retry", json=retry).json()["code"] == "unsafe_retry"
    retry.update(action="verify", factor_id="new-factor")
    response = client.post(f"/api/jobs/{jid}/retry", json=retry)
    assert response.status_code == 200
    assert server.memory.jobs[response.json()["id"]].action == "verify"
    assert server.memory.jobs[response.json()["id"]].state == "enabled_unverified"


def test_unchanged_failure_can_retry_and_unknown_mutation_cannot(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    jid = client.post("/api/jobs", json=body()).json()["id"]
    server.memory.jobs[jid].emit({"type": "done", "state": "unchanged", "code": "login_failed"})
    assert client.post(f"/api/jobs/{jid}/retry", json=body(operation_id="retry_before_change_123")).status_code == 200
    server.memory.jobs[jid].state = "removal_unknown"
    assert client.post(f"/api/jobs/{jid}/retry", json=body(operation_id="unsafe_attempt_123456")).json()["code"] == "unsafe_retry"


def test_poll_and_operation_lookup_are_owner_scoped(client):
    job = server.Job("other", "another-session", "other_operation", "hash")
    job.emit({"type": "secret", "new_secret": "PRIVATE_CANARY", "receipt": "other"})
    server.memory.jobs[job.id] = job
    response = client.post("/api/job-events", json={"cursors": {job.id: 0}})
    assert "PRIVATE_CANARY" not in response.text
    assert response.json()["jobs"][job.id]["error"] == "job_not_found"
    assert client.get("/api/operations/other_operation").status_code == 404


def test_cancel_after_terminal_event_does_not_rewrite_result(client):
    sid = client.cookies.get(server.COOKIE)
    job = server.Job("finished", sid, "finished_operation", "hash")
    job.emit({"type": "done", "state": "verified", "code": "verified"})
    server.memory.jobs[job.id] = job
    response = client.post("/api/jobs/finished/cancel", json={})
    assert response.json()["done"]
    assert job.events[-1]["outcome"] == "success"
    assert not job.cancelled


def test_global_capacity_applies_across_sessions(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    for index in range(10):
        assert client.post("/api/jobs", json=body(index)).status_code == 200
    response = client.post("/api/session", json={"access_key": "fixture-access"})
    client.headers["x-csrf-token"] = response.json()["csrf"]
    assert client.post("/api/jobs", json=body(11)).json()["code"] == "busy"


def test_ten_real_demo_processes_complete_with_one_poll_channel(client, monkeypatch):
    monkeypatch.setenv("MFA_MODE", "demo")
    ids = [client.post("/api/jobs", json=body(i)).json()["id"] for i in range(10)]
    cursors = dict.fromkeys(ids, 0)
    outcomes = {}
    deadline = time.monotonic() + 30
    while cursors and time.monotonic() < deadline:
        snapshot = client.post("/api/job-events", json={"cursors": cursors}).json()["jobs"]
        for jid, item in snapshot.items():
            for event in item["events"]:
                cursors[jid] = event["seq"]
                if event["type"] == "secret":
                    assert client.post(f"/api/jobs/{jid}/receipt", json={"receipt": event["receipt"]}).status_code == 200
                if event["type"] == "done":
                    outcomes[jid] = event["outcome"]
                    del cursors[jid]
        time.sleep(.05)
    assert len(outcomes) == 10 and set(outcomes.values()) == {"success"}
    pids = [server.memory.jobs[jid].process.pid for jid in ids]
    assert len(set(pids)) == 10


def test_cancel_after_removal_delivers_and_activates_before_stopping():
    stopped = False
    events = []
    class Adapter(DemoAdapter):
        def disable(self, factor):
            nonlocal stopped
            super().disable(factor)
            stopped = True
        def verify_new(self, credentials, new):
            raise AssertionError("Cancelled verification should not start")
    adapter = Adapter()
    rotate(adapter, {}, events.append, lambda token: True, lambda: stopped)
    assert any(event["type"] == "secret" for event in events)
    assert adapter.factors
    assert events[-1]["state"] == "enabled_unverified"
    assert events[-1]["code"] == "verification_cancelled"


def test_cancelled_real_demo_worker_still_delivers_key_and_other_job_completes(client, monkeypatch):
    monkeypatch.setenv("MFA_MODE", "demo")
    ids = [client.post("/api/jobs", json=body(index)).json()["id"] for index in range(2)]
    cursors = dict.fromkeys(ids, 0)
    results = {}
    deadline = time.monotonic() + 20
    while cursors and time.monotonic() < deadline:
        snapshot = client.post("/api/job-events", json={"cursors": cursors}).json()["jobs"]
        for jid, item in snapshot.items():
            for event in item["events"]:
                cursors[jid] = event["seq"]
                if event["type"] == "secret":
                    if jid == ids[0]:
                        assert client.post(f"/api/jobs/{jid}/cancel", json={}).json()["deferred"]
                    assert client.post(f"/api/jobs/{jid}/receipt", json={"receipt": event["receipt"]}).status_code == 200
                if event["type"] == "done":
                    results[jid] = event
                    del cursors[jid]
        time.sleep(.03)
    assert results[ids[0]]["outcome"] == "cancelled"
    assert results[ids[0]]["state"] == "enabled_unverified"
    assert results[ids[1]]["outcome"] == "success"


def test_verification_retry_never_mutates():
    class ReadOnlyAdapter:
        def verify_current(self, credentials, new):
            assert new == {"secret": "JBSWY3DPEHPK3PXP", "factor_id": "new"}
        def close(self): pass
    events = []
    verify_only(ReadOnlyAdapter(), {"totp_secret": "JBSWY3DPEHPK3PXP", "factor_id": "new"}, events.append, lambda: False)
    assert events[-1]["state"] == "verified"
    assert not any(event.get("stage") in {"removing", "enrolling", "activating"} for event in events)


def test_ten_device_cookie_and_fingerprint_contexts_are_isolated():
    flows = [PrivacyFlow(Config()) for _ in range(10)]
    try:
        assert len({flow.result.device_id for flow in flows}) == 10
        assert len({flow._ensure_registration_context().context_id for flow in flows}) == 10
        assert len({id(flow._fingerprint) for flow in flows}) == 10
        assert len({id(flow.session.wrapped) for flow in flows}) == 10
        flows[0].session.cookies.set("isolation-fixture", "not-shared", domain="chatgpt.com")
        assert all(not flow.session.cookies.get("isolation-fixture") for flow in flows[1:])
        original = flows[1]._fingerprint["lang"]
        flows[0]._fingerprint["lang"] = "fixture-language"
        assert flows[1]._fingerprint["lang"] == original
    finally:
        for flow in flows: flow.session.close()
