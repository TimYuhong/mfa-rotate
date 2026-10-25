import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import sys
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
    monkeypatch.setattr(server, "GLOBAL_MAX_CONCURRENT", 30)
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
    caps = client.get("/api/capabilities").json()
    assert caps["global_max_concurrent"] == 30 and caps["active_count"] == 10
    assert caps["available"]  # Other sessions can still use the global capacity.


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
    ids = []
    for session in range(3):
        if session:
            response = client.post("/api/session", json={"access_key": "fixture-access"})
            client.headers["x-csrf-token"] = response.json()["csrf"]
        for index in range(10):
            response = client.post("/api/jobs", json=body(session * 10 + index))
            assert response.status_code == 200
            ids.append(response.json()["id"])
        assert client.post("/api/jobs", json=body(100 + session)).json()["code"] == "busy"
    response = client.post("/api/session", json={"access_key": "fixture-access"})
    client.headers["x-csrf-token"] = response.json()["csrf"]
    assert client.post("/api/jobs", json=body(31)).json()["code"] == "busy"
    caps = client.get("/api/capabilities").json()
    assert caps["active_count"] == caps["global_max_concurrent"] == 30 and not caps["available"]
    server.memory.jobs[ids[0]].emit({"type": "done", "state": "verified", "code": "verified"})
    assert client.get("/api/capabilities").json()["active_count"] == 29
    assert client.post("/api/jobs", json=body(31)).status_code == 200
    assert client.get("/api/capabilities").json()["active_count"] == 30


def test_concurrent_admissions_across_sessions_cannot_exceed_global_limit(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    sessions = [(client.cookies.get(server.COOKIE), client.headers["x-csrf-token"])]
    for _ in range(3):
        response = client.post("/api/session", json={"access_key": "fixture-access"})
        sessions.append((client.cookies.get(server.COOKIE), response.json()["csrf"]))
    def submit(index):
        sid, csrf = sessions[index % len(sessions)]
        return client.post("/api/jobs", json=body(index), headers={"cookie": f"{server.COOKIE}={sid}", "x-csrf-token": csrf})
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(submit, range(40)))
    assert sum(response.status_code == 200 for response in responses) == 30
    assert sum(response.status_code == 409 and response.json()["code"] == "busy" for response in responses) == 10
    assert sum(server.occupied(job) for job in server.memory.jobs.values()) == 30
    assert all(sum(job.owner == sid for job in server.memory.jobs.values()) <= 10 for sid, _ in sessions)


def test_terminal_event_does_not_release_global_slot_before_cleanup(client, monkeypatch):
    monkeypatch.setattr(server, "GLOBAL_MAX_CONCURRENT", 1)
    release = client.portal.call(asyncio.Event)
    async def hold(job, credentials):
        try:
            await release.wait()
        finally:
            credentials.clear()
    monkeypatch.setattr(server, "execute", hold)
    try:
        response = client.post("/api/jobs", json=body())
        job = server.memory.jobs[response.json()["id"]]
        job.emit({"type": "done", "state": "verified", "code": "verified"})
        assert client.get("/api/capabilities").json()["active_count"] == 1
        assert client.post("/api/jobs", json=body(1)).json()["code"] == "busy"
    finally:
        client.portal.call(release.set)
        client.portal.call(asyncio.sleep, 0)
    assert job.task.done()
    assert client.get("/api/capabilities").json()["active_count"] == 0
    assert client.post("/api/jobs", json=body(1)).status_code == 200


def test_slot_api_rejects_account_data_and_binds_lease_to_session(client, monkeypatch):
    monkeypatch.setattr(server, "execute", reserve_only)
    response = client.post("/api/job-slots", json={"password": "PRIVATE_CANARY"})
    assert response.status_code == 422 and "PRIVATE_CANARY" not in response.text
    assert not server.memory.admission.waiting and not server.memory.jobs
    lease = client.post("/api/job-slots", json={}).json()
    assert lease["status"] == "ready" and len(server.memory.admission.leases) == 1
    assert client.post("/api/job-slots", json={}).json()["token"] == lease["token"]
    original_cookie = client.cookies.get(server.COOKIE)
    original_csrf = client.headers["x-csrf-token"]
    login = client.post("/api/session", json={"access_key": "fixture-access"})
    client.headers["x-csrf-token"] = login.json()["csrf"]
    assert client.post("/api/jobs", json=body(slot_token=lease["token"])).json()["code"] == "slot_expired"
    assert not server.memory.jobs
    client.request("DELETE", f"/api/job-slots/{lease['token']}", json={})
    assert len(server.memory.admission.leases) == 1
    client.headers.update({"cookie": f"{server.COOKIE}={original_cookie}", "x-csrf-token": original_csrf})
    assert client.post("/api/jobs", json=body(slot_token=lease["token"])).status_code == 200
    assert not server.memory.admission.leases


def test_slot_api_counts_reservations_and_legacy_clients_cannot_jump_queue(client, monkeypatch):
    monkeypatch.setattr(server, "GLOBAL_MAX_CONCURRENT", 1)
    monkeypatch.setattr(server, "execute", reserve_only)
    lease = client.post("/api/job-slots", json={}).json()
    first_sid = client.cookies.get(server.COOKIE)
    login = client.post("/api/session", json={"access_key": "fixture-access"})
    client.headers["x-csrf-token"] = login.json()["csrf"]
    assert client.post("/api/job-slots", json={}).json()["status"] == "queued"
    assert client.post("/api/jobs", json=body(1)).json()["code"] == "busy"
    assert client.get("/api/capabilities").json()["reserved_count"] == 1
    assert client.get("/api/capabilities").json()["active_count"] == 0
    assert not client.get("/api/capabilities").json()["available"]
    server.memory.admission.release(lease["token"], first_sid)
    assert client.post("/api/jobs", json=body(1)).status_code == 200
    assert client.get("/api/capabilities").json()["active_count"] == 1


@pytest.mark.parametrize(("setting", "expected"), [("100", 30), ("0", 1), ("7", 7)])
def test_configured_global_limit_is_clamped_to_hard_maximum(setting, expected):
    result = subprocess.run([sys.executable, "-B", "-c", "from app.server import GLOBAL_MAX_CONCURRENT; print(GLOBAL_MAX_CONCURRENT)"],
                            cwd=server.ROOT, env={**os.environ, "MFA_GLOBAL_MAX_CONCURRENT": setting}, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == str(expected)


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
