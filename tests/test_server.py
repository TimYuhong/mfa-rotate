from fastapi.testclient import TestClient
from app import server
import pytest


@pytest.fixture
def client(monkeypatch):
    server.memory = server.Memory()
    monkeypatch.setattr(server, "MODE", "demo")
    monkeypatch.setattr(server, "LOCAL", True)
    monkeypatch.setattr(server, "ACCESS", "fixture-access")
    monkeypatch.setenv("MFA_MODE", "demo")
    with TestClient(server.app, base_url=server.ORIGIN) as c:
        yield c


def auth(client):
    response = client.post("/api/session", json={"access_key": "fixture-access"}, headers={"origin": server.ORIGIN})
    assert response.status_code == 200
    return {"origin": server.ORIGIN, "x-csrf-token": response.json()["csrf"]}


def test_disabled_does_not_accept_credentials(client, monkeypatch):
    monkeypatch.setattr(server, "MODE", "disabled")
    response = client.post("/api/jobs", json={"password": "canary"}, headers={"origin": server.ORIGIN})
    assert response.status_code == 503
    assert "canary" not in response.text


def test_validation_never_echoes_password(client):
    headers = auth(client)
    response = client.post("/api/jobs", json={"email": "bad", "password": "CANARY_password_123"}, headers=headers)
    assert response.status_code == 422
    assert "CANARY" not in response.text


def test_wrong_origin_rejected(client):
    response = client.post("/api/session", json={"access_key": "fixture-access"}, headers={"origin": "https://evil.invalid"})
    assert response.status_code == 403


def test_unauthenticated_stream_rejected(client):
    assert client.get("/api/jobs/unknown/events").status_code == 401


def test_cross_session_cannot_read_job(client):
    auth(client)
    job = server.Job("fixture", "someone-else", "fixture-operation", "hash")
    server.memory.jobs[job.id] = job
    assert client.get("/api/jobs/fixture/events").status_code == 404


def test_receipt_bound_to_job(client):
    headers = auth(client)
    owner = client.cookies.get(server.COOKIE)
    job = server.Job("fixture", owner, "fixture-operation", "hash")
    job.pending_receipt = "correct_receipt_1234567890"
    server.memory.jobs[job.id] = job
    assert client.post("/api/jobs/fixture/receipt", json={"receipt": "wrong_receipt_1234567890"}, headers=headers).status_code == 409


def test_missing_csrf_rejected(client):
    auth(client)
    assert client.post("/api/jobs/any/cancel", json={}, headers={"origin": server.ORIGIN}).status_code == 403


def test_memory_expiry_drops_sensitive_events(client):
    job = server.Job("fixture", "owner", "op", "hash")
    job.emit({"type": "done", "code": "verified"})
    job.ended -= server.TTL + 1
    job.events.append({"new_secret": "canary"})
    server.memory.jobs[job.id] = job
    server.memory.cleanup()
    assert job.id not in server.memory.jobs


def test_security_headers(client):
    response = client.get("/api/health")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"


def test_body_limit(client):
    response = client.post("/api/session", json={"access_key": "X" * 9000}, headers={"origin": server.ORIGIN})
    assert response.status_code == 413


def test_job_delete_cannot_interrupt_mutation(client):
    headers = auth(client)
    job = server.Job("fixture", client.cookies.get(server.COOKIE), "op", "hash")
    server.memory.jobs[job.id] = job
    assert client.request("DELETE", "/api/jobs/fixture", json={}, headers=headers).status_code == 409


def test_completed_operation_cannot_be_replayed(client):
    headers = auth(client)
    sid = client.cookies.get(server.COOKIE)
    job = server.Job("fixture", sid, "operation_123456789", "hash")
    job.emit({"type": "done", "code": "verified"})
    server.memory.jobs[job.id] = job
    assert client.request("DELETE", "/api/jobs/fixture", json={}, headers=headers).status_code == 200
    response = client.post("/api/jobs", json={"email": "a@example.com", "password": "p", "totp_secret": "JBSWY3DPEHPK3PXP", "operation_id": job.operation, "storage_ready": True, "authorized": True}, headers=headers)
    assert response.status_code == 409
    assert response.json()["code"] == "operation_already_completed"
