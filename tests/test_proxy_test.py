import asyncio
import json
from types import SimpleNamespace

import pytest
from curl_cffi.requests.exceptions import Timeout
from fastapi.testclient import TestClient
from app import proxy_test as probe, server
from test_concurrency import body


def fixtures(monkeypatch, response=None, error=None):
    events = []
    async def prepare(route, target_hosts):
        assert route["mode"] == "pool" and target_hosts == ("www.cloudflare.com",)
        return {"proxy_url": "socks5://pool-user:CANARY@gateway.example:3010", "pre_proxy": "http://127.0.0.1:7897", "resolve": []}
    class Bridge:
        def __init__(self, route): events.append(("bridge", route))
        def __enter__(self): return {"proxy_url": "socks5://pool-user:CANARY@127.0.0.1:1234", "resolve": []}
        def __exit__(self, *args): events.append(("bridge-close", True))
    class Session:
        def __init__(self, **kwargs): events.append(("session", kwargs))
        def __enter__(self): return self
        def __exit__(self, *args): events.append(("session-close", True))
        def get(self, url, **kwargs):
            assert url == "https://www.cloudflare.com/cdn-cgi/trace"
            assert kwargs == {"timeout": 12, "allow_redirects": False}
            events.append(("request", url))
            if error: raise error
            return response or SimpleNamespace(status_code=200, content=b"fixture", text="ip=203.0.113.7\nloc=SG\n")
    monkeypatch.setattr(probe, "prepare_route", prepare)
    monkeypatch.setattr(probe, "TaskProxyTransport", Bridge)
    monkeypatch.setattr(probe, "Session", Session)
    times = iter([100.0, 100.123])
    monkeypatch.setattr(probe.time, "perf_counter", lambda: next(times))
    return events


def test_anonymous_probe_reports_country_ip_and_measured_latency(monkeypatch):
    events = fixtures(monkeypatch)
    result = probe.probe_connection({"mode": "pool", "proxy_url": "fixture"})
    assert result == {"ok": True, "country": "SG", "ip": "203.0.113.7", "latency_ms": 123}
    assert [event[0] for event in events] == ["bridge", "session", "request", "session-close", "bridge-close"]
    assert events[1][1]["trust_env"] is False
    assert events[1][1]["proxy"].startswith("socks5://pool-user:CANARY@127.0.0.1:")


@pytest.mark.parametrize("response", [
    SimpleNamespace(status_code=503, content=b"fixture", text="CANARY"),
    SimpleNamespace(status_code=200, content=b"fixture", text="ip=not-an-ip\nloc=SG\nCANARY"),
    SimpleNamespace(status_code=200, content=b"fixture", text="ip=203.0.113.7\nloc=CANARY"),
])
def test_invalid_egress_information_never_makes_up_success(monkeypatch, response):
    events = fixtures(monkeypatch, response=response)
    result = probe.probe_connection({"mode": "pool"})
    assert not result["ok"] and "latency_ms" not in result and "CANARY" not in json.dumps(result)
    assert len([event for event in events if event[0] == "request"]) == 1


def test_network_failure_is_redacted_and_never_retried(monkeypatch):
    events = fixtures(monkeypatch, error=Timeout("CANARY_proxy_password", code=28))
    result = probe.probe_connection({"mode": "pool"})
    assert result == {"ok": False, "code": "proxy_test_timeout", "message": "连接超时"}
    assert len([event for event in events if event[0] == "request"]) == 1
    assert events[-1][0] == "bridge-close"


def test_parent_only_accepts_safe_child_fields():
    assert probe.safe_result({"ok": True, "country": "SG", "ip": "203.0.113.7", "latency_ms": -1})["ok"] is False
    assert probe.safe_result({"ok": True, "country": "SG", "ip": "203.0.113.7", "latency_ms": "12"})["ok"] is False
    assert "CANARY" not in json.dumps(probe.safe_result({"ok": False, "code": "unknown", "message": "CANARY"}))


@pytest.fixture
def client(monkeypatch):
    server.memory = server.Memory()
    monkeypatch.setattr(server, "MODE", "demo")
    monkeypatch.setattr(server, "LOCAL", True)
    monkeypatch.setattr(server, "ACCESS", "fixture-access")
    with TestClient(server.app, base_url=server.ORIGIN) as client:
        login = client.post("/api/session", json={"access_key": "fixture-access"}, headers={"origin": server.ORIGIN})
        client.headers.update({"origin": server.ORIGIN, "x-csrf-token": login.json()["csrf"]})
        yield client


def test_random_test_does_not_replace_task_pool_and_is_always_pool_routed(client, monkeypatch):
    calls = []
    async def run(route, sid):
        assert sid in server.memory.proxy_tests
        calls.append(dict(route))
        return {"ok": True, "country": "SG", "ip": "203.0.113.7", "latency_ms": 1234}
    monkeypatch.setattr(server, "run_proxy_test", run)
    monkeypatch.setattr(server.secrets, "choice", lambda values: values[-1])
    previous = client.put("/api/proxy-pool", json={"proxies": ["old.example:3010:old:p"]}).json()
    proxies = [f"gateway.example:3010:u{i}:CANARY" for i in range(3)]
    response = client.post("/api/proxy-pool/test", json={"proxies": proxies})
    assert response.status_code == 200
    assert response.json() == {"ok": True, "country": "SG", "ip": "203.0.113.7", "latency_ms": 1234, "selected": 3}
    assert calls[0] == {"mode": "pool", "local": True, "proxy_url": "socks5://u2:CANARY@gateway.example:3010"}
    assert client.get("/api/proxy-pool").json() == previous
    assert not server.memory.proxy_tests and not server.memory.jobs and "CANARY" not in response.text


def test_manual_test_authentication_csrf_validation_and_isolation(client, monkeypatch):
    async def forbidden(*args): raise AssertionError("Must not start an unauthorized test")
    monkeypatch.setattr(server, "run_proxy_test", forbidden)
    response = client.post("/api/proxy-pool/test", json={"proxies": ["http://u:CANARY@169.254.169.254:3010"]})
    assert response.status_code == 422 and "CANARY" not in response.text
    client.headers.pop("x-csrf-token")
    assert client.post("/api/proxy-pool/test", json={"proxies": ["gateway.example:3010:u:p"]}).status_code == 403
    client.cookies.clear()
    assert client.post("/api/proxy-pool/test", json={"proxies": ["gateway.example:3010:u:p"]}).status_code == 401


def test_tests_are_bounded_and_do_not_overlap_the_same_owners_account_jobs(client):
    sid = client.cookies.get(server.COOKIE)
    server.memory.proxy_tests[sid] = None
    assert client.post("/api/proxy-pool/test", json={"proxies": ["gateway.example:3010:u:p"]}).json()["code"] == "proxy_test_busy"
    assert client.post("/api/jobs", json=body()).json()["code"] == "proxy_test_busy"
    server.memory.proxy_tests = {f"other-{i}": None for i in range(3)}
    assert client.post("/api/proxy-pool/test", json={"proxies": ["gateway.example:3010:u:p"]}).json()["code"] == "proxy_test_busy"
    server.memory.proxy_tests.clear()
    server.memory.jobs["running"] = server.Job("running", sid, "operation", "account")
    assert client.post("/api/proxy-pool/test", json={"proxies": ["gateway.example:3010:u:p"]}).json()["code"] == "proxy_pool_busy"


@pytest.mark.parametrize("timeout", [False, True])
def test_subprocess_uses_stdin_and_cleans_up_on_timeout(client, monkeypatch, timeout):
    captured = []
    class Process:
        returncode = None
        def kill(self): self.returncode = -9; captured.append("kill")
        async def wait(self): captured.append("wait"); return self.returncode
        async def communicate(self, payload):
            value = json.loads(payload)
            assert value["proxy_url"] == "socks5://u:CANARY@gateway.example:3010"
            if timeout: raise asyncio.TimeoutError()
            self.returncode = 0
            return json.dumps({"ok": True, "country": "SG", "ip": "203.0.113.7", "latency_ms": 123}).encode(), b""
    async def create(*args, **kwargs):
        assert "CANARY" not in repr(args) and "app.proxy_test" in args
        return Process()
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", create)
    result = client.post("/api/proxy-pool/test", json={"proxies": ["gateway.example:3010:u:CANARY"]}).json()
    assert result["ok"] is not timeout
    assert (captured == ["kill", "wait"]) if timeout else captured == []
    assert not server.memory.proxy_tests
