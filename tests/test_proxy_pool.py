import asyncio
import io
import json
import socket
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from app import server, proxy_pool as pools
from app.adapter import ProtocolAdapter
from test_concurrency import body


def entry(value="gateway.example:3010:user:CANARY_proxy", local=False):
    return pools.parse_proxy(value, b"key", 1, local)


@pytest.mark.parametrize("scheme", ["http", "https", "socks5", "socks5h"])
def test_protocol_and_escaped_credentials(scheme):
    item = entry(f"{scheme}://UsEr:p%40ss%3Aword@gateway.example:3010")
    assert item.url == f"{scheme}://UsEr:p%40ss%3Aword@gateway.example:3010"
    assert "p%40ss" not in repr(item)


def test_default_socks5_password_and_dedupe_without_network(monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError("Saving a pool must not perform network IO")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(pools, "AsyncSession", forbidden)
    async def scenario():
        manager = pools.ProxyPools(b"key")
        result = await manager.replace("owner", ["gateway.example:3010:User:CANARY_proxy", "socks5://User:CANARY_proxy@gateway.example:3010"], False)
        assert result["count"] == 1
        assert result["entries"][0]["endpoint"] == "socks5://gateway.example:3010"
        assert "CANARY" not in json.dumps(result) and "User" not in json.dumps(result)
        assert entry("gateway.example:3010:user:p:a:ss").url.endswith("user:p%3Aa%3Ass@gateway.example:3010")
        assert manager.acquire("owner", result["version"], "task")[1]["proxy_url"].startswith("socks5://")
    asyncio.run(scenario())


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "0.0.0.0", "::1", "::ffff:127.0.0.1", "ff02::1"])
def test_production_address_policy(address):
    host = f"[{address}]" if ":" in address else address
    with pytest.raises(pools.ProxyError, match="proxy_address_blocked"): entry(f"socks5://{host}:1080")


def test_local_only_loopback_exception():
    assert entry("socks5://127.0.0.1:7897", True).host == "127.0.0.1"
    with pytest.raises(pools.ProxyError): entry("socks5://10.0.0.1:1080", True)


@pytest.mark.parametrize("value", ["file:///etc/passwd", "ftp://gateway.example:21", "http://gateway.example:80/admin", "http://gateway.example:80?x=1", "http://u:p%0d%0a@gateway.example:80", "gateway.example:99999:u:p"])
def test_invalid_input_never_echoes(value):
    with pytest.raises(pools.ProxyError) as error: entry(value)
    assert value not in str(error.value)


def test_dns_rebinding_mixed_addresses_and_pinning(monkeypatch):
    def addresses(host, port, *args):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ("8.8.8.8", "127.0.0.1")]
    monkeypatch.setattr(socket, "getaddrinfo", addresses)
    with pytest.raises(pools.ProxyError, match="proxy_address_blocked"): asyncio.run(pools.resolve_proxy(entry(), False))
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))])
    assert asyncio.run(pools.resolve_proxy(entry(), False)) == ["gateway.example:3010:8.8.8.8"]


def test_local_fake_dns_keeps_private_address_policy(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.40", port))])
    calls = []
    async def public(host): calls.append(host); return ["8.8.8.8"]
    monkeypatch.setattr(pools, "resolve_public_dns", public)
    assert asyncio.run(pools.resolve_proxy(entry(), True)) == ["gateway.example:3010:8.8.8.8"]
    with pytest.raises(pools.ProxyError, match="proxy_address_blocked"): asyncio.run(pools.resolve_proxy(entry(), False))
    assert len(calls) == 1
    async def private(host): return ["169.254.169.254"]
    monkeypatch.setattr(pools, "resolve_public_dns", private)
    with pytest.raises(pools.ProxyError, match="proxy_address_blocked"): asyncio.run(pools.resolve_proxy(entry(), True))


def test_local_socks5_pins_real_destinations_preferring_ipv4(monkeypatch):
    monkeypatch.setattr(pools, "_TARGET_PIN_CACHE", {})
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.11", port))])
    calls = []
    async def public(host): calls.append(host); return ["8.8.4.4", "2606:4700:4700::1111"]
    monkeypatch.setattr(pools, "resolve_public_dns", public)
    pins = asyncio.run(pools.target_pins(True, "socks5"))
    assert pins == [f"{host}:443:8.8.4.4" for host in pools.TARGET_HOSTS]
    assert asyncio.run(pools.target_pins(True, "socks5")) == pins
    assert len(calls) == 3
    assert asyncio.run(pools.target_pins(True, "socks5h")) == []
    assert asyncio.run(pools.target_pins(False, "socks5")) == []


def test_task_preparation_only_resolves_it_does_not_probe(monkeypatch):
    async def pinned(*args): return ["gateway.example:3010:8.8.8.8"]
    def forbidden(*args, **kwargs): raise AssertionError("No connectivity tests")
    monkeypatch.setattr(pools, "resolve_proxy", pinned)
    monkeypatch.setattr(pools, "AsyncSession", forbidden)
    route = asyncio.run(pools.prepare_route({"mode": "pool", "proxy_url": entry().url, "local": False}))
    assert route["resolve"] == ["gateway.example:3010:8.8.8.8"]
    assert route["proxy_url"] == entry().url
    assert asyncio.run(pools.prepare_route({"mode": "direct"})) == {"mode": "direct"}


def test_local_direct_honors_enabled_windows_proxy_without_using_pool(monkeypatch):
    monkeypatch.setattr(pools, "windows_system_proxy", lambda: "http://127.0.0.1:7897")
    route = asyncio.run(pools.prepare_route({"mode": "direct", "local": True}))
    assert route == {"mode": "direct", "proxy_url": "http://127.0.0.1:7897", "resolve": []}
    # Server-provided local routing is required; other modes never inherit the desktop proxy.
    assert asyncio.run(pools.prepare_route({"mode": "direct", "local": False})) == {"mode": "direct"}
    monkeypatch.setattr(pools, "windows_system_proxy", lambda: None)
    assert asyncio.run(pools.prepare_route({"mode": "direct", "local": True})) == {"mode": "direct"}


def test_local_pool_keeps_final_proxy_and_uses_current_system_proxy_as_front(monkeypatch):
    async def pinned(*args): return ["gateway.example:3010:8.8.8.8"]
    async def targets(*args): return []
    monkeypatch.setattr(pools, "windows_system_proxy", lambda: "http://127.0.0.1:7897")
    monkeypatch.setattr(pools, "resolve_proxy", pinned)
    monkeypatch.setattr(pools, "target_pins", targets)
    route = asyncio.run(pools.prepare_route({"mode": "pool", "local": True, "proxy_url": "socks5://u:p@gateway.example:3010"}))
    assert route["proxy_url"] == "socks5://u:p@gateway.example:3010"
    assert route["pre_proxy"] == "http://127.0.0.1:7897"


def test_pool_without_local_system_proxy_leaves_os_routing_intact(monkeypatch):
    async def pinned(*args): return []
    async def targets(*args): return []
    monkeypatch.setattr(pools, "windows_system_proxy", lambda: None)
    monkeypatch.setattr(pools, "resolve_proxy", pinned)
    monkeypatch.setattr(pools, "target_pins", targets)
    route = asyncio.run(pools.prepare_route({"mode": "pool", "local": True, "proxy_url": "socks5://8.8.8.8:3010"}))
    assert route == {"mode": "pool", "proxy_url": "socks5://8.8.8.8:3010", "resolve": []}
    def forbidden(): raise AssertionError("Production must not inherit desktop settings")
    monkeypatch.setattr(pools, "windows_system_proxy", forbidden)
    assert asyncio.run(pools.prepare_route({"mode": "pool", "local": False, "proxy_url": "socks5://8.8.8.8:3010"})) == route


def test_pool_dns_uses_the_current_front_network(monkeypatch):
    calls = []
    async def public(host, proxy): calls.append((host, proxy)); return ["8.8.4.4"]
    monkeypatch.setattr(pools, "resolve_public_dns", public)
    monkeypatch.setattr(pools, "_TARGET_PIN_CACHE", {})
    front = "http://127.0.0.1:7897"
    assert asyncio.run(pools.resolve_proxy(entry(), True, front)) == ["gateway.example:3010:8.8.4.4"]
    assert asyncio.run(pools.target_pins(True, "socks5", front)) == [f"{host}:443:8.8.4.4" for host in pools.TARGET_HOSTS]
    assert calls == [(host, front) for host in ("gateway.example", *pools.TARGET_HOSTS)]


def test_random_unused_first_then_shared_and_release_independent(monkeypatch):
    candidates = []
    def choose(values): candidates.append([e.id for e in values]); return values[-1]
    monkeypatch.setattr(pools.secrets, "choice", choose)
    async def scenario():
        manager = pools.ProxyPools(b"key")
        state = await manager.replace("a", [f"gateway.example:3010:u{i}:p" for i in range(3)], False)
        assigned = [manager.acquire("a", state["version"], f"task-{i}") for i in range(10)]
        assert len({key for key, _ in assigned[:3]}) == 3
        assert [len(items) for items in candidates[:4]] == [3, 2, 1, 3]
        assert all(len(items) == 3 for items in candidates[3:])
        assert sum(map(len, manager.leases.values())) == 10
        key = assigned[3][0]
        manager.release(key, "wrong-task")
        assert sum(map(len, manager.leases.values())) == 10
        manager.release(key, "task-3")
        assert key in manager.leases and "task-4" in manager.leases[key]
        for i, (assigned_key, _) in enumerate(assigned): manager.release(assigned_key, f"task-{i}")
        assert not manager.leases
        await manager.close()
    asyncio.run(scenario())


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


def upload(client, values=None):
    response = client.put("/api/proxy-pool", json={"proxies": values or ["gateway.example:3010:user:CANARY_proxy"]})
    assert response.status_code == 200
    return response.json()["version"]


def test_pool_api_auth_isolation_and_no_check_endpoint(client):
    version = upload(client); original_owner = client.cookies.get(server.COOKIE)
    assert "CANARY" not in client.get("/api/proxy-pool").text
    assert client.post("/api/proxy-pool/check", json={"version": version}).status_code == 404
    client.cookies.clear()
    assert client.get("/api/proxy-pool").status_code == 401
    login = client.post("/api/session", json={"access_key": "fixture-access"})
    client.headers["x-csrf-token"] = login.json()["csrf"]
    assert client.get("/api/proxy-pool").json()["entries"] == []
    own = upload(client, ["different.example:3010:u:p"])
    assert own != version
    assert client.request("DELETE", "/api/proxy-pool", json={}).status_code == 200
    client.cookies.set(server.COOKIE, original_owner, domain="127.0.0.1", path="/")
    assert client.get("/api/proxy-pool").json()["version"] == version
    client.headers.pop("x-csrf-token")
    assert client.request("DELETE", "/api/proxy-pool", json={}).status_code == 403


def test_production_rejects_direct_and_empty_pool(client, monkeypatch):
    monkeypatch.setattr(server, "LOCAL", False); monkeypatch.setattr(server, "SECURE", True)
    assert client.get("/api/capabilities").json()["routing"]["allow_direct"] is False
    assert client.post("/api/jobs", json=body(network_mode="direct")).json()["code"] == "direct_forbidden"
    assert client.post("/api/jobs", json=body()).json()["code"] == "proxy_required"


def test_ten_tasks_with_three_proxies_no_detection_and_no_proxy_limit(client, monkeypatch):
    captured = []
    async def reserve(job, credentials): captured.append(credentials.copy()); credentials.clear()
    monkeypatch.setattr(server, "execute", reserve)
    version = upload(client, [f"gateway.example:3010:u{i}:p" for i in range(3)])
    payloads = [body(i, network_mode="pool", proxy_pool_version=version) for i in range(11)]
    ids = [client.post("/api/jobs", json=item).json()["id"] for item in payloads[:10]]
    assert len(set(ids)) == 10
    assert len({item["network"]["proxy_url"] for item in captured[:3]}) == 3
    assert len({item["network"]["proxy_url"] for item in captured}) == 3
    assert client.post("/api/jobs", json=payloads[0]).json()["id"] == ids[0]
    assert sum(map(len, server.memory.proxies.leases.values())) == 10
    assert client.post("/api/jobs", json=payloads[10]).json()["code"] == "busy"
    assert client.put("/api/proxy-pool", json={"proxies": ["other.example:1080"]}).json()["code"] == "proxy_pool_busy"
    assert client.request("DELETE", "/api/proxy-pool", json={}).status_code == 409


def test_pool_versions_are_scoped_to_owner(client):
    async def scenario():
        manager = pools.ProxyPools(b"key")
        a = await manager.replace("a", ["gateway.example:3010:u:p"], False)
        await manager.replace("b", ["other.example:3010:u:p"], False)
        with pytest.raises(pools.ProxyError, match="proxy_pool_changed"): manager.acquire("b", a["version"], "task")
    asyncio.run(scenario())


def test_terminal_event_keeps_shared_assignments_until_cleanup(monkeypatch):
    async def scenario():
        memory = server.Memory(); monkeypatch.setattr(server, "memory", memory)
        state = await memory.proxies.replace("a", ["gateway.example:3010:u:p"], False)
        item = server.Job("fixture", "a", "operation", "account")
        item.proxy_key, route = memory.proxies.acquire("a", state["version"], item.id)
        memory.proxies.acquire("a", state["version"], "other-task")
        item.cancelled = True
        entered, release = asyncio.Event(), asyncio.Event()
        async def terminate(job): entered.set(); await release.wait()
        monkeypatch.setattr(server, "terminate", terminate)
        task = asyncio.create_task(server.execute(item, {"network": route})); await entered.wait()
        assert item.done and item.id in memory.proxies.leases[item.proxy_key]
        release.set(); await task
        assert memory.proxies.leases[item.proxy_key] == {"other-task"}
    asyncio.run(scenario())


def test_worker_route_failure_preserves_mutation_state_and_redacts(monkeypatch, capsys):
    from app import worker, adapter
    monkeypatch.setenv("MFA_MODE", "live")
    payload = {"action": "rotate", "initial_state": "unchanged", "network": {"mode": "pool", "proxy_url": "socks5://u:CANARY@169.254.169.254:1080", "local": False}}
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(json.dumps(payload) + "\n"))
    monkeypatch.setattr(adapter, "ProtocolAdapter", lambda **kwargs: (_ for _ in ()).throw(AssertionError("Must not login")))
    worker.main()
    text = capsys.readouterr().out; event = json.loads(text)
    assert "CANARY" not in text and event["state"] == "unchanged" and event["code"] == "proxy_address_blocked"


def test_adapter_keeps_assigned_route_in_all_auth_sessions(monkeypatch):
    from app import adapter
    configurations = []
    class Flow:
        def __init__(self, config, **kwargs): configurations.append(config); self.result = SimpleNamespace(totp_secret="")
        def run_protocol_login(self, *args, **kwargs):
            return SimpleNamespace(access_token="fixture", session_token="fixture", session_json=json.dumps({"user": {"email": "a@example.com"}, "account": {"id": "account"}}))
    monkeypatch.setattr(adapter, "PrivacyFlow", Flow)
    route = {"mode": "pool", "proxy_url": "socks5://u:p@gateway.example:1080", "resolve": ["gateway.example:1080:8.8.8.8"]}
    item = ProtocolAdapter(network_route=route)
    for reauth in (True, False, True): item._login({"email": "a@example.com", "password": "fixture", "totp_secret": "fixture"}, reauth=reauth)
    assert all(config.proxy == route["proxy_url"] and config.pre_proxy == "off" and config.proxy_resolve == tuple(route["resolve"]) for config in configurations)
