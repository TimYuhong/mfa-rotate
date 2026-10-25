"""Real local sockets prove both proxy hops; no network or account requests."""
import base64
import contextlib
import socket
import ssl
import threading
from urllib.parse import unquote, urlsplit

import pytest
from app.proxy_transport import TaskProxyTransport, receive_exact
from app.adapter import PrivacyFlow
from config import Config


def header(connection):
    value = b""
    while not value.endswith(b"\r\n\r\n"):
        value += receive_exact(connection, 1)
    return value.decode()


class ProxyFixture:
    def __init__(self, front, final, tls_error=False):
        self.front, self.final, self.tls_error = front, final, tls_error
        self.events, self.errors, self.connections, self.handlers = [], [], [], []
        self.stop = threading.Event()

    def __enter__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(8); self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True); self.thread.start()
        return self

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept(); connection.settimeout(5)
                self.connections.append(connection)
                thread = threading.Thread(target=self.handle, args=(connection,), daemon=True)
                self.handlers.append(thread); thread.start()
            except socket.timeout: continue
            except OSError: break

    def socks(self, connection, label):
        assert receive_exact(connection, 1) == b"\x05"
        methods = receive_exact(connection, receive_exact(connection, 1)[0])
        assert 2 in methods
        connection.sendall(b"\x05"); connection.sendall(b"\x02")
        assert receive_exact(connection, 1) == b"\x01"
        user = receive_exact(connection, receive_exact(connection, 1)[0])
        password = receive_exact(connection, receive_exact(connection, 1)[0])
        self.events.append((label + "-auth", (user, password)))
        connection.sendall(b"\x01\x00")
        request = receive_exact(connection, 4)
        assert request[:3] == b"\x05\x01\x00"
        if request[3] == 1: address = socket.inet_ntop(socket.AF_INET, receive_exact(connection, 4))
        elif request[3] == 4: address = socket.inet_ntop(socket.AF_INET6, receive_exact(connection, 16))
        else: address = receive_exact(connection, receive_exact(connection, 1)[0]).decode()
        port = int.from_bytes(receive_exact(connection, 2), "big")
        self.events.append((label + "-connect", (address, port)))
        connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")

    def handle(self, connection):
        try:
            with connection:
                if self.front.startswith("socks"):
                    self.socks(connection, "front")
                else:
                    value = header(connection); self.events.append(("front-http", value))
                    assert value.startswith("CONNECT 8.8.8.8:3010 HTTP/1.1")
                    token = base64.b64encode(b"front-user:front-pass").decode()
                    assert f"Proxy-Authorization: Basic {token}" in value
                    connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if self.tls_error:
                    connection.sendall(b"HTTP/1.1 400 TLS required\r\nContent-Length: 0\r\n\r\n")
                    return
                if self.final.startswith("socks"):
                    self.socks(connection, "pool")
                value = header(connection); self.events.append(("pool-http", value))
                assert "front-user" not in value
                if not self.final.startswith("socks"):
                    token = base64.b64encode(b"pool-user:pool-pass").decode()
                    assert f"Proxy-Authorization: Basic {token}" in value
                body = b'{"fixture":true}'
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        except (OSError, AssertionError) as error:
            if not self.stop.is_set(): self.errors.append(type(error).__name__)

    def __exit__(self, *args):
        self.stop.set(); self.listener.close()
        for connection in self.connections:
            with contextlib.suppress(OSError): connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        self.thread.join(1)
        for handler in self.handlers: handler.join(1)


@pytest.mark.parametrize("front_scheme", ["http", "https", "socks5", "socks5h"])
@pytest.mark.parametrize("pool_scheme", ["http", "https", "socks5", "socks5h"])
def test_front_and_pool_protocols_keep_selected_final_exit(front_scheme, pool_scheme, monkeypatch):
    tls_hosts = []
    # Transport semantics use transparent fixture TLS; the certificate failure
    # test below exercises the real SSL context with verification enabled.
    def tls(self, connection, hostname, owned): tls_hosts.append(hostname); return connection
    monkeypatch.setattr(TaskProxyTransport, "tls", tls)
    with ProxyFixture(front_scheme, pool_scheme) as fixture:
        route = {"mode": "pool", "proxy_url": f"{pool_scheme}://pool-user:pool-pass@gateway.example:3010",
                 "pre_proxy": f"{front_scheme}://front-user:front-pass@127.0.0.1:{fixture.port}",
                 "resolve": ["gateway.example:3010:8.8.8.8"]}
        transport = TaskProxyTransport(route)
        with transport as prepared:
            assert route["proxy_url"].endswith("@gateway.example:3010")
            assert "pre_proxy" not in prepared
            parsed = urlsplit(prepared["proxy_url"])
            assert parsed.hostname == "127.0.0.1" and unquote(parsed.username) == "pool-user"
            assert parsed.scheme == ("http" if pool_scheme == "https" else pool_scheme)
            flow = PrivacyFlow(Config(proxy=prepared["proxy_url"], pre_proxy="off", proxy_resolve=tuple(prepared["resolve"])))
            try:
                # Read raw fixture HTTP through the wrapped client's transport,
                # without weakening the application's HTTPS origin guard.
                for _ in range(2):
                    response = flow.session.wrapped.get("http://127.0.0.2/fixture", timeout=5)
                    assert response.status_code == 200 and response.json() == {"fixture": True}
            finally: flow.session.close()
        assert transport.stop.is_set() and not transport.sockets and not transport.thread.is_alive()
        assert len([event for event in fixture.events if event[0] == "pool-http"]) == 2
        if front_scheme.startswith("socks"):
            assert ("front-connect", ("8.8.8.8", 3010)) in fixture.events
            assert ("front-auth", (b"front-user", b"front-pass")) in fixture.events
        if pool_scheme.startswith("socks"):
            assert ("pool-auth", (b"pool-user", b"pool-pass")) in fixture.events
        assert tls_hosts.count("gateway.example") == (2 if pool_scheme == "https" else 0)
        assert tls_hosts.count("127.0.0.1") == (2 if front_scheme == "https" else 0)
        assert not fixture.errors


def test_bad_https_pool_tls_fails_without_cleartext_fallback(monkeypatch):
    contexts = []
    original = ssl.create_default_context
    def context():
        result = original(); contexts.append(result); return result
    monkeypatch.setattr(ssl, "create_default_context", context)
    with ProxyFixture("http", "https", tls_error=True) as fixture:
        with TaskProxyTransport({"proxy_url": "https://pool-user:pool-pass@gateway.example:3010",
            "pre_proxy": f"http://front-user:front-pass@127.0.0.1:{fixture.port}",
            "resolve": ["gateway.example:3010:8.8.8.8"]}) as prepared:
            flow = PrivacyFlow(Config(proxy=prepared["proxy_url"], pre_proxy="off"))
            try:
                with pytest.raises(Exception): flow.session.wrapped.get("http://127.0.0.2/fixture", timeout=5)
            finally: flow.session.close()
        assert contexts and all(item.check_hostname and item.verify_mode == ssl.CERT_REQUIRED for item in contexts)
        assert not [event for event in fixture.events if event[0] == "pool-http"]


def test_no_front_keeps_route_unchanged_and_starts_no_listener():
    route = {"mode": "pool", "proxy_url": "socks5://pool-user:pool-pass@gateway.example:3010", "resolve": []}
    transport = TaskProxyTransport(route)
    with transport as prepared: assert prepared == route and transport.listener is None


def test_worker_closes_its_bridge_and_clears_payload(monkeypatch, capsys):
    import io
    import json
    from app import worker, adapter, proxy_pool, proxy_transport
    events = []
    async def prepared(route): return {"mode": "pool", "proxy_url": "socks5://fixture", "pre_proxy": "http://fixture"}
    class Bridge:
        def __init__(self, route): self.route = route
        def __enter__(self): events.append("bridge-start"); return {"mode": "pool", "proxy_url": "socks5://127.0.0.1:1"}
        def close(self): events.append("bridge-close")
    class Adapter:
        def __init__(self, **kwargs):
            assert kwargs["network_route"]["proxy_url"] == "socks5://127.0.0.1:1"
            events.append("adapter-start")
    def run(adapter, credentials, *args):
        events.append("run"); assert "network" not in credentials
    monkeypatch.setenv("MFA_MODE", "live")
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(json.dumps({"action": "rotate", "network": {"mode": "pool"}}) + "\n"))
    monkeypatch.setattr(proxy_pool, "prepare_route", prepared)
    monkeypatch.setattr(proxy_transport, "TaskProxyTransport", Bridge)
    monkeypatch.setattr(adapter, "ProtocolAdapter", Adapter)
    monkeypatch.setattr(worker, "rotate", run)
    worker.main()
    assert events == ["bridge-start", "adapter-start", "run", "bridge-close"]
