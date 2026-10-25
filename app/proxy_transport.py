"""Task-scoped TCP relay: existing system proxy -> selected pool proxy.

Only the proxy gateway connection passes through this relay. Cookie jars and TLS
to the account service remain in the original per-task curl sessions.
"""
import base64
import ipaddress
import select
import socket
import ssl
import threading
from urllib.parse import unquote, urlsplit, urlunsplit


def receive_exact(connection, size):
    result = b""
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise OSError("proxy_connection_closed")
        result += part
    return result


class TaskProxyTransport:
    def __init__(self, route):
        self.route = dict(route)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sockets = set()
        self.listener = None
        self.thread = None

    def __enter__(self):
        if not self.route.get("pre_proxy"):
            return self.route
        self.front = urlsplit(self.route["pre_proxy"])
        self.target = urlsplit(self.route["proxy_url"])
        self.destination = self.target.hostname
        self.destination_port = self.target.port
        # Use the validated gateway address, preventing a later DNS rebind.
        gateway_prefix = f"{self.target.hostname}:{self.target.port}:"
        pins = list(self.route.get("resolve", []))
        for pin in pins:
            if pin.startswith(gateway_prefix):
                addresses = pin[len(gateway_prefix):].split(",")
                self.destination = next((ip for ip in addresses if ":" not in ip), addresses[0]).strip("[]")
                break
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        port = self.listener.getsockname()[1]
        auth = self.target.netloc.rsplit("@", 1)[0] + "@" if "@" in self.target.netloc else ""
        # HTTPS proxy TLS is validated in the bridge with the original hostname.
        # The local leg uses HTTP; target-site HTTPS is still end-to-end curl TLS.
        scheme = "http" if self.target.scheme == "https" else self.target.scheme
        self.route["proxy_url"] = urlunsplit((scheme, f"{auth}127.0.0.1:{port}", "", "", ""))
        self.route["resolve"] = [pin for pin in pins if not pin.startswith(gateway_prefix)]
        self.route.pop("pre_proxy", None)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self.route

    def track(self, connection):
        with self.lock:
            if self.stop.is_set():
                connection.close()
                raise OSError("task_transport_closed")
            self.sockets.add(connection)
        return connection

    def tls(self, connection, hostname, owned):
        context = ssl.create_default_context()
        secured = context.wrap_socket(connection, server_hostname=hostname, do_handshake_on_connect=False)
        owned.append(secured)
        with self.lock:
            self.sockets.discard(connection)
        self.track(secured)
        secured.do_handshake()
        return secured

    def connect_front(self, owned):
        front = self.front
        port = front.port or (443 if front.scheme == "https" else 1080 if front.scheme.startswith("socks") else 80)
        connection = self.track(socket.create_connection((front.hostname, port), timeout=10))
        owned.append(connection)
        if front.scheme == "https":
            connection = self.tls(connection, front.hostname, owned)
        host = f"[{self.destination}]" if ":" in self.destination else self.destination
        if front.scheme in ("http", "https"):
            auth = ""
            if front.username:
                value = unquote(front.username) + ":" + unquote(front.password or "")
                auth = "Proxy-Authorization: Basic " + base64.b64encode(value.encode()).decode() + "\r\n"
            authority = f"{host}:{self.destination_port}"
            connection.sendall((f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}\r\n").encode())
            header = b""
            while not header.endswith(b"\r\n\r\n"):
                if len(header) >= 16384:
                    raise OSError("system_proxy_header_too_large")
                header += receive_exact(connection, 1)
            status = header.split(b"\r\n", 1)[0].split(b" ")
            if len(status) < 2 or status[1] != b"200":
                raise OSError("system_proxy_connect_rejected")
        elif front.scheme in ("socks5", "socks5h"):
            connection.sendall(b"\x05\x02\x00\x02" if front.username else b"\x05\x01\x00")
            version, method = receive_exact(connection, 2)
            if version != 5 or method not in (0, 2):
                raise OSError("system_proxy_handshake_failed")
            if method == 2:
                user, password = unquote(front.username or "").encode(), unquote(front.password or "").encode()
                if not 0 < len(user) <= 255 or len(password) > 255:
                    raise OSError("system_proxy_auth_invalid")
                connection.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
                if receive_exact(connection, 2) != b"\x01\x00":
                    raise OSError("system_proxy_auth_failed")
            address = ipaddress.ip_address(self.destination)
            connection.sendall(b"\x05\x01\x00" + bytes([1 if address.version == 4 else 4]) + address.packed + int(self.destination_port).to_bytes(2, "big"))
            response = receive_exact(connection, 4)
            if response[0] != 5 or response[1] != 0:
                raise OSError("system_proxy_connect_rejected")
            if response[3] == 1: receive_exact(connection, 4)
            elif response[3] == 4: receive_exact(connection, 16)
            elif response[3] == 3: receive_exact(connection, receive_exact(connection, 1)[0])
            else: raise OSError("system_proxy_response_invalid")
            receive_exact(connection, 2)
        else:
            raise OSError("system_proxy_scheme_invalid")
        if self.target.scheme == "https":
            connection = self.tls(connection, self.target.hostname, owned)
        return connection

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
                self.track(connection)
                threading.Thread(target=self.relay, args=(connection,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def relay(self, client):
        upstream = None
        owned = []
        try:
            upstream = self.connect_front(owned)
            while not self.stop.is_set():
                pending = isinstance(upstream, ssl.SSLSocket) and upstream.pending() > 0
                readable, _, _ = select.select([client, upstream], [], [], 0 if pending else 1)
                if pending and upstream not in readable:
                    readable.append(upstream)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, ValueError):
            pass  # curl receives a network failure; never print proxy credentials.
        finally:
            for connection in (client, *owned):
                if connection is not None:
                    with self.lock:
                        self.sockets.discard(connection)
                    connection.close()

    def close(self):
        self.stop.set()
        if self.listener is not None:
            self.listener.close()
        with self.lock:
            connections = list(self.sockets)
            self.sockets.clear()
        for connection in connections:
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            connection.close()
        if self.thread:
            self.thread.join(timeout=1)

    def __exit__(self, *args):
        self.close()
