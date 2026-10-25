"""
HTTP 客户端 - 使用 curl_cffi 实现 TLS 指纹模拟
支持 Cloudflare 绕过，降级到 requests
"""
import logging
import select
import socket
import threading
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)
_TUNNELS: dict[tuple[str, str], str] = {}
_TUNNELS_LOCK = threading.Lock()

# 尝试使用 curl_cffi（推荐，自带 TLS 指纹模拟）
try:
    from curl_cffi import CurlOpt
    from curl_cffi.requests import Session as CffiSession

    _HAS_CFFI = True
    logger.debug("curl_cffi 可用，使用 TLS 指纹模拟")
except ImportError:
    _HAS_CFFI = False
    logger.debug("curl_cffi 不可用，降级到 requests")

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 通用 UA（fallback，优先使用 fingerprint.generate_fingerprint() 生成的值）
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
)


def _has_scheme(value: str) -> bool:
    return "://" in value


def normalize_proxy_url(proxy: Optional[str], default_scheme: str = "http") -> Optional[str]:
    """Normalize a main proxy URL; scheme-less input defaults to HTTP."""
    value = (proxy or "").strip()
    if not value or value.lower() in {"off", "none", "0", "false", "no"}:
        return None
    if _has_scheme(value):
        return value
    scheme = str(default_scheme or "http").strip().lower() or "http"
    return f"{scheme}://{value}"


def _is_local_proxy(value: str) -> bool:
    v = (value or "").lower()
    return (
        "127.0.0.1" in v
        or "localhost" in v
        or "[::1]" in v
    )


def _tcp_open(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _socks5_probe(host: str, port: int, timeout: float = 0.6) -> bool:
    """真实探测端口是否会说 SOCKS5：发 no-auth 握手，等 0x05 0x00 应答。

    只测 TCP 能连会把 Clash 的 HTTP 端口（如 7890）或其它服务误判成 SOCKS5，
    导致 libcurl 报 `curl: (97) Received invalid version in initial SOCKS5
    response`。需要认证的服务器回 0x05 0x02，同样不算可用（本机前置无凭据）。
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            return s.recv(2) == b"\x05\x00"
    except OSError:
        return False


def _normalize_pre_proxy(pre_proxy: Optional[str], proxy: Optional[str]) -> Optional[str]:
    pre = (pre_proxy or "").strip()
    if pre.lower() in {"off", "none", "0", "false", "no"}:
        return None
    if pre:
        return pre if _has_scheme(pre) else f"socks5://{pre}"

    # If a remote proxy is configured, an empty pre_proxy means "use local
    # desktop proxy if present" for Clash/Clash Verge style setups.
    if not proxy or _is_local_proxy(proxy):
        return None
    for port in (7897, 7890, 7891, 1080):
        # 必须真实通过 SOCKS5 握手才算数；否则把 HTTP 端口当 SOCKS5 用
        # 会在 libcurl 侧报 curl (97) invalid version in SOCKS5 response。
        if _socks5_probe("127.0.0.1", port):
            return f"socks5://127.0.0.1:{port}"
    return None


def _socks5_connect(
    proxy_url: str, dst_host: str, dst_port: int, timeout: float = 10.0,
) -> socket.socket:
    u = urlsplit(proxy_url)
    if u.scheme.lower() not in {"socks5", "socks5h"}:
        raise RuntimeError(f"pre_proxy only supports socks5 for SOCKS chaining: {u.scheme}")
    s = socket.create_connection(
        (u.hostname or "127.0.0.1", u.port or 1080), timeout=float(timeout),
    )
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if resp != b"\x05\x00":
        s.close()
        raise RuntimeError(f"local SOCKS5 pre_proxy handshake failed: {resp!r}")
    host_b = dst_host.encode("idna")
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + int(dst_port).to_bytes(2, "big")
    s.sendall(req)
    head = s.recv(4)
    if len(head) < 4 or head[1] != 0:
        s.close()
        raise RuntimeError(f"local SOCKS5 pre_proxy connect failed: {head!r}")
    atyp = head[3]
    if atyp == 1:
        s.recv(4)
    elif atyp == 3:
        n = s.recv(1)[0]
        s.recv(n)
    elif atyp == 4:
        s.recv(16)
    s.recv(2)
    return s


def _pipe(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 60)
            if not readable:
                return
            for src in readable:
                data = src.recv(65536)
                if not data:
                    return
                (b if src is a else a).sendall(data)
    finally:
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass


def _start_tcp_tunnel(remote_host: str, remote_port: int, pre_proxy: str) -> str:
    key = (f"{remote_host}:{remote_port}", pre_proxy)
    with _TUNNELS_LOCK:
        if key in _TUNNELS:
            return _TUNNELS[key]
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        local_port = listener.getsockname()[1]

        def _serve() -> None:
            while True:
                try:
                    client, _addr = listener.accept()
                    upstream = _socks5_connect(pre_proxy, remote_host, remote_port)
                    threading.Thread(target=_pipe, args=(client, upstream), daemon=True).start()
                except Exception as e:
                    logger.warning("SOCKS chain tunnel accept/connect failed: %s", e)

        threading.Thread(target=_serve, daemon=True).start()
        tunnel = f"127.0.0.1:{local_port}"
        _TUNNELS[key] = tunnel
        logger.info("SOCKS 链式隧道已启动: %s -> %s via %s", tunnel, key[0], pre_proxy)
        return tunnel


def _chain_socks_proxy(proxy: str, pre_proxy: Optional[str]) -> tuple[str, Optional[str]]:
    if not proxy or not pre_proxy:
        return proxy, pre_proxy
    u = urlsplit(proxy)
    if u.scheme.lower() not in {"socks5", "socks5h"} or _is_local_proxy(proxy):
        return proxy, pre_proxy
    tunnel = _start_tcp_tunnel(u.hostname or "", u.port or 1080, pre_proxy)
    netloc = tunnel
    if u.username:
        auth = u.username
        if u.password:
            auth += f":{u.password}"
        netloc = f"{auth}@{tunnel}"
    # Use socks5h for the local tunnel so the final destination hostname is
    # sent to the upstream SOCKS server. Otherwise Clash fake-ip DNS
    # (198.18.0.0/15) may be resolved locally and forwarded upstream.
    chained = urlunsplit(("socks5h", netloc, "", "", ""))
    return chained, None


def create_http_session(
    proxy: Optional[str] = None,
    pre_proxy: Optional[str] = None,
    impersonate: str = "safari18_0",
    user_agent: Optional[str] = None,
    proxy_resolve: tuple[str, ...] = (),
):
    """
    创建 HTTP 会话。优先使用 curl_cffi 模拟浏览器 TLS 指纹，
    不可用时降级到 requests。
    """
    proxy = normalize_proxy_url(proxy, default_scheme="http")
    if _HAS_CFFI:
        pre_proxy = _normalize_pre_proxy(pre_proxy, proxy)
        if proxy and pre_proxy:
            proxy, pre_proxy = _chain_socks_proxy(proxy, pre_proxy)
        kwargs = {"impersonate": impersonate}
        curl_options = {}
        if proxy_resolve:
            curl_options[CurlOpt.RESOLVE] = [entry.encode() for entry in proxy_resolve]
        if pre_proxy:
            curl_options[CurlOpt.PRE_PROXY] = pre_proxy
            logger.info("前置代理已启用: %s", pre_proxy)
        if curl_options:
            kwargs["curl_options"] = curl_options
        session = CffiSession(**kwargs)
        # 使用显式配置，避免被系统 HTTP(S)_PROXY 隐式污染。
        session.trust_env = False
        if proxy:
            # Keep the user-provided proxy scheme exactly as-is. Some providers
            # advertise SOCKS5 but reject socks5h-style remote DNS handshakes.
            session.proxies = {"https": proxy, "http": proxy}
        else:
            # 显式设置空代理，覆盖系统环境变量 (trust_env=False 对 libcurl 不够)
            session.proxies = {"https": "", "http": ""}
        return session
    else:
        if proxy_resolve:
            raise RuntimeError("proxy_dns_pinning_unavailable")
        if pre_proxy:
            logger.warning("requests fallback 不支持前置代理，已忽略 pre_proxy")
        session = requests.Session()
        session.trust_env = False
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        if proxy:
            session.proxies = {"https": proxy, "http": proxy}
        session.headers["User-Agent"] = user_agent or USER_AGENT
        return session
