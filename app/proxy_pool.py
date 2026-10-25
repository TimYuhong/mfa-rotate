"""Session-owned, memory-only proxy pools. No credentials in public snapshots."""
import asyncio
import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit, urlencode

from curl_cffi.requests import AsyncSession

SCHEMES = {"http", "https", "socks5", "socks5h"}
FAKE_RANGES = (ipaddress.ip_network("198.18.0.0/15"), ipaddress.ip_network("2001:2::/48"))
TARGET_HOSTS = ("chatgpt.com", "auth.openai.com", "sentinel.openai.com")
_TARGET_PIN_CACHE = {}  # Public DNS only; never sessions, cookies or credentials.


def fake_ip(value):
    address = ipaddress.ip_address(value)
    return any(address.version == network.version and address in network for network in FAKE_RANGES)


class ProxyError(Exception):
    def __init__(self, code, line=None):
        self.code, self.line = code, line
        super().__init__(code)


def allowed_ip(value, local):
    address = ipaddress.ip_address(value.split("%", 1)[0])
    # IPv4-mapped IPv6 must satisfy the underlying IPv4 policy too.
    if getattr(address, "ipv4_mapped", None):
        address = address.ipv4_mapped
    public = address.is_global and not (address.is_multicast or address.is_reserved or address.is_unspecified or address.is_link_local or address.is_loopback)
    return public or (local and address.is_loopback)


@dataclass
class ProxyEntry:
    id: str
    endpoint: str
    url: str = field(repr=False)
    host: str
    port: int
    key: str = field(repr=False)


def parse_proxy(value, key, index, local):
    try:
        if not value or len(value) > 2048 or re.search(r"[\x00-\x20\x7f]", value):
            raise ValueError()
        text = value if "://" in value else "socks5://" + value
        # Also accept provider-style scheme://host:port:user:pass.
        scheme, rest = text.split("://", 1)
        if "@" not in rest and not rest.startswith("[") and rest.count(":") >= 3:
            host, port, user, password = rest.split(":", 3)
            text = f"{scheme}://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
        parsed = urlsplit(text)
        if parsed.scheme not in SCHEMES or not parsed.hostname or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError()
        host = parsed.hostname.rstrip(".").encode("idna").decode().lower()
        if "%" in host or len(host) > 253:
            raise ValueError()
        port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else 1080)
        if not 1 <= port <= 65535:
            raise ValueError()
        user, password = unquote(parsed.username or ""), unquote(parsed.password or "")
        if any(re.search(r"[\x00-\x1f\x7f]", item) for item in (user, password)) or bool(user) != (parsed.password is not None):
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
                raise ValueError()
        else:
            if not allowed_ip(host, local):
                raise ProxyError("proxy_address_blocked", index)
        hostname = f"[{host}]" if ":" in host else host
        auth = f"{quote(user, safe='')}:{quote(password, safe='')}@" if user else ""
        url = f"{parsed.scheme}://{auth}{hostname}:{port}"
        digest = hmac.new(key, url.encode(), hashlib.sha256).hexdigest()
        return ProxyEntry(str(index), f"{parsed.scheme}://{hostname}:{port}", url, host, port, digest)
    except ProxyError:
        raise
    except (ValueError, UnicodeError):
        raise ProxyError("proxy_invalid", index) from None


async def resolve_proxy(entry, local, dns_proxy=None):
    try:
        literal = ipaddress.ip_address(entry.host)
    except ValueError:
        if dns_proxy and entry.host != "localhost":
            ips = await resolve_public_dns(entry.host, dns_proxy)
        else:
            try:
                addresses = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, entry.host, entry.port, 0, socket.SOCK_STREAM), timeout=8)
            except (OSError, asyncio.TimeoutError):
                raise ProxyError("proxy_dns_failed") from None
            ips = sorted({item[4][0] for item in addresses})
        # Desktop TUN clients use benchmark ranges for fake DNS. Resolve those
        # names through a fixed HTTPS resolver; never accept the virtual address
        # as a proxy endpoint or relax the production/private-address policy.
        if local and ips and all(fake_ip(ip) for ip in ips):
            ips = await resolve_public_dns(entry.host, dns_proxy) if dns_proxy else await resolve_public_dns(entry.host)
        if not ips or any(not allowed_ip(ip, local) for ip in ips):
            raise ProxyError("proxy_address_blocked")
        encoded = ",".join(f"[{ip}]" if ":" in ip else ip for ip in ips)
        return [f"{entry.host}:{entry.port}:{encoded}"]
    else:
        if not allowed_ip(str(literal), local):
            raise ProxyError("proxy_address_blocked")
        return []


async def resolve_public_dns(host, proxy=None):
    try:
        ips = set()
        async with AsyncSession(proxy=proxy or "", trust_env=False) as session:
            for record_type in ("A", "AAAA"):
                url = "https://cloudflare-dns.com/dns-query?" + urlencode({"name": host, "type": record_type})
                response = await session.get(url, headers={"Accept": "application/dns-json"}, timeout=8, allow_redirects=False)
                if response.status_code != 200:
                    raise ValueError()
                data = response.json()
                if data.get("Status") != 0:
                    raise ValueError()
                for answer in data.get("Answer", []):
                    if answer.get("type") in (1, 28):
                        ips.add(str(ipaddress.ip_address(answer["data"])))
        if not ips:
            raise ValueError()
        return sorted(ips)
    except Exception:
        raise ProxyError("proxy_dns_failed") from None


async def target_pins(local, scheme, dns_proxy=None, hosts=TARGET_HOSTS):
    # SOCKS5 resolves destinations on the client. A desktop TUN fake IP must
    # never be forwarded to the remote gateway as the real destination address.
    if not local or scheme != "socks5":
        return []
    pins = []
    for host in hosts:
        cache_key = (host, dns_proxy)
        cached = _TARGET_PIN_CACHE.get(cache_key)
        if cached and cached[0] > time.monotonic():
            pins.append(cached[1])
            continue
        try:
            if dns_proxy:
                ips = await resolve_public_dns(host, dns_proxy)
            else:
                answers = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, 443, 0, socket.SOCK_STREAM), timeout=8)
                ips = sorted({answer[4][0] for answer in answers})
            if ips and any(fake_ip(ip) for ip in ips):
                ips = await resolve_public_dns(host, dns_proxy) if dns_proxy else await resolve_public_dns(host)
            if not ips or any(not allowed_ip(ip, False) for ip in ips):
                raise ProxyError("proxy_dns_failed")
            # Residential SOCKS gateways commonly provide IPv4 egress only.
            # Keep IPv6-only destinations supported, but prefer A records when both exist.
            ipv4 = [ip for ip in ips if ipaddress.ip_address(ip).version == 4]
            ips = ipv4 or ips
            encoded = ",".join(f"[{ip}]" if ":" in ip else ip for ip in ips)
            pin = f"{host}:443:{encoded}"
            _TARGET_PIN_CACHE[cache_key] = (time.monotonic() + 60, pin)
            pins.append(pin)
        except (OSError, asyncio.TimeoutError):
            raise ProxyError("proxy_dns_failed") from None
    return pins


def windows_system_proxy():
    """Read the user's existing Windows Internet proxy without changing settings."""
    if sys.platform != "win32":
        return None
    from urllib.request import getproxies_registry
    proxies = getproxies_registry()
    return proxies.get("https") or proxies.get("http") or proxies.get("socks")


async def prepare_route(route, target_hosts=TARGET_HOSTS):
    """Resolve the assigned proxy only when its task starts; no connectivity probes."""
    local = route.get("local") is True
    mode = route.get("mode", "direct")
    system_proxy = windows_system_proxy() if local else None
    if mode != "pool":
        proxy_url = system_proxy
        if not proxy_url:
            return {"mode": "direct"}
    else:
        proxy_url = route["proxy_url"]
    entry = parse_proxy(proxy_url, b"task-route", 1, local)
    front = parse_proxy(system_proxy, b"system-route", 1, True).url if mode == "pool" and system_proxy else None
    pins = await resolve_proxy(entry, local, front) if front else await resolve_proxy(entry, local)
    if target_hosts == TARGET_HOSTS:
        pins += await target_pins(local, urlsplit(entry.url).scheme, front) if front else await target_pins(local, urlsplit(entry.url).scheme)
    else:
        pins += await target_pins(local, urlsplit(entry.url).scheme, front, target_hosts)
    prepared = {"mode": mode, "proxy_url": entry.url, "resolve": pins}
    if front:
        prepared["pre_proxy"] = front
    return prepared


@dataclass
class Pool:
    version: str
    entries: list


class ProxyPools:
    def __init__(self, key):
        self.key = key
        self.pools = {}
        self.leases = {}
        self.locks = {}

    def lock(self, owner):
        return self.locks.setdefault(owner, asyncio.Lock())

    def snapshot(self, owner):
        pool = self.pools.get(owner)
        entries = [] if not pool else [{"id": e.id, "endpoint": e.endpoint} for e in pool.entries]
        return {"version": pool.version if pool else "", "entries": entries, "count": len(entries)}

    async def replace(self, owner, values, local):
        entries, seen = [], set()
        for index, value in enumerate(values, 1):
            entry = parse_proxy(value, self.key, index, local)
            if entry.key not in seen:
                seen.add(entry.key)
                entry.id = str(len(entries) + 1)
                entries.append(entry)
        if not entries or len(entries) > 50:
            raise ProxyError("proxy_invalid")
        previous = self.pools.get(owner)
        if previous and [e.key for e in previous.entries] == [e.key for e in entries]:
            return self.snapshot(owner)
        self.pools[owner] = Pool(secrets.token_urlsafe(24), entries)
        return self.snapshot(owner)

    def require(self, owner, version):
        pool = self.pools.get(owner)
        if not pool:
            raise ProxyError("proxy_required")
        if not version or not hmac.compare_digest(pool.version, version):
            raise ProxyError("proxy_pool_changed")
        return pool

    def acquire(self, owner, version, job_id):
        pool = self.require(owner, version)
        unused = [entry for entry in pool.entries if not self.leases.get(entry.key)]
        entry = secrets.choice(unused or pool.entries)
        self.leases.setdefault(entry.key, set()).add(job_id)
        return entry.key, {"mode": "pool", "proxy_url": entry.url}

    def release(self, key, token):
        users = self.leases.get(key)
        if users:
            users.discard(token)
            if not users:
                del self.leases[key]

    async def remove(self, owner):
        self.pools.pop(owner, None)

    def prune(self, owners):
        for owner in list(self.pools):
            if owner not in owners:
                self.pools.pop(owner)
                self.locks.pop(owner, None)

    async def close(self):
        self.pools.clear()
        self.leases.clear()
        self.locks.clear()
