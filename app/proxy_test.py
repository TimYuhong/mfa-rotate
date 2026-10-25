"""One explicitly requested anonymous proxy test. Credentials arrive over stdin."""
import asyncio
import ipaddress
import json
import logging
import re
import sys
import time

from curl_cffi import CurlOpt
from curl_cffi.requests import Session
from .proxy_pool import ProxyError, prepare_route
from .proxy_transport import TaskProxyTransport

TRACE_HOST = "www.cloudflare.com"
TEST_MESSAGES = {
    "proxy_test_timeout": "连接超时",
    "proxy_dns_failed": "代理或目标域名无法解析",
    "proxy_address_blocked": "代理地址不允许",
    "proxy_invalid": "代理格式不正确",
    "proxy_test_auth": "代理认证失败",
    "proxy_test_tls": "TLS 握手或证书校验失败",
    "proxy_test_response": "出口信息返回异常",
    "proxy_test_failed": "代理连接未完成",
}


def failed(code):
    code = code if code in TEST_MESSAGES else "proxy_test_failed"
    return {"ok": False, "code": code, "message": TEST_MESSAGES[code]}


def safe_result(value):
    """Whitelist the child output; never return arbitrary exception text."""
    try:
        if value.get("ok") is not True:
            return failed(value.get("code"))
        ip = str(ipaddress.ip_address(value["ip"]))
        country, latency = value["country"], value["latency_ms"]
        if not re.fullmatch(r"[A-Z]{2}", country) or type(latency) is not int or not 0 <= latency <= 30000:
            raise ValueError()
        return {"ok": True, "country": country, "ip": ip, "latency_ms": latency}
    except (KeyError, ValueError, TypeError, AttributeError):
        return failed("proxy_test_response")


def probe_connection(route):
    try:
        prepared = asyncio.run(prepare_route(route, target_hosts=(TRACE_HOST,)))
        with TaskProxyTransport(prepared) as transport:
            options = {CurlOpt.RESOLVE: [value.encode() for value in transport.get("resolve", [])]}
            with Session(proxy=transport["proxy_url"], impersonate="safari18_0", trust_env=False, curl_options=options) as session:
                started = time.perf_counter()
                response = session.get(f"https://{TRACE_HOST}/cdn-cgi/trace", timeout=12, allow_redirects=False)
                elapsed = round((time.perf_counter() - started) * 1000)
                if response.status_code != 200 or len(response.content) > 16384:
                    return failed("proxy_test_response")
                fields = dict(line.split("=", 1) for line in response.text.splitlines() if "=" in line)
                return safe_result({"ok": True, "ip": fields.get("ip"), "country": fields.get("loc"), "latency_ms": elapsed})
    except ProxyError as error:
        return failed(error.code)
    except Exception as error:
        code = getattr(error, "code", None)
        if code == 28 or isinstance(error, TimeoutError): return failed("proxy_test_timeout")
        if code in (35, 60): return failed("proxy_test_tls")
        if code == 67: return failed("proxy_test_auth")
        return failed("proxy_test_failed")


def main():
    logging.disable(logging.CRITICAL)
    payload = json.loads(sys.stdin.readline())
    try:
        result = probe_connection(payload)
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    finally:
        payload.clear()


if __name__ == "__main__":
    main()
