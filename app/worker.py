"""One process per job. Credentials travel over pipes, never argv or disk."""
import json
import os
import queue
import sys
import threading
import asyncio
from .core import DemoAdapter, rotate, verify_only


def main():
    payload = json.loads(sys.stdin.readline())
    replies = queue.Queue()
    stop = threading.Event()

    def reader():
        for line in sys.stdin:
            try:
                command = json.loads(line)
                if command.get("type") == "cancel":
                    stop.set()
                elif command.get("type") == "receipt":
                    replies.put(command.get("receipt"))
            except Exception:
                pass
    threading.Thread(target=reader, daemon=True).start()

    def emit(event):
        sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def wait_receipt(token):
        try:
            return replies.get(timeout=180) == token
        except queue.Empty:
            return False

    if os.getenv("MFA_MODE") == "demo":
        adapter = DemoAdapter()
        transport = None
    else:
        from .adapter import ProtocolAdapter
        from .proxy_pool import prepare_route, ProxyError
        try:
            route = asyncio.run(prepare_route(payload.pop("network", {"mode": "direct"})))
        except ProxyError as error:
            emit({"type": "done", "stage": "stopped", "state": payload.get("initial_state", "unchanged"), "code": error.code})
            payload.clear()
            return
        from .proxy_transport import TaskProxyTransport
        transport = TaskProxyTransport(route)
        try:
            adapter = ProtocolAdapter(cancelled=stop.is_set, network_route=transport.__enter__())
        except Exception:
            transport.close()
            raise
    try:
        if payload.get("action") == "verify":
            verify_only(adapter, payload, emit, stop.is_set)
        else:
            rotate(adapter, payload, emit, wait_receipt, stop.is_set)
    finally:
        payload.clear()
        if transport is not None:
            transport.close()


if __name__ == "__main__":
    main()
