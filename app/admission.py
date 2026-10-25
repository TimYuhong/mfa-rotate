"""Bounded FIFO session turns. Waiting accounts and credentials stay in browsers."""
from collections import OrderedDict
from dataclasses import dataclass
import secrets
import time


@dataclass(frozen=True)
class Lease:
    owner: str
    expires: float


class AdmissionQueue:
    def __init__(self, maximum_waiters=100, waiter_ttl=15, lease_ttl=10):
        self.maximum_waiters = maximum_waiters
        self.waiter_ttl = waiter_ttl
        self.lease_ttl = lease_ttl
        self.waiting = OrderedDict()
        self.leases = {}

    def cleanup(self, owners=None, now=None):
        now = time.monotonic() if now is None else now
        for owner, expires in list(self.waiting.items()):
            if expires <= now or (owners is not None and owner not in owners):
                del self.waiting[owner]
        for token, lease in list(self.leases.items()):
            if lease.expires <= now or (owners is not None and lease.owner not in owners):
                del self.leases[token]

    def request(self, owner, active, global_limit, session_limit, now=None):
        now = time.monotonic() if now is None else now
        self.cleanup(now=now)
        own = next((token for token, lease in self.leases.items() if lease.owner == owner), None)
        if own:
            return {"status": "ready", "token": own}
        if owner not in self.waiting and len(self.waiting) >= self.maximum_waiters:
            raise OverflowError("admission_queue_full")
        # Updating the heartbeat preserves the original position in OrderedDict.
        self.waiting[owner] = now + self.waiter_ttl
        used = sum(active.values()) + len(self.leases)
        for candidate in list(self.waiting):
            if used >= global_limit:
                break
            reserved = sum(lease.owner == candidate for lease in self.leases.values())
            if active.get(candidate, 0) + reserved >= session_limit:
                continue
            del self.waiting[candidate]
            token = secrets.token_urlsafe(24)
            self.leases[token] = Lease(candidate, now + self.lease_ttl)
            used += 1
        own = next((token for token, lease in self.leases.items() if lease.owner == owner), None)
        if own:
            return {"status": "ready", "token": own}
        return {"status": "queued", "position": list(self.waiting).index(owner) + 1, "retry_after_ms": 1500}

    def consume(self, token, owner, now=None):
        self.cleanup(now=now)
        lease = self.leases.get(token)
        if not lease or lease.owner != owner:
            return False
        del self.leases[token]
        return True

    def release(self, token, owner):
        lease = self.leases.get(token)
        if lease and lease.owner == owner:
            del self.leases[token]

