from app.admission import AdmissionQueue
import pytest


def test_full_server_queues_only_one_small_entry_per_session():
    queue = AdmissionQueue()
    active = {"active-a": 10, "active-b": 10, "active-c": 10}
    for index in range(100):
        result = queue.request(f"waiting-{index}", active, 30, 10, now=0)
        assert result["status"] == "queued" and result["position"] == index + 1
    for _ in range(50):
        assert queue.request("waiting-0", active, 30, 10, now=1)["position"] == 1
    assert len(queue.waiting) == 100 and not queue.leases
    with pytest.raises(OverflowError):
        queue.request("extra", active, 30, 10, now=1)
    queue.cleanup(now=17)
    assert not queue.waiting and not queue.leases


def test_fifo_turns_prevent_a_new_or_fast_session_from_jumping_the_queue():
    queue = AdmissionQueue()
    active = {"a": 10, "b": 10, "c": 10}
    queue.request("first", active, 30, 10, now=0)
    queue.request("second", active, 30, 10, now=0)
    active["a"] = 9
    assert queue.request("new", active, 30, 10, now=1)["status"] == "queued"
    first = queue.request("first", active, 30, 10, now=1)
    assert first["status"] == "ready"
    assert queue.request("first", active, 30, 10, now=1)["token"] == first["token"]
    assert len(queue.leases) == 1
    assert not queue.consume(first["token"], "second", now=1)
    assert queue.consume(first["token"], "first", now=1)
    active["first"] = 1
    active["b"] = 9
    assert queue.request("first", active, 30, 10, now=2)["status"] == "queued"
    second = queue.request("second", active, 30, 10, now=2)
    assert second["status"] == "ready"
    assert sum(active.values()) + len(queue.leases) == 30


def test_leases_expire_and_session_quota_counts_reserved_slots():
    queue = AdmissionQueue()
    lease = queue.request("a", {"a": 9}, 30, 10, now=0)
    assert lease["status"] == "ready"
    assert queue.request("a", {"a": 9}, 30, 10, now=1) == lease
    assert not queue.consume(lease["token"], "a", now=11)
    assert queue.request("a", {"a": 10}, 30, 10, now=12)["status"] == "queued"
    queue.cleanup(owners=set(), now=12)
    assert not queue.waiting and not queue.leases


def test_reserved_slots_are_part_of_the_global_budget():
    queue = AdmissionQueue()
    first = queue.request("a", {}, 1, 10, now=0)
    assert queue.request("b", {}, 1, 10, now=0)["status"] == "queued"
    queue.release(first["token"], "b")
    assert len(queue.leases) == 1
    queue.release(first["token"], "a")
    assert queue.request("a", {}, 1, 10, now=1)["status"] == "queued"
    assert queue.request("b", {}, 1, 10, now=1)["status"] == "ready"

