"""Offline baseline only: initialized protocol contexts, no login or account mutation."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CHILD = """
import json, os, sys, time
started = time.process_time()
from app.adapter import PrivacyFlow
from config import Config
flow = PrivacyFlow(Config())
context = flow._ensure_registration_context()
print(json.dumps({'pid': os.getpid(), 'device': context.device_id, 'context': context.context_id,
                  'startup_cpu_seconds': time.process_time()-started}), flush=True)
sys.stdin.readline()
flow.session.close()
"""


def rss(pid):
    if os.name != "nt":
        status = Path(f"/proc/{pid}/status").read_text()
        return int(next(line.split()[1] for line in status.splitlines() if line.startswith("VmRSS:"))) * 1024
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
            "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    handle = kernel.OpenProcess(0x410, False, pid)
    if not handle: raise OSError("Cannot read worker memory")
    try:
        counters = Counters(); counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise OSError("Cannot read worker memory")
        return counters.WorkingSetSize
    finally:
        kernel.CloseHandle(handle)


def measure(count):
    processes = []
    records = []
    started = time.monotonic()
    try:
        for _ in range(count):
            processes.append(subprocess.Popen([sys.executable, "-B", "-c", CHILD], cwd=ROOT,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        for process in processes:
            record = json.loads(process.stdout.readline())
            records.append(record)
        elapsed = time.monotonic() - started
        memory = [sum(rss(pid) for pid in {p.pid, r["pid"]}) / 1024**2 for p, r in zip(processes, records)]
        assert len({r["device"] for r in records}) == count
        assert len({r["context"] for r in records}) == count
        return {"workers": count, "rss_total_mib": round(sum(memory), 1), "rss_median_mib": round(statistics.median(memory), 1),
                "rss_max_mib": round(max(memory), 1), "startup_seconds": round(elapsed, 2),
                "startup_cpu_seconds_total": round(sum(r["startup_cpu_seconds"] for r in records), 2),
                "unique_devices": count, "unique_contexts": count, "network_requests": 0}
    finally:
        for process in processes:
            try:
                process.communicate("exit\n", timeout=15)
            except (subprocess.TimeoutExpired, OSError):
                process.kill(); process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", nargs="+", type=int, default=[1, 10])
    args = parser.parse_args()
    if any(not 1 <= value <= 10 for value in args.workers): parser.error("Use 1 to 10 workers")
    print(json.dumps({"platform": sys.platform, "scope": "offline protocol initialization, not live login peak",
                      "results": [measure(count) for count in args.workers]}, indent=2))
