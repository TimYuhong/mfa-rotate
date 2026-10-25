"""Check the Git index before publishing; never print matched secret values."""
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
BLOCKED_PARTS = {"node_modules", ".venv", "__pycache__", "output", ".local-notes", ".auth"}
BLOCKED_FILES = {"DEPLOYMENT.md", "LOCAL-VERIFICATION.md", "FRONTEND-COMPONENTS.md", "scripts/import_core.py"}
PATTERNS = {
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "access token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{30,})"),
    "personal Windows path": re.compile(rb"\b[A-Za-z]:[\\/](?:Users|tools|Program Files|WorkSoftware)[\\/]", re.I),
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def main():
    paths = [value.decode("utf-8") for value in git("ls-files", "--cached", "-z").split(b"\0") if value]
    if not paths:
        raise SystemExit("No indexed files. Stage the intended public files first.")
    local_keys = []
    settings = ROOT / ".env"
    if settings.is_file():
        for line in settings.read_text(encoding="utf-8-sig").splitlines():
            name, separator, value = line.partition("=")
            if separator and name.strip() == "MFA_ACCESS_KEY" and len(value.strip()) >= 8:
                local_keys.append(value.strip().strip("\"'").encode())
    findings = []
    for name in paths:
        path = PurePosixPath(name)
        if (set(path.parts) & BLOCKED_PARTS or name in BLOCKED_FILES
                or name.startswith(".deploy-") or name.startswith("frontend/dist/")
                or (path.name == ".env" or path.suffix == ".env")
                or path.suffix.lower() in {".har", ".db", ".sqlite", ".sqlite3", ".key", ".pem", ".pfx", ".p12"}
                or name.endswith((".tar.gz", ".zip", ".tsbuildinfo"))):
            findings.append((name, "private/runtime artifact"))
            continue
        data = git("show", ":" + name)
        if any(key in data for key in local_keys):
            findings.append((name, "local service access key"))
        if b"\0" not in data:
            for label, pattern in PATTERNS.items():
                if pattern.search(data):
                    findings.append((name, label))
    if findings:
        for name, label in findings:
            print(f"FAIL {name}: {label}")
        raise SystemExit(1)
    print(f"PASS {len(paths)} indexed files; no blocked artifacts or detected credentials/paths.")
    print("This bounded check does not replace reviewing the staged diff.")


if __name__ == "__main__":
    main()
