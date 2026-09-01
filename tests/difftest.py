"""Differential test: self-contained logrelay.py vs library reference.

Runs both implementations over identical inputs/flags through a local
receiver, normalizes timestamps, and byte-compares the resulting messages.
"""

import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv" / "Scripts" / "python.exe"
SC = ROOT / "logrelay.py"
LIB = ROOT / "tests" / "logrelay_library.py"

TS_RE = re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+([+-]\d{2}:\d{2}|Z)")


def normalize(data):
    return TS_RE.sub(b"<TS>", data)


class Receiver(threading.Thread):
    def __init__(self, proto, port):
        super().__init__(daemon=True)
        self.proto = proto
        self.port = port
        self.messages = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        if proto != "udp":
            self.sock.listen(5)
        self.done = threading.Event()

    def run(self):
        try:
            if self.proto == "udp":
                self.sock.settimeout(0.2)
                while not self.done.is_set():
                    try:
                        data, _ = self.sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    self.messages.append(data)
                return
            self.sock.settimeout(0.2)
            while not self.done.is_set():
                try:
                    conn, _ = self.sock.accept()
                except (socket.timeout, OSError):
                    if self.done.is_set():
                        return
                    continue
                buf = b""
                conn.settimeout(2)
                while True:
                    try:
                        chunk = conn.recv(65535)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    while True:
                        if buf[:1].isdigit():
                            sp = buf.find(b" ")
                            if sp == -1:
                                break
                            length = int(buf[:sp])
                            if len(buf) < sp + 1 + length:
                                break
                            self.messages.append(buf[sp + 1:sp + 1 + length])
                            buf = buf[sp + 1 + length:]
                        else:
                            nl = buf.find(b"\n")
                            if nl == -1:
                                break
                            self.messages.append(buf[:nl])
                            buf = buf[nl + 1:]
                conn.close()
        except OSError:
            pass  # socket closed by stop()

    def stop(self):
        self.done.set()
        self.sock.close()
        self.join(timeout=2)


INPUT = (
    "plain line one\n"
    "unicode: café ünïcode ✓ 日本語\n"
    "\n"
    "   leading spaces preserved\n"
    "quotes \"back\\\\slash\" and [brackets]\n"
    "tab\there\n"
    + "x" * 300 + "\n"
).encode("utf-8")

CASES = [
    # (label, extra args)
    ("udp-default", []),
    ("udp-utc", ["--utc"]),
    ("udp-full-header", ["--hostname", "diffhost", "--appname", "diffapp",
                         "--procid", "4242", "--msgid", "ID4711",
                         "--facility", "local0", "--priority", "warning"]),
    ("udp-sd", ["--sd", 'mydata@32473 iut="3" event="login"',
                "--sd", 'origin ip="1.2.3.4"']),
    ("udp-no-bom", ["--no-utf8-bom"]),
    ("udp-severity-num", ["--priority", "2", "--facility", "19"]),
    ("tcp-nt", ["--proto", "tcp"]),
    ("tcp-oc", ["--proto", "tcp", "--framing", "octet-counting"]),
    ("tcp-nt-sd", ["--proto", "tcp", "--sd", 'meta sequence="9"']),
]


def run_impl(script, port, args):
    cmd = [str(PY), str(script), "--host", "127.0.0.1", "--port", str(port),
           "--procid", "1"] + args
    proc = subprocess.run(cmd, input=INPUT, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"{script} rc={proc.returncode}: {proc.stderr.decode()}")
    return proc


def main():
    base_port = 15200
    failures = 0
    for i, (label, args) in enumerate(CASES):
        proto = "udp" if label.startswith("udp") else "tcp"
        results = {}
        for name, script in (("sc", SC), ("lib", LIB)):
            rx = Receiver(proto, base_port + i * 2 + (0 if name == "sc" else 1))
            rx.start()
            import time
            time.sleep(0.3)
            run_impl(script, rx.port, args)
            time.sleep(0.5)
            rx.stop()
            results[name] = [m for m in rx.messages]

        a, b = results["sc"], results["lib"]
        na = [normalize(m) for m in a]
        nb = [normalize(m) for m in b]
        if na == nb:
            print(f"OK   {label}: {len(a)} messages identical")
        else:
            failures += 1
            print(f"FAIL {label}: sc={len(a)} lib={len(b)} messages differ")
            for x, y in zip(na, nb):
                if x != y:
                    print(f"  sc : {x!r}")
                    print(f"  lib: {y!r}")
                    break
    print("ALL OK" if not failures else f"{failures} FAILURES")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
