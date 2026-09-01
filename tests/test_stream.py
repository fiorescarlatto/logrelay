"""Streaming + resilience test for the self-contained implementation.

1. streaming: feed lines slowly through a pipe (simulates `tail -f |`),
   verify messages arrive incrementally while the writer is still open
2. dead server: verify drop-and-continue behavior (warnings, exit 0,
   no hang), then verify messages flow again after recovery
"""
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv" / "Scripts" / "python.exe"
SC = ROOT / "logrelay.py"


class Receiver(threading.Thread):
    def __init__(self, proto, port):
        super().__init__(daemon=True)
        self.proto = proto
        self.port = port
        self.messages = []
        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        if proto != "udp":
            self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.done = threading.Event()

    def run(self):
        while not self.done.is_set():
            try:
                if self.proto == "udp":
                    data, _ = self.sock.recvfrom(65535)
                    self.messages.append(data)
                    continue
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.proto == "udp":
                continue
            buf = b""
            conn.settimeout(10)
            while True:
                try:
                    chunk = conn.recv(65535)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buf += chunk
                while True:
                    if buf[:1].isdigit():
                        sp = buf.find(b" ")
                        if sp == -1:
                            break
                        ln = int(buf[:sp])
                        if len(buf) < sp + 1 + ln:
                            break
                        self.messages.append(buf[sp + 1:sp + 1 + ln])
                        buf = buf[sp + 1 + ln:]
                    else:
                        nl = buf.find(b"\n")
                        if nl == -1:
                            break
                        self.messages.append(buf[:nl])
                        buf = buf[nl + 1:]
            conn.close()

    def stop(self):
        self.done.set()
        self.sock.close()
        self.join(timeout=2)


def start_relay(port, extra_args=None):
    extra_args = extra_args or []
    return subprocess.Popen(
        [str(PY), str(SC), "--host", "127.0.0.1", "--port", str(port),
         "--hostname", "streamH", "--appname", "streamA", "--procid", "1",
         "--timeout", "1"] + list(extra_args),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_streaming():
    print("== streaming (tail -f style) ==")
    rx = Receiver("udp", 15270)
    rx.start()
    time.sleep(0.3)
    proc = start_relay(15270)
    try:
        timestamps = []
        for i in range(1, 6):
            proc.stdin.write(f"stream line {i}\n".encode())
            proc.stdin.flush()
            timestamps.append(time.monotonic())
            time.sleep(0.4)
        # while stdin is still open, receiver should already have messages
        time.sleep(0.5)
        n_open = len(rx.messages)
        proc.stdin.close()
        proc.wait(timeout=10)
        time.sleep(0.3)
    finally:
        rx.stop()

    ok = True
    if n_open == 5:
        print("OK   5/5 messages relayed incrementally (stdin stayed open)")
    else:
        ok = False
        print(f"FAIL only {n_open}/5 messages while streaming")
    if proc.returncode == 0:
        print("OK   exit code 0")
    else:
        ok = False
        print(f"FAIL exit code {proc.returncode}")
    for m in rx.messages:
        if b"stream line" not in m:
            ok = False
            print(f"FAIL bad message: {m!r}")
    return ok


def test_dead_server():
    print("== dead server (drop & continue, tcp) ==")
    # TCP: a dead port fails the connect immediately, exercising the
    # warning + drop path. (UDP is fire-and-forget and never errors.)
    proc = start_relay(15271, extra_args=["--proto", "tcp"])
    try:
        t0 = time.monotonic()
        for i in range(20):
            proc.stdin.write(f"line during outage {i}\n".encode())
            proc.stdin.flush()
            time.sleep(0.05)
        elapsed_during = time.monotonic() - t0
        proc.stdin.close()
        proc.wait(timeout=15)
        err = proc.stderr.read().decode(errors="replace")
    finally:
        if proc.poll() is None:
            proc.kill()

    ok = True
    if proc.returncode == 0:
        print("OK   survived dead server, exit code 0")
    else:
        ok = False
        print(f"FAIL exit code {proc.returncode}")
    if "dropped" in err or "connect" in err:
        print(f"OK   warned on stderr: {err.strip().splitlines()[0]!r}")
    else:
        ok = False
        print("FAIL no warning on stderr")
    # must not block: 20 lines x 50ms + startup ~= 2-3s max
    if proc.returncode == 0 and elapsed_during < 15:
        print(f"OK   non-blocking ({elapsed_during:.1f}s for 20 sends)")
    else:
        ok = False
        print(f"FAIL blocked or wrong exit ({elapsed_during:.1f}s)")
    return ok


def test_recovery():
    print("== recovery after server returns (tcp) ==")
    # Deterministic timing: pre-flight connect fails (~1.3s with --timeout 1),
    # the outage line is dropped during cooldown, the receiver starts late
    # (t≈2.5s), and the recovered line (t≈4s) exercises the reconnect.
    proc = start_relay(15272, extra_args=["--proto", "tcp", "--timeout", "1"])
    rx = None
    try:
        proc.stdin.write(b"outage line\n")
        proc.stdin.flush()
        time.sleep(2.5)   # pre-flight failed; outage dropped during cooldown
        rx = Receiver("tcp", 15272)
        rx.start()
        time.sleep(1.5)   # cooldown window passes
        proc.stdin.write(b"recovered line\n")
        proc.stdin.flush()
        time.sleep(1)
        proc.stdin.close()
        proc.wait(timeout=10)
        time.sleep(0.3)
    finally:
        if proc.poll() is None:
            proc.kill()
        if rx is not None:
            rx.stop()
    recovered = any(b"recovered line" in m for m in rx.messages)
    outage_dropped = not any(b"outage line" in m for m in rx.messages)
    ok = recovered
    print("OK   message after recovery delivered" if recovered else "FAIL recovery lost")
    print("OK   outage message dropped (by design)" if outage_dropped else "FAIL outage line arrived")
    return ok


def main():
    results = [
        test_streaming(),
        test_dead_server(),
        test_recovery(),
    ]
    print("ALL OK" if all(results) else "FAILURES PRESENT")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
