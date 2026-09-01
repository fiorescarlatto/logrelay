"""Direct transport-level TLS test for the self-contained implementation."""
import importlib.util
import socket
import ssl
import threading
import time

spec = importlib.util.spec_from_file_location("sc", "logrelay.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

PORT = 15292


def receiver(msgs):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("tests/server_cert.pem", "tests/server_key.pem")
    conn, _ = s.accept()
    conn = ctx.wrap_socket(conn, server_side=True)
    print("[rx] handshake done")
    buf = b""
    while True:
        try:
            chunk = conn.recv(65535)
        except Exception as exc:
            print(f"[rx] recv error: {exc!r}")
            break
        if not chunk:
            break
        buf += chunk
        while buf:
            if buf[:1].isdigit():
                sp = buf.find(b" ")
                if sp == -1:
                    break
                ln = int(buf[:sp])
                if len(buf) < sp + 1 + ln:
                    break
                msgs.append(buf[sp + 1:sp + 1 + ln])
                buf = buf[sp + 1 + ln:]
            else:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                msgs.append(buf[:nl])
                buf = buf[nl + 1:]
    conn.close()
    s.close()


msgs = []

for framing, label in ((m.FRAMING_OCTET_COUNTING, "octet-counting"),
                       (m.FRAMING_NON_TRANSPARENT, "non-transparent")):
    t = threading.Thread(target=receiver, args=(msgs,), daemon=True)
    t.start()
    time.sleep(0.3)
    tr = m.TlsTransport("127.0.0.1", PORT, 5, framing,
                        "tests/server_cert.pem", False, None, None, None)
    tr.send(b"<14>1 msg-one")
    tr.send(b"<14>1 msg-two")
    tr.close()
    time.sleep(0.5)
    ok = len(msgs) == 2
    print(f"{label}: received={len(msgs)} {'OK' if ok else 'FAIL'} {msgs!r}")
    msgs.clear()
