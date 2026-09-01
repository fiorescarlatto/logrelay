"""Deterministic TLS transport test with event synchronization."""
import importlib.util
import socket
import ssl
import threading
import time

PORT = 15288


def server(listening, msgs):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("tests/server_cert.pem", "tests/server_key.pem")
    listening.set()
    conn, _ = s.accept()
    conn = ctx.wrap_socket(conn, server_side=True)
    buf = b""
    while True:
        try:
            chunk = conn.recv(65535)
        except Exception as exc:
            print(f"[srv] recv err: {exc!r}")
            break
        if not chunk:
            print("[srv] EOF")
            break
        print(f"[srv] got {len(chunk)}: {chunk!r}")
        buf += chunk
    conn.close()
    s.close()


def main():
    msgs = []
    listening = threading.Event()
    t = threading.Thread(target=server, args=(listening, msgs), daemon=True)
    t.start()
    listening.wait(timeout=5)

    spec = importlib.util.spec_from_file_location("sc", "logrelay.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    tr = m.TlsTransport("127.0.0.1", PORT, 5, m.FRAMING_OCTET_COUNTING,
                        "tests/server_cert.pem", False, None, None, None)
    print("[cli] connected")
    tr.send(b"<14>1 msg-one")
    print("[cli] sent one")
    time.sleep(0.2)
    tr.send(b"<14>1 msg-two")
    print("[cli] sent two")
    time.sleep(0.2)
    tr.close()
    print("[cli] closed")
    time.sleep(0.5)


if __name__ == "__main__":
    main()
