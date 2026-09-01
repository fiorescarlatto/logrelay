"""Compare library TLS transport vs self-contained TLS transport, same receiver."""
import importlib.util
import socket
import ssl
import sys
import threading
import time

PORT = 15289


def make_receiver(msgs, tag):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("tests/server_cert.pem", "tests/server_key.pem")

    def run():
        conn, _ = s.accept()
        conn = ctx.wrap_socket(conn, server_side=True)
        buf = b""
        while True:
            try:
                chunk = conn.recv(65535)
            except Exception as exc:
                print(f"[{tag}] recv err: {exc!r}")
                break
            if not chunk:
                print(f"[{tag}] EOF")
                break
            print(f"[{tag}] got {len(chunk)}: {chunk!r}")
            buf += chunk
        conn.close()
        s.close()

    t = threading.Thread(target=run, daemon=True)
    return t


def run():
    pass


def main():
    which = sys.argv[1]
    msgs = []
    tag = which
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("tests/server_cert.pem", "tests/server_key.pem")

    def server():
        conn, _ = s.accept()
        conn = ctx.wrap_socket(conn, server_side=True)
        buf = b""
        while True:
            try:
                chunk = conn.recv(65535)
            except Exception as exc:
                print(f"[{tag}] recv err: {exc!r}")
                break
            if not chunk:
                print(f"[{tag}] EOF")
                break
            print(f"[{tag}] got {len(chunk)}: {chunk!r}")
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

    t = threading.Thread(target=server, daemon=True)
    t.start()
    time.sleep(0.3)

    if which == "lib":
        from rfc5424logging import Rfc5424SysLogHandler, FRAMING_OCTET_COUNTING
        h = Rfc5424SysLogHandler(address=("127.0.0.1", PORT), socktype=socket.SOCK_STREAM,
                                 framing=FRAMING_OCTET_COUNTING, tls_enable=True,
                                 tls_ca_bundle="tests/server_cert.pem", timeout=5)
        import logging
        h.transport.transmit(b"<14>1 msg-one")
        h.transport.transmit(b"<14>1 msg-two")
        h.close()
    else:
        spec = importlib.util.spec_from_file_location("sc", "logrelay.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        tr = m.TlsTransport("127.0.0.1", PORT, 5, m.FRAMING_OCTET_COUNTING,
                            "tests/server_cert.pem", False, None, None, None)
        tr.send(b"<14>1 msg-one")
        tr.send(b"<14>1 msg-two")
        tr.close()
    time.sleep(0.5)
    print(f"received {len(msgs)}: {msgs!r}")


if __name__ == "__main__":
    main()
