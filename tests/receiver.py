#!/usr/bin/env python3
"""Minimal syslog wire-format receiver for testing logrelay.

usage: receiver.py udp|tcp PORT OUTFILE [CERTFILE KEYFILE]

UDP  : one datagram == one syslog message
TCP  : parses both RFC 6587 framings (octet-counting and non-transparent);
       accepts multiple sequential connections
TLS  : same as TCP but wrapped in a server-side TLS context

Every received message is written to OUTFILE as one line (messages contain
no raw newlines because line-based input never has them and TCP framing
escapes them).
"""

import socket
import ssl
import sys


def serve_udp(port, out):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    while True:
        data, _ = sock.recvfrom(65535)
        out.write(data.rstrip(b"\n") + b"\n")
        out.flush()


def read_messages(conn):
    buf = b""
    while True:
        chunk = conn.recv(65535)
        if not chunk:
            break
        buf += chunk
        while buf:
            if buf[:1].isdigit():
                sp = buf.find(b" ")
                if sp == -1:
                    break
                length = int(buf[:sp])
                if len(buf) < sp + 1 + length:
                    break
                yield buf[sp + 1:sp + 1 + length]
                buf = buf[sp + 1 + length:]
            else:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                yield buf[:nl]
                buf = buf[nl + 1:]


def serve_tcp(port, out, certfile=None, keyfile=None):
    import ssl
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        sock = context.wrap_socket(sock, server_side=True)
    while True:
        try:
            conn, _ = sock.accept()
        except (ConnectionError, ssl.SSLError, OSError):
            # failed handshake (e.g. client aborted) - keep listening
            continue
        try:
            for msg in read_messages(conn):
                out.write(msg + b"\n")
                out.flush()
        except (ConnectionError, ssl.SSLError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def main():
    proto, port, outfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    cert = sys.argv[4] if len(sys.argv) > 4 else None
    key = sys.argv[5] if len(sys.argv) > 5 else None
    with open(outfile, "wb") as out:
        if proto == "udp":
            serve_udp(port, out)
        elif proto in ("tcp", "tls"):
            serve_tcp(port, out, cert, key)
        else:
            raise SystemExit(f"unknown proto {proto}")


if __name__ == "__main__":
    main()
