#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""logrelay - relay log lines from a file or stdin to a syslog server (RFC 5424).

usage:
    tail -f mylog.log | python3 logrelay.py --host 10.0.0.1
    python3 logrelay.py /var/log/app.log --host logs.example.com --proto tcp
    python3 logrelay.py --host logs.example.com --facility local0 --priority warning

Self-contained: Python 3.10+ standard library only, no third-party packages.

Behavior:
    * one syslog message per input line, empty lines are skipped
    * reads stdin by default (works with `tail -f`), or a file argument
    * on send failure the message is dropped, a warning is written to stderr
      and streaming continues (reconnects are throttled)
    * UTF-8 output with RFC 5424 BOM (disable with --no-utf8-bom)
"""

import argparse
import os
import shlex
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

PROGRAM = "logrelay"
VERSION = "0.2.0"

NILVALUE = "-"
SP = b" "
BOM_UTF8 = b"\xef\xbb\xbf"
REGISTERED_SD_IDS = ("timeQuality", "origin", "meta")

FACILITY_NAMES = {
    "kern": 0, "kernel": 0, "usr": 1, "user": 1, "mail": 2, "daemon": 3,
    "auth": 4, "syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
    "authpriv": 10, "ftp": 11, "ntp": 12,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

SEVERITY_NAMES = {
    "emerg": 0, "panic": 0, "emergency": 0,
    "alert": 1,
    "crit": 2, "critical": 2,
    "err": 3, "error": 3,
    "warning": 4, "warn": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}

# RFC 6587 framing (section 3.4)
FRAMING_OCTET_COUNTING = 1
FRAMING_NON_TRANSPARENT = 2

CONNECT_COOLDOWN = 2.0   # seconds between connection attempts to a dead server
WARN_INTERVAL = 10.0     # seconds between "dropped N messages" warnings


def filter_printusascii(text):
    """RFC 5424 PRINTUSASCII: %d33-126 only."""
    return "".join(c for c in text if 33 <= ord(c) <= 126)


# --------------------------------------------------------------------------
# message assembly (mirrors rfc5424logging.handler.build_msg)
# --------------------------------------------------------------------------

def build_message(cfg, line):
    """Build one RFC 5424 syslog message as bytes.

    SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]
    HEADER     = "<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID"
    """
    now = datetime.now(timezone.utc) if cfg.utc else datetime.now().astimezone()
    timestamp = now.isoformat()

    pri = (cfg.facility << 3) | cfg.severity
    hostname = filter_printusascii(cfg.hostname or "")[:255] or NILVALUE
    appname = filter_printusascii(cfg.appname or "")[:48] or NILVALUE
    procid = filter_printusascii(cfg.procid or "")[:128] or NILVALUE
    msgid = filter_printusascii(cfg.msgid or "")[:32] or NILVALUE

    # PRI and VERSION are NOT separated by SP (RFC 5424: HEADER = PRI VERSION SP TIMESTAMP ...)
    header = SP.join((
        f"<{pri}>1".encode("ascii"),
        timestamp.encode("ascii"),
        hostname.encode("ascii", "replace")[:255],
        appname.encode("ascii", "replace")[:48],
        procid.encode("ascii", "replace")[:128],
        msgid.encode("ascii", "replace")[:32],
    ))

    structured_data = build_structured_data(cfg)

    if line:
        msg = line.encode("utf-8", "replace")
        if cfg.msg_as_utf8:
            msg = BOM_UTF8 + msg
        return SP.join((header, structured_data, msg))
    return SP.join((header, structured_data))


def build_structured_data(cfg):
    """Serialize structured data elements; NILVALUE when there are none."""
    if not cfg.structured_data:
        return NILVALUE.encode("ascii")

    elements = []
    for sd_id, params in cfg.structured_data.items():
        sd_id = filter_printusascii(sd_id)
        sd_id = sd_id.replace("=", "").replace(" ", "").replace("]", "").replace('"', "")
        enterprise_id = filter_printusascii(str(cfg.enterprise_id)) if cfg.enterprise_id is not None else None

        if "@" in sd_id:
            sd_id, enterprise_id = sd_id.rsplit("@", 1)
        elif sd_id not in REGISTERED_SD_IDS and enterprise_id is None:
            raise ValueError(
                f"structured data id {sd_id!r} has no @enterprise-id suffix and no --enterprise-id was given")

        if enterprise_id and len(enterprise_id) > 30:
            raise ValueError("enterprise id is too long (max 30 chars)")
        sd_id = sd_id.replace("@", "")
        if sd_id not in REGISTERED_SD_IDS:
            if enterprise_id is None:
                raise ValueError(
                    f"structured data id {sd_id!r} has no @enterprise-id suffix and no --enterprise-id was given")
            if len(sd_id) + len(enterprise_id) > 32:
                sd_id = sd_id[:31 - len(enterprise_id)]
            sd_id = "@".join((sd_id, enterprise_id))

        sd_params = []
        for name, value in params.items():
            name = filter_printusascii(str(name))
            name = name.replace("=", "").replace(" ", "").replace("]", "").replace('"', "")
            value = "" if value is None else str(value)
            value = value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
            sd_params.append(b"".join((
                name.encode("ascii", "replace")[:32],
                b'="',
                value.encode("utf-8", "replace"),
                b'"',
            )))

        joined = SP.join(sd_params)
        spacer = SP if sd_params else b""
        elements.append(b"".join((b"[", sd_id.encode("ascii", "replace"), spacer, joined, b"]")))

    return b"".join(elements)


# --------------------------------------------------------------------------
# truncation (only MSG is cut; HEADER and STRUCTURED-DATA stay intact)
# --------------------------------------------------------------------------

def _sd_element_end(data, start):
    """data[start] == b'['; return index just past the matching ']'.
    ']' inside PARAM-VALUEs is escaped as '\\]' and a literal backslash as
    '\\\\', so skip escapes pairwise."""
    i = start + 1
    n = len(data)
    while i < n:
        c = data[i:i + 1]
        if c == b"\\":
            i += 2
            continue
        if c == b"]":
            return i + 1
        i += 1
    return n


def _split_message(data):
    """Split a built message into (header, sd, msg) byte parts.
    Header fields are PRINTUSASCII-filtered (spaces removed), so the first
    7 space-separated tokens are exactly PRI VER TIMESTAMP HOSTNAME APP-NAME
    PROCID MSGID."""
    fields = data.split(b" ", 6)
    if len(fields) < 7:
        return data, b"", b""
    header = b" ".join(fields[:6])
    rest = fields[6]
    if rest.startswith(b"["):
        end = 0
        while end < len(rest) and rest[end:end + 1] == b"[":
            end = _sd_element_end(rest, end)
        sd = rest[:end]
        msg = rest[end + 1:] if end < len(rest) else b""
    elif rest.startswith(b"- "):
        sd, msg = b"-", rest[2:]
    else:
        sd, msg = b"-", rest
    return header, sd, msg


def truncate_message(data, max_length):
    """Truncate a fully built syslog message to max_length bytes without
    corrupting HEADER/STRUCTURED-DATA (only MSG is cut, at a UTF-8 edge)."""
    if not max_length or len(data) <= max_length:
        return data
    header, sd, msg = _split_message(data)
    base = header + b" " + sd
    if not msg or len(base) + 1 >= max_length:
        return base
    budget = max_length - len(base) - 1
    msg = msg[:budget].decode("utf-8", "ignore").encode("utf-8")
    return base + b" " + msg


# --------------------------------------------------------------------------
# transports (mirrors rfc5424logging.transport)
# --------------------------------------------------------------------------

class UdpTransport:
    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.address = None
        self.open()

    def open(self):
        error = None
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
                self.host, self.port, 0, socket.SOCK_DGRAM):
            try:
                self.sock = socket.socket(family, socktype, proto)
                self.sock.settimeout(self.timeout)
                self.address = sockaddr
                return
            except OSError as exc:
                error = exc
                if self.sock is not None:
                    self.sock.close()
        raise error or OSError(f"no address for {self.host}:{self.port}")

    def send(self, data):
        try:
            self.sock.sendto(data, self.address)
        except OSError:
            self.close()
            self.open()
            self.sock.sendto(data, self.address)

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None


class TcpTransport:
    def __init__(self, host, port, timeout, framing):
        self.host, self.port, self.timeout = host, port, timeout
        self.framing = framing
        self.sock = None
        self.open()

    def open(self):
        error = None
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
                self.host, self.port, 0, socket.SOCK_STREAM):
            try:
                self.sock = socket.socket(family, socktype, proto)
                self.sock.settimeout(self.timeout)
                self.sock.connect(sockaddr)
                return
            except OSError as exc:
                error = exc
                if self.sock is not None:
                    self.sock.close()
        raise error or OSError(f"no address for {self.host}:{self.port}")

    def send(self, data):
        # RFC 6587 framing
        if self.framing == FRAMING_NON_TRANSPARENT:
            data = data.replace(b"\n", b"\\n") + b"\n"
        else:
            data = b" ".join((str(len(data)).encode("ascii"), data))
        try:
            self.sock.sendall(data)
        except OSError:
            self.close()
            self.open()
            self.sock.sendall(data)

    def close(self):
        # Graceful close: shutdown(SHUT_WR) prevents Windows from sending a
        # RST when unread data is pending (e.g. TLS 1.3 session tickets the
        # client never reads), which would make the receiver abort and drop
        # messages that were already transmitted. Draining then lets the
        # server finish reading before the final close.
        sock, self.sock = self.sock, None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(0.3)
            while sock.recv(4096):
                pass
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass


class TlsTransport(TcpTransport):
    def __init__(self, host, port, timeout, framing, ca_bundle, verify,
                 client_cert, client_key, key_password):
        self.ca_bundle = ca_bundle
        self.verify = verify
        self.client_cert = client_cert
        self.client_key = client_key
        self.key_password = key_password
        super().__init__(host, port, timeout, framing)

    def open(self):
        super().open()
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH,
                                             cafile=self.ca_bundle)
        if not self.verify:
            # check_hostname must be disabled before CERT_NONE
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context.verify_mode = ssl.CERT_REQUIRED
        if self.client_cert:
            context.load_cert_chain(self.client_cert, self.client_key,
                                    self.key_password)
        self.sock = context.wrap_socket(self.sock, server_hostname=self.host)


class UnixTransport:
    def __init__(self, path, socktype=None):
        self.path = path
        self.requested_socktype = socktype
        self.sock = None
        self.open()

    def open(self):
        types = [socket.SOCK_DGRAM, socket.SOCK_STREAM]
        if self.requested_socktype is not None:
            types = [self.requested_socktype]
        # the syslog socket may be unavailable right now; stay quiet
        for socktype in types:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socktype)
                self.sock.connect(self.path)
                return
            except OSError:
                if self.sock is not None:
                    self.sock.close()
                    self.sock = None

    def send(self, data):
        if self.sock is None:
            raise OSError(f"cannot connect to unix socket {self.path}")
        self.sock.send(data)

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None


# --------------------------------------------------------------------------
# sender: drop-and-continue with throttled reconnects
# --------------------------------------------------------------------------

class Sender:
    def __init__(self, transport_factory, verbose=False, max_length=8192):
        self._factory = transport_factory
        self._verbose = verbose
        self._max_length = max_length
        self._transport = None
        self._last_attempt = 0.0
        self._dropped = 0
        self._last_warn = 0.0
        self._connect()

    def _connect(self):
        self._last_attempt = time.monotonic()
        if self._transport is not None:
            self._close_transport()
            self._transport = None
        try:
            self._transport = self._factory()
        except Exception as exc:
            self._warn(f"connect to server failed: {exc}")
            return False
        if self._dropped:
            self._note(f"reconnected (dropped {self._dropped} message(s) while offline)")
            self._dropped = 0
        return True

    def _note(self, text):
        sys.stderr.write(f"{PROGRAM}: {text}\n")

    def _warn(self, text):
        if time.monotonic() - self._last_warn >= WARN_INTERVAL:
            self._last_warn = time.monotonic()
            self._note(text)

    def _drop(self, reason):
        self._dropped += 1
        self._warn(f"dropped {self._dropped} message(s) so far (last error: {reason})")

    def send(self, message):
        if self._transport is None:
            if time.monotonic() - self._last_attempt < CONNECT_COOLDOWN:
                self._drop("server unreachable")
                return
            if not self._connect():
                self._drop("server unreachable")
                return
        data = truncate_message(message, self._max_length)
        try:
            self._transport.send(data)
            if self._verbose:
                self._note(f"sent: {data.decode('utf-8', 'replace')}")
        except Exception as exc:
            # transport is dead; recreate on the next send (cooldown-gated)
            self._close_transport()
            self._drop(exc)

    def _close_transport(self):
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None

    def close(self):
        self._close_transport()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def facility_arg(value):
    v = value.strip().lower()
    if v.isdigit():
        n = int(v)
        if 0 <= n <= 23:
            return n
        raise argparse.ArgumentTypeError(f"facility must be 0-23, got {value!r}")
    if v in FACILITY_NAMES:
        return FACILITY_NAMES[v]
    raise argparse.ArgumentTypeError(
        f"unknown facility {value!r} (use one of: {', '.join(FACILITY_NAMES)} or 0-23)")


def severity_arg(value):
    v = value.strip().lower()
    if v.isdigit():
        n = int(v)
        if 0 <= n <= 7:
            return n
        raise argparse.ArgumentTypeError(f"severity must be 0-7, got {value!r}")
    if v in SEVERITY_NAMES:
        return SEVERITY_NAMES[v]
    raise argparse.ArgumentTypeError(
        f"unknown severity {value!r} (use one of: emerg, alert, crit, err, warning, notice, info, debug or 0-7)")


def parse_sd(spec, enterprise_id):
    """Parse one --sd argument: 'ID [NAME="VALUE" ...]' -> (id, params dict)."""
    parts = shlex.split(spec)
    if not parts:
        raise ValueError("empty structured data element")
    sd_id, params = parts[0], {}
    for token in parts[1:]:
        name, sep, value = token.partition("=")
        if not sep:
            raise ValueError(f"structured data parameter {token!r} is not NAME=VALUE")
        params[name] = value
    if "@" not in sd_id and sd_id not in REGISTERED_SD_IDS and enterprise_id is None:
        raise ValueError(
            f"structured data id {sd_id!r} has no @enterprise-id suffix and no --enterprise-id was given")
    return sd_id, params


class Config:
    """Namespace for message assembly (kept tiny for speed in the hot loop)."""
    __slots__ = ("facility", "severity", "hostname", "appname", "procid",
                 "msgid", "structured_data", "enterprise_id", "utc",
                 "msg_as_utf8")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Relay log lines from a file or stdin to a syslog server (RFC 5424). "
                    "Self-contained: standard library only.",
        epilog=(
            "examples:\n"
            "  tail -f mylog.log | python3 logrelay.py --host 10.0.0.1\n"
            "  python3 logrelay.py mylog.log --host logs.example.com --proto tcp\n"
            "  python3 logrelay.py --host logs.example.com --facility local0 --priority warning\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", nargs="?", default="-",
                        help="input file (default: '-' reads stdin, e.g. piped from 'tail -f')")
    parser.add_argument("--host", required=True,
                        help="syslog server hostname or IP address")
    parser.add_argument("--port", type=int, default=514,
                        help="syslog server port (default: 514)")
    parser.add_argument("--proto", choices=("udp", "tcp", "tls", "unix"), default="udp",
                        help="transport protocol (default: udp)")
    parser.add_argument("--path", default="/dev/log",
                        help="unix socket path when --proto unix (default: /dev/log)")
    parser.add_argument("-f", "--facility", type=facility_arg, default=FACILITY_NAMES["user"],
                        help="syslog facility: name (kern, user, mail, daemon, auth, syslog, lpr, news, "
                             "uucp, cron, authpriv, ftp, local0-local7) or 0-23 (default: user)")
    parser.add_argument("-p", "--priority", "--severity", dest="severity", type=severity_arg,
                        default=SEVERITY_NAMES["info"],
                        help="syslog severity: name (emerg, alert, crit, err, warning, notice, info, debug) "
                             "or 0-7 (default: info)")
    parser.add_argument("--hostname", default=socket.gethostname(),
                        help="HOSTNAME header field (default: local hostname)")
    parser.add_argument("--appname", default="logrelay",
                        help="APP-NAME header field (default: logrelay)")
    parser.add_argument("--procid", default=str(os.getpid()),
                        help="PROCID header field (default: current PID)")
    parser.add_argument("--msgid", default=None,
                        help="MSGID header field (default: '-')")
    parser.add_argument("--sd", action="append", default=[], metavar="SPEC",
                        help="structured data element 'ID [NAME=\"VALUE\" ...]', repeatable, e.g. "
                             "--sd 'mydata@32473 iut=\"3\" event=\"login\"'")
    parser.add_argument("--enterprise-id", default=None, metavar="PEN",
                        help="Private Enterprise Number used for structured data IDs without @suffix")
    parser.add_argument("--utc", action="store_true",
                        help="timestamp messages in UTC instead of local time")
    parser.add_argument("--no-utf8-bom", action="store_true",
                        help="do not prepend the UTF-8 BOM to the message part (RFC 5424 MSG-UTF8)")
    parser.add_argument("--max-length", type=int, default=8192, metavar="BYTES",
                        help="truncate outgoing messages to this size, 0 disables (default: 8192)")
    parser.add_argument("--framing", choices=("non-transparent", "octet-counting"),
                        default="non-transparent",
                        help="RFC 6587 framing for tcp/tls (default: non-transparent)")
    parser.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS",
                        help="socket connect/send timeout (default: 5)")
    parser.add_argument("--tls-ca", default=None, metavar="FILE",
                        help="CA bundle to verify the TLS server certificate (default: system CAs)")
    parser.add_argument("--tls-no-verify", action="store_true",
                        help="disable TLS certificate verification")
    parser.add_argument("--tls-client-cert", default=None, metavar="FILE",
                        help="client certificate for TLS mutual auth")
    parser.add_argument("--tls-client-key", default=None, metavar="FILE",
                        help="client private key for TLS mutual auth")
    parser.add_argument("--tls-key-password", default=None,
                        help="password for the TLS client key")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log every sent message to stderr")
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {VERSION}")
    return parser


def open_input(path):
    if path in ("-", None):
        return sys.stdin.buffer
    return open(path, "rb")


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    structured_data = {}
    for spec in args.sd:
        try:
            sd_id, params = parse_sd(spec, args.enterprise_id)
        except ValueError as exc:
            raise SystemExit(f"{PROGRAM}: --sd: {exc}")
        structured_data[sd_id] = params

    if args.proto == "unix":
        socktype = None
        factory = lambda: UnixTransport(args.path, socktype)
    elif args.proto == "udp":
        factory = lambda: UdpTransport(args.host, args.port, args.timeout)
    elif args.proto == "tcp":
        framing = FRAMING_OCTET_COUNTING if args.framing == "octet-counting" else FRAMING_NON_TRANSPARENT
        factory = lambda: TcpTransport(args.host, args.port, args.timeout, framing)
    else:
        framing = FRAMING_OCTET_COUNTING if args.framing == "octet-counting" else FRAMING_NON_TRANSPARENT
        factory = lambda: TlsTransport(
            args.host, args.port, args.timeout, framing,
            args.tls_ca, not args.tls_no_verify,
            args.tls_client_cert, args.tls_client_key, args.tls_key_password)

    cfg = Config()
    cfg.facility = args.facility
    cfg.severity = args.severity
    cfg.hostname = args.hostname
    cfg.appname = args.appname
    cfg.procid = args.procid
    cfg.msgid = args.msgid
    cfg.structured_data = structured_data
    cfg.enterprise_id = args.enterprise_id
    cfg.utc = args.utc
    cfg.msg_as_utf8 = not args.no_utf8_bom

    exit_code = 0
    sender = Sender(factory, verbose=args.verbose, max_length=args.max_length)
    try:
        # test the connection up front so bad --host values fail fast
        if args.proto != "unix" and not sender._connect():
            sender._dropped = 0  # do not count the pre-flight attempt
        stream = open_input(args.file)
        try:
            first = True
            for raw in iter(stream.readline, b""):
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if first:
                    first = False
                    if line.startswith("\ufeff"):
                        line = line[1:]
                if not line:
                    continue
                sender.send(build_message(cfg, line))
        finally:
            if stream is not sys.stdin.buffer:
                stream.close()
    except KeyboardInterrupt:
        exit_code = 130
    finally:
        sender.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
