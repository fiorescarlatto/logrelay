#!/usr/bin/env python3
"""logrelay - relay log lines from a file or stdin to a syslog server (RFC 5424).

Usage:
    tail -f mylog.log | python3 logrelay.py --host 10.0.0.1
    python3 logrelay.py /var/log/app.log --host logs.example.com --proto tcp
    python3 logrelay.py --host logs.example.com --facility local0 --priority warning

This is the REFERENCE implementation backed by the 'rfc5424-logging-handler'
package. The shipped logrelay.py is a self-contained rewrite with an
identical wire format; this file is kept for differential testing.
"""

import argparse
import logging
import os
import shlex
import socket
import sys
import time

from rfc5424logging import (
    Rfc5424SysLogHandler,
    FRAMING_NON_TRANSPARENT,
    FRAMING_OCTET_COUNTING,
)

PROGRAM = "logrelay"
VERSION = "0.1.0"

FACILITY_NAMES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
    "lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
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

# syslog severity 0-7 -> python logging level understood by the handler's
# priority_map (70=EMERG and 60=ALERT are custom levels, see below)
SEVERITY_TO_LOGGING = (70, 60, 50, 40, 30, 25, 20, 10)

REGISTERED_SD_IDS = ("timeQuality", "origin", "meta")

CONNECT_COOLDOWN = 2.0   # seconds between connection attempts to a dead server
WARN_INTERVAL = 10.0     # seconds between "dropped N messages" warnings


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


def _sd_element_end(data, start):
    """data[start] == b'['; return index just past the matching ']'.
    ']' inside PARAM-VALUEs is escaped as '\\]' by the encoder, and a
    literal backslash is escaped as '\\\\', so skip them pairwise."""
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
    """Split a built syslog message into (header, sd, msg) byte parts.
    Header fields are PRINTUSASCII-filtered (spaces removed), so the first
    6 space-separated tokens are exactly PRI+VER TIMESTAMP HOSTNAME APP-NAME
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
        sd = b"-"
        msg = rest[2:]
    else:
        sd, msg = b"-", rest
    return header, sd, msg


def truncate_message(data, max_length):
    """Truncate a fully built syslog message to max_length bytes without
    corrupting HEADER/STRUCTURED-DATA (only MSG is cut)."""
    if not max_length or len(data) <= max_length:
        return data
    header, sd, msg = _split_message(data)
    base = header + b" " + sd
    if not msg or len(base) + 1 >= max_length:
        return base
    budget = max_length - len(base) - 1
    msg = msg[:budget].decode("utf-8", "ignore").encode("utf-8")
    return base + b" " + msg


class SyslogSender:
    """Sends one message per line. Drop-and-continue on failures."""

    def __init__(self, handler_factory, verbose=False, max_length=8192, msgid=None, level=logging.INFO):
        self._factory = handler_factory
        self._verbose = verbose
        self._max_length = max_length
        self._msgid = msgid
        self._level = level
        self._handler = None
        self._last_attempt = 0.0
        self._dropped = 0
        self._last_warn = 0.0
        self._connect()

    def _connect(self):
        self._last_attempt = time.monotonic()
        if self._handler is not None:
            try:
                self._handler.close()
            except Exception:
                pass
            self._handler = None
        try:
            self._handler = self._factory()
            if self._dropped:
                sys.stderr.write(f"{PROGRAM}: reconnected (dropped {self._dropped} message(s) while offline)\n")
                self._dropped = 0
            return True
        except Exception as exc:
            self._warn(f"connect failed: {exc}")
            return False

    def _warn(self, text):
        now = time.monotonic()
        if now - self._last_warn >= WARN_INTERVAL:
            self._last_warn = now
            sys.stderr.write(f"{PROGRAM}: {text}\n")

    def _drop(self, reason):
        self._dropped += 1
        self._warn(f"dropped {self._dropped} message(s) so far (last error: {reason})")

    def send(self, line):
        if self._handler is None:
            if time.monotonic() - self._last_attempt < CONNECT_COOLDOWN:
                self._drop("server unreachable")
                return
            if not self._connect():
                self._drop("server unreachable")
                return
        record = logging.LogRecord(PROGRAM, self._level, PROGRAM, 0, line, (), None)
        if self._msgid:
            record.msgid = self._msgid
        try:
            data = self._handler.build_msg(record)
            data = truncate_message(data, self._max_length)
            self._handler.transport.transmit(data)
            if self._verbose:
                sys.stderr.write(f"{PROGRAM}: sent: {data.decode('utf-8', 'replace')}\n")
        except Exception as exc:
            # transport is dead; recreate on the next send (cooldown-gated)
            self._handler = None
            self._drop(exc)

    def close(self):
        if self._handler is not None:
            try:
                self._handler.close()
            except Exception:
                pass
            self._handler = None


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Relay log lines from a file or stdin to a syslog server (RFC 5424).",
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
    parser.add_argument("--framing", choices=("non-transparent", "octet-counting"), default="non-transparent",
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
        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        return sys.stdin
    return open(path, "r", encoding="utf-8", errors="replace")


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    # register custom levels so the handler's priority_map resolves them
    logging.addLevelName(70, "EMERG")
    logging.addLevelName(60, "ALERT")
    logging.addLevelName(25, "NOTICE")

    structured_data = {}
    for spec in args.sd:
        try:
            sd_id, params = parse_sd(spec, args.enterprise_id)
        except ValueError as exc:
            raise SystemExit(f"{PROGRAM}: --sd: {exc}")
        structured_data[sd_id] = params

    if args.proto == "unix":
        address = args.path
        socktype = None
    else:
        address = (args.host, args.port)
        socktype = socket.SOCK_STREAM if args.proto in ("tcp", "tls") else socket.SOCK_DGRAM

    framing = FRAMING_OCTET_COUNTING if args.framing == "octet-counting" else FRAMING_NON_TRANSPARENT

    # library quirk: registered SD ids (timeQuality/origin/meta) hit
    # len(enterprise_id) even when no enterprise id is needed; an empty
    # string keeps them registered without appending an @suffix
    effective_pen = args.enterprise_id
    if effective_pen is None and any(sd_id in REGISTERED_SD_IDS for sd_id in structured_data):
        effective_pen = ""

    def make_handler():
        return Rfc5424SysLogHandler(
            address=address,
            facility=args.facility,
            socktype=socktype,
            framing=framing,
            msg_as_utf8=not args.no_utf8_bom,
            hostname=args.hostname or None,
            appname=args.appname or "",
            procid=args.procid or "",
            structured_data=structured_data or None,
            enterprise_id=effective_pen,
            utc_timestamp=args.utc,
            timeout=args.timeout,
            tls_enable=args.proto == "tls",
            tls_ca_bundle=args.tls_ca,
            tls_verify=not args.tls_no_verify,
            tls_client_cert=args.tls_client_cert,
            tls_client_key=args.tls_client_key,
            tls_key_password=args.tls_key_password,
        )

    sender = SyslogSender(make_handler, verbose=args.verbose,
                          max_length=args.max_length, msgid=args.msgid,
                          level=SEVERITY_TO_LOGGING[args.severity])

    exit_code = 0
    try:
        stream = open_input(args.file)
        try:
            for line in iter(stream.readline, ""):
                line = line.rstrip("\r\n")
                if not line:
                    continue
                sender.send(line)
        finally:
            if stream is not sys.stdin:
                stream.close()
    except KeyboardInterrupt:
        exit_code = 130
    finally:
        sender.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
