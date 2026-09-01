# logrelay

Relay log lines from a file or stdin to a syslog server (RFC 5424).

```bash
tail -f mylog.log | python3 logrelay.py --host 10.0.0.1
```

**Self-contained**: single file, Python 3.10+ standard library only.
Deploy with `scp logrelay.py server:` and run.

## Usage

```bash
# follow a log file and relay to a syslog server
tail -f mylog.log | python3 logrelay.py --host 10.0.0.1

# relay an existing file (reads until EOF, then exits)
python3 logrelay.py /var/log/myapp.log --host logs.example.com

# TCP with octet-counting framing (rsyslog), custom facility/severity
python3 logrelay.py mylog.log --host logs.example.com --proto tcp \
    --framing octet-counting --facility local0 --priority warning

# TLS with a private CA and structured data
python3 logrelay.py mylog.log --host logs.example.com --proto tls \
    --tls-ca /etc/ssl/company-ca.pem --sd 'mydata@32473 env="prod"'
```

Only `--host` is required; everything else has a sensible default.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `file` | `-` (stdin) | input file; `-` reads stdin (use with `tail -f`) |
| `--host` | *required* | syslog server hostname or IP |
| `--port` | `514` | syslog server port |
| `--proto` | `udp` | `udp`, `tcp`, `tls`, or `unix` |
| `--path` | `/dev/log` | unix socket path (with `--proto unix`) |
| `-f`, `--facility` | `user` | facility: name (`kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0`-`local7`) or `0`-`23` |
| `-p`, `--priority`, `--severity` | `info` | severity: name (`emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`) or `0`-`7` |
| `--hostname` | local hostname | HOSTNAME header field |
| `--appname` | `logrelay` | APP-NAME header field |
| `--procid` | current PID | PROCID header field |
| `--msgid` | `-` | MSGID header field |
| `--sd` | none | structured data element, repeatable: `ID [NAME="VALUE" ...]` |
| `--enterprise-id` | none | Private Enterprise Number for SD IDs without `@suffix` |
| `--utc` | off | timestamp in UTC instead of local time |
| `--no-utf8-bom` | BOM on | drop the RFC 5424 UTF-8 BOM from the message |
| `--max-length` | `8192` | truncate outgoing messages (bytes), `0` disables |
| `--framing` | `non-transparent` | RFC 6587 framing for tcp/tls; `octet-counting` |
| `--timeout` | `5` | socket connect/send timeout (seconds) |
| `--tls-ca` | system CAs | CA bundle file for server verification |
| `--tls-no-verify` | off | skip TLS certificate verification |
| `--tls-client-cert` / `--tls-client-key` | none | client cert/key for TLS mutual auth |
| `--tls-key-password` | none | password for the client key |
| `-v`, `--verbose` | off | log each sent message to stderr |

## Behavior

* One syslog message (RFC 5424) per input line; empty lines are skipped.
* Reads stdin incrementally. Works with `tail -f`, `tail -F`, or any
  streaming producer. A file argument is read to EOF.
* **Drop & continue**: on send failure the message is dropped, a warning is
  written to stderr, and streaming continues. Reconnects are throttled
  (2 s cooldown) so a dead server never blocks the pipe. Exit code stays 0.
* SIGINT (Ctrl-C) exits cleanly with code 130.
* TLS 1.3 session tickets are drained gracefully on close so a fast
  exit/reconnect never aborts the server-side connection.

## Structured data

Each `--sd` argument defines one SD-ELEMENT: an ID (optionally `name@pen`)
followed by `NAME="VALUE"` parameters:

```bash
--sd 'mydata@32473 iut="3" event="login"' --sd 'origin ip="10.0.0.1"'
--sd 'meta sequence="1"'                     # registered id, no PEN needed
--sd 'env="prod"' --enterprise-id 32473      # pen given via flag
```

## Deployment

```bash
scp logrelay.py user@server:/usr/local/bin/logrelay.py
ssh user@server 'tail -f /var/log/app.log | python3 /usr/local/bin/logrelay.py --host 10.0.0.1'
```

Requirements on the target: any Python >= 3.10 (`python3` on all modern
distros).

## Receiving side examples

rsyslog (`/etc/rsyslog.d/60-relay.conf`):

```conf
module(load="imudp")
input(type="imudp" port="514")            # UDP
module(load="imptcp")
input(type="imptcp" port="514")           # TCP (non-transparent framing)
```

Quick manual check on the wire:

```bash
nc -ul 514        # UDP
nc -l 514         # TCP (non-transparent framing, one message per line)
```

## Tests

Use [uv](https://docs.astral.sh/uv/) to set up the test environment:

```bash
uv sync            # creates .venv with the dev group installed
```

`tests/` contains a wire-format receiver, differential tests against the
`rfc5424-logging-handler` reference implementation (kept in
`tests/logrelay_library.py`), truncation unit tests, TLS transport tests and
streaming/resilience tests:

```bash
python tests/test_truncate.py       # message truncation unit tests
python tests/difftest.py            # wire format vs reference implementation
python tests/test_tls_direct.py     # TLS transports (needs OpenSSL for certs)
python tests/test_stream.py         # streaming, dead server, recovery
```

Each script is standalone and prints `ALL OK` on success (non-zero exit on
failure). `tests/receiver.py` is a minimal standalone syslog receiver for
manual testing (`udp|tcp|tls PORT OUTFILE [cert key]`).
