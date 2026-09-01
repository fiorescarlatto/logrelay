#!/usr/bin/env bash
#
# logrelay.sh - follow log files and relay them to a syslog/rsyslog host
# using logrelay.py (RFC 5424). Designed to run under systemd
# (service/logrelay.service) but works standalone too.
#
# Configure everything in the CONFIG section below, then:
#   sudo systemctl restart logrelay.service
#
set -u -o pipefail

# ================================ CONFIG ===================================

# Absolute path to logrelay.py.
# Default: repo layout (one level up from this script).
LOGRELAY_PY="${LOGRELAY_PY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logrelay.py}"

# Python interpreter on the target machine.
PYTHON="${PYTHON:-python3}"

# Destination syslog/rsyslog server (REQUIRED).
SYSLOG_HOST="${SYSLOG_HOST:-10.0.0.1}"
SYSLOG_PORT="${SYSLOG_PORT:-514}"
SYSLOG_PROTO="${SYSLOG_PROTO:-udp}"        # udp | tcp | tls | unix

# Facility and severity applied to every relayed line (names or numbers,
# see: python3 logrelay.py --help).
FACILITY="${FACILITY:-local0}"
PRIORITY="${PRIORITY:-info}"

# APP-NAME header field. Empty = default ("logrelay"). To set a different
# appname per log file, fill APPNAMES with one entry per LOGFILES entry
# (empty string = default).
APPNAME="${APPNAME:-}"
APPNAMES=()

# Log files to follow; each file gets its own relay pipeline.
# tail -F survives log rotation and files that disappear/reappear.
# TAIL_ARGS default "-n 0 -F" relays only NEW lines; use e.g.
# TAIL_ARGS="-n 100 -F" to also relay the last 100 lines on startup.
LOGFILES=(
    "/var/log/myapp/app.log"
    # "/var/log/myapp/error.log"
)
TAIL_ARGS="${TAIL_ARGS:--n 0 -F}"

# Extra flags passed through to logrelay.py, e.g.:
#   EXTRA_ARGS=(--utc --no-utf8-bom --sd 'mydata@32473 env="prod"')
EXTRA_ARGS=()

# ============================== END CONFIG =================================

die() {
    echo "logrelay.sh: error: $*" >&2
    exit 1
}

[ -n "$SYSLOG_HOST" ] || die "SYSLOG_HOST is not configured - edit $(readlink -f "$BASH_SOURCE" 2>/dev/null || echo "$BASH_SOURCE")"
command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found in PATH"
[ -f "$LOGRELAY_PY" ] || die "logrelay.py not found at: $LOGRELAY_PY"
[ "${#LOGFILES[@]}" -gt 0 ] || die "LOGFILES is empty - edit the CONFIG section"

declare -a children=()

# stop [exit_code]: kill relay pipelines and exit (0 on clean shutdown).
# Each pipeline is `tail | logrelay.py`; the tracked pids are the python
# sides. pkill (best effort, procps) also signals the tail feeds. Under
# systemd the default KillMode=control-group cleans everything up anyway.
stop() {
    trap - TERM INT
    local p
    for p in "${children[@]}"; do
        kill "$p" 2>/dev/null
    done
    if command -v pkill >/dev/null 2>&1; then
        pkill -TERM -P $$ 2>/dev/null
    fi
    wait 2>/dev/null
    exit "${1:-0}"
}
trap 'stop 0' TERM INT

for file in "${LOGFILES[@]}"; do
    if [ ! -e "$file" ]; then
        echo "logrelay.sh: warning: $file does not exist (yet) - tail -F will follow it as soon as it appears" >&2
    elif [ ! -r "$file" ]; then
        echo "logrelay.sh: warning: $file is not readable for uid=$(id -u) - adjust User=/Group= in the unit file" >&2
    fi
done

for i in "${!LOGFILES[@]}"; do
    file="${LOGFILES[$i]}"
    args=(
        --host "$SYSLOG_HOST"
        --port "$SYSLOG_PORT"
        --proto "$SYSLOG_PROTO"
        -f "$FACILITY"
        -p "$PRIORITY"
    )
    if [ "${#APPNAMES[@]}" -gt "$i" ] && [ -n "${APPNAMES[$i]}" ]; then
        args+=(--appname "${APPNAMES[$i]}")
    elif [ -n "$APPNAME" ]; then
        args+=(--appname "$APPNAME")
    fi
    # shellcheck disable=SC2086
    tail $TAIL_ARGS -- "$file" \
        | "$PYTHON" "$LOGRELAY_PY" ${args[@]+"${args[@]}"} \
                    ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} - &
    pid=$!
    children+=("$pid")
    echo "logrelay.sh: relaying $file (pid $pid)" >&2
done

# Supervise: if any relay pipeline dies, stop the others and exit non-zero
# so systemd (Restart=on-failure) restarts the whole service.
# Poll the relay pids (do NOT use `wait -n`: a pipeline job only completes
# when tail exits too, and an idle tail -F never exits on its own).
while :; do
    for pid in "${children[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            rc=$?
            echo "logrelay.sh: relay pipeline (pid $pid) exited rc=$rc - stopping" >&2
            stop "$rc"
        fi
    done
    sleep 2
done
