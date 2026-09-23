#!/bin/sh
# Runs cert-monitor's periodic jobs in the "scheduler" container: check every
# CHECK_INTERVAL_SECONDS, and discover (if DISCOVER_DOMAINS is set) and prune
# about once a day.
set -u

TARGETS_FILE=${TARGETS_FILE:-/config/targets.txt}
CHECK_INTERVAL_SECONDS=${CHECK_INTERVAL_SECONDS:-21600}
CHECK_ARGS=${CHECK_ARGS:-}
DISCOVER_DOMAINS=${DISCOVER_DOMAINS:-}
DISCOVER_ARGS=${DISCOVER_ARGS:-}
KEEP_DAYS=${KEEP_DAYS:-90}
DAY=86400

if [ ! -f "$TARGETS_FILE" ]; then
    echo "[error] $TARGETS_FILE not found; create targets.txt next to docker-compose.yml" >&2
    exit 1
fi

trap 'echo "[info] scheduler stopping"; exit 0' TERM INT

cd /app
last_daily=0
while true; do
    # Exit codes 1 and 2 mean "something needs attention", not a crash, so
    # they don't stop the loop. CHECK_ARGS etc. are split into words on purpose.
    python cert_monitor.py check --targets-file "$TARGETS_FILE" $CHECK_ARGS

    now=$(date +%s)
    if [ $((now - last_daily)) -ge "$DAY" ]; then
        if [ -n "$DISCOVER_DOMAINS" ]; then
            python cert_monitor.py discover $DISCOVER_DOMAINS --targets-file "$TARGETS_FILE" $DISCOVER_ARGS
        fi
        python cert_monitor.py prune --keep-days "$KEEP_DAYS"
        last_daily=$now
    fi

    # Sleep in the background so a stop signal is handled right away.
    sleep "$CHECK_INTERVAL_SECONDS" &
    wait $!
done
