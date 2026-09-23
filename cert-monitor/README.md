# cert-monitor

A CLI tool that checks TLS certificate expiry for a list of hosts, keeps a
history of every check in SQLite, and emails admins before certificates
lapse. Built to run from cron.

Current state: **Phase 2** (CLI + SQLite history + deduplicated email alerts).
See the [roadmap](#roadmap) for what comes next.

## Install

```bash
cd cert-monitor
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Check certificates

```bash
# check specific hosts (default port 443)
python cert_monitor.py check example.com github.com:8443

# check a list of targets from a file
python cert_monitor.py check --targets-file targets.example.txt

# treat anything within 14 days as "expiring soon" instead of the default 30
python cert_monitor.py check --targets-file targets.example.txt --threshold 14

# email admins about anything that newly needs attention
python cert_monitor.py check --targets-file targets.example.txt --email

# dump full results (issuer, SANs, chain validity, etc.) to JSON
python cert_monitor.py check --targets-file targets.example.txt --json-out results.json
```

Every check is recorded in `cert_monitor.db` in the current directory. Use
`--db /path/to/file.db` to put it somewhere else.

Each target gets one of these statuses:

| Status          | Meaning                                                        |
|-----------------|----------------------------------------------------------------|
| `OK`            | Trusted chain and more than `--threshold` days left            |
| `EXPIRING_SOON` | Trusted chain, `--threshold` days or fewer left                |
| `EXPIRED`       | Past its expiry date                                           |
| `INVALID_CHAIN` | Not expired, but untrusted (self-signed, unknown CA, wrong hostname, ...) |
| `UNREACHABLE`   | DNS failure, connection refused, timeout, or no certificate    |

### View history

```bash
# latest result for every target that has been checked
python cert_monitor.py history

# the last 20 checks for one target
python cert_monitor.py history example.com --limit 20
```

### Exit codes

`check` returns `0` if everything is OK, `1` if something is expiring soon,
and `2` if something is expired, unreachable, or has an invalid chain.

## Email alerts

With `--email`, admins get **one email each time a target moves into a new
alert state**, not one on every run:

- Expiry alerts fire at each tier in `--alert-tiers` (default `30,14,7,3,1`
  days). A cert that has 25 days left triggers the 30-day alert once. It
  won't alert again until it drops to 14 days.
- `EXPIRED`, `UNREACHABLE`, and `INVALID_CHAIN` alert once when they start.
- When a target goes back to `OK` (for example after renewal), its alert
  state resets, so the next problem alerts again.
- If sending fails, nothing is recorded, so the next run retries.

Sent alerts are logged in the `alerts` table.

If you monitor short-lived certificates (for example ones that last only a
few days), lower `--threshold` and `--alert-tiers` to match. Otherwise those
targets will always show as expiring soon.

Set these environment variables before running with `--email`:

| Variable           | Required | Notes                              |
|--------------------|----------|------------------------------------|
| `SMTP_HOST`        | yes      | e.g. `smtp.gmail.com`              |
| `SMTP_PORT`        | no       | default `587` (STARTTLS)           |
| `SMTP_USER`        | no       | omit for unauthenticated relays    |
| `SMTP_PASSWORD`    | no       | omit for unauthenticated relays    |
| `ALERT_FROM_EMAIL` | yes      | sender address                     |
| `ALERT_TO_EMAILS`  | yes      | comma-separated recipient list     |

If `--email` is passed but a required variable is missing, the run prints a
warning and skips sending. The checks themselves still run and are recorded.

## Running on a schedule (cron)

Put the SMTP settings in a file that only you can read, so they're not in
the crontab itself:

```bash
cat > ~/.cert-monitor.env <<'EOF'
export SMTP_HOST=smtp.example.com
export SMTP_USER=alerts@example.com
export SMTP_PASSWORD=change-me
export ALERT_FROM_EMAIL=alerts@example.com
export ALERT_TO_EMAILS=admin1@example.com,admin2@example.com
EOF
chmod 600 ~/.cert-monitor.env
```

Then add a crontab entry with `crontab -e`:

```cron
# every 6 hours; dedup means admins are only emailed when something changes
0 */6 * * * . $HOME/.cert-monitor.env && cd /path/to/cert-monitor && ./venv/bin/python cert_monitor.py check --targets-file targets.txt --email >> cert_monitor.log 2>&1
```

Frequent runs are safe because alerts are deduplicated. More runs just mean
finer-grained history and faster detection of outages.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests start local TLS servers with generated certificates to cover each
status, so they don't need internet access.

## Roadmap

- ~~**Phase 1** — CLI checker with email alerts.~~
- ~~**Phase 2** — SQLite history, deduplicated alerts, cron.~~
- **Phase 3** — FastAPI/Flask dashboard + Slack webhook alerts.
- **Phase 4** — Certificate Transparency log discovery, escalation chains,
  RBAC, history retention/pruning, Docker Compose packaging.
