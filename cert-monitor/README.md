# cert-monitor

A tool that checks TLS certificate expiry for a list of hosts, keeps a
history of every check in SQLite, alerts admins by email and Slack before
certificates lapse, and shows everything on a web dashboard. The checks are
built to run from cron.

Current state: **Phase 3** (CLI + SQLite history + email/Slack alerts + web
dashboard). See the [roadmap](#roadmap) for what comes next.

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

## Web dashboard

```bash
python cert_monitor.py serve
```

Then open <http://127.0.0.1:8080>. The dashboard is read-only. It shows the
data that `check` runs record, and it doesn't run checks itself.

- **Status page:** counts for each status, and every target's latest
  result with problems listed first. It reloads every 5 minutes.
- **Target page:** click a target to see its certificate details (subject,
  issuer, SANs, serial, validity dates, chain trust), its last 50 checks, and
  the alerts sent for it. When the serial number changes in the history, the
  certificate was renewed.
- **Stale check warning:** if a target's latest check is older than
  `--stale-hours` (default 24), it gets a "stale" badge. This catches the
  case where the cron job has stopped and the dashboard is showing old
  results.
- **JSON API:** `GET /api/status` returns every target's latest result, and
  `GET /api/targets/<host>/<port>` returns one target's history.

### Access and security

By default the dashboard only accepts connections from this machine
(`127.0.0.1`). To reach it from other machines, set a password and choose
an address to listen on:

```bash
export DASHBOARD_USER=admin            # optional, defaults to "admin"
export DASHBOARD_PASSWORD='a-long-random-password'
python cert_monitor.py serve --host 0.0.0.0 --port 8080
```

`serve` won't start on a non-local address unless `DASHBOARD_PASSWORD` is
set. When it's set, every page and API call asks for that username and
password (HTTP basic auth).

Basic auth sends the password with every request. `serve` uses Flask's
built-in server, which only speaks plain HTTP, so anyone watching the
network can read the password. If you open the dashboard to other machines,
put a reverse proxy that handles HTTPS in front of it (nginx, Caddy, etc.).

Certificate fields come from remote servers, so a hostile server could put
HTML or script in them. The dashboard HTML-escapes every value it displays,
and it sends a strict Content-Security-Policy header.

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

## Slack alerts

With `--slack`, the same alerts are posted to a Slack channel through an
[incoming webhook](https://api.slack.com/messaging/webhooks):

```bash
export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'
python cert_monitor.py check --targets-file targets.txt --slack
```

Slack follows the same once-per-state-change rules as email. Each channel
keeps track of what it has already sent, so you can use `--email --slack`
together. If one channel fails, only that channel retries on the next run.

Treat the webhook URL like a password, since anyone who has it can post to
your channel. Text taken from certificates is escaped before posting, so a
hostile server can't put `@channel` pings or disguised links into your
alerts.

## Running on a schedule (cron)

Put the SMTP and Slack settings in a file that only you can read, so they're not in
the crontab itself:

```bash
cat > ~/.cert-monitor.env <<'EOF'
export SMTP_HOST=smtp.example.com
export SMTP_USER=alerts@example.com
export SMTP_PASSWORD=change-me
export ALERT_FROM_EMAIL=alerts@example.com
export ALERT_TO_EMAILS=admin1@example.com,admin2@example.com
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
EOF
chmod 600 ~/.cert-monitor.env
```

Then add a crontab entry with `crontab -e`:

```cron
# every 6 hours; alerts are only sent when something changes
0 */6 * * * . $HOME/.cert-monitor.env && cd /path/to/cert-monitor && ./venv/bin/python cert_monitor.py check --targets-file targets.txt --email --slack >> cert_monitor.log 2>&1
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
- ~~**Phase 3** — Web dashboard + Slack webhook alerts.~~
- **Phase 4** — Certificate Transparency log discovery, escalation chains,
  RBAC, history retention/pruning, Docker Compose packaging.
