# cert-monitor

A tool that checks TLS certificate expiry for a list of hosts, keeps a
history of every check in SQLite, alerts admins by email and Slack before
certificates lapse, and shows everything on a web dashboard with admin and
viewer accounts. Admins acknowledge alerts, and unacknowledged urgent ones
escalate. It can also search Certificate Transparency logs to find hosts
you aren't monitoring and certificates you didn't request.

Run it with cron on a server, or with [Docker Compose](#docker-compose).

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

### Clean up old history

```bash
# delete checks older than 90 days (the default)
python cert_monitor.py prune --keep-days 90
```

Each target's most recent check is always kept, even if it's older than
the cutoff, so targets you've stopped checking still show on the
dashboard. Sent alerts are never deleted, so you keep a full record of who
was told what.

### Exit codes

`check` returns `0` if everything is OK, `1` if something is expiring soon,
and `2` if something is expired, unreachable, or has an invalid chain.

## Web dashboard

The dashboard requires an account, so create one first:

```bash
python cert_monitor.py user add alice --role admin
python cert_monitor.py serve
```

Then open <http://127.0.0.1:8080> and sign in. The dashboard shows the data
that `check` runs record. It doesn't run checks itself.

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
  `GET /api/targets/<host>/<port>` returns one target's history. Scripts can
  sign in with HTTP basic auth, for example
  `curl -u alice https://certs.example.com/api/status`.

### Accounts and roles

There are two roles:

| Role     | Can do                                                   |
|----------|----------------------------------------------------------|
| `viewer` | See everything on the dashboard and use the JSON API     |
| `admin`  | Everything a viewer can, plus acknowledge alerts         |

Manage accounts from the command line on the server:

```bash
python cert_monitor.py user add alice --role admin    # prompts for a password
python cert_monitor.py user add bob --role viewer
python cert_monitor.py user add bob --role admin      # existing user: resets password and role
python cert_monitor.py user list
python cert_monitor.py user remove bob
```

Passwords must be at least 12 characters and are stored as salted scrypt
hashes. For scripts (Docker, provisioning), `--password-stdin` reads the
password from standard input instead of prompting. Changes take effect
immediately: a removed user is signed out on their next request, and a new
role applies straight away.

### Access and security

- **Listening address:** `serve` listens on `127.0.0.1` (this machine only)
  unless you pass `--host`, e.g. `--host 0.0.0.0` to accept connections from
  other machines.
- **HTTPS:** `serve` runs [waitress](https://docs.pylonsproject.org/projects/waitress/),
  a production-ready web server, but it only speaks plain HTTP. If people
  sign in from other machines, put a reverse proxy that handles HTTPS in
  front of it (nginx, Caddy, etc.). Then set `DASHBOARD_SECURE_COOKIES=1` so
  browsers only send the login cookie over HTTPS.
- **Sessions:** a login lasts 12 hours. Set `DASHBOARD_SECRET_KEY` to a long
  random string (e.g. from `python -c "import secrets;
  print(secrets.token_hex(32))"`) so people stay signed in when the server
  restarts. Without it, a random key is generated at each start.
- **Forged requests:** every form includes a CSRF token and the login cookie
  is `SameSite=Lax`, so other websites can't submit actions on a signed-in
  admin's behalf. HTTP basic auth only works on the read-only `/api/` routes.
- **Login throttling:** there is none built in. If the dashboard is reachable
  from the internet, rate-limit `/login` at your reverse proxy.
- **Hostile certificates:** certificate fields come from remote servers, so
  a hostile server could put HTML or script in them. The dashboard
  HTML-escapes every value it displays, and it sends a strict
  Content-Security-Policy header.

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

## Acknowledging and escalating alerts

When an admin sees an alert and starts handling it, they **acknowledge**
it. They can do that from the target's page on the dashboard (with an
optional note, such as a ticket number) or from the command line:

```bash
python cert_monitor.py ack vpn.example.com --note "OPS-123, renewing today"
```

Acknowledging shows everyone who is handling the alert. It also stops the
alert from being **escalated**. To turn escalation on, add
`--escalate-after HOURS` to `check`:

```bash
export ESCALATION_EMAILS=it-manager@example.com
export ESCALATION_SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'   # e.g. a #ops-escalations channel
python cert_monitor.py check --targets-file targets.txt --email --slack --escalate-after 24
```

An alert is escalated when all of these are true:

- **It's urgent:** the certificate is `EXPIRED`, `INVALID_CHAIN`, or
  `UNREACHABLE`, or has `--escalate-within-days` (default 7) or fewer days
  left. Earlier warnings, like the 30-day one, are never escalated.
- **It's been waiting:** the regular alert went out at least
  `--escalate-after` hours ago.
- **Nobody has acknowledged it.**

Escalations go through the same channels you enabled for regular alerts,
but to the escalation contacts instead. Each alert is escalated once.

An acknowledgement covers one alert at one stage. If a certificate moves
on to its next expiry warning (say from 7 days to 3 days) and still hasn't
been renewed, that's a new alert and needs a new acknowledgement.
Similarly, if a problem clears up and later comes back, the old
acknowledgement doesn't carry over.

## Finding certificates in Certificate Transparency logs

Every publicly trusted certificate is recorded in public Certificate
Transparency (CT) logs. `discover` searches those logs through
[crt.sh](https://crt.sh) for your domains and their subdomains:

```bash
python cert_monitor.py discover example.com example.org --targets-file targets.txt
```

```
example.com: 4 unexpired certificate(s) in CT logs
HOSTNAME           STATUS         EXPIRES                    ISSUER
example.com        monitored      2026-11-20T23:59:59+00:00  C=US, O=Let's Encrypt, CN=R11
*.example.com      wildcard       2026-12-01T12:00:00+00:00  C=US, O=DigiCert Inc, CN=DigiCert ...
mail.example.com   NOT MONITORED  2026-10-30T08:14:02+00:00  C=US, O=Let's Encrypt, CN=R11
www.example.com    monitored      2026-11-20T23:59:59+00:00  C=US, O=Let's Encrypt, CN=R11
```

It helps in two ways:

- **Finding hosts you forgot to monitor.** Any hostname with a certificate
  that isn't in your targets file (or already checked) shows as
  `NOT MONITORED`. Add `--add` to append those hostnames to
  `--targets-file`. Wildcard names like `*.example.com` can't be checked
  directly, so they're only listed. Review what `--add` wrote, since not
  every hostname with a certificate serves HTTPS on port 443.
- **Spotting certificates you didn't request.** The first run for a domain
  records every current certificate as a baseline. Each later run reports
  certificates issued since the previous run. If one appears that nobody
  on your team requested, someone may have obtained a certificate for your
  domain to impersonate it. Add `--email` and/or `--slack` to be told about
  each new certificate once. Failed sends are retried on the next run.

`discover` exits with `0` if nothing new was found, `1` if new certificates
appeared, and `2` if a crt.sh lookup failed. A failed lookup records
nothing, so a partial answer is never mistaken for the full list.

crt.sh is a free public service and is often slow or briefly unavailable.
Run `discover` once a day rather than every few minutes, and expect the
occasional failed run. Very large domains may return more results than
crt.sh (or the 50 MB response limit here) can handle.

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
export ESCALATION_EMAILS=it-manager@example.com
EOF
chmod 600 ~/.cert-monitor.env
```

Then add a crontab entry with `crontab -e`:

```cron
# every 6 hours; alerts are only sent when something changes
0 */6 * * * . $HOME/.cert-monitor.env && cd /path/to/cert-monitor && ./venv/bin/python cert_monitor.py check --targets-file targets.txt --email --slack --escalate-after 24 >> cert_monitor.log 2>&1
# daily at 6am, look for new certificates issued for your domains
0 6 * * * . $HOME/.cert-monitor.env && cd /path/to/cert-monitor && ./venv/bin/python cert_monitor.py discover example.com --targets-file targets.txt --email --slack >> cert_monitor.log 2>&1
# weekly on Sunday at 3am, trim history older than 90 days
0 3 * * 0 cd /path/to/cert-monitor && ./venv/bin/python cert_monitor.py prune --keep-days 90 >> cert_monitor.log 2>&1
```

Frequent runs are safe because alerts are deduplicated. More runs just mean
finer-grained history and faster detection of outages.

## Docker Compose

`docker-compose.yml` runs two containers from the same image. Both share a
`data` volume that holds the database:

- **`dashboard`:** the web dashboard, published on the host at
  `127.0.0.1:8080`.
- **`scheduler`:** runs `check` every `CHECK_INTERVAL_SECONDS` (default 6
  hours). Once a day it also runs `discover` for `DISCOVER_DOMAINS` (if
  set) and `prune`.

Setup:

```bash
cd cert-monitor
cp .env.example .env                  # fill in SMTP/Slack settings and DASHBOARD_SECRET_KEY
cp targets.example.txt targets.txt    # list your hosts
docker compose build
docker compose run --rm dashboard python cert_monitor.py user add alice --role admin
docker compose up -d
```

Then open <http://127.0.0.1:8080>. Other commands run inside a container
the same way:

```bash
docker compose exec dashboard python cert_monitor.py history
docker compose exec dashboard python cert_monitor.py ack vpn.example.com --by alice --note "OPS-123"
docker compose exec dashboard python cert_monitor.py user add bob --role viewer
docker compose logs -f scheduler
```

Things to know:

- **Configuration:** `.env` holds your secrets, so keep it out of version
  control (it's already in `.gitignore`). The scheduler's `CHECK_ARGS` and
  `DISCOVER_ARGS` settings are the extra options passed to `check` and
  `discover`, e.g. `--email --slack --escalate-after 24`.
- **Targets file:** `targets.txt` is mounted read-only, and edits take
  effect on the next check. Compose refuses to start if the file doesn't
  exist. For that reason the scheduler never runs `discover --add`: run it
  yourself and review what it appends.
- **Hardening:** both containers run as an unprivileged user with a
  read-only filesystem, no Linux capabilities, and `no-new-privileges`.
  Only the `data` volume and `/tmp` are writable.
- **Remote access:** the dashboard is published on the host's loopback
  only. To reach it from other machines, put an HTTPS reverse proxy in front
  of it and set `DASHBOARD_SECURE_COOKIES=1`.
- **Backups:** everything (history, alerts, accounts, acknowledgements)
  lives in the `data` volume. To take a consistent copy while it's
  running:

  ```bash
  docker compose exec dashboard python -c "import sqlite3; sqlite3.connect('/data/cert_monitor.db').execute(\"VACUUM INTO '/data/backup.db'\")"
  docker compose cp dashboard:/data/backup.db ./cert-monitor-backup.db
  ```

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests start local TLS servers with generated certificates to cover each
status, and use recorded crt.sh responses for discovery, so they don't need
internet access.

## Roadmap

All four planned phases are done:

1. CLI checker with email alerts
2. SQLite history, deduplicated alerts, cron
3. Web dashboard and Slack alerts
4. Certificate Transparency discovery, alert acknowledgement and escalation,
   admin/viewer accounts, history cleanup, Docker Compose packaging

Possible next steps: manage targets from the dashboard instead of a file,
check certificates on non-HTTPS services that upgrade to TLS with STARTTLS
(SMTP, IMAP), and add PagerDuty or Microsoft Teams alert channels.
