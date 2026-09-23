# cert-monitor (Phase 1)

A CLI tool that checks TLS certificate expiry for a list of hosts and warns
before they lapse. This is Phase 1 of the certificate monitoring app design:
a dependency-light script you can run by hand or from cron. Later phases add
persistence/history, a web dashboard, and multi-channel alerting.

## Install

```bash
cd cert-monitor
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# check specific hosts
python cert_monitor.py example.com github.com:8443

# check a list of targets from a file
python cert_monitor.py --targets-file targets.example.txt

# flag anything expiring within 14 days instead of the default 30
python cert_monitor.py --targets-file targets.example.txt --threshold 14

# also email admins about anything that needs attention
python cert_monitor.py --targets-file targets.example.txt --email

# dump full results (issuer, SANs, chain validity, etc.) to JSON
python cert_monitor.py --targets-file targets.example.txt --json-out results.json
```

Sample output:

```
TARGET                           STATUS            DAYS  NOT AFTER                  ISSUER
------------------------------------------------------------------------------------------
expired.badssl.com               EXPIRED             -3  2015-04-12T23:59:59+00:00  CN=COMODO RSA Domain Validation Secure Server CA
self-signed.badssl.com           INVALID_CHAIN        -  -                          self-signed certificate
example.com                      OK                 120  2026-01-15T23:59:59+00:00  CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
```

### Exit codes

For use in cron/CI: `0` = all OK, `1` = something is expiring soon, `2` =
something is expired, unreachable, or failing chain validation.

## Email alerts

Set these environment variables before running with `--email`:

| Variable          | Required | Notes                                  |
|--------------------|----------|-----------------------------------------|
| `SMTP_HOST`        | yes      | e.g. `smtp.gmail.com`                   |
| `SMTP_PORT`        | no       | default `587`                           |
| `SMTP_USER`        | no       | omit for unauthenticated relays         |
| `SMTP_PASSWORD`    | no       | omit for unauthenticated relays         |
| `ALERT_FROM_EMAIL` | yes      | sender address                          |
| `ALERT_TO_EMAILS`  | yes      | comma-separated recipient list          |

If `--email` is passed but required variables are missing, the script prints
a warning and skips sending rather than failing the whole run.

## Running on a schedule

```cron
# every day at 7am, alert if anything is within 14 days of expiring
0 7 * * * cd /path/to/cert-monitor && ./venv/bin/python cert_monitor.py --targets-file targets.example.txt --threshold 14 --email
```

## Roadmap

- **Phase 2** — persist check history in SQLite, run on cron.
- **Phase 3** — FastAPI/Flask dashboard + Slack webhook alerts.
- **Phase 4** — Certificate Transparency log discovery, escalation chains,
  RBAC, Docker Compose packaging.
