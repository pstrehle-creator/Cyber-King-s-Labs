import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import cert_monitor
import storage
from cert_monitor import CertCheckResult

TIERS = [30, 14, 7, 3, 1]
T0 = "2026-01-01T00:00:00+00:00"


class Recorder:
    """Stands in for urlopen, recording each JSON payload posted."""

    def __init__(self, fail=False):
        self.fail = fail
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request.full_url, json.loads(request.data)))
        if self.fail:
            raise urllib.error.URLError("down")
        return mock.MagicMock()

    @property
    def payloads(self):
        return [payload for _, payload in self.requests]


def _result(status, days=None, host="example.com", **extra):
    return CertCheckResult(hostname=host, port=443, status=status, days_remaining=days, **extra)


class TeamsTests(unittest.TestCase):
    URL = "https://example.webhook.office.com/workflows/abc"

    def _send(self, alerts, recorder, env=None):
        env = {"TEAMS_WEBHOOK_URL": self.URL} if env is None else env
        with mock.patch.dict("os.environ", env, clear=True), \
                mock.patch("cert_monitor.urllib.request.urlopen", recorder), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            return cert_monitor.send_alert_teams(alerts)

    def test_posts_adaptive_card_with_plain_text_lines(self):
        recorder = Recorder()
        hostile = _result("INVALID_CHAIN", error="bad cert [click here](https://phish.example) **urgent**")
        self.assertTrue(self._send([(hostile, "INVALID_CHAIN")], recorder))

        url, payload = recorder.requests[0]
        self.assertEqual(url, self.URL)
        self.assertEqual(payload["type"], "message")
        attachment = payload["attachments"][0]
        self.assertEqual(attachment["contentType"], "application/vnd.microsoft.card.adaptive")
        card = attachment["content"]
        self.assertEqual(card["type"], "AdaptiveCard")
        title, *lines = card["body"]
        self.assertEqual(title["text"], "cert-monitor: 1 certificate(s) need attention")
        self.assertTrue(all(block["type"] == "RichTextBlock" for block in lines))
        runs = [run for block in lines for run in block["inlines"]]
        self.assertTrue(all(run["type"] == "TextRun" for run in runs))
        text = "\n".join(run["text"] for run in runs)
        self.assertIn("example.com:443: INVALID_CHAIN", text)
        self.assertIn("[click here](https://phish.example)", text)
        self.assertNotIn("phish", title["text"])

    def test_requires_https_webhook(self):
        for env in ({}, {"TEAMS_WEBHOOK_URL": "http://example.webhook.office.com/x"}):
            recorder = Recorder()
            self.assertFalse(self._send([(_result("EXPIRED", -1), "EXPIRED")], recorder, env))
            self.assertEqual(recorder.requests, [])

    def test_failed_post_returns_false(self):
        self.assertFalse(self._send([(_result("EXPIRED", -1), "EXPIRED")], Recorder(fail=True)))


class PagerDutyTriggerTests(unittest.TestCase):
    def _send(self, alerts, recorder, env=None):
        env = {"PAGERDUTY_ROUTING_KEY": "R0UT1NGKEY"} if env is None else env
        with mock.patch.dict("os.environ", env, clear=True), \
                mock.patch("cert_monitor.urllib.request.urlopen", recorder), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            return cert_monitor.send_alert_pagerduty(alerts)

    def test_one_event_per_target(self):
        recorder = Recorder()
        alerts = [
            (_result("EXPIRED", -2, host="vpn.example.com", not_after="2026-01-01T00:00:00+00:00"), "EXPIRED"),
            (_result("EXPIRING_SOON", 12, host="www.example.com"), "EXPIRING_SOON:14"),
            (_result("EXPIRING_SOON", 5, host="api.example.com"), "EXPIRING_SOON:7"),
            (_result("UNREACHABLE", host="mail.example.com", error="timed out"), "UNREACHABLE"),
        ]
        self.assertTrue(self._send(alerts, recorder))
        self.assertTrue(all(url == cert_monitor.PAGERDUTY_EVENTS_URL for url, _ in recorder.requests))
        events = {e["dedup_key"]: e for e in recorder.payloads}
        self.assertEqual(len(events), 4)

        vpn = events["cert-monitor:vpn.example.com:443"]
        self.assertEqual(vpn["routing_key"], "R0UT1NGKEY")
        self.assertEqual(vpn["event_action"], "trigger")
        self.assertEqual(vpn["payload"]["severity"], "critical")
        self.assertEqual(vpn["payload"]["source"], "vpn.example.com:443")
        self.assertIn("EXPIRED, -2 days left", vpn["payload"]["summary"])
        self.assertEqual(vpn["payload"]["custom_details"]["not_after"], "2026-01-01T00:00:00+00:00")

        severities = {k.split(":")[1]: e["payload"]["severity"] for k, e in events.items()}
        self.assertEqual(severities["www.example.com"], "warning")
        self.assertEqual(severities["api.example.com"], "error")
        self.assertEqual(severities["mail.example.com"], "error")

    def test_eu_endpoint(self):
        recorder = Recorder()
        env = {"PAGERDUTY_ROUTING_KEY": "k", "PAGERDUTY_EVENTS_URL": "https://events.eu.pagerduty.com/v2/enqueue"}
        self._send([(_result("EXPIRED", -1), "EXPIRED")], recorder, env)
        self.assertEqual(recorder.requests[0][0], "https://events.eu.pagerduty.com/v2/enqueue")

    def test_missing_routing_key(self):
        recorder = Recorder()
        self.assertFalse(self._send([(_result("EXPIRED", -1), "EXPIRED")], recorder, env={}))
        self.assertEqual(recorder.requests, [])

    def test_any_failure_is_reported(self):
        self.assertFalse(self._send([(_result("EXPIRED", -1), "EXPIRED")], Recorder(fail=True)))


class PagerDutyResolveTests(unittest.TestCase):
    def setUp(self):
        self.conn = storage.connect(":memory:")
        self.target_id = storage.upsert_target(self.conn, "example.com", 443)
        self.env = mock.patch.dict("os.environ", {"PAGERDUTY_ROUTING_KEY": "k"}, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.conn.close()

    def _run(self, status, days=None):
        """One check run's PagerDuty work, as cmd_check does it."""
        result = _result(status, days)
        alerts = cert_monitor.find_new_alerts(self.conn, [(self.target_id, result)], TIERS, ["pagerduty"])
        for target_id, _, key in alerts["pagerduty"]:
            storage.record_alert(self.conn, target_id, key, "pagerduty", T0)
        return [key for _, _, key in alerts["pagerduty"]]

    def _resolve(self, recorder):
        with mock.patch("cert_monitor.urllib.request.urlopen", recorder), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            cert_monitor.resolve_pagerduty_incidents(self.conn)
        return [p for p in recorder.payloads if p["event_action"] == "resolve"]

    def _log(self):
        return [(r["alert_key"], r["channel"]) for r in storage.target_alerts(self.conn, self.target_id, 10)]

    def test_recovery_resolves_the_incident_once(self):
        self.assertEqual(self._run("EXPIRED", -1), ["EXPIRED"])
        self.assertEqual(self._resolve(Recorder()), [])

        self._run("OK", 80)
        self.assertIsNone(storage.active_alert(self.conn, self.target_id))
        resolves = self._resolve(Recorder())
        self.assertEqual(resolves, [{"routing_key": "k", "event_action": "resolve", "dedup_key": "cert-monitor:example.com:443"}])
        self.assertEqual(self._log()[0], ("RESOLVED", "pagerduty"))

        self._run("OK", 80)
        self.assertEqual(self._resolve(Recorder()), [])

    def test_failed_resolve_is_retried(self):
        self._run("UNREACHABLE")
        self._run("OK", 80)
        self.assertEqual(len(self._resolve(Recorder(fail=True))), 1)
        self._run("OK", 80)
        self.assertEqual(len(self._resolve(Recorder())), 1)
        self.assertEqual(self._resolve(Recorder()), [])

    def test_breaking_again_before_the_resolve_cancels_it(self):
        self._run("UNREACHABLE")
        self._run("OK", 80)
        self._resolve(Recorder(fail=True))
        self.assertEqual(self._run("EXPIRED", -1), ["EXPIRED"])
        self.assertEqual(self._resolve(Recorder()), [])

    def test_removed_host_incident_is_resolved(self):
        self._run("EXPIRED", -1)
        storage.remove_target(self.conn, self.target_id, "alice", T0)
        self.assertIsNone(storage.active_alert(self.conn, self.target_id))
        self.assertEqual(len(self._resolve(Recorder())), 1)

    def test_email_only_recovery_leaves_nothing_pending(self):
        storage.record_alert(self.conn, self.target_id, "EXPIRED", "email", T0)
        storage.clear_alert_state(self.conn, self.target_id)
        self.assertEqual(storage.pending_pagerduty_resolves(self.conn), [])


class CheckCommandChannelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "n.db")

    def tearDown(self):
        self.tmp.cleanup()

    def _main(self, *argv, recorder, env):
        with mock.patch.dict("os.environ", env, clear=True), \
                mock.patch("cert_monitor.urllib.request.urlopen", recorder), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            return cert_monitor.main([*argv, "--db", self.db_path])

    def test_teams_and_pagerduty_from_check(self):
        env = {"TEAMS_WEBHOOK_URL": "https://teams.example/hook", "PAGERDUTY_ROUTING_KEY": "k"}
        recorder = Recorder()
        self._main("check", "127.0.0.1:1", "--teams", "--pagerduty", recorder=recorder, env=env)
        self._main("check", "127.0.0.1:1", "--teams", "--pagerduty", recorder=recorder, env=env)
        urls = [url for url, _ in recorder.requests]
        self.assertEqual(urls.count("https://teams.example/hook"), 1)
        self.assertEqual(urls.count(cert_monitor.PAGERDUTY_EVENTS_URL), 1)

    def test_removing_every_host_still_resolves_incidents(self):
        env = {"PAGERDUTY_ROUTING_KEY": "k"}
        self._main("check", "127.0.0.1:1", "--pagerduty", recorder=Recorder(), env=env)
        self._main("targets", "remove", "127.0.0.1:1", "--by", "alice", recorder=Recorder(), env=env)
        recorder = Recorder()
        self.assertEqual(self._main("check", "--pagerduty", recorder=recorder, env=env), 2)
        self.assertEqual([p["event_action"] for p in recorder.payloads], ["resolve"])

    def test_pagerduty_is_never_used_for_escalation(self):
        conn = storage.connect(self.db_path)
        target_id = storage.upsert_target(conn, "127.0.0.1", 1)
        storage.record_alert(conn, target_id, "UNREACHABLE", "pagerduty", "2020-01-01T00:00:00+00:00")
        conn.commit()
        conn.close()
        recorder = Recorder()
        self._main(
            "check", "127.0.0.1:1", "--pagerduty", "--escalate-after", "1",
            recorder=recorder, env={"PAGERDUTY_ROUTING_KEY": "k"},
        )
        self.assertEqual(recorder.requests, [])


if __name__ == "__main__":
    unittest.main()
