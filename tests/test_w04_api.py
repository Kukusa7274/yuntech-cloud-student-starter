"""W4 offline contract checks. No AWS calls, no classroom answers.

Every event-shaped request is built from a file in tests/fixtures/ on purpose:
if the test suite stops reading those files it is no longer checking the
student's fixtures. `test_fixtures_are_actually_read` enforces that.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

spec = importlib.util.spec_from_file_location("w04_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)

REPORTER = "reporter-token-for-offline-tests"
OPERATOR = "operator-token-for-offline-tests"
TOKENS = {"reporter": REPORTER, "operator": OPERATOR}


def load(name):
    """Read a fixture file. The suite must depend on these files, not on literals."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class ServiceBase(unittest.TestCase):
    def serve(self, tokens=TOKENS):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        version = Path(tmp.name) / "version"
        version.write_text("b" * 40)
        self.server = service.make_server(version, port=0, tokens=tokens)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = "http://127.0.0.1:" + str(self.server.server_port)
        return self

    def call(self, method, path, body=None, token=None, content_type="application/json"):
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", content_type)
        if token is not None:
            request.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def raw(self, path):
        with urllib.request.urlopen(self.base + path) as response:
            return response.status, response.read().decode("utf-8")


class EventContract(ServiceBase):
    def setUp(self):
        self.serve()

    def test_valid_fixture_is_accepted(self):
        status, body = self.call("POST", "/events", load("valid.json"), REPORTER)
        self.assertEqual(status, 201)
        self.assertEqual(body["event_id"], load("valid.json")["event_id"])
        self.assertIn("received_at", body)
        self.assertTrue(body["received_at"].endswith("Z"))

    def test_fixture_without_timezone_is_rejected(self):
        status, body = self.call("POST", "/events", load("reject_observed_at_naive.json"), REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(body["field"], "observed_at")

    def test_fixture_with_space_in_event_id_is_rejected(self):
        status, body = self.call("POST", "/events", load("reject_event_id_space.json"), REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(body["field"], "event_id")

    def test_utc_z_timestamp_is_accepted(self):
        body = load("valid.json")
        body["event_id"] = "Group8-1-0099"
        body["observed_at"] = "2026-09-29T10:00:00Z"
        self.assertEqual(self.call("POST", "/events", body, REPORTER)[0], 201)

    def test_null_note_is_rejected_but_absent_note_is_fine(self):
        body = load("valid.json")
        body["event_id"] = "Group8-1-0098"
        body["note"] = None
        status, reply = self.call("POST", "/events", body, REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(reply["field"], "note")

        body = load("valid.json")
        body["event_id"] = "Group8-1-0097"
        del body["note"]
        self.assertEqual(self.call("POST", "/events", body, REPORTER)[0], 201)

    def test_device_id_limit_is_32_not_64(self):
        body = load("valid.json")
        # Each POST needs its own event_id, otherwise the second call is refused
        # with 409 and the field check under test never runs.
        body["event_id"] = "Group8-1-0096"
        self.assertEqual(self.call("POST", "/events", body, REPORTER)[0], 201)
        body["event_id"] = "Group8-1-0095"
        body["device_id"] = "d" * 32
        self.assertEqual(self.call("POST", "/events", body, REPORTER)[0], 201)
        body["event_id"] = "Group8-1-0094"
        body["device_id"] = "d" * 33
        status, reply = self.call("POST", "/events", body, REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(reply["field"], "device_id")

    def test_unexpected_field_is_rejected_without_echoing_the_key(self):
        body = load("valid.json")
        body["site"] = "A"
        status, reply = self.call("POST", "/events", body, REPORTER)
        self.assertEqual(status, 400)
        self.assertNotIn("site", json.dumps(reply))

    def test_missing_required_field_names_itself(self):
        body = load("valid.json")
        del body["device_id"]
        status, reply = self.call("POST", "/events", body, REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(reply["field"], "device_id")

    def test_bad_type_value_is_rejected(self):
        body = load("valid.json")
        body["type"] = "warning"
        status, reply = self.call("POST", "/events", body, REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(reply["field"], "type")

    def test_body_over_4_kib_is_rejected_before_field_rules(self):
        body = load("valid.json")
        body["note"] = "x" * 5000
        status, reply = self.call("POST", "/events", body, REPORTER)
        self.assertEqual(status, 400)
        self.assertEqual(reply["error"], "body_too_large")

    def test_wrong_content_type_is_rejected(self):
        status, _ = self.call("POST", "/events", load("valid.json"), REPORTER, content_type="text/plain")
        self.assertEqual(status, 400)


class AuthAndOrder(ServiceBase):
    """Review item 1: authenticate first, authorise second, validate last."""

    def setUp(self):
        self.serve()

    def test_missing_token_is_401_even_for_an_invalid_event(self):
        status, _ = self.call("POST", "/events", load("reject_event_id_space.json"))
        self.assertEqual(status, 401)

    def test_unknown_token_is_401(self):
        status, _ = self.call("POST", "/events", load("valid.json"), "not-a-real-token")
        self.assertEqual(status, 401)

    def test_operator_may_not_post(self):
        status, _ = self.call("POST", "/events", load("valid.json"), OPERATOR)
        self.assertEqual(status, 403)

    def test_reporter_may_not_list(self):
        status, _ = self.call("GET", "/events", token=REPORTER)
        self.assertEqual(status, 403)

    def test_duplicate_event_id_is_409_within_one_process(self):
        payload = load("valid.json")
        self.assertEqual(self.call("POST", "/events", payload, REPORTER)[0], 201)
        status, reply = self.call("POST", "/events", payload, REPORTER)
        self.assertEqual(status, 409)
        self.assertEqual(reply["field"], "event_id")

    def test_operator_can_list_and_fetch(self):
        payload = load("valid.json")
        self.call("POST", "/events", payload, REPORTER)
        status, listed = self.call("GET", "/events", token=OPERATOR)
        self.assertEqual(status, 200)
        self.assertEqual(listed["count"], 1)
        status, single = self.call("GET", "/events/" + payload["event_id"], token=OPERATOR)
        self.assertEqual(status, 200)
        self.assertEqual(single["event_id"], payload["event_id"])
        self.assertEqual(self.call("GET", "/events/Group8-1-nope", token=OPERATOR)[0], 404)

    def test_replies_never_echo_the_token_or_the_body(self):
        body = load("reject_observed_at_naive.json")
        marker = "Group8-1-0002"
        status, reply = self.call("POST", "/events", body, "wrong-token")
        self.assertEqual(status, 401)
        rendered = json.dumps(reply, ensure_ascii=False)
        self.assertNotIn("wrong-token", rendered)
        self.assertNotIn(marker, rendered)
        self.assertEqual(sorted(reply), ["error"])


class HealthAndPage(ServiceBase):
    def test_health_reports_auth_configured(self):
        self.serve()
        status, body = self.raw("/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["auth_configured"])

    def test_health_without_tokens_reports_auth_not_configured(self):
        self.serve(tokens=None)
        self.assertFalse(json.loads(self.raw("/health")[1])["auth_configured"])

    def test_display_page_avoids_inner_html_and_browser_storage(self):
        self.serve()
        status, html = self.raw("/")
        self.assertEqual(status, 200)
        for banned in ("innerHTML", "localStorage", "sessionStorage", "?token=", "document.write"):
            self.assertNotIn(banned, html)
        self.assertIn("textContent", html)


class FixturesAreRealInputs(ServiceBase):
    """Review item 4: prove the suite really reads tests/fixtures/."""

    def test_every_fixture_file_is_referenced_by_a_test(self):
        source = Path(__file__).read_text(encoding="utf-8")
        for path in sorted(FIXTURES.glob("*.json")):
            self.assertIn(path.name, source, f"{path.name} is never read by any test")

    def test_changing_the_valid_fixture_changes_the_outcome(self):
        original = (FIXTURES / "valid.json").read_text(encoding="utf-8")
        self.addCleanup((FIXTURES / "valid.json").write_text, original, encoding="utf-8")
        (FIXTURES / "valid.json").write_text(original.replace("Group8-1-0001", "bad id 0001"),
                                            encoding="utf-8")
        self.serve()
        self.assertEqual(self.call("POST", "/events", load("valid.json"), REPORTER)[0], 400)


if __name__ == "__main__":
    unittest.main()
