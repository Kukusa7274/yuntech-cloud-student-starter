"""W4 offline contract checks. No AWS calls, no classroom answers.

Every event-shaped request is built from a file in tests/fixtures/ on purpose:
if the test suite stops reading those files it is no longer checking the
student's fixtures. `test_fixtures_are_actually_read` enforces that.
"""
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
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


class ProductionEntryPoint(unittest.TestCase):
    """Every other test calls make_server() directly, which is NOT how the host
    starts the service: on the box systemd runs `python3 app/service.py`, and the
    tokens arrive through EnvironmentFile. A suite that never exercises that path
    passes while the deployed service answers 401 to everything."""

    def test_tokens_are_read_from_the_systemd_environment(self):
        self.assertEqual(
            service.tokens_from_environment({"REPORTER_TOKEN": "r", "OPERATOR_TOKEN": "o"}),
            {"reporter": "r", "operator": "o"})
        self.assertEqual(service.tokens_from_environment({}),
                         {"reporter": "", "operator": ""})

    def test_running_the_module_wires_the_environment_into_the_server(self):
        import shutil
        import socket
        import subprocess
        import tempfile
        import time
        import urllib.request

        # Mirror the server: ThreadingHTTPServer sets allow_reuse_address, so a
        # port left in TIME_WAIT by a previous run is still bindable. Without this
        # the probe would wrongly report "busy" and silently skip the one test
        # that covers the production start-up path.
        probe = socket.socket()
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", 8080))
        except OSError:
            self.skipTest("port 8080 is genuinely busy in this environment")
        finally:
            probe.close()

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        app = Path(tmp.name) / "app"
        app.mkdir()
        shutil.copy(ROOT / "app/service.py", app / "service.py")
        (app / "version").write_text("d" * 40 + "\n")

        environ = {"PATH": os.environ["PATH"], "REPORTER_TOKEN": "r-from-env",
                   "OPERATOR_TOKEN": "o-from-env"}
        child = subprocess.Popen([sys.executable, str(app / "service.py")], env=environ,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(child.wait)
        self.addCleanup(child.terminate)
        try:
            body = None
            for _ in range(40):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=2) as response:
                        body = json.load(response)
                    break
                except OSError:
                    time.sleep(0.25)
            self.assertIsNotNone(body, "service.py did not answer /health when run as __main__")
            self.assertIs(body["auth_configured"], True)
            self.assertEqual(body["version"], "d" * 40)
        finally:
            child.terminate()
            child.wait(timeout=5)


class DeployCommandQuoting(unittest.TestCase):
    """ssh concatenates its argv and the REMOTE shell re-parses the result.

    An unquoted fragment such as "a && b" arrives as `sh -c a && b`, so `b` runs
    outside the privileged shell as the unprivileged login user. That is how the
    first deploy attempt failed: mkdir ran as ec2-user and the token file never
    landed, while the script reported the install as successful.
    """

    def _what_the_remote_shell_would_run(self, fragment, quote=True):
        import os
        import subprocess
        import tempfile
        sys.path.insert(0, str(ROOT / "deploy"))
        deploy = importlib.import_module("deploy_aws")
        joined = " ".join(["sudo", "sh", "-c", deploy.shq(fragment) if quote else fragment])
        with tempfile.TemporaryDirectory() as td:
            # The outer shell opens `cat > ...` before running anything, so the
            # target directory has to exist or the probe fails for the wrong reason.
            for part in fragment.replace("&&", " ").split():
                if part.startswith("/"):
                    Path(part).parent.mkdir(parents=True, exist_ok=True)
            # Stub every command the fragment names, so the unquoted variant -- which
            # really does run mkdir/cat in the OUTER shell -- has no side effects and
            # its structure can be inspected instead of blowing up on /etc.
            for name in ("sudo", "mkdir", "cat"):
                stub = Path(td) / name
                stub.write_text(f'#!/bin/sh\nprintf "{name}"; for a in "$@"; do printf " [%s]" "$a"; done\n'
                                'printf "\\n"\n', encoding="utf-8")
                stub.chmod(0o755)
            env = dict(os.environ, PATH=td + os.pathsep + os.environ["PATH"])
            done = subprocess.run(["sh", "-c", joined], capture_output=True, text=True, env=env)
            redirected = any(Path(part).exists()
                             for part in fragment.replace("&&", " ").split()
                             if part.startswith("/") and not Path(part).is_dir())
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip().splitlines(), redirected

    def _fragment(self, tmp):
        return f"umask 077 && mkdir -p {tmp}/inspection && cat > {tmp}/inspection/app.env"

    def test_quoted_fragment_arrives_as_one_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            received, redirected = self._what_the_remote_shell_would_run(self._fragment(tmp))
        self.assertEqual(len(received), 1, received)
        self.assertTrue(received[0].startswith("sudo [sh] [-c] ["), received)
        self.assertIn(f"cat > {tmp}/inspection/app.env", received[0])
        self.assertFalse(redirected, "quoted form still let the outer shell redirect")

    def test_the_unquoted_form_escapes_the_privileged_shell(self):
        # Guards against shq() being removed as "unnecessary". Without the quoting
        # the outer shell runs mkdir and cat itself, as the unprivileged user.
        with tempfile.TemporaryDirectory() as tmp:
            received, redirected = self._what_the_remote_shell_would_run(self._fragment(tmp),
                                                                        quote=False)
        self.assertGreater(len(received), 1, "unquoted form no longer escapes; revisit shq()")
        self.assertTrue(any(line.startswith("mkdir ") for line in received), received)
        self.assertTrue(redirected, "the outer shell performed the redirect itself")


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
