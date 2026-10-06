"""W5 offline checks for the durable store.

READ THIS BEFORE TRUSTING IT: there is no PostgreSQL and no RDS here. `psycopg2`
is replaced by a fake driver that keeps the events in a dict, so these tests
prove that service.py DECIDES 201 / 200 / 409 correctly and that it never builds
SQL by string concatenation. They prove nothing about AWS, about TLS, or about the
real database. The real evidence is the five-row idempotency matrix run against
the deployed host (tests/idempotency_matrix.sh).

The fake is deliberately thin: it recognises statements by a distinctive phrase
instead of parsing SQL, and it serialises every statement behind one lock the way
a real server serialises conflicting inserts.
"""
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

spec = importlib.util.spec_from_file_location("w05_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)

REPORTER = "reporter-token-for-offline-tests"
OPERATOR = "operator-token-for-offline-tests"
TOKENS = {"reporter": REPORTER, "operator": OPERATOR}

DB_KWARGS_SEEN = []


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# A fake psycopg2, enough of one to run PostgresStore against.
# --------------------------------------------------------------------------
class FakeDatabase:
    """events table + the four statements PostgresStore issues.

    timestamptz columns come back as timezone-aware datetimes, which is what
    psycopg2 does; returning strings here would let the tests pass while the real
    service failed on a datetime method call.
    """

    def __init__(self):
        self.rows = {}                     # event_id -> tuple(device_id, observed_at, type, note, received_at)
        self.lock = threading.Lock()
        self.statements = []                # (sql, params) every caller ran
        self.tick = 0

    def _received(self):
        self.tick += 1
        return datetime(2026, 10, 6, 1, self.tick, tzinfo=timezone.utc)

    def execute(self, sql, params, cursor):
        with self.lock:
            self.statements.append((sql, params))
            if "CREATE TABLE IF NOT EXISTS" in sql:
                return
            if "ON CONFLICT (event_id) DO NOTHING" in sql:
                event_id, device_id, observed, kind, note = params
                if event_id in self.rows:
                    cursor._row = None      # the primary key refused the write
                    return
                received = self._received()
                self.rows[event_id] = (device_id, observed, kind, note, received)
                cursor._row = (received,)
                return
            if "FROM events WHERE event_id = %s" in sql:
                # SELECT_BY_ID_SQL asks for 5 columns; event_id is the parameter.
                cursor._row = self.rows.get(params[0])
                return
            if "ORDER BY received_at DESC" in sql:
                ordered = sorted(self.rows.items(), key=lambda kv: kv[1][4], reverse=True)
                cursor._rows = [(eid,) + value for eid, value in ordered[:params[0]]]
                return
            raise AssertionError("unexpected statement: " + sql)


class FakeCursor:
    def __init__(self, connection):
        self._connection = connection
        self._row = None
        self._rows = []

    def execute(self, sql, params=None):
        self._connection.database.execute(sql, params, self)

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConnection:
    def __init__(self, database, pool):
        self.database = database
        self.pool = pool

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        pass


class FakePool:
    def __init__(self, database):
        self.database = database
        self.closed = False

    def getconn(self):
        if self.closed:
            raise AssertionError("borrow from a closed pool")
        return FakeConnection(self.database, self)

    def putconn(self, connection, close=False):
        return None

    def closeall(self):
        self.closed = True


def install_fake_driver(database):
    """Register a fake psycopg2 for the duration of one test."""
    import types
    driver = types.ModuleType("psycopg2")
    pool_module = types.ModuleType("psycopg2.pool")

    def threaded_connection_pool(minconn, maxconn, **kwargs):
        DB_KWARGS_SEEN.append(kwargs)
        return FakePool(database)

    pool_module.ThreadedConnectionPool = threaded_connection_pool
    driver.pool = pool_module
    driver.errors = types.ModuleType("psycopg2.errors")
    sys.modules["psycopg2"] = driver
    sys.modules["psycopg2.pool"] = pool_module
    sys.modules["psycopg2.errors"] = driver.errors
    return driver


def remove_fake_driver():
    for name in ("psycopg2", "psycopg2.pool", "psycopg2.errors"):
        sys.modules.pop(name, None)


def postgres_store(database, ca_file="/etc/inspection/rds-ca.pem"):
    install_fake_driver(database)
    config = {"host": "db.example.invalid", "port": 5432, "dbname": "inspection",
              "user": "inspection", "password": "not-a-real-password", "ca_file": ca_file}
    return service.PostgresStore(config, TOKENS)


class DurableStoreBase(unittest.TestCase):
    def setUp(self):
        self.db = FakeDatabase()
        self.store = postgres_store(self.db)
        self.addCleanup(remove_fake_driver)

    def post(self, store, body, token=REPORTER):
        outcome, event = store.insert(body)
        if outcome == "conflict":
            return 409, {"error": "duplicate_event_id", "field": "event_id"}
        return (201 if outcome == "created" else 200), event

    def event(self, event_id="Group8-1-0500", note="巡檢正常"):
        body = load("valid.json")
        body["event_id"] = event_id
        body["note"] = note
        return body


class Idempotency(DurableStoreBase):
    """The W5 rule table: new -> 201, identical repeat -> 200, changed -> 409."""

    def test_first_delivery_is_201(self):
        status, event = self.post(self.store, self.event())
        self.assertEqual(status, 201)
        self.assertEqual(event["event_id"], "Group8-1-0500")
        self.assertIn("received_at", event)

    def test_identical_repeat_is_200_and_keeps_the_original_received_at(self):
        body = self.event()
        first_status, first = self.post(self.store, body)
        second_status, second = self.post(self.store, dict(body))
        self.assertEqual((first_status, second_status), (201, 200))
        self.assertEqual(second["received_at"], first["received_at"],
                         "200 must return the ORIGINAL received_at, proving nothing new was written")
        self.assertEqual(len(self.db.rows), 1, "the repeat must not create a second row")

    def test_same_id_different_note_is_409(self):
        self.post(self.store, self.event(note="巡檢正常"))
        status, _ = self.post(self.store, self.event(note="異常"))
        self.assertEqual(status, 409)
        self.assertEqual(len(self.db.rows), 1)

    def test_same_id_different_device_is_409(self):
        self.post(self.store, self.event())
        other = self.event()
        other["device_id"] = "Group8-d02"
        self.assertEqual(self.post(self.store, other)[0], 409)

    def test_same_instant_written_in_two_timezones_is_the_same_content(self):
        first = self.event()
        first["observed_at"] = "2026-09-29T10:00:00+08:00"
        shifted = self.event()
        shifted["observed_at"] = "2026-09-29T02:00:00Z"   # the same moment, written differently
        self.assertEqual(self.post(self.store, first)[0], 201)
        self.assertEqual(self.post(self.store, shifted)[0], 200,
                         "an identical instant is the same event, not a conflicting one")

    def test_a_null_note_never_reaches_the_store(self):
        """`"note": null` is not the same as omitting note, but it is refused
        earlier: validate_event rejects a null note with 400, so the durable
        store only ever sees an absent note (stored as SQL NULL) or a string.
        Writing this at the store level would be a false test."""
        without = self.event()
        del without["note"]
        self.assertEqual(self.post(self.store, without)[0], 201)
        self.assertIsNone(self.store.get("Group8-1-0500")["note"] if
                          "note" in self.store.get("Group8-1-0500") else None,
                          "an absent note is stored as NULL and omitted from the reply")
        # ... and repeating it identically is still 200.
        self.assertEqual(self.post(self.store, {k: v for k, v in without.items()})[0], 200)

    def test_two_simultaneous_deliveries_produce_exactly_one_row(self):
        # The "check then write" bug: both threads would see 'not there' and both
        # insert. Here the insert is unconditional and the key decides.
        body = self.event("Group8-1-0501")
        results = []
        errors = []
        # Hold both threads inside the store until the last one has arrived: a
        # barrier on the fake database's lock is the closest stand-in for two
        # inserts reaching the server in the same instant.
        hold = threading.Barrier(2)

        def deliver():
            try:
                hold.wait(timeout=10)
                results.append(self.post(self.store, dict(body))[0])
            except Exception as exc:                 # surface it in the assert
                errors.append(exc)

        threads = [threading.Thread(target=deliver) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(errors, [], "a delivery thread raised")
        self.assertEqual(sorted(results), [200, 201], "one winner, one identical repeat")
        self.assertEqual(len(self.db.rows), 1)

    def test_events_survive_a_new_store_object(self):
        """The point of W5: a restart does not lose events. A fresh store over the
        same database still sees them -- this is the in-process stand-in for
        `sudo systemctl restart inspection`."""
        self.post(self.store, self.event("Group8-1-0502"))
        restarted = postgres_store(self.db)
        self.assertEqual(len(restarted.recent(50)), 1)
        self.assertEqual(restarted.get("Group8-1-0502")["event_id"], "Group8-1-0502")
        self.assertEqual(self.post(restarted, self.event("Group8-1-0502"))[0], 200,
                         "after a restart a repeat is still 200, not a second row")


class ParameterisedSql(DurableStoreBase):
    """Review item 1: submitted text is data, never syntax."""

    def test_every_statement_uses_placeholders_not_interpolation(self):
        body = self.event(note="'; DROP TABLE events; --")
        self.post(self.store, body)
        self.post(self.store, dict(body))
        self.store.recent(50)
        self.store.get("Group8-1-0500")
        self.assertTrue(self.db.statements)
        for sql, params in self.db.statements:
            for payload in ("Group8-1-0500", "巡檢", "DROP TABLE"):
                self.assertNotIn(payload, sql,
                                 "a submitted value reached the SQL text instead of a placeholder")
            if "INSERT" in sql:
                self.assertEqual(sql.count("%s"), 5, sql)
                self.assertIsInstance(params, (tuple, list), "parameters must be passed separately")

    def test_the_injected_note_is_stored_as_plain_text(self):
        nasty = "'; DROP TABLE events; --"
        self.post(self.store, self.event(note=nasty))
        stored = self.store.get("Group8-1-0500")
        self.assertEqual(stored["note"], nasty)
        self.assertEqual(len(self.db.rows), 1)

    def test_a_statement_without_parameters_is_only_the_schema(self):
        self.post(self.store, self.event())
        unparameterised = [sql for sql, params in self.db.statements if params is None]
        for sql in unparameterised:
            self.assertIn("CREATE TABLE IF NOT EXISTS", sql)


class TlsIsNotOptional(DurableStoreBase):
    def test_the_connection_demands_verify_full_and_a_ca_file(self):
        self.post(self.store, self.event())
        self.assertTrue(DB_KWARGS_SEEN)
        kwargs = DB_KWARGS_SEEN[0]
        self.assertEqual(kwargs["sslmode"], "verify-full")
        self.assertTrue(kwargs["sslrootcert"].endswith(".pem"))
        self.assertLessEqual(kwargs["connect_timeout"], 10)

    def test_the_default_ca_path_is_the_one_the_packer_installs(self):
        self.assertEqual(service.DB_CA_FILE, "/etc/inspection/rds-ca.pem")


def _guess(exc):
    return service.classify_database_error(exc)


class Diagnosis(DurableStoreBase):
    """The four cases the W5 troubleshooting table asks you to tell apart."""

    def test_each_failure_maps_to_its_own_category(self):
        cases = {
            "certificate verify failed: self signed certificate": "tls_verification_failed",
            "password authentication failed for user": "db_authentication_failed",
            "connection to server at 10.0.1.5 port 5432 timed out": "db_unreachable_timeout",
            "could not connect to server: Connection refused": "db_unreachable",
            'no pg_hba.conf entry for host "10.0.1.5"': "db_unreachable",
            'syntax error at or near "SELCT"': "database_error",
        }
        for message, expected in cases.items():
            self.assertEqual(_guess(Exception(message)), expected, message)

    def test_a_timeout_exception_object_is_classified_as_a_timeout(self):
        self.assertEqual(_guess(TimeoutError("timed out")), "db_unreachable_timeout")

    def test_the_journal_line_names_the_category_but_not_the_message(self):
        secret = "hunter2-not-a-real-password"
        problem = service.DatabaseProblem(
            "db_authentication_failed",
            Exception("FATAL: password authentication failed for user ... password=" + secret))
        import io
        import contextlib
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            service.note_database_problem(problem)
        line = buffer.getvalue()
        self.assertIn("db_authentication_failed", line)
        self.assertIn("Exception", line)
        self.assertNotIn(secret, line, "the driver message can contain the DSN; never log it")

    def test_store_selection_and_health_flag(self):
        complete = {"DB_HOST": "db.example.invalid", "DB_PORT": "5432", "DB_NAME": "inspection",
                    "DB_USER": "inspection", "DB_PASSWORD": "x"}
        self.assertEqual(service.store_from_environment(complete, TOKENS).kind, "postgres")
        for missing in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD"):
            partial = {k: v for k, v in complete.items() if k != missing}
            self.assertIsNone(service.database_config_from_environment(partial),
                              f"a secret missing {missing} must count as unconfigured")
        self.assertEqual(service.store_from_environment({}, TOKENS).kind, "memory")

    def test_health_reports_which_store_is_live(self):
        for environ, expected in (({}, False), ({"DB_HOST": "h", "DB_NAME": "n",
                                                 "DB_USER": "u", "DB_PASSWORD": "p"}, True)):
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            version = Path(tmp.name) / "version"
            version.write_text("c" * 40)
            server = service.make_server(version, port=0, tokens=TOKENS,
                                         store=service.store_from_environment(environ, TOKENS))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            with urllib.request.urlopen(
                    "http://127.0.0.1:" + str(server.server_port) + "/health", timeout=5) as response:
                body = json.load(response)
            self.assertIs(body["db_configured"], expected)
            self.assertIn(body["storage"], ("memory", "postgres"))

    def test_health_never_leaks_the_connection_settings(self):
        store = postgres_store(self.db)
        store.get("Group8-1-0500")
        # Nothing this module ever emits may contain the password.
        import io
        import contextlib
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            store.get("Group8-1-0500")
            store.recent(5)
            store.insert(self.event())
        self.assertNotIn("not-a-real-password", buffer.getvalue())

        # A driver exception raised on the query path carries the DSN in its
        # message; the category line must drop it.
        problem = service.DatabaseProblem("db_authentication_failed",
                                          Exception("password=not-a-real-password rejected"))
        line = io.StringIO()
        with contextlib.redirect_stderr(line):
            service.note_database_problem(problem)
        self.assertNotIn("not-a-real-password", line.getvalue())
        self.assertEqual(store.kind, "postgres")


class UnavailableDatabase(DurableStoreBase):
    """When the database cannot serve a request, the reply says nothing useful
    to an attacker and everything useful to the operator."""

    def test_a_client_sees_only_a_generic_503(self):
        class Broken(service.PostgresStore):
            def _borrow(self):
                raise service.DatabaseProblem("db_authentication_failed",
                                              Exception("password=hunter2 failed"))

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        version = Path(tmp.name) / "version"
        version.write_text("d" * 40)
        store = Broken({"host": "h", "port": 5432, "dbname": "inspection", "user": "u",
                        "password": "hunter2", "ca_file": "/etc/inspection/rds-ca.pem"}, TOKENS)
        server = service.make_server(version, port=0, tokens=TOKENS, store=store)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        request = urllib.request.Request(
            "http://127.0.0.1:" + str(server.server_port) + "/events",
            data=json.dumps(load("valid.json")).encode("utf-8"), method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", "Bearer " + REPORTER)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                status, payload = response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, json.load(exc)

        self.assertEqual(status, 503)
        self.assertEqual(payload, {"error": "database_unavailable"})
        self.assertNotIn("hunter2", json.dumps(payload))
        self.assertNotIn("db_authentication_failed", json.dumps(payload),
                         "the category belongs in journalctl, not in the HTTP reply")

    def test_validation_still_precedes_the_database(self):
        """A malformed event is refused with 400 even when the database is down:
        the body rules are cheaper to check than a connection, and the W4 order
        of checks must not change."""
        class Broken(service.PostgresStore):
            def _borrow(self):
                raise service.DatabaseProblem("db_unreachable_timeout", Exception("timed out"))

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        version = Path(tmp.name) / "version"
        version.write_text("e" * 40)
        server = service.make_server(version, port=0, tokens=TOKENS,
                                     store=Broken({"host": "h", "port": 5432, "dbname": "inspection",
                                                   "user": "u", "password": "p",
                                                   "ca_file": "/etc/inspection/rds-ca.pem"}, TOKENS))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:" + str(server.server_port)

        bad = load("reject_observed_at_naive.json")
        request = urllib.request.Request(base + "/events",
                                         data=json.dumps(bad).encode("utf-8"), method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", "Bearer " + REPORTER)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 400)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            self.assertEqual(json.load(exc)["error"], "observed_at_missing_timezone")

        # ... but authentication still comes before either of them.
        anonymous = urllib.request.Request(base + "/events",
                                           data=json.dumps(bad).encode("utf-8"), method="POST")
        anonymous.add_header("Content-Type", "application/json")
        try:
            urllib.request.urlopen(anonymous, timeout=5)
            self.fail("expected 401")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 401)


if __name__ == "__main__":
    unittest.main()