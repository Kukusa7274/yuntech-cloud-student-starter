#!/usr/bin/env python3
"""W5 inspection service: authenticated event intake over a private PostgreSQL
database, so a restart no longer loses events and a repeated delivery no longer
creates a second row.

W4 kept events in a dict inside the process. W5 replaces that with the database,
but only when the database secret is actually present. Two stores therefore
exist, and /health says which one is live:

    PostgresStore  DB_* is set        -> durable, survives a restart
    MemoryStore    DB_* is missing    -> W4 behaviour, events die with the process

The fallback exists because the W5 brief requires the service to keep starting
and reporting 200 when the secret has not reached the host yet (rebuilding a
broken host with up.sh must still pass /health). It is a DEGRADED mode, not an
equivalent one: it keeps the W4 duplicate rule (any repeat is 409) and it loses
events on restart. deploy_aws.py therefore treats db_configured=false after a
successful deployment as a failure rather than a success.

Idempotency is decided by the database, never by a SELECT-then-INSERT in this
process. The insert is attempted unconditionally and the primary key decides;
only AFTER the insert is refused does the service read the stored row back, and
then only to choose between 200 and 409. Two requests arriving at the same
microsecond both attempt the insert, and exactly one wins.

The order of the checks in do_POST / do_GET is still load-bearing:
    401 (who are you) -> 403 (may you) -> 400 (is it valid) -> 409/200 -> 201
A caller with no valid token must not learn the field rules from the reply, so
authentication is decided before the body is even looked at.
"""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import contextlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import threading

MAX_BODY_BYTES = 4 * 1024
EVENT_TYPES = ("status", "anomaly", "test")
ALLOWED_FIELDS = {"event_id", "device_id", "observed_at", "type", "note"}
REQUIRED_FIELDS = ("event_id", "device_id", "observed_at", "type")
EVENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
DEVICE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
LIST_LIMIT = 50
DB_CA_FILE = "/etc/inspection/rds-ca.pem"
DB_CONNECT_TIMEOUT = 5
POOL_MIN = 1
POOL_MAX = 4

# One statement. event_id is the primary key, so the conflict target is the key
# itself and DO NOTHING never overwrites a row. RETURNING tells us whether this
# call was the one that created it -- there is no separate "did it exist?" query
# racing the write.
INSERT_SQL = (
    "INSERT INTO events (event_id, device_id, observed_at, type, note) "
    "VALUES (%s, %s, %s, %s, %s) "
    "ON CONFLICT (event_id) DO NOTHING "
    "RETURNING received_at"
)
SELECT_BY_ID_SQL = (
    "SELECT device_id, observed_at, type, note, received_at "
    "FROM events WHERE event_id = %s"
)
RECENT_SQL = (
    "SELECT event_id, device_id, observed_at, type, note, received_at "
    "FROM events ORDER BY received_at DESC, event_id DESC LIMIT %s"
)
CREATE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    event_id    text PRIMARY KEY,
    device_id   text NOT NULL,
    observed_at timestamptz NOT NULL,
    type        text NOT NULL,
    note        text,
    received_at timestamptz NOT NULL DEFAULT now()
)
"""

DISPLAY_PAGE = """<!doctype html>
<html lang="zh-Hant">
<head><meta charset="utf-8"><title>巡檢事件</title></head>
<body>
<h1>巡檢事件</h1>
<p>貼上 operator 權令牌後讀取清單。權令牌只留在這個頁面的變數裡，不寫進網址、不存進瀏覽器。</p>
<p><input id="tok" type="password" autocomplete="off" size="52" placeholder="operator token">
<button id="load">讀取清單</button></p>
<pre id="out">尚未載入。</pre>
<script>
var out = document.getElementById("out");
document.getElementById("load").addEventListener("click", function () {
  var token = document.getElementById("tok").value;   // 只存在這個頁面變數裡，不寫進網址、不留任何持久儲存
  out.textContent = "載入中…";
  fetch("/events", {headers: {Authorization: "Bearer " + token}})
    .then(function (r) { return r.json().then(function (b) { return {ok: r.ok, code: r.status, body: b}; }); })
    .then(function (res) {
      if (!res.ok) { out.textContent = "HTTP " + res.code + " " + JSON.stringify(res.body); return; }
      var rows = res.body.events.map(function (e) {
        // note 來自別人送來的文字：一律用 textContent，不當成 HTML 解析。
        return e.received_at + "  " + e.event_id + "  " + e.device_id + "  " + e.type
               + (e.note ? "  " + e.note : "");
      });
      out.textContent = rows.length ? rows.join("\\n") : "(尚無事件)";
    })
    .catch(function (err) { out.textContent = "無法連線：" + err.message; });
});
</script>
</body></html>
"""


class Rejected(Exception):
    """A refusal that already carries its status code and a safe message.

    Only `error` and `field` ever reach the client: never a token, never the
    submitted body, never a database connection string.
    """

    def __init__(self, status, error, field=None):
        super().__init__(error)
        self.status = status
        self.error = error
        self.field = field


class DatabaseProblem(Exception):
    """The database could not serve this request.

    Carries a CATEGORY only. The driver's message can contain the connection
    string (which embeds the password), so it is logged as a type name and a
    category and never as text.
    """

    def __init__(self, category, exception=None):
        super().__init__(category)
        self.category = category
        self.exception = exception


def classify_database_error(exc):
    """Map a driver exception to a diagnostic category.

    The W5 troubleshooting table asks for exactly this classification:
    timeout (security group / routing), wrong password (secret file),
    certificate verification failure (CA file / hostname), SQL error (program).
    """
    text = str(exc).lower()
    if "certificate verify failed" in text or "certificate verify" in text:
        return "tls_verification_failed"
    if "password authentication failed" in text or "authentication failed" in text:
        return "db_authentication_failed"
    if "sslrootcert" in text or "sslmode" in text or "no ssl connection" in text:
        return "tls_configuration_error"
    if isinstance(exc, TimeoutError) or "timeout" in text or "timed out" in text:
        return "db_unreachable_timeout"
    if "could not connect" in text or "connection refused" in text or "no route to host" in text:
        return "db_unreachable"
    if "no pg_hba.conf entry" in text:
        return "db_unreachable"
    return "database_error"


def note_database_problem(problem):
    """Write a diagnosable line to the journal -- and nothing else.

    systemd sends stderr to journalctl, which is where the W5 troubleshooting
    section sends you. The category and the exception TYPE are enough to tell
    the four cases apart; the exception message is deliberately dropped because
    psycopg2 puts the DSN, and therefore the password, into some of them.
    """
    kind = type(problem.exception).__name__ if problem.exception is not None else "None"
    print(f"db-error category={problem.category} driver={kind}", file=sys.stderr, flush=True)


def iso(moment):
    """Render an aware datetime the way the W4 contract rendered it."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def as_utc(moment):
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


class MemoryStore:
    """W4 behaviour, kept for the case where the database secret is absent.

    Deliberately NOT durable and deliberately NOT the W5 duplicate rule: a
    repeat here is 409 whatever the content, because that is the W4 contract the
    offline suite checks. /health exposes this state as db_configured=false so a
    deployment that forgot the secret is visible instead of silent.
    """

    kind = "memory"

    def __init__(self, tokens):
        self.tokens = {role: value or "" for role, value in (tokens or {}).items()}
        self.auth_configured = all(self.tokens.get(role) for role in ("reporter", "operator"))
        self.events = {}
        self.lock = threading.Lock()

    def insert(self, body):
        """-> (outcome, payload). outcome is created / same / conflict."""
        with self.lock:
            if body["event_id"] in self.events:
                return "conflict", None
            event = dict(body)
            event["received_at"] = datetime.now(timezone.utc).isoformat(
                timespec="seconds").replace("+00:00", "Z")
            self.events[body["event_id"]] = event
        return "created", event

    def recent(self, limit):
        with self.lock:
            return list(self.events.values())[-limit:]

    def get(self, event_id):
        with self.lock:
            return self.events.get(event_id)


class PostgresStore:
    """Durable store. Every SQL statement is parameterised.

    The connection parameters are assembled once and never formatted into a
    string: psycopg2 takes them as keyword arguments, so the password never
    passes through a log line, a traceback repr or a str() of the config.
    """

    kind = "postgres"

    def __init__(self, config, tokens):
        self.config = dict(config)
        self.tokens = {role: value or "" for role, value in (tokens or {}).items()}
        self.auth_configured = all(self.tokens.get(role) for role in ("reporter", "operator"))
        self._pool = None
        self._pool_lock = threading.Lock()

    def _connection_kwargs(self):
        return {
            "host": self.config["host"],
            "port": self.config["port"],
            "dbname": self.config["dbname"],
            "user": self.config["user"],
            "password": self.config["password"],
            # verify-full encrypts AND checks that the peer really is the RDS
            # instance named in the certificate. Turning this off would make the
            # database reachable by anything that could answer on that address.
            "sslmode": "verify-full",
            "sslrootcert": self.config["ca_file"],
            "connect_timeout": DB_CONNECT_TIMEOUT,
        }

    def _ensure_pool(self):
        pool = self._pool
        if pool is not None:
            return pool
        with self._pool_lock:
            # Re-check inside the lock: two request threads can arrive together.
            if self._pool is None:
                self._pool = self._create_pool()
            return self._pool

    def _create_pool(self):
        """Build the pool, then make sure the table exists.

        Kept separate from _ensure_pool so initialising the schema borrows a
        connection from the finished pool instead of re-entering the lazily
        initialising getter (that would deadlock on a non-reentrant lock).
        """
        try:
            # Imported here, not at module scope: the offline suite and a host
            # without the driver must still be able to import this file and run
            # the memory store.
            import psycopg2
            from psycopg2 import pool as pg_pool
        except ImportError as exc:
            raise DatabaseProblem("driver_missing", exc)
        try:
            pool = pg_pool.ThreadedConnectionPool(POOL_MIN, POOL_MAX,
                                                  **self._connection_kwargs())
        except Exception as exc:                 # the driver raises several types
            raise DatabaseProblem(classify_database_error(exc), exc)
        try:
            with self._borrow_from(pool) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(CREATE_SQL)
                connection.commit()
        except Exception as exc:
            with contextlib.suppress(Exception):
                pool.closeall()
            raise DatabaseProblem(classify_database_error(exc), exc)
        return pool

    @contextlib.contextmanager
    def _borrow_from(self, pool):
        connection = pool.getconn()
        broken = False
        try:
            yield connection
        except Exception:
            # Never hand a half-used or broken connection back to the pool.
            broken = True
            raise
        finally:
            with contextlib.suppress(Exception):
                pool.putconn(connection, close=broken)

    def _borrow(self):
        return self._borrow_from(self._ensure_pool())

    def insert(self, body):
        observed = as_utc(datetime.fromisoformat(body["observed_at"]))
        note = body.get("note")
        event_id = body["event_id"]
        try:
            with self._borrow() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(INSERT_SQL,
                                   (event_id, body["device_id"], observed, body["type"], note))
                    created = cursor.fetchone()
                    if created is None:
                        # The insert lost the race, or the row already existed.
                        # Only now is a read justified: to tell 200 from 409.
                        cursor.execute(SELECT_BY_ID_SQL, (event_id,))
                        stored = cursor.fetchone()
                    else:
                        stored = None
                connection.commit()
        except DatabaseProblem:
            raise
        except Exception as exc:
            raise DatabaseProblem(classify_database_error(exc), exc)

        if created is not None:
            event = dict(body)
            event["received_at"] = iso(created[0])
            return "created", event

        device_id, stored_observed, stored_type, stored_note, received_at = stored
        identical = (
            device_id == body["device_id"]
            and as_utc(stored_observed) == observed
            and stored_type == body["type"]
            and stored_note == note
        )
        if not identical:
            return "conflict", None
        # 200, and the original received_at: proof that nothing new was written.
        event = dict(body)
        event["received_at"] = iso(received_at)
        return "same", event

    def recent(self, limit):
        try:
            with self._borrow() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(RECENT_SQL, (limit,))
                    rows = cursor.fetchall()
                connection.commit()
        except DatabaseProblem:
            raise
        except Exception as exc:
            raise DatabaseProblem(classify_database_error(exc), exc)
        # ASCENDING, like W4's dict order, so the display page reads oldest first.
        return [self._row_to_event(row) for row in reversed(rows)]

    def get(self, event_id):
        try:
            with self._borrow() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(SELECT_BY_ID_SQL, (event_id,))
                    row = cursor.fetchone()
                connection.commit()
        except DatabaseProblem:
            raise
        except Exception as exc:
            raise DatabaseProblem(classify_database_error(exc), exc)
        return None if row is None else self._row_to_event((event_id,) + tuple(row))

    @staticmethod
    def _row_to_event(row):
        event_id, device_id, observed, kind, note, received_at = row
        event = {"event_id": event_id, "device_id": device_id,
                 "observed_at": iso(observed), "type": kind}
        if note is not None:
            event["note"] = note
        event["received_at"] = iso(received_at)
        return event


def database_config_from_environment(environ=None):
    """Return the DB_* settings, or None when the secret is not fully present.

    A partially filled set is treated as absent on purpose: connecting with an
    empty password looks exactly like an authentication failure and costs a
    round of guessing.
    """
    env = os.environ if environ is None else environ
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
    if not all((env.get(name) or "").strip() for name in required):
        return None
    try:
        port = int(env.get("DB_PORT") or 5432)
    except ValueError:
        return None
    return {
        "host": env["DB_HOST"].strip(),
        "port": port,
        "dbname": env["DB_NAME"].strip(),
        "user": env["DB_USER"].strip(),
        "password": env["DB_PASSWORD"],
        "ca_file": (env.get("DB_CA_FILE") or DB_CA_FILE).strip(),
    }


def store_from_environment(environ=None, tokens=None):
    """Pick the durable store when the secret is present, the W4 one otherwise."""
    config = database_config_from_environment(environ)
    if config is None:
        return MemoryStore(tokens)
    return PostgresStore(config, tokens)


def validate_event(body):
    """Return None when the event satisfies the contract, else raise Rejected(400)."""
    if not isinstance(body, dict):
        raise Rejected(400, "body_not_object", "body")
    unexpected = set(body) - ALLOWED_FIELDS
    if unexpected:
        # The problem is the document's shape, not one column, and the offending
        # key is caller-controlled -- do not echo it back.
        raise Rejected(400, "unexpected_field", "body")
    for name in REQUIRED_FIELDS:
        if name not in body:
            raise Rejected(400, "missing_field", name)

    if not isinstance(body["event_id"], str) or not EVENT_ID_RE.fullmatch(body["event_id"]):
        raise Rejected(400, "invalid_event_id", "event_id")
    if not isinstance(body["device_id"], str) or not DEVICE_ID_RE.fullmatch(body["device_id"]):
        raise Rejected(400, "invalid_device_id", "device_id")
    if body["type"] not in EVENT_TYPES:
        raise Rejected(400, "invalid_type", "type")

    observed = body["observed_at"]
    if not isinstance(observed, str):
        raise Rejected(400, "invalid_observed_at", "observed_at")
    try:
        moment = datetime.fromisoformat(observed)
    except ValueError:
        raise Rejected(400, "invalid_observed_at", "observed_at")
    if moment.tzinfo is None:
        # datetime.fromisoformat() does NOT raise on a missing offset; it returns
        # a naive datetime. Checking tzinfo is the only way to catch this.
        raise Rejected(400, "observed_at_missing_timezone", "observed_at")

    if "note" in body:  # `in`, not .get(): an absent note is fine, a null one is not.
        if not isinstance(body["note"], str):
            raise Rejected(400, "invalid_note", "note")
        if len(body["note"]) > 200:
            raise Rejected(400, "note_too_long", "note")


def make_server(version_file, port=8080, tokens=None, store=None):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    if store is None:
        # No store injected -> build one from the environment. The offline suite
        # injects its own and therefore needs no environment at all.
        store = store_from_environment(tokens=tokens)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        # ---------- replies ----------
        def _send(self, status, payload, content_type="application/json; charset=utf-8"):
            data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _refuse(self, status, error, field=None):
            reply = {"error": error}
            if field is not None:
                reply["field"] = field
            self._send(status, reply)

        def _report(self, exc):
            self._refuse(exc.status, exc.error, exc.field)

        # ---------- authentication / authorization ----------
        def _require(self, *allowed_roles):
            header = self.headers.get("Authorization", "")
            token = header[7:].strip() if header.startswith("Bearer ") else ""
            matched = None
            for role, known in store.tokens.items():
                if known and hmac.compare_digest(token, known):
                    matched = role
                    break
            if matched is None:
                raise Rejected(401, "unauthenticated")
            if matched not in allowed_roles:
                raise Rejected(403, "forbidden")
            return matched

        # ---------- body ----------
        def _read_body(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if len(raw) > MAX_BODY_BYTES:
                raise Rejected(400, "body_too_large", "body")
            return raw

        # ---------- routes ----------
        def do_POST(self):
            try:
                if self.path.split("?", 1)[0] != "/events":
                    self._refuse(404, "not_found")
                    return
                self._require("reporter")          # 1) 401 then 403
                raw = self._read_body()             # 2) then only look at the body
                media = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
                if media != "application/json":
                    raise Rejected(400, "unsupported_media_type", "body")
                try:
                    body = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    raise Rejected(400, "malformed_json", "body")
                validate_event(body)               # 3) 400
                # 4) the store decides: the primary key settles whether this is a
                #    first delivery (201), an identical repeat (200) or a
                #    different event wearing an existing id (409).
                outcome, event = store.insert(body)
                if outcome == "conflict":
                    raise Rejected(409, "duplicate_event_id", "event_id")
                self._send(201 if outcome == "created" else 200, event)
            except Rejected as exc:
                self._report(exc)
            except DatabaseProblem as problem:
                # The client learns only that the database is unavailable. The
                # category goes to the journal, never into the reply.
                note_database_problem(problem)
                self._refuse(503, "database_unavailable")

        def do_GET(self):
            route = self.path.split("?", 1)[0]
            try:
                if route == "/health":
                    self._send(200, {"status": "ok", "service": "inspection", "version": version,
                                     "started_at": started,
                                     "auth_configured": store.auth_configured,
                                     "db_configured": store.kind == "postgres",
                                     "storage": store.kind})
                    return
                if route == "/":
                    self._send(200, DISPLAY_PAGE.encode("utf-8"), "text/html; charset=utf-8")
                    return
                if route == "/events":
                    self._require("operator")
                    events = store.recent(LIST_LIMIT)
                    self._send(200, {"count": len(events), "events": events})
                    return
                if route.startswith("/events/"):
                    self._require("operator")
                    event = store.get(route[len("/events/"):])
                    if event is None:
                        self._refuse(404, "not_found", "event_id")
                        return
                    self._send(200, event)
                    return
                self._refuse(404, "not_found")
            except Rejected as exc:
                self._report(exc)
            except DatabaseProblem as problem:
                note_database_problem(problem)
                self._refuse(503, "database_unavailable")

        def log_message(self, fmt, *args):
            pass  # Never log request paths, bodies, headers, tokens or query strings.

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def tokens_from_environment(environ=None):
    """Read the two tokens systemd injects from /etc/inspection/app.env.

    This is the ONLY place that touches the environment. make_server() takes the
    tokens as a parameter, so offline tests need no environment at all and the
    dependency stays injectable.
    """
    env = os.environ if environ is None else environ
    return {"reporter": env.get("REPORTER_TOKEN", ""),
            "operator": env.get("OPERATOR_TOKEN", "")}


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version"),
                tokens=tokens_from_environment()).serve_forever()