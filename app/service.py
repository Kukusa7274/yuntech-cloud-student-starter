#!/usr/bin/env python3
"""W4 inspection service: authenticated event intake over a deliberately
in-memory store. A service restart drops every event; W5 makes it durable.

The order of the checks in do_POST / do_GET is load-bearing:
    401 (who are you) -> 403 (may you) -> 400 (is it valid) -> 409 -> 201
A caller with no valid token must not learn the field rules from the reply, so
authentication is decided before the body is even looked at.
"""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import re
import threading

MAX_BODY_BYTES = 4 * 1024
EVENT_TYPES = ("status", "anomaly", "test")
ALLOWED_FIELDS = {"event_id", "device_id", "observed_at", "type", "note"}
REQUIRED_FIELDS = ("event_id", "device_id", "observed_at", "type")
EVENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
DEVICE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
LIST_LIMIT = 50

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
    submitted body.
    """

    def __init__(self, status, error, field=None):
        super().__init__(error)
        self.status = status
        self.error = error
        self.field = field


class Store:
    """W4 is intentionally process-local; see the module docstring."""

    def __init__(self, tokens):
        self.tokens = {role: value or "" for role, value in (tokens or {}).items()}
        self.auth_configured = all(self.tokens.get(role) for role in ("reporter", "operator"))
        self.events = {}
        self.lock = threading.Lock()


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


def make_server(version_file, port=8080, tokens=None):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    store = Store(tokens)
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
                with store.lock:                    # check-and-insert must be atomic
                    if body["event_id"] in store.events:
                        raise Rejected(409, "duplicate_event_id", "event_id")
                    event = dict(body)
                    event["received_at"] = datetime.now(timezone.utc).isoformat(
                        timespec="seconds").replace("+00:00", "Z")
                    store.events[event["event_id"]] = event
                self._send(201, event)              # 4) 201
            except Rejected as exc:
                self._report(exc)

        def do_GET(self):
            route = self.path.split("?", 1)[0]
            try:
                if route == "/health":
                    self._send(200, {"status": "ok", "service": "inspection", "version": version,
                                     "started_at": started,
                                     "auth_configured": store.auth_configured})
                    return
                if route == "/":
                    self._send(200, DISPLAY_PAGE.encode("utf-8"), "text/html; charset=utf-8")
                    return
                if route == "/events":
                    self._require("operator")
                    with store.lock:
                        events = list(store.events.values())[-LIST_LIMIT:]
                    self._send(200, {"count": len(events), "events": events})
                    return
                if route.startswith("/events/"):
                    self._require("operator")
                    with store.lock:
                        event = store.events.get(route[len("/events/"):])
                    if event is None:
                        self._refuse(404, "not_found", "event_id")
                        return
                    self._send(200, event)
                    return
                self._refuse(404, "not_found")
            except Rejected as exc:
                self._report(exc)

        def log_message(self, fmt, *args):
            pass  # Never log request paths, bodies, headers, tokens or query strings.

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
