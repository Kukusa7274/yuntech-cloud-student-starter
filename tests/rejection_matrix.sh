#!/usr/bin/env bash
# W4 T3: run the 7-row rejection matrix against the deployed host in one pass.
#
#   tests/rejection_matrix.sh
#
# The two tokens are loaded from .local/app.env into shell variables and are
# never printed: no `set -x`, no `cat`, no `echo`. curl only ever receives them
# through a variable expansion, so everything this script prints is safe to paste
# into the report.
#
# The address comes from .local/resources.json, which deploy.sh rewrites on every
# successful deployment. Rows 1 and 5 share one event_id on purpose: 409 only
# holds while the service process still remembers it (in-memory store, W4).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RES="$ROOT/.local/resources.json"
SECRET="$ROOT/.local/app.env"
SCRATCH="$ROOT/.local/rejection-matrix"

[ -f "$RES" ]    || { echo "STOP: missing $RES -- deploy first."; exit 1; }
[ -f "$SECRET" ] || { echo "STOP: missing $SECRET"; exit 1; }
SECRET_MODE="$(stat -c '%a' "$SECRET")"
[ "$SECRET_MODE" = "600" ] || { echo "STOP: .local/app.env is $SECRET_MODE, not 600"; exit 1; }

IP="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["instance"]["public_ip"])' "$RES")"
[ -n "$IP" ] || { echo "STOP: no public_ip recorded in resources.json"; exit 1; }

# Load tokens into variables only. The file is read line by line, never cat'ed.
REPORTER_TOKEN=""
OPERATOR_TOKEN=""
while IFS='=' read -r name value; do
  case "$name" in
    REPORTER_TOKEN) REPORTER_TOKEN="$value" ;;
    OPERATOR_TOKEN) OPERATOR_TOKEN="$value" ;;
  esac
done < "$SECRET"
if [ -z "$REPORTER_TOKEN" ] || [ -z "$OPERATOR_TOKEN" ]; then
  echo "STOP: $SECRET does not define both tokens"; exit 1
fi

BASE="http://$IP"
mkdir -p "$SCRATCH"
HEALTH_BODY="$(curl -sS --max-time 10 "$BASE/health")"
VERSION="$(printf '%s' "$HEALTH_BODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("version",""))')"
AUTH_OK="$(printf '%s' "$HEALTH_BODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("auth_configured"))')"

if [ -z "$VERSION" ] || [ "$AUTH_OK" != "True" ]; then
  echo "STOP: /health did not report a version with auth_configured=true"
  echo "      $HEALTH_BODY"
  exit 1
fi

echo "== rejection matrix $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
echo "version: $VERSION"
echo "host:    $IP"
echo

FAILURES=0
# row <n> <expected> <description> <method> <path> <token|-> <fixture|->
row() {
  local n="$1" expected="$2" desc="$3" method="$4" path="$5" token="$6" fixture="$7"
  local out="$SCRATCH/body.$n" code body verdict
  local -a args=(-sS --max-time 10 -X "$method" -o "$out" -w '%{http_code}')
  if [ "$token" != "-" ]; then args+=(-H "Authorization: Bearer $token"); fi
  if [ "$fixture" != "-" ]; then
    args+=(-H "Content-Type: application/json" --data-binary "@$ROOT/tests/fixtures/$fixture")
  fi
  if ! code="$(curl "${args[@]}" "$BASE$path")"; then
    code="000"
  fi
  body="$(tr -d '\n' < "$out" 2>/dev/null || true)"
  rm -f "$out"
  if [ "$code" = "$expected" ]; then verdict=""; else verdict="   << UNEXPECTED (want $expected)"; FAILURES=$((FAILURES + 1)); fi
  printf '#%s  %-38s -> %s  %s%s\n' "$n" "$desc" "$code" "${body:-<empty>}" "$verdict"
}

row 1 201 "POST /events  reporter + valid fixture"      POST /events "$REPORTER_TOKEN" valid.json
row 2 401 "POST /events  no token"                      POST /events "-"                valid.json
row 3 403 "POST /events  operator token"                POST /events "$OPERATOR_TOKEN"   valid.json
row 4 400 "POST /events  reporter, no timezone"         POST /events "$REPORTER_TOKEN"   reject_observed_at_naive.json
row 5 409 "POST /events  reporter, repeat of row 1"     POST /events "$REPORTER_TOKEN"   valid.json
row 6 403 "GET  /events   reporter token"               GET  /events  "$REPORTER_TOKEN" "-"
row 7 200 "GET  /events   operator token"               GET  /events  "$OPERATOR_TOKEN" "-"

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "all 7 rows matched the expected status codes"
else
  echo "$FAILURES row(s) differed from the expected status codes -- record the reason in the report"
fi
echo "note: the store is in memory, so row 1 returns 409 on a re-run until the service restarts"
