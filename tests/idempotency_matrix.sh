#!/usr/bin/env bash
# W5 T3: run the 5-row idempotency matrix against the deployed host in one pass.
#
#   tests/idempotency_matrix.sh
#
#   #1 new event_id                      -> 201
#   #2 identical repeat                  -> 200, no new row
#   #3 same event_id, different note     -> 409
#   #4 after `systemctl restart inspection`, #1 is still there
#   #5 count of #1 in PostgreSQL, via psql on the host -> 1
#
# The output is written to be pasted straight into the report: the opening
# /health version and db_configured, then one line per row with the number, the
# HTTP status and the service's own body, then the psql count.
#
# NOTHING SENSITIVE IS PRINTED: no token, no password, no connection string, no
# request header. The two tokens are read into files under .local/ with mode 600
# and handed to curl through `--config`, never through argv, because argv is
# visible to `ps` on this machine. The database password is never read here at
# all: row #5 runs on the host, where it already lives in /etc/inspection/app.env.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/.local/w03-config.sh"
RES="$ROOT/.local/resources.json"
APPSECRET="$ROOT/.local/app.env"
SCRATCH="$ROOT/.local/idempotency-matrix"

[ -f "$CFG" ]       || { echo "STOP: missing $CFG"; exit 1; }
# shellcheck source=/dev/null
source "$CFG"
[ -f "$RES" ]       || { echo "STOP: missing $RES -- deploy first."; exit 1; }
[ -f "$APPSECRET" ] || { echo "STOP: missing $APPSECRET"; exit 1; }
MODE="$(stat -c '%a' "$APPSECRET")"
[ "$MODE" = "600" ] || { echo "STOP: .local/app.env is $MODE, not 600"; exit 1; }

KEY="$HOME/.ssh/${W3_NAME_PREFIX}_ed25519"
[ -f "$KEY" ] || { echo "STOP: missing SSH key $KEY (rows #4 and #5 need it)."; exit 1; }

# The event id must start with your group code. Override with EVENT_ID=... if the
# row below has already been used for a previous trial run.
EVENT_ID="${EVENT_ID:-Group8-1-0500}"
BASE_NOTE="巡檢矩陣基準事件"

umask 077
mkdir -p "$SCRATCH"

# ---------- read the tokens out of the secret file, into files, never into argv ----------
read -r REPORTER_TOKEN OPERATOR_TOKEN < <(
  awk -F= '
    $1=="REPORTER_TOKEN" {r=substr($0, index($0,"=")+1)}
    $1=="OPERATOR_TOKEN" {o=substr($0, index($0,"=")+1)}
    END {print (r==""?"MISSING":r), (o==""?"MISSING":o)}' "$APPSECRET"
)
if [ "$REPORTER_TOKEN" = "MISSING" ] || [ "$OPERATOR_TOKEN" = "MISSING" ]; then
  echo "STOP: .local/app.env does not define both tokens"; exit 1
fi
# A token containing a quote or a backslash would break the curl config file
# below, so refuse rather than send something subtly wrong.
for token in "$REPORTER_TOKEN" "$OPERATOR_TOKEN"; do
  if [[ "$token" =~ [\"\\] || "$token" == *$'\n'* ]]; then
    echo "STOP: a token contains a quote or a backslash; regenerate your tokens"
    exit 1
  fi
done

printf 'header = "Authorization: Bearer %s"\n' "$REPORTER_TOKEN"  > "$SCRATCH/reporter.cfg"
printf 'header = "Authorization: Bearer %s"\n' "$OPERATOR_TOKEN"   > "$SCRATCH/operator.cfg"
unset REPORTER_TOKEN OPERATOR_TOKEN

RECORDED_IP="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["instance"].get("public_ip") or "")' "$RES")"
IID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["instance"]["id"])' "$RES")"

# Re-query the live address instead of trusting the record. Every Stop/Start
# hands out a new public IPv4, so a value written last week is routinely stale --
# and a stale address looks exactly like a broken service.
# Read-only, through the same lab.run_aws path as every other course call.
IP="$(python3 - "$ROOT" "$IID" <<'PY' 2>/dev/null
import contextlib
import io
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
import lab
with contextlib.redirect_stdout(io.StringIO()):
    ctx = lab.verify()
row = lab.run_aws(["ec2", "describe-instances", "--instance-ids", sys.argv[2],
                   "--query", "Reservations[0].Instances[0].[State.Name,PublicIpAddress]"],
                  ctx["region"])
if not row or row[0] != "running":
    print("")
else:
    print(row[1])
PY
)"
case "$IP" in
  ""|*" "*)
    echo "STOP: could not read a live IPv4 for $IID from describe-instances."
    echo "      (state/address came back as '$IP')"
    echo "      Run scripts/verify-aws.sh, and Start the instance if it is stopped."
    echo "      Do NOT fall back to the recorded address $RECORDED_IP."
    exit 1 ;;
esac
BASE="http://$IP"
[ "$IP" = "$RECORDED_IP" ] || echo "[address] recorded $RECORDED_IP -> live $IP (Stop/Start changes it)"

# The event_id travels on a remote command line in row #5, so it is restricted to
# the same character set the service accepts. Anything else is a typo, not a test.
if ! [[ "$EVENT_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
  echo "STOP: EVENT_ID must match [A-Za-z0-9_-]{1,64}; got '$EVENT_ID'"
  exit 1
fi

# ---------- the opening line of the report ----------
HEALTH="$(curl -sS --max-time 10 "$BASE/health")" || { echo "STOP: no answer from /health at $BASE"; exit 1; }
VERSION="$(printf '%s' "$HEALTH" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("version",""))')"
DB_OK="$(printf '%s' "$HEALTH" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("db_configured"))')"
STORAGE="$(printf '%s' "$HEALTH" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("storage",""))')"

echo "== idempotency matrix $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
echo "version:       $VERSION"
echo "db_configured: $DB_OK   (storage: $STORAGE)"
echo "event_id:      $EVENT_ID"
echo

if [ "$DB_OK" != "True" ]; then
  echo "STOP: db_configured is not true. Rows #4 and #5 cannot pass while the service"
  echo "      runs in its in-memory fallback: events would vanish on restart and"
  echo "      psql would find an empty table. Deploy the DB secret first."
  exit 1
fi

# ---------- body builders: synthetic test data, straight from the fixture ----------
build_body() {   # <event_id> <note>
  python3 -c '
import json,sys
body=json.load(open(sys.argv[1],encoding="utf-8"))
body["event_id"]=sys.argv[2]
body["note"]=sys.argv[3]
print(json.dumps(body,ensure_ascii=False))' "$ROOT/tests/fixtures/valid.json" "$1" "$2"
}

FAILURES=0
row() {   # <number> <expected> <description> <method> <path> <cfg|-> <payload|-> <expect_key|-> <expect_value|->
  local n="$1" expected="$2" desc="$3" method="$4" path="$5" cfg="$6" payload="$7"
  local want_key="${8:--}" want_value="${9:--}"
  local out="$SCRATCH/body.$n" body_in="" code body verdict
  local -a args=(-sS --max-time 15 -X "$method" -o "$out" -w '%{http_code}')
  if [ "$cfg" != "-" ]; then args+=(--config "$cfg"); fi
  if [ "$payload" != "-" ]; then
    # The event body goes in through a file as well: `note` is caller-supplied
    # text, and argv is readable by every process on this machine.
    body_in="$SCRATCH/payload.$n"
    printf '%s' "$payload" > "$body_in"
    args+=(-H 'Content-Type: application/json' --data-binary "@$body_in")
  fi
  code="$(curl "${args[@]}" "$BASE$path")" || code="000"
  body="$(tr -d '\n' < "$out" 2>/dev/null || true)"
  rm -f "$out" "$body_in"
  verdict=""
  if [ "$code" != "$expected" ]; then
    verdict="   << UNEXPECTED (want $expected)"; FAILURES=$((FAILURES + 1))
  elif [ "$want_key" != "-" ]; then
    # Checked without grep: a substring match on the body is not a value match.
    if ! printf '%s' "$body" | python3 -c '
import json,sys
try: doc=json.load(sys.stdin)
except ValueError: sys.exit(1)
sys.exit(0 if str(doc.get(sys.argv[1]))==sys.argv[2] else 1)' "$want_key" "$want_value"; then
      verdict="   << body does not carry $want_key=$want_value"; FAILURES=$((FAILURES + 1))
    fi
  fi
  printf '#%s  %-42s -> %s  %s%s\n' "$n" "$desc" "$code" "${body:-<empty>}" "$verdict"
}

# ---------- rows #1-#3 : the idempotency rule, decided by the primary key ----------
row 1 201 "POST /events  new event_id" POST /events "$SCRATCH/reporter.cfg" \
    "$(build_body "$EVENT_ID" "$BASE_NOTE")" event_id "$EVENT_ID"
row 2 200 "POST /events  identical repeat" POST /events "$SCRATCH/reporter.cfg" \
    "$(build_body "$EVENT_ID" "$BASE_NOTE")" event_id "$EVENT_ID"
row 3 409 "POST /events  same id, different note" POST /events "$SCRATCH/reporter.cfg" \
    "$(build_body "$EVENT_ID" "${BASE_NOTE}（內容已修改）")" -

# ---------- row #4 : restart the service, the event must still be there ----------
echo "#4  restarting inspection ..."
ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes \
    -o ConnectTimeout=15 "ec2-user@$IP" "sudo systemctl restart inspection" >/dev/null
for _ in $(seq 1 20); do
  if curl -sS --max-time 5 "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
row 4 200 "GET  /events/<id> after restart" GET "/events/$EVENT_ID" "$SCRATCH/operator.cfg" - \
    event_id "$EVENT_ID"

# ---------- row #5 : the row only the database can answer ----------
# Runs on the host, where the password already sits in the secret file. The
# password is read into an environment variable there and passed to psql as
# PGPASSWORD, so it never appears in argv here or there.
#
# The remote command is one single-quoted fragment: ssh concatenates argv and the
# REMOTE shell re-parses it, so anything unquoted would be evaluated outside the
# privileged shell (the same trap deploy_aws.py's shq() documents). \$DB_* escapes
# for the local shell only, so the host expands them after sourcing app.env.
echo "#5  counting rows in PostgreSQL on the host ..."
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes
          -o ConnectTimeout=15 "ec2-user@$IP")
REMOTE="sudo bash -c 'set -a; . /etc/inspection/app.env; set +a; PGPASSWORD=\$DB_PASSWORD psql -q -t -A \"host=\$DB_HOST dbname=\$DB_NAME user=\$DB_USER sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem\" -v event_id=\"$EVENT_ID\"'"
SQL="SELECT count(*) FROM events WHERE event_id = :'event_id';"
# SC2029: REMOTE is expanded HERE on purpose -- the command is assembled locally,
# with $DB_* escaped so the host expands them after sourcing app.env.
# shellcheck disable=SC2029
COUNT="$(printf '%s\n' "$SQL" | ssh "${SSH_OPTS[@]}" "$REMOTE" 2>/dev/null | tr -d '[:space:]')"

if [ -z "$COUNT" ]; then
  echo "#5  count query on the host returned nothing"
  echo "      Check on the host: sudo journalctl -u inspection -n 30, and that /etc/inspection/app.env has DB_*"
  FAILURES=$((FAILURES + 1))
else
  verdict=""
  if [ "$COUNT" != "1" ]; then
    verdict="   << UNEXPECTED (want 1)"; FAILURES=$((FAILURES + 1))
  fi
  printf '#5  %-42s -> %s  count=%s%s\n' "psql SELECT count(*) WHERE event_id" "psql" "$COUNT" "$verdict"
fi

rm -f "$SCRATCH/reporter.cfg" "$SCRATCH/operator.cfg"

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "all 5 rows matched the expected results"
else
  echo "$FAILURES row(s) differed -- record the reason in the report rather than editing this output"
fi