#!/usr/bin/env bash
# W4 T3: install a COMMITTED build onto the SAME host kept from W3.
# This only updates an existing host; it never creates one. If the host is gone
# use deploy/up.sh to rebuild instead.
#
#   deploy/deploy.sh [commit] [--yes]
#
# Pre-flight (all of it runs before any AWS or SSH call):
#   * .local/app.env exists and is mode 600   -> the two tokens
#   * the SSH private key for this group exists
#   * the commit resolves
# The secret is never placed on a command line, never printed, never packed
# into user data and never committed: it reaches the host on SSH stdin only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/.local/w03-config.sh"
if [ ! -f "$CFG" ]; then
  echo "STOP: missing $CFG (T1/W3 config; see deploy/resources.example.md)."
  exit 1
fi
# shellcheck source=/dev/null
source "$CFG"

RES="$ROOT/.local/resources.json"
SECRET="$ROOT/.local/app.env"
UD="$ROOT/.local/w04-user-data.sh"
KEY="$HOME/.ssh/${W3_NAME_PREFIX}_ed25519"

COMMIT="HEAD"
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then COMMIT="$1"; shift; fi

# ---------- pre-flight: refuse to start on a bad state instead of patching it ----------
if [ "$(id -u)" = "0" ]; then
  echo "STOP: do not run this with sudo."
  echo "      sudo changes \$HOME to /root, so the script would look for the SSH key and"
  echo "      the learnerlab AWS profile in the wrong place -- and it would run lab.py as root."
  echo "      Re-run as your normal user:  bash deploy/deploy.sh ${COMMIT}"
  exit 1
fi

[ -f "$RES" ]   || { echo "STOP: missing $RES -- no recorded host to deploy to."; exit 1; }
[ -f "$KEY" ]   || { echo "STOP: missing SSH private key $KEY (private key is never read or printed by the agent)."; exit 1; }
if [ ! -f "$SECRET" ]; then
  echo "STOP: missing .local/app.env -- create REPORTER_TOKEN and OPERATOR_TOKEN first (W4 README)."
  echo "      It must be 600; the deployment moves it to /etc/inspection/app.env over SSH stdin."
  exit 1
fi
SECRET_MODE="$(stat -c '%a' "$SECRET")"
if [ "$SECRET_MODE" != "600" ]; then
  echo "STOP: .local/app.env is mode $SECRET_MODE, not 600. Fix it yourself (chmod 600) and re-run."
  echo "      Not loosening or tightening it automatically -- that hides a real mistake."
  exit 1
fi
git -C "$ROOT" rev-parse --verify --quiet "${COMMIT}^{commit}" >/dev/null \
  || { echo "STOP: '$COMMIT' is not a commit in this repository."; exit 1; }

COMMIT_FULL="$(git -C "$ROOT" rev-parse --verify "${COMMIT}^{commit}")"

IID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["instance"]["id"])' "$RES")"
RECORDED_IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["instance"].get("public_ip") or "(none recorded)")' "$RES")"

echo "== deploy.sh: what will be changed on the EXISTING host =="
echo "  Instance    : $IID   (from .local/resources.json; no other host is touched)"
echo "  Recorded IP : $RECORDED_IP  <- stale after a Stop/Start; the real address is re-queried before any SSH"
echo "  Commit      : $COMMIT  ($COMMIT_FULL)"
echo "              packaging app/service.py + deploy/nginx.conf only, then reinstalling on the host"
echo "  Secret file : .local/app.env (mode 600, contents never shown)"
echo "                -> /etc/inspection/app.env (root, 600) over SSH stdin, then inspection restarted"
echo "  Cost        : none; no resource is created or deleted. Public IPv4 already attached."
echo "  Key         : $KEY  (same ed25519 key pair imported in W3)"
echo
echo "  NOT done: no new instance, no SG/key-pair change, no IAM change, no user-data secret."

if [ "${1:-}" != "--yes" ]; then
  read -r -p "Type YES to proceed: " ans
  if [ "$ans" != "YES" ]; then echo "cancelled; nothing was changed"; exit 1; fi
fi

# make_user_data.py opens its output with exclusive create, so clear it first.
rm -f "$UD"
export W3_REGION SSH_KEY="$KEY" UD_FILE="$UD" RES_FILE="$RES" SECRET_FILE="$SECRET"
export W3_GROUP="$W3_GROUP" W3_OWNER="$W3_OWNER" DEPLOY_COMMIT_FULL="$COMMIT_FULL"
python3 "$ROOT/deploy/deploy_aws.py"
