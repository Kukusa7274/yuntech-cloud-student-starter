#!/usr/bin/env bash
# Complete local W5 bookkeeping for an already-created RDS instance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/.local/w03-config.sh"
RES="$ROOT/.local/resources.json"
DBENV="$ROOT/.local/db.env"

if [ "$(id -u)" = "0" ]; then
  echo "STOP: do not run this with sudo; use your normal user and learnerlab profile."
  exit 1
fi
[ -f "$CFG" ] || { echo "STOP: missing $CFG."; exit 1; }
[ -f "$RES" ] || { echo "STOP: missing $RES."; exit 1; }
[ -f "$DBENV" ] || { echo "STOP: missing $DBENV; refusing to recreate or guess the password."; exit 1; }
# shellcheck source=/dev/null
source "$CFG"

DBI="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["db"]["rds"]["identifier"])' "$RES")"
echo "== Resume local W5 state for the recorded RDS instance =="
echo "  RDS          : $DBI (read-only describe; no create/modify/delete)"
echo "  Local writes : .local/db.env endpoint and .local/resources.json state only"
echo "  Secret       : existing password preserved; never displayed"
echo "  Cost/network : no AWS resource or exposure change; existing RDS billing continues"
echo "  Cleanup      : none; no AWS resources created"
echo

if [ "${1:-}" != "--yes" ]; then
  if [ "$#" -gt 0 ]; then
    echo "Usage: bash deploy/db-resume.sh [--yes]"
    exit 2
  fi
  read -r -p "Type RESUME to verify AWS and complete local state: " answer
  if [ "$answer" != "RESUME" ]; then
    echo "cancelled; nothing was changed"
    exit 1
  fi
fi

export W3_REGION W3_GROUP W3_OWNER W3_NAME_PREFIX
export RES_FILE="$RES" DB_ENV_FILE="$DBENV" W3_VPC_ID
python3 "$ROOT/deploy/db_aws.py" --recover-existing
