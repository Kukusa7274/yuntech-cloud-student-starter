#!/usr/bin/env bash
# W3 T4: release resources recorded in .local/resources.json by EXACT ID only
# (no name-based search, no broad deletes). Tags are checked before terminating.
#   deploy/down.sh --stop [--yes]  : stop instance only, keep everything, verify stopped
#   deploy/down.sh          [--yes] : terminate instance, read back that instance/EBS/ENI/
#                                     SG/key pair no longer exist, then delete SG + key pair
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/.local/w03-config.sh"
if [ ! -f "$CFG" ]; then
  echo "STOP: missing $CFG"; exit 1
fi
# shellcheck source=/dev/null
source "$CFG"

RES="$ROOT/.local/resources.json"
if [ ! -f "$RES" ]; then
  echo "STOP: no $RES (nothing recorded to release)."; exit 1
fi

mode="${1:-}"
case "$mode" in
  --stop)
    echo "== down.sh --stop : will STOP the instance (SG/key pair/volume kept, instance stays stopped) ==" ;;
  "")
    echo "== down.sh : will TERMINATE the instance, then DELETE SG + key pair by recorded ID ==" ;;
  *)
    echo "usage: deploy/down.sh [--stop] [--yes]"; exit 1 ;;
esac

echo "Recorded resources:"
python3 - "$RES" <<'PY'
import json, sys
res = json.load(open(sys.argv[1], encoding="utf-8"))
for key in ("instance", "volume", "eni", "sg", "keypair"):
    if key in res and isinstance(res[key], dict):
        print(f"  {key:8s} {res[key].get('id') or res[key].get('name')}")
print("  status:", res.get("status"))
PY

if [ "${2:-}" != "--yes" ]; then
  read -r -p "Type YES to proceed: " ans
  if [ "$ans" != "YES" ]; then echo "cancelled"; exit 1; fi
fi

export W3_REGION W3_GROUP W3_OWNER MODE="$mode" RES_FILE="$RES"
python3 "$ROOT/deploy/down_aws.py"