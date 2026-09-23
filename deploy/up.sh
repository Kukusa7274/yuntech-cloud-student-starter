#!/usr/bin/env bash
# W3 T2/T4: bring up the inspection-service host.
# Creates exactly: 1 SG + 1 imported key pair + 1 EC2 (AL2023 t3.micro, default VPC).
# Records every resource ID into .local/resources.json immediately after creation.
# Ends only after /health returns 200 with version == the deployed commit.
# Usage: deploy/up.sh [--yes]   (prints the plan and asks for confirmation first)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="$ROOT/.local/w03-config.sh"
if [ ! -f "$CFG" ]; then
  echo "STOP: missing $CFG (copy from deploy/resources.example.md guidance; T1 values)."
  exit 1
fi
# shellcheck source=/dev/null
source "$CFG"

RES="$ROOT/.local/resources.json"
UD="$ROOT/.local/w03-user-data.sh"
export W3_RESUME="${W3_RESUME:-}"

if [ "$W3_RESUME" = "1" ]; then
  echo "== up.sh (resume): resources already active; observation continues from layer 2 =="
else
echo "== up.sh: resources to CREATE (W3 scope only, T1-approved plan) =="
echo "  Security group : $W3_NAME_PREFIX-sg   ingress TCP 22,80 from $W3_SOURCE_IP only (no 0.0.0.0/0, no ::/0)"
echo "  Key pair       : $W3_NAME_PREFIX-key  imported ed25519 PUBLIC key (private stays in ~/.ssh)"
echo "  EC2 instance   : $W3_AMI_ID | t3.micro | $W3_SUBNET_ID ($W3_AZ)"
echo "                   root gp3 8GiB encrypted + DeleteOnTermination, IMDSv2 required"
echo "                   tags: course=yuntech-115-1 week=w03 group=$W3_GROUP owner=$W3_OWNER"
echo "  User data      : commit $W3_COMMIT (only app/service.py + deploy/nginx.conf) -> /health version"
echo "  Costs          : EC2 on-demand + EBS gp3 + public IPv4 (official pricing pages)"
fi
if [ "${1:-}" != "--yes" ]; then
  read -r -p "Type YES to proceed: " ans
  if [ "$ans" != "YES" ]; then echo "cancelled"; exit 1; fi
fi

# 1) local ed25519 key; private key never leaves the Codespace / never committed
KEY="$HOME/.ssh/${W3_NAME_PREFIX}_ed25519"
if [ ! -f "$KEY" ]; then
  ssh-keygen -t ed25519 -f "$KEY" -N "" -C "${W3_NAME_PREFIX}-w3" -q
fi
chmod 600 "$KEY"

# 2) package user data from the COMMITTED files (raw script; AWS CLI base64-encodes it)
rm -f "$UD"   # make_user_data.py writes with exclusive create
bash "$ROOT/deploy/make-user-data.sh" "$W3_COMMIT" "$UD"

# 3) AWS core: create + record IDs + five-layer observation + /health verification
#    /health version is the FULL 40-char SHA; resolve it here for the check.
export W3_COMMIT_FULL="$(git -C "$ROOT" rev-parse --verify "${W3_COMMIT}^{commit}")"
export W3_REGION W3_SOURCE_IP W3_GROUP W3_OWNER W3_VPC_ID W3_SUBNET_ID W3_AMI_ID W3_NAME_PREFIX W3_COMMIT
export SSH_KEY="$KEY" UD_FILE="$UD" RES_FILE="$RES"
python3 "$ROOT/deploy/up_aws.py"