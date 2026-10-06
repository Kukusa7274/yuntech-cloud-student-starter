#!/usr/bin/env bash
# W5 T2: create the private database tier the inspection service will use.
#
#   deploy/db-up.sh [--yes]
#
# Creates EXACTLY these five things, in this order, and records every ID into
# .local/resources.json immediately after it is created:
#
#   1. two private subnets (/24, non-overlapping, two different AZs)
#   2. one route table that holds ONLY the local route
#   3. one DB subnet group naming both subnets
#   4. one security group SG-db: inbound TCP 5432 from the HOST security group
#   5. one RDS PostgreSQL instance, db.t3.micro, 20 GiB gp3, encrypted,
#      PubliclyAccessible=false, single AZ, database "inspection"
#
# Two rules that are easy to get wrong and are enforced here rather than trusted:
#
#   * "private" means the subnet's own route table has no 0.0.0.0/0 -> igw route.
#     A subnet that is not explicitly associated keeps using the VPC main route
#     table, which in this Lab DOES have an IGW route -- so the subnet would be
#     public despite the name. Every subnet is therefore explicitly associated.
#   * the master password never appears in argv (ps and shell history can read
#     argv), never in stdout, and never in a tracked file. It reaches the AWS CLI
#     through --cli-input-json on a 600 file inside .local/.
#
# NOT created here: NAT gateway, public IP, any IAM change, any change to the
# EC2 instance, its SG, its key pair or the default VPC. Those are W3's and are
# only referenced, never modified.
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
DBENV="$ROOT/.local/db.env"

if [ "$(id -u)" = "0" ]; then
  echo "STOP: do not run this with sudo. sudo changes \$HOME to /root, so the script"
  echo "      would look for the learnerlab AWS profile in the wrong place."
  echo "      Re-run as your normal user:  bash deploy/db-up.sh"
  exit 1
fi

[ -f "$RES" ] || { echo "STOP: missing $RES -- no recorded host to sit beside."; exit 1; }

# Refuse to build a second database tier. Re-running this script after a partial
# failure is how you end up paying for two RDS instances.
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8")); raise SystemExit(0 if "db" in d else 1)' "$RES"; then
  echo "STOP: .local/resources.json already has a \"db\" section -- a database tier exists."
  echo "      Do not re-run this script: it would create a SECOND RDS instance."
  echo "      If your first instance failed mid-creation, fix or delete that instance by ID first."
  exit 1
fi

# The host SG is a *reference*, not a CIDR. Read it from the record, never guess.
if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1],encoding="utf-8")); raise SystemExit(0 if d.get("sg",{}).get("id") else 1)' "$RES"; then
  echo "STOP: .local/resources.json has no host security group id -- cannot scope SG-db."
  echo "      If the W3 host was terminated, rebuild it with deploy/up.sh first."
  exit 1
fi

if [ -e "$DBENV" ]; then
  echo "STOP: $DBENV already exists. Refusing to overwrite a password you may already"
  echo "      have deployed. Remove it yourself ONLY if you are certain no host needs it."
  exit 1
fi

echo "== db-up.sh: resources to CREATE (W5 T2 scope) =="
echo "  Subnets      : two new /24 in $W3_VPC_ID, non-overlapping with existing subnets,"
echo "                 in two different AZs, each explicitly associated to the new route table"
echo "  Route table  : one, local route only (no 0.0.0.0/0 -> igw): that association is what"
echo "                 makes the subnets private"
echo "  DB subnet grp: one, naming both subnets (RDS requires >= 2 AZs to place it)"
echo "  SG-db        : one, INBOUND TCP 5432 ONLY, source = the host SG from resources.json"
echo "                 (a reference to the SG, NOT your IP and NOT 0.0.0.0/0)"
echo "  RDS          : PostgreSQL | db.t3.micro | 20 GiB gp3 | encrypted"
echo "                 PubliclyAccessible=false | single AZ | database 'inspection'"
echo "  Password     : generated here, written to .local/db.env (mode 600), never printed,"
echo "                 never in argv, never committed. NOT reused from any other file."
echo "  Costs        : RDS instance + 20 GiB gp3 storage, billed per official pricing page."
echo "                 Startup takes several minutes (teacher measured ~7.5)."
echo "  NOT created  : no NAT gateway, no public IP, no IAM change, no change to the EC2"
echo "                 instance / its SG / its key pair, nothing deleted."
echo "  Cleanup      : W5 T4 STOPS the instance and the host, it does not delete them."
echo "                 Every ID above is in .local/resources.json; a later deletion must"
echo "                 use those recorded IDs -- by ID, never by name."
echo

if [ "${1:-}" != "--yes" ]; then
  read -r -p "Type YES to proceed: " ans
  if [ "$ans" != "YES" ]; then echo "cancelled; nothing was changed"; exit 1; fi
fi

export W3_REGION W3_GROUP W3_OWNER W3_NAME_PREFIX
export RES_FILE="$RES" DB_ENV_FILE="$DBENV" W3_VPC_ID
python3 "$ROOT/deploy/db_aws.py"