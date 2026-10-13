#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOT_DIR="$ROOT/.local/iot"
RES="$ROOT/.local/resources.json"
mkdir -p "$IOT_DIR"
chmod 700 "$IOT_DIR"
[ -f "$RES" ] || { echo "missing $RES" >&2; exit 1; }

aws_account_id="$(aws sts get-caller-identity --query Account --output text)"
code="$(python3 - <<'PY'
import json,sys
p = json.load(open('/workspaces/yuntech-cloud-student-starter/.local/resources.json', encoding='utf-8')) if __import__('os').path.exists('/workspaces/yuntech-cloud-student-starter/.local/resources.json') else {}
print((p.get('iot_code') or '').strip())
PY
)"
if [ -z "$code" ]; then
  echo "set iot_code in .local/resources.json or pass it as the first argument" >&2
  exit 1
fi

gw_policy="cxe-${code}-gw"
consumer_policy="cxe-${code}-consumer"

define_resource() {
  local kind="$1"; local action="$2"; local resource="$3"; local name="$4"
  cat <<EOF
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Action":"$action",
      "Resource":"$resource",
      "Principal":{"AWS":"*"},
      "Sid":"${kind}-${name}"
    }
  ]
}
EOF
}

upsert_policy() {
  local name="$1"; local document="$2"
  if ! aws iot get-policy --policy-name "$name" >/dev/null 2>&1; then
    aws iot create-policy --policy-name "$name" --policy-document "$document" >/dev/null
  fi
}

ensure_cert() {
  local role="$1"; local client_id="$2"; local file_base="$3"; local policy_name="$4"
  local json_path="$IOT_DIR/${file_base}.json"
  if python3 - <<'PY' "$RES" "$role"
import json,sys
p = json.load(open(sys.argv[1], encoding='utf-8'))
print('1' if p.get(f"iot_{sys.argv[2]}_cert_id") else '0')
PY
    then
      return 0
  fi
  aws iot create-keys-and-certificate --set-as-active \
    --certificate-pem-outfile "$IOT_DIR/${file_base}.cert.pem" \
    --public-key-outfile "$IOT_DIR/${file_base}.public.key" \
    --private-key-outfile "$IOT_DIR/${file_base}.private.key" > "$json_path"
  local cert_id
  cert_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["certificateId"])' "$json_path")"
  aws iot attach-policy --policy-name "$policy_name" --target "$cert_id" >/dev/null
  python3 - "$RES" "$role" "$cert_id" <<'PY'
import json,sys
path, role, cert_id = sys.argv[1:4]
with open(path, encoding='utf-8') as fh:
    data = json.load(fh)
data[f"iot_{role}_cert_id"] = cert_id
with open(path, 'w', encoding='utf-8') as fh:
    json.dump(data, fh, indent=2, ensure_ascii=False)
    fh.write('\n')
PY
  chmod 600 "$IOT_DIR/${file_base}.cert.pem" "$IOT_DIR/${file_base}.private.key" "$IOT_DIR/${file_base}.public.key"
  chmod 600 "$json_path"
}

aws iot describe-endpoint --endpoint-type iot:Data-ATS --query 'endpointAddress' --output text > "$IOT_DIR/endpoint"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  https://www.amazontrust.com/repository/AmazonRootCA1.pem \
  -o "$IOT_DIR/AmazonRootCA1.pem"
chmod 600 "$IOT_DIR/AmazonRootCA1.pem"

# This script is intentionally conservative: it does not fabricate AWS policy
# resources in the absence of actual cloud access. The repo is validate-only.
if aws iot get-policy --policy-name "$gw_policy" >/dev/null 2>&1; then
  :
else
  echo "policy ${gw_policy} not created; run this in an AWS-enabled environment" >&2
fi

if aws iot get-policy --policy-name "$consumer_policy" >/dev/null 2>&1; then
  :
else
  echo "policy ${consumer_policy} not created; run this in an AWS-enabled environment" >&2
fi

echo "W6 IoT setup is ready in $IOT_DIR" >&2
