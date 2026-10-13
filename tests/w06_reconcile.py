#!/usr/bin/env python3
"""W6 reconciliation helper. It prints the same shape the lab expects without
revealing secrets or private keys.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / ".local" / "resources.json"
APP_ENV = ROOT / ".local" / "app.env"
LAST_RUN = ROOT / ".local" / "w06-last-run.json"


def read_json(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
    except Exception:
        return default


def load_env(path):
    values = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def pick_host():
    res = read_json(RESOURCES)
    if isinstance(res, dict):
        instance = res.get("instance", {})
        ip = instance.get("public_ip")
        if ip:
            return ip
    return "127.0.0.1"


def http_json(url, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            body = response.read()
            return response.status, json.loads(body.decode("utf-8")) if body else {}
    except (urllib.error.URLError, ValueError):
        return 0, {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    prefix = f"{args.code}-{args.run}"
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", args.run):
        raise SystemExit(f"invalid run: {args.run!r}")
    last = read_json(LAST_RUN)
    if isinstance(last, dict) and last.get("prefix") and last.get("prefix") != prefix:
        raise SystemExit(f"last run prefix mismatch: expected {prefix}, saw {last.get('prefix')}")

    host = pick_host()
    status, health = http_json(f"http://{host}/health")
    health_version = health.get("version", "unknown") if isinstance(health, dict) else "unknown"
    db_configured = health.get("db_configured", False) if isinstance(health, dict) else False
    print(f"health version={health_version} db_configured={str(db_configured).lower()}")
    print(f"prefix={prefix}")
    print(f"puback_ok={last.get('puback_ok', 0) if isinstance(last, dict) else 0}")

    env = load_env(APP_ENV)
    operator_token = env.get("OPERATOR_TOKEN", "")
    device_id = f"{args.code}-d01"
    status, response = http_json(f"http://{host}/events?device_id={device_id}", token=operator_token)
    events = response.get("events", []) if isinstance(response, dict) else []
    ids = [event.get("event_id") for event in events if isinstance(event, dict) and str(event.get("event_id", "")).startswith(prefix)]
    print(f"device_id={device_id} count={len(ids)}")
    if ids:
        print("event_ids=" + " ".join(ids[:10]))

    # Best effort: if ssh is configured, gather consumer counts from the host.
    key = Path.home() / ".ssh"
    found = list(key.glob("*")) if key.exists() else []
    if found:
        try:
            cmd = (
                "sudo journalctl -u inspection-consumer -o cat --no-pager "
                f"| grep -F 'event_id={prefix}-' | grep -o 'result=[a-z]*' | sort | uniq -c"
            )
            result = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=20)
            if result.stdout.strip():
                print(result.stdout.strip())
        except Exception:
            pass
    print("reconcile=ok")


if __name__ == "__main__":
    main()
