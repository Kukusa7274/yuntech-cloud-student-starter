#!/usr/bin/env python3
"""Simulate an IoT gateway emitting 32 device events to the W6 topic."""
import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from paho.mqtt import client as mqtt
from paho.mqtt.client import CallbackAPIVersion

ROOT = Path(__file__).resolve().parents[1]
IOT_DIR = ROOT / ".local" / "iot"
LAST_RUN = ROOT / ".local" / "w06-last-run.json"


def read_text(path):
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def validate(run):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", run):
        raise SystemExit(f"invalid run prefix: {run!r}")


def make_events(code, run):
    prefix = f"{code}-{run}"
    events = []
    for device in [f"{code}-d{n:02d}" for n in range(1, 11)]:
        for index in range(1, 4):
            event_id = f"{prefix}-{device}-{index:02d}"
            events.append({
                "event_id": event_id,
                "device_id": device,
                "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "type": "status",
            })
    events.append(events[0].copy())
    events.append({
        "event_id": f"{prefix}-{code}-d99-01",
        "device_id": f"{code}-d99",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "type": "status",
    })
    return prefix, events


def connect_client(code):
    endpoint = read_text(IOT_DIR / "endpoint")
    cert = IOT_DIR / "gw.cert.pem"
    key = IOT_DIR / "gw.private.key"
    if not endpoint or not cert.exists() or not key.exists():
        raise SystemExit("missing IoT cert/key; run deploy/iot-up.sh first")
    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"gw-{code}")
    client.tls_set(
        ca_certs=str(IOT_DIR / "AmazonRootCA1.pem"),
        certfile=str(cert),
        keyfile=str(key),
    )
    return client, endpoint


class Publisher:
    def __init__(self, code, run):
        self.code = code
        self.run = run
        self.prefix, self.events = make_events(code, run)
        self.client, self.endpoint = connect_client(code)
        self.published = 0
        self.client.on_publish = self.on_publish

    def on_publish(self, client, userdata, mid):
        self.published += 1

    def run(self):
        self.client.connect(self.endpoint, 8883, keepalive=60)
        self.client.loop_start()
        try:
            for event in self.events:
                payload = json.dumps(event, separators=(",", ":"))
                result = self.client.publish(f"cxe/{self.code}/gw/events", payload=payload, qos=1)
                result.wait_for_publish(timeout=20)
            time.sleep(1)
        finally:
            self.client.loop_stop()
            self.client.disconnect()
        LAST_RUN.parent.mkdir(parents=True, exist_ok=True)
        LAST_RUN.write_text(json.dumps({"code": self.code, "run": self.run, "prefix": self.prefix,
                                       "puback_ok": self.published}, indent=2), encoding="utf-8")
        print(f"puback_ok={self.published}/32")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    validate(args.run)
    publisher = Publisher(args.code, args.run)
    publisher.run()


if __name__ == "__main__":
    main()
