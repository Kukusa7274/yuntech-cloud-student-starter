#!/usr/bin/env python3
"""Simple MQTT 5 smoke test for the W6 IoT lab.

It is intentionally small and tolerant: the repo does not contain the AWS
identity material, so the script reads the locally generated cert/key files and
prints the MQTT connection and ack codes without requiring the full AWS lab to
be active.
"""
import argparse
import json
import sys
from pathlib import Path

from paho.mqtt import client as mqtt
from paho.mqtt.client import CallbackAPIVersion

ROOT = Path(__file__).resolve().parents[1]
IOT_DIR = ROOT / ".local" / "iot"


def read_text(path):
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def role_files(role):
    if role == "gw":
        return "gw.cert.pem", "gw.private.key"
    return "consumer.cert.pem", "consumer.private.key"


def build_client(role, code):
    cert_name, key_name = role_files(role)
    cert_path = IOT_DIR / cert_name
    key_path = IOT_DIR / key_name
    endpoint = read_text(IOT_DIR / "endpoint")
    if not endpoint:
        raise SystemExit("missing .local/iot/endpoint; run deploy/iot-up.sh first")
    if not cert_path.exists() or not key_path.exists():
        raise SystemExit(f"missing {cert_path.name} or {key_path.name} in .local/iot")
    client_id = f"{role}-{code}" if code else role
    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=client_id)
    client.tls_set(
        ca_certs=str(IOT_DIR / "AmazonRootCA1.pem"),
        certfile=str(cert_path),
        keyfile=str(key_path),
    )
    return client, endpoint


def reason_code_value(value):
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if hasattr(value, "value"):
        return int(value.value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class Runner:
    def __init__(self, role, code, pub_topic=None, sub_topic=None, wait_seconds=5):
        self.role = role
        self.code = code or "demo"
        self.pub_topic = pub_topic
        self.sub_topic = sub_topic
        self.wait_seconds = wait_seconds
        self.client, self.endpoint = build_client(role, self.code)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_subscribe = self.on_subscribe
        self.client.on_publish = self.on_publish
        self.count = 0

    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        print(f"connack={reason_code_value(reason_code)}", flush=True)
        if self.sub_topic:
            client.subscribe(self.sub_topic, qos=1)
        if self.pub_topic:
            payload = json.dumps({"check": "t2", "code": self.code}, separators=(",", ":"))
            client.publish(self.pub_topic, payload=payload, qos=1)

    def on_subscribe(self, client, userdata, mid, reason_codes, properties=None):
        if isinstance(reason_codes, (list, tuple)):
            code = reason_codes[0] if reason_codes else 0
        else:
            code = reason_codes
        print(f"suback={reason_code_value(code)}", flush=True)

    def on_publish(self, client, userdata, mid, reason_code, properties=None):
        self.count += 1
        print(f"puback={reason_code_value(reason_code)}", flush=True)

    def on_message(self, client, userdata, message):
        payload = message.payload.decode("utf-8", errors="replace")
        print(f"recv topic={message.topic} payload={payload}", flush=True)

    def run(self):
        self.client.connect(self.endpoint, 8883, keepalive=60)
        self.client.loop_start()
        try:
            deadline = self.wait_seconds
            end = __import__("time").time() + deadline
            while __import__("time").time() < end:
                if self.pub_topic and self.count:
                    break
                if self.sub_topic:
                    __import__("time").sleep(0.1)
                else:
                    __import__("time").sleep(0.1)
        finally:
            self.client.loop_stop()
        self.client.disconnect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as", dest="role", choices=["gw", "consumer"], required=True)
    parser.add_argument("--pub")
    parser.add_argument("--sub")
    parser.add_argument("--wait", type=int, default=5)
    parser.add_argument("--code", default="")
    args = parser.parse_args()
    if not args.pub and not args.sub:
        parser.error("one of --pub or --sub is required")
    runner = Runner(args.role, args.code, pub_topic=args.pub, sub_topic=args.sub, wait_seconds=args.wait)
    runner.run()


if __name__ == "__main__":
    main()
