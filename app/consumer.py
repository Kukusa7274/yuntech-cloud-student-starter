#!/usr/bin/env python3
"""IoT MQTT consumer that validates device_id against a configured allowlist and
posts accepted events to the local inspection service.
"""
import json
import os
import sys
import time
from urllib import error, request

from paho.mqtt import client as mqtt
from paho.mqtt.client import CallbackAPIVersion


PORT = 8883


def read_env(name, default=""):
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else default


def allowed_devices():
    raw = read_env("IOT_DEVICE_IDS", "")
    if not raw:
        return set()
    values = []
    for part in raw.replace(";", ",").split(","):
        text = part.strip()
        if text:
            values.append(text)
    return set(values)


def post_event(payload):
    token = read_env("REPORTER_TOKEN", "")
    req = request.Request(
        "http://127.0.0.1:8080/events",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=5) as response:
            status = response.getcode()
    except error.HTTPError as exc:
        status = exc.code
    except Exception:
        return "error"
    if status == 201:
        return "created"
    if status == 200:
        return "duplicate"
    if 400 <= status < 500:
        return "rejected"
    return "error"


def get_event_id(payload):
    if not isinstance(payload, dict):
        return "unknown"
    value = payload.get("event_id")
    return str(value) if value is not None else "unknown"


class Consumer:
    def __init__(self):
        self.endpoint = read_env("IOT_ENDPOINT")
        self.topic = read_env("IOT_TOPIC")
        self.client_id = read_env("IOT_CLIENT_ID")
        self.ca_path = read_env("IOT_CA")
        self.cert_path = read_env("IOT_CERT")
        self.key_path = read_env("IOT_KEY")
        self.devices = allowed_devices()
        self.client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=self.client_id)
        self.client.tls_set(ca_certs=self.ca_path, certfile=self.cert_path, keyfile=self.key_path)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_subscribe = self.on_subscribe

    def connect(self):
        self.client.connect(self.endpoint, PORT, keepalive=60)
        self.client.loop_forever()

    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            print(f"connack={reason_code}", flush=True)
            return
        print(f"connack={reason_code}", flush=True)
        result, mid = client.subscribe(self.topic, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            print(f"subscribed rc={result}", flush=True)
            sys.exit(1)

    def on_subscribe(self, client, userdata, mid, reason_codes, properties=None):
        code = reason_codes[0] if isinstance(reason_codes, (list, tuple)) and reason_codes else 0
        print(f"subscribed rc={code}", flush=True)

    def on_message(self, client, userdata, message):
        try:
            payload = json.loads(message.payload.decode("utf-8"))
        except Exception:
            payload = {}
        event_id = get_event_id(payload)
        device_id = payload.get("device_id") if isinstance(payload, dict) else None
        if device_id not in self.devices:
            print(f"event_id={event_id} result=rejected", flush=True)
            return
        result = post_event(payload)
        print(f"event_id={event_id} result={result}", flush=True)


def main():
    if not all((read_env("IOT_ENDPOINT"), read_env("IOT_TOPIC"), read_env("IOT_CLIENT_ID"),
                read_env("IOT_CA"), read_env("IOT_CERT"), read_env("IOT_KEY"))):
        raise SystemExit("missing IOT_* configuration; set the environment before starting consumer")
    consumer = Consumer()
    consumer.connect()


if __name__ == "__main__":
    main()
