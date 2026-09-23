#!/usr/bin/env python3
"""W3 down.sh AWS core. Handles ONLY IDs from .local/resources.json.
--stop : stop instance and verify stopped.
delete: verify tags -> terminate -> read back instance/EBS/ENI/SG/key pair absent
        -> delete SG + key pair. Uses scripts/lab.py run_aws only."""
import json
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import lab

REGION = os.environ.get("W3_REGION", "us-east-1")


def aw(args):
    return lab.run_aws(args, REGION)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def missing_ok(call):
    """True when AWS reports the resource no longer exists."""
    try:
        call()
        return False
    except lab.LabError as exc:
        return "NotFound" in str(exc)


def save(res, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def main():
    res_path = os.environ["RES_FILE"]
    with open(res_path, encoding="utf-8") as f:
        res = json.load(f)
    mode = os.environ["MODE"]
    iid = res["instance"]["id"]

    lab.verify()

    if mode == "--stop":
        aw(["ec2", "stop-instances", "--instance-ids", iid])
        while True:
            st = aw(["ec2", "describe-instances", "--instance-ids", iid,
                     "--query", "Reservations[0].Instances[0].State.Name"])
            if st == "stopped":
                break
            time.sleep(5)
        res["status"] = "stopped"
        res["stopped_utc"] = now()
        if isinstance(res.get("instance"), dict):
            res["instance"]["state"] = "stopped"  # keep the record consistent with the real state
        save(res, res_path)
        print(f"STOPPED and verified: {iid} is stopped  {now()}")
        return

    # --- delete mode: check tags before terminating ---
    d = aw(["ec2", "describe-instances", "--instance-ids", iid,
            "--query", "Reservations[0].Instances[0]"])
    tags = {t["Key"]: t["Value"] for t in d.get("Tags", [])}
    expected = {"course": "yuntech-115-1", "week": "w03",
                "group": os.environ["W3_GROUP"], "owner": os.environ["W3_OWNER"]}
    if any(tags.get(k) != v for k, v in expected.items()):
        print("STOP: tag mismatch on", iid, tags)
        sys.exit(1)
    print(f"[tags-ok] {iid} matches course/week/group/owner  {now()}")

    # --- terminate and wait ---
    aw(["ec2", "terminate-instances", "--instance-ids", iid])
    print(f"[terminate] {iid}  {now()}")
    while True:
        try:
            st = aw(["ec2", "describe-instances", "--instance-ids", iid,
                     "--query", "Reservations[0].Instances[0].State.Name"])
        except lab.LabError:
            st = "gone"
        if st == "terminated" or st == "gone":
            break
        time.sleep(5)
    print(f"[terminated] {iid}  {now()}")

    # --- read back: five items no longer exist ---
    # AWS keeps a recently-terminated instance readable (State=terminated) for a
    # while; treat 'terminated' as not-existing in addition to a NotFound error.
    def instance_gone(iid):
        try:
            st = aw(["ec2", "describe-instances", "--instance-ids", iid,
                     "--query", "Reservations[0].Instances[0].State.Name"])
            return st == "terminated"
        except lab.LabError as exc:
            return "NotFound" in str(exc)

    inst_gone = instance_gone(iid)
    vol_gone = missing_ok(lambda: aw(["ec2", "describe-volumes", "--volume-ids", res["volume"]["id"]]))
    eni_gone = missing_ok(lambda: aw(["ec2", "describe-network-interfaces",
                                      "--network-interface-ids", res["eni"]["id"]]))
    print(f"[readback1] instance_gone={inst_gone} vol_gone={vol_gone} eni_gone={eni_gone}  {now()}")

    aw(["ec2", "delete-security-group", "--group-id", res["sg"]["id"]])
    print(f"[delete] SG {res['sg']['id']}  {now()}")
    sg_gone = missing_ok(lambda: aw(["ec2", "describe-security-groups",
                                     "--group-ids", res["sg"]["id"]]))

    aw(["ec2", "delete-key-pair", "--key-name", res["keypair"]["name"]])
    print(f"[delete] KeyPair {res['keypair']['name']}  {now()}")
    kp_gone = missing_ok(lambda: aw(["ec2", "describe-key-pairs",
                                     "--key-names", res["keypair"]["name"]]))

    print(f"[readback2] sg_gone={sg_gone} keypair_gone={kp_gone}  {now()}")
    if not (inst_gone and vol_gone and eni_gone and sg_gone and kp_gone):
        print("STOP: some resources still readable; do NOT re-run blindly.")
        sys.exit(1)

    res["status"] = "deleted"
    res["deleted_utc"] = now()
    save(res, res_path)
    print(f"DOWN OK at {now()} (all five read back as absent)")


if __name__ == "__main__":
    main()