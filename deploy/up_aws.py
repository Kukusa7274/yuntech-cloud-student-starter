#!/usr/bin/env python3
"""W3 up.sh AWS core. Creates SG + imported key pair + EC2, records IDs to
.local/resources.json after each create, observes the five layers, verifies
/health == 200 with the deployed commit. Uses scripts/lab.py run_aws only.

W3_RESUME=1 : skip creation (resources already active in resources.json) and
resume observation from layer 2. Used when a run was interrupted mid-flight."""
import base64
import json
import os
import subprocess
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


def save(res, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def describe_iid(iid):
    return aw(["ec2", "describe-instances", "--instance-ids", iid,
               "--query", "Reservations[0].Instances[0]"])


def main():
    res_path = os.environ["RES_FILE"]
    resume = os.environ.get("W3_RESUME") == "1"
    lab.verify()

    if resume:
        with open(res_path, encoding="utf-8") as f:
            res = json.load(f)
        if res.get("status") != "active":
            print("STOP: resources.json is not active; cannot resume.")
            sys.exit(1)
        iid = res["instance"]["id"]
        ip = res["instance"].get("public_ip")
        d = describe_iid(iid)
        print(f"[resume] {iid} state={d.get('State', {}).get('Name')} ip={ip}  {now()}")
        print("[resume] creation + L1 + early-curl were recorded in the first run; resume at L2.")
    else:
        if os.path.exists(res_path):
            with open(res_path, encoding="utf-8") as f:
                res = json.load(f)
            if res.get("status") == "active":
                print("STOP: .local/resources.json is active; run deploy/down.sh (or --stop) first.")
                sys.exit(1)
        res = {}

        vpc = os.environ["W3_VPC_ID"]
        subnet = os.environ["W3_SUBNET_ID"]
        ami = os.environ["W3_AMI_ID"]
        prefix = os.environ["W3_NAME_PREFIX"]
        src = os.environ["W3_SOURCE_IP"]
        commit = os.environ.get("W3_COMMIT_FULL") or os.environ["W3_COMMIT"]
        tags = [{"Key": "course", "Value": "yuntech-115-1"},
                {"Key": "week", "Value": "w03"},
                {"Key": "group", "Value": os.environ["W3_GROUP"]},
                {"Key": "owner", "Value": os.environ["W3_OWNER"]}]

        def tag_spec(restype):
            # AWS CLI shorthand: Tags=[{Key=...,Value=...},...] ; literal { } required.
            inner = ",".join("{Key=%s,Value=%s}" % (t["Key"], t["Value"]) for t in tags)
            return "ResourceType=%s,Tags=[%s]" % (restype, inner)

        # --- 1. Security group + ingress (22/80 only, from the /32 only) ---
        sg = aw(["ec2", "create-security-group", "--group-name", prefix + "-sg",
                 "--description", "W3 inspection host " + prefix, "--vpc-id", vpc,
                 "--tag-specifications", tag_spec("security-group")])
        sgid = sg["GroupId"]
        res["sg"] = {"id": sgid, "name": prefix + "-sg"}
        res["created_utc"] = now()
        res["status"] = "active"
        save(res, res_path)
        print(f"[created] SG {sgid}  {now()}")

        perms = [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
                  "IpRanges": [{"CidrIp": src}]} for p in (22, 80)]
        aw(["ec2", "authorize-security-group-ingress", "--group-id", sgid,
            "--ip-permissions", json.dumps(perms)])
        print(f"[ingress] TCP 22,80 <-- {src}  {now()}")

        # --- 2. Import key pair (public key only) ---
        with open(os.environ["SSH_KEY"] + ".pub", encoding="utf-8") as f:
            pub = f.read().strip()
        kp = aw(["ec2", "import-key-pair", "--key-name", prefix + "-key",
                 "--public-key-material", base64.b64encode(pub.encode()).decode(),
                 "--tag-specifications", tag_spec("key-pair")])
        res["keypair"] = {"name": prefix + "-key", "fingerprint": kp.get("KeyFingerprint", "")}
        save(res, res_path)
        print(f"[created] KeyPair {prefix}-key fp={res['keypair']['fingerprint']}  {now()}")

        # --- 3. Instance (raw user-data file; CLI base64-encodes it, do NOT pre-encode) ---
        bdm = json.dumps([{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8, "VolumeType": "gp3",
                                                              "Encrypted": True, "DeleteOnTermination": True}}])
        mdo = json.dumps({"HttpTokens": "required", "HttpEndpoint": "enabled"})
        inst = aw(["ec2", "run-instances", "--image-id", ami, "--instance-type", "t3.micro",
                   "--subnet-id", subnet, "--security-group-ids", sgid,
                   "--key-name", prefix + "-key",
                   "--user-data", "file://" + os.environ["UD_FILE"],
                   "--block-device-mappings", bdm, "--metadata-options", mdo,
                   "--tag-specifications", tag_spec("instance")])
        iid = inst["Instances"][0]["InstanceId"]
        res["instance"] = {"id": iid, "state": "pending", "public_ip": ""}
        save(res, res_path)
        print(f"[created] Instance {iid}  {now()}")

        # --- L1: running ---
        ip = None
        while True:
            d = describe_iid(iid)
            st = d.get("State", {}).get("Name")
            if st == "running":
                ip = d.get("PublicIpAddress")
                res["instance"].update(state="running", public_ip=ip)
                save(res, res_path)
                print(f"L1 running public_ip={ip}  {now()}")
                break
            if st in ("terminated", "shutting-down", "stopped"):
                print(f"STOP: instance went to {st}")
                sys.exit(1)
            time.sleep(3)

        vol = d["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
        eni = d["NetworkInterfaces"][0]["NetworkInterfaceId"]
        boot = d["BlockDeviceMappings"][0]["Ebs"]
        res["volume"] = {"id": vol}
        res["eni"] = {"id": eni}
        res["root_boot"] = boot
        res["metadata"] = d.get("MetadataOptions", {})
        save(res, res_path)
        print(f"[readback] vol={vol} eni={eni}  {now()}")
        print(f"[readback] IMDSv2 HttpTokens={d.get('MetadataOptions', {}).get('HttpTokens')} "
              f"DeleteOnTermination={boot.get('DeleteOnTermination')}")
        volinfo = aw(["ec2", "describe-volumes", "--volume-ids", vol,
                      "--query", "Volumes[0].{Type:VolumeType,Encrypted:Encrypted,Size:Size}"])
        print(f"[readback] volume {volinfo}")

        # --- early curl immediately after running (expected failure; record both exit + http) ---
        p = subprocess.run(["curl", "-sS", "--max-time", "8", "-o", "/dev/null",
                            "-w", "%{http_code}", "http://" + ip + "/health"],
                           capture_output=True, text=True, timeout=30)
        print(f"[early-curl] exit={p.returncode} http={p.stdout or '(no http code)'} "
              f"err={(p.stderr or '').strip()[:120]}  {now()}")

    # --- L2: status checks 2/2 (avoid '+' in --query; use array form) ---
    while True:
        sc = aw(["ec2", "describe-instance-status", "--instance-ids", iid,
                 "--query", "InstanceStatuses[0].[InstanceStatus.Status,SystemStatus.Status]"])
        if sc == ["ok", "ok"]:
            print(f"L2 status-checks 2/2  {now()}")
            break
        time.sleep(5)

    # --- L3/L4/L5 over SSH (host fingerprint captured first; verification stays ON) ---
    kh = os.path.join(os.path.dirname(res_path), "known_hosts")
    with open(kh, "w", encoding="utf-8") as f:
        subprocess.run(["ssh-keyscan", "-t", "ed25519", ip], stdout=f,
                       stderr=subprocess.DEVNULL, timeout=30, check=True)
    fp = subprocess.run(["ssh-keygen", "-lf", kh], capture_output=True, text=True)
    print(f"[ssh] host fingerprint: {(fp.stdout or fp.stderr).strip()}")
    ssh = ["ssh", "-i", os.environ["SSH_KEY"], "-o", "UserKnownHostsFile=" + kh,
           "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "ec2-user@" + ip]

    r = subprocess.run(ssh + ["cloud-init", "status", "--wait", "--long"],
                       capture_output=True, text=True, timeout=240)
    print(f"L3 cloud-init exit={r.returncode}  {now()}")
    print("status output (first 300 chars):")
    print((r.stdout or "")[:300])
    if r.stderr:
        print("stderr:", (r.stderr or "")[:200])

    r2 = subprocess.run(ssh + ["ss", "-ltn"], capture_output=True, text=True, timeout=60)
    print("L4 listeners (nginx:80, inspection:127.0.0.1:8080 expected):")
    print((r2.stdout or "")[:400])

    commit = os.environ.get("W3_COMMIT_FULL") or os.environ["W3_COMMIT"]
    r3 = subprocess.run(["curl", "-sS", "--max-time", "8", "http://" + ip + "/health"],
                        capture_output=True, text=True, timeout=30)
    ver_ok = False
    ok200 = r3.returncode == 0
    try:
        body = json.loads(r3.stdout)
        ver_ok = (body.get("status") == "ok" and body.get("service") == "inspection"
                  and body.get("version") == commit)
    except (ValueError, TypeError):
        pass
    print(f"L5 /health exit={r3.returncode} version_match={ver_ok}  {now()}")
    print("body:", (r3.stdout or "").strip()[:200])
    if not (ok200 and ver_ok):
        print("STOP: /health verification failed; inspect via the recorded layers.")
        sys.exit(1)
    print(f"UP OK at {now()}")


if __name__ == "__main__":
    main()