#!/usr/bin/env python3
"""W4 deploy.sh core: update the already-running W3 host in place.

Every AWS call goes through scripts/lab.py run_aws. The host is addressed by the
EXACT instance id recorded in .local/resources.json -- no name search -- and its
public IPv4 is re-queried immediately before use, because every Stop/Start hands
out a new address.

Why the service is restarted twice: the generated install script ends with
`systemctl restart inspection`, but /etc/inspection/app.env does not exist yet.
systemd's `EnvironmentFile=-...` treats a missing file as optional and starts the
service anyway, so the first restart comes up with auth_configured=false. The
token file is therefore pushed afterwards and the service restarted once more.

The token file travels on SSH standard input only: never an argument, never
stdout, never user data, never Git.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import lab

REGION = os.environ.get("W3_REGION", "us-east-1")
REMOTE_SECRET = "/etc/inspection/app.env"


def aw(args):
    return lab.run_aws(args, REGION)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save(res, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(res, stream, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def shq(text):
    """Quote one shell fragment for the remote login shell.

    ssh concatenates its argv with spaces and the REMOTE shell re-parses the
    result, so `["sh", "-c", "a && b"]` arrives as `sh -c a && b` and the `&&`
    then runs OUTSIDE sh, as the unprivileged login user. Wrapping the fragment
    keeps the redirection inside the privileged shell.
    """
    return "'" + text.replace("'", "'\\''") + "'"


def ssh_run(argv, key, ip, stdin_file=None, timeout=300):
    """Run one command on the host. stdin_file is piped, never named in argv."""
    command = ["ssh", "-i", key,
               "-o", "StrictHostKeyChecking=accept-new",
               "-o", "IdentitiesOnly=yes",
               "-o", "ConnectTimeout=15",
               "ec2-user@" + ip, *argv]
    stdin = open(stdin_file, "rb") if stdin_file else subprocess.DEVNULL
    try:
        return subprocess.run(command, stdin=stdin, capture_output=True, text=True, timeout=timeout)
    finally:
        if stdin_file:
            stdin.close()


def health(ip, timeout=8):
    try:
        with urllib.request.urlopen("http://" + ip + "/health", timeout=timeout) as response:
            return response.status, json.load(response)
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


def main():
    res_path = os.environ["RES_FILE"]
    key = os.environ["SSH_KEY"]
    secret = os.environ["SECRET_FILE"]
    ud = os.environ["UD_FILE"]
    commit = os.environ["DEPLOY_COMMIT_FULL"]

    with open(res_path, encoding="utf-8") as stream:
        res = json.load(stream)
    iid = res["instance"]["id"]

    lab.verify()

    # --- resolve the live address; never trust the recorded one ---
    state = aw(["ec2", "describe-instances", "--instance-ids", iid,
                "--query", "Reservations[0].Instances[0].[State.Name,PublicIpAddress]"])
    if not state or state[0] != "running":
        print(f"STOP: {iid} is {state[0] if state else 'unknown'}, not running. Start it first, then deploy.")
        sys.exit(1)
    ip = state[1]
    recorded = res["instance"].get("public_ip")
    if ip != recorded:
        print(f"[address] recorded {recorded} -> live {ip}  {now()}")
    print(f"[target] {iid}  ip={ip}  commit={commit[:7]}  {now()}")

    # --- package from the commit (make_user_data.py uses git show: no git clone, no secret) ---
    subprocess.run(["bash", os.path.join(os.path.dirname(os.path.abspath(__file__)), "make-user-data.sh"),
                    commit, ud], check=True, capture_output=True, text=True)

    # --- 1) install the committed build (this restarts inspection once, without tokens) ---
    result = ssh_run(["sudo", "bash", "-s"], key, ip, stdin_file=ud)
    if result.returncode:
        print("STOP: install script failed over SSH.")
        print("stderr tail:", (result.stderr or "")[-400:])
        sys.exit(1)
    print(f"[installed] committed build in place  {now()}")

    # --- 2) push the token file on stdin; umask 077 makes it 600 before it is ever written ---
    push = shq(f"umask 077 && mkdir -p {os.path.dirname(REMOTE_SECRET)} && cat > {REMOTE_SECRET}")
    result = ssh_run(["sudo", "sh", "-c", push], key, ip, stdin_file=secret)
    if result.returncode:
        print("STOP: could not place the token file. Nothing is printed about its contents.")
        print("stderr tail:", (result.stderr or "")[-200:])
        sys.exit(1)
    mode = ssh_run(["sudo", "stat", "-c", "%a", REMOTE_SECRET], key, ip)
    print(f"[secret] {REMOTE_SECRET} installed, mode {mode.stdout.strip()}  {now()}")
    if mode.stdout.strip() != "600":
        print("STOP: token file is not 600 on the host.")
        sys.exit(1)

    # --- 3) restart so the service actually reads the token file ---
    result = ssh_run(["sudo", "systemctl", "restart", "inspection"], key, ip)
    if result.returncode:
        print("STOP: could not restart inspection.")
        print("stderr tail:", (result.stderr or "")[-200:])
        sys.exit(1)
    print(f"[restarted] inspection re-read its environment  {now()}")

    # --- 4) verify: same commit AND authentication actually configured ---
    status, body = 0, {}
    for _ in range(20):
        status, body = health(ip)
        if status == 200 and body.get("version") == commit:
            break
        time.sleep(3)
    print(f"[verify] /health http={status} version_match={body.get('version') == commit} "
          f"auth_configured={body.get('auth_configured')}  {now()}")
    if status != 200 or body.get("version") != commit:
        print("STOP: /health does not report the deployed commit.")
        sys.exit(1)
    if body.get("auth_configured") is not True:
        print("STOP: auth_configured is not true -- the token file did not reach the service.")
        sys.exit(1)

    res["instance"]["state"] = "running"
    res["instance"]["public_ip"] = ip
    res["deployed_commit"] = commit
    res["deployed_utc"] = now()
    save(res, res_path)
    print(f"DEPLOY OK at {now()} (version {commit[:7]}, auth_configured true)")


if __name__ == "__main__":
    main()
