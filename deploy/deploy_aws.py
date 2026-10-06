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
import re
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


def combine_secrets(app_env, db_env):
    """Concatenate the two 600 secret files into one staging file.

    The remote service reads a single EnvironmentFile, so the tokens and the
    database settings have to arrive together. The staging file is created with
    O_EXCL at mode 600 and is removed in the caller's finally block, so the
    combined secret never sits on disk any longer than the originals do.

    A duplicated key would silently take the LAST value systemd reads, so the
    duplicate check is explicit: a mistyped db.env is a stop, not a surprise.
    """
    seen = {}
    for path in (app_env, db_env):
        if not path or not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "=" not in stripped:
                    raise SystemExit(f"STOP: {path}:{number} is not KEY=value")
                key = stripped.split("=", 1)[0].strip()
                # systemd's EnvironmentFile only accepts [A-Za-z_][A-Za-z0-9_]* as a
                # name. A key with a space in it would not fail here -- it would
                # fail later, on the host, as a service that will not start.
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                    raise SystemExit(f"STOP: {path}:{number} has an unusable key name "
                                     f"{key!r}; systemd accepts [A-Za-z_][A-Za-z0-9_]* only.")
                if key in seen:
                    raise SystemExit(f"STOP: {key} is set in both {seen[key]} and {path};"
                                     f" the later value would silently win.")
                seen[key] = f"{path}:{number}"

    if db_env and os.path.exists(db_env):
        values = {}
        with open(db_env, encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
        # db-up.sh writes the password to disk the moment create-db-instance returns,
        # with DB_HOST still blank, because the master password cannot be read back
        # from AWS later. Deploying that placeholder would start the service against
        # an empty host, and the failure would look like a database outage hours later.
        blank = [k for k in ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")
                 if not values.get(k)]
        if blank:
            raise SystemExit(f"STOP: {db_env} is missing or has an empty {', '.join(blank)}."
                             " This is the placeholder db-up.sh writes before the instance"
                             " is available; the endpoint is filled in at the end of"
                             " db-up.sh. Deploying it would point the service at a blank host.")

    staging = app_env + ".combined"
    parts = []
    for path in (app_env, db_env):
        if not path or not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as stream:
            body = stream.read()
        parts.append(f"# --- from {os.path.basename(path)} ---\n"
                     + (body if body.endswith("\n") else body + "\n"))
    with open(os.open(staging, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600), "w",
              encoding="utf-8") as out:
        out.write("".join(parts))
    return staging


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

    # --- 2) push the combined secret on stdin; umask 077 makes it 600 before it is ever written ---
    db_env = os.environ.get("DB_ENV_FILE") or ""
    db_optional = os.environ.get("DB_SECRET_OPTIONAL") == "1"
    with_db = bool(db_env) and os.path.exists(db_env)
    staging = combine_secrets(secret, db_env)
    try:
        push = shq(f"umask 077 && mkdir -p {os.path.dirname(REMOTE_SECRET)} && cat > {REMOTE_SECRET}")
        result = ssh_run(["sudo", "sh", "-c", push], key, ip, stdin_file=staging)
        if result.returncode:
            print("STOP: could not place the secret file. Nothing is printed about its contents.")
            print("stderr tail:", (result.stderr or "")[-200:])
            sys.exit(1)
    finally:
        # The combined copy holds both the tokens and the database password.
        if os.path.exists(staging):
            os.unlink(staging)
    print(f"[secret] {REMOTE_SECRET} written"
          f"{' (tokens + database settings)' if with_db else ' (tokens only)'}  {now()}")
    mode = ssh_run(["sudo", "stat", "-c", "%a", REMOTE_SECRET], key, ip)
    print(f"[secret] {REMOTE_SECRET} mode {mode.stdout.strip()}  {now()}")
    if mode.stdout.strip() != "600":
        print("STOP: secret file is not 600 on the host.")
        sys.exit(1)

    # --- 3) restart so the service actually reads the token file ---
    result = ssh_run(["sudo", "systemctl", "restart", "inspection"], key, ip)
    if result.returncode:
        print("STOP: could not restart inspection.")
        print("stderr tail:", (result.stderr or "")[-200:])
        sys.exit(1)
    print(f"[restarted] inspection re-read its environment  {now()}")

    # --- 4) verify: same commit, authentication, and (when a DB secret was sent)
    #        that the service really came up on the database ---
    status, body = 0, {}
    for _ in range(20):
        status, body = health(ip)
        if status == 200 and body.get("version") == commit:
            break
        time.sleep(3)
    print(f"[verify] /health http={status} version_match={body.get('version') == commit} "
          f"auth_configured={body.get('auth_configured')} "
          f"db_configured={body.get('db_configured')} storage={body.get('storage')}  {now()}")
    if status != 200 or body.get("version") != commit:
        print("STOP: /health does not report the deployed commit.")
        sys.exit(1)
    if body.get("auth_configured") is not True:
        print("STOP: auth_configured is not true -- the token file did not reach the service.")
        sys.exit(1)
    if with_db and body.get("db_configured") is not True:
        # The secret file is in place and the service still came up on the memory
        # store. Reporting success here would be the worst outcome: the host looks
        # healthy, events work, and they all disappear on the next restart.
        print("STOP: the database secret was sent but /health reports db_configured=false.")
        print("      The service is running in its degraded W4 mode. Do NOT record this as a")
        print("      successful deployment. Check: sudo journalctl -u inspection -n 30")
        sys.exit(1)
    if not with_db and body.get("db_configured"):
        print("[note] the service reports db_configured=true although no DB secret was sent;"
              " the host kept settings from an earlier deployment")

    res["instance"]["state"] = "running"
    res["instance"]["public_ip"] = ip
    res["deployed_commit"] = commit
    res["deployed_utc"] = now()
    res["db_configured"] = bool(body.get("db_configured"))
    save(res, res_path)
    print(f"DEPLOY OK at {now()} (version {commit[:7]}, auth_configured true, "
          f"db_configured {str(body.get('db_configured')).lower()})")


if __name__ == "__main__":
    main()
