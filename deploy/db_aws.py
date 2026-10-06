#!/usr/bin/env python3
"""W5 db-up.sh AWS core: build the private database tier beside the W3 host.

Every AWS call goes through scripts/lab.py run_aws, so the learnerlab profile and
the verified region/account are always the ones in play.

Design points that are easy to get wrong, and why each is handled here rather
than left to review:

* "private" is a property of the ROUTE TABLE, not of a name. A subnet that is
  never explicitly associated keeps using the VPC main route table, and in this
  Lab the main table carries a 0.0.0.0/0 -> igw route. So each new subnet is
  explicitly associated to a route table that has only the local route, and the
  script reads the association back before touching RDS.

* The master password must not reach argv. `ps` and shell history both expose
  argv, and this password is the only thing standing between anyone who reaches
  the private subnet and the inspection database. So the whole create call is
  passed as --cli-input-json on a 0600 file inside .local/, which is removed in
  a finally block whether the call succeeds or fails.

* Only a /32-free SG reference reaches SG-db. The ingress source is the host's
  security group ID, which means "anything wearing that SG" -- not a Codespace
  IP address, and not 0.0.0.0/0.

* Nothing is deleted, and nothing outside .local/resources.json is modified.
"""
import ipaddress
import json
import os
import secrets
import string
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import lab

REGION = os.environ.get("W3_REGION", "us-east-1")
DB_NAME = "inspection"
DB_USER = "inspection"
# 20 characters from a set with no quote, backslash, space or percent: the value
# is pasted into a libpq conninfo string and into a systemd EnvironmentFile, and
# a stray quote in either place would corrupt both files.
PASSWORD_ALPHABET = string.ascii_letters + string.digits


def aw(args):
    return lab.run_aws(args, REGION)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save(res, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(res, stream, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def tags(prefix="w05"):
    """Same four keys as W3 so ownership is auditable from the console alone."""
    inner = ",".join("{Key=%s,Value=%s}" % (k, v) for k, v in (
        ("course", "yuntech-115-1"), ("week", prefix),
        ("group", os.environ["W3_GROUP"]), ("owner", os.environ["W3_OWNER"])))
    return "ResourceType=%s,Tags=[%s]"


def pick_subnets(vpc_id, vpc_cidr, existing_cidrs, needed=2):
    """Return (cidr, az) pairs: /24 blocks inside the VPC CIDR, not overlapping any
    existing subnet, in as many different AZs as the VPC actually has subnets in.

    Computed from the live VPC rather than hardcoded: another person's Lab
    allocates different ranges, and a hardcoded 172.31.x.0/24 can collide.
    """
    vpc_net = ipaddress.ip_network(vpc_cidr)
    # How many /24 blocks does this VPC actually contain? Need `needed`, plus one
    # left aside (the VPC's own first block). A /16 has 256; a /20 has 16 and is
    # still fine; a /24 has 1 and cannot host a two-subnet DB tier.
    capacity = 1 << (24 - vpc_net.prefixlen) if vpc_net.prefixlen < 24 else 0
    if capacity < needed + 1:
        raise SystemExit(f"STOP: VPC CIDR {vpc_cidr} holds {capacity} /24 block(s); "
                         f"need {needed + 1} (two subnets plus one kept in reserve).")
    used = [ipaddress.ip_network(c) for c in existing_cidrs]

    # AZs that already have a subnet in this VPC are the ones this VPC spans.
    azs = []
    for subnet in aw(["ec2", "describe-subnets", "--filters", f"Name=vpc-id,Values={vpc_id}",
                      "--query", "Subnets[].[AvailabilityZone,CidrBlock]"]):
        az = subnet[0]
        used.append(ipaddress.ip_network(subnet[1]))
        if az not in azs:
            azs.append(az)
    azs.sort()
    if len(azs) < needed:
        raise SystemExit(f"STOP: VPC spans only {len(azs)} AZ(s); need {needed} for the RDS "
                         f"subnet group. Found: {azs}")

    chosen = []
    # Enumerate every /24 inside the VPC CIDR and take the first free ones. Doing
    # it by "walk the second octet" would silently misbehave on a VPC whose CIDR
    # is not a /16, because the host bits do not start at the third octet.
    for candidate in vpc_net.subnets(new_prefix=24):
        # The VPC's own /24 stays free so a later exercise can still use it.
        if candidate.network_address == vpc_net.network_address:
            continue
        if any(candidate.overlaps(other) for other in used):
            continue
        chosen.append((str(candidate), azs[len(chosen)]))
        used.append(candidate)
        if len(chosen) == needed:
            return chosen
    raise SystemExit("STOP: no free /24 left in the VPC CIDR for two subnets.")


def first(value):
    """Unwrap a projection that may come back as a list or as a bare scalar.

    `aws --query 'Vpcs[0].CidrBlock'` returns the string, not ["the string"].
    Indexing it blindly yields the first CHARACTER -- "1" for 172.31.0.0/16 --
    which fails much later with a confusing message.
    """
    if isinstance(value, list):
        return value[0] if value else ""
    return value if value else ""


def write_db_env(path, host, port, password, exclusive):
    """Write the database secret: mode 600, never printed, never on a command line.

    The first write uses O_EXCL so a pre-existing or attacker-planted file is refused
    rather than overwritten. Later writes (filling in the endpoint once the instance
    is available) truncate in place so a partially written file is never observable,
    and O_NOFOLLOW keeps a symlink from redirecting the secret somewhere else.
    """
    flags = os.O_CREAT | os.O_WRONLY | (os.O_EXCL if exclusive else os.O_TRUNC)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        handle = os.open(path, flags, 0o600)
    except FileExistsError:
        raise SystemExit(f"STOP: {path} already exists. Refusing to overwrite a database "
                         "secret that may already be deployed to the host. If you are "
                         "certain it is stale, delete it yourself first.")
    except OSError as error:
        # ELOOP: something is a symlink where the secret belongs.
        raise SystemExit(f"STOP: cannot write {path} ({error.strerror}). If that path is a "
                         "symlink, remove it first -- the secret must not be written "
                         "through a link to somewhere else.")
    with open(handle, "w", encoding="utf-8") as stream:
        stream.write("# W5 database secret. 600, .local/ is git-ignored, never printed or committed.\n")
        stream.write(f"DB_HOST={host}\nDB_PORT={port}\nDB_NAME={DB_NAME}\n"
                     f"DB_USER={DB_USER}\nDB_PASSWORD={password}\n")


def main():
    res_path = os.environ["RES_FILE"]
    db_env_path = os.environ["DB_ENV_FILE"]
    vpc_id = os.environ["W3_VPC_ID"]
    prefix = os.environ["W3_NAME_PREFIX"]

    lab.verify()

    with open(res_path, encoding="utf-8") as stream:
        res = json.load(stream)
    host_sg = res["sg"]["id"]

    vpc_cidr = first(aw(["ec2", "describe-vpcs", "--vpc-ids", vpc_id,
                     "--query", "Vpcs[0].CidrBlock"]))
    if not vpc_cidr:
        raise SystemExit(f"STOP: {vpc_id} has no CidrBlock in {REGION}. "
                         "Is this the right region?")

    plan = pick_subnets(vpc_id, vpc_cidr, [])
    print(f"[plan] VPC {vpc_id} {vpc_cidr}; new subnets: " +
          ", ".join(f"{c} in {az}" for c, az in plan))
    print(f"[plan] SG-db ingress 5432 will reference host SG {host_sg}  {now()}")

    # ---------- 1) route table (local route only) ----------
    rt = aw(["ec2", "create-route-table", "--vpc-id", vpc_id,
             "--description", "W5 private DB subnets, local route only",
             "--tag-specifications", tags() % "route-table"])
    rt_id = rt["RouteTable"]["RouteTableId"]
    res["db"] = {"route_table": {"id": rt_id}}
    save(res, res_path)
    print(f"[created] RouteTable {rt_id}  {now()}")

    # Verify the association actually took, because "private" depends on it and a
    # silent failure here is exactly how a public database ships to production.
    assoc = aw(["ec2", "describe-route-tables", "--route-table-ids", rt_id,
                "--query", "RouteTables[0].Associations"])
    if not any(a.get("Main") is False for a in assoc):
        print("[readback] route table association list is empty so far; subnets follow")

    # ---------- 2) two private subnets ----------
    for cidr, az in plan:
        sub = aw(["ec2", "create-subnet", "--vpc-id", vpc_id, "--cidr-block", cidr,
                  "--availability-zone", az,
                  "--tag-specifications", tags() % "subnet"])
        sid = sub["Subnet"]["SubnetId"]
        key = "subnet_" + az.split("-")[-1]
        res["db"].setdefault("subnets", []).append({"id": sid, "cidr": cidr, "az": az})
        save(res, res_path)
        print(f"[created] Subnet {sid} {cidr} ({az})  {now()}")

        aw(["ec2", "create-tags", "--resources", sid, "--tags",
            "Key=name,Value=" + prefix + "-db-" + az.split("-")[-1]])
        aw(["ec2", "associate-route-table", "--route-table-id", rt_id,
            "--subnet-id", sid])
        print(f"[assoc]   {sid} -> {rt_id} (explicit; without this it is NOT private)")

    # Read the association back per subnet instead of trusting the call's exit code.
    for entry in res["db"]["subnets"]:
        back = aw(["ec2", "describe-route-tables", "--route-table-ids", rt_id,
                   "--query", "RouteTables[0].Associations[?SubnetId==`" + entry["id"] + "`].SubnetId"])
        if back != [entry["id"]]:
            raise SystemExit(f"STOP: {entry['id']} is not associated with {rt_id}; "
                             f"it would inherit the main table and could be public.")
        print(f"[readback] {entry['id']} uses {rt_id}, local route only")

    # Explicit association is only half of "private". The table itself must not
    # carry a route out to an internet gateway: a single 0.0.0.0/0 here would turn
    # both DB subnets public while every other check still passed. A freshly created
    # table has just the local route, so this reads "1 route, gateway=local".
    routes = aw(["ec2", "describe-route-tables", "--route-table-ids", rt_id,
                 "--query", "RouteTables[0].Routes[].[DestinationPrefix,GatewayId]"])
    off_table = [r for r in routes if r[1] != "local"]
    if off_table:
        raise SystemExit(f"STOP: {rt_id} carries non-local routes {off_table}. A default "
                         f"route here would make the DB subnets reachable from the internet.")
    print(f"[readback] {rt_id} carries {len(routes)} route(s), every one gateway=local")

    # ---------- 3) DB subnet group ----------
    subnet_ids = [e["id"] for e in res["db"]["subnets"]]
    dsg = aw(["rds", "create-db-subnet-group", "--db-subnet-group-name", prefix + "-db-subnets",
              "--db-subnet-group-description", "W5 inspection RDS, two AZs",
              "--subnet-ids", ",".join(subnet_ids),
              "--tags", "Key=course,Value=yuntech-115-1,Key=week,Value=w05,Key=group,Value="
              + os.environ["W3_GROUP"] + ",Key=owner,Value=" + os.environ["W3_OWNER"]])
    dsg_name = dsg["DBSubnetGroup"]["DBSubnetGroupName"]
    res["db"]["subnet_group"] = {"name": dsg_name, "subnet_ids": subnet_ids}
    save(res, res_path)
    print(f"[created] DBSubnetGroup {dsg_name}  {now()}")

    # ---------- 4) SG-db: inbound 5432 from the host SG, nothing else ----------
    sg = aw(["ec2", "create-security-group", "--group-name", prefix + "-sg-db",
             "--description", "W5 RDS: inbound 5432 from the host SG only",
             "--vpc-id", vpc_id, "--tag-specifications", tags() % "security-group"])
    sg_id = sg["GroupId"]
    res["db"]["sg"] = {"id": sg_id, "name": prefix + "-sg-db", "ingress_from_sg": host_sg}
    save(res, res_path)
    print(f"[created] SG-db {sg_id}  {now()}")

    ingress = [{
        "IpProtocol": "tcp",
        "FromPort": 5432,
        "ToPort": 5432,
        # A security-group reference: "anything wearing the host SG", not the
        # Codespace IP and not the internet.
        "UserIdGroupPairs": [{"GroupId": host_sg, "Description": "inspection host SG"}],
    }]
    aw(["ec2", "authorize-security-group-ingress", "--group-id", sg_id,
        "--ip-permissions", json.dumps(ingress)])
    print(f"[ingress] TCP 5432 <-- SG {host_sg}  {now()}")

    rules = aw(["ec2", "describe-security-groups", "--group-ids", sg_id,
                "--query", "SecurityGroups[0].IpPermissions"])
    problem = []
    if len(rules) != 1:
        problem.append(f"expected exactly 1 ingress rule, found {len(rules)}")
    else:
        rule = rules[0]
        if rule.get("IpProtocol") != "tcp":
            problem.append(f"protocol is {rule.get('IpProtocol')}, expected tcp")
        if rule.get("FromPort") != 5432 or rule.get("ToPort") != 5432:
            problem.append(f"port range is {rule.get('FromPort')}-{rule.get('ToPort')}, "
                           "expected 5432-5432")
        if rule.get("IpRanges"):
            problem.append(f"a CIDR source is present: {rule['IpRanges']}")
        pairs = [p.get("GroupId") for p in rule.get("UserIdGroupPairs", [])]
        if pairs != [host_sg]:
            problem.append(f"source is SG {pairs}, expected exactly ['{host_sg}']")
    if problem:
        raise SystemExit(f"STOP: SG-db {sg_id} is not the rule the W5 spec asks for:\n  - "
                         + "\n  - ".join(problem)
                         + "\n      A database reachable from more than the host is the "
                           "failure this whole design exists to prevent.")
    print(f"[readback] SG-db ingress is exactly one rule: tcp 5432-5432 from SG {host_sg}, no CIDR")

    # ---------- 5) RDS instance ----------
    password = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(20))
    dbi = prefix + "-w5"

    # Record the identifier BEFORE the call. The create request is the one step here
    # whose outcome can be genuinely unknown (a timeout leaves AWS building the
    # instance while this process sees a failure). Without this line, an instance in
    # that state is invisible in resources.json and the natural next move -- re-run
    # the script -- silently creates a second, billable database.
    res["db"]["rds"] = {"identifier": dbi, "state": "create-requested"}
    save(res, res_path)
    payload = {
        "DBInstanceIdentifier": dbi,
        "DBInstanceClass": "db.t3.micro",
        "Engine": "postgres",
        "MasterUsername": DB_USER,
        "MasterUserPassword": password,
        "AllocatedStorage": 20,
        "MaxAllocatedStorage": 100,
        "StorageType": "gp3",
        "StorageEncrypted": True,
        "PubliclyAccessible": False,
        "MultiAZ": False,
        "DBSubnetGroupName": dsg_name,
        "VpcSecurityGroupIds": [sg_id],
        "DBName": DB_NAME,
        "BackupRetentionPeriod": 0,
        "Tags": [{"Key": "course", "Value": "yuntech-115-1"}, {"Key": "week", "Value": "w05"},
                 {"Key": "group", "Value": os.environ["W3_GROUP"]},
                 {"Key": "owner", "Value": os.environ["W3_OWNER"]}],
    }
    cli_file = db_env_path + ".create-input.json"
    try:
        with open(os.open(cli_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
                  "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
        print(f"[create] RDS {dbi} (db.t3.micro, 20 GiB gp3, encrypted, private, single AZ)  {now()}")
        print("[note]   startup takes several minutes; the script will wait and then read back")
        aw(["rds", "create-db-instance", "--cli-input-json", "file://" + cli_file])
    finally:
        # The password must not survive the call in a readable file.
        if os.path.exists(cli_file):
            os.unlink(cli_file)

    # The create request has returned: the instance exists and now the password
    # exists only inside AWS. Persist it immediately, before the multi-minute wait.
    # Waiting first would mean a failed wait destroys the secret while leaving the
    # database standing, and a master password cannot be read back from AWS.
    write_db_env(db_env_path, "", 5432, password, exclusive=True)
    res["db"]["secret_file"] = ".local/db.env"
    res["db"]["rds"]["state"] = "creating"
    save(res, res_path)
    print(f"[secret] {db_env_path} written now, mode 600; DB_HOST is filled in once available  {now()}")

    # ---------- 6) wait, then read back ----------
    print("[wait]   polling describe-db-instances until status=available ...")
    status = ""
    for _ in range(120):          # ~7.5 min at 5s, matching the teacher's measurement
        info = aw(["rds", "describe-db-instances", "--db-instance-identifier", dbi,
                   "--query", "DBInstances[0].[DBInstanceStatus,PubliclyAccessible,Endpoint.Address]"])
        status = info[0] if info else "unknown"
        if status == "available":
            break
        if status in ("failed", "incompatible-restore", "incompatible-parameters"):
            raise SystemExit(f"STOP: RDS went to {status}. Do not re-run this script; "
                             f"inspect {dbi} by ID first.")
        import time
        time.sleep(5)

    if status != "available":
        raise SystemExit(f"STOP: RDS is {status}, not available. Do not re-run this script; "
                         f"it would create a second instance.")

    info = aw(["rds", "describe-db-instances", "--db-instance-identifier", dbi,
               "--query", "DBInstances[0].[Endpoint.Address,Endpoint.Port,StorageEncrypted,"
                          "AllocatedStorage,StorageType,MultiAZ,DBSubnetGroupName,"
                          "VpcSecurityGroups[0].VpcSecurityGroupId,PubliclyAccessible,"
                          "Engine,DBInstanceClass,MasterUsername,DBName]"])
    (endpoint, port, encrypted, allocated, storage_type, multi_az, group_name, member_sg,
     publicly_accessible, engine, klass, master_user, master_db) = info

    # Every field the W5 spec names is asserted against the value AWS reports, not
    # against what we asked for. A request that was silently adjusted by a default
    # VPC, an account-level default or a quota is exactly what this catches.
    drift = []
    if publicly_accessible is not False:
        drift.append(f"PubliclyAccessible is {publicly_accessible}, expected False")
    if not encrypted:
        drift.append("StorageEncrypted is False, expected True")
    if allocated != 20:
        drift.append(f"AllocatedStorage is {allocated}, expected 20")
    if storage_type != "gp3":
        drift.append(f"StorageType is {storage_type}, expected gp3")
    if multi_az:
        drift.append("MultiAZ is true, expected single AZ")
    if engine != "postgres":
        drift.append(f"Engine is {engine}, expected postgres")
    if klass != "db.t3.micro":
        drift.append(f"DBInstanceClass is {klass}, expected db.t3.micro")
    if master_user != DB_USER or master_db != DB_NAME:
        drift.append(f"master is {master_user}/{master_db}, expected {DB_USER}/{DB_NAME}")
    if group_name != dsg_name:
        drift.append(f"DBSubnetGroup is {group_name}, expected {dsg_name}")
    if member_sg != sg_id:
        drift.append(f"attached SG is {member_sg}, expected {sg_id}")
    if drift:
        raise SystemExit("STOP: the running instance does not match the W5 spec:\n  - "
                         + "\n  - ".join(drift)
                         + "\n      Do NOT re-run db-up.sh; fix or delete this instance by ID.")

    # ---------- 7) the password, once, to one 600 file, never printed ----------
    # Overwrites the placeholder written right after create, now with the real
    # endpoint read back from AWS.
    write_db_env(db_env_path, endpoint, port, password, exclusive=False)

    res["db"]["rds"] = {
        "identifier": dbi, "state": status, "endpoint": endpoint, "port": port, "engine": engine,
        "class": klass, "allocated_gib": allocated, "storage_type": storage_type,
        "encrypted": encrypted, "publicly_accessible": publicly_accessible, "multi_az": multi_az,
        "subnet_group": group_name, "sg": member_sg,
    }
    res["db"]["secret_file"] = ".local/db.env"
    save(res, res_path)
    print(f"[secret] {db_env_path} written, mode 600, contents never shown  {now()}")

    print()
    print("== readback (values reported by describe-db-instances, not by the request) ==")
    print(f"  DBInstanceIdentifier : {dbi}")
    print(f"  status               : {status}")
    print(f"  PubliclyAccessible   : {publicly_accessible}")
    print(f"  StorageEncrypted     : {encrypted}   StorageType: {storage_type}  {allocated} GiB")
    print(f"  Engine / Class       : {engine} / {klass}")
    print(f"  MultiAZ              : {multi_az} (single AZ as specified)")
    print(f"  endpoint             : {endpoint}:{port}")
    print(f"  DBSubnetGroup        : {group_name} ({', '.join(subnet_ids)})")
    print(f"  VpcSecurityGroups    : {member_sg}")
    print()
    print(f"DB-UP OK at {now()}")
    print("next: deploy/deploy.sh will copy .local/db.env onto the host as part of the secret file")


if __name__ == "__main__":
    main()