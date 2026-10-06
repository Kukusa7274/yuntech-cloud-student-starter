"""An offline rehearsal of deploy/db_aws.py main(), the whole call sequence.

Every other W5 test calls a helper directly with inputs I chose. That is why two
TypeErrors got through and only appeared once db-up.sh was actually run against
AWS: main() -- the function that assembles every AWS response and indexes into
it -- had no coverage at all.

This module runs main() end to end against a fake AWS layer whose responses
carry the exact shapes the real CLI returns, including the two that already bit
us:

  * a single-value --query projection returns a bare string, not [string]
  * the --tag-specifications shorthand needs its inner braces literal

The shapes below were transcribed from real describe-* output captured from this
lab's VPC, not invented. No AWS call is made and no file outside tmp is touched.
"""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "deploy"))

os.environ.setdefault("W3_GROUP", "test-group")
os.environ.setdefault("W3_OWNER", "test-owner")

_spec = importlib.util.spec_from_file_location("w05_db_aws_rehearsal",
                                                ROOT / "deploy/db_aws.py")
db_aws = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(db_aws)

VPC = "vpc-02d401c7385395dbc"
HOST_SG = "sg-07e50dbdb1acbd808"

# Transcribed from describe-subnets on the lab VPC: six /20s already taken, and
# the last one ends at 172.31.95.255, so a /24 plan has to start at .96.
REAL_SUBNETS = [
    {"SubnetId": "subnet-0c95d4de6889351d9", "CidrBlock": "172.31.80.0/20",
     "AvailabilityZone": "us-east-1a"},
    {"SubnetId": "subnet-0fa452f4964ad745d", "CidrBlock": "172.31.16.0/20",
     "AvailabilityZone": "us-east-1b"},
    {"SubnetId": "subnet-02be5f7d3df615b53", "CidrBlock": "172.31.32.0/20",
     "AvailabilityZone": "us-east-1c"},
    {"SubnetId": "subnet-07152a32a2079b0df", "CidrBlock": "172.31.0.0/20",
     "AvailabilityZone": "us-east-1d"},
    {"SubnetId": "subnet-0c79b546c30e10042", "CidrBlock": "172.31.48.0/20",
     "AvailabilityZone": "us-east-1e"},
    {"SubnetId": "subnet-00fc10cdf8bac200d", "CidrBlock": "172.31.64.0/20",
     "AvailabilityZone": "us-east-1f"},
]


class FakeAws:
    """Answers the calls main() makes, in order, and records every argv.

    Response shapes match the real CLI:
      * describe-vpcs with a single-value projection  -> "172.31.0.0/16" (str)
      * create-* / describe-* with a multi projection -> the parsed JSON structure
      * describe-db-instances polling                -> "creating" then "available"
    """

    def __init__(self):
        self.calls = []
        self.created = {"route-table": None, "subnets": [], "sg": None,
                        "subnet-group": None, "db": None}
        self.associated = set()
        self.polls = 0
        self.resuming = False
        self.recovery_public = False

    # ---- the callable db_aws.aw() expects -------------------------------
    def __call__(self, args):
        self.calls.append(args)
        service, action = args[0], args[1]
        flat = " ".join(args)
        if service == "ec2" and action == "describe-vpcs":
            return "172.31.0.0/16"          # bare string, the trap from run 1
        if service == "ec2" and action == "describe-subnets":
            if "SubnetId" in flat:
                rows = [[s["SubnetId"], s["AvailabilityZone"], s["CidrBlock"]]
                        for s in REAL_SUBNETS]
                if self.resuming:
                    rows.extend([
                        ["subnet-resume-a", "us-east-1a", "172.31.96.0/24"],
                        ["subnet-resume-b", "us-east-1b", "172.31.97.0/24"],
                    ])
                return rows
            # The real call carries --query 'Subnets[].[AvailabilityZone,CidrBlock]',
            # so each row arrives as a two-element list, not as a dict.
            return [[s["AvailabilityZone"], s["CidrBlock"]] for s in REAL_SUBNETS]
        if service == "ec2" and action == "create-route-table":
            self.created["route-table"] = "rtb-0abc123"
            return {"RouteTable": {"RouteTableId": "rtb-0abc123"}}
        if service == "ec2" and action == "describe-route-tables":
            if "RouteTables[0].{" in flat:
                return {"VpcId": VPC, "Gateways": ["local"],
                        "Subnets": ["subnet-resume-a", "subnet-resume-b"]}
            if "Associations[?" in flat:
                side = flat.split("SubnetId==`")[-1].split("`]")[0]
                return [side] if side in self.associated else []
            if "VpcId" in flat:
                return VPC
            if "Routes" in flat:
                return [["172.31.0.0/16", "local"]]
            return [{"Main": False, "SubnetId": None}]
        if service == "ec2" and action == "create-subnet":
            cidr = args[args.index("--cidr-block") + 1]
            az = args[args.index("--availability-zone") + 1]
            sid = f"subnet-new{len(self.created['subnets'])}"
            self.created["subnets"].append({"id": sid, "cidr": cidr, "az": az})
            return {"Subnet": {"SubnetId": sid}}
        if service == "ec2" and action == "create-tags":
            return {}
        if service == "ec2" and action == "associate-route-table":
            self.associated.add(args[args.index("--subnet-id") + 1])
            return {}
        if service == "rds" and action == "create-db-subnet-group":
            return {"DBSubnetGroup": {"DBSubnetGroupName": "w03-g8-o1-db-subnets"}}
        if service == "ec2" and action == "create-security-group":
            self.created["sg"] = "sg-0db999"
            return {"GroupId": "sg-0db999"}
        if service == "ec2" and action == "authorize-security-group-ingress":
            return {"Return": True}
        if service == "ec2" and action == "describe-security-groups":
            return [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                     "IpRanges": [],
                     "UserIdGroupPairs": [{"GroupId": HOST_SG,
                                           "Description": "inspection host SG"}]}]
        if service == "rds" and action == "create-db-instance":
            self.created["db"] = "w03-g8-o1-w5"
            return {"DBInstance": {"DBInstanceIdentifier": "w03-g8-o1-w5"}}
        if service == "rds" and action == "describe-db-instances":
            if "Identifier:DBInstanceIdentifier" in flat:
                return {
                    "Identifier": "w03-g8-o1-w5", "Status": "available",
                    "Public": self.recovery_public, "Encrypted": True,
                    "Allocated": 20, "StorageType": "gp3", "MultiAZ": False,
                    "Engine": "postgres", "Class": "db.t3.micro",
                    "Master": "inspection", "DBName": "inspection",
                    "Endpoint": "db.rehearsal.invalid", "Port": 5432,
                    "SubnetGroup": "w03-g8-o1-db-subnets", "Vpc": VPC,
                    "Subnets": ["subnet-resume-a", "subnet-resume-b"],
                    "SecurityGroups": ["sg-0db999"],
                }
            if "DBInstanceStatus" in flat:               # the polling query
                self.polls += 1
                return ["available" if self.polls > 1 else "creating", None]
            if "DBSubnetGroup.DBSubnetGroupName" not in flat:
                raise AssertionError("DB subnet group name must use the nested RDS response field")
            return ["db.rehearsal.invalid", 5432, True, 20, "gp3", False,
                    "w03-g8-o1-db-subnets", "sg-0db999", False,
                    "postgres", "db.t3.micro", "inspection", "inspection"]
        raise AssertionError("unexpected AWS call: " + " ".join(args[:3]))


class Rehearsal(unittest.TestCase):
    """main() must complete with no AWS call and no TypeError."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.res = Path(self.tmp.name) / "resources.json"
        self.res.write_text(json.dumps(
            {"sg": {"id": HOST_SG}, "instance": {"id": "i-0b6a509de0b71f42e"}}),
            encoding="utf-8")
        self.db_env = Path(self.tmp.name) / "db.env"

        self.env = {"RES_FILE": str(self.res), "DB_ENV_FILE": str(self.db_env),
                    "W3_VPC_ID": VPC, "W3_NAME_PREFIX": "w03-g8-o1",
                    "W3_GROUP": "test-group", "W3_OWNER": "test-owner"}
        patcher = mock.patch.dict(os.environ, self.env, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        # The availability poll really does sleep 5s between attempts; without this
        # the rehearsal costs 7 wall-clock seconds and proves nothing extra.
        no_sleep = mock.patch("time.sleep")
        no_sleep.start()
        self.addCleanup(no_sleep.stop)

    def run_main(self, aws=None):
        aws = aws or FakeAws()
        with mock.patch.object(db_aws, "aw", aws), \
             mock.patch.object(db_aws.lab, "verify", return_value={"region": "us-east-1"}), \
             mock.patch("builtins.print"):
            db_aws.main()
        return aws

    def prepare_recovery(self):
        self.res.write_text(json.dumps({
            "sg": {"id": HOST_SG},
            "db": {
                "route_table": {"id": "rtb-resume"},
                "subnets": [
                    {"id": "subnet-resume-a", "cidr": "172.31.96.0/24",
                     "az": "us-east-1a"},
                    {"id": "subnet-resume-b", "cidr": "172.31.97.0/24",
                     "az": "us-east-1b"},
                ],
                "subnet_group": {
                    "name": "w03-g8-o1-db-subnets",
                    "subnet_ids": ["subnet-resume-a", "subnet-resume-b"],
                },
                "sg": {"id": "sg-0db999", "ingress_from_sg": HOST_SG},
                "rds": {"identifier": "w03-g8-o1-w5", "state": "creating"},
                "secret_file": ".local/db.env",
            },
        }), encoding="utf-8")
        self.db_env.write_text(
            "# existing W5 secret\nDB_HOST=\nDB_PORT=5432\nDB_NAME=inspection\n"
            "DB_USER=inspection\nDB_PASSWORD=keep-this-private\n",
            encoding="utf-8")
        os.chmod(self.db_env, 0o600)

    def run_recovery(self, aws):
        with mock.patch.object(db_aws, "aw", aws), \
             mock.patch.object(db_aws.lab, "verify", return_value={"region": "us-east-1"}), \
             mock.patch("builtins.print"):
            db_aws.recover_existing()

    def test_recovery_fills_endpoint_preserves_password_and_only_reads_aws(self):
        self.prepare_recovery()
        aws = FakeAws()
        self.run_recovery(aws)
        body = dict(line.split("=", 1) for line in
                    self.db_env.read_text(encoding="utf-8").splitlines()
                    if line and not line.startswith("#"))
        self.assertEqual(body["DB_HOST"], "db.rehearsal.invalid")
        self.assertEqual(body["DB_PASSWORD"], "keep-this-private")
        self.assertEqual(os.stat(self.db_env).st_mode & 0o777, 0o600)
        saved = json.loads(self.res.read_text(encoding="utf-8"))["db"]["rds"]
        self.assertEqual(saved["state"], "available")
        self.assertEqual(saved["endpoint"], "db.rehearsal.invalid")
        self.assertTrue(all(call[1] in ("describe-db-instances",
                                        "describe-route-tables",
                                        "describe-security-groups")
                            for call in aws.calls))

    def test_recovery_refuses_public_instance_without_changing_local_files(self):
        self.prepare_recovery()
        before_secret = self.db_env.read_bytes()
        before_record = self.res.read_bytes()
        aws = FakeAws()
        aws.recovery_public = True
        with self.assertRaisesRegex(SystemExit, "Public is True"):
            self.run_recovery(aws)
        self.assertEqual(self.db_env.read_bytes(), before_secret)
        self.assertEqual(self.res.read_bytes(), before_record)

    def test_network_only_partial_state_resumes_without_recreating_it(self):
        self.res.write_text(json.dumps({
            "sg": {"id": HOST_SG},
            "instance": {"id": "i-0b6a509de0b71f42e"},
            "db": {
                "route_table": {"id": "rtb-0abc123"},
                "subnets": [
                    {"id": "subnet-resume-a", "cidr": "172.31.96.0/24",
                     "az": "us-east-1a"},
                    {"id": "subnet-resume-b", "cidr": "172.31.97.0/24",
                     "az": "us-east-1b"},
                ],
            },
        }), encoding="utf-8")
        aws = FakeAws()
        aws.resuming = True
        aws.associated.update(("subnet-resume-a", "subnet-resume-b"))
        self.run_main(aws)
        actions = [call[1] for call in aws.calls]
        self.assertNotIn("create-route-table", actions)
        self.assertNotIn("create-subnet", actions)
        self.assertNotIn("associate-route-table", actions)
        self.assertIn("create-db-subnet-group", actions)
        self.assertIn("create-db-instance", actions)

    def test_the_whole_sequence_runs(self):
        aws = self.run_main()                       # must not raise
        actions = [c[1] for c in aws.calls]
        for expected in ("describe-vpcs", "create-route-table", "create-subnet",
                         "create-db-subnet-group", "create-security-group",
                         "authorize-security-group-ingress", "create-db-instance",
                         "describe-db-instances"):
            self.assertIn(expected, actions)

    def test_the_chosen_subnets_do_not_collide_and_span_two_azs(self):
        self.run_main()
        with mock.patch.object(
                db_aws, "aw",
                return_value=[[row["AvailabilityZone"], row["CidrBlock"]]
                              for row in REAL_SUBNETS]):
            plan = db_aws.pick_subnets(VPC, "172.31.0.0/16",
                                       [r["CidrBlock"] for r in REAL_SUBNETS])
        self.assertEqual([c for c, _ in plan], ["172.31.96.0/24", "172.31.97.0/24"])
        self.assertEqual(len({az for _, az in plan}), 2, "two different AZs")

    def test_every_created_id_is_recorded_as_it_is_created(self):
        self.run_main()
        saved = json.loads(self.res.read_text(encoding="utf-8"))["db"]
        self.assertEqual(saved["route_table"]["id"], "rtb-0abc123")
        self.assertEqual([s["id"] for s in saved["subnets"]],
                         ["subnet-new0", "subnet-new1"])
        self.assertEqual(saved["sg"]["id"], "sg-0db999")
        self.assertEqual(saved["rds"]["identifier"], "w03-g8-o1-w5")
        self.assertEqual(saved["rds"]["state"], "available")

    def test_the_secret_file_is_complete_and_owner_only(self):
        self.run_main()
        self.assertEqual(oct(os.stat(self.db_env).st_mode & 0o777), oct(0o600))
        body = dict(line.split("=", 1) for line in
                    self.db_env.read_text(encoding="utf-8").splitlines()
                    if line and not line.startswith("#"))
        self.assertEqual(body["DB_HOST"], "db.rehearsal.invalid")
        self.assertEqual(body["DB_NAME"], "inspection")
        self.assertEqual(body["DB_USER"], "inspection")
        self.assertTrue(body["DB_PASSWORD"], "the generated password must be present")
        self.assertTrue(all(v.strip() for v in body.values()),
                        "no value may be left blank once the instance is available")

    def test_the_password_exists_on_disk_before_the_wait_finishes(self):
        """If the wait dies, the password must already be safe and findable."""
        aws = FakeAws()
        aws.polls = -1                        # every poll stays "creating"
        boom = SystemExit("simulated: the wait was interrupted")
        with mock.patch.object(db_aws, "aw", aws), \
             mock.patch.object(db_aws.lab, "verify", return_value={"region": "us-east-1"}), \
             mock.patch("time.sleep", side_effect=boom), \
             mock.patch("builtins.print"):
            with self.assertRaises(SystemExit):
                db_aws.main()
        self.assertTrue(self.db_env.exists(),
                        "the password must be on disk before the long wait")
        saved = json.loads(self.res.read_text(encoding="utf-8"))["db"]
        self.assertEqual(saved["rds"]["state"], "creating")

    def test_a_single_value_projection_is_not_indexed_as_a_list(self):
        # The exact bug from run 1: "172.31.0.0/16"[0] == "1".
        self.run_main()
        self.assertEqual(db_aws.first("172.31.0.0/16"), "172.31.0.0/16")

    def test_the_tag_shorthand_keeps_its_literal_braces_on_every_create(self):
        aws = self.run_main()
        tagged = [c for c in aws.calls if "--tag-specifications" in c]
        self.assertEqual(len(tagged), 4, "route table + 2 subnets + SG")
        for call in tagged:
            spec = call[call.index("--tag-specifications") + 1]
            self.assertNotIn("%s", spec)
            self.assertRegex(spec, r"^ResourceType=[a-z-]+,Tags=\[\{Key=course,Value=yuntech-115-1\},")

    def test_db_subnet_group_tags_are_separate_cli_list_members(self):
        aws = self.run_main()
        call = next(c for c in aws.calls
                    if c[:2] == ["rds", "create-db-subnet-group"])
        subnet_ids_at = call.index("--subnet-ids")
        self.assertEqual(call[subnet_ids_at + 1:subnet_ids_at + 3],
                         ["subnet-new0", "subnet-new1"])
        tags_at = call.index("--tags")
        self.assertEqual(call[tags_at + 1:tags_at + 5], [
            "Key=course,Value=yuntech-115-1",
            "Key=week,Value=w05",
            "Key=group,Value=test-group",
            "Key=owner,Value=test-owner",
        ])


if __name__ == "__main__":
    unittest.main()