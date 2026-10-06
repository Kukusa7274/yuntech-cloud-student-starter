"""W5 offline checks for the deployment scripts.

No AWS calls: scripts/lab.py is importable without credentials, and the two
functions under test that would otherwise talk to AWS -- pick_subnets() and
combine_secrets() -- are pure or take their input as a parameter, so the module
attribute `aw` is replaced with a stub here.

These tests check the arithmetic and the quoting. They cannot check that AWS
accepts the result; the real evidence is db-up.sh's readback and the idempotency
matrix run against the deployed host.
"""
import importlib.util
import ipaddress
import os
import shutil
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "deploy"))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


os.environ.setdefault("W3_GROUP", "test-group")
os.environ.setdefault("W3_OWNER", "1")

db_aws = load_module("w05_db_aws", "deploy/db_aws.py")
deploy_aws = load_module("w05_deploy_aws", "deploy/deploy_aws.py")


def stub_describe_subnets(rows):
    """Replace the AWS call pick_subnets makes, and record the queries."""
    seen = []

    def fake_aw(args):          # same signature as db_aws.aw(args)
        seen.append(args)
        if args[0] == "ec2" and args[1] == "describe-subnets":
            return rows
        raise AssertionError("unexpected AWS call: " + " ".join(args[:2]))

    return fake_aw, seen


class SubnetSelection(unittest.TestCase):
    """Spec 1: two private subnets, non-overlapping, in two different AZs."""

    def setUp(self):
        self.original = db_aws.aw

    def tearDown(self):
        db_aws.aw = self.original

    def pick(self, vpc_cidr, rows, should_work=True):
        fake, seen = stub_describe_subnets(rows)
        db_aws.aw = fake
        if not should_work:
            with self.assertRaises(SystemExit):
                db_aws.pick_subnets("vpc-test", vpc_cidr, [])
            return None
        chosen = db_aws.pick_subnets("vpc-test", vpc_cidr, [])
        # The query must be scoped to this VPC, never "all subnets in the account".
        self.assertIn("--filters", seen[0])
        self.assertIn("Name=vpc-id,Values=vpc-test", seen[0])
        return chosen

    def assert_invariants(self, vpc_cidr, chosen, existing):
        vpc = ipaddress.ip_network(vpc_cidr)
        self.assertEqual(len(chosen), 2, chosen)
        cids = [ipaddress.ip_network(cid) for cid, _ in chosen]
        azs = [az for _, az in chosen]
        self.assertEqual(len(set(azs)), 2, "the two subnets must be in different AZs")
        self.assertEqual(len(set(cids)), 2, "the two subnets must differ")
        for cid in cids:
            self.assertEqual(cid.prefixlen, 24, "a /24 was specified")
            self.assertTrue(cid.subnet_of(vpc), f"{cid} escaped the VPC {vpc}")
            self.assertNotEqual(cid.network_address, vpc.network_address,
                                "the VPC's own block stays in reserve")
            for taken in existing:
                self.assertFalse(cid.overlaps(ipaddress.ip_network(taken)),
                                 f"{cid} overlaps the existing subnet {taken}")
        for index, first in enumerate(cids):
            for second in cids[index + 1:]:
                self.assertFalse(first.overlaps(second), "the two new subnets overlap")

    def test_default_vpc_shape(self):
        existing = [["us-east-1a", "172.31.0.0/24"], ["us-east-1a", "172.31.1.0/24"],
                    ["us-east-1b", "172.31.2.0/24"]]
        chosen = self.pick("172.31.0.0/16", existing)
        self.assert_invariants("172.31.0.0/16", chosen, [c for _, c in existing])

    def test_a_wider_vpc_does_not_confuse_the_walk(self):
        # A VPC that is not a /16: the host bits do not start at the third octet,
        # so anything that walks "the second octet" picks the wrong range here.
        existing = [["us-east-1a", "172.16.0.0/16"], ["us-east-1b", "172.17.0.0/24"]]
        chosen = self.pick("172.16.0.0/12", existing)
        self.assert_invariants("172.16.0.0/12", chosen, [c for _, c in existing])

    def test_a_tight_vpc_is_still_usable(self):
        existing = [["us-east-1a", "10.0.0.0/21"], ["us-east-1b", "10.0.8.0/22"]]
        chosen = self.pick("10.0.0.0/20", existing)
        self.assert_invariants("10.0.0.0/20", chosen, [c for _, c in existing])

    def test_three_azs_still_yield_two_subnets(self):
        existing = [["us-east-1c", "172.31.0.0/24"], ["us-east-1a", "172.31.1.0/24"],
                    ["us-east-1b", "172.31.2.0/24"]]
        chosen = self.pick("172.31.0.0/16", existing)
        self.assert_invariants("172.31.0.0/16", chosen, [c for _, c in existing])

    def test_a_vpc_that_spans_one_az_is_refused(self):
        # RDS needs two AZs for its subnet group; refusing beats creating
        # something the service cannot place the database in.
        self.pick("172.31.0.0/16", [["us-east-1a", "172.31.0.0/24"]], should_work=False)

    def test_a_vpc_too_small_for_two_blocks_is_refused(self):
        self.pick("10.1.0.0/24", [["us-east-1a", "10.1.0.0/24"], ["us-east-1b", "10.1.1.0/24"]],
                  should_work=False)

    def test_a_caller_supplied_list_is_honoured_too(self):
        fake, _ = stub_describe_subnets([["us-east-1a", "172.31.0.0/24"],
                                         ["us-east-1b", "172.31.1.0/24"]])
        db_aws.aw = fake
        chosen = db_aws.pick_subnets("vpc-test", "172.31.0.0/16", ["172.31.2.0/24"])
        self.assertNotIn("172.31.2.0/24", [c for c, _ in chosen],
                         "a range passed in by the caller must be treated as taken")
        self.assert_invariants("172.31.0.0/16", chosen,
                               ["172.31.0.0/24", "172.31.1.0/24", "172.31.2.0/24"])


# A complete W5 db.env. Partial fixtures now fail on purpose -- a secret file
# with a blank DB_HOST is the placeholder db-up.sh writes mid-create, and
# combine_secrets must refuse it rather than deploy it.
DB_ENV = ("DB_HOST=db.example.invalid\nDB_PORT=5432\nDB_NAME=inspection\n"
          "DB_USER=u\nDB_PASSWORD=p\n")


class SecretStaging(unittest.TestCase):
    """W5: both secret files reach the host as one EnvironmentFile."""

    def combine(self, app, db):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        app_path = Path(tmp.name) / "app.env"
        app_path.write_text(app, encoding="utf-8")
        os.chmod(app_path, 0o600)
        db_path = None
        if db is not None:
            db_path = Path(tmp.name) / "db.env"
            db_path.write_text(db, encoding="utf-8")
            os.chmod(db_path, 0o600)
        staging = deploy_aws.combine_secrets(str(app_path), str(db_path) if db_path else "")
        self.addCleanup(lambda: os.path.exists(staging) and os.unlink(staging))
        return staging

    def keys(self, path):
        return [line.split("=", 1)[0]
                for line in Path(path).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")]

    def test_tokens_and_database_settings_end_up_in_one_file(self):
        staging = self.combine("REPORTER_TOKEN=r\nOPERATOR_TOKEN=o\n",
                               "DB_HOST=h\nDB_PORT=5432\nDB_NAME=inspection\n"
                               "DB_USER=u\nDB_PASSWORD=p\n")
        self.assertEqual(self.keys(staging),
                         ["REPORTER_TOKEN", "OPERATOR_TOKEN", "DB_HOST", "DB_PORT",
                          "DB_NAME", "DB_USER", "DB_PASSWORD"])

    def test_the_staging_file_is_owner_only(self):
        # It holds the tokens AND the database password, so 600 is the point.
        staging = self.combine("REPORTER_TOKEN=r\nOPERATOR_TOKEN=o\n", DB_ENV)
        self.assertEqual(stat.S_IMODE(os.stat(staging).st_mode), 0o600)

    def test_a_missing_db_file_degrades_to_tokens_only(self):
        staging = self.combine("REPORTER_TOKEN=r\nOPERATOR_TOKEN=o\n", None)
        self.assertEqual(self.keys(staging), ["REPORTER_TOKEN", "OPERATOR_TOKEN"])

    def test_a_duplicate_key_is_refused_not_silently_overwritten(self):
        # systemd would keep the last value, so a typo in db.env would quietly
        # point the service at the wrong database.
        with self.assertRaises(SystemExit) as caught:
            self.combine("DB_HOST=old\nREPORTER_TOKEN=r\nOPERATOR_TOKEN=o\n",
                         "DB_HOST=new\nDB_PASSWORD=p\n")
        self.assertIn("DB_HOST", str(caught.exception))

    def test_a_key_systemd_would_reject_is_refused_here(self):
        with self.assertRaises(SystemExit):
            self.combine("REPORTER_TOKEN=r\nOPERATOR_TOKEN=o\nnot a key=value\n", None)

    def test_a_line_without_an_equals_sign_is_refused(self):
        with self.assertRaises(SystemExit):
            self.combine("REPORTER_TOKEN=r\njust-a-word\n", None)

    def test_a_file_without_a_trailing_newline_is_joined_correctly(self):
        staging = self.combine("REPORTER_TOKEN=r\nOPERATOR_TOKEN=o", DB_ENV.rstrip("\n"))
        self.assertEqual(self.keys(staging),
                         ["REPORTER_TOKEN", "OPERATOR_TOKEN", "DB_HOST", "DB_PORT",
                          "DB_NAME", "DB_USER", "DB_PASSWORD"])

    def test_comments_and_blank_lines_do_not_become_variables(self):
        staging = self.combine("# tokens\n\nREPORTER_TOKEN=r\nOPERATOR_TOKEN=o\n",
                               "# database\n" + DB_ENV)
        # The comment and the blank line produce no variables; the real keys do.
        self.assertEqual(self.keys(staging),
                         ["REPORTER_TOKEN", "OPERATOR_TOKEN", "DB_HOST", "DB_PORT",
                          "DB_NAME", "DB_USER", "DB_PASSWORD"])

    def test_the_password_is_in_the_staging_file_and_nowhere_else(self):
        staging = self.combine("REPORTER_TOKEN=r\nOPERATOR_TOKEN=o\n",
                               DB_ENV.replace("DB_PASSWORD=p", "DB_PASSWORD=synthetic-only"))
        body = Path(staging).read_text(encoding="utf-8")
        self.assertIn("DB_PASSWORD=synthetic-only", body)
        # The module must not carry the secret anywhere but that file.
        source = (ROOT / "deploy/deploy_aws.py").read_text(encoding="utf-8")
        self.assertNotIn("synthetic-only", source)


class RemoteFragmentQuoting(unittest.TestCase):
    """ssh re-parses argv on the remote shell, so quoting is load-bearing."""

    def test_shq_keeps_one_fragment_as_one_argument(self):
        self.assertEqual(deploy_aws.shq("a && b"), "'a && b'")
        self.assertEqual(deploy_aws.shq("it's"), "'it'\\''s'")


class SecretFileHygiene(unittest.TestCase):
    """The master password cannot be read back from AWS. Whatever is not on disk
    at the moment create-db-instance returns is gone for good."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, "db.env")

    def test_first_write_is_600_and_refuses_a_pre_existing_file(self):
        db_aws.write_db_env(self.path, "", 5432, "synthetic-only", exclusive=True)
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), oct(0o600))
        with self.assertRaises(SystemExit):
            db_aws.write_db_env(self.path, "host", 5432, "other", exclusive=True)
        # The first write wins, because O_EXCL must fail loudly instead of
        # silently replacing a secret that is already deployed to the host.
        self.assertIn("DB_PASSWORD=synthetic-only",
                      Path(self.path).read_text(encoding="utf-8"))

    def test_the_later_write_fills_in_the_endpoint_and_keeps_the_password(self):
        db_aws.write_db_env(self.path, "", 5432, "synthetic-only", exclusive=True)
        db_aws.write_db_env(self.path, "db.example.invalid", 5432, "synthetic-only",
                            exclusive=False)
        body = Path(self.path).read_text(encoding="utf-8")
        self.assertIn("DB_HOST=db.example.invalid", body)
        self.assertIn("DB_PASSWORD=synthetic-only", body)
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), oct(0o600))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "needs O_NOFOLLOW")
    def test_a_symlink_cannot_redirect_the_secret(self):
        target = os.path.join(self.tmp, "somewhere-else")
        os.symlink(target, self.path)
        with self.assertRaises(SystemExit):
            db_aws.write_db_env(self.path, "h", 5432, "synthetic-only", exclusive=False)
        self.assertFalse(os.path.exists(target),
                         "the secret must not be written through the symlink")

    def test_deploy_refuses_the_placeholder_left_by_an_unfinished_wait(self):
        # What db-up.sh writes the instant create-db-instance returns: the password is
        # safe on disk but DB_HOST is still blank. The check that has to catch it if
        # the multi-minute wait never finished.
        db_aws.write_db_env(self.path, "", 5432, "synthetic-only", exclusive=True)
        app = os.path.join(self.tmp, "app.env")
        Path(app).write_text("REPORTER_TOKEN=r\nOPERATOR_TOKEN=o\n", encoding="utf-8")
        with self.assertRaises(SystemExit) as caught:
            deploy_aws.combine_secrets(app, self.path)
        self.assertIn("DB_HOST", str(caught.exception))


if __name__ == "__main__":
    unittest.main()