"""Isolated native PostgreSQL tests, never a production database."""

import os, copy, unittest
from pathlib import Path
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
import psycopg
from helper.auth import Caller
from helper.journal import Journal
from helper.service import Issuer
from helper.errors import HelperError
from test_context_helper import envelope, ENV
import base64

URL = os.environ.get("UUID_TEST_DATABASE_URL", "")


class FixtureJournal(Journal):
    def _connect(self, caller):
        return psycopg.connect(
            URL.replace("fixture_admin@", "uuid_fixture_" + caller.environment + "@")
        )


@unittest.skipUnless(URL, "isolated fixture URL required")
class PostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "127.0.0.1" not in URL or "fixture" not in URL:
            raise RuntimeError("fixture only")
        with psycopg.connect(URL, autocommit=True) as c:
            c.execute(Path("migrations/002_emission_journal.sql").read_text())
            for suffix in ["dev", "prod"]:
                role = "uuid_fixture_" + suffix
                if not c.execute(
                    "SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)
                ).fetchone():
                    c.execute(f"CREATE ROLE {role} LOGIN")
                c.execute(f"GRANT sonoora_uuid_{suffix} TO {role}")

    def setUp(self):
        with psycopg.connect(URL) as c:
            c.execute(
                "TRUNCATE uuid_audit.emission_requests,uuid_audit.emission_receipts,uuid_audit.emission_quotas"
            )
        self.journal = FixtureJournal()
        self.caller = Caller("api-dev", "dev")
        self.issuer = Issuer(
            self.journal,
            encrypt=lambda: base64.b64encode(os.urandom(256)).decode(),
            env=ENV,
        )

    def test_receipt_scope_and_role_privileges(self):
        req = envelope()
        result = self.issuer.issue(self.caller, req)
        self.assertEqual(
            self.journal.lookup(self.caller, req["requestId"]), result["audit"]
        )
        with self.assertRaises(HelperError):
            self.journal.lookup(Caller("api-prod", "prod"), req["requestId"])
        for sql in [
            "SELECT * FROM uuid_audit.emission_receipts",
            "DELETE FROM uuid_audit.emission_receipts",
            "UPDATE uuid_audit.emission_requests SET request_hash='x'",
        ]:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.journal._connect(self.caller) as c:
                    c.execute(sql)

    def test_concurrent_retries_one_key_many_fresh_receipts(self):
        req = envelope()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(
                pool.map(lambda _: self.issuer.issue(self.caller, req), range(8))
            )
        self.assertEqual(len({r["idempotencyKey"] for r in results}), 1)
        self.assertEqual(len({r["audit"]["issuanceId"] for r in results}), 8)
        with psycopg.connect(URL) as c:
            self.assertEqual(
                c.execute(
                    "SELECT count(*) FROM uuid_audit.emission_requests"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                c.execute(
                    "SELECT count(*) FROM uuid_audit.emission_receipts"
                ).fetchone()[0],
                8,
            )

    def test_changed_request_rejected(self):
        req = envelope()
        self.issuer.issue(self.caller, req)
        req["idempotencyKey"] = str(uuid4())
        with self.assertRaises(HelperError) as error:
            self.issuer.issue(self.caller, req)
        self.assertEqual(error.exception.status, 409)

    def test_effective_key_preserved_across_requests(self):
        req = envelope()
        req["idempotencyKey"] = str(uuid4())
        a = self.issuer.issue(self.caller, req)
        req["requestId"] = str(uuid4())
        b = self.issuer.issue(self.caller, req)
        self.assertEqual(a["idempotencyKey"], b["idempotencyKey"])

    def test_quota_no_receipt_on_rejection(self):
        req = envelope()
        for _ in range(30):
            self.issuer.issue(self.caller, req)
        with self.assertRaises(HelperError) as error:
            self.issuer.issue(self.caller, req)
        self.assertEqual(error.exception.status, 429)
        with psycopg.connect(URL) as c:
            self.assertEqual(
                c.execute(
                    "SELECT count(*) FROM uuid_audit.emission_receipts"
                ).fetchone()[0],
                30,
            )

    def test_preparation_survives_encryption_failure(self):
        req = envelope()

        def fail():
            raise RuntimeError("synthetic failure")

        with self.assertRaises(RuntimeError):
            Issuer(self.journal, encrypt=fail, env=ENV).issue(self.caller, req)
        key = self.journal.prepare(self.caller, req)
        self.assertEqual(self.issuer.issue(self.caller, req)["idempotencyKey"], key)
