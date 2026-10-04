"""Opt-in native PostgreSQL proof. Dedicated local fixture DB only."""

import os, copy, unittest
from pathlib import Path
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
import psycopg
from psycopg.types.json import Jsonb
from helper.auth import Caller
from helper.journal import Journal
from helper.errors import HelperError
from test_context_helper import envelope

URL = os.environ.get("UUID_TEST_DATABASE_URL", "")


@unittest.skipUnless(URL, "UUID_TEST_DATABASE_URL required (isolated fixture)")
class PostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "127.0.0.1" not in URL or "fixture" not in URL:
            raise RuntimeError("fixture only")
        with psycopg.connect(URL, autocommit=True) as c:
            c.execute(Path("migrations/001_context_journal.sql").read_text())
            for role, group in [
                ("uuid_fixture_dev", "sonoora_uuid_dev"),
                ("uuid_fixture_prod", "sonoora_uuid_prod"),
            ]:
                if not c.execute(
                    "SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)
                ).fetchone():
                    c.execute(f"CREATE ROLE {role} LOGIN")
                c.execute(f"GRANT {group} TO {role}")

    @staticmethod
    def connection(role="uuid_fixture_dev"):
        return psycopg.connect(URL.replace("fixture_admin@", role + "@"))

    def setUp(self):
        with psycopg.connect(URL) as c:
            c.execute(
                "TRUNCATE uuid_audit.operations,uuid_audit.issuances,uuid_audit.quotas CASCADE"
            )
        self.context = envelope()["context"]
        self.receipt = {
            "environment": "dev",
            "verifiedCaller": "api-dev",
            "operationId": self.context["operationId"],
            "providerIdempotencyKey": self.context["providerIdempotencyKey"],
            "contextHash": "a" * 64,
            "requestId": str(uuid4()),
            "issuanceId": str(uuid4()),
        }

    def emit(self, ctx=None, receipt=None, role="uuid_fixture_dev"):
        with self.connection(role) as c:
            return c.execute(
                "SELECT uuid_audit.record_emission(%s,%s)",
                (Jsonb(ctx or self.context), Jsonb(receipt or self.receipt)),
            ).fetchone()

    def test_insert_lookup_scope_no_update(self):
        self.emit()
        with self.connection() as c:
            self.assertEqual(
                c.execute(
                    "SELECT uuid_audit.read_receipt(%s)", (self.receipt["requestId"],)
                ).fetchone()[0],
                self.receipt,
            )
        with self.connection("uuid_fixture_prod") as c:
            self.assertIsNone(
                c.execute(
                    "SELECT uuid_audit.read_receipt(%s)", (self.receipt["requestId"],)
                ).fetchone()[0]
            )
        for sql in [
            "SELECT * FROM uuid_audit.issuances",
            "UPDATE uuid_audit.issuances SET receipt=receipt",
            "DELETE FROM uuid_audit.issuances",
        ]:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.connection() as c:
                    c.execute(sql)

    def test_wrong_environment_and_owner_rejected(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.emit(role="uuid_fixture_prod")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.emit(role="fixture_admin")

    def test_concurrent_replay_one_commit(self):
        def run(_):
            try:
                self.emit()
                return True
            except psycopg.Error:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(run, range(8))), 1)

    def test_immutable_context(self):
        self.emit()
        ctx = copy.deepcopy(self.context)
        ctx["command"]["amounts"] = ["9"]
        r = {**self.receipt, "requestId": str(uuid4()), "issuanceId": str(uuid4())}
        with self.assertRaises(psycopg.Error) as e:
            self.emit(ctx, r)
        self.assertEqual(e.exception.sqlstate, "P0002")

    def test_distributed_quota_rolls_back_denied_issuance(self):
        for _ in range(30):
            self.emit(
                receipt={
                    **self.receipt,
                    "requestId": str(uuid4()),
                    "issuanceId": str(uuid4()),
                }
            )
        with self.assertRaises(psycopg.Error) as e:
            self.emit()
        self.assertEqual(e.exception.sqlstate, "P0003")
        with psycopg.connect(URL) as c:
            self.assertEqual(
                c.execute("SELECT count(*) FROM uuid_audit.issuances").fetchone()[0], 30
            )

    def test_journal_commit_and_conflict_mapping(self):
        outer = self

        class FixtureJournal(Journal):
            def _connect(self, caller):
                return outer.connection()

        j = FixtureJournal()
        caller = Caller("api-dev", "dev")
        j.record(caller, self.context, self.receipt)
        with self.assertRaises(HelperError) as e:
            j.record(caller, self.context, self.receipt)
        self.assertEqual(e.exception.status, 409)
