"""Capacity policy exercises against an isolated native PostgreSQL fixture."""
import os, copy, time, unittest
from pathlib import Path
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
import psycopg
from psycopg.types.json import Jsonb
from helper.auth import Caller
from helper.errors import HelperError
from test_postgres_journal import FixtureJournal
from test_context_helper import envelope
URL = os.environ.get('UUID_TEST_DATABASE_URL', '')

@unittest.skipUnless(URL, 'isolated fixture required')
class CapacityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if '127.0.0.1' not in URL or 'capacity_fixture_20261007' not in URL:
            raise RuntimeError('fixture only')
        with psycopg.connect(URL, autocommit=True) as conn:
            conn.execute(Path('migrations/002_emission_journal.sql').read_text())
            conn.execute(Path('migrations/003_emission_capacity.sql').read_text())
            for suffix in ['dev','prod']:
                role='uuid_fixture_'+suffix
                if not conn.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(role,)).fetchone():
                    conn.execute(f'CREATE ROLE {role} LOGIN')
                conn.execute(f'GRANT sonoora_uuid_{suffix} TO {role}')
    def setUp(self):
        with psycopg.connect(URL) as conn:
            conn.execute('TRUNCATE uuid_audit.emission_requests,uuid_audit.emission_receipts,uuid_audit.emission_capacity_counters')
            conn.execute("UPDATE uuid_audit.emission_capacity_policy SET per_second=100,per_minute=120 WHERE bucket='global'")
            conn.execute("UPDATE uuid_audit.emission_capacity_policy SET per_second=100,per_minute=90 WHERE bucket<>'global'")
        self.journal=FixtureJournal();self.caller=Caller('api-dev','dev')
    def prepare(self, n=0, purpose='money_transfer', subject='fixture'):
        req=envelope();req['context']['purpose']=purpose;req['context']['details']['userId']=subject
        try: return self.journal.prepare(self.caller,req)
        except HelperError as error: return error.status
    def test_concurrent_global_cap_and_purpose_reservation(self):
        with psycopg.connect(URL) as conn:
            conn.execute("UPDATE uuid_audit.emission_capacity_policy SET per_minute=12 WHERE bucket='global'")
            conn.execute("UPDATE uuid_audit.emission_capacity_policy SET per_minute=8 WHERE bucket='wallet_create'")
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda n:self.prepare(n,'wallet_create',f'user{n}'),range(24)))
        self.assertEqual(sum(isinstance(v,str) for v in results),8)
        self.assertTrue(all(v==429 for v in results if not isinstance(v,str)))
        self.assertTrue(all(isinstance(self.prepare(n,subject=f'money{n}'),str) for n in range(4)))
        self.assertEqual(self.prepare(subject='extra'),429)
        with psycopg.connect(URL) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM uuid_audit.emission_requests').fetchone()[0],12)
    def test_subject_scope_policy_privileges_and_context_idempotency(self):
        with psycopg.connect(URL) as conn:
            conn.execute("UPDATE uuid_audit.emission_capacity_policy SET per_minute=2 WHERE bucket='subject'")
        req=envelope();req['context']['details']['userId']='one'
        a=self.journal.prepare(self.caller,req);b=self.journal.prepare(self.caller,req)
        self.assertEqual(a,b)
        self.assertEqual(self.prepare(purpose='wallet_create',subject='one'),429)
        self.assertIsInstance(self.prepare(subject='two'),str)
        for sql in ['SELECT * FROM uuid_audit.emission_capacity_policy','UPDATE uuid_audit.emission_capacity_policy SET per_minute=1000','DELETE FROM uuid_audit.emission_capacity_counters']:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.journal._connect(self.caller) as conn:conn.execute(sql)
        with self.assertRaises(HelperError):self.journal.prepare(Caller('api-prod','prod'),req)
    def test_missing_policy_and_invalid_purpose_fail_closed(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.journal._connect(self.caller) as conn:
                conn.execute('SELECT uuid_audit.prepare_request(%s,NULL,NULL,%s)',(Jsonb(envelope()),uuid4()))
        req=envelope();req['context']['purpose']='unexpected'
        with self.assertRaises(HelperError):self.journal.prepare(self.caller,req)
        with psycopg.connect(URL) as conn:conn.execute("DELETE FROM uuid_audit.emission_capacity_policy WHERE environment='dev' AND bucket='subject'")
        try:
            with self.assertRaises(HelperError):self.journal.prepare(self.caller,envelope())
        finally:
            with psycopg.connect(URL) as conn:conn.execute("INSERT INTO uuid_audit.emission_capacity_policy VALUES('dev','subject',30,4)")
    def test_parallel_preparation_capacity_and_counter_cleanup(self):
        with psycopg.connect(URL) as conn:
            conn.execute('UPDATE uuid_audit.emission_capacity_policy SET per_minute=600,per_second=100')
            conn.execute("INSERT INTO uuid_audit.emission_capacity_counters VALUES('dev','expired',60,now()-interval '3 days',1)")
        started=time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda n:self.prepare(n,subject=f'load-{n}'),range(120)))
        self.assertTrue(all(isinstance(v,str) for v in results),results)
        elapsed=time.monotonic()-started
        with psycopg.connect(URL) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM uuid_audit.emission_capacity_counters WHERE bucket='expired'").fetchone()[0],0)
        print({'fixture':'uuid-120-preparations','seconds':round(elapsed,3),'concurrency':4})
