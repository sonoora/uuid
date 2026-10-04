import os
import threading
import psycopg
from psycopg.types.json import Jsonb
from .errors import HelperError
from .canonical import digest
from uuid import uuid4

_slots = threading.BoundedSemaphore(4)


class Journal:
    def _connect(self, caller):
        url = os.environ.get(
            "UUID_AUDIT_DATABASE_URL_" + caller.environment.upper(), ""
        )
        if not url:
            raise HelperError("JOURNAL_UNAVAILABLE", 503)
        return psycopg.connect(
            url,
            connect_timeout=5,
            sslmode="require",
            options="-c statement_timeout=5000",
        )

    def _run(self, caller, action):
        if not _slots.acquire(timeout=1):
            raise HelperError("JOURNAL_UNAVAILABLE", 503)
        try:
            with self._connect(caller) as conn:
                return action(conn)
        except HelperError:
            raise
        except psycopg.Error as exc:
            if exc.sqlstate == "P0002":
                raise HelperError("CONTEXT_CONFLICT", 409) from None
            if exc.sqlstate == "P0003":
                raise HelperError("RATE_LIMITED", 429) from None
            raise HelperError("JOURNAL_UNAVAILABLE", 503) from None
        finally:
            _slots.release()

    def prepare(self, caller, envelope):
        row = self._run(
            caller,
            lambda conn: conn.execute(
                "SELECT uuid_audit.prepare_request(%s,%s,%s,%s)",
                (
                    Jsonb(envelope),
                    digest("request", envelope),
                    digest("context", envelope["context"]),
                    envelope["idempotencyKey"] or str(uuid4()),
                ),
            ).fetchone(),
        )
        return str(row[0])

    def record(self, caller, receipt):
        self._run(
            caller,
            lambda conn: conn.execute(
                "SELECT uuid_audit.record_receipt(%s)",
                (Jsonb(receipt),),
            ).fetchone(),
        )

    def lookup(self, caller, request_id):
        row = self._run(
            caller,
            lambda conn: conn.execute(
                "SELECT uuid_audit.read_emission_receipt(%s)", (request_id,)
            ).fetchone(),
        )
        if not row or row[0] is None:
            raise HelperError("NOT_FOUND", 404)
        return row[0]
