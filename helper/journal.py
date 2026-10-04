import os
import threading
import psycopg
from psycopg.types.json import Jsonb
from .errors import HelperError

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

    def record(self, caller, context, receipt):
        self._run(
            caller,
            lambda conn: conn.execute(
                "SELECT uuid_audit.record_emission(%s,%s)",
                (Jsonb(context), Jsonb(receipt)),
            ).fetchone(),
        )

    def lookup(self, caller, request_id):
        row = self._run(
            caller,
            lambda conn: conn.execute(
                "SELECT uuid_audit.read_receipt(%s)", (request_id,)
            ).fetchone(),
        )
        if not row or row[0] is None:
            raise HelperError("NOT_FOUND", 404)
        return row[0]
