import sqlite3
import unittest

from server.app.collector.repository import (
    ensure_schema,
    get_proxy_operation_audit_by_request_id,
    write_proxy_operation_audit,
)


class TestProxyOperationAudit(unittest.TestCase):
    def test_write_and_read_audit_record(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            ensure_schema(connection)
            write_proxy_operation_audit(
                connection,
                request_id="proxy-req-1",
                actor_id="user-1",
                actor_role="admin",
                scope="proxy:dhcp:write",
                operation="deleteStaticLease",
                target="00:11:22:33:44:55",
                status="success",
                error_code=None,
                details_json='{"resultSummary":"ok"}',
                created_at="2026-03-22T10:00:00Z",
            )
            connection.commit()

            record = get_proxy_operation_audit_by_request_id(connection, "proxy-req-1")

        self.assertIsNotNone(record)
        if record is None:
            self.fail("Expected audit record")
        self.assertEqual(record["operation"], "deleteStaticLease")
        self.assertEqual(record["status"], "success")

    def test_missing_request_id_returns_none(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            ensure_schema(connection)
            record = get_proxy_operation_audit_by_request_id(connection, "missing")
        self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()
