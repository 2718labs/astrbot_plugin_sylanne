"""Permanent bounded metadata-selector checks; no installed P2 qualification."""
import json
import sqlite3

import unittest

from sylanne3.authority_service.owner_stop_reply_v1 import _read_owner_reply_control_targets_v1
from sylanne3.runtime_contracts import NamespaceId


def _listing_db(rows):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE runtime_jobs(job_id TEXT,continuation_json TEXT,phase TEXT,bot_id TEXT,persona_id TEXT,work_kind TEXT,operation_id TEXT)")
    db.execute("CREATE TABLE graph_bundle_operations(bot TEXT,persona TEXT,operation_id TEXT,commit_seq INTEGER)")
    for job, phase, sequence, bot in rows:
        operation = "create:" + job
        db.execute("INSERT INTO runtime_jobs VALUES(?,?,?,?,?,?,?)",
            (job, json.dumps({"job": job}), phase, bot, "persona", "d11.foreground_cycle.v1", operation))
        db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?)", (bot, "persona", operation, sequence))
    return db


class OwnerReplyControlListTests(unittest.TestCase):
    def test_thirty_three_historical_cycles_leave_latest_current_stop_on_first_page(self):
        rows = [(f"history-{i}", "completed", i + 1, "bot") for i in range(33)]
        rows += [("current", "running", 100, "bot"), ("other", "running", 101, "another-bot")]
        with _listing_db(rows) as db:
            page, cursor = _read_owner_reply_control_targets_v1(db, NamespaceId("bot", "persona"), None)
            assert len(page) == 32 and page[0][0] == "current"
            assert "other" not in dict(page)
            tail, final_cursor = _read_owner_reply_control_targets_v1(db, NamespaceId("bot", "persona"), cursor)
            assert len(tail) == 2 and final_cursor is None
            assert len({job for job, _ in (*page, *tail)}) == 34


    def test_unknown_work_pages_without_truncation_and_uses_actual_creation_order(self):
        rows = [(f"unknown-{i:02}", "pending_confirmation", 100 - i, "bot") for i in range(33)]
        rows += [("latest", "draining", 200, "bot"), ("history", "cancelled", 300, "bot")]
        with _listing_db(rows) as db:
            page, cursor = _read_owner_reply_control_targets_v1(db, NamespaceId("bot", "persona"), None)
            assert len(page) == 32 and page[0][0] == "latest"
            tail, final_cursor = _read_owner_reply_control_targets_v1(db, NamespaceId("bot", "persona"), cursor)
            assert [job for job, _ in tail] == ["unknown-31", "unknown-32", "history"]
            assert final_cursor is None
            assert len({job for job, _ in (*page, *tail)}) == 35


    def test_reply_control_cursor_rejects_changed_keyset_contract(self):
        with _listing_db([]) as db:
            for cursor in ['[0,1,"current"] ', '[2,1,"current"]', '[0,0,"current"]']:
                with self.subTest(cursor=cursor), self.assertRaisesRegex(ValueError, "canonical Owner reply control cursor"):
                    _read_owner_reply_control_targets_v1(db, NamespaceId("bot", "persona"), cursor)


if __name__ == "__main__":
    unittest.main()
