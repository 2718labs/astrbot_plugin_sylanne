"""P2 admission epoch covers independent Authority SQLite writers."""

import sqlite3

from sylanne3.authority_service import AuthorityServiceCore
from sylanne3.authority_service.v2_dispatch_admission_epoch import (
    current_admission_stamp_in_tx,
)


def _core(path):
    return AuthorityServiceCore(
        path, authorizer=lambda *_: True,
        deletion_verifier=lambda *_: True,
        execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True, create=True)


def test_epoch_tracks_other_connection_and_schema_gap(tmp_path):
    path = tmp_path / "authority.db"
    core = _core(path)
    try:
        with core._tx() as db:
            before = current_admission_stamp_in_tx(db)
        with sqlite3.connect(path) as other:
            other.execute(
                "UPDATE authority_meta SET value=? WHERE key='authority_id'",
                ("changed",))
        with core._tx() as db:
            after = current_admission_stamp_in_tx(db)
        assert after.epoch == before.epoch + 1
        assert after.schema_version == before.schema_version

        # A table created during the graph callback did not yet have a
        # trigger. Its schema change still invalidates the P2 snapshot.
        with sqlite3.connect(path) as other:
            other.execute("CREATE TABLE authority_new_writer(value TEXT)")
            other.execute("INSERT INTO authority_new_writer VALUES('race')")
        with core._tx() as db:
            after_ddl = current_admission_stamp_in_tx(db)
        assert after_ddl.schema_version != after.schema_version
        with sqlite3.connect(path) as other:
            other.execute("INSERT INTO authority_new_writer VALUES('later')")
        with core._tx() as db:
            covered = current_admission_stamp_in_tx(db)
        assert covered.epoch == after_ddl.epoch + 1

        # A writer that drops a trigger can hide its DML from the counter,
        # but cannot hide SQLite's durable schema cookie transition.
        with sqlite3.connect(path) as other:
            name = other.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name='authority_new_writer' LIMIT 1").fetchone()[0]
            other.execute(f'DROP TRIGGER "{name}"')
            other.execute("INSERT INTO authority_new_writer VALUES('uncovered')")
        with core._tx() as db:
            repaired = current_admission_stamp_in_tx(db)
        assert repaired.schema_version != covered.schema_version
    finally:
        core.close()
