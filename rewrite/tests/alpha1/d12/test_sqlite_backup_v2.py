"""Actual SQLite WAL snapshots; not four-store compatibility or restore proof."""
from pathlib import Path
import sqlite3
import pytest
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d12_sqlite_backup_v2 import snapshot_sqlite_file_v2


def test_actual_wal_rows_blob_and_append_trigger_survive_without_source_mutation(tmp_path):
    source=tmp_path/'source.sqlite3';db=sqlite3.connect(source)
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('CREATE TABLE originals(id INTEGER PRIMARY KEY,payload BLOB NOT NULL,amount INTEGER NOT NULL) STRICT')
    db.execute("CREATE TRIGGER immutable BEFORE UPDATE ON originals BEGIN SELECT RAISE(ABORT,'immutable'); END")
    db.execute('INSERT INTO originals VALUES(1,?,?)',(b'actual\x00original',37));db.commit()
    assert Path(str(source)+'-wal').exists()
    wal_before=Path(str(source)+'-wal').read_bytes();source_before=source.read_bytes()
    result=snapshot_sqlite_file_v2(source,tmp_path/'backup.sqlite3',maximum_bytes=1024*1024)
    assert result['restore_authorized'] is False and result['source_write_performed'] is False
    assert source.read_bytes()==source_before and Path(str(source)+'-wal').read_bytes()==wal_before
    copied=sqlite3.connect(tmp_path/'backup.sqlite3')
    try:
        assert copied.execute('SELECT * FROM originals').fetchall()==[(1,b'actual\x00original',37)]
        with pytest.raises(sqlite3.IntegrityError,match='immutable'):
            copied.execute('UPDATE originals SET amount=0')
    finally:copied.close();db.close()
    with pytest.raises(AuthorityUnavailable):snapshot_sqlite_file_v2(source,tmp_path/'backup.sqlite3',maximum_bytes=1024*1024)


def test_snapshot_bound_rejects_without_relabeling_partial_as_ready(tmp_path):
    source=tmp_path/'source.sqlite3';db=sqlite3.connect(source)
    db.execute('CREATE TABLE content(data BLOB)');db.execute('INSERT INTO content VALUES(?)',(bytes(16384),));db.commit();db.close()
    with pytest.raises(AuthorityUnavailable,match='byte bound'):
        snapshot_sqlite_file_v2(source,tmp_path/'partial.sqlite3',maximum_bytes=4096)
