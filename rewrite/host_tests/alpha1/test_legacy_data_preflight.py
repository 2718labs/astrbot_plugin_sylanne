"""Unmigrated data is rejected before a native graph store can create files."""

from sylanne3.host.legacy_data_preflight import inspect_native_data_dir_v1


def test_empty_and_existing_native_candidate_are_distinct(tmp_path):
    root = tmp_path / "plugin-data"
    assert inspect_native_data_dir_v1(root).status == "fresh"
    root.mkdir()
    assert inspect_native_data_dir_v1(root).status == "fresh"
    (root / "sylanne3.sqlite3").write_bytes(b"SQLite fixture bytes")
    result = inspect_native_data_dir_v1(root)
    assert result.status == "existing_native_candidate"
    assert "catalogue" in result.detail


def test_unknown_legacy_and_orphan_journal_require_migration(tmp_path):
    root = tmp_path / "plugin-data"
    root.mkdir()
    (root / "sylanne3.sqlite3-wal").write_bytes(b"orphan")
    assert inspect_native_data_dir_v1(root).status == "migration_required"
    (root / "sylanne3.sqlite3-wal").unlink()
    (root / "legacy-person-profile.json").write_text("{}", encoding="utf-8")
    assert inspect_native_data_dir_v1(root).status == "migration_required"
    assert (root / "legacy-person-profile.json").read_text(encoding="utf-8") == "{}"
