"""An installer manifest must agree with a fresh managed-file enumeration."""

import pytest

from sylanne3.runtime.c09_installation_inventory_v2 import (
    InstallationFilesystemManifestV2, InstalledResourceV2, InventoryHold,
    require_exact_cold_rescan_v2, scan_installed_filesystem_v2,
)
from sylanne3.runtime_contracts import canonical_digest


def installed(tmp_path):
    db = tmp_path / "graph.db"
    db.write_bytes(b"sqlite-content")
    backup = tmp_path / "controlled-backups"
    backup.mkdir()
    (backup / "old.db").write_bytes(b"old-backup")
    for dirname in ("exports", "rebuild-temp", "cache"):
        (tmp_path / dirname).mkdir()
    paths = {
        "sqlite_db": db,
        "sqlite_wal": tmp_path / "graph.db-wal",
        "sqlite_shm": tmp_path / "graph.db-shm",
        "controlled_backup": backup,
        "export": tmp_path / "exports",
        "rebuild_temp": tmp_path / "rebuild-temp",
        "cache": tmp_path / "cache",
    }
    resources = tuple(sorted((
        InstalledResourceV2(
            kind, kind, str(path.resolve()), "bot/persona",
            "graph" if kind.startswith("sqlite_") else kind,
            2, 7, "installer", "sqlite" if kind.startswith("sqlite_") else "directory",
            ("bot/persona",), "cleaner-v1")
        for kind, path in paths.items()), key=lambda item: item.path))
    schema = "sylanne3.c09.installation_filesystem_manifest.v2"
    manifest = InstallationFilesystemManifestV2(
        "authority", "installation", "bot/persona", resources,
        canonical_digest((schema, "authority", "installation", "bot/persona", resources)))
    return manifest, backup


@pytest.mark.parametrize("change", ["new", "delete", "rewrite"])
def test_cold_rescan_holds_on_backup_change(tmp_path, change):
    manifest, backup = installed(tmp_path)
    first = scan_installed_filesystem_v2(
        manifest, pinned_manifest_digest=manifest.manifest_digest)
    assert require_exact_cold_rescan_v2(
        manifest, first, pinned_manifest_digest=manifest.manifest_digest,
        pinned_scan_digest=first.scan_digest) == first
    if change == "new":
        (backup / "rotated.db").write_bytes(b"new-backup")
    elif change == "delete":
        (backup / "old.db").unlink()
    else:
        (backup / "old.db").write_bytes(b"changed-backup")
    with pytest.raises(InventoryHold, match="changed since frozen inventory"):
        require_exact_cold_rescan_v2(
            manifest, first, pinned_manifest_digest=manifest.manifest_digest,
            pinned_scan_digest=first.scan_digest)


def test_registered_missing_path_and_unpinned_manifest_hold(tmp_path):
    manifest, _ = installed(tmp_path)
    with pytest.raises(InventoryHold, match="trusted digest"):
        scan_installed_filesystem_v2(
            manifest, pinned_manifest_digest=canonical_digest("another"))
    db = next(item for item in manifest.resources if item.kind == "sqlite_db")
    from pathlib import Path
    Path(db.path).unlink()
    with pytest.raises(InventoryHold, match="registered path missing"):
        scan_installed_filesystem_v2(
            manifest, pinned_manifest_digest=manifest.manifest_digest)
