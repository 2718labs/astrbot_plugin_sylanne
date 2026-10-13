"""Actual managed support-export cleanup after a stopped Host runtime."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from sylanne3.host.c09_local_cleanup import (
    LocalCleanupHold, purge_stopped_support_exports_v1,
)
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.support_export import write_view_status_export_v1


def _export(root: Path, scope: str) -> Path:
    bot, persona = scope.split("/")
    receipt = write_view_status_export_v1(
        root=root, operation_id=str(uuid4()), scope=scope,
        workspace={"namespace": {"bot": bot, "persona": persona},
                   "access_generation": 1,
                   "view_diagnostics": [
                       {"view_type": "d06.memory", "read_status": "ready"}]},
    )
    return Path(receipt["local_path"])


@pytest.mark.asyncio
async def test_scoped_support_export_bytes_are_removed_and_other_scope_retained(tmp_path):
    root = tmp_path / "support_exports"
    root.mkdir()
    target = _export(root, "bot/persona")
    other = _export(root, "bot/other")
    runtime = RuntimeContext(tmp_path, dependencies=None)
    receipt = await purge_stopped_support_exports_v1(
        runtime, NamespaceId("bot", "persona"),
        deletion_operation_id="delete-original")
    assert receipt.status == "managed_support_exports_purged"
    assert receipt.removed[0][0] == target.name
    assert len(receipt.removed[0][1]) == 64
    assert not target.exists()
    assert other.is_file()
    assert runtime.health.status == "stopped"


@pytest.mark.asyncio
async def test_unknown_file_holds_before_deleting_known_export(tmp_path):
    root = tmp_path / "support_exports"
    root.mkdir()
    target = _export(root, "bot/persona")
    (root / "unknown.bin").write_bytes(b"unmanaged")
    runtime = RuntimeContext(tmp_path, dependencies=None)
    with pytest.raises(LocalCleanupHold, match="unmanaged"):
        await purge_stopped_support_exports_v1(
            runtime, NamespaceId("bot", "persona"),
            deletion_operation_id="delete-original")
    assert target.is_file()


@pytest.mark.asyncio
async def test_legal_filename_does_not_authorize_deletion_of_changed_export(tmp_path):
    root = tmp_path / "support_exports"
    root.mkdir()
    target = _export(root, "bot/persona")
    target.write_bytes(target.read_bytes().replace(b'"view_status"', b'"unsafe_data"'))
    before = target.read_bytes()
    runtime = RuntimeContext(tmp_path, dependencies=None)
    with pytest.raises(LocalCleanupHold, match="original differs"):
        await purge_stopped_support_exports_v1(
            runtime, NamespaceId("bot", "persona"), deletion_operation_id="delete-original")
    assert target.read_bytes() == before


@pytest.mark.asyncio
async def test_exporter_and_cleanup_reject_new_unmanaged_directory(tmp_path):
    root = tmp_path / "support_exports"
    root.mkdir()
    target = _export(root, "bot/persona")
    before = target.read_bytes()
    (root / "nested").mkdir()
    with pytest.raises(ValueError):
        _export(root, "bot/persona")
    runtime = RuntimeContext(tmp_path, dependencies=None)
    with pytest.raises(LocalCleanupHold, match="unmanaged"):
        await purge_stopped_support_exports_v1(
            runtime, NamespaceId("bot", "persona"), deletion_operation_id="delete-original")
    assert target.read_bytes() == before


@pytest.mark.asyncio
async def test_exporter_and_cleanup_reject_replaced_export_root(tmp_path):
    root = tmp_path / "support_exports"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = _export(root, "bot/persona")
    before = target.read_bytes()
    moved = outside / target.name
    target.rename(moved)
    root.rmdir()
    try:
        root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(ValueError):
        _export(root, "bot/persona")
    runtime = RuntimeContext(tmp_path, dependencies=None)
    with pytest.raises(LocalCleanupHold, match="unsafe"):
        await purge_stopped_support_exports_v1(
            runtime, NamespaceId("bot", "persona"), deletion_operation_id="delete-original")
    assert moved.read_bytes() == before
