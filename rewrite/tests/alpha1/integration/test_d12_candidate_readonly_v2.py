"""Candidate codecs over actual retained four-store paid-root/joint history.

This is the detached reader boundary, not privileged supervisor acceptance.
It makes SQLite snapshots of real prior acceptance files, never creates an
execution/Owner success row and never reruns numerical mathematics.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d12_candidate_compatibility_v2 import _run_candidate_readonly_worker_v2
from sylanne3.authority_service.d12_sqlite_backup_v2 import snapshot_sqlite_file_v2
from sylanne3.authority_service.c09_storage_control_v1 import InstalledC09InstanceLeaseV1


@pytest.fixture(scope="module")
def actual_stopped_four_store_copies(tmp_path_factory):
    location = os.environ.get("SYLANNE_D04_HISTORY_GRAPH")
    package = os.environ.get("SYLANNE_C11_CANDIDATE_PACKAGE")
    if not location or not package:
        pytest.skip("requires preserved real four-store paid execution acceptance and an installed candidate")
    graph, root = Path(location).resolve(strict=True), Path(package).resolve(strict=True)
    directory = tmp_path_factory.mktemp("actual-current-four-store-copies")
    names = dict(core="authority.db", deletion="deletion.db", execution="execution.db", graph=graph.name)
    # Preserve the retained acceptance artifacts. These isolated byte copies
    # carry the real original rows, including committed WAL if present; the
    # lease controls only this test cohort, never the old Authority process.
    source = directory / "stopped-source"
    source.mkdir()
    for name in names.values():
        for suffix in ("", "-wal", "-shm"):
            actual = graph.parent / (name + suffix)
            if actual.exists():
                before = hashlib.sha256(actual.read_bytes()).digest()
                shutil.copyfile(actual, source / actual.name)
                assert hashlib.sha256(actual.read_bytes()).digest() == before
                assert hashlib.sha256((source / actual.name).read_bytes()).digest() == before
    with InstalledC09InstanceLeaseV1(source / "instance.lock") as lease:
        copies = {role: snapshot_sqlite_file_v2(source / name, directory / (role + ".sqlite3"),
            maximum_bytes=512 * 1024**2, maximum_rows=100000, instance_lease=lease) for role, name in names.items()}
    with sqlite3.connect(Path(copies["graph"]["backup_observation"]["resolved_path"]).as_uri() + "?mode=ro&immutable=1", uri=True) as db:
        rows = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2").fetchall()
        assert len(rows) == 1
        requirements = json.loads(rows[0][0])
        kinds = dict(db.execute("SELECT kind,count(*) FROM graph_d04_originals_v3 GROUP BY kind"))
        assert kinds["root_cost"] == kinds["numeric_cost"] == kinds["numeric_artifact"] == 1
    manifest = hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest()
    return root, manifest, copies, requirements["namespace"], requirements["authority_namespace"]


def test_actual_four_store_candidate_decoders_without_math_or_admission(actual_stopped_four_store_copies):
    root, manifest, copies, namespace, authority_namespace = actual_stopped_four_store_copies
    result = _run_candidate_readonly_worker_v2(root, manifest, copies, namespace, authority_namespace)
    assert result["business_admission"] is False and result["writes_performed"] is False
    assert result["domains"] == [f"d{number:02d}" for number in range(1, 14)]
    assert result["native"]["abi_version"] == 2 and result["native"]["max_dimension"] >= 72
    assert result["inventories"] == {role: value["logical_inventory"] for role, value in copies.items()}
    assert result["decoded_rows"]["graph_d04_originals_v3"] >= 28


def test_actual_four_store_decoder_rejects_changed_copy_commitment(actual_stopped_four_store_copies):
    root, manifest, copies, namespace, authority_namespace = actual_stopped_four_store_copies
    changed = deepcopy(copies)
    digest = changed["graph"]["logical_inventory"]["inventory_digest"]
    changed["graph"]["logical_inventory"]["inventory_digest"] = ("0" if digest[0] != "0" else "1") + digest[1:]
    with pytest.raises(AuthorityUnavailable, match="qualification failed"):
        _run_candidate_readonly_worker_v2(root, manifest, changed, namespace, authority_namespace)
