"""Pure historical verification of retained actual installed acceptance files.

Supply the preserved Graph and its original installed package. These regressions
never create successful execution/Owner rows, call FFI, or claim a protected
registry/Authority/upgrade acceptance from an ordinary test directory.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from sylanne3.authority_service.d12_historical_d04_recipe_v1 import _run_retained_recipe_worker_v1
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


@pytest.fixture(scope="module")
def actual_retained_d04_originals():
    graph_path = os.environ.get("SYLANNE_D04_HISTORY_GRAPH")
    package_path = os.environ.get("SYLANNE_D04_HISTORY_PACKAGE")
    if not graph_path or not package_path:
        pytest.skip("requires preserved actual installed paid-root/joint acceptance files")
    graph, package = Path(graph_path).resolve(strict=True), Path(package_path).resolve(strict=True)
    manifest = hashlib.sha256((package / "release-manifest.json").read_bytes()).hexdigest()
    with sqlite3.connect(graph.as_uri() + "?mode=ro", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        rows = db.execute("SELECT kind,original_ref,payload_json,payload_digest FROM graph_d04_originals_v3 "
            "WHERE kind IN ('root_prepared','root_artifact','root_adoption_bridge','root_cost',"
            "'numeric_prepared','numeric_artifact','numeric_terminal','numeric_cost')").fetchall()
        saved = {}
        for kind, ref, encoded, digest in rows:
            value = json.loads(encoded)
            assert canonical_serialize(value) == encoded and canonical_digest(value) == digest
            saved.setdefault(kind, []).append((ref, value))
        assert all(len(saved.get(kind, [])) == 1 for kind in (
            "root_prepared", "root_artifact", "root_adoption_bridge", "root_cost",
            "numeric_prepared", "numeric_artifact", "numeric_terminal", "numeric_cost"))
    packets = {}
    for kind, prefix in (("numeric", "numeric"), ("authored_root", "root")):
        ref, prepared = saved[prefix + "_prepared"][0]
        assert saved[prefix + "_artifact"][0][0] == saved[prefix + "_cost"][0][0] == ref
        terminal = (saved["numeric_terminal"][0][1] if kind == "numeric"
            else saved["root_adoption_bridge"][0][1]["terminal"])
        assert terminal["binding"] == prepared["binding"]
        assert prepared["binding"]["native_manifest_sha256"] == manifest
        assert terminal["measurement"]["status"] == "completed"
        assert saved[prefix + "_cost"][0][1]["terminal_digest"] == canonical_digest(terminal)
        packets[kind] = {"prepared": prepared, "terminal": terminal, "artifact": saved[prefix + "_artifact"][0][1]}
    return package, manifest, packets


def test_actual_retained_recipe_identity_and_pure_root_numeric_math(actual_retained_d04_originals):
    package, manifest, packets = actual_retained_d04_originals
    identities = _run_retained_recipe_worker_v1(package, manifest, "identity", None)
    for kind, packet in packets.items():
        binding = packet["prepared"]["binding"]
        assert all(binding[key] == value for key, value in identities[kind].items())
        result = _run_retained_recipe_worker_v1(package, manifest,
            "numeric_math" if kind == "numeric" else "authored_root_math", packet)
        assert result["binding_digest"] == canonical_digest(binding)
        assert result["prepared_digest"] == canonical_digest(packet["prepared"])
        assert result["terminal_digest"] == canonical_digest(packet["terminal"])
        assert result["trusted"] is False


def test_actual_retained_proof_rejects_changed_manifest_and_measured_artifact(actual_retained_d04_originals):
    package, manifest, packets = actual_retained_d04_originals
    wrong = ("0" if manifest[0] != "0" else "1") + manifest[1:]
    with pytest.raises(AuthorityUnavailable, match="verification failed"):
        _run_retained_recipe_worker_v1(package, wrong, "identity", None)
    changed = deepcopy(packets["authored_root"])
    changed["terminal"]["measurement"]["artifact_digest"] = wrong
    with pytest.raises(AuthorityUnavailable, match="verification failed"):
        _run_retained_recipe_worker_v1(package, manifest, "authored_root_math", changed)
