"""Real ABI2 counterexamples for the conditional checkpoint initial box."""

import _ctypes
from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import platform
import shutil

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
from sylanne3.domains.d04.root import decode_numeric_checkpoint, encode_numeric_checkpoint
from sylanne3.native_runtime.d04_checkpoint_initial_box import (
    D04ProductPreflightHold, preflight_d04_checkpoint_initial_box,
    verify_d04_checkpoint_initial_box,
)
from sylanne3.native_runtime.loader import NativeIntegrityError, _runtime_target, load_production_native

from rewrite.tests.alpha1.numerics.test_authored_root_initial_box import native_asset
from rewrite.tests.alpha1.runtime.test_authoritative_coupling_snapshot import _fixture, _insert, _read
from rewrite.tests.alpha1.runtime.test_current_numeric_sources import _drive
from rewrite.tests.alpha1.numerics.test_current_numeric_sources_multisource import _read_v2


ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture
def installed_package(tmp_path, native_asset):
    root = tmp_path / "installed"
    os_name, arch, libc = _runtime_target()
    native_rel = f"rewrite/sylanne3/_native/{os_name}-{arch}/{native_asset.name}"
    files = []
    for rel, source in (
        (native_rel, native_asset),
        ("resources/catalogue/d04-affect-scheme.json",
         ROOT / "resources/catalogue/d04-affect-scheme.json"),
        ("resources/catalogue/d04-fixed-block-operator.json",
         ROOT / "resources/catalogue/d04-fixed-block-operator.json"),
    ):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        files.append({"path": rel, "bytes": target.stat().st_size,
                      "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    catalogue_rel = "resources/catalogue/current.json"
    catalogue = root / catalogue_rel
    catalogue.write_text(json.dumps({
        "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]},
    }), encoding="utf8")
    files.append({"path": catalogue_rel, "bytes": catalogue.stat().st_size,
                  "sha256": hashlib.sha256(catalogue.read_bytes()).hexdigest()})
    affect = json.loads((root / files[1]["path"]).read_text(encoding="utf8"))
    manifest = {
        "schema_version": 1,
        "native_math": {"contract": "abi2.fixed-block-interval.v1", "capability_flags": 1},
        "platform": {"os": os_name, "arch": arch, "abi_version": 2,
                     "native_filename": native_asset.name, "libc": libc, "cpu_features": []},
        "native": files[0], "files": files,
        "affect_scheme": {"path": files[1]["path"], "bytes": files[1]["bytes"],
                          "sha256": files[1]["sha256"],
                          "catalogue_capability": "d04.affect.scheme.v1",
                          **{field: affect[field] for field in (
                              "scheme_version", "operator_version", "parameter_version",
                              "coupling_version")}},
    }
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (root / "release-manifest.json").write_bytes(raw)
    handle = load_production_native(root, trusted_manifest_sha256=hashlib.sha256(raw).hexdigest())
    try:
        yield root, handle
    finally:
        if platform.system() == "Windows":
            _ctypes.FreeLibrary(handle._library._handle)
        else:
            _ctypes.dlclose(handle._library._handle)
        handle._library._handle = 0


def _source_case(tmp_path, *, bound):
    store, namespace, scheme, assets, source, key = _fixture(tmp_path)
    row = store._db.execute("SELECT value FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
    checkpoint = decode_numeric_checkpoint(json.loads(row[0]))
    checkpoint = replace(checkpoint, numeric_error_bound=bound)
    store._db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                      (canonical_json(encode_numeric_checkpoint(checkpoint)), key.token))
    drive = sourced_numeric_drive_write(_drive(key, source))
    _insert(store._db, namespace, drive.key, drive.value)
    graph = _read(store, namespace, scheme, assets, key)
    sources = _read_v2(store, graph, scheme, (drive.key.token,))
    return store, graph, sources, checkpoint


def test_24d_initial_box_replay_binds_exact_graph_value_and_manifest(tmp_path, installed_package):
    root, handle = installed_package
    store, graph, sources, checkpoint = _source_case(tmp_path, bound=0.5)
    try:
        result = preflight_d04_checkpoint_initial_box(
            handle, root, graph, sources, checkpoint,
        )
        assert result.status == "candidate_hold"
        assert result.manifest_sha256 == handle.production_binding.manifest_sha256
        assert result.checkpoint_value_digest == graph.checkpoint_value_digest
        assert result.verified_initial_error >= math.sqrt(24) * 0.1
        assert result.verified_initial_error < result.inherited_error == 0.5
        verify_d04_checkpoint_initial_box(handle, root, graph, sources, checkpoint, result)
        with pytest.raises(D04ProductPreflightHold, match="transcript"):
            verify_d04_checkpoint_initial_box(
                handle, root, graph, sources, checkpoint,
                replace(result, verified_initial_error=0.0),
            )
        with pytest.raises(D04ProductPreflightHold, match="graph source value"):
            preflight_d04_checkpoint_initial_box(
                handle, root, graph, sources,
                replace(checkpoint, certificate_digest="0" * 64),
            )
    finally:
        store.close()


def test_per_coordinate_error_claim_cannot_cover_24d_radius(tmp_path, installed_package):
    root, handle = installed_package
    store, graph, sources, checkpoint = _source_case(tmp_path, bound=0.11)
    try:
        # The DTO accepts 0.11 because every coordinate differs by 0.1;
        # ABI2 must reject it as a Euclidean trajectory error.
        assert checkpoint.numeric_error_bound == 0.11
        with pytest.raises(D04ProductPreflightHold, match="does not enclose"):
            preflight_d04_checkpoint_initial_box(handle, root, graph, sources, checkpoint)
    finally:
        store.close()


def test_loaded_manifest_mutation_fails_before_box_replay(tmp_path, installed_package):
    root, handle = installed_package
    store, graph, sources, checkpoint = _source_case(tmp_path, bound=0.5)
    try:
        with (root / "release-manifest.json").open("ab") as stream:
            stream.write(b" ")
        with pytest.raises(NativeIntegrityError, match="manifest changed"):
            preflight_d04_checkpoint_initial_box(handle, root, graph, sources, checkpoint)
    finally:
        store.close()
