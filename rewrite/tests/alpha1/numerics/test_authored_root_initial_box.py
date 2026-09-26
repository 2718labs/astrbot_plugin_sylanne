"""Real package-bound ABI2 initial boxes for authored D04 candidates."""

import _ctypes
from dataclasses import replace
import hashlib
import json
import math as mathlib
from pathlib import Path
import platform
import shutil
import subprocess

import pytest

from sylanne3.domains.d04 import (
    AuthoredRootBlockInput,
    AuthoredRootInput,
    AuthoredRootPreset,
    RootAssetBindings,
    RootBlockIdentity,
    RootBlockTemplate,
    compile_authored_root_candidate,
)
from sylanne3.native_runtime import (
    ABI2NativeLibrary,
    ABI2ResultError,
    load_production_native,
    run_authored_root_initial_box_math,
    verify_authored_root_initial_box_math,
)
from sylanne3.native_runtime.loader import _runtime_target


AXES = tuple(f"axis:{index:02d}" for index in range(24))


@pytest.fixture(scope="module")
def native_asset():
    root = Path(__file__).resolve().parents[4]
    native_root = root / "rewrite" / "native"
    subprocess.run(["cargo", "build", "--quiet"], cwd=native_root, check=True, timeout=120)
    return native_root / "target" / "debug" / {
        "Windows": "sylanne3_kernel.dll",
        "Linux": "libsylanne3_kernel.so",
        "Darwin": "libsylanne3_kernel.dylib",
    }[platform.system()]


def _package(root, native_asset, marker):
    os_name, arch, libc = _runtime_target()
    relative = f"rewrite/sylanne3/_native/{os_name}-{arch}/{native_asset.name}"
    target = root / relative
    target.parent.mkdir(parents=True)
    shutil.copyfile(native_asset, target)
    entry = {"path": relative, "bytes": target.stat().st_size,
             "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
    manifest = {
        "schema_version": 1,
        "native_math": {"contract": "abi2.fixed-block-interval.v1", "capability_flags": 1},
        "platform": {"os": os_name, "arch": arch, "abi_version": 2,
                     "native_filename": native_asset.name, "libc": libc, "cpu_features": []},
        "native": entry, "files": [entry], "package_marker": marker,
    }
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (root / "release-manifest.json").write_bytes(raw)
    return load_production_native(root, trusted_manifest_sha256=hashlib.sha256(raw).hexdigest())


@pytest.fixture
def handles(tmp_path, native_asset):
    first = _package(tmp_path / "package-one", native_asset, "one")
    second = _package(tmp_path / "package-two", native_asset, "two")
    try:
        yield first, second
    finally:
        for handle in (first, second):
            if platform.system() == "Windows":
                _ctypes.FreeLibrary(handle._library._handle)
            else:
                _ctypes.dlclose(handle._library._handle)
            handle._library._handle = 0


def _candidate():
    assets = RootAssetBindings(
        "scheme:v1", "operator:v1", "parameter:v1", "coupling:v1", "readout:v1",
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
    )
    preset = AuthoredRootPreset(
        "preset:one", "v1", assets, AXES,
        (RootBlockTemplate("feeling:base", "feeling", "author_supplied_box"),
         RootBlockTemplate("mood:base", "mood", "author_supplied_box")),
    )
    selections = (
        AuthoredRootBlockInput(
            RootBlockIdentity("feeling:one", "feeling:base", "feeling",
                              "person:one", "meaning:care", "authored:feeling"),
            AXES, (2.0,) * 24,
            ((1.95, 2.05), (1.85, 2.15)) + ((1.9, 2.1),) * 22,
            "box:feeling",
        ),
        AuthoredRootBlockInput(
            RootBlockIdentity("mood:one", "mood:base", "mood", None, None,
                              "authored:mood"),
            AXES, (1.0,) * 24, ((0.9, 1.1),) * 24, "box:mood",
        ),
    )
    selection = AuthoredRootInput(
        "candidate:one", ("bot:one", "persona:one"), "owner:one", "draft:one",
        42.0, preset.digest, assets.digest, selections,
    )
    return compile_authored_root_candidate(preset, selection)


def test_real_native_initial_boxes_bind_every_checkpoint_and_package(handles):
    first, _ = handles
    candidate = _candidate()
    math = run_authored_root_initial_box_math(first, candidate)
    assert math.status == "conditional_math_candidate"
    assert math.candidate_sha256 == candidate.digest
    assert math.production_binding == first.production_binding
    assert len(math.blocks) == len(candidate.checkpoints) == 2
    assert all(block.verified_initial_error > 0 for block in math.blocks)
    assert math.blocks[0].initial_box_sha256 != math.blocks[1].initial_box_sha256
    for checkpoint, block in zip(candidate.checkpoints, math.blocks):
        corner = tuple(interval[1] for interval in checkpoint.ordered_box)
        assert mathlib.dist(corner, checkpoint.latent_state) <= block.verified_initial_error
    verify_authored_root_initial_box_math(first, candidate, math)


def test_wrong_package_box_order_and_candidate_change_are_rejected(handles):
    first, second = handles
    candidate = _candidate()
    math = run_authored_root_initial_box_math(first, candidate)
    assert first.production_binding != second.production_binding
    with pytest.raises(ABI2ResultError, match="binding|candidate"):
        verify_authored_root_initial_box_math(second, candidate, math)
    checkpoint = candidate.checkpoints[0]
    swapped = replace(checkpoint, ordered_box=(checkpoint.ordered_box[1], checkpoint.ordered_box[0],
                                              *checkpoint.ordered_box[2:]))
    changed_box = replace(candidate, checkpoints=(swapped, *candidate.checkpoints[1:]))
    with pytest.raises(ABI2ResultError, match="candidate"):
        verify_authored_root_initial_box_math(first, changed_box, math)
    changed_identity = replace(candidate.blocks[0], meaning_ref="meaning:trust")
    changed_checkpoint = replace(checkpoint, block=changed_identity)
    changed = replace(candidate, blocks=(changed_identity, *candidate.blocks[1:]),
                      checkpoints=(changed_checkpoint, *candidate.checkpoints[1:]))
    with pytest.raises(ABI2ResultError, match="candidate"):
        verify_authored_root_initial_box_math(first, changed, math)


def test_tampered_radius_or_digest_does_not_verify(handles):
    first, _ = handles
    candidate = _candidate()
    math = run_authored_root_initial_box_math(first, candidate)
    false_block = replace(math.blocks[0], verified_initial_error=0.0)
    with pytest.raises(ABI2ResultError, match="candidate"):
        verify_authored_root_initial_box_math(
            first, candidate, replace(math, blocks=(false_block, *math.blocks[1:])),
        )


def test_unbound_native_handle_cannot_issue_authored_root_math(handles):
    first, _ = handles
    direct = ABI2NativeLibrary(first._library, first.path)
    with pytest.raises(ABI2ResultError, match="package-bound"):
        run_authored_root_initial_box_math(direct, _candidate())
