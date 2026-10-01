"""Root V2 keeps authored latent and normalized readout in separate planes."""

from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from sylanne3.domains.d04.joint_state_output_v1 import JointStateOutputPolicyV1
from sylanne3.domains.d04.root import (
    AuthoredRootBlockInput, AuthoredRootInput, AuthoredRootPreset,
    RootAssetBindings, RootBlockIdentity, RootBlockTemplate,
    compile_authored_root_candidate, encode_root_checkpoint_candidate,
)
from sylanne3.domains.d04.root_projection_v2 import (
    RootProjectionHold, project_authored_root_candidate_v2,
)
from sylanne3.native_runtime.authored_root_initial_box import (
    AuthoredRootInitialBoxBlockMathCandidate, AuthoredRootInitialBoxMathCandidate,
)
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    D04LoadedTanhReadoutAsset, D04TanhReadoutRow,
)
from sylanne3.native_runtime.loader import NativeLoadBinding
from sylanne3.runtime_contracts import canonical_digest


CATALOGUE = Path(__file__).resolve().parents[4] / "resources/catalogue"
HASH = "a" * 64


def _inputs(*, box_width: float = 0.0, error: float = 0.0):
    policy_data = json.loads((CATALOGUE / "d04-joint-state-output-policy.v1.json").read_text())
    policy = JointStateOutputPolicyV1(**{
        **policy_data, "axis_ids": tuple(policy_data["axis_ids"]),
    })
    asset_data = json.loads((CATALOGUE / "d04-tanh-readout.v1.json").read_text())
    readout = D04LoadedTanhReadoutAsset(
        asset_data["readout_id"], asset_data["readout_version"],
        asset_data["scheme_version"], tuple(asset_data["axis_ids"]),
        tuple(asset_data["axis_units"]),
        tuple(D04TanhReadoutRow(
            item["output_id"], item["axis_id"], item["unit"],
            item["output_version"], item["transform"],
            tuple(float(value) for value in item["coefficients"]),
        ) for item in asset_data["outputs"]),
        policy.readout_sha256,
    )
    assets = RootAssetBindings(
        readout.scheme_version, "operator:1", "parameter:1", "coupling:1",
        readout.readout_version, HASH, HASH, HASH, HASH, readout.asset_sha256,
    )
    preset = AuthoredRootPreset(
        "preset:root-v2", "v1", assets, policy.axis_ids,
        (RootBlockTemplate("feeling:base", "feeling", "author_supplied_box"),
         RootBlockTemplate("mood:base", "mood", "author_supplied_box")),
    )
    feeling = RootBlockIdentity("feeling:one", "feeling:base", "feeling",
                                "person:one", "meaning:one", "source:feeling")
    mood = RootBlockIdentity("mood:one", "mood:base", "mood",
                             None, None, "source:mood")
    selection = AuthoredRootInput(
        "candidate:root-v2", ("bot", "persona"), "author:1", "draft:1",
        10.0, preset.digest, assets.digest,
        (AuthoredRootBlockInput(feeling, policy.axis_ids, (2.0,) * 24,
                                ((2.0 - box_width, 2.0 + box_width),) * 24,
                                "box:feeling"),
         AuthoredRootBlockInput(mood, policy.axis_ids, (1.0,) * 24,
                                ((1.0, 1.0),) * 24, "box:mood")),
    )
    root = compile_authored_root_candidate(preset, selection)
    binding = NativeLoadBinding(HASH, HASH, "windows", "x86_64", None, 2)
    blocks = tuple(AuthoredRootInitialBoxBlockMathCandidate(
        canonical_digest(encode_root_checkpoint_candidate(checkpoint)),
        HASH, error if index == 0 else 0.0,
    ) for index, checkpoint in enumerate(root.checkpoints))
    binding_digest = canonical_digest(asdict(binding))
    transcript = canonical_digest({
        "schema": "d04.authored-root-initial-box-math.v1",
        "candidate_sha256": root.digest,
        "binding_sha256": binding_digest,
        "blocks": [asdict(block) for block in blocks],
        "status": "conditional_math_candidate",
    })
    math = AuthoredRootInitialBoxMathCandidate(
        root.digest, binding, binding_digest, blocks, transcript,
    )
    return root, math, readout, policy


def test_root_projection_uses_tanh_coordinates_without_changing_latent():
    root, math, readout, policy = _inputs()
    projected = project_authored_root_candidate_v2(root, math, readout, policy)
    assert projected.status == "candidate_hold_for_w01_root_adoption"
    assert projected.semantic_calibration == "unvalidated"
    assert projected.member_block_ids == ("feeling:one", "mood:one")
    assert projected.members[0].latent_state[0] == 2.0
    assert 0.9 < projected.members[0].coordinates[0][1] < 1.0
    assert projected.members[1].kind == "mood"
    assert projected.members[1].coordinates != projected.members[0].coordinates
    assert all(len(member.axes) == 24 for member in projected.members)


def test_root_projection_rejects_uncovered_box_or_changed_identity():
    root, math, readout, policy = _inputs(box_width=0.1, error=0.0)
    with pytest.raises(RootProjectionHold, match="initial box proof"):
        project_authored_root_candidate_v2(root, math, readout, policy)
    root, math, readout, policy = _inputs()
    with pytest.raises(RootProjectionHold, match="fixed output policy"):
        project_authored_root_candidate_v2(root, math, readout,
                                           replace(policy, readout_sha256="b" * 64))
    with pytest.raises(RootProjectionHold, match="identity tanh"):
        bad_row = replace(readout.rows[0], coefficients=(0.5, 0.5) + (0.0,) * 22)
        project_authored_root_candidate_v2(root, math,
                                           replace(readout, rows=(bad_row,) + readout.rows[1:]),
                                           policy)
