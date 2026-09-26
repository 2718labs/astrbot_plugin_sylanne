"""D04 authored initial roots are typed candidates, never product commits."""

from dataclasses import replace
import json

import pytest

from sylanne3.domains.d04.root import (
    AuthoredRootCandidate,
    AuthoredRootPreset,
    RootAssetBindings,
    RootBlockIdentity,
    RootBlockTemplate,
    RootNumericCheckpointCandidate,
    decode_root_candidate,
    decode_root_preset,
    encode_root_candidate,
    encode_root_preset,
)
from sylanne3.domains.d04 import AffectProvider
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry


AXES = tuple(f"axis:{index:02d}" for index in range(24))
HASH = "a" * 64


def _preset():
    assets = RootAssetBindings(
        scheme_version="scheme:1", operator_version="operator:1",
        parameter_version="parameter:1", coupling_version="coupling:1",
        readout_version="readout:1", scheme_sha256=HASH,
        operator_sha256="b" * 64, parameter_sha256="c" * 64,
        coupling_sha256="d" * 64, readout_sha256="e" * 64,
    )
    return AuthoredRootPreset(
        preset_id="preset:1", preset_version="preset-version:1", assets=assets, axes=AXES,
        block_templates=(
            RootBlockTemplate("feeling:default", "feeling", "author_supplied_box"),
            RootBlockTemplate("mood:default", "mood", "author_supplied_box"),
        ),
    )


def _candidate(persona="alice", object_id="person:one", preset=None):
    preset = preset or _preset()
    namespace = ("bot:one", persona)
    draft_id = f"draft:{persona}"
    blocks = (
        RootBlockIdentity("feeling:one", "feeling:default", "feeling", object_id,
                          "meaning:care", f"authored:{persona}:one"),
        RootBlockIdentity("feeling:two", "feeling:default", "feeling", object_id,
                          "meaning:boundary", f"authored:{persona}:two"),
        RootBlockIdentity("mood:primary", "mood:default", "mood", None, None,
                          f"authored:{persona}:mood"),
    )
    checkpoints = tuple(
        RootNumericCheckpointCandidate(
            preset_digest=preset.digest, asset_digest=preset.assets.digest, block_id=block.block_id,
            namespace=namespace, author_id="owner:one", draft_id=draft_id,
            block=block, assets=preset.assets,
            axes=AXES, latent_state=(2.0,) * 24, ordered_box=((1.9, 2.1),) * 24,
            initial_error_source="author_declared_box", initial_error_ref=f"{draft_id}:bounds",
            cursor=42.0,
        ) for block in blocks
    )
    return AuthoredRootCandidate(
        preset=preset, preset_digest=preset.digest, candidate_id=f"candidate:{persona}",
        namespace=namespace, author_id="owner:one", draft_id=draft_id,
        cursor=42.0, blocks=blocks, historical_source_refs=(), checkpoints=checkpoints,
    )


def test_two_roles_and_meaning_blocks_round_trip_without_shared_state_claim():
    preset = _preset()
    alice = _candidate(preset=preset)
    bob = _candidate("bob", "person:two", preset)
    assert alice.preset is bob.preset
    assert alice.preset.digest == bob.preset.digest
    assert alice.digest != bob.digest
    assert decode_root_preset(json.loads(json.dumps(encode_root_preset(preset)))) == preset
    assert "namespace" not in encode_root_preset(preset)
    assert "author_id" not in encode_root_preset(preset)
    assert "cursor" not in encode_root_preset(preset)
    assert len({item.block_id for item in alice.checkpoints}) == 3
    assert decode_root_candidate(json.loads(json.dumps(encode_root_candidate(alice)))) == alice
    assert all(0 <= value <= 4 for cp in alice.checkpoints for value in cp.latent_state)
    assert alice.historical_source_refs == ()
    assert not set(item.block.authored_source_id for item in alice.checkpoints) & set(
        item.block.authored_source_id for item in bob.checkpoints)
    assert alice.status == "candidate"
    assert not hasattr(alice, "numeric_certificate")


def test_fabricated_history_and_cross_role_or_block_binding_are_rejected():
    candidate = _candidate()
    with pytest.raises(ValueError, match="historical_source_refs"):
        replace(candidate, historical_source_refs=("invented:past",))
    with pytest.raises(ValueError, match="block"):
        replace(candidate, checkpoints=candidate.checkpoints[:-1])
    foreign = _candidate("bob").checkpoints[0]
    with pytest.raises(ValueError, match="namespace"):
        replace(candidate, checkpoints=(foreign, *candidate.checkpoints[1:]))
    with pytest.raises(ValueError, match="template"):
        replace(candidate, blocks=(replace(candidate.blocks[0], template_id="unknown"),
                                   *candidate.blocks[1:]))


def test_latent_box_axis_and_readout_are_not_implicitly_converted():
    candidate = _candidate()
    checkpoint = candidate.checkpoints[0]
    with pytest.raises(ValueError, match="ordered_box"):
        replace(checkpoint, ordered_box=((2.1, 1.9),) + checkpoint.ordered_box[1:])
    with pytest.raises(ValueError, match="latent_state"):
        replace(checkpoint, latent_state=(4.1,) + checkpoint.latent_state[1:])
    with pytest.raises(ValueError, match="axes"):
        replace(candidate, checkpoints=(replace(checkpoint, axes=tuple(reversed(AXES))), *candidate.checkpoints[1:]))
    assert "readout_coordinates" not in encode_root_candidate(candidate)


def test_digest_version_and_json_schema_tamper_fail_closed():
    candidate = _candidate()
    payload = encode_root_candidate(candidate)
    payload["preset_digest"] = "0" * 64
    with pytest.raises(ValueError, match="preset_digest"):
        decode_root_candidate(payload)
    payload = encode_root_candidate(candidate)
    payload["preset"]["assets"]["operator_version"] = "operator:other"
    with pytest.raises(ValueError, match="preset_digest"):
        decode_root_candidate(payload)
    payload = encode_root_candidate(candidate)
    payload["checkpoints"][0]["asset_digest"] = "f" * 64
    with pytest.raises(ValueError, match="asset_digest"):
        decode_root_candidate(payload)
    payload = encode_root_candidate(candidate)
    payload["checkpoints"][0]["namespace"][1] = "bob"
    with pytest.raises(ValueError, match="namespace"):
        decode_root_candidate(payload)
    payload = encode_root_candidate(candidate)
    payload["checkpoints"][0]["assets"]["readout_version"] = "readout:other"
    with pytest.raises(ValueError, match="asset_digest"):
        decode_root_candidate(payload)
    payload = encode_root_candidate(candidate)
    payload["committed"] = True
    with pytest.raises(ValueError, match="fields"):
        decode_root_candidate(payload)


def test_graph_specs_register_only_candidate_surface():
    provider = AffectProvider()
    specs = {item.name: item for item in provider.type_specs()}
    assert specs["d04.authored_root_preset.v1"].writer_domain == "d04"
    assert specs["d04.authored_root_candidate.v1"].storage_role == "projection"
    assert specs["d04.root_numeric_checkpoint_candidate.v1"].storage_role == "projection"
    assert "d04.numeric_checkpoint.v1" not in specs
    registry = TypeRegistry()
    for name in ("d04.authored_root_preset.v1", "d04.authored_root_candidate.v1",
                 "d04.root_numeric_checkpoint_candidate.v1"):
        registry.register(specs[name])
    candidate = _candidate()
    key = AtomKey(Owner("persona", "bot:one", "alice"),
                  "d04.authored_root_candidate.v1", "draft:1")
    assert registry.validate(key, encode_root_candidate(candidate)) == encode_root_candidate(candidate)
    invalid = encode_root_candidate(candidate)
    invalid["status"] = "adopted"
    with pytest.raises(ValueError, match="candidate-only"):
        registry.validate(key, invalid)
