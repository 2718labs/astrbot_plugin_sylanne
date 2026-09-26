"""Pure compilation of authored D04 roots from explicit role selections."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04.root import (
    AuthoredRootBlockInput,
    AuthoredRootInput,
    AuthoredRootPreset,
    RootAssetBindings,
    RootBlockIdentity,
    RootBlockTemplate,
    compile_authored_root_candidate,
    decode_root_candidate,
    encode_root_candidate,
)


AXES = tuple(f"axis:{index:02d}" for index in range(24))


def _preset():
    assets = RootAssetBindings(
        scheme_version="scheme:1", operator_version="operator:1",
        parameter_version="parameter:1", coupling_version="coupling:1",
        readout_version="readout:1", scheme_sha256="a" * 64,
        operator_sha256="b" * 64, parameter_sha256="c" * 64,
        coupling_sha256="d" * 64, readout_sha256="e" * 64,
    )
    return AuthoredRootPreset(
        "preset:shared", "v1", assets, AXES,
        (RootBlockTemplate("feeling:base", "feeling", "author_supplied_box"),
         RootBlockTemplate("mood:base", "mood", "author_supplied_box")),
    )


def _selection(preset, persona="alice"):
    feeling = RootBlockIdentity(
        "feeling:one", "feeling:base", "feeling", f"person:{persona}",
        "meaning:care", f"authored:{persona}:feeling",
    )
    mood = RootBlockIdentity(
        "mood:one", "mood:base", "mood", None, None,
        f"authored:{persona}:mood",
    )
    return AuthoredRootInput(
        candidate_id="candidate:one", namespace=("bot:one", persona),
        author_id="owner:one", draft_id="draft:one", cursor=42.0,
        preset_digest=preset.digest, asset_digest=preset.assets.digest,
        blocks=(
            AuthoredRootBlockInput(feeling, AXES, (2.0,) * 24,
                                   ((1.9, 2.1),) * 24, "bounds:feeling"),
            AuthoredRootBlockInput(mood, AXES, (1.0,) * 24,
                                   ((0.9, 1.1),) * 24, "bounds:mood"),
        ),
    )


def test_reusable_preset_compiles_isolated_role_checkpoints():
    preset = _preset()
    alice = compile_authored_root_candidate(preset, _selection(preset))
    bob = compile_authored_root_candidate(preset, _selection(preset, "bob"))
    assert alice.preset is bob.preset
    assert alice.digest != bob.digest
    assert alice.namespace == ("bot:one", "alice")
    assert alice.historical_source_refs == ()
    assert alice.status == "candidate"
    assert [cp.block for cp in alice.checkpoints] == list(alice.blocks)
    assert all(cp.namespace == alice.namespace and cp.author_id == alice.author_id
               and cp.draft_id == alice.draft_id and cp.cursor == alice.cursor
               and cp.assets == preset.assets and cp.axes == preset.axes
               for cp in alice.checkpoints)
    assert alice.checkpoints[0].latent_state == (2.0,) * 24
    assert alice.checkpoints[0].ordered_box == ((1.9, 2.1),) * 24
    assert alice.checkpoints[0].initial_error_source == "author_declared_box"
    assert decode_root_candidate(encode_root_candidate(alice)) == alice


def test_same_preset_id_with_changed_content_cannot_satisfy_selected_digest():
    preset = _preset()
    changed = replace(preset, assets=replace(preset.assets, operator_sha256="f" * 64))
    assert changed.preset_id == preset.preset_id
    assert changed.digest != preset.digest
    with pytest.raises(ValueError, match="preset_digest"):
        compile_authored_root_candidate(changed, _selection(preset))
    assert compile_authored_root_candidate(changed, _selection(changed)).digest != (
        compile_authored_root_candidate(preset, _selection(preset)).digest
    )


def test_same_candidate_id_with_changed_authored_meaning_or_state_has_new_digest():
    preset = _preset()
    selection = _selection(preset)
    original = compile_authored_root_candidate(preset, selection)
    first = selection.blocks[0]
    revised = replace(
        selection,
        blocks=(replace(first, identity=replace(first.identity, meaning_ref="meaning:trust"),
                        latent_state=(2.05,) + first.latent_state[1:]), selection.blocks[1]),
    )
    changed = compile_authored_root_candidate(preset, revised)
    assert changed.candidate_id == original.candidate_id
    assert changed.digest != original.digest
    assert changed.checkpoints[0].block.meaning_ref == "meaning:trust"
    assert changed.checkpoints[0].latent_state[0] == 2.05


def test_initial_box_axis_and_asset_mismatch_fail_closed():
    preset = _preset()
    selection = _selection(preset)
    first = selection.blocks[0]
    with pytest.raises(ValueError, match="ordered_box"):
        compile_authored_root_candidate(
            preset, replace(selection, blocks=(replace(
                first, ordered_box=((2.1, 1.9),) + first.ordered_box[1:]),
                selection.blocks[1])),
        )
    with pytest.raises(ValueError, match="latent_state"):
        compile_authored_root_candidate(
            preset, replace(selection, blocks=(replace(
                first, latent_state=(-0.5,) + first.latent_state[1:]),
                selection.blocks[1])),
        )
    with pytest.raises(ValueError, match="axes"):
        compile_authored_root_candidate(
            preset, replace(selection, blocks=(replace(first, axes=tuple(reversed(AXES))),
                                              selection.blocks[1])),
        )
    with pytest.raises(ValueError, match="asset_digest"):
        compile_authored_root_candidate(
            preset, replace(selection, asset_digest="f" * 64),
        )
