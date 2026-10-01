"""Mixed readout stays an unsigned premise and preserves causal scope."""

from dataclasses import replace
from fractions import Fraction

import pytest

from sylanne3.domains.d04.product_readout import (
    D04ReadoutHold, project_mixed_affect_candidate_v2,
)
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.native_runtime.d04_joint_product_math import (
    D04FamilyAssignment, D04JointMemberReadout, D04JointProductMathCandidate,
)
from sylanne3.native_runtime.tanh_asset_readout import run_d04_conditional_tanh_readout_math
from sylanne3.native_runtime.tanh_interval import _outward_binary64

from .test_product_readout_candidate import _case


def _mixed_case():
    checkpoint, ref, first, scheme, asset, full, read = _case()
    namespace = read.namespace
    second = source_key(*namespace.as_tuple, "source:two").token
    record = SourceRecord(
        "source:two", "evidence:two", "speaker", "reported", "reported",
        1.0, 2.0, "family:two", ("entity:alice",), ("context",), (),
    )
    more = (
        GraphAtom(source_key(*namespace.as_tuple, "source:two"), 1, record.to_dict()),
        GraphAtom(access_key(*namespace.as_tuple, "source:two"), 1, {
            "source_id": "source:two", "audiences": ["entity:alice"],
            "purposes": ["context"], "status": "active", "recorded_at": 2.0,
        }),
        GraphAtom(source_correction_head_key(namespace, "source:two"), 0, {}, False),
    )
    atoms = list(read.snapshot.atoms)
    atoms[4] = replace(atoms[4], value={
        **atoms[4].value,
        "historical_source_refs": [first, second],
        "interpretation_refs": ["interpretation:one", "interpretation:two"],
        "active_driver_refs": ["driver:one", "driver:two"],
    })
    read = replace(read, snapshot=replace(read.snapshot, atoms=tuple(atoms) + more))
    family_ids = ("family:one", "family:two")
    without = tuple((family, run_d04_conditional_tanh_readout_math(
        asset, tuple(value * factor for value in checkpoint.latent_state), 0.0,
    )) for family, factor in zip(family_ids, (0.0, 0.5)))
    effects = tuple((family, tuple((
        _outward_binary64(Fraction.from_float(whole.lower)
                          - Fraction.from_float(absent.upper), lower=True),
        _outward_binary64(Fraction.from_float(whole.upper)
                          - Fraction.from_float(absent.lower), lower=False),
    ) for whole, absent in zip(full.outputs, branch.outputs)))
                    for family, branch in without)
    member = D04JointMemberReadout(ref, full, without, effects)
    another_ref = AtomKey(
        AtomKey.from_token(ref).owner, "d04.numeric_checkpoint.v1", "block:two",
    ).token
    joint = D04JointProductMathCandidate(
        "component:digest", (ref, another_ref), None, 0.0, "full:transcript",
        tuple((family, f"{family}:transcript") for family in family_ids),
        (member, replace(member, checkpoint_ref=another_ref)), "joint:transcript",
    )
    families = (D04FamilyAssignment(first, family_ids[0]),
                D04FamilyAssignment(second, family_ids[1]))
    kwargs = dict(checkpoint=checkpoint, checkpoint_ref=ref,
                  checkpoint_revision=3, scheme=scheme, source_read=read,
                  asset=asset, joint_math=joint, families=families)
    return kwargs


def test_mixed_candidate_separates_whole_feeling_and_interval_family_effects():
    kwargs = _mixed_case()
    candidate = project_mixed_affect_candidate_v2(**kwargs)
    assert candidate.status.startswith("unsigned_hold")
    assert candidate.historical_source_refs == tuple(
        item.source_ref for item in kwargs["families"])
    assert candidate.interpretation_refs == (
        "interpretation:one", "interpretation:two")
    assert candidate.active_driver_refs == ("driver:one", "driver:two")
    assert len(candidate.overall) == 24
    assert len(candidate.interval_effects) == 48
    assert all(not hasattr(item, "source_ref") for item in candidate.overall)
    assert all(item.semantics == "current_interval_drive_effect_given_committed_initial_state"
               for item in candidate.interval_effects)
    assert candidate.family_sources == (
        ("family:one", (kwargs["families"][0].source_ref,)),
        ("family:two", (kwargs["families"][1].source_ref,)),
    )


def test_mixed_candidate_rejects_tampered_effect_or_incomplete_lineage():
    kwargs = _mixed_case()
    joint = kwargs["joint_math"]
    member = joint.members[0]
    with pytest.raises(D04ReadoutHold, match="joint math member"):
        project_mixed_affect_candidate_v2(**{
            **kwargs, "joint_math": replace(
                joint, member_refs=(joint.member_refs[0],), members=(member,),
            ),
        })
    first = member.effects[0]
    bad = ((first[0], ((9.0, 10.0),) + first[1][1:]),) + member.effects[1:]
    with pytest.raises(D04ReadoutHold, match="full-minus-without"):
        project_mixed_affect_candidate_v2(**{
            **kwargs, "joint_math": replace(joint, members=(
                replace(member, effects=bad), joint.members[1],
            )),
        })
    read = kwargs["source_read"]
    with pytest.raises(D04ReadoutHold, match="lineage is incomplete"):
        project_mixed_affect_candidate_v2(**{
            **kwargs, "source_read": replace(read, snapshot=replace(
                read.snapshot, atoms=read.snapshot.atoms[:-3],
            )),
        })
