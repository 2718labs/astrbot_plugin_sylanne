"""The D04 family ledger spans blocks and stays held without semantic authority."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d01 import ActiveRoleQualification, PersonaBlock, PersonaPlan
from sylanne3.domains.d04.drive_allocation import (
    CompiledDrivePolicy, CompiledMechanismRule, RoleCondition,
)
from sylanne3.domains.d04.family_drive_v2 import (
    AffineTimeMapV1, FamilyDosePortionV2, FamilyDoseShareV3, FamilyDriveHold,
    compile_family_interval_drive_candidate,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.memory_types import access_key
from sylanne3.runtime_contracts import NamespaceId

from rewrite.tests.alpha1.numerics.test_d04_semantic_drive_candidate import _share


NS = NamespaceId("bot", "persona")


def _fixture():
    source = _share()
    source_record = replace(source.source, source_kind="reported")
    second = _share(facet_id="facet-2", contribution="event-2")
    plan = PersonaPlan(
        "plan", NS, 1,
        (PersonaBlock("identity", "semantic_identity", "self", "read_only"),),
        (), True,
    )
    role_key = AtomKey(Owner("persona", "bot", "persona"),
                       "d01.persona_plan.v1", "plan")
    role = ActiveRoleQualification(NS, plan.head_id, plan,
                                   (GraphVersion(role_key, 1),), 7, 1)
    atoms = [GraphAtom(role_key, 1, {"head": plan.head_id})]
    for index, share in enumerate((source, second), 1):
        appraisal = asdict(share.appraisal)
        appraisal["meaning_facets"] = [asdict(f) for f in share.appraisal.meaning_facets]
        appraisal["competing_interpretation_refs"] = list(
            appraisal["competing_interpretation_refs"])
        appraisal["source_refs"] = list(appraisal["source_refs"])
        for facet in appraisal["meaning_facets"]:
            facet["unknown_fields"] = list(facet["unknown_fields"])
            facet["source_refs"] = list(facet["source_refs"])
        checkpoint = AtomKey(Owner("persona", "bot", "persona"),
                             "d04.numeric_checkpoint.v1", f"block-{index}")
        atoms.extend((
            GraphAtom(AtomKey.from_token(share.appraisal_ref), 1, appraisal),
            GraphAtom(checkpoint, 1, {"initial": index}),
        ))
    atoms.extend((
        GraphAtom(AtomKey.from_token(source.source_ref), 1, source_record.to_dict()),
        GraphAtom(access_key("bot", "persona", source_record.source_id), 1, {
            "source_id": source_record.source_id,
            "audiences": ["owner"], "purposes": ["context"],
            "status": "active", "recorded_at": 0.0,
        }),
        GraphAtom(source_correction_head_key(NS, source_record.source_id),
                  0, {}, False),
    ))
    portions = tuple(FamilyDosePortionV2(
        AtomKey(Owner("persona", "bot", "persona"),
                "d04.numeric_checkpoint.v1", f"block-{i}").token,
        share.appraisal_ref, 1, share.facet_id, share.source_ref, 1, 1,
        (0.1,) + (0.0,) * 23,
    ) for i, share in enumerate((source, second), 1))
    rules = tuple(CompiledMechanismRule(name, (1.0, 1.0, 1.0))
                  for name in dict.fromkeys(axis.split(":")[0]
                                            for axis in REGISTERED_AXIS_IDS))
    policy = CompiledDrivePolicy("mapping-1", "compiler-1", "condition-1",
                                 "policy-1", 1.0, rules)
    condition = RoleCondition(plan.head_id, "1", "condition-1", "policy-1")
    return GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", 7),)), role, condition, policy, portions


def _compile(snapshot, role, condition, policy, portions):
    return compile_family_interval_drive_candidate(
        snapshot=snapshot, namespace=NS, role=role, condition=condition,
        policy=policy,
        time_map=AffineTimeMapV1(10.0, 12.0, 10.0, 12.0),
        portions=portions, audience=("owner",), purpose="context",
    )


def test_two_blocks_share_one_family_dose_and_integrate_rate():
    snapshot, role, condition, policy, portions = _fixture()
    candidate = _compile(snapshot, role, condition, policy, portions)
    assert candidate.schema == "d04.family_interval_drive_candidate.v2"
    assert candidate.status == "HOLD"
    assert "authenticated_d04_semantic_mapping_acceptance_receipt" in candidate.missing_inputs
    assert candidate.family_dose_l1 == pytest.approx(0.2)
    assert len(candidate.portions) == 2
    assert all(row.rate[0] == pytest.approx(0.05) for row in candidate.portions)
    assert all(row.rate[0] * candidate.time_map.solver_duration
               == pytest.approx(row.dose[0]) for row in candidate.portions)
    assert len({row.contribution_key for row in candidate.portions}) == 2


def test_duplicate_family_claim_and_revoked_access_hold():
    snapshot, role, condition, policy, portions = _fixture()
    with pytest.raises(FamilyDriveHold, match="duplicate family allocation"):
        _compile(snapshot, role, condition, policy, portions + (portions[0],))
    cross_block_retry = replace(portions[0], checkpoint_ref=portions[1].checkpoint_ref)
    with pytest.raises(FamilyDriveHold, match="duplicate family allocation"):
        _compile(snapshot, role, condition, policy, (portions[0], cross_block_retry))
    access = access_key("bot", "persona", "source-1")
    revoked = replace(snapshot, atoms=tuple(
        replace(atom, value={**atom.value, "status": "withdrawn"})
        if atom.key == access else atom for atom in snapshot.atoms
    ))
    with pytest.raises(FamilyDriveHold, match="revoked or unauthorized"):
        _compile(revoked, role, condition, policy, portions)


def test_family_budget_cannot_be_reissued_per_block():
    snapshot, role, condition, policy, portions = _fixture()
    excessive = tuple(replace(p, dose=(0.6,) + (0.0,) * 23) for p in portions)
    with pytest.raises(FamilyDriveHold, match="budget exceeded"):
        _compile(snapshot, role, condition, policy, excessive)


def test_one_contribution_has_explicit_two_block_shares_and_one_dose():
    snapshot, role, condition, policy, portions = _fixture()
    claim = portions[0]
    shared = tuple(FamilyDoseShareV3(
        checkpoint_ref=block, appraisal_ref=claim.appraisal_ref,
        appraisal_revision=claim.appraisal_revision, facet_id=claim.facet_id,
        source_ref=claim.source_ref, source_revision=claim.source_revision,
        access_revision=claim.access_revision,
        contribution_dose=(0.8,) + (0.0,) * 23, share=fraction,
    ) for block, fraction in ((portions[0].checkpoint_ref, 0.25),
                              (portions[1].checkpoint_ref, 0.75)))
    candidate = _compile(snapshot, role, condition, policy, shared)
    assert candidate.schema == "d04.family_interval_drive_candidate.v3"
    assert candidate.family_dose_l1 == pytest.approx(0.8)
    assert [row.dose[0] for row in candidate.portions] == pytest.approx([0.2, 0.6])
    assert [row.rate[0] for row in candidate.portions] == pytest.approx([0.1, 0.3])
    assert len(candidate.contribution_allocations) == 1
    assert "w01_authenticated_installed_identity_time_mapping" in candidate.missing_inputs
    allocation = candidate.contribution_allocations[0]
    assert allocation.contribution_dose[0] == 0.8
    assert allocation.block_shares == ((portions[0].checkpoint_ref, 0.25),
                                       (portions[1].checkpoint_ref, 0.75))
    assert all(row.allocation_ref == allocation.allocation_ref for row in candidate.portions)
    with pytest.raises(FamilyDriveHold, match="sum to one"):
        _compile(snapshot, role, condition, policy, (shared[0],))
    with pytest.raises(FamilyDriveHold, match="sum to one"):
        _compile(snapshot, role, condition, policy,
                 (replace(shared[0], share=1.0), replace(shared[1], share=1.0)))
    with pytest.raises(FamilyDriveHold, match="budget exceeded"):
        _compile(snapshot, role, condition, policy,
                 tuple(replace(row, contribution_dose=(1.2,) + (0.0,) * 23)
                       for row in shared))
    with pytest.raises(FamilyDriveHold, match="contribution dose differs"):
        _compile(snapshot, role, condition, policy,
                 (shared[0], replace(shared[1], contribution_dose=(0.7,) + (0.0,) * 23)))
    with pytest.raises(FamilyDriveHold, match="duplicate block share"):
        _compile(snapshot, role, condition, policy,
                 (shared[0], replace(shared[1], checkpoint_ref=shared[0].checkpoint_ref)))


def test_nonidentity_time_map_holds_until_operator_step_and_drive_are_mapped():
    snapshot, role, condition, policy, portions = _fixture()
    with pytest.raises(FamilyDriveHold, match="nonidentity time map"):
        compile_family_interval_drive_candidate(
            snapshot=snapshot, namespace=NS, role=role, condition=condition,
            policy=policy, time_map=AffineTimeMapV1(10.0, 12.0, 100.0, 104.0),
            portions=portions, audience=("owner",), purpose="context",
        )
