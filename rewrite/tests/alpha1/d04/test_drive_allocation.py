"""Negative boundaries for the provisional semantic to 24D drive candidate."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04 import AppraisalBundle, MeaningFacet
from sylanne3.domains.d04.drive_allocation import (
    CompiledDrivePolicy,
    CompiledMeaningSignal,
    CompiledMechanismRule,
    RoleCondition,
    allocate_semantic_drives,
)
from sylanne3.native_runtime.d04_block_instances import D04DriveSegment
from sylanne3.native_runtime.d04_engineering_scheme import DIMENSION, MECHANISMS


ROLE = RoleCondition("role:sylanne", "persona:7", "condition:3", "policy:5")
POLICY = CompiledDrivePolicy(
    "mapping:9", "trusted-compiler:receipt:4", "condition:3", "policy:5", 1.0,
    tuple(CompiledMechanismRule(name, (1.0, 0.5, 0.25)) for name in MECHANISMS),
)


def _appraisal(
    appraisal_id: str = "appraisal:1", *, source: str = "source:event-1",
    target: str = "entity:alice", facet_id: str = "facet:1",
    unknown_fields: tuple[str, ...] = (), family: str = "reported",
    reality: str = "external_report",
) -> AppraisalBundle:
    facet = MeaningFacet(
        facet_id, target, "interpretation:1", "value:care", "unknown",
        None if "controllability" in unknown_fields else 0.4,
        None if "anticipated_impact" in unknown_fields else 0.6,
        "wanted contact", None,
        None if "confidence" in unknown_fields else 0.7,
        unknown_fields, (source,),
    )
    return AppraisalBundle(
        appraisal_id, "event:1", target, (facet,), ("interpretation:1",),
        (source,), family, reality, f"contribution:{appraisal_id}", 10.0,
    )


def _signals(
    appraisal: AppraisalBundle, *, meaning: str = "meaning:contact",
    source: str | None = None, magnitude: float | None = 0.8,
) -> tuple[CompiledMeaningSignal, ...]:
    return tuple(
        CompiledMeaningSignal(
            appraisal.appraisal_id, appraisal.meaning_facets[0].facet_id, meaning,
            appraisal.source_refs[0] if source is None else source, name, magnitude,
        )
        for name in MECHANISMS
    )


def _allocate(
    appraisals: tuple[AppraisalBundle, ...], signals: tuple[CompiledMeaningSignal, ...],
    *, policy: CompiledDrivePolicy | None = POLICY,
):
    return allocate_semantic_drives(
        appraisals, signals, role_condition=ROLE, policy=policy,
        role_start=10.0, role_end=12.0,
    )


def _dose(drives) -> float:
    return sum(sum(abs(value) for value in item.segment.drive) * 2.0 for item in drives)


def test_duplicate_paraphrase_does_not_multiply_one_causal_source_dose() -> None:
    original = _appraisal()
    paraphrase = _appraisal("appraisal:paraphrase", facet_id="facet:paraphrase")
    one = _allocate((original,), _signals(original))
    duplicated = _allocate((original, paraphrase), _signals(original) + _signals(paraphrase))
    assert not one.held and not duplicated.held
    assert len(duplicated.drives) == 1
    assert duplicated.drives[0].segment.drive == one.drives[0].segment.drive
    assert _dose(duplicated.drives) == pytest.approx(1.0)
    assert isinstance(duplicated.drives[0].segment, D04DriveSegment)
    assert len(duplicated.drives[0].segment.drive) == DIMENSION
    assert duplicated.drives[0].appraisal_refs == ("appraisal:1", "appraisal:paraphrase")


def test_source_cap_applies_across_distinct_objects_and_meanings_without_merging_them() -> None:
    alice = _appraisal()
    bob = _appraisal("appraisal:bob", target="entity:bob", facet_id="facet:bob")
    result = _allocate((alice, bob), _signals(alice) + _signals(bob, meaning="meaning:boundary"))
    assert not result.held
    assert {item.identity.object_ref for item in result.drives} == {"entity:alice", "entity:bob"}
    assert {item.identity.meaning_ref for item in result.drives} == {"meaning:contact", "meaning:boundary"}
    assert _dose(result.drives) == pytest.approx(1.0)


def test_independent_sources_have_independent_dose_and_identity() -> None:
    first = _appraisal()
    second = _appraisal("appraisal:2", source="source:event-2", facet_id="facet:2")
    result = _allocate((first, second), _signals(first) + _signals(second))
    assert not result.held
    assert {item.identity.source_ref for item in result.drives} == {"source:event-1", "source:event-2"}
    assert _dose(result.drives) == pytest.approx(2.0)


def test_unknown_source_does_not_block_an_independent_source() -> None:
    known = _appraisal()
    unresolved = _appraisal("appraisal:2", source="source:event-2", facet_id="facet:2")
    result = _allocate(
        (known, unresolved), _signals(known) + _signals(unresolved, magnitude=None),
    )
    assert [item.identity.source_ref for item in result.drives] == ["source:event-1"]
    assert [(item.source_ref, item.reason) for item in result.held] == [
        ("source:event-2", "compiled_magnitude_unknown"),
    ]


def test_missing_source_or_incomplete_compiled_semantics_holds_the_source() -> None:
    appraisal = _appraisal()
    wrong_source = _allocate((appraisal,), _signals(appraisal, source="source:unrelated"))
    assert not wrong_source.drives
    assert any(item.reason == "compiled_signal_missing" for item in wrong_source.held)

    incomplete = _allocate((appraisal,), _signals(appraisal)[:-1])
    assert not incomplete.drives
    assert incomplete.held[0].reason == "compiled_signal_missing"

    unknown = _allocate((appraisal,), _signals(appraisal, magnitude=None))
    assert not unknown.drives
    assert unknown.held[0].reason == "compiled_magnitude_unknown"


def test_unknown_required_fact_is_not_converted_to_zero_or_certainty() -> None:
    appraisal = _appraisal(unknown_fields=("controllability", "confidence"))
    rules = tuple(
        replace(rule, required_known_fields=("controllability",))
        if rule.mechanism_id == "agency_mobilization" else rule
        for rule in POLICY.rules
    )
    result = _allocate((appraisal,), _signals(appraisal), policy=replace(POLICY, rules=rules))
    assert not result.drives
    assert result.held[0].reason == "required_semantic_field_unknown"


def test_authored_content_keeps_reality_boundary_and_missing_policy_holds() -> None:
    authored = _appraisal(family="authored", reality="authored_content")
    result = _allocate((authored,), _signals(authored))
    assert not result.held
    assert result.drives[0].source_family == "authored"
    assert result.drives[0].content_reality == "authored_content"
    assert _allocate((authored,), _signals(authored), policy=None).held[0].reason == (
        "role_condition_or_mapping_missing"
    )


def test_conflicting_paraphrase_and_mismatched_role_version_hold() -> None:
    first = _appraisal()
    paraphrase = _appraisal("appraisal:other", facet_id="facet:other")
    conflict = _allocate((first, paraphrase), _signals(first) + _signals(paraphrase, magnitude=0.4))
    assert not conflict.drives
    assert conflict.held[0].reason == "conflicting_paraphrase"

    stale = _allocate((first,), _signals(first), policy=replace(POLICY, condition_version="condition:old"))
    assert not stale.drives
    assert stale.held[0].reason == "role_condition_mapping_version_mismatch"
