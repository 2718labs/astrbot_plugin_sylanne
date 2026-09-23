"""The five proposed mechanisms remain sourced, separable candidates."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04 import (
    AffectAxis,
    AffectProvider,
    AffectScheme,
    AppraisalBundle,
    MeaningFacet,
    MechanismSignal,
    SemanticDriveRule,
)


MECHANISMS = (
    "expectation", "approach_protection", "agency", "relationship", "self_evaluation",
)


def _scheme() -> AffectScheme:
    return AffectScheme(
        "d04.affect.scheme.v1", "candidate:five:1", "operator:fixture", "parameter:fixture",
        "coupling:fixture",
        tuple(AffectAxis(name, "normalized", f"candidate {name} response") for name in MECHANISMS),
        (),
    )


def _appraisal() -> AppraisalBundle:
    shared = dict(
        target_ref="entity:alice", value_ref="value:shared-time",
        responsibility_hypothesis="unknown", controllability=None,
        anticipated_impact=0.6, relation_meaning="wanted to meet",
        self_meaning=None, confidence=None,
        unknown_fields=("controllability", "confidence"), source_refs=("source:late-message",),
    )
    return AppraisalBundle(
        "appraisal:late:1", "event:late", "entity:alice",
        (
            MeaningFacet(facet_id="facet:hope", interpretation_ref="interpretation:delay", **shared),
            MeaningFacet(facet_id="facet:worry", interpretation_ref="interpretation:avoidance", **shared),
        ),
        ("interpretation:delay", "interpretation:avoidance"), ("source:late-message",),
        "reported", "external_report", "event:late|entity:alice|appraisal:1", 10.0,
    )


def _signal(facet: str, mechanism: str, value: float | None, reason: str | None = None) -> MechanismSignal:
    interpretation = "interpretation:delay" if facet == "facet:hope" else "interpretation:avoidance"
    return MechanismSignal(facet, interpretation, mechanism, value, ("source:late-message",), reason)


def _rules() -> tuple[SemanticDriveRule, ...]:
    return tuple(SemanticDriveRule(name, f"mechanism:{name}", 1.0) for name in MECHANISMS)


def test_mixed_mechanisms_remain_separate_by_meaning_and_interpretation() -> None:
    signals = (
        _signal("facet:hope", "expectation", 0.7),
        _signal("facet:hope", "approach_protection", 0.6),
        _signal("facet:worry", "expectation", -0.5),
        _signal("facet:worry", "relationship", -0.4),
        _signal("facet:worry", "agency", None, "no evidence of control"),
        _signal("facet:worry", "self_evaluation", None, "self meaning not appraised"),
    )
    candidate = AffectProvider().assemble_mechanism_drives(
        _appraisal(), _scheme(), signals, _rules(), mapping_version="candidate:mapping:1",
    )
    assert candidate.mapping_version == "candidate:mapping:1"
    assert candidate.contribution_key == "event:late|entity:alice|appraisal:1"
    assert {(item.facet_id, item.mechanism_id, item.drive) for item in candidate.contributions} == {
        ("facet:hope", "expectation", 0.7),
        ("facet:hope", "approach_protection", 0.6),
        ("facet:worry", "expectation", -0.5),
        ("facet:worry", "relationship", -0.4),
    }
    assert all(item.source_refs == ("source:late-message",) for item in candidate.contributions)
    assert ("facet:worry", "agency", "no evidence of control") in {
        (item.facet_id, item.mechanism_id, item.reason) for item in candidate.unresolved
    }
    assert ("facet:hope", "relationship", "missing_signal") in {
        (item.facet_id, item.mechanism_id, item.reason) for item in candidate.unresolved
    }


def test_intervention_changes_only_its_sourced_mechanism_contribution() -> None:
    original = (_signal("facet:hope", "expectation", 0.7), _signal("facet:worry", "relationship", -0.4))
    changed = (replace(original[0], value=-0.2), original[1])
    provider = AffectProvider()
    before = provider.assemble_mechanism_drives(
        _appraisal(), _scheme(), original, _rules(), mapping_version="candidate:mapping:1",
    )
    after = provider.assemble_mechanism_drives(
        _appraisal(), _scheme(), changed, _rules(), mapping_version="candidate:mapping:1",
    )
    assert [(c.facet_id, c.mechanism_id, c.drive) for c in before.contributions] == [
        ("facet:hope", "expectation", 0.7), ("facet:worry", "relationship", -0.4),
    ]
    assert [(c.facet_id, c.mechanism_id, c.drive) for c in after.contributions] == [
        ("facet:hope", "expectation", -0.2), ("facet:worry", "relationship", -0.4),
    ]
    assert before.unresolved == after.unresolved


def test_unmapped_novel_meaning_remains_a_representation_gap() -> None:
    result = AffectProvider().assemble_mechanism_drives(
        _appraisal(), _scheme(), (_signal("facet:hope", "novel_grief", 0.9),),
        _rules(), mapping_version="candidate:mapping:1",
    )
    assert result.contributions == ()
    assert ("facet:hope", "novel_grief", "unmapped_mechanism") in {
        (item.facet_id, item.mechanism_id, item.reason) for item in result.unresolved
    }
    assert next(item for item in result.unresolved if item.mechanism_id == "novel_grief").value == 0.9


def test_signal_cannot_cross_facet_interpretation_or_source_boundary() -> None:
    provider = AffectProvider()
    signal = _signal("facet:hope", "expectation", 0.7)
    with pytest.raises(ValueError, match="interpretation"):
        provider.assemble_mechanism_drives(
            _appraisal(), _scheme(), (replace(signal, interpretation_ref="interpretation:avoidance"),),
            _rules(), mapping_version="candidate:mapping:1",
        )
    with pytest.raises(ValueError, match="source"):
        provider.assemble_mechanism_drives(
            _appraisal(), _scheme(), (replace(signal, source_refs=("source:unseen",)),),
            _rules(), mapping_version="candidate:mapping:1",
        )


def test_rewording_same_mechanism_cannot_duplicate_drive() -> None:
    signal = _signal("facet:hope", "expectation", 0.7)
    with pytest.raises(ValueError, match="duplicate mechanism signal"):
        AffectProvider().assemble_mechanism_drives(
            _appraisal(), _scheme(), (signal, signal), _rules(), mapping_version="candidate:mapping:1",
        )
