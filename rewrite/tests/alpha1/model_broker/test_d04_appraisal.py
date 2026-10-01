import json
from dataclasses import replace

import pytest

from sylanne3.domains.d01 import PersonaBlock, PersonaView, ValueRule
from sylanne3.domains.d03.context import WorldEvent
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d07 import (
    CurrentInterpretationCandidate, EvidenceStatus, Stance,
)
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.model_broker.d04_appraisal import (
    AppraisalInputV1, AppraisalInstallationV1, BoundInterpretationV1,
    OUTPUT_SCHEMA, QualifiedAppraisalSourceV1, freeze_appraisal_request_v1,
    parse_appraisal_output_v1,
)
from sylanne3.runtime_contracts import NamespaceId, SourceQualification, VersionedRef


NS = NamespaceId("bot", "persona")


def _ref(kind, subject, type_name, name, version=1):
    return VersionedRef(
        AtomKey(Owner(kind, *NS.as_tuple, subject), type_name, name).token,
        version,
    )


def _frozen():
    source = SourceRecord(
        "source:one", "I may be late; I will call when I know.", "user:one",
        "reported", "reported", 5.0, 6.0, "family:one", ("private",),
        ("context",),
    )
    source_ref = VersionedRef(source_key(*NS.as_tuple, source.source_id).token, 2)
    bound_source = QualifiedAppraisalSourceV1(
        source, source_ref,
        VersionedRef(access_key(*NS.as_tuple, source.source_id).token, 3),
        VersionedRef(source_correction_head_key(NS, source.source_id).token, 0),
    )
    event = WorldEvent(
        "world:late", "message_received", (("entity:user", "sender"),),
        5.0, 5.0, 6.0, "scene:private", (source_ref.ref,), "reported",
    )
    event_ref = _ref("event", event.event_id, "d03.world_event", "current", 2)
    role = PersonaView(
        "plan:one@2", NS,
        (PersonaBlock("value:care", "value", "Values mutual care", "growth"),),
        (ValueRule("rule:care", "mutual care", (), (), ()),), (), True,
    )
    role_ref = _ref("persona", None, "d01.persona_activation.v1", "current", 4)
    interpretation = CurrentInterpretationCandidate(
        "interpretation:late", "activity:one", "late_call",
        "The caller may be delayed", Stance.SUSPEND, 0.4,
        EvidenceStatus.INSUFFICIENT, (source_ref.ref,), ("family:one",),
        ("cause",),
    )
    interpretation_ref = _ref(
        "activity", "activity:one", "d07.current_interpretation.v1",
        interpretation.interpretation_id, 2,
    )
    input = AppraisalInputV1(
        NS, (bound_source,),
        SourceQualification((source_ref.ref,), "reported", 5.0, 6.0,
                            "external_report", "qualified", 0.4,
                            "not_applicable"),
        event_ref, event, role_ref, role,
        (BoundInterpretationV1(interpretation_ref, interpretation),),
        "entity:user",
    )
    installation = AppraisalInstallationV1(
        "install:one", "provider:one", "model:one", "config:one", "a" * 64,
        512,
    )
    return freeze_appraisal_request_v1(input, installation)


def _output(frozen):
    source = frozen.input.sources[0].source_ref.ref
    interpretation = frozen.input.interpretations[0].ref.ref
    return {
        "schema": OUTPUT_SCHEMA,
        "facets": [{
            "facet_id": "facet:care", "target_ref": "entity:user",
            "interpretation_ref": interpretation, "value_ref": "rule:care",
            "responsibility_hypothesis": "unknown",
            "controllability": None, "anticipated_impact": 0.3,
            "relation_meaning": "I hoped for contact", "self_meaning": None,
            "confidence": None,
            "unknown_fields": ["responsibility_hypothesis", "controllability",
                               "self_meaning", "confidence"],
            "source_refs": [source],
        }],
        "mechanism_signals": [{
            "facet_id": "facet:care", "mechanism_id": "affiliative_approach",
            "rationale": "Possible wish to reconnect", "source_refs": [source],
        }],
        "possible_feelings": ["possibly concerned"],
        "unknown_fields": ["caller_intent"],
    }


def test_exact_wire_and_untrusted_subjective_candidate_carry_original_identities():
    frozen = _frozen()
    assert [message.role for message in frozen.messages] == ["system", "user"]
    data = json.loads(frozen.messages[1].content)
    assert data["sources"][0]["record"]["text"].startswith("I may be late")
    assert data["source_qualification"]["source_refs"] == [
        frozen.input.sources[0].source_ref.ref]
    assert data["event_ref"]["version"] == 2
    assert data["role_ref"]["version"] == 4
    assert data["interpretations"][0]["ref"]["version"] == 2
    assert "model:one" in frozen.canonical_wire
    candidate = parse_appraisal_output_v1(json.dumps(_output(frozen)), frozen)
    assert candidate.status == "untrusted_subjective_suggestion"
    assert candidate.bundle.meaning_facets[0].confidence is None
    assert candidate.bundle.meaning_facets[0].unknown_fields
    assert candidate.mechanism_signals[0].mechanism_id == "affiliative_approach"
    assert not hasattr(candidate.mechanism_signals[0], "magnitude")
    assert candidate.source_refs == (frozen.input.sources[0].source_ref.ref,)
    assert candidate.qualified_source_refs == candidate.source_refs
    assert frozen.input.event_ref in candidate.basis_refs
    assert frozen.input.sources[0].correction_ref in candidate.basis_refs
    assert candidate.provider_id == "provider:one"
    assert candidate.model_id == "model:one"
    assert candidate.provider_config_digest == "a" * 64
    assert len(candidate.output_digest) == 64
    assert candidate.model_request_digest == frozen.model_request_digest
    assert candidate.provider_wire_digest == frozen.provider_wire_digest
    changed_config = freeze_appraisal_request_v1(
        frozen.input, replace(frozen.installation, provider_config_digest="b" * 64))
    assert changed_config.provider_wire_digest == frozen.provider_wire_digest
    assert changed_config.model_request_digest != frozen.model_request_digest


def test_empty_meaning_is_held_as_unknown_without_inventing_a_feeling():
    frozen = _frozen()
    data = _output(frozen)
    data.update(facets=[], mechanism_signals=[], possible_feelings=[],
                unknown_fields=["meaning"])
    candidate = parse_appraisal_output_v1(json.dumps(data), frozen)
    assert candidate.bundle is None
    assert candidate.source_refs == ()
    assert candidate.unknown_fields == ("meaning",)


@pytest.mark.parametrize("change", [
    lambda d: d.update(permission=True),
    lambda d: d["facets"][0].update(value_ref="rule:unseen"),
    lambda d: d["facets"][0].update(source_refs=["source:unseen"]),
    lambda d: d["facets"][0].update(interpretation_ref="interpretation:unseen"),
    lambda d: d["facets"][0].update(confidence=0.0),
    lambda d: d["mechanism_signals"][0].update(magnitude=0.8),
    lambda d: d["mechanism_signals"][0].update(mechanism_id="new_axis"),
    lambda d: d.update(facets=[]),
])
def test_scope_unknown_and_numeric_issuer_misclaims_are_rejected(change):
    frozen = _frozen()
    data = _output(frozen)
    change(data)
    with pytest.raises(ValueError):
        parse_appraisal_output_v1(json.dumps(data), frozen)


def test_duplicate_json_keys_stale_request_and_cross_namespace_are_rejected():
    frozen = _frozen()
    with pytest.raises(ValueError):
        parse_appraisal_output_v1(
            '{"schema":"x","schema":"y","facets":[],"mechanism_signals":[],"possible_feelings":[],"unknown_fields":[]}',
            frozen,
        )
    with pytest.raises(ValueError):
        parse_appraisal_output_v1(json.dumps(_output(frozen)),
                                  replace(frozen, canonical_wire="changed"))
    wrong_source = replace(
        frozen.input.sources[0],
        source_ref=VersionedRef(source_key("other", "persona", "source:one").token, 2),
    )
    with pytest.raises(ValueError):
        replace(frozen.input, sources=(wrong_source,))
