"""Frozen C04 input retains graph originals and runs only installed D06 math."""

from dataclasses import replace
import json

import pytest

from sylanne3.domains.d06.c04_work_input_v2 import (
    AssociationQueryCoverageV2,
    AssociationWorkInputV2,
    D04SalienceOriginalV2,
    FrozenGraphReadV2,
    activate_association_work_v2,
)
from sylanne3.domains.d06.current_association_candidates import CurrentAssociationBudgetV1
from sylanne3.domains.d06 import SelectionTicket, source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom, NamespaceEpoch, Owner
from sylanne3.memory_association import ActivationPolicy
from sylanne3.memory_types import SourceRecord, access_key, association_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")


def _source(source_id: str, *, parent: tuple[str, ...] = ()) -> FrozenGraphReadV2:
    key = source_key(*NS.as_tuple, source_id)
    record = SourceRecord(source_id, f"text {source_id}", "speaker", "reported",
                          "reported", 1.0, 1.0, "root", ("self",),
                          ("context",), parent)
    return FrozenGraphReadV2.from_atom(GraphAtom(key, 1, record.to_dict()))


def _access(source_id: str, *, revision: int = 1) -> FrozenGraphReadV2:
    return FrozenGraphReadV2.from_atom(GraphAtom(
        access_key(*NS.as_tuple, source_id), revision,
        {"source_id": source_id, "audiences": ["self"], "purposes": ["context"],
         "status": "active", "recorded_at": 1.0}))


def _edge(weight: float = 0.8) -> FrozenGraphReadV2:
    key = association_key(*NS.as_tuple, "cue", "edge")
    return FrozenGraphReadV2.from_atom(GraphAtom(key, 1, {
        "association_id": "edge", "source_ref": source_key(*NS.as_tuple, "cue").token,
        "target_ref": source_key(*NS.as_tuple, "target").token,
        "kind": "similarity", "weight": weight, "context_tags": ["now"],
        "basis_source_refs": [source_key(*NS.as_tuple, "ancestor").token],
        "content_reality": "subjective",
    }))


def _input(*, epoch: int = 7, truncated: bool = False,
           mood_extra_source: bool = False) -> AssociationWorkInputV2:
    cue = source_key(*NS.as_tuple, "cue")
    target = source_key(*NS.as_tuple, "target")
    focus = AtomKey(Owner("persona", *NS.as_tuple), "d07.focus.v1", "persona")
    ticket = AtomKey(Owner("persona", *NS.as_tuple), "d07.attention_ticket.v1", "attention")
    mood = AtomKey(Owner("persona", *NS.as_tuple), "d04.mood_field.v1", "primary")
    reads = [
        FrozenGraphReadV2.from_atom(GraphAtom(
            focus, 2, {"primary_ticket_ref": ticket.token, "focus_epoch": 2})),
        FrozenGraphReadV2.from_atom(GraphAtom(ticket, 3, {
            "ticket_id": "attention", "source_refs": [cue.token],
            "causal_root": cue.token, "eligible": True,
            "resources_available": True, "cancel_refs": [],
        })),
        FrozenGraphReadV2.from_atom(GraphAtom(mood, 4, {
            "mood_id": mood.token, "basis_version": "scheme-v1",
            "coordinates": [["valence", 0.0]],
            "source_refs": [cue.token, *([source_key(*NS.as_tuple, "mood-only").token]
                                         if mood_extra_source else [])],
            "parameter_version": "parameters-v1", "coupling_version": "coupling-v1",
            "cursor": 1.0, "revision": 1,
        })),
        _edge(),
    ]
    for source_id, parents in (("cue", ()), ("target", ("ancestor",)),
                               ("ancestor", ())):
        reads.extend((_source(source_id, parent=parents), _access(source_id),
                      FrozenGraphReadV2.absent(source_correction_head_key(NS, source_id))))
    if mood_extra_source:
        reads.extend((_source("mood-only"), _access("mood-only"),
                      FrozenGraphReadV2.absent(
                          source_correction_head_key(NS, "mood-only"))))
    queries = (
        AssociationQueryCoverageV2(cue.token, 0, (_edge().key.token,),
                                   _edge().key.token if truncated else None),
        AssociationQueryCoverageV2(target.token, 1, ()),
    )
    return AssociationWorkInputV2(
        NS, "activity", "operation", cue.token, focus.token, ticket.token, mood.token,
        SelectionTicket("choice", "activity", "candidates", ("selected",), 2),
        D04SalienceOriginalV2(cue.token, mood.token, (0.3, 0.7), (0.4, 0.8),
                              "coupling-v1"),
        "self", "context", ("now",),
        ActivationPolicy(0.5, 0.25, 32, 128, 1e-6),
        CurrentAssociationBudgetV1(), tuple(reads), queries,
        NamespaceEpoch(*NS.as_tuple, epoch), truncated,
    )


def _replace_read(work: AssociationWorkInputV2, old: FrozenGraphReadV2,
                  new: FrozenGraphReadV2) -> AssociationWorkInputV2:
    return replace(work, reads=tuple(new if item == old else item for item in work.reads))


def test_stable_execution_and_observation_epoch_not_in_semantic_digest() -> None:
    work = _input()
    reversed_work = replace(work, reads=tuple(reversed(work.reads)),
                            edge_queries=tuple(reversed(work.edge_queries)),
                            context_tags=("now",))
    later_epoch = replace(work, graph_epoch=NamespaceEpoch(*NS.as_tuple, 99))
    assert work.input_digest == reversed_work.input_digest == later_epoch.input_digest
    result = activate_association_work_v2(work)
    assert result == activate_association_work_v2(reversed_work)
    assert result.result_digest == activate_association_work_v2(later_epoch).result_digest
    assert len(result.candidates) == 1
    assert result.candidates[0].source_ref == source_key(*NS.as_tuple, "target").token
    assert result.candidates[0].mood_weighted_activation == pytest.approx(
        result.candidates[0].activation * 0.6)
    assert result.candidates[0].evidence_eligibility == "subjective_association_only"


def test_every_original_value_version_and_page_truncation_affects_digest() -> None:
    work = _input()
    edge = next(item for item in work.reads if item.key.type_name == "memory.association.v1")
    target_access = next(item for item in work.reads if item.key == access_key(*NS.as_tuple, "target"))
    mood = next(item for item in work.reads if item.key.type_name == "d04.mood_field.v1")
    changed_edge = _replace_read(work, edge, _edge(0.6))
    changed_access = _replace_read(work, target_access, _access("target", revision=2))
    changed_mood = _replace_read(work, mood, FrozenGraphReadV2.from_atom(
        GraphAtom(mood.key, 5, mood.value)))
    changed_salience = replace(work, salience_original=replace(
        work.salience_original, conditioned_interval=(0.5, 0.8)))
    changed_selection = replace(work, selection_ticket=replace(
        work.selection_ticket, ticket_id="choice-2"))
    partial = _input(truncated=True)
    for changed in (changed_edge, changed_access, changed_mood, changed_salience,
                    changed_selection, partial):
        assert changed.input_digest != work.input_digest
    assert activate_association_work_v2(partial).coverage == "partial"
    assert activate_association_work_v2(partial).stop_reason == "traversal_budget_or_page_limit"


def test_negative_correction_and_ancestor_reads_are_mandatory() -> None:
    work = _input()
    correction = next(item for item in work.reads
                      if item.key == source_correction_head_key(NS, "target"))
    with pytest.raises(ValueError, match="correction head"):
        _replace_read(work, correction, FrozenGraphReadV2.from_atom(
            GraphAtom(correction.key, 1, {"state": "pending_reevaluation"})))
    with pytest.raises(ValueError, match="correction head"):
        replace(work, reads=tuple(item for item in work.reads if item != correction))
    ancestor = next(item for item in work.reads
                    if item.key == source_key(*NS.as_tuple, "ancestor"))
    with pytest.raises(ValueError, match="source, access or explicit correction"):
        replace(work, reads=tuple(item for item in work.reads if item != ancestor))


def test_mood_source_original_and_access_closure_are_mandatory() -> None:
    work = _input(mood_extra_source=True)
    mood_source = source_key(*NS.as_tuple, "mood-only")
    assert activate_association_work_v2(work).input_digest == work.input_digest
    for key in (mood_source, access_key(*NS.as_tuple, "mood-only"),
                source_correction_head_key(NS, "mood-only")):
        with pytest.raises(ValueError, match="source, access or explicit correction"):
            replace(work, reads=tuple(row for row in work.reads if row.key != key))
    mood = next(row for row in work.reads if row.key.type_name == "d04.mood_field.v1")
    broken = dict(mood.value)
    broken["source_refs"] = ["not-an-atom-ref"]
    with pytest.raises((TypeError, ValueError)):
        _replace_read(work, mood, FrozenGraphReadV2.from_atom(
            GraphAtom(mood.key, mood.revision, broken)))


def test_query_completeness_and_algorithm_allowlist() -> None:
    work = _input()
    with pytest.raises(ValueError, match="installed"):
        replace(work, algorithm_id="caller.function")
    with pytest.raises(ValueError, match="installed numeric policy"):
        replace(work, policy=ActivationPolicy(0.6, 0.25, 32, 128, 1e-6))
    with pytest.raises(ValueError, match="truncation"):
        replace(_input(truncated=True), truncated=False)
    with pytest.raises(ValueError, match="reachable source query"):
        replace(work, edge_queries=work.edge_queries[:1])
    no_context_match = replace(work, context_tags=("other",),
                               edge_queries=work.edge_queries[:1])
    assert activate_association_work_v2(no_context_match).candidates == ()
    with pytest.raises(TypeError, match="frozen"):
        activate_association_work_v2(lambda: None)


def test_durable_canonical_round_trip_rejects_unknown_and_noncanonical_rows() -> None:
    work = _input()
    encoded = work.to_json()
    decoded = AssociationWorkInputV2.from_json(encoded)
    assert decoded.to_dict() == work.to_dict()
    assert decoded.to_json() == encoded
    assert decoded.input_digest == work.input_digest
    assert activate_association_work_v2(decoded) == activate_association_work_v2(work)
    extra = json.loads(encoded)
    extra["reads"][0]["unexpected"] = True
    with pytest.raises(ValueError, match="graph read fields"):
        AssociationWorkInputV2.from_dict(extra)
    noncanonical = json.loads(encoded)
    noncanonical["reads"].reverse()
    with pytest.raises(ValueError, match="row order"):
        AssociationWorkInputV2.from_json(json.dumps(noncanonical, sort_keys=True,
                                                      separators=(",", ":")))
