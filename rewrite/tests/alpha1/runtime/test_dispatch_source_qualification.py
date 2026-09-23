"""D11 source promotion requires a real D06 graph proof and ancestor closure."""

from dataclasses import replace

from sylanne3.domains.d08 import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.dispatch_candidate import (
    DispatchCandidateEvidenceV1, qualify_dispatch_candidate_sources,
)
from sylanne3.runtime_contracts import OperationIdentity, VersionedRef, canonical_digest


def _case():
    atoms = []
    for source_id, parents in (("child", ("parent",)), ("parent", ())):
        source = SourceRecord(
            source_id, "source text", "speaker", "observed", "confirmed",
            1.0, 2.0, "family", ("entity:user",), ("expression",), parents,
        )
        atoms.extend((
            GraphAtom(source_key("bot", "persona", source_id), 1, source.to_dict()),
            GraphAtom(access_key("bot", "persona", source_id), 1, {
                "source_id": source_id, "audiences": ["entity:user"],
                "purposes": ["expression"], "status": "active", "recorded_at": 2.0,
            }),
        ))
    root, access = atoms[:2]
    spec = RequiredCheckSpec(
        "source_grant", "d06.source_grant", "persona:persona", "action:one",
        "expression", root.key.token, tuple(VersionedRef(atom.key.token, 1)
                                                  for atom in atoms),
    )
    identity = OperationIdentity(
        "activity:one", "effect:one", "attempt:one", "prepare",
        "operation:one", canonical_digest("source-input"),
    )
    intent = ActionIntent(
        "action:one", 1, "goal:one", (), "entity:user", "message",
        "expression", "reversible", canonical_digest("params"), identity,
        "schema:one", (spec,), GoalPredicate("communicated", "delivery", (), 0.0, None),
        ("message:one",), None, (root.key.token,),
    )
    candidate = DispatchCandidateEvidenceV1(
        identity.operation_id, "action", "schema", "grant", "batch",
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, (root.key.token,),
        ((root.key.token, 1),), ((access.key.token, 1),), 0, 0, 7,
    )
    return candidate, intent, GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", 7),))


def _qualify(candidate, intent, snapshot, *, current=True):
    return qualify_dispatch_candidate_sources(
        candidate, intent, snapshot, audience=("entity:user",),
        batch_audiences=("entity:user",), current_barrier_confirmed=current,
        valid_until=10.0,
    )


def test_complete_current_source_and_ancestor_produce_bound_proof():
    candidate, intent, snapshot = _case()
    result = _qualify(candidate, intent, snapshot)
    assert result.status == "source_qualified"
    assert result.source_audience == ("entity:user",)
    assert len(result.source_proof_versions) == 4
    assert result.source_proof_digest != candidate.source_proof_digest
    assert result.digest == _qualify(candidate, intent, snapshot).digest


def test_missing_parent_withdrawn_access_or_unconfirmed_barrier_remain_hold():
    candidate, intent, snapshot = _case()
    assert _qualify(candidate, intent, snapshot, current=False) == candidate
    assert _qualify(candidate, intent, replace(snapshot, atoms=snapshot.atoms[:2])) == candidate
    atoms = list(snapshot.atoms)
    atoms[3] = replace(atoms[3], value={**atoms[3].value, "status": "withdrawn"})
    assert _qualify(candidate, intent, replace(snapshot, atoms=tuple(atoms))) == candidate


def test_unpinned_criteria_or_changed_query_epoch_remain_hold():
    candidate, intent, snapshot = _case()
    spec = intent.required_checks[0]
    no_source_check = replace(spec, check_kind="boundary", provider_id="d05.boundary")
    assert _qualify(candidate, replace(intent, required_checks=(no_source_check,)),
                    snapshot) == candidate
    unpinned = replace(spec, required_input_versions=spec.required_input_versions +
                       (VersionedRef("criteria:external", 1),))
    assert _qualify(candidate, replace(intent, required_checks=(unpinned,)), snapshot) == candidate
    assert _qualify(replace(candidate, query_epoch=8), intent, snapshot) == replace(
        candidate, query_epoch=8)
