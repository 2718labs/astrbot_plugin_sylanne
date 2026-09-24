"""The D11 read gate must bind the committed D08/D09 candidate before any claim."""

from __future__ import annotations

from dataclasses import asdict, replace
from copy import deepcopy
import json

from sylanne3.domains.d08 import (
    ActionIntent, ActionSchema, ActionSchemaRecord, CommunicationIntentGrant,
    GoalPredicate, RequiredCheckSpec, SegmentGrant,
)
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim,
    SegmentCandidate, segment_payload_digest,
)
from sylanne3.domains.d11.final_admission import _current_candidate_bundle
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, VersionedRef, canonical_digest, canonical_serialize,
)


def _candidate_graph():
    namespace = NamespaceId("bot", "persona")
    owner = Owner("activity", "bot", "persona", "activity:send")
    checks = tuple(
        RequiredCheckSpec(kind, provider, "persona:persona", "action:send", "respond",
                          "policy:one", (VersionedRef("policy:one", 1),))
        for kind, provider in (
            ("role_binding", "d03.role_binding"),
            ("boundary", "d05.boundary"),
            ("source_grant", "d06.source_grant"),
            ("commitment_conflict", "d08.commitment_conflict"),
            ("dispatch_budget", "d11.dispatch_budget"),
        )
    )
    identity = OperationIdentity(
        "activity:send", "effect:send", "attempt:one", "prepare", "operation:send",
        canonical_digest({"input": "send"}),
    )
    intent = ActionIntent(
        "action:send", 1, "goal:send", (), "entity:alice", "message", "respond",
        "reversible", "0" * 64, identity, "schema:send", checks,
        GoalPredicate("communicated", "d11.delivery", (), 0.0, None),
        ("message:alice",), None, ("source:one",),
    )
    schema = ActionSchemaRecord.bind(intent, ActionSchema("schema:send", "message", False, checks))
    check_refs = tuple("check:" + canonical_digest({
        "kind": item.check_kind, "provider": item.provider_id,
        "subject": item.subject_ref, "action": item.action_ref,
        "purpose": item.purpose, "criteria_version": item.criteria_version,
        "input_versions": item.required_input_versions,
    }) for item in checks)
    use = ClaimUse("claim:one", 0, 5, ClaimKind.REPORTED_CLAIM)
    segment = SegmentGrant(
        "segment:one", "effect:send", 0,
        segment_payload_digest("Hello", (), (use,)), 20, (), None,
        check_refs, 100.0, 0,
    )
    grant = CommunicationIntentGrant(
        "communication-grant:" + "1" * 64, "communication:one", "contact:one", 1,
        intent.action_id, intent.action_id, intent.revision, intent.target_ref,
        (intent.target_ref,), "expression", (), (ClaimKind.REPORTED_CLAIM.value,),
        (), (segment,), "2" * 64, check_refs, 100.0, 0,
    )
    provider = D09ExpressionProvider()
    claim = ExpressionClaim(
        "claim:one", "Hello", ClaimKind.REPORTED_CLAIM, intent.source_refs,
        grant.audiences, ("expression",), "disclosure:one",
    )
    blueprint = provider.prepare_blueprint(grant, "scene:one", 1, (claim,), now=1.0).blueprint
    assert blueprint is not None
    batch = provider.build_verified_batch_v1(
        grant, blueprint,
        (SegmentCandidate("segment:one", "effect:send", "Hello", (use,), (), (), 0.0),),
        now=1.0,
    )
    values = (
        ("d08.action_intent.v1", intent.action_id, asdict(intent)),
        ("d08.action_schema.v1", schema.schema_ref, asdict(schema)),
        ("d08.communication_intent_grant.v1", grant.grant_id, asdict(grant)),
        ("d09.verified_segment_batch.v1", batch["batch_id"], batch),
    )
    atoms = tuple(GraphAtom(AtomKey(owner, type_name, name), 1,
                            json.loads(canonical_serialize(value)))
                  for type_name, name, value in values)
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, *(atom.key.token for atom in atoms),
        canonical_digest(intent), canonical_digest(schema), canonical_digest(grant),
        batch["batch_digest"], intent.source_refs, (), (), 1, 1, 1,
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 1),))
    return candidate, intent, snapshot, namespace


def test_current_committed_bundle_is_structurally_bound_but_not_an_admission():
    candidate, intent, snapshot, namespace = _candidate_graph()
    assert _current_candidate_bundle(candidate, intent, snapshot, namespace, 5.0)
    assert not _current_candidate_bundle(candidate, intent, snapshot, namespace, 101.0)


def test_changed_batch_or_grant_does_not_reuse_candidate_digest():
    candidate, intent, snapshot, namespace = _candidate_graph()
    for index, change in ((2, {"contact_id": "contact:other"}),
                          (3, {"target_ref": "entity:other"})):
        atom = snapshot.atoms[index]
        changed = replace(atom, value={**atom.value, **change})
        current = replace(snapshot, atoms=(*snapshot.atoms[:index], changed,
                                           *snapshot.atoms[index + 1:]))
        assert not _current_candidate_bundle(candidate, intent, current, namespace, 5.0)


def test_self_consistent_batch_digest_cannot_expand_frozen_segment_scope():
    candidate, intent, snapshot, namespace = _candidate_graph()
    value = deepcopy(snapshot.atoms[3].value)
    value["segments"][0]["max_chars"] = 1000
    value["batch_digest"] = canonical_digest({
        key: item for key, item in value.items() if key != "batch_digest"
    })
    changed = replace(snapshot.atoms[3], value=value)
    current = replace(snapshot, atoms=(*snapshot.atoms[:3], changed))
    assert not _current_candidate_bundle(
        replace(candidate, batch_digest=value["batch_digest"]),
        intent, current, namespace, 5.0,
    )


def test_candidate_cannot_point_to_foreign_owner_or_missing_atom():
    candidate, intent, snapshot, namespace = _candidate_graph()
    foreign = replace(snapshot.atoms[3], key=AtomKey(
        Owner("activity", "bot", "other", "activity:send"),
        "d09.verified_segment_batch.v1", snapshot.atoms[3].key.name,
    ))
    assert not _current_candidate_bundle(
        replace(candidate, batch_ref=foreign.key.token), intent,
        replace(snapshot, atoms=(*snapshot.atoms[:3], foreign)), namespace, 5.0,
    )
    assert not _current_candidate_bundle(candidate, intent,
                                         replace(snapshot, atoms=snapshot.atoms[:3]), namespace, 5.0)
