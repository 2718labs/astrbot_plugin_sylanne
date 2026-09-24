"""A committed D06 source, rather than the host clock, anchors D03 arrival."""

from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from sylanne3.domains.d03 import message_arrival
from sylanne3.domains.d03.context import ContextProvider
from sylanne3.domains.d03.message_arrival import build_message_arrival_candidate
from sylanne3.domains.d06 import D06DomainAdapter, SourceAdmission
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, IngressIdentityReceipt,
    NamespaceEpoch, Owner,
)
from sylanne3.graph_coordinator import (
    IngressHostFacts, IngressLineage, ingress_host_fingerprint,
    ingress_host_identity_json,
)
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, NamespaceId, OperationIdentity,
    QueryEpoch, RUNTIME_SCHEMA, VersionGuard, canonical_digest,
)


def _inputs(occurred_at=10.0):
    namespace = NamespaceId("bot", "persona")
    ingress = HostIngressEnvelope(
        namespace, "platform", "conversation", "sender", "message", "hello",
        occurred_at, 11.0, "private",
        SourceLineage("a" * 64, "reported", "platform-source", "external_report",
                      "reported_claim"),
    )
    # The v2 ingress replaces the host's proposed learned_at with the paired
    # Authority sample before D06 writes the source.
    admitted = D06DomainAdapter(namespace).admit_source(SourceAdmission(
        "a" * 64, "hello", "sender", "reported", "reported",
        "reported_claim", "not_applicable", occurred_at, 20.0,
        "platform-source", ("conversation",), ("context", "consolidation"),
    ))
    scene = SimpleNamespace(
        namespace=namespace, platform_ref="platform",
        conversation_ref="conversation", visibility="private",
        scene_ref=scene_ref_for_conversation(namespace, "platform", "conversation"),
    )
    source_version = GraphVersion(source_key("bot", "persona", "a" * 64), 1)
    access_version = GraphVersion(access_key("bot", "persona", "a" * 64), 1)
    access = {
        "source_id": admitted.source.source_id,
        "audiences": ["conversation"], "purposes": ["context", "consolidation"],
        "status": "active", "recorded_at": 20.0,
    }
    return ingress, scene, admitted, access, source_version, access_version


@pytest.mark.parametrize("occurred_at", [10.0, None])
def test_arrival_uses_authority_receipt_time_not_host_receive_candidate(occurred_at):
    ingress, scene, admitted, access, source_version, access_version = _inputs(occurred_at)
    candidate = build_message_arrival_candidate(
        ingress, scene, admitted.source, access, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    assert candidate.event.occurred_from == 20.0
    assert candidate.event.occurred_until == 20.0
    assert candidate.event.learned_at == 20.0
    assert admitted.source.occurred_at == occurred_at
    assert candidate.event.reality == "host_observed"
    assert candidate.event.participant_roles == ((candidate.sender_anchor.entity_id,
                                                  "sender_account"),)


def test_arrival_rejects_source_and_qualification_time_disagreement():
    ingress, scene, admitted, access, source_version, access_version = _inputs()
    wrong = replace(admitted.qualification, learned_at=21.0)
    with pytest.raises(ValueError, match="qualified source differs"):
        build_message_arrival_candidate(
            ingress, scene, admitted.source, access, wrong,
            source_version=source_version, access_version=access_version,
        )


def test_arrival_rejects_currently_withdrawn_access():
    ingress, scene, admitted, access, source_version, access_version = _inputs()
    access["status"] = "withdrawn"
    with pytest.raises(ValueError, match="qualified source differs"):
        build_message_arrival_candidate(
            ingress, scene, admitted.source, access, admitted.qualification,
            source_version=source_version, access_version=access_version,
        )


def _proposal_inputs(*, sender_revision=0, event_revision=0):
    ingress, scene, admitted, access, source_version, access_version = _inputs()
    candidate = build_message_arrival_candidate(
        ingress, scene, admitted.source, access, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    namespace = ingress.namespace
    sender_atom = None
    if sender_revision:
        prior = asdict(candidate.sender_anchor)
        prior["creation_evidence_refs"] = [
            source_key("bot", "persona", "b" * 64).token,
        ]
        sender_atom = GraphAtom(candidate.sender_key, sender_revision, prior)
    reads = (
        source_version, access_version,
        GraphVersion(candidate.sender_key, sender_revision),
        GraphVersion(candidate.event_key, event_revision),
    )
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(
            "arrival-activity", None, "arrival-attempt", "arrival",
            "arrival-operation", canonical_digest({"input_refs": [source_version.key.token]}),
        ),
        AuthorityContext(
            "trusted-host", "d11", "arrival-lease", namespace,
            ("persona", "event"), "context", (ingress.conversation_ref,),
            "host-ingress-policy", 1,
        ),
        VersionGuard(
            reads, (QueryEpoch(namespace, "all", 1),), 0, 0,
            "catalogue", "scheme", "operator", "policy", (), (), (),
        ),
        admitted.qualification, (source_version.key.token,),
        "budget", 30.0, 30.0, "interval", (ingress.message_id,),
    )
    return envelope, candidate, sender_atom


def test_compiled_arrival_guards_source_access_and_both_target_keys():
    assert hasattr(message_arrival, "build_message_arrival_proposal")
    envelope, candidate, _ = _proposal_inputs()
    proposal = message_arrival.build_message_arrival_proposal(
        envelope, candidate, sender_atom=None,
    )
    assert proposal.domain == "d03"
    assert proposal.proposal_schema == "d03.proposal.v1"
    assert {write.key for write in proposal.typed_writes} == {
        candidate.sender_key, candidate.event_key,
    }
    source_and_access = {candidate.source_version.key, candidate.access_version.key}
    sender_write, event_write = proposal.typed_writes
    assert set(sender_write.dependencies) == source_and_access
    assert set(event_write.dependencies) == source_and_access | {candidate.sender_key}
    assert "hello" not in str(tuple(write.value for write in proposal.typed_writes))
    assert event_write.value["reality"] == "host_observed"
    assert event_write.value["kind"] == "message_received"
    _, _, admitted, access, _, _ = _inputs()
    snapshot = GraphSnapshot((
        GraphAtom(candidate.source_version.key, 1, admitted.source.to_dict()),
        GraphAtom(candidate.access_version.key, 1, access),
        GraphAtom(candidate.sender_key, 0, {}, False),
        GraphAtom(candidate.event_key, 0, {}, False),
    ), (NamespaceEpoch("bot", "persona", 1),))
    with pytest.raises(ValueError, match="trusted host scene evidence"):
        ContextProvider().validate(proposal, snapshot)
    altered_scene = replace(
        proposal.typed_writes[-1],
        value={**proposal.typed_writes[-1].value, "scene_ref": "scene:other"},
    )
    altered = replace(proposal, typed_writes=proposal.typed_writes[:-1] + (altered_scene,))
    with pytest.raises(ValueError, match="trusted host scene evidence"):
        ContextProvider().validate(altered, snapshot)
    disguised_event = replace(
        proposal.typed_writes[-1],
        value={**proposal.typed_writes[-1].value, "kind": "message_arrival"},
    )
    disguised = replace(proposal, typed_writes=proposal.typed_writes[:-1] + (disguised_event,))
    with pytest.raises(ValueError, match="trusted host scene evidence"):
        ContextProvider().validate(disguised, snapshot)


def test_compiled_arrival_reuses_existing_compatible_account_anchor():
    envelope, candidate, sender_atom = _proposal_inputs(sender_revision=3)
    proposal = message_arrival.build_message_arrival_proposal(
        envelope, candidate, sender_atom=sender_atom,
    )
    assert tuple(write.key for write in proposal.typed_writes) == (candidate.event_key,)
    assert candidate.sender_key in proposal.typed_writes[0].dependencies


def test_compiled_arrival_rejects_existing_event_and_conflicting_anchor():
    envelope, candidate, _ = _proposal_inputs(event_revision=1)
    with pytest.raises(ValueError, match="event.*revision-0"):
        message_arrival.build_message_arrival_proposal(
            envelope, candidate, sender_atom=None,
        )
    envelope, candidate, sender_atom = _proposal_inputs(sender_revision=3)
    bad_anchor = GraphAtom(
        candidate.sender_key, 3,
        {**sender_atom.value, "kind": "person"},
    )
    with pytest.raises(ValueError, match="sender anchor"):
        message_arrival.build_message_arrival_proposal(
            envelope, candidate, sender_atom=bad_anchor,
        )


def test_compiled_arrival_rejects_missing_current_source_guard():
    envelope, candidate, _ = _proposal_inputs()
    guard = replace(
        envelope.version_guard,
        read_versions=tuple(read for read in envelope.version_guard.read_versions
                            if read.key != candidate.access_version.key),
    )
    with pytest.raises(ValueError, match="source.*access"):
        message_arrival.build_message_arrival_proposal(
            replace(envelope, version_guard=guard), candidate, sender_atom=None,
        )


def test_provider_rechecks_reused_anchor_against_transaction_snapshot():
    envelope, candidate, sender_atom = _proposal_inputs(sender_revision=3)
    proposal = message_arrival.build_message_arrival_proposal(
        envelope, candidate, sender_atom=sender_atom,
    )
    _, _, admitted, access, _, _ = _inputs()
    source_atom = GraphAtom(candidate.source_version.key, 1, admitted.source.to_dict())
    access_atom = GraphAtom(candidate.access_version.key, 1, access)
    event_absent = GraphAtom(candidate.event_key, 0, {}, False)
    good = GraphSnapshot(
        (source_atom, access_atom, sender_atom, event_absent),
        (NamespaceEpoch("bot", "persona", 1),),
    )
    provider = ContextProvider()
    with pytest.raises(ValueError, match="trusted host scene evidence"):
        provider.validate(proposal, good)
    conflicting = GraphAtom(
        candidate.sender_key, 3, {**sender_atom.value, "kind": "person"},
    )
    bad = replace(good, atoms=(source_atom, access_atom, conflicting, event_absent))
    with pytest.raises(ValueError, match="sender anchor"):
        provider.validate(proposal, bad)


def test_self_consistent_event_and_sender_rewrites_still_need_d11_ingress_proof():
    envelope, candidate, sender_atom = _proposal_inputs(sender_revision=3)
    proposal = message_arrival.build_message_arrival_proposal(
        envelope, candidate, sender_atom=sender_atom,
    )
    _, _, admitted, access, _, _ = _inputs()
    source_atom = GraphAtom(candidate.source_version.key, 1, admitted.source.to_dict())
    access_atom = GraphAtom(candidate.access_version.key, 1, access)
    provider = ContextProvider()

    other_event_id = "world:other-arrival"
    other_event_key = AtomKey(
        Owner("event", "bot", "persona", other_event_id), "d03.world_event", "current",
    )
    event_write = replace(
        proposal.typed_writes[0], key=other_event_key,
        value={**proposal.typed_writes[0].value, "event_id": other_event_id},
    )
    event_proposal = replace(proposal, typed_writes=(event_write,))
    event_snapshot = GraphSnapshot(
        (source_atom, access_atom, sender_atom, GraphAtom(other_event_key, 0, {}, False)),
        (NamespaceEpoch("bot", "persona", 1),),
    )
    with pytest.raises(ValueError, match="trusted host scene evidence"):
        provider.validate(event_proposal, event_snapshot)

    other_sender_id = "entity:account-v1:other"
    other_sender_key = AtomKey(
        Owner("persona", "bot", "persona"), "d03.entity_anchor", other_sender_id,
    )
    other_sender = GraphAtom(
        other_sender_key, 3,
        {**sender_atom.value, "entity_id": other_sender_id},
    )
    sender_write = replace(
        proposal.typed_writes[0],
        value={**proposal.typed_writes[0].value,
               "participant_roles": [[other_sender_id, "sender_account"]]},
        dependencies=(candidate.source_version.key, candidate.access_version.key,
                      other_sender_key),
    )
    sender_proposal = replace(
        proposal, typed_writes=(sender_write,),
        dependencies=DependencySet(current_invalidation=(
            candidate.source_version, candidate.access_version,
            GraphVersion(other_sender_key, 3),
        )),
    )
    sender_snapshot = GraphSnapshot(
        (source_atom, access_atom, other_sender,
         GraphAtom(candidate.event_key, 0, {}, False)),
        (NamespaceEpoch("bot", "persona", 1),),
    )
    with pytest.raises(ValueError, match="trusted host scene evidence"):
        provider.validate(sender_proposal, sender_snapshot)


def test_trusted_receipt_rebuilds_exact_arrival_but_scene_still_holds():
    envelope, candidate, sender_atom = _proposal_inputs(sender_revision=3)
    proposal = message_arrival.build_message_arrival_proposal(
        envelope, candidate, sender_atom=sender_atom)
    ingress, scene, admitted, access, _, _ = _inputs()
    host = IngressHostFacts(
        ingress.namespace, ingress.platform_ref, ingress.conversation_ref,
        ingress.sender_ref, ingress.message_id, ingress.text,
        ingress.occurred_at, admitted.source.recorded_at, ingress.visibility,
        IngressLineage(**asdict(ingress.lineage)),
    )
    receipt = IngressIdentityReceipt(
        ingress_host_identity_json(host, ingress_ids(host.lineage.source_ref)[2]),
        ingress_host_fingerprint(host), admitted.source.recorded_at, "b" * 64,
    )
    snapshot = GraphSnapshot((
        GraphAtom(candidate.source_version.key, 1, admitted.source.to_dict()),
        GraphAtom(candidate.access_version.key, 1, access),
        sender_atom, GraphAtom(candidate.event_key, 0, {}, False),
    ), (NamespaceEpoch("bot", "persona", 1),), (receipt,))
    assert message_arrival.derive_trusted_message_arrival_identity(
        proposal, snapshot) == (scene.scene_ref, scene.visibility)
    with pytest.raises(ValueError, match="trusted host scene evidence"):
        ContextProvider().validate(proposal, snapshot)
    forged_receipt = replace(receipt, content_fingerprint="c" * 64)
    with pytest.raises(ValueError, match="trusted ingress identity"):
        message_arrival.derive_trusted_message_arrival_identity(
            proposal, replace(snapshot, ingress_receipts=(forged_receipt,)))
    forged_source = replace(snapshot.atoms[0], value={
        **snapshot.atoms[0].value, "text": "replacement message"})
    with pytest.raises(ValueError, match="trusted ingress identity"):
        message_arrival.derive_trusted_message_arrival_identity(
            proposal, replace(snapshot, atoms=(forged_source,) + snapshot.atoms[1:]))
    forged_event = replace(proposal.typed_writes[0], value={
        **proposal.typed_writes[0].value,
        "participant_roles": [["entity:account-v1:forged", "sender_account"]],
    })
    with pytest.raises(ValueError, match="trusted ingress identity"):
        message_arrival.derive_trusted_message_arrival_identity(
            replace(proposal, typed_writes=(forged_event,)), snapshot)
