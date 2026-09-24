"""D03 admits a host arrival only with W01's same-transaction scene proof."""

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from sylanne3.domains.d03.message_arrival import (
    build_message_arrival_candidate, build_message_arrival_proposal,
)
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_types import GraphVersion
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.memory_types import SourceRecord, access_key
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DomainBundle, OperationIdentity,
    QueryEpoch, RUNTIME_SCHEMA, SourceQualification, VersionGuard,
    canonical_digest,
)

from test_current_scene_proof_v2 import current_scene


def _arrival(current_scene, operation_id):
    store, _, coordinator, namespace, receipt, source_atom, _, epoch = current_scene
    record = SourceRecord.from_dict(source_atom.value)
    identity = json.loads(receipt.identity_json)
    ingress = HostIngressEnvelope(
        namespace, identity["platform_ref"], identity["conversation_ref"],
        identity["sender_ref"], identity["message_id"], record.text,
        record.occurred_at, record.recorded_at, identity["visibility"],
        SourceLineage(**identity["lineage"]),
    )
    scene = SimpleNamespace(
        namespace=namespace, platform_ref=ingress.platform_ref,
        conversation_ref=ingress.conversation_ref,
        visibility=ingress.visibility,
        scene_ref=scene_ref_for_conversation(
            namespace, ingress.platform_ref, ingress.conversation_ref),
    )
    access = access_key(*namespace.as_tuple, record.source_id)
    with store._lock:
        access_revision, access_json = store._db.execute(
            "SELECT revision,value FROM graph_atoms WHERE token=?",
            (access.token,),
        ).fetchone()
        versions = dict(store._db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current'", namespace.as_tuple,
        ).fetchall())
        authority_epochs = store._db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        budget_ref = store._db.execute(
            "SELECT lease_id FROM runtime_budget_leases WHERE bot_id=? AND persona_id=? "
            "AND state='active' LIMIT 1", namespace.as_tuple,
        ).fetchone()[0]
    qualification = SourceQualification(
        (source_atom.key.token,), "reported", record.occurred_at,
        record.recorded_at, "external_report", "qualified", 0.5,
        "not_applicable",
    )
    candidate = build_message_arrival_candidate(
        ingress, scene, record, json.loads(access_json), qualification,
        source_version=GraphVersion(source_atom.key, source_atom.revision),
        access_version=GraphVersion(access, access_revision),
    )
    bootstrap = coordinator._GraphCoordinator__bootstrap
    lease, capability = coordinator.grant(
        bootstrap, actor="host", issuer_domain="d11", namespace=namespace,
        domains=("d03",), activation_generation=1, operation_id=operation_id,
    )
    authority = AuthorityContext(
        "host", "d11", capability, namespace, ("persona", "event"), "context",
        (ingress.conversation_ref,), "host-ingress-policy", 1,
    )
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(
            "arrival-activity", None, "arrival-attempt", "arrival",
            operation_id, canonical_digest({"input_refs": [source_atom.key.token]}),
        ),
        authority,
        VersionGuard(
            (GraphVersion(source_atom.key, source_atom.revision),
             GraphVersion(access, access_revision),
             GraphVersion(candidate.sender_key, 0),
             GraphVersion(candidate.event_key, 0)),
            (QueryEpoch(namespace, "all", epoch.revision),),
            *authority_epochs, store._registry.catalogue_hash,
            versions["scheme"], versions["operator"], versions["policy"],
            (), (), (),
        ),
        qualification, (source_atom.key.token,), budget_ref,
        4_102_444_800.0, 100.0, "character-v1", (ingress.message_id,),
    )
    proposal = build_message_arrival_proposal(
        envelope, candidate, sender_atom=None)
    return coordinator, lease, DomainBundle(
        envelope, (proposal,), (), (), (), (), (), (), ()), candidate


def test_v2_coordinator_validates_exact_host_arrival_in_locked_snapshot(
        current_scene, monkeypatch):
    coordinator, lease, bundle, candidate = _arrival(
        current_scene, "d03-arrival-commit")
    provider = coordinator._GraphCoordinator__providers["d03"][0]
    validate = provider.validate
    observed = []

    def capture(proposal, snapshot):
        observed.append((validate(proposal, snapshot), snapshot))
        raise RuntimeError("validated under coordinator lock")

    monkeypatch.setattr(provider, "validate", capture)
    with pytest.raises(RuntimeError, match="validated under coordinator lock"):
        coordinator.commit_domain_bundle(bundle, lease)
    assert len(observed) == 1
    assert observed[0][0] == bundle.proposals[0]
    assert len(observed[0][1].scene_proofs) == 1
    assert observed[0][1].scene_proofs[0].graph_epoch == (
        observed[0][1].epochs[0].revision)
    store = current_scene[0]
    row = store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?",
        (candidate.event_key.token,),
    ).fetchone()
    assert row is None


def test_v2_coordinator_rejects_forged_scene(current_scene):
    coordinator, lease, bundle, candidate = _arrival(
        current_scene, "d03-arrival-forged-scene")
    proposal = bundle.proposals[0]
    event_write = proposal.typed_writes[-1]
    forged = replace(event_write, value={
        **event_write.value, "scene_ref": "scene:forged"})
    proposal = replace(proposal,
                       typed_writes=proposal.typed_writes[:-1] + (forged,))
    with pytest.raises(ValueError, match="trusted ingress identity"):
        coordinator.commit_domain_bundle(
            replace(bundle, proposals=(proposal,)), lease)
    assert current_scene[0]._db.execute(
        "SELECT 1 FROM graph_atoms WHERE token=?",
        (candidate.event_key.token,),
    ).fetchone() is None


def test_v2_coordinator_holds_changed_owner_head(current_scene, monkeypatch):
    coordinator, lease, bundle, candidate = _arrival(
        current_scene, "d03-arrival-changed-owner")
    port = coordinator._GraphCoordinator__content_fence_v2
    original = port.get_current_owner_guard_for_fence

    def changed_guard(**kwargs):
        guard, permit = original(**kwargs)
        return replace(guard, authorization_revision=guard.authorization_revision + 1), permit

    monkeypatch.setattr(port, "get_current_owner_guard_for_fence", changed_guard)
    with pytest.raises(UnavailableGuard, match="Owner head lacks matching"):
        coordinator.commit_domain_bundle(bundle, lease)
    assert current_scene[0]._db.execute(
        "SELECT 1 FROM graph_atoms WHERE token=?",
        (candidate.event_key.token,),
    ).fetchone() is None
