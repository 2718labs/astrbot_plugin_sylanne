"""A continuing host ingress needs current Owner/D01/D03 graph evidence."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_contract_digest,
)
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.domains.d03 import WorldEvent
from sylanne3.graph_types import (
    AtomKey, CurrentSceneProof, GraphAtom, GraphVersion, GraphWrite, Owner,
    owner_grant_key,
)
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.ingress_observation import read_committed_ingress_identity
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, canonical_digest,
)

from test_first_ingress_v2 import _ingress_inputs
from test_scene_binding_v2 import _bind_scene, _scene_case


@pytest.fixture
def current_scene(tmp_path):
    case = _scene_case(tmp_path, enable_ingress=True)
    store, authority_db, _port, coordinator, namespace, _principal, _, policy, bootstrap = case
    _bind_scene(case)
    host, clock, encoding = _ingress_inputs(namespace)
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    try:
        with store._lock:
            key = source_key(*namespace.as_tuple, host.lineage.source_ref)
            row = store._db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (key.token,),
            ).fetchone()
            source = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
            receipt = read_committed_ingress_identity(
                store._db, namespace, host.lineage.source_ref)
            owner_row = store._db.execute(
                "SELECT operation_id,request_digest,grant_id,grant_digest,"
                "graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest "
                "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            owner_proof = OwnerGraphCommitProofV1(
                namespace, *owner_row[:5], 1, *owner_row[5:])
            grant = json.loads(store._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?",
                (owner_grant_key(*namespace.as_tuple).token,),
            ).fetchone()[0])
            guard = OwnerAuthorizationGuardV1(
                grant["authority_id"], grant["installation_id"],
                namespace, 1, owner_contract_digest(owner_proof), 0, 0)
            epoch = coordinator._v2_graph_stamp(namespace)[1]
        yield store, authority_db, coordinator, namespace, receipt, source, guard, epoch
    finally:
        store.close()
        authority_db.close()


def test_scene_proof_uses_current_graph_heads(current_scene):
    store, _, coordinator, namespace, receipt, source, guard, epoch = current_scene
    with store._lock:
        proof = coordinator._current_scene_proof_locked(
            store._db, namespace, receipt, source, guard, epoch)
    assert type(proof) is CurrentSceneProof
    assert proof.source_ref == source.key.owner.subject
    assert proof.graph_epoch == epoch.revision
    assert proof.binding_receipt_graph_epoch <= proof.graph_epoch


def test_changed_owner_or_binding_receipt_holds(current_scene):
    store, _, coordinator, namespace, receipt, source, guard, epoch = current_scene
    with store._lock:
        with pytest.raises(UnavailableGuard, match="Owner head lacks matching"):
            coordinator._current_scene_proof_locked(
                store._db, namespace, receipt, source,
                replace(guard, authorization_revision=2), epoch)
        store._db.execute(
            "UPDATE graph_scene_binding_receipts_v1 SET receipt_json=? "
            "WHERE bot=? AND persona=?",
            ("{}", *namespace.as_tuple),
        )
        with pytest.raises(UnavailableGuard, match="receipt is invalid"):
            coordinator._current_scene_proof_locked(
                store._db, namespace, receipt, source, guard, epoch)


def test_current_binding_payload_must_match_its_history(current_scene):
    store, _, coordinator, namespace, receipt, source, guard, epoch = current_scene
    with store._lock:
        token, encoded = store._db.execute(
            "SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.role_binding'", namespace.as_tuple,
        ).fetchone()
        altered = json.loads(encoded)
        altered["social_role"] = "different_role"
        store._db.execute(
            "UPDATE graph_atoms SET value=? WHERE token=?",
            (json.dumps(altered, sort_keys=True, separators=(",", ":")), token),
        )
        with pytest.raises(UnavailableGuard, match="receipt differs from current heads"):
            coordinator._current_scene_proof_locked(
                store._db, namespace, receipt, source, guard, epoch)


def test_v2_write_transaction_passes_same_snapshot_proof_to_provider(
        current_scene, monkeypatch):
    store, _, coordinator, namespace, receipt, source_atom, _, epoch = current_scene
    bootstrap = coordinator._GraphCoordinator__bootstrap
    lease, capability = coordinator.grant(
        bootstrap, actor="host", issuer_domain="d11", namespace=namespace,
        domains=("d03",), activation_generation=1,
        operation_id="scene-proof-probe")
    authority = AuthorityContext(
        "host", "d11", capability, namespace, ("event",), "context",
        ("conversation",), "host-ingress-policy", 1)
    scene_ref = scene_ref_for_conversation(namespace, "platform", "conversation")
    event_id = "world:scene-proof-probe"
    event_key = AtomKey(Owner("event", *namespace.as_tuple, event_id),
                        "d03.world_event", "current")
    event = WorldEvent(
        event_id, "message_received", (("entity:sender", "sender_account"),),
        source_atom.value["recorded_at"], source_atom.value["recorded_at"],
        source_atom.value["recorded_at"], scene_ref,
        (source_atom.key.token,), "host_observed")
    access = access_key(*namespace.as_tuple, source_atom.key.owner.subject)
    with store._lock:
        access_revision = store._db.execute(
            "SELECT revision FROM graph_atoms WHERE token=?", (access.token,)
        ).fetchone()[0]
        versions = dict(store._db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current'", namespace.as_tuple,
        ).fetchall())
        access_epochs = store._db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        budget_ref = store._db.execute(
            "SELECT lease_id FROM runtime_budget_leases WHERE bot_id=? AND persona_id=? "
            "AND state='active' LIMIT 1", namespace.as_tuple,
        ).fetchone()[0]
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity("scene-proof-activity", None, "scene-proof-attempt",
                          "commit", "scene-proof-probe",
                          canonical_digest({"input_refs": [source_atom.key.token]})),
        authority,
        VersionGuard(
            (GraphVersion(source_atom.key, source_atom.revision),
             GraphVersion(access, access_revision), GraphVersion(event_key, 0)),
            (QueryEpoch(namespace, "all", epoch.revision),),
            *access_epochs, store._registry.catalogue_hash,
            versions["scheme"], versions["operator"], versions["policy"],
            (), (), ()),
        SourceQualification(
            (source_atom.key.token,), "reported", source_atom.value["occurred_at"],
            source_atom.value["recorded_at"], "external_report", "qualified",
            0.5, "not_applicable"),
        (source_atom.key.token,), budget_ref, 4_102_444_800.0, 100.0,
        "character-v1", (),
    )
    value = asdict(event)
    value["participant_roles"] = [list(pair) for pair in event.participant_roles]
    value["source_refs"] = list(event.source_refs)
    provider = coordinator._GraphCoordinator__providers["d03"][0]
    observed = []

    def capture(_proposal, snapshot):
        observed.append(snapshot)
        raise RuntimeError("captured before domain write")

    monkeypatch.setattr(provider, "validate", capture)
    proposal = DomainProposal(
        "d03", "d03.proposal.v1", provider.descriptor.request_schema_hash,
        envelope, (GraphWrite(event_key, value),), DependencySet(), (), ())
    bundle = DomainBundle(envelope, (proposal,), (), (), (), (), (), (), ())
    with pytest.raises(RuntimeError, match="captured before domain write"):
        coordinator.commit_domain_bundle(bundle, lease)
    assert len(observed) == 1
    snapshot = observed[0]
    assert snapshot.ingress_receipts == (receipt,)
    assert len(snapshot.scene_proofs) == 1
    assert snapshot.scene_proofs[0].source_ref == source_atom.key.owner.subject
    assert snapshot.scene_proofs[0].scene_ref == scene_ref
    assert snapshot.scene_proofs[0].graph_epoch == snapshot.epochs[0].revision
    assert store._db.execute(
        "SELECT 1 FROM graph_atoms WHERE token=?", (event_key.token,)
    ).fetchone() is None
