"""Pinned GraphStore facts control the Authority-current D01 role head."""

from dataclasses import asdict, replace
import json

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.current_self_identity_graph_verifier import (
    PinnedCurrentSelfIdentityGraphVerifier,
)
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_digest,
)
from sylanne3.contracts import canonical_json
from sylanne3.domains.d01 import PersonaActivation, PersonaBlock, PersonaPlan
from sylanne3.graph_store import ProductionGraphStore, TypeRegistry
from sylanne3.graph_types import AtomKey, Owner, owner_grant_key
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest


def _case(tmp_path):
    fences, core, _, deletion, guard_journal, execution, _ = installed(tmp_path)
    anchor = fences.current_anchor(credential="ok", subject="subject-a")
    namespace = NamespaceId("bot-a", "persona-a")
    graph = ProductionGraphStore(tmp_path / "graph.db", TypeRegistry())
    db = graph._db
    incarnation = "graph-incarnation-a"
    requirements = SnapshotRequirementsV2(
        namespace, anchor.authority_id, anchor.namespace,
        anchor.activation_generation, anchor.deletion_journal_id,
        anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq,
        anchor.execution_digest, anchor.revocation_epoch, incarnation)
    grant = {
        "schema": "sylanne3.graph.owner_grant.v1",
        "authority_id": anchor.authority_id, "installation_id": "installation-a",
        "grant_id": "owner-grant-a", "principal": {
            "identity_provider": "idp", "account_ref": "account-a",
            "account_incarnation": "incarnation-a"},
        "ticket_id": "ticket-a", "creation_operation_id": "create-a",
        "creation_digest": "sha256:" + "a" * 64,
        "issue_operation_id": "issue-a", "grant_revision": 1,
        "state": "pending_authority", "scope": "bot/persona",
        "issuer_ref": "authority:installed-a",
        "capabilities": ["workbench.read"], "purposes": ["context"],
        "audiences": ["owner"], "activation_generation": anchor.activation_generation,
        "graph_incarnation": incarnation,
    }
    proof = OwnerGraphCommitProofV1(
        namespace, "issue-a", "sha256:" + "b" * 64,
        grant["grant_id"], "sha256:" + canonical_digest(grant),
        incarnation, 1, 1, 1, "sha256:" + "c" * 64)
    owner_guard = OwnerAuthorizationGuardV1(
        anchor.authority_id, "installation-a", namespace, 1,
        owner_digest(proof), 0, 0)
    plan = PersonaPlan("plan-a", namespace, 1,
                       (PersonaBlock("block-a", "semantic_identity",
                                     "I am myself", "read_only"),), (), False)
    activation = PersonaActivation(
        namespace, plan.plan_id, plan.version, plan.head_id,
        grant["grant_id"], 1, incarnation, anchor.activation_generation, 1)
    db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?,?)",
               (*namespace.as_tuple, "sylanne3.authority.v2",
                canonical_json(asdict(requirements)), 3))
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", (*namespace.as_tuple, 3))
    db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
               (*namespace.as_tuple, 1, 0))
    db.execute("INSERT INTO graph_owner_issue_operations_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*namespace.as_tuple, proof.operation_id, proof.request_digest,
                proof.grant_id, proof.grant_digest, incarnation,
                proof.graph_access_epoch, proof.graph_epoch,
                proof.graph_receipt_digest, canonical_json(asdict(proof))))
    for key, value in (
            (owner_grant_key(*namespace.as_tuple), grant),
            (AtomKey(Owner("persona", *namespace.as_tuple),
                     "d01.persona_plan.v1", plan.plan_id), asdict(plan)),
            (AtomKey(Owner("persona", *namespace.as_tuple),
                     "d01.persona_activation.v1", "current"), asdict(activation))):
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
                   (key.token, *namespace.as_tuple, key.owner.kind,
                    key.owner.subject, key.type_name, key.name, 1,
                    canonical_json(json.loads(json.dumps(value)))))
    db.commit()
    verifier = PinnedCurrentSelfIdentityGraphVerifier(tmp_path / "graph.db")
    return verifier, namespace, anchor, owner_guard, graph, core, deletion, guard_journal, execution


def test_real_graph_store_current_role_and_revocation_negative(tmp_path):
    verifier, ns, anchor, owner_guard, graph, core, deletion, guard, execution = _case(tmp_path)
    try:
        assert verifier.current(ns, anchor, "installation-a", owner_guard) == (
            "graph-incarnation-a", "plan-a@1")
        assert verifier.current(ns, anchor, "other-installation", owner_guard) is None
        assert verifier.current(ns, anchor, "installation-a", replace(
            owner_guard, pending_revoke_operation_id="revoke-a")) is None
        graph._db.execute("UPDATE graph_authority_epochs SET delete_epoch=1")
        graph._db.commit()
        assert verifier.current(ns, anchor, "installation-a", owner_guard) is None
    finally:
        graph.close(); core.close(); deletion.close(); guard.close(); execution.close()
