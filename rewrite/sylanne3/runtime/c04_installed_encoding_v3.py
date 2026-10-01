"""Actual post-joint, current Owner-fenced C04 encoding baseline commit."""
import json

from ..contracts import canonical_json
from ..graph_store import GraphStore
from ..graph_types import owner_grant_key
from ..runtime_contracts import AuthorityContext, canonical_digest
from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
from .d04_installed_stage_fence_v3 import run_installed_d04_stage_v3
from .installed_c04_encoding_context_v3 import (
    ACTIVITY, encoding_context_operation_id_v3,
    observe_installed_c04_encoding_environment_v3, stage_current_c04_encoding_context_v3,
    issue_committed_c04_encoding_baseline_v3,
)
from .c04_encoding_baseline_store_v3 import _receipt


def commit_post_joint_c04_encoding_v3(graph, bootstrap, bundle, *, c02_operation_id,
        source_ref, joint_operation_id):
    graph._admin(bootstrap)
    namespace = bundle.installation_policy.namespace
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    environment = observe_installed_c04_encoding_environment_v3(graph, bootstrap, namespace)
    operation = encoding_context_operation_id_v3(namespace, joint_operation_id, source_ref)
    observed = []

    def observe(scope):
        current, permit = port.get_current_background_owner_authority_for_fence_v1(
            namespace=namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
        if type(current) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit:
            raise ValueError("C04 encoding actual background Owner authority differs")
        with store._lock:
            row = store._db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",
                (owner_grant_key(*namespace.as_tuple).token,)).fetchone()
            if row is None or row[1] != 1:
                raise ValueError("C04 encoding actual Owner grant is unavailable")
            principal = OwnerPrincipalV1(**json.loads(row[0])["principal"])
        pairing = port.current_owner_principal_binding(namespace=namespace,
            authority_namespace=scope.authority_namespace, principal=principal)
        if (pairing is None or pairing.principal != principal or pairing.namespace != namespace
                or pairing.installation_id != bundle.installation_policy.installation_id
                or pairing.authority_id != scope.pinned_anchor.authority_id):
            raise ValueError("C04 encoding current Owner actor pairing is unavailable")
        observed.append((scope, current, principal, pairing.actor_id))

    def commit(db, metadata, epoch, now, guard, role, current_source):
        if len(observed) != 1 or observed[0][1].guard != guard:
            raise ValueError("C04 encoding current Owner observation changed")
        scope, current, principal, actor = observed[0]
        route = current_source[1]
        authority = AuthorityContext(actor, "d04", "installed-c04-encoding:" + operation,
            namespace, ("activity", "event", "persona", "scene"), "consolidation",
            (route.conversation_ref,), port.installation_grant.publisher_policy_ref,
            metadata.requirements.activation_generation)
        owner = graph._owner_graph_binding_locked(authority, principal,
            target_admission=current.target_admission, storage_admission=current.storage_admission,
            current_guard=guard)
        if (owner.authorization_head != guard.authorization_head
                or owner.authorization_revision != guard.authorization_revision):
            raise ValueError("C04 encoding actual Owner grant/head differs")
        stage = stage_current_c04_encoding_context_v3(graph, db, namespace=namespace,
            joint_operation_id=joint_operation_id, source_ref=source_ref, authority=authority,
            current_owner=owner, scope=scope, environment=environment)
        receipt = GraphStore._graph_commit_in_transaction(store, stage.candidate,
            _capability=graph._GraphCoordinator__graph_capability)
        if receipt.status != "committed" or receipt.revisions or receipt.invalidated:
            raise ValueError("C04 encoding must commit exactly its actual read event")
        store.cas_graph_recovery_metadata(metadata, metadata.requirements,
            _capability=graph._GraphCoordinator__graph_capability)
        prior = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?",
            namespace.as_tuple).fetchone()
        seq = (0 if prior is None else prior[0]) + 1
        db.execute("INSERT INTO graph_bundle_sequence VALUES(?,?,?) ON CONFLICT(bot,persona) "
            "DO UPDATE SET last_seq=excluded.last_seq", (*namespace.as_tuple, seq))
        db.execute("INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,"
            "effect_id,commit_seq,receipt_json) VALUES(?,?,?,?,?,NULL,?,?)", (*namespace.as_tuple,
            operation, canonical_digest(stage.candidate), ACTIVITY, seq,
            canonical_json({"ledger_refs": [], "outbox_refs": []})))
        actual = _receipt(db, namespace, operation)
        record = issue_committed_c04_encoding_baseline_v3(db, stage, actual_receipt=actual)
        return {"schema": "c04.installed_encoding_receipt.v3", "status": "encoding_baseline_committed",
            "operation_id": operation, "joint_operation_id": joint_operation_id,
            "source_ref": source_ref, "record_digest": record.record_digest,
            "original_digest": record.original.digest, "proof_digest": record.proof.proof_digest,
            "graph_receipt_digest": canonical_digest(actual)}

    return run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id,
        source_ref=source_ref, operation_id=operation, stage="c04_encoding",
        request_digest=canonical_digest((ACTIVITY, namespace, c02_operation_id, source_ref, joint_operation_id)),
        commit=commit, semantic=True, fence_observer=observe)
