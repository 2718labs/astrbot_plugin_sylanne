"""Exact committed authored-root replay under the current signed Owner fence."""
from __future__ import annotations
from dataclasses import asdict
import json
from ..contracts import canonical_json
from ..domains.d04.authored_lineage_v3 import decode_authored_root_candidate_v3
from ..domains.d12.scheme_command import D12SchemeAdoptionReceiptV1
from ..domains.d12.types import active_scheme_head_key
from ..graph_types import GraphReceipt, GraphVersion, AtomKey, NamespaceEpoch
from ..runtime_contracts import FenceScope, NamespaceId, canonical_digest
from .d04_root_original_store_v3 import read_d04_root_original_v3
from .d11_d04_root_freeze_v3 import read_d11_root_freeze_v3


def replay_current_d04_root_v3(graph, authority, lease, *, operation_id, compiled_digest, parent_budget_lease_ref, preset):
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    namespace = authority.namespace
    with store._lock:
        exists = store._db.execute("SELECT 1 FROM graph_d04_root_originals_v3 WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, operation_id)).fetchone()
    if exists is None:
        return None
    owner = graph._GraphCoordinator__owner_leases[lease]
    proof = graph._GraphCoordinator__owner_session_proofs[lease]
    attempt = "d04-root-v3-" + canonical_digest((namespace, operation_id, parent_budget_lease_ref))[:48]
    request = canonical_digest((compiled_digest, operation_id, parent_budget_lease_ref))
    def read():
        db = store._db
        db.execute("BEGIN")
        try:
            original = read_d04_root_original_v3(db, namespace=namespace, operation_id=operation_id)
            frozen = read_d11_root_freeze_v3(db, graph._GraphCoordinator__d11_issuer,
                namespace=namespace, operation_id=operation_id)
            candidate = decode_authored_root_candidate_v3(json.loads(original.candidate_json))
            adoption = db.execute("SELECT request_digest,attempt_id,receipt_json,receipt_sha256 FROM graph_d12_adoption_operations_v1 "
                "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone()
            if (frozen is None or frozen.original_digest != original.signed_freeze_digest
                    or frozen.parent_budget_lease_ref != parent_budget_lease_ref or candidate.preset != preset
                    or adoption is None or adoption[:2] != (request, attempt)):
                raise ValueError("D04 root retry differs from immutable Owner/head/budget/preset originals")
            raw = json.loads(adoption[2])
            receipt = D12SchemeAdoptionReceiptV1(**{**raw, "namespace": NamespaceId(**raw["namespace"])})
            frozen_read = json.loads(frozen.freeze_read_json)
            if (canonical_json(asdict(receipt)) != adoption[2] or canonical_digest(receipt) != adoption[3]
                    or receipt.namespace != namespace or receipt.operation_id != operation_id
                    or receipt.compiled_digest != compiled_digest or receipt.active_head_ref != active_scheme_head_key(namespace).token
                    or frozen_read["active_scheme_head"] != {"ref": receipt.active_head_ref, "version": receipt.active_head_revision}
                    or frozen_read["preset_digest"] != preset.digest or frozen_read["asset_digest"] != preset.assets.digest):
                raise ValueError("D04 root retry signed adoption receipt differs")
            head = db.execute("SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?",
                (receipt.active_head_ref, receipt.active_head_revision)).fetchone()
            if (head is None or head[1:] != (1, operation_id)
                    or json.loads(head[0])["compiled_digest"] != compiled_digest):
                raise ValueError("D04 root retry adopted head history differs")
            event = db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? "
                "AND session='d04.authored_root.v3' AND event_id=?", (*namespace.as_tuple, operation_id)).fetchone()
            if event is None or json.loads(event[1]) != []:
                raise ValueError("D04 root retry event history differs")
            root_receipt = GraphReceipt("committed", tuple(GraphVersion(AtomKey.from_token(ref), revision)
                for ref, revision in json.loads(event[0])), (), NamespaceEpoch(*namespace.as_tuple, event[2]))
            return receipt, root_receipt
        finally:
            db.rollback()
    old_permit, state = port.get_fence_operation(namespace=namespace,
        authority_namespace=graph._GraphCoordinator__d04_installed_joint_assembly.installation_policy.authority_namespace, operation_id=attempt)
    if old_permit is None:
        raise ValueError("D04 root original has no independent original fence")
    if state == "active":
        # Finish a lost post-commit ACK using its exact original permit. Never
        # mint a second write permit or re-run the initial-box/readout math.
        with store._lock:
            metadata, epoch = graph._v2_graph_stamp(namespace)
        scope = FenceScope(namespace, metadata.requirements.authority_namespace, authority.activation_generation,
            "write", attempt, old_permit, old_permit.pinned_anchor, epoch, metadata.graph_revision)
        if port.validate_fence(scope) != old_permit or not graph._anchor_matches(metadata.requirements, old_permit.pinned_anchor):
            raise ValueError("D04 root lost-ACK original fence no longer qualifies")
        graph._owner_binding_in_fence(authority, scope, owner.principal, owner, owner_session_proof=proof)
        with store._lock:
            if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                raise ValueError("D04 root replay snapshot changed")
            result = read()
        port.finish_fence(scope, request_id="finish:" + attempt, request_digest="sha256:" + canonical_digest({
            "action": "finish_d04_root_v3", "operation_id": attempt, "permit_token": old_permit.token}))
        return result
    if state != "finished":
        raise ValueError("D04 root original fence is unresolved")
    return graph._read_v2(authority, read, owner_binding=owner, owner_session_proof=proof)
