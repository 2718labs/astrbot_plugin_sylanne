"""Atomic authored-root adoption after one independently recorded CPU execution."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from weakref import WeakValueDictionary

from ..contracts import Event, Scope, canonical_json
from ..domains.d04.authored_lineage_v3 import authored_root_write_rows_v3
from ..domains.d04.authored_root_recovery_v3 import verify_authored_root_math_artifact_v3
from ..domains.d12.scheme_command import D12SchemeAdoptionReceiptV1
from ..domains.d12.types import active_scheme_head_key, character_draft_key
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, GraphReceipt, NamespaceEpoch
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .budget import settle_budget
from .d04_appraisal_driver_v3 import read_d04_original_v3, record_d04_original_in_transaction_v3
from .d04_root_execution_v3 import read_root_prepared_v3, root_execution_ids_v3
from .d04_root_original_store_v3 import record_d04_root_original_v3
from .d04_root_selection_v3 import read_current_root_execution_selection_v3
from .d11_d04_root_freeze_v3 import D11RootFreezeReadV3
from .d11_types import cost_settlement_from_runtime, cost_settlement_graph_write


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _RootCommitWitnessV3:
    graph: object
    prepared: object
    bridge: object
    before: object
    epoch: object
    selection: object
    artifact: object
    target: object
    head_receipt: object = None


_ROOT_WITNESSES = WeakValueDictionary()


def require_root_commit_witness_v3(graph, db, witness, *, after_head=False):
    if (type(witness) is not _RootCommitWitnessV3 or _ROOT_WITNESSES.get(id(witness)) is not witness
            or witness.graph is not graph or db is not graph._GraphCoordinator__store._db or not db.in_transaction):
        raise ValueError("root commit requires the actual installed operation witness")
    binding = witness.prepared.binding
    stamp, epoch = graph._v2_graph_stamp(binding.namespace)
    if (read_root_prepared_v3(db, binding.namespace, binding.operation_id) != witness.prepared
            or stamp.graph_revision != witness.before.graph_revision + int(after_head)
            or epoch.revision != witness.epoch.revision + int(after_head)
            or stamp.requirements != (witness.target if after_head else witness.before.requirements)):
        raise ValueError("root commit current business stamp differs")
    head = active_scheme_head_key(binding.namespace)
    for ref, revision, value, valid in witness.selection.read_rows:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
        expected = (revision, value, valid)
        if after_head and ref == head.token:
            expected = (witness.selection.new_head.generation,
                canonical_json({"schema": head.type_name, **asdict(witness.selection.new_head)}), 1)
        if ((0, "{}", 0) if row is None else row) != expected:
            raise ValueError("root commit complete current/negative read changed")
    if after_head:
        event = db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session='d12.scheme_adoption.v1' AND event_id=?",
            (*binding.namespace.as_tuple, binding.operation_id)).fetchone()
        if (event is None or json.loads(event[1]) or event[2] != epoch.revision
                or witness.head_receipt is None
                or tuple((v.key.token, v.revision) for v in witness.head_receipt.revisions)
                != tuple(tuple(v) for v in json.loads(event[0]))):
            raise ValueError("root commit intentional head/cost event differs")
    return witness


def _stage_root_actual_cpu_v3(graph, db, prepared, terminal):
    binding = prepared.binding
    if terminal.binding != binding:
        raise ValueError("root actual CPU terminal identity differs")
    prior = read_d04_original_v3(db, binding.namespace, "root_cost", binding.operation_id)
    if prior is not None:
        raise ValueError("root actual CPU was already closed outside this atomic adoption")
    quote = graph._GraphCoordinator__d02_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    reserve = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if (canonical_serialize(quote) != prepared.quote_payload_json or canonical_digest(quote) != binding.quote_digest
            or reserve != (binding.reservation_digest, binding.parent_budget_lease_ref, prepared.reserve_receipt_json)):
        raise ValueError("root actual CPU signed quote/reservation changed")
    paid = settle_budget(db, binding.parent_budget_lease_ref, binding.reservation_operation_id,
        binding.reservation_digest, {"thread_cpu_ms": terminal.measurement.actual_cpu_ms}, execution_revoked=True)
    if paid.status not in {"settled", "overrun"}:
        raise ValueError("root actual CPU terminal has not been accounted")
    identity = root_execution_ids_v3(binding.namespace, binding.operation_id)
    cost_id = "d04-root-cost:" + canonical_digest((binding.namespace, binding.operation_id))[:48]
    cost = cost_settlement_from_runtime(db, bot_id=binding.namespace.bot_id,
        persona_id=binding.namespace.persona_id, activity_id=identity["activity"],
        bundle_operation_id=binding.operation_id, effect_id=None, settlement_id=cost_id,
        lease_id=binding.parent_budget_lease_ref, cost_operation_id=binding.reservation_operation_id,
        budget_operation_id=binding.reservation_operation_id, budget_phase="settle",
        prior_unknown_ref=None, execution_revoked=True)
    write = cost_settlement_graph_write(cost)
    result = {"schema": "d04.authored-root-cost.v3", "binding_digest": binding.digest,
        "prepared_digest": prepared.digest, "terminal_digest": terminal.digest,
        "operation_id": binding.operation_id, "status": terminal.measurement.status,
        "actual_cpu_ns": terminal.measurement.actual_cpu_ns, "actual_cpu_ms": terminal.measurement.actual_cpu_ms,
        "settlement_json": canonical_serialize(asdict(paid)), "graph_write_json": canonical_serialize(asdict(write))}
    record_d04_original_in_transaction_v3(db, binding.namespace, "root_cost", binding.operation_id, result)
    return result, write


def adopt_executed_root_v3(graph, authority, lease, executed, *, preset):
    """Validate a real root terminal and atomically commit head, six roots and cost."""
    from ..authority_service.d04_root_execution_bridge_v3 import (
        D04RootAdoptionBridgeV3, root_bridge_to_wire_v3)
    from ..domains.d04.authored_root_recovery_v3 import decode_authored_root_math_artifact_v3
    from ..host.installed_d04_output_policy import load_installed_d04_output_policy_v1
    from ..host.installed_tanh_readout_asset import load_installed_tanh_readout_candidate
    from ..native_runtime.loader import load_production_native
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from .d04_executed_root_freeze_v3 import issue_executed_d11_root_freeze_v3
    from .first_ingress_v2 import trusted_upper

    prepared, binding = executed.prepared, executed.prepared.binding
    duplicate = replay_executed_root_v3(graph, authority, lease,
        operation_id=binding.operation_id, compiled_digest=json.loads(prepared.input_payload_json)["compiled_digest"],
        parent_budget_lease_ref=binding.parent_budget_lease_ref, preset=preset)
    if duplicate is not None:
        return duplicate
    assembly, store = graph._GraphCoordinator__d04_installed_joint_assembly, graph._GraphCoordinator__store
    port = graph._GraphCoordinator__c04_authority_port_v3
    if type(port) is not InstalledC04AuthorityPortV3 or executed.terminal is None:
        raise ValueError("root adoption needs its installed independent terminal")
    if (getattr(executed.terminal, "adoption_allowed", True) is False
            or executed.terminal.measurement.status != "completed"
            or executed.terminal.measurement.actual_cpu_ms > binding.cpu_ceiling_ms):
        raise ValueError("failed root execution requires historical CPU settlement")
    # Restore is an actual service read, not a supplied artifact/result DTO.
    original = port.root_restore_original(binding)
    if original.prepared != prepared or original.terminal != executed.terminal:
        raise ValueError("root restored original differs from the execution terminal")
    artifact = decode_authored_root_math_artifact_v3(original.artifact_payload)
    handle = load_production_native(assembly.package_root, trusted_manifest_sha256=binding.native_manifest_sha256)
    output_policy = load_installed_d04_output_policy_v1(assembly.package_root,
        binding.native_manifest_sha256, require_formal=False, require_backend_runtime=True)
    readout = load_installed_tanh_readout_candidate(assembly.package_root, binding.native_manifest_sha256,
        preset.assets, expected_readout_id=output_policy.policy.readout_id,
        available_cpu_features=assembly.available_cpu_features)
    bridge = port.root_adoption_bridge(binding)
    if (type(bridge) is not D04RootAdoptionBridgeV3 or bridge.binding != binding
            or bridge.prepared_digest != prepared.digest or bridge.terminal != original.terminal):
        raise ValueError("root actual adoption bridge differs")
    graph._authorize(lease, authority, frozenset(("d04", "d11", "d12")), owner_read=True)
    owner = graph._GraphCoordinator__owner_leases[lease]
    if ((owner.authorization_head, owner.authorization_revision) !=
            (bridge.owner_authority.guard.authorization_head, bridge.owner_authority.guard.authorization_revision)
            or asdict(owner.principal) != json.loads(prepared.input_payload_json)["owner"]["principal"]):
        raise ValueError("root current Owner differs from independently observed authority")
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    raw = json.loads(prepared.input_payload_json)
    finished = False
    witness = None
    try:
        port.root_validate_gate(binding, bridge)
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                before, epoch = graph._v2_graph_stamp(binding.namespace)
                requirement_row = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    binding.namespace.as_tuple).fetchone()
                if (requirement_row != (bridge.before_requirements_json,)
                        or before.graph_revision != bridge.before_graph_revision
                        or before.graph_revision != raw["graph_revision"] or epoch.revision != raw["graph_epoch"]
                        or not graph._anchor_matches(before.requirements, bridge.before_anchor)):
                    raise ValueError("root final business snapshot changed")
                current_owner = graph._owner_graph_binding_locked(authority, owner.principal,
                    target_admission=bridge.owner_authority.target_admission, storage_admission=bridge.owner_authority.storage_admission, current_guard=bridge.owner_authority.guard)
                if current_owner != owner:
                    raise ValueError("root final actual Owner Graph grant changed")
                selection = read_current_root_execution_selection_v3(graph, db, authority,
                    operation_id=binding.operation_id, compiled_digest=raw["compiled_digest"], preset=preset)
                if (selection.candidate.digest != binding.candidate_digest
                        or canonical_serialize(selection.read_rows) != canonical_serialize(raw["read_rows"])
                        or asdict(selection.new_head) != raw["new_head"]):
                    raise ValueError("root final selection differs from the actually executed input")
                output = verify_authored_root_math_artifact_v3(selection.candidate, artifact,
                    handle.production_binding, readout.asset, output_policy.policy, binding.operation_id)
                target = replace(before.requirements, execution_seq=bridge.after_anchor.execution_seq,
                    execution_digest=bridge.after_anchor.execution_digest)
                if not graph._anchor_matches(target, bridge.after_anchor):
                    raise ValueError("root adoption bridge changed more than its own execution interval")
                witness = _RootCommitWitnessV3(graph, prepared, bridge, before, epoch, selection, artifact, target)
                _ROOT_WITNESSES[id(witness)] = witness
                require_root_commit_witness_v3(graph, db, witness)
                record_d04_original_in_transaction_v3(db, binding.namespace, "root_adoption_bridge",
                    binding.operation_id, root_bridge_to_wire_v3(bridge))
                cost, cost_write = _stage_root_actual_cpu_v3(graph, db, prepared, bridge.terminal)
                head_key, draft_key = active_scheme_head_key(binding.namespace), character_draft_key(binding.namespace)
                if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (cost_write.key.token,)).fetchone():
                    raise ValueError("root actual CPU graph settlement already exists")
                reads = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision, _, _ in selection.read_rows)
                head_writes = (GraphWrite(head_key, {"schema": head_key.type_name, **asdict(selection.new_head)}), cost_write)
                head_candidate = GraphCandidate(Event(Scope(*binding.namespace.as_tuple, "d12.scheme_adoption.v1"),
                    binding.operation_id, now, "scheme_adoption", {"compiled_digest": raw["compiled_digest"],
                    "root_kind": "d04.authored_root.v3", "execution_terminal_digest": bridge.terminal.digest}),
                    reads + (GraphVersion(cost_write.key, 0),), head_writes, (epoch,))
                def record_head(_db, receipt):
                    store.cas_graph_recovery_metadata(before, target, _capability=graph._GraphCoordinator__graph_capability)
                head_receipt = GraphStore._graph_commit_in_transaction(store, head_candidate,
                    _receipt_hook=record_head, _capability=graph._GraphCoordinator__graph_capability)
                if head_receipt.status != "committed":
                    raise ValueError("root head and measured CPU did not atomically commit")
                old_witness = witness
                witness = replace(witness, head_receipt=head_receipt)
                _ROOT_WITNESSES.pop(id(old_witness), None)
                _ROOT_WITNESSES[id(witness)] = witness
                require_root_commit_witness_v3(graph, db, witness, after_head=True)
                adoption = D12SchemeAdoptionReceiptV1(binding.operation_id, binding.namespace, raw["compiled_digest"],
                    head_key.token, selection.new_head.generation - 1, head_key.token,
                    selection.new_head.generation, head_receipt.epoch.revision)
                db.execute("INSERT INTO graph_d12_adoption_operations_v1 VALUES(?,?,?,?,?,?,?)",
                    (*binding.namespace.as_tuple, binding.operation_id,
                    canonical_digest((raw["compiled_digest"], binding.operation_id, binding.parent_budget_lease_ref)),
                    bridge.permit.operation_id, canonical_json(asdict(adoption)), canonical_digest(adoption)))
                current_rows = tuple((ref, *db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone())
                    if ref == head_key.token else (ref, revision, value, valid)
                    for ref, revision, value, valid in selection.read_rows)
                rows = authored_root_write_rows_v3(output.members)
                read = D11RootFreezeReadV3(binding.namespace, binding.operation_id, raw["owner"]["actor"],
                    raw["owner_session_id"], raw["owner_session_binding_digest"],
                    VersionedRef(head_key.token, selection.new_head.generation),
                    VersionedRef(draft_key.token, selection.new_head.draft_revision), selection.new_head.draft_digest,
                    selection.root_input_digest, selection.candidate.digest, preset.digest, preset.assets.digest,
                    binding.native_manifest_sha256, binding.native_sha256, artifact.initial_box_proof.proof_digest,
                    output.readout_output_digest, artifact.initial_box_proof.proof_digest, output.issuance_digest,
                    canonical_serialize(rows), output.write_set_digest, canonical_digest(current_rows),
                    canonical_digest((bridge.permit.token, raw["owner"], raw["owner_session_binding_digest"])))
                freeze = issue_executed_d11_root_freeze_v3(db, graph, witness, read, now_utc=now)
                mid, mid_epoch = graph._v2_graph_stamp(binding.namespace)
                root_candidate = GraphCandidate(Event(Scope(*binding.namespace.as_tuple, "d04.authored_root.v3"),
                    binding.operation_id, now, "d04_authored_root_v3", {"candidate_digest": selection.candidate.digest,
                    "freeze_digest": freeze.original_digest, "execution_terminal_digest": bridge.terminal.digest}),
                    tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision, _, _ in current_rows),
                    tuple(GraphWrite(AtomKey.from_token(ref), value) for ref, _, value in rows), (mid_epoch,))
                recorded = []
                def record_root(_db, receipt):
                    recorded.append(record_d04_root_original_v3(_db, namespace=binding.namespace,
                        operation_id=binding.operation_id, candidate=selection.candidate,
                        initial_box=artifact.initial_box_proof, output=output, freeze=freeze, receipt=receipt))
                    store.cas_graph_recovery_metadata(mid, target, _capability=graph._GraphCoordinator__graph_capability)
                root_receipt = GraphStore._graph_commit_in_transaction(store, root_candidate,
                    _receipt_hook=record_root, _capability=graph._GraphCoordinator__graph_capability)
                link = {"schema": "d04.authored-root-execution-link.v3", "operation_id": binding.operation_id,
                    "binding_digest": binding.digest, "prepared_digest": prepared.digest,
                    "terminal_digest": bridge.terminal.digest, "artifact_digest": artifact.artifact_digest,
                    "cost_original_digest": canonical_digest(cost), "freeze_digest": freeze.original_digest,
                    "root_original_digest": recorded[0].original_digest,
                    "head_event_session": "d12.scheme_adoption.v1", "root_event_session": "d04.authored_root.v3",
                    "head_receipt_digest": canonical_digest(head_receipt),
                    "root_receipt_digest": canonical_digest(root_receipt), "adoption_receipt": asdict(adoption),
                    "graph_revision": before.graph_revision + 2, "graph_epoch": root_receipt.epoch.revision}
                record_d04_original_in_transaction_v3(db, binding.namespace, "root_execution_link", binding.operation_id, link)
                db.commit()
                finished = True
            except BaseException:
                db.rollback()
                raise
        port.root_finish_gate(binding, bridge, outcome="committed")
        return adoption, root_receipt
    except (ValueError, TypeError):
        if not finished:
            port.root_finish_gate(binding, bridge, outcome="abandoned")
        raise
    finally:
        if witness is not None:
            _ROOT_WITNESSES.pop(id(witness), None)


def replay_executed_root_v3(graph, authority, lease, *, operation_id, compiled_digest,
        parent_budget_lease_ref, preset):
    """Same operation replays its actual final receipt without budget or FFI."""
    from ..authority_service.d04_root_execution_bridge_v3 import D04RootAdoptionBridgeV3, root_bridge_from_wire_v3
    from .d04_root_original_store_v3 import read_d04_root_original_v3
    from .d11_d04_root_freeze_v3 import read_d11_root_freeze_v3
    graph._authorize(lease, authority, frozenset(("d04", "d11", "d12")), owner_read=True)
    store, port, ns = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3, authority.namespace
    with store._lock:
        saved = read_d04_original_v3(store._db, ns, "root_execution_link", operation_id)
        saved_gate = read_d04_original_v3(store._db, ns, "root_adoption_bridge", operation_id)
    if saved is None:
        return None
    if saved_gate is None:
        raise ValueError("root committed original lacks its actual adoption gate")
    bridge = root_bridge_from_wire_v3(saved_gate[0], D04RootAdoptionBridgeV3)
    binding = bridge.binding
    if (binding.namespace != ns or binding.operation_id != operation_id or binding.preset_digest != preset.digest
            or binding.parent_budget_lease_ref != parent_budget_lease_ref):
        raise ValueError("root retry changes its original namespace/preset/budget")
    state = port.root_gate_status(binding, bridge)
    if state == "active":
        port.root_finish_gate(binding, bridge, outcome="committed")
    elif state != "finished":
        raise ValueError("root exact original adoption remains unresolved")
    owner = graph._GraphCoordinator__owner_leases[lease]
    proof = graph._GraphCoordinator__owner_session_proofs[lease]
    def read():
        db = store._db
        db.execute("BEGIN")
        try:
            prepared = read_root_prepared_v3(db, ns, operation_id)
            actual = read_d04_original_v3(db, ns, "root_execution_link", operation_id)
            root = read_d04_root_original_v3(db, namespace=ns, operation_id=operation_id)
            freeze = read_d11_root_freeze_v3(db, graph._GraphCoordinator__d11_issuer, namespace=ns, operation_id=operation_id)
            if prepared is None or actual != saved or freeze is None:
                raise ValueError("root original replay closure is missing")
            raw, link = json.loads(prepared.input_payload_json), actual[0]
            if (prepared.binding != binding or raw["compiled_digest"] != compiled_digest
                    or raw["owner"]["actor"] != authority.actor or root.signed_freeze_digest != freeze.original_digest
                    or link["root_original_digest"] != root.original_digest
                    or link["terminal_digest"] != bridge.terminal.digest):
                raise ValueError("root replay differs from original Owner/compilation/execution")
            receipt_raw = link["adoption_receipt"]
            adopted = D12SchemeAdoptionReceiptV1(**{**receipt_raw, "namespace": NamespaceId(**receipt_raw["namespace"])})
            event = db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? "
                "AND session='d04.authored_root.v3' AND event_id=?", (*ns.as_tuple, operation_id)).fetchone()
            if event is None or json.loads(event[1]):
                raise ValueError("root original graph receipt is unavailable")
            receipt = GraphReceipt("committed", GraphStore._version_rows(event[0]), (), NamespaceEpoch(*ns.as_tuple, event[2]))
            if canonical_digest(receipt) != link["root_receipt_digest"]:
                raise ValueError("root exact original graph receipt changed")
            return adopted, receipt
        finally:
            db.rollback()
    return graph._read_v2(authority, read, owner_binding=owner, owner_session_proof=proof)
