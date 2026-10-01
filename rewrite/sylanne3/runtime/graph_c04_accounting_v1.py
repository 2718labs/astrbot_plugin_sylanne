"""Concrete W01 system entry for the installed historical C04 cost fence."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import time

from ..authority_service.internal_accounting_v1 import (
    HistoricalInternalCostRequestV1, HistoricalInternalCostGrantV1,
    from_wire, to_wire,
)
from ..contracts import Event, Scope, canonical_json
from ..graph_coordinator import UnavailableGuard
from ..graph_store import GraphStore, ProductionGraphStore
from ..graph_types import GraphCandidate, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_historical_accounting_v1 import (
    stage_historical_c04_cost_in_transaction_v1,
    record_historical_c04_body_after_cas_v1,
    close_historical_c04_job_in_transaction_v1,
)
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1


def reconcile_historical_c04_cost_v1(coordinator, bootstrap, namespace, operation_id, *, close_job=False):
    coordinator._admin(bootstrap)
    store = coordinator._GraphCoordinator__store
    port = coordinator._GraphCoordinator__c04_authority_port_v3
    content = coordinator._GraphCoordinator__content_fence_v2
    issuer = coordinator._GraphCoordinator__d02_issuer
    body_authority = coordinator._GraphCoordinator__body_quote_authority
    capability = coordinator._GraphCoordinator__graph_capability
    if (type(namespace) is not NamespaceId or type(close_job) is not bool
            or not isinstance(store, ProductionGraphStore) or port is None
            or content is None or issuer is None or body_authority is None):
        raise UnavailableGuard("installed historical internal accounting unavailable")
    # Cost and a later job closure have separate immutable attempts. Closing
    # cannot replay a settled CPU reservation or redefine the cost receipt.
    phase_key = "closure:" + operation_id if close_job else operation_id
    with store._lock:
        metadata, epoch = coordinator._v2_graph_stamp(namespace)
        db = store._db
        db.execute("BEGIN")
        try:
            prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
            saved = db.execute("SELECT binding_digest,attempt_id,request_json,receipt_json "
                "FROM graph_c04_historical_accounting_v1 WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple, phase_key)).fetchone()
            cost_saved = db.execute("SELECT receipt_json FROM graph_c04_historical_accounting_v1 "
                "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone()
        finally:
            db.rollback()
    if prepared is None or prepared.binding.namespace != metadata.requirements.authority_namespace:
        raise UnavailableGuard("historical C04 preparation or namespace missing")
    binding = prepared.binding
    if close_job and (cost_saved is None or cost_saved[0] is None):
        reconcile_historical_c04_cost_v1(coordinator, bootstrap, namespace, operation_id)
        return reconcile_historical_c04_cost_v1(coordinator, bootstrap, namespace, operation_id, close_job=True)
    if saved is not None:
        if saved[0] != binding.binding_digest:
            raise UnavailableGuard("historical C04 operation changed binding")
        request = from_wire(json.loads(saved[2]), HistoricalInternalCostRequestV1)
        if saved[3] is not None:
            port.internal_accounting(request, "recover_finish")
            return json.loads(saved[3])
    else:
        target = metadata.requirements
        anchor = content.current_anchor(namespace=namespace, authority_namespace=target.authority_namespace)
        if not coordinator._accounting_anchor_covers(target, anchor):
            raise UnavailableGuard("historical C04 anchor differs from graph history")
        attempt_id = "c04-accounting-" + canonical_digest((namespace, phase_key, binding.binding_digest, anchor))[:48]
        request = HistoricalInternalCostRequestV1(attempt_id, binding, anchor)
        with store._lock:
            db.execute("BEGIN IMMEDIATE")
            try:
                if coordinator._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise UnavailableGuard("C04 graph changed before accounting intent")
                db.execute("INSERT INTO graph_c04_historical_accounting_v1 VALUES(?,?,?,?,?,?,NULL)",
                    (*namespace.as_tuple, phase_key, binding.binding_digest, attempt_id,
                     canonical_json(to_wire(request))))
                db.commit()
            except BaseException:
                db.rollback()
                raise
    grant = port.internal_accounting(request, "begin")
    if type(grant) is not HistoricalInternalCostGrantV1 or grant.evidence.binding != binding:
        raise UnavailableGuard("historical C04 Authority evidence differs")
    port.internal_accounting(request, "validate", grant)
    result = None
    with store._lock:
        db.execute("BEGIN IMMEDIATE")
        try:
            current, current_epoch = coordinator._v2_graph_stamp(namespace)
            if ((current, current_epoch) != (metadata, epoch)
                    or not coordinator._accounting_anchor_covers(current.requirements, request.expected_anchor)):
                raise UnavailableGuard("historical C04 accounting graph changed")
            if close_job:
                cost_receipt = json.loads(cost_saved[0])
                cpu = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
                body = read_c04_body_cost_original_v1(db, namespace, operation_id)
                if (cpu is None or canonical_digest(cpu) != cost_receipt["cpu_original_digest"]
                        or cpu.proof_digest != grant.evidence.proof_digest
                        or (canonical_digest(body) if body else None) != cost_receipt["body_original_digest"]):
                    raise UnavailableGuard("historical job closure cost original differs")
                closure, writes = close_historical_c04_job_in_transaction_v1(db, namespace,
                    prepared, grant.evidence, body_gap=cost_receipt["body_gap"],
                    generation=request.expected_anchor.activation_generation)
                reads = tuple(GraphVersion(w.key, (db.execute("SELECT revision FROM graph_atoms "
                    "WHERE token=?", (w.key.token,)).fetchone() or (0,))[0]) for w in writes)
                stage = None
            else:
                stage = stage_historical_c04_cost_in_transaction_v1(db, namespace, grant.evidence,
                    resource_issuer=issuer, body_authority=body_authority)
                writes, reads, closure = stage.writes, stage.reads, None
            anchor = request.expected_anchor
            candidate = GraphCandidate(Event(Scope(*namespace.as_tuple, binding.activity_id),
                "c04-historical-" + canonical_digest((binding.binding_digest, phase_key))[:48], time.time(),
                "c04.historical-accounting.v1", {"evidence_digest": grant.evidence.digest}),
                tuple(reads), tuple(writes), (epoch,))

            def record(_db, receipt):
                nonlocal result
                if receipt.status != "committed":
                    raise UnavailableGuard("historical C04 accounting event differs")
                replacement = replace(current.requirements, deletion_seq=anchor.deletion_seq,
                    deletion_digest=anchor.deletion_digest, execution_seq=anchor.execution_seq,
                    execution_digest=anchor.execution_digest, revocation_epoch=anchor.revocation_epoch)
                store.cas_graph_recovery_metadata(current, replacement, _capability=capability)
                if stage is not None:
                    body = record_historical_c04_body_after_cas_v1(_db, stage)
                    result = {"schema": "c04.historical-cost-receipt.v1", "operation_id": operation_id,
                        "binding_digest": binding.binding_digest, "evidence": to_wire(grant.evidence),
                        "cpu_original_digest": canonical_digest(stage.cpu),
                        "body_original_digest": canonical_digest(body) if body else None,
                        "body_gap": stage.body_gap, "cost_ref": stage.writes[0].key.token,
                        "job_closed": False, "job_closure": None}
                else:
                    result = {**cost_receipt, "job_closed": True, "job_closure": closure}
                result.update({"graph_receipt_digest": canonical_digest(receipt),
                    "reconciliation_generation": anchor.activation_generation})
                _db.execute("UPDATE graph_c04_historical_accounting_v1 SET receipt_json=? "
                    "WHERE bot=? AND persona=? AND operation_id=? AND receipt_json IS NULL",
                    (canonical_json(result), *namespace.as_tuple, phase_key))
                if _db.execute("SELECT changes()").fetchone() != (1,):
                    raise UnavailableGuard("historical C04 accounting receipt raced")
            GraphStore._graph_commit_in_transaction(store, candidate, _receipt_hook=record, _capability=capability)
            if result is None:
                raise UnavailableGuard("historical C04 accounting CAS incomplete")
            db.commit()
        except BaseException:
            db.rollback()
            # Retain the actual original permit on any unresolved outcome.
            # A retry reuses the durable attempt and never executes work.
            raise
    port.internal_accounting(request, "finish", grant)
    return result
