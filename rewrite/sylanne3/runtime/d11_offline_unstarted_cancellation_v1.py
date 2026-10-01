"""Atomic permanent retirement and release of an unstarted offline reservation."""
from dataclasses import dataclass, replace
import json
import time

from ..authority_service.d11_offline_unstarted_cancellation_v1 import (
    D11OfflineUnstartedCancellationGrantV1, unstarted_cancellation_operation_id_v1,
    unstarted_cancellation_from_wire_v1, unstarted_cancellation_to_wire_v1,
)
from ..contracts import Event, Scope
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_store import GraphStore
from ..graph_types import GraphCandidate, GraphReceipt, GraphVersion, NamespaceEpoch
from ..runtime_contracts import canonical_digest, canonical_serialize
from .budget import BudgetLease, BudgetReceipt, cancel_unstarted_offline_reservation_v1, get_budget_lease, _minus
from .d10_offline_tick_execution_v1 import _decode_json
from .d11_offline_accounting_v1 import read_offline_accounting_prepared_v1
from .d11_offline_originals_v1 import TABLE, SIGN_KIND, WORK_KIND, ALGORITHM_ID
from .d11_types import RuntimeJobValue, runtime_job_key, job_graph_write, reconcile_runtime_write
from .jobs import get_job, _save_job


_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class _OfflineCancellationWitnessV1:
    graph: object
    gate: D11OfflineUnstartedCancellationGrantV1
    prepared: object
    metadata: object
    epoch: object


def require_offline_cancellation_witness_v1(db, witness):
    from ..host.v2_fence_port import V2FencePort
    if (type(witness) is not _OfflineCancellationWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or db is not witness.graph._GraphCoordinator__store._db or not db.in_transaction
            or not witness.graph._GraphCoordinator__store._lock._is_owned()
            or type(witness.graph._GraphCoordinator__content_fence_v2) is not V2FencePort
            or witness.prepared.binding != witness.gate.binding
            or canonical_digest(plain_v1(witness.prepared)) != witness.gate.accounting_original_digest
            or witness.graph._v2_graph_stamp(witness.gate.binding.namespace) != (witness.metadata, witness.epoch)
            or not witness.graph._accounting_anchor_covers(witness.metadata.requirements, witness.gate.permit.pinned_anchor)):
        raise ValueError("offline cancellation requires its actual installed active transaction witness")
    return witness.gate


_RECEIPT_FIELDS = frozenset({"schema", "operation_id", "binding_digest", "accounting_original_digest", "prepared_digest",
    "gate_digest", "no_future_claim_digest", "claim_gate_id", "status", "reservation_operation_id", "reservation_digest",
    "released_ceiling", "budget_receipt_json", "budget_before_json", "budget_after_json", "parent_before_json", "parent_after_json",
    "job_disposition", "job_observed_digest", "event_id", "graph_receipt_digest", "write_commitments"})


def unstarted_cancellation_receipt_from_wire_v1(raw):
    if (type(raw) is not dict or set(raw) != _RECEIPT_FIELDS or raw["schema"] != "d11.offline-unstarted-cancellation-receipt.v1"
            or raw["status"] != "cancelled_unstarted"
            or raw["job_disposition"] not in {"cancelled", "changed_worker_requires_reconciliation"}
            or type(raw["released_ceiling"]) is not dict or set(raw["released_ceiling"]) != {"thread_cpu_ms"}
            or type(raw["released_ceiling"]["thread_cpu_ms"]) is not int or raw["released_ceiling"]["thread_cpu_ms"] < 1
            or type(raw["write_commitments"]) is not list or len(raw["write_commitments"]) > 1
            or any(type(row) is not dict or set(row) != {"ref", "revision", "digest"}
                or type(row["revision"]) is not int or row["revision"] < 1 for row in raw["write_commitments"])):
        raise ValueError("exact offline unstarted cancellation receipt required")
    from ..authority_service.d11_offline_tick_contract_v1 import _hex, _text
    for name in ("binding_digest", "accounting_original_digest", "prepared_digest", "gate_digest",
        "no_future_claim_digest", "reservation_digest", "graph_receipt_digest"):
        _hex(raw[name])
    for name in ("operation_id", "claim_gate_id", "reservation_operation_id", "event_id"):
        _text(raw[name])
    if raw["job_observed_digest"] is not None:
        _hex(raw["job_observed_digest"])
    for row in raw["write_commitments"]:
        _hex(row["digest"])
        _text(row["ref"])
    _decode_json(raw["budget_receipt_json"], BudgetReceipt)
    for name in ("budget_before_json", "budget_after_json"):
        _decode_json(raw[name], BudgetLease)
    if (raw["parent_before_json"] is None) != (raw["parent_after_json"] is None):
        raise ValueError("offline cancellation parent ledger projection is incomplete")
    for name in ("parent_before_json", "parent_after_json"):
        if raw[name] is not None:
            _decode_json(raw[name], BudgetLease)
    return raw


def _read_signed(db, binding, kind, issuer):
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*binding.namespace.as_tuple, kind, binding.execution_id)).fetchone()
    if row is None:
        return None
    raw = json.loads(row[1])
    digest = canonical_digest(raw)
    issuer._signer.verify(SIGN_KIND, canonical_serialize((binding.namespace, kind, binding.execution_id, digest)), row[3])
    if row[0] != unstarted_cancellation_operation_id_v1(binding) or digest != row[2] or canonical_serialize(raw) != row[1]:
        raise ValueError("offline cancellation signed original bytes differ")
    if kind == "cancellation_gate":
        if unstarted_cancellation_from_wire_v1(raw).binding != binding:
            raise ValueError("offline cancellation original binding differs")
    elif kind == "cancellation_receipt":
        unstarted_cancellation_receipt_from_wire_v1(raw)
    else:
        raise ValueError("unknown offline cancellation original kind")
    return raw


def _record_signed(db, binding, kind, raw, issuer):
    prior = _read_signed(db, binding, kind, issuer)
    if prior is not None:
        if prior != raw:
            raise ValueError("offline cancellation original replay changed")
        return
    digest = canonical_digest(raw)
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((binding.namespace, kind, binding.execution_id, digest)))
    db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*binding.namespace.as_tuple, kind, binding.execution_id,
        unstarted_cancellation_operation_id_v1(binding), canonical_serialize(raw), digest, signature))


def _event_id(binding):
    return "d11-offline-cancel-event:" + canonical_digest((binding.namespace, binding.execution_id))[:48]


def _stage_job(db, binding):
    if db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=?", (binding.job_id,)).fetchone() is None:
        return (), "changed_worker_requires_reconciliation", None
    job = get_job(db, binding.job_id)
    before = job_graph_write(job)
    observed = canonical_digest(before.value)
    atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (before.key.token,)).fetchone()
    if ((job.operation_id, job.activity_id, job.bot_id, job.persona_id, job.work_kind, job.budget_ref,
            job.resource_ref, job.fence, job.lease_holder, job.cancel_epoch, job.effect_id, job.snapshot_ref, job.deadline_utc) !=
            (binding.operation_id, binding.activity_id, *binding.namespace.as_tuple, WORK_KIND, binding.parent_budget_lease_ref,
            ALGORITHM_ID, binding.job_fence, binding.job_holder, binding.job_cancel_epoch, None,
            "offline-tick-input:" + binding.input_digest[:48], binding.deadline_utc)
            or job.phase not in {"running", "draining"} or atom != (canonical_serialize(before.value), 1)):
        return (), "changed_worker_requires_reconciliation", observed
    final = replace(job, phase="cancelled", lease_holder=None, lease_expires_utc=None, wake_condition=None, result_ref=None)
    _save_job(db, final)
    return (job_graph_write(final),), "cancelled", observed


def validate_offline_unstarted_cancellation_composite_v1(db, *, gate, result, require_current_anchor=False):
    if type(gate) is not D11OfflineUnstartedCancellationGrantV1:
        raise TypeError("exact offline cancellation gate required")
    unstarted_cancellation_receipt_from_wire_v1(result)
    binding = gate.binding
    expected = {"operation_id": unstarted_cancellation_operation_id_v1(binding), "binding_digest": binding.digest,
        "accounting_original_digest": gate.accounting_original_digest, "prepared_digest": gate.prepared_digest,
        "gate_digest": gate.digest, "no_future_claim_digest": gate.no_future_claim_digest, "claim_gate_id": gate.claim_gate_id,
        "reservation_operation_id": binding.reservation_operation_id, "reservation_digest": binding.reservation_digest,
        "released_ceiling": {"thread_cpu_ms": binding.cpu_ceiling_ms}, "event_id": _event_id(binding)}
    if any(result[name] != value for name, value in expected.items()):
        raise ValueError("offline cancellation composite has another actual execution/reservation")
    before = _decode_json(result["budget_before_json"], BudgetLease)
    after = _decode_json(result["budget_after_json"], BudgetLease)
    expected_after = replace(before, reserved=_minus(before.reserved, result["released_ceiling"]), version=before.version + 1)
    if ((before.lease_id, before.bot_id, before.persona_id) != (binding.parent_budget_lease_ref, *binding.namespace.as_tuple)
            or before.state == "closed" or after != expected_after):
        raise ValueError("offline cancellation changed used/unconfirmed/limits or released the wrong ceiling")
    if before.parent_id is None:
        if result["parent_before_json"] is not None or result["parent_after_json"] is not None:
            raise ValueError("offline root cancellation invented a parent")
    else:
        parent = _decode_json(result["parent_before_json"], BudgetLease)
        if (result["parent_before_json"] != result["parent_after_json"]
                or (parent.lease_id, parent.bot_id, parent.persona_id, parent.currency) !=
                    (before.parent_id, before.bot_id, before.persona_id, before.currency)
                or parent.state == "closed" or any(parent.reserved.get(name, 0) < amount for name, amount in before.limits.items())):
            raise ValueError("offline cancellation released or changed its parent allocation")
    receipt = _decode_json(result["budget_receipt_json"], BudgetReceipt)
    expected_receipt = BudgetReceipt("cancelled_unstarted", binding.reservation_operation_id, binding.reservation_digest,
        after.lease_id, after.version, after.used, after.reserved, after.unconfirmed)
    proof_binding = json.dumps({"schema": "d11.unstarted-reservation-cancellation-binding.v1",
        "binding_digest": binding.digest, "accounting_original_digest": gate.accounting_original_digest,
        "claim_gate_id": gate.claim_gate_id, "no_future_claim_digest": gate.no_future_claim_digest,
        "cancellation_gate_digest": gate.digest, "ceiling": result["released_ceiling"]}, sort_keys=True, separators=(",", ":"))
    operation = db.execute("SELECT digest,lease_id,receipt_json,resolution_binding_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='cancel_unstarted'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    from .budget import _receipt_json
    if receipt != expected_receipt or operation != (binding.reservation_digest, binding.parent_budget_lease_ref, _receipt_json(receipt), proof_binding):
        raise ValueError("offline cancellation lacks its exact immutable budget cancellation receipt")
    reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
    if reservation != (binding.reservation_digest, canonical_serialize(result["released_ceiling"]), "cancelled_unstarted", None):
        raise ValueError("offline cancellation reservation was not permanently retired without fake actual CPU")
    if db.execute("SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
            (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone() is not None:
        raise ValueError("unstarted cancellation conflicts with an executed cost settlement")
    event = db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*binding.namespace.as_tuple, binding.activity_id, _event_id(binding))).fetchone()
    if event is None:
        raise ValueError("offline cancellation actual Graph event is absent")
    graph_receipt = GraphReceipt("committed", GraphStore._version_rows(event[0]), GraphStore._version_rows(event[1]),
        NamespaceEpoch(*binding.namespace.as_tuple, event[2]))
    versions = {row.key.token: row.revision for row in graph_receipt.revisions}
    job_ref = runtime_job_key(*binding.namespace.as_tuple, binding.activity_id, binding.job_id).token
    if (canonical_digest(graph_receipt) != result["graph_receipt_digest"]
            or versions != {row["ref"]: row["revision"] for row in result["write_commitments"]}
            or set(versions) != ({job_ref} if result["job_disposition"] == "cancelled" else set())):
        raise ValueError("offline cancellation Graph receipt contains another job/cost/Source member")
    if versions:
        commitment = result["write_commitments"][0]
        row = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (job_ref, versions[job_ref])).fetchone()
        previous = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?", (job_ref, versions[job_ref] - 1)).fetchone()
        if (row is None or row[0] != _event_id(binding) or row[2] != 1 or canonical_digest(json.loads(row[1])) != commitment["digest"]
                or previous is None or previous[1] != 1 or canonical_digest(json.loads(previous[0])) != result["job_observed_digest"]):
            raise ValueError("offline cancellation historical job write did not close its actual prior projection")
        old, final = _decode_json(previous[0], RuntimeJobValue), _decode_json(row[1], RuntimeJobValue)
        if ((old.operation_id, old.activity_id, old.bot_id, old.persona_id, old.work_kind, old.parent_budget_lease_ref,
                old.resource_ref, old.fence, old.lease_holder, old.cancel_epoch, old.effect_id, old.snapshot_ref, old.deadline_utc) !=
                (binding.operation_id, binding.activity_id, *binding.namespace.as_tuple, WORK_KIND, binding.parent_budget_lease_ref,
                ALGORITHM_ID, binding.job_fence, binding.job_holder, binding.job_cancel_epoch, None,
                "offline-tick-input:" + binding.input_digest[:48], binding.deadline_utc)
                or old.phase not in {"running", "draining"}
                or final != replace(old, phase="cancelled", lease_holder=None, lease_expires_utc=None, wake_condition_digest=None, result_ref=None)):
            raise ValueError("offline cancellation job closure changed its actual worker or usage")
    if require_current_anchor:
        from ..runtime_contracts import SnapshotRequirementsV2
        from ..authority_service.d11_offline_tick_bridge_v1 import _requirements_match
        metadata = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
        if metadata is None or not _requirements_match(_decode_json(metadata[0], SnapshotRequirementsV2), gate.permit.pinned_anchor):
            raise ValueError("offline cancellation Graph did not reach its actual accounting anchor")
    return result


def verify_offline_unstarted_cancellation_commit_v1(db, *, gate, issuer, resource_issuer, require_current_anchor=False):
    binding = gate.binding
    saved = _read_signed(db, binding, "cancellation_gate", issuer)
    result = _read_signed(db, binding, "cancellation_receipt", issuer)
    prepared = read_offline_accounting_prepared_v1(db, binding=binding, issuer=issuer, resource_issuer=resource_issuer)
    if (saved != unstarted_cancellation_to_wire_v1(gate) or result is None or prepared is None
            or canonical_digest(plain_v1(prepared)) != gate.accounting_original_digest):
        raise ValueError("offline cancellation composite lacks its genuine signed originals")
    return validate_offline_unstarted_cancellation_composite_v1(db, gate=gate, result=result, require_current_anchor=require_current_anchor)


def cancel_unstarted_offline_tick_v1(graph, bootstrap, *, binding):
    from ..host.v2_fence_port import V2FencePort
    graph._admin(bootstrap)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    issuer, resources = graph._GraphCoordinator__d11_issuer, graph._GraphCoordinator__d02_issuer
    if type(port) is not V2FencePort:
        raise TypeError("offline cancellation requires the actual paired installed port")
    with store._lock:
        prepared = read_offline_accounting_prepared_v1(store._db, binding=binding, issuer=issuer, resource_issuer=resources)
        saved = _read_signed(store._db, binding, "cancellation_receipt", issuer)
        saved_gate = _read_signed(store._db, binding, "cancellation_gate", issuer)
        if saved is not None:
            if saved_gate is None:
                raise ValueError("offline cancellation receipt lacks its actual gate")
            gate = unstarted_cancellation_from_wire_v1(saved_gate)
            result = verify_offline_unstarted_cancellation_commit_v1(store._db, gate=gate, issuer=issuer, resource_issuer=resources)
        else:
            result = None
    if result is not None:
        port.offline_tick_unstarted_cancellation_v1(binding=binding, action="finish", gate=gate)
        return result
    if prepared is None or saved_gate is not None:
        raise ValueError("offline cancellation actual content-free original is absent")
    gate = port.offline_tick_unstarted_cancellation_v1(binding=binding, action="begin")
    port.offline_tick_unstarted_cancellation_v1(binding=binding, action="validate", gate=gate)
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        witness = None
        try:
            if read_offline_accounting_prepared_v1(db, binding=binding, issuer=issuer, resource_issuer=resources) != prepared:
                raise ValueError("offline cancellation signed accounting original changed")
            metadata, epoch = graph._v2_graph_stamp(binding.namespace)
            witness = _OfflineCancellationWitnessV1(graph, gate, prepared, metadata, epoch)
            _ACTIVE[id(witness)] = witness
            before = get_budget_lease(db, binding.parent_budget_lease_ref)
            parent_before = get_budget_lease(db, before.parent_id) if before.parent_id else None
            budget_receipt = cancel_unstarted_offline_reservation_v1(db, witness=witness)
            after = get_budget_lease(db, before.lease_id)
            parent_after = get_budget_lease(db, before.parent_id) if before.parent_id else None
            writes, disposition, observed = _stage_job(db, binding)
            reads = tuple(GraphVersion(write.key, (db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone() or (0,))[0]) for write in writes)
            for write in writes:
                reconcile_runtime_write(db, write)
            candidate = GraphCandidate(Event(Scope(*binding.namespace.as_tuple, binding.activity_id), _event_id(binding), time.time(),
                "d11.offline-unstarted-cancellation.v1", {"no_future_claim_digest": gate.no_future_claim_digest}), reads, writes, (epoch,))
            receipt = GraphStore._graph_commit_in_transaction(store, candidate, _capability=graph._GraphCoordinator__graph_capability)
            if receipt.status != "committed":
                raise ValueError("offline cancellation Graph event changed")
            anchor = gate.permit.pinned_anchor
            target = replace(metadata.requirements, deletion_seq=anchor.deletion_seq, deletion_digest=anchor.deletion_digest,
                execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest, revocation_epoch=anchor.revocation_epoch)
            store.cas_graph_recovery_metadata(metadata, target, _capability=graph._GraphCoordinator__graph_capability)
            versions = {row.key: row.revision for row in receipt.revisions}
            result = {"schema": "d11.offline-unstarted-cancellation-receipt.v1", "operation_id": unstarted_cancellation_operation_id_v1(binding),
                "binding_digest": binding.digest, "accounting_original_digest": gate.accounting_original_digest,
                "prepared_digest": gate.prepared_digest, "gate_digest": gate.digest, "no_future_claim_digest": gate.no_future_claim_digest,
                "claim_gate_id": gate.claim_gate_id, "status": "cancelled_unstarted", "reservation_operation_id": binding.reservation_operation_id,
                "reservation_digest": binding.reservation_digest, "released_ceiling": {"thread_cpu_ms": binding.cpu_ceiling_ms},
                "budget_receipt_json": canonical_serialize(plain_v1(budget_receipt)), "budget_before_json": canonical_serialize(plain_v1(before)),
                "budget_after_json": canonical_serialize(plain_v1(after)), "parent_before_json": None if parent_before is None else canonical_serialize(plain_v1(parent_before)),
                "parent_after_json": None if parent_after is None else canonical_serialize(plain_v1(parent_after)),
                "job_disposition": disposition, "job_observed_digest": observed, "event_id": _event_id(binding), "graph_receipt_digest": canonical_digest(receipt),
                "write_commitments": [{"ref": write.key.token, "revision": versions[write.key], "digest": canonical_digest(write.value)} for write in writes]}
            validate_offline_unstarted_cancellation_composite_v1(db, gate=gate, result=result, require_current_anchor=True)
            _record_signed(db, binding, "cancellation_gate", unstarted_cancellation_to_wire_v1(gate), issuer)
            _record_signed(db, binding, "cancellation_receipt", result, issuer)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            if witness is not None:
                _ACTIVE.pop(id(witness), None)
    port.offline_tick_unstarted_cancellation_v1(binding=binding, action="finish", gate=gate)
    return result
