"""Atomic historical offline CPU closure without content adoption or execution."""
from dataclasses import replace
import hashlib
import json
import time

from ..authority_service.d11_offline_historical_accounting_v1 import (
    D11OfflineHistoricalCostGrantV1, historical_accounting_operation_id_v1,
    historical_accounting_from_wire_v1, historical_accounting_to_wire_v1,
)
from ..contracts import Event, Scope
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_store import GraphStore
from ..graph_types import GraphCandidate, GraphReceipt, GraphVersion, NamespaceEpoch
from ..runtime_contracts import canonical_digest, canonical_serialize
from .budget import BudgetReceipt, get_budget_lease, settle_budget, _settlement_binding
from .d10_offline_tick_execution_v1 import offline_tick_ids_v1
from .d11_offline_accounting_v1 import read_offline_accounting_prepared_v1
from .d11_offline_originals_v1 import TABLE, SIGN_KIND, WORK_KIND, ALGORITHM_ID
from .d11_types import (RuntimeCostSettlement, RuntimeJobValue, runtime_job_key, runtime_cost_settlement_key,
    cost_settlement_from_runtime, cost_settlement_graph_write, job_graph_write, reconcile_runtime_write)
from .jobs import get_job, _save_job


_RECEIPT_FIELDS = frozenset({"schema", "operation_id", "binding_digest", "accounting_original_digest",
    "prepared_digest", "claim_digest", "terminal_digest", "gate_digest", "durable_closure_digest",
    "status", "actual_cpu_ms", "cost_status", "cost_ref", "cost_digest", "job_disposition",
    "job_observed_digest", "adoption_status", "event_id", "graph_receipt_digest", "write_commitments"})


def historical_accounting_receipt_from_wire_v1(raw):
    if (type(raw) is not dict or set(raw) != _RECEIPT_FIELDS
            or raw["schema"] != "d11.offline-historical-cost-receipt.v1"
            or raw["adoption_status"] != "not_adopted"
            or raw["status"] not in {"completed", "failed", "unknown"}
            or raw["cost_status"] not in {"settled", "overrun", "pending_confirmation"}
            or raw["job_disposition"] not in {"failed", "pending_confirmation", "changed_worker_requires_reconciliation"}
            or type(raw["write_commitments"]) is not list or not 1 <= len(raw["write_commitments"]) <= 2
            or any(type(row) is not dict or set(row) != {"ref", "revision", "digest"}
                or type(row["revision"]) is not int or row["revision"] < 1 for row in raw["write_commitments"])
            or len({row["ref"] for row in raw["write_commitments"]}) != len(raw["write_commitments"])
            or (raw["status"] == "unknown" and (raw["actual_cpu_ms"] is not None or raw["cost_status"] != "pending_confirmation"))
            or (raw["status"] != "unknown" and (type(raw["actual_cpu_ms"]) is not int or raw["actual_cpu_ms"] < 0
                or raw["cost_status"] not in {"settled", "overrun"}))):
        raise ValueError("offline historical accounting receipt fields differ")
    from ..authority_service.d11_offline_tick_contract_v1 import _hex, _chain, _text
    for name in ("binding_digest", "accounting_original_digest", "prepared_digest", "gate_digest",
                 "durable_closure_digest", "cost_digest", "graph_receipt_digest"):
        _hex(raw[name])
    for name in ("claim_digest", "terminal_digest"):
        _chain(raw[name])
    for name in ("operation_id", "event_id", "cost_ref"):
        _text(raw[name])
    if raw["job_observed_digest"] is not None:
        _hex(raw["job_observed_digest"])
    for row in raw["write_commitments"]:
        _hex(row["digest"])
        _text(row["ref"])
    return raw


def _read_signed(db, binding, kind, issuer):
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
        (*binding.namespace.as_tuple, kind, binding.execution_id)).fetchone()
    if row is None:
        return None
    raw = json.loads(row[1])
    digest = canonical_digest(raw)
    issuer._signer.verify(SIGN_KIND, canonical_serialize((binding.namespace, kind, binding.execution_id, digest)), row[3])
    if (row[0] != historical_accounting_operation_id_v1(binding) or digest != row[2]
            or canonical_serialize(raw) != row[1]):
        raise ValueError("offline signed historical accounting bytes differ")
    if kind == "historical_accounting_gate":
        if historical_accounting_from_wire_v1(raw).binding != binding:
            raise ValueError("offline historical original binding differs")
    elif kind == "historical_accounting_receipt":
        historical_accounting_receipt_from_wire_v1(raw)
    else:
        raise ValueError("unknown historical offline original kind")
    return raw


def _record_signed(db, binding, kind, raw, issuer):
    prior = _read_signed(db, binding, kind, issuer)
    if prior is not None:
        if prior != raw:
            raise ValueError("offline historical accounting replay changed")
        return
    wire, digest = canonical_serialize(raw), canonical_digest(raw)
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((binding.namespace, kind, binding.execution_id, digest)))
    db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*binding.namespace.as_tuple, kind,
        binding.execution_id, historical_accounting_operation_id_v1(binding), wire, digest, signature))


def _event_id(binding):
    return "d11-offline-historical-event:" + canonical_digest((binding.namespace, binding.execution_id))[:48]


def _actual(gate):
    return None if gate.status == "unknown" else {"thread_cpu_ms": gate.actual_cpu_ms}


def _stage_cost_and_job(db, gate):
    binding = gate.binding
    if db.execute("SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
            (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone() is not None:
        raise ValueError("offline existing settlement needs its authenticated composite receipt")
    settled = settle_budget(db, binding.parent_budget_lease_ref, binding.reservation_operation_id,
        binding.reservation_digest, _actual(gate), execution_revoked=True)
    if settled.status not in ({"pending_confirmation"} if gate.status == "unknown" else {"settled", "overrun"}):
        raise ValueError("offline historical actual CPU settlement differs")
    ids = offline_tick_ids_v1(binding.namespace, binding.schedule_ref, binding.scheduled_at_utc)
    cost = cost_settlement_from_runtime(db, bot_id=binding.namespace.bot_id, persona_id=binding.namespace.persona_id,
        activity_id=binding.activity_id, bundle_operation_id=historical_accounting_operation_id_v1(binding), effect_id=None,
        settlement_id=ids["reservation"], lease_id=binding.parent_budget_lease_ref,
        cost_operation_id=binding.reservation_operation_id, budget_operation_id=binding.reservation_operation_id,
        budget_phase="settle", prior_unknown_ref=None, execution_revoked=True)
    writes = [cost_settlement_graph_write(cost)]
    disposition, observed_digest = "changed_worker_requires_reconciliation", None
    if db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=?", (binding.job_id,)).fetchone() is not None:
        job = get_job(db, binding.job_id)
        projection = job_graph_write(job)
        observed_digest = canonical_digest(projection.value)
        atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (projection.key.token,)).fetchone()
        if ((job.operation_id, job.activity_id, job.bot_id, job.persona_id, job.work_kind,
                job.budget_ref, job.resource_ref, job.fence, job.lease_holder, job.cancel_epoch) ==
                (binding.operation_id, binding.activity_id, *binding.namespace.as_tuple, WORK_KIND,
                binding.parent_budget_lease_ref, ALGORITHM_ID, binding.job_fence, binding.job_holder, binding.job_cancel_epoch)
                and job.phase in {"running", "draining"} and job.effect_id is None
                and job.snapshot_ref == "offline-tick-input:" + binding.input_digest[:48]
                and job.deadline_utc == binding.deadline_utc
                and atom == (canonical_serialize(projection.value), 1)):
            disposition = "pending_confirmation" if gate.status == "unknown" else "failed"
            usage = dict(job.usage)
            if gate.actual_cpu_ms is not None:
                usage["thread_cpu_ms"] = max(usage.get("thread_cpu_ms", 0), gate.actual_cpu_ms)
            final = replace(job, phase=disposition, lease_holder=None, lease_expires_utc=None, wake_condition=None,
                result_ref=None, usage=usage)
            _save_job(db, final)
            writes.append(job_graph_write(final))
    return cost, tuple(writes), disposition, observed_digest


def verify_offline_historical_accounting_commit_v1(db, *, gate, issuer, resource_issuer, require_current_anchor=False):
    """Verify the signed composite and its historical Graph writes, never today's job."""
    if type(gate) is not D11OfflineHistoricalCostGrantV1:
        raise TypeError("actual offline accounting grant required")
    binding = gate.binding
    saved = _read_signed(db, binding, "historical_accounting_gate", issuer)
    result = _read_signed(db, binding, "historical_accounting_receipt", issuer)
    prepared = read_offline_accounting_prepared_v1(db, binding=binding, issuer=issuer, resource_issuer=resource_issuer)
    if (saved != historical_accounting_to_wire_v1(gate) or result is None or prepared is None
            or canonical_digest(plain_v1(prepared)) != gate.accounting_original_digest):
        raise ValueError("offline historical composite lacks its actual signed originals")
    return validate_offline_historical_accounting_composite_v1(db, gate=gate, result=result,
        require_current_anchor=require_current_anchor)


def validate_offline_historical_accounting_composite_v1(db, *, gate, result, require_current_anchor=False):
    """Closed structural joins after the caller authenticates signed originals."""
    if type(gate) is not D11OfflineHistoricalCostGrantV1:
        raise TypeError("exact D11 historical accounting grant required")
    historical_accounting_receipt_from_wire_v1(result)
    binding = gate.binding
    from .d10_offline_tick_execution_v1 import _decode_json
    expected = {"operation_id": historical_accounting_operation_id_v1(binding), "binding_digest": binding.digest,
        "accounting_original_digest": gate.accounting_original_digest, "prepared_digest": gate.prepared_digest,
        "claim_digest": gate.claim_digest, "terminal_digest": gate.terminal_digest, "gate_digest": gate.digest,
        "durable_closure_digest": gate.durable_closure_digest, "status": gate.status,
        "actual_cpu_ms": gate.actual_cpu_ms, "event_id": _event_id(binding), "adoption_status": "not_adopted"}
    if any(result[name] != value for name, value in expected.items()):
        raise ValueError("offline historical receipt original commitments differ")
    settlement = db.execute("SELECT digest,lease_id,resolution_binding_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if settlement != (binding.reservation_digest, binding.parent_budget_lease_ref, _settlement_binding(_actual(gate), True)):
        raise ValueError("offline historical exact usage and durable revocation settlement differ")
    event = db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*binding.namespace.as_tuple, binding.activity_id, _event_id(binding))).fetchone()
    if event is None:
        raise ValueError("offline historical accounting Graph event is absent")
    receipt = GraphReceipt("committed", GraphStore._version_rows(event[0]), GraphStore._version_rows(event[1]),
        NamespaceEpoch(*binding.namespace.as_tuple, event[2]))
    versions = {row.key.token: row.revision for row in receipt.revisions}
    if (canonical_digest(receipt) != result["graph_receipt_digest"]
            or versions != {row["ref"]: row["revision"] for row in result["write_commitments"]}):
        raise ValueError("offline historical actual Graph receipt differs")
    ids = offline_tick_ids_v1(binding.namespace, binding.schedule_ref, binding.scheduled_at_utc)
    cost_ref = runtime_cost_settlement_key(*binding.namespace.as_tuple, binding.activity_id, ids["reservation"]).token
    job_ref = runtime_job_key(*binding.namespace.as_tuple, binding.activity_id, binding.job_id).token
    expected_members = {cost_ref} if result["job_disposition"] == "changed_worker_requires_reconciliation" else {cost_ref, job_ref}
    if set(versions) != expected_members or result["cost_ref"] != cost_ref:
        raise ValueError("offline historical accounting contains another cost/job/Source member")
    cost_value, job_value, job_previous = None, None, None
    for row in result["write_commitments"]:
        history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (row["ref"], row["revision"])).fetchone()
        if history is None or history[0] != _event_id(binding) or history[2] != 1 or canonical_digest(json.loads(history[1])) != row["digest"]:
            raise ValueError("offline historical cost/job atomic write commitment differs")
        if row["ref"] == result["cost_ref"]:
            cost_value = json.loads(history[1])
            _decode_json(history[1], RuntimeCostSettlement)
        else:
            job_value = _decode_json(history[1], RuntimeJobValue)
            previous = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
                (row["ref"], row["revision"] - 1)).fetchone()
            if previous is None or previous[1] != 1 or canonical_digest(json.loads(previous[0])) != result["job_observed_digest"]:
                raise ValueError("offline historical job is not the exact observed previous projection")
            job_previous = _decode_json(previous[0], RuntimeJobValue)
    if (cost_value is None or canonical_digest(cost_value) != result["cost_digest"]
            or cost_value["actual"] != _actual(gate) or cost_value["execution_revoked"] is not True
            or cost_value["status"] != result["cost_status"]
            or cost_value["unconfirmed"] != ({"thread_cpu_ms": binding.cpu_ceiling_ms} if gate.status == "unknown" else {})):
        raise ValueError("offline historical full actual cost or retained unknown ceiling differs")
    budget_row = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='settle'", (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    budget_receipt = _decode_json(budget_row[0], BudgetReceipt)
    expected_status = ("pending_confirmation" if gate.status == "unknown" else
        "overrun" if gate.actual_cpu_ms > binding.cpu_ceiling_ms else "settled")
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    if ((budget_receipt.operation_id, budget_receipt.digest, budget_receipt.lease_id, budget_receipt.status) !=
            (binding.reservation_operation_id, binding.reservation_digest, binding.parent_budget_lease_ref, expected_status)
            or (lease.bot_id, lease.persona_id) != binding.namespace.as_tuple):
        raise ValueError("offline historical exact original budget receipt differs")
    expected_cost = RuntimeCostSettlement(*binding.namespace.as_tuple, binding.activity_id,
        historical_accounting_operation_id_v1(binding), None, ids["reservation"], binding.parent_budget_lease_ref,
        lease.currency, binding.reservation_operation_id, expected_status, {"thread_cpu_ms": binding.cpu_ceiling_ms},
        _actual(gate), {"thread_cpu_ms": binding.cpu_ceiling_ms} if gate.status == "unknown" else {},
        "settle", binding.reservation_operation_id, hashlib.sha256(budget_row[0].encode("utf-8")).hexdigest(), None, True)
    if cost_value != plain_v1(expected_cost):
        raise ValueError("offline historical cost key and full reservation/receipt identity differ")
    if job_value is not None:
        if ((job_previous.operation_id, job_previous.activity_id, job_previous.bot_id, job_previous.persona_id,
                job_previous.effect_id, job_previous.job_id, job_previous.work_kind, job_previous.parent_budget_lease_ref,
                job_previous.resource_ref, job_previous.fence, job_previous.lease_holder, job_previous.cancel_epoch,
                job_previous.snapshot_ref, job_previous.deadline_utc) !=
                (binding.operation_id, binding.activity_id, *binding.namespace.as_tuple, None, binding.job_id, WORK_KIND,
                binding.parent_budget_lease_ref, ALGORITHM_ID, binding.job_fence, binding.job_holder, binding.job_cancel_epoch,
                "offline-tick-input:" + binding.input_digest[:48], binding.deadline_utc)
                or job_previous.phase not in {"running", "draining"}
                or job_value.phase != result["job_disposition"]
                or result["job_disposition"] != ("pending_confirmation" if gate.status == "unknown" else "failed")
                or job_value.lease_holder is not None or job_value.lease_expires_utc is not None
                or job_value.result_ref is not None or job_value.wake_condition_digest is not None
                or any(getattr(job_value, name) != getattr(job_previous, name) for name in
                    ("bot_id", "persona_id", "activity_id", "operation_id", "effect_id", "job_id", "snapshot_ref", "work_kind",
                     "continuation_digest", "deadline_utc", "parent_budget_lease_ref", "resource_ref",
                     "operator_versions_digest", "fence", "cancel_epoch"))):
            raise ValueError("offline historical job closure changed the original worker/business identity")
    if require_current_anchor:
        from ..runtime_contracts import SnapshotRequirementsV2
        from ..authority_service.d11_offline_tick_bridge_v1 import _requirements_match
        metadata = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
            binding.namespace.as_tuple).fetchone()
        if metadata is None or not _requirements_match(_decode_json(metadata[0], SnapshotRequirementsV2), gate.permit.pinned_anchor):
            raise ValueError("offline historical Graph did not reach its actual accounting anchor")
    return result


def reconcile_historical_offline_tick_cost_v1(graph, bootstrap, *, binding):
    from ..host.v2_fence_port import V2FencePort
    from .d11_offline_adoption_v1 import _read_signed as read_adoption_original
    graph._admin(bootstrap)
    port, store = graph._GraphCoordinator__content_fence_v2, graph._GraphCoordinator__store
    issuer, resources = graph._GraphCoordinator__d11_issuer, graph._GraphCoordinator__d02_issuer
    if type(port) is not V2FencePort:
        raise TypeError("offline historical accounting needs its actual installed paired port")
    with store._lock:
        prepared = read_offline_accounting_prepared_v1(store._db, binding=binding, issuer=issuer, resource_issuer=resources)
        saved = _read_signed(store._db, binding, "historical_accounting_receipt", issuer)
        saved_gate = _read_signed(store._db, binding, "historical_accounting_gate", issuer)
        adopted = read_adoption_original(store._db, binding.namespace, "adoption_receipt", binding.execution_id, issuer)
        if saved is not None:
            if saved_gate is None:
                raise ValueError("offline historical composite gate is absent")
            gate = historical_accounting_from_wire_v1(saved_gate)
            result = verify_offline_historical_accounting_commit_v1(store._db, gate=gate, issuer=issuer, resource_issuer=resources)
        else:
            result = None
    if adopted is not None:
        if saved is not None:
            raise ValueError("offline adoption and historical not-adopted closure conflict")
        return graph.adopt_current_offline_tick_v1(bootstrap, namespace=binding.namespace,
            prepared_original_ref=binding.prepared_original_ref)
    if result is not None:
        port.offline_tick_historical_accounting_v1(binding=binding, action="finish", gate=gate)
        return result
    if prepared is None or saved_gate is not None:
        raise ValueError("offline historical accounting requires its atomic original preparation")
    gate = port.offline_tick_historical_accounting_v1(binding=binding, action="begin")
    if (type(gate) is not D11OfflineHistoricalCostGrantV1 or gate.binding != binding
            or gate.accounting_original_digest != canonical_digest(plain_v1(prepared))):
        raise ValueError("offline historical installed original differs")
    port.offline_tick_historical_accounting_v1(binding=binding, action="validate", gate=gate)
    anchor = gate.permit.pinned_anchor
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            current = read_offline_accounting_prepared_v1(db, binding=binding, issuer=issuer, resource_issuer=resources)
            if current != prepared:
                raise ValueError("offline historical signed accounting preparation changed")
            metadata, epoch = graph._v2_graph_stamp(binding.namespace)
            if not graph._accounting_anchor_covers(metadata.requirements, anchor):
                raise ValueError("offline historical current ledger does not cover retained facts")
            if read_adoption_original(db, binding.namespace, "adoption_receipt", binding.execution_id, issuer) is not None:
                raise ValueError("offline actual adoption already committed")
            cost, writes, disposition, observed = _stage_cost_and_job(db, gate)
            reads = tuple(GraphVersion(write.key, (db.execute("SELECT revision FROM graph_atoms WHERE token=?",
                (write.key.token,)).fetchone() or (0,))[0]) for write in writes)
            for write in writes:
                reconcile_runtime_write(db, write)
            candidate = GraphCandidate(Event(Scope(*binding.namespace.as_tuple, binding.activity_id), _event_id(binding),
                time.time(), "d11.historical-offline-cpu.v1", {"terminal_digest": gate.terminal_digest}), reads, writes, (epoch,))
            receipt = GraphStore._graph_commit_in_transaction(store, candidate, _capability=graph._GraphCoordinator__graph_capability)
            if receipt.status != "committed":
                raise ValueError("offline historical accounting event changed")
            replacement = replace(metadata.requirements, deletion_seq=anchor.deletion_seq, deletion_digest=anchor.deletion_digest,
                execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest, revocation_epoch=anchor.revocation_epoch)
            store.cas_graph_recovery_metadata(metadata, replacement, _capability=graph._GraphCoordinator__graph_capability)
            versions = {version.key: version.revision for version in receipt.revisions}
            result = {"schema": "d11.offline-historical-cost-receipt.v1",
                "operation_id": historical_accounting_operation_id_v1(binding), "binding_digest": binding.digest,
                "accounting_original_digest": gate.accounting_original_digest, "prepared_digest": gate.prepared_digest,
                "claim_digest": gate.claim_digest, "terminal_digest": gate.terminal_digest, "gate_digest": gate.digest,
                "durable_closure_digest": gate.durable_closure_digest, "status": gate.status, "actual_cpu_ms": gate.actual_cpu_ms,
                "cost_status": cost.status, "cost_ref": writes[0].key.token, "cost_digest": canonical_digest(writes[0].value),
                "job_disposition": disposition, "job_observed_digest": observed, "adoption_status": "not_adopted",
                "event_id": _event_id(binding), "graph_receipt_digest": canonical_digest(receipt),
                "write_commitments": [{"ref": write.key.token, "revision": versions[write.key],
                    "digest": canonical_digest(write.value)} for write in writes]}
            historical_accounting_receipt_from_wire_v1(result)
            _record_signed(db, binding, "historical_accounting_gate", historical_accounting_to_wire_v1(gate), issuer)
            _record_signed(db, binding, "historical_accounting_receipt", result, issuer)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    port.offline_tick_historical_accounting_v1(binding=binding, action="finish", gate=gate)
    return result
