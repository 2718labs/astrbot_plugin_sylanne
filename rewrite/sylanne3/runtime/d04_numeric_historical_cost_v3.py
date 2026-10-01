"""Historical actual CPU accounting without source, clock or worker admission."""
from __future__ import annotations
from dataclasses import asdict, replace
import json
import time
from ..contracts import Event, Scope
from ..graph_store import GraphStore
from ..graph_types import GraphCandidate, GraphVersion
from ..runtime_contracts import canonical_digest, canonical_serialize
from .budget import get_budget_lease, settle_budget
from .d04_appraisal_driver_v3 import read_d04_original_v3, record_d04_original_in_transaction_v3
from .d04_numeric_accounting_prepared_v3 import read_numeric_accounting_prepared_v3
from .d04_numeric_cost_v3 import D04NumericCostOriginalV3, numeric_cost_operation_v3, read_d04_numeric_cost_original_v3
from .d11_types import cost_settlement_from_runtime, cost_settlement_graph_write, job_graph_write, reconcile_runtime_write
from .jobs import get_job, _save_job


def _stage_historical_cpu_v3(db, prepared, original, issuer):
    from ..authority_service.d04_numeric_contract_v3 import D04NumericTerminalV3, D04NumericMeasuredCostClosureV3
    if (not db.in_transaction or type(original) not in {D04NumericTerminalV3, D04NumericMeasuredCostClosureV3}
            or original.binding != prepared.binding):
        raise ValueError("D04 historical CPU requires its independent exact measured original")
    binding, measurement = prepared.binding, original.measurement
    prior = read_d04_numeric_cost_original_v3(db, binding.namespace, binding.operation_id)
    if prior is not None:
        if prior.terminal_digest != original.digest or prior.actual_cpu_ns != measurement.actual_cpu_ns:
            raise ValueError("D04 historical CPU conflicts with its settled original")
        return prior, (), None
    quote = issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    if (canonical_digest(quote) != binding.quote_digest or canonical_serialize(quote) != prepared.quote_payload_json
            or quote.work_kind != "d04.joint_numeric_cpu.v3" or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref
            or quote.operation_id != binding.operation_id or quote.activity_id != binding.activity_id
            or (quote.bot_id, quote.persona_id) != binding.namespace.as_tuple
            or dict(quote.ceiling) != {"cpu_ms": binding.cpu_ceiling_ms}):
        raise ValueError("D04 historical CPU signed quote identity differs")
    reserve = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='reserve'", (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    if (reserve != (binding.reservation_digest, lease.lease_id, prepared.reserve_receipt_json)
            or (lease.bot_id, lease.persona_id) != binding.namespace.as_tuple):
        raise ValueError("D04 historical original CPU reservation differs")
    settled = settle_budget(db, lease.lease_id, binding.reservation_operation_id, binding.reservation_digest,
        {"cpu_ms": measurement.actual_cpu_ms}, execution_revoked=True)
    if settled.status not in {"settled", "overrun"}:
        raise ValueError("D04 measured actual CPU remains unresolved")
    cost_operation = numeric_cost_operation_v3(binding.namespace, binding.operation_id)
    event_id = "d04-numeric-historical:" + canonical_digest((binding.namespace, binding.operation_id))[:48]
    cost = cost_settlement_from_runtime(db, bot_id=binding.namespace.bot_id, persona_id=binding.namespace.persona_id,
        activity_id=binding.activity_id, bundle_operation_id=event_id, effect_id=None, settlement_id=cost_operation,
        lease_id=lease.lease_id, cost_operation_id=binding.reservation_operation_id,
        budget_operation_id=binding.reservation_operation_id, budget_phase="settle", prior_unknown_ref=None, execution_revoked=True)
    cost_write = cost_settlement_graph_write(cost)
    writes = [cost_write]
    identity = json.loads(prepared.job_identity_json)
    job = get_job(db, binding.job_id)
    stable = (job.job_id, job.operation_id, job.activity_id, job.bot_id, job.persona_id, job.work_kind, job.budget_ref, job.resource_ref)
    expected = tuple(identity[name] for name in ("job_id", "operation_id", "activity_id", "bot_id", "persona_id", "work_kind", "budget_ref", "resource_ref"))
    if stable != expected:
        raise ValueError("D04 historical original job identity differs")
    closure = {"schema": "d04.numeric-execution-closure.v3", "operation_id": binding.operation_id,
        "binding_digest": binding.digest, "terminal_digest": original.digest,
        "execution_status": measurement.status, "adoption_status": "not_adopted",
        "actual_cpu_ns": measurement.actual_cpu_ns, "actual_cpu_ms": measurement.actual_cpu_ms,
        "job_status": "changed_worker_requires_reconciliation"}
    if job.fence == identity["fence"] and job.phase in {"queued", "running", "draining"}:
        # Historical closure consumes no worker permission. It may end only
        # this exact old execution after independent terminal authentication.
        final = replace(job, phase="cancelled" if job.cancel_epoch else "failed", lease_holder=None,
            lease_expires_utc=None, result_ref="d04-numeric-not-adopted:" + binding.digest[:40],
            usage={**dict(job.usage), "cpu_ms": max(job.usage.get("cpu_ms", 0), measurement.actual_cpu_ms)})
        _save_job(db, final)
        writes.append(job_graph_write(final))
        closure["job_status"] = final.phase
    elif job.phase in {"failed", "cancelled"}:
        closure["job_status"] = job.phase
    value = D04NumericCostOriginalV3(binding.namespace, binding.operation_id, prepared.prepared_digest,
        binding.digest, original.terminal_ref, original.digest, measurement.status, measurement.actual_cpu_ns,
        measurement.actual_cpu_ms, canonical_serialize(asdict(settled)), canonical_serialize(asdict(cost_write)))
    record_d04_original_in_transaction_v3(db, binding.namespace, "numeric_cost", binding.operation_id, asdict(value))
    record_d04_original_in_transaction_v3(db, binding.namespace, "numeric_execution_closure", binding.operation_id, closure)
    return value, tuple(writes), closure


def reconcile_historical_d04_numeric_cost_v3(graph, bootstrap, bundle, *, operation_id):
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from ..authority_service.d04_numeric_accounting_v3 import numeric_accounting_to_wire_v3, numeric_accounting_from_wire_v3, D04NumericHistoricalCostGrantV3
    graph._admin(bootstrap)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3
    namespace = bundle.installation_policy.namespace
    if type(port) is not InstalledC04AuthorityPortV3 or port._bundle is not bundle:
        raise ValueError("D04 historical CPU needs its installed accounting port")
    with store._lock:
        prepared = read_numeric_accounting_prepared_v3(store._db, namespace, operation_id,
            issuer=graph._GraphCoordinator__d02_issuer)
        completed = read_d04_original_v3(store._db, namespace, "numeric_historical_cost", operation_id)
        saved = read_d04_original_v3(store._db, namespace, "numeric_accounting_gate", operation_id)
        adopted = read_d04_original_v3(store._db, namespace, "numeric_adoption", operation_id)
    if prepared is None:
        raise ValueError("D04 content-free original accounting identity is absent")
    binding = prepared.binding
    if adopted is not None:
        # A lost final finish ACK must recover the actual adopted result;
        # it cannot create a later contradictory not-adopted accounting fact.
        return graph.adopt_post_c02_joint_numeric_v3(bootstrap, bundle, operation_id=operation_id)
    if completed is not None:
        gate = numeric_accounting_from_wire_v3(saved[0])
        port.numeric_accounting(binding, "recover_finish", gate)
        return completed[0]
    gate = port.numeric_accounting(binding, "begin")
    if type(gate) is not D04NumericHistoricalCostGrantV3 or gate.original.binding != binding:
        raise ValueError("D04 historical actual terminal original differs")
    port.numeric_accounting(binding, "validate", gate)
    anchor = gate.permit.pinned_anchor
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            metadata, epoch = graph._v2_graph_stamp(namespace)
            if not graph._accounting_anchor_covers(metadata.requirements, anchor):
                raise ValueError("D04 historical current ledger does not cover retained business facts")
            record_d04_original_in_transaction_v3(db, namespace, "numeric_accounting_gate", operation_id, numeric_accounting_to_wire_v3(gate))
            cost, writes, closure = _stage_historical_cpu_v3(db, prepared, gate.original, graph._GraphCoordinator__d02_issuer)
            if not writes:
                raise ValueError("D04 paid CPU original lacks its unique adoption/accounting closure")
            event_id = "d04-numeric-historical:" + canonical_digest((namespace, operation_id))[:48]
            reads = tuple(GraphVersion(write.key, (db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone() or (0,))[0])
                for write in writes)
            for write in writes:
                reconcile_runtime_write(db, write)
            candidate = GraphCandidate(Event(Scope(*namespace.as_tuple, binding.activity_id), event_id, time.time(),
                "d04.historical-actual-cpu.v3", {"terminal_digest": gate.original.digest}), reads, writes, (epoch,))
            receipt = GraphStore._graph_commit_in_transaction(store, candidate, _capability=graph._GraphCoordinator__graph_capability)
            if receipt.status != "committed":
                raise ValueError("D04 historical accounting event changed")
            replacement = replace(metadata.requirements, deletion_seq=anchor.deletion_seq, deletion_digest=anchor.deletion_digest,
                execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest, revocation_epoch=anchor.revocation_epoch)
            store.cas_graph_recovery_metadata(metadata, replacement, _capability=graph._GraphCoordinator__graph_capability)
            result = {"schema": "d04.numeric-historical-cost-receipt.v3", "status": "actual_cpu_accounted",
                "operation_id": operation_id, "binding_digest": binding.digest, "terminal_digest": gate.original.digest,
                "cost_original_digest": cost.digest, "event_id": event_id, "graph_receipt_digest": canonical_digest(receipt),
                "adoption_status": "not_adopted", "job_closure": closure,
                "actual_cpu_ns": gate.original.measurement.actual_cpu_ns, "actual_cpu_ms": gate.original.measurement.actual_cpu_ms}
            record_d04_original_in_transaction_v3(db, namespace, "numeric_historical_cost", operation_id, result)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    port.numeric_accounting(binding, "finish", gate)
    return result
