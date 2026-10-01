"""W01-owned C04 historical accounting in the shared business transaction."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json

from ..authority_service.internal_accounting_v1 import HistoricalInternalCostEvidenceV1
from ..domains.d02 import BodyDomain, BodyReservation, BodyState
from ..domains.d02.c04_fixed_component_cost import (
    C04BodyCostOriginalV1, install_d02_c04_body_cost_schema, read_c04_body_cost_original_v1,
)
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .budget import get_budget_lease, settle_budget
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_product_lifecycle_v3 import read_original_c04_product_job_v3
from .d11_c04_internal_cost import (
    C04CpuCostOriginalV1, C04CostHold, install_d11_c04_cost_schema, read_c04_cpu_cost_original_v1,
)
from .d11_types import cost_settlement_from_runtime, cost_settlement_graph_write, job_graph_write
from .jobs import _save_job


@dataclass(frozen=True, slots=True)
class HistoricalC04CostStageV1:
    cpu: C04CpuCostOriginalV1
    writes: tuple
    reads: tuple
    body_original: C04BodyCostOriginalV1 | None
    body_gap: str | None


def install_c04_historical_schema_v1(db):
    install_d11_c04_cost_schema(db)
    install_d02_c04_body_cost_schema(db)
    db.execute("""CREATE TABLE IF NOT EXISTS graph_c04_historical_accounting_v1 (
        bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,
        binding_digest TEXT NOT NULL,attempt_id TEXT NOT NULL,request_json TEXT NOT NULL,
        receipt_json TEXT,PRIMARY KEY(bot,persona,operation_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_c04_historical_job_closures_v1 (
        bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,
        original_json TEXT NOT NULL,original_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id))""")
    for op in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_c04_historical_job_closures_v1_{op.lower()}
            BEFORE {op} ON graph_c04_historical_job_closures_v1
            BEGIN SELECT RAISE(ABORT,'historical closure is immutable'); END""")


def install_c04_adoption_provenance_schema_v3(db):
    db.execute("""CREATE TABLE IF NOT EXISTS graph_c04_adoption_provenance_v3 (
        bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,
        original_json TEXT NOT NULL,original_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id))""")
    for op in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_c04_adoption_provenance_v3_{op.lower()}
            BEFORE {op} ON graph_c04_adoption_provenance_v3
            BEGIN SELECT RAISE(ABORT,'C04 adopted provenance is immutable'); END""")


def _body_lineage(db, token, start_revision, current_revision, kind):
    rows = db.execute("SELECT revision,value,valid FROM graph_history WHERE token=? "
                      "AND revision>=? AND revision<=? ORDER BY revision",
                      (token, start_revision, current_revision)).fetchall()
    if tuple(row[0] for row in rows) != tuple(range(start_revision, current_revision + 1)):
        raise C04CostHold("original body accounting ancestry is incomplete")
    values = tuple(kind(**json.loads(row[1])) for row in rows if row[2] == 1)
    if len(values) != len(rows):
        raise C04CostHold("body accounting ancestry includes an invalidated head")
    if kind is BodyState:
        if len({v.profile_id for v in values}) != 1 or any(v.version != row[0] for v, row in zip(values, rows, strict=True)):
            raise C04CostHold("body state lineage changed its identity")
    elif len({(v.reservation_id, v.quote_id, v.effect_id, v.reserved_cost) for v in values}) != 1:
        raise C04CostHold("body reservation lineage changed its original identity")
    return values


def stage_historical_c04_cost_in_transaction_v1(db, namespace, evidence, *, resource_issuer, body_authority):
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(evidence) is not HistoricalInternalCostEvidenceV1):
        raise C04CostHold("installed historical accounting transaction required")
    binding, operation_id = evidence.binding, evidence.binding.operation_id
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    if prepared is None or prepared.binding != binding:
        raise C04CostHold("original C04 preparation differs")
    quote = resource_issuer.original_signed_quote(db, binding.resource_quote_ref, binding.resource_quote_version)
    if (canonical_digest(quote) != binding.resource_quote_digest
            or quote.work_kind != "d06.c04_internal_cpu.v1"
            or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref
            or (quote.bot_id, quote.persona_id, quote.operation_id, quote.activity_id) !=
               (*namespace.as_tuple, operation_id, binding.activity_id)
            or set(quote.ceiling) != {"cpu_ms"}
            or prepared.budget_reservation_operation_id != "c04-internal-budget:" + binding.binding_digest):
        raise C04CostHold("historical signed CPU quote differs")
    reserve = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, prepared.budget_reservation_operation_id)).fetchone()
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    reservation = db.execute("SELECT digest,ceiling_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, prepared.budget_reservation_operation_id)).fetchone()
    if (reserve is None or reserve[:2] != (binding.binding_digest, lease.lease_id)
            or hashlib.sha256(reserve[2].encode()).hexdigest() != prepared.budget_reservation_digest
            or reservation is None or reservation[0] != binding.binding_digest
            or json.loads(reservation[1]) != dict(quote.ceiling)
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple):
        raise C04CostHold("original C04 reserve identity differs")
    receipt = settle_budget(db, lease.lease_id, prepared.budget_reservation_operation_id,
        binding.binding_digest, {"cpu_ms": evidence.actual_cpu_ms}, execution_revoked=True)
    if receipt.status not in {"settled", "overrun"}:
        raise C04CostHold("original measured CPU remains unaccounted")
    cpu = C04CpuCostOriginalV1(namespace, operation_id, binding.binding_digest,
        prepared.prepared_digest, evidence.proof_digest, evidence.terminal_receipt_ref,
        evidence.terminal_receipt_digest, evidence.status, evidence.actual_cpu_ms, lease.lease_id,
        prepared.budget_reservation_operation_id, prepared.budget_reservation_digest,
        receipt.status, evidence.component_completed)
    prior = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
    if prior is not None and prior != cpu:
        raise C04CostHold("historical CPU original conflicts")
    if prior is None:
        db.execute("INSERT INTO d11_c04_cpu_cost_originals_v1 VALUES(?,?,?,?,?)",
            (*namespace.as_tuple, operation_id, canonical_serialize(asdict(cpu)), canonical_digest(asdict(cpu))))
    cost_operation = "c04-historical-cost:" + binding.binding_digest[:48]
    cost = cost_settlement_from_runtime(db, bot_id=namespace.bot_id, persona_id=namespace.persona_id,
        activity_id=binding.activity_id, bundle_operation_id=cost_operation, effect_id=None,
        settlement_id=cost_operation, lease_id=lease.lease_id,
        cost_operation_id=prepared.budget_reservation_operation_id,
        budget_operation_id=prepared.budget_reservation_operation_id, budget_phase="settle",
        prior_unknown_ref=None, execution_revoked=True)
    cost_write = cost_settlement_graph_write(cost)
    writes, reads = [cost_write], [GraphVersion(cost_write.key, 0)]
    body_original = read_c04_body_cost_original_v1(db, namespace, operation_id)
    if body_original is not None:
        if body_original.binding_digest != binding.binding_digest or body_original.proof_digest != evidence.proof_digest:
            raise C04CostHold("historical body original conflicts")
        return HistoricalC04CostStageV1(cpu, tuple(writes), tuple(reads), body_original, None)
    state_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                          (prepared.body_state_ref, *namespace.as_tuple)).fetchone()
    reservation_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                          (binding.body_reservation_ref, *namespace.as_tuple)).fetchone()
    if state_row is None or reservation_row is None or state_row[2] != 1 or reservation_row[2] != 1:
        return HistoricalC04CostStageV1(cpu, tuple(writes), tuple(reads), None, "target_erased")
    try:
        state = BodyState(**json.loads(state_row[1]))
        reserved = BodyReservation(**json.loads(reservation_row[1]))
        _body_lineage(db, prepared.body_state_ref, prepared.body_state_revision, state_row[0], BodyState)
        _body_lineage(db, binding.body_reservation_ref, prepared.body_reservation_revision, reservation_row[0], BodyReservation)
        body_quote = body_authority.original_body_quote(db, binding.body_quote_ref,
            binding.body_quote_version, quote, operation_id)
        if (canonical_digest(body_quote) != binding.body_quote_digest
                or state.profile_id != body_quote.profile_id or state.version != state_row[0]
                or reserved.quote_id != body_quote.quote_id or reserved.effect_id != quote.effect_id):
            raise C04CostHold("historical body quote or lineage differs")
        components = tuple(c for c in body_quote.components if c.component_id == binding.component_id)
        if len(components) != 1 or components[0].duration_rate != 0:
            raise C04CostHold("historical fixed body component differs")
        if evidence.component_completed:
            settled = BodyDomain().settle_component(state, reserved, binding.component_id,
                actual_cost=components[0].fixed_cost, component_receipt=evidence.component_receipt_ref)
            if settled.duplicate or settled.overrun or settled.unpaid_cost:
                raise C04CostHold("historical body charge requires reconciliation")
            settlement_key = AtomKey.from_token(quote.d02_settlement_refs[0])
            body_writes = (BodyDomain.state_write(namespace, settled.state),
                BodyDomain.reservation_write(namespace, binding.activity_id, settled.reservation),
                BodyDomain.settlement_write(namespace, binding.activity_id, settlement_key.name, settled))
            if len(quote.d02_settlement_refs) != 1 or body_writes[-1].key != settlement_key:
                raise C04CostHold("historical body settlement reference differs")
            body_original = C04BodyCostOriginalV1(namespace, operation_id, binding.binding_digest,
                evidence.proof_digest, prepared.body_state_ref, binding.body_reservation_ref,
                settlement_key.token, evidence.component_receipt_ref, components[0].fixed_cost,
                canonical_digest(body_writes), "internal-work-outcome:" + binding.execution_id)
        else:
            # The installed signed failed terminal proves this fixed component
            # did not complete. It releases occupancy, without a body charge.
            cancellation = BodyDomain.release_or_cancel(reserved, execution_known=True)
            body_writes = (BodyDomain.reservation_write(namespace, binding.activity_id, cancellation.reservation),)
        for write in body_writes:
            row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
            reads.append(GraphVersion(write.key, row[0] if row else 0))
        writes.extend(body_writes)
        return HistoricalC04CostStageV1(cpu, tuple(writes), tuple(reads), body_original, None)
    except (C04CostHold, TypeError, ValueError) as exc:
        return HistoricalC04CostStageV1(cpu, tuple(writes), tuple(reads), None,
                                       "unpaid_requires_reconciliation:" + type(exc).__name__)


def record_historical_c04_body_after_cas_v1(db, stage):
    if not db.in_transaction:
        raise C04CostHold("historical body original requires same graph CAS")
    original = stage.body_original
    if original is None:
        return None
    prior = read_c04_body_cost_original_v1(db, original.namespace, original.operation_id)
    if prior is not None:
        if prior != original:
            raise C04CostHold("historical body original replay conflicts")
        return prior
    for write in stage.writes:
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is None or row[1] != 1 or json.loads(row[0]) != write.value:
            raise C04CostHold("historical body graph CAS missing")
    db.execute("INSERT INTO d02_c04_body_cost_originals_v1 VALUES(?,?,?,?,?)",
        (*original.namespace.as_tuple, original.operation_id, canonical_serialize(asdict(original)), canonical_digest(asdict(original))))
    return original


def close_historical_c04_job_in_transaction_v1(db, namespace, prepared, evidence, *, body_gap, generation):
    """Close the exact original job; acquisition and deadline are untouched."""
    job = read_original_c04_product_job_v3(db, namespace, prepared)
    prior = db.execute("SELECT original_json,original_digest FROM graph_c04_historical_job_closures_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, prepared.binding.operation_id)).fetchone()
    if prior is not None:
        raw = json.loads(prior[0])
        if canonical_digest(raw) != prior[1] or raw["evidence_digest"] != evidence.digest:
            raise C04CostHold("historical job closure replay conflicts")
        return raw, ()
    if job.phase == "completed" and job.continuation.get("product_status") == "adopted":
        return {"status": "adopted_original_retained", "job_id": job.job_id}, ()
    usage = dict(job.usage)
    anomaly = usage.get("cpu_ms", 0) > evidence.actual_cpu_ms
    usage["cpu_ms"] = max(usage.get("cpu_ms", 0), evidence.actual_cpu_ms)
    original = {"schema": "c04.historical-job-closure.v1", "namespace": asdict(namespace),
        "job_id": job.job_id, "operation_id": prepared.binding.operation_id,
        "prepared_digest": prepared.prepared_digest, "binding_digest": prepared.binding.binding_digest,
        "evidence_digest": evidence.digest, "original_generation": prepared.binding.activation_generation,
        "reconciliation_generation": generation, "original_job_digest": canonical_digest(asdict(job)),
        "execution": evidence.status, "adoption": "not_adopted", "body_gap": body_gap,
        "actual_cpu_ms": evidence.actual_cpu_ms, "usage_anomaly": anomaly,
        "previous_phase": job.phase, "previous_fence": job.fence, "cancel_epoch": job.cancel_epoch}
    digest = canonical_digest(original)
    continuation = {**job.continuation, "historical_closure_digest": digest, "product_status": "not_adopted"}
    closed = replace(job, phase="cancelled" if job.phase == "cancelled" else "failed",
        lease_holder=None, lease_expires_utc=None, fence=job.fence + 1,
        continuation=continuation, usage=usage, result_ref="c04-historical-closure:" + digest[:48], wake_condition=None)
    if read_original_c04_product_job_v3(db, namespace, prepared) != job:
        raise C04CostHold("historical job changed before closure CAS")
    _save_job(db, closed)
    db.execute("INSERT INTO graph_c04_historical_job_closures_v1 VALUES(?,?,?,?,?)",
        (*namespace.as_tuple, prepared.binding.operation_id, canonical_serialize(original), digest))
    return original, (job_graph_write(closed),)
