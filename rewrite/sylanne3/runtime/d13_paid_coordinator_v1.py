"""D13 paid lifecycle transaction bodies for the sole W01 Graph writer.

Every mutation requires the caller's fenced SQLite transaction. Network reads
and the single model dispatch remain outside that transaction. Recovery uses
the saved original call and result read, never a replacement worker/call ID.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime
from hashlib import sha256
import json
import sqlite3

from ..authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from ..authority_service.v2_model_egress_wire import from_wire, to_wire
from ..authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadV1, from_wire as read_from_wire,
    to_wire as read_to_wire,
)
from ..domains.d13.precompression import (
    accept_verified_model_candidate_v2, compile_extractive_model_output,
)
from ..domains.d13.provider import block_graph_value
from ..graph_types import AtomKey, GraphWrite, Owner
from ..model_broker.d13_precompression import (
    D13PrecompressionInstallationV1, FrozenD13PrecompressionRequestV1,
    parse_d13_precompression_output_v1,
)
from ..runtime_contracts import (
    CompressedTurnBlockV2, ConversationWindowProjectionV1, NamespaceId,
    canonical_digest, canonical_serialize,
)
from .budget import BudgetReceipt, reserve_budget
from .d11_types import job_graph_write
from .d13_paid_intent_original_v1 import (
    D13PaidCallOriginalV1, D13PaidIntentOriginalV1, PAID_WORK_KIND,
    load_d13_paid_intent_original_v1, read_current_d13_paid_intent_original_v1,
    read_d13_paid_call_original_v1, record_d13_paid_intent_original_v1,
)
from .d13_precompression_job import (
    D13PaidPrecompressionIntentV1, issue_paid_precompression_quote_v1,
)
from .jobs import (
    PersistentJob, acquire_job, checkpoint_job, create_job, get_job, transition_job,
)
from .model_cost_settlement import (
    OriginalModelCostFactV1, apply_original_model_budget_in_transaction,
    prepare_original_model_cost_plan,
)


def install_d13_paid_coordinator_schema_v1(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d13_paid_schedule_inputs_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, job_ref TEXT NOT NULL,
        scene_ref TEXT NOT NULL, payload_json TEXT NOT NULL,
        payload_digest TEXT NOT NULL, pending INTEGER NOT NULL DEFAULT 1 CHECK(pending IN (0,1)),
        PRIMARY KEY(bot,persona,job_ref))""")
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS graph_d13_paid_one_schedule_scene_v1
        ON graph_d13_paid_schedule_inputs_v1(bot,persona,scene_ref) WHERE pending=1""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d13_paid_schedule_input_no_change_v1
        BEFORE UPDATE OF payload_json,payload_digest,scene_ref,job_ref,bot,persona
        ON graph_d13_paid_schedule_inputs_v1
        BEGIN SELECT RAISE(ABORT, 'D13 paid schedule input is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d13_paid_schedule_input_no_delete_v1
        BEFORE DELETE ON graph_d13_paid_schedule_inputs_v1
        BEGIN SELECT RAISE(ABORT, 'D13 paid schedule input is immutable'); END""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d13_paid_scene_jobs_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, scene_ref TEXT NOT NULL,
        input_digest TEXT NOT NULL, job_ref TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('queued','running','standby','active','finished','retired')),
        expires_at_utc REAL NOT NULL,
        PRIMARY KEY(bot,persona,job_ref),
        UNIQUE(bot,persona,scene_ref,input_digest))""")
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS graph_d13_paid_one_pending_scene_v1
        ON graph_d13_paid_scene_jobs_v1(bot,persona,scene_ref)
        WHERE state IN ('queued','running','standby')""")
    for table, extra in (
        ("graph_d13_paid_result_reads_v1", "read_attempt_id TEXT NOT NULL,"),
        ("graph_d13_paid_cost_receipts_v1", ""),
    ):
        db.execute(f"""CREATE TABLE IF NOT EXISTS {table} (
            bot TEXT NOT NULL, persona TEXT NOT NULL, job_ref TEXT NOT NULL,
            {extra} payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,job_ref))""")
        for action in ("UPDATE", "DELETE"):
            db.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()}
                BEFORE {action} ON {table}
                BEGIN SELECT RAISE(ABORT, 'D13 paid lifecycle original is immutable'); END""")


def _transaction(db):
    if not db.in_transaction:
        raise ValueError("D13 paid lifecycle needs caller-owned fenced transaction")


def _live_job(db, original, call, *, holder, fence, now_utc):
    _transaction(db)
    job = get_job(db, original.binding.job_ref)
    if (job.work_kind != PAID_WORK_KIND or
            (job.bot_id, job.persona_id) != original.namespace.as_tuple or
            job.operation_id != original.binding.original_operation_id or
            job.phase != "running" or job.cancel_epoch != 0 or
            job.lease_holder != holder or job.fence != fence or
            call.worker_fence != fence or job.lease_expires_utc is None or
            now_utc >= min(original.binding.expires_at_utc,
                datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())):
        raise ValueError("original D13 paid worker is no longer current")
    stored = read_d13_paid_call_original_v1(db, original.namespace, job.job_id)
    if stored is None or stored[0] != call:
        raise ValueError("D13 paid call original changed")
    return job


@dataclass(frozen=True, slots=True)
class D13PaidScheduleReceiptV1:
    original: D13PaidIntentOriginalV1
    budget: BudgetReceipt
    job: PersistentJob


@dataclass(frozen=True, slots=True)
class D13PaidReadEvidenceV1:
    original_digest: str
    call_original_digest: str
    read: WorkerModelResultReadV1
    fact: OriginalModelCostFactV1
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class D13PaidSettlementV1:
    evidence_digest: str
    receipt: BudgetReceipt
    cost_write: GraphWrite


@dataclass(frozen=True, slots=True)
class D13PaidStandbyPreparationV1:
    original: D13PaidIntentOriginalV1
    evidence_digest: str
    settlement: D13PaidSettlementV1
    block: CompressedTurnBlockV2 | None
    reason: str | None
    job: PersistentJob


@dataclass(frozen=True, slots=True)
class D13PaidRecoveryV1:
    original: D13PaidIntentOriginalV1
    frozen: FrozenD13PrecompressionRequestV1
    job: PersistentJob
    call_original: D13PaidCallOriginalV1 | None
    evidence: D13PaidReadEvidenceV1 | None
    settlement: D13PaidSettlementV1 | None
    next_action: str


def paid_d13_scene_ledger_in_transaction_v1(db, namespace, scene_ref, *, now_utc):
    """DB-only scene exclusion and immutable source-version deduplication."""
    _transaction(db)
    rows = db.execute(
        "SELECT job_ref,input_digest,state,expires_at_utc FROM "
        "graph_d13_paid_scene_jobs_v1 WHERE bot=? AND persona=? AND scene_ref=?",
        namespace.as_tuple + (scene_ref,),
    ).fetchall()
    outstanding = False
    for job_ref, _digest, state, expires in rows:
        if state in {"queued", "running"}:
            # Expired unresolved external work remains excluded until recovery.
            outstanding = True
        elif state == "standby":
            job = get_job(db, job_ref)
            token = AtomKey(Owner("persona", *namespace.as_tuple),
                            "d13.compressed_turn_block.v2", job.result_ref).token
            atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",
                              (token,)).fetchone()
            if atom is not None and atom[1] == 1:
                block = json.loads(atom[0])
                if block.get("status") == "active":
                    db.execute("UPDATE graph_d13_paid_scene_jobs_v1 SET state='active' "
                               "WHERE bot=? AND persona=? AND job_ref=?",
                               namespace.as_tuple + (job_ref,))
                elif block.get("status") == "standby" and now_utc < expires:
                    outstanding = True
                else:
                    db.execute("UPDATE graph_d13_paid_scene_jobs_v1 SET state='retired' "
                               "WHERE bot=? AND persona=? AND job_ref=?",
                               namespace.as_tuple + (job_ref,))
            else:
                db.execute("UPDATE graph_d13_paid_scene_jobs_v1 SET state='retired' "
                           "WHERE bot=? AND persona=? AND job_ref=?",
                           namespace.as_tuple + (job_ref,))
    return outstanding, frozenset(row[1] for row in rows)


def schedule_paid_d13_in_transaction_v1(
    db, intent: D13PaidPrecompressionIntentV1,
    current_window: ConversationWindowProjectionV1, *,
    resource_issuer, budget_issuer, valid_until_utc: float,
) -> D13PaidScheduleReceiptV1:
    """Sign, reserve, enqueue and seal one independent original atomically."""
    _transaction(db)
    if type(intent) is not D13PaidPrecompressionIntentV1 or current_window != intent.frozen.window:
        raise ValueError("paid D13 schedule requires original current frozen window")
    ns, job = current_window.namespace, intent.job
    outstanding, attempted = paid_d13_scene_ledger_in_transaction_v1(
        db, ns, intent.plan.scene_ref.ref, now_utc=current_window.trusted_utc)
    other_jobs = db.execute(
        "SELECT continuation_json,phase FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
        "AND work_kind='d13.precompress'", ns.as_tuple).fetchall()
    if any(json.loads(encoded).get("conversation_ref") == current_window.conversation_ref
           and phase in {"queued", "running", "waiting", "deferred"}
           for encoded, phase in other_jobs):
        outstanding = True
    if db.execute("SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? "
                  "AND type_name='d13.compressed_turn_block.v2' AND valid=1 "
                  "AND json_extract(value,'$.conversation_ref')=? "
                  "AND json_extract(value,'$.status')='standby' "
                  "AND json_extract(value,'$.expires_at_utc')>? LIMIT 1",
                  ns.as_tuple + (current_window.conversation_ref,
                                 current_window.trusted_utc)).fetchone() is not None:
        outstanding = True
    if outstanding or intent.plan.input_digest in attempted:
        raise ValueError("D13 scene already has pending work or this source was attempted")
    quote = issue_paid_precompression_quote_v1(
        db, intent, resource_issuer=resource_issuer, budget_issuer=budget_issuer,
        valid_until_utc=valid_until_utc)
    digest = canonical_digest({"schema": "d13.paid-budget-reservation.v1",
                               "intent_digest": intent.intent_digest,
                               "quote_digest": canonical_digest(quote)})
    budget = reserve_budget(db, job.budget_ref, job.operation_id, digest, intent.ceiling)
    # Authority's original reader locates phase='create' by original operation.
    persisted = create_job(db, job, job.operation_id, digest)
    original = record_d13_paid_intent_original_v1(
        db, ns, intent.frozen, intent.binding, intent.exact_count,
        intent.frozen.installation, current_window,
        quote_id=quote.quote_id, quote_version=quote.version,
        budget_operation_id=job.operation_id,
        resource_issuer=resource_issuer, budget_issuer=budget_issuer)
    db.execute("INSERT INTO graph_d13_paid_scene_jobs_v1 "
               "(bot,persona,scene_ref,input_digest,job_ref,state,expires_at_utc) "
               "VALUES(?,?,?,?,?,'queued',?)", ns.as_tuple + (
                   intent.plan.scene_ref.ref, intent.plan.input_digest,
                   job.job_id, intent.plan.expires_at_utc))
    return D13PaidScheduleReceiptV1(original, budget, persisted)


def acquire_paid_d13_in_transaction_v1(
    db, namespace: NamespaceId, job_id: str, holder: str, *,
    now_utc: str, lease_seconds: int,
) -> PersistentJob:
    """Acquire only the first worker; sealed calls must retain their fence."""
    _transaction(db)
    job = get_job(db, job_id)
    if (job.work_kind != PAID_WORK_KIND or
            (job.bot_id, job.persona_id) != namespace.as_tuple or
            load_d13_paid_intent_original_v1(db, namespace, job_id) is None):
        raise ValueError("installed original D13 paid job required")
    if read_d13_paid_call_original_v1(db, namespace, job_id) is not None:
        if job.phase != "running" or job.lease_holder != holder:
            raise ValueError("sealed D13 call may only recover its original worker")
        return job
    if job.phase != "queued" or job.fence != 0 or job.cancel_epoch != 0:
        raise ValueError("D13 acquisition cannot replace an original running fence")
    updated = acquire_job(db, job_id, holder, now_utc=now_utc, lease_seconds=lease_seconds)
    db.execute("UPDATE graph_d13_paid_scene_jobs_v1 SET state='running' "
               "WHERE bot=? AND persona=? AND job_ref=? AND state='queued'",
               namespace.as_tuple + (job_id,))
    if db.execute("SELECT changes()").fetchone() != (1,):
        raise ValueError("D13 paid scene slot no longer queued")
    return updated


def _fact_wire(fact):
    return {name: to_wire(getattr(fact, name))
            for name in ("intent", "recovery", "admission", "receipt")}


def _fact_from_wire(raw):
    return OriginalModelCostFactV1(
        from_wire(raw["intent"], ModelEgressIntentV1),
        from_wire(raw["recovery"], ModelEgressRecoveryV1),
        from_wire(raw["admission"], ModelAdmissionV2),
        from_wire(raw["receipt"], ModelTerminalReceiptV2))


def _evidence_payload(original, call, read, fact):
    return {"schema": "d13.paid_result_read_evidence.v1",
            "original_digest": original.original_digest,
            "call_original_digest": call.original_digest,
            "read": read_to_wire(read), "fact": _fact_wire(fact)}


def record_paid_d13_result_read_in_transaction_v1(
    db, original: D13PaidIntentOriginalV1, call_original: D13PaidCallOriginalV1,
    fact: OriginalModelCostFactV1, read: WorkerModelResultReadV1, *,
    holder: str, fence: int, now_utc: float,
) -> D13PaidReadEvidenceV1:
    """Persist authenticated bytes before settlement removes read qualification.

    The public W01 method must obtain ``read`` and ``fact`` from its installed
    Authority ports; typed caller values are not themselves authorization.
    """
    _live_job(db, original, call_original, holder=holder, fence=fence, now_utc=now_utc)
    if type(read) is not WorkerModelResultReadV1 or type(fact) is not OriginalModelCostFactV1:
        raise TypeError("original Authority read and terminal fact required")
    read.require_original_intent(fact.intent)
    request, observation, intent = read.request, read.observation, fact.intent
    if (request.purpose != "d13_precompress_paid" or
            (request.namespace, request.installation_id, request.job_id,
             request.acquire_operation_id, request.original_operation_id,
             request.call_id, request.binding_digest, request.model_request_digest,
             request.consumer_operation_id) != (
                original.namespace, original.binding.installation_id,
                original.binding.job_ref, original.binding.original_operation_id,
                original.budget_operation_id, original.binding.call_id,
                original.binding.binding_digest, call_original.request_digest,
                "d13-adopt:" + original.binding.binding_digest) or
            intent.request_digest != call_original.request_digest or
            intent.binding_digest != original.binding.binding_digest or
            intent.operation_id != original.binding.original_operation_id or
            intent.acquire_operation_id != original.binding.original_operation_id or
            (intent.provider_id, intent.model_id, intent.provider_config_digest,
             intent.max_output_tokens) != (
                original.binding.provider_id, original.binding.model_id,
                original.binding.provider_config_digest,
                json.loads(original.frozen_json)["installation"]["max_output_tokens"]) or
            dict(intent.budget_ceiling) != original.ceiling or
            intent.budget_reservation_operation_id != original.budget_operation_id or
            intent.worker_fence != call_original.worker_fence or
            intent.subject != holder or
            intent.budget_reservation_digest != original.budget_reservation_digest or
            read.terminal_receipt != fact.receipt or
            fact.recovery.state != "observed" or
            observation.digest != fact.recovery.observation_digest or
            observation.usage != fact.recovery.usage or observation.cost != fact.recovery.cost):
        raise ValueError("D13 paid Authority original result identity differs")
    from ..authority_service.v2_worker_model_result_contract import d13_paid_read_attempt_id_v1
    if not any(request.read_attempt_id == d13_paid_read_attempt_id_v1(
            request.consumer_operation_id, attempt) for attempt in range(1, 65)):
        raise ValueError("D13 paid result read attempt is outside original sequence")
    payload = _evidence_payload(original, call_original, read, fact)
    encoded, digest = canonical_serialize(payload), canonical_digest(payload)
    prior = db.execute("SELECT payload_json,payload_digest FROM "
                       "graph_d13_paid_result_reads_v1 WHERE bot=? AND persona=? AND job_ref=?",
                       original.namespace.as_tuple + (original.binding.job_ref,)).fetchone()
    if prior is not None:
        if prior != (encoded, digest):
            raise ValueError("original D13 result read replay changed")
    else:
        reservation = db.execute("SELECT digest,state FROM runtime_budget_reservations "
                                 "WHERE lease_id=? AND operation_id=?",
                                 (intent.budget_lease_id, original.budget_operation_id)).fetchone()
        if reservation != (original.budget_reservation_digest, "reserved"):
            raise ValueError("D13 result must be read and saved before budget settlement")
        db.execute("INSERT INTO graph_d13_paid_result_reads_v1 "
                   "(bot,persona,job_ref,read_attempt_id,payload_json,payload_digest) "
                   "VALUES(?,?,?,?,?,?)", original.namespace.as_tuple + (
                       original.binding.job_ref, request.read_attempt_id, encoded, digest))
    return D13PaidReadEvidenceV1(original.original_digest, call_original.original_digest,
                                read, fact, digest)


def read_paid_d13_evidence_in_transaction_v1(db, original, call):
    _transaction(db)
    row = db.execute("SELECT read_attempt_id,payload_json,payload_digest FROM "
                     "graph_d13_paid_result_reads_v1 WHERE bot=? AND persona=? AND job_ref=?",
                     original.namespace.as_tuple + (original.binding.job_ref,)).fetchone()
    if row is None:
        return None
    payload = json.loads(row[1])
    read = read_from_wire(payload["read"], WorkerModelResultReadV1)
    fact = _fact_from_wire(payload["fact"])
    expected = _evidence_payload(original, call, read, fact)
    if (row != (read.request.read_attempt_id, canonical_serialize(expected),
                canonical_digest(expected))):
        raise ValueError("D13 result evidence original changed")
    read.require_original_intent(fact.intent)
    if (read.terminal_receipt != fact.receipt or read.observation.digest != fact.recovery.observation_digest
            or read.observation.usage != fact.recovery.usage or read.observation.cost != fact.recovery.cost):
        raise ValueError("D13 evidence differs from its original terminal")
    return D13PaidReadEvidenceV1(original.original_digest, call.original_digest, read, fact, row[2])


def read_paid_d13_settlement_in_transaction_v1(db, original, evidence):
    _transaction(db)
    row = db.execute("SELECT payload_json,payload_digest FROM "
                     "graph_d13_paid_cost_receipts_v1 WHERE bot=? AND persona=? AND job_ref=?",
                     original.namespace.as_tuple + (original.binding.job_ref,)).fetchone()
    if row is None:
        return None
    payload = json.loads(row[0])
    if (payload["evidence_digest"] != evidence.evidence_digest or
            canonical_serialize(payload) != row[0] or canonical_digest(payload) != row[1]):
        raise ValueError("D13 original cost receipt changed")
    write = GraphWrite(AtomKey.from_token(payload["cost_write"]["key"]),
                       payload["cost_write"]["value"],
                       tuple(AtomKey.from_token(token)
                             for token in payload["cost_write"]["dependencies"]))
    atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",
                      (write.key.token,)).fetchone()
    if atom is None or atom[1] != 1 or json.loads(atom[0]) != write.value:
        raise ValueError("D13 paid cost graph original is absent or invalid")
    return D13PaidSettlementV1(evidence.evidence_digest,
                              BudgetReceipt(**payload["receipt"]), write)


def settle_paid_d13_in_transaction_v1(db, original, call_original, *, resource_issuer):
    """Settle the original fact once and return its required D11 graph write."""
    _transaction(db)
    evidence = read_paid_d13_evidence_in_transaction_v1(db, original, call_original)
    if evidence is None:
        raise ValueError("D13 paid cost requires its durable prior Authority read")
    prior = read_paid_d13_settlement_in_transaction_v1(db, original, evidence)
    if prior is not None:
        return prior
    plan = prepare_original_model_cost_plan(
        db, resource_issuer, original.namespace, evidence.fact,
        quote_id=original.quote_id, quote_version=original.quote_version,
        work_kind=PAID_WORK_KIND)
    application = apply_original_model_budget_in_transaction(db, resource_issuer, plan, evidence.fact)
    write = application.cost_write
    payload = {"schema": "d13.paid_cost_receipt.v1",
               "evidence_digest": evidence.evidence_digest,
               "receipt": asdict(application.receipt),
               "cost_write": {"key": write.key.token, "value": write.value,
                              "dependencies": [key.token for key in write.dependencies]}}
    db.execute("INSERT INTO graph_d13_paid_cost_receipts_v1 "
               "(bot,persona,job_ref,payload_json,payload_digest) VALUES(?,?,?,?,?)",
               original.namespace.as_tuple + (original.binding.job_ref,
                   canonical_serialize(payload), canonical_digest(payload)))
    return D13PaidSettlementV1(evidence.evidence_digest, application.receipt, write)


def prepare_paid_d13_standby_in_transaction_v1(
    db, original, call_original, frozen, current_window, selected_main, *,
    resource_issuer, budget_issuer, holder, fence, now_utc,
) -> D13PaidStandbyPreparationV1:
    """Revalidate saved bytes after settlement; never reread spent provider call."""
    job = _live_job(db, original, call_original, holder=holder, fence=fence, now_utc=now_utc)
    if type(selected_main) is not D13PrecompressionInstallationV1 or selected_main != frozen.installation:
        raise ValueError("D13 paid selected main model changed")
    current = read_current_d13_paid_intent_original_v1(
        db, original.namespace, frozen, original.binding, original.exact_count,
        selected_main, current_window, quote_id=original.quote_id,
        quote_version=original.quote_version, budget_operation_id=original.budget_operation_id,
        resource_issuer=resource_issuer, budget_issuer=budget_issuer)
    if current != original:
        raise ValueError("D13 paid original source no longer current")
    evidence = read_paid_d13_evidence_in_transaction_v1(db, original, call_original)
    if evidence is None:
        raise ValueError("D13 paid result read evidence is missing")
    settlement = read_paid_d13_settlement_in_transaction_v1(db, original, evidence)
    if settlement is None:
        raise ValueError("D13 paid original actual cost has not been settled")
    block = None
    reason = None
    if settlement.receipt.status != "settled":
        reason = "paid_cost_unknown_or_overrun"
    else:
        try:
            result = json.loads(evidence.read.observation.result_json)
            if type(result) is not dict or set(result) != {"text"} or type(result["text"]) is not str:
                raise ValueError("D13 result text shape differs")
            parsed = parse_d13_precompression_output_v1(result["text"], frozen)
            candidate = compile_extractive_model_output(current_window, frozen.plan, parsed.model_text)

            class SavedOriginalVerifier:
                def verify_current_paid_model_block_v2(self, value, *, plan, window):
                    return (value == candidate and plan == frozen.plan and
                            window == current_window and current == original and
                            settlement.evidence_digest == evidence.evidence_digest)

            block = accept_verified_model_candidate_v2(
                candidate, frozen.plan, current_window, paid_verifier=SavedOriginalVerifier())
        except (TypeError, ValueError):
            reason = "invalid_paid_extractive_output"
    if block is not None:
        key = AtomKey(Owner("persona", *original.namespace.as_tuple),
                      "d13.compressed_turn_block.v2", block.block_ref)
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone() is not None:
            raise ValueError("D13 paid standby cache identity is already occupied")
    return D13PaidStandbyPreparationV1(original, evidence.evidence_digest, settlement, block, reason, job)


def finalize_paid_d13_in_transaction_v1(db, preparation, *, holder, fence):
    """Complete alongside the caller's standby/job graph CAS; charge survives rejection."""
    _transaction(db)
    if type(preparation) is not D13PaidStandbyPreparationV1 or get_job(db, preparation.job.job_id) != preparation.job:
        raise ValueError("D13 paid completion original job changed")
    evidence = read_paid_d13_evidence_in_transaction_v1(
        db, preparation.original,
        read_d13_paid_call_original_v1(db, preparation.original.namespace, preparation.job.job_id)[0])
    checkpoint_job(db, preparation.job.job_id, holder, fence,
                   continuation=preparation.job.continuation,
                   usage=dict(evidence.read.observation.usage))
    block = preparation.block
    completed = transition_job(db, preparation.job.job_id, holder, fence,
                               target_phase="completed" if block is not None else "failed",
                               result_ref=block.block_ref if block is not None else None)
    db.execute("UPDATE graph_d13_paid_scene_jobs_v1 SET state=? "
               "WHERE bot=? AND persona=? AND job_ref=? AND state='running'",
               ("standby" if block is not None else "finished",) +
               preparation.original.namespace.as_tuple + (completed.job_id,))
    if db.execute("SELECT changes()").fetchone() != (1,):
        raise ValueError("D13 paid scene slot completion changed")
    writes = [job_graph_write(completed)]
    if block is not None:
        writes.append(GraphWrite(
            AtomKey(Owner("persona", *preparation.original.namespace.as_tuple),
                    "d13.compressed_turn_block.v2", block.block_ref),
            block_graph_value(block),
            tuple(AtomKey.from_token(ref.ref) for ref in block.source_dependencies)))
    return completed, tuple(writes)


def recover_paid_d13_in_transaction_v1(db, namespace, job_id):
    """Typed recovery decision. A sealed call only permits original-fact recovery."""
    _transaction(db)
    loaded = load_d13_paid_intent_original_v1(db, namespace, job_id)
    if loaded is None:
        return None
    original, frozen = loaded
    job = get_job(db, job_id)
    saved_call = read_d13_paid_call_original_v1(db, namespace, job_id)
    call = None if saved_call is None else saved_call[0]
    evidence = None if call is None else read_paid_d13_evidence_in_transaction_v1(db, original, call)
    settlement = None if evidence is None else read_paid_d13_settlement_in_transaction_v1(db, original, evidence)
    if job.phase in {"completed", "failed", "cancelled"}:
        action = "terminal"
    elif settlement is not None:
        action = "adopt_saved_evidence"
    elif evidence is not None:
        action = "settle_saved_evidence"
    elif call is not None:
        action = "recover_original_authority_only"
    elif job.phase == "queued":
        action = "acquire_original"
    else:
        action = "seal_original_worker"
    return D13PaidRecoveryV1(original, frozen, job, call, evidence, settlement, action)


__all__ = [name for name in globals() if name.startswith("D13Paid") or
           name.endswith("_in_transaction_v1") or name == "install_d13_paid_coordinator_schema_v1"]
