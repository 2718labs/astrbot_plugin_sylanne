"""Durable D11 cost accounting for one isolated D12 scheme preview.

W01 commits begin/reserve and claim before running its bounded sandbox. The
sandbox runs outside the database transaction. A signed thread-CPU report is
then settled in a separate caller-owned BEGIN IMMEDIATE transaction. A lost
report or uncertain termination retains the D11 ceiling as unconfirmed debt.
This module does not create the sandbox or certify its production isolation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, is_dataclass
import json
import re
import sqlite3
import time
from typing import Callable

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .budget import get_budget_lease, reserve_budget, settle_budget
from .issuers import D11BudgetGrantIssuer, IssuerAuthorityDenied


SCHEME_PREVIEW_WORK_KIND = "scheme_preview"
CPU_DIMENSION = "thread_cpu_ms"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_INTENT_KIND = "d11.d12-preview-intent.v1"
_REPORT_KIND = "d11.d12-preview-report.v1"
_RECEIPT_KIND = "d11.d12-preview-cost-receipt.v1"


class PreviewCostConflict(ValueError):
    """Durable operation or signed preview-cost original differs."""


def _id(value: object, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _transaction(db: sqlite3.Connection) -> None:
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        raise ValueError("caller-owned BEGIN IMMEDIATE transaction required")


def _issuer(issuer: D11BudgetGrantIssuer) -> None:
    if not isinstance(issuer, D11BudgetGrantIssuer):
        raise TypeError("D11BudgetGrantIssuer required")


def _sign(issuer: D11BudgetGrantIssuer, kind: str, payload: object) -> str:
    # D11's signer also signs the grant. This private bridge is local to the
    # D11 runtime until a public generic original-signing method exists.
    return issuer._signer.sign(kind, canonical_serialize(_plainify(payload)))


def _verify(issuer: D11BudgetGrantIssuer, kind: str, payload: object,
            signature: str) -> None:
    issuer._signer.verify(kind, canonical_serialize(_plainify(payload)), signature)


def _plainify(value: object):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {key: _plainify(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plainify(item) for item in value]
    return value


def d12_preview_sandbox_namespace_v1(
    namespace: NamespaceId, operation_id: str,
) -> NamespaceId:
    if type(namespace) is not NamespaceId:
        raise TypeError("production NamespaceId required")
    _id(operation_id, "operation_id")
    return NamespaceId(
        namespace.bot_id,
        "preview." + canonical_digest((namespace.as_tuple, operation_id))[:32],
    )


def _budget_operation_id(namespace: NamespaceId, operation_id: str) -> str:
    return "d12preview:" + canonical_digest((namespace.as_tuple, operation_id))


@dataclass(frozen=True, slots=True)
class D12PreviewWorkEvidenceV1:
    compiled_digest: str
    sandbox_namespace: NamespaceId
    source_snapshot_digest: str
    production_revision_before: int
    production_revision_after: int
    external_effect_refs: tuple[str, ...]
    formal_contribution_refs: tuple[str, ...]
    production_write_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest(self.compiled_digest, "compiled_digest")
        _digest(self.source_snapshot_digest, "source_snapshot_digest")
        if type(self.sandbox_namespace) is not NamespaceId:
            raise TypeError("sandbox NamespaceId required")
        for name in ("production_revision_before", "production_revision_after"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"invalid {name}")
        for name in ("external_effect_refs", "formal_contribution_refs",
                     "production_write_refs"):
            if type(getattr(self, name)) is not tuple:
                raise TypeError(f"{name} must be a tuple")


@dataclass(frozen=True, slots=True)
class D12PreviewRunIntentV1:
    namespace: NamespaceId
    operation_id: str
    sandbox_namespace: NamespaceId
    compiled_digest: str
    source_snapshot_digest: str
    production_revision: int
    budget_ref: str
    budget_operation_id: str
    budget_digest: str
    ceiling_thread_cpu_ms: int
    max_wall_ms: int
    run_intent_digest: str
    experiment_digest: str
    grant_version: int
    grant_signature: str
    reserve_receipt_digest: str
    intent_digest: str
    signature: str


@dataclass(frozen=True, slots=True)
class D12PreviewExecutionReportV1:
    intent_digest: str
    run_intent_digest: str
    experiment_digest: str
    status: str
    thread_cpu_started_ns: int
    thread_cpu_finished_ns: int
    wall_started_ns: int
    wall_finished_ns: int
    max_wall_ms: int
    actual_thread_cpu_ms: int
    evidence_json: str | None
    error_digest: str | None
    report_digest: str
    signature: str


@dataclass(frozen=True, slots=True)
class D12PreviewCostReceiptV1:
    cost_ref: str
    intent_digest: str
    report_digest: str | None
    budget_ref: str
    budget_operation_id: str
    budget_digest: str
    reserve_receipt_digest: str
    settle_receipt_digest: str
    actual_thread_cpu_ms: int | None
    status: str
    signature: str


@dataclass(frozen=True, slots=True)
class D12PreviewCostStateV1:
    intent: D12PreviewRunIntentV1
    state: str
    report: D12PreviewExecutionReportV1 | None
    receipt: D12PreviewCostReceiptV1 | None


def _plain(value: object) -> dict:
    return asdict(value)


def _signed_payload(value: object) -> dict:
    payload = _plain(value)
    payload.pop("signature")
    return payload


def _intent_binding(*, namespace: NamespaceId, operation_id: str,
                    sandbox_namespace: NamespaceId, compiled_digest: str,
                    source_snapshot_digest: str, production_revision: int,
                    budget_ref: str, ceiling_thread_cpu_ms: int,
                    max_wall_ms: int,
                    run_intent_digest: str, experiment_digest: str) -> str:
    if type(namespace) is not NamespaceId or type(sandbox_namespace) is not NamespaceId:
        raise TypeError("production and sandbox NamespaceId required")
    _id(operation_id, "operation_id")
    _digest(compiled_digest, "compiled_digest")
    _digest(source_snapshot_digest, "source_snapshot_digest")
    _digest(run_intent_digest, "run_intent_digest")
    _digest(experiment_digest, "experiment_digest")
    _id(budget_ref, "budget_ref")
    if sandbox_namespace != d12_preview_sandbox_namespace_v1(namespace, operation_id):
        raise ValueError("sandbox namespace differs from operation")
    if type(production_revision) is not int or production_revision < 0:
        raise ValueError("invalid production_revision")
    if type(ceiling_thread_cpu_ms) is not int or ceiling_thread_cpu_ms < 1:
        raise ValueError("positive thread CPU ceiling required")
    if type(max_wall_ms) is not int or max_wall_ms < 1:
        raise ValueError("positive wall deadline required")
    return canonical_digest({
        "schema": _INTENT_KIND, "work_kind": SCHEME_PREVIEW_WORK_KIND,
        "namespace": namespace, "operation_id": operation_id,
        "sandbox_namespace": sandbox_namespace,
        "compiled_digest": compiled_digest,
        "source_snapshot_digest": source_snapshot_digest,
        "production_revision": production_revision, "budget_ref": budget_ref,
        "ceiling_thread_cpu_ms": ceiling_thread_cpu_ms,
        "max_wall_ms": max_wall_ms,
        "run_intent_digest": run_intent_digest,
        "experiment_digest": experiment_digest,
    })


def _isolated(evidence: D12PreviewWorkEvidenceV1,
              intent: D12PreviewRunIntentV1) -> bool:
    return (type(evidence) is D12PreviewWorkEvidenceV1
            and evidence.compiled_digest == intent.compiled_digest
            and evidence.sandbox_namespace == intent.sandbox_namespace
            and evidence.source_snapshot_digest == intent.source_snapshot_digest
            and evidence.production_revision_before == intent.production_revision
            and evidence.production_revision_after == intent.production_revision
            and not evidence.external_effect_refs
            and not evidence.formal_contribution_refs
            and not evidence.production_write_refs)


def install_d12_preview_budget_schema_v1(db: sqlite3.Connection) -> None:
    _transaction(db)
    db.execute("""CREATE TABLE IF NOT EXISTS runtime_d12_preview_cost_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        intent_json TEXT NOT NULL, state TEXT NOT NULL,
        report_json TEXT, receipt_json TEXT,
        PRIMARY KEY(bot,persona,operation_id))""")


def _decode(encoded: str, cls: type):
    value = json.loads(encoded)
    if type(value) is not dict or set(value) != {item.name for item in fields(cls)}:
        raise PreviewCostConflict("preview original shape changed")
    if cls is D12PreviewRunIntentV1:
        for name in ("namespace", "sandbox_namespace"):
            item = value[name]
            value[name] = NamespaceId(item["bot_id"], item["persona_id"])
    result = cls(**value)
    if canonical_serialize(_plain(result)) != encoded:
        raise PreviewCostConflict("preview original bytes changed")
    return result


def _report_valid(issuer: D11BudgetGrantIssuer,
                  intent: D12PreviewRunIntentV1,
                  report: D12PreviewExecutionReportV1) -> bool:
    if type(report) is not D12PreviewExecutionReportV1:
        return False
    try:
        _verify(issuer, _REPORT_KIND, _signed_payload(report), report.signature)
    except IssuerAuthorityDenied:
        return False
    payload = _signed_payload(report)
    payload.pop("report_digest")
    if (report.report_digest != canonical_digest(payload)
            or report.intent_digest != intent.intent_digest
            or report.run_intent_digest != intent.run_intent_digest
            or report.experiment_digest != intent.experiment_digest
            or report.status not in {"succeeded", "failed", "timeout"}
            or type(report.thread_cpu_started_ns) is not int
            or type(report.thread_cpu_finished_ns) is not int
            or type(report.wall_started_ns) is not int
            or type(report.wall_finished_ns) is not int
            or report.thread_cpu_started_ns < 0
            or report.wall_started_ns < 0
            or report.thread_cpu_finished_ns < report.thread_cpu_started_ns
            or report.wall_finished_ns < report.wall_started_ns
            or type(report.max_wall_ms) is not int or report.max_wall_ms < 1
            or report.max_wall_ms != intent.max_wall_ms
            or report.actual_thread_cpu_ms != max(
                1, (report.thread_cpu_finished_ns - report.thread_cpu_started_ns
                    + 999_999) // 1_000_000)):
        return False
    elapsed_wall_ms = (
        report.wall_finished_ns - report.wall_started_ns + 999_999
    ) // 1_000_000
    if (elapsed_wall_ms > report.max_wall_ms) != (report.status == "timeout"):
        return False
    if report.status == "succeeded":
        if report.evidence_json is None or report.error_digest is not None:
            return False
        try:
            value = json.loads(report.evidence_json)
            sandbox = value["sandbox_namespace"]
            value["sandbox_namespace"] = NamespaceId(
                sandbox["bot_id"], sandbox["persona_id"])
            for name in ("external_effect_refs", "formal_contribution_refs",
                         "production_write_refs"):
                value[name] = tuple(value[name])
            evidence = D12PreviewWorkEvidenceV1(**value)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return False
        return (_isolated(evidence, intent)
                and report.evidence_json == canonical_serialize(_plain(evidence)))
    return report.evidence_json is None and report.error_digest is not None


def read_d12_preview_cost_v1(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, operation_id: str, cost_ref: str | None = None,
) -> D12PreviewCostStateV1 | None:
    """Verify signed originals and the corresponding D11 budget rows."""
    _transaction(db)
    _issuer(issuer)
    if type(namespace) is not NamespaceId:
        raise TypeError("production NamespaceId required")
    _id(operation_id, "operation_id")
    row = db.execute(
        "SELECT intent_json,state,report_json,receipt_json "
        "FROM runtime_d12_preview_cost_v1 WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    try:
        intent = _decode(row[0], D12PreviewRunIntentV1)
        _verify(issuer, _INTENT_KIND, _signed_payload(intent), intent.signature)
        binding = _intent_binding(
            namespace=intent.namespace, operation_id=intent.operation_id,
            sandbox_namespace=intent.sandbox_namespace,
            compiled_digest=intent.compiled_digest,
            source_snapshot_digest=intent.source_snapshot_digest,
            production_revision=intent.production_revision,
            budget_ref=intent.budget_ref,
            ceiling_thread_cpu_ms=intent.ceiling_thread_cpu_ms,
            max_wall_ms=intent.max_wall_ms,
            run_intent_digest=intent.run_intent_digest,
            experiment_digest=intent.experiment_digest)
        grant, grant_sig = issuer.signed_budget_grant_at_version(
            db, intent.budget_ref, intent.grant_version)
    except (TypeError, ValueError, KeyError, IssuerAuthorityDenied,
            json.JSONDecodeError) as exc:
        raise PreviewCostConflict("signed preview intent changed") from exc
    if (intent.namespace != namespace or intent.operation_id != operation_id
            or intent.intent_digest != binding or intent.budget_digest != binding
            or intent.budget_operation_id != _budget_operation_id(namespace, operation_id)
            or intent.grant_signature != grant_sig
            or (grant.bot_id, grant.persona_id, grant.lease_id)
            != (*namespace.as_tuple, intent.budget_ref)
            or SCHEME_PREVIEW_WORK_KIND not in grant.allowed_work_kinds
            or grant.max_ceiling.get(CPU_DIMENSION, 0)
            < intent.ceiling_thread_cpu_ms):
        raise PreviewCostConflict("preview intent binding differs")
    reservation = db.execute(
        "SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (intent.budget_ref, intent.budget_operation_id),
    ).fetchone()
    reserve = db.execute(
        "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, intent.budget_operation_id),
    ).fetchone()
    if (reservation is None or reservation[0] != binding
            or reservation[1] != canonical_serialize({
                CPU_DIMENSION: intent.ceiling_thread_cpu_ms})
            or reserve is None or reserve[:2] != (binding, intent.budget_ref)
            or canonical_digest(json.loads(reserve[2]))
            != intent.reserve_receipt_digest):
        raise PreviewCostConflict("D11 preview reservation changed")
    state = row[1]
    report = _decode(row[2], D12PreviewExecutionReportV1) if row[2] else None
    receipt = _decode(row[3], D12PreviewCostReceiptV1) if row[3] else None
    if report is not None and not _report_valid(issuer, intent, report):
        raise PreviewCostConflict("signed execution report changed")
    if state in {"prepared", "running"}:
        if cost_ref is not None:
            raise PreviewCostConflict("preview has no cost receipt yet")
        if report is not None or receipt is not None or reservation[2] != "reserved":
            raise PreviewCostConflict("unsettled preview state differs")
        return D12PreviewCostStateV1(intent, state, None, None)
    if receipt is None:
        raise PreviewCostConflict("settled preview receipt absent")
    if cost_ref is not None and receipt.cost_ref != cost_ref:
        raise PreviewCostConflict("preview cost ref differs")
    try:
        _verify(issuer, _RECEIPT_KIND, _signed_payload(receipt), receipt.signature)
    except IssuerAuthorityDenied as exc:
        raise PreviewCostConflict("signed preview receipt changed") from exc
    settle = db.execute(
        "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*namespace.as_tuple, intent.budget_operation_id),
    ).fetchone()
    if (settle is None or settle[:2] != (binding, intent.budget_ref)
            or canonical_digest(json.loads(settle[2]))
            != receipt.settle_receipt_digest
            or receipt.intent_digest != binding
            or receipt.budget_ref != intent.budget_ref
            or receipt.budget_operation_id != intent.budget_operation_id
            or receipt.budget_digest != binding
            or receipt.reserve_receipt_digest != intent.reserve_receipt_digest
            or receipt.status != state
            or receipt.cost_ref != "d12-preview-cost:" + canonical_digest((
                binding, receipt.report_digest, receipt.settle_receipt_digest))):
        raise PreviewCostConflict("D11 preview settlement changed")
    if state == "pending_confirmation":
        if (report is not None or receipt.report_digest is not None
                or receipt.actual_thread_cpu_ms is not None
                or reservation[2] != "unknown" or reservation[3] is not None):
            raise PreviewCostConflict("unknown preview cost was filled")
    else:
        if (report is None or receipt.report_digest != report.report_digest
                or receipt.actual_thread_cpu_ms != report.actual_thread_cpu_ms
                or reservation[2] not in {"settled", "overrun"}
                or reservation[3] != canonical_serialize({
                    CPU_DIMENSION: report.actual_thread_cpu_ms})
                or state != ("overrun" if reservation[2] == "overrun"
                             else "settled" if report.status == "succeeded"
                             else report.status)):
            raise PreviewCostConflict("preview execution bill differs")
    return D12PreviewCostStateV1(intent, state, report, receipt)


def begin_d12_preview_cost_v1(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, operation_id: str,
    sandbox_namespace: NamespaceId, compiled_digest: str,
    source_snapshot_digest: str, production_revision: int,
    budget_ref: str, ceiling_thread_cpu_ms: int,
    max_wall_ms: int,
    run_intent_digest: str, experiment_digest: str,
) -> D12PreviewRunIntentV1:
    """Persist signed intent and D11 reservation; caller commits before claim."""
    _transaction(db)
    _issuer(issuer)
    binding = _intent_binding(
        namespace=namespace, operation_id=operation_id,
        sandbox_namespace=sandbox_namespace, compiled_digest=compiled_digest,
        source_snapshot_digest=source_snapshot_digest,
        production_revision=production_revision, budget_ref=budget_ref,
        ceiling_thread_cpu_ms=ceiling_thread_cpu_ms,
        max_wall_ms=max_wall_ms,
        run_intent_digest=run_intent_digest,
        experiment_digest=experiment_digest)
    prior = read_d12_preview_cost_v1(
        db, issuer, namespace=namespace, operation_id=operation_id)
    if prior is not None:
        if prior.intent.intent_digest != binding:
            raise PreviewCostConflict("preview operation reused with different input")
        return prior.intent
    lease = get_budget_lease(db, budget_ref)
    grant = issuer.current_budget_grant(db, budget_ref)
    if ((lease.bot_id, lease.persona_id) != namespace.as_tuple
            or (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency)
            != (namespace.bot_id, namespace.persona_id, budget_ref, lease.currency)
            or SCHEME_PREVIEW_WORK_KIND not in grant.allowed_work_kinds
            or grant.max_ceiling.get(CPU_DIMENSION, 0) < ceiling_thread_cpu_ms
            or grant.valid_until_utc <= time.time()):
        raise IssuerAuthorityDenied("signed D11 scheme_preview grant is insufficient")
    _, grant_sig = issuer.signed_budget_grant_at_version(
        db, budget_ref, grant.version)
    budget_op = _budget_operation_id(namespace, operation_id)
    reserved = reserve_budget(
        db, budget_ref, budget_op, binding,
        {CPU_DIMENSION: ceiling_thread_cpu_ms})
    payload = dict(
        namespace=namespace, operation_id=operation_id,
        sandbox_namespace=sandbox_namespace, compiled_digest=compiled_digest,
        source_snapshot_digest=source_snapshot_digest,
        production_revision=production_revision, budget_ref=budget_ref,
        budget_operation_id=budget_op, budget_digest=binding,
        ceiling_thread_cpu_ms=ceiling_thread_cpu_ms,
        max_wall_ms=max_wall_ms,
        run_intent_digest=run_intent_digest,
        experiment_digest=experiment_digest, grant_version=grant.version,
        grant_signature=grant_sig,
        reserve_receipt_digest=canonical_digest(_plain(reserved)),
        intent_digest=binding)
    intent = D12PreviewRunIntentV1(**payload, signature=_sign(
        issuer, _INTENT_KIND, payload))
    db.execute(
        "INSERT INTO runtime_d12_preview_cost_v1 VALUES(?,?,?,?,?,?,?)",
        (*namespace.as_tuple, operation_id,
         canonical_serialize(_plain(intent)), "prepared", None, None),
    )
    return intent


def claim_d12_preview_run_v1(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, operation_id: str,
) -> D12PreviewRunIntentV1 | None:
    """Claim once durably; commit before any sandbox work. None means no rerun."""
    current = read_d12_preview_cost_v1(
        db, issuer, namespace=namespace, operation_id=operation_id)
    if current is None:
        raise PreviewCostConflict("preview intent absent")
    if current.state != "prepared":
        return None
    db.execute(
        "UPDATE runtime_d12_preview_cost_v1 SET state='running' "
        "WHERE bot=? AND persona=? AND operation_id=? AND state='prepared'",
        (*namespace.as_tuple, operation_id),
    )
    return current.intent


def run_d12_preview_once_v1(
    issuer: D11BudgetGrantIssuer, intent: D12PreviewRunIntentV1, *,
    max_wall_ms: int,
    run_preview: Callable[[], D12PreviewWorkEvidenceV1],
) -> D12PreviewExecutionReportV1:
    """Measure one W01-bounded synchronous sandbox run outside SQLite.

    W01 must enforce the deadline and stop its worker. Python cannot forcibly
    terminate a hung callback; if termination is uncertain, mark unknown.
    """
    _issuer(issuer)
    if type(intent) is not D12PreviewRunIntentV1 or not callable(run_preview):
        raise TypeError("signed intent and sandbox callback required")
    _verify(issuer, _INTENT_KIND, _signed_payload(intent), intent.signature)
    if type(max_wall_ms) is not int or max_wall_ms != intent.max_wall_ms:
        raise ValueError("execution wall deadline differs from signed intent")
    wall_start, cpu_start = time.monotonic_ns(), time.thread_time_ns()
    evidence = None
    error_digest = None
    try:
        evidence = run_preview()
        if not _isolated(evidence, intent):
            raise ValueError("sandbox result is not isolated")
    except Exception as exc:
        error_digest = canonical_digest((
            type(exc).__module__, type(exc).__qualname__, str(exc)))
    cpu_end, wall_end = time.thread_time_ns(), time.monotonic_ns()
    if cpu_end < cpu_start or wall_end < wall_start:
        raise ValueError("preview measurement clock regressed")
    elapsed_wall_ms = (wall_end - wall_start + 999_999) // 1_000_000
    status = ("timeout" if elapsed_wall_ms > max_wall_ms else
              "failed" if error_digest is not None else "succeeded")
    if status == "timeout" and error_digest is None:
        error_digest = canonical_digest(("preview_wall_deadline_exceeded", elapsed_wall_ms))
    payload = dict(
        intent_digest=intent.intent_digest,
        run_intent_digest=intent.run_intent_digest,
        experiment_digest=intent.experiment_digest,
        status=status, thread_cpu_started_ns=cpu_start,
        thread_cpu_finished_ns=cpu_end, wall_started_ns=wall_start,
        wall_finished_ns=wall_end, max_wall_ms=max_wall_ms,
        actual_thread_cpu_ms=max(1, (cpu_end - cpu_start + 999_999) // 1_000_000),
        evidence_json=(canonical_serialize(_plain(evidence))
                       if status == "succeeded" else None),
        error_digest=error_digest)
    report_digest = canonical_digest(payload)
    signed = dict(payload, report_digest=report_digest)
    return D12PreviewExecutionReportV1(**signed, signature=_sign(
        issuer, _REPORT_KIND, signed))


def _receipt(issuer: D11BudgetGrantIssuer, intent: D12PreviewRunIntentV1,
             *, report_digest: str | None, settle_digest: str,
             actual_thread_cpu_ms: int | None, status: str) -> D12PreviewCostReceiptV1:
    payload = dict(
        cost_ref="d12-preview-cost:" + canonical_digest((
            intent.intent_digest, report_digest, settle_digest)),
        intent_digest=intent.intent_digest, report_digest=report_digest,
        budget_ref=intent.budget_ref,
        budget_operation_id=intent.budget_operation_id,
        budget_digest=intent.budget_digest,
        reserve_receipt_digest=intent.reserve_receipt_digest,
        settle_receipt_digest=settle_digest,
        actual_thread_cpu_ms=actual_thread_cpu_ms, status=status)
    return D12PreviewCostReceiptV1(**payload, signature=_sign(
        issuer, _RECEIPT_KIND, payload))


def settle_d12_preview_cost_v1(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, operation_id: str,
    report: D12PreviewExecutionReportV1,
) -> D12PreviewCostReceiptV1:
    """Persist signed report and actual bill, including failure/overrun cost."""
    current = read_d12_preview_cost_v1(
        db, issuer, namespace=namespace, operation_id=operation_id)
    if current is None or current.state == "prepared":
        raise PreviewCostConflict("preview has not been claimed")
    if not _report_valid(issuer, current.intent, report):
        raise PreviewCostConflict("execution report differs from signed intent")
    if current.receipt is not None:
        if current.report != report:
            raise PreviewCostConflict("preview cost already settled with different report")
        return current.receipt
    if current.state != "running":
        raise PreviewCostConflict("preview is not settleable")
    settled = settle_budget(
        db, current.intent.budget_ref, current.intent.budget_operation_id,
        current.intent.budget_digest,
        {CPU_DIMENSION: report.actual_thread_cpu_ms}, execution_revoked=True)
    status = ("overrun" if settled.status == "overrun" else
              "settled" if report.status == "succeeded" else report.status)
    receipt = _receipt(
        issuer, current.intent, report_digest=report.report_digest,
        settle_digest=canonical_digest(_plain(settled)),
        actual_thread_cpu_ms=report.actual_thread_cpu_ms, status=status)
    db.execute(
        "UPDATE runtime_d12_preview_cost_v1 "
        "SET state=?,report_json=?,receipt_json=? "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (status, canonical_serialize(_plain(report)),
         canonical_serialize(_plain(receipt)),
         *namespace.as_tuple, operation_id),
    )
    return receipt


def mark_d12_preview_unknown_v1(
    db: sqlite3.Connection, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, operation_id: str,
) -> D12PreviewCostReceiptV1:
    """Unknown terminal state holds the original ceiling; never invents zero."""
    current = read_d12_preview_cost_v1(
        db, issuer, namespace=namespace, operation_id=operation_id)
    if current is None or current.state == "prepared":
        raise PreviewCostConflict("preview has not been claimed")
    if current.receipt is not None:
        if current.state != "pending_confirmation":
            raise PreviewCostConflict("known preview bill already settled")
        return current.receipt
    settled = settle_budget(
        db, current.intent.budget_ref, current.intent.budget_operation_id,
        current.intent.budget_digest, None, execution_revoked=False)
    if settled.status != "pending_confirmation":
        raise PreviewCostConflict("unknown cost did not retain ceiling")
    receipt = _receipt(
        issuer, current.intent, report_digest=None,
        settle_digest=canonical_digest(_plain(settled)),
        actual_thread_cpu_ms=None, status="pending_confirmation")
    db.execute(
        "UPDATE runtime_d12_preview_cost_v1 SET state='pending_confirmation',"
        "receipt_json=? WHERE bot=? AND persona=? AND operation_id=?",
        (canonical_serialize(_plain(receipt)), *namespace.as_tuple, operation_id),
    )
    return receipt


__all__ = (
    "CPU_DIMENSION", "SCHEME_PREVIEW_WORK_KIND", "D12PreviewCostReceiptV1",
    "D12PreviewCostStateV1", "D12PreviewExecutionReportV1",
    "D12PreviewRunIntentV1", "D12PreviewWorkEvidenceV1",
    "PreviewCostConflict", "begin_d12_preview_cost_v1",
    "claim_d12_preview_run_v1", "d12_preview_sandbox_namespace_v1",
    "install_d12_preview_budget_schema_v1", "mark_d12_preview_unknown_v1",
    "read_d12_preview_cost_v1", "run_d12_preview_once_v1",
    "settle_d12_preview_cost_v1",
)
