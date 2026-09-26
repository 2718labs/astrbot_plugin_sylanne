"""Fenced D11 material for acquiring an already committed D06 correction job.

The coordinator owns Authority V2 permits, acquire intents/receipts, graph
commits, and outbox dispatch. These functions only inspect the existing
business database and, inside its caller-owned write transaction, acquire the
already reserved job. They neither settle cost nor complete reevaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import sqlite3

from ..domains.d06 import source_correction_head_key, validate_source_correction_head
from ..graph_types import AtomKey
from ..runtime_contracts import FenceScope, NamespaceId
from .budget import get_budget_lease, require_budget_family_admissible
from .d11_types import job_graph_write, runtime_job_key
from .issuers import (
    D06_SOURCE_CORRECTION_WORK_KIND, D11BudgetJobIssuer,
    IssuerAuthorityDenied, ResourceQuote, d06_source_correction_job_ref,
    d06_source_correction_outbox_ref, d06_source_correction_quote_id,
    _d06_correction_policy_id, _payload,
)
from .jobs import PersistentJob, acquire_job, get_job, plan_job_acquire
from ..runtime_contracts import canonical_digest


class SourceCorrectionJobHold(RuntimeError):
    """The frozen correction identity no longer authorizes job acquisition."""


@dataclass(frozen=True)
class SourceCorrectionJobSnapshot:
    namespace: NamespaceId
    job: PersistentJob
    job_revision: int
    outbox_ref: str
    outbox_revision: int
    original_digest: str
    original_graph_revision: int
    request_digest: str
    correction_source_ref: str
    source_refs: tuple[str, ...]
    head_refs: tuple[str, ...]
    target_refs: tuple[str, ...]
    quote: ResourceQuote
    reservation_digest: str
    graph_revision: int
    graph_epoch: int
    activation_generation: int


def _row(db: sqlite3.Connection, sql: str, args: tuple):
    return db.execute(sql, args).fetchone()


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise SourceCorrectionJobHold(message)


def _read_json(value: str, label: str) -> dict:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise SourceCorrectionJobHold(f"{label} is invalid; HOLD") from exc
    _need(type(decoded) is dict, f"{label} is invalid; HOLD")
    return decoded


def _atom(db: sqlite3.Connection, namespace: NamespaceId, ref: str,
          type_name: str) -> tuple[int, dict]:
    try:
        key = AtomKey.from_token(ref)
    except (TypeError, ValueError) as exc:
        raise SourceCorrectionJobHold("correction graph ref is invalid; HOLD") from exc
    _need(key.type_name == type_name and (key.owner.bot, key.owner.persona)
          == namespace.as_tuple, "correction graph ref crosses namespace; HOLD")
    row = _row(db, "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
               "AND bot=? AND persona=?", (ref, *namespace.as_tuple))
    _need(row is not None and row[2] == 1, "correction graph atom is absent; HOLD")
    return row[0], _read_json(row[1], "correction graph atom")


def _stamp(db: sqlite3.Connection, namespace: NamespaceId) -> tuple[int, int, int]:
    metadata = _row(db, "SELECT graph_revision,requirements_json FROM "
                    "graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    namespace.as_tuple)
    epoch = _row(db, "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                 namespace.as_tuple)
    _need(metadata is not None and epoch is not None,
          "Authority V2 business stamp is absent; HOLD")
    requirements = _read_json(metadata[1], "Authority V2 requirements")
    generation = requirements.get("activation_generation")
    _need(type(generation) is int and generation > 0,
          "Authority V2 activation is absent; HOLD")
    return metadata[0], epoch[0], generation


def _scope_matches_recovery(db: sqlite3.Connection, scope: FenceScope) -> bool:
    row = _row(db, "SELECT requirements_json FROM graph_recovery_metadata_v2 "
               "WHERE bot=? AND persona=?", scope.namespace.as_tuple)
    if row is None:
        return False
    requirements = _read_json(row[0], "Authority V2 requirements")
    return (requirements.get("schema") == "sylanne3.authority.v2"
            and requirements.get("namespace") == {
                "bot_id": scope.namespace.bot_id,
                "persona_id": scope.namespace.persona_id}
            and requirements.get("authority_namespace") == scope.authority_namespace
            and requirements.get("authority_id") == scope.pinned_anchor.authority_id
            and requirements.get("activation_generation") == scope.generation)


def read_source_correction_job_snapshot(
        db: sqlite3.Connection, issuer: D11BudgetJobIssuer,
        namespace: NamespaceId, job_id: str, *, now_utc: float,
) -> SourceCorrectionJobSnapshot:
    """Read original signed and durable facts under a caller-owned DB snapshot.

    This is a preflight only. The caller must validate its independent V2 read
    fence outside the GraphStore lock and repeat this check inside its V2 write
    transaction before applying an acquisition.
    """
    if type(namespace) is not NamespaceId or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("typed namespace and D11 issuer are required")
    if not db.in_transaction:
        raise SourceCorrectionJobHold("correction read needs a pinned transaction; HOLD")
    if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        raise ValueError("now_utc must be finite")
    try:
        job = get_job(db, job_id)
    except Exception as exc:
        raise SourceCorrectionJobHold("correction job is absent; HOLD") from exc
    _need(job.work_kind == D06_SOURCE_CORRECTION_WORK_KIND
          and (job.bot_id, job.persona_id) == namespace.as_tuple
          and job.effect_id is None and job.cancel_epoch == 0
          and job.phase in {"queued", "running"},
          "correction job is not runnable; HOLD")
    deadline = datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00"))
    _need(now_utc < deadline.timestamp(), "correction deadline expired; HOLD")
    job_ref = runtime_job_key(*namespace.as_tuple, job.activity_id, job.job_id).token
    _need(job_ref == d06_source_correction_job_ref(
          namespace, job.activity_id, job.operation_id),
          "correction job identity differs; HOLD")
    quote_ref = job.operator_versions.get("resource_quote")
    _need(type(quote_ref) is str and ":" in quote_ref,
          "correction job lacks original quote; HOLD")
    quote_id, version_text = quote_ref.rsplit(":", 1)
    _need(version_text.isdecimal(), "correction quote version differs; HOLD")
    version = int(version_text)
    try:
        quote = issuer._d02.original_signed_quote(db, quote_id, version)
        grant = issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        require_budget_family_admissible(db, job.budget_ref)
    except Exception as exc:
        raise SourceCorrectionJobHold("correction signed grant or lease lost; HOLD") from exc
    quote_row = _row(db, "SELECT status FROM runtime_resource_quotes "
                     "WHERE quote_id=? AND version=?", (quote_id, version))
    _need(quote_row == ("active",) and quote.valid_until_utc > now_utc
          and quote.deadline_utc > now_utc and grant.valid_until_utc > now_utc
          and lease.state == "active", "correction authority expired or revoked; HOLD")
    parts = quote.snapshot_ref.split(":")
    _need(len(parts) == 3 and parts[0] == "d06correctionsnap",
          "correction quote lacks policy; HOLD")
    try:
        policy = issuer._d02._load_d06_correction_policy(db, parts[1])
    except IssuerAuthorityDenied as exc:
        raise SourceCorrectionJobHold("correction policy revoked; HOLD") from exc
    outbox_ref = d06_source_correction_outbox_ref(
        namespace, job.activity_id, job.operation_id)
    _need((quote.quote_id, quote.version, quote.bot_id, quote.persona_id,
           quote.activity_id, quote.operation_id, quote.effect_id,
           quote.parent_budget_lease_ref, quote.work_kind, quote.graph_job_ref,
           quote.outbox_refs, quote.d02_settlement_refs, quote.required_worker_fence,
           quote.snapshot_ref, quote.resource_ref) == (
           d06_source_correction_quote_id(namespace, job.operation_id), 1,
           *namespace.as_tuple, job.activity_id, job.operation_id, None,
           job.budget_ref, D06_SOURCE_CORRECTION_WORK_KIND, job_ref,
           (outbox_ref,), (), None, job.snapshot_ref, job.resource_ref)
          and abs(quote.deadline_utc - deadline.timestamp()) < 0.000001
          and (grant.bot_id, grant.persona_id, grant.lease_id, grant.currency)
          == (lease.bot_id, lease.persona_id, lease.lease_id, lease.currency)
          and grant.version == policy.grant_version
          and (grant.grant_id, grant.lease_id, grant.policy_ref)
          == (policy.grant_id, policy.lease_id, policy.provider_policy_ref)
          and D06_SOURCE_CORRECTION_WORK_KIND in grant.allowed_work_kinds
          and dict(quote.ceiling) == dict(policy.quote_ceiling)
          and all(amount <= grant.max_ceiling.get(name, 0)
                  for name, amount in quote.ceiling.items())
          and policy.policy_id == _d06_correction_policy_id(
              policy.installation_id, grant, job.operation_id)
          and policy.job_ref == job_ref and policy.outbox_ref == outbox_ref
          and (policy.bot_id, policy.persona_id, policy.activity_id,
               policy.operation_id) == (*namespace.as_tuple, job.activity_id,
                                        job.operation_id),
          "correction signed identity or ceiling differs; HOLD")
    _need(quote.snapshot_ref == "d06correctionsnap:" + policy.policy_id + ":" +
          canonical_digest({"policy": _payload(policy),
                            "envelope": policy.envelope_digest})[:32]
          and quote.resource_ref == "d06correctionresource:" + canonical_digest({
              "policy_id": policy.policy_id, "resource_ref": policy.resource_ref,
              "operation_id": policy.operation_id})[:48],
          "correction signed quote derivation differs; HOLD")
    operation = _row(db, "SELECT digest,activity_id,effect_id,receipt_json FROM "
                     "graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                     namespace.as_tuple + (job.operation_id,))
    fence = _row(db, "SELECT digest,post_graph_revision,post_graph_epoch FROM "
                 "graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?",
                 namespace.as_tuple + (job.operation_id,))
    _need(operation is not None and fence is not None and operation[0] == fence[0]
          and operation[1:3] == (job.activity_id, None),
          "original correction V2 commit is absent; HOLD")
    detail = _read_json(operation[3], "correction receipt").get("source_correction")
    _need(type(detail) is dict and detail.get("request_digest") == policy.request_digest
          and detail.get("correction_source_ref") == policy.correction_source_ref
          and detail.get("source_refs") == list(policy.source_refs)
          and detail.get("invalidated_target_refs") == list(policy.target_refs)
          and detail.get("reevaluation_outbox_ref") == outbox_ref
          and detail.get("audit_event_ref") == job.operation_id
          and detail.get("reevaluation_status") == "pending"
          and detail.get("graph_revision") == fence[1],
          "original correction receipt differs; HOLD")
    heads = tuple(source_correction_head_key(
        namespace, AtomKey.from_token(ref).owner.subject).token
        for ref in policy.source_refs)
    _need(detail.get("correction_head_refs") == list(heads),
          "original correction heads differ; HOLD")
    authority_epochs = _row(db, "SELECT access_epoch,delete_epoch FROM "
                            "graph_authority_epochs WHERE bot=? AND persona=?",
                            namespace.as_tuple)
    _need(authority_epochs == (detail.get("access_epoch"),
                               detail.get("deletion_epoch")),
          "correction access or deletion epoch changed; HOLD")
    _, correction = _atom(db, namespace, policy.correction_source_ref, "memory.source")
    _need(correction.get("text") == policy.statement
          and correction.get("source_kind") == "reported"
          and correction.get("assertion_status") == "reported",
          "original correction source changed; HOLD")
    for source_ref, head_ref in zip(policy.source_refs, heads):
        source_revision, _ = _atom(db, namespace, source_ref, "memory.source")
        _, head = _atom(db, namespace, head_ref, "d06.source_correction_head.v1")
        try:
            validate_source_correction_head(AtomKey.from_token(head_ref), head)
        except (TypeError, ValueError) as exc:
            raise SourceCorrectionJobHold("correction head is invalid; HOLD") from exc
        _need(head == {"source_ref": source_ref,
                       "source_revision": source_revision,
                       "correction_source_ref": policy.correction_source_ref,
                       "target_refs": list(policy.target_refs),
                       "operation_id": job.operation_id,
                       "state": "pending_reevaluation",
                       "access_epoch": detail["access_epoch"],
                       "deletion_epoch": detail["deletion_epoch"]},
              "correction head changed; HOLD")
    job_revision, job_atom = _atom(db, namespace, job_ref, "runtime.job")
    _need(job_atom == job_graph_write(job).value,
          "correction job graph projection differs; HOLD")
    outbox_revision, outbox = _atom(db, namespace, outbox_ref, "runtime.outbox")
    outbox_key = AtomKey.from_token(outbox_ref)
    _need(outbox == {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id,
                     "activity_id": job.activity_id, "operation_id": job.operation_id,
                     "effect_id": None, "outbox_id": outbox_key.name,
                     "job_id": job.job_id, "job_ref": job_ref,
                     "payload_ref": AtomKey.from_token(
                         policy.correction_source_ref).owner.subject,
                     "idempotency_key": "source-correction:" + job.operation_id,
                     "phase": "pending",
                     "dispatch_generation": outbox.get("dispatch_generation")},
          "correction outbox graph identity differs; HOLD")
    ledger = _row(db, "SELECT b.phase,j.job_id,j.operation_id FROM "
                  "graph_bundle_outbox AS b JOIN graph_outbox_jobs AS j "
                  "ON j.bot=b.bot AND j.persona=b.persona AND j.outbox_ref=b.outbox_ref "
                  "WHERE b.bot=? AND b.persona=? AND b.outbox_ref=? "
                  "AND b.operation_id=?", namespace.as_tuple +
                  (outbox_ref, job.operation_id))
    _need(ledger == ("pending", job.job_id, job.operation_id),
          "correction outbox ledger differs; HOLD")
    dependency = _row(db, "SELECT dependency_revision FROM graph_dependencies "
                      "WHERE dependent_token=? AND dependency_token=?",
                      (outbox_ref, job_ref))
    _need(dependency is not None and dependency[0] > 0,
          "correction outbox job dependency is absent; HOLD")
    reservation = _row(db, "SELECT digest,ceiling_json,state,actual_json FROM "
                       "runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                       (job.budget_ref, job.operation_id))
    _need(reservation is not None and reservation[2:] == ("reserved", None)
          and _read_json(reservation[1], "correction reservation")
          == dict(quote.ceiling), "correction budget reservation differs; HOLD")
    reserve_op = _row(db, "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
                      "WHERE bot_id=? AND persona_id=? AND operation_id=? "
                      "AND phase='reserve'", namespace.as_tuple + (job.operation_id,))
    _need(reserve_op is not None and reserve_op[:2]
          == (reservation[0], job.budget_ref),
          "correction budget reserve receipt differs; HOLD")
    budget_receipt = _read_json(reserve_op[2], "correction budget receipt")
    _need((budget_receipt.get("status"), budget_receipt.get("operation_id"),
           budget_receipt.get("digest"), budget_receipt.get("lease_id"))
          == ("reserved", job.operation_id, reservation[0], job.budget_ref),
          "correction budget reserve receipt differs; HOLD")
    graph_revision, graph_epoch, generation = _stamp(db, namespace)
    _need(outbox.get("dispatch_generation") == generation,
          "correction outbox generation changed; HOLD")
    return SourceCorrectionJobSnapshot(
        namespace, job, job_revision, outbox_ref, outbox_revision,
        operation[0], fence[1], policy.request_digest,
        policy.correction_source_ref, policy.source_refs, heads,
        policy.target_refs, quote, reservation[0], graph_revision,
        graph_epoch, generation)


def plan_source_correction_job_acquire(
        snapshot: SourceCorrectionJobSnapshot, holder: str, *,
        now_utc: float, lease_seconds: int) -> PersistentJob:
    """Plan a worker lease without reading content or mutating the database."""
    if type(snapshot) is not SourceCorrectionJobSnapshot:
        raise TypeError("snapshot must be SourceCorrectionJobSnapshot")
    _need(type(now_utc) in (int, float) and math.isfinite(now_utc)
          and now_utc < snapshot.quote.valid_until_utc
          and now_utc < snapshot.quote.deadline_utc,
          "correction acquisition deadline expired; HOLD")
    _need(type(lease_seconds) is int and 1 <= lease_seconds <= 3600,
          "correction worker lease is invalid; HOLD")
    signed_deadline = min(snapshot.quote.valid_until_utc,
                          snapshot.quote.deadline_utc)
    if snapshot.job.phase == "queued":
        _need(now_utc + lease_seconds <= signed_deadline,
              "correction worker lease exceeds signed deadline; HOLD")
    elif snapshot.job.lease_expires_utc is not None:
        _need(datetime.fromisoformat(snapshot.job.lease_expires_utc.replace(
            "Z", "+00:00")).timestamp() <= signed_deadline,
            "correction worker lease exceeds signed deadline; HOLD")
    _need(snapshot.job.phase == "queued" or (
        snapshot.job.phase == "running" and snapshot.job.lease_holder == holder
        and snapshot.job.lease_expires_utc is not None
        and datetime.fromisoformat(snapshot.job.lease_expires_utc.replace(
            "Z", "+00:00")).timestamp() > now_utc),
        "correction worker lease was lost; HOLD")
    now_text = datetime.fromtimestamp(now_utc, timezone.utc).isoformat().replace(
        "+00:00", "Z")
    try:
        return plan_job_acquire(snapshot.job, holder, now_utc=now_text,
                                lease_seconds=lease_seconds)
    except Exception as exc:
        raise SourceCorrectionJobHold("correction job cannot be acquired; HOLD") from exc


def acquire_source_correction_job_in_transaction(
        db: sqlite3.Connection, issuer: D11BudgetJobIssuer,
        snapshot: SourceCorrectionJobSnapshot, scope: FenceScope,
        holder: str, *, fence_holder: str, now_utc: float, lease_seconds: int,
) -> PersistentJob:
    """Acquire only after the caller validated its V2 write permit outside lock.

    The caller must commit the resulting job graph write, V2 fence receipt,
    acquire intent/receipt and business revision atomically in this same
    transaction. Any exception requires rollback. This function intentionally
    leaves the outbox pending and records no actual usage.
    """
    if not db.in_transaction or type(scope) is not FenceScope:
        raise SourceCorrectionJobHold("correction acquire needs V2 write transaction; HOLD")
    _need(scope.operation == "write" and scope.namespace == snapshot.namespace
          and scope.generation == snapshot.activation_generation
          and scope.permit.holder == fence_holder
          and _scope_matches_recovery(db, scope)
          and (scope.graph_revision, scope.graph_epoch.revision)
          == (snapshot.graph_revision, snapshot.graph_epoch),
          "correction V2 write scope differs; HOLD")
    current = read_source_correction_job_snapshot(
        db, issuer, snapshot.namespace, snapshot.job.job_id, now_utc=now_utc)
    _need(current == snapshot, "correction frozen identity changed; HOLD")
    planned = plan_source_correction_job_acquire(
        snapshot, holder, now_utc=now_utc, lease_seconds=lease_seconds)
    acquired = acquire_job(db, snapshot.job.job_id, holder,
                           now_utc=datetime.fromtimestamp(
                               now_utc, timezone.utc).isoformat().replace(
                                   "+00:00", "Z"),
                           lease_seconds=lease_seconds)
    _need(acquired == planned, "correction acquired job differs from plan; HOLD")
    return acquired


__all__ = [
    "SourceCorrectionJobHold", "SourceCorrectionJobSnapshot",
    "read_source_correction_job_snapshot", "plan_source_correction_job_acquire",
    "acquire_source_correction_job_in_transaction",
]
