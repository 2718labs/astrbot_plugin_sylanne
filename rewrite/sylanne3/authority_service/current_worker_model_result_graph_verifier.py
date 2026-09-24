"""Pinned current graph check for a completed first-ingress worker result.

This is a result-release check, not model admission. The original reservation
may already be settled; the completed body still needs a live worker lease,
source permission, and recovery anchor at the moment of release.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, fields
from datetime import datetime
import json
import math
from pathlib import Path
import sqlite3
from typing import Callable

from ..contracts import canonical_json
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime.d11_types import (
    RuntimeOutboxValue, job_graph_write, runtime_job_key, runtime_outbox_key,
)
from ..runtime.encoding_call_binding import (
    CommittedEncodingBaselineV1, binding_to_json, load_binding,
)
from ..runtime.first_ingress_v2 import ingress_ids
from ..runtime.jobs import get_job
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, SourceQualification, canonical_serialize
from .v2_contract import FencePermitV2
from .v2_model_egress_contract import ModelEgressIntentV1
from .current_d04_baseline_graph_proof import committed_baseline_current
from .v2_worker_model_result_contract import WorkerModelResultReadRequestV1
from ..graph_coordinator import NamespaceProvisionReceiptV2


def _canonical(raw: str):
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise ValueError("noncanonical graph value")
    return value


def _utc(value: str) -> float:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("UTC lease required")
    return parsed.timestamp()


class PinnedCurrentWorkerModelResultGraphVerifier:
    """One read-only graph snapshot; no budget-reserved/outbox-pending gate."""

    def __init__(self, graph_db_path: str | Path, *,
                 trusted_now_utc: Callable[[], float],
                 d11_issuer: D11BudgetJobIssuer):
        path = Path(graph_db_path)
        if (not path.is_absolute() or not callable(trusted_now_utc)
                or type(d11_issuer) is not D11BudgetJobIssuer):
            raise ValueError("pinned graph, trusted clock and signed D11 issuer required")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")
        self._clock = trusted_now_utc
        self._issuer = d11_issuer

    def current(self, request: WorkerModelResultReadRequestV1,
                intent: ModelEgressIntentV1, permit: FencePermitV2) -> bool:
        if (type(request) is not WorkerModelResultReadRequestV1
                or type(intent) is not ModelEgressIntentV1
                or type(permit) is not FencePermitV2
                or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.operation_id)
                   != (request.authority_id, request.authority_namespace,
                       request.read_attempt_id)
                or (intent.authority_id, intent.namespace, intent.call_id,
                    intent.job_id, intent.request_digest,
                    intent.operation_id, intent.budget_reservation_operation_id) !=
                   (request.authority_id, request.authority_namespace,
                    request.call_id, request.job_id, request.model_request_digest,
                    request.acquire_operation_id, request.original_operation_id)):
            return False
        try:
            now = self._clock()
            if type(now) not in (int, float) or not math.isfinite(now):
                return False
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return self._check(db, request, intent, permit, float(now))
                finally:
                    db.execute("ROLLBACK")
        except Exception:
            return False

    def _check(self, db: sqlite3.Connection, request: WorkerModelResultReadRequestV1,
               intent: ModelEgressIntentV1, permit: FencePermitV2,
               now: float) -> bool:
        ns = request.namespace.as_tuple
        meta = db.execute(
            "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", ns).fetchone()
        graph_epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (meta is None or meta[0] != "sylanne3.authority.v2"
                or graph_epoch is None or epochs is None):
            return False
        data = _canonical(meta[1])
        if type(data) is not dict or data.get("namespace") != asdict(request.namespace):
            return False
        requirements = SnapshotRequirementsV2(**{
            **data, "namespace": NamespaceId(**data["namespace"])})
        anchor = permit.pinned_anchor
        if (requirements.namespace != request.namespace
                or (requirements.authority_id, requirements.authority_namespace,
                    requirements.activation_generation,
                    requirements.deletion_journal_id, requirements.deletion_seq,
                    requirements.deletion_digest, requirements.execution_journal_id,
                    requirements.execution_seq, requirements.execution_digest,
                    requirements.revocation_epoch) !=
                   (anchor.authority_id, anchor.namespace,
                    anchor.activation_generation, anchor.deletion_journal_id,
                    anchor.deletion_seq, anchor.deletion_digest,
                    anchor.execution_journal_id, anchor.execution_seq,
                    anchor.execution_digest, anchor.revocation_epoch)
                or intent.authority_activation_generation != anchor.activation_generation
                or intent.authority_revocation_epoch != anchor.revocation_epoch
                or intent.authority_deletion_seq != anchor.deletion_seq
                or intent.authority_execution_seq != anchor.execution_seq
                or (intent.access_epoch, intent.delete_epoch) != epochs):
            return False

        job = get_job(db, request.job_id)
        if ((job.bot_id, job.persona_id) != ns
                or job.work_kind != "d06.encode_source"
                or job.operation_id != request.original_operation_id
                or job.phase != "running" or job.effect_id is not None
                or job.result_ref is not None or job.cancel_epoch != 0
                or job.fence != intent.worker_fence
                or job.lease_holder != intent.subject
                or job.lease_holder != permit.subject
                or job.lease_expires_utc is None
                or now >= _utc(job.lease_expires_utc)
                or now >= _utc(job.deadline_utc)):
            return False
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = db.execute(
            "SELECT value,valid FROM graph_atoms WHERE token=?", (job_key.token,)
        ).fetchone()
        if (job_atom is None or job_atom[1] != 1
                or _canonical(job_atom[0]) != job_graph_write(job).value):
            return False

        binding = load_binding(db, request.namespace, job.job_id)
        if (binding is None
                or (binding.call_id, binding.binding_digest,
                    binding.model_request_digest,
                    binding.budget_reservation_operation_id) !=
                   (request.call_id, request.binding_digest,
                    request.model_request_digest, request.original_operation_id)
                or binding.source_id not in intent.source_refs
                or binding.source_revision != intent.source_revisions[0][1]
                or binding.access_revision != intent.access_revisions[0][1]
                or binding.budget_lease_id != intent.budget_lease_id):
            return False
        frozen = binding.request
        authority = frozen["envelope"]["authority"]
        audience = authority["audience"]
        if (frozen["schema"] not in {
                    "sylanne.first-ingress-encoding-call.v2",
                    "sylanne.first-ingress-encoding-call.v3"}
                or frozen["acquire_operation_id"] != request.acquire_operation_id
                or frozen["original_operation_id"] != request.original_operation_id
                or frozen["envelope"]["identity"]["operation_id"]
                   != request.acquire_operation_id
                or frozen["worker_fence"] != job.fence
                or frozen["worker_lease_expires_utc"] != job.lease_expires_utc
                or authority["actor"] != intent.subject
                or authority["worker_fence"] != job.fence
                or authority["purpose"] != "consolidation"
                or type(audience) is not list or not audience
                or any(type(item) is not str or not item for item in audience)):
            return False
        acquire = db.execute(
            "SELECT i.job_id,i.original_operation_id,i.actor,i.encoding_binding_json,"
            "r.job_json,i.requirements_json FROM graph_job_acquire_intents_v2 AS i "
            "JOIN graph_job_acquire_receipts_v2 AS r ON "
            "r.bot=i.bot AND r.persona=i.persona "
            "AND r.acquire_operation_id=i.acquire_operation_id "
            "WHERE i.bot=? AND i.persona=? AND i.acquire_operation_id=?",
            ns + (request.acquire_operation_id,),
        ).fetchall()
        if len(acquire) != 1:
            return False
        acquired_job = _canonical(acquire[0][4])
        acquire_requirements = _canonical(acquire[0][5])
        if (acquire[0][:4] != (job.job_id, job.operation_id,
                              job.lease_holder, binding_to_json(binding))
                or acquired_job.get("job_id") != job.job_id
                or acquired_job.get("fence") != job.fence
                or acquired_job.get("lease_holder") != job.lease_holder
                or acquired_job.get("lease_expires_utc") != job.lease_expires_utc
                or acquire_requirements.get("graph_incarnation")
                   != requirements.graph_incarnation
                or acquire_requirements.get("authority_id") != anchor.authority_id
                or acquire_requirements.get("authority_namespace") != anchor.namespace
                or acquire_requirements.get("activation_generation")
                   != anchor.activation_generation):
            return False
        if frozen["schema"] == "sylanne.first-ingress-encoding-call.v3":
            baseline = CommittedEncodingBaselineV1(**frozen["baseline"])
            acquire_stamp = db.execute(
                "SELECT graph_revision,graph_epoch FROM "
                "graph_job_acquire_intents_v2 WHERE bot=? AND persona=? "
                "AND acquire_operation_id=?",
                ns + (request.acquire_operation_id,),
            ).fetchone()
            if acquire_stamp is None:
                return False
            if not committed_baseline_current(
                    db, namespace=request.namespace, baseline=baseline,
                    source_id=binding.source_id, requirements=requirements,
                    current_graph_revision=meta[2],
                    current_graph_epoch=graph_epoch[0],
                    acquire_graph_revision=acquire_stamp[0],
                    acquire_graph_epoch=acquire_stamp[1],
                    issuer=self._issuer):
                return False
        original = db.execute(
            "SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (job.operation_id,),
        ).fetchone()
        _, expected_activity, expected_operation, expected_job, expected_outbox, expected_key = (
            ingress_ids(binding.source_id))
        outbox_key = runtime_outbox_key(*ns, job.activity_id, expected_outbox)
        if (original is None or original[:2] != (job.activity_id, None)
                or (job.activity_id, job.operation_id, job.job_id) !=
                   (expected_activity, expected_operation, expected_job)):
            return False
        original_receipt = _canonical(original[2])
        if (job_key.token not in original_receipt.get("ledger_refs", ())
                or outbox_key.token not in original_receipt.get("outbox_refs", ())):
            return False
        original_outbox_rows = db.execute(
            "SELECT value FROM graph_history WHERE token=? AND valid=1 "
            "AND event_bot=? AND event_persona=? AND event_session=? "
            "AND event_id=?",
            (outbox_key.token, *ns, job.activity_id, job.operation_id),
        ).fetchall()
        if len(original_outbox_rows) != 1:
            return False
        outbox = RuntimeOutboxValue(**_canonical(original_outbox_rows[0][0]))
        if ((outbox.bot_id, outbox.persona_id, outbox.activity_id,
             outbox.operation_id, outbox.effect_id, outbox.outbox_id,
             outbox.job_id, outbox.job_ref, outbox.payload_ref,
             outbox.idempotency_key) !=
            (*ns, job.activity_id, job.operation_id, None, expected_outbox,
             job.job_id, job_key.token, binding.source_id, expected_key)
                or outbox.phase != "pending"):
            return False
        if db.execute(
            "SELECT 1 FROM runtime_encoding_call_redactions_v1 "
            "WHERE bot=? AND persona=? AND (call_id=? OR source_id=?) LIMIT 1",
            ns + (request.call_id, binding.source_id),
        ).fetchone() is not None:
            return False

        quote_ref = job.operator_versions.get("resource_quote")
        if type(quote_ref) is not str or ":" not in quote_ref:
            return False
        original_quote_fence = job.fence
        if frozen["schema"] == "sylanne.first-ingress-encoding-call.v3":
            original_job_rows = db.execute(
                "SELECT value FROM graph_history WHERE token=? AND valid=1 "
                "AND event_bot=? AND event_persona=? AND event_session=? "
                "AND event_id=?",
                (job_key.token, *ns, job.activity_id, job.operation_id),
            ).fetchall()
            if len(original_job_rows) != 1:
                return False
            original_job = _canonical(original_job_rows[0][0])
            if (original_job.get("job_id") != job.job_id
                    or original_job.get("operation_id") != job.operation_id
                    or original_job.get("phase") != "queued"
                    or original_job.get("fence") != 0):
                return False
            # The signed quote belongs to the queued original ingress, before
            # the acquire raised the live worker fence to its current value.
            original_quote_fence = None
        quote_id, quote_version = quote_ref.rsplit(":", 1)
        quote = self._issuer.resource_issuer.original_signed_quote(
            db, quote_id, int(quote_version))
        issuance = db.execute(
            "SELECT activation_generation,quote_id,grant_id "
            "FROM runtime_ingress_issuance WHERE bot=? AND persona=? "
            "AND operation_id=?", ns + (job.operation_id,),
        ).fetchone()
        provision_row = db.execute(
            "SELECT operation_id,digest,receipt_json "
            "FROM graph_namespace_provisioning_v2 WHERE bot=? AND persona=?",
            ns,
        ).fetchone()
        if provision_row is None:
            return False
        provision = _canonical(provision_row[2])
        if (type(provision) is not dict
                or set(provision) != {field.name for field in fields(NamespaceProvisionReceiptV2)}):
            return False
        provision_receipt = NamespaceProvisionReceiptV2(
            **{**provision, "namespace": NamespaceId(**provision["namespace"])})
        if canonical_json(asdict(provision_receipt)) != provision_row[2]:
            return False
        grant, signature = self._issuer.signed_budget_grant_at_version(
            db, provision["root_lease_id"], provision["root_grant_version"])
        if (provision["operation_id"] != provision_row[0]
                or provision["input_digest"] != provision_row[1]
                or provision["namespace"] != asdict(request.namespace)
                or provision["installation_id"] != request.installation_id
                or provision["authority_id"] != anchor.authority_id
                or provision["authority_namespace"] != anchor.namespace
                or provision["generation"] != anchor.activation_generation
                or provision["graph_incarnation"] != requirements.graph_incarnation
                or issuance != (anchor.activation_generation, quote_id, grant.grant_id)
                or (provision["root_lease_id"], provision["root_grant_id"],
                    provision["root_grant_signature"]) !=
                   (job.budget_ref, grant.grant_id, signature)
                or (grant.bot_id, grant.persona_id, grant.lease_id) !=
                   (*ns, job.budget_ref)
                or job.work_kind not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(name, 0)
                       for name, amount in quote.ceiling.items())
                or (quote.bot_id, quote.persona_id, quote.activity_id,
                    quote.operation_id, quote.effect_id,
                    quote.parent_budget_lease_ref, quote.work_kind,
                    quote.snapshot_ref, quote.resource_ref,
                    quote.required_worker_fence,
                    quote.graph_job_ref, quote.outbox_refs) !=
                   (*ns, job.activity_id, job.operation_id, None,
                    job.budget_ref, job.work_kind, job.snapshot_ref,
                    job.resource_ref, original_quote_fence, job_key.token,
                    (outbox_key.token,))
                or dict(quote.ceiling) != dict(intent.budget_ceiling)):
            return False
        reservation = db.execute(
            "SELECT digest,ceiling_json FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id),
        ).fetchone()
        if reservation != (intent.budget_reservation_digest,
                           canonical_json(dict(intent.budget_ceiling))):
            return False
        reserve_receipt = db.execute(
            "SELECT digest FROM runtime_budget_operations WHERE bot_id=? "
            "AND persona_id=? AND operation_id=? AND phase='reserve'",
            ns + (job.operation_id,),
        ).fetchone()
        if reserve_receipt != (intent.budget_reservation_digest,):
            return False
        qualification_row = db.execute(
            "SELECT source_qualification_json FROM runtime_ingress_issuance "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (job.operation_id,),
        ).fetchone()
        if qualification_row is None or qualification_row[0] is None:
            return False
        qualification_data = _canonical(qualification_row[0])
        qualification = SourceQualification(**{
            **qualification_data,
            "source_refs": tuple(qualification_data["source_refs"]),
        })
        if (canonical_serialize(asdict(qualification)) != qualification_row[0]
                or json.loads(canonical_serialize(qualification))
                   != frozen["envelope"]["source_qualification"]
                or qualification.source_refs != (source_token := source_key(*ns, binding.source_id).token,)):
            return False

        if (intent.source_refs != (binding.source_id,)
                or intent.source_revisions != ((binding.source_id,
                                                binding.source_revision),)
                or intent.access_revisions != ((binding.source_id,
                                                binding.access_revision),)):
            return False
        access_token = access_key(*ns, binding.source_id).token
        source_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (source_token,),).fetchone()
        access_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (access_token,),).fetchone()
        dependency = db.execute(
            "SELECT dependency_revision FROM graph_dependencies WHERE "
            "dependent_token=? AND dependency_token=?",
            (access_token, source_token),).fetchone()
        if (source_row is None or access_row is None
                or source_row[2] != 1 or access_row[2] != 1
                or source_row[0] != binding.source_revision
                or access_row[0] != binding.access_revision
                or dependency != (source_row[0],)):
            return False
        source = SourceRecord.from_dict(_canonical(source_row[1]))
        access = _canonical(access_row[1])
        validate_access(access)
        return (source.source_id == binding.source_id
                and access["source_id"] == binding.source_id
                and access["status"] == "active"
                and "consolidation" in source.purposes
                and "consolidation" in access["purposes"]
                and set(audience).issubset(source.audiences)
                and set(audience).issubset(access["audiences"]))


__all__ = ("PinnedCurrentWorkerModelResultGraphVerifier",)
