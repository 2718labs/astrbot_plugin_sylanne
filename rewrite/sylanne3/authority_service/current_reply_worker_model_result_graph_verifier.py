"""Pinned current graph check for post-C02 reply model result release."""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
from datetime import datetime
import json
import math
from pathlib import Path
import sqlite3
from typing import Callable

from ..contracts import canonical_json
from ..domains.d07 import AttentionTicket, D07DomainProvider, FocusState
from ..graph_types import AtomKey, Owner
from ..graph_store import GraphStore
from ..memory_types import SourceRecord, access_key, validate_access
from ..runtime.d11_types import job_graph_write, runtime_job_key
from ..runtime.budget import get_budget_lease
from ..runtime.jobs import get_job
from ..runtime.ingress_observation import read_committed_ingress_identity
from ..runtime.reply_model_job import reply_envelope_from_wire_v1
from ..runtime.issuers import D11BudgetJobIssuer, d06_first_ingress_c02_quote_id
from ..runtime_contracts import (
    CommitReceipt, NamespaceEpoch, NamespaceId, SnapshotRequirementsV2,
    canonical_digest, canonical_serialize,
)
from .v2_contract import FencePermitV2
from .v2_model_egress_contract import ModelEgressIntentV1
from .v2_reply_worker_model_result_contract import ReplyWorkerModelResultReadRequestV1


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


class PinnedCurrentReplyWorkerModelResultGraphVerifier:
    """Read-only graph admission; missing producer proof keeps result HOLD."""

    _PREPARATION_TABLE = "graph_post_c02_reply_model_preparations_v1"

    def __init__(self, graph_db_path: str | Path, *,
                 trusted_now_utc: Callable[[], float],
                 d11_issuer: D11BudgetJobIssuer):
        path = Path(graph_db_path)
        if (not path.is_absolute() or not callable(trusted_now_utc)
                or type(d11_issuer) is not D11BudgetJobIssuer):
            raise ValueError("pinned graph, clock and signed D11 issuer required")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")
        self._clock = trusted_now_utc
        self._issuer = d11_issuer

    def current(self, request: ReplyWorkerModelResultReadRequestV1,
                intent: ModelEgressIntentV1, permit: FencePermitV2) -> bool:
        if (type(request) is not ReplyWorkerModelResultReadRequestV1
                or type(intent) is not ModelEgressIntentV1
                or type(permit) is not FencePermitV2
                or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.operation_id)
                   != (request.authority_id, request.authority_namespace,
                       request.read_attempt_id)):
            return False
        try:
            # This check is structural only. The original intent is loaded by
            # Authority's result store, never accepted from the RPC caller.
            if (intent.authority_id, intent.namespace, intent.job_id,
                intent.operation_id, intent.budget_reservation_operation_id,
                intent.call_id, intent.request_digest, intent.binding_digest) != (
                    request.authority_id, request.authority_namespace,
                    request.job_id, request.acquire_operation_id,
                    request.original_operation_id, request.call_id,
                    request.model_request_digest, request.binding_digest):
                return False
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

    def _check(self, db: sqlite3.Connection,
               request: ReplyWorkerModelResultReadRequestV1,
               intent: ModelEgressIntentV1, permit: FencePermitV2,
               now: float) -> bool:
        ns = request.namespace.as_tuple
        if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (self._PREPARATION_TABLE,)).fetchone() is None:
            return False
        meta = db.execute(
            "SELECT schema,requirements_json FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", ns).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if meta is None or meta[0] != "sylanne3.authority.v2" or epochs is None:
            return False
        data = _canonical(meta[1])
        if type(data) is not dict or data.get("namespace") != asdict(request.namespace):
            return False
        requirements = SnapshotRequirementsV2(**{
            **data, "namespace": NamespaceId(**data["namespace"])})
        anchor = permit.pinned_anchor
        if (requirements.authority_id, requirements.authority_namespace,
            requirements.activation_generation, requirements.deletion_journal_id,
            requirements.deletion_seq, requirements.deletion_digest,
            requirements.execution_journal_id, requirements.execution_seq,
            requirements.execution_digest, requirements.revocation_epoch) != (
                anchor.authority_id, anchor.namespace,
                anchor.activation_generation, anchor.deletion_journal_id,
                anchor.deletion_seq, anchor.deletion_digest,
                anchor.execution_journal_id, anchor.execution_seq,
                anchor.execution_digest, anchor.revocation_epoch):
            return False
        if (intent.authority_activation_generation != anchor.activation_generation
                or intent.authority_revocation_epoch != anchor.revocation_epoch
                or (intent.access_epoch, intent.delete_epoch) != epochs):
            return False
        job = get_job(db, request.job_id)
        if ((job.bot_id, job.persona_id) != ns
                or job.work_kind != "reply" or job.phase != "running"
                or job.operation_id != request.original_operation_id
                or job.fence != intent.worker_fence
                or job.lease_holder != intent.subject
                or job.lease_holder != permit.subject
                or job.cancel_epoch != 0 or job.result_ref is not None
                or job.lease_expires_utc is None
                or now >= _utc(job.lease_expires_utc)
                or now >= _utc(job.deadline_utc)):
            return False
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,)).fetchone()
        if (job_row is None or job_row[2] != 1
                or _canonical(job_row[1]) != job_graph_write(job).value):
            return False
        source_key = AtomKey.from_token(request.source_ref)
        source_id = source_key.owner.subject
        source_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (request.source_ref,)).fetchone()
        access_token = access_key(*ns, source_id).token
        access_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (access_token,)).fetchone()
        dependency = db.execute(
            "SELECT dependency_revision FROM graph_dependencies WHERE "
            "dependent_token=? AND dependency_token=?",
            (access_token, request.source_ref)).fetchone()
        if (source_row is None or access_row is None
                or source_row[2] != 1 or access_row[2] != 1
                or source_row[0] != request.source_revision
                or access_row[0] != request.access_revision
                or dependency != (source_row[0],)):
            return False
        source = SourceRecord.from_dict(_canonical(source_row[1]))
        access = _canonical(access_row[1])
        validate_access(access)
        if (source.source_id != source_id or access["source_id"] != source_id
                or access["status"] != "active"
                or "expression" not in source.purposes
                or "expression" not in access["purposes"]
                or not set(request.audience) <= set(source.audiences)
                or not set(request.audience) <= set(access["audiences"])):
            return False
        ingress = read_committed_ingress_identity(
            db, request.namespace, source_id)
        identity = _canonical(ingress.identity_json) if ingress is not None else None
        if (identity is None or identity["visibility"] != "private"
                or request.audience != (identity["conversation_ref"],)):
            return False
        focus_key = AtomKey(Owner("persona", *ns), "d07.focus.v1",
                            request.namespace.persona_id)
        ticket_key = AtomKey(Owner("persona", *ns),
                             "d07.attention_ticket.v1", request.attention_ticket_id)
        focus_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (focus_key.token,)).fetchone()
        ticket_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (ticket_key.token,)).fetchone()
        if (focus_row is None or ticket_row is None
                or focus_row[2] != 1 or ticket_row[2] != 1
                or focus_row[0] != request.focus_revision):
            return False
        focus_value = _canonical(focus_row[1])
        ticket_value = _canonical(ticket_row[1])
        types = {spec.name: spec for spec in D07DomainProvider.type_specs()}
        types["d07.focus.v1"].validator(focus_value)
        types["d07.attention_ticket.v1"].validator(ticket_value)
        focus = FocusState(**{
            **{key: value for key, value in focus_value.items() if key != "schema"},
            "auxiliary_ticket_refs": tuple(focus_value["auxiliary_ticket_refs"]),
        })
        ticket = AttentionTicket(**{
            **{key: value for key, value in ticket_value.items() if key != "schema"},
            "cancel_refs": tuple(ticket_value["cancel_refs"]),
            "source_refs": tuple(ticket_value["source_refs"]),
        })
        if (focus.persona_id != request.namespace.persona_id
                or focus.primary_ticket_ref != ticket_key.token
                or ticket.ticket_id != request.attention_ticket_id
                or ticket.category != "interaction"
                or ticket.causal_root != request.source_ref
                or ticket.source_refs != (request.source_ref,)
                or ticket.valid_until <= now or not ticket.eligible
                or not ticket.resources_available or ticket.cancel_refs):
            return False
        original = db.execute(
            "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
            "FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (request.c02_operation_id,)).fetchone()
        if original is None:
            return False
        event = db.execute(
            "SELECT reads,revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (original[1], request.c02_operation_id),).fetchone()
        if event is None:
            return False
        detail = _canonical(original[4])
        c02_receipt = CommitReceipt(
            "committed", request.c02_operation_id, original[0], original[1],
            original[2], original[3], GraphStore._version_rows(event[0]),
            GraphStore._version_rows(event[1]),
            (NamespaceEpoch(*ns, event[2]),), tuple(detail["ledger_refs"]),
            tuple(detail["outbox_refs"]))
        writes = {}
        for item in c02_receipt.write_versions:
            key = item.key
            if key.type_name in {"memory.episode.v1", "memory.subjective_trace.v2"}:
                if key.type_name in writes:
                    return False
                writes[key.type_name] = (key, item.revision)
        if set(writes) != {"memory.episode.v1", "memory.subjective_trace.v2"}:
            return False
        if any(db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (key.token,),
            ).fetchone() != (revision, 1)
            for key, revision in writes.values()):
            return False
        episode_key, episode_revision = writes["memory.episode.v1"]
        episode = db.execute(
            "SELECT revision,value,valid FROM graph_history WHERE token=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (episode_key.token, *ns, original[1], request.c02_operation_id),
        ).fetchall()
        if (len(episode) != 1 or episode[0][0] != episode_revision
                or episode[0][2] != 1
                or request.source_ref not in _canonical(episode[0][1]).get(
                    "source_refs", ())):
            return False
        archive = db.execute(
            "SELECT schema,bundle_digest,evidence_json,quote_json FROM "
            "graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? "
            "AND operation_id=?", ns + (request.c02_operation_id,),
        ).fetchone()
        cost_attempt = db.execute(
            "SELECT state FROM graph_c02_cost_attempts_v1 WHERE bot=? "
            "AND persona=? AND operation_id=?",
            ns + (request.c02_operation_id,),
        ).fetchone()
        cost_operation_id = "c02-cost-" + canonical_digest({
            "namespace": list(ns), "operation_id": request.c02_operation_id,
        })[:48]
        cost = db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? "
            "AND persona=? AND operation_id=?",
            ns + (cost_operation_id,),
        ).fetchone()
        c02_quote = self._issuer.resource_issuer.original_signed_quote(
            db, d06_first_ingress_c02_quote_id(
                request.namespace, request.c02_operation_id), 1)
        c02_reservation = db.execute(
            "SELECT state FROM runtime_budget_reservations WHERE lease_id=? "
            "AND operation_id=?",
            (c02_quote.parent_budget_lease_ref, request.c02_operation_id),
        ).fetchone()
        c02_settled = db.execute(
            "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? "
            "AND persona_id=? AND operation_id=? AND phase='settle'",
            ns + (request.c02_operation_id,),
        ).fetchone()
        if (archive is None or archive[0] != "sylanne.first-ingress-c02-candidate.v2"
                or archive[1] != original[0]
                or _canonical(archive[2]).get("source_ref") != source_id
                or archive[3] != canonical_serialize(asdict(c02_quote))
                or cost_attempt != ("committed",) or cost is None
                or c02_reservation is None
                or c02_reservation[0] not in {"unknown", "settled", "overrun"}
                or c02_settled is None):
            return False
        cost_detail = _canonical(cost[0])
        if (cost_detail.get("original_operation_id") != request.c02_operation_id
                or not cost_detail.get("cost_ref")
                or db.execute(
                    "SELECT 1 FROM graph_atoms WHERE token=? AND valid=1",
                    (cost_detail["cost_ref"],),
                ).fetchone() is None):
            return False
        preparation = db.execute(
            "SELECT original_operation_id,job_id,activity_id,c02_receipt_digest,"
            "source_id,source_revision,access_revision,attention_ticket_id,"
            "focus_revision,audience,quote_id,quote_version,reservation_digest,"
            "deadline_utc,graph_job_ref,graph_job_revision,state,"
            "acquire_operation_id,actor,worker_fence,call_id,"
            "model_request_digest,binding_digest,envelope_json,request_json "
            "FROM graph_post_c02_reply_model_preparations_v1 "
            "WHERE bot=? AND persona=? AND c02_operation_id=? AND source_ref=?",
            ns + (request.c02_operation_id, request.source_ref),
        ).fetchone()
        if preparation is None:
            return False
        (original_operation_id, job_id, activity_id, c02_digest,
         row_source_id, source_revision, access_revision, ticket_id,
         focus_revision, audience, quote_id, quote_version, reservation_digest,
         deadline_utc, graph_job_ref, graph_job_revision, state,
         acquire_operation_id, actor, worker_fence, call_id,
         model_request_digest, binding_digest, envelope_json,
         request_json) = preparation
        c02_fields = asdict(c02_receipt)
        if ((original_operation_id, job_id, activity_id, c02_digest,
             row_source_id, source_revision, access_revision, ticket_id,
             focus_revision, audience, graph_job_ref, graph_job_revision,
             state, acquire_operation_id, actor, worker_fence, call_id,
             model_request_digest, binding_digest) !=
            (request.original_operation_id, request.job_id, job.activity_id,
             canonical_digest(c02_fields), source_id, request.source_revision,
             request.access_revision, request.attention_ticket_id,
             request.focus_revision, request.audience[0], job_key.token,
             job_row[0], "acquired", request.acquire_operation_id,
             intent.subject, intent.worker_fence, request.call_id,
             request.model_request_digest, request.binding_digest)
                or len(request.audience) != 1
                or type(deadline_utc) not in (int, float)
                or job.operator_versions.get("resource_quote")
                   != f"{quote_id}:{quote_version}"):
            return False
        acquired_history = db.execute(
            "SELECT revision,value,valid FROM graph_history WHERE token=? "
            "AND event_bot=? AND event_persona=? AND event_session=? "
            "AND event_id=?",
            (job_key.token, *ns, job.activity_id, acquire_operation_id),
        ).fetchall()
        queued_history = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? "
            "AND event_bot=? AND event_persona=? AND event_session=? "
            "AND event_id=?",
            (job_key.token, *ns, job.activity_id, original_operation_id),
        ).fetchall()
        if (len(acquired_history) != 1
                or acquired_history[0] != (job_row[0], job_row[1], 1)
                or len(queued_history) != 1 or queued_history[0][1] != 1
                or _canonical(queued_history[0][0]).get("phase") != "queued"):
            return False
        acquire = db.execute(
            "SELECT state FROM graph_post_c02_reply_model_acquires_v1 "
            "WHERE bot=? AND persona=? AND acquire_operation_id=? "
            "AND original_operation_id=?",
            ns + (acquire_operation_id, original_operation_id),
        ).fetchone()
        if acquire != ("committed",):
            return False
        quote = self._issuer.resource_issuer.original_signed_quote(
            db, quote_id, quote_version)
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, original_operation_id),).fetchone()
        reserve_receipt = db.execute(
            "SELECT digest FROM runtime_budget_operations WHERE bot_id=? "
            "AND persona_id=? AND operation_id=? AND phase='reserve'",
            ns + (original_operation_id,),).fetchone()
        if ((quote.bot_id, quote.persona_id, quote.activity_id,
             quote.operation_id, quote.effect_id,
             quote.parent_budget_lease_ref, quote.work_kind,
             quote.snapshot_ref, quote.resource_ref, quote.graph_job_ref,
             quote.outbox_refs, quote.d02_settlement_refs,
             quote.required_worker_fence, quote.deadline_utc,
             quote.valid_until_utc) !=
            (*ns, job.activity_id, original_operation_id, None,
             job.budget_ref, "reply", job.snapshot_ref, job.resource_ref,
             job_key.token, (), (), None, deadline_utc, deadline_utc)
                or quote.version != quote_version or quote.ceiling != dict(intent.budget_ceiling)
                or lease.state != "active"
                or (lease.bot_id, lease.persona_id) != ns
                or (grant.bot_id, grant.persona_id, grant.lease_id)
                   != (*ns, job.budget_ref)
                or grant.valid_until_utc <= now
                or any(lease.reserved.get(name, 0) < amount
                       for name, amount in quote.ceiling.items())
                or "reply" not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(name, 0)
                       for name, amount in quote.ceiling.items())
                or reservation != (reservation_digest,
                                   canonical_json(dict(quote.ceiling)), "reserved")
                or reserve_receipt != (reservation_digest,)
                or reservation_digest != canonical_digest({
                    "schema": "sylanne.post-c02-reply-budget-reservation.v1",
                    "original_operation_id": original_operation_id,
                    "quote": asdict(quote), "c02_receipt": c02_fields,
                })
                or reservation_digest != intent.budget_reservation_digest):
            return False
        if type(envelope_json) is not str or type(request_json) is not str:
            return False
        envelope = reply_envelope_from_wire_v1(envelope_json)
        if (_canonical(canonical_serialize(asdict(envelope)))
                != _canonical(request_json).get("envelope")):
            return False
        frozen = _canonical(request_json)
        authority = frozen["envelope"]["authority"]
        if (frozen["call_id"] != request.call_id
                or frozen["envelope"]["identity"]["operation_id"]
                   != request.acquire_operation_id
                or authority["actor"] != intent.subject
                or authority["worker_fence"] != intent.worker_fence
                or tuple(authority["audience"]) != request.audience
                or authority["purpose"] != "proposal"
                or frozen["max_output_tokens"] != intent.max_output_tokens
                or frozen["provider_id"] != intent.provider_id
                or frozen["model_id"] != intent.model_id):
            return False
        computed_request_digest = canonical_digest({
            "envelope": envelope, "call_id": frozen["call_id"],
            "provider_id": frozen["provider_id"],
            "model_id": frozen["model_id"],
            "purpose": authority["purpose"],
            "required_capabilities": frozen["required_capabilities"],
            "privacy_tier": frozen["privacy_tier"],
            "template": frozen["prompt_template_digest"],
            "payload": frozen["payload"],
            "timeout_seconds": float(frozen["timeout_seconds"]),
            "max_output_tokens": frozen["max_output_tokens"],
        })
        computed_binding_digest = canonical_digest({
            "schema": "sylanne.post-c02-reply-model-binding.v1",
            "job_id": job.job_id,
            "original_operation_id": job.operation_id,
            "acquire_operation_id": acquire_operation_id,
            "worker_fence": job.fence,
            "source_ref": request.source_ref,
            "source_revision": source_revision,
            "access_revision": access_revision,
            "attention_ticket_id": ticket_id,
            "focus_revision": focus_revision,
            "call_id": call_id,
            "request_digest": computed_request_digest,
        })
        return (computed_request_digest == request.model_request_digest
                and computed_binding_digest == request.binding_digest)


__all__ = ["PinnedCurrentReplyWorkerModelResultGraphVerifier"]
