"""Immutable pre-call D13 paid identity, recorded only by a fenced W01 writer.

This store does not issue a paid job, select the live model, or admit egress.
The caller must supply a current Owner/graph fence and a host-selected model;
the original D02/D11 signatures and reserved budget are re-read here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import json
import sqlite3

from ..authority_service.v2_model_egress_wire import (
    from_wire as model_from_wire, to_wire as model_to_wire,
)
from ..domains.d13.paid_lifecycle import (
    D13PaidOriginalBindingV1, bind_paid_original_v1,
)
from ..model_broker.d13_precompression import (
    D13ExactTokenCountV1, D13PrecompressionInstallationV1,
    FrozenD13PrecompressionRequestV1, freeze_d13_precompression_request_v1,
    gate_d13_exact_token_count_v1,
    issue_unadmitted_d13_model_request_v1,
    thaw_d13_precompression_request_v1,
)
from ..model_broker.broker import ModelCallRequest
from ..runtime_contracts import (
    ConversationWindowProjectionV1, NamespaceId, canonical_digest,
    canonical_serialize,
)
from .budget import get_budget_lease
from .d11_types import runtime_job_key
from .issuers import D02ResourceIssuer, D11BudgetGrantIssuer
from .jobs import get_job

PAID_WORK_KIND = "d13.precompress.paid.v1"


@dataclass(frozen=True, slots=True)
class D13PaidIntentOriginalV1:
    namespace: NamespaceId
    binding: D13PaidOriginalBindingV1
    frozen_json: str
    exact_count: D13ExactTokenCountV1 | None
    job_digest: str
    quote_id: str
    quote_version: int
    quote_digest: str
    grant_id: str
    grant_version: int
    grant_digest: str
    budget_operation_id: str
    budget_reservation_digest: str
    ceiling: dict[str, int]
    access_epoch: int
    delete_epoch: int
    activation_epoch: int
    original_digest: str


@dataclass(frozen=True, slots=True)
class D13PaidCallOriginalV1:
    """The first acquired worker's exact immutable Authority request wire."""

    namespace: NamespaceId
    job_ref: str
    binding_digest: str
    intent_original_digest: str
    request_json: str
    request_digest: str
    worker_fence: int
    original_digest: str


def install_d13_paid_intent_original_v1(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d13_paid_intent_originals_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, job_ref TEXT NOT NULL,
        operation_id TEXT NOT NULL, original_json TEXT NOT NULL,
        original_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,job_ref),
        UNIQUE(bot,persona,operation_id)
    )""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_d13_paid_intent_no_{action.lower()}_v1
            BEFORE {action} ON graph_d13_paid_intent_originals_v1
            BEGIN SELECT RAISE(ABORT, 'D13 paid intent is immutable'); END""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d13_paid_call_originals_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, job_ref TEXT NOT NULL,
        call_id TEXT NOT NULL, original_json TEXT NOT NULL,
        original_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,job_ref),
        UNIQUE(bot,persona,call_id)
    )""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_d13_paid_call_no_{action.lower()}_v1
            BEFORE {action} ON graph_d13_paid_call_originals_v1
            BEGIN SELECT RAISE(ABORT, 'D13 paid call is immutable'); END""")


def _verified_original(
    db: sqlite3.Connection, namespace: NamespaceId,
    frozen: FrozenD13PrecompressionRequestV1,
    binding: D13PaidOriginalBindingV1,
    exact_count: D13ExactTokenCountV1 | None,
    selected_main: D13PrecompressionInstallationV1,
    current_window: ConversationWindowProjectionV1,
    *, quote_id: str, quote_version: int, budget_operation_id: str,
    resource_issuer: D02ResourceIssuer, budget_issuer: D11BudgetGrantIssuer,
) -> D13PaidIntentOriginalV1:
    if (type(namespace) is not NamespaceId or
            type(frozen) is not FrozenD13PrecompressionRequestV1 or
            type(binding) is not D13PaidOriginalBindingV1 or
            type(selected_main) is not D13PrecompressionInstallationV1 or
            type(current_window) is not ConversationWindowProjectionV1 or
            type(resource_issuer) is not D02ResourceIssuer or
            not isinstance(budget_issuer, D11BudgetGrantIssuer)):
        raise ValueError("typed installed paid originals required")
    if (namespace != frozen.window.namespace or
            current_window != frozen.window or
            selected_main != frozen.installation or
            frozen != freeze_d13_precompression_request_v1(
                frozen.window, frozen.plan, selected_main) or
            binding != bind_paid_original_v1(
                frozen, original_operation_id=binding.original_operation_id,
                call_id=binding.call_id) or
            gate_d13_exact_token_count_v1(frozen, exact_count).status != "ready"):
        raise ValueError("selected model, frozen wire, or optional count changed")
    job = get_job(db, binding.job_ref)
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if epochs != (current_window.access_epoch, current_window.delete_epoch):
        raise ValueError("D13 current rights epochs changed")
    if (job.work_kind != PAID_WORK_KIND or
            job.phase != "queued" or
            (job.bot_id, job.persona_id) != namespace.as_tuple or
            job.operation_id != binding.original_operation_id or
            job.continuation.get("binding_digest") != binding.binding_digest or
            job.continuation.get("frozen_input_digest") != frozen.digest or
            job.continuation.get("wire_digest") != frozen.wire_digest or
            job.continuation.get("read_closure_digest") != frozen.read_closure_digest):
        raise ValueError("independent paid job original differs")
    quote = resource_issuer.original_signed_quote(db, quote_id, quote_version)
    grant = budget_issuer.current_budget_grant(db, job.budget_ref)
    lease = get_budget_lease(db, job.budget_ref)
    ceiling = dict(quote.ceiling)
    if (quote.work_kind != PAID_WORK_KIND or
            quote.operation_id != job.operation_id or
            budget_operation_id != quote.operation_id or
            quote.activity_id != job.activity_id or
            quote.graph_job_ref is None or
            quote.graph_job_ref != runtime_job_key(
                *namespace.as_tuple, job.activity_id, job.job_id).token or
            quote.parent_budget_lease_ref != job.budget_ref or
            quote.resource_ref != job.resource_ref or
            (quote.bot_id, quote.persona_id) != namespace.as_tuple or
            grant.lease_id != job.budget_ref or
            (grant.bot_id, grant.persona_id) != namespace.as_tuple or
            PAID_WORK_KIND not in grant.allowed_work_kinds or
            any(amount > grant.max_ceiling.get(dimension, 0)
                for dimension, amount in ceiling.items()) or
            ceiling.get("output_tokens", 0) < selected_main.max_output_tokens or
            (ceiling.get("input_tokens", 0) <= 0 and
             ceiling.get("model_tokens", 0) <= selected_main.max_output_tokens) or
            lease.state != "active" or lease.currency != grant.currency or
            grant.valid_until_utc <= frozen.window.trusted_utc or
            quote.valid_until_utc <= frozen.window.trusted_utc or
            (lease.bot_id, lease.persona_id) != namespace.as_tuple):
        raise ValueError("dedicated signed paid quote/grant differs")
    quote_status = db.execute(
        "SELECT status FROM runtime_resource_quotes WHERE quote_id=? AND version=?",
        (quote_id, quote_version),
    ).fetchone()
    if quote_status != ("active",):
        raise ValueError("paid quote is not active")
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (job.budget_ref, budget_operation_id),
    ).fetchone()
    if (reservation is None or reservation[2] != "reserved" or
            json.loads(reservation[1]) != ceiling):
        raise ValueError("dedicated paid ceiling is not reserved")
    fields = dict(
        namespace=namespace, binding=binding,
        frozen_json=canonical_serialize(asdict(frozen)), exact_count=exact_count,
        job_digest=canonical_digest(job), quote_id=quote_id,
        quote_version=quote_version, quote_digest=canonical_digest(quote),
        grant_id=grant.grant_id, grant_version=grant.version,
        grant_digest=canonical_digest(grant),
        budget_operation_id=budget_operation_id,
        budget_reservation_digest=reservation[0], ceiling=ceiling,
        access_epoch=frozen.window.access_epoch,
        delete_epoch=frozen.window.delete_epoch,
        activation_epoch=frozen.window.activation_epoch,
    )
    return D13PaidIntentOriginalV1(
        **fields, original_digest=canonical_digest({
            "schema": "d13.paid_intent_original.v1", **fields,
        }),
    )


def record_d13_paid_intent_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId,
    frozen: FrozenD13PrecompressionRequestV1,
    binding: D13PaidOriginalBindingV1,
    exact_count: D13ExactTokenCountV1 | None,
    selected_main: D13PrecompressionInstallationV1,
    current_window: ConversationWindowProjectionV1,
    *, quote_id: str, quote_version: int, budget_operation_id: str,
    resource_issuer: D02ResourceIssuer, budget_issuer: D11BudgetGrantIssuer,
) -> D13PaidIntentOriginalV1:
    """Record in the same trusted W01 transaction as the paid job reservation."""
    if not db.in_transaction:
        raise ValueError("paid intent needs caller-owned write transaction")
    original = _verified_original(
        db, namespace, frozen, binding, exact_count, selected_main,
        current_window,
        quote_id=quote_id, quote_version=quote_version,
        budget_operation_id=budget_operation_id,
        resource_issuer=resource_issuer, budget_issuer=budget_issuer,
    )
    payload = canonical_serialize(asdict(original))
    prior = db.execute(
        "SELECT original_json,original_digest FROM graph_d13_paid_intent_originals_v1 "
        "WHERE bot=? AND persona=? AND job_ref=?",
        namespace.as_tuple + (binding.job_ref,),
    ).fetchone()
    if prior is not None:
        if prior != (payload, original.original_digest):
            raise ValueError("paid intent replay changed")
        return original
    db.execute(
        "INSERT INTO graph_d13_paid_intent_originals_v1 "
        "(bot,persona,job_ref,operation_id,original_json,original_digest) "
        "VALUES(?,?,?,?,?,?)",
        namespace.as_tuple + (binding.job_ref, binding.original_operation_id,
                              payload, original.original_digest),
    )
    return original


def read_current_d13_paid_intent_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId,
    frozen: FrozenD13PrecompressionRequestV1,
    binding: D13PaidOriginalBindingV1,
    exact_count: D13ExactTokenCountV1 | None,
    selected_main: D13PrecompressionInstallationV1,
    current_window: ConversationWindowProjectionV1,
    *, quote_id: str, quote_version: int, budget_operation_id: str,
    resource_issuer: D02ResourceIssuer, budget_issuer: D11BudgetGrantIssuer,
) -> D13PaidIntentOriginalV1 | None:
    """Reopen an acquired original against current source and signed cost facts.

    The saved queued-job digest is historical. Acquisition advances the job
    phase/fence and trusted time advances, so neither may be compared byte for
    byte to the original snapshot. The caller supplies a fresh W01 window.
    """
    if not db.in_transaction:
        raise ValueError("paid intent read needs caller-owned current transaction")
    from .d13_paid_original_read_v3 import d13_paid_original_point_v3
    handled, row = d13_paid_original_point_v3(db, table='graph_d13_paid_intent_originals_v1', columns=('operation_id', 'original_json', 'original_digest'),
        key_columns=("bot","persona","job_ref"), key=(*namespace.as_tuple,binding.job_ref))
    if not handled:
        row = db.execute(
            "SELECT operation_id,original_json,original_digest FROM "
            "graph_d13_paid_intent_originals_v1 WHERE bot=? AND persona=? AND job_ref=?",
            namespace.as_tuple + (binding.job_ref,),
        ).fetchone()
    if row is None:
        return None
    payload = json.loads(row[1])
    if (type(payload) is not dict
            or set(payload) != {field.name for field in fields(D13PaidIntentOriginalV1)}
            or payload["namespace"] != asdict(namespace)
            or payload["binding"] != asdict(binding)
            or payload["frozen_json"] != canonical_serialize(asdict(frozen))
            or payload["exact_count"] != (
                asdict(exact_count) if exact_count is not None else None)
            or payload["quote_id"] != quote_id
            or payload["quote_version"] != quote_version
            or payload["budget_operation_id"] != budget_operation_id
            or row[0] != binding.original_operation_id
            or row[2] != payload["original_digest"]
            or canonical_serialize(payload) != row[1]):
        raise ValueError("paid intent original identity changed")
    original = D13PaidIntentOriginalV1(
        **{**payload, "namespace": namespace, "binding": binding,
           "exact_count": exact_count})
    digest_fields = {
        field.name: getattr(original, field.name)
        for field in fields(D13PaidIntentOriginalV1)
        if field.name != "original_digest"
    }
    if (canonical_digest({"schema": "d13.paid_intent_original.v1",
                          **digest_fields}) != original.original_digest
            or gate_d13_exact_token_count_v1(frozen, exact_count).status != "ready"
            or selected_main != frozen.installation
            or frozen != freeze_d13_precompression_request_v1(
                frozen.window, frozen.plan, selected_main)
            or binding != bind_paid_original_v1(
                frozen, original_operation_id=binding.original_operation_id,
                call_id=binding.call_id)):
        raise ValueError("paid intent frozen model or source differs")
    refreshed = freeze_d13_precompression_request_v1(
        current_window, frozen.plan, selected_main)
    if (current_window.namespace != namespace
            or current_window.trusted_utc < frozen.window.trusted_utc
            or current_window.trusted_utc >= binding.expires_at_utc
            or (current_window.owner_ref, current_window.conversation_ref,
                current_window.scene_ref, current_window.audience_ref) != (
                    frozen.window.owner_ref, frozen.window.conversation_ref,
                    frozen.window.scene_ref, frozen.window.audience_ref)
            or refreshed.turns != frozen.turns):
        raise ValueError("paid source window changed or expired")
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if epochs != (current_window.access_epoch, current_window.delete_epoch):
        raise ValueError("paid current rights epochs changed")
    job = get_job(db, binding.job_ref)
    if (job.work_kind != PAID_WORK_KIND or job.phase != "running"
            or (job.bot_id, job.persona_id) != namespace.as_tuple
            or job.operation_id != binding.original_operation_id
            or job.fence < 1 or job.cancel_epoch != 0
            or job.continuation.get("binding_digest") != binding.binding_digest
            or job.continuation.get("frozen_input_digest") != frozen.digest
            or job.continuation.get("wire_digest") != frozen.wire_digest
            or job.continuation.get("read_closure_digest")
               != frozen.read_closure_digest):
        raise ValueError("paid original worker is not current")
    quote = resource_issuer.original_signed_quote(db, quote_id, quote_version)
    grant = budget_issuer.current_budget_grant(db, job.budget_ref)
    lease = get_budget_lease(db, job.budget_ref)
    quote_status = db.execute(
        "SELECT status FROM runtime_resource_quotes WHERE quote_id=? AND version=?",
        (quote_id, quote_version),
    ).fetchone()
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (job.budget_ref, budget_operation_id),
    ).fetchone()
    if (canonical_digest(quote) != original.quote_digest
            or quote.work_kind != PAID_WORK_KIND
            or quote.operation_id != budget_operation_id
            or quote.parent_budget_lease_ref != job.budget_ref
            or quote.resource_ref != job.resource_ref
            or dict(quote.ceiling) != original.ceiling
            or canonical_digest(grant) != original.grant_digest
            or grant.lease_id != job.budget_ref
            or PAID_WORK_KIND not in grant.allowed_work_kinds
            or grant.valid_until_utc <= current_window.trusted_utc
            or quote.valid_until_utc <= current_window.trusted_utc
            or quote_status != ("active",)
            or lease.state != "active"
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple
            or lease.currency != grant.currency
            or reservation is None
            or reservation[0] != original.budget_reservation_digest
            or json.loads(reservation[1]) != original.ceiling
            or reservation[2] not in {"reserved", "settled", "overrun",
                                      "partial_unknown", "partial_overrun"}):
        raise ValueError("paid quote, grant or reservation changed")
    return original


def record_d13_paid_call_original_v1(
    db: sqlite3.Connection, original: D13PaidIntentOriginalV1,
    frozen: FrozenD13PrecompressionRequestV1,
    current_window: ConversationWindowProjectionV1,
    request: ModelCallRequest, *,
    resource_issuer: D02ResourceIssuer,
    budget_issuer: D11BudgetGrantIssuer,
) -> D13PaidCallOriginalV1:
    """W01's first acquired worker seals the complete request before egress."""
    if not db.in_transaction:
        raise ValueError("paid call original needs caller-owned graph transaction")
    if (type(original) is not D13PaidIntentOriginalV1
            or type(request) is not ModelCallRequest):
        raise TypeError("typed original and model request required")
    binding = original.binding
    current = read_current_d13_paid_intent_original_v1(
        db, original.namespace, frozen, binding, original.exact_count,
        frozen.installation, current_window,
        quote_id=original.quote_id, quote_version=original.quote_version,
        budget_operation_id=original.budget_operation_id,
        resource_issuer=resource_issuer, budget_issuer=budget_issuer)
    if current != original:
        raise ValueError("paid intent original changed before call sealing")
    envelope = request.envelope
    expected = issue_unadmitted_d13_model_request_v1(
        envelope, frozen, call_id=binding.call_id,
        timeout_seconds=request.timeout_seconds,
        privacy_tier=request.privacy_tier)
    job = get_job(db, binding.job_ref)
    versions = frozenset((item.key.token, item.revision)
                         for item in envelope.version_guard.read_versions)
    source_versions = frozenset(
        (item.ref, item.version) for item in (
            frozen.plan.scene_ref, frozen.plan.audience_ref,
            *frozen.plan.source_dependencies))
    if job.lease_expires_utc is None:
        raise ValueError("paid request worker lease is absent")
    deadline = min(
        datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
        datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp(),
        current.binding.expires_at_utc)
    if deadline <= current_window.trusted_utc or envelope.deadline_utc != deadline:
        raise ValueError("paid request deadline differs from current job, worker or binding")
    if (request != expected
            or request.digest != expected.digest
            or envelope.identity.operation_id != binding.original_operation_id
            or envelope.identity.activity_id != job.activity_id
            or envelope.authority.actor != job.lease_holder
            or envelope.authority.worker_fence != job.fence
            or envelope.parent_budget_lease_ref != job.budget_ref
            or envelope.version_guard.access_epoch != current_window.access_epoch
            or envelope.version_guard.delete_epoch != current_window.delete_epoch
            or not source_versions.issubset(versions)):
        raise ValueError("paid request differs from acquired worker or source")
    fields = dict(
        namespace=original.namespace, job_ref=binding.job_ref,
        binding_digest=binding.binding_digest,
        intent_original_digest=original.original_digest,
        request_json=canonical_serialize(model_to_wire(request)),
        request_digest=request.digest,
        worker_fence=job.fence,
    )
    call = D13PaidCallOriginalV1(
        **fields, original_digest=canonical_digest({
            "schema": "d13.paid_call_original.v1", **fields}))
    payload = canonical_serialize(asdict(call))
    prior = db.execute(
        "SELECT call_id,original_json,original_digest FROM "
        "graph_d13_paid_call_originals_v1 WHERE bot=? AND persona=? AND job_ref=?",
        original.namespace.as_tuple + (binding.job_ref,),
    ).fetchone()
    if prior is not None:
        if prior != (binding.call_id, payload, call.original_digest):
            raise ValueError("paid call original replay changed")
        return call
    db.execute(
        "INSERT INTO graph_d13_paid_call_originals_v1 "
        "(bot,persona,job_ref,call_id,original_json,original_digest) "
        "VALUES(?,?,?,?,?,?)",
        original.namespace.as_tuple + (
            binding.job_ref, binding.call_id, payload, call.original_digest),
    )
    return call


def read_d13_paid_call_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, job_ref: str,
) -> tuple[D13PaidCallOriginalV1, ModelCallRequest] | None:
    """Read W01's stored wire; the caller must still verify current authority."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("paid call read needs caller-owned graph transaction")
    from .d13_paid_original_read_v3 import d13_paid_original_point_v3
    handled, row = d13_paid_original_point_v3(db, table='graph_d13_paid_call_originals_v1', columns=('call_id', 'original_json', 'original_digest'),
        key_columns=("bot","persona","job_ref"), key=(*namespace.as_tuple,job_ref))
    if not handled:
        row = db.execute(
            "SELECT call_id,original_json,original_digest FROM "
            "graph_d13_paid_call_originals_v1 WHERE bot=? AND persona=? AND job_ref=?",
            namespace.as_tuple + (job_ref,),
        ).fetchone()
    if row is None:
        return None
    payload = json.loads(row[1])
    if (type(payload) is not dict
            or set(payload) != {field.name for field in fields(D13PaidCallOriginalV1)}
            or payload["namespace"] != asdict(namespace)
            or payload["job_ref"] != job_ref
            or canonical_serialize(payload) != row[1]):
        raise ValueError("paid call stored wire changed")
    call = D13PaidCallOriginalV1(**{**payload, "namespace": namespace})
    digest_fields = {field.name: getattr(call, field.name)
                     for field in fields(D13PaidCallOriginalV1)
                     if field.name != "original_digest"}
    request = model_from_wire(json.loads(call.request_json), ModelCallRequest)
    if (row[0] != request.call_id
            or row[2] != call.original_digest
            or call.request_digest != request.digest
            or canonical_digest({"schema": "d13.paid_call_original.v1",
                                 **digest_fields}) != call.original_digest):
        raise ValueError("paid call original digest differs")
    return call, request


def load_d13_paid_intent_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, job_ref: str,
) -> tuple[D13PaidIntentOriginalV1, FrozenD13PrecompressionRequestV1] | None:
    """Restore original identity only; this never grants current source access."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("original identity read requires caller transaction")
    from .d13_paid_original_read_v3 import d13_paid_original_point_v3
    handled, row = d13_paid_original_point_v3(db, table='graph_d13_paid_intent_originals_v1', columns=('operation_id', 'original_json', 'original_digest'),
        key_columns=("bot","persona","job_ref"), key=(*namespace.as_tuple,job_ref))
    if not handled:
        row = db.execute(
            "SELECT operation_id,original_json,original_digest FROM "
            "graph_d13_paid_intent_originals_v1 WHERE bot=? AND persona=? AND job_ref=?",
            namespace.as_tuple + (job_ref,),
        ).fetchone()
    if row is None:
        return None
    payload = json.loads(row[1])
    if (type(payload) is not dict or
            set(payload) != {field.name for field in fields(D13PaidIntentOriginalV1)} or
            payload["namespace"] != asdict(namespace) or
            canonical_serialize(payload) != row[1]):
        raise ValueError("D13 paid original stored identity changed")
    frozen = thaw_d13_precompression_request_v1(payload["frozen_json"])
    binding = D13PaidOriginalBindingV1(**payload["binding"])
    count = (None if payload["exact_count"] is None else
             D13ExactTokenCountV1(**payload["exact_count"]))
    original = D13PaidIntentOriginalV1(**{
        **payload, "namespace": namespace, "binding": binding, "exact_count": count,
    })
    digest_fields = {field.name: getattr(original, field.name)
                     for field in fields(D13PaidIntentOriginalV1)
                     if field.name != "original_digest"}
    if (row[0] != binding.original_operation_id or row[2] != original.original_digest or
            binding.job_ref != job_ref or frozen.window.namespace != namespace or
            binding != bind_paid_original_v1(
                frozen, original_operation_id=binding.original_operation_id,
                call_id=binding.call_id) or
            gate_d13_exact_token_count_v1(frozen, count).status != "ready" or
            original.original_digest != canonical_digest({
                "schema": "d13.paid_intent_original.v1", **digest_fields})):
        raise ValueError("D13 paid immutable original digest changed")
    return original, frozen
