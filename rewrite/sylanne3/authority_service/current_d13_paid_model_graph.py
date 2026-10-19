"""Independent, pinned Graph proof for one D13 paid model original.

This reader never treats the immutable intent as a current access grant.  It
reopens the original signed budget and replays the current D13 window in the
same read-only Graph transaction used by the Authority admission/read gate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime
import json
import sqlite3
from typing import TYPE_CHECKING

from ..contracts import canonical_json
from ..domains.d13.paid_lifecycle import D13PaidOriginalBindingV1, bind_paid_original_v1
from ..domains.d13.precompression import PrecompressionPlan
from ..model_broker.d13_precompression import (
    D13ExactTokenCountV1, D13PrecompressionInstallationV1,
    freeze_d13_precompression_request_v1,
)
from ..runtime.budget import get_budget_lease, require_budget_family_admissible
from ..runtime.d11_types import job_graph_write, runtime_job_key
from ..runtime.jobs import PersistentJob, get_job
from ..model_broker.broker import ModelCallRequest
from ..runtime_contracts import (
    CompletedTurnV1, ConversationWindowProjectionV1, NamespaceId,
    SnapshotRequirementsV2, VersionedRef, canonical_digest,
    canonical_serialize,
)
from .v2_model_egress_contract import ModelEgressIntentV1

if TYPE_CHECKING:
    from ..runtime.d13_paid_intent_original_v1 import D13PaidIntentOriginalV1
    from ..runtime.issuers import D11BudgetJobIssuer


def _canonical(raw: str):
    value = json.loads(raw)
    if canonical_serialize(value) != raw:
        raise ValueError("noncanonical D13 original")
    return value


def _ref(value):
    if type(value) is not dict or set(value) != {"ref", "version"}:
        raise ValueError("invalid D13 reference")
    return VersionedRef(**value)


def _window(value):
    if type(value) is not dict or set(value) != {item.name for item in fields(ConversationWindowProjectionV1)}:
        raise ValueError("invalid D13 window fields")
    turns = tuple(CompletedTurnV1(**{
        **turn,
        "audience_ref": _ref(turn["audience_ref"]),
        "raw_ref": _ref(turn["raw_ref"]),
        "source_ref": _ref(turn["source_ref"]),
        "access_ref": _ref(turn["access_ref"]),
    }) for turn in value["turns"])
    result = ConversationWindowProjectionV1(**{
        **value, "namespace": NamespaceId(**value["namespace"]),
        "scene_ref": _ref(value["scene_ref"]),
        "audience_ref": _ref(value["audience_ref"]),
        "turns": turns,
        "source_dependencies": tuple(_ref(ref) for ref in value["source_dependencies"]),
        "read_set": tuple(_ref(ref) for ref in value["read_set"]),
        "missing_ranges": tuple(tuple(pair) for pair in value["missing_ranges"]),
    })
    if canonical_serialize(asdict(result)) != canonical_serialize(value):
        raise ValueError("D13 window canonical shape changed")
    return result


def _plan(value):
    if type(value) is not dict or set(value) != {item.name for item in fields(PrecompressionPlan)}:
        raise ValueError("invalid D13 plan fields")
    result = PrecompressionPlan(**{
        **value, "source_dependencies": tuple(_ref(ref) for ref in value["source_dependencies"]),
        "scene_ref": _ref(value["scene_ref"]),
        "audience_ref": _ref(value["audience_ref"]),
    })
    if canonical_serialize(asdict(result)) != canonical_serialize(value):
        raise ValueError("D13 plan canonical shape changed")
    return result


@dataclass(frozen=True, slots=True)
class CurrentD13PaidModelGraph:
    original: D13PaidIntentOriginalV1
    window: ConversationWindowProjectionV1
    job: PersistentJob
    request: ModelCallRequest


def read_current_d13_paid_model_graph(
    db: sqlite3.Connection, intent: ModelEgressIntentV1,
    issuer: D11BudgetJobIssuer, now: float,
) -> CurrentD13PaidModelGraph:
    """Rebuild current job, source, rights and signed budget from Graph DB."""
    from .d13_authority_model_source_v3 import read_bound_d13_current_model_v3
    actual=read_bound_d13_current_model_v3(db,intent,issuer,now)
    if actual is not None:return actual
    if not db.in_transaction:
        raise ValueError("D13 paid proof requires one pinned Graph transaction")
    from ..runtime.d13_paid_intent_original_v1 import (
        D13PaidIntentOriginalV1, PAID_WORK_KIND,
        read_current_d13_paid_intent_original_v1,
        read_d13_paid_call_original_v1,
    )
    job = get_job(db, intent.job_id)
    namespace = NamespaceId(job.bot_id, job.persona_id)
    ns = namespace.as_tuple
    meta = db.execute(
        "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
        "WHERE bot=? AND persona=?", ns,
    ).fetchone()
    epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns,
    ).fetchone()
    rights = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", ns,
    ).fetchone()
    if (meta is None or meta[0] != "sylanne3.authority.v2"
            or meta[2] < intent.graph_revision
            or epoch is None or epoch[0] < intent.graph_epoch
            or rights != (intent.access_epoch, intent.delete_epoch)):
        raise ValueError("D13 Graph or rights epoch changed")
    requirements_data = _canonical(meta[1])
    if requirements_data.get("namespace") != asdict(namespace):
        raise ValueError("D13 namespace requirements changed")
    requirements = SnapshotRequirementsV2(**{
        **requirements_data, "namespace": namespace,
    })
    if (requirements.authority_id, requirements.authority_namespace,
            requirements.activation_generation, requirements.revocation_epoch,
            requirements.deletion_seq, requirements.execution_seq) != (
            intent.authority_id, intent.namespace,
            intent.authority_activation_generation, intent.authority_revocation_epoch,
            intent.authority_deletion_seq, intent.authority_execution_seq):
        raise ValueError("D13 Authority graph anchor changed")
    if (job.work_kind != PAID_WORK_KIND or job.phase != "running"
            or job.effect_id is not None or job.cancel_epoch != 0
            or job.result_ref is not None or job.fence != intent.worker_fence
            or job.lease_holder != intent.subject or job.lease_expires_utc is None
            or now >= min(
                datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp(),
            )):
        raise ValueError("D13 worker job is no longer current")
    job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
    atom = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (job_key.token,),
    ).fetchone()
    if atom is None or atom[2] != 1 or _canonical(atom[1]) != job_graph_write(job).value:
        raise ValueError("D13 current job Graph atom differs")
    original_job_row = db.execute(
        "SELECT job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='create'", ns + (job.operation_id,),
    ).fetchone()
    if original_job_row is None:
        raise ValueError("D13 original queued job missing")
    original_job = PersistentJob(**_canonical(original_job_row[0]))
    if (original_job.phase != "queued" or original_job.fence != 0
            or original_job.job_id != job.job_id
            or replace(job, phase="queued", fence=0, lease_holder=None,
                       lease_expires_utc=None) != original_job):
        raise ValueError("D13 current job differs from immutable original")
    rows = db.execute(
        "SELECT operation_id,original_json,original_digest FROM "
        "graph_d13_paid_intent_originals_v1 WHERE bot=? AND persona=? AND job_ref=?",
        ns + (job.job_id,),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError("D13 paid original absent or ambiguous")
    row = rows[0]
    data = _canonical(row[1])
    binding = D13PaidOriginalBindingV1(**data["binding"])
    frozen_data = _canonical(data["frozen_json"])
    window = _window(frozen_data["window"])
    plan = _plan(frozen_data["plan"])
    installation = D13PrecompressionInstallationV1(**frozen_data["installation"])
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    if data["frozen_json"] != canonical_serialize(asdict(frozen)):
        raise ValueError("D13 original frozen wire changed")
    exact_count = (None if data["exact_count"] is None else
                   D13ExactTokenCountV1(**data["exact_count"]))
    original = D13PaidIntentOriginalV1(**{
        **data, "namespace": namespace, "binding": binding,
        "exact_count": exact_count,
    })
    digest_fields = {item.name: getattr(original, item.name)
                     for item in fields(D13PaidIntentOriginalV1)
                     if item.name != "original_digest"}
    if (row != (binding.original_operation_id,
                canonical_serialize(asdict(original)), original.original_digest)
            or original.original_digest != canonical_digest({
                "schema": "d13.paid_intent_original.v1", **digest_fields})
            or original.job_digest != canonical_digest(original_job)
            or original.namespace != namespace
            or binding != bind_paid_original_v1(
                frozen, original_operation_id=binding.original_operation_id,
                call_id=binding.call_id)
            or original.binding.job_ref != job.job_id
            or original.binding.original_operation_id != job.operation_id
            or (window.access_epoch, window.delete_epoch,
                window.activation_epoch) != (
                original.access_epoch, original.delete_epoch,
                original.activation_epoch)
            or original.activation_epoch != requirements.activation_generation
            or now >= binding.expires_at_utc):
        raise ValueError("D13 paid original identity changed")
    # The shared D13 DB replay applies the same current source, access,
    # correction, audience, order and activation rules as its W01 issuer.
    from ..graph_types import AtomKey
    from ..runtime.d13_current_window import read_current_d13_window_for_authority_v1
    scene = AtomKey.from_token(window.scene_ref.ref).owner.subject
    current_window = read_current_d13_window_for_authority_v1(
        db, namespace, scene, window.conversation_ref, 64, now,
        expected_activation_generation=window.activation_epoch)
    if (current_window.access_epoch != intent.access_epoch
            or current_window.delete_epoch != intent.delete_epoch):
        raise ValueError("D13 current rights differ from model intent")
    checked_original = read_current_d13_paid_intent_original_v1(
        db, namespace, frozen, binding, exact_count, installation,
        current_window, quote_id=original.quote_id,
        quote_version=original.quote_version,
        budget_operation_id=original.budget_operation_id,
        resource_issuer=issuer.resource_issuer,
        budget_issuer=issuer,
    )
    if checked_original != original:
        raise ValueError("D13 source or signed original changed")
    from .d13_source_identity_v1 import d13_original_source_identity_v1
    source_refs, source_revisions, access_revisions = d13_original_source_identity_v1(frozen)
    from ..domains.d06 import source_correction_head_key
    for source_id in source_refs:
        head = source_correction_head_key(namespace, source_id)
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (head.token,)).fetchone():
            raise ValueError("D13 source correction head changed")
    if (intent.source_refs != source_refs
            or intent.source_revisions != source_revisions
            or intent.access_revisions != access_revisions):
        raise ValueError("D13 source or access revision differs")
    quote = issuer.resource_issuer.original_signed_quote(
        db, original.quote_id, original.quote_version)
    grant = issuer.current_budget_grant(db, job.budget_ref)
    lease = get_budget_lease(db, job.budget_ref)
    require_budget_family_admissible(db, job.budget_ref)
    ceiling = dict(intent.budget_ceiling)
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (job.budget_ref, original.budget_operation_id),
    ).fetchone()
    quote_state = db.execute(
        "SELECT status FROM runtime_resource_quotes WHERE quote_id=? AND version=?",
        (original.quote_id, original.quote_version),
    ).fetchone()
    call = read_d13_paid_call_original_v1(db, namespace, job.job_id)
    if call is None:
        raise ValueError("D13 immutable model request is absent")
    call_original, request = call
    if (call_original.binding_digest != binding.binding_digest
            or call_original.intent_original_digest != original.original_digest
            or call_original.worker_fence != job.fence
            or call_original.request_digest != intent.request_digest
            or request.digest != intent.request_digest):
        raise ValueError("D13 model request original changed")
    if (original.quote_digest != canonical_digest(quote)
            or original.grant_digest != canonical_digest(grant)
            or (grant.grant_id, grant.version) != (
                original.grant_id, original.grant_version)
            or quote.work_kind != PAID_WORK_KIND
            or quote.operation_id != job.operation_id
            or (quote.bot_id, quote.persona_id,
                quote.activity_id, quote.effect_id) != (
                *ns, job.activity_id, None)
            or quote.required_worker_fence is not None
            or quote.graph_job_ref != job_key.token
            or quote.outbox_refs != ()
            or quote.d02_settlement_refs != ()
            or quote.parent_budget_lease_ref != job.budget_ref
            or quote.snapshot_ref != job.snapshot_ref
            or quote.resource_ref != job.resource_ref
            or quote.ceiling != ceiling or original.ceiling != ceiling
            or quote_state != ("active",)
            or now >= quote.valid_until_utc or now >= grant.valid_until_utc
            or grant.lease_id != job.budget_ref
            or PAID_WORK_KIND not in grant.allowed_work_kinds
            or lease.state != "active"
            or any(amount > grant.max_ceiling.get(name, 0)
                   or lease.reserved.get(name, 0) < amount
                   for name, amount in ceiling.items())
            or reservation != (
                original.budget_reservation_digest, canonical_json(ceiling), "reserved")
            or (intent.budget_lease_id,
                intent.budget_reservation_operation_id,
                intent.budget_reservation_digest) != (
                job.budget_ref, original.budget_operation_id,
                original.budget_reservation_digest)
            or intent.max_output_tokens != installation.max_output_tokens
            or ceiling.get("output_tokens", 0) < intent.max_output_tokens
            or (intent.provider_id, intent.model_id,
                intent.provider_config_digest) != (
                installation.provider_id, installation.model_id,
                installation.provider_config_digest)):
        raise ValueError("D13 signed quote or reserved ceiling changed")
    return CurrentD13PaidModelGraph(original, current_window, job, request)
