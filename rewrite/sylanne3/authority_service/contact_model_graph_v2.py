"""Pinned current contact inputs and actual prepared/call/budget originals."""
from dataclasses import replace
from datetime import datetime
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d06.qualified_expression import prepare_qualified_expression_unit, QualifiedExpressionRequest, SourceTextSpan
from ..graph_types import GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, AtomKey, owner_grant_key
from ..memory_types import SourceRecord, access_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.contact_paid_original_v2 import require_contact_original_v2, read_contact_original_v2
from ..runtime.contact_plan_adoption_v2 import read_adopted_contact_plan_v2, require_contact_inventory_current_v2
from ..runtime.contact_model_job_v2 import read_contact_prepared_v2, contact_model_ids_v2
from ..runtime.jobs import get_job
from ..runtime.budget import get_budget_lease, require_budget_family_admissible
from ..runtime.d11_types import job_graph_write
from .v2_model_egress_wire import to_wire


def require_contact_policy_current_v2(service, plan):
    from .d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
    if type(service) is not InstalledD10ContactPolicyServiceV1 or service.namespace != plan.namespace:
        raise ValueError("actual installed Core contact-policy reader required")
    with service.core._tx() as db:
        owner = service.tickets.current_migration_head_in_tx(db, authority_namespace=service.fences.namespace)
        value = service._head(db, _policy_id_from_plan(service, db, plan))
        if (owner is None or owner.state != "active" or value is None or value.action != "issue"
                or value.original_ref != plan.policy_original_ref or value.digest != plan.policy_original_digest
                or value.policy.version != plan.policy_version or value.namespace != plan.namespace
                or value.owner_head_digest != owner.guard.authorization_head
                or value.owner_authorization_revision != owner.guard.authorization_revision
                or value.owner_principal_epoch != service._principal_epoch(db, owner)
                or not value.policy.window_start <= service._clock() < value.policy.window_end):
            raise ValueError("contact Owner policy was withdrawn or changed")
        return value


def _policy_id_from_plan(service, db, plan):
    from .d10_contact_policy_service_v1 import TABLE
    rows = db.execute("SELECT * FROM " + TABLE + " WHERE authority_namespace=? AND installation_id=?",
        (service.fences.namespace, service.installation_id)).fetchall()
    originals = tuple(service._decode(row) for row in rows)
    matches = tuple(value for value in originals if value.original_ref == plan.policy_original_ref)
    if len(matches) != 1:
        raise ValueError("contact actual signed policy original missing")
    return matches[0].policy.policy_id


def require_contact_scope_current_v2(db, plan, expression, *, now):
    """Recompute exact D06 source qualifications; no caller freshness flag."""
    from ..domains.d08.contact_plan_v2 import AdoptedContactExpressionPlanV2, contact_plan_key_v2
    from ..domains.d09.natural_reply import NaturalExpressionPlanV2
    if (type(plan) is not AdoptedContactExpressionPlanV2 or type(expression) is not NaturalExpressionPlanV2
            or expression.plan_ref.ref != contact_plan_key_v2(plan).token
            or not db.in_transaction or not now < min(plan.valid_until_utc, expression.valid_until_utc)):
        raise ValueError("contact current read requires one live pinned SQLite transaction")
    ns = plan.namespace
    atoms = []
    for version in plan.qualified_read_versions:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (version.key.token, *ns.as_tuple)).fetchone()
        if version.revision == 0:
            if row is not None:
                raise ValueError("contact absent source/correction dependency appeared")
            atoms.append(GraphAtom(version.key, 0, {}, False))
        else:
            if row is None or (row[0], row[2]) != (version.revision, 1):
                raise ValueError("contact Source, route or policy dependency changed")
            atoms.append(GraphAtom(version.key, row[0], json.loads(row[1]), True))
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    barriers = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if epoch is None or barriers is None:
        raise ValueError("contact current Graph epoch unavailable")
    snapshot = GraphSnapshot(tuple(atoms), (NamespaceEpoch(*ns.as_tuple, epoch[0]),))
    if (canonical_digest(expression.units) != plan.qualified_units_digest
            or expression.namespace != ns or expression.audience_id != plan.audience_id
            or not expression.units or expression.promise_grants):
        raise ValueError("contact full adopted expression commitment changed")
    for unit in expression.units:
        if (unit.d06_claim_kind != "attributed_report" or unit.source_kind == "internal"
                or unit.purpose != "expression" or unit.audience_ref != plan.audience_id
                or unit.evidence_span is None or not unit.source_refs):
            raise ValueError("contact expression unit lacks its installed D06 qualification")
        candidate = prepare_qualified_expression_unit(snapshot, namespace=ns,
            request=QualifiedExpressionRequest(plan.source_ref.ref, unit.d06_claim_kind, SourceTextSpan(*unit.evidence_span)),
            audiences=(plan.audience_id,), access_epoch=barriers[0], deletion_epoch=barriers[1], valid_until=unit.expires_at_utc)
        expected = {"qualified_text": candidate.source_excerpt, "qualification_digest": candidate.qualification_digest,
            "speaker_id": candidate.speaker_id, "occurred_at": candidate.occurred_at, "learned_at": candidate.learned_at,
            "source_kind": candidate.source_kind, "assertion_status": candidate.assertion_status,
            "attribution_required": candidate.attribution_required, "polarity_status": candidate.polarity_status,
            "source_excerpt": candidate.source_excerpt}
        if any(getattr(unit, key) != value for key, value in expected.items()):
            raise ValueError("contact adopted unit no longer equals actual D06 source qualification")
    return snapshot, barriers


def read_current_contact_model_graph_v2(db, intent, issuer, now, *, allow_unsealed_prepare=False,
        allow_accounted_result=False, contact_policy_service=None):
    from ..runtime.natural_reply_job_v2 import _request_from_wire
    job = get_job(db, intent.job_id)
    if job is None:
        raise ValueError("Contact V2 actual persistent model job is missing")
    ns = NamespaceId(job.bot_id, job.persona_id)
    metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    barriers = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if metadata is None or epoch is None or barriers != (intent.access_epoch, intent.delete_epoch):
        raise ValueError("contact actual recovery metadata/Source barriers differ")
    current = json.loads(metadata[0])
    if ((current["authority_id"], current["authority_namespace"], current["activation_generation"], current["revocation_epoch"]) !=
            (intent.authority_id, intent.namespace, intent.authority_activation_generation, intent.authority_revocation_epoch)
            or current["namespace"] != {"bot_id": ns.bot_id, "persona_id": ns.persona_id}
            or (not allow_accounted_result and (metadata[1], epoch[0], current["deletion_seq"], current["execution_seq"]) !=
                (intent.graph_revision, intent.graph_epoch, intent.authority_deletion_seq, intent.authority_execution_seq))
            or allow_accounted_result and (intent.graph_revision > metadata[1] or intent.graph_epoch > epoch[0]
                or intent.authority_deletion_seq > current["deletion_seq"] or intent.authority_execution_seq > current["execution_seq"])):
        raise ValueError("contact exact Graph/current Authority anchor differs")
    prepared, frozen = read_contact_prepared_v2(db, namespace=ns, job_id=job.job_id, issuer=issuer)
    plan, expression, raw, plan_digest = read_adopted_contact_plan_v2(db, namespace=ns, contact_id=prepared.contact_id, issuer=issuer)
    require_contact_inventory_current_v2(db, ns, raw)
    require_contact_scope_current_v2(db, plan, expression, now=now)
    require_contact_policy_current_v2(contact_policy_service, plan)
    prepared_commit, _ = require_contact_original_v2(db, issuer, ns, "prepare_commit", job.job_id)
    from ..runtime.d04_root_original_store_v1 import _receipt
    actual_prepare_receipt = _receipt(db, ns, prepared.prepare_operation_id)
    request_raw, _ = require_contact_original_v2(db, issuer, ns, "request", job.job_id)
    request = _request_from_wire(request_raw["wire"])
    sealed = read_contact_original_v2(db, issuer, ns, "call", job.job_id)
    if ((sealed is None and not allow_unsealed_prepare) or sealed is not None and sealed[0] != to_wire(intent)
            or prepared_commit["prepared_digest"] != prepared.digest
            or prepared_commit["receipt_digest"] != canonical_digest(actual_prepare_receipt)
            or prepared_commit["operation_id"] != prepared.prepare_operation_id
            or prepared.plan_original_digest != plan_digest
            or prepared.phase != job.work_kind or intent.binding_digest != prepared.digest
            or intent.operation_id != prepared.acquire_operation_id or intent.acquire_operation_id != prepared.acquire_operation_id
            or intent.call_id != prepared.call_id or intent.request_digest != request.digest
            or job.operation_id != prepared.prepare_operation_id or job.phase != "running"
            or job.cancel_epoch != plan.cancellation_epoch or job.lease_holder != intent.subject or job.fence != intent.worker_fence
            or job.result_ref is not None or job.lease_expires_utc is None
            or now >= min(datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                          datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())):
        raise ValueError("contact current actual prepared job/call/worker differs")
    quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    reserved = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (plan.parent_budget_lease_id, prepared.prepare_operation_id)).fetchone()
    reserve_operation = db.execute("SELECT digest FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*ns.as_tuple, prepared.prepare_operation_id)).fetchone()
    if (canonical_digest(quote) != prepared.quote_digest or quote.work_kind != prepared.phase
            or quote.operation_id != prepared.prepare_operation_id or reserve_operation != (prepared.reservation_digest,)
            or reserved is None or reserved[0] != prepared.reservation_digest or json.loads(reserved[1]) != dict(quote.ceiling)
            or reserved[2] not in ({"reserved", "settled", "unknown", "partial_unknown", "overrun", "partial_overrun"} if allow_accounted_result else {"reserved"})
            or intent.budget_reservation_operation_id != prepared.prepare_operation_id
            or intent.budget_reservation_digest != prepared.reservation_digest
            or intent.budget_lease_id != quote.parent_budget_lease_ref or tuple(sorted(quote.ceiling.items())) != intent.budget_ceiling):
        raise ValueError("contact signed quote/reservation actual ledger differs")
    if not allow_accounted_result:
        require_budget_family_admissible(db, quote.parent_budget_lease_ref)
    from ..model_broker.contact_expression_v2 import contact_provider_messages_v2
    contact_provider_messages_v2(request, frozen.installation)
    if (request.identity.operation_id != prepared.acquire_operation_id or request.identity.phase != prepared.phase
            or request.identity.activity_id != prepared.activity_id or request.envelope.authority.actor != intent.subject
            or request.envelope.authority.worker_fence != intent.worker_fence
            or request.envelope.authority.audience != (plan.audience_id,) or request.envelope.authority.purpose != "proposal"
            or request.envelope.authority.namespace != ns or now >= request.envelope.deadline_utc
            or request.envelope.parent_budget_lease_ref != intent.budget_lease_id
            or (intent.provider_id, intent.model_id, intent.provider_config_digest, intent.max_output_tokens) !=
                (frozen.installation.provider_id, frozen.installation.model_id, frozen.installation.provider_config_digest, frozen.installation.max_output_tokens)):
        raise ValueError("contact actual typed request escapes its frozen scope")
    guard = request.envelope.version_guard
    sources = tuple(sorted((row.key.owner.subject, row.revision) for row in plan.qualified_read_versions
        if row.key.type_name == "memory.source" and row.revision > 0))
    accesses = tuple(sorted((row.key.owner.subject, row.revision) for row in plan.qualified_read_versions
        if row.key.type_name == "memory.access" and row.revision > 0))
    if (tuple(sorted(intent.source_revisions)) != sources or tuple(sorted(intent.access_revisions)) != accesses
            or tuple(sorted(intent.source_refs)) != tuple(ref for ref, _ in sources)
            or (intent.access_epoch, intent.delete_epoch, intent.authority_activation_generation) !=
               (guard.access_epoch, guard.delete_epoch, request.envelope.authority.activation_generation)):
        raise ValueError("contact call changed its exact Source/access and actual request anchor")
    job_atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_graph_write(job).key.token,)).fetchone()
    if job_atom is None or job_atom[1] != 1 or json.loads(job_atom[0]) != job_graph_write(job).value:
        raise ValueError("contact actual running job projection changed")
    if prepared.phase == "contact_review":
        from ..runtime.contact_model_preparation_v2 import read_paid_contact_result_v2
        previous, previous_frozen, generated, paid = read_paid_contact_result_v2(db, namespace=ns,
            contact_id=plan.contact_id, phase="contact_generation", issuer=issuer, resource_issuer=issuer.resource_issuer)
        if (generated.output_digest != prepared.generation_output_digest or paid["terminal_digest"] != prepared.generation_terminal_digest
                or paid["cost_ref"] != prepared.generation_cost_ref or frozen.generation_output_digest != generated.output_digest):
            raise ValueError("contact review differs from its complete actually paid generation")
    return prepared, frozen, job, request
