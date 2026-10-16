"""Pinned current contact inputs and actual prepared/call/budget originals."""
from ..runtime.contact_original_read_v3 import contact_original_point_v3
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


def require_contact_policy_current_v2(service, plan, *, db=None):
    if db is not None:
        from .contact_model_work_v3 import require_contact_policy_observation_for_plan_v3
        observed = require_contact_policy_observation_for_plan_v3(db,service,plan)
        if observed is not None:
            return observed
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
    from .contact_background_graph_v3 import require_contact_source_db_v3
    authority_work = require_contact_source_db_v3(db)
    atoms = []
    for version in plan.qualified_read_versions:
        row = contact_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token', 'bot', 'persona'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2]))((version.key.token, *ns.as_tuple)),legacy_reader=lambda: db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (version.key.token, *ns.as_tuple)).fetchone())
        if version.revision == 0:
            if row is not None:
                raise ValueError("contact absent source/correction dependency appeared")
            if authority_work is None:
                atoms.append(GraphAtom(version.key, 0, {}, False))
        else:
            if row is None or (row[0], row[2]) != (version.revision, 1):
                raise ValueError("contact Source, route or policy dependency changed")
            if authority_work is None:
                atoms.append(GraphAtom(version.key, row[0], json.loads(row[1]), True))
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    barriers = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if epoch is None or barriers is None:
        raise ValueError("contact current Graph epoch unavailable")
    snapshot = authority_work.projection if authority_work is not None else GraphSnapshot(tuple(atoms), (NamespaceEpoch(*ns.as_tuple, epoch[0]),))
    from .current_authority_graph_read_v3 import authority_source_expression_kwargs_v3
    from ..runtime.contact_host_source_v3 import contact_host_expression_kwargs_v3
    from ..runtime.contact_domain_source_v3 import contact_domain_expression_kwargs_v3
    source_kwargs = contact_domain_expression_kwargs_v3(db) or contact_host_expression_kwargs_v3(db)
    if source_kwargs is None:
        source_kwargs = authority_source_expression_kwargs_v3(db,ns) if authority_work is not None else {}
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
            audiences=(plan.audience_id,), access_epoch=barriers[0], deletion_epoch=barriers[1], valid_until=unit.expires_at_utc,
            **source_kwargs)
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
    require_contact_policy_current_v2(contact_policy_service, plan, db=db)
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
            or job.operation_id != prepared.prepare_operation_id
            or job.cancel_epoch != plan.cancellation_epoch or job.fence != intent.worker_fence
            or (allow_accounted_result and (job.phase not in {"running","completed"}
                or job.result_ref != (prepared.call_id if job.phase == "completed" else None)))
            or (not allow_accounted_result and (job.phase != "running" or job.lease_holder != intent.subject
                or job.result_ref is not None or job.lease_expires_utc is None
                or now >= min(datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())))):
        raise ValueError("contact current actual prepared job/call/worker differs")
    parent = issuer.current_budget_grant(db,plan.parent_budget_lease_id)
    budget = get_budget_lease(db,parent.lease_id)
    if (parent.version != plan.budget_grant_version or canonical_digest(parent) != plan.budget_grant_digest
            or parent.lease_id != intent.budget_lease_id or budget.state != "active"
            or prepared.phase not in parent.allowed_work_kinds or now >= parent.valid_until_utc):
        raise ValueError("Contact actual current original finite parent grant changed")
    acquire, _ = require_contact_original_v2(db,issuer,ns,"stage_receipt",prepared.acquire_operation_id)
    attempt, _ = require_contact_original_v2(db,issuer,ns,"stage_attempt",prepared.acquire_operation_id)
    acquire_permit, _ = require_contact_original_v2(db,issuer,ns,"stage_permit",prepared.acquire_operation_id)
    acquire_operation = contact_original_point_v3(db,table="graph_bundle_operations",
        columns=("receipt_json",),key_columns=("bot","persona","operation_id"),
        key=(*ns.as_tuple,prepared.acquire_operation_id),legacy_reader=lambda: db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple,prepared.acquire_operation_id)).fetchone())
    if (acquire_operation is None or acquire["prepared_digest"] != prepared.digest
            or acquire["operation_id"] != prepared.acquire_operation_id or acquire["attempt_id"] != attempt["attempt_id"]
            or attempt["job_id"] != job.job_id or attempt["phase"] != "acquire"
            or attempt["prepared_digest"] != prepared.digest
            or acquire["result"] != {"status":"acquired","job_id":job.job_id,"request_digest":request.digest}
            or acquire_permit["attempt_id"] != attempt["attempt_id"]
            or acquire_permit["permit"]["operation_id"] != prepared.acquire_operation_id
            or acquire_permit["permit"]["operation"] != "write"):
        raise ValueError("Contact actual once acquire COMMIT / attempt / original permit differs")
    event = contact_original_point_v3(db,table='graph_events',columns=('reads','revisions','invalidated','epoch_revision'),
        key_columns=('bot','persona','session','event_id'),key=(*ns.as_tuple,prepared.activity_id,prepared.acquire_operation_id),
        legacy_reader=lambda: db.execute('SELECT reads,revisions,invalidated,epoch_revision FROM graph_events '
            'WHERE bot=? AND persona=? AND session=? AND event_id=?',
            (*ns.as_tuple,prepared.activity_id,prepared.acquire_operation_id)).fetchone())
    from ..graph_types import GraphReceipt
    if event is None:
        raise ValueError('Contact actual once acquired Graph event absent')
    actual_acquire = GraphReceipt('committed',
        tuple(GraphVersion(AtomKey.from_token(token),revision) for token,revision in json.loads(event[1])),
        tuple(GraphVersion(AtomKey.from_token(token),revision) for token,revision in json.loads(event[2])),
        NamespaceEpoch(*ns.as_tuple,event[3]))
    actual_acquire_row = json.loads(acquire_operation[0])
    if (actual_acquire_row['status'] != 'committed' or actual_acquire_row['graph_receipt_digest'] != canonical_digest(actual_acquire)
            or event[3] != attempt['graph_epoch'] + 1
            or not any(version.key == job_graph_write(job).key for version in actual_acquire.write_versions)):
        raise ValueError('Contact actual acquire job write / current immutable COMMIT receipt differs')
    quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    reserved = contact_original_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json', 'state'),key_columns=('lease_id', 'operation_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1]))((plan.parent_budget_lease_id, prepared.prepare_operation_id)),legacy_reader=lambda: db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (plan.parent_budget_lease_id, prepared.prepare_operation_id)).fetchone())
    reserve_operation = contact_original_point_v3(db,table='runtime_budget_operations',columns=('digest',),key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],'reserve'))((*ns.as_tuple, prepared.prepare_operation_id)),legacy_reader=lambda: db.execute("SELECT digest FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*ns.as_tuple, prepared.prepare_operation_id)).fetchone())
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
    job_atom = contact_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((job_graph_write(job).key.token,)),legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_graph_write(job).key.token,)).fetchone())
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
