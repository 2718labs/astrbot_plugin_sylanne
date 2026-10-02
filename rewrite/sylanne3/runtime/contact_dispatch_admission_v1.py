"""Seal a contact command from W01's actual final six-provider read."""
from dataclasses import asdict
from datetime import datetime, timezone
import json

from ..dispatch_runtime import DispatchRequest
from ..domains.d03.context import RoleBinding
from ..domains.d09.contact_batch_v1 import validate_contact_verified_batch_v1
from ..domains.d10.contact_claim_v2 import contact_claim_key_v2
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from ..runtime_journal import BudgetConstraint, RecoveryConstraintFootprint, QuotaOccupancy
from .budget import get_budget_lease
from .contact_final_issuer_v1 import inspect_contact_final_d11_v1, _value
from .contact_qualification_v1 import issue_contact_checks_locked_v1, _social_reads
from .dispatch_admission import DispatchAdmissionV1, DispatchAdmissionReceiptV1, check_receipts_against_specs
from .installed_dispatch_admission_issuer import (
    TrustedDispatchAdmissionContextV1, inspect_current_owner_grant,
    _message_reservation_dimension_limit,
)
from .d11_types import RuntimeOutboxValue
from .jobs import get_job


def issue_contact_dispatch_admission_v1(*, db, bundle, evidence, graph_receipt,
        current_read, stage, route, context, scope, d02_issuer, d11_issuer,
        quote, grant, current_policy, current_effect, effect_snapshot, clock_reading,
        clock_policy, owner_guard, provisional_qualification, now_utc):
    """Recompute checks before sealing; supplied provisional evidence cannot pass alone."""
    from .contact_final_projection_v1 import require_contact_projection_read_v1
    require_contact_projection_read_v1(current_read, db, phases=('post_cas_e_plus_1',))
    namespace, identity = bundle.envelope.authority.namespace, bundle.envelope.identity
    snapshot = current_read.check(db)
    query = route.query
    if (scope.namespace != namespace or scope.operation != 'write'
            or scope.generation != bundle.envelope.authority.activation_generation
            or graph_receipt.status != 'committed'
            or graph_receipt.epoch.revision != query.revision
            or snapshot.epochs != (graph_receipt.epoch,)
            or query.revision != scope.graph_epoch.revision + 1
            or evidence.operation_id != identity.operation_id
            or evidence.effect_id != identity.effect_id):
        raise ValueError('contact final command lacks its actual E+1 commit and installed fence')
    qualification = issue_contact_checks_locked_v1(db, snapshot, query, scope,
        current_read=current_read, stage=stage, route=route, context=context,
        d02_issuer=d02_issuer, d11_issuer=d11_issuer, quote=quote, grant=grant,
        current_policy=current_policy, current_effect=current_effect, effect_snapshot=effect_snapshot,
        now_utc=now_utc, valid_until_utc=bundle.envelope.deadline_utc)
    if qualification != provisional_qualification:
        raise ValueError('contact provisional and final provider closures changed')
    runtime = inspect_contact_final_d11_v1(db, bundle=bundle, candidate=evidence,
        qualification=qualification, d11_issuer=d11_issuer, now_utc=now_utc)
    projection, role_read, _ = _social_reads(db, snapshot, query, stage.content, route, context, now_utc)
    owner_row = db.execute('SELECT graph_incarnation FROM graph_owner_issue_operations_v1 '
        'WHERE bot=? AND persona=?', namespace.as_tuple).fetchone()
    if owner_row is None:
        raise ValueError('contact command lost its actual Owner installation proof')
    trusted = TrustedDispatchAdmissionContextV1(scope, clock_reading, clock_policy,
        projection, graph_receipt, owner_guard, current_effect, effect_snapshot)
    owner = inspect_current_owner_grant(db, namespace, (route.conversation_ref,), 'expression',
        trusted_context=trusted, graph_incarnation=owner_row[0])
    if owner.status != 'owner_verified' or owner.grant_id is None or current_effect.state != 'absent':
        raise ValueError('contact current Owner or execution inventory changed')
    matched = tuple(atom for atom in projection.role_bindings if atom.key.name in role_read.matched_bindings
        and atom.value['scene_ref'] == stage.content.scene_id)
    if len(matched) != 1:
        raise ValueError('contact command has no unique current scene-role binding')
    value = matched[0].value
    role = RoleBinding(**{**value, 'norm_refs': tuple(value['norm_refs']), 'source_refs': tuple(value['source_refs'])})
    _, batch_raw = _value(db, namespace, evidence.batch_ref, 'd09.contact_verified_batch.v1')
    batch = validate_contact_verified_batch_v1(batch_raw)
    content = batch.content
    runtime_admission = runtime.runtime_admission
    lease = get_budget_lease(db, runtime_admission.budget.lease_id)
    reservation = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations '
        'WHERE lease_id=? AND operation_id=?', (lease.lease_id, identity.operation_id)).fetchone()
    ceiling = json.loads(reservation[1])
    selected = _message_reservation_dimension_limit(lease, ceiling)
    if selected is None:
        raise ValueError('contact message has no actual reserved dimension limit')
    dimension, limit = selected
    _, outbox_raw = _value(db, namespace, runtime.outbox_ref, 'runtime.outbox')
    outbox = RuntimeOutboxValue(**outbox_raw)
    job = get_job(db, AtomKey.from_token(runtime.job_ref).name)
    _, parent_raw = _value(db, namespace, evidence.grant_ref, 'd08.communication_intent_grant.v1')
    from ..domains.d08.execution import GoalExecutionProvider
    decoder = next(s.validator for s in GoalExecutionProvider().register_types()
        if s.name == 'd08.communication_intent_grant.v1')
    parent = decoder(parent_raw)
    from .contact_claim_adoption_v1 import read_current_own_contact_continuation_v1
    from .contact_qualification_v1 import _plan_policy
    from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2, contact_window_id_v2
    read_current_own_contact_continuation_v1(db, current_read, content=content, segment_index=0,
        current_policy=current_policy, scope=scope, now_utc=now_utc)
    claim_atom = current_read.head(db, contact_claim_key_v2(namespace, content.contact_id), required=True)
    own_claim = decode_contact_claim_v2(claim_atom.value)
    _, policy_atom, policy, _, _ = _plan_policy(db, current_read, content, current_policy, scope, now_utc)
    inventories = tuple(current_read.complete_inventory(db, kind) for kind in ('d10.contact_claim.v1', 'd10.contact_claim.v2'))
    if (claim_atom.revision != 1 or own_claim.communication_action_id != parent.communication_action_id
            or own_claim.window_id != contact_window_id_v2(policy) or own_claim.policy_version != policy.version
            or own_claim.approval_ref != current_policy.original.original_ref
            or own_claim.approval_digest != current_policy.original.digest):
        raise ValueError('Contact proactive footprint lost its actual approved whole quota claim')
    quota_scope = canonical_digest({'claim_ref':claim_atom.key.token, 'claim_revision':claim_atom.revision,
        'claim_value':own_claim, 'policy_ref':policy_atom.key.token, 'policy_revision':policy_atom.revision,
        'policy_value':policy_atom.value, 'current_policy_original':current_policy.original,
        'complete_claim_inventories':inventories})
    bucket = 'contact-quota:' + canonical_digest((namespace, own_claim.subject_ref, own_claim.channel, own_claim.category))
    gate = 'contact-object:' + canonical_digest((namespace, own_claim.subject_ref, own_claim.channel, own_claim.category))
    footprint = RecoveryConstraintFootprint('/'.join(namespace.as_tuple), identity.activity_id,
        identity.effect_id, external_idempotency_ref=outbox.idempotency_key,
        conflict_keys=('target:' + parent.target_ref,), communication_action=parent.communication_action_id,
        contact_id=content.contact_id, segment_id=evidence.segment_id,
        object_gate_keys=(gate,), quota_occupancies=(QuotaOccupancy(bucket, own_claim.window_id, 1),),
        budgets=(BudgetConstraint(lease.lease_id, str(lease.used.get(dimension, 0)),
            str(lease.reserved.get(dimension, 0) + lease.unconfirmed.get(dimension, 0)), str(limit)),))
    command_digest = canonical_digest({'operation_id': identity.operation_id,
        'outbox_ref': runtime.outbox_ref, 'idempotency_key': outbox.idempotency_key,
        'batch_ref': evidence.batch_ref, 'segment_index': evidence.segment_index,
        'payload_digest': evidence.payload_digest, 'fence_token': scope.permit.token,
        'proactive_contact':True, 'actual_quota_scope_digest':quota_scope})
    request = DispatchRequest('/'.join(namespace.as_tuple), identity.operation_id,
        identity.activity_id, identity.effect_id, identity.attempt_id, command_digest,
        outbox.payload_ref, evidence.payload_digest, 'platform:astrbot-private-v1',
        parent.required_check_refs, outbox.dispatch_generation, scope.generation, job.fence,
        scope.permit.token, content.cancellation_epoch, footprint, True, batch.parent_grant_ref,
        parent.segment_manifest_digest, evidence.segment_index, len(content.segments), parent.contact_policy_check_ref)
    deadline = int(min(content.valid_until, bundle.envelope.deadline_utc,
        datetime.fromisoformat(job.deadline_utc.replace('Z', '+00:00')).timestamp(),
        *(check.valid_until for check in qualification.checks)))
    if deadline <= now_utc:
        raise ValueError('contact final command deadline expired')
    admission = DispatchAdmissionV1(namespace=request.namespace, graph_incarnation=owner_row[0],
        activity_id=identity.activity_id, effect_id=identity.effect_id, attempt_id=identity.attempt_id,
        operation_id=identity.operation_id, dispatch_generation=request.dispatch_generation,
        admission_ref='admission:' + canonical_digest((identity.operation_id, identity.effect_id, evidence.digest))[:40],
        candidate_digest=evidence.digest, request_digest=canonical_digest(request),
        action_intent_digest=evidence.action_digest, action_intent_schema_version='d08.action_intent.v1',
        action_schema_digest=evidence.schema_digest, action_schema_version='d08.action_schema.v1',
        required_checks_digest=canonical_digest(stage.intent.required_checks),
        required_checks_schema_version='d08.required_check_spec.v1', grant_digest=evidence.grant_digest,
        batch_digest=evidence.batch_digest, segment_index=evidence.segment_index, payload_digest=evidence.payload_digest,
        account_ref=route.platform_ref, destination_ref=route.conversation_ref, scene_ref=route.scene_ref,
        owner_head_ref=owner.grant_id, role_ref=role.social_role, binding_ref=role.role_binding_id,
        object_ref=stage.intent.target_ref, action_ref=stage.intent.action_id, purpose='expression',
        audience=(route.conversation_ref,), graph_reads=tuple((v.key.token, v.revision) for v in snapshot.versions),
        query_epoch=query.revision, access_epoch=evidence.access_epoch, delete_epoch=evidence.delete_epoch,
        check_receipts=qualification.checks, budget_parent_lease_ref=lease.lease_id,
        budget_lease_ref=lease.lease_id, budget_reservation_operation_id=identity.operation_id,
        budget_reservation_digest=reservation[0], budget_ceiling=ceiling, budget_currency=lease.currency,
        budget_version=lease.version, contact_reservation_ref=contact_claim_key_v2(namespace, content.contact_id).token,
        utc_deadline=datetime.fromtimestamp(deadline, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        clock_policy_ref=clock_policy.source_id, clock_policy_digest=canonical_digest(asdict(clock_policy)))
    check_receipts_against_specs(admission, stage.intent.required_checks, now_utc)
    receipt = DispatchAdmissionReceiptV1(admission, scope.graph_revision + 1, query.revision,
        canonical_digest({'admission_digest': admission.digest, 'graph_revision': scope.graph_revision + 1,
            'graph_epoch': query.revision}))
    return receipt, request
