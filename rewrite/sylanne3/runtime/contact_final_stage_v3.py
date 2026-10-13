"""Installed first Contact action, six providers and atomic final admission.

The request is only a locator. No supplied content, approval, check, quote,
continuation or executable callback becomes permission. No sender is installed.
"""
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json
import time

from ..contracts import Event, Scope, canonical_json
from ..graph_types import AtomKey, GraphCandidate, GraphWrite, Owner, owner_grant_key
from ..runtime_contracts import DomainBundle, DomainProposal, DependencySet, VersionedRef, QueryEpoch, canonical_digest
from .contact_final_projection_v3 import _contact_projection_read_v3
from .d01_production_operations_v1 import MissingProductionOriginalV1, production_read_plan_v1

_ISSUED = {}
_RECEIPTS = {}
_QUALIFIED = {}

def _publish_material(material):
    runtime = material.runtime
    if (runtime._active_contact_final_stage_call_v1 is not material.stage_call
            or runtime._active_contact_final_command_v1 != (material.request, material.frame.envelope.identity.operation_id)
            or runtime._active_contact_final_scope_v1 is not material.scope):
        raise ValueError('Contact material has no actual installed command issuance')
    old = getattr(runtime, '_active_contact_final_material_v1', None)
    if old is not None:
        _ISSUED.pop(id(old), None)
    _ISSUED[id(material)] = material
    runtime._active_contact_final_material_v1 = material
    return material

def require_installed_contact_material_v3(material):
    if (type(material) is not _ContactFinalMaterialV3 or _ISSUED.get(id(material)) is not material
            or material.runtime._active_contact_final_material_v1 is not material
            or material.runtime._active_contact_final_stage_call_v1 is not material.stage_call
            or material.runtime._active_contact_final_scope_v1 is not material.scope
            or material.runtime._active_contact_final_owner_v1 is not material.owner
            or material.runtime._active_contact_final_guard_v1 is not material.owner_guard
            or material.runtime._active_contact_final_clock_v1 is not material.clock_reading
            or material.runtime._active_contact_final_effect_v1 is not material.current_effect
            or material.runtime._active_contact_final_effect_snapshot_v1 is not material.effect_snapshot
            or material.runtime._active_contact_final_command_v1 != (material.request, material.frame.envelope.identity.operation_id)):
        raise ValueError('Contact material is not the current concrete installed stage')
    return material

def revoke_contact_final_material_v3(runtime):
    material = getattr(runtime, '_active_contact_final_material_v1', None)
    if material is not None:
        _ISSUED.pop(id(material), None)
        _QUALIFIED.pop(id(material), None)
        for phase in ('provisional_e_plus_1', 'post_cas_e_plus_1'):
            _RECEIPTS.pop((id(material), phase), None)
    runtime._active_contact_final_material_v1 = None

@dataclass(frozen=True, slots=True)
class _ContactFinalMaterialV3:
    runtime: object
    operation: object
    request: 'PrepareCurrentContactDispatchRequestV3'
    frame: object
    scope: object
    owner: object
    owner_guard: object
    content: object
    current_policy: object
    current_effect: object
    effect_snapshot: object
    clock_reading: object
    quote: object
    grant: object
    job: object
    outbox: object
    stage_call: object
    provisional_writes: tuple = ()
    final_bundle: object = None



@dataclass(frozen=True, slots=True)
class PrepareCurrentContactDispatchRequestV3:
    contact_id: str
    segment_index: int = 0

    def __post_init__(self):
        if (type(self.contact_id) is not str or not self.contact_id.startswith('contact:')
                or len(self.contact_id) > 128 or type(self.segment_index) is not int or self.segment_index != 0):
            raise ValueError('Contact final command only accepts its fixed first segment locator')


def contact_final_runtime_ids_v3(namespace, contact_id, activity_id):
    from .d11_types import runtime_job_key, runtime_outbox_key
    digest = canonical_digest(('d11.contact-first-runtime.v1', namespace, contact_id))
    job, outbox = 'contact-message-job:' + digest[:48], 'contact-message-outbox:' + digest[:48]
    return runtime_job_key(*namespace.as_tuple, activity_id, job), runtime_outbox_key(*namespace.as_tuple, activity_id, outbox)


def _raw_plan(db, namespace, contact_id):
    from .contact_plan_adoption_v2 import TABLE
    from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
    row = db.execute(f'SELECT payload_json FROM {TABLE} WHERE bot=? AND persona=? AND contact_id=?',
        (*namespace.as_tuple,contact_id)).fetchone()
    if row is None:
        raise MissingProductionOriginalV1('actual_adopted_contact_plan_v2')
    return decode_contact_plan_v2(json.loads(row[0])['plan'])


def read_plan_contact_final_v3(db, *, namespace, activity_id, operation_kind, request):
    from ..domains.d08.contact_plan_v2 import contact_plan_key_v2, contact_plan_keys_v2
    from ..domains.d09.contact_batch_v3 import contact_batch_keys_v3
    from ..domains.d10.contact_claim_v2 import contact_claim_key_v2
    from .contact_final_action_v1 import contact_final_action_ids_v1
    from .contact_route_binding_v1 import contact_route_read_inputs_v1
    from .contact_model_job_v2 import contact_model_ids_v2
    from .contact_paid_original_v2 import TABLE
    from .d11_types import runtime_job_key
    if type(request) is not PrepareCurrentContactDispatchRequestV3:
        raise TypeError('closed Contact final locator request required')
    plan = _raw_plan(db, namespace, request.contact_id)
    if (plan.namespace, plan.activity_id) != (namespace, activity_id):
        raise ValueError('Contact final command crossed its actual namespace/activity')
    ids = contact_final_action_ids_v1(plan.contact_id, 0)
    owner = Owner('activity', *namespace.as_tuple, plan.activity_id)
    keys = [owner_grant_key(*namespace.as_tuple), *contact_plan_keys_v2(plan),
        *contact_batch_keys_v3(namespace, plan.activity_id, plan.contact_id), contact_claim_key_v2(namespace, plan.contact_id),
        AtomKey(owner, 'd08.goal.v1', ids['goal']), AtomKey(owner, 'd08.action_intent.v1', ids['action']),
        AtomKey(owner, 'd08.action_cancellation.v1', ids['action']), AtomKey(owner, 'd08.action_schema.v1', ids['schema']), *contact_final_runtime_ids_v3(namespace, plan.contact_id, plan.activity_id)]
    keys.extend(row.key for row in plan.qualified_read_versions)
    keys.extend(AtomKey.from_token(ref.ref) for ref in (plan.opportunity_ref, plan.source_ref, plan.route_account_ref))
    route_keys, route_roots = contact_route_read_inputs_v1(db, namespace, plan.route_account_ref.ref)
    keys.extend(route_keys)
    roots = {row.key.token for row in plan.qualified_read_versions if row.key.type_name == 'memory.source' and row.revision > 0}
    roots.update(route_roots)
    from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
    types = CONTACT_FINAL_QUERY_TYPES_V3
    for kind in ('d03.role_binding', 'd05.boundary_rule'):
        rows = db.execute('SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND valid=1 LIMIT 129',
            (*namespace.as_tuple, kind)).fetchall()
        if len(rows) > 128:
            raise MissingProductionOriginalV1('complete_contact_structural_inventory:' + kind)
        for (wire,) in rows:
            roots.update(json.loads(wire)['source_refs'])
    for phase in ('contact_generation', 'contact_review'):
        job = contact_model_ids_v2(plan, phase)['job']
        keys.append(runtime_job_key(*namespace.as_tuple, plan.activity_id, job))
        paid = db.execute(f"SELECT payload_json FROM {TABLE} WHERE bot=? AND persona=? AND kind='paid_cost' AND original_ref=?",
            (*namespace.as_tuple, job)).fetchone()
        if paid:
            keys.append(AtomKey.from_token(json.loads(paid[0])['cost_ref']))
    return production_read_plan_v1(types, keys, tuple(sorted(roots)), (plan.source_ref.ref,))


def command_identity_contact_final_v3(db, *, namespace, request, operation_id, issuer):
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    content = read_contact_reviewed_content_original_v2(db, namespace=namespace, contact_id=request.contact_id,
        issuer=issuer, resource_issuer=issuer._d02)
    first = content.segments[0]
    if operation_id != first.operation_id:
        raise ValueError('Contact final command cannot mint a second first-segment operation')
    return content.activity_id, first.segment.effect_id, content.audience_id


@dataclass(frozen=True, slots=True)
class ContactFinalStageV3:
    material: _ContactFinalMaterialV3
    action: object
    qualification: object
    bundle: DomainBundle
    stage: object


def _contact_expression_frame_v3(frame, content):
    """Only authenticated reviewed claim roots describe expression permission.

    Full context/structural inputs and every guarded head remain unchanged.
    This private derivation is called after the paired-original reader; it is
    not a caller permission flag and never changes generic frame freezing.
    """
    from ..domains.d09.contact_content_v2 import ContactReviewedContentV2
    from ..memory_types import source_key
    if type(content) is not ContactReviewedContentV2:
        raise TypeError('Contact expression roots need the actual typed reviewed content')
    roots = tuple(sorted({ref for segment in content.segments for claim in segment.claims for ref in claim.source_refs}))
    if not roots or len(roots) > frame.limits.max_source_roots:
        raise MissingProductionOriginalV1('actual_bounded_contact_expression_claim_roots')
    current = {v.key.token:v.revision for v in frame.snapshot.versions}
    signed = {v.key.token:v.revision for v in content.read_versions}
    for ref in roots:
        key = AtomKey.from_token(ref)
        if (key != source_key(*content.namespace.as_tuple,key.owner.subject)
                or signed.get(ref,0) < 1 or current.get(ref) != signed[ref]):
            raise ValueError('Contact expression claim root lacks its actual signed/current source binding')
    return replace(frame,envelope=replace(frame.envelope,
        source_qualification=replace(frame.envelope.source_qualification,source_refs=roots)))


def _contact_dispatch_epoch_frame_v3(frame):
    """Derive dispatch's epoch scope after the real finite SQL refreeze.

    This changes no head, query page, revision or permission. Dispatch's
    existing reader independently checks every D03/D05 row against SQLite.
    Only the installed stage publishes the resulting frame as material.
    """
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
    if type(frame) is not CurrentOperationFrameV1 or len(frame.snapshot.epochs) != 1:
        raise ValueError('Contact v3 dispatch epoch lacks its actual typed frame')
    ns, epoch = frame.envelope.authority.namespace, frame.snapshot.epochs[0]
    query = QueryEpoch(ns, 'namespace', epoch.revision)
    pages = frame.query_coverage
    if ((epoch.bot, epoch.persona) != ns.as_tuple or frame.envelope.version_guard.query_epochs != (query,)
            or len(pages) != len(CONTACT_FINAL_QUERY_TYPES_V3)
            or {p.type_id for p in pages} != set(CONTACT_FINAL_QUERY_TYPES_V3)
            or any(p.epoch != query or not p.complete or p.continuation_ref is not None for p in pages)):
        raise ValueError('Contact v3 dispatch epoch lacks complete actual query coverage')
    return replace(frame, envelope=replace(frame.envelope, version_guard=replace(
        frame.envelope.version_guard, query_epochs=(QueryEpoch(ns, 'all', epoch.revision),))))


def _with_actual_absent_keys(material, db, keys):
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    frame = material.frame
    closure = read_plan_contact_final_v3(db, namespace=material.scope.namespace, activity_id=material.content.activity_id,
        operation_kind='prepare_contact_dispatch_v3', request=material.request)
    plan = production_read_plan_v1(tuple(page.type_id for page in frame.query_coverage),
        (*[atom.key for atom in frame.snapshot.atoms], *keys), closure.source_roots,
        frame.envelope.input_refs)
    frozen = freeze_domain_production_frame_v1(material.runtime.graph, db, envelope=frame.envelope,
        current_owner=material.owner, scope=material.scope, plan=plan, now_utc=frame.now_utc,
        observed_originals=frame.observed_originals, installed_policy_refs=frame.installed_policy_refs, limits=frame.limits)
    for key in keys:
        if frozen.snapshot.get(key).revision != 0:
            raise ValueError('Contact final output already exists; no duplicate adoption')
    frozen = _contact_expression_frame_v3(frozen, material.content)
    frozen = _contact_dispatch_epoch_frame_v3(frozen)
    return _publish_material(replace(material, frame=frozen))


@contextmanager
def _provisional(material, db, writes):
    require_installed_contact_material_v3(material)
    graph = material.runtime.graph
    envelope = material.frame.envelope
    candidate = GraphCandidate(Event(Scope(*material.scope.namespace.as_tuple, material.content.activity_id),
        envelope.identity.operation_id, material.frame.now_utc, 'domain_bundle', {'contact_provisional': material.content.digest}),
        envelope.version_guard.read_versions, tuple(w for _, w in writes), material.frame.snapshot.epochs)
    with graph._GraphCoordinator__store._provisional_graph_stage_in_transaction(candidate,
            _capability=graph._GraphCoordinator__graph_capability) as receipt:
        event = db.execute('SELECT event_id,digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND epoch_revision=?',
            (*material.scope.namespace.as_tuple, material.content.activity_id, receipt.epoch.revision)).fetchall()
        if len(event) != 1 or not event[0][0].startswith('provisional:'):
            raise ValueError('Contact provisional receipt has no unique actual SQL event')
        _RECEIPTS[id(material), 'provisional_e_plus_1'] = (receipt, *event[0])
        try:
            yield receipt
        finally:
            _RECEIPTS.pop((id(material), 'provisional_e_plus_1'), None)


def _require_contact_deadline_v1(m):
    from .first_ingress_v2 import trusted_upper
    if (trusted_upper(m.clock_reading) >= m.frame.envelope.deadline_utc
            or time.monotonic() >= m.frame.envelope.monotonic_deadline):
        raise ValueError('Contact fixed trusted UTC/local deadline expired')


def _installed_contact_context_v3(material, db, read):
    """Use the registered compiled D03 instance under this exact private read.

    A newly constructed ContextProvider has no role catalogue. Binding rows
    cannot manufacture that catalogue or replace its installed registration.
    """
    from ..domains.d03.context import ContextProvider
    from .contact_final_projection_v3 import require_contact_projection_read_v3
    require_installed_contact_material_v3(material)
    require_contact_projection_read_v3(read, db,
        phases=('pre_e', 'provisional_e_plus_1', 'post_cas_e_plus_1'))
    if read._witness.material is not material:
        raise ValueError('Contact D03 reader belongs to another installed stage')
    registration = material.runtime.graph._GraphCoordinator__providers.get('d03')
    if (type(registration) is not tuple or len(registration) != 3
            or type(registration[0]) is not ContextProvider
            or registration[1] != 'd03.proposal.v1'
            or registration[2] != registration[0].descriptor.request_schema_hash):
        raise ValueError('Contact lacks its actual installed D03 registration')
    return registration[0]


def _qualification(material, db, read, action):
    _require_contact_deadline_v1(material)
    from ..domains.d03.context import ContextProvider
    from .contact_route_binding_v1 import read_current_contact_route_binding_v1
    from .contact_qualification_v3 import issue_contact_checks_locked_v3
    route = read_current_contact_route_binding_v1(db, read, account_ref=_raw_plan(db, material.scope.namespace, material.content.contact_id).route_account_ref.ref,
        target_entity_ref=action.intent.target_ref, audience=material.content.audience_id)
    return issue_contact_checks_locked_v3(db, read.frame.snapshot, route.query, material.scope,
        current_read=read, stage=action, route=route, context=_installed_contact_context_v3(material, db, read),
        d02_issuer=material.runtime.graph._GraphCoordinator__d02_issuer,
        d11_issuer=material.runtime.graph._GraphCoordinator__d11_issuer,
        quote=material.quote, grant=material.grant, current_policy=material.current_policy,
        current_effect=material.current_effect, effect_snapshot=material.effect_snapshot,
        now_utc=material.frame.now_utc, valid_until_utc=material.frame.envelope.deadline_utc), route


def stage_prepare_current_contact_dispatch_in_transaction_v3(db, *, frame, request, installed_readers):
    from .domain_production_registry_v1 import installed_operation_v1
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2, require_contact_inventory_current_v2
    from .d11_types import RuntimeOutboxValue, job_graph_write, outbox_graph_write, reconcile_runtime_write
    from .jobs import create_job
    from .budget import reserve_budget
    from ..graph_coordinator import budget_operation_digest
    from .contact_dispatch_candidate_v3 import contact_dispatch_segment_payload_ref_v3
    from ..domains.d09.contact_batch_v3 import contact_batch_keys_v3
    from .contact_batch_freezer_v3 import freeze_installed_contact_verified_batch_v3
    from ..domains.d08.execution import GoalExecutionProvider, RequiredCheckRegistry
    from ..domains.d03.context import ContextProvider
    from ..domains.d01.production_operations_v1 import stage_result_v1, plain_v1
    from .contact_final_action_v3 import prepare_contact_action_stage_v3, contact_whole_grant_request_v1
    from .contact_claim_adoption_v3 import prepare_whole_contact_claim_v3
    from .contact_qualification_v3 import read_contact_check_versions_locked_v3
    from .contact_route_binding_v1 import read_current_contact_route_binding_v1
    from .d10_production_operations_v1 import InstalledD10ProductionReadersV1
    if type(request) is not PrepareCurrentContactDispatchRequestV3 or type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError('Contact final command requires its concrete installed readers')
    graph = installed_readers.role_clock_reader.graph
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    runtime._current()
    scope = installed_readers.contact_policy_scope
    issuer = graph._GraphCoordinator__d11_issuer
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle.private_reply_dispatch is None:
        raise MissingProductionOriginalV1('actual_installed_private_message_price')
    content = read_contact_reviewed_content_original_v2(db, namespace=scope.namespace, contact_id=request.contact_id,
        issuer=issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
    plan, _, original, _ = read_adopted_contact_plan_v2(db, namespace=scope.namespace, contact_id=request.contact_id, issuer=issuer)
    require_contact_inventory_current_v2(db, scope.namespace, original)
    if (content.activity_id, content.segments[0].operation_id, content.segments[0].segment.effect_id) != (
            frame.envelope.identity.activity_id, frame.envelope.identity.operation_id, frame.envelope.identity.effect_id):
        raise ValueError('Contact final material identity differs from its paid original')
    frame = _contact_expression_frame_v3(frame, content)
    policy = assembly.admin_bundle.private_reply_dispatch
    grant = issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    if grant != assembly.installation_policy.root_grant or any(len(item.segment.body) > policy.segment_max_chars for item in content.segments):
        raise ValueError('Contact message exceeds its actual installed private price/segment scope')
    deadline = min(frame.envelope.deadline_utc, content.valid_until, frame.now_utc + policy.deadline_after_seconds, grant.valid_until_utc)
    job_key, outbox_key = contact_final_runtime_ids_v3(scope.namespace, content.contact_id, content.activity_id)
    quote = issuer.issue_private_reply_dispatch_quote_v2(db, policy=policy, namespace=scope.namespace,
        identity=frame.envelope.identity, parent_grant=grant, deadline_utc=deadline,
        graph_job_ref=job_key.token, outbox_refs=(outbox_key.token,), now_utc=frame.now_utc)
    from .first_ingress_v2 import trusted_upper
    clock_upper = trusted_upper(runtime._active_contact_final_clock_v1)
    local_deadline = min(frame.envelope.monotonic_deadline, time.monotonic() + deadline - clock_upper)
    if clock_upper >= deadline or time.monotonic() >= local_deadline:
        raise ValueError('Contact fixed trusted UTC/local deadline expired before staging')
    envelope = replace(frame.envelope, deadline_utc=deadline, monotonic_deadline=local_deadline,
        version_guard=replace(frame.envelope.version_guard, resource_lease_versions=(VersionedRef(quote.quote_id, quote.version),)))
    frame = replace(frame, envelope=envelope)
    job = replace(issuer.job_for(envelope, db, now_utc=frame.now_utc), phase='waiting',
        wake_condition={'kind':'contact_host_takeover', 'operation_id':envelope.identity.operation_id})
    create_job(db, job, 'contact-job-create:' + canonical_digest((scope.namespace, job.job_id))[:48], canonical_digest(job))
    reserve_budget(db, grant.lease_id, envelope.identity.operation_id,
        budget_operation_digest(envelope, grant.lease_id, dict(quote.ceiling)), dict(quote.ceiling))
    batch_keys = contact_batch_keys_v3(scope.namespace, content.activity_id, content.contact_id)
    batch_key = batch_keys[0]
    outbox = RuntimeOutboxValue(*scope.namespace.as_tuple, content.activity_id, envelope.identity.operation_id,
        envelope.identity.effect_id, outbox_key.name, job.job_id, job_key.token,
        contact_dispatch_segment_payload_ref_v3(batch_key.token, 0), 'contact-send:' + canonical_digest((scope.namespace, content.contact_id, 0)),
        'pending', scope.generation)
    material = _ContactFinalMaterialV3(runtime, installed_operation_v1('prepare_contact_dispatch_v3'), request,
        frame, scope, runtime._active_contact_final_owner_v1, runtime._active_contact_final_guard_v1,
        content, installed_readers.current_contact_policy, runtime._active_contact_final_effect_v1,
        runtime._active_contact_final_effect_snapshot_v1, runtime._active_contact_final_clock_v1, quote, grant, job, outbox,
        runtime._active_contact_final_stage_call_v1)
    material = _publish_material(material)
    with _contact_projection_read_v3(material, db, phase='pre_e') as read:
        route = read_current_contact_route_binding_v1(db, read, account_ref=plan.route_account_ref.ref,
            target_entity_ref=plan.target_entity_ref, audience=content.audience_id)
        claim_write = prepare_whole_contact_claim_v3(db, read, content=content, current_policy=material.current_policy, scope=scope, now_utc=frame.now_utc)
        versions = read_contact_check_versions_locked_v3(db, read.frame.snapshot, route.query, scope,
            current_read=read, content=content, segment_index=0, route=route, context=_installed_contact_context_v3(material, db, read),
            d02_issuer=graph._GraphCoordinator__d02_issuer, d11_issuer=issuer, quote=quote, grant=grant,
            current_policy=material.current_policy, now_utc=frame.now_utc)
        action = prepare_contact_action_stage_v3(envelope=read.frame.envelope, content=content, index=0,
            current_checks=versions, route=route, quote=quote, grant=grant, now_utc=frame.now_utc)
    runtime_writes = (job_graph_write(job), outbox_graph_write(outbox, job_key))
    for write in runtime_writes:
        reconcile_runtime_write(db, write)
    initial = tuple(('d08', w) for w in action.proposal.typed_writes) + (('d10', claim_write),) + tuple(('d11', w) for w in runtime_writes)
    material = _with_actual_absent_keys(material, db, tuple(w.key for _,w in initial))
    action = replace(action, proposal=replace(action.proposal, envelope=material.frame.envelope))
    material = _publish_material(replace(material, provisional_writes=initial))
    with _provisional(material, db, initial) as receipt:
        with _contact_projection_read_v3(material, db, phase='provisional_e_plus_1', receipt=receipt) as read:
            first_qualification, staged_route = _qualification(material, db, read, action)
            registry = RequiredCheckRegistry()
            registry.register(action.schema)
            decision = registry.qualify(action.intent, first_qualification.checks, now=frame.now_utc)
            if decision.status != 'qualified':
                raise ValueError('Contact first-segment six providers refused its real quota/permission')
            parent = registry.freeze_contact_communication_grant_v1(action.intent, decision,
                contact_whole_grant_request_v1(content), route_binding=staged_route, db=db, read=read, scope=scope, now=frame.now_utc)
            grant_key = AtomKey(Owner('activity', *scope.namespace.as_tuple, content.activity_id), 'd08.communication_intent_grant.v1', parent.grant_id)
    material = _with_actual_absent_keys(material, db, (grant_key,))
    action = replace(action, proposal=replace(action.proposal, envelope=material.frame.envelope))
    discovered_parent = parent
    material = _publish_material(replace(material, provisional_writes=initial))
    with _provisional(material, db, initial) as receipt:
        with _contact_projection_read_v3(material, db, phase='provisional_e_plus_1', receipt=receipt) as read:
            first_qualification, staged_route = _qualification(material, db, read, action)
            registry = RequiredCheckRegistry()
            registry.register(action.schema)
            decision = registry.qualify(action.intent, first_qualification.checks, now=frame.now_utc)
            if decision.status != 'qualified':
                raise ValueError('Contact full-read six-provider qualification refused')
            parent = registry.freeze_contact_communication_grant_v1(action.intent, decision,
                contact_whole_grant_request_v1(content), route_binding=staged_route, db=db, read=read, scope=scope, now=frame.now_utc)
            from ..runtime_contracts import canonical_serialize
            if canonical_serialize(parent) != canonical_serialize(discovered_parent):
                raise ValueError('Contact parent identity changed after complete negative grant read')
            batch_writes = freeze_installed_contact_verified_batch_v3(material, db, read=read, action=action,
                qualification=first_qualification, parent_grant_ref=grant_key.token, grant=parent)
    grant_key = AtomKey(Owner('activity', *scope.namespace.as_tuple, content.activity_id), 'd08.communication_intent_grant.v1', parent.grant_id)
    parent_write = GraphWrite(grant_key, plain_v1(parent))
    all_writes = (*initial, ('d08', parent_write), *(('d09', write) for write in batch_writes))
    material = _with_actual_absent_keys(material, db, (grant_key, *batch_keys))
    material = _publish_material(replace(material, provisional_writes=all_writes))
    envelope = material.frame.envelope
    action = replace(action, proposal=replace(action.proposal, envelope=envelope))
    proposals = []
    for domain in ('d08', 'd09', 'd10', 'd11'):
        writes = tuple(w for d,w in all_writes if d == domain)
        registered = graph._GraphCoordinator__providers[domain]
        keys = {k for w in writes for k in w.dependencies}
        from ..domains.d09.contact_batch_v3 import PROPOSAL_SCHEMA, PROPOSAL_HASH
        proposals.append(DomainProposal(domain, PROPOSAL_SCHEMA if domain == 'd09' else registered[1],
            PROPOSAL_HASH if domain == 'd09' else registered[2], envelope, writes,
            DependencySet(current_invalidation=tuple(v for v in envelope.version_guard.read_versions if v.key in keys)), (), ()))
    bundle = DomainBundle(envelope, tuple(proposals), (), (), (), (), (outbox.idempotency_key,), (job_key.token,), (outbox_key.token,))
    material = _publish_material(replace(material, final_bundle=bundle))
    with _provisional(material, db, all_writes) as receipt:
        with _contact_projection_read_v3(material, db, phase='provisional_e_plus_1', receipt=receipt, bundle=bundle) as read:
            qualification, _ = _qualification(material, db, read, action)
            if qualification.checks != first_qualification.checks:
                raise ValueError('Contact whole-batch provisional providers changed')
    stage = stage_result_v1(material.frame, 'd08', 'prepare_contact_dispatch_v3', request,
        provenance={'reviewed_content_digest':content.digest, 'qualification_digest':qualification.digest,
            'job_ref':job_key.token, 'outbox_ref':outbox_key.token}, jobs=(job,))
    result = ContactFinalStageV3(material, action, qualification, bundle, stage)
    runtime._active_contact_final_stage_v1 = result
    return result


@dataclass(frozen=True, slots=True)
class _ContactFinalCommitWitnessV3:
    stage: ContactFinalStageV3
    graph: object
    v2_write: tuple


_COMMITS = {}


def require_contact_final_commit_v3(witness, graph, db, bundle, v2_write):
    from .d01_production_operations_v1 import CurrentDomainReadV1
    if (type(witness) is not _ContactFinalCommitWitnessV3 or _COMMITS.get(id(witness)) is not witness
            or witness.graph is not graph or witness.stage.bundle is not bundle
            or witness.v2_write != v2_write or v2_write is None
            or witness.stage.material.runtime._active_contact_final_stage_v1 is not witness.stage):
        raise ValueError('Contact GCP lacks its exact installed final stage/bundle issuance')
    m = require_installed_contact_material_v3(witness.stage.material)
    store = graph._GraphCoordinator__store
    if (m.runtime.graph is not graph or db is not store._db or not db.in_transaction or not store._lock._is_owned()
            or m.final_bundle is not bundle or bundle.envelope != m.frame.envelope
            or graph._v2_graph_stamp(m.scope.namespace) != (v2_write[0], v2_write[1])
            or v2_write[0].graph_revision != m.scope.graph_revision or v2_write[1] != m.scope.graph_epoch
            or not graph._anchor_matches(v2_write[0].requirements, m.scope.pinned_anchor)):
        raise ValueError('Contact final commit original R/E or actual SQL transaction changed')
    CurrentDomainReadV1(m.frame).check(db)
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_dispatch_candidate_v3 import validate_contact_dispatch_candidate_writes_v3
    if read_contact_reviewed_content_original_v2(db, namespace=m.scope.namespace, contact_id=m.content.contact_id,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer) != m.content:
        raise ValueError('Contact final stage no longer matches its actual signed paid pair')
    validate_contact_dispatch_candidate_writes_v3(tuple((p.domain,w) for p in bundle.proposals for w in p.typed_writes),
        namespace=m.scope.namespace, identity=bundle.envelope.identity, read_versions=bundle.envelope.version_guard.read_versions,
        source_refs=bundle.envelope.source_qualification.source_refs, access_epoch=bundle.envelope.version_guard.access_epoch,
        delete_epoch=bundle.envelope.version_guard.delete_epoch, query_epoch=m.scope.graph_epoch.revision)
    _require_contact_deadline_v1(m)
    # The quote is issued in this very transaction; D02's signed quote ledger
    # is not the W01 guard-version index. Register only after the exact private
    # witness, current frame and independently loaded signed quote agree.
    resource = graph._GraphCoordinator__d02_issuer
    issuer = graph._GraphCoordinator__d11_issuer
    if (resource.qualified_quote(bundle.envelope, db, now_utc=m.frame.now_utc) != m.quote
            or issuer.current_budget_grant(db, m.grant.lease_id) != m.grant):
        raise ValueError('Contact v3 actual signed quote/current budget differs')
    ref, version = m.quote.quote_id, str(m.quote.version)
    prior = db.execute('SELECT version FROM graph_guard_versions WHERE bot=? AND persona=? '
        'AND kind=? AND ref=?', (*m.scope.namespace.as_tuple, 'resource_lease', ref)).fetchone()
    if prior is not None and prior != (version,):
        raise ValueError('Contact v3 actual resource quote guard version conflicts')
    if prior is None:
        db.execute('INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)',
            (*m.scope.namespace.as_tuple, 'resource_lease', ref, version))
    return witness


def seal_contact_final_admission_v3(witness, graph, db, receipt, evidence):
    from ..domains.d03.context import ContextProvider
    from .contact_dispatch_admission_v3 import issue_contact_dispatch_admission_v3
    from .dispatch_admission import insert_admission
    from .contact_final_issuer_v3 import inspect_contact_final_d11_v3
    if (type(witness) is not _ContactFinalCommitWitnessV3 or _COMMITS.get(id(witness)) is not witness
            or witness.graph is not graph or witness.stage.material.runtime._active_contact_final_stage_v1 is not witness.stage):
        raise ValueError('Contact final admission hook is not the active installed GCP stage')
    stage, m = witness.stage, require_installed_contact_material_v3(witness.stage.material)
    event = db.execute('SELECT event_id,digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND epoch_revision=?',
        (*m.scope.namespace.as_tuple, m.content.activity_id, receipt.epoch.revision)).fetchall()
    if len(event) != 1 or event[0][0] != m.frame.envelope.identity.operation_id:
        raise ValueError('Contact final receipt is not its actual operation event')
    _RECEIPTS[id(m), 'post_cas_e_plus_1'] = (receipt, *event[0])
    try:
        with _contact_projection_read_v3(m, db, phase='post_cas_e_plus_1', receipt=receipt, bundle=stage.bundle) as read:
            qualification, route = _qualification(m, db, read, stage.action)
            from ..runtime_contracts import canonical_serialize
            if canonical_serialize(qualification) != canonical_serialize(stage.qualification):
                raise ValueError('Contact final six-provider actual closure differs from provisional')
            from .contact_qualification_evidence_v3 import issue_contact_qualification_evidence_v3
            _QUALIFIED[id(m)] = issue_contact_qualification_evidence_v3(m,db,read,qualification,route)
            admission, request = issue_contact_dispatch_admission_v3(db=db, bundle=stage.bundle, evidence=evidence,
                graph_receipt=receipt, current_read=read, stage=stage.action, route=route, context=_installed_contact_context_v3(m, db, read),
                scope=m.scope, d02_issuer=graph._GraphCoordinator__d02_issuer, d11_issuer=graph._GraphCoordinator__d11_issuer,
                quote=m.quote, grant=m.grant, current_policy=m.current_policy, current_effect=m.current_effect,
                effect_snapshot=m.effect_snapshot, clock_reading=m.clock_reading,
                clock_policy=graph._GraphCoordinator__scene_clock_policy, owner_guard=m.owner_guard,
                provisional_qualification=stage.qualification, now_utc=m.frame.now_utc)
            insert_admission(db, admission, request)
            runtime = inspect_contact_final_d11_v3(db, bundle=stage.bundle, candidate=evidence,
                qualification=qualification, d11_issuer=graph._GraphCoordinator__d11_issuer, now_utc=m.frame.now_utc)
            from .dispatch_action_job_binding import bind_action_job
            binding = bind_action_job(db, stage.action.intent, admission, contact_issuance=witness)
            return admission, request, runtime.runtime_admission, binding
    finally:
        _RECEIPTS.pop((id(m), 'post_cas_e_plus_1'), None)


def require_contact_action_job_v3(witness, db, action, admission):
    from .dispatch_admission import load_request
    if (type(witness) is not _ContactFinalCommitWitnessV3 or _COMMITS.get(id(witness)) is not witness
            or witness.stage.action.intent != action):
        raise ValueError('Contact action/job binding lacks installed final GCP issuance')
    m = require_installed_contact_material_v3(witness.stage.material)
    proof = _RECEIPTS.get((id(m), 'post_cas_e_plus_1'))
    if proof is None:
        raise ValueError('Contact action/job binding is outside its actual final receipt phase')
    with _contact_projection_read_v3(m, db, phase='post_cas_e_plus_1', receipt=proof[0], bundle=witness.stage.bundle) as read:
        issued = load_request(db, m.scope.namespace, admission.admission_ref)
        if (issued is None or issued[0].admission != admission or issued[1].proactive_contact is not True
                or issued[1].footprint.contact_id != m.content.contact_id
                or not issued[1].footprint.quota_occupancies or not issued[1].footprint.object_gate_keys
                or issued[1].contact_policy_check_ref is None
                or m.job.phase != 'waiting' or m.job.work_kind != 'message'
                or m.job.wake_condition != {'kind':'contact_host_takeover', 'operation_id':admission.operation_id}):
            raise ValueError('Contact action/job binding differs from its actual proactive admission')
        return m.job


def commit_contact_final_stage_v3(runtime, db, *, operation, request, preparation, readers,
        scope, owner, guard, metadata, epoch, process_lease, external_originals):
    from ..authority_service.v2_contract import to_wire
    from ..domains.d01.production_operations_v1 import stage_result_v1
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1
    if (type(preparation) is not ContactFinalStageV3 or runtime._active_contact_final_stage_v1 is not preparation
            or preparation.material.scope is not scope or preparation.material.owner is not owner
            or preparation.material.owner_guard is not guard or preparation.material.request != request
            or preparation.material.operation != operation or preparation.material.runtime is not runtime):
        raise ValueError('Contact commit requires the actual closed installed first-stage identity')
    m = require_installed_contact_material_v3(preparation.material)
    attempt = db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*scope.namespace.as_tuple, m.frame.envelope.identity.operation_id)).fetchone()
    if attempt is None or attempt[1:] != (scope.operation_id, canonical_json(to_wire(scope.permit))):
        raise ValueError('Contact final commit lost its actual retained Owner attempt')
    finish = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':m.frame.envelope.identity.operation_id, 'request_digest':attempt[0], 'permit_token':scope.permit.token})
    v2_write = (metadata, epoch, 'finish:' + scope.operation_id, finish, canonical_json(to_wire(scope.permit)))
    witness = _ContactFinalCommitWitnessV3(preparation, runtime.graph, v2_write)
    _COMMITS[id(witness)] = witness
    try:
        receipt = runtime.graph._commit_domain_bundle_fenced(preparation.bundle, process_lease, in_transaction=True,
            v2_write=v2_write, now_utc=m.frame.now_utc, dispatch_clock_reading=m.clock_reading,
            dispatch_clock_frozen_now_utc=m.frame.now_utc, domain_production_issuance_v1=witness)
    finally:
        _COMMITS.pop(id(witness), None)
    from .dispatch_admission import load_request
    row = db.execute('SELECT admission_ref FROM graph_dispatch_admissions WHERE bot=? AND persona=? AND operation_id=?',
        (*scope.namespace.as_tuple, receipt.operation_id)).fetchall()
    if len(row) != 1:
        raise ValueError('Contact final command has no unique same-transaction admission')
    admission, command = load_request(db, scope.namespace, row[0][0])
    commitments = [{'ref':v.key.token, 'revision':v.revision, 'digest':canonical_digest(next(
        w.value for p in preparation.bundle.proposals for w in p.typed_writes if w.key == v.key))} for v in receipt.write_versions]
    qualification_evidence = _QUALIFIED.get(id(m))
    if qualification_evidence is None or qualification_evidence.operation_id != receipt.operation_id:
        raise ValueError('Contact final lost its actually sealed post-CAS qualification evidence')
    from ..domains.d01.production_operations_v1 import plain_v1
    primary = stage_result_v1(m.frame, 'd08', 'prepare_contact_dispatch_v3', request, jobs=(m.job,),
        provenance={'schema':'d08.contact-final-original.v3', 'reviewed_content_digest':m.content.digest, 'qualification_digest':preparation.qualification.digest,
            'qualification_evidence':plain_v1(qualification_evidence), 'commit_state':'committed_pending_finish',
            'admission_ref':admission.admission.admission_ref, 'admission_receipt_digest':admission.receipt_digest,
            'request_digest':canonical_digest(command), 'footprint_digest':canonical_digest(command.footprint),
            'write_commitments':commitments, 'job_ref':preparation.bundle.persistent_job_refs[0],
            'outbox_ref':preparation.bundle.outbox_refs[0]})
    original = record_adopted_domain_operation_v1(db, primary, receipt)
    return _contact_final_result_v3(receipt=receipt,original_digest=original.original_digest,
        job_id=m.job.job_id,admission_ref=admission.admission.admission_ref,dispatch_request_digest=canonical_digest(command))


def _contact_final_result_v3(*, receipt, original_digest, job_id, admission_ref, dispatch_request_digest):
    """Fixed result encoding; these values are evidence, never authority."""
    from ..runtime_contracts import CommitReceipt
    from .domain_production_originals_v1 import _receipt_wire
    if type(receipt) is not CommitReceipt or receipt.status != 'committed':
        raise ValueError('Contact result requires its actual committed typed receipt')
    for value in (original_digest,dispatch_request_digest):
        if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('Contact result digest is not canonical')
    if any(type(value) is not str or not value for value in (job_id,admission_ref)):
        raise ValueError('Contact result lost its actual job/admission identity')
    return {'schema':'sylanne.domain-production-receipt.v1', 'domain':'d08', 'operation_kind':'prepare_contact_dispatch_v3',
        'operation_id':receipt.operation_id, 'activity_id':receipt.activity_id, 'original_ref':'d08-current:'+original_digest[:48],
        'original_digest':original_digest, 'receipt':_receipt_wire(receipt), 'receipt_digest':canonical_digest(receipt),
        'job_states':[[job_id,'waiting']], 'coverage':'complete', 'missing_inputs':[], 'continuation_ref':None,
        'outbox':[], 'contact_admission_ref':admission_ref, 'dispatch_request_digest':dispatch_request_digest}


def validate_contact_final_result_v3(result, *, original, job_id, admission_ref, dispatch_request_digest):
    """Compare the entire saved result against independently read SQL originals."""
    from ..runtime_contracts import canonical_serialize
    if original['domain']!='d08' or original['operation_kind']!='prepare_contact_dispatch_v3':
        raise ValueError('Contact result has another adopted original family')
    expected=_contact_final_result_v3(receipt=original['receipt'],original_digest=original['original_digest'],
        job_id=job_id,admission_ref=admission_ref,dispatch_request_digest=dispatch_request_digest)
    if type(result) is not dict or canonical_serialize(result)!=canonical_serialize(expected):
        raise ValueError('Contact saved result differs from its closed actual receipt/original/request/job')
    return expected


_CONTACT_FINAL_PROVENANCE_FIELDS = frozenset({'schema','reviewed_content_digest','qualification_digest','admission_ref',
    'admission_receipt_digest','request_digest','footprint_digest','write_commitments','job_ref','outbox_ref',
    'qualification_evidence','commit_state'})
_CONTACT_FINAL_WRITE_TYPES = frozenset({'d08.goal.v1','d08.action_intent.v1','d08.action_schema.v1',
    'd08.action_cancellation.v1','d08.communication_intent_grant.v1','d09.contact_verified_batch.v3',
    'd09.contact_batch_provenance.v3','d09.contact_batch_eligibility.v3',
    'd10.contact_claim.v2','runtime.job','runtime.outbox'})

def validate_contact_final_provenance_v3(value, *, prepared_evidence=None):
    """Closed C09/cold-reader shape; this is evidence decoding, not permission."""
    if type(value) is not dict or set(value) != _CONTACT_FINAL_PROVENANCE_FIELDS:
        raise ValueError('Contact final provenance fields differ')
    if value['schema'] != 'd08.contact-final-original.v3' or value['commit_state'] != 'committed_pending_finish':
        raise ValueError('Contact original commit marker cannot claim a later Authority ACK')
    from .contact_qualification_evidence_v3 import decode_contact_qualification_evidence_v3
    if prepared_evidence is None:
        qualification = decode_contact_qualification_evidence_v3(value['qualification_evidence'],
            expected_digest=value['qualification_digest'])
    else:
        from .dispatch_initial_source_read_v3 import require_prepared_contact_evidence_v3
        qualification=require_prepared_contact_evidence_v3(prepared_evidence)
        if qualification.qualification.digest!=value['qualification_digest']:
            raise ValueError('private prepared Contact original qualification digest differs')
    for field in ('reviewed_content_digest','qualification_digest','admission_receipt_digest','request_digest','footprint_digest'):
        item = value[field]
        if type(item) is not str or len(item) != 64 or any(c not in '0123456789abcdef' for c in item):
            raise ValueError('Contact final provenance digest differs')
    if type(value['admission_ref']) is not str or not value['admission_ref'].startswith('admission:') or len(value['admission_ref']) != 50 or any(c not in '0123456789abcdef' for c in value['admission_ref'][10:]):
        raise ValueError('Contact final provenance admission locator differs')
    members = value['write_commitments']
    if type(members) is not list or len(members) != len(_CONTACT_FINAL_WRITE_TYPES):
        raise ValueError('Contact final provenance lacks its full finite write inventory')
    by_type, namespace, activity = {}, None, None
    for member in members:
        if type(member) is not dict or set(member) != {'ref','revision','digest'} or type(member['revision']) is not int or member['revision'] != 1:
            raise ValueError('Contact final provenance member/version differs')
        key = AtomKey.from_token(member['ref'])
        if key.type_name not in _CONTACT_FINAL_WRITE_TYPES or key.type_name in by_type or key.owner.kind != ('persona' if key.type_name == 'd10.contact_claim.v2' else 'activity'):
            raise ValueError('Contact final provenance member family or uniqueness differs')
        actual_namespace = (key.owner.bot,key.owner.persona)
        if namespace is not None and actual_namespace != namespace:
            raise ValueError('Contact final provenance member namespace differs')
        namespace = actual_namespace
        if key.owner.kind == 'activity':
            if activity is not None and key.owner.subject != activity:
                raise ValueError('Contact final provenance member activity differs')
            activity = key.owner.subject
        digest = member['digest']
        if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Contact final provenance member digest differs')
        by_type[key.type_name] = key.token
    if value['job_ref'] != by_type['runtime.job'] or value['outbox_ref'] != by_type['runtime.outbox']:
        raise ValueError('Contact final provenance actual job/outbox member differs')
    if namespace != qualification.namespace.as_tuple or any(
            not any(row.ref == member['ref'] and row.revision == member['revision'] and row.valid
                and canonical_digest(json.loads(row.value_json)) == member['digest'] for row in qualification.members)
            for member in members):
        raise ValueError('Contact qualification evidence does not contain its actual complete committed members')
    return tuple(sorted(set(by_type.values()) | {row.ref for row in qualification.members}))


def verify_contact_final_committed_v3(db, *, namespace, result, issuer, graph):
    """After real COMMIT, read durable evidence; no reader or send authority is issued."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .dispatch_admission import load_request
    from .dispatch_action_job_binding import load_action_job_binding
    from .d11_types import job_graph_write
    from .jobs import get_job
    from ..runtime_contracts import canonical_serialize
    original = read_adopted_domain_operation_v1(db, namespace, result['operation_id'])
    if (original is None or original['operation_kind'] != 'prepare_contact_dispatch_v3'
            or original['original_digest'] != result['original_digest']):
        raise ValueError('Contact COMMIT readback lost its actual adopted original')
    proof = original['payload']['provenance']
    validate_contact_final_provenance_v3(proof)
    from .contact_qualification_evidence_v3 import decode_contact_qualification_evidence_v3, verify_contact_qualification_sql_v3
    qualified = decode_contact_qualification_evidence_v3(proof['qualification_evidence'],expected_digest=proof['qualification_digest'])
    verify_contact_qualification_sql_v3(db,qualified,registry=graph._GraphCoordinator__store._registry)
    if (qualified.operation_id != result['operation_id'] or qualified.namespace != namespace
            or qualified.activation_generation != original['payload']['authority']['activation_generation']):
        raise ValueError('Contact COMMIT qualification operation/generation identity differs')
    issued = load_request(db, namespace, proof['admission_ref'])
    if issued is None:
        raise ValueError('Contact COMMIT readback lost its durable admission/request')
    admission, request = issued
    if (request.proactive_contact is not True or request.segment_index != 0
            or not request.footprint.quota_occupancies or not request.footprint.object_gate_keys
            or admission.receipt_digest != proof['admission_receipt_digest']
            or canonical_digest(request) != proof['request_digest']
            or canonical_digest(request.footprint) != proof['footprint_digest']
            or request.operation_id != result['operation_id'] or request.activity_id != result['activity_id']
            or request.effect_id != original['receipt'].effect_id
            or request.activation_generation != original['payload']['authority']['activation_generation']
            or request.dispatch_generation != request.activation_generation
            or admission.graph_epoch != original['receipt'].invalidated_epochs[0].revision
            or len(proof['write_commitments']) != len(original['receipt'].write_versions)
            or load_action_job_binding(db, namespace, proof['admission_ref']) is None):
        raise ValueError('Contact COMMIT readback identity/actual quota/admission differs')
    metadata, epoch = graph._v2_graph_stamp(namespace)
    fence = db.execute('SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest '
        'FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?', (*namespace.as_tuple,result['operation_id'])).fetchone()
    attempt = db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
        (*namespace.as_tuple,result['operation_id'])).fetchone()
    from ..authority_service.v2_contract import from_wire
    from .budget import get_budget_lease
    if fence is None or attempt is None:
        raise ValueError('Contact COMMIT lacks its durable original fence/Owner attempt')
    permit = from_wire(json.loads(fence[1]))
    expected_finish = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':result['operation_id'], 'request_digest':attempt[0], 'permit_token':permit.token})
    if (fence[0] != original['receipt'].operation_digest or fence[1] != attempt[2]
            or permit.operation != 'write' or permit.operation_id != attempt[1]
            or permit.token != request.content_fence
            or fence[4] != fence[2]+1 or fence[5] != fence[3]+1
            or (metadata.graph_revision,epoch.revision) != (fence[4],fence[5])
            or metadata.requirements.activation_generation != request.activation_generation
            or metadata.requirements.graph_incarnation != admission.admission.graph_incarnation
            or not graph._anchor_matches(metadata.requirements,permit.pinned_anchor)
            or fence[6:] != ('finish:'+attempt[1],expected_finish)
            or (admission.graph_revision,admission.graph_epoch) != (fence[4],fence[5])):
        raise ValueError('Contact COMMIT actual root/generation/R-E/fence linkage differs')
    if db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',namespace.as_tuple).fetchone() != (
            admission.admission.access_epoch,admission.admission.delete_epoch):
        raise ValueError('Contact COMMIT actual access/delete barrier differs')
    for ref,revision in admission.admission.graph_reads:
        actual = db.execute('SELECT revision FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(ref,*namespace.as_tuple)).fetchone()
        if actual != ((revision,) if revision else None):
            raise ValueError('Contact COMMIT actual full admission read inventory differs')
    events = db.execute('SELECT event_id FROM graph_events WHERE bot=? AND persona=? AND session=? AND epoch_revision=?',
        (*namespace.as_tuple,request.activity_id,fence[5])).fetchall()
    if events != [(request.operation_id,)]:
        raise ValueError('Contact COMMIT actual post epoch event differs')
    if {(x['ref'],x['revision']) for x in proof['write_commitments']} != {(v.key.token,v.revision) for v in original['receipt'].write_versions}:
        raise ValueError('Contact COMMIT member commitments differ from its exact receipt')
    parent = issuer.current_budget_grant(db,original['payload']['parent_budget'])
    lease = get_budget_lease(db,parent.lease_id)
    job_ref = AtomKey.from_token(proof['job_ref'])
    job = get_job(db,job_ref.name)
    resource_version = job.operator_versions.get('resource_quote')
    if type(resource_version) is not str:
        raise ValueError('Contact COMMIT waiting job lacks its actual quote version')
    quote_id, quote_version = resource_version.rsplit(':',1)
    quote = issuer._d02._load_quote(db,quote_id,int(quote_version))
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime_contracts import OperationIdentity, AuthorityContext
    from types import SimpleNamespace
    identity = decode_typed_production_value_v1(original['payload']['identity'],OperationIdentity)
    authority = decode_typed_production_value_v1(original['payload']['authority'],AuthorityContext)
    # Read-only identity view for the existing signed price-policy verifier;
    # neither this value nor historical process capability grants new work.
    issuer._qualified_private_reply_dispatch_policy(db,SimpleNamespace(identity=identity,authority=authority),quote,parent)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or parent != assembly.installation_policy.root_grant:
        raise ValueError('Contact COMMIT signed parent differs from its actual installed root')
    reserved = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (parent.lease_id,request.operation_id)).fetchone()
    if ((parent.bot_id,parent.persona_id,lease.bot_id,lease.persona_id) != (*namespace.as_tuple,*namespace.as_tuple)
            or lease.state != 'active' or lease.version != admission.admission.budget_version
            or quote.work_kind != 'message' or quote.graph_job_ref != proof['job_ref'] or quote.outbox_refs != (proof['outbox_ref'],)
            or (quote.bot_id,quote.persona_id,quote.activity_id,quote.operation_id,quote.effect_id,quote.parent_budget_lease_ref) != (
                *namespace.as_tuple,request.activity_id,request.operation_id,request.effect_id,parent.lease_id)
            or reserved != (admission.admission.budget_reservation_digest,canonical_json(dict(quote.ceiling)),'reserved')
            or canonical_serialize(admission.admission.budget_ceiling) != canonical_serialize(dict(quote.ceiling))):
        raise ValueError('Contact COMMIT actual signed parent/message quote/reservation differs')
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    content = read_contact_reviewed_content_original_v2(db,namespace=namespace,contact_id=request.footprint.contact_id,
        issuer=issuer,resource_issuer=issuer._d02)
    if content.digest != proof['reviewed_content_digest'] or content.segments[0].operation_id != request.operation_id:
        raise ValueError('Contact COMMIT actual signed paid original differs')
    expression_roots = tuple(sorted({ref for item in content.segments for claim in item.claims for ref in claim.source_refs}))
    if (qualified.expression_roots != expression_roots or qualified.audience != content.audience_id
            or qualified.qualification.route_semantic_digest != content.route_semantic_digest
            or qualified.current_effect.effect_id != request.effect_id
            or qualified.graph_epoch != admission.graph_epoch
            or qualified.qualification.checks != admission.admission.check_receipts):
        raise ValueError('Contact COMMIT qualification actual content/checks/route binding differs')
    from .contact_dispatch_candidate_v3 import validate_contact_dispatch_candidate_writes_v3
    from ..domains.d08.execution import GoalExecutionProvider
    from ..domains.d09.contact_batch_v3 import validate_contact_verified_batch_v3
    from ..domains.d10.contact_claim_v2 import ContactClaimV2, decode_contact_claim_v2, contact_window_id_v2
    from ..domains.d10 import decode_contact_policy
    from ..runtime_journal import QuotaOccupancy
    from .d11_types import RuntimeOutboxValue
    all_writes = []
    for member in proof['write_commitments']:
        key = AtomKey.from_token(member['ref'])
        raw = db.execute('SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
            (key.token,*namespace.as_tuple)).fetchone()
        if raw is None:
            raise ValueError('Contact COMMIT four-join member is absent')
        domain = 'd11' if key.type_name.startswith('runtime.') else key.type_name[:3]
        deps = tuple(AtomKey.from_token(token) for (token,) in db.execute(
            'SELECT dependency_token FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',(key.token,)))
        all_writes.append((domain,GraphWrite(key,json.loads(raw[0]),deps)))
    typed = {w.key.type_name:w for _,w in all_writes}
    validators = {spec.name:spec.validator for spec in GoalExecutionProvider().register_types()}
    intent = validators['d08.action_intent.v1'](typed['d08.action_intent.v1'].value)
    evidence = validate_contact_dispatch_candidate_writes_v3(tuple(all_writes),namespace=namespace,identity=identity,
        read_versions=original['receipt'].read_versions,source_refs=intent.source_refs,
        access_epoch=admission.admission.access_epoch,delete_epoch=admission.admission.delete_epoch,query_epoch=fence[3])
    parent_action = validators['d08.communication_intent_grant.v1'](typed['d08.communication_intent_grant.v1'].value)
    from .contact_batch_current_v3 import require_current_contact_batch_v3
    batch, batch_proof, eligibility = require_current_contact_batch_v3(db, namespace=namespace,
        batch_ref=typed['d09.contact_verified_batch.v3'].key.token, operation_id=result['operation_id'],
        generation=request.activation_generation, graph_incarnation=metadata.requirements.graph_incarnation)
    if (batch_proof.owner_head_digest != qualified.owner_guard.owner_head_digest
            or batch_proof.qualification.checks != qualified.qualification.checks
            or batch_proof.qualification.owner_policy_digest != qualified.owner_policy.digest):
        raise ValueError('Contact v2 COMMIT actual proof/current Owner/qualification differs')
    claim = decode_contact_claim_v2(typed['d10.contact_claim.v2'].value)
    outbox = RuntimeOutboxValue(**typed['runtime.outbox'].value)
    policies = [json.loads(wire) for (wire,) in db.execute('SELECT value FROM graph_atoms WHERE bot=? AND persona=? '
        "AND type_name='d10.contact_policy.v1' AND valid=1",namespace.as_tuple)
        if json.loads(wire)['approval_ref']==claim.approval_ref]
    if len(policies)!=1:
        raise ValueError('Contact COMMIT lost its unique actual approved quota policy')
    policy = decode_contact_policy(policies[0],namespace)
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    plan,_,_,_ = read_adopted_contact_plan_v2(db,namespace=namespace,contact_id=content.contact_id,issuer=issuer)
    expected_claim = ContactClaimV2(content.contact_id,parent_action.communication_action_id,plan.target_entity_ref,
        policy.channel,policy.category,tuple(item.segment.effect_id for item in content.segments),(),
        'claimed',policy.policy_id,policy.version,contact_window_id_v2(policy),policy.window_start,policy.window_end,
        plan.policy_original_ref,plan.policy_original_digest)
    if canonical_serialize(claim)!=canonical_serialize(expected_claim):
        raise ValueError('Contact COMMIT actual whole claim/window/approval differs from its signed plan')
    expected_job,expected_outbox = contact_final_runtime_ids_v3(namespace,content.contact_id,content.activity_id)
    bucket_digest = canonical_digest((namespace,claim.subject_ref,claim.channel,claim.category))
    if (proof['job_ref']!=expected_job.token or proof['outbox_ref']!=expected_outbox.token
            or batch.content!=content or evidence.digest!=admission.admission.candidate_digest
            or parent_action.qualification_receipt_digest!=canonical_digest(admission.admission.check_receipts)
            or parent_action.contact_policy_check_ref!=request.contact_policy_check_ref
            or request.segment_authorization_ref!=parent_action.segment_authorization_ref(evidence.segment_id)
            or request.segment_manifest_digest!=parent_action.segment_manifest_digest
            or request.segment_index!=evidence.segment_index
            or request.segment_count!=len(parent_action.segment_grants)
            or claim.contact_id!=content.contact_id or claim.communication_action_id!=parent_action.communication_action_id
            or claim.window_id!=contact_window_id_v2(policy) or claim.policy_version!=policy.version
            or request.footprint.communication_action!=parent_action.communication_action_id
            or request.footprint.object_gate_keys!=('contact-object:'+bucket_digest,)
            or request.footprint.quota_occupancies!=(QuotaOccupancy('contact-quota:'+bucket_digest,claim.window_id,1),)
            or outbox.job_id!=job.job_id or outbox.job_ref!=proof['job_ref'] or outbox.phase!='pending'
            or outbox.operation_id!=request.operation_id or outbox.effect_id!=request.effect_id
            or outbox.dispatch_generation!=request.dispatch_generation or outbox.payload_ref!=request.payload_ref
            or outbox.idempotency_key!=request.footprint.external_idempotency_ref):
        raise ValueError('Contact COMMIT actual four-join/quota/job/outbox scope differs')
    if (db.execute('SELECT operation_id,phase FROM graph_bundle_outbox WHERE bot=? AND persona=? AND outbox_ref=?',
            (*namespace.as_tuple,proof['outbox_ref'])).fetchone() != (request.operation_id,'pending')
            or db.execute('SELECT job_id,operation_id FROM graph_outbox_jobs WHERE bot=? AND persona=? AND outbox_ref=?',
                (*namespace.as_tuple,proof['outbox_ref'])).fetchone() != (job.job_id,request.operation_id)):
        raise ValueError('Contact COMMIT durable outbox/job binding differs')
    for row in proof['write_commitments']:
        key = AtomKey.from_token(row['ref'])
        if key.owner.bot != namespace.bot_id or key.owner.persona != namespace.persona_id or type(row['revision']) is not int:
            raise ValueError('Contact COMMIT member crossed its namespace/version')
        history = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
            (key.token, row['revision'])).fetchone()
        current = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
            (key.token, *namespace.as_tuple)).fetchone()
        if (history is None or history[0] != result['operation_id'] or history[2] != 1
                or canonical_digest(json.loads(history[1])) != row['digest']
                or current != (row['revision'], history[1], 1)):
            raise ValueError('Contact COMMIT actual member/current head differs')
    job = get_job(db, AtomKey.from_token(proof['job_ref']).name)
    if (job.phase != 'waiting' or job.fence != 0 or job.cancel_epoch != 0
            or job.operation_id != request.operation_id or job.effect_id != request.effect_id
            or job.wake_condition != {'kind':'contact_host_takeover', 'operation_id':request.operation_id}):
        raise ValueError('Contact COMMIT waiting job identity differs')
    actual_job = db.execute('SELECT value FROM graph_atoms WHERE token=?', (proof['job_ref'],)).fetchone()
    if actual_job is None or canonical_serialize(json.loads(actual_job[0])) != canonical_serialize(job_graph_write(job).value):
        raise ValueError('Contact COMMIT durable job and Graph projection differ')
    validate_contact_final_result_v3(result,original=original,job_id=job.job_id,
        admission_ref=admission.admission.admission_ref,dispatch_request_digest=canonical_digest(request))
    return issued
