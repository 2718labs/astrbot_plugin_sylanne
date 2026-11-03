"""Fixed installed background consumer of actual adopted domain outbox rows."""
from dataclasses import dataclass, replace, asdict
import json
import time
from .domain_background_read_v3 import (background_point_v3,background_json_loads_v3,bind_background_reads_v3)

from ..contracts import canonical_json, Event, Scope
from ..graph_store import GraphStore
from ..graph_types import owner_grant_key, GraphCandidate
from ..runtime_contracts import AuthorityContext, OperationIdentity, QueryEpoch, canonical_digest
from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
from .domain_production_contracts_v1 import ProductionOutboxStageV1, ProductionOriginalRefV1
from .d01_production_operations_v1 import MissingProductionOriginalV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .domain_production_followups_v1 import (read_plan_current_domain_followup_v1,resolve_domain_followup_v1,
    OrdinaryContinuityFollowupCommandV1,ordinary_continuity_event_v1,read_ordinary_continuity_cause_v1,
    require_ordinary_continuity_budget_v1,ordinary_continuity_trigger_kind_v1,
    SingleEventReviewFollowupCommandV1,single_event_review_event_v1,single_event_review_trigger_kind_v1,
    require_single_event_review_budget_v1,native_growth_followup_command_v1,native_growth_followup_command_operation_v1,read_single_event_review_cause_v1)
from .contact_followup_v1 import ContactFollowupCommandV1
from .domain_production_frame_v1 import freeze_domain_production_frame_v1
from .domain_production_registry_v1 import installed_operation_v1

RESOLVER = 'sylanne.domain-followup-resolver.v1'
_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class _BackgroundFollowupV1:
    graph: object
    event: ProductionOutboxStageV1
    authority: AuthorityContext
    owner: object
    command: object
    parent_budget: str
    operation_id: str
    observed_epoch: int
    prior_receipt: object = None
    causal_original_digest: str | None = None
    general_growth_parent_metadata: object = None



def single_event_review_command_v1(event,command):
    if event.event_kind not in {'single_event_growth_review_required_v1','single_event_review_cognition_adopted_v1'}:return False
    from .domain_production_followups_v1 import DomainFollowupCommandV1
    from .d01_single_event_growth_v1 import ReviewSingleEventGrowthRequestV1
    expected=SingleEventReviewFollowupCommandV1 if event.event_kind=='single_event_review_cognition_adopted_v1' else DomainFollowupCommandV1
    if (event.receiver_domain!='d01' or type(command)is not expected
            or command.receiver_domain!='d01' or command.operation_kind!='review_single_event_growth_v1'
            or type(command.request)is not ReviewSingleEventGrowthRequestV1):
        raise ValueError('single-event review command differs from its exact registered outbox contract')
    return True


def require_background_followup_v1(value, graph, authority, operation_id):
    if (type(value) is not _BackgroundFollowupV1 or _ACTIVE.get(id(value)) is not value
            or value.graph is not graph or value.authority != authority or value.operation_id != operation_id):
        raise ValueError('actual installed background followup issuance is unavailable')
    return value.owner


def observe_background_followup_owner_v1(value, graph, authority, scope):
    require_background_followup_v1(value, graph, authority, value.operation_id)
    return _observe_owner(graph, authority, scope)


def _observe_owner(graph, authority, scope):
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    current, permit = port.get_current_background_owner_authority_for_fence_v1(namespace=authority.namespace,
        authority_namespace=scope.authority_namespace, permit=scope.permit)
    if type(current) is not D12CurrentOwnerAuthorityV1 or permit != scope.permit:
        raise ValueError('current background Owner authority differs')
    pairing = port.current_owner_actor_binding(namespace=authority.namespace,
        authority_namespace=scope.authority_namespace, actor_id=authority.actor)
    if pairing is None or pairing.installation_id != port.installation_grant.installation_id:
        raise ValueError('background Owner actor is no longer paired')
    with store._lock:
        owner = graph._owner_graph_binding_locked(authority, pairing.principal,
            target_admission=current.target_admission, storage_admission=current.storage_admission,
            current_guard=current.guard)
    if (owner.authorization_head != current.guard.authorization_head
            or owner.authorization_revision != current.guard.authorization_revision
            or current.guard.pending_revoke_operation_id is not None):
        raise ValueError('background Owner original/head changed')
    return current.guard, owner


def _event(db, namespace, dedupe, issuer):
    specialized=db.execute("SELECT event_kind FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",(*namespace.as_tuple,dedupe)).fetchone()
    if specialized is not None and specialized[0] in {"artifact_task_wait_registered","artifact_task_amendment_adopted","owner_source_note_task_submitted_v1"}:
        raise ValueError("artifact task events require their actual Self continuation consumer")
    row=background_point_v3(db,table='graph_domain_production_outbox_v1',
        columns=('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state','receipt_json'),
        key_columns=('bot','persona','dedupe_key'),key=(*namespace.as_tuple,dedupe),
        legacy_reader=lambda:db.execute('SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state,receipt_json '
            'FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?',(*namespace.as_tuple,dedupe)).fetchone())
    if row is None or row[5] not in {'pending','waiting','completed'}:
        raise ValueError('actual background outbox original is unavailable')
    from .domain_production_followups_v1 import read_general_growth_lifecycle_cause_v1
    from .d01_single_event_growth_v1 import read_single_event_followup_cause_v1
    original=read_ordinary_continuity_cause_v1(db,namespace=namespace,event_kind=row[2],
        causal_operation_id=row[0],original_ref=row[3],issuer=issuer)
    if original is None:
        original=read_single_event_review_cause_v1(db,namespace=namespace,event_kind=row[2],
            causal_operation_id=row[0],original_ref=row[3],issuer=issuer)
    if original is None:
        original=read_single_event_followup_cause_v1(db,namespace=namespace,event_kind=row[2],
            causal_operation_id=row[0],original_ref=row[3],issuer=issuer)
    if original is None:
        original=read_general_growth_lifecycle_cause_v1(db,namespace=namespace,event_kind=row[2],
            causal_operation_id=row[0],original_ref=row[3],issuer=issuer)
    if original is None:
        from .d07_general_growth_attention_v1 import read_general_growth_followup_cause_v1
        original = read_general_growth_followup_cause_v1(db, namespace=namespace, event_kind=row[2],
            causal_operation_id=row[0], original_ref=row[3], issuer=issuer)
    if original is None:
        original = read_adopted_domain_operation_v1(db, namespace, row[0])
    if original is None:
        raise ValueError('background causal adoption changed')
    trigger_kind=single_event_review_trigger_kind_v1(row[2])or ordinary_continuity_trigger_kind_v1(row[2])or ('d01.'+original['general_lifecycle_kind']if 'general_lifecycle_kind'in original
        else original['domain']+'.current-'+original['operation_kind'])
    event = ProductionOutboxStageV1(namespace,row[0],row[1],row[2],ProductionOriginalRefV1(trigger_kind,row[3],row[4]))
    if event.dedupe_key != dedupe:
        raise ValueError('background outbox identity changed')
    from .domain_production_followups_v1 import verify_current_followup_trigger_v1
    verify_current_followup_trigger_v1(db, namespace, event, original, issuer)
    return event, original, row[5], None if row[6] is None else background_json_loads_v3(row[6])


def _resolve(graph, db, event, authority, owner, scope, now):
    # Decode only the installed closed CommandEnvelope wire retained by actual
    # causal adoption; it supplies intent identities, never current authority.
    from .d07_general_growth_attention_v1 import (TRIGGER_EVENT, general_growth_followup_parent_v1,
        bind_general_growth_followup_parent_v1, general_growth_parent_metadata_status_v1,
        read_general_growth_followup_cause_v1, read_plan_general_growth_followup_v1)
    from .domain_background_read_v3 import _active_v3
    issuer=graph._GraphCoordinator__d11_issuer
    reader=_active_v3(db)
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    trial_child=(reader is not None and reader.kind=='followup_child'
        and type(reader.handoff.command)is GeneralGrowthTrialFollowupCommandV1)
    general=event.event_kind in (TRIGGER_EVENT,'general_growth_attention_available_for_service')and not trial_child
    trigger=general_growth_followup_parent_v1(db,event=event,issuer=issuer) if general or trial_child else None
    if reader is not None and general:bind_general_growth_followup_parent_v1(db,reader,event,trigger)
    from .domain_production_followups_v1 import read_general_growth_lifecycle_cause_v1,_GENERAL_GROWTH_LIFECYCLE_V1
    lifecycle=event.event_kind in _GENERAL_GROWTH_LIFECYCLE_V1
    from .d01_single_event_growth_v1 import read_single_event_followup_cause_v1
    ordinary=ordinary_continuity_event_v1(event.event_kind)
    review=single_event_review_event_v1(event.event_kind)
    original=read_ordinary_continuity_cause_v1(db,namespace=authority.namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,issuer=issuer)
    if original is None:
        original=read_single_event_review_cause_v1(db,namespace=authority.namespace,event_kind=event.event_kind,
            causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,issuer=issuer)
    if original is None:
        original=read_single_event_followup_cause_v1(db,namespace=authority.namespace,event_kind=event.event_kind,
            causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,issuer=issuer)
    if original is None:
        original=read_general_growth_lifecycle_cause_v1(db,namespace=authority.namespace,event_kind=event.event_kind,
            causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,issuer=issuer)if lifecycle else None
    if original is None:
        original=read_general_growth_followup_cause_v1(db,namespace=authority.namespace,event_kind=event.event_kind,
            causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,issuer=issuer) if general else None
    if original is None:original=read_adopted_domain_operation_v1(db,authority.namespace,event.causal_operation_id)
    missing=general_growth_parent_metadata_status_v1(db,trigger=trigger,owner=owner,authority=authority,
        issuer=issuer,now=now) if general else None
    if ordinary or review:authority=replace(authority,purpose='consolidation')
    ordinary_missing=None
    service_completion=None
    owner_job=_actual_native_attention_job_v1(reader,event,original)
    if event.event_kind=='ordinary_continuity_attention_available_for_service' and reader is not None:
        service_completion=_ordinary_service_completion_v1(reader,event,original,_ORDINARY_SERVICE_PRIORS_V1.get(reader))
    if ordinary and service_completion is None and owner_job is None:
        try:require_ordinary_continuity_budget_v1(db,namespace=authority.namespace,original=original,issuer=issuer,now=now)
        except MissingProductionOriginalV1 as error:ordinary_missing=error
    if event.event_kind=='single_event_review_attention_available_for_service' and reader is not None:
        service_completion=_single_event_service_completion_v1(reader,event,original,_ORDINARY_SERVICE_PRIORS_V1.get(reader))
    if review and service_completion is None and owner_job is None:
        try:require_single_event_review_budget_v1(db,namespace=authority.namespace,original=original,issuer=issuer,now=now)
        except MissingProductionOriginalV1 as error:ordinary_missing=error
    if general and missing is None:authority=replace(authority,purpose='consolidation')
    deadline=trigger.original_deadline_utc if general and missing is None else now+60
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    from ..runtime_contracts import CommandEnvelope, RUNTIME_SCHEMA, VersionGuard, SourceQualification
    ns = authority.namespace
    metadata, epoch = graph._v2_graph_stamp(ns)
    versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
        "AND ref='current' AND kind IN ('scheme','operator','policy')", ns.as_tuple))
    envelope = CommandEnvelope(RUNTIME_SCHEMA,
        OperationIdentity('domain-followup:'+event.dedupe_key[:48], None, 'domain-followup:'+event.dedupe_key[:48],
            'resolve_followup', event.dedupe_key, canonical_digest({'input_refs':[]})), authority,
        VersionGuard((),(QueryEpoch(ns,'namespace',epoch.revision),),owner.access_epoch,owner.delete_epoch,
            graph._GraphCoordinator__store._registry.catalogue_hash, versions['scheme'],versions['operator'],versions['policy'],(),(),()),
        SourceQualification((),'derived',None,now,'inference','ineligible',None,'not_applicable'),(),
        original['payload']['parent_budget'],deadline,time.monotonic()+max(0,deadline-now),'domain-followup:'+event.dedupe_key[:48],())
    if owner_job is not None:
        from .d01_production_operations_v1 import production_read_plan_v1
        plan=production_read_plan_v1((),(),(),())
    elif trial_child or event.event_kind=='general_growth_action_outcome_available':
        from .d01_production_operations_v1 import production_read_plan_v1
        plan=production_read_plan_v1((),(),(),())
    elif lifecycle:
        from .d01_production_operations_v1 import production_read_plan_v1
        plan=production_read_plan_v1((),(),(),(event.trigger_original.original_ref,))
    elif general:
        from .d01_production_operations_v1 import production_read_plan_v1
        plan=production_read_plan_v1((),(),(),()) if missing is not None else read_plan_general_growth_followup_v1(
            db,namespace=ns,event=event,trigger=trigger,issuer=issuer)
    else:plan=read_plan_current_domain_followup_v1(db,namespace=ns,event=event)
    causal = event.trigger_original if ordinary or review else ProductionOriginalRefV1(original['domain']+'.current-'+original['operation_kind'],
        event.trigger_original.original_ref, event.trigger_original.original_digest)
    frame = freeze_domain_production_frame_v1(graph, db, envelope=envelope, current_owner=owner, scope=scope,
        plan=plan, now_utc=now, observed_originals=(causal,), limits=ProductionOperationLimitsV1())
    if service_completion is not None:
        from .domain_production_followups_v1 import DomainFollowupResolutionV1
        status='single_event_review_service_observed' if review else 'ordinary_service_observed'
        return frame,DomainFollowupResolutionV1(status,(),(),())
    if owner_job is not None:
        from .domain_production_followups_v1 import DomainFollowupResolutionV1
        return frame,DomainFollowupResolutionV1("native_attention_job_waiting",(),(),("actual_d07_original_execution",),owner_job.job_id)
    if ordinary_missing is not None:
        from .domain_production_followups_v1 import DomainFollowupResolutionV1
        return frame,DomainFollowupResolutionV1('waiting_for_original',(),(),tuple(ordinary_missing.missing_inputs))
    if general and missing is not None:
        from .domain_production_followups_v1 import DomainFollowupResolutionV1
        return frame,DomainFollowupResolutionV1('waiting_for_original',(),(),(missing,),
            'general-growth-followup:'+canonical_digest((ns,event.dedupe_key))[:48])
    if trial_child:
        from .domain_production_followups_v1 import resolve_general_growth_trial_metadata_v1
        return frame,resolve_general_growth_trial_metadata_v1(db,frame,event,original,issuer=issuer)
    return frame, resolve_domain_followup_v1(db, frame, event, installed_graph=graph)


def validate_followup_command_in_transaction_v1(value, graph, db, scope, owner, now):
    require_background_followup_v1(value, graph, value.authority, value.operation_id)
    if native_growth_followup_command_v1(value.command):
        return _validate_actual_ordinary_child_write_v1(value,graph,db,scope,owner,now)
    frame, resolution = _resolve(graph, db, value.event, value.authority, owner, scope, now)
    if resolution.status in {'ordinary_service_observed','single_event_review_service_observed'}:
        from .domain_background_read_v3 import _active_v3
        reader=_active_v3(db)
        getter=_single_event_service_completion_v1 if resolution.status=='single_event_review_service_observed' else _ordinary_service_completion_v1
        fact=getter(reader,value.event,reader.local_result[1],value.prior_receipt)
        if fact is None:raise ValueError('ordinary service completion lost its actual current adopted original')
        _ORDINARY_SERVICE_WRITES_V1[id(value)]=(value,db,scope,fact)
    from .domain_background_read_v3 import _active_v3
    reader=_active_v3(db)
    fact=None if reader is None else _NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader)
    if value.command is None and _uses_native_attention_job_disposition_v1(value.event,value.prior_receipt,fact):
        job_preparation=_require_native_job_disposition_binding_v1(reader,value.event,reader.local_result[1],value.prior_receipt,fact)
        _NATIVE_ATTENTION_JOB_WRITES_V1[id(value)]=(value,db,scope,fact,job_preparation)
    if value.command is not None and value.command not in resolution.commands:
        raise ValueError('background command is no longer derived from the current exact outbox')
    return frame, resolution


def _save_disposition(graph, db, issued, resolution, result):
    event = issued.event
    if native_growth_followup_command_v1(issued.command):
        binding=_ORDINARY_CHILD_WRITES_V1.get(id(issued))
        if binding is None or binding[0]is not issued or binding[1]is not db:
            raise ValueError('ordinary disposition lost the actual current Method outbox metadata')
        old=binding[5]
    else:
        old = issued.prior_receipt if issued.causal_original_digest is not None else _event(db, issued.authority.namespace, event.dedupe_key, graph._GraphCoordinator__d11_issuer)[3]
    native_job_binding=_NATIVE_ATTENTION_JOB_WRITES_V1.get(id(issued))
    if native_job_binding is not None and (native_job_binding[0]is not issued or native_job_binding[1]is not db):
        raise ValueError("native attention waiting disposition lost its actual fresh WRITE binding")
    completed = [] if old is None else list(old['completed_commands'])
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    general_command=type(issued.command)is GeneralGrowthTrialFollowupCommandV1
    from .joint_node_execution_v1 import JOINT_EVENTS
    from .persona_growth_review_contract_v1 import GROWTH_EVENTS_V1
    if event.event_kind in JOINT_EVENTS or event.event_kind in GROWTH_EVENTS_V1.values():
        current_commands = {canonical_digest(command) for command in resolution.commands}
        completed = [item for item in completed if item['command_digest'] in current_commands]
    command_digest = None if issued.command is None else canonical_digest(issued.command)
    structural = (issued.command is not None and issued.command.operation_kind == 'encode_structured_experience'
        and result.get('operation_kind') == 'encode_structured_experience' and result.get('coverage') == 'partial'
        and result.get('missing_inputs') == ['actual_d04_then_feeling_and_d06_subjective_trace_encoding'])
    service_handoff=(event.event_kind in {'ordinary_continuity_attention_available_for_service','single_event_review_attention_available_for_service'}
        and native_growth_followup_command_v1(issued.command)
        and issued.command.operation_kind=='serve_concern'
        and _ORDINARY_D07_PREPARATIONS_V1.get(id(issued))is not None
        and result.get('coverage')=='deferred')
    if (not general_command and command_digest is not None and result.get('schema') == 'sylanne.domain-production-receipt.v1'
            and (result.get('coverage') == 'complete' or structural or service_handoff)):
        item = {'command_digest':command_digest,'operation_id':issued.operation_id,'receipt_digest':result['receipt_digest']}
        if item not in completed: completed.append(item)
    expected = {canonical_digest(command) for command in resolution.commands if type(command)is not GeneralGrowthTrialFollowupCommandV1}
    no_match=(resolution.status=='no_matching_general_start'and issued.event.event_kind=='general_growth_action_outcome_available'
        and not resolution.commands and not resolution.target_refs and not resolution.missing_originals)
    growth_observed = (resolution.status == 'growth_review_observed' and issued.event.event_kind in {
        'persona_growth_requires_commitment_reevaluation', 'persona_growth_requires_life_reevaluation',
        'single_event_growth_review_required_v1','ordinary_continuity_assessment_available'}
        and not resolution.commands and not resolution.missing_originals)
    all_done = no_match or growth_observed or resolution.status == 'ready' and not any(type(command)is GeneralGrowthTrialFollowupCommandV1 for command in resolution.commands) and expected <= {item['command_digest'] for item in completed}
    service_completed=False
    if event.event_kind in {'ordinary_continuity_attention_available_for_service','single_event_review_attention_available_for_service'}:
        service_binding=_ORDINARY_SERVICE_WRITES_V1.get(id(issued))
        service_completed=(issued.command is None and resolution.status in {'ordinary_service_observed','single_event_review_service_observed'}
            and service_binding is not None and service_binding[0]is issued and service_binding[1]is db)
        all_done=service_completed
    state = 'completed' if all_done else 'waiting'
    missing = list(resolution.missing_originals)
    if command_digest is not None and result.get('coverage') != 'complete':
        missing += list(result.get('missing_inputs', ('current_child_operation_originals',)))
    missing = list(dict.fromkeys(missing))
    if len(completed)>16 or len(missing)>128:raise ValueError('followup disposition exceeds installed bound')
    _, epoch = graph._v2_graph_stamp(issued.authority.namespace)
    continuation=result.get('continuation_ref')or resolution.continuation_ref
    if event.event_kind in {'ordinary_continuity_attention_available_for_service','single_event_review_attention_available_for_service'}:
        if service_completed:
            missing=[];continuation=None
        elif continuation is None and old is not None:
            continuation=old['continuation_ref']
            missing=list(dict.fromkeys((*missing,*old['missing_originals'])))
    if issued.event.event_kind in('general_growth_action_outcome_available','actual_life_outcome_available_for_growth'):
        from .domain_background_read_v3 import _active_v3
        census=_active_v3(db).general_trial_census
        if (not result.get('continuation_ref') and census is not None
                and census.complete and census.incomplete_count):
            if general_command or issued.command is None:
                continuation='general-start-cursor:'+(census.matches[-1][0]if census.matches else '')
            else:continuation=None if old is None else old['continuation_ref']
    receipt = {'schema':'sylanne.domain-followup-disposition.v1','resolver_version':RESOLVER,
        'dedupe_key':event.dedupe_key,'causal_operation_id':event.causal_operation_id,
        'causal_original_digest':issued.causal_original_digest or read_adopted_domain_operation_v1(db,issued.authority.namespace,event.causal_operation_id)['original_digest'],
        'trigger_original_digest':event.trigger_original.original_digest,
        'manifest_digest':graph._GraphCoordinator__content_fence_v2.installation_grant.manifest_digest,
        'state':state,'observed_epoch':epoch.revision,'completed_commands':completed,
        'missing_originals':missing,'continuation_ref':continuation,
        'consumer_operation_id':issued.operation_id}
    if native_job_binding is not None:
        from .domain_production_followups_v1 import _NATIVE_ATTENTION_JOB_SCHEMA_V1
        if issued.command is not None or completed:
            raise ValueError("observing an Owner prepared job cannot invent completed followup commands")
        receipt["schema"]=_NATIVE_ATTENTION_JOB_SCHEMA_V1
        receipt["job_preparation"]=native_job_binding[4]
        if state=="waiting":
            receipt["continuation_ref"]=native_job_binding[3].job_id
            receipt["missing_originals"]=["actual_d07_original_execution"]
        else:
            receipt["continuation_ref"]=None;receipt["missing_originals"]=[]
    db.execute('UPDATE graph_domain_production_outbox_v1 SET state=?,consumer_operation_id=?,receipt_json=? '
        'WHERE bot=? AND persona=? AND dedupe_key=? AND state IN (\'pending\',\'waiting\')',
        (state,issued.operation_id,canonical_json(receipt),*issued.authority.namespace.as_tuple,event.dedupe_key))
    if db.execute('SELECT changes()').fetchone() != (1,): raise ValueError('background outbox disposition raced')
    return receipt


def finish_followup_command_in_transaction_v1(value, graph, db, resolution, result):
    require_background_followup_v1(value, graph, value.authority, value.operation_id)
    if native_growth_followup_command_v1(value.command):
        return finish_actual_ordinary_continuity_child_v1(value,graph,db,result)
    return _save_disposition(graph,db,value,resolution,result)


def _consume_legacy_domain_followup_v1(graph, bootstrap, bundle, *, dedupe_key):
    graph._admin(bootstrap)
    ns, store, port = bundle.installation_policy.namespace, graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise ValueError('followup consumer lacks its actual installed assembly')
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(ns)
        row = store._db.execute('SELECT value FROM graph_atoms WHERE token=?',(owner_grant_key(*ns.as_tuple).token,)).fetchone()
        if row is None: raise ValueError('followup Owner grant is absent')
        principal = OwnerPrincipalV1(**json.loads(row[0])['principal'])
        store._db.execute('BEGIN')
        try: event, original, state, prior = _event(store._db, ns, dedupe_key, graph._GraphCoordinator__d11_issuer)
        finally: store._db.rollback()
    pairing = port.current_owner_principal_binding(namespace=ns,authority_namespace=metadata.requirements.authority_namespace,principal=principal)
    if pairing is None: raise ValueError('followup Owner is unpaired')
    prior_authority = original['payload']['authority']
    authority = AuthorityContext(pairing.actor_id,'d12','installed-followup:'+dedupe_key[:48],ns,
        tuple(prior_authority['owner_scope']),prior_authority['purpose'],tuple(prior_authority['audience']),
        port.installation_grant.publisher_policy_ref,metadata.requirements.activation_generation)
    captured = []
    def observer(scope):
        observed = _observe_owner(graph,authority,scope)
        captured[:] = [(scope,*observed)]
        return observed
    from .first_ingress_v2 import trusted_upper
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    def read():
        db=store._db;db.execute('BEGIN')
        try:
            actual_event,_,actual_state,actual_prior = _event(db,ns,dedupe_key,graph._GraphCoordinator__d11_issuer)
            if actual_event!=event:raise ValueError('followup changed before current read')
            if actual_state=='completed' or (event.event_kind not in {'qualified_contact_opportunity_requires_action','single_event_growth_review_required_v1'} and actual_prior is not None and actual_prior['observed_epoch']==graph._v2_graph_stamp(ns)[1].revision):
                return None,actual_prior
            return _resolve(graph,db,event,authority,captured[0][2],captured[0][0],now),actual_prior
        finally:db.rollback()
    observed, prior = graph._read_v2(authority,read,fence_observer=observer)
    if observed is None:return prior
    frame,resolution=observed
    done=set() if prior is None else {item['command_digest'] for item in prior['completed_commands']}
    command=next((item for item in resolution.commands if canonical_digest(item) not in done),None)
    op=command.operation_id if type(command) is ContactFollowupCommandV1 else 'domain-consume:'+canonical_digest((ns,dedupe_key,RESOLVER,
        canonical_digest(command) if command is not None else None,frame.snapshot.epochs[0].revision))[:48]
    if command is not None:
        if command.operation_kind not in {'mark_goal_growth_review_v1','mark_life_growth_review_v1','recheck_action','prepare_contact','encode_structured_experience','adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1','input:qualify_joint_plan_nodes_v1','input:observe_joint_external_node_v1','input:prepare_joint_external_semantic_question_v1','serve_concern'} and not single_event_review_command_v1(event,command):
            raise ValueError('background resolver has no installed pure receiver for this command')
        authority=replace(authority,audience=command.audience_refs or (command.audience_ref,),
            purpose='expression' if command.operation_kind in {'adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1'} else authority.purpose)
    issued=_BackgroundFollowupV1(graph,event,authority,captured[0][2],command,original['payload']['parent_budget'],op,epoch.revision)
    _ACTIVE[id(issued)]=issued
    try:
        if command is not None:
            result = graph._GraphCoordinator__domain_production_runtime_v1.run_current(authority,None,
                operation_kind=command.operation_kind,request=command.request,operation_id=op,
                activity_id=command.activity_id,audience_ref=command.audience_ref,
                parent_budget_lease_ref=issued.parent_budget,_background_followup=issued)
            if result.get('outbox'):
                wake = getattr(graph,'_GraphCoordinator__domain_followup_wake_v1',None)
                if callable(wake):wake()
            return result
        observed_write=[]
        def context(scope,guard,owner):
            from contextlib import nullcontext
            observed_write[:]=[(scope,owner)]
            return nullcontext()
        def commit(db,metadata,epoch,now,owner,scope):
            current_frame,current_resolution=validate_followup_command_in_transaction_v1(issued,graph,db,scope,owner,now)
            prior_receipt=_event(db,ns,dedupe_key,graph._GraphCoordinator__d11_issuer)[3]
            done=set() if prior_receipt is None else {item['command_digest'] for item in prior_receipt['completed_commands']}
            if any(canonical_digest(command) not in done for command in current_resolution.commands):
                raise ValueError('followup became ready; request a fresh exact command')
            candidate=GraphCandidate(Event(Scope(*ns.as_tuple,'domain.followup.v1'),op,now,RESOLVER,
                {'dedupe_key':dedupe_key,'causal_original_digest':event.trigger_original.original_digest}),
                current_frame.snapshot.versions,(),(epoch,))
            receipt=GraphStore._graph_commit_in_transaction(store,candidate,_capability=graph._GraphCoordinator__graph_capability)
            if receipt.status!='committed':raise ValueError('followup read event CAS failed')
            store.cas_graph_recovery_metadata(metadata,metadata.requirements,_capability=graph._GraphCoordinator__graph_capability)
            prior_seq=db.execute('SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
            seq=(0 if prior_seq is None else prior_seq[0])+1
            db.execute('INSERT INTO graph_bundle_sequence VALUES(?,?,?) ON CONFLICT(bot,persona) '
                'DO UPDATE SET last_seq=excluded.last_seq',(*ns.as_tuple,seq))
            db.execute('INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) '
                'VALUES(?,?,?,?,?,NULL,?,?)',(*ns.as_tuple,op,canonical_digest(candidate),'domain.followup.v1',seq,
                canonical_json({'ledger_refs':[],'outbox_refs':[]})))
            return _save_disposition(graph,db,issued,current_resolution,{})
        return graph._owner_domain_write_v3(authority,None,operation_id=op,
            request_digest=canonical_digest((RESOLVER,event.dedupe_key,op)),domains=(event.receiver_domain,),
            capability='workbench.read',commit=commit,fence_context=context,background_original=issued)
    finally:
        _ORDINARY_SERVICE_WRITES_V1.pop(id(issued),None)
        _NATIVE_ATTENTION_JOB_WRITES_V1.pop(id(issued),None)
        _ACTIVE.pop(id(issued),None)



def consume_current_domain_followup_v1(graph,bootstrap,bundle,*,dedupe_key,context=None):
    from .habit_maintenance_followup_v3 import prepare_current_habit_maintenance_followup_v3
    handled,work=prepare_current_habit_maintenance_followup_v3(graph,bootstrap,bundle,dedupe_key=dedupe_key,context=context)
    if handled:return work
    from .habit_followup_source_v3 import prepare_current_habit_followup_v3
    handled,work=prepare_current_habit_followup_v3(graph,bootstrap,bundle,dedupe_key=dedupe_key,context=context)
    if handled:return work
    from .current_conditioned_self_read_v3 import prepare_current_conditioned_followup_v3
    handled,work=prepare_current_conditioned_followup_v3(graph,bootstrap,bundle,dedupe_key=dedupe_key)
    if handled:return work
    from ..runtime_storage_v3 import runtime_storage_v3
    if runtime_storage_v3(graph._GraphCoordinator__store._db)is None:
        return _consume_legacy_domain_followup_v1(graph,bootstrap,bundle,dedupe_key=dedupe_key)
    from .domain_background_read_v3 import prepare_domain_background_read_v3,raise_background_work_error_v3
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    work=prepare_domain_background_read_v3(graph,bootstrap,bundle,kind='followup',
        operation_id='domain-followup:'+dedupe_key[:48],deadline_utc=now+60,dedupe_key=dedupe_key)
    work.map_terminal_v3('issuer',lambda prepared:finish_background_followup_preparation_v3(graph,prepared),raise_background_work_error_v3)
    return work


def prepare_background_followup_data_v3(reader):
    graph,db,ns=reader.graph,reader.db,reader.namespace
    event,original,state,prior=_event(db,ns,reader.dedupe_key,graph._GraphCoordinator__d11_issuer)
    if state=='completed':return (event,original,state,prior,None,None,None,None)
    if event.event_kind in {'ordinary_continuity_attention_available_for_service','single_event_review_attention_available_for_service'}:
        _ORDINARY_SERVICE_PRIORS_V1[reader]=prior
    actual_job=_actual_native_attention_job_v1(reader,event,original)
    from .contact_initial_plan_source_v3 import require_initial_contact_plan_source_v3
    require_initial_contact_plan_source_v3(reader,event,original)
    from .joint_node_execution_v1 import JOINT_EVENTS
    if reader.kind=='followup'and not ordinary_continuity_event_v1(event.event_kind)and not single_event_review_event_v1(event.event_kind)and event.event_kind not in JOINT_EVENTS and event.event_kind not in('qualified_contact_opportunity_requires_action','general_growth_action_outcome_available','actual_life_outcome_available_for_growth','single_event_growth_review_required_v1') and prior is not None and prior['observed_epoch']==reader.graph_stamp[1].revision:
        return (event,original,'unchanged',prior,None,None,None,None)
    if event.event_kind=='ordinary_continuity_attention_available_for_service' and _ordinary_service_prior_job_v1(event,original,prior) is not None:
        completion=_ordinary_service_completion_v1(reader,event,original,prior)
        if completion is None:
            return (event,original,'ordinary_execution_pending',prior,None,None,None,None)
    if _single_event_service_prior_job_v1(event,original,prior) is not None:
        if _single_event_service_completion_v1(reader,event,original,prior) is None:
            return (event,original,'ordinary_execution_pending',prior,None,None,None,None)
    if _uses_native_attention_job_disposition_v1(event,prior,actual_job):
        _require_native_job_disposition_binding_v1(reader,event,original,prior,actual_job)
        from .domain_production_followups_v1 import _NATIVE_ATTENTION_JOB_SCHEMA_V1
        if prior is not None and prior.get("schema")==_NATIVE_ATTENTION_JOB_SCHEMA_V1:
            completion=(_single_event_service_completion_v1 if event.event_kind=="single_event_review_attention_available_for_service"else _ordinary_service_completion_v1)(reader,event,original,prior)
            if completion is None:return (event,original,"ordinary_execution_pending",prior,None,None,None,None)
    frame,resolution=_resolve(graph,db,event,reader.authority,reader.owner,reader.fence.scope,reader.now)
    done=set()if prior is None else {item['command_digest']for item in prior['completed_commands']}
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    if reader.kind=='followup_child'and type(reader.handoff.command)is GeneralGrowthTrialFollowupCommandV1:
        command=next((c for c in resolution.commands if c==reader.handoff.command),None)
    else:
        available=tuple(c for c in resolution.commands if canonical_digest(c)not in done)
        last=None if prior is None else prior['consumer_operation_id']
        if (event.event_kind=='actual_life_outcome_available_for_growth'and type(last)is str
                and last.startswith(('general-growth-trial:','general-growth-wait:','general-start-handoff:'))):
            command=next((c for c in available if type(c)is not GeneralGrowthTrialFollowupCommandV1),None)
            if command is None:command=next(iter(available),None)
        else:command=next(iter(available),None)
    op=command.operation_id if type(command) is ContactFollowupCommandV1 else 'domain-consume:'+canonical_digest((ns,event.dedupe_key,RESOLVER,
        canonical_digest(command)if command is not None else None,frame.snapshot.epochs[0].revision))[:48]
    from .d07_general_growth_attention_v1 import general_growth_background_parent_v1,general_growth_attention_ids_v1
    parent=general_growth_background_parent_v1(reader)
    if type(command)is GeneralGrowthTrialFollowupCommandV1:
        op='general-growth-trial:'+canonical_digest((ns,command.start_original_digest,command.request.settled_progress_ref))[:48]
    elif parent is not None and command is not None:
        if command.operation_kind=='register_general_growth_attention_v1':
            op=general_growth_attention_ids_v1(ns,parent.outcome_original.original_digest,
                command.request.target_block,command.request.scope)['operation']
        else:op='general-growth-serve:'+canonical_digest((ns,command.activity_id))[:48]
    if native_growth_followup_command_v1(command):
        op=native_growth_followup_command_operation_v1(ns,command)
    if _uses_native_attention_job_disposition_v1(event,prior,_NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader)):
        from .domain_production_followups_v1 import native_attention_job_observer_operation_v1
        job_preparation=_require_native_job_disposition_binding_v1(reader,event,original,prior,_NATIVE_ATTENTION_OWNER_JOBS_V1[reader])
        op=native_attention_job_observer_operation_v1(ns,event.dedupe_key,job_preparation,frame.snapshot.epochs[0].revision)
    from .joint_node_execution_v1 import joint_qualification_operation_id_v1, current_joint_executor_wakes_v1
    if command is not None and command.operation_kind == 'input:qualify_joint_plan_nodes_v1':
        op = joint_qualification_operation_id_v1(ns, command.request)
    if command is not None and command.operation_kind == 'serve_concern' and command.request.trigger_original_ref.startswith('joint-external-question:'):
        op = 'joint-cognition:' + canonical_digest((ns, command.request.trigger_original_ref))[:48]
    reader.joint_executor_wakes = ()
    if event.event_kind in JOINT_EVENTS and command is None:
        reader.joint_executor_wakes = current_joint_executor_wakes_v1(db, frame=frame, resolution=resolution,
            issuer=graph._GraphCoordinator__d11_issuer, require_adopted_qualification=True)
    elif command is not None and command.operation_kind == 'input:qualify_joint_plan_nodes_v1':
        reader.joint_executor_wakes = current_joint_executor_wakes_v1(db, frame=frame, resolution=resolution,
            issuer=graph._GraphCoordinator__d11_issuer, require_adopted_qualification=False)
    child_frame=None
    if reader.kind=='followup_child':
        from .domain_background_read_v3 import require_background_followup_handoff_v3
        handoff=require_background_followup_handoff_v3(reader.handoff,graph,reader.bundle)
        if (event.causal_operation_id!=handoff.causal_operation_id or event.trigger_original!=handoff.trigger_original
                or original['original_digest']!=handoff.causal_original_digest or command!=handoff.command):
            raise ValueError('followup child proposal changed under its independently observed current inputs')
        if command is not None and not native_growth_followup_command_v1(command):
            from .domain_production_read_plans_v1 import read_plan_current_domain_operation_v1
            from .domain_production_contracts_v1 import ProductionOperationLimitsV1
            from ..runtime_contracts import OperationIdentity
            operation=installed_operation_v1(command.operation_kind)
            authority=replace(reader.authority,audience=command.audience_refs or (command.audience_ref,),
                purpose='expression' if command.operation_kind in {'adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1'} else frame.envelope.authority.purpose)
            try:
                general_readers=None
                if type(command)is GeneralGrowthTrialFollowupCommandV1:
                    from .domain_production_registry_v1 import installed_readers_for_operation_v1
                    general_readers=installed_readers_for_operation_v1(graph,operation,scope=reader.fence.scope,
                        owner_guard=reader.owner_guard,owner_binding=reader.owner)
                    plan=read_plan_current_domain_operation_v1(db,namespace=ns,activity_id=command.activity_id,
                        domain='d01',operation_kind=command.operation_kind,request=command.request,
                        operation_id=op,now_utc=reader.now,audiences=authority.audience,installed_readers=general_readers)
                elif parent is not None and command.operation_kind=='serve_concern':
                    from .d07_general_growth_attention_v1 import read_plan_general_growth_followup_v1
                    plan=read_plan_general_growth_followup_v1(db,namespace=ns,event=event,trigger=parent,
                        issuer=graph._GraphCoordinator__d11_issuer)
                else:
                    plan=read_plan_current_domain_operation_v1(db,namespace=ns,activity_id=command.activity_id,
                        domain=operation.domain,operation_kind=operation.operation_kind,request=command.request,
                        operation_id=op,now_utc=reader.now,audiences=authority.audience)
                envelope=replace(frame.envelope,identity=OperationIdentity(op,None,command.activity_id,command.operation_kind,
                    canonical_digest(command.request),frame.envelope.identity.canonical_input_digest),authority=authority)
                if type(command)in (GeneralGrowthTrialFollowupCommandV1,SingleEventReviewFollowupCommandV1):
                    envelope=replace(envelope,parent_budget_lease_ref=command.parent_budget_lease_ref,
                        deadline_utc=command.original_deadline_utc,
                        monotonic_deadline=time.monotonic()+max(0,command.original_deadline_utc-reader.now))
                child_frame=freeze_domain_production_frame_v1(graph,db,envelope=envelope,current_owner=reader.owner,
                    scope=reader.fence.scope,plan=plan,now_utc=reader.now,observed_originals=frame.observed_originals,
                    limits=ProductionOperationLimitsV1())
                if type(command)is GeneralGrowthTrialFollowupCommandV1:
                    from .d01_general_growth_v1 import validate_general_growth_outcome_followup_v1
                    validate_general_growth_outcome_followup_v1(db,frame=child_frame,request=command.request,
                        installed_readers=general_readers)
            except MissingProductionOriginalV1 as error:
                if type(command)is not GeneralGrowthTrialFollowupCommandV1:raise
                from .domain_production_followups_v1 import DomainFollowupResolutionV1
                state='general_waiting'
                resolution=DomainFollowupResolutionV1('waiting_for_original',(),(command.start_original_ref,),
                    tuple(error.missing_inputs),resolution.continuation_ref)
                child_frame=None
                op='general-growth-wait:'+canonical_digest((ns,command.start_original_digest,frame.snapshot.epochs[0].revision,tuple(error.missing_inputs)))[:48]
    return event,original,state,prior,frame,resolution,command,(op,child_frame)


def finish_background_followup_preparation_v3(graph,prepared,*,contact_plan_parent=None):
    from .domain_background_read_v3 import (PreparedBackgroundOperationV3,BackgroundFollowupProgressV3,
        BackgroundFollowupChildHandoffV3,background_followup_progress_v3)
    if type(prepared)is not PreparedBackgroundOperationV3:raise TypeError('actual background preparation result required')
    prepared.require_v3(graph);reader=prepared.owner
    from .d07_general_growth_attention_v1 import general_growth_background_parent_v1
    if getattr(reader,'contact_plan_result',None) is not None:
        return background_followup_progress_v3('child_completed',reader.contact_plan_result,None)
    event,original,state,prior,frame,resolution,command,child=prepared.local_result
    if state=='completed':return background_followup_progress_v3('completed',prior,None)
    if state=='unchanged':return background_followup_progress_v3('unchanged',prior,None)
    if state=='ordinary_execution_pending':
        _wake_actual_native_attention_job_v1(graph,prior,_NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader))
        return background_followup_progress_v3('waiting',prior,None)
    if reader.kind=='followup'and command is not None:
        handoff=BackgroundFollowupChildHandoffV3.from_prepared_v3(prepared,event,original,command,reader.owner.principal)
        from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
        if type(command)is GeneralGrowthTrialFollowupCommandV1:
            _persist_general_growth_handoff_cursor_v1(graph,reader,event,original,frame,resolution,command)
        return background_followup_progress_v3('child_ready',None,handoff)
    if reader.kind=='followup_child'and type(command)is SingleEventReviewFollowupCommandV1 and command.operation_kind in {'register_single_event_review_attention_v1','serve_concern'}:
        return graph._run_single_event_review_followup_child_v1(prepared)
    if reader.kind=='followup_child'and type(command)is OrdinaryContinuityFollowupCommandV1:
        return graph._run_ordinary_continuity_followup_child_v1(prepared)
    op,_=child
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    general_waiting=state=='general_waiting'and reader.kind=='followup_child'and type(command)is GeneralGrowthTrialFollowupCommandV1
    authority=reader.authority
    if command is not None:authority=replace(authority,audience=command.audience_refs or (command.audience_ref,),
            purpose='expression' if command.operation_kind in {'adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1'} else frame.envelope.authority.purpose)
    if _uses_native_attention_job_disposition_v1(event,prior,_NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader)):
        authority=frame.envelope.authority
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    parent_budget=command.parent_budget_lease_ref if type(command)in (GeneralGrowthTrialFollowupCommandV1,SingleEventReviewFollowupCommandV1) else original['payload']['parent_budget']
    issued=_BackgroundFollowupV1(graph,event,authority,reader.owner,command,parent_budget,op,
        frame.snapshot.epochs[0].revision,prior,original['original_digest'],
        general_growth_background_parent_v1(reader))
    if original.get('domain_original_digest')is not None:
        issued=replace(issued,causal_original_digest=original['domain_original_digest'])
    _ACTIVE[id(issued)]=issued
    try:
        with bind_background_reads_v3(reader,db=reader.db):
            if command is not None and not general_waiting:
                from .d07_general_growth_attention_v1 import general_growth_child_command_allowed_v1
                if (command.operation_kind not in('mark_goal_growth_review_v1','mark_life_growth_review_v1','recheck_action','prepare_contact','encode_structured_experience','adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1','input:qualify_joint_plan_nodes_v1','input:observe_joint_external_node_v1','input:prepare_joint_external_semantic_question_v1','serve_concern')
                        and not general_growth_child_command_allowed_v1(issued,graph,command)
                        and not general_growth_trial_child_command_allowed_v1(issued,graph,command)
                        and not single_event_review_command_v1(issued.event,command)):
                    raise ValueError('followup child has no installed exact pure receiver')
                result=graph._GraphCoordinator__domain_production_runtime_v1.run_current(authority,None,
                    operation_kind=command.operation_kind,request=command.request,operation_id=op,
                    activity_id=command.activity_id,audience_ref=command.audience_ref,
                    parent_budget_lease_ref=issued.parent_budget,_background_followup=issued,
                    _contact_plan_parent_v3=contact_plan_parent)
                if contact_plan_parent is not None:
                    from .contact_plan_physical_write_v3 import require_contact_plan_physical_v3
                    return require_contact_plan_physical_v3(result)
                if issued.command.operation_kind == 'serve_concern':
                    service = graph._GraphCoordinator__d07_execution_service_v1
                    for job_id, phase in result.get('job_states', ()):
                        if phase == 'queued': service.wake_committed_job_v1(job_id)
                if issued.command.operation_kind == 'input:qualify_joint_plan_nodes_v1' and result.get('coverage') == 'complete':
                    result = {**result, 'joint_executor_wakes': reader.joint_executor_wakes}
                return background_followup_progress_v3('child_completed',result,None)
            single_event_wake=[]
            def commit(db,metadata,epoch,now,owner,scope):
                current_frame,current_resolution=validate_followup_command_in_transaction_v1(issued,graph,db,scope,owner,now)
                if event.event_kind=='single_event_growth_review_required_v1':
                    from .d01_single_event_growth_v1 import current_single_event_followup_wake_v1
                    single_event_wake[:]=[current_single_event_followup_wake_v1(db,namespace=reader.namespace,event=event)]
                completed=set()if prior is None else {i['command_digest']for i in prior['completed_commands']}
                if not general_waiting and any(canonical_digest(c)not in completed for c in current_resolution.commands):
                    raise ValueError('followup became ready; derive a fresh actual child proposal')
                candidate=GraphCandidate(Event(Scope(*reader.namespace.as_tuple,'domain.followup.v1'),op,now,RESOLVER,
                    {'dedupe_key':event.dedupe_key,'causal_original_digest':event.trigger_original.original_digest}),
                    current_frame.snapshot.versions,(),(epoch,))
                store=reader.store
                receipt=GraphStore._graph_commit_in_transaction(store,candidate,_capability=graph._GraphCoordinator__graph_capability)
                if receipt.status!='committed':raise ValueError('followup read event CAS failed')
                store.cas_graph_recovery_metadata(metadata,metadata.requirements,_capability=graph._GraphCoordinator__graph_capability)
                row=db.execute('SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?',reader.namespace.as_tuple).fetchone()
                sequence=(0 if row is None else row[0])+1
                db.execute('INSERT INTO graph_bundle_sequence VALUES(?,?,?) ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq',(*reader.namespace.as_tuple,sequence))
                db.execute('INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) VALUES(?,?,?,?,?,NULL,?,?)',
                    (*reader.namespace.as_tuple,op,canonical_digest(candidate),'domain.followup.v1',sequence,canonical_json({'ledger_refs':[],'outbox_refs':[]})))
                waiting_result={'coverage':'partial','missing_inputs':list(resolution.missing_originals),'continuation_ref':resolution.continuation_ref}if general_waiting else {}
                return _save_disposition(graph,db,issued,current_resolution,waiting_result)
            from contextlib import contextmanager
            @contextmanager
            def general_wait_context(scope,guard,owner):
                if _uses_native_attention_job_disposition_v1(event,prior,_NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader)):
                    from .domain_background_read_v3 import bind_native_attention_disposition_write_v1
                    with bind_native_attention_disposition_write_v1(reader,issued=issued,scope=scope,guard=guard,current_owner=owner):yield
                elif event.event_kind=='single_event_growth_review_required_v1':
                    from .domain_background_read_v3 import bind_single_event_disposition_write_v1
                    with bind_single_event_disposition_write_v1(reader,issued=issued,scope=scope,guard=guard,current_owner=owner):yield
                else:
                    from .domain_background_read_v3 import bind_general_growth_trial_fresh_write_v1
                    with bind_general_growth_trial_fresh_write_v1(reader,issued=issued,scope=scope,guard=guard,current_owner=owner):yield
            result=graph._owner_domain_write_v3(authority,None,operation_id=op,
                request_digest=canonical_digest((RESOLVER,event.dedupe_key,op)),domains=(event.receiver_domain,),
                capability='workbench.read',commit=commit,background_original=issued,
                fence_context=general_wait_context if general_waiting or event.event_kind=='single_event_growth_review_required_v1' or _uses_native_attention_job_disposition_v1(event,prior,_NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader)) else None)
            _wake_actual_native_attention_job_v1(graph,result,_NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader))
            if reader.joint_executor_wakes:
                result = {**result, 'joint_executor_wakes': reader.joint_executor_wakes}
            if single_event_wake:
                result={**result,'single_event_wake':single_event_wake[0]}
            from .domain_production_followups_v1 import _NATIVE_ATTENTION_JOB_SCHEMA_V1
            status='completed'if result.get('schema')==_NATIVE_ATTENTION_JOB_SCHEMA_V1 and result['state']=='completed'else'waiting'
            return background_followup_progress_v3(status,result,None)
    finally:
        _ORDINARY_SERVICE_WRITES_V1.pop(id(issued),None)
        _NATIVE_ATTENTION_JOB_WRITES_V1.pop(id(issued),None)
        _ACTIVE.pop(id(issued),None)


def consume_background_followup_child_v3(graph,bootstrap,bundle,*,handoff):
    from .domain_background_read_v3 import prepare_domain_background_read_v3,require_background_followup_handoff_v3,raise_background_work_error_v3
    from .first_ingress_v2 import trusted_upper
    handoff=require_background_followup_handoff_v3(handoff,graph,bundle)
    graph._admin(bootstrap)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    trial_command=handoff.command if type(handoff.command)in (GeneralGrowthTrialFollowupCommandV1,SingleEventReviewFollowupCommandV1) else None
    parent=handoff.general_growth_parent_metadata
    if parent is not None and now>=parent.original_deadline_utc:
        return consume_current_domain_followup_v1(graph,bootstrap,bundle,dedupe_key=handoff.dedupe_key)
    if trial_command is not None and now>=trial_command.original_deadline_utc:
        return consume_current_domain_followup_v1(graph,bootstrap,bundle,dedupe_key=handoff.dedupe_key)
    deadline=trial_command.original_deadline_utc if trial_command is not None else now+60 if parent is None else parent.original_deadline_utc
    work=prepare_domain_background_read_v3(graph,bootstrap,bundle,kind='followup_child',
        operation_id='domain-followup-child:'+canonical_digest((handoff.namespace,handoff.dedupe_key,canonical_digest(handoff.command)))[:48],
        deadline_utc=deadline,dedupe_key=handoff.dedupe_key)
    work.state.handoff=handoff
    work.map_terminal_v3('issuer',lambda prepared:finish_background_followup_preparation_v3(graph,prepared),raise_background_work_error_v3)
    return work

def general_growth_trial_child_command_allowed_v1(issued,graph,command):
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    require_background_followup_v1(issued,graph,issued.authority,issued.operation_id)
    if type(command)is not GeneralGrowthTrialFollowupCommandV1:return False
    if (issued.command is not command or issued.event.event_kind not in('general_growth_action_outcome_available',
            'actual_life_outcome_available_for_growth')or issued.event.receiver_domain!='d01'
            or issued.parent_budget!=command.parent_budget_lease_ref
            or issued.authority.purpose!=command.source_authority.purpose
            or issued.authority.audience!=command.source_authority.audience
            or issued.authority.actor!=command.source_authority.actor):
        raise ValueError('General child crossed its actual signed Start actor/purpose/audience/original budget')
    return True


def actual_general_growth_trial_child_deadline_v1(issued,graph):
    if not general_growth_trial_child_command_allowed_v1(issued,graph,issued.command):return None
    return issued.command.original_deadline_utc



def _persist_general_growth_handoff_cursor_v1(graph,reader,event,original,frame,resolution,command):
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    census=reader.general_trial_census
    if (reader.kind!='followup'or not reader.sealed or type(command)is not GeneralGrowthTrialFollowupCommandV1
            or command not in resolution.commands or census is None or not census.complete
            or not any(ref==command.start_original_ref and row[3]==command.start_original_digest for ref,row in census.matches)):
        raise ValueError('General handoff cursor is not its actual complete verified metadata candidate')
    cursor='general-start-cursor:'+command.start_original_ref
    op='general-start-handoff:'+canonical_digest((reader.namespace,event.dedupe_key,
        command.start_original_digest,reader.graph_stamp[0].graph_revision))[:48]
    issued=_BackgroundFollowupV1(graph,event,reader.authority,reader.owner,None,
        original['payload']['parent_budget'],op,frame.snapshot.epochs[0].revision,
        reader.local_result[3],original['original_digest'],None)
    _ACTIVE[id(issued)]=issued
    try:
        def commit(db,metadata,epoch,now,owner,scope):
            if scope.operation!='write'or scope.permit.operation!='write':
                raise ValueError('General handoff cursor lost its actual Owner bookkeeping WRITE scope')
            reader.require_write_data_v3(db,scope,owner)
            with bind_background_reads_v3(reader,db=db,scope=scope,current_owner=owner):
                current,causal,state,_=_event(db,reader.namespace,event.dedupe_key,graph._GraphCoordinator__d11_issuer)
                if current!=event or causal['original_digest']!=original['original_digest']or state not in('pending','waiting'):
                    raise ValueError('General handoff bookkeeping changed its actual causal outbox')
                candidate=GraphCandidate(Event(Scope(*reader.namespace.as_tuple,'domain.followup.v1'),op,now,RESOLVER,
                    {'dedupe_key':event.dedupe_key,'start_original_digest':command.start_original_digest}),
                    (),(),(epoch,))
                receipt=GraphStore._graph_commit_in_transaction(reader.store,candidate,
                    _capability=graph._GraphCoordinator__graph_capability)
                if receipt.status!='committed':raise ValueError('General handoff metadata cursor CAS failed')
                reader.store.cas_graph_recovery_metadata(metadata,metadata.requirements,
                    _capability=graph._GraphCoordinator__graph_capability)
                row=db.execute('SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?',reader.namespace.as_tuple).fetchone()
                sequence=(0 if row is None else row[0])+1
                db.execute('INSERT INTO graph_bundle_sequence VALUES(?,?,?) ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq',
                    (*reader.namespace.as_tuple,sequence))
                db.execute('INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) '
                    'VALUES(?,?,?,?,?,NULL,?,?)',(*reader.namespace.as_tuple,op,canonical_digest(candidate),'domain.followup.v1',sequence,
                        canonical_json({'ledger_refs':[],'outbox_refs':[]})))
                return _save_disposition(graph,db,issued,resolution,{'continuation_ref':cursor})
        with bind_background_reads_v3(reader,db=reader.db):
            return graph._owner_domain_write_v3(reader.authority,None,operation_id=op,
                request_digest=canonical_digest((RESOLVER,event.dedupe_key,op)),domains=(event.receiver_domain,),
                capability='workbench.read',commit=commit,background_original=issued)
    finally:
        _ORDINARY_SERVICE_WRITES_V1.pop(id(issued),None)
        _NATIVE_ATTENTION_JOB_WRITES_V1.pop(id(issued),None)
        _ACTIVE.pop(id(issued),None)



_ORDINARY_CHILDREN_V1={}
_ORDINARY_CHILD_WRITES_V1={}
_ORDINARY_D07_PREPARATIONS_V1={}
_ORDINARY_SERVICE_WRITES_V1={}
from weakref import WeakKeyDictionary
_ORDINARY_SERVICE_PRIORS_V1=WeakKeyDictionary()


def _issue_actual_native_growth_followup_child_v1(prepared,graph,command_type):
    """Only the retained official Background result may issue this named child."""
    from .domain_background_read_v3 import PreparedBackgroundOperationV3,require_background_followup_handoff_v3
    if command_type not in (OrdinaryContinuityFollowupCommandV1,SingleEventReviewFollowupCommandV1):
        raise TypeError('only exact registered native growth child command families may issue')
    if type(prepared)is not PreparedBackgroundOperationV3:raise TypeError('actual retained Background preparation required')
    prepared.require_v3(graph);reader=prepared.owner
    if not reader.db.in_transaction or not reader.store._lock._is_owned():
        raise ValueError('ordinary continuity child issuance requires its actual retained Graph snapshot transaction')
    event,original,state,prior,frame,resolution,command,child=prepared.local_result
    if(reader.kind!='followup_child'or state in {'completed','unchanged','general_waiting'}
            or type(command)is not command_type or command not in resolution.commands
            or (not ordinary_continuity_event_v1(event.event_kind) if command_type is OrdinaryContinuityFollowupCommandV1
                else not single_event_review_event_v1(event.event_kind))):
        raise ValueError('ordinary continuity issuer lacks its actual complete named child selection')
    handoff=require_background_followup_handoff_v3(reader.handoff,graph,reader.bundle)
    if (handoff.command!=command or handoff.causal_operation_id!=event.causal_operation_id
            or handoff.trigger_original!=event.trigger_original or handoff.causal_original_digest!=original['original_digest']):
        raise ValueError('ordinary continuity issuer changed its actual immutable handoff')
    metadata,epoch=graph._v2_graph_stamp(reader.namespace)
    if (metadata,epoch)!=reader.graph_stamp:raise ValueError('ordinary continuity child metadata snapshot became stale')
    authority=command.source_authority
    op=native_growth_followup_command_operation_v1(reader.namespace,command)
    issued=_BackgroundFollowupV1(graph,event,authority,reader.owner,command,command.parent_budget_lease_ref,
        op,epoch.revision,prior,original.get('domain_original_digest',original['original_digest']))
    _ACTIVE[id(issued)]=issued
    _ORDINARY_CHILDREN_V1[id(issued)]=(issued,prepared,reader,command,original)
    try:ordinary_continuity_child_command_allowed_v1(issued,graph,command)
    except BaseException:
        release_actual_ordinary_continuity_child_v1(issued)
        raise
    return issued


def ordinary_continuity_child_command_allowed_v1(issued,graph,command):
    if type(command)is SingleEventReviewFollowupCommandV1:
        return single_event_review_child_command_allowed_v1(issued,graph,command)
    if not native_growth_followup_command_v1(command):return False
    require_background_followup_v1(issued,graph,issued.authority,issued.operation_id)
    entry=_ORDINARY_CHILDREN_V1.get(id(issued))
    if(entry is None or entry[0]is not issued or entry[3]is not command or issued.command is not command
            or not ordinary_continuity_event_v1(issued.event.event_kind)
            or issued.parent_budget!=command.parent_budget_lease_ref or issued.authority!=command.source_authority
            or issued.operation_id!=native_growth_followup_command_operation_v1(issued.authority.namespace,command)):
        raise ValueError('ordinary continuity child lost its actual private native issuer/original budget')
    entry[1].require_v3(graph)
    return True



def require_actual_ordinary_continuity_child_origin_v1(issued,graph):
    ordinary_continuity_child_command_allowed_v1(issued,graph,issued.command)
    return _ORDINARY_CHILDREN_V1[id(issued)][1]


def actual_ordinary_continuity_child_deadline_v1(issued,graph):
    if not ordinary_continuity_child_command_allowed_v1(issued,graph,issued.command):return None
    return issued.command.original_deadline_utc


def require_actual_ordinary_continuity_child_budget_v1(issued,graph,db,now):
    ordinary_continuity_child_command_allowed_v1(issued,graph,issued.command)
    original=_ORDINARY_CHILDREN_V1[id(issued)][4]
    if type(issued.command)is SingleEventReviewFollowupCommandV1:
        return require_single_event_review_budget_v1(db,namespace=issued.authority.namespace,original=original,
            issuer=graph._GraphCoordinator__d11_issuer,now=now)
    return require_ordinary_continuity_budget_v1(db,namespace=issued.authority.namespace,original=original,
        issuer=graph._GraphCoordinator__d11_issuer,now=now)


def _validate_actual_ordinary_child_write_v1(issued,graph,db,scope,owner,now):
    ordinary_continuity_child_command_allowed_v1(issued,graph,issued.command)
    if (db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()
            or scope.operation!='write'or scope.permit.operation!='write'
            or owner.authorization_head!=issued.owner.authorization_head
            or owner.authorization_revision!=issued.owner.authorization_revision):
        raise ValueError('ordinary continuity child requires its actual fresh Owner WRITE transaction')
    require_actual_ordinary_continuity_child_budget_v1(issued,graph,db,now)
    ns=issued.authority.namespace;event=issued.event;command=issued.command
    if type(command)is SingleEventReviewFollowupCommandV1:
        from .current_method_learning_read_v3 import read_actual_single_event_review_child_metadata_v1
        metadata=read_actual_single_event_review_child_metadata_v1(db,issued)
    else:
        from .current_method_learning_read_v3 import read_actual_ordinary_continuity_child_metadata_v1
        metadata=read_actual_ordinary_continuity_child_metadata_v1(db,issued)
    row=metadata['outbox'];cause=metadata['cause']
    original=_ORDINARY_CHILDREN_V1[id(issued)][4]
    if (row is None or row[:5]!=(event.causal_operation_id,event.receiver_domain,event.event_kind,
            event.trigger_original.original_ref,event.trigger_original.original_digest)
            or row[5]not in {'pending','waiting'}
            or cause!=(original['domain'],original['operation_kind'],issued.causal_original_digest,
                original['receipt'].operation_digest,canonical_digest(original['receipt']))):
        raise ValueError('ordinary continuity child lost its actual current Method outbox/cause metadata')
    digest=canonical_digest(('sylanne.domain-production-command.v1',ns,issued.authority.actor,
        command.operation_kind,command.request,issued.operation_id,command.activity_id,
        command.audience_ref,command.parent_budget_lease_ref))
    _ORDINARY_CHILD_WRITES_V1[id(issued)]=(issued,db,scope,owner,digest,row[6])
    from .domain_production_followups_v1 import DomainFollowupResolutionV1
    return None,DomainFollowupResolutionV1('ready',(command,),(),())




def _ordinary_service_prior_job_v1(event,original,prior):
    if event.event_kind!='ordinary_continuity_attention_available_for_service' or prior is None:return None
    attention=original['ordinary_continuity_attention']
    op='ordinary-continuity-serve:'+attention.semantic_question_ref.removeprefix('ordinary-continuity-question:')
    from .d07_execution_v1 import d07_execution_ids_v1
    job=d07_execution_ids_v1(event.namespace,op,'concern')['job']
    if(prior['schema']!='sylanne.domain-followup-disposition.v1' or prior['state']!='waiting'
            or prior['dedupe_key']!=event.dedupe_key or prior['consumer_operation_id']!=op
            or prior['causal_original_digest']!=original['domain_original_digest']
            or prior['trigger_original_digest']!=event.trigger_original.original_digest
            or prior['continuation_ref']!=job or prior['missing_originals']!=['actual_d07_original_execution']
            or len(prior['completed_commands'])!=1 or prior['completed_commands'][0]['operation_id']!=op):
        return None
    return job


def _ordinary_service_completion_v1(reader,event,original,prior):
    actual=_actual_native_attention_job_v1(reader,event,original)
    job=actual.job_id if actual is not None else _ordinary_service_prior_job_v1(event,original,prior)
    if job is None:return None
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    from .d07_ordinary_continuity_cognition_v1 import read_ordinary_continuity_service_completion_v1
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    fact=read_ordinary_continuity_service_completion_v1(reader.db,namespace=reader.namespace,
        job_id=job,issuer=reader.graph._GraphCoordinator__d11_issuer)
    if fact is not None:fact.require_current_v1(reader)
    return fact


def release_ordinary_continuity_service_metadata_v1(reader):
    _ORDINARY_SERVICE_PRIORS_V1.pop(reader,None)
    _NATIVE_ATTENTION_OWNER_JOBS_V1.pop(reader,None)


def capture_actual_ordinary_continuity_d07_preparation_v1(runtime,db,*,witness,preparation,receipt,original_digest):
    issued=getattr(runtime,'_active_background_followup_v1',None)
    if issued is not None and type(issued.command)is SingleEventReviewFollowupCommandV1:
        return _capture_single_event_review_d07_preparation_v1(runtime,db,witness=witness,
            preparation=preparation,receipt=receipt,original_digest=original_digest)
    if issued is None or type(issued.command)is not OrdinaryContinuityFollowupCommandV1:return None
    if issued.command.operation_kind!='serve_concern':return None
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE as COMMIT_ACTIVE
    from .d07_execution_v1 import D07PreparationStageV1,SIGN_KIND
    from .d07_ordinary_continuity_cognition_v1 import D07OrdinaryContinuityPreparedV1
    from ..runtime_contracts import CommitReceipt,canonical_serialize
    from .current_method_learning_read_v3 import _method_active,is_native_ordinary_continuity_method_v1
    graph=runtime.graph
    ordinary_continuity_child_command_allowed_v1(issued,graph,issued.command)
    reader=_method_active(db)
    binding=_ORDINARY_CHILD_WRITES_V1.get(id(issued))
    if(type(witness)is not _ProductionCommitWitnessV1 or COMMIT_ACTIVE.get(id(witness))is not witness
            or witness.runtime is not runtime or witness.graph is not graph or witness.stage is not preparation
            or type(preparation)is not D07PreparationStageV1 or type(receipt)is not CommitReceipt
            or receipt.status!='committed'or binding is None or binding[1]is not db or binding[2]is not witness.scope
            or reader is None or not is_native_ordinary_continuity_method_v1(reader)
            or witness.request is not issued.command.request or preparation.frame is not witness.frame
            or type(preparation.prepared)is not D07OrdinaryContinuityPreparedV1):
        raise ValueError('ordinary service handoff requires its actual Method W01 preparation witness')
    prepared=preparation.prepared;command=issued.command;ns=issued.authority.namespace
    original=_ORDINARY_CHILDREN_V1[id(issued)][4];attention=original['ordinary_continuity_attention']
    if(prepared.namespace!=ns or prepared.operation_id!=issued.operation_id or prepared.activity_id!=command.activity_id
            or prepared.semantic_question_ref!=command.request.trigger_original_ref
            or prepared.continuity_attention_ref!=attention.original_ref or prepared.basis_original!=attention.basis_original
            or prepared.phase!=attention.phase or prepared.trigger_assessment_original!=attention.trigger_assessment_original
            or prepared.original_parent_budget_lease_ref!=command.parent_budget_lease_ref
            or prepared.original_parent_grant_digest!=command.original_grant_digest
            or prepared.original_deadline_utc!=command.original_deadline_utc
            or receipt.operation_id!=prepared.prepare_operation_id or preparation.job.job_id!=prepared.job_id
            or preparation.job.phase!='queued'or not db.in_transaction):
        raise ValueError('ordinary service preparation changed its actual attention/budget/queued job identity')
    headers=[]
    for kind in ('prepared','prepare_commit'):
        row=db.execute('SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 '
            'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',(*ns.as_tuple,kind,prepared.job_id)).fetchone()
        if row is None:raise ValueError('ordinary service lacks its actual same-W01 signed preparation original')
        graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,kind,prepared.job_id,row[0])),row[1])
        headers.append(row)
    if headers[1][0]!=original_digest:raise ValueError('ordinary service returned another recorded prepare-commit original')
    fact=(issued,reader,db,receipt,prepared.prepare_operation_id,prepared.job_id,headers[0][0],original_digest)
    _ORDINARY_D07_PREPARATIONS_V1[id(issued)]=fact
    return None

def finish_actual_ordinary_continuity_child_v1(issued,graph,db,result):
    """Consume the new child original inside the same actual W01 WRITE transaction."""
    ordinary_continuity_child_command_allowed_v1(issued,graph,issued.command)
    binding=_ORDINARY_CHILD_WRITES_V1.get(id(issued));command=issued.command
    if (binding is None or binding[0]is not issued or binding[1]is not db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or result.get('schema')!='sylanne.domain-production-receipt.v1'
            or result.get('operation_id')!=issued.operation_id or result.get('operation_kind')!=command.operation_kind):
        raise ValueError('ordinary continuity disposition requires the actual child W01 result/transaction')
    from .domain_production_originals_v1 import TABLE,_receipt
    receipt=_receipt(result['receipt']);ns=issued.authority.namespace
    if command.operation_kind=='serve_concern':
        fact=_ORDINARY_D07_PREPARATIONS_V1.get(id(issued))
        if(fact is None or fact[0]is not issued or fact[2]is not db or receipt!=fact[3]
                or result.get('prepare_operation_id')!=fact[4] or result.get('coverage')!='deferred'
                or result.get('missing_inputs')!=['actual_d07_original_execution']
                or result.get('continuation_ref')!=fact[5] or result.get('job_states')!=[[fact[5],'queued']]
                or result.get('original_ref')!='d07-prepared:'+issued.operation_id
                or result.get('original_digest')!=fact[7] or result.get('receipt_digest')!=canonical_digest(receipt)):
            raise ValueError('ordinary service deferred result differs from its actual signed job handoff')
        from .domain_production_followups_v1 import DomainFollowupResolutionV1
        return _save_disposition(graph,db,issued,DomainFollowupResolutionV1('ready',(command,),(),()),result)
    saved=db.execute('SELECT domain,operation_kind,request_digest,original_digest,bundle_digest,receipt_digest '
        'FROM '+TABLE+' WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,issued.operation_id)).fetchone()
    actual=db.execute('SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations '
        'WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,issued.operation_id)).fetchone()
    if (receipt.status!='committed'or receipt.operation_id!=issued.operation_id
            or receipt.activity_id!=command.activity_id or result.get('domain')!=command.receiver_domain
            or result.get('activity_id')!=receipt.activity_id or result['receipt_digest']!=canonical_digest(receipt)
            or saved!=(command.receiver_domain,command.operation_kind,binding[4],result['original_digest'],
                receipt.operation_digest,canonical_digest(receipt))
            or result['original_ref']!=command.receiver_domain+'-current:'+result['original_digest'][:48]
            or actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
        raise ValueError('ordinary continuity child result differs from its actual committed original/bundle')
    from .domain_production_followups_v1 import DomainFollowupResolutionV1
    resolution=DomainFollowupResolutionV1('ready',(command,),(),())
    return _save_disposition(graph,db,issued,resolution,result)


def release_actual_ordinary_continuity_child_v1(issued):
    _ORDINARY_SERVICE_WRITES_V1.pop(id(issued),None)
    _NATIVE_ATTENTION_JOB_WRITES_V1.pop(id(issued),None)
    _ORDINARY_D07_PREPARATIONS_V1.pop(id(issued),None)
    _ORDINARY_CHILD_WRITES_V1.pop(id(issued),None)
    _ORDINARY_CHILDREN_V1.pop(id(issued),None)
    _ACTIVE.pop(id(issued),None)


def issue_actual_ordinary_continuity_followup_child_v1(prepared,graph):
    return _issue_actual_native_growth_followup_child_v1(prepared,graph,OrdinaryContinuityFollowupCommandV1)


def issue_actual_single_event_review_followup_child_v1(prepared,graph):
    return _issue_actual_native_growth_followup_child_v1(prepared,graph,SingleEventReviewFollowupCommandV1)


def single_event_review_child_command_allowed_v1(issued,graph,command):
    if type(command)is not SingleEventReviewFollowupCommandV1:return False
    if command.operation_kind not in {'register_single_event_review_attention_v1','serve_concern'}:
        raise ValueError('D01 final review requires its actual Background SelectedTarget writer')
    require_background_followup_v1(issued,graph,issued.authority,issued.operation_id)
    entry=_ORDINARY_CHILDREN_V1.get(id(issued))
    if (entry is None or entry[0]is not issued or entry[3]is not command or issued.command is not command
            or not single_event_review_event_v1(issued.event.event_kind)
            or issued.parent_budget!=command.parent_budget_lease_ref or issued.authority!=command.source_authority
            or issued.operation_id!=native_growth_followup_command_operation_v1(issued.authority.namespace,command)):
        raise ValueError('review child lost its actual private native issuer/original budget')
    entry[1].require_v3(graph)
    return True


def require_actual_single_event_review_child_origin_v1(issued,graph):
    single_event_review_child_command_allowed_v1(issued,graph,issued.command)
    return _ORDINARY_CHILDREN_V1[id(issued)][1]


def _single_event_service_prior_job_v1(event,original,prior):
    if event.event_kind!='single_event_review_attention_available_for_service' or prior is None:return None
    attention=original['single_event_review_parent']
    from .d07_single_event_review_v1 import single_event_review_service_operation_id_v1
    op=single_event_review_service_operation_id_v1(attention)
    from .d07_execution_v1 import d07_execution_ids_v1
    job=d07_execution_ids_v1(event.namespace,op,'concern')['job']
    if (prior['schema']!='sylanne.domain-followup-disposition.v1' or prior['state']!='waiting'
            or prior['dedupe_key']!=event.dedupe_key or prior['consumer_operation_id']!=op
            or prior['causal_original_digest']!=original['domain_original_digest']
            or prior['trigger_original_digest']!=event.trigger_original.original_digest
            or prior['continuation_ref']!=job or prior['missing_originals']!=['actual_d07_original_execution']
            or len(prior['completed_commands'])!=1 or prior['completed_commands'][0]['operation_id']!=op):
        return None
    return job


def _capture_single_event_review_d07_preparation_v1(runtime,db,*,witness,preparation,receipt,original_digest):
    issued=getattr(runtime,'_active_background_followup_v1',None)
    if issued is None or type(issued.command)is not SingleEventReviewFollowupCommandV1:return None
    if issued.command.operation_kind!='serve_concern':return None
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE as COMMIT_ACTIVE
    from .d07_execution_v1 import D07PreparationStageV1,SIGN_KIND
    from .d07_single_event_review_v1 import D07SingleEventReviewPreparedV1
    from ..runtime_contracts import CommitReceipt,canonical_serialize
    from .current_method_learning_read_v3 import _method_active,read_actual_single_event_review_child_metadata_v1
    graph=runtime.graph
    single_event_review_child_command_allowed_v1(issued,graph,issued.command)
    binding=_ORDINARY_CHILD_WRITES_V1.get(id(issued));reader=_method_active(db)
    if (type(witness)is not _ProductionCommitWitnessV1 or COMMIT_ACTIVE.get(id(witness))is not witness
            or witness.runtime is not runtime or witness.graph is not graph or witness.stage is not preparation
            or type(preparation)is not D07PreparationStageV1 or type(receipt)is not CommitReceipt
            or receipt.status!='committed' or binding is None or binding[1]is not db or binding[2]is not witness.scope
            or reader is None or witness.request is not issued.command.request or preparation.frame is not witness.frame
            or type(preparation.prepared)is not D07SingleEventReviewPreparedV1):
        raise ValueError('review service handoff requires its actual Method W01 preparation witness')
    read_actual_single_event_review_child_metadata_v1(db,issued)
    prepared=preparation.prepared;command=issued.command;ns=issued.authority.namespace
    attention=_ORDINARY_CHILDREN_V1[id(issued)][4]['single_event_review_parent']
    if (prepared.namespace!=ns or prepared.operation_id!=issued.operation_id or prepared.activity_id!=command.activity_id
            or prepared.semantic_question_ref!=command.request.trigger_original_ref
            or prepared.review_attention_ref!=attention.original_ref or prepared.review_case_original!=attention.case_original
            or prepared.original_parent_budget_lease_ref!=command.parent_budget_lease_ref
            or prepared.original_parent_grant_digest!=command.original_grant_digest
            or prepared.original_deadline_utc!=command.original_deadline_utc
            or receipt.operation_id!=prepared.prepare_operation_id or preparation.job.job_id!=prepared.job_id
            or preparation.job.phase!='queued' or not db.in_transaction):
        raise ValueError('review service preparation changed its actual attention/parent/job identity')
    headers=[]
    for kind in ('prepared','prepare_commit'):
        row=db.execute('SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 '
            'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',(*ns.as_tuple,kind,prepared.job_id)).fetchone()
        if row is None:raise ValueError('review service lacks its actual signed preparation original')
        graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,kind,prepared.job_id,row[0])),row[1])
        headers.append(row)
    if headers[1][0]!=original_digest:raise ValueError('review service changed its recorded prepare-commit original')
    _ORDINARY_D07_PREPARATIONS_V1[id(issued)]=(issued,reader,db,receipt,prepared.prepare_operation_id,
        prepared.job_id,headers[0][0],original_digest)


def _single_event_service_completion_v1(reader,event,original,prior):
    actual=_actual_native_attention_job_v1(reader,event,original)
    job=actual.job_id if actual is not None else _single_event_service_prior_job_v1(event,original,prior)
    if job is None:return None
    from .d07_single_event_review_v1 import read_single_event_review_service_disposition_v1
    fact=read_single_event_review_service_disposition_v1(reader.db,namespace=reader.namespace,
        job_id=job,issuer=reader.graph._GraphCoordinator__d11_issuer)
    if fact is not None:
        fact.require_current_v1(reader)
        if fact.status not in {'adopted','parse_rejected'}:
            raise ValueError('review service has no actual registered terminal disposition')
    return fact

_NATIVE_ATTENTION_OWNER_JOBS_V1=WeakKeyDictionary()
_NATIVE_ATTENTION_JOB_WRITES_V1={}


def _actual_native_attention_job_v1(reader,event,original):
    from .domain_production_followups_v1 import _NATIVE_ATTENTION_SERVICE_EVENTS_V1
    if reader is None or event.event_kind not in _NATIVE_ATTENTION_SERVICE_EVENTS_V1:return None
    from .d07_single_event_review_v1 import read_current_d07_attention_prepared_job_metadata_v1
    fact=read_current_d07_attention_prepared_job_metadata_v1(reader.db,namespace=reader.namespace,
        issuer=reader.graph._GraphCoordinator__d11_issuer)
    if fact is not None:
        fact.require_current_v1(reader)
        if fact.family!=("single_event_review"if event.event_kind=="single_event_review_attention_available_for_service"else"ordinary_continuity"):
            raise ValueError("actual queued job belongs to another attention family")
        _NATIVE_ATTENTION_OWNER_JOBS_V1[reader]=fact
    else:_NATIVE_ATTENTION_OWNER_JOBS_V1.pop(reader,None)
    return fact


def _uses_native_attention_job_disposition_v1(event,prior,fact):
    if fact is None:return False
    from .domain_production_followups_v1 import _NATIVE_ATTENTION_JOB_SCHEMA_V1
    if prior is not None and prior.get("schema")==_NATIVE_ATTENTION_JOB_SCHEMA_V1:return True
    return prior is None or not prior["completed_commands"]


def _require_native_job_disposition_binding_v1(reader,event,original,prior,fact):
    from .domain_production_followups_v1 import (_NATIVE_ATTENTION_JOB_SCHEMA_V1,native_attention_job_preparation_wire_v1)
    fact.require_current_v1(reader)
    value=native_attention_job_preparation_wire_v1(fact,reader.namespace)
    if prior is not None and prior.get("schema")==_NATIVE_ATTENTION_JOB_SCHEMA_V1:
        if (prior["job_preparation"]!=value or prior["dedupe_key"]!=event.dedupe_key
                or prior["causal_original_digest"]!=original["domain_original_digest"]
                or prior["trigger_original_digest"]!=event.trigger_original.original_digest
                or prior["completed_commands"]):
            raise ValueError("native attention disposition cannot replace its actual immutable preparation/budget")
    return value


def require_actual_native_attention_disposition_v1(reader,issued):
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    require_background_followup_v1(issued,reader.graph,issued.authority,issued.operation_id)
    if (not reader.sealed or reader.kind!="followup"or issued.command is not None
            or issued.event.receiver_domain!="d07"
            or issued.event.event_kind not in {"ordinary_continuity_attention_available_for_service","single_event_review_attention_available_for_service"}
            or reader.local_result is None or reader.local_result[0]!=issued.event):
        raise ValueError("native attention disposition needs its actual sealed Background event/current Owner")
    fact=_NATIVE_ATTENTION_OWNER_JOBS_V1.get(reader)
    if fact is None:raise ValueError("native attention disposition has no actual signed prepared job")
    _require_native_job_disposition_binding_v1(reader,issued.event,reader.local_result[1],issued.prior_receipt,fact)
    return fact


def _wake_actual_native_attention_job_v1(graph,value,fact):
    if value is None or fact is None or fact.job_phase not in {"queued","running","completed"}:return
    from .domain_production_followups_v1 import _NATIVE_ATTENTION_JOB_SCHEMA_V1
    if value.get("schema")!=_NATIVE_ATTENTION_JOB_SCHEMA_V1 or value["state"]!="waiting":return
    job=value["job_preparation"]["job_id"]
    if value["continuation_ref"]!=job or fact.job_id!=job:raise ValueError("native attention waiting cursor changed its actual job")
    graph._GraphCoordinator__d07_execution_service_v1.wake_committed_job_v1(job)
