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
from .domain_production_followups_v1 import read_plan_current_domain_followup_v1, resolve_domain_followup_v1
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
    trigger_kind=('d01.'+original['general_lifecycle_kind']if 'general_lifecycle_kind'in original
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
    original=read_general_growth_lifecycle_cause_v1(db,namespace=authority.namespace,event_kind=event.event_kind,
        causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,issuer=issuer)if lifecycle else None
    if original is None:
        original=read_general_growth_followup_cause_v1(db,namespace=authority.namespace,event_kind=event.event_kind,
            causal_operation_id=event.causal_operation_id,original_ref=event.trigger_original.original_ref,issuer=issuer) if general else None
    if original is None:original=read_adopted_domain_operation_v1(db,authority.namespace,event.causal_operation_id)
    missing=general_growth_parent_metadata_status_v1(db,trigger=trigger,owner=owner,authority=authority,
        issuer=issuer,now=now) if general else None
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
    if trial_child or event.event_kind=='general_growth_action_outcome_available':
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
    causal = ProductionOriginalRefV1(original['domain']+'.current-'+original['operation_kind'],
        event.trigger_original.original_ref, event.trigger_original.original_digest)
    frame = freeze_domain_production_frame_v1(graph, db, envelope=envelope, current_owner=owner, scope=scope,
        plan=plan, now_utc=now, observed_originals=(causal,), limits=ProductionOperationLimitsV1())
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
    frame, resolution = _resolve(graph, db, value.event, value.authority, owner, scope, now)
    if value.command is not None and value.command not in resolution.commands:
        raise ValueError('background command is no longer derived from the current exact outbox')
    return frame, resolution


def _save_disposition(graph, db, issued, resolution, result):
    event = issued.event
    old = issued.prior_receipt if issued.causal_original_digest is not None else _event(db, issued.authority.namespace, event.dedupe_key, graph._GraphCoordinator__d11_issuer)[3]
    completed = [] if old is None else list(old['completed_commands'])
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    general_command=type(issued.command)is GeneralGrowthTrialFollowupCommandV1
    from .joint_node_execution_v1 import JOINT_EVENTS
    if event.event_kind in JOINT_EVENTS:
        current_commands = {canonical_digest(command) for command in resolution.commands}
        completed = [item for item in completed if item['command_digest'] in current_commands]
    command_digest = None if issued.command is None else canonical_digest(issued.command)
    structural = (issued.command is not None and issued.command.operation_kind == 'encode_structured_experience'
        and result.get('operation_kind') == 'encode_structured_experience' and result.get('coverage') == 'partial'
        and result.get('missing_inputs') == ['actual_d04_then_feeling_and_d06_subjective_trace_encoding'])
    if (not general_command and command_digest is not None and result.get('schema') == 'sylanne.domain-production-receipt.v1'
            and (result.get('coverage') == 'complete' or structural)):
        item = {'command_digest':command_digest,'operation_id':issued.operation_id,'receipt_digest':result['receipt_digest']}
        if item not in completed: completed.append(item)
    expected = {canonical_digest(command) for command in resolution.commands if type(command)is not GeneralGrowthTrialFollowupCommandV1}
    no_match=(resolution.status=='no_matching_general_start'and issued.event.event_kind=='general_growth_action_outcome_available'
        and not resolution.commands and not resolution.target_refs and not resolution.missing_originals)
    all_done = no_match or resolution.status == 'ready' and not any(type(command)is GeneralGrowthTrialFollowupCommandV1 for command in resolution.commands) and expected <= {item['command_digest'] for item in completed}
    state = 'completed' if all_done else 'waiting'
    missing = list(resolution.missing_originals)
    if command_digest is not None and result.get('coverage') != 'complete':
        missing += list(result.get('missing_inputs', ('current_child_operation_originals',)))
    missing = list(dict.fromkeys(missing))
    if len(completed)>16 or len(missing)>128:raise ValueError('followup disposition exceeds installed bound')
    _, epoch = graph._v2_graph_stamp(issued.authority.namespace)
    continuation=result.get('continuation_ref')or resolution.continuation_ref
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
    db.execute('UPDATE graph_domain_production_outbox_v1 SET state=?,consumer_operation_id=?,receipt_json=? '
        'WHERE bot=? AND persona=? AND dedupe_key=? AND state IN (\'pending\',\'waiting\')',
        (state,issued.operation_id,canonical_json(receipt),*issued.authority.namespace.as_tuple,event.dedupe_key))
    if db.execute('SELECT changes()').fetchone() != (1,): raise ValueError('background outbox disposition raced')
    return receipt


def finish_followup_command_in_transaction_v1(value, graph, db, resolution, result):
    require_background_followup_v1(value, graph, value.authority, value.operation_id)
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
            if actual_state=='completed' or (event.event_kind != 'qualified_contact_opportunity_requires_action' and actual_prior is not None and actual_prior['observed_epoch']==graph._v2_graph_stamp(ns)[1].revision):
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
        if command.operation_kind not in {'recheck_action','prepare_contact','encode_structured_experience','adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1','input:qualify_joint_plan_nodes_v1','input:observe_joint_external_node_v1','input:prepare_joint_external_semantic_question_v1','serve_concern'}:
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
    finally:_ACTIVE.pop(id(issued),None)



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
    from .contact_initial_plan_source_v3 import require_initial_contact_plan_source_v3
    require_initial_contact_plan_source_v3(reader,event,original)
    from .joint_node_execution_v1 import JOINT_EVENTS
    if reader.kind=='followup'and event.event_kind not in JOINT_EVENTS and event.event_kind not in('qualified_contact_opportunity_requires_action','general_growth_action_outcome_available','actual_life_outcome_available_for_growth') and prior is not None and prior['observed_epoch']==reader.graph_stamp[1].revision:
        return (event,original,'unchanged',prior,None,None,None,None)
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
        if command is not None:
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
                if type(command)is GeneralGrowthTrialFollowupCommandV1:
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
    if reader.kind=='followup'and command is not None:
        handoff=BackgroundFollowupChildHandoffV3.from_prepared_v3(prepared,event,original,command,reader.owner.principal)
        from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
        if type(command)is GeneralGrowthTrialFollowupCommandV1:
            _persist_general_growth_handoff_cursor_v1(graph,reader,event,original,frame,resolution,command)
        return background_followup_progress_v3('child_ready',None,handoff)
    op,_=child
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    general_waiting=state=='general_waiting'and reader.kind=='followup_child'and type(command)is GeneralGrowthTrialFollowupCommandV1
    authority=reader.authority
    if command is not None:authority=replace(authority,audience=command.audience_refs or (command.audience_ref,),
            purpose='expression' if command.operation_kind in {'adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1'} else frame.envelope.authority.purpose)
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    parent_budget=command.parent_budget_lease_ref if type(command)is GeneralGrowthTrialFollowupCommandV1 else original['payload']['parent_budget']
    issued=_BackgroundFollowupV1(graph,event,authority,reader.owner,command,parent_budget,op,
        frame.snapshot.epochs[0].revision,prior,original['original_digest'],
        general_growth_background_parent_v1(reader))
    _ACTIVE[id(issued)]=issued
    try:
        with bind_background_reads_v3(reader,db=reader.db):
            if command is not None and not general_waiting:
                from .d07_general_growth_attention_v1 import general_growth_child_command_allowed_v1
                if (command.operation_kind not in('recheck_action','prepare_contact','encode_structured_experience','adopt_contact_expression_plan_v2','prepare_contact_model_v2','prepare_contact_dispatch_v3','prepare_contact_prospective_v1','input:qualify_joint_plan_nodes_v1','input:observe_joint_external_node_v1','input:prepare_joint_external_semantic_question_v1','serve_concern')
                        and not general_growth_child_command_allowed_v1(issued,graph,command)
                        and not general_growth_trial_child_command_allowed_v1(issued,graph,command)):
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
            def commit(db,metadata,epoch,now,owner,scope):
                current_frame,current_resolution=validate_followup_command_in_transaction_v1(issued,graph,db,scope,owner,now)
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
                from .domain_background_read_v3 import bind_general_growth_trial_fresh_write_v1
                with bind_general_growth_trial_fresh_write_v1(reader,issued=issued,scope=scope,guard=guard,current_owner=owner):yield
            result=graph._owner_domain_write_v3(authority,None,operation_id=op,
                request_digest=canonical_digest((RESOLVER,event.dedupe_key,op)),domains=(event.receiver_domain,),
                capability='workbench.read',commit=commit,background_original=issued,
                fence_context=general_wait_context if general_waiting else None)
            if reader.joint_executor_wakes:
                result = {**result, 'joint_executor_wakes': reader.joint_executor_wakes}
            return background_followup_progress_v3('waiting',result,None)
    finally:_ACTIVE.pop(id(issued),None)


def consume_background_followup_child_v3(graph,bootstrap,bundle,*,handoff):
    from .domain_background_read_v3 import prepare_domain_background_read_v3,require_background_followup_handoff_v3,raise_background_work_error_v3
    from .first_ingress_v2 import trusted_upper
    handoff=require_background_followup_handoff_v3(handoff,graph,bundle)
    graph._admin(bootstrap)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    trial_command=handoff.command if type(handoff.command)is GeneralGrowthTrialFollowupCommandV1 else None
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
    finally:_ACTIVE.pop(id(issued),None)
