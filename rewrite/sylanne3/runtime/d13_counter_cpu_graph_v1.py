"""Named W01 preparation of an independent D13 full-HTTP counter CPU job.

A Core instruction is a locator, never permission. The installed entry obtains
current paired Owner authority and rederives current Source facts before quotes.
"""
from dataclasses import dataclass,replace
from datetime import datetime,timezone
import hashlib,json,time
from ..runtime_contracts import (AuthorityContext,CommandEnvelope,OperationIdentity,VersionGuard,
    SourceQualification,VersionedRef,NamespaceId,RUNTIME_SCHEMA,QueryEpoch,canonical_digest)
from ..graph_types import (AtomKey,Owner,GraphVersion,GraphCandidate,owner_grant_key,validate_owner_grant_v1)
from ..contracts import Event,Scope,canonical_json
from ..graph_store import GraphStore
from ..authority_service.d13_core_counter_contract_v1 import (D13CounterCPUPrepareInstructionV1,
    D13CurrentFramePrepareSelectorV7,D13CoreFrameIntentHeaderV7)
from ..authority_service.internal_work_contract import InternalWorkBindingV1
from .c04_internal_work_original_v1 import (C04InternalWorkPreparedV1,read_c04_internal_work_prepared_v1,
    record_c04_internal_work_prepared_v1)
from .d13_counter_cpu_quote_policy_v1 import D13_COUNTER_CPU_WORK_KIND,D13CounterCpuQuotePolicyAuthorityV1
from .budget import reserve_budget
from .jobs import PersistentJob,create_job,acquire_job
from .d11_types import job_graph_write
from .first_ingress_v2 import trusted_upper

_ACTIVE={}

@dataclass(frozen=True,slots=True)
class _D13CounterSelfScopeV1:
    graph:object
    authority:AuthorityContext
    owner:object
    operation_id:str
    bundle:object
    instruction:D13CounterCPUPrepareInstructionV1


def require_d13_counter_self_scope_v1(value,graph,authority,operation_id):
    if (type(value) is not _D13CounterSelfScopeV1 or _ACTIVE.get(id(value)) is not value
            or value.graph is not graph or value.authority!=authority or value.operation_id!=operation_id
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not value.bundle):
        raise ValueError('actual installed D13 counter Self issuance unavailable')
    return value.owner


@dataclass(frozen=True,slots=True)
class _D13CounterBodyStageV1:
    instruction:D13CounterCPUPrepareInstructionV1
    envelope:CommandEnvelope
    body:object
    resource_quote:object
    body_profile_ref:str
    body_profile_revision:int
    body_state_ref:str
    body_state_revision:int
    owner_grant_ref:str
    owner_grant_revision:int
    owner_grant_digest:str
    read_versions:tuple
    before_epoch:int


def _head(db,namespace,key):
    if NamespaceId.from_key(key)!=namespace:
        raise ValueError('D13 counter Graph key crossed namespace')
    row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
    if row is None or row[2]!=1:raise ValueError('D13 counter current original unavailable')
    value=json.loads(row[1])
    if canonical_json(value)!=row[1]:raise ValueError('D13 counter current canonical original differs')
    return row[0],value


def stage_current_d13_counter_body_v1(db,*,issued,graph,scope,owner,now_utc,cpu_authority):
    from ..domains.d02 import BodyDomain,BodyState,BodyReservation
    from ..domains.d03.context import ContextProvider
    from ..authority_service.d13_core_counter_source_v1 import derive_current_counter_plan_v1
    require_d13_counter_self_scope_v1(issued,graph,issued.authority,issued.operation_id)
    if not db.in_transaction or type(cpu_authority) is not D13CounterCpuQuotePolicyAuthorityV1:
        raise ValueError('actual D13 counter W01 transaction and installed CPU authority required')
    ins=issued.instruction;ns=ins.namespace;metadata,epoch=graph._v2_graph_stamp(ns)
    context=graph._GraphCoordinator__providers['d03'][0]
    if type(context) is not ContextProvider:raise ValueError('installed D03 resolver unavailable')
    original=derive_current_counter_plan_v1(db,d02_issuer=graph._GraphCoordinator__d02_issuer,
        d11_issuer=graph._GraphCoordinator__d11_issuer,context=context,namespace=ns,
        c02_operation_id=ins.c02_operation_id,source_ref=ins.source_ref.ref,
        installed_bundle=issued.bundle,now_utc=now_utc,epoch=epoch,original_deadline=ins.prospective_plan_deadline_utc)
    grant=graph._GraphCoordinator__d11_issuer.current_budget_grant(db,ins.parent_budget_lease_ref)
    owner_key=owner_grant_key(*ns.as_tuple);owner_rev,owner_value=_head(db,ns,owner_key)
    validate_owner_grant_v1(owner_value)
    if (original.plan.plan_ref!=ins.plan_ref or canonical_digest(original.plan)!=ins.prospective_plan_digest
            or original.preparation_evidence.source_ref!=ins.source_ref
            or grant.lease_id!=ins.parent_budget_lease_ref or canonical_digest(grant)!=ins.budget_grant_digest
            or canonical_digest(owner_value)!=ins.owner_grant_digest or owner_rev!=owner.grant_revision
            or ins.activation_generation!=metadata.requirements.activation_generation
            or not ins.frozen_at_utc<=now_utc<ins.expires_at_utc):
        raise ValueError('D13 counter original Source/Owner/prospective plan/parent grant changed')
    reads={r.key:r for r in original.read_versions};reads[owner_key]=GraphVersion(owner_key,owner_rev)
    versions=dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' AND kind IN ('scheme','operator','policy')",ns.as_tuple))
    qualification=SourceQualification(tuple(dict.fromkeys(ref.ref for unit in original.plan.units for ref in unit.source_refs)),
        'derived',original.inputs.source.source.occurred_at,original.inputs.source.source.recorded_at,
        'inference','ineligible',None,'not_applicable')
    envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(ins.activity_id,ins.execution_id,ins.counter_operation_id,
        'prepare_current_d13_counter_cpu_v1',ins.frame_intent_id,ins.input_digest),issued.authority,
        VersionGuard(tuple(reads.values()),(QueryEpoch(ns,'namespace',epoch.revision),),owner.access_epoch,owner.delete_epoch,
            graph._GraphCoordinator__store._registry.catalogue_hash,versions['scheme'],versions['operator'],versions['policy'],(),(),()),
        qualification,(),ins.parent_budget_lease_ref,ins.expires_at_utc,
        time.monotonic()+max(0,ins.expires_at_utc-now_utc),ins.frame_intent_id,())
    resource=cpu_authority.request_quote(db,namespace=ns,policy_id=ins.cpu_policy_id,policy_version=ins.cpu_policy_version,
        envelope=envelope,owner=owner,d11_issuer=graph._GraphCoordinator__d11_issuer,algorithm_ref=ins.algorithm_id,now_utc=now_utc)
    body_authority=graph._GraphCoordinator__body_quote_authority
    policy=body_authority.policy(db,ns,ins.body_policy_id,ins.body_policy_version)
    if policy.work_kind!=D13_COUNTER_CPU_WORK_KIND or policy.valid_until<ins.expires_at_utc:
        raise ValueError('actual installed D13 body policy differs or expires')
    profile=BodyDomain.profile_write(policy.profile);profile_rev,profile_value=_head(db,ns,profile.key)
    if profile.value!=profile_value:raise ValueError('D13 current body profile differs from policy')
    state_key=AtomKey(Owner('persona',*ns.as_tuple),'d02.body_state.v1',policy.profile.profile_id)
    state_rev,state_value=_head(db,ns,state_key);state=BodyState(**state_value)
    if state.version!=state_rev:raise ValueError('D13 current body state version differs')
    inventory=db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND owner_kind='activity' AND type_name='d02.reservation.v1' ORDER BY token LIMIT 1025",ns.as_tuple).fetchall()
    if len(inventory)>1024:raise ValueError('actual body inventory exceeds installed bound')
    reservations=[]
    for ref,rev,encoded,valid in inventory:
        reservation=BodyReservation(**json.loads(encoded));key=AtomKey.from_token(ref)
        if valid!=1 or BodyDomain.reservation_write(ns,key.owner.subject,reservation).key!=key:
            raise ValueError('actual D13 body reservation inventory differs')
        reservations.append(reservation);reads[key]=GraphVersion(key,rev)
    reads[profile.key]=GraphVersion(profile.key,profile_rev);reads[state_key]=GraphVersion(state_key,state_rev)
    graph._GraphCoordinator__d02_issuer.issue_quote(db,resource)
    envelope=replace(envelope,version_guard=replace(envelope.version_guard,
        read_versions=tuple(reads.values()),resource_lease_versions=(VersionedRef(resource.quote_id,resource.version),)))
    if graph._GraphCoordinator__d02_issuer.qualified_quote(envelope,db,now_utc=now_utc)!=resource:
        raise ValueError('D13 original signed CPU resource quote differs')
    body=body_authority.issue_fixed_quote_and_reservation(db,graph._GraphCoordinator__d02_issuer,envelope,resource,
        ins.body_policy_id,ins.body_policy_version,state,tuple(reservations),'d13counter-body:'+ins.frame_intent_id,ins.execution_id)
    if body.replayed:raise ValueError('D13 body quote exists without complete counter preparation')
    for token in (body.reservation_write.key.token,*resource.d02_settlement_refs):
        key=AtomKey.from_token(token)
        if db.execute('SELECT 1 FROM graph_atoms WHERE token=?',(token,)).fetchone() is not None:
            raise ValueError('D13 new counter resource key already exists')
        reads[key]=GraphVersion(key,0)
    return _D13CounterBodyStageV1(ins,envelope,body,resource,profile.key.token,profile_rev,
        state_key.token,state_rev,owner_key.token,owner_rev,canonical_digest(owner_value),tuple(reads.values()),epoch.revision)


def commit_current_d13_counter_cpu_in_tx_v1(db,*,graph,issued,scope,owner,now_utc,cpu_authority):
    from ..graph_coordinator import namespace_ref
    ins=issued.instruction;ns=ins.namespace
    from .d13_counter_cpu_accounting_v1 import install_d13_counter_accounting_schema_v1
    install_d13_counter_accounting_schema_v1(db)
    previous=read_c04_internal_work_prepared_v1(db,ns,ins.counter_operation_id)
    if previous is not None:
        if (previous.binding.input_digest,previous.binding.execution_id,previous.binding.algorithm_ref)!=(ins.input_digest,ins.execution_id,ins.algorithm_id):
            raise ValueError('D13 CPU prepared replay differs from the original Core instruction')
        return {'binding_digest':previous.binding.binding_digest,'prepared_digest':previous.prepared_digest,'job_id':ins.job_id}
    stage=stage_current_d13_counter_body_v1(db,issued=issued,graph=graph,scope=scope,owner=owner,now_utc=now_utc,cpu_authority=cpu_authority)
    quote=stage.resource_quote;body_quote=stage.body.body_quote
    if len(body_quote.components)!=1 or body_quote.components[0].duration_rate!=0:
        raise ValueError('D13 counter needs one actual fixed Body component')
    binding=InternalWorkBindingV1(namespace_ref(ns),ins.activity_id,ins.counter_operation_id,ins.execution_id,ins.input_digest,
        quote.quote_id,quote.version,canonical_digest(quote),body_quote.quote_id,stage.body.body_quote_version,canonical_digest(body_quote),
        stage.body.reservation_write.key.token,body_quote.components[0].component_id,quote.parent_budget_lease_ref,
        ins.activation_generation,ins.algorithm_id,quote.snapshot_ref,ins.algorithm_build_digest)
    budget_operation='d13-counter-budget:'+binding.binding_digest
    reservation=reserve_budget(db,binding.parent_budget_lease_ref,budget_operation,binding.binding_digest,quote.ceiling)
    row=db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",(*ns.as_tuple,budget_operation)).fetchone()
    if reservation.status!='reserved' or row is None or row[:2]!=(binding.binding_digest,binding.parent_budget_lease_ref):
        raise ValueError('D13 actual CPU budget reservation differs')
    instant=datetime.fromtimestamp(now_utc,timezone.utc).isoformat().replace('+00:00','Z')
    job=PersistentJob(ins.job_id,ins.counter_operation_id,ins.activity_id,ins.execution_id,*ns.as_tuple,quote.snapshot_ref,
        'queued',D13_COUNTER_CPU_WORK_KIND,{'schema':'sylanne3.d13.counter-job.v1','frame_intent_id':ins.frame_intent_id,
            'frame_intent_digest':ins.frame_intent_digest,'input_digest':ins.input_digest,'binding_digest':binding.binding_digest,
            'execution_id':ins.execution_id,'algorithm_id':ins.algorithm_id,'algorithm_build_digest':ins.algorithm_build_digest},None,
        datetime.fromtimestamp(ins.expires_at_utc,timezone.utc).isoformat().replace('+00:00','Z'),binding.parent_budget_lease_ref,
        quote.resource_ref,{'algorithm':ins.algorithm_id,'build':ins.algorithm_build_digest,'resource_quote':quote.quote_id+':'+str(quote.version)},
        None,None,0,0,{},None)
    create_job(db,job,'d13-counter-job:'+binding.binding_digest,canonical_digest(job))
    running=acquire_job(db,job.job_id,graph._GraphCoordinator__holder,now_utc=instant,
        lease_seconds=min(300,max(1,int(ins.expires_at_utc-now_utc))))
    job_write=job_graph_write(running);reads={r.key:r for r in stage.read_versions};reads[job_write.key]=GraphVersion(job_write.key,0)
    _,epoch=graph._v2_graph_stamp(ns)
    store=graph._GraphCoordinator__store;cap=graph._GraphCoordinator__graph_capability
    candidate=GraphCandidate(Event(Scope(*ns.as_tuple,'d13-counter-v1'),ins.counter_operation_id+':prepare',now_utc,
        'd13.counter.cpu.prepared.v1',{'frame_intent_id':ins.frame_intent_id,'instruction_digest':canonical_digest(ins)}),
        tuple(reads.values()),(stage.body.reservation_write,job_write),(epoch,))
    GraphStore._graph_commit_in_transaction(store,candidate,_capability=cap)
    metadata,after_epoch=graph._v2_graph_stamp(ns)
    if after_epoch.revision!=stage.before_epoch+1:raise ValueError('D13 counter CAS advanced an unexpected epoch')
    for r in stage.read_versions:
        if r.key==stage.body.reservation_write.key:continue
        current=db.execute('SELECT revision FROM graph_atoms WHERE token=?',(r.key.token,)).fetchone()
        if (current[0] if current else 0)!=r.revision:raise ValueError('D13 preparation original changed during CAS')
    versions={r.key.token:r.revision for r in stage.read_versions}
    versions.update({stage.body.reservation_write.key.token:1,job_write.key.token:1})
    barrier=db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
    prepared=C04InternalWorkPreparedV1(binding,stage.body_profile_ref,stage.body_profile_revision,stage.body_state_ref,
        stage.body_state_revision,1,stage.owner_grant_ref,stage.owner_grant_revision,stage.owner_grant_digest,
        budget_operation,hashlib.sha256(row[2].encode()).hexdigest(),tuple(sorted(versions.items())),metadata.graph_revision,*barrier)
    record_c04_internal_work_prepared_v1(db,ns,prepared)
    store.cas_graph_recovery_metadata(metadata,metadata.requirements,_capability=cap)
    return {'binding_digest':binding.binding_digest,'prepared_digest':prepared.prepared_digest,'job_id':running.job_id}


def prepare_current_d13_counter_cpu_v1(graph,bootstrap,bundle,*,instruction):
    """Installed entry: actual Core draft then current Owner-fenced named CPU W01."""
    from ..authority_service.v2_owner_contract import OwnerPrincipalV1
    from ..host.d13_core_counter_port_v1 import InstalledD13CoreCounterPortV1
    from .domain_followup_consumer_v1 import _observe_owner
    graph._admin(bootstrap)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    port=graph._GraphCoordinator__content_fence_v2;store=graph._GraphCoordinator__store
    if (type(instruction) is not D13CounterCPUPrepareInstructionV1 or assembly is None
            or assembly.admin_bundle is not bundle or instruction.namespace!=bundle.installation_policy.namespace
            or instruction.install_id!=bundle.installation_policy.installation_id):
        raise ValueError('D13 counter instruction belongs to another actual installation')
    selector=D13CurrentFramePrepareSelectorV7(instruction.install_id,instruction.authority_namespace,
        instruction.namespace,instruction.c02_operation_id,instruction.plan_ref,instruction.counter_operation_id)
    actual=InstalledD13CoreCounterPortV1(port,policy=bundle.d13_wire_policy).prepare_current_d13_frame_v7(selector)
    if type(actual) is D13CoreFrameIntentHeaderV7:
        with store._lock:
            db=store._db;db.execute('BEGIN')
            try:prior=read_c04_internal_work_prepared_v1(db,instruction.namespace,instruction.counter_operation_id)
            finally:db.rollback()
        if prior is None or prior.binding.input_digest!=instruction.input_digest:
            raise ValueError('Core prepared header lacks its actual same CPU W01 original')
        return {'binding_digest':prior.binding.binding_digest,'prepared_digest':prior.prepared_digest,'job_id':instruction.job_id}
    if actual!=instruction:raise ValueError('caller instruction differs from actual immutable Core draft')
    ns=instruction.namespace;operation_id=instruction.counter_operation_id+':prepare'
    with store._lock:
        metadata,_=graph._v2_graph_stamp(ns)
        owner_rev,owner_value=_head(store._db,ns,owner_grant_key(*ns.as_tuple))
        validate_owner_grant_v1(owner_value)
        source_id=AtomKey.from_token(instruction.source_ref.ref).owner.subject
        rows=store._db.execute('SELECT conversation_ref FROM graph_first_ingress_identity_v1 WHERE bot=? AND persona=? AND source_ref=?',
            (*ns.as_tuple,source_id)).fetchall()
        if len(rows)!=1:raise ValueError('actual counter C02 has no unique current conversation locator')
        audience=rows[0][0]
    pairing=port.current_owner_principal_binding(namespace=ns,authority_namespace=instruction.authority_namespace,
        principal=OwnerPrincipalV1(**owner_value['principal']))
    if pairing is None:raise ValueError('D13 counter current Owner is unpaired')
    authority=AuthorityContext(pairing.actor_id,'d13','installed-d13-counter:'+instruction.frame_intent_id,
        ns,('d02','d11','d13'),'expression',(audience,),port.installation_grant.publisher_policy_ref,
        metadata.requirements.activation_generation)
    captured=[]
    def observe(scope):
        result=_observe_owner(graph,authority,scope);captured[:]=[result];return result
    graph._read_v2(authority,lambda:None,fence_observer=observe)
    issued=_D13CounterSelfScopeV1(graph,authority,captured[0][1],operation_id,bundle,instruction)
    cpu_authority=graph._GraphCoordinator__d13_counter_cpu_quote_authority_v1
    def commit(db,metadata,epoch,now,owner,scope):
        return commit_current_d13_counter_cpu_in_tx_v1(db,graph=graph,issued=issued,scope=scope,
            owner=owner,now_utc=now,cpu_authority=cpu_authority)
    from .natural_producer_qualification_v1 import host_natural_producer_context_v1
    def observe_sources(scope,owner_guard,current_owner):
        if canonical_digest(owner_guard)!=instruction.owner_responsibility_digest:
            raise ValueError('D13 counter current independent Owner guard differs from Core responsibility')
        return host_natural_producer_context_v1(graph,scope=scope,
            parent_original_id=instruction.c02_operation_id,phase='prepare')
    _ACTIVE[id(issued)]=issued
    try:
        return graph._owner_domain_write_v3(authority,None,operation_id=operation_id,
            request_digest=canonical_digest({'schema':'sylanne3.d13.counter-prepare-write.v1','instruction':instruction}),
            domains=('d02','d11','d13'),capability='d13.counter.cpu.prepare',commit=commit,background_original=issued,fence_context=observe_sources,
            new_work_admission=lambda db:graph.local_module_admission.require_v1(('d02','d11','d13'),'prepare_current_d13_counter_cpu_v1'))
    finally:_ACTIVE.pop(id(issued),None)
