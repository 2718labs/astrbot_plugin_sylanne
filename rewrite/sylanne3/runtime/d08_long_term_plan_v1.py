"""Installed B3 current-window producers, exact Joint gates and read-only recovery."""
from dataclasses import dataclass,replace
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from ..domains.d08.long_term_plan_v1 import (LONG_PLAN_TYPE,JOINT_WINDOW_TYPE,WINDOW_ADVANCE_TYPE,LongTermPlanV1,JointWindowV1,LongTermWindowAdvanceV1,long_term_value_from_wire_v1,long_term_value_to_wire_v1,long_term_key_v1)
from ..graph_types import AtomKey,GraphVersion,GraphWrite,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,schema_hash
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,production_read_plan_v1,waiting_stage_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .joint_node_execution_v1 import QualifyJointPlanNodesRequestV1,qualify_joint_plan_nodes_v1,joint_result_versions_digest_v1,read_joint_binding_v1,qualify_joint_binding_v1
from .d08_production_operations_v1 import InstalledD08ProductionReadersV1,joint_plan_terms_digest_v1
from ..domains.d08.execution import _decode_joint_plan

OPERATIONS=frozenset(('adopt_long_term_plan_v1','prepare_joint_window_v1','enter_current_joint_window_v1','finalize_current_joint_window_v1','advance_long_term_window_v1','pause_long_term_plan_v1','resume_long_term_plan_v1','stop_long_term_plan_v1'))

@dataclass(frozen=True,slots=True)
class AdoptLongTermPlanRequestV1:
    plan:LongTermPlanV1
    def __post_init__(self):
        if type(self.plan)is not LongTermPlanV1 or self.plan.revision!=1 or self.plan.current_window_ref is not None or self.plan.state!='described':raise ValueError('new long plan is descriptive and has no current execution window')

@dataclass(frozen=True,slots=True)
class PrepareJointWindowRequestV1:
    window:JointWindowV1
    strategy_projection_ref:str|None=None
    strategy_projection_digest:str|None=None
    def __post_init__(self):
        if type(self.window)is not JointWindowV1 or self.window.state!='described'or self.window.final_joint_plan_ref is not None:raise ValueError('window preparation only registers a nonexecutive typed draft')
        if (self.strategy_projection_ref is None)!=(self.strategy_projection_digest is None):raise ValueError('window preference needs both actual conditioned projection ref and digest')

@dataclass(frozen=True,slots=True)
class EnterCurrentJointWindowRequestV1:
    window_ref:str
    expected_revision:int

@dataclass(frozen=True,slots=True)
class FinalizeCurrentJointWindowRequestV1:
    window_ref:str
    expected_revision:int
    joint_plan_ref:str
    joint_plan_revision:int
    final_terms_original_ref:str
    final_terms_original_digest:str
    binding_refs:tuple[str,...]
    party_acceptance_original_refs:tuple[str,...]

@dataclass(frozen=True,slots=True)
class AdvanceLongTermWindowRequestV1:
    previous_window_ref:str
    previous_window_revision:int
    next_window_ref:str
    next_window_revision:int
    milestone_evidence_original_refs:tuple[str,...]
    joint_qualification_original_ref:str
    joint_qualification_original_digest:str
    result_versions_digest:str

@dataclass(frozen=True,slots=True)
class PauseLongTermPlanRequestV1:
    plan_ref:str
    expected_revision:int

@dataclass(frozen=True,slots=True)
class ResumeLongTermPlanRequestV1:
    plan_ref:str
    expected_revision:int
    pause_original_ref:str

@dataclass(frozen=True,slots=True)
class StopLongTermPlanRequestV1:
    plan_ref:str
    expected_revision:int

@dataclass(frozen=True,slots=True)
class LongTermWindowRecoveryObservationV1:
    namespace:NamespaceId
    producer_original:ProductionOriginalRefV1
    producer_operation_id:str
    producing_receipt_digest:str
    window_ref:str|None
    window_revision:int|None
    state:str
    final_binding_refs:tuple[str,...]
    outcome_original_refs:tuple[str,...]
    coverage:str
    missing_inputs:tuple[str,...]


def _head(db,read,ref,kind,revision=None):
    atom=read.head(db,ref,required=True)
    if atom.key.type_name!=kind or revision is not None and atom.revision!=revision:raise ValueError('B3 exact current revision changed')
    return atom,long_term_value_from_wire_v1(kind,atom.value)

def _write(frame,atom,value):
    return GraphWrite(atom.key,long_term_value_to_wire_v1(value),dependencies=tuple(v.key for v in frame.snapshot.versions if v.key!=atom.key))

def _new_write(frame,key,value):
    atom=frame.snapshot.get(key)
    if atom is None or atom.revision!=0 or atom.valid:raise ValueError('new long plan identity already exists')
    return GraphWrite(key,long_term_value_to_wire_v1(value),dependencies=tuple(v.key for v in frame.snapshot.versions if v.key!=key))

def _actual_adoption(db,read,operation_id,kind):
    read.committed_operation(db,operation_id)
    original=read_adopted_domain_operation_v1(db,read.frame.envelope.authority.namespace,operation_id)
    if original is None or original['domain']!='d08'or original['operation_kind']!=kind:raise MissingProductionOriginalV1('actual_long_window_producer:'+operation_id)
    return original

def _require_qualified_sources(db,read,value):
    purpose=getattr(value,'purpose','context');audience=getattr(value,'audience',read.frame.envelope.authority.audience)
    read.source_family(db,value.source_refs,purpose=purpose,audience=None)
    if not set(read.frame.envelope.authority.audience)<=set(audience):raise ValueError('long window changed its signed audience')

def _joint_current(db,frame,window,*,issuer,completed):
    read=CurrentDomainReadV1(frame)
    atom=read.head(db,window.final_joint_plan_ref,required=True)
    if atom.revision!=window.final_joint_plan_revision:raise MissingProductionOriginalV1('current_window_final_joint_revision')
    plan=_decode_joint_plan(atom.value)
    request=QualifyJointPlanNodesRequestV1(atom.key.token,atom.revision,joint_result_versions_digest_v1(db,namespace=frame.envelope.authority.namespace,plan=plan))
    qualification=qualify_joint_plan_nodes_v1(db,frame=frame,request=request,readers=InstalledD08ProductionReadersV1(issuer=issuer))
    if tuple(node.node_id for node in plan.nodes)!=tuple(node.node_id for node in window.node_drafts)or tuple(node.resource_ref for node in plan.nodes)!=window.final_binding_refs:raise ValueError('current Joint changed exact window slots/bindings')
    for draft,node,qualified in zip(window.node_drafts,plan.nodes,qualification.nodes):
        if node.owner_ref!=draft.party_scope or node.success_predicate!=draft.success_predicate or node.compensation_ref!=draft.compensation_ref or node.cancellation_point!=draft.cancellation_point:raise ValueError('final Joint changed draft party/predicate/cancellation/compensation')
        if completed:
            expected='externally_confirmed'if draft.executor_kind=='external'else 'completed_verified'
            if qualified.state!=expected or qualified.proof_ref is None:raise MissingProductionOriginalV1('actual_window_predicate_result:'+node.node_id)
        elif qualified.state not in {'ready','completed_verified','externally_confirmed'}:raise MissingProductionOriginalV1('current_window_joint_qualification:'+node.node_id)
    # The recomputation is a current predicate check, never a newly born original.
    from .joint_node_execution_v1 import joint_qualification_operation_id_v1,joint_qualification_ref_v1,JointPlanQualificationV1,QUALIFICATION_KIND
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3,background_verify_signature_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    operation=joint_qualification_operation_id_v1(window.namespace,request);ref=joint_qualification_ref_v1(window.namespace,operation)
    row=_producer_original_point_v3(db,table='graph_d10_production_inputs_v1',columns=('kind','producing_operation_id','payload_json','payload_digest','signature'),key_columns=('bot','persona','original_ref'),key=(*window.namespace.as_tuple,ref),legacy_reader=lambda:db.execute('SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?',(*window.namespace.as_tuple,ref)).fetchone())
    if row is None:raise MissingProductionOriginalV1('actual_durable_joint_window_qualification')
    background_verify_signature_v3(issuer._signer,'d11.d10-production-input.v1',row[2],row[4])
    stored=decode_typed_production_value_v1(background_json_loads_v3(row[2]),JointPlanQualificationV1)
    business=('namespace','plan_ref','plan_revision','plan_digest','terms_digest','result_versions_digest','nodes','source_refs')
    adoption=read_adopted_domain_operation_v1(db,window.namespace,operation)
    if row[0]!=QUALIFICATION_KIND or row[1]!=operation or stored.digest!=row[3]or stored.original_ref!=ref or any(getattr(stored,name)!=getattr(qualification,name)for name in business)or adoption is None or(adoption['domain'],adoption['operation_kind'])!=('d10','input:qualify_joint_plan_nodes_v1'):raise ValueError('window qualification differs from its real signed qualified producer')
    for version in stored.read_versions:
        if read.head(db,version.key).revision!=version.revision:raise MissingProductionOriginalV1('current_original_joint_qualification_read_version')
    read.original(stored.original_ref,digest=stored.digest)
    return plan,stored

_REQUESTS={'adopt_long_term_plan_v1':AdoptLongTermPlanRequestV1,'prepare_joint_window_v1':PrepareJointWindowRequestV1,'enter_current_joint_window_v1':EnterCurrentJointWindowRequestV1,'finalize_current_joint_window_v1':FinalizeCurrentJointWindowRequestV1,'advance_long_term_window_v1':AdvanceLongTermWindowRequestV1,'pause_long_term_plan_v1':PauseLongTermPlanRequestV1,'resume_long_term_plan_v1':ResumeLongTermPlanRequestV1,'stop_long_term_plan_v1':StopLongTermPlanRequestV1}
def long_term_request_from_wire_v1(kind,raw):
    from dataclasses import fields
    cls=_REQUESTS[kind]
    if type(raw)is not dict or set(raw)!={f.name for f in fields(cls)}:raise ValueError('long window request closed fields differ')
    values=dict(raw)
    if 'plan'in values:values['plan']=long_term_value_from_wire_v1(LONG_PLAN_TYPE,values['plan'])
    if 'window'in values:values['window']=long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,values['window'])
    for k in('binding_refs','party_acceptance_original_refs','milestone_evidence_original_refs'):
        if k in values:values[k]=tuple(values[k])
    return cls(**values)


def _entry(db,frame,kind,request,installed):
    from .current_habit_source_read_v3 import require_current_habit_source_frame_v3
    require_current_habit_source_frame_v3(db,frame=frame,operation_kind=kind,request=request)
    if type(installed)is not InstalledD08ProductionReadersV1:raise TypeError('long windows use the actual installed Joint original reader')
    read=CurrentDomainReadV1(frame);read.check(db)
    if frame.envelope.authority.purpose!='context':raise ValueError('window preparation and current result observation require context')
    return read

def _emit(db,frame,kind,request,*,writes,provenance,causal,roots,semantic,predecessors=(),versions=(),events=()):
    from .domain_mesh_tick_v1 import MeshTickInputsV1,stage_joint_habit_mesh_companion_v1,combine_semantic_mesh_stage_v1
    inputs=MeshTickInputsV1(causal_original=causal,source_roots=roots,predecessors=predecessors,semantic_originals=(causal,),semantic_versions=versions,cancellation_generation=0,semantic_digest=canonical_digest(semantic),original_deadline_utc=frame.envelope.deadline_utc)
    companion=stage_joint_habit_mesh_companion_v1(db,frame=frame,operation_kind=kind,request=request,actual_inputs=inputs)
    provenance={**provenance,'semantic_mesh':companion.trace}
    base=stage_result_v1(frame,'d08',kind,request,writes=writes,provenance=provenance,receiver_events=events,proposal_schema='d08.proposal.v1',proposal_hash=schema_hash({'domain':'d08','proposal':1}))
    return combine_semantic_mesh_stage_v1(base,companion)

def stage_adopt_long_term_plan_v1(db,*,frame,request,installed):
    kind='adopt_long_term_plan_v1';read=_entry(db,frame,kind,request,installed);plan=request.plan
    if plan.namespace!=frame.envelope.authority.namespace:raise ValueError('long plan crossed namespace')
    _require_qualified_sources(db,read,plan)
    authorization=read.original(plan.owner_authorization_original_ref,digest=plan.owner_authorization_original_digest)
    goal=read.head(db,plan.goal_ref,required=True);project=read.head(db,plan.project_ref,required=True)
    if goal.value['state']not in {'active','proposed'}or project.value['reality']!='real_execution':raise MissingProductionOriginalV1('actual_long_plan_goal_and_real_project')
    for milestone in plan.milestones:
        read.head(db,milestone.goal_ref,required=True);read.head(db,milestone.project_ref,required=True);read.source_family(db,milestone.source_refs)
    key=long_term_key_v1(plan.namespace,LONG_PLAN_TYPE,plan.plan_id)
    return _emit(db,frame,kind,request,writes=(_new_write(frame,key,plan),),provenance={'plan':plan,'authorization':authorization},causal=authorization,roots=plan.source_refs,semantic={'plan':plan})

def stage_prepare_joint_window_v1(db,*,frame,request,installed):
    kind='prepare_joint_window_v1';read=_entry(db,frame,kind,request,installed);window=request.window
    atom,plan=_head(db,read,window.long_term_plan_ref,LONG_PLAN_TYPE,window.long_term_plan_revision)
    _require_qualified_sources(db,read,plan);_require_qualified_sources(db,read,window)
    if plan.state in {'paused','stopped','closed'}:raise MissingProductionOriginalV1('long_plan_current_preparation_not_paused')
    draft=read.original(window.draft_terms_original_ref,digest=window.draft_terms_original_digest)
    if window.prior_window_ref is None:
        if window.window_index!=0 or plan.current_window_ref is not None:raise ValueError('first window must be the actual zero index')
    else:
        _,prior=_head(db,read,window.prior_window_ref,JOINT_WINDOW_TYPE)
        if prior.long_term_plan_ref!=atom.key.token or window.window_index!=prior.window_index+1:raise ValueError('future descriptive window changed its exact predecessor')
    for node in window.node_drafts:
        read.head(db,node.goal_ref,required=True);read.head(db,node.project_ref,required=True)
        recipe=read.head(db,node.recipe_ref,required=True)
        if recipe.revision!=node.recipe_revision:raise MissingProductionOriginalV1('draft_actual_recipe_revision')
        for audience in node.audience:read.source_family(db,node.source_refs,purpose=node.purpose,audience=audience)
    preference=select_current_long_term_window_v1(db,frame=frame,request=request,installed=installed)
    key=long_term_key_v1(window.namespace,JOINT_WINDOW_TYPE,window.window_id)
    return _emit(db,frame,kind,request,writes=(_new_write(frame,key,window),),provenance={'window':window,'long_plan_head':GraphVersion(atom.key,atom.revision),'draft_original':draft,'conditioned_preference':preference},causal=draft,roots=tuple(dict.fromkeys((*plan.source_refs,*window.source_refs))),semantic={'window':window},versions=(GraphVersion(atom.key,atom.revision),))

def stage_enter_current_joint_window_v1(db,*,frame,request,installed):
    kind='enter_current_joint_window_v1';read=_entry(db,frame,kind,request,installed)
    atom,window=_head(db,read,request.window_ref,JOINT_WINDOW_TYPE,request.expected_revision)
    _,plan=_head(db,read,window.long_term_plan_ref,LONG_PLAN_TYPE)
    _require_qualified_sources(db,read,plan);_require_qualified_sources(db,read,window)
    if plan.state in {'paused','stopped','closed'}or window.state not in {'described','preparing'}or frame.now_utc>=window.original_deadline_utc:raise MissingProductionOriginalV1('current_window_original_preparation_scope')
    prior_qualification=None
    if window.prior_window_ref is not None:
        _,prior=_head(db,read,window.prior_window_ref,JOINT_WINDOW_TYPE)
        if plan.current_window_ref!=window.prior_window_ref or window.window_index!=prior.window_index+1:raise ValueError('next preparing window is not the exact current successor')
        _,prior_qualification=_joint_current(db,frame,prior,issuer=installed.issuer,completed=True)
    elif window.window_index!=0 or plan.current_window_ref is not None:raise ValueError('first preparing window has an unrelated current pointer')
    # Preparing only permits original, separately admitted local registrations.
    # It grants no external party responsibility, Action dispatch or new Root.
    updated=replace(window,state='preparing')
    causal=read.original(window.draft_terms_original_ref,digest=window.draft_terms_original_digest)
    writes=()if updated==window else(_write(frame,atom,updated),)
    return _emit(db,frame,kind,request,writes=writes,provenance={'window':updated,'prior_actual_qualification':prior_qualification},causal=causal,roots=window.source_refs,semantic={'window':updated})

def _match_final_bindings(db,frame,window,plan,issuer):
    from .domain_background_read_v3 import background_history_v3
    from .joint_node_execution_v1 import SourceNoteJointExecutorV1,ArtifactJointExecutorV1,ContactJointExecutorV1,JointContactProspectiveBindingV1
    from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    executor_kinds={SourceNoteJointExecutorV1:'source_note',ArtifactJointExecutorV1:'draft_file',ContactJointExecutorV1:'contact'}
    for draft,node in zip(window.node_drafts,plan.nodes):
        if draft.executor_kind=='external':
            from .joint_external_observation_v1 import read_joint_d08_original_v1
            contract=read_joint_d08_original_v1(db,namespace=window.namespace,original_ref=node.resource_ref,issuer=issuer)
            if(contract.original_ref,contract.digest,contract.party_ref,contract.success_predicate,contract.source_refs,contract.original_deadline_utc,contract.purpose,contract.audience)!=(draft.typed_request_ref,draft.typed_input_original_digest,draft.party_scope,draft.success_predicate,draft.source_refs,draft.original_deadline_utc,draft.purpose,draft.audience)or draft.typed_request_digest!=canonical_digest({'contract':plain_v1(contract)})or draft.resource_commitment!=contract.digest:raise ValueError('external final contract differs from actual draft commitments')
            continue
        binding=read_joint_binding_v1(db,namespace=window.namespace,ref=node.resource_ref,issuer=issuer)
        _,state=qualify_joint_binding_v1(db,frame=frame,binding=binding,issuer=issuer)
        if state!='current'or executor_kinds[type(binding.executor)]!=draft.executor_kind or(binding.project_ref,binding.recipe_ref,binding.goal_ref,binding.target_ref,binding.source_refs,binding.parent_budget_lease_ref,binding.parent_grant_digest,binding.original_deadline_utc,binding.purpose,binding.audience)!=(draft.project_ref,draft.recipe_ref,draft.goal_ref,draft.target_ref,draft.source_refs,draft.parent_grant_ref,draft.parent_grant_digest,draft.original_deadline_utc,draft.purpose,draft.audience):raise ValueError('final binding changes the exact typed draft scope or Root')
        recipe=CurrentDomainReadV1(frame).head(db,binding.recipe_ref,required=True)
        if recipe.revision!=draft.recipe_revision:raise ValueError('final binding changes committed recipe revision')
        if type(binding)is JointArtifactProspectiveBindingV1:
            if(draft.typed_request_ref,draft.typed_input_original_digest)!=(binding.task_scope_ref,binding.task_scope_digest)or draft.typed_request_digest!=canonical_digest({'binding':plain_v1(binding)})or draft.cancellation_ref!=binding.task_scope_ref:raise ValueError('Artifact window must preserve its real prospective task scope and request before C4 Action')
        elif type(binding)is JointContactProspectiveBindingV1:
            if(draft.typed_request_ref,draft.typed_input_original_digest)!=(binding.prospective_original_ref,binding.prospective_original_digest)or draft.typed_request_digest!=canonical_digest({'binding':plain_v1(binding)}):raise ValueError('Contact window must preserve its actual prospective birth and fixed request')
        else:
            if type(binding.executor)is not SourceNoteJointExecutorV1:raise ValueError('managed local executor requires its installed prospective variant')
            cancellation_key=AtomKey(AtomKey.from_token(binding.action_ref).owner,'d08.action_cancellation.v1',AtomKey.from_token(binding.action_ref).name)
            if draft.cancellation_ref!=cancellation_key.token:raise ValueError('final binding changed actual cancellation identity')
            history=background_history_v3(db,binding.action_ref,binding.action_revision,columns=('event_id',))
            original=None if history is None else read_adopted_domain_operation_v1(db,window.namespace,history[0])
            if original is None or original['operation_kind']!='prepare_selected_source_note_action_v2'or canonical_digest(original['payload']['request'])!=draft.typed_request_digest or(original['payload']['provenance']['selected_decision_ref'],original['payload']['provenance']['selected_decision_digest'])!=(draft.typed_request_ref,draft.typed_input_original_digest):raise ValueError('actual selected SourceNote request differs from adopted draft input and parameters')
        resource=canonical_digest((binding.parent_budget_lease_ref,binding.parent_grant_id,binding.parent_grant_version,binding.parent_grant_digest))
        if resource!=draft.resource_commitment:raise ValueError('actual binding changes original resource commitment')


def stage_finalize_current_joint_window_v1(db,*,frame,request,installed):
    kind='finalize_current_joint_window_v1';read=_entry(db,frame,kind,request,installed)
    atom,window=_head(db,read,request.window_ref,JOINT_WINDOW_TYPE,request.expected_revision)
    plan_atom,long_plan=_head(db,read,window.long_term_plan_ref,LONG_PLAN_TYPE)
    _require_qualified_sources(db,read,long_plan);_require_qualified_sources(db,read,window)
    if window.state not in {'preparing','waiting'}or long_plan.state in {'paused','stopped','closed'}:raise MissingProductionOriginalV1('actual_owner_window_preparing')
    updated=replace(window,final_joint_plan_ref=request.joint_plan_ref,final_joint_plan_revision=request.joint_plan_revision,final_binding_refs=request.binding_refs,final_terms_original_ref=request.final_terms_original_ref,final_terms_original_digest=request.final_terms_original_digest,party_acceptance_original_refs=request.party_acceptance_original_refs,state='waiting')
    current,qualification=_joint_current(db,frame,updated,issuer=installed.issuer,completed=False)
    from .domain_background_read_v3 import background_history_v3
    current_atom=read.head(db,request.joint_plan_ref,required=True)
    history=background_history_v3(db,current_atom.key.token,current_atom.revision,columns=('event_id',))
    adoption=_actual_adoption(db,read,history[0],'adopt_joint_plan')
    adopted_request=adoption['payload']['request']
    if adopted_request['joint_plan_proposal_ref']!=request.final_terms_original_ref or tuple(adopted_request['party_consent_original_refs'])!=request.party_acceptance_original_refs:raise ValueError('final window does not use actual accepted final Joint terms')
    intent,terms=installed._read_intent(db,read,request.final_terms_original_ref)
    if terms.original_digest!=request.final_terms_original_digest or joint_plan_terms_digest_v1(intent)!=qualification.terms_digest:raise ValueError('final window terms digest differs from current actual consent')
    _match_final_bindings(db,frame,updated,current,installed.issuer)
    writes=[]
    if updated.window_index==0:
        if long_plan.current_window_ref is not None:raise ValueError('first ready window cannot replace another pointer')
        updated=replace(updated,state='ready')
        writes.append(_write(frame,plan_atom,replace(long_plan,revision=long_plan.revision+1,current_window_ref=atom.key.token,state='ready')))
    writes.insert(0,_write(frame,atom,updated))
    return _emit(db,frame,kind,request,writes=tuple(writes),provenance={'window':updated,'joint_qualification':qualification,'accepted_final_terms':terms},causal=terms,roots=tuple(dict.fromkeys((*window.source_refs,*current.source_refs))),semantic={'window':updated,'long_plan_current_window':atom.key.token if updated.state=='ready'else long_plan.current_window_ref},events=(('d08','joint_window_results_require_advance'),))

def stage_advance_long_term_window_v1(db,*,frame,request,installed):
    kind='advance_long_term_window_v1';read=_entry(db,frame,kind,request,installed)
    before_atom,before=_head(db,read,request.previous_window_ref,JOINT_WINDOW_TYPE,request.previous_window_revision)
    next_atom,next_window=_head(db,read,request.next_window_ref,JOINT_WINDOW_TYPE,request.next_window_revision)
    plan_atom,plan=_head(db,read,before.long_term_plan_ref,LONG_PLAN_TYPE)
    for value in(plan,before,next_window):_require_qualified_sources(db,read,value)
    if plan.current_window_ref!=before_atom.key.token or plan.state in {'paused','stopped','closed'}or next_window.state!='waiting'or next_window.prior_window_ref!=before_atom.key.token or next_window.window_index!=before.window_index+1 or next_window.long_term_plan_ref!=plan_atom.key.token:raise ValueError('advance requires exact current predecessor and fully accepted successor')
    _,qualification=_joint_current(db,frame,before,issuer=installed.issuer,completed=True)
    if (qualification.original_ref,qualification.digest,qualification.result_versions_digest)!=(request.joint_qualification_original_ref,request.joint_qualification_original_digest,request.result_versions_digest):raise ValueError('advance changed actual current predicate qualification')
    causal=read.original(qualification.original_ref,digest=qualification.digest)
    evidence=tuple(read.original(ref)for ref in request.milestone_evidence_original_refs)
    if not evidence or not set(n.proof_ref for n in qualification.nodes)<=set(request.milestone_evidence_original_refs):raise MissingProductionOriginalV1('every_actual_window_node_predicate_proof')
    _joint_current(db,frame,next_window,issuer=installed.issuer,completed=False)
    ready=replace(next_window,state='ready');closed=replace(before,state='closed');advanced=replace(plan,revision=plan.revision+1,current_window_ref=next_atom.key.token,state='ready')
    advance=LongTermWindowAdvanceV1(plan.namespace,'window-advance:'+canonical_digest((before_atom.key.token,before_atom.revision,next_atom.key.token,next_atom.revision))[:48],plan_atom.key.token,plan_atom.revision,before_atom.key.token,before_atom.revision,qualification.original_ref,qualification.digest,qualification.result_versions_digest,request.milestone_evidence_original_refs,next_atom.key.token,next_atom.revision,next_window.final_terms_original_ref,next_window.party_acceptance_original_refs,tuple(dict.fromkeys((*before.source_refs,*next_window.source_refs))))
    key=long_term_key_v1(plan.namespace,WINDOW_ADVANCE_TYPE,advance.advance_id)
    writes=(_write(frame,before_atom,closed),_write(frame,next_atom,ready),_write(frame,plan_atom,advanced),_new_write(frame,key,advance))
    return _emit(db,frame,kind,request,writes=writes,provenance={'advance':advance,'actual_node_qualification':qualification,'milestone_evidence':evidence},causal=causal,roots=advance.source_refs,semantic={'plan':advanced,'previous':closed,'next':ready,'advance':advance},predecessors=(causal,))

def _control(db,*,frame,request,installed,kind,target):
    read=_entry(db,frame,kind,request,installed);atom,plan=_head(db,read,request.plan_ref,LONG_PLAN_TYPE,request.expected_revision)
    _require_qualified_sources(db,read,plan)
    if plan.state in {'stopped','closed'}:raise ValueError('terminal long plan cannot resume or change its original commitments')
    if target=='waiting':
        if plan.state!='paused':raise ValueError('resume requires actual paused long plan')
        prior=_actual_adoption(db,read,request.pause_original_ref,'pause_long_term_plan_v1')
        if prior['payload']['request']['plan_ref']!=atom.key.token:raise ValueError('resume names another paused plan')
    updated=replace(plan,revision=plan.revision+1,state=target)
    causal=read.original(plan.owner_authorization_original_ref,digest=plan.owner_authorization_original_digest)
    return _emit(db,frame,kind,request,writes=(_write(frame,atom,updated),),provenance={'before':plan,'after':updated},causal=causal,roots=plan.source_refs,semantic={'plan':updated})
def stage_pause_long_term_plan_v1(db,*,frame,request,installed):return _control(db,frame=frame,request=request,installed=installed,kind='pause_long_term_plan_v1',target='paused')
def stage_resume_long_term_plan_v1(db,*,frame,request,installed):return _control(db,frame=frame,request=request,installed=installed,kind='resume_long_term_plan_v1',target='waiting')
def stage_stop_long_term_plan_v1(db,*,frame,request,installed):return _control(db,frame=frame,request=request,installed=installed,kind='stop_long_term_plan_v1',target='stopped')


def read_plan_current_long_term_operation_v1(db,*,namespace,activity_id,operation_kind,request):
    from .current_habit_source_read_v3 import current_habit_source_read_plan_v3
    if operation_kind not in OPERATIONS or type(request)is not _REQUESTS[operation_kind]:raise ValueError('unknown long window operation/request')
    return current_habit_source_read_plan_v3(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)

def recover_long_term_window_v1(db,*,work,frame,producer_original,producer_operation_id,issuer):
    from .semantic_recovery_source_v3 import require_current_semantic_recovery_work_v3,read_committed_semantic_producer_v3
    namespace=frame.envelope.authority.namespace
    require_current_semantic_recovery_work_v3(work,db=db,namespace=namespace,producer_operation_id=producer_operation_id)
    actual=read_committed_semantic_producer_v3(work,db=db,namespace=namespace,producer_operation_id=producer_operation_id,issuer=issuer)
    operation=producer_operation_id
    if actual['domain']!='d08'or actual['operation_kind']not in OPERATIONS or producer_original.original_digest!=actual['original_digest']or producer_original.original_ref!='d08-current:'+actual['original_digest'][:48]:raise ValueError('long window recovery observes only its exact committed producer identity')
    read=CurrentDomainReadV1(frame);read.check(db);read.committed_operation(db,operation)
    windows=tuple(v for v in actual['receipt'].write_versions if v.key.type_name==JOINT_WINDOW_TYPE)
    if not windows:
        plans=tuple(v for v in actual['receipt'].write_versions if v.key.type_name==LONG_PLAN_TYPE)
        if len(plans)!=1:raise ValueError('long plan recovery lacks one actual plan/window identity')
        _,plan=_head(db,read,plans[0].key,LONG_PLAN_TYPE)
        return LongTermWindowRecoveryObservationV1(frame.envelope.authority.namespace,producer_original,operation,canonical_digest(actual['receipt']),None,None,plan.state,(),(),'complete',())
    # Advance writes old and next; observe the pointer's exact current window.
    candidates=[]
    for version in windows:
        atom,window=_head(db,read,version.key,JOINT_WINDOW_TYPE)
        candidates.append((atom,window))
    selected=next(((a,w)for a,w in candidates if w.state=='ready'),candidates[-1])
    atom,window=selected
    return LongTermWindowRecoveryObservationV1(window.namespace,producer_original,operation,canonical_digest(actual['receipt']),atom.key.token,atom.revision,window.state,window.final_binding_refs,(),'complete',())


def select_current_long_term_window_v1(db,*,frame,request,installed):
    if request.strategy_projection_ref is None:return None
    from .conditioned_self_operations_v1 import require_current_conditioned_life_projection_v1
    read=CurrentDomainReadV1(frame)
    node=request.window.node_drafts[0]
    projection=require_current_conditioned_life_projection_v1(db,read,request.strategy_projection_ref,request.strategy_projection_digest,project_ref=node.project_ref,recipe_ref=node.recipe_ref,issuer=installed.issuer)
    # Preference records observed conditions; it changes neither the fixed draft
    # nor eligibility. Unknown conditions preserve the caller's alternatives.
    return projection

def stage_current_long_term_operation_v1(db,*,frame,request,installed_readers,operation_kind):
    if operation_kind not in OPERATIONS or type(request)is not _REQUESTS[operation_kind]:raise ValueError('unknown B3 long-window request')
    return globals()['stage_'+operation_kind](db,frame=frame,request=request,installed=installed_readers)


def current_long_term_original_maintenance_v1(db,*,frame,operation_kind,request,installed):
    if operation_kind not in {'pause_long_term_plan_v1','stop_long_term_plan_v1'}or type(request)is not _REQUESTS[operation_kind]or request.expected_revision<1:return False
    read=_entry(db,frame,operation_kind,request,installed);atom,plan=_head(db,read,request.plan_ref,LONG_PLAN_TYPE,request.expected_revision)
    _require_qualified_sources(db,read,plan)
    if plan.state in {'stopped','closed'}:return False
    from .d10_habit_v1 import require_joint_habit_head_original_v1
    require_joint_habit_head_original_v1(db,read=read,atom=atom,allowed_producers={('d08',kind)for kind in ('adopt_long_term_plan_v1','pause_long_term_plan_v1','resume_long_term_plan_v1','stop_long_term_plan_v1','finalize_current_joint_window_v1','advance_long_term_window_v1')})
    read.original(plan.owner_authorization_original_ref,digest=plan.owner_authorization_original_digest)
    return True


def long_term_operation_metadata_output_keys_v1(namespace,*,operation_kind,request):
    """Pure keys derived from the fixed typed command, never a body/permission recipe."""
    if operation_kind not in OPERATIONS or type(request)is not _REQUESTS[operation_kind]:raise ValueError('exact installed long-window metadata command required')
    if operation_kind=='adopt_long_term_plan_v1':return(long_term_key_v1(namespace,LONG_PLAN_TYPE,request.plan.plan_id),)
    if operation_kind=='prepare_joint_window_v1':return(long_term_key_v1(namespace,JOINT_WINDOW_TYPE,request.window.window_id),)
    if operation_kind=='advance_long_term_window_v1':
        identity='window-advance:'+canonical_digest((request.previous_window_ref,request.previous_window_revision,request.next_window_ref,request.next_window_revision))[:48]
        return(AtomKey.from_token(request.previous_window_ref),AtomKey.from_token(request.next_window_ref),long_term_key_v1(namespace,WINDOW_ADVANCE_TYPE,identity))
    ref=request.window_ref if operation_kind in {'enter_current_joint_window_v1','finalize_current_joint_window_v1'}else request.plan_ref
    return(AtomKey.from_token(ref),)
