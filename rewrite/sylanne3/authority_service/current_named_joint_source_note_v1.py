"""Independent named SourceNote Window restriction plus original WRITE evidence.

The READ observation grants no foreground execution. A WRITE observation must
also consume the exact existing FG/OwnerTask service on that original permit.
"""
from dataclasses import dataclass,fields
from types import SimpleNamespace
from ..runtime_contracts import NamespaceId,canonical_digest
from ..graph_types import GraphVersion,GraphSnapshot,NamespaceEpoch,AtomKey,owner_grant_key
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from ..runtime.issuers import BudgetLeaseGrant
from .v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
from .current_foreground_activity_v1 import (ForegroundActivityRequestV1,ForegroundActivityEvidenceV1,
    foreground_typed_command_digest_v1,foreground_fence_operation_id_v1)
from .current_owner_source_note_task_v1 import(OwnerTaskActivityRequestV1,OwnerTaskActivityEvidenceV1,
    owner_task_typed_command_digest_v1,owner_task_fence_operation_id_v1)
from ..domains.d08.personal_candidate_v1 import ConsumePersonalDecisionRequestV1,PersonalCandidateFutureIdentityV1
from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1,ProductionQueryCoverageV1,ProductionOperationLimitsV1
from ..runtime.joint_window_management_v1 import ManagedWindowArgumentV1

OPERATION='prepare_selected_source_note_action_v2'


def named_joint_source_note_digest_v1(namespace,original_selector,argument,command):
    return canonical_digest(('d10.named-joint-source-note-command.v1',namespace,original_selector,argument,command))


@dataclass(frozen=True,slots=True)
class NamedJointSourceNoteSelectorV1:
    namespace:NamespaceId
    installation_id:str
    original_selector:ForegroundActivityRequestV1|OwnerTaskActivityRequestV1
    argument:ManagedWindowArgumentV1
    command:ConsumePersonalDecisionRequestV1
    request_digest:str
    schema:str='d10.named-joint-source-note-selector.v1'
    def __post_init__(self):
        from ..runtime.domain_production_registry_v1 import installed_operation_v1
        original=self.original_selector
        digest=(foreground_typed_command_digest_v1 if type(original)is ForegroundActivityRequestV1 else owner_task_typed_command_digest_v1)
        if(self.schema!='d10.named-joint-source-note-selector.v1'or type(self.namespace)is not NamespaceId
                or type(original)not in {ForegroundActivityRequestV1,OwnerTaskActivityRequestV1}
                or(original.namespace,original.installation_id,original.operation_kind)!=(self.namespace,self.installation_id,OPERATION)
                or type(self.argument)is not ManagedWindowArgumentV1 or self.argument.executor_kind!='source_note'
                or type(self.command)is not ConsumePersonalDecisionRequestV1 or self.command.decision_ref!=self.argument.typed_input_original_ref
                or original.request_digest!=digest(installed_operation_v1(OPERATION),self.command)
                or self.request_digest!=named_joint_source_note_digest_v1(self.namespace,original,self.argument,self.command)):
            raise ValueError('Named SourceNote binds its exact existing original selector, adopted slot and ConsumeRequest')
    @property
    def operation_id(self):return self.original_selector.operation_id
    @property
    def operation_kind(self):return OPERATION


@dataclass(frozen=True,slots=True)
class NamedJointSourceNoteCurrentV1:
    request:NamedJointSourceNoteSelectorV1
    permit:FencePermitV2
    current_self:AuthorityCurrentSelfIdentityV1
    owner_guard:ProductionOwnerGuardV1
    window_head:GraphVersion
    window_digest:str
    window_producer_ref:str
    window_producer_digest:str
    long_plan_head:GraphVersion
    long_plan_digest:str
    long_plan_producer_ref:str
    long_plan_producer_digest:str
    node_digest:str
    decision_head:GraphVersion
    decision_digest:str
    preparation_original_ref:str
    preparation_original_digest:str
    selected_candidate_digest:str
    audience:tuple[str,...]
    future_identity:PersonalCandidateFutureIdentityV1
    parent_grant:BudgetLeaseGrant
    original_deadline_utc:float
    valid_until_utc:float
    read_versions:tuple[GraphVersion,...]
    query_coverage:tuple[ProductionQueryCoverageV1,...]
    source_closure:tuple[GraphVersion,...]
    source_purpose_groups:tuple[tuple[str,tuple[str,...],tuple[str,...]],...]
    source_proof_digest:str
    guard_inventory_digest:str
    observed_at_utc:float
    prior_window_head:GraphVersion|None
    prior_qualification_ref:str|None
    prior_qualification_digest:str|None
    prior_result_versions_digest:str|None
    original_evidence:ForegroundActivityEvidenceV1|OwnerTaskActivityEvidenceV1|None
    schema:str='d10.named-joint-source-note-current.v1'
    def __post_init__(self):
        from ..runtime.issuers import BudgetLeaseGrant
        if(self.schema!='d10.named-joint-source-note-current.v1'or type(self.request)is not NamedJointSourceNoteSelectorV1
                or type(self.permit)is not FencePermitV2 or self.permit.operation not in {'read','write'}
                or type(self.current_self)is not AuthorityCurrentSelfIdentityV1 or self.current_self.permit!=self.permit
                or type(self.owner_guard)is not ProductionOwnerGuardV1 or type(self.parent_grant)is not BudgetLeaseGrant
                or type(self.audience)is not tuple or not self.audience
                or type(self.future_identity)is not PersonalCandidateFutureIdentityV1
                or self.future_identity.action_operation_id!=self.request.operation_id
                or self.decision_head.key.token!=self.request.command.decision_ref
                or self.decision_digest!=self.request.argument.typed_input_original_digest
                or not self.observed_at_utc<self.valid_until_utc<=min(self.original_deadline_utc,self.parent_grant.valid_until_utc)):
            raise ValueError('Named SourceNote current has no exact original future/current Window/Root scope')
        if self.permit.operation=='read':
            if self.original_evidence is not None:raise ValueError('A restriction READ cannot masquerade as foreground issuance')
        elif(type(self.original_evidence)not in {ForegroundActivityEvidenceV1,OwnerTaskActivityEvidenceV1}
                or self.original_evidence.request!=self.request.original_selector
                or self.original_evidence.current_self!=self.current_self or self.original_evidence.owner_guard!=self.owner_guard
                or self.audience!=(self.original_evidence.request.audiences if type(self.original_evidence)is ForegroundActivityEvidenceV1 else self.original_evidence.authorization.cause.audiences)):
            raise ValueError('SourceNote WRITE must also carry the unchanged actual original Self issuance')
        for version in(*self.read_versions,*self.source_closure,self.window_head,self.long_plan_head,self.decision_head):
            if type(version)is not GraphVersion or NamespaceId.from_key(version.key)!=self.request.namespace:raise ValueError('SourceNote current crossed namespace')
        prior=(self.prior_window_head,self.prior_qualification_ref,self.prior_qualification_digest,self.prior_result_versions_digest)
        if not(all(v is None for v in prior)or type(prior[0])is GraphVersion and all(type(v)is str and v for v in prior[1:])):raise ValueError('SourceNote successor needs one actual complete prior qualification')


    def require_for_v3(self,*,request,permit,installation_id,authority_namespace):
        if self.request!=request or self.permit!=permit or self.current_self.installation_id!=installation_id or self.current_self.authority_namespace!=authority_namespace:
            raise AuthorityUnavailable('Named SourceNote paired observation changed its actual request/permit/installation')
        return self

def note_selector_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not NamedJointSourceNoteSelectorV1:raise TypeError('Exact named SourceNote selector required')
    return plain_v1(value)


def note_selector_from_wire_v1(raw):
    from ..runtime.joint_window_management_v1 import managed_window_argument_from_wire_v1
    from .current_foreground_activity_v1 import foreground_from_wire_v1
    from .current_owner_source_note_task_v1 import owner_task_activity_from_wire_v1
    if type(raw)is not dict or set(raw)!={field.name for field in fields(NamedJointSourceNoteSelectorV1)}:raise ValueError('Closed SourceNote selector fieldset differs')
    original=raw['original_selector']
    original=(foreground_from_wire_v1(original,ForegroundActivityRequestV1)if original['schema']=='d11.foreground-activity-request.v1'else owner_task_activity_from_wire_v1(original,OwnerTaskActivityRequestV1))
    value=NamedJointSourceNoteSelectorV1(NamespaceId(**raw['namespace']),raw['installation_id'],original,
        managed_window_argument_from_wire_v1(raw['argument']),ConsumePersonalDecisionRequestV1(**raw['command']),raw['request_digest'],raw['schema'])
    if note_selector_to_wire_v1(value)!=raw:raise ValueError('SourceNote selector canonical wire differs')
    return value


def note_current_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not NamedJointSourceNoteCurrentV1:raise TypeError('Exact named SourceNote observation required')
    return plain_v1(value)


def note_current_from_wire_v1(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime.issuers import BudgetLeaseGrant
    if type(raw)is not dict or set(raw)!={field.name for field in fields(NamedJointSourceNoteCurrentV1)}:raise ValueError('Closed SourceNote observation fieldset differs')
    grant=decode_typed_production_value_v1(raw['parent_grant'],BudgetLeaseGrant)
    # Decode all other fixed typed fields without accepting an arbitrary object.
    values={field.name:raw[field.name]for field in fields(NamedJointSourceNoteCurrentV1)}
    values['request']=note_selector_from_wire_v1(raw['request'])
    from .v2_contract import from_wire
    values['permit']=from_wire(raw['permit'])
    for name,kind in(('current_self',AuthorityCurrentSelfIdentityV1),('owner_guard',ProductionOwnerGuardV1),('future_identity',PersonalCandidateFutureIdentityV1)):
        values[name]=decode_typed_production_value_v1(raw[name],kind)
    for name in('window_head','long_plan_head','decision_head','prior_window_head'):
        values[name]=None if raw[name]is None else decode_typed_production_value_v1(raw[name],GraphVersion)
    for name,kind in(('read_versions',GraphVersion),('source_closure',GraphVersion),('query_coverage',ProductionQueryCoverageV1)):
        values[name]=tuple(decode_typed_production_value_v1(item,kind)for item in raw[name])
    values['audience']=tuple(raw['audience'])
    values['source_purpose_groups']=tuple((purpose,tuple(audiences),tuple(roots))for purpose,audiences,roots in raw['source_purpose_groups'])
    original=raw['original_evidence']
    if original is not None:
        from .current_foreground_activity_v1 import foreground_from_wire_v1
        from .current_owner_source_note_task_v1 import owner_task_activity_from_wire_v1
        original=(foreground_from_wire_v1(original,ForegroundActivityEvidenceV1)if original['schema']=='d11.foreground-activity-evidence.v1'else owner_task_activity_from_wire_v1(original,OwnerTaskActivityEvidenceV1))
    values['original_evidence']=original;values['parent_grant']=grant
    value=NamedJointSourceNoteCurrentV1(**values)
    if note_current_to_wire_v1(value)!=raw:raise ValueError('SourceNote current canonical wire differs')
    return value


def note_metadata_groups_v1(state):
    request=state.request;entry=state.metadata.get(request.argument.window_ref)
    if entry is None or entry[:2]!=(request.argument.window_revision,1):raise AuthorityUnavailable('SourceNote restriction lost its actual current Window')
    window=entry[3];plan_entry=state.metadata.get(window['long_term_plan_ref'])
    if plan_entry is None or plan_entry[1]!=1:raise AuthorityUnavailable('SourceNote restriction has no actual LongPlan metadata')
    plan=plan_entry[3];node=next((node for node in window['node_drafts']if node['node_id']==request.argument.node_id),None)
    if node is None or(node['executor_kind'],node['typed_request_ref'],node['typed_input_original_digest'],node['typed_request_digest'])!=('source_note',request.command.decision_ref,request.argument.typed_input_original_digest,canonical_digest(request.command)):
        raise AuthorityUnavailable('SourceNote restriction changed its exact adopted Consume commitment')
    import time
    state.work.deadline_utc=min(state.work.deadline_utc,node['original_deadline_utc'])
    state.initial_monotonic_deadline=min(state.initial_monotonic_deadline,time.monotonic()+state.work.deadline_utc-state.work.now_utc)
    state.note_node=node;groups={}
    def add(roots,purpose,audiences):
        for audience in audiences:groups.setdefault((purpose,audience),set()).update(roots)
    add(window['source_refs'],'context',node['audience']);add(window['source_refs'],'consolidation',node['audience'])
    add(plan['source_refs'],plan['purpose'],plan['audience']);add(node['source_refs'],node['purpose'],node['audience'])
    prior=window.get('prior_window_ref')
    if prior is not None:
        if prior not in state.metadata:raise AuthorityUnavailable('SourceNote successor has no actual prior metadata')
        add(state.metadata[prior][3]['source_refs'],'context',node['audience'])
        add(state.metadata[prior][3]['source_refs'],'consolidation',node['audience'])
    return tuple((purpose,audience,tuple(sorted(roots)))for(purpose,audience),roots in sorted(groups.items())if roots)


def refresh_named_source_note_frame_v1(state):
    from ..runtime_contracts import QueryEpoch
    from .named_joint_binding_body_v1 import _FAMILIES
    ns=state.work.namespace;node=state.note_node
    pages=tuple(ProductionQueryCoverageV1(QueryEpoch(ns,'namespace',state.work.graph_stamp[0]),kind,
        tuple(GraphVersion(AtomKey.from_token(ref),head[0])for ref,head in state.work.heads.items()if AtomKey.from_token(ref).type_name==kind),True,None)for kind in sorted(_FAMILIES))
    state.semantic_frame=SimpleNamespace(snapshot=GraphSnapshot(tuple(state.bodies.values()),(NamespaceEpoch(*ns.as_tuple,state.work.graph_stamp[0]),)),
        query_coverage=pages,owner_guard=state.owner_guard,now_utc=state.work.now_utc,observed_originals=tuple(state.original_refs.values()),installed_policy_refs=(),
        activation_generation=state.current_self.activation_generation,limits=ProductionOperationLimitsV1(),
        envelope=SimpleNamespace(authority=SimpleNamespace(namespace=ns,purpose='context',audience=tuple(node['audience']),actor=state.current_self.self_entity_ref),
            parent_budget_lease_ref=node['parent_grant_ref'],deadline_utc=state.valid_until,identity=SimpleNamespace(operation_id=state.request.operation_id)))


def _parent(state):
    from .named_joint_binding_source_read_v3 import _fixed,_column
    from ..runtime.issuers import BudgetLeaseGrant
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime_contracts import canonical_serialize
    node=state.note_node;ns=state.work.namespace;current=node['parent_grant_ref'];chain=[]
    while current is not None:
        if current in state.budget_lease_ids or len(chain)>=32:raise AuthorityUnavailable('SourceNote original budget family is cyclic or exceeds its actual bound')
        state.budget_lease_ids.add(current)
        lease=_fixed(state.work,'runtime_budget_leases',('lease_id','parent_id','bot_id','persona_id','currency','state'),'lease_id=?',(current,))
        row=_fixed(state.work,'runtime_budget_grants',('version','signature','status'),'lease_id=? ORDER BY version DESC',(current,))
        debt=_fixed(state.work,'runtime_budget_debt_blocks',('lease_id',),'lease_id=?',(current,))
        if lease is None or lease[2:4]!=ns.as_tuple or lease[5]!='active'or row is None or row[2]!='active'or debt is not None:raise AuthorityUnavailable('SourceNote actual original budget family is not current')
        raw=_column(state,'runtime_budget_grants','grant_json',('lease_id','version'),(current,row[0]))
        state.service.issuer._signer.verify('budget-grant.v1',canonical_serialize(raw),row[1]);grant=decode_typed_production_value_v1(raw,BudgetLeaseGrant)
        if(grant.lease_id,grant.version,grant.bot_id,grant.persona_id,grant.currency)!=(current,row[0],*ns.as_tuple,lease[4]):raise AuthorityUnavailable('SourceNote original grant identity changed')
        chain.append((lease,grant));current=lease[1]
    policy=state.service.installed_bundle.installation_policy
    if not chain or chain[-1][0][0]!=policy.root_lease.lease_id or chain[-1][1]!=policy.root_grant or canonical_digest(chain[0][1])!=node['parent_grant_digest']:
        raise AuthorityUnavailable('SourceNote cannot replace its actual installed original Root family')
    from ..runtime.d11_life_contract_v1 import WORK_KIND
    if any(WORK_KIND not in grant.allowed_work_kinds for _,grant in chain):raise AuthorityUnavailable('SourceNote original Root never admitted its actual Life route')
    state.parent_grant=chain[0][1];state.valid_until=min(state.work.deadline_utc,node['original_deadline_utc'],*(grant.valid_until_utc for _,grant in chain))
    if state.work.now_utc>=state.valid_until:raise AuthorityUnavailable('SourceNote original Root/Window deadline expired')


def qualify_named_source_note_body_v1(state,original_evidence):
    from .named_joint_binding_body_v1 import _NamedSemanticRead,_pump,_prepare_atom
    from .named_joint_binding_source_read_v3 import _head_positive
    from ..runtime.current_joint_window_source_read_v3 import _current_window,managed_window_selector_digest_v1
    from ..runtime.d08_source_note_action_v1 import selected_source_note_binding_from_originals_v2
    from ..domains.d08.long_term_plan_v1 import JOINT_WINDOW_TYPE,long_term_value_from_wire_v1
    from ..runtime.d08_long_term_plan_v1 import _joint_current
    from ..domains.d08.execution import _decode_goal
    state.point_rows={};state.original_refs={};state.selected_history=set();state.producer_ids={state.request.command.prepared_candidates_operation_id}
    state.budget_lease_ids=set();state.quote_keys=set();state.job_ids=set();state.d12_head_values={};state.d12_compilations={};state.d12_candidate_refs=set()
    from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
    owner=owner_grant_key(*state.work.namespace.as_tuple)
    state.owner_guard=ProductionOwnerGuardV1(owner.token,state.work.heads[owner.token][0],canonical_digest(state.owner_entry.grant),state.owner_entry.head.guard.authorization_head.removeprefix('sha256:'))
    state.semantic_read=_NamedSemanticRead(state);_prepare_atom(state,owner);_parent(state)
    digest=managed_window_selector_digest_v1(state.work.namespace,'source_note',state.request.argument.typed_input_original_ref,state.request.argument.typed_input_original_digest)
    with state.work.quantum_v3():inventory=state.guard_inventory.require()
    matches=tuple(row for row in inventory.rows if row['selector_digest']==digest)
    if len(matches)!=1 or matches[0]['retired']:raise AuthorityUnavailable('SourceNote restriction has no actual nonretired immutable guard')
    row=matches[0];state.producer_ids.add(row['registration_operation_id'])
    def predicate(frame):
        selected=_current_window(state.work.db,state.semantic_read,row,preparing=True,issuer=state.service.issuer)
        window_atom,window,plan_atom,plan,node=selected
        if window_atom.revision!=state.request.argument.window_revision:raise AuthorityUnavailable('SourceNote Window changed its selected revision')
        decision=state.semantic_read.head(state.work.db,state.request.command.decision_ref,required=True)
        if canonical_digest(decision.value)!=state.request.argument.typed_input_original_digest:raise AuthorityUnavailable('SourceNote immutable Decision differs from its Window input')
        prepared,chosen,actual=selected_source_note_binding_from_originals_v2(state.work.db,namespace=state.work.namespace,request=state.request.command)
        binding,future=chosen.binding,chosen.future_identity;original=state.request.original_selector
        entity=state.semantic_read.head(state.work.db,binding.target_entity_ref,required=True)
        goal=state.semantic_read.head(state.work.db,binding.goal_ref,required=True);recipe=state.semantic_read.head(state.work.db,binding.recipe_ref,required=True)
        if((binding.goal_ref,binding.project_ref,binding.recipe_ref,recipe.revision,entity.value['entity_id'],_decode_goal(goal.value).satisfaction_predicate)!=
                (node.goal_ref,node.project_ref,node.recipe_ref,node.recipe_revision,node.target_ref,node.success_predicate)
                or binding.source_ref not in node.source_refs or(future.parent_budget_lease_ref,future.deadline_utc)!=(node.parent_grant_ref,node.original_deadline_utc)
                or future.action_operation_id!=original.operation_id):raise AuthorityUnavailable('SourceNote restriction changed its actual chosen future/target/recipe/Root terms')
        if type(original)is ForegroundActivityRequestV1 and(original.activity_id,original.parent_budget_lease_ref,original.requested_deadline_utc,original.audiences)!=(future.activity_id,future.parent_budget_lease_ref,future.deadline_utc,node.audience):
            raise AuthorityUnavailable('SourceNote restriction changed the exact original foreground future')
        _head_positive(state,decision)
        return selected,decision,prepared,chosen,actual
    selected,decision,prepared,chosen,actual=_pump(state,predicate)
    window_atom,window,plan_atom,plan,node=selected
    prior_head=prior_ref=prior_digest=prior_results=None
    if window.prior_window_ref is not None:
        prior=state.bodies[AtomKey.from_token(window.prior_window_ref)]
        _,qualification=_pump(state,lambda frame:_joint_current(state.work.db,frame,long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,prior.value),issuer=state.service.issuer,completed=True))
        prior_head=GraphVersion(prior.key,prior.revision);prior_ref=qualification.original_ref;prior_digest=qualification.digest;prior_results=qualification.result_versions_digest
    wp=_head_positive(state,window_atom);lp=_head_positive(state,plan_atom)
    closure=tuple(sorted(set(v for material in state.materials for v in material.versions),key=lambda v:v.key.token))
    versions={v.key:v.revision for v in closure};versions.update((key,atom.revision)for key,atom in state.bodies.items())
    read_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda item:item[0].token))
    groups=tuple((purpose,(audience,),roots)for purpose,audience,roots in state.groups)
    proof=canonical_digest(('d10.named-joint-source-note-proof.v1',state.work.graph_stamp[1:],groups,closure,
        tuple(sorted((ref,witness.canonical_semantic_digest)for material in state.materials for ref,witness in material.witnesses.items()))))
    refresh_named_source_note_frame_v1(state)
    return NamedJointSourceNoteCurrentV1(state.request,state.work.permit,state.current_self,state.owner_guard,
        GraphVersion(window_atom.key,window_atom.revision),canonical_digest(window_atom.value),'d08-current:'+wp['original_digest'][:48],wp['original_digest'],
        GraphVersion(plan_atom.key,plan_atom.revision),canonical_digest(plan_atom.value),'d08-current:'+lp['original_digest'][:48],lp['original_digest'],canonical_digest(node),
        GraphVersion(decision.key,decision.revision),canonical_digest(decision.value),'d08-current:'+actual['original_digest'][:48],actual['original_digest'],canonical_digest(chosen),node.audience,chosen.future_identity,
        state.parent_grant,node.original_deadline_utc,state.valid_until,read_versions,state.semantic_frame.query_coverage,closure,groups,proof,state.guard_inventory.digest,state.work.now_utc,
        prior_head,prior_ref,prior_digest,prior_results,original_evidence)



def source_note_scope_operation_id_v1(request):
    original=request.original_selector
    return foreground_fence_operation_id_v1(original)if type(original)is ForegroundActivityRequestV1 else owner_task_fence_operation_id_v1(original)


def install_named_source_note_original_services_v1(service,foreground,owner_task):
    from .current_named_joint_binding_v1 import InstalledCurrentNamedJointBindingV1
    from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
    from .current_owner_source_note_task_v1 import InstalledCurrentOwnerSourceNoteTaskV1
    if type(service)is not InstalledCurrentNamedJointBindingV1 or service.source_note_original_services!=(None,None):raise AuthorityUnavailable('Named SourceNote original services install exactly once on the actual paired installation')
    for value,kind in((foreground,InstalledCurrentForegroundActivityV1),(owner_task,InstalledCurrentOwnerSourceNoteTaskV1)):
        if value is not None and(type(value)is not kind or value.self_identity is not service.self_identity or value.issuer is not service.issuer):raise AuthorityUnavailable('Named SourceNote cannot borrow another original issuer/installation')
    service.source_note_original_services=(foreground,owner_task)


def observe_named_source_note_current_v1(service,*,credential,subject,permit,request):
    if(type(request)is not NamedJointSourceNoteSelectorV1 or type(permit)is not FencePermitV2 or permit.operation not in {'read','write'}
            or request.namespace!=service.self_identity._namespace_id or request.installation_id!=service.self_identity._installation_id
            or subject!=service.self_identity._read_subject or permit.operation=='write'and permit.operation_id!=source_note_scope_operation_id_v1(request)):
        raise AuthorityUnavailable('Named SourceNote current changed its actual installed selector/Scope')
    original_service=service.source_note_original_services[0 if type(request.original_selector)is ForegroundActivityRequestV1 else 1]
    if original_service is None:raise AuthorityUnavailable('The actual original SourceNote issuer is not installed for this Root')
    original_evidence=None
    if permit.operation=='write':
        original_evidence,observed=original_service.current(credential=credential,subject=subject,permit=permit,request=request.original_selector)
        if observed!=permit:raise AuthorityUnavailable('Named SourceNote original issuer changed its exact WRITE permit')
    state=_prepare_named_source_note_inputs_v1(service,credential=credential,subject=subject,permit=permit,request=request,original_evidence=original_evidence)
    try:return state.current(),permit
    finally:state.release_v3()


def _prepare_named_source_note_inputs_v1(service,*,credential,subject,permit,request,original_evidence):
    from .current_authority_graph_read_v3 import(begin_authority_graph_read_work_v3,_AuthorityNamespaceReadV3,
        AuthorityGraphProjectionV3,_AuthoritySourceMaterialReadV3,_ISSUER)
    from .named_joint_binding_source_read_v3 import(NamedJointAuthorityInputsV3,_current_self,_NamedSelectionV3,_KEY)
    reading=service.clock();now=reading.utc_seconds+reading.utc_error_seconds
    deadline=service.installed_bundle.installation_policy.root_grant.valid_until_utc
    work=begin_authority_graph_read_work_v3(service,credential=credential,subject=subject,permit=permit,
        namespace=request.namespace,request=request,parent_original_id=request.command.decision_ref,now_utc=now,deadline_utc=deadline)
    state=NamedJointAuthorityInputsV3(_KEY,work,service)
    try:
        while not work.catalogue_reader.complete:
            with work.quantum_v3()as meter:work.catalogue_reader.advance_v3(meter)
        work.namespace_reader=_AuthorityNamespaceReadV3(work,catalogue=work.catalogue_reader.rows,catalogue_hash=work.catalogue_reader.catalogue_hash)
        while not work.namespace_reader.graph_eof:
            with work.quantum_v3()as meter:work.namespace_reader.advance_v3(meter)
        work.projection=AuthorityGraphProjectionV3(_ISSUER,work)
        from ..runtime.current_joint_window_source_read_v3 import create_joint_guard_inventory_for_work_v3
        state.guard_inventory=create_joint_guard_inventory_for_work_v3(work,service.issuer)
        while not state.guard_inventory.complete:
            with work.quantum_v3()as meter:state.guard_inventory.advance(meter)
        state.groups=note_metadata_groups_v1(state);_current_self(state)
        from .owner_location_read_v3 import prepare_owner_location_for_named_joint_graph_work_v3
        state.owner_entry=prepare_owner_location_for_named_joint_graph_work_v3(work)
        grant=state.owner_entry.grant
        if 'workbench.create'not in grant['capabilities']or any(purpose not in grant['purposes']or audience not in grant['audiences']for purpose,audience,_ in state.groups):raise AuthorityUnavailable('Named SourceNote exceeds actual completed Owner17')
        state.roots=tuple(sorted({ref for _,_,roots in state.groups for ref in roots}))
        for purpose,audience,roots in state.groups:
            material=_AuthoritySourceMaterialReadV3(work,_NamedSelectionV3(state,roots,purpose,audience));state.materials.append(material)
            while material.phase=='rights':
                with work.quantum_v3()as meter:material.advance_v3(meter)
        if any(material.phase!='cell'or material.pending for material in state.materials):raise AuthorityUnavailable('Named SourceNote requires actual Source ALL before protected input bodies')
        state.closure_refs=tuple(sorted({ref for material in state.materials for ref in material.witnesses}));state.metadata_only=False
        state.observed=qualify_named_source_note_body_v1(state,original_evidence);state.complete=True
        return state
    except BaseException:state.release_v3();raise
