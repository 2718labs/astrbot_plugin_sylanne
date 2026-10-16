"""Descriptive long plans and exact current Joint windows; no execution grant."""
from dataclasses import asdict,dataclass,fields
from ...graph_types import AtomKey,Owner,TypeSpec
from ...runtime_contracts import NamespaceId,canonical_digest,schema_hash
from .execution import GoalPredicate

LONG_PLAN_TYPE='d08.long_term_plan.v1'
JOINT_WINDOW_TYPE='d08.joint_window.v1'
WINDOW_ADVANCE_TYPE='d08.long_term_window_advance.v1'
WINDOW_STATES=frozenset(('described','preparing','ready','waiting','paused','stopped','closed'))

def _ref(ns,ref,kind):
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=ns or key.type_name!=kind:raise ValueError('long plan reference namespace/type differs')
    return key

def _digest(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):raise ValueError('exact SHA256 commitment required')

def _roots(ns,refs):
    if type(refs)is not tuple or not 1<=len(refs)<=32 or len(set(refs))!=len(refs):raise ValueError('long plan needs its bounded unique Source roots')
    for ref in refs:_ref(ns,ref,'memory.source')

def _predicate(raw):
    if type(raw)is not dict or set(raw)!=set(GoalPredicate.__dataclass_fields__):raise ValueError('exact GoalPredicate fields required')
    return GoalPredicate(**{**raw,'parameters':tuple(tuple(x)for x in raw['parameters'])})

@dataclass(frozen=True,slots=True)
class LongTermMilestoneV1:
    milestone_id:str
    goal_ref:str
    project_ref:str
    depends_on:tuple[str,...]
    success_predicate:GoalPredicate
    source_refs:tuple[str,...]
    def __post_init__(self):
        if not self.milestone_id or type(self.depends_on)is not tuple or len(set(self.depends_on))!=len(self.depends_on) or self.milestone_id in self.depends_on or type(self.success_predicate)is not GoalPredicate:raise ValueError('milestone requires its nonexecutive predicate and dependency identities')

@dataclass(frozen=True,slots=True)
class LongTermPlanV1:
    namespace:NamespaceId
    plan_id:str
    revision:int
    goal_ref:str
    project_ref:str
    milestones:tuple[LongTermMilestoneV1,...]
    current_window_ref:str|None
    state:str
    owner_authorization_original_ref:str
    owner_authorization_original_digest:str
    source_refs:tuple[str,...]
    purpose:str
    audience:tuple[str,...]
    schema:str='d08.long-term-plan.v1'
    def __post_init__(self):
        if self.schema!='d08.long-term-plan.v1'or type(self.namespace)is not NamespaceId or not self.plan_id.startswith('long-plan:')or type(self.revision)is not int or self.revision<1 or self.state not in {'described','preparing','ready','waiting','paused','stopped','closed'}:raise ValueError('long plan requires its exact revision and descriptive/current state')
        _ref(self.namespace,self.goal_ref,'d08.goal.v1');_ref(self.namespace,self.project_ref,'d10.life_project.v1');_roots(self.namespace,self.source_refs);_digest(self.owner_authorization_original_digest)
        if not self.owner_authorization_original_ref or not self.purpose or type(self.audience)is not tuple or not self.audience or len(set(self.audience))!=len(self.audience):raise ValueError('long plan retains actual Owner authorization and signed audience')
        if self.current_window_ref is not None:_ref(self.namespace,self.current_window_ref,JOINT_WINDOW_TYPE)
        if type(self.milestones)is not tuple or not self.milestones or any(type(x)is not LongTermMilestoneV1 for x in self.milestones):raise ValueError('long plan needs typed descriptive milestones')
        ids=tuple(x.milestone_id for x in self.milestones)
        if len(set(ids))!=len(ids):raise ValueError('milestone identities must be unique')
        done=set()
        while len(done)<len(ids):
            available={m.milestone_id for m in self.milestones if set(m.depends_on)<=done}
            if not available-done:raise ValueError('milestone dependency graph is cyclic or incomplete')
            done.update(available)
        for m in self.milestones:
            _ref(self.namespace,m.goal_ref,'d08.goal.v1');_ref(self.namespace,m.project_ref,'d10.life_project.v1');_roots(self.namespace,m.source_refs)

@dataclass(frozen=True,slots=True)
class JointWindowNodeDraftV1:
    node_id:str
    party_scope:str
    executor_kind:str
    typed_request_ref:str
    typed_request_digest:str
    typed_input_original_digest:str
    goal_ref:str
    project_ref:str
    recipe_ref:str
    recipe_revision:int
    target_ref:str
    source_refs:tuple[str,...]
    success_predicate:GoalPredicate
    parent_grant_ref:str
    parent_grant_digest:str
    original_deadline_utc:float
    cancellation_point:bool
    cancellation_ref:str
    compensation_ref:str|None
    resource_commitment:str
    purpose:str
    audience:tuple[str,...]
    def __post_init__(self):
        if not self.node_id or not self.party_scope or self.executor_kind not in {'source_note','draft_file','contact','external'}or type(self.recipe_revision)is not int or self.recipe_revision<1 or type(self.success_predicate)is not GoalPredicate or self.success_predicate.valid_until!=self.original_deadline_utc or self.purpose not in {'context','expression','consolidation'}or type(self.audience)is not tuple or not self.audience or len(set(self.audience))!=len(self.audience)or type(self.cancellation_point)is not bool or not all((self.typed_request_ref,self.target_ref,self.parent_grant_ref,self.cancellation_ref,self.resource_commitment)):raise ValueError('window draft fixes request/party/recipe/predicate/Root/deadline/cancellation before current preparation')
        _digest(self.typed_request_digest);_digest(self.typed_input_original_digest);_digest(self.parent_grant_digest)

@dataclass(frozen=True,slots=True)
class JointWindowV1:
    namespace:NamespaceId
    window_id:str
    long_term_plan_ref:str
    long_term_plan_revision:int
    window_index:int
    prior_window_ref:str|None
    node_drafts:tuple[JointWindowNodeDraftV1,...]
    candidate_refs:tuple[str,...]
    draft_terms_original_ref:str
    draft_terms_original_digest:str
    final_joint_plan_ref:str|None
    final_joint_plan_revision:int|None
    final_binding_refs:tuple[str,...]
    final_terms_original_ref:str|None
    final_terms_original_digest:str|None
    party_acceptance_original_refs:tuple[str,...]
    state:str
    original_deadline_utc:float
    source_refs:tuple[str,...]
    schema:str='d08.joint-window.v1'
    def __post_init__(self):
        if self.schema!='d08.joint-window.v1'or type(self.namespace)is not NamespaceId or not self.window_id.startswith('joint-window:')or type(self.window_index)is not int or self.window_index<0 or type(self.long_term_plan_revision)is not int or self.long_term_plan_revision<1 or self.state not in WINDOW_STATES:raise ValueError('window requires exact descriptive/current identity')
        _ref(self.namespace,self.long_term_plan_ref,LONG_PLAN_TYPE);_roots(self.namespace,self.source_refs);_digest(self.draft_terms_original_digest)
        if self.prior_window_ref is not None:_ref(self.namespace,self.prior_window_ref,JOINT_WINDOW_TYPE)
        if type(self.node_drafts)is not tuple or not 1<=len(self.node_drafts)<=8 or any(type(x)is not JointWindowNodeDraftV1 for x in self.node_drafts)or len({x.node_id for x in self.node_drafts})!=len(self.node_drafts):raise ValueError('current Joint window permits one to eight exact node drafts')
        if type(self.candidate_refs)is not tuple or len(self.candidate_refs)>6 or len(set(self.candidate_refs))!=len(self.candidate_refs):raise ValueError('window permits at most six exact candidate alternatives')
        for node in self.node_drafts:
            _ref(self.namespace,node.goal_ref,'d08.goal.v1');_ref(self.namespace,node.project_ref,'d10.life_project.v1');_ref(self.namespace,node.recipe_ref,'d10.activity_recipe.v1');_roots(self.namespace,node.source_refs)
            if node.original_deadline_utc>self.original_deadline_utc:raise ValueError('window node extends its original deadline')
        if self.final_joint_plan_ref is None:
            if self.final_joint_plan_revision is not None or self.final_binding_refs or self.final_terms_original_ref is not None or self.final_terms_original_digest is not None or self.state in {'ready','closed'}:raise ValueError('descriptive window cannot carry fictional final bindings')
        else:
            _ref(self.namespace,self.final_joint_plan_ref,'d08.joint_plan.v1');_digest(self.final_terms_original_digest)
            if type(self.final_joint_plan_revision)is not int or self.final_joint_plan_revision<1 or len(self.final_binding_refs)!=len(self.node_drafts)or not self.final_terms_original_ref or not self.party_acceptance_original_refs:raise ValueError('final window needs exact actual bindings, terms and real acceptance')
    @property
    def draft_digest(self):return canonical_digest({'nodes':self.node_drafts,'deadline':self.original_deadline_utc,'window':self.window_id})

@dataclass(frozen=True,slots=True)
class LongTermWindowAdvanceV1:
    namespace:NamespaceId
    advance_id:str
    plan_ref:str
    plan_revision:int
    previous_window_ref:str
    previous_window_revision:int
    joint_qualification_original_ref:str
    joint_qualification_original_digest:str
    result_versions_digest:str
    milestone_evidence_original_refs:tuple[str,...]
    next_window_ref:str
    next_window_revision:int
    next_final_terms_original_ref:str
    next_acceptance_original_refs:tuple[str,...]
    source_refs:tuple[str,...]
    schema:str='d08.long-term-window-advance.v1'
    def __post_init__(self):
        if self.schema!='d08.long-term-window-advance.v1'or not self.advance_id or any(type(x)is not int or x<1 for x in(self.plan_revision,self.previous_window_revision,self.next_window_revision))or not self.milestone_evidence_original_refs or not self.next_acceptance_original_refs:raise ValueError('window advance needs actual prior predicates and next exact acceptance')
        _ref(self.namespace,self.plan_ref,LONG_PLAN_TYPE);_ref(self.namespace,self.previous_window_ref,JOINT_WINDOW_TYPE);_ref(self.namespace,self.next_window_ref,JOINT_WINDOW_TYPE);_roots(self.namespace,self.source_refs)
        _digest(self.joint_qualification_original_digest);_digest(self.result_versions_digest)

_TYPES={LONG_PLAN_TYPE:LongTermPlanV1,JOINT_WINDOW_TYPE:JointWindowV1,WINDOW_ADVANCE_TYPE:LongTermWindowAdvanceV1}
def long_term_value_to_wire_v1(value):
    if type(value)not in _TYPES.values():raise TypeError('registered long plan value required')
    return asdict(value)
def long_term_value_from_wire_v1(kind,raw):
    cls=_TYPES[kind]
    if type(raw)is not dict or set(raw)!={f.name for f in fields(cls)}:raise ValueError('closed long plan wire fields differ')
    v={**raw,'namespace':NamespaceId(**raw['namespace']),'source_refs':tuple(raw['source_refs'])}
    if cls is LongTermPlanV1:
        v['audience']=tuple(raw['audience']);v['milestones']=tuple(LongTermMilestoneV1(**{**m,'depends_on':tuple(m['depends_on']),'source_refs':tuple(m['source_refs']),'success_predicate':_predicate(m['success_predicate'])})for m in raw['milestones'])
    elif cls is JointWindowV1:
        v['node_drafts']=tuple(JointWindowNodeDraftV1(**{**n,'source_refs':tuple(n['source_refs']),'audience':tuple(n['audience']),'success_predicate':_predicate(n['success_predicate'])})for n in raw['node_drafts'])
        for k in('candidate_refs','final_binding_refs','party_acceptance_original_refs'):v[k]=tuple(raw[k])
    else:
        for k in('milestone_evidence_original_refs','next_acceptance_original_refs'):v[k]=tuple(raw[k])
    return cls(**v)
def long_term_key_v1(ns,kind,identity):return AtomKey(Owner('persona',*ns.as_tuple,ns.persona_id),kind,identity)
def long_term_type_specs_v1():
    return tuple(TypeSpec(kind,('persona',),'state',lambda raw,k=kind:long_term_value_from_wire_v1(k,raw),immutable=kind==WINDOW_ADVANCE_TYPE,writer_domain='d08',schema_hash=schema_hash(kind))for kind in _TYPES)
