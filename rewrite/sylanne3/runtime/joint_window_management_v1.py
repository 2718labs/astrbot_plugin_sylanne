"""Additional Joint window restrictions over the original independently issued executors."""
from dataclasses import dataclass,fields,replace
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.long_term_plan_v1 import LONG_PLAN_TYPE,JOINT_WINDOW_TYPE,long_term_value_from_wire_v1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1

MANAGED_EXECUTORS=frozenset(('source_note','draft_file','contact'))

@dataclass(frozen=True,slots=True)
class ManagedWindowArgumentV1:
    window_ref:str
    window_revision:int
    node_id:str
    executor_kind:str
    typed_input_original_ref:str
    typed_input_original_digest:str
    typed_request_digest:str
    schema:str='d08.managed-window-argument.v1'
    def __post_init__(self):
        if self.schema!='d08.managed-window-argument.v1'or AtomKey.from_token(self.window_ref).type_name!=JOINT_WINDOW_TYPE or type(self.window_revision)is not int or self.window_revision<1 or not self.node_id or self.executor_kind not in MANAGED_EXECUTORS or not self.typed_input_original_ref:raise ValueError('managed window argument names its actual typed input and exact current slot')
        for value in(self.typed_input_original_digest,self.typed_request_digest):
            if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):raise ValueError('managed input/request commitment differs')

def managed_window_argument_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(ManagedWindowArgumentV1)}:raise ValueError('closed managed window argument fields differ')
    return ManagedWindowArgumentV1(**raw)

@dataclass(frozen=True,slots=True)
class JointWindowClassificationV1:
    namespace:NamespaceId
    selector_kind:str
    selector_digest:str
    state:str
    argument:ManagedWindowArgumentV1|None
    plan_ref:str|None
    plan_revision:int|None
    plan_state:str|None
    current_window_ref:str|None
    window_state:str|None
    metadata_epoch:int
    complete:bool
    ordinary_original_ref:str|None=None
    ordinary_original_digest:str|None=None
    schema:str='d08.joint-window-classification.v1'
    def __post_init__(self):
        if self.schema!='d08.joint-window-classification.v1'or type(self.namespace)is not NamespaceId or self.state not in {'ordinary','managed','retired','unknown'}or type(self.complete)is not bool or type(self.metadata_epoch)is not int or self.metadata_epoch<0:raise ValueError('Joint classification is an actual complete metadata observation')
        if self.state=='managed'and(type(self.argument)is not ManagedWindowArgumentV1 or not self.plan_ref or self.plan_revision is None or self.plan_state is None or self.window_state is None):raise ValueError('managed classification needs actual current plan/window metadata')
        if self.state=='ordinary'and(not self.complete or not self.ordinary_original_ref or not self.ordinary_original_digest):raise ValueError('ordinary requires actual original recipe plus complete never-managed classification')


def managed_window_selector_digest_v1(namespace,executor_kind,input_ref,input_digest):
    return canonical_digest((namespace,executor_kind,input_ref,input_digest))

def _require_classification(value,*,namespace,execution):
    if type(value)is not JointWindowClassificationV1 or value.namespace!=namespace or not value.complete or value.state in {'retired','unknown'}:raise MissingProductionOriginalV1('complete_actual_joint_window_classification_or_retired_deny')
    if value.state=='ordinary':return None
    if execution and(value.window_state!='ready'or value.current_window_ref!=value.argument.window_ref or value.plan_state in {'paused','stopped','closed'}):raise MissingProductionOriginalV1('managed_joint_window_ready_and_actual_long_plan_current_pointer')
    return value.argument

def require_managed_joint_preparation_v1(db,*,frame,operation_kind,request):
    from .current_habit_source_read_v3 import require_current_joint_window_management_v3
    classification,argument=require_current_joint_window_management_v3(db,frame=frame,operation_kind=operation_kind,request=request)
    selected=_require_classification(classification,namespace=frame.envelope.authority.namespace,execution=False)
    if selected is None:
        if argument is not None:raise ValueError('ordinary original cannot borrow a managed argument')
        return None
    if type(argument)is not ManagedWindowArgumentV1 or argument!=selected:raise MissingProductionOriginalV1('actual_named_managed_preparation_entry')
    read=CurrentDomainReadV1(frame);atom=read.head(db,argument.window_ref,required=True)
    window=long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,atom.value)
    plan_atom=read.head(db,window.long_term_plan_ref,required=True);plan=long_term_value_from_wire_v1(LONG_PLAN_TYPE,plan_atom.value)
    if atom.revision!=argument.window_revision or window.state!='preparing'or plan.state in {'paused','stopped','closed'}or frame.now_utc>=window.original_deadline_utc:raise MissingProductionOriginalV1('actual_current_owner_preparing_window_without_execution_permission')
    node=next((n for n in window.node_drafts if n.node_id==argument.node_id),None)
    if node is None or(node.executor_kind,node.typed_request_ref,node.typed_input_original_digest,node.typed_request_digest)!=(argument.executor_kind,argument.typed_input_original_ref,argument.typed_input_original_digest,argument.typed_request_digest)or canonical_digest(plain_v1(request))!=argument.typed_request_digest:raise ValueError('managed preparation changed its exact adopted input/request commitment')
    if frame.envelope.parent_budget_lease_ref!=node.parent_grant_ref or frame.envelope.deadline_utc>node.original_deadline_utc:raise ValueError('managed preparation cannot expand original Root or absolute TTL')
    if argument.executor_kind=='source_note':
        from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1
        if operation_kind!='prepare_selected_source_note_action_v2'or type(request)is not ConsumePersonalDecisionRequestV1 or request.decision_ref!=node.typed_request_ref:raise ValueError('managed SourceNote preserves its original selected Decision producer')
        decision=read.head(db,request.decision_ref,required=True)
        if canonical_digest(decision.value)!=node.typed_input_original_digest:raise ValueError('managed SourceNote input original changed')
    else:
        from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1,JointContactProspectiveBindingV1
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
        if operation_kind!='input:register_joint_node_execution_binding_v1'or type(request)is not RegisterJointNodeExecutionBindingRequestV1:raise ValueError('managed prospective executor preserves its actual original binding registration')
        binding=request.binding
        if argument.executor_kind=='draft_file':
            if type(binding)is not JointArtifactProspectiveBindingV1 or(binding.task_scope_ref,binding.task_scope_digest)!=(node.typed_request_ref,node.typed_input_original_digest):raise ValueError('Artifact preparation requires its actual prospective scope before C4 Action')
        elif type(binding)is not JointContactProspectiveBindingV1 or(binding.prospective_original_ref,binding.prospective_original_digest)!=(node.typed_request_ref,node.typed_input_original_digest):raise ValueError('Contact preparation requires its actual prospective birth')
    return argument

def attach_managed_joint_preparation_v1(stage,argument):
    if argument is None:return stage
    # Known legacy wrappers retain their exact validators and after-CAS readers.
    from .d08_source_note_action_v1 import SourceNoteActionStageV1
    from .domain_production_inputs_v1 import StagedDomainInputV1
    if type(stage)not in {SourceNoteActionStageV1,StagedDomainInputV1}:raise TypeError('managed preparation cannot unwrap another executor stage')
    base=stage.stage;raw=json.loads(base.original_payload_json)
    raw['provenance']['managed_window_argument']=plain_v1(argument)
    digest=canonical_digest(raw)
    from .domain_production_contracts_v1 import ProductionOriginalRefV1,ProductionOutboxStageV1
    original=ProductionOriginalRefV1(base.domain+'.current-'+base.operation_kind,base.domain+'-current:'+digest[:48],digest,base.read_versions)
    outbox=tuple(ProductionOutboxStageV1(i.namespace,i.causal_operation_id,i.receiver_domain,i.event_kind,original)for i in base.outbox)
    return replace(stage,stage=replace(base,original_payload_json=canonical_serialize(raw),original_digest=digest,outbox=outbox))

def require_managed_joint_execution_v1(db,*,namespace,issuer,action_ref=None,binding=None,frame=None):
    from .current_habit_source_read_v3 import read_current_joint_window_execution_classification_v3
    classification=read_current_joint_window_execution_classification_v3(db,namespace=namespace,action_ref=action_ref,binding=binding,issuer=issuer,frame=frame)
    if frame is None:
        from .current_joint_window_source_read_v3 import is_joint_window_restriction_checked_v3
        if not is_joint_window_restriction_checked_v3(classification,namespace):raise ValueError('actual metadata-only Joint restriction observation required')
        return None
    return _require_classification(classification,namespace=namespace,execution=True)

def prepare_current_joint_window_node_v1(graph,context,argument,request):
    from .current_habit_source_read_v3 import prepare_current_managed_joint_node_source_work_v3
    if type(argument)is not ManagedWindowArgumentV1:raise TypeError('named Joint preparation requires its exact adopted managed argument')
    return prepare_current_managed_joint_node_source_work_v3(graph,context,argument,request)


GUARD_TABLE='graph_joint_window_managed_guards_v1'
GUARD_SIGN_KIND='d11.joint-window-managed-guard.v1'
GUARD_COLUMNS=('selector_digest','executor_kind','input_ref','input_digest','request_digest','window_ref','window_birth_revision','window_birth_digest','node_id','plan_ref','registration_operation_id','registration_receipt_digest','action_ref','binding_ref','birth_operation_id','birth_receipt_digest','retired','signature')

def install_joint_window_management_schema_v1(db):
    if db.in_transaction:raise ValueError('install managed metadata before runtime transactions')
    from .b3_managed_metadata_v1 import install_managed_metadata_table_v1
    install_managed_metadata_table_v1(db,GUARD_TABLE)

def _signed_guard(issuer,namespace,values):
    return (*values,issuer._signer.sign(GUARD_SIGN_KIND,canonical_serialize((namespace,values))))

def record_joint_window_management_after_cas_v1(db,*,witness,primary,receipt,issuer):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE,_members
    window_writes=tuple(w for p in primary.proposals for w in p.typed_writes if w.key.type_name==JOINT_WINDOW_TYPE)
    payload=json.loads(primary.original_payload_json);raw_argument=payload['provenance'].get('managed_window_argument')
    if not window_writes and raw_argument is None:return ()
    if type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness or _members(witness.stage)[0]is not primary or witness.frame.envelope.identity.operation_id!=receipt.operation_id or receipt.status!='committed'or not db.in_transaction or db is not witness.graph._GraphCoordinator__store._db:raise ValueError('managed locator signing requires its actual successful same-W01 private witness')
    ns=primary.namespace;versions={v.key:v.revision for v in receipt.write_versions};written=[]
    for write in window_writes:
        window=long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,write.value)
        if primary.operation_kind!='prepare_joint_window_v1':continue
        for node in window.node_drafts:
            if node.executor_kind not in MANAGED_EXECUTORS:continue
            selector=managed_window_selector_digest_v1(ns,node.executor_kind,node.typed_request_ref,node.typed_input_original_digest)
            values=(selector,node.executor_kind,node.typed_request_ref,node.typed_input_original_digest,node.typed_request_digest,write.key.token,versions[write.key],canonical_digest(write.value),node.node_id,window.long_term_plan_ref,receipt.operation_id,canonical_digest(receipt),None,None,None,None,0)
            expected=_signed_guard(issuer,ns,values)
            prior=db.execute('SELECT '+','.join(GUARD_COLUMNS)+' FROM '+GUARD_TABLE+' WHERE bot=? AND persona=? AND selector_digest=?',(*ns.as_tuple,selector)).fetchone()
            if prior is None:db.execute('INSERT INTO '+GUARD_TABLE+' VALUES('+','.join('?'for _ in range(20))+')',(*ns.as_tuple,*expected))
            elif tuple(prior)!=expected:raise ValueError('managed original input cannot move to another window or clear retirement')
            written.append(selector)
    if raw_argument is not None:
        argument=managed_window_argument_from_wire_v1(raw_argument)
        selector=managed_window_selector_digest_v1(ns,argument.executor_kind,argument.typed_input_original_ref,argument.typed_input_original_digest)
        row=db.execute('SELECT '+','.join(GUARD_COLUMNS)+' FROM '+GUARD_TABLE+' WHERE bot=? AND persona=? AND selector_digest=?',(*ns.as_tuple,selector)).fetchone()
        if row is None or row[16]!=0:raise MissingProductionOriginalV1('actual_durable_managed_preparation_guard')
        issuer._signer.verify(GUARD_SIGN_KIND,canonical_serialize((ns,tuple(row[:-1]))),row[-1])
        if(row[4],row[5],row[8])!=(argument.typed_request_digest,argument.window_ref,argument.node_id):raise ValueError('managed birth changed actual pending selector commitment')
        action_refs=tuple(w.key.token for p in primary.proposals for w in p.typed_writes if w.key.type_name=='d08.action_intent.v1')
        if argument.executor_kind=='source_note':
            if len(action_refs)!=1:raise ValueError('managed SourceNote birth needs its actual single Action registration')
            action_ref,binding_ref=action_refs[0],None
        else:
            from .joint_node_execution_v1 import decode_joint_binding_v1
            binding=decode_joint_binding_v1(payload['request']['binding']);action_ref,binding_ref=binding.action_ref,binding.original_ref
        if row[14]is not None and(row[12],row[13],row[14],row[15])!=(action_ref,binding_ref,receipt.operation_id,canonical_digest(receipt)):raise ValueError('managed birth replay changes actual executor identity')
        values=(*row[:12],action_ref,binding_ref,receipt.operation_id,canonical_digest(receipt),0)
        signature=_signed_guard(issuer,ns,values)[-1]
        db.execute('UPDATE '+GUARD_TABLE+' SET action_ref=?,binding_ref=?,birth_operation_id=?,birth_receipt_digest=?,signature=? WHERE bot=? AND persona=? AND selector_digest=?',(action_ref,binding_ref,receipt.operation_id,canonical_digest(receipt),signature,*ns.as_tuple,selector));written.append(selector)
    return tuple(written)

def retire_joint_window_managed_guards_v1(db,*,namespace,selector_digests,issuer):
    """Use the same authenticated opaque-row transformation as the real C09 writer."""
    if not db.in_transaction:raise ValueError('managed retirement belongs to the actual C09 transaction')
    from .b3_managed_metadata_v1 import metadata_columns_v1,retired_managed_metadata_row_v1
    columns=metadata_columns_v1(GUARD_TABLE)
    if columns!=('bot','persona',*GUARD_COLUMNS):raise ValueError('managed metadata exact installed columns differ')
    for selector in selector_digests:
        row=db.execute('SELECT '+','.join(columns)+' FROM '+GUARD_TABLE+
            ' WHERE bot=? AND persona=? AND selector_digest=?',(*namespace.as_tuple,selector)).fetchone()
        if row is None:raise ValueError('C09 cannot retire an unobserved managed classification')
        updated=retired_managed_metadata_row_v1(GUARD_TABLE,columns,tuple(row),issuer=issuer)
        assignments=','.join(name+'=?'for name in GUARD_COLUMNS[1:])
        db.execute('UPDATE '+GUARD_TABLE+' SET '+assignments+
            ' WHERE bot=? AND persona=? AND selector_digest=?',(*updated[3:],*namespace.as_tuple,selector))

JOINT_WINDOW_MANAGEMENT_STORAGE_V1={GUARD_TABLE:{'namespace_columns':('bot','persona'),'content_columns':(),'metadata_columns':GUARD_COLUMNS,'source_closure':'actual_typed_WindowDraft_dependencies','retirement':'retain_only_selector_digest_namespace_retired_signature','cold':'complete_actual_WindowDraft_classification_and_receipt_join_before_ordinary'}}
