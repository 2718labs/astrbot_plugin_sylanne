"""Signed, two-child Values preparation for one real Owner SourceNote task."""
from dataclasses import dataclass
import json

from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1, EvaluateCurrentValuesRequestV1
from ..domains.d08.execution import GoalExecutionProvider
from ..domains.d08.personal_plan_v1 import PersonalPlanV1
from .domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionQueryCoverageV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d01_production_operations_v1 import (CurrentDomainReadV1, MissingProductionOriginalV1,
    InstalledD01ProductionReadersV1, FrozenValuesCandidateSetV1, FrozenValuesContextV1, production_read_plan_v1)
from .domain_production_inputs_v1 import FreezeCurrentValuesInputRequestV1
from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1, OwnerSourceNoteTaskContinuationV2
from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2, require_current_owner_source_note_task_authorization_v2
from .owner_source_note_task_execution_v1 import read_owner_source_note_task_responsibility_v2
from .owner_source_note_need_v1 import (read_owner_source_note_need_original_v2,
    require_current_owner_source_note_need_v1, install_owner_source_note_need_readers_v1,
    read_plan_owner_source_note_need_v1, PrepareOwnerSourceNoteNeedRequestV1)
from .d11_life_preparation_v1 import _read, _record
from .jobs import get_job
from .d11_types import job_graph_write

OPERATION = 'input:freeze_owner_source_note_values_parent_v1'
KIND = 'owner_source_note_values_parent_v1'
_CHILDREN = {'freeze':'input:freeze_values','evaluate':'evaluate_values'}
_READERS_KEY = object()


@dataclass(frozen=True, slots=True)
class FreezeOwnerSourceNoteValuesParentRequestV1:
    authorization_original_ref: str
    task_job_ref: str
    need_original_ref: str

    def __post_init__(self):
        if (not self.authorization_original_ref.startswith('owner-source-note-authorization:')
                or AtomKey.from_token(self.task_job_ref).type_name != 'runtime.job'
                or not self.need_original_ref.startswith('d07-current:')):
            raise ValueError('Owner Values parent selects its actual authorization, task and Need')


def owner_source_note_values_ids_v1(namespace, request):
    if type(namespace) is not NamespaceId or type(request) is not FreezeOwnerSourceNoteValuesParentRequestV1:
        raise TypeError('Owner Values IDs require their exact task selectors')
    marker = canonical_digest(('d08.owner-source-note-values.v1',namespace,request))[:40]
    return {'parent_ref':'owner-note-values-parent:'+marker,'parent_operation_id':'owner-note-values-parent:'+marker+':freeze',
        'candidate_set_ref':'owner-note-values-candidates:'+marker,'context_ref':'owner-note-values-context:'+marker,
        'freeze_operation_id':'owner-note-values-freeze:'+marker,'evaluate_operation_id':'owner-note-values-evaluate:'+marker}


def _child_requests(ids):
    return {'freeze':FreezeCurrentValuesInputRequestV1(ids['candidate_set_ref'],ids['context_ref']),
        'evaluate':EvaluateCurrentValuesRequestV1(ids['candidate_set_ref'],ids['context_ref'])}


@dataclass(frozen=True, slots=True)
class OwnerTaskValuesParentV1:
    request: FreezeOwnerSourceNoteValuesParentRequestV1
    namespace: NamespaceId
    authorization_digest: str
    responsibility_ref: str
    responsibility_digest: str
    need_original_digest: str
    owner_guard: ProductionOwnerGuardV1
    self_actor_ref: str
    task_job_head: GraphVersion
    task_job_digest: str
    goal_head: GraphVersion
    plan_head: GraphVersion
    source_refs: tuple[str, ...]
    candidates: FrozenValuesCandidateSetV1
    context: FrozenValuesContextV1
    hard_heads: tuple[tuple[GraphVersion, str, bool], ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    child_operations: tuple[tuple[str, str, str, str], ...]
    parent_budget_lease_ref: str
    budget_grant_digest: str
    original_deadline_utc: float
    frozen_at_utc: float
    registration_operation_id: str
    schema: str = 'd08.owner-task-values-parent.v1'

    def __post_init__(self):
        if (self.schema != 'd08.owner-task-values-parent.v1' or type(self.request) is not FreezeOwnerSourceNoteValuesParentRequestV1
                or type(self.namespace) is not NamespaceId or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.candidates) is not FrozenValuesCandidateSetV1 or type(self.context) is not FrozenValuesContextV1
                or self.candidates.plan_head is not None or self.context.role_binding_complete
                or {row[0] for row in self.child_operations} != set(_CHILDREN)
                or len(self.child_operations) != 2 or len(self.hard_heads)>128
                or not self.frozen_at_utc < self.original_deadline_utc
                or self.registration_operation_id != owner_source_note_values_ids_v1(self.namespace,self.request)['parent_operation_id']):
            raise ValueError('Owner Values parent is one exact bounded SourceNote preparation')
        for head,digest,valid in self.hard_heads:
            if type(head) is not GraphVersion or NamespaceId.from_key(head.key) != self.namespace or type(valid) is not bool:
                raise ValueError('Owner Values hard facts crossed their actual namespace')
            if type(digest) is not str or len(digest)!=64:
                raise ValueError('Owner Values hard fact commitment differs')

    @property
    def original_ref(self):
        return owner_source_note_values_ids_v1(self.namespace,self.request)['parent_ref']

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


class InstalledOwnerTaskValuesReadersV1:
    def __init__(self,key,*,graph,scope,issued):
        if key is not _READERS_KEY:
            raise TypeError('Owner Values uses its actual private task factory')
        self.graph,self.scope,self.issued=graph,scope,issued
        self.issuer=graph._GraphCoordinator__d11_issuer
        self.bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        self.body_quote_authority=graph._GraphCoordinator__body_quote_authority
        self.need_readers=install_owner_source_note_need_readers_v1(graph)

    def current(self):
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        return require_owner_source_note_task_issuance_v1(self.issued,self.graph,self.scope)

    def require_child(self,db,*,frame,command,slot):
        from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskActivityValuesChildRequestV1,owner_task_typed_command_digest_v1
        from .domain_production_registry_v1 import installed_operation_v1
        evidence=self.current();selector=evidence.request
        if (type(selector) is not OwnerTaskActivityValuesChildRequestV1 or selector.child_slot!=slot
                or evidence.owner_guard!=frame.owner_guard or evidence.current_self.self_entity_ref!=frame.envelope.authority.actor
                or selector.request_digest!=owner_task_typed_command_digest_v1(installed_operation_v1(_CHILDREN[slot]),command)
                or selector.operation_id!=frame.envelope.identity.operation_id):
            raise ValueError('Values child has no actual same-command Owner task private issuance')
        job=get_job(db,AtomKey.from_token(selector.task_job_ref).name)
        return qualify_owner_task_values_child_in_core_v1(db,request=selector,authorization=evidence.authorization,
            job=job,current_self=evidence.current_self,owner_guard=evidence.owner_guard,now_utc=frame.now_utc,issuer=self.issuer)


def install_owner_task_values_readers_v1(graph,*,scope,owner_guard,owner_task_issuance):
    from ..graph_coordinator import GraphCoordinator
    from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
    if type(graph) is not GraphCoordinator:
        raise TypeError('actual Owner task Graph is required')
    evidence=require_owner_source_note_task_issuance_v1(owner_task_issuance,graph,scope)
    if evidence.request.operation_kind not in {OPERATION,*_CHILDREN.values()}:
        raise ValueError('Owner Values factory cannot serve an unrelated task command')
    return InstalledOwnerTaskValuesReadersV1(_READERS_KEY,graph=graph,scope=scope,issued=owner_task_issuance)


def install_owner_task_values_child_readers_v1(graph,*,scope,owner_guard,owner_task_issuance):
    readers=install_owner_task_values_readers_v1(graph,scope=scope,owner_guard=owner_guard,owner_task_issuance=owner_task_issuance)
    base=InstalledD01ProductionReadersV1(issuer=readers.issuer,owner_guard=owner_guard)
    base._owner_task_values_child_v1=readers
    return base


def _actual_parent(db,*,frame,request,readers):
    if type(request) is not FreezeOwnerSourceNoteValuesParentRequestV1 or type(readers) is not InstalledOwnerTaskValuesReadersV1:
        raise TypeError('exact current Owner Values parent request/readers required')
    read=CurrentDomainReadV1(frame);read.check(db)
    evidence=readers.current();ns=frame.envelope.authority.namespace
    from ..authority_service.current_owner_source_note_task_v1 import owner_task_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    if (evidence.request.operation_kind!=OPERATION or evidence.owner_guard!=frame.owner_guard
            or evidence.request.authorization_original_ref!=request.authorization_original_ref
            or evidence.request.task_job_ref!=request.task_job_ref
            or evidence.request.request_digest!=owner_task_typed_command_digest_v1(installed_operation_v1(OPERATION),request)):
        raise ValueError('Owner Values parent differs from its actual private Self command')
    saved=read_owner_source_note_task_authorization_v2(db,namespace=ns,original_ref=request.authorization_original_ref,issuer=readers.issuer)
    if saved is None:raise MissingProductionOriginalV1('actual_signed_Owner_Values_authorization')
    auth=saved[0]
    require_current_owner_source_note_task_authorization_v2(db,frame=frame,authorization=auth,issuer=readers.issuer,
        installed_bundle=readers.bundle,body_quote_authority=readers.body_quote_authority)
    qualified=require_current_owner_source_note_need_v1(db,frame=frame,original_ref=request.need_original_ref,installed_readers=readers.need_readers)
    need,need_original=read_owner_source_note_need_original_v2(db,namespace=ns,original_ref=request.need_original_ref)
    job_key=AtomKey.from_token(request.task_job_ref);job=get_job(db,job_key.name)
    job_head=read.head(db,job_key,required=True)
    cont=decode_typed_production_value_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
    responsibility=read_owner_source_note_task_responsibility_v2(db,namespace=ns,original_ref=cont.responsibility_ref,issuer=readers.issuer)
    if (responsibility is None or responsibility[1]!=auth or job_head.value!=job_graph_write(job).value
            or job.phase!='running' or job.lease_holder!=frame.envelope.authority.actor or job.fence!=frame.envelope.authority.worker_fence
            or cont.step!='values' or cont.pending_effect_refs or job.cancel_epoch or cont.cancel_generation
            or need.authorization_original_ref!=auth.original_ref or need.responsibility_digest!=responsibility[0].digest
            or qualified.new_c3_required or not qualified.complete or qualified.meaningful_gaps):
        raise MissingProductionOriginalV1('actual_running_Owner_Values_same_task_Need_responsibility')
    pins={name:(version,digest) for name,version,digest in auth.heads}
    plan_head=read.head(db,pins['plan'][0].key,required=True)
    plan=decode_typed_production_value_v1(plan_head.value,PersonalPlanV1)
    ids=owner_source_note_task_ids_v1(ns,auth.cause.owner_operation_id)
    if plan.candidate_refs!=(ids['candidate_ref'],) or len(plan.nodes)!=1 or plan.nodes[0].node_id!=ids['node_id'] or plan.nodes[0].action_kind!='source_note' or plan.method_candidates:
        raise ValueError('Owner Values cannot manufacture unrelated or method-trial candidates')
    target=read.head(db,pins['target'][0].key,required=True)
    candidates=FrozenValuesCandidateSetV1(((ids['candidate_ref'],('personal_plan','source_note')),),(pins['plan'][0],),None)
    context=FrozenValuesContextV1(tuple(sorted({'source_note','consolidation',target.value['kind']})),
        (pins['target'][0],pins['role'][0]),False)
    value_ids=owner_source_note_values_ids_v1(ns,request)
    if frame.envelope.identity.operation_id!=value_ids['parent_operation_id']:
        raise ValueError('Owner Values parent changed its stable original operation')
    children=tuple((slot,kind,value_ids[slot+'_operation_id'],owner_task_typed_command_digest_v1(installed_operation_v1(kind),_child_requests(value_ids)[slot]))
        for slot,kind in _CHILDREN.items())
    grant=readers.issuer.current_budget_grant(db,auth.cause.parent_budget_lease_ref)
    hard=tuple((GraphVersion(atom.key,atom.revision),canonical_digest(atom.value),atom.valid) for atom in frame.snapshot.atoms)
    return OwnerTaskValuesParentV1(request,ns,auth.digest,cont.responsibility_ref,responsibility[0].digest,need_original['original_digest'],
        frame.owner_guard,frame.envelope.authority.actor,GraphVersion(job_key,job_head.revision),canonical_digest(job),
        pins['goal'][0],pins['plan'][0],auth.source_refs,candidates,context,hard,frame.query_coverage,children,
        auth.cause.parent_budget_lease_ref,canonical_digest(grant),min(auth.cause.original_deadline_utc,qualified.original_deadline_utc),
        frame.now_utc,frame.envelope.identity.operation_id)


def stage_freeze_owner_source_note_values_parent_v1(db,*,frame,request,installed_readers):
    parent=_actual_parent(db,frame=frame,request=request,readers=installed_readers)
    provider=GoalExecutionProvider()
    return stage_result_v1(frame,'d08',OPERATION,request,provenance={'owner_task_values_parent':parent},
        proposal_schema='d08.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)


def record_owner_source_note_values_parent_after_cas_v1(db,*,frame,stage,receipt,installed_readers):
    raw=json.loads(stage.original_payload_json)['provenance']['owner_task_values_parent']
    parent=decode_typed_production_value_v1(raw,OwnerTaskValuesParentV1)
    if receipt.status!='committed' or receipt.operation_id!=parent.registration_operation_id or receipt.write_versions:
        raise ValueError('Owner Values parent requires its actual metadata-only W01 original')
    return _record(db,issuer=installed_readers.issuer,namespace=parent.namespace,kind=KIND,ref=parent.original_ref,
        operation_id=receipt.operation_id,value=parent)


def read_owner_task_values_parent_v1(db,*,namespace,original_ref,issuer):
    saved=_read(db,issuer=issuer,namespace=namespace,kind=KIND,ref=original_ref)
    if saved is None:return None
    parent=decode_typed_production_value_v1(saved[0],OwnerTaskValuesParentV1)
    original=read_adopted_domain_operation_v1(db,namespace,saved[1])
    if (parent.namespace!=namespace or parent.original_ref!=original_ref or parent.registration_operation_id!=saved[1]
            or original is None or (original['domain'],original['operation_kind'])!=('d08',OPERATION)
            or original['receipt'].write_versions or original['payload']['provenance']['owner_task_values_parent']!=saved[0]
            or original['payload']['authority']['actor']!=parent.self_actor_ref
            or original['payload']['owner_guard']!=plain_v1(parent.owner_guard)):
        raise ValueError('Owner Values parent lost its exact signed Self W01 producer')
    return parent,original


def _require_parent_current(db,*,parent,authorization,job,owner_guard,actor,now_utc,issuer,allow_job_advance=False):
    if (parent.authorization_digest!=authorization.digest or parent.request.authorization_original_ref!=authorization.original_ref
            or parent.owner_guard!=owner_guard or parent.self_actor_ref!=actor
            or parent.parent_budget_lease_ref!=authorization.cause.parent_budget_lease_ref
            or now_utc>=parent.original_deadline_utc or job.cancel_epoch
            or canonical_digest(issuer.current_budget_grant(db,parent.parent_budget_lease_ref))!=parent.budget_grant_digest):
        raise MissingProductionOriginalV1('actual_current_Owner_Values_parent_scope')
    cont=decode_typed_production_value_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
    if (job_graph_write(job).key!=parent.task_job_head.key or job.phase!='running' or job.lease_holder!=actor
            or cont.authorization_original_ref!=parent.request.authorization_original_ref
            or (cont.responsibility_ref,cont.responsibility_digest)!=(parent.responsibility_ref,parent.responsibility_digest)
            or cont.cancel_generation or cont.pending_effect_refs
            or not allow_job_advance and (cont.step!='values' or canonical_digest(job)!=parent.task_job_digest)):
        raise ValueError('Owner Values child changed its actual task responsibility or original worker')
    for head,digest,valid in parent.hard_heads:
        if allow_job_advance and head.key==parent.task_job_head.key:continue
        row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(head.key.token,)).fetchone()
        if head.revision==0 and row is None:continue
        if row is None or (row[0],canonical_digest(json.loads(row[1])),bool(row[2]))!=(head.revision,digest,valid):
            raise MissingProductionOriginalV1('current_frozen_Owner_Values_fact:'+head.key.type_name)
    for page in parent.query_coverage:
        current=db.execute('SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129',
            (*parent.namespace.as_tuple,page.type_id)).fetchall()
        if (len(current)>128 or not page.complete or page.continuation_ref is not None
                or tuple(GraphVersion(AtomKey.from_token(ref),rev) for ref,rev in current)!=page.row_versions):
            raise MissingProductionOriginalV1('current_complete_Owner_Values_query:'+page.type_id)
    need=read_owner_source_note_need_original_v2(db,namespace=parent.namespace,original_ref=parent.request.need_original_ref)
    if need is None or need[1]['original_digest']!=parent.need_original_digest:
        raise ValueError('Owner Values changed its adopted Need original')
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    for purpose in ('context','consolidation'):
        _source_family_current_sql_v1(db,namespace=parent.namespace,roots=parent.source_refs,purpose=purpose,audiences=authorization.cause.audiences)


def qualify_owner_task_values_child_in_core_v1(db,*,request,authorization,job,current_self,owner_guard,now_utc,issuer):
    saved=read_owner_task_values_parent_v1(db,namespace=authorization.cause.namespace,
        original_ref=request.values_parent_original_ref,issuer=issuer)
    if saved is None:raise MissingProductionOriginalV1('actual_signed_Owner_Values_parent')
    parent,_=saved
    _require_parent_current(db,parent=parent,authorization=authorization,job=job,owner_guard=owner_guard,
        actor=current_self.self_entity_ref,now_utc=now_utc,issuer=issuer)
    ids=owner_source_note_values_ids_v1(parent.namespace,parent.request)
    child=next(row for row in parent.child_operations if row[0]==request.child_slot)
    if ((request.operation_kind,request.operation_id,request.request_digest)!=child[1:]
            or parent.digest!=request.values_parent_original_digest or request.task_job_ref!=parent.task_job_head.key.token):
        raise ValueError('Owner Values child is not its parent frozen exact typed command')
    if request.child_slot=='evaluate':
        _require_child_original(db,parent=parent,slot='freeze',issuer=issuer)
    return parent,_child_requests(ids)[request.child_slot]


def _require_child_original(db,*,parent,slot,issuer):
    ids=owner_source_note_values_ids_v1(parent.namespace,parent.request)
    operation=read_adopted_domain_operation_v1(db,parent.namespace,ids[slot+'_operation_id'])
    if (operation is None or (operation['domain'],operation['operation_kind'])!=('d01',_CHILDREN[slot])
            or operation['payload']['request']!=plain_v1(_child_requests(ids)[slot])
            or operation['payload']['authority']['actor']!=parent.self_actor_ref
            or operation['payload']['parent_budget']!=parent.parent_budget_lease_ref):
        raise MissingProductionOriginalV1('actual_Owner_Values_'+slot+'_child')
    if slot=='freeze':
        from .d01_production_operations_v1 import TABLE,SIGN_KIND
        for ref,kind,value in ((ids['candidate_set_ref'],'values_candidates',parent.candidates),
                (ids['context_ref'],'values_context',parent.context)):
            row=db.execute('SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM '+TABLE+
                ' WHERE bot=? AND persona=? AND original_ref=?',(*parent.namespace.as_tuple,ref)).fetchone()
            if row is None or row[:2]!=(kind,ids['freeze_operation_id']) or json.loads(row[2])!=plain_v1(value) or canonical_digest(json.loads(row[2]))!=row[3]:
                raise ValueError('Owner Values child changed its actual frozen signed candidate/context')
            issuer._signer.verify(SIGN_KIND,row[2],row[4])
    return operation


def freeze_owner_task_values_from_parent_v1(db,*,frame,producing_operation_id,candidate_set_ref,context_ref,child_reader,base_readers):
    if type(child_reader) is not InstalledOwnerTaskValuesReadersV1 or type(base_readers) is not InstalledD01ProductionReadersV1:
        raise TypeError('Owner Values freeze requires its actual private child reader')
    command=FreezeCurrentValuesInputRequestV1(candidate_set_ref,context_ref)
    parent,_=child_reader.require_child(db,frame=frame,command=command,slot='freeze')
    ids=owner_source_note_values_ids_v1(parent.namespace,parent.request)
    if producing_operation_id!=ids['freeze_operation_id']:
        raise ValueError('Owner Values freeze changed its once child producer')
    return (base_readers.record_input(db,frame=frame,original_ref=candidate_set_ref,producing_operation_id=producing_operation_id,
        kind='values_candidates',value=parent.candidates),base_readers.record_input(db,frame=frame,original_ref=context_ref,
        producing_operation_id=producing_operation_id,kind='values_context',value=parent.context))


def require_owner_task_values_evaluation_child_v1(db,*,frame,request,child_reader):
    if type(child_reader) is not InstalledOwnerTaskValuesReadersV1:
        raise TypeError('Owner Values evaluation requires its actual private child reader')
    return child_reader.require_child(db,frame=frame,command=request,slot='evaluate')


def read_plan_owner_task_values_parent_v1(db,*,namespace,request,installed_readers):
    readers=installed_readers
    need_request=PrepareOwnerSourceNoteNeedRequestV1(request.authorization_original_ref,request.task_job_ref)
    base=read_plan_owner_source_note_need_v1(db,namespace=namespace,request=need_request,installed_readers=readers.need_readers)
    return production_read_plan_v1((*base.fixed_type_ids,'d01.persona_activation.v1','d01.persona_plan.v1'),base.exact_keys,
        base.source_roots,(*base.required_original_refs,request.need_original_ref))


def read_plan_owner_task_values_child_v1(db,*,namespace,selector,issuer):
    saved=read_owner_task_values_parent_v1(db,namespace=namespace,original_ref=selector.values_parent_original_ref,issuer=issuer)
    if saved is None:raise MissingProductionOriginalV1('actual_signed_Owner_Values_parent_readplan')
    parent,_=saved;ids=owner_source_note_values_ids_v1(namespace,parent.request)
    originals=(parent.original_ref,parent.request.authorization_original_ref,parent.responsibility_ref,parent.request.need_original_ref)
    if selector.child_slot=='evaluate': originals+= (ids['candidate_set_ref'],ids['context_ref'])
    return production_read_plan_v1(tuple(page.type_id for page in parent.query_coverage),tuple(head.key for head,_,_ in parent.hard_heads),parent.source_refs,originals)


def read_current_owner_task_values_evaluation_v1(db,*,read,request,candidate_refs,issuer):
    rows=db.execute("SELECT original_ref FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? "
        "AND EXISTS(SELECT 1 FROM json_each(payload_json,'$.child_operations') c WHERE json_extract(c.value,'$[0]')='evaluate' "
        "AND json_extract(c.value,'$[2]')=?) LIMIT 2",(*read.frame.envelope.authority.namespace.as_tuple,KIND,request.value_evaluation_operation_id)).fetchall()
    if not rows:return None
    if len(rows)!=1:raise ValueError('Owner Values evaluation has ambiguous actual parents')
    parent,_=read_owner_task_values_parent_v1(db,namespace=read.frame.envelope.authority.namespace,original_ref=rows[0][0],issuer=issuer)
    saved=read_owner_source_note_task_authorization_v2(db,namespace=parent.namespace,original_ref=parent.request.authorization_original_ref,issuer=issuer)
    if saved is None:raise MissingProductionOriginalV1('actual_current_Owner_Values_authorization')
    job=get_job(db,parent.task_job_head.key.name)
    _require_parent_current(db,parent=parent,authorization=saved[0],job=job,owner_guard=read.frame.owner_guard,
        actor=read.frame.envelope.authority.actor,now_utc=read.frame.now_utc,issuer=issuer,allow_job_advance=True)
    if (request.plan_ref,request.goal_ref,request.need_qualification_original_ref)!=(parent.plan_head.key.token,parent.goal_head.key.token,parent.request.need_original_ref):
        raise ValueError('Owner Values consumer selected another actual Plan/Goal/Need')
    freeze=_require_child_original(db,parent=parent,slot='freeze',issuer=issuer)
    evaluation=_require_child_original(db,parent=parent,slot='evaluate',issuer=issuer)
    parent_original=read_adopted_domain_operation_v1(db,parent.namespace,parent.registration_operation_id)
    if not parent_original['receipt'].commit_seq < freeze['receipt'].commit_seq < evaluation['receipt'].commit_seq:
        raise ValueError('Owner Values children changed their prospective actual order')
    for version in evaluation['read_versions']:
        if version.key!=parent.task_job_head.key and read.head(db,version.key).revision!=version.revision:
            raise MissingProductionOriginalV1('current_actual_Owner_Values_evaluation_fact')
    read.head(db,parent.task_job_head.key,required=True)
    values=evaluation['payload']['provenance']['evaluation']
    if (set(values['preferred'])|set(values['rejected'])|set(values['unresolved']))!=set(candidate_refs) or set(candidate_refs)!={row[0] for row in parent.candidates.candidates}:
        raise ValueError('Owner Values evaluation changed its actual fixed task candidates')
    return evaluation


def read_owner_task_values_parent_original_ref_v1(db,*,namespace,original_ref,issuer):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    if not original_ref.startswith('owner-note-values-parent:'):return None
    saved=read_owner_task_values_parent_v1(db,namespace=namespace,original_ref=original_ref,issuer=issuer)
    return None if saved is None else ProductionOriginalRefV1('d11.life_'+KIND,original_ref,saved[0].digest)
