"""Content-only Life encoding COMMIT; no before/comparison/affect inference.

An Owner command consumes the real paid worker result. Public locators and
decoded traces do not authorize current use. W01 rechecks the exact issued
stage under its original write permit and commits all four members together.
"""
from dataclasses import dataclass,replace,fields
from datetime import datetime
import json

from ..graph_types import AtomKey,GraphWrite,GraphVersion,TypeSpec
from ..runtime_contracts import NamespaceId,DomainBundle,canonical_digest,canonical_serialize,schema_hash
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from .domain_production_contracts_v1 import ProductionQueryCoverageV1
from .d06_internal_life_episode_v2 import EpisodeReadV2,_sha
from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1,read_current_internal_life_encoding_cause_v1
from .internal_life_content_preparation_v1 import PrepareInternalLifeContentRequestV1,read_plan_internal_life_content_v1
from .internal_life_content_worker_v2 import read_committed_internal_life_request_v2,read_life_worker_original_v2
from .internal_life_paid_result_v2 import read_life_paid_original_v2,record_life_paid_original_v2,read_life_cost_commit_v2
from .jobs import get_job
from .d11_types import job_graph_write
from .d01_production_operations_v1 import CurrentDomainReadV1,production_read_plan_v1
from ..model_broker.internal_life_content_v1 import InternalLifeContentCandidateV1,parse_internal_life_content_output_v1,thaw_internal_life_content_request_v1
from ..authority_service.internal_life_model_result_contract_v2 import InternalLifeModelResultReadV2,internal_life_result_from_wire_v2

OPERATION='adopt_internal_life_content_v1'
TRACE='memory.internal_life_content_trace.v1'
PROVENANCE='memory.internal_life_content_provenance.v1'
ELIGIBILITY='memory.internal_life_content_eligibility.v1'
KINDS=(TRACE,PROVENANCE,ELIGIBILITY)
PROPOSAL_SCHEMA='d06.internal-life-content-adoption.proposal.v1'
PROPOSAL_HASH=schema_hash({'schema':PROPOSAL_SCHEMA,'types':KINDS,'capability':'content-only','issuer':'exact-installed-production-witness'})
JOB_SCHEMA='d11.internal-life-content-adoption.proposal.v1'
JOB_HASH=schema_hash({'schema':JOB_SCHEMA,'transition':'actual-running-worker-to-completed-after-paid-result','issuer':'same-exact-Life-content-witness'})

@dataclass(frozen=True,slots=True)
class AdoptInternalLifeContentRequestV1:
    episode_ref:str
    causal_operation_id:str
    def __post_init__(self):EncodeInternalLifeRequestV1(self.episode_ref,self.causal_operation_id)

def content_keys_v1(episode_ref):
    from .d06_internal_life_episode_v2 import EPISODE
    key=AtomKey.from_token(episode_ref)
    if key.type_name!=EPISODE:raise ValueError('Life content trace requires actual Episode v2')
    return tuple(AtomKey(key.owner,k,'content') for k in KINDS)

@dataclass(frozen=True,slots=True)
class InternalLifeContentTraceV1:
    trace_ref:str
    namespace:NamespaceId
    episode_ref:str
    occurrence_digest:str
    producing_operation_id:str
    job_id:str
    call_id:str
    prepared_digest:str
    worker_binding_digest:str
    result_digest:str
    cost_ref:str
    cost_commit_digest:str
    activation_generation:int
    graph_incarnation:str
    candidate:InternalLifeContentCandidateV1
    completion:str='content_completed'
    before_state:str='evidence_unavailable'
    comparison:str='undetermined'
    affect:str='unavailable'
    schema:str=TRACE
    def __post_init__(self):
        from ..authority_service.contract import identifier
        if (self.schema!=TRACE or type(self.namespace) is not NamespaceId
                or self.trace_ref!=content_keys_v1(self.episode_ref)[0].token
                or NamespaceId.from_key(AtomKey.from_token(self.episode_ref))!=self.namespace
                or type(self.activation_generation) is not int or self.activation_generation<1
                or type(self.candidate) is not InternalLifeContentCandidateV1
                or (self.completion,self.before_state,self.comparison,self.affect)!=
                   ('content_completed','evidence_unavailable','undetermined','unavailable')
                or self.candidate.occurrence_digest!=self.occurrence_digest):
            raise ValueError('Life content-only trace identity/capability differs')
        for n in ('occurrence_digest','prepared_digest','worker_binding_digest','result_digest','cost_commit_digest'):_sha(getattr(self,n))
        for n in ('producing_operation_id','job_id','call_id','graph_incarnation'):identifier(getattr(self,n),n)
        suffix=self.job_id.removeprefix('life-content-job:')
        if len(suffix)!=48 or any(c not in '0123456789abcdef' for c in suffix) or (self.job_id,self.call_id,self.producing_operation_id)!=tuple('life-content-'+p+':'+suffix for p in ('job','call','adopt')):
            raise ValueError('Life content trace changed its once family')
        cost=AtomKey.from_token(self.cost_ref)
        if cost.type_name!='runtime.cost_settlement' or NamespaceId.from_key(cost)!=self.namespace:raise ValueError('Life content cost scope differs')

@dataclass(frozen=True,slots=True)
class InternalLifeContentProvenanceV1:
    trace:InternalLifeContentTraceV1
    owner_head_digest:str
    input_epoch:int
    historical_reads:tuple[EpisodeReadV2,...]
    current_reads:tuple[EpisodeReadV2,...]
    query_coverage:tuple[ProductionQueryCoverageV1,...]
    schema:str=PROVENANCE
    def __post_init__(self):
        if self.schema!=PROVENANCE or type(self.trace) is not InternalLifeContentTraceV1 or type(self.input_epoch) is not int or self.input_epoch<1:
            raise ValueError('Life content provenance closed scope differs')
        _sha(self.owner_head_digest)
        for rows in (self.historical_reads,self.current_reads):
            if (type(rows) is not tuple or not 1<=len(rows)<=1024 or any(type(r) is not EpisodeReadV2 for r in rows)
                    or tuple(r.ref for r in rows)!=tuple(sorted({r.ref for r in rows}))
                    or any(NamespaceId.from_key(AtomKey.from_token(r.ref))!=self.trace.namespace for r in rows)):
                raise ValueError('Life content provenance finite read closure differs')
        expected=tuple(r for r in self.historical_reads if AtomKey.from_token(r.ref).type_name not in
            {*KINDS,'runtime.job','runtime.cost_settlement'})
        if self.current_reads!=expected or not self.query_coverage or any(type(q) is not ProductionQueryCoverageV1 or not q.complete for q in self.query_coverage):
            raise ValueError('Life content current projection or full query coverage differs')

@dataclass(frozen=True,slots=True)
class InternalLifeContentEligibilityV1:
    trace_ref:str
    provenance_ref:str
    provenance_digest:str
    producing_operation_id:str
    schema:str=ELIGIBILITY
    def __post_init__(self):
        from ..authority_service.contract import identifier
        key=AtomKey.from_token(self.trace_ref);_sha(self.provenance_digest)
        identifier(self.producing_operation_id,'producing_operation_id')
        if (self.schema!=ELIGIBILITY or key.type_name!=TRACE
                or self.provenance_ref!=AtomKey(key.owner,PROVENANCE,'content').token):
            raise ValueError('Life content eligibility exact member differs')

def decode_content_v1(kind,raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    cls=dict(zip(KINDS,(InternalLifeContentTraceV1,InternalLifeContentProvenanceV1,InternalLifeContentEligibilityV1))).get(kind)
    if cls is None or type(raw) is not dict or set(raw)!={f.name for f in fields(cls)}:raise ValueError('Life content exact fields/type differ')
    v=decode_typed_production_value_v1(raw,cls)
    if canonical_serialize(plain_v1(v))!=canonical_serialize(raw):raise ValueError('Life content canonical value differs')
    return v

def content_type_specs_v1():
    return tuple(TypeSpec(k,('event',),'projection' if k==ELIGIBILITY else 'state',
        lambda raw,k=k:decode_content_v1(k,raw),immutable=k!=ELIGIBILITY,writer_domain='d06',
        schema_hash=schema_hash({'type':k,'fields':tuple(f.name for f in fields(cls))}))
        for k,cls in zip(KINDS,(InternalLifeContentTraceV1,InternalLifeContentProvenanceV1,InternalLifeContentEligibilityV1)))

def read_plan_content_adoption_v1(db,*,namespace,activity_id,operation_kind,request):
    if operation_kind!=OPERATION or type(request) is not AdoptInternalLifeContentRequestV1:raise TypeError('Life content exact adoption locator required')
    p=read_plan_internal_life_content_v1(db,namespace=namespace,activity_id=activity_id,
        operation_kind='prepare_internal_life_content',request=PrepareInternalLifeContentRequestV1(request.episode_ref,request.causal_operation_id))
    from .d06_internal_life_episode_v2 import PROVENANCE as EP,decode_internal_life_value_v2
    key=AtomKey.from_token(request.episode_ref)
    ep=decode_internal_life_value_v2(EP,json.loads(db.execute('SELECT value FROM graph_atoms WHERE token=?',(AtomKey(key.owner,EP,'record').token,)).fetchone()[0]))
    from ..model_broker.internal_life_content_v1 import internal_life_content_ids_for_occurrence_v1
    ids=internal_life_content_ids_for_occurrence_v1(ep)
    # Cost identity is independently deterministic from the actual once call;
    # loading the signed prepared is deferred to the installed stage reader.
    from .model_cost_settlement import original_model_cost_operation_id_v1
    from .d11_types import runtime_cost_settlement_key
    cost=runtime_cost_settlement_key(*namespace.as_tuple,activity_id,original_model_cost_operation_id_v1(namespace,ids['call']))
    return production_read_plan_v1(tuple(sorted(set((*p.fixed_type_ids,*KINDS)))),
        tuple(sorted(set((*p.exact_keys,*content_keys_v1(request.episode_ref),cost)),key=lambda k:k.token)),
        p.source_roots,p.required_original_refs)

def _build(db,frame,request,readers):
    read=CurrentDomainReadV1(frame);read.check(db)
    cause=read_current_internal_life_encoding_cause_v1(db,frame=frame,
        request=EncodeInternalLifeRequestV1(request.episode_ref,request.causal_operation_id),installed_readers=readers)
    from ..model_broker.internal_life_content_v1 import internal_life_content_ids_v1
    ids=internal_life_content_ids_v1(cause)
    ids={**ids,'adopt':'life-content-adopt:'+ids['job'].removeprefix('life-content-job:')}
    p,b,model=read_committed_internal_life_request_v2(db,namespace=frame.envelope.authority.namespace,issuer=readers.issuer,job_id=ids['job'])
    frozen=thaw_internal_life_content_request_v1(json.loads(p.frozen_json))
    if frame.envelope.identity.operation_id!=ids['adopt'] or cause.occurrence.event.namespace!=p.namespace:
        raise ValueError('Life content adoption changed its once occurrence command')
    raw=read_life_paid_original_v2(db,p.namespace,readers.issuer,'result',p.job_id)
    if raw is None:raise ValueError('Life content adoption missing real delivered result original')
    result=internal_life_result_from_wire_v2(raw,InternalLifeModelResultReadV2)
    fact=readers.life_content_fact_v2
    if fact is None or fact.receipt!=result.terminal_receipt:raise ValueError('Life content adoption missing actual Authority model terminal/cost fact')
    result.require_original(fact.intent,p,frozen,b)
    cost=read_life_cost_commit_v2(db,namespace=p.namespace,issuer=readers.issuer,prepared=p,
        intent=fact.intent,terminal=fact.receipt,fact=fact)
    if (frame.now_utc<result.read_at_utc or frame.now_utc>=min(frozen.input.expires_at_utc,b.deadline_utc,model.envelope.deadline_utc)):
        raise ValueError('Life delivered original deadline expired before content adoption')
    if result.observation.digest!=fact.recovery.observation_digest or type(result.observation.result) is not dict or set(result.observation.result)!={'text'}:
        raise ValueError('Life delivered body differs from actual observed terminal')
    candidate=parse_internal_life_content_output_v1(result.observation.result['text'],frozen)
    job=get_job(db,p.job_id)
    head=read.head(db,job_graph_write(job).key,required=True)
    if head.revision!=2 or head.value['phase']!='running':raise ValueError('Life adoption needs actual acquired running Graph head')
    if job.phase=='completed':
        pre=replace(job,phase='running',result_ref=None,lease_holder=b.worker_subject,
            lease_expires_utc=head.value['lease_expires_utc'])
        if job_graph_write(pre).value!=head.value or replace(pre,phase='completed',result_ref=p.call_id,
                wake_condition=None,lease_holder=None,lease_expires_utc=None)!=job:
            raise ValueError('Life same-transaction completed SQL job differs from actual pre-CAS worker')
        job=pre
    elif job_graph_write(job).value!=head.value:raise ValueError('Life running SQL job differs from actual Graph projection')
    if (job.phase!='running' or job.lease_holder!=b.worker_subject or job.fence!=1 or job.cancel_epoch!=0
            or frame.now_utc>=datetime.fromisoformat(job.lease_expires_utc.replace('Z','+00:00')).timestamp()):
        raise ValueError('Life content adoption worker lease/job is no longer current')
    completed=replace(job,phase='completed',result_ref=p.call_id,wake_condition=None,lease_holder=None,lease_expires_utc=None)
    keys=content_keys_v1(p.episode_ref)
    for k in keys:
        atom=read.head(db,k)
        if atom.revision!=0:raise ValueError('Life content trace already exists; use its authenticated completed original')
    trace=InternalLifeContentTraceV1(keys[0].token,p.namespace,p.episode_ref,p.occurrence_digest,ids['adopt'],
        p.job_id,p.call_id,p.digest,b.digest,canonical_digest(raw),cost.cost_ref,canonical_digest(cost),
        p.activation_generation,p.graph_incarnation,candidate)
    history=tuple(EpisodeReadV2(a.key.token,a.revision,canonical_digest(a.value),a.valid) for a in sorted(frame.snapshot.atoms,key=lambda a:a.key.token))
    current=tuple(r for r in history if AtomKey.from_token(r.ref).type_name not in {*KINDS,'runtime.job','runtime.cost_settlement'})
    proof=InternalLifeContentProvenanceV1(trace,frame.owner_guard.owner_head_digest,frame.envelope.version_guard.query_epochs[0].revision,
        history,current,frame.query_coverage)
    elig=InternalLifeContentEligibilityV1(trace.trace_ref,keys[1].token,canonical_digest(plain_v1(proof)),trace.producing_operation_id)
    writes=(GraphWrite(keys[0],plain_v1(trace)),GraphWrite(keys[1],plain_v1(proof)),
        GraphWrite(keys[2],plain_v1(elig),tuple(AtomKey.from_token(r.ref) for r in current)),job_graph_write(completed))
    return p,b,result,cost,proof,completed,writes

@dataclass(frozen=True,slots=True)
class InternalLifeContentAdoptionStageV1:
    stage:object
    job_proposal:object
    frame:object
    prepared:object
    completed_job:object
    proof:InternalLifeContentProvenanceV1
    result:InternalLifeModelResultReadV2

def stage_adopt_internal_life_content_in_transaction_v1(db,*,frame,request,installed_readers):
    p,b,result,cost,proof,job,writes=_build(db,frame,request,installed_readers)
    stage=stage_result_v1(frame,'d06',OPERATION,request,writes=writes[:3],
        provenance={'schema':'d06.internal-life-content-encoding-commit.v1','proof':plain_v1(proof),
            'result_digest':proof.trace.result_digest,'capability':'content_only','before':'evidence_unavailable','affect':'unavailable'},
        proposal_schema=PROPOSAL_SCHEMA,proposal_hash=PROPOSAL_HASH)
    jp=stage_result_v1(frame,'d11',OPERATION,request,writes=(writes[3],),proposal_schema=JOB_SCHEMA,proposal_hash=JOB_HASH).proposals[0]
    return InternalLifeContentAdoptionStageV1(stage,jp,frame,p,job,proof,result)

def content_bundle_v1(stage):
    return DomainBundle(stage.frame.envelope,(*stage.stage.proposals,stage.job_proposal),(),(),(),(),
        (stage.proof.trace.producing_operation_id,),(stage.job_proposal.typed_writes[0].key.token,),())

def require_exact_content_issuance_v1(witness,graph,bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or type(witness.stage) is not InternalLifeContentAdoptionStageV1
            or witness.bundle is not bundle or witness.operation.operation_kind!=OPERATION):
        raise ValueError('Life content requires exact installed Owner/current production issuance')
    return witness

def verify_content_stage_v1(db,stage,readers,request):
    actual=stage_adopt_internal_life_content_in_transaction_v1(db,frame=stage.frame,request=request,installed_readers=readers)
    if actual!=stage:raise ValueError('Life content actual paid/current stage changed before COMMIT')
    return stage

def validate_content_proposal_v1(proposal,snapshot):
    expected=(PROPOSAL_SCHEMA,PROPOSAL_HASH) if proposal.domain=='d06' else (JOB_SCHEMA,JOB_HASH)
    if (proposal.proposal_schema,proposal.proposal_schema_hash)!=expected:raise ValueError('Life content independent proposal schema differs')
    if proposal.domain=='d06':
        if tuple(w.key.type_name for w in proposal.typed_writes)!=KINDS:raise ValueError('Life content complete three-member inventory differs')
        for w in proposal.typed_writes:decode_content_v1(w.key.type_name,w.value)
        if any(w.dependencies for w in proposal.typed_writes[:2]):raise ValueError('Life content immutable history has invalidating edges')
    elif len(proposal.typed_writes)!=1 or proposal.typed_writes[0].key.type_name!='runtime.job' or proposal.typed_writes[0].value['phase']!='completed':
        raise ValueError('Life content completion requires its exact completed job member')
    return proposal

def require_content_job_registration_v1(witness,db):
    require_exact_content_issuance_v1(witness,witness.graph,witness.bundle)
    if db is not witness.graph._GraphCoordinator__store._db or not db.in_transaction:
        raise ValueError('Life content once job registration needs actual installed SQL transaction')
    p=witness.stage.prepared;key=job_graph_write(witness.stage.completed_job).key.token
    row=db.execute("SELECT operation_id FROM graph_bundle_refs WHERE bot=? AND persona=? AND ref_kind='persistent_job' AND ref=?",(*p.namespace.as_tuple,key)).fetchone()
    if row!=(p.prepare_operation_id,) or witness.bundle.persistent_job_refs!=(key,):
        raise ValueError('Life content cannot register another once job')
    return (key,)

def validate_content_history_v1(db,proof,issuer):
    """Real durable SQL/event/history originals, independent of current rights."""
    from .d04_root_original_store_v1 import _receipt
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1,_receipt_wire
    ns=proof.trace.namespace;op=proof.trace.producing_operation_id
    receipt=_receipt(db,ns,op);adopted=read_adopted_domain_operation_v1(db,ns,op)
    event_epoch=db.execute('SELECT epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',(*ns.as_tuple,receipt.activity_id,op)).fetchone()
    result_raw=read_life_paid_original_v2(db,ns,issuer,'result',proof.trace.job_id)
    commit=read_life_paid_original_v2(db,ns,issuer,'adoption_commit',proof.trace.job_id)
    if (result_raw is None or canonical_digest(result_raw)!=proof.trace.result_digest
            or commit!={'schema':'d06.internal-life-content-adoption-commit.v1','job_id':proof.trace.job_id,
                'result_digest':proof.trace.result_digest,'trace_ref':proof.trace.trace_ref,
                'operation_id':op,'receipt':_receipt_wire(receipt),'receipt_digest':canonical_digest(receipt)}
            or adopted is None or adopted['domain']!='d06' or adopted['operation_kind']!=OPERATION
            or adopted['receipt']!=receipt or adopted['payload']['provenance']['proof']!=plain_v1(proof)
            or event_epoch!=(proof.input_epoch+1,)
            or receipt.read_versions!=tuple(GraphVersion(AtomKey.from_token(r.ref),r.revision) for r in proof.historical_reads)):
        raise ValueError('Life content durable encoding/result/receipt/input readset differs')
    p,b,model=read_committed_internal_life_request_v2(db,namespace=ns,issuer=issuer,job_id=proof.trace.job_id)
    raw=read_life_worker_original_v2(db,namespace=ns,issuer=issuer,kind='call',job_id=p.job_id)
    from ..authority_service.v2_model_egress_wire import from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    intent=from_wire(raw['intent'],ModelEgressIntentV1)
    result=internal_life_result_from_wire_v2(result_raw,InternalLifeModelResultReadV2)
    frozen=thaw_internal_life_content_request_v1(json.loads(p.frozen_json))
    result.require_original(intent,p,frozen,b)
    cost=read_life_cost_commit_v2(db,namespace=ns,issuer=issuer,prepared=p,intent=intent,terminal=result.terminal_receipt)
    if ((p.digest,b.digest,cost.cost_ref,canonical_digest(cost),parse_internal_life_content_output_v1(result.observation.result['text'],frozen))!=
            (proof.trace.prepared_digest,proof.trace.worker_binding_digest,proof.trace.cost_ref,proof.trace.cost_commit_digest,proof.trace.candidate)):
        raise ValueError('Life content historical trace differs from its actual paid output originals')
    for r in proof.historical_reads:
        row=db.execute('SELECT h.revision,h.value,h.valid FROM graph_history h JOIN graph_events e ON (h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) WHERE h.token=? AND e.bot=? AND e.persona=? AND e.epoch_revision<=? ORDER BY h.revision DESC LIMIT 1',
            (r.ref,*ns.as_tuple,proof.input_epoch)).fetchone()
        actual=(0,canonical_digest({}),False) if row is None else (row[0],canonical_digest(json.loads(row[1])),bool(row[2]))
        if actual!=(r.revision,r.digest,r.valid) or row is not None and row[2] not in (0,1):
            raise ValueError('Life content producing read history/negative version differs')
    for page in proof.query_coverage:
        if page.epoch.revision!=proof.input_epoch or page.epoch.namespace!=ns or not page.complete or page.continuation_ref is not None:
            raise ValueError('Life content historical complete query epoch differs')
        rows=db.execute('SELECT token,revision FROM (SELECT h.token,h.revision,ROW_NUMBER() OVER (PARTITION BY h.token ORDER BY h.revision DESC) n FROM graph_history h '
            'JOIN graph_events e ON (h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
            "WHERE e.bot=? AND e.persona=? AND json_extract(h.token,'$[4]')=? AND e.epoch_revision<=?) WHERE n=1 ORDER BY token LIMIT 1025",
            (*ns.as_tuple,page.type_id,proof.input_epoch)).fetchall()
        if len(rows)>1024 or tuple(GraphVersion(AtomKey.from_token(t),rev) for t,rev in rows)!=page.row_versions:
            raise ValueError('Life content historical query inventory differs or exceeds bound')
    keys=content_keys_v1(proof.trace.episode_ref)
    elig=InternalLifeContentEligibilityV1(keys[0].token,keys[1].token,canonical_digest(plain_v1(proof)),op)
    expected={keys[0]:plain_v1(proof.trace),keys[1]:plain_v1(proof),keys[2]:plain_v1(elig)}
    written={v.key:v.revision for v in receipt.write_versions}
    from .d11_types import runtime_job_key,RuntimeJobValue
    jobkey=runtime_job_key(*ns.as_tuple,p.activity_id,p.job_id)
    if written!={**{k:1 for k in keys},jobkey:3}:raise ValueError('Life content actual four-member COMMIT inventory differs')
    jr=db.execute('SELECT event_id,value,valid,dependencies FROM graph_history WHERE token=? AND revision=3',(jobkey.token,)).fetchone()
    if jr is None or jr[0]!=op or jr[2:]!=(1,'[]'):raise ValueError('Life completed job actual producing history differs')
    jraw=json.loads(jr[1]);j=RuntimeJobValue(**jraw)
    if (canonical_serialize(jraw)!=jr[1] or (j.bot_id,j.persona_id,j.activity_id,j.job_id,j.operation_id,j.phase,j.result_ref,
            j.fence,j.cancel_epoch,j.lease_holder,j.lease_expires_utc)!=
            (*ns.as_tuple,p.activity_id,p.job_id,p.prepare_operation_id,'completed',p.call_id,1,0,None,None)):
        raise ValueError('Life completed job namespace/once/result/worker transition differs')
    for k,v in expected.items():
        row=db.execute('SELECT event_id,value,valid,dependencies FROM graph_history WHERE token=? AND revision=1',(k.token,)).fetchone()
        deps=tuple(sorted((r.ref,r.revision) for r in proof.current_reads)) if k==keys[2] else ()
        if row is None or row[:3]!=(op,canonical_serialize(v),1):raise ValueError('Life content historical fact member bytes differ')
        edges=json.loads(row[3])
        if (type(edges) is not list or any(type(e) is not list or len(e)!=2 or type(e[0]) is not str or type(e[1]) is not int for e in edges)
                or tuple(sorted(map(tuple,edges)))!=deps):raise ValueError('Life content historical invalidation projection differs')
    expected_writes=[{'key':keys[0].token,'value':expected[keys[0]],'dependencies':[]},
        {'key':keys[1].token,'value':expected[keys[1]],'dependencies':[]},
        {'key':keys[2].token,'value':expected[keys[2]],'dependencies':[r.ref for r in proof.current_reads]},
        {'key':jobkey.token,'value':jraw,'dependencies':[]}]
    if adopted['payload']['writes']!=expected_writes:
        raise ValueError('Life shared production original complete four-member write set differs')
    return proof

def require_current_content_trace_v1(db,*,frame,trace_ref,installed_readers,capability='content'):
    if capability!='content':raise ValueError('Life numerical before/comparison/affect capability unavailable; HOLD')
    key=AtomKey.from_token(trace_ref);ns=frame.envelope.authority.namespace
    if key.type_name!=TRACE or NamespaceId.from_key(key)!=ns:raise ValueError('Life content current locator scope/type differs')
    read=CurrentDomainReadV1(frame);read.check(db)
    proof=decode_content_v1(PROVENANCE,read.head(db,AtomKey(key.owner,PROVENANCE,'content'),required=True).value)
    if proof.trace.trace_ref!=trace_ref or proof.owner_head_digest!=frame.owner_guard.owner_head_digest:
        raise ValueError('Life current content member/Owner qualification differs')
    validate_content_history_v1(db,proof,installed_readers.issuer)
    job=get_job(db,proof.trace.job_id);jw=job_graph_write(job)
    job_atom=read.head(db,jw.key,required=True)
    if (job.phase!='completed' or job.result_ref!=proof.trace.call_id or job.fence!=1 or job.cancel_epoch!=0
            or job_atom.revision!=3 or job_atom.value!=jw.value):
        raise ValueError('Life current completed SQL/Graph job projection differs')
    prepared=read_committed_internal_life_request_v2(db,namespace=ns,issuer=installed_readers.issuer,job_id=proof.trace.job_id)[0]
    frozen=thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json))
    read_current_internal_life_encoding_cause_v1(db,frame=frame,request=EncodeInternalLifeRequestV1(
        proof.trace.episode_ref,frozen.input.cause.occurrence.event.causal_operation_id),installed_readers=installed_readers)
    for r in proof.current_reads:
        a=read.head(db,r.ref)
        if (a.revision,canonical_digest(a.value),a.valid)!=(r.revision,r.digest,r.valid):raise ValueError('Life content current qualification changed')
    eligibility=read.head(db,AtomKey(key.owner,ELIGIBILITY,'content'),required=True)
    expected=InternalLifeContentEligibilityV1(trace_ref,AtomKey(key.owner,PROVENANCE,'content').token,canonical_digest(plain_v1(proof)),proof.trace.producing_operation_id)
    if eligibility.revision!=1 or eligibility.value!=plain_v1(expected):raise ValueError('Life content current eligibility is invalid or changed')
    edges=tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies WHERE dependent_token=? ORDER BY dependency_token',(eligibility.key.token,)))
    if edges!=tuple(sorted((r.ref,r.revision) for r in proof.current_reads)):raise ValueError('Life content current dependency edges changed')
    trace=read.head(db,key,required=True)
    if trace.revision!=1 or trace.value!=plain_v1(proof.trace):raise ValueError('Life content current immutable fact differs')
    roots=tuple(r.ref for r in proof.current_reads if AtomKey.from_token(r.ref).type_name=='memory.source')
    read.source_family(db,roots,purpose=frame.envelope.authority.purpose)
    return proof.trace

def commit_content_adoption_v1(runtime,db,*,operation,request,preparation,readers,scope,owner,guard,
        metadata,epoch,process_lease,external_originals):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1,_receipt_wire
    from .jobs import transition_job
    from .d11_types import reconcile_runtime_write
    from ..contracts import canonical_json
    from ..authority_service.v2_contract import to_wire
    verify_content_stage_v1(db,preparation,readers,request)
    job=transition_job(db,preparation.prepared.job_id,readers.life_content_fact_v2.intent.subject,1,
        target_phase='completed',result_ref=preparation.prepared.call_id)
    if job!=preparation.completed_job:raise ValueError('Life same-tx completion transition differs')
    bundle=content_bundle_v1(preparation)
    reconcile_runtime_write(db,preparation.job_proposal.typed_writes[0])
    attempt=db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
        (*preparation.prepared.namespace.as_tuple,preparation.proof.trace.producing_operation_id)).fetchone()
    if attempt is None or attempt[1]!=scope.operation_id or attempt[2]!=canonical_json(to_wire(scope.permit)):
        raise ValueError('Life content adoption missing exact Owner write attempt')
    witness=_ProductionCommitWitnessV1(runtime,runtime.graph,scope,preparation.frame,preparation,operation,request,owner,guard,bundle,tuple(external_originals))
    finish='sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3','operation_id':preparation.proof.trace.producing_operation_id,
        'request_digest':attempt[0],'permit_token':scope.permit.token})
    _ACTIVE[id(witness)]=witness
    try:
        receipt=runtime.graph._commit_domain_bundle_fenced(bundle,process_lease,in_transaction=True,
            v2_write=(metadata,epoch,'finish:'+scope.operation_id,finish,canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc,domain_production_issuance_v1=witness)
    finally:_ACTIVE.pop(id(witness),None)
    expected={w.key for p in bundle.proposals for w in p.typed_writes}
    if len(receipt.write_versions)!=4 or {v.key for v in receipt.write_versions}!=expected:
        raise ValueError('Life content COMMIT lacks exact trace/provenance/eligibility/job inventory')
    record_life_paid_original_v2(db,preparation.prepared.namespace,readers.issuer,'adoption_commit',job.job_id,
        {'schema':'d06.internal-life-content-adoption-commit.v1','job_id':job.job_id,
         'result_digest':preparation.proof.trace.result_digest,'trace_ref':preparation.proof.trace.trace_ref,
         'operation_id':receipt.operation_id,'receipt':_receipt_wire(receipt),'receipt_digest':canonical_digest(receipt)})
    # Keep the complete shared producing payload, including both proposals.
    primary=preparation.stage
    payload=json.loads(primary.original_payload_json)
    payload['writes']=plain_v1(tuple(w for p in bundle.proposals for w in p.typed_writes))
    primary=replace(primary,original_payload_json=canonical_serialize(payload),original_digest=canonical_digest(payload))
    original=record_adopted_domain_operation_v1(db,primary,receipt)
    return {'schema':'sylanne.internal-life-content-production-receipt.v1','domain':'d06','operation_kind':OPERATION,
        'operation_id':receipt.operation_id,'activity_id':job.activity_id,'original_ref':original.original_ref,
        'original_digest':original.original_digest,'receipt':_receipt_wire(receipt),'receipt_digest':canonical_digest(receipt),
        'job_states':[[job.job_id,'completed']],'coverage':'complete','completion':'content_completed',
        'capability':'content_only','before_state':'evidence_unavailable','comparison':'undetermined','affect':'unavailable',
        'missing_inputs':['life_numeric_before_comparison_affect_bridge'],'continuation_ref':None,'outbox':[]}


class InstalledInternalLifeContentReaderV1:
    """Current content capability under an actual installed Owner read fence.

    A public trace/DTO cannot manufacture this Owner lease, session, permit,
    current generation or qualified Source read. Numerical capabilities HOLD.
    """
    def __init__(self, *, graph, installed_readers):
        from ..graph_coordinator import GraphCoordinator
        from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
        if (type(graph) is not GraphCoordinator or type(installed_readers) is not InstalledD06StructuredExperienceReadersV1
                or installed_readers.resource_issuer is not installed_readers.issuer.resource_issuer
                or installed_readers.issuer is not graph._GraphCoordinator__d11_issuer
                or installed_readers.resource_issuer is not graph._GraphCoordinator__d02_issuer
                or installed_readers.body_quote_authority is not graph._GraphCoordinator__body_quote_authority):
            raise ValueError('Life content reader needs the actual installed Graph and readers')
        self._graph,self._readers=graph,installed_readers

    def read(self, *, authority, lease, trace_ref, capability='content'):
        from ..graph_coordinator import OwnerLeaseBindingV1
        from .domain_production_frame_v1 import freeze_domain_production_frame_v1
        from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1,read_current_domain_policy_refs_v1
        from .first_ingress_v2 import trusted_upper
        graph=self._graph;store=graph._GraphCoordinator__store
        graph._authorize(lease,authority,frozenset({'d06'}),owner_read=True)
        owner=graph._GraphCoordinator__owner_leases.get(lease)
        session=graph._GraphCoordinator__owner_session_proofs.get(lease)
        if type(owner) is not OwnerLeaseBindingV1 or session is None or capability!='content':
            raise ValueError('Life current content requires authenticated Owner/session and content-only capability')
        key=AtomKey.from_token(trace_ref)
        if key.type_name!=TRACE or NamespaceId.from_key(key)!=authority.namespace:
            raise ValueError('Life current content locator namespace/type differs')
        context={}
        def observe(scope):
            guard,current=graph._owner_binding_in_fence(authority,scope,owner.principal,owner,session)
            clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
            context.update(scope=scope,owner=current,now=trusted_upper(clock))
            return guard,scope.permit
        def current_read():
            db=store._db;db.execute('BEGIN')
            try:
                raw=db.execute('SELECT value,valid FROM graph_atoms WHERE token=?',(AtomKey(key.owner,PROVENANCE,'content').token,)).fetchone()
                if raw is None or raw[1]!=1:raise ValueError('Life current content has no authenticated provenance')
                proof=decode_content_v1(PROVENANCE,json.loads(raw[0]))
                p,b,model=read_committed_internal_life_request_v2(db,namespace=authority.namespace,
                    issuer=self._readers.issuer,job_id=proof.trace.job_id)
                frozen=thaw_internal_life_content_request_v1(json.loads(p.frozen_json))
                request=AdoptInternalLifeContentRequestV1(p.episode_ref,frozen.input.cause.occurrence.event.causal_operation_id)
                plan=read_plan_content_adoption_v1(db,namespace=authority.namespace,activity_id=p.activity_id,operation_kind=OPERATION,request=request)
                policies=read_current_domain_policy_refs_v1(db,namespace=authority.namespace,plan=plan,installed_readers=self._readers)
                originals=read_current_domain_original_refs_v1(db,namespace=authority.namespace,plan=plan,installed_readers=self._readers)
                envelope=replace(model.envelope,authority=authority)
                frame=freeze_domain_production_frame_v1(graph,db,envelope=envelope,current_owner=context['owner'],
                    scope=context['scope'],plan=plan,now_utc=context['now'],observed_originals=originals,installed_policy_refs=policies)
                return require_current_content_trace_v1(db,frame=frame,trace_ref=trace_ref,installed_readers=self._readers,capability=capability)
            finally:db.rollback()
        return graph._read_v2(authority,current_read,fence_observer=observe)
