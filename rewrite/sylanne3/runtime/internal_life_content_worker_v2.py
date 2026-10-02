"""FIRST Life worker acquisition with distinct Owner and TLS worker roles.

The Owner command authorizes the original once job. Only its private installed
issuance selects the execution subject; external requests contain no worker.
V1 Owner-held acquisitions are historical and cannot be silently migrated.
"""
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import sqlite3

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import GraphVersion
from ..runtime_contracts import DomainBundle, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize, schema_hash
from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1
from .domain_production_contracts_v1 import CurrentOperationFrameV1
from .internal_life_worker_binding_v2 import (InternalLifeWorkerBindingV2, InternalLifeWorkerFrameV2,
    decode_internal_life_worker_binding_v2, require_installed_life_worker_v2)
from .internal_life_content_preparation_v1 import PrepareInternalLifeContentRequestV1, read_plan_internal_life_content_v1
from .internal_life_content_worker_v1 import _current, read_life_worker_original_v1
from .jobs import acquire_job, get_job
from .d11_types import TYPE_SCHEMA_HASHES, job_graph_write
from .reply_model_job import reply_request_wire_v1
from .natural_reply_job_v2 import _request_from_wire
from ..model_broker.internal_life_content_v1 import WORK_KIND, TEMPLATE_DIGEST

OPERATION='acquire_internal_life_content_v2'
PROPOSAL_SCHEMA='d11.internal-life-worker-acquisition.proposal.v2'
PROPOSAL_HASH=schema_hash({'schema':PROPOSAL_SCHEMA,'job_schema_hash':TYPE_SCHEMA_HASHES['runtime.job'],
    'transition':'once_prepare/queued_to_running/Owner_authorizes/installed_worker_executes'})
TABLE='graph_internal_life_worker_originals_v2'
SIGN_KIND='d06.internal-life-worker-original.v2'
COLUMNS=('bot','persona','kind','job_id','payload_json','payload_digest','signature')
DDL=f'''CREATE TABLE {TABLE} (
    bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL, job_id TEXT NOT NULL,
    payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL, signature TEXT NOT NULL,
    PRIMARY KEY(bot,persona,kind,job_id))'''
TRIGGERS=tuple(f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} "
    "BEGIN SELECT RAISE(ABORT,'Life worker original is immutable'); END" for action in ('UPDATE','DELETE'))


@dataclass(frozen=True, slots=True)
class AcquireInternalLifeContentRequestV2:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        EncodeInternalLifeRequestV1(self.episode_ref,self.causal_operation_id)


@dataclass(frozen=True, slots=True)
class InternalLifeContentAcquisitionStageV2:
    stage: object
    prepared: object
    frozen: object
    job: object
    request: object
    frame: InternalLifeWorkerFrameV2
    issuance: object


def require_life_worker_schema_v2(db):
    with sqlite3.connect(':memory:') as expected:
        expected.execute(DDL)
        for sql in TRIGGERS:expected.execute(sql)
        query='SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name'
        if tuple(db.execute(query,(TABLE,)))!=tuple(expected.execute(query,(TABLE,))):
            raise ValueError('Life worker original exact DDL/immutable triggers differ')


def install_life_worker_schema_v2(db):
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    for sql in TRIGGERS:db.execute(sql.replace('CREATE TRIGGER ','CREATE TRIGGER IF NOT EXISTS ',1))
    require_life_worker_schema_v2(db)


def validate_life_worker_inventory_row_v2(columns,row):
    from .d06_internal_life_episode_v2 import _sha
    from ..runtime_contracts import NamespaceId
    from .domain_production_originals_v1 import _receipt,_receipt_wire
    if tuple(columns)!=COLUMNS or type(row) is not tuple or len(row)!=7:
        raise ValueError('Life worker inventory closed columns differ')
    bot,persona,kind,job,encoded,digest,signature=row;ns=NamespaceId(bot,persona)
    _sha(digest);_sha(signature)
    if type(encoded) is not str or len(encoded)>1048576:
        raise ValueError('Life worker original exceeds its finite byte bound')
    raw=json.loads(encoded)
    if canonical_serialize(raw)!=encoded or canonical_digest(raw)!=digest:
        raise ValueError('Life worker inventory bytes/commitment differ')
    if kind=='binding':
        b=decode_internal_life_worker_binding_v2(raw)
        if b.namespace!=ns or b.job_id!=job:raise ValueError('Life worker binding crossed its actual inventory scope')
    elif kind=='request':
        if type(raw) is not dict or set(raw)!={'schema','binding_digest','prepared_digest','request_digest','wire'}:
            raise ValueError('Life worker model input closed fields differ')
        if raw['schema']!='d06.internal-life-worker-request.v2':raise ValueError('Life worker model input version differs')
        for name in ('binding_digest','prepared_digest','request_digest'):_sha(raw[name])
        model=_request_from_wire(raw['wire'])
        suffix=job.removeprefix('life-content-job:')
        if (len(suffix)!=48 or any(c not in '0123456789abcdef' for c in suffix)
                or job!='life-content-job:'+suffix or model.envelope.authority.namespace!=ns
                or model.identity.operation_id!='life-content-acquire:'+suffix
                or model.call_id!='life-content-call:'+suffix or model.identity.phase!='internal_life_content_v2'
                or model.envelope.authority.purpose!='consolidation' or model.envelope.authority.worker_fence!=1
                or model.prompt_template_digest!=TEMPLATE_DIGEST or model.digest!=raw['request_digest']
                or canonical_serialize(reply_request_wire_v1(model.envelope,model))!=raw['wire']):
            raise ValueError('Life worker request changed its closed once execution identity')
    elif kind=='acquire_commit':
        if type(raw) is not dict or set(raw)!={'schema','binding_digest','prepared_digest','request_digest','operation_id','receipt','receipt_digest'}:
            raise ValueError('Life worker commit closed fields differ')
        if raw['schema']!='d06.internal-life-worker-acquire-commit.v2':raise ValueError('Life worker commit version differs')
        for name in ('binding_digest','prepared_digest','request_digest','receipt_digest'):_sha(raw[name])
        receipt=_receipt(raw['receipt'])
        if (receipt.status!='committed' or receipt.operation_id!=raw['operation_id']
                or canonical_digest(receipt)!=raw['receipt_digest']
                or canonical_serialize(_receipt_wire(receipt))!=canonical_serialize(raw['receipt'])
                or len(receipt.write_versions)!=1 or receipt.write_versions[0].revision!=2
                or receipt.write_versions[0].key.type_name!='runtime.job' or receipt.write_versions[0].key.name!=job
                or NamespaceId.from_key(receipt.write_versions[0].key)!=ns):
            raise ValueError('Life worker commit does not bind its actual once job member')
    elif kind=='call':
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire,to_wire
        from ..authority_service.v2_contract import FencePermitV2,from_wire as fence_from_wire,to_wire as fence_to_wire
        if type(raw) is not dict or set(raw)!={'schema','prepared_digest','binding_digest','request_digest','intent','permit'}:
            raise ValueError('Life worker call original closed fields differ')
        if raw['schema']!='d06.internal-life-worker-model-call.v2':raise ValueError('Life worker call original version differs')
        for name in ('prepared_digest','binding_digest','request_digest'):_sha(raw[name])
        intent=from_wire(raw['intent'],ModelEgressIntentV1)
        permit=fence_from_wire(raw['permit'])
        if type(permit) is not FencePermitV2:
            raise ValueError('Life worker model call requires its exact original fence permit')
        if (intent.job_id!=job or intent.binding_digest!=raw['binding_digest']
                or intent.request_digest!=raw['request_digest'] or permit.operation!='model_egress'
                or (permit.subject,permit.operation_id,permit.token,permit.fence_epoch,permit.revision)!=
                    (intent.subject,intent.operation_id,intent.fence_token,intent.fence_epoch,intent.fence_revision)
                or canonical_digest(asdict(permit.pinned_anchor))!=intent.anchor_digest
                or to_wire(intent)!=raw['intent'] or fence_to_wire(permit)!=raw['permit']):
            raise ValueError('Life worker call differs from its actual model permit')
    else:raise ValueError('unregistered Life worker original kind')
    return raw


def read_life_worker_original_v2(db,*,namespace,issuer,kind,job_id):
    if db.execute('SELECT 1 FROM sqlite_master WHERE type=? AND name=?',('table',TABLE)).fetchone() is None:return None
    require_life_worker_schema_v2(db)
    row=db.execute(f'SELECT payload_json,payload_digest,signature FROM {TABLE} WHERE bot=? AND persona=? AND kind=? AND job_id=?',
        (*namespace.as_tuple,kind,job_id)).fetchone()
    if row is None:return None
    raw=validate_life_worker_inventory_row_v2(COLUMNS,(*namespace.as_tuple,kind,job_id,*row))
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,kind,job_id,row[1])),row[2])
    return raw


def _record(db,namespace,issuer,kind,job_id,value):
    if not db.in_transaction:raise ValueError('Life worker original requires its actual acquisition transaction')
    require_life_worker_schema_v2(db)
    raw=plain_v1(value);encoded=canonical_serialize(raw);digest=canonical_digest(raw)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((namespace,kind,job_id,digest)))
    row=(*namespace.as_tuple,kind,job_id,encoded,digest,signature)
    validate_life_worker_inventory_row_v2(COLUMNS,row)
    old=read_life_worker_original_v2(db,namespace=namespace,issuer=issuer,kind=kind,job_id=job_id)
    if old is not None:
        if old!=raw:raise ValueError('Life worker once original cannot change')
        return old
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',row)
    return raw


def read_plan_internal_life_acquire_v2(db,*,namespace,activity_id,operation_kind,request):
    if operation_kind!=OPERATION or type(request) is not AcquireInternalLifeContentRequestV2:
        raise TypeError('exact installed Life V2 acquisition locator required')
    return read_plan_internal_life_content_v1(db,namespace=namespace,activity_id=activity_id,
        operation_kind='prepare_internal_life_content',request=PrepareInternalLifeContentRequestV1(request.episode_ref,request.causal_operation_id))


def _binding(issued,frame,prepared,frozen):
    from .internal_life_worker_binding_v2 import owner_lease_commitment_v2
    require_installed_life_worker_v2(issued,issued.runtime,frame)
    owner,scope=issued.owner,issued.scope
    return InternalLifeWorkerBindingV2(prepared.namespace,prepared.installation_id,issued.grant.manifest_digest,
        issued.grant.subject,canonical_digest(issued.grant),owner.principal,owner.actor,
        owner_lease_commitment_v2(owner),frame.owner_guard,
        canonical_digest(owner.target_admission),canonical_digest(owner.storage_admission),prepared.digest,
        prepared.occurrence_digest,prepared.episode_ref,prepared.job_id,prepared.prepare_operation_id,
        prepared.acquire_operation_id,prepared.call_id,prepared.quote_digest,prepared.reservation_digest,
        canonical_digest(scope.permit),canonical_digest(scope),scope.graph_revision,scope.graph_epoch.revision,
        scope.generation,prepared.graph_incarnation,min(frame.envelope.deadline_utc,frozen.input.expires_at_utc))


def _model(frame,prepared,frozen,workflow,job):
    from ..model_broker.broker import ModelCallRequest
    f,b=frame.owner_frame,frame.binding;key=job_graph_write(job).key
    if tuple(v for v in f.snapshot.versions if v.key==key)!=(GraphVersion(key,1),):
        raise ValueError('Life worker request lost its original queued-job read')
    guard=replace(f.envelope.version_guard,
        read_versions=tuple(GraphVersion(v.key,v.revision+1) if v.key==key else v for v in f.snapshot.versions),
        query_epochs=tuple(QueryEpoch(v.namespace,v.scope_ref,v.revision+1) for v in f.envelope.version_guard.query_epochs),
        resource_lease_versions=(VersionedRef(prepared.quote_id,prepared.quote_version),))
    envelope=replace(f.envelope,identity=replace(f.envelope.identity,phase='internal_life_content_v2'),
        authority=replace(f.envelope.authority,actor=b.worker_subject,worker_fence=job.fence,
            capability_ref='life-worker-binding:'+b.digest),version_guard=guard,deadline_utc=b.deadline_utc,
        monotonic_deadline=f.envelope.monotonic_deadline-(f.envelope.deadline_utc-b.deadline_utc))
    return ModelCallRequest(envelope,prepared.call_id,workflow.provider_id,workflow.model_id,
        frozenset(workflow.required_capabilities),workflow.privacy_tier,TEMPLATE_DIGEST,
        json.loads(frozen.wire_json),workflow.timeout_seconds,workflow.max_output_tokens)


def stage_acquire_internal_life_content_in_transaction_v2(db,*,frame,request,installed_readers):
    if type(request) is not AcquireInternalLifeContentRequestV2 or not db.in_transaction:
        raise ValueError('Life V2 worker requires its actual registered acquisition transaction')
    issued=installed_readers.life_worker_issuance_v2
    require_installed_life_worker_v2(issued,issued.runtime,frame)
    prepared,frozen,workflow=_current(db,frame,request,installed_readers)
    if (read_life_worker_original_v1(db,namespace=prepared.namespace,issuer=installed_readers.issuer,
            kind='request',ref=prepared.job_id) is not None
            or read_life_worker_original_v2(db,namespace=prepared.namespace,issuer=installed_readers.issuer,
                kind='binding',job_id=prepared.job_id) is not None):
        raise ValueError('Life occurrence already has an acquisition; explicit migration required, HOLD')
    job=get_job(db,prepared.job_id)
    if job is None or job.phase!='queued' or job.fence!=0 or job.cancel_epoch!=0:
        raise ValueError('Life worker cannot replace or reacquire its immutable once execution')
    binding=_binding(issued,frame,prepared,frozen)
    worker_frame=InternalLifeWorkerFrameV2(frame,binding)
    job=acquire_job(db,prepared.job_id,binding.worker_subject,
        now_utc=datetime.fromtimestamp(frame.now_utc,timezone.utc).isoformat().replace('+00:00','Z'),
        lease_seconds=min(3600,int(workflow.timeout_seconds)+120))
    model=_model(worker_frame,prepared,frozen,workflow,job)
    install_life_worker_schema_v2(db)
    _record(db,prepared.namespace,installed_readers.issuer,'binding',prepared.job_id,binding)
    _record(db,prepared.namespace,installed_readers.issuer,'request',prepared.job_id,
        {'schema':'d06.internal-life-worker-request.v2','binding_digest':binding.digest,
         'prepared_digest':prepared.digest,'request_digest':model.digest,
         'wire':canonical_serialize(reply_request_wire_v1(model.envelope,model))})
    primary=stage_result_v1(frame,'d11',OPERATION,request,writes=(job_graph_write(job),),
        provenance={'schema':'d06.internal-life-worker-acquisition.v2','binding':plain_v1(binding),
            'binding_digest':binding.digest,'request_digest':model.digest,'job_ref':job_graph_write(job).key.token},
        proposal_schema=PROPOSAL_SCHEMA,proposal_hash=PROPOSAL_HASH)
    validate_internal_life_acquisition_proposal_v2(primary.proposals[0],frame.snapshot,binding)
    return InternalLifeContentAcquisitionStageV2(primary,prepared,frozen,job,model,worker_frame,issued)


def validate_internal_life_acquisition_proposal_v2(proposal,snapshot,binding):
    from ..runtime_contracts import DomainProposal
    from ..graph_types import GraphSnapshot
    from .d11_types import _decode,RuntimeJobValue
    if (type(proposal) is not DomainProposal or type(snapshot) is not GraphSnapshot
            or type(binding) is not InternalLifeWorkerBindingV2
            or (proposal.domain,proposal.proposal_schema,proposal.proposal_schema_hash)!=('d11',PROPOSAL_SCHEMA,PROPOSAL_HASH)
            or len(proposal.typed_writes)!=1):
        raise ValueError('Life worker requires its independent dual-role proposal')
    w=proposal.typed_writes[0];v=_decode(w);before=snapshot.get(w.key);e=proposal.envelope
    if (type(v) is not RuntimeJobValue or before is None or not before.valid or before.revision!=1
            or w.key.type_name!='runtime.job' or w.key.name!=binding.job_id
            or (v.bot_id,v.persona_id,v.activity_id,v.effect_id,v.work_kind)!=
               (*binding.namespace.as_tuple,e.identity.activity_id,None,WORK_KIND)
            or (v.operation_id,e.identity.operation_id,e.identity.phase,e.authority.actor)!=
               (binding.prepare_operation_id,binding.acquire_operation_id,OPERATION,binding.owner_actor)
            or v.job_id!=binding.job_id or v.parent_budget_lease_ref!=e.parent_budget_lease_ref
            or w.dependencies or v.phase!='running' or v.fence!=1 or v.cancel_epoch!=0 or v.result_ref is not None
            or v.lease_holder!=binding.worker_subject or v.lease_expires_utc is None
            or before.value.get('phase')!='queued' or before.value.get('fence')!=0
            or before.value.get('lease_holder') is not None or before.value.get('lease_expires_utc') is not None):
        raise ValueError('Life dual-role acquisition changed its exact once job/Owner/worker')
    expected={**before.value,'phase':'running','fence':1,
        'lease_holder':v.lease_holder,'lease_expires_utc':v.lease_expires_utc}
    if canonical_serialize(w.value)!=canonical_serialize(expected):
        raise ValueError('Life worker acquisition changed fields outside its exact transition')
    return proposal


def require_exact_internal_life_acquisition_issuance_v2(witness,graph,bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or type(witness.stage) is not InternalLifeContentAcquisitionStageV2
            or witness.operation.operation_kind!=OPERATION or type(witness.request) is not AcquireInternalLifeContentRequestV2
            or witness.frame is not witness.stage.frame.owner_frame or witness.bundle is not bundle
            or witness.stage.stage.proposals!=bundle.proposals):
        raise ValueError('Life worker acquisition requires its exact active installed dual-role witness')
    issued=require_installed_life_worker_v2(witness.stage.issuance,witness.runtime,witness.frame)
    if (issued.owner is not witness.owner or issued.guard!=witness.guard or issued.scope is not witness.scope):
        raise ValueError('Life worker active Owner/permit delegation differs')
    return witness


def verify_internal_life_acquisition_in_transaction_v2(db,stage,readers):
    if type(stage) is not InternalLifeContentAcquisitionStageV2 or not db.in_transaction:
        raise ValueError('Life worker requires its actual acquired transaction')
    f=stage.frame.owner_frame
    issued=require_installed_life_worker_v2(stage.issuance,stage.issuance.runtime,f)
    prepared,frozen,workflow=_current(db,f,AcquireInternalLifeContentRequestV2(stage.prepared.episode_ref,
        stage.frozen.input.cause.occurrence.event.causal_operation_id),readers)
    b=_binding(issued,f,prepared,frozen)
    job=get_job(db,prepared.job_id);model=_model(stage.frame,prepared,frozen,workflow,job)
    actual_binding=read_life_worker_original_v2(db,namespace=prepared.namespace,issuer=readers.issuer,kind='binding',job_id=prepared.job_id)
    actual_request=read_life_worker_original_v2(db,namespace=prepared.namespace,issuer=readers.issuer,kind='request',job_id=prepared.job_id)
    if (prepared!=stage.prepared or frozen!=stage.frozen or b!=stage.frame.binding or job!=stage.job or model!=stage.request
            or actual_binding!=plain_v1(b) or actual_request!=
               {'schema':'d06.internal-life-worker-request.v2','binding_digest':b.digest,'prepared_digest':prepared.digest,
                'request_digest':model.digest,'wire':canonical_serialize(reply_request_wire_v1(model.envelope,model))}):
        raise ValueError('Life worker acquired originals/current qualification differ')
    validate_internal_life_acquisition_proposal_v2(stage.stage.proposals[0],f.snapshot,b)
    return stage


def internal_life_acquisition_bundle_v2(stage):
    if type(stage) is not InternalLifeContentAcquisitionStageV2:raise TypeError('exact Life worker stage required')
    return DomainBundle(stage.frame.owner_frame.envelope,stage.stage.proposals,(),(),(),(),(),
        (job_graph_write(stage.job).key.token,),())


def require_internal_life_acquisition_job_registration_v2(witness,db):
    require_exact_internal_life_acquisition_issuance_v2(witness,witness.graph,witness.bundle)
    if db is not witness.graph._GraphCoordinator__store._db or not db.in_transaction:
        raise ValueError('Life worker registration needs its actual SQL transaction')
    p=witness.stage.prepared;key=job_graph_write(witness.stage.job).key.token
    row=db.execute("SELECT operation_id FROM graph_bundle_refs WHERE bot=? AND persona=? AND ref_kind='persistent_job' AND ref=?",
        (*p.namespace.as_tuple,key)).fetchone()
    if row!=(p.prepare_operation_id,) or witness.bundle.persistent_job_refs!=(key,):
        raise ValueError('Life worker cannot register a second once job')
    return (key,)


def commit_internal_life_acquisition_v2(runtime,db,*,operation,request,preparation,readers,
        scope,owner,guard,metadata,epoch,process_lease,external_originals):
    from ..contracts import canonical_json
    from ..authority_service.v2_contract import to_wire
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1,_receipt_wire
    from .d11_types import reconcile_runtime_write
    verify_internal_life_acquisition_in_transaction_v2(db,preparation,readers)
    graph=runtime.graph;p=preparation.prepared;b=preparation.frame.binding
    attempt=db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
        (*p.namespace.as_tuple,p.acquire_operation_id)).fetchone()
    if attempt is None or attempt[1:]!=(scope.operation_id,canonical_json(to_wire(scope.permit))):
        raise ValueError('Life worker has no exact actual Owner command/permit')
    bundle=internal_life_acquisition_bundle_v2(preparation)
    reconcile_runtime_write(db,job_graph_write(preparation.job))
    witness=_ProductionCommitWitnessV1(runtime,graph,scope,preparation.frame.owner_frame,preparation,
        operation,request,owner,guard,bundle,tuple(external_originals))
    finish='sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':p.acquire_operation_id,'request_digest':attempt[0],'permit_token':scope.permit.token})
    _ACTIVE[id(witness)]=witness
    try:
        receipt=graph._commit_domain_bundle_fenced(bundle,process_lease,in_transaction=True,
            v2_write=(metadata,epoch,'finish:'+scope.operation_id,finish,canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.owner_frame.now_utc,domain_production_issuance_v1=witness)
    finally:_ACTIVE.pop(id(witness),None)
    _record(db,p.namespace,readers.issuer,'acquire_commit',p.job_id,
        {'schema':'d06.internal-life-worker-acquire-commit.v2','binding_digest':b.digest,
         'prepared_digest':p.digest,'request_digest':preparation.request.digest,'operation_id':p.acquire_operation_id,
         'receipt':_receipt_wire(receipt),'receipt_digest':canonical_digest(receipt)})
    original=record_adopted_domain_operation_v1(db,preparation.stage,receipt)
    return {'schema':'sylanne.domain-production-receipt.v1','domain':'d11','operation_kind':OPERATION,
        'operation_id':p.acquire_operation_id,'activity_id':p.activity_id,'original_ref':original.original_ref,
        'original_digest':original.original_digest,'receipt':_receipt_wire(receipt),'receipt_digest':canonical_digest(receipt),
        'job_states':[[p.job_id,'running']],'coverage':'deferred',
        'missing_inputs':['actual_internal_life_content_terminal_and_adoption'],'continuation_ref':p.job_id,'outbox':[]}


def read_committed_internal_life_request_v2(db,*,namespace,issuer,job_id):
    """Authenticate durable originals and history, never current execution rights."""
    from .internal_life_content_preparation_v1 import read_committed_internal_life_prepared_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1,_receipt_wire
    from .d04_root_original_store_v1 import _receipt
    from ..model_broker.internal_life_content_v1 import thaw_internal_life_content_request_v1
    from .d11_types import runtime_job_key
    p=read_committed_internal_life_prepared_v1(db,namespace=namespace,issuer=issuer,job_id=job_id)
    braw=read_life_worker_original_v2(db,namespace=namespace,issuer=issuer,kind='binding',job_id=job_id)
    saved=read_life_worker_original_v2(db,namespace=namespace,issuer=issuer,kind='request',job_id=job_id)
    commit=read_life_worker_original_v2(db,namespace=namespace,issuer=issuer,kind='acquire_commit',job_id=job_id)
    if any(v is None for v in (braw,saved,commit)):
        raise ValueError('Life worker input lacks its complete durable acquisition originals')
    b=decode_internal_life_worker_binding_v2(braw);model=_request_from_wire(saved['wire'])
    receipt=_receipt(db,namespace,p.acquire_operation_id)
    adopted=read_adopted_domain_operation_v1(db,namespace,p.acquire_operation_id)
    key=runtime_job_key(*namespace.as_tuple,p.activity_id,p.job_id)
    actual=db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?',
        (key.token,2)).fetchone()
    if adopted is None or actual is None:raise ValueError('Life worker input has no actual shared COMMIT/history')
    authority=adopted['payload']['authority']
    expected_authority={**authority,'actor':b.worker_subject,'worker_fence':1,
        'capability_ref':'life-worker-binding:'+b.digest}
    expected_reads=tuple(GraphVersion(v.key,v.revision+1) if v.key==key else v for v in receipt.read_versions)
    frozen=thaw_internal_life_content_request_v1(json.loads(p.frozen_json))
    history=json.loads(actual[0])
    if (commit!={'schema':'d06.internal-life-worker-acquire-commit.v2','binding_digest':b.digest,
            'prepared_digest':p.digest,'request_digest':model.digest,'operation_id':p.acquire_operation_id,
            'receipt':_receipt_wire(receipt),'receipt_digest':canonical_digest(receipt)}
            or saved['binding_digest']!=b.digest or saved['prepared_digest']!=p.digest
            or saved['request_digest']!=model.digest or b.prepared_digest!=p.digest
            or (b.namespace,b.episode_ref,b.occurrence_digest,b.job_id,b.prepare_operation_id,b.acquire_operation_id,b.call_id)!=
               (p.namespace,p.episode_ref,p.occurrence_digest,p.job_id,p.prepare_operation_id,p.acquire_operation_id,p.call_id)
            or b.quote_digest!=p.quote_digest or b.reservation_digest!=p.reservation_digest
            or b.installation_id!=p.installation_id or b.activation_generation!=p.activation_generation
            or b.graph_incarnation!=p.graph_incarnation or b.owner_guard.owner_head_digest!=p.owner_head_digest
            or adopted['domain']!='d11' or adopted['operation_kind']!=OPERATION or adopted['receipt']!=receipt
            or adopted['payload']['provenance']!={'schema':'d06.internal-life-worker-acquisition.v2',
                'binding':braw,'binding_digest':b.digest,'request_digest':model.digest,'job_ref':key.token}
            or receipt.write_versions!=(GraphVersion(key,2),) or actual[1:]!=(1,p.acquire_operation_id)
            or canonical_serialize(adopted['payload']['writes'])!=canonical_serialize([
                {'key':key.token,'value':history,'dependencies':[]}])
            or history['phase']!='running' or history['fence']!=1 or history['cancel_epoch']!=0
            or history['lease_holder']!=b.worker_subject
            or canonical_serialize(plain_v1(model.envelope.authority))!=canonical_serialize(expected_authority)
            or model.envelope.version_guard.read_versions!=expected_reads
            or model.envelope.deadline_utc!=b.deadline_utc or model.payload!=json.loads(frozen.wire_json)
            or model.identity.operation_id!=p.acquire_operation_id or model.call_id!=p.call_id):
        raise ValueError('Life worker durable request/Owner delegation/COMMIT/history bindings differ')
    return p,b,model
