"""Life content preparation in the installed current-production transaction.

The public request is a locator. Current Episode, causal originals, Source,
Owner and the actual installed workflow are re-read before once reservation.
This is queued preparation, never content-completed or numerical C02.
"""
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import json
import sqlite3

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..model_broker.internal_life_content_v1 import (
    WORK_KIND, TEMPLATE_VERSION, TEMPLATE_DIGEST, InternalLifeContentInputV1,
    internal_life_content_ids_v1, freeze_internal_life_content_request_v1,
    thaw_internal_life_content_request_v1, internal_life_content_ids_for_occurrence_v1,
)
from .d06_internal_life_encoding_v1 import (
    EncodeInternalLifeRequestV1, read_current_internal_life_encoding_cause_v1,
)
from .d06_internal_life_episode_v2 import EPISODE, _sha
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .budget import get_budget_lease, require_budget_family_admissible, reserve_budget
from .jobs import PersistentJob, create_job, get_job
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA, runtime_job_key, job_graph_write
from .issuers import ResourceQuote
from .domain_production_contracts_v1 import StagedDomainOperationV1, CurrentOperationFrameV1
from ..model_broker.internal_life_content_v1 import FrozenInternalLifeContentRequestV1

OPERATION = 'prepare_internal_life_content'
TABLE = 'graph_internal_life_content_originals_v1'
SIGN_KIND = 'd06.internal-life-content-original.v1'
DDL = f'''CREATE TABLE {TABLE} (
    bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL,
    original_ref TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
    signature TEXT NOT NULL, PRIMARY KEY(bot,persona,kind,original_ref))'''
TRIGGERS = tuple(f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} "
    "BEGIN SELECT RAISE(ABORT,'Life content original is immutable'); END" for action in ('UPDATE','DELETE'))


@dataclass(frozen=True, slots=True)
class PrepareInternalLifeContentRequestV1:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        EncodeInternalLifeRequestV1(self.episode_ref, self.causal_operation_id)


@dataclass(frozen=True, slots=True)
class InternalLifeContentPreparedV1:
    namespace: NamespaceId
    activity_id: str
    installation_id: str
    job_id: str
    prepare_operation_id: str
    acquire_operation_id: str
    action_id: str
    call_id: str
    episode_ref: str
    occurrence_digest: str
    owner_head_digest: str
    activation_generation: int
    graph_incarnation: str
    frozen_json: str
    frozen_digest: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_digest: str
    provider_config_ref: str
    schema: str = 'd06.internal-life-content-prepared.v1'

    def __post_init__(self):
        from ..authority_service.contract import identifier
        if (self.schema != 'd06.internal-life-content-prepared.v1' or type(self.namespace) is not NamespaceId
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.quote_version) is not int or self.quote_version != 1):
            raise ValueError('Life content prepared scope/version differs')
        for name in ('activity_id','installation_id','job_id','prepare_operation_id','acquire_operation_id',
                     'action_id','call_id','quote_id','provider_config_ref','graph_incarnation'):
            identifier(getattr(self,name),name)
        for name in ('occurrence_digest','owner_head_digest','frozen_digest','quote_digest','reservation_digest'):
            _sha(getattr(self,name))
        frozen = thaw_internal_life_content_request_v1(json.loads(self.frozen_json))
        event = frozen.input.cause.occurrence.event
        ids = internal_life_content_ids_v1(frozen.input.cause)
        if (canonical_serialize(plain_v1(frozen)) != self.frozen_json or frozen.digest != self.frozen_digest
                or self.episode_ref != frozen.input.episode_version.key.token
                or self.occurrence_digest != frozen.input.occurrence_digest
                or (self.namespace,self.activity_id,self.installation_id,self.activation_generation,self.graph_incarnation) !=
                    (event.namespace,event.activity.activity_id,frozen.installation_id,event.activation_generation,event.graph_incarnation)
                or (self.job_id,self.prepare_operation_id,self.acquire_operation_id,self.action_id,self.call_id,self.quote_id) !=
                    tuple(ids[name] for name in ('job','prepare','acquire','action','call','quote'))):
            raise ValueError('Life prepared result differs from its complete immutable occurrence/once binding')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def require_internal_life_content_schema_v1(db):
    with sqlite3.connect(':memory:') as expected:
        expected.execute(DDL)
        for ddl in TRIGGERS: expected.execute(ddl)
        sql='SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name'
        if tuple(db.execute(sql,(TABLE,))) != tuple(expected.execute(sql,(TABLE,))):
            raise ValueError('Life content original exact DDL/immutable triggers differ')


def install_internal_life_content_schema_v1(db):
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    for ddl in TRIGGERS: db.execute(ddl.replace('CREATE TRIGGER ','CREATE TRIGGER IF NOT EXISTS ',1))
    require_internal_life_content_schema_v1(db)


def decode_internal_life_prepared_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    result=decode_typed_production_value_v1(raw,InternalLifeContentPreparedV1)
    if canonical_serialize(plain_v1(result)) != canonical_serialize(raw):
        raise ValueError('Life content prepared wire differs')
    return result


def read_internal_life_prepared_v1(db, *, namespace, issuer, job_id):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:
        return None
    require_internal_life_content_schema_v1(db)
    row=db.execute(f"SELECT payload_json,payload_digest,signature FROM {TABLE} WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",
        (*namespace.as_tuple,job_id)).fetchone()
    if row is None: return None
    raw=json.loads(row[0]); prepared=decode_internal_life_prepared_v1(raw)
    if (canonical_serialize(raw)!=row[0] or canonical_digest(raw)!=row[1]
            or prepared.namespace!=namespace or prepared.job_id!=job_id):
        raise ValueError('Life content signed preparation selector differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,'prepared',job_id,row[1])),row[2])
    return prepared


def _record_prepared(db, issuer, prepared):
    if not db.in_transaction:
        raise ValueError('Life preparation requires the actual producing SQL transaction')
    require_internal_life_content_schema_v1(db)
    old=read_internal_life_prepared_v1(db,namespace=prepared.namespace,issuer=issuer,job_id=prepared.job_id)
    if old is not None:
        if old!=prepared: raise ValueError('Life once preparation cannot change its original')
        return
    wire=canonical_serialize(plain_v1(prepared));digest=canonical_digest(json.loads(wire))
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((prepared.namespace,'prepared',prepared.job_id,digest)))
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',
        (*prepared.namespace.as_tuple,'prepared',prepared.job_id,wire,digest,signature))


def read_plan_internal_life_content_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d06_internal_life_episode_v2 import internal_life_episode_read_inputs_v2, PROVENANCE, decode_internal_life_value_v2
    from .d01_production_operations_v1 import raw_head_value_v1
    if type(request) is not PrepareInternalLifeContentRequestV1 or operation_kind!=OPERATION:
        raise TypeError('exact Life content preparation locator required')
    keys,roots,originals=internal_life_episode_read_inputs_v2(db,namespace,request.episode_ref)
    key=AtomKey.from_token(request.episode_ref)
    proof=decode_internal_life_value_v2(PROVENANCE,raw_head_value_v1(db,namespace,AtomKey(key.owner,PROVENANCE,'record')))
    # Derive unqualified absent-job locators from actual stored provenance.
    # No fabricated preparation original or before-state value is needed.
    ids=internal_life_content_ids_for_occurrence_v1(proof)
    if proof.event.activity.activity_id!=activity_id or proof.event.causal_operation_id!=request.causal_operation_id:
        raise ValueError('Life content read plan is not its actual occurrence')
    return production_read_plan_v1(('d01.persona_activation.v1','d03.self_perspective.v1'),
        (*keys,owner_grant_key(*namespace.as_tuple),runtime_job_key(*namespace.as_tuple,activity_id,ids['job'])),
        roots,(*originals,request.causal_operation_id))


def prepare_internal_life_content_in_transaction_v1(db, *, frame, request, installed_readers, installed_bundle):
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.model_workflows_v3 import AdminModelWorkflowsV3
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..model_broker.natural_reply import NaturalReplyInstallationV2
    read=CurrentDomainReadV1(frame);read.check(db)
    if (type(request) is not PrepareInternalLifeContentRequestV1 or type(installed_bundle) is not AdminInstallationBundle
            or type(installed_bundle.model_workflows) not in (AdminModelWorkflowsV3,AdminModelWorkflowsV4,AdminModelWorkflowsV5,AdminModelWorkflowsV6,AdminModelWorkflowsV7)):
        raise TypeError('actual installed Life content request/workflow version required')
    cause=read_current_internal_life_encoding_cause_v1(db,frame=frame,
        request=EncodeInternalLifeRequestV1(request.episode_ref,request.causal_operation_id),installed_readers=installed_readers)
    ns,now=frame.envelope.authority.namespace,frame.now_utc
    ids=internal_life_content_ids_v1(cause)
    if frame.envelope.identity.operation_id!=ids['prepare']:
        raise ValueError('Life occurrence cannot obtain another charge from a new caller operation')
    workflow=installed_bundle.model_workflows.life_content
    if (workflow is None or (workflow.work_kind,workflow.purpose,workflow.template_version)!=
            (WORK_KIND,'consolidation',TEMPLATE_VERSION)
            or frame.envelope.authority.purpose!='consolidation' or len(frame.envelope.authority.audience)!=1
            or frame.envelope.authority.audience[0] not in workflow.audiences):
        raise ValueError('actual installed Life content workflow/purpose/audience is unavailable')
    read.source_family(db,cause.occurrence.episode.source_refs,purpose='consolidation')
    install_internal_life_content_schema_v1(db)
    prior=read_internal_life_prepared_v1(db,namespace=ns,issuer=installed_readers.issuer,job_id=ids['job'])
    if prior is not None:
        if (prior.occurrence_digest!=canonical_digest(plain_v1(cause.occurrence.event))
                or prior.owner_head_digest!=frame.owner_guard.owner_head_digest
                or prior.provider_config_ref!=workflow.provider_config_ref):
            raise ValueError('Life current qualification/once original drifted; HOLD')
        return prior,thaw_internal_life_content_request_v1(json.loads(prior.frozen_json)),get_job(db,prior.job_id),()
    grant=installed_readers.issuer.current_budget_grant(db,frame.envelope.parent_budget_lease_ref)
    lease=get_budget_lease(db,grant.lease_id);require_budget_family_admissible(db,lease.lease_id)
    if (lease.state!='active' or WORK_KIND not in grant.allowed_work_kinds
            or now+workflow.timeout_seconds>=grant.valid_until_utc
            or db.execute('SELECT 1 FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
                (lease.lease_id,ids['prepare'])).fetchone() is not None):
        raise ValueError('Life content budget/reservation is unavailable or lacks its original; HOLD')
    def version(ref):
        atom=read.head(db,AtomKey.from_token(ref),required=True)
        return GraphVersion(atom.key,atom.revision)
    event=cause.occurrence.event
    deadline=min(frame.envelope.deadline_utc,grant.valid_until_utc)
    input=InternalLifeContentInputV1(cause,version(request.episode_ref),version(event.self_mapping_ref),
        version(event.perspective_ref),frame.envelope.authority.audience[0],now,deadline,
        canonical_digest({'source_roots':cause.occurrence.episode.source_refs,
            'actual_read_versions':frame.envelope.version_guard.read_versions,
            'audience':frame.envelope.authority.audience,'purpose':'consolidation'}))
    frozen=freeze_internal_life_content_request_v1(input,NaturalReplyInstallationV2(
        installed_bundle.installation_policy.installation_id,workflow.provider_config_digest,
        workflow.provider_id,workflow.model_id,workflow.max_output_tokens))
    ceiling=dict(workflow.quote_ceiling)
    quote=ResourceQuote(ids['quote'],1,*ns.as_tuple,event.activity.activity_id,ids['prepare'],None,
        lease.lease_id,WORK_KIND,ids['snapshot'],deadline,workflow.provider_config_ref,
        runtime_job_key(*ns.as_tuple,event.activity.activity_id,ids['job']).token,(),(),ceiling,None,deadline)
    installed_readers.resource_issuer.issue_quote(db,quote)
    reservation=canonical_digest({'schema':'d06.internal-life-content-reservation.v1',
        'occurrence':input.occurrence_digest,'frozen_digest':frozen.digest,'quote':plain_v1(quote)})
    reserve_budget(db,lease.lease_id,ids['prepare'],reservation,ceiling)
    job=PersistentJob(ids['job'],ids['prepare'],event.activity.activity_id,None,*ns.as_tuple,ids['snapshot'],
        'queued',WORK_KIND,{'episode_ref':request.episode_ref,'causal_operation_id':request.causal_operation_id},None,
        datetime.fromtimestamp(deadline,timezone.utc).isoformat().replace('+00:00','Z'),lease.lease_id,
        workflow.provider_config_ref,{'resource_quote':ids['quote']+':1'},None,None,0,0,{},None)
    prepared=InternalLifeContentPreparedV1(ns,event.activity.activity_id,frozen.installation_id,
        ids['job'],ids['prepare'],ids['acquire'],ids['action'],ids['call'],request.episode_ref,
        input.occurrence_digest,frame.owner_guard.owner_head_digest,event.activation_generation,event.graph_incarnation,
        canonical_serialize(plain_v1(frozen)),frozen.digest,ids['quote'],1,canonical_digest(quote),reservation,workflow.provider_config_ref)
    create_job(db,job,'create:'+ids['prepare'],reservation);_record_prepared(db,installed_readers.issuer,prepared)
    return prepared,frozen,job,(job_graph_write(job),)


@dataclass(frozen=True, slots=True)
class InternalLifeContentPreparationStageV1:
    stage: StagedDomainOperationV1
    prepared: InternalLifeContentPreparedV1
    frozen: FrozenInternalLifeContentRequestV1
    job: PersistentJob
    frame: CurrentOperationFrameV1


def stage_prepare_internal_life_content_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
    if type(installed_readers) is not InstalledD06StructuredExperienceReadersV1:
        raise TypeError('actual Life current readers required')
    bundle=installed_readers.life_content_bundle
    prepared,frozen,job,writes=prepare_internal_life_content_in_transaction_v1(db,frame=frame,
        request=request,installed_readers=installed_readers,installed_bundle=bundle)
    if not writes:
        raise MissingProductionOriginalV1('existing_life_content_preparation_readonly_recovery')
    provider=D11RuntimeProvider()
    primary=stage_result_v1(frame,'d11',OPERATION,request,writes=writes,
        provenance={'prepared_digest':prepared.digest,'episode_ref':prepared.episode_ref,
            'occurrence_digest':prepared.occurrence_digest,'job_ref':writes[0].key.token},
        proposal_schema=D11_PROPOSAL_SCHEMA,proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(primary.proposals[0],frame.snapshot)
    return InternalLifeContentPreparationStageV1(primary,prepared,frozen,job,frame)


def verify_internal_life_content_preparation_in_transaction_v1(db, staged, readers, bundle):
    if type(staged) is not InternalLifeContentPreparationStageV1 or not db.in_transaction:
        raise ValueError('actual installed Life prepared stage/transaction required')
    frame,prepared=staged.frame,staged.prepared
    request=PrepareInternalLifeContentRequestV1(prepared.episode_ref,
        staged.frozen.input.cause.occurrence.event.causal_operation_id)
    actual,frozen,job,writes=prepare_internal_life_content_in_transaction_v1(db,frame=frame,
        request=request,installed_readers=readers,installed_bundle=bundle)
    quote=readers.resource_issuer.original_signed_quote(db,prepared.quote_id,prepared.quote_version)
    reservation=db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (quote.parent_budget_lease_ref,prepared.prepare_operation_id)).fetchone()
    workflow=bundle.model_workflows.life_content
    if (writes or actual!=prepared or frozen!=staged.frozen or job!=staged.job
            or frame.envelope.identity.operation_id!=prepared.prepare_operation_id
            or staged.stage.domain!='d11' or staged.stage.operation_kind!=OPERATION
            or staged.stage.proposals[0].envelope!=frame.envelope
            or tuple(write for proposal in staged.stage.proposals for write in proposal.typed_writes)!=(job_graph_write(job),)
            or canonical_digest(quote)!=prepared.quote_digest
            or (quote.operation_id,quote.work_kind,quote.resource_ref,quote.graph_job_ref)!=
                (prepared.prepare_operation_id,WORK_KIND,workflow.provider_config_ref,job_graph_write(job).key.token)
            or reservation!=(prepared.reservation_digest,canonical_serialize(dict(quote.ceiling)),'reserved')):
        raise ValueError('Life queued preparation is not its current signed quote/reservation/job original')
    return staged


def record_internal_life_preparation_after_cas_v1(db, *, prepared, issuer, receipt):
    from .d04_root_original_store_v1 import _receipt
    from .domain_production_originals_v1 import _receipt_wire
    actual=_receipt(db,prepared.namespace,prepared.prepare_operation_id)
    job=get_job(db,prepared.job_id);write=job_graph_write(job)
    if (not db.in_transaction or receipt!=actual or receipt.status!='committed'
            or receipt.operation_id!=prepared.prepare_operation_id
            or receipt.write_versions!=(GraphVersion(write.key,1),)
            or job.phase!='queued' or job.operation_id!=prepared.prepare_operation_id):
        raise ValueError('Life preparation lacks its exact actual Graph CAS/job member')
    history=db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',
        (write.key.token,)).fetchone()
    if history!=(canonical_serialize(write.value),1,prepared.prepare_operation_id):
        raise ValueError('Life preparation current CAS history does not contain its exact queued job')
    payload={'schema':'d06.internal-life-content-prepare-commit.v1','prepared_digest':prepared.digest,
        'operation_id':prepared.prepare_operation_id,'receipt':_receipt_wire(receipt),
        'receipt_digest':canonical_digest(receipt)}
    wire=canonical_serialize(payload);digest=canonical_digest(payload)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((prepared.namespace,'prepare_commit',prepared.job_id,digest)))
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',
        (*prepared.namespace.as_tuple,'prepare_commit',prepared.job_id,wire,digest,signature))
    # This certifies same-transaction membership. The caller's COMMIT and a
    # separate durable reader remain required before business consumption.
    return digest


def read_committed_internal_life_prepared_v1(db, *, namespace, issuer, job_id):
    """Historical COMMIT proof, no current Source/Owner permission issuance."""
    from .d04_root_original_store_v1 import _receipt
    from .domain_production_originals_v1 import _receipt_wire, read_adopted_domain_operation_v1
    prepared=read_internal_life_prepared_v1(db,namespace=namespace,issuer=issuer,job_id=job_id)
    if prepared is None: raise ValueError('Life content actual prepared original absent')
    row=db.execute(f"SELECT payload_json,payload_digest,signature FROM {TABLE} WHERE bot=? AND persona=? AND kind='prepare_commit' AND original_ref=?",
        (*namespace.as_tuple,job_id)).fetchone()
    if row is None: raise ValueError('Life content preparation was never durably committed')
    raw=json.loads(row[0]);receipt=_receipt(db,namespace,prepared.prepare_operation_id)
    expected={'schema':'d06.internal-life-content-prepare-commit.v1','prepared_digest':prepared.digest,
        'operation_id':prepared.prepare_operation_id,'receipt':_receipt_wire(receipt),'receipt_digest':canonical_digest(receipt)}
    original=read_adopted_domain_operation_v1(db,namespace,prepared.prepare_operation_id)
    if (canonical_serialize(raw)!=row[0] or canonical_digest(raw)!=row[1]
            or canonical_serialize(raw)!=canonical_serialize(expected) or original is None
            or original['domain']!='d11' or original['operation_kind']!=OPERATION
            or original['receipt']!=receipt):
        raise ValueError('Life content durable production/event receipt identity differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,'prepare_commit',job_id,row[1])),row[2])
    return prepared
