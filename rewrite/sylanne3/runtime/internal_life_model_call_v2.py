"""Once model draft and sealed original for the installed Life V2 worker.

A draft is passive input. Only Core's current Graph verifier and real mTLS
model-egress admission authorize execution. The seal stores that real permit.
"""
import json
from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1,ModelEgressIntentV1
from ..authority_service.v2_model_egress_wire import to_wire
from ..authority_service.v2_contract import FencePermitV2,to_wire as fence_wire
from ..runtime_contracts import canonical_digest
from .internal_life_content_worker_v2 import read_committed_internal_life_request_v2,read_life_worker_original_v2,_record
from .internal_life_content_preparation_v1 import read_committed_internal_life_prepared_v1
from .jobs import get_job


def internal_life_model_draft_v2(db,*,namespace,issuer,job_id,metadata,epoch):
    if not db.in_transaction:raise ValueError('Life model draft requires an actual pinned SQL transaction')
    prepared,binding,request=read_committed_internal_life_request_v2(db,namespace=namespace,issuer=issuer,job_id=job_id)
    job=get_job(db,job_id)
    quote=issuer.resource_issuer.original_signed_quote(db,prepared.quote_id,prepared.quote_version)
    if (job.phase!='running' or job.fence!=1 or job.cancel_epoch!=0 or job.lease_holder!=binding.worker_subject
            or request.envelope.authority.actor!=binding.worker_subject or request.envelope.authority.worker_fence!=job.fence):
        raise ValueError('Life model actual acquired worker is not current')
    target=metadata.requirements
    sources=tuple(sorted((v.key.owner.subject,v.revision) for v in request.envelope.version_guard.read_versions
        if v.key.type_name=='memory.source' and v.revision>0))
    accesses=tuple(sorted((v.key.owner.subject,v.revision) for v in request.envelope.version_guard.read_versions
        if v.key.type_name=='memory.access' and v.revision>0))
    draft=ModelEgressDraftV1(target.authority_id,target.authority_namespace,binding.worker_subject,
        prepared.acquire_operation_id,prepared.call_id,request.digest,job_id,job.fence,
        tuple(ref for ref,_ in sources),sources,accesses,request.envelope.version_guard.access_epoch,
        request.envelope.version_guard.delete_epoch,epoch.revision,metadata.graph_revision,
        target.activation_generation,target.revocation_epoch,target.deletion_seq,target.execution_seq,
        quote.parent_budget_lease_ref,prepared.prepare_operation_id,prepared.reservation_digest,
        tuple(sorted(quote.ceiling.items())),request.provider_id,request.model_id,
        json.loads(prepared.frozen_json)['provider_config_digest'],request.max_output_tokens,
        acquire_operation_id=prepared.acquire_operation_id,binding_digest=binding.digest)
    return prepared,binding,request,draft


def seal_internal_life_model_call_v2(db,*,namespace,issuer,job_id,intent,permit,metadata,epoch):
    if type(intent) is not ModelEgressIntentV1 or type(permit) is not FencePermitV2:
        raise TypeError('actual typed Core model intent and permit required')
    prepared,binding,request,draft=internal_life_model_draft_v2(db,namespace=namespace,issuer=issuer,
        job_id=job_id,metadata=metadata,epoch=epoch)
    if ModelEgressDraftV1.from_intent(intent)!=draft:
        raise ValueError('Core Life model original differs from its durable acquired request')
    return _record(db,namespace,issuer,'call',job_id,{'schema':'d06.internal-life-worker-model-call.v2',
        'prepared_digest':prepared.digest,'binding_digest':binding.digest,'request_digest':request.digest,
        'intent':to_wire(intent),'permit':fence_wire(permit)})
