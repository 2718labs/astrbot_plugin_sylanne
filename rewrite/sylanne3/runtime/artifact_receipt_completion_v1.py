"""Finish a V3 Artifact cycle only from its actual delivered receipt turn.

This explicit operation leaves the old natural C5/C6 completion contract intact.
Adapter acceptance and unresolved sends never close the foreground job.
"""
from dataclasses import dataclass,replace
import json

from ..graph_types import AtomKey
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from .artifact_completion_receipt_v1 import (DeriveArtifactCompletionReceiptRequestV1,receipt_ids_v1,
    read_current_artifact_completion_receipt_v1)
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,production_read_plan_v1

OPERATION='finish_artifact_receipt_cycle_v1'


@dataclass(frozen=True,slots=True)
class FinishArtifactReceiptCycleRequestV1:
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):receipt_ids_v1(self.selector)


def finish_operation_id_v1(selector):return receipt_ids_v1(selector)['receipt']+':finish'


def require_delivered_artifact_receipt_v1(db,*,namespace,receipt):
    from .artifact_receipt_dispatch_v1 import recover_artifact_receipt_dispatch_candidate_in_transaction_v1
    from .foreground_cycle_v1 import _require_delivered_turn_history_v1
    from ..authority_service.v2_contract import MutationReceiptV2,from_wire,to_wire
    from .d13_outbound_observation_v1 import TABLE
    actual=recover_artifact_receipt_dispatch_candidate_in_transaction_v1(db,namespace,receipt.message_operation_id)
    if (actual is None or actual.evidence.receipt_digest!=receipt.digest or actual.evidence.effect_id!=receipt.effect_id
            or actual.evidence.receipt_source_ref!=receipt.source_ref
            or actual.evidence.completion_digest!=receipt.completion_digest
            or actual.evidence.completion_receipt_digest!=receipt.completion_receipt_digest):
        raise MissingProductionOriginalV1('actual_committed_same_receipt_message_batch')
    rows=db.execute('SELECT observation_digest,source_ref,slot_ref,batch_ref,observation_json,original_json,original_digest '
        'FROM '+TABLE+" WHERE bot=? AND persona=? AND final_operation_id=? AND json_extract(observation_json,'$.pending.platform_observation.outcome')='delivered' LIMIT 2",
        (*namespace.as_tuple,receipt.message_operation_id)).fetchall()
    if len(rows)!=1:raise MissingProductionOriginalV1('actual_delivered_Artifact_receipt_not_accepted_or_unknown')
    digest,source_ref,slot_ref,batch_ref,encoded,original_json,original_digest=rows[0]
    observed=from_wire(json.loads(encoded));original=json.loads(original_json)
    if (type(observed) is not MutationReceiptV2 or observed.durable_state!='committed'
            or canonical_serialize(to_wire(observed))!=encoded or canonical_digest(observed)!=digest
            or canonical_serialize(original)!=original_json or canonical_digest(original)!=original_digest):
        raise ValueError('Artifact delivery lost actual immutable observation/adoption commitments')
    observation=observed.pending.platform_observation
    if (observed.pending.phase!='observed' or observation is None or observation.outcome!='delivered'
            or (observation.binding.origin.operation_id,observation.binding.origin.effect_id)!=(receipt.message_operation_id,receipt.effect_id)
            or observation.binding.origin.payload_digest.removeprefix('sha256:')!=actual.evidence.payload_digest
            or batch_ref!=actual.evidence.batch_ref or original['schema']!='d13.outbound_adoption.v1'
            or (original['source_ref'],original['slot_ref'],original['batch_ref'],original['observation_digest'])!=(source_ref,slot_ref,batch_ref,digest)):
        raise ValueError('Artifact delivery crossed its actual message/receipt/payload/turn')
    _require_delivered_turn_history_v1(db,namespace,original['operation_id'],source_ref,slot_ref)
    return original


def _current_completion_v1(db,*,namespace,selector,issuer,installed_bundle,owner_guard,now_utc,audiences):
    receipt=read_current_artifact_completion_receipt_v1(db,namespace=namespace,selector=selector,issuer=issuer,
        installed_bundle=installed_bundle,owner_guard=owner_guard,now_utc=now_utc,audiences=audiences)
    delivery=require_delivered_artifact_receipt_v1(db,namespace=namespace,receipt=receipt)
    return receipt,delivery


def stage_finish_artifact_receipt_cycle_v1(db,*,frame,request,installed_readers):
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    from .jobs import get_job,_utc
    from .d11_types import D11_PROPOSAL_SCHEMA,D11RuntimeProvider,job_graph_write
    if type(request) is not FinishArtifactReceiptCycleRequestV1 or type(installed_readers) is not InstalledArtifactDraftModelReadersV1:
        raise TypeError('receipt completion requires its exact installed Artifact readers')
    read=CurrentDomainReadV1(frame);read.check(db);ns=frame.envelope.authority.namespace
    if frame.envelope.identity.operation_id!=finish_operation_id_v1(request.selector):
        raise ValueError('receipt completion changed its original once identity')
    receipt,delivery=_current_completion_v1(db,namespace=ns,selector=request.selector,issuer=installed_readers.issuer,
        installed_bundle=installed_readers.installed_bundle,owner_guard=frame.owner_guard,now_utc=frame.now_utc,
        audiences=frame.envelope.authority.audience)
    job=get_job(db,AtomKey.from_token(request.selector.task.cycle_job_ref).name)
    read.head(db,job_graph_write(job).key,required=True)
    old=foreground_cycle_from_wire_v1(job.continuation)
    if (type(old.call_plan) is not ForegroundCallPlanV3 or old.call_plan.phase_group.selector!=request.selector
            or old.pending_effect_refs or old.wait is not None or job.phase!='running' or job.cancel_epoch
            or _utc(job.lease_expires_utc,'lease_expires_utc').timestamp()<=frame.now_utc):
        raise MissingProductionOriginalV1('actual_running_uncancelled_V3_cycle_without_pending_unknown_effects')
    from .d07_reflection_execution_v1 import require_no_pending_self_reflection_v3
    require_no_pending_self_reflection_v3(db,frame=frame,job=job,continuation=old,issuer=installed_readers.issuer,installed_bundle=installed_readers.installed_bundle)
    read.committed_operation(db,receipt.message_operation_id)
    read.source_family(db,(receipt.source_ref,),purpose='expression')
    completed=replace(old,stage='completed',stage_cursor=old.stage_cursor+1,
        completed_operation_refs=tuple(dict.fromkeys((*old.completed_operation_refs,receipt.message_operation_id))))
    updated=replace(job,phase='completed',continuation=plain_v1(completed),result_ref=receipt.message_operation_id,
        wake_condition=None,lease_holder=None,lease_expires_utc=None)
    return stage_result_v1(frame,'d11',OPERATION,request,writes=(job_graph_write(updated),),
        provenance={'artifact_receipt_completion':receipt,'delivery_operation_id':delivery['operation_id'],'continuation':completed},
        proposal_schema=D11_PROPOSAL_SCHEMA,proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)


def read_plan_finish_artifact_receipt_cycle_v1(db,*,namespace,request,installed_readers,now_utc,audiences):
    from .artifact_completion_receipt_v1 import read_plan_artifact_completion_receipt_v1
    base=read_plan_artifact_completion_receipt_v1(db,namespace=namespace,
        request=DeriveArtifactCompletionReceiptRequestV1(request.selector),installed_readers=installed_readers,now_utc=now_utc,audiences=audiences)
    ids=receipt_ids_v1(request.selector)
    from ..memory_types import source_key,access_key
    sk=source_key(*namespace.as_tuple,ids['source_id'])
    return production_read_plan_v1(base.fixed_type_ids,tuple(dict.fromkeys((*base.exact_keys,sk,
        access_key(*namespace.as_tuple,ids['source_id'])))),tuple(dict.fromkeys((*base.source_roots,sk.token))),base.required_original_refs)


def qualify_artifact_receipt_completion_foreground_v1(db,*,request,continuation,issuer,installed_bundle,owner_guard,now_utc):
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    if type(continuation.call_plan) is not ForegroundCallPlanV3:raise ValueError('receipt completion cannot upgrade an old cycle')
    selector=continuation.call_plan.phase_group.selector
    receipt,delivery=_current_completion_v1(db,namespace=request.namespace,selector=selector,issuer=issuer,
        installed_bundle=installed_bundle,owner_guard=owner_guard,now_utc=now_utc,audiences=request.audiences)
    body=FinishArtifactReceiptCycleRequestV1(selector)
    if (request.operation_kind!=OPERATION or request.operation_id!=finish_operation_id_v1(selector)
            or request.plan_ref!=selector.plan_ref or request.purpose!='consolidation'
            or request.draft_root_registration_ref!=selector.task.root_registration_ref
            or request.c02_operation_id!=selector.task.c02_operation_id
            or request.parent_budget_lease_ref!=continuation.call_plan.parent_budget_lease_ref
            or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(OPERATION),body)):
        raise ValueError('receipt completion changed its exact original task/message/Root/current request')
    return {receipt.source_ref,*(head.key.token for head,_ in receipt.parent_source_heads)},receipt.original_deadline_utc
