"""Derive the next fixed Contact phase from its actual causal outbox."""
from dataclasses import dataclass
from ..domains.d08.contact_plan_v1 import contact_ids_v1
from .domain_production_followups_v1 import DomainFollowupCommandV1, DomainFollowupResolutionV1
from .contact_plan_adoption_v2 import AdoptCurrentContactExpressionPlanRequestV2, read_adopted_contact_plan_v2, TABLE
from .contact_product_adapter_v2 import PrepareCurrentContactModelRequestV2
from .contact_model_job_v2 import contact_model_ids_v2
from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
from .contact_paid_original_v2 import read_contact_original_v2
from .contact_model_preparation_v2 import read_paid_contact_result_v2
from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
from .jobs import get_job
from .d01_production_operations_v1 import CurrentDomainReadV1


@dataclass(frozen=True, slots=True)
class ContactFollowupCommandV1(DomainFollowupCommandV1):
    operation_id: str = ''


def resolve_contact_action_followup_v1(db, frame, event, original, continuation, graph):
    read = CurrentDomainReadV1(frame)
    ns = frame.envelope.authority.namespace
    request = original['payload']['request']
    opportunity = read.head(db,request['opportunity_ref'],required=True)
    ids = contact_ids_v1(ns,opportunity.value['source_ref'],opportunity.value['subject_ref'],'private_text')
    audience = original['payload']['authority']['audience'][0]
    target = request['opportunity_ref']
    def wait(reason):
        return DomainFollowupResolutionV1('waiting_for_original',(),(target,),(reason,),continuation)
    def command(kind, typed, operation_id, *, final=False):
        child = ContactFollowupCommandV1('d08' if kind != 'prepare_contact_model_v2' else 'd11',kind,typed,
            ids['activity'],audience,operation_id=operation_id)
        return DomainFollowupResolutionV1('ready' if final else 'partial',(child,),(target,),
            () if final else ('actual_next_contact_phase_original',),None if final else continuation)
    if not frame.now_utc < opportunity.value['expires_at']:
        return wait('current_contact_opportunity_expired')
    from .contact_plan_adoption_v3 import TABLE as PLAN3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        present=[]
        for table in (TABLE,PLAN3):
            exists=meter.read_fixed_row(db,'sqlite_master',('name',),"type='table' AND name=?",(table,))
            if exists is not None and meter.read_fixed_row(db,table,('contact_id',),
                    'bot=? AND persona=? AND contact_id=?',(*ns.as_tuple,ids['contact']))is not None:
                present.append(table)
    if len(present)>1:raise ValueError('Contact has conflicting actual immutable Plan versions')
    if not present:
        return command('adopt_contact_expression_plan_v2',AdoptCurrentContactExpressionPlanRequestV2(
            request['opportunity_ref'],request['contact_policy_ref'],request['target_route_ref']),ids['plan'])
    from .domain_background_read_v3 import require_background_contact_source_component_v3
    require_background_contact_source_component_v3(db,ns,ids['contact'],'contact_followup')
    issuer = graph._GraphCoordinator__d11_issuer
    plan, expression, raw, plan_digest = read_adopted_contact_plan_v2(db,namespace=ns,contact_id=ids['contact'],issuer=issuer)
    if not frame.now_utc < plan.valid_until_utc:
        return wait('actual_contact_plan_deadline_expired')
    for phase in ('contact_generation','contact_review'):
        model_ids = contact_model_ids_v2(plan,phase)
        prepared = read_contact_original_v2(db,issuer,ns,'prepared',model_ids['job'])
        if prepared is None:
            return command('prepare_contact_model_v2',PrepareCurrentContactModelRequestV2(plan.contact_id,phase),model_ids['prepare'])
        job = get_job(db,model_ids['job'])
        if job is None or job.phase != 'completed':
            return wait('actual_' + phase + '_terminal_and_paid_cost')
        actual = read_paid_contact_result_v2(db,namespace=ns,contact_id=plan.contact_id,phase=phase,
            issuer=issuer,resource_issuer=graph._GraphCoordinator__d02_issuer)
        if phase == 'contact_generation' and actual[2].status != 'untrusted_content_candidate':
            return wait('actual_contact_generation_no_contact_hold')
        if phase == 'contact_review' and actual[2].verdict != 'pass':
            return wait('actual_contact_review_' + actual[2].verdict + '_hold')
    content = read_contact_reviewed_content_original_v2(db,namespace=ns,contact_id=plan.contact_id,
        issuer=issuer,resource_issuer=graph._GraphCoordinator__d02_issuer)
    from .contact_continuation_v1 import read_contact_segment_original_v1,_point,_prefix
    from ..runtime_contracts import canonical_digest
    first=None
    for index,item in enumerate(content.segments):
        segment=read_contact_segment_original_v1(db,namespace=ns,contact_id=plan.contact_id,segment_index=index,issuer=issuer)
        if segment is None:
            if index:
                _prefix(db,first=first,index=index,issuer=issuer)
            return command('prepare_contact_dispatch_v3',PrepareCurrentContactDispatchRequestV3(plan.contact_id,index),
                item.operation_id,final=False)
        if index==0:first=segment
        if (segment.operation_id,segment.effect_id,segment.reviewed_content_digest)!=(item.operation_id,item.segment.effect_id,content.digest):
            raise ValueError('Contact controller immutable segment does not belong to this paid whole manifest')
        cost='contact-cost-'+canonical_digest((ns,item.segment.effect_id,'initial'))[:48]
        stored=_point(db,table='graph_contact_effect_originals_v1',columns=('payload_json','payload_digest','signature'),
            key_columns=('bot','persona','kind','original_ref'),key=(*ns.as_tuple,'settlement',cost))
        if stored is None:return wait('actual_contact_segment_observation_and_settlement')
        attempt=_point(db,table='graph_contact_effect_accounting_attempts_v1',columns=('origin_digest','fact_digest','request_json','state'),
            key_columns=('bot','persona','operation_id'),key=(*ns.as_tuple,cost))
        if attempt is None or attempt[3]!='committed':return wait('actual_contact_segment_accounting_commit')
        _prefix(db,first=first,index=index+1,issuer=issuer)
    return wait('actual_contact_all_graph_settled_pending_core_and_delivery_verification')
