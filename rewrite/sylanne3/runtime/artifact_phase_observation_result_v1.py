"""Independent Artifact judgments from actual paid D07 adoption originals.

Current readers requalify Source/Owner/job rights. Historical C09 readers use
separately authenticated Life and D07 indices from the same captured source.
No supplied result DTO or favorable subset of findings is accepted as evidence.
"""
from dataclasses import dataclass
import json
from ..graph_types import AtomKey,GraphVersion,Owner
from ..runtime_contracts import canonical_digest,canonical_serialize
from .d01_production_operations_v1 import MissingProductionOriginalV1,CurrentDomainReadV1
from .artifact_phase_observation_v1 import (KIND,observation_basis_from_wire_v1,
    require_artifact_phase_observation_basis_history_v1,semantic_observation_status_v1)
from .foreground_artifact_observation_plan_v3 import artifact_observation_ids_v1


@dataclass(frozen=True,slots=True)
class ArtifactPhaseSemanticObservationV1:
    condition_id:str
    basis_ref:str
    basis_digest:str
    terminal_ref:str
    terminal_digest:str
    prepared_digest:str
    interpretation_refs:tuple[str,...]
    interpretation_digests:tuple[str,...]
    status:str


def _d07_point_v1(db,*,namespace,kind,ref,issuer,read_d07_original):
    if issuer is not None:
        if read_d07_original is not None:raise ValueError('historical index cannot replace the actual signed D07 reader')
        from .d07_execution_v1 import read_d07_original_v1
        row=read_d07_original_v1(db,issuer,namespace,kind,ref)
    else:
        if read_d07_original is None:
            raise MissingProductionOriginalV1('actual_signed_D07_reader_or_authenticated_C09_D07_index')
        row=read_d07_original(namespace,kind,ref)
    if row is None:raise MissingProductionOriginalV1('actual_independent_artifact_observer_'+kind)
    if canonical_digest(row[0])!=row[1]:raise ValueError('independent observer original commitment differs')
    return row


def _actual_observation_v1(db,*,basis,issuer=None,read_d07_original=None,frame=None):
    from .artifact_phase_observation_execution_v1 import artifact_observation_prepared_from_wire_v3
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1,parse_d07_cognition_output_v1
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1,from_wire as result_from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_model_egress_wire import from_wire as intent_from_wire
    from .natural_reply_job_v2 import _request_from_wire
    from .d07_execution_v1 import decode_d07_execution_original_v1
    from .domain_production_read_plans_v1 import _committed
    ids=basis.ids;ns=basis.namespace
    def point(kind,ref):return _d07_point_v1(db,namespace=ns,kind=kind,ref=ref,issuer=issuer,read_d07_original=read_d07_original)
    raw,prepared_digest=point('prepared',ids['job'])
    prepared=artifact_observation_prepared_from_wire_v3(raw)
    if (prepared.digest!=prepared_digest or(prepared.namespace,prepared.operation_id,prepared.job_id,prepared.call_id,
            prepared.observation_basis_ref,prepared.observation_basis_digest,prepared.c02_operation_id)!=
            (ns,ids['operation'],ids['job'],ids['call'],basis.original_ref,basis.digest,basis.request.selector.task.c02_operation_id)):
        raise ValueError('independent observation prepared another task/phase/basis/call')
    frozen=thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    heads={head.key.token:(head.revision,digest) for head,digest in basis.source_heads}
    if (frozen.input.question_key!=basis.question_scope or frozen.input.question!=basis.question.question
            or frozen.input.target_ref!=basis.content_source_head.key.token
            or tuple(source.source_ref.ref for source in frozen.input.sources)!=basis.source_refs
            or any((source.source_ref.version,canonical_digest(source.record.to_dict()))!=heads[source.source_ref.ref]
                for source in frozen.input.sources)):
        raise ValueError('independent observation changed its exact frozen task/content sources')
    question=point('semantic_question',basis.ids['question'])
    from ..domains.d01.production_operations_v1 import plain_v1
    if question!=(plain_v1(basis.question),prepared.semantic_question_digest):
        raise ValueError('independent observation lacks its actual original registered question')
    request=_request_from_wire(canonical_serialize(point('request',ids['job'])[0]))
    intent=intent_from_wire(point('call',ids['job'])[0],ModelEgressIntentV1)
    actual_result,result_digest=point('result','d07-result:'+ids['call'])
    result=result_from_wire(actual_result,D07CognitionResultReadV1)
    result.require_original(intent,prepared)
    if (intent.request_digest!=request.digest or intent.budget_reservation_operation_id!=prepared.operation_id
            or intent.budget_reservation_digest!=prepared.reservation_digest
            or request.call_id!=prepared.call_id or dict(request.payload)!=json.loads(frozen.canonical_wire)
            or intent.budget_lease_id!=basis.parent_budget_lease_ref):
        raise ValueError('observer output crossed actual signed request/grant/lease/reservation')
    paid=point('paid_cost',ids['job'])[0];body=point('body_cost',ids['job'])[0]
    from .budget import BudgetReceipt
    receipt=BudgetReceipt(**paid['budget_receipt'])
    if (not paid['paid'] or paid['unknown_dimensions'] or body['unpaid_cost']
            or paid['prepared_digest']!=prepared.digest or paid['result_digest']!=result.observation.digest
            or paid['terminal_digest']!=canonical_digest(result.terminal_receipt)
            or (body['prepared_digest'],body['terminal_digest'],body['result_digest'])!=
                (prepared.digest,paid['terminal_digest'],paid['result_digest'])
            or(receipt.lease_id,receipt.operation_id,receipt.digest)!=(basis.parent_budget_lease_ref,prepared.operation_id,prepared.reservation_digest)
            or receipt.status not in{'settled','overrun'}):
        raise ValueError('observer evidence lacks exact independently known model/body settlement')
    from .model_cost_settlement import original_model_cost_operation_id_v1
    _committed(db,ns,original_model_cost_operation_id_v1(ns,prepared.call_id))
    terminal_ref='d07-terminal:'+ids['call'];terminal,terminal_digest=point('execution',terminal_ref)
    execution=decode_d07_execution_original_v1(terminal)
    response=json.loads(result.observation.result_json)
    if set(response)!={'text'}:raise ValueError('observer result is not its actual original model text')
    suggestion=parse_d07_cognition_output_v1(response['text'],frozen)
    if ((execution.operation_id,execution.activity_id,execution.result_digest,execution.parent_budget_ref,execution.source_refs)!=
            (prepared.operation_id,prepared.activity_id,suggestion.output_digest,basis.parent_budget_lease_ref,basis.source_refs)):
        raise ValueError('observer terminal differs from actual output/task/source/budget')
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    producer=read_adopted_domain_operation_v1(db,ns,basis.registration_operation_id)
    if producer is None:raise ValueError('observation lost its actual preparation CAS')
    prepared_at=producer['payload']['now_utc']
    if (not prepared_at<=result.timing.started_at<=result.timing.ended_at<basis.original_deadline_utc):
        raise ValueError('observer completed outside its unchanged original task deadline')
    _committed(db,ns,prepared.operation_id)
    if frame is not None:
        from .jobs import get_job
        job=get_job(db,prepared.job_id)
        if (job.phase!='completed' or job.cancel_epoch or job.result_ref!=terminal_ref
                or job.budget_ref!=basis.parent_budget_lease_ref):
            raise ValueError('observer evidence has no current uncancelled completed job')
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    ledger=_producer_original_point_v3(db,table='graph_bundle_operations',columns=('receipt_json',),
        key_columns=('bot','persona','operation_id'),key=(*ns.as_tuple,prepared.operation_id),
        legacy_reader=lambda:db.execute('SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
            (*ns.as_tuple,prepared.operation_id)).fetchone())
    stage=json.loads(ledger[0])
    if (stage['schema'],stage['phase'],stage['prepared_digest'])!=('d07.actual-graph-stage.v1','behavior_adopted',prepared.digest):
        raise ValueError('observer interpretation was not actually adopted by its final Graph stage')
    values=[];refs=[];digests=[]
    read=None if frame is None else CurrentDomainReadV1(frame)
    for index,finding in enumerate(suggestion.findings):
        name='d07-interpretation:'+canonical_digest((ns,prepared.call_id,suggestion.output_digest,index))[:48]
        key=AtomKey(Owner('activity',*ns.as_tuple,prepared.activity_id),'d07.current_interpretation.v1',name)
        adopted,adopted_digest=point('adopted',key.token)
        revision=adopted['interpretation_revision']
        if read is not None:
            atom=read.head(db,key,required=True);value=atom.value
            if atom.revision!=revision:raise ValueError('observer interpretation is no longer current')
        else:
            from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
            row=artifact_model_graph_point_v3(db,('value','valid'),token=key.token,revision=revision)
            if row is None or row[1]!=1:raise ValueError('observer historical interpretation is absent or invalid')
            value=json.loads(row[0])
        from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
        birth=artifact_model_graph_point_v3(db,('event_bot','event_persona','event_id','valid'),token=key.token,revision=revision)
        if birth!=(*ns.as_tuple,prepared.operation_id,1):
            raise ValueError('observer interpretation was not born in its exact actual adoption CAS')
        if (adopted['schema']!='d07.actual-cognition-adoption.v1'
                or(adopted['interpretation_ref'],adopted['interpretation_value_digest'],adopted['adoption_operation_id'],
                    adopted['prepared_digest'],adopted['actual_result_digest'],adopted['question_scope'],adopted['graph_receipt_digest'])!=
                   (key.token,canonical_digest(value),prepared.operation_id,prepared.digest,result_digest,
                    basis.question_scope,stage['graph_receipt_digest'])
                or value['question_key']!=basis.question_scope or value['activity_id']!=prepared.activity_id
                or(value['proposition'],value['stance'],value['evidence_status'],value['source_refs'],value['meaningful_unknowns'])!=
                    (finding.proposition,finding.stance,finding.evidence_status,list(finding.source_refs),list(suggestion.unknowns))):
            raise ValueError('observer cannot borrow or select another adopted semantic judgment')
        values.append(value);refs.append(key.token);digests.append(canonical_digest(value))
    status=semantic_observation_status_v1(tuple(values))
    if status in{'satisfied','violated'}and not set(basis.source_refs)<=set(ref for value in values for ref in value['source_refs']):
        status='unknown'
    return ArtifactPhaseSemanticObservationV1(basis.request.condition_id,basis.original_ref,basis.digest,
        terminal_ref,terminal_digest,prepared.digest,tuple(refs),tuple(digests),status)


def read_artifact_phase_semantic_observations_v1(db,*,namespace,selector,contract,observer_original_refs,
        issuer=None,read_life_original=None,read_d07_original=None,frame=None,installed_readers=None,
        now_utc=None,owner_guard=None,installed_bundle=None):
    from .artifact_phase_postconditions_v1 import _history_life_payload_point_v2
    from .artifact_phase_observation_v1 import require_current_artifact_phase_observation_basis_v1
    semantic=tuple(c for c in contract.conditions if c.phase_kind==selector.phase_kind and c.kind in{'tone','task_semantics'})
    results=[]
    for condition in semantic:
        ids=artifact_observation_ids_v1(selector,condition.condition_id)
        row=_history_life_payload_point_v2(db,('payload_json','producing_operation_id'),namespace=namespace,
            kind=KIND,ref=ids['basis'],issuer=issuer,read_original=read_life_original)
        if row is None:raise MissingProductionOriginalV1('actual_independent_artifact_observation_basis')
        basis=require_artifact_phase_observation_basis_history_v1(db,namespace=namespace,original_ref=ids['basis'],
            producing_operation_id=row[1],raw=json.loads(row[0]))
        if ((basis.request.selector,basis.request.contract_ref,basis.contract_digest,basis.condition_digest)!=
                (selector,contract.original_ref,contract.digest,canonical_digest(condition))):
            raise ValueError('semantic observation crossed actual contract/condition/check phase')
        if frame is not None:
            require_current_artifact_phase_observation_basis_v1(db,frame=frame,basis=basis,installed_readers=installed_readers)
        elif installed_bundle is not None:
            from .artifact_phase_observation_v1 import readonly_current_artifact_phase_observation_basis_v1
            readonly_current_artifact_phase_observation_basis_v1(db,basis=basis,issuer=issuer,
                installed_bundle=installed_bundle,owner_guard=owner_guard,now_utc=now_utc)
        results.append(_actual_observation_v1(db,basis=basis,issuer=issuer,read_d07_original=read_d07_original,frame=frame))
    expected=tuple(value.terminal_ref for value in results)
    if observer_original_refs!=expected:
        raise ValueError('assessment must consume every exact independent observer original once in registered order')
    return {value.condition_id:value for value in results}
