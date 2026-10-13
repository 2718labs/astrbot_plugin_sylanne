"""Closed original-result shape for the independent Life content worker.

Requests are locators, never read permissions. A service must separately load
the actual prepared/acquired originals, current Owner/Source qualifications,
egress ledger, terminal and paid cost before returning this response. A model
terminal does not establish a content adoption COMMIT or numeric Life C02.
"""
from dataclasses import dataclass, fields
import math

from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier
from .v2_model_egress_contract import ModelEgressIntentV1, ModelEgressObservationV1, ModelTerminalReceiptV2
from .v2_model_egress_wire import to_wire as terminal_wire, from_wire as terminal_from_wire

SCHEMA = 'd06.internal-life-content-model-result-read.v1'
PURPOSE = 'internal_life_content_consolidation_v1'


def _sha(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Life model-result original commitment differs')


def internal_life_content_read_attempt_id_v1(consumer_operation_id, attempt):
    identifier(consumer_operation_id,'consumer_operation_id')
    if type(attempt) is not int or not 1<=attempt<=64:
        raise ValueError('Life model-result attempt is outside its finite sequence')
    return 'life-content-result-read:'+canonical_digest({
        'schema':SCHEMA,'consumer_operation_id':consumer_operation_id,'attempt':attempt})[:48]


@dataclass(frozen=True, slots=True)
class InternalLifeModelResultReadRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    episode_ref: str
    occurrence_digest: str
    causal_operation_id: str
    job_id: str
    acquire_operation_id: str
    original_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    consumer_operation_id: str
    read_attempt_id: str
    purpose: str = PURPOSE
    schema: str = SCHEMA

    def __post_init__(self):
        from ..runtime.d06_internal_life_episode_v2 import EPISODE
        if (self.schema!=SCHEMA or self.purpose!=PURPOSE or type(self.namespace) is not NamespaceId):
            raise ValueError('Life model-result reader scope differs')
        for name in ('authority_id','authority_namespace','installation_id','causal_operation_id',
                'job_id','acquire_operation_id','original_operation_id','call_id','consumer_operation_id','read_attempt_id'):
            identifier(getattr(self,name),name)
        if type(self.episode_ref) is not str or len(self.episode_ref)>4096:
            raise ValueError('Life model-result Episode locator differs')
        episode=AtomKey.from_token(self.episode_ref)
        if episode.type_name!=EPISODE or NamespaceId.from_key(episode)!=self.namespace:
            raise ValueError('Life model-result Episode type/namespace differs')
        for value in (self.occurrence_digest,self.binding_digest,self.model_request_digest):_sha(value)
        suffix=self.job_id.removeprefix('life-content-job:')
        if (self.job_id!='life-content-job:'+suffix or len(suffix)!=48
                or any(c not in '0123456789abcdef' for c in suffix)
                or (self.original_operation_id,self.acquire_operation_id,self.call_id,self.consumer_operation_id)!=
                    ('life-content-prepare:'+suffix,'life-content-acquire:'+suffix,
                     'life-content-call:'+suffix,'life-content-adopt:'+suffix)
                or not any(self.read_attempt_id==internal_life_content_read_attempt_id_v1(self.consumer_operation_id,n)
                    for n in range(1,65))):
            raise ValueError('Life model-result selector is outside its original once family')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class InternalLifeModelResultReadV1:
    request: InternalLifeModelResultReadRequestV1
    observation: ModelEgressObservationV1
    terminal_receipt: ModelTerminalReceiptV2
    read_at_utc: float
    current_scope_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        request,observation,receipt=self.request,self.observation,self.terminal_receipt
        _sha(self.current_scope_digest)
        if (self.schema!=SCHEMA or type(request) is not InternalLifeModelResultReadRequestV1
                or type(observation) is not ModelEgressObservationV1 or type(receipt) is not ModelTerminalReceiptV2
                or observation.status!='completed' or type(self.read_at_utc) not in (int,float)
                or not math.isfinite(self.read_at_utc) or self.read_at_utc<=0
                or (observation.authority_id,observation.namespace,observation.operation_id,
                    observation.call_id,observation.request_digest)!=
                    (request.authority_id,request.authority_namespace,request.acquire_operation_id,
                     request.call_id,request.model_request_digest)
                or (receipt.call_id,receipt.request_digest,receipt.observation_digest,receipt.installation_id)!=
                    (request.call_id,request.model_request_digest,observation.digest,request.installation_id)):
            raise ValueError('Life actual completed model result/terminal differ')

    def require_original(self,intent,prepared,frozen):
        """Structural comparison only; arguments must come from authenticated SQL."""
        from ..runtime.internal_life_content_preparation_v1 import InternalLifeContentPreparedV1
        from ..model_broker.internal_life_content_v1 import FrozenInternalLifeContentRequestV1
        request=self.request
        if (type(intent) is not ModelEgressIntentV1 or type(prepared) is not InternalLifeContentPreparedV1
                or type(frozen) is not FrozenInternalLifeContentRequestV1
                or frozen.digest!=prepared.frozen_digest
                or frozen.input.episode_version.key.token!=prepared.episode_ref
                or (request.namespace,request.installation_id,request.episode_ref,request.occurrence_digest,
                    request.causal_operation_id,request.job_id,request.original_operation_id,
                    request.acquire_operation_id,request.call_id,request.binding_digest)!=
                    (prepared.namespace,prepared.installation_id,prepared.episode_ref,prepared.occurrence_digest,
                     frozen.input.cause.occurrence.event.causal_operation_id,prepared.job_id,
                     prepared.prepare_operation_id,prepared.acquire_operation_id,prepared.call_id,prepared.digest)
                or (intent.authority_id,intent.namespace,intent.job_id,intent.operation_id,
                    intent.acquire_operation_id,intent.call_id,intent.request_digest,intent.binding_digest)!=
                    (request.authority_id,request.authority_namespace,prepared.job_id,prepared.acquire_operation_id,
                     prepared.acquire_operation_id,prepared.call_id,request.model_request_digest,prepared.digest)
                or self.observation.subject!=intent.subject):
            raise ValueError('Life delivered result differs from its actual occurrence/prepared once call')


def internal_life_result_to_wire_v1(value):
    if type(value) is InternalLifeModelResultReadRequestV1:return plain_v1(value)
    if type(value) is not InternalLifeModelResultReadV1:raise TypeError('closed Life model-result DTO required')
    data=plain_v1(value)
    from .v2_model_egress_contract import model_observation_to_wire_v1
    data['observation']=model_observation_to_wire_v1(value.observation)
    data['terminal_receipt']=terminal_wire(value.terminal_receipt)
    return data


def _shape(raw,kind):
    if type(raw) is not dict or set(raw)!={field.name for field in fields(kind)}:
        raise ValueError('Life model-result wire exact fields differ')
    return dict(raw)


def internal_life_result_from_wire_v1(raw,kind):
    if kind not in (InternalLifeModelResultReadRequestV1,InternalLifeModelResultReadV1):
        raise ValueError('unsupported Life model-result wire type')
    data=_shape(raw,kind)
    if kind is InternalLifeModelResultReadRequestV1:
        data['namespace']=NamespaceId(**_shape(data['namespace'],NamespaceId))
    else:
        data['request']=internal_life_result_from_wire_v1(data['request'],InternalLifeModelResultReadRequestV1)
        from .v2_model_egress_contract import model_observation_from_wire_v1
        data['observation']=model_observation_from_wire_v1(data['observation'])
        if len(data['observation'].usage)>64 or len(data['observation'].cost)>64:
            raise ValueError('Life model-result observation amount pairs differ')
        data['terminal_receipt']=terminal_from_wire(data['terminal_receipt'],ModelTerminalReceiptV2)
    result=kind(**data)
    if canonical_serialize(internal_life_result_to_wire_v1(result))!=canonical_serialize(raw):
        raise ValueError('Life model-result wire is noncanonical')
    return result
