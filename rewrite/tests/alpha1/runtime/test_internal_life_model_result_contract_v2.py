"""Life-only model-result codec/once identities, without installed permissions.

Observation and terminal are synthetic structural originals. These cases do
not test Authority release, signatures, settlement or content adoption.
"""
from copy import deepcopy
from dataclasses import replace
import json
import pytest

from sylanne3.authority_service.internal_life_model_result_contract_v2 import (
    InternalLifeModelResultReadRequestV2,InternalLifeModelResultReadV2,
    internal_life_content_read_attempt_id_v2,internal_life_result_to_wire_v2,internal_life_result_from_wire_v2,
)
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressObservationV1,ModelTerminalReceiptV2
from sylanne3.graph_types import AtomKey
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


@pytest.fixture
def result():
    suffix='a'*48;consumer='life-content-adopt:'+suffix
    episode=AtomKey(source_key('bot','persona','source-1').owner,'memory.episode.v2','record')
    request=InternalLifeModelResultReadRequestV2('authority','bot/persona',NamespaceId('bot','persona'),
        'installation',episode.token,'b'*64,'actual-life-advance',
        'life-content-job:'+suffix,'life-content-acquire:'+suffix,'life-content-prepare:'+suffix,
        'life-content-call:'+suffix,'c'*64,'3'*64,'d'*64,consumer,internal_life_content_read_attempt_id_v2(consumer,1))
    observation=ModelEgressObservationV1('authority','bot/persona','reader',request.acquire_operation_id,
        request.call_id,request.model_request_digest,'completed','{"synthetic":true}',
        (('tokens',3),),(('units',1),),'synthetic-provider-call')
    receipt=ModelTerminalReceiptV2('e'*64,request.call_id,request.model_request_digest,'f'*64,
        observation.digest,'sha256:'+'0'*64,'installation','1'*64)
    return InternalLifeModelResultReadV2(request,observation,receipt,123.,'2'*64)


def test_complete_internal_life_result_roundtrip_preserves_originals(result):
    wire=json.loads(json.dumps(internal_life_result_to_wire_v2(result),allow_nan=False))
    actual=internal_life_result_from_wire_v2(wire,InternalLifeModelResultReadV2)
    assert actual==result and actual.observation.usage==(('tokens',3),)
    assert actual.terminal_receipt.observation_digest==actual.observation.digest


@pytest.mark.parametrize('change',('old_purpose','wrong_episode_type','cross_namespace','new_consumer',
    'different_call_family','different_job_family','noncanonical_attempt','extra_request',
    'extra_observation','amount_bool','pair_shape','unknown','terminal_digest','read_time_bool','extra_response'))
def test_internal_life_response_closed_scope_and_wire_tamper_refusal(result,change):
    wire=deepcopy(internal_life_result_to_wire_v2(result));request=wire['request']
    if change=='old_purpose':request['purpose']='first_ingress_c02'
    elif change=='wrong_episode_type':
        old=AtomKey.from_token(request['episode_ref']);request['episode_ref']=AtomKey(old.owner,'memory.episode.v1',old.name).token
    elif change=='cross_namespace':request['namespace']['bot_id']='other'
    elif change=='new_consumer':request['consumer_operation_id']='life-content-adopt:'+'b'*48
    elif change=='different_call_family':request['call_id']='life-content-call:'+'b'*48
    elif change=='different_job_family':request['job_id']='first-ingress-job'
    elif change=='noncanonical_attempt':request['read_attempt_id']='first-ingress-worker-read-'+'a'*48
    elif change=='extra_request':request['allow']=True
    elif change=='extra_observation':wire['observation']['extra']=True
    elif change=='amount_bool':wire['observation']['usage'][0][1]=True
    elif change=='pair_shape':wire['observation']['cost'][0].append(1)
    elif change=='unknown':wire['observation']['status']='unknown';wire['observation']['result_json']=None
    elif change=='terminal_digest':wire['terminal_receipt']['observation_digest']='3'*64
    elif change=='read_time_bool':wire['read_at_utc']=True
    else:wire['extra']=True
    with pytest.raises((ValueError,TypeError)):
        internal_life_result_from_wire_v2(wire,InternalLifeModelResultReadV2)


def test_life_read_attempt_sequence_is_bounded_and_cannot_be_bool(result):
    op=result.request.consumer_operation_id
    assert internal_life_content_read_attempt_id_v2(op,1)!=internal_life_content_read_attempt_id_v2(op,2)
    for attempt in (0,65,True,1.0):
        with pytest.raises(ValueError):internal_life_content_read_attempt_id_v2(op,attempt)


def test_old_worker_read_contract_does_not_accept_life_v2_dto(result):
    from sylanne3.authority_service.v2_worker_model_result_contract import from_wire,WorkerModelResultReadRequestV1
    with pytest.raises(ValueError):from_wire(internal_life_result_to_wire_v2(result.request),WorkerModelResultReadRequestV1)
