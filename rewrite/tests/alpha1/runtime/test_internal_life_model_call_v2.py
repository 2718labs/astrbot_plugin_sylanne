"""Unissued typed Model/Fence row codec; no permission or admission assertion."""
from copy import deepcopy
from dataclasses import asdict
import pytest
from test_internal_life_worker_binding_v2 import fixture,D
from sylanne3.authority_service.v2_contract import FencePermitV2,to_wire as fence_wire
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
from sylanne3.authority_service.v2_model_egress_wire import to_wire as model_wire
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime.internal_life_content_worker_v2 import COLUMNS,validate_life_worker_inventory_row_v2
from sylanne3.runtime_contracts import canonical_digest,canonical_serialize


def row():
    prepared,frame,_,_=fixture();binding=frame.binding
    anchor=RestoreAnchor('authority','ns:authority',1,'deletion',0,'genesis','execution',0,'genesis',0,'unissued-proof')
    permit=FencePermitV2('authority','ns:authority',binding.worker_subject,'holder',1,'model_egress',
        prepared.acquire_operation_id,'a'*48,2,0,anchor)
    intent=ModelEgressIntentV1('authority','ns:authority',binding.worker_subject,prepared.acquire_operation_id,
        prepared.call_id,D,prepared.job_id,1,permit.token,permit.fence_epoch,permit.revision,canonical_digest(asdict(anchor)),
        ('source',),(('source',1),),(('source',1),),0,0,7,12,1,0,0,0,'lease',prepared.prepare_operation_id,
        prepared.reservation_digest,(('output_tokens',1),),'provider','model',D,1,
        acquire_operation_id=prepared.acquire_operation_id,binding_digest=binding.digest)
    raw={'schema':'d06.internal-life-worker-model-call.v2','prepared_digest':prepared.digest,
        'binding_digest':binding.digest,'request_digest':D,'intent':model_wire(intent),'permit':fence_wire(permit)}
    return prepared,raw


def validate(prepared,raw):
    return validate_life_worker_inventory_row_v2(COLUMNS,(*prepared.namespace.as_tuple,'call',prepared.job_id,
        canonical_serialize(raw),canonical_digest(raw),D))


def test_call_row_roundtrip_uses_real_discriminated_fence_codec():
    prepared,raw=row()
    assert validate(prepared,raw)==raw


@pytest.mark.parametrize('change',['bool_revision','wrong_permit','wrong_binding','extra_field','wrong_kind','typed_anchor_hash'])
def test_rehashed_call_row_refuses_permit_and_request_drift(change):
    p,raw=row();raw=deepcopy(raw)
    if change=='bool_revision':raw['permit']['revision']=False
    elif change=='wrong_permit':raw['permit']['operation_id']='another-operation'
    elif change=='wrong_binding':raw['binding_digest']='e'*64
    elif change=='extra_field':raw['permit']['caller_allow']=True
    elif change=='wrong_kind':raw['permit']['kind']='not-a-fence'
    else:
        from sylanne3.authority_service.v2_contract import from_wire
        raw['intent']['anchor_digest']=canonical_digest(from_wire(raw['permit']).pinned_anchor)
    with pytest.raises((ValueError,TypeError)):validate(p,raw)
