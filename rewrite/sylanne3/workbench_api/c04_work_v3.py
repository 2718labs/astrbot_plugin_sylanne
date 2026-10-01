"""Explicit Owner policy and exact original C04 work controls."""
from dataclasses import fields, asdict
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyV1
from ..runtime.c04_current_trigger_v3 import CurrentC04TriggerV3
from ..runtime.c04_v3_contracts import AssociationBudgetV3

ACTIONS={'c04_cpu_policy':'c04.cpu_policy.install','c04_prepare':'c04.internal_work.prepare','c04_advance':'c04.internal_work.prepare'}
INPUTS={'c04_cpu_policy':frozenset({'policy'}),'c04_prepare':frozenset({'request'}),'c04_advance':frozenset({'original_operation_id'})}


def _exact(raw,cls):
    if type(raw) is not dict or set(raw)!={field.name for field in fields(cls)}:
        raise ValueError('C04 explicit versioned fields differ')
    return dict(raw)


def validate_c04_input_v3(action,raw):
    if action not in ACTIONS or type(raw) is not dict or set(raw)!=INPUTS[action]:raise ValueError('C04 command fields differ')
    if action=='c04_cpu_policy':
        value=_exact(raw['policy'],C04InternalCpuQuotePolicyV1)
        value['namespace']=NamespaceId(**_exact(value['namespace'],NamespaceId))
        return C04InternalCpuQuotePolicyV1(**value)
    if action=='c04_prepare':
        value=_exact(raw['request'],CurrentC04TriggerV3)
        value['budget']=AssociationBudgetV3(**_exact(value['budget'],AssociationBudgetV3))
        if type(value['context_tags']) is not list or len(value['context_tags'])>32:raise ValueError('bounded explicit C04 tags required')
        value['context_tags']=tuple(value['context_tags'])
        return CurrentC04TriggerV3(**value)
    value=raw['original_operation_id']
    if type(value) is not str or not 1<=len(value)<=128:raise ValueError('exact C04 original operation required')
    return value


def execute_c04_work_v3(issuer,*,session,action,scope,purpose,audience,operation_id,input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    request=validate_c04_input_v3(action,input_data)
    capability=ACTIONS[action]
    if (audience!='owner' or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token or not session.allows(scope,capability,purpose,audience)):
        return _unavailable('signed_c04_owner_capability_unavailable')
    grant=issuer._resolve(session,scope,purpose,audience,domains=('d02','d04','d06','d07','d11','d12'))
    if grant is None or capability not in grant.capabilities:return _unavailable('signed_c04_owner_capability_unavailable')
    graph=issuer._coordinator
    if action=='c04_cpu_policy':
        result=graph.adopt_current_c04_cpu_policy_v3(grant.authority,grant.lease,operation_id=operation_id,policy=request)
    elif action=='c04_prepare':
        # Current source/route rights are derived by the coordinator. The W09
        # login remains Owner-only and never supplies a projection or work proof.
        result=graph.prepare_owner_c04_trigger_v3(grant.authority,grant.lease,operation_id=operation_id,request=request)
    else:
        result=graph.advance_owner_c04_work_v3(grant.authority,grant.lease,original_operation_id=request)
    return {'status':'ready','receipt':{'schema':'d12.c04-work-receipt.v3','operation_id':operation_id,
        'action':action,'input_digest':canonical_digest(input_data),'original':result,'original_digest':canonical_digest(result)}}
