"""Explicit signed Owner allocation of a real D07 child budget."""
from ..runtime_contracts import canonical_digest

ACTION = 'd07_cognition_budget'


def validate_d07_budget_input_v1(value):
    if (type(value) is not dict or set(value)!={'parent_budget_lease_ref','ceiling'}
            or type(value['parent_budget_lease_ref']) is not str or not 1<=len(value['parent_budget_lease_ref'])<=128
            or type(value['ceiling']) is not dict or not 1<=len(value['ceiling'])<=16
            or any(type(key) is not str or not key or len(key)>64 or type(amount) is not int or amount<=0
                for key,amount in value['ceiling'].items())):
        raise ValueError('explicit D07 parent and positive bounded dimensions required')


def execute_d07_budget_v1(issuer,*,session,scope,purpose,audience,operation_id,input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    validate_d07_budget_input_v1(input_data)
    if (audience!='owner' or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token or not session.allows(scope,'workbench.create',purpose,audience)):
        return _unavailable('signed_d07_budget_owner_unavailable')
    grant=issuer._resolve(session,scope,purpose,audience,domains=('d07','d11','d12'))
    if grant is None or 'workbench.create' not in grant.capabilities:
        return _unavailable('signed_d07_budget_owner_unavailable')
    original=issuer._coordinator.allocate_current_d07_cognition_budget_v1(grant.authority,grant.lease,
        operation_id=operation_id,**input_data)
    return {'status':'ready','receipt':{'schema':'d12.d07-budget-receipt.v1','operation_id':operation_id,
        'input_digest':canonical_digest(input_data),'original':original,'original_digest':canonical_digest(original)}}
