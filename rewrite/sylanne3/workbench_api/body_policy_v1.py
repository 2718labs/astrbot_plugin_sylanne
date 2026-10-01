"""Exact explicit Owner adoption of installed fixed body work policies."""
from dataclasses import fields
from ..domains.d02 import BodyProfile, BodyState, WorkComponent
from ..domains.d02.body_quote_original import FixedBodyPolicyV1
from ..runtime_contracts import NamespaceId, canonical_digest

ACTION = 'd02_fixed_work_policy'
CAPABILITY = 'd02.body_policy.install'


def _exact(raw, cls):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(cls)}:
        raise ValueError('body policy requires every exact versioned field')
    return dict(raw)


def decode_fixed_body_policy_v1(raw):
    value = _exact(raw, FixedBodyPolicyV1)
    profile = _exact(value['profile'], BodyProfile)
    profile['namespace'] = NamespaceId(**_exact(profile['namespace'], NamespaceId))
    for field in ('applicable_axes', 'work_kinds'):
        if type(profile[field]) is not list or not 1 <= len(profile[field]) <= 32:
            raise ValueError('body policy axes/work kinds must be explicitly bounded')
        profile[field] = tuple(profile[field])
    value['profile'] = BodyProfile(**profile)
    value['initial_state'] = BodyState(**_exact(value['initial_state'], BodyState))
    value['component'] = WorkComponent(**_exact(value['component'], WorkComponent))
    result = FixedBodyPolicyV1(**value)
    if result.work_kind not in {'d06.c04_internal_cpu.v1','d07.cognition'}:
        raise ValueError('body policy work kind has no installed executor')
    return result


def execute_body_policy_v1(issuer, *, session, scope, purpose, audience, operation_id, input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    if (audience != 'owner' or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token or not session.allows(scope, CAPABILITY, purpose, audience)):
        return _unavailable('signed_body_policy_owner_capability_unavailable')
    if type(input_data) is not dict or set(input_data) != {'policy'}:
        raise ValueError('explicit complete fixed body policy required')
    policy = decode_fixed_body_policy_v1(input_data['policy'])
    grant = issuer._resolve(session, scope, purpose, audience, domains=('d02','d11','d12'))
    if grant is None or CAPABILITY not in grant.capabilities or policy.profile.namespace != grant.authority.namespace:
        return _unavailable('body_policy_namespace_or_capability_unavailable')
    result = issuer._coordinator.adopt_current_fixed_body_work_policy_v1(grant.authority, grant.lease,
        operation_id=operation_id, policy=policy)
    if type(result) is not dict or result.get('operation_id') != operation_id:
        raise ValueError('fixed body policy did not return its durable original')
    return {'status':'ready','receipt':{'schema':'d12.body-policy-receipt.v1','operation_id':operation_id,
        'input_digest':canonical_digest(input_data),'original':result,'original_digest':canonical_digest(result)}}
