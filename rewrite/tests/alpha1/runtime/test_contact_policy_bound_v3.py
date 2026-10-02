"""Native/min-deadline evidence and historical quota recomputation.

Typed policy, rule, claim and row codecs are real; the Owner original is a
synthetic fixture. These tests never issue an installed permission or sender.
"""
from dataclasses import replace
import pytest
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d08.execution import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.domains.d10 import (ContactContinuation, ContactPolicy, ProactiveOpportunity, LifeDomain,
    contact_policy_graph_write, proactive_opportunity_graph_write)
from sylanne3.domains.d10.contact_claim_v2 import ContactClaimV2, contact_claim_key_v2, contact_window_id_v2
from sylanne3.authority_service.d10_contact_policy_service_v1 import D10ContactPolicyOriginalV1
from sylanne3.graph_types import GraphVersion
from sylanne3.memory_types import source_key
from sylanne3.runtime.contact_policy_bound_v3 import (ContactPolicyQualificationBoundV3,
    issue_installed_contact_policy_bound_v3, validate_contact_policy_bound_members_v3)
from sylanne3.runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from sylanne3.runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
from sylanne3.runtime_contracts import NamespaceId, OperationIdentity, CheckReceipt, VersionedRef, canonical_serialize

NS=NamespaceId('bot','persona'); D='a'*64

@pytest.fixture
def native():
    policy=ContactPolicy('policy:one',NS,1,'user','private','ordinary',True,False,1,0.,240.)
    opportunity=ProactiveOpportunity('opportunity:one',NS,source_key(*NS.as_tuple,'source').token,
        'user','private','ordinary',0.,180.)
    owner=D10ContactPolicyOriginalV1('authority:fixture','authority','installation',NS,policy,'owner',
        'sha256:'+D,1,1,contact_window_id_v2(policy),'approval','issue',0.,D)
    own=ContactClaimV2('contact:one','action:whole','user','private','ordinary',('effect:one',),(),
        'claimed',policy.policy_id,1,contact_window_id_v2(policy),0.,240.,owner.original_ref,owner.digest)
    continuation=ContactContinuation(own.contact_id,own.communication_action_id,'effect:one')
    local=LifeDomain.contact_policy_check(policy,opportunity,(own,),now=1.,continuation=continuation)
    versions=(VersionedRef('criterion',1),)
    receipt=CheckReceipt('contact_policy','persona:persona','action:one','expression',versions,'full','pass',180.,'d10.contact_policy')
    pw=contact_policy_graph_write(policy,owner_grant_revision=1,approval_ref=owner.original_ref,
        approval_authority_id=owner.authority_id,installation_id=owner.installation_id)
    ow=proactive_opportunity_graph_write(opportunity,source_revision=1,access_revision=1)
    rows=tuple(OfflineTickGraphReadV1(key.token,1,canonical_serialize(value),True) for key,value in
        ((pw.key,pw.value),(ow.key,ow.value),(contact_claim_key_v2(NS,own.contact_id),plain_v1(own))))
    spec=RequiredCheckSpec('contact_policy','d10.contact_policy','persona:persona','action:one','expression','criterion',versions)
    action=ActionIntent('action:one',1,'goal:one',(),'user','message','expression','limited',D,
        OperationIdentity('activity','effect:one','attempt:one','prepare','operation',D),'schema:one',(spec,),
        GoalPredicate('communicated','d11.observer',(),0.,None),('effect:one',),None,(opportunity.source_ref,))
    bound=ContactPolicyQualificationBoundV3(receipt,local,GraphVersion(pw.key,1),GraphVersion(ow.key,1),
        continuation,120.,replace(receipt,valid_until=120.))
    return bound,rows,owner,action


def verify(case, **changes):
    bound,rows,owner,action=case
    return validate_contact_policy_bound_members_v3(bound,members=rows,namespace=NS,
        owner_policy=owner,action=action,now_utc=1.,deadline_utc=120.,**changes)


def test_native_receipt_unchanged_bound_roundtrip_and_complete_recorded_quota(native):
    bound,*_=native
    assert bound.provider_receipt.valid_until==180. and bound.bounded_receipt.valid_until==120.
    assert decode_typed_production_value_v1(plain_v1(bound),ContactPolicyQualificationBoundV3)==bound
    assert verify(native)==bound

@pytest.mark.parametrize('change', ['missing','native_ttl','new_claim','quiet','window','wrong_revision','wrong_namespace','owner','own_observed','effect'])
def test_recomputed_recorded_native_inventory_rejects_drift(native,change):
    import json
    bound,rows,owner,action=native;rows=list(rows)
    if change=='missing':rows.pop()
    if change=='native_ttl':bound=replace(bound,local_check=replace(bound.local_check,valid_until=181.),
        provider_receipt=replace(bound.provider_receipt,valid_until=181.))
    if change in {'quiet','window','own_observed'}:
        i=0 if change!='own_observed' else 2;value=json.loads(rows[i].value_json)
        if change=='quiet':value['quiet']=True
        if change=='window':value['window_end']=150.
        if change=='own_observed':value['observations']=[['effect:one','unknown']];value['status']='pending_confirmation'
        rows[i]=replace(rows[i],value_json=canonical_serialize(value))
    if change=='new_claim':
        value=json.loads(rows[2].value_json);value['contact_id']='contact:other';value['communication_action_id']='action:other'
        rows.append(OfflineTickGraphReadV1(contact_claim_key_v2(NS,'contact:other').token,1,canonical_serialize(value),True))
    if change=='wrong_revision':bound=replace(bound,policy_version=GraphVersion(bound.policy_version.key,2))
    if change=='wrong_namespace':
        from sylanne3.domains.d10 import contact_policy_key
        bound=replace(bound,policy_version=GraphVersion(contact_policy_key(NamespaceId('other','persona'),'policy:one'),1))
    if change=='owner':owner=replace(owner,signature='b'*64)
    if change=='effect':action=replace(action,identity=replace(action.identity,effect_id='effect:other'))
    with pytest.raises(ValueError):verify((bound,tuple(rows),owner,action))

@pytest.mark.parametrize('change', ['extended','deadline','subject','input','result','bool_deadline','unknown_field'])
def test_closed_wire_cannot_substitute_deadline_receipt_or_criterion(native,change):
    bound,*_=native;raw=plain_v1(bound)
    if change=='extended':raw['bounded_receipt']['valid_until']=180.
    if change=='deadline':raw['operation_deadline_utc']=121.
    if change=='subject':raw['bounded_receipt']['subject_ref']='persona:other'
    if change=='input':raw['bounded_receipt']['input_versions'][0]['version']=2
    if change=='result':raw['provider_receipt']['result']='unknown'
    if change=='bool_deadline':raw['operation_deadline_utc']=True
    if change=='unknown_field':raw['caller_allow']=True
    with pytest.raises((ValueError,TypeError)):
        decode_typed_production_value_v1(raw,ContactPolicyQualificationBoundV3)


def test_public_dto_does_not_issue_private_policy_bound(native):
    with pytest.raises((ValueError,TypeError,AttributeError)):
        issue_installed_contact_policy_bound_v3(None,object(),scope=None,intent=None,
            policy_id='policy:one',opportunity_id='opportunity:one',current_policy=None)


def test_recomputed_raw_and_bounded_input_drift_cannot_self_authenticate(native):
    from sylanne3.runtime_contracts import VersionedRef
    bound,rows,owner,action=native
    altered=(VersionedRef('criterion',2),)
    bound=replace(bound,provider_receipt=replace(bound.provider_receipt,input_versions=altered),
        bounded_receipt=replace(bound.bounded_receipt,input_versions=altered))
    with pytest.raises(ValueError,match='actual action/full rule'):
        verify((bound,rows,owner,action))


def test_live_issuer_has_no_caller_continuation_or_deadline_input(native):
    for supplied in ({'continuation':native[0].continuation},{'deadline_utc':999.}):
        with pytest.raises(TypeError,match='unexpected keyword'):
            issue_installed_contact_policy_bound_v3(None,object(),scope=None,intent=None,
                policy_id='policy:one',opportunity_id='opportunity:one',current_policy=None,**supplied)
