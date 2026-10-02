"""D08 actual typed segment reference vs Graph locator; no send authority."""
from dataclasses import replace
import pytest
from test_natural_final_admission_v2 import _case
from sylanne3.dispatch_runtime import _identifier
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.contact_dispatch_admission_v3 import _contact_segment_authorization_ref_v3


def test_d08_manifest_authorization_is_stable_wire_and_graph_locator_is_separate():
    parent=_case()[0].communication_grant;segment=parent.segment_grants[0]
    ref=_contact_segment_authorization_ref_v3(parent,segment_id=segment.segment_id,
        effect_id=segment.effect_id,payload_digest=segment.payload_digest,segment_index=0)
    assert ref==parent.segment_authorization_ref(segment.segment_id)
    assert _identifier(ref,'segment_authorization_ref')==ref
    locator=AtomKey(Owner('activity','bot','persona','activity'),'d08.communication_intent_grant.v1',parent.grant_id).token
    with pytest.raises(ValueError,match='content-free'):_identifier(locator,'segment_authorization_ref')
    assert ref!=locator


@pytest.mark.parametrize('change',['id','effect','payload','position','bool_position','untyped'])
def test_wrong_segment_original_cannot_supply_dispatch_authorization(change):
    parent=_case()[0].communication_grant;segment=parent.segment_grants[0]
    args=dict(segment_id=segment.segment_id,effect_id=segment.effect_id,
        payload_digest=segment.payload_digest,segment_index=0)
    if change=='id':args['segment_id']='segment:other'
    if change=='effect':args['effect_id']='effect:other'
    if change=='payload':args['payload_digest']='a'*64
    if change=='position':args['segment_index']=1
    if change=='bool_position':args['segment_index']=False
    if change=='untyped':parent=object()
    with pytest.raises(ValueError):_contact_segment_authorization_ref_v3(parent,**args)
