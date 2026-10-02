"""Real typed claim JSON and dependency wire; no installed qualification."""
from types import SimpleNamespace

import pytest

from sylanne3.domains.d10.contact_claim_v2 import ContactClaimV2, decode_contact_claim_v2
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.contact_claim_adoption_v3 import _contact_claim_write_v3
from sylanne3.runtime_contracts import NamespaceId


@pytest.mark.parametrize('observations', [(), (('effect:first', 'unknown'),)])
def test_claim_json_roundtrip_retains_real_window_parent_and_all_dependencies(observations):
    ns = NamespaceId('bot', 'persona')
    policy = AtomKey(Owner('persona', *ns.as_tuple), 'd10.contact_policy.v1', 'policy')
    opportunity = AtomKey(Owner('persona', *ns.as_tuple), 'd10.proactive_opportunity.v1', 'opportunity')
    claim = ContactClaimV2('contact:whole', 'action:whole-parent', 'entity:target',
        'private', 'conversation', ('effect:first',), observations,
        'pending_confirmation' if observations else 'claimed', 'contact-policy:one', 1,
        'contact-window:one', 1., 100., 'owner-policy:one', 'a' * 64)
    write = _contact_claim_write_v3(ns, claim, policy_key=policy, opportunity_key=opportunity)
    assert decode_contact_claim_v2(write.value) == claim
    assert type(write.value['segment_effects']) is list and type(write.value['observations']) is list
    assert write.value['communication_action_id'] == 'action:whole-parent'
    assert write.dependencies == (policy, opportunity)


def test_plain_caller_claim_cannot_enter_typed_write_codec():
    with pytest.raises(TypeError, match='actual typed'):
        _contact_claim_write_v3(NamespaceId('bot', 'persona'), SimpleNamespace(),
            policy_key=None, opportunity_key=None)
