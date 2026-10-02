"""Pure deadline guard and unissued public-call refusal, no Owner permission.

Actual SQL/Core/Owner recovery is tested by the installed integration node.
These numeric fixtures exercise independent expiry limits only.
"""
from types import SimpleNamespace as S
from dataclasses import replace
import pytest

from sylanne3.runtime.contact_saved_owner_projection_v3 import (
    _require_live,_read_saved_contact_owner_projection_v3,_owner_binding_wire_v3,
)


def terms():
    return (S(deadline_utc=100.,qualification=S(checks=tuple(S(valid_until=100.) for _ in range(6)))),
        S(valid_until=100.),S(valid_until_utc=100.),S(valid_until_utc=100.,deadline_utc=100.))


def test_unissued_call_cannot_enter_saved_owner_observation():
    with pytest.raises(ValueError,match='active installed Owner'):
        _read_saved_contact_owner_projection_v3(None,None,{},None,None)


def test_current_time_is_required_instead_of_historical_qualification_time():
    evidence,content,parent,quote=terms()
    _require_live(evidence,99.,content,parent,quote)
    with pytest.raises(ValueError,match='expired'):
        _require_live(evidence,100.,content,parent,quote)


@pytest.mark.parametrize('limit',('deadline','content','parent','quote','quote_deadline',*(str(i) for i in range(6))))
def test_each_original_limit_can_independently_block_recovery(limit):
    evidence,content,parent,quote=terms()
    if limit=='deadline':evidence.deadline_utc=50.
    elif limit=='content':content.valid_until=50.
    elif limit=='parent':parent.valid_until_utc=50.
    elif limit=='quote':quote.valid_until_utc=50.
    elif limit=='quote_deadline':quote.deadline_utc=50.
    else:evidence.qualification.checks[int(limit)].valid_until=50.
    with pytest.raises(ValueError,match='expired'):
        _require_live(evidence,50.,content,parent,quote)


def concrete_owner_binding():
    from sylanne3.graph_coordinator import OwnerLeaseBindingV1
    from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
    from sylanne3.runtime_contracts import NamespaceId
    return OwnerLeaseBindingV1(OwnerPrincipalV1('dashboard','account-1','incarnation-1'),
        'owner',NamespaceId('bot','persona'),'workbench_user_action','owner',
        'grant-1','bot/persona','issuer-1',frozenset({'write','workbench.read'}),
        frozenset({'workbench_user_action'}),frozenset({'owner'}),'a'*64,1,2,3,
        'graph-1','b'*64,1,0)


def test_complete_owner_binding_projection_handles_concrete_frozen_sets():
    binding=concrete_owner_binding()
    from sylanne3.runtime_contracts import canonical_serialize
    with pytest.raises(TypeError,match='frozenset'):canonical_serialize(binding)
    original=_owner_binding_wire_v3(binding)
    assert _owner_binding_wire_v3(replace(binding))==original
    for changed in (replace(binding,purpose='other'),replace(binding,audience='other'),
            replace(binding,grant_revision=True),replace(binding,revocation_epoch=1),
            replace(binding,capabilities=binding.capabilities|{'extra'}),
            replace(binding,principal=replace(binding.principal,account_incarnation='incarnation-2'))):
        assert _owner_binding_wire_v3(changed)!=original


@pytest.mark.parametrize('values',({'read'},('read',),frozenset({True})))
def test_owner_binding_projection_rejects_non_closed_grant_sets(values):
    with pytest.raises(TypeError,match='finite grant sets'):
        _owner_binding_wire_v3(replace(concrete_owner_binding(),capabilities=values))
