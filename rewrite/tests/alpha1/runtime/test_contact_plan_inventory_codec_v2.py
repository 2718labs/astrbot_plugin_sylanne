"""Exact local GraphAtom codec; public DTOs do not issue current authority."""
from copy import deepcopy

import pytest

from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.graph_types import AtomKey,GraphAtom,Owner
from sylanne3.runtime.contact_plan_adoption_v2 import _decode_contact_plan_inventory_atom_v2
from sylanne3.runtime_contracts import NamespaceId

NS=NamespaceId('bot','persona')
KIND='d10.contact_policy.v1'


def wire():
    return plain_v1(GraphAtom(AtomKey(Owner('persona',*NS.as_tuple),KIND,'policy'),1,
        {'fixture':'opaque registered family body'},True))


def test_exact_graph_atom_inventory_handles_body_without_generic_dict_decoder():
    value=wire()
    assert plain_v1(_decode_contact_plan_inventory_atom_v2(value,kind=KIND,namespace=NS))==value


@pytest.mark.parametrize('change',['bool_revision','zero_revision','int_valid','extra','type','namespace','body','unregistered'])
def test_finite_inventory_atom_rejects_wire_and_scope_drift(change):
    value=deepcopy(wire());kind=KIND
    if change=='bool_revision':value['revision']=True
    elif change=='zero_revision':value['revision']=0
    elif change=='int_valid':value['valid']=1
    elif change=='extra':value['permission']=True
    elif change=='type':value['key']=AtomKey(Owner('persona',*NS.as_tuple),'d03.entity_anchor','policy').token
    elif change=='namespace':value['key']=AtomKey(Owner('persona','other','persona'),KIND,'policy').token
    elif change=='body':value['value']=[]
    else:kind='caller.type'
    with pytest.raises(ValueError):
        _decode_contact_plan_inventory_atom_v2(value,kind=kind,namespace=NS)
