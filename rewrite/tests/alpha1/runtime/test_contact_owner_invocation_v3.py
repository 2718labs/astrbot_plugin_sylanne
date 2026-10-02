"""Closed Contact invocation identity codec regression from installed S46 failure."""
from dataclasses import asdict,replace
import json
import pytest
from sylanne3.runtime.contact_owner_invocation_v3 import (
    _owner_storage_wire_v3,owner_binding_from_wire_v3,authority_from_wire_v3,
)
from sylanne3.runtime.contact_saved_owner_projection_v3 import _owner_binding_wire_v3
from sylanne3.runtime_contracts import canonical_serialize,AuthorityContext
from test_contact_saved_owner_projection_v3 import concrete_owner_binding


def test_plain_owner_identity_codec_roundtrips_and_leaves_existing_typed_wire_unchanged():
    owner=concrete_owner_binding()
    typed=json.loads(_owner_binding_wire_v3(owner))
    assert '$type' in typed['principal'] and '$type' in typed['namespace']
    raw=_owner_storage_wire_v3(owner)
    assert set(raw['principal'])=={'identity_provider','account_ref','account_incarnation'}
    assert set(raw['namespace'])=={'bot_id','persona_id'}
    assert owner_binding_from_wire_v3(raw)==owner
    assert json.loads(_owner_binding_wire_v3(owner))==typed
    with pytest.raises(ValueError,match='identity fields'):owner_binding_from_wire_v3(typed)
    for name in ('capabilities','purposes','audiences'):
        with pytest.raises(ValueError):owner_binding_from_wire_v3({**raw,name:raw[name]+raw[name][:1]})
    with pytest.raises(ValueError):owner_binding_from_wire_v3({**raw,'grant_revision':True})
    with pytest.raises(ValueError):owner_binding_from_wire_v3({**raw,'bearer':'forbidden'})


def test_plain_authority_context_roundtrip_is_closed_not_generic_tag_stripping():
    owner=concrete_owner_binding()
    authority=AuthorityContext(owner.actor,'d12','process-only-marker',owner.namespace,
        ('persona',),owner.purpose,(owner.audience,),'owner-grant-v1',1)
    raw=json.loads(canonical_serialize(asdict(authority)))
    assert authority_from_wire_v3(raw)==authority
    tagged=json.loads(canonical_serialize(authority))
    with pytest.raises(ValueError,match='context fields'):authority_from_wire_v3(tagged)
    with pytest.raises(ValueError):authority_from_wire_v3({**raw,'namespace':{**raw['namespace'],'$type':'arbitrary'}})
    with pytest.raises(ValueError):authority_from_wire_v3({**raw,'activation_generation':True})
