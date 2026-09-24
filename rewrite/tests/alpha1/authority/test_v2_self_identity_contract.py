"""The shared D03/Authority DTO is structural, never an authorization proof."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_self_identity_contract import (
    SelfIdentityMutationV1, from_wire, to_wire,
)
from sylanne3.runtime_contracts import NamespaceId


def test_mutation_wire_is_exact_and_binds_replay_digest():
    mutation = SelfIdentityMutationV1(
        "authority-a", "ns-a", NamespaceId("bot-a", "persona-a"),
        "installation-a", "a" * 64, "entity:role-a", "set", "register-a", 0)
    wire = to_wire(mutation)
    assert from_wire(wire) == mutation
    assert replace(mutation, self_entity_ref="entity:role-b").request_digest != mutation.request_digest
    with pytest.raises(ValueError):
        from_wire({**wire, "self_reported_current": True})
    with pytest.raises(ValueError):
        replace(mutation, self_entity_ref="entity:account-v1:sender")


def test_d03_reexports_the_single_authority_current_dto():
    from sylanne3.authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    from sylanne3.domains.d03.self_identity_qualification import AuthorityCurrentSelfIdentityV1 as D03Type

    assert D03Type is AuthorityCurrentSelfIdentityV1
