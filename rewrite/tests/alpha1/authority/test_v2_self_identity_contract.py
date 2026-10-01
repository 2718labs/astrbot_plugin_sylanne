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


def _codec_current_vector():
    # Structural protocol vector only: it never authorizes a Graph operation.
    from sylanne3.runtime.restore_anchor import RestoreAnchor
    from sylanne3.authority_service.v2_contract import FencePermitV2
    from sylanne3.authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    anchor = RestoreAnchor('authority-codec', 'namespace-codec', 1, 'deletion-codec', 0,
        'genesis', 'execution-codec', 0, 'genesis', 0, 'codec-vector-not-authority')
    permit = FencePermitV2('authority-codec', 'namespace-codec', 'codec-subject', 'codec-holder',
        1, 'read', 'codec-read', 'x' * 48, 1, 0, anchor)
    return AuthorityCurrentSelfIdentityV1(NamespaceId('codec-bot', 'codec-persona'),
        'namespace-codec', 'authority-codec', 'codec-installation', 'a' * 64, 1,
        'graph-origin', 'role-head', 3, 3, 'persona:codec-persona', 'entity:codec-self',
        'self-map:codec', 1, 0, 'registration-codec', 'b' * 64, 1, 'sha256:' + 'c' * 64,
        0, 0, 'codec-request', permit)


def test_legacy_current_wire_and_commitment_keep_pinned_original_bytes():
    from sylanne3.authority_service.v2_self_identity_contract import current_self_identity_commitment_v1
    from sylanne3.runtime_contracts import canonical_digest
    current = _codec_current_vector()
    # Measured against the actual pre-extension package snapshot1136, not
    # derived from the current serializer under test.
    assert canonical_digest(to_wire(current)) == '316a8311e984f062cf99183e2d32c857bf49ec528a8b8f0abeaa74229ef9c79e'
    assert current_self_identity_commitment_v1(current) == '0487499e7835a052dd09ae2c585373e3ac7c920982b0febf3873b91d7337a63d'
    assert from_wire(to_wire(current)) == current
    assert 'origin_graph_incarnation' not in to_wire(current)
    assert 'storage_admission_digest' not in to_wire(current)


def test_storage_extension_is_atomic_and_keeps_immutable_mapping_identity():
    from sylanne3.domains.d03.self_identity_qualification import self_identity_mapping_from_current
    current = _codec_current_vector()
    extension = replace(current, graph_incarnation='graph-rebased',
        origin_graph_incarnation=current.graph_incarnation, storage_admission_digest='sha256:' + 'd' * 64)
    second = replace(extension, graph_incarnation='graph-rebased-again', storage_admission_digest='sha256:' + 'e' * 64)
    assert from_wire(to_wire(extension)) == extension
    assert from_wire(to_wire(second)) == second
    assert self_identity_mapping_from_current(current) == self_identity_mapping_from_current(extension)
    assert self_identity_mapping_from_current(current) == self_identity_mapping_from_current(second)
    wire = to_wire(extension)
    invalid = (
        {name: value for name, value in wire.items() if name != 'origin_graph_incarnation'},
        {name: value for name, value in wire.items() if name != 'storage_admission_digest'},
        {**wire, 'origin_graph_incarnation': None, 'storage_admission_digest': None},
        {**wire, 'origin_graph_incarnation': wire['graph_incarnation']},
        {**wire, 'storage_admission_digest': 'd' * 64},
        {**wire, 'unverified_location': True},
    )
    for changed in invalid:
        with pytest.raises(ValueError):
            from_wire(changed)
