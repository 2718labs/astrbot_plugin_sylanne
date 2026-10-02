"""Exact real guard contracts; installed material issuance is not simulated."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
from sylanne3.runtime.contact_batch_freezer_v3 import _contact_batch_owner_head_v3
from sylanne3.runtime_contracts import NamespaceId


@pytest.mark.parametrize('drift', [None, 'authority', 'frame', 'policy', 'namespace', 'wrong_guard'])
def test_actual_authority_and_frame_guard_have_distinct_fields_and_same_head(drift):
    ns = NamespaceId('bot', 'persona')
    digest, other = 'a' * 64, 'b' * 64
    authority = OwnerAuthorizationGuardV1('authority', 'installation', ns, 1, 'sha256:' + digest, 0, 0)
    production = ProductionOwnerGuardV1('actual-owner-grant', 1, digest, digest)
    policy = SimpleNamespace(owner_head_digest='sha256:' + digest)
    if drift == 'authority': authority = replace(authority, authorization_head='sha256:' + other)
    if drift == 'frame': production = replace(production, owner_head_digest=other)
    if drift == 'policy': policy.owner_head_digest = 'sha256:' + other
    if drift == 'namespace': authority = replace(authority, namespace=NamespaceId('other', 'persona'))
    if drift == 'wrong_guard': authority = production
    material = SimpleNamespace(owner_guard=authority, frame=SimpleNamespace(owner_guard=production),
        scope=SimpleNamespace(namespace=ns), current_policy=SimpleNamespace(original=policy))
    if drift is None:
        assert _contact_batch_owner_head_v3(material) == digest
    else:
        with pytest.raises(ValueError, match='Owner head differs'):
            _contact_batch_owner_head_v3(material)
