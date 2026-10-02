"""Canonical storage codec/signature regression, not an Owner issuance fixture."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d10_contact_policy_service_v1 import (
    D10ContactPolicyOriginalV1, InstalledD10ContactPolicyServiceV1,
    contact_policy_original_from_wire_v1, contact_policy_original_to_wire_v1,
)
from sylanne3.domains.d10 import ContactPolicy
from sylanne3.domains.d10.contact_claim_v2 import contact_window_id_v2
from sylanne3.runtime_contracts import NamespaceId, canonical_serialize


def original_row():
    # Only the pure storage decoder is exercised here. Actual current Owner
    # and permission issuance is covered by the installed external test.
    service = object.__new__(InstalledD10ContactPolicyServiceV1)
    service._key = b"storage-codec-fixture-key-32-byte!"
    service.fences = SimpleNamespace(namespace="authority:fixture")
    service.namespace = ns = NamespaceId("bot", "persona")
    service.installation_id = "installation:fixture"
    policy = ContactPolicy("policy:fixture", ns, 1, "entity:fixture", "private",
        "conversation", True, False, 1, 10., 100.)
    material = dict(authority_namespace=service.fences.namespace, authority_id="authority:fixture",
        installation_id=service.installation_id, namespace=ns, policy=policy,
        owner_actor_id="owner:fixture", owner_head_digest="sha256:" + "a" * 64,
        owner_authorization_revision=1, owner_principal_epoch=0,
        window_id=contact_window_id_v2(policy), operation_id="operation:fixture",
        action="issue", issued_at_utc=20., schema="d10.owner-contact-policy-original.v1")
    value = D10ContactPolicyOriginalV1(**material, signature=service._sign(material))
    row = (value.authority_namespace, value.installation_id, policy.policy_id, policy.version,
        value.operation_id, value.action, canonical_serialize(value), value.digest, value.signature)
    return service, value, row


def test_storage_retains_existing_typed_bytes_signature_and_distinct_rpc_wire():
    service, value, row = original_row()
    assert service._decode(row) == value
    assert "$type" in json.loads(row[6])
    wire = contact_policy_original_to_wire_v1(value)
    assert "$type" not in wire
    assert contact_policy_original_from_wire_v1(wire) == value


@pytest.mark.parametrize("path", [(), ("namespace",), ("policy",), ("policy", "namespace")])
def test_storage_rejects_changed_canonical_type_at_every_level(path):
    service, _, row = original_row()
    raw = json.loads(row[6]); nested = raw
    for name in path:
        nested = nested[name]
    nested["$type"] = "caller.Untrusted"
    damaged = (*row[:6], canonical_serialize(raw), *row[7:])
    with pytest.raises(AuthorityUnavailable):
        service._decode(damaged)


def test_storage_rejects_changed_value_and_signature():
    service, value, row = original_row()
    changed = replace(value, owner_principal_epoch=1)
    damaged = (*row[:6], canonical_serialize(changed), changed.digest, changed.signature)
    with pytest.raises(AuthorityUnavailable):
        service._decode(damaged)
    damaged = (*row[:8], "b" * 64)
    with pytest.raises(AuthorityUnavailable):
        service._decode(damaged)
