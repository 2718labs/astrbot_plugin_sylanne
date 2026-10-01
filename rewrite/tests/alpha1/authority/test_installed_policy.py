from __future__ import annotations

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.installed_policy import (
    InstalledAuthorityPolicyV1, InstalledPeerScopeV1,
)
from sylanne3.authority_service.mtls_server import MtlsPeerCredential


def test_pinned_peer_is_limited_to_its_namespace_and_holder():
    digest = "a" * 64
    policy = InstalledAuthorityPolicyV1({
        digest: InstalledPeerScopeV1("bot:persona", "plugin-holder")
    })
    peer = MtlsPeerCredential(digest)
    assert policy.core_authorizer(peer, "read", "bot:persona", "plugin-holder")
    assert policy.core_authorizer(peer, "current", "bot:persona", None)
    for action, namespace, holder in (
        ("read", "other:persona", "plugin-holder"),
        ("dispatch", "bot:persona", "other-holder"),
        ("install", "bot:persona", "plugin-holder"),
        ("revoke", "bot:persona", "plugin-holder"),
        ("migration_begin", "bot:persona", "plugin-holder"),
        ("owner_identity_pair", "bot:persona", None),
    ):
        assert not policy.core_authorizer(peer, action, namespace, holder)
    assert not policy.administrator_authorizer(
        peer, "pair", "authority:enrollment", "profile")
    assert not policy.core_authorizer(
        MtlsPeerCredential("b" * 64), "read", "bot:persona", None)


def test_local_credential_is_action_scoped_and_requires_fresh_os_token(monkeypatch):
    import sylanne3.authority_service.installed_policy as module

    effective = {"value": True}
    monkeypatch.setattr(module, "_effective_windows_administrator",
                        lambda: effective["value"])
    policy = InstalledAuthorityPolicyV1({
        "a" * 64: InstalledPeerScopeV1("bot:persona", "plugin-holder")
    })
    credential = policy.local_administrator_credential(
        "owner_identity_revoke", "bot:persona")
    assert policy.core_authorizer(
        credential, "owner_identity_revoke", "bot:persona", None)
    assert not policy.core_authorizer(
        credential, "install", "bot:persona", None)
    assert not policy.core_authorizer(
        credential, "owner_identity_revoke", "other:persona", None)
    effective["value"] = False
    assert not policy.core_authorizer(
        credential, "owner_identity_revoke", "bot:persona", None)
    with pytest.raises(AuthorityUnavailable, match="HOLD"):
        policy.local_administrator_credential("install", "bot:persona")


def test_unverified_publisher_and_remote_enrollment_hold():
    policy = InstalledAuthorityPolicyV1({
        "a" * 64: InstalledPeerScopeV1("bot:persona", "plugin-holder")
    })
    assert not policy.publisher_manifest_verifier(
        "profile", "Sylanne", "4.28.1", "f" * 64)
    assert not policy.administrator_authorizer(
        MtlsPeerCredential("a" * 64), "pair", "authority:enrollment", "profile")
