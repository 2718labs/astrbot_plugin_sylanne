"""Installation grants require an administrator's exact mTLS/package mapping."""

import pytest

from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AdministratorInstallationV2, AuthorityRpcServer,
    MtlsPeerCredential,
)
from sylanne3.runtime_contracts import InstallationGrantV2


PEER = MtlsPeerCredential("a" * 64)
OTHER = MtlsPeerCredential("b" * 64)
REQUEST = {
    "protocol": AUTHORITY_V2_PROTOCOL, "profile_id": "installed-profile",
    "plugin_name": "astrbot_plugin_sylanne", "host_api_version": "4.28.1",
    "manifest_sha256": "c" * 64,
}


def server(tmp_path, *, mapped=True, trusted=True):
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda *args: True,
        deletion_verifier=lambda *args: True,
        execution_verifier=lambda *args: True,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    mapping = {(PEER.certificate_sha256, "installed-profile"): AdministratorInstallationV2(
        "install-a", "admin-holder-a", "policy-a", "capabilities-v2", "c" * 64,
    )} if mapped else {}
    rpc = AuthorityRpcServer(
        core, administrator_authorizer=lambda *args: True,
        publisher_manifest_verifier=lambda *args: trusted,
        installations_v2=mapping,
    )
    return core, rpc


def paired(rpc, request=REQUEST, peer=PEER, channel=b"channel-a"):
    handshake = rpc._dispatch_for_test("handshake", request, peer, channel)
    return handshake["channel_binding_sha256"]


def grant(rpc, binding, request=REQUEST, peer=PEER, channel=b"channel-a", command=None):
    return rpc._dispatch_for_test(
        "installation_grant_v2", request, peer, channel,
        handshake_binding=binding, command={} if command is None else command,
    )


def test_installation_grant_is_admin_mapped_and_channel_bound(tmp_path):
    core, rpc = server(tmp_path)
    try:
        binding = paired(rpc)
        actual = InstallationGrantV2(**grant(rpc, binding))
        assert actual.authority_id == core._id(core._db)
        assert actual.subject == "mtls:sha256:" + PEER.certificate_sha256
        assert actual.administrator_holder == "admin-holder-a"
        assert actual.installation_id == "install-a"
        assert actual.manifest_digest == REQUEST["manifest_sha256"]
        assert actual.channel_binding_sha256 == binding
        assert not hasattr(actual, "activation_generation")
        with pytest.raises(RuntimeError):
            grant(rpc, binding, command={"administrator_holder": "attacker"})
        with pytest.raises(RuntimeError):
            grant(rpc, binding, channel=b"other-channel")
        with pytest.raises(RuntimeError):
            grant(rpc, binding, request={**REQUEST, "manifest_sha256": "d" * 64})
        with pytest.raises(RuntimeError):
            grant(rpc, binding, peer=OTHER)
    finally:
        core.close()


@pytest.mark.parametrize("mapped,trusted", [(False, True), (True, False)])
def test_installation_grant_requires_mapping_and_publisher_verifier(
    tmp_path, mapped, trusted,
):
    core, rpc = server(tmp_path, mapped=mapped, trusted=trusted)
    try:
        if not trusted:
            with pytest.raises(RuntimeError):
                paired(rpc)
        else:
            with pytest.raises(RuntimeError):
                grant(rpc, paired(rpc))
    finally:
        core.close()
