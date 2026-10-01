"""Migration management crosses two real mTLS peer sessions."""

import ssl
import hashlib
from dataclasses import replace

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.mtls_server import (
    AuthorityRpcServer, AuthorityServerTlsConfig, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_migration_rpc import (
    SCHEMA, MigrationManagementBindingV2, MigrationRpcHandlerV2, to_wire,
)
from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from test_v2_migration_rpc import _setup, _close
from test_v2_migration_local_state import _source_receipt


def _peer(path):
    der = ssl.PEM_cert_to_DER_cert(path.read_text(encoding="ascii"))
    return MtlsPeerCredential(hashlib.sha256(der).hexdigest())


@pytest.mark.asyncio
async def test_two_management_peers_bind_current_tls_channel_and_replay(tmp_path, monkeypatch):
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    source, target = _peer(files["client.pem"]), _peer(files["second.pem"])
    bundle, _, plan = _setup(tmp_path)
    fence, migration, _, core, *_ = bundle
    core._authorize_callback = lambda peer, *_: peer in (source, target, "admin")

    def resolve(peer, profile, channel, namespace):
        role = "source" if peer == source else "target" if peer == target else None
        if role is None or profile != "profile-a" or namespace != "ns-a":
            return None
        return MigrationManagementBindingV2(
            peer.certificate_sha256, profile, channel, namespace,
            role, "holder-" + role, "install-" + role,
            "holder-source", "install-source", "holder-target", "install-target",
        )

    handler = MigrationRpcHandlerV2(
        {"ns-a": migration}, resolve_management_binding=resolve)
    server = AuthorityRpcServer(
        core, v2_fences={"ns-a": fence}, v2_migration_rpc=handler,
        administrator_authorizer=lambda peer, *_: peer in (source, target),
        publisher_manifest_verifier=lambda *_: True,
    )
    listener = await server.start(
        "127.0.0.1", 0,
        AuthorityServerTlsConfig(
            str(files["server.pem"]), str(files["server.key"]),
            str(files["ca.pem"]), timeout_seconds=2,
        ),
    )
    port = listener.sockets[0].getsockname()[1]
    (tmp_path / "release-manifest.json").write_text("{}", encoding="utf-8")

    def client(cert):
        profile = AuthorityTlsProfile(
            "profile-a", "127.0.0.1", port, "localhost", server._authority_id(),
            files["ca.pem"], files[f"{cert}.pem"], files[f"{cert}.key"],
            timeout_seconds=2,
        )
        transport = MtlsAuthorityTransport({"profile-a": profile})
        return AuthorityClient(
            AuthoritySelection("profile-a"), package_root=tmp_path,
            data_dir=tmp_path, transport=transport,
        ), transport

    source_client, source_transport = client("client")
    target_client, target_transport = client("second")
    command = {
        "schema": SCHEMA, "operation": "begin_transfer", "namespace": "ns-a",
        "request_id": "begin-a", "plan": to_wire(plan),
    }
    try:
        assert (await source_client.status_v2()).state == "paired"
        assert (await target_client.status_v2()).state == "paired"
        with pytest.raises(RuntimeError):
            await target_client.migration_command_v2(command)
        receipt, status = await source_client.migration_command_v2(command)
        assert receipt.phase == "begun" and status.plan == plan
        assert await source_client.migration_command_v2(command) == (receipt, status)
        (tmp_path / "source.snapshot").write_bytes(b"controlled source closure")
        snapshot = _source_receipt(tmp_path, status)
        migration._source_verifier = None
        with pytest.raises(RuntimeError):
            await source_client.migration_command_v2({
                "schema": SCHEMA, "operation": "revoke_source",
                "namespace": "ns-a", "request_id": "revoke-a",
                "permit": to_wire(status.source_permit),
                "snapshot": to_wire(snapshot),
            })
        assert (await source_client.migration_command_v2({
            "schema": SCHEMA, "operation": "recover_transfer",
            "namespace": "ns-a", "transfer_id": plan.transfer_id,
        })).history.phase == "begun"
        with pytest.raises(RuntimeError):
            await source_client.migration_command_v2({
                **command, "plan": {**command["plan"],
                                    "target_installation_id": "other"},
            })
        recovery = await target_client.migration_command_v2({
            "schema": SCHEMA, "operation": "recover_transfer",
            "namespace": "ns-a", "transfer_id": plan.transfer_id,
        })
        assert recovery.history.plan == plan
        assert recovery.owner_head is None
        original_handle = handler.handle

        def missing_owner_head(**kwargs):
            result = original_handle(**kwargs)
            if kwargs["command"]["operation"] == "recover_transfer":
                result["result"]["recovery"].pop("owner_head")
            return result

        with monkeypatch.context() as patch:
            patch.setattr(handler, "handle", missing_owner_head)
            with pytest.raises(AuthorityUnavailable, match="migration wire"):
                await target_client.migration_command_v2({
                    "schema": SCHEMA, "operation": "recover_transfer",
                    "namespace": "ns-a", "transfer_id": plan.transfer_id,
                })
        original = source_client._v2_handshake
        source_client._v2_handshake = replace(
            original, channel_binding_sha256="e" * 64)
        with pytest.raises(RuntimeError, match="handshake channel"):
            await source_client.migration_command_v2(command)
    finally:
        await source_transport.close()
        await target_transport.close()
        listener.close()
        await listener.wait_closed()
        await server.aclose()
        _close(bundle)
