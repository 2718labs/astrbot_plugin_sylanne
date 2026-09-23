"""Explicit v2 genesis is mapped by the administrator and bound to a peer."""

from dataclasses import asdict
import json

import pytest

from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AdministratorInstallationV2, AuthorityRpcServer,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityHandshake, AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId, NamespaceRuntimeState


PEER_A = MtlsPeerCredential("a" * 64)
PEER_B = MtlsPeerCredential("b" * 64)
ROLE = NamespaceId("bot-a", "persona-a")
REQUEST = {
    "protocol": AUTHORITY_V2_PROTOCOL,
    "profile_id": "installed",
    "plugin_name": "astrbot_plugin_sylanne",
    "host_api_version": "4.28.1",
    "manifest_sha256": "c" * 64,
}


@pytest.fixture
def installed(tmp_path):
    seed = DeletionJournal(tmp_path / "seed.db", create=True)
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="opaque-role-a",
        journal_id="execution-a", create=True,
    )
    seed_head = seed.latest_head()
    seed_head = JournalHead(seed_head.journal_id, seed_head.seq,
                            seed_head.chain_digest)
    actions = []

    def authorize(credential, action, namespace, holder):
        actions.append((credential, action, namespace, holder))
        if action in {"install", "seal_v2_only"}:
            return credential == PEER_A
        return credential == PEER_A and namespace == "opaque-role-a" and (
            holder is None or holder in {"holder-a", "holder-other"}
        )

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorize,
        deletion_verifier=lambda ns, before, current, phase:
            ns == "seed" and current == seed_head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            ns == "seed" and current == JournalHead("seed-execution", 0, "genesis"),
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    try:
        core.register_namespace(PEER_A, "seed", "seed-holder", seed_head,
                                JournalHead("seed-execution", 0, "genesis"))
        core.seal_v2_only(PEER_A)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace="opaque-role-a",
        )
        installations = {
            (peer.certificate_sha256, "installed"): AdministratorInstallationV2(
                f"install-{name}", f"holder-{name}", "policy-a", "capabilities-v2",
                "c" * 64,
            ) for peer, name in ((PEER_A, "a"), (PEER_B, "b"))
        }
        server = AuthorityRpcServer(
            core, v2_fences=service,
            administrator_authorizer=lambda *args: True,
            publisher_manifest_verifier=lambda *args: True,
            installations_v2=installations,
            namespace_bindings_v2={
                (PEER_A.certificate_sha256, "installed", ROLE): "opaque-role-a",
            },
        )
        yield server, core, actions, tmp_path
    finally:
        core.close()
        seed.close()
        deletion.close()
        guard.close()
        execution.close()


def paired(server, peer=PEER_A):
    channel = b"channel-" + peer.certificate_sha256.encode()
    response = server._dispatch_for_test("handshake", REQUEST, peer, channel)
    binding = response["channel_binding_sha256"]

    def call(method, command):
        return server._dispatch_for_test(
            method, REQUEST, peer, channel, handshake_binding=binding,
            command=command,
        )

    return call, response


def test_genesis_rpc_requires_explicit_mapped_management_call(installed):
    server, core, actions, _ = installed
    call, _ = paired(server)
    namespace = asdict(ROLE)
    before = call("namespace_bootstrap", {"namespace": namespace})
    assert before["state"] == NamespaceRuntimeState.UNBOUND
    assert core._db.execute(
        "SELECT 1 FROM authority_namespaces WHERE namespace='opaque-role-a'"
    ).fetchone() is None
    assert not any(action == "namespace_genesis" for _, action, _, _ in actions)

    command = {"namespace": namespace, "request_id": "genesis-a"}
    result = call("namespace_genesis", command)
    assert result["state"] == NamespaceRuntimeState.ACTIVE
    assert result["holder"] == "holder-a"
    assert result["namespace"] == namespace
    assert result["authority_namespace"] == "opaque-role-a"
    assert result["generation"] == 1
    assert call("namespace_genesis", command) == result
    assert (PEER_A, "namespace_genesis", "opaque-role-a", "holder-a") in actions
    assert core._db.execute(
        "SELECT count(*) FROM authority_events WHERE namespace='opaque-role-a'"
    ).fetchone() == (1,)

    server._installations_v2[(PEER_A.certificate_sha256, "installed")] = (
        AdministratorInstallationV2(
            "install-other", "holder-other", "policy-a", "capabilities-v2",
            "c" * 64,
        )
    )
    with pytest.raises(RuntimeError):
        call("namespace_genesis", command)
    with pytest.raises(RuntimeError):
        call("namespace_genesis", {**command, "holder": "attacker"})
    with pytest.raises(RuntimeError):
        call("namespace_genesis", {"namespace": asdict(NamespaceId("x", "y")),
                                   "request_id": "other"})
    other_call, _ = paired(server, PEER_B)
    with pytest.raises(RuntimeError):
        other_call("namespace_genesis", command)


def test_administrator_cannot_bind_two_roles_to_one_authority_namespace(installed):
    server, core, _, _ = installed
    with pytest.raises(ValueError, match="one-to-one"):
        AuthorityRpcServer(
            core, v2_fences=server._v2_fences,
            administrator_authorizer=lambda *args: True,
            publisher_manifest_verifier=lambda *args: True,
            installations_v2=server._installations_v2,
            namespace_bindings_v2={
                (PEER_A.certificate_sha256, "installed", ROLE): "opaque-role-a",
                (PEER_B.certificate_sha256, "installed",
                 NamespaceId("bot-b", "persona-b")): "opaque-role-a",
            },
        )


@pytest.mark.asyncio
async def test_transport_decodes_only_bound_genesis_response(installed):
    server, _, _, root = installed
    call, paired_response = paired(server)
    profile = AuthorityTlsProfile(
        "installed", "localhost", 443, "localhost", server._authority_id(),
        root / "ca.pem", root / "client.pem", root / "client.key",
    )
    transport = MtlsAuthorityTransport({"installed": profile})
    request = AuthorityProvisioningRequest(
        AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
        root, root, PublisherPackageIdentity("c" * 64),
    )
    handshake = AuthorityHandshake(
        paired_response["state"], paired_response["installation_authority_id"],
        paired_response["installation_identity_ref"],
        paired_response["channel_binding_sha256"], True,
    )

    async def rpc(_request, _handshake, method, command, *, protocol):
        assert protocol == AUTHORITY_V2_PROTOCOL
        assert method == "namespace_genesis"
        assert command == {"namespace": asdict(ROLE), "request_id": "genesis-b"}
        return json.loads(json.dumps(call(method, command)))

    transport._content_rpc = rpc
    result = await transport.v2_namespace_genesis(request, handshake, ROLE, "genesis-b")
    assert result.state is NamespaceRuntimeState.ACTIVE
    assert result.authority_namespace == "opaque-role-a"
    assert result.anchor is not None

    async def bad_rpc(*args, **kwargs):
        return json.loads(json.dumps({**asdict(result),
                                      "channel_binding_sha256": "d" * 64}))

    transport._content_rpc = bad_rpc
    with pytest.raises(RuntimeError, match="response is invalid"):
        await transport.v2_namespace_genesis(request, handshake, ROLE, "genesis-b")
