"""Installed C04 terminal reread stays closed without a same-chain service."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import ssl

import pytest

from host_tests.alpha1 import test_authority_mtls_loopback as _cert_fixture
from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkTerminalProofV1, InternalWorkTerminalV2, _phase_id,
    claim_internal_work_v1,
)
from sylanne3.authority_service.internal_work_rpc_wire import from_wire, to_wire
from sylanne3.authority_service.internal_work_service import (
    AuthorityInternalWorkVerifiedReceiptV1,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime_contracts import canonical_digest
from tests.alpha1.authority.test_internal_work_terminal_v2 import _binding


def _locator() -> InternalWorkTerminalProofV1:
    binding = _binding()
    claim = claim_internal_work_v1(binding)
    terminal = InternalWorkTerminalV2(
        binding.binding_digest, claim.mutation_id,
        _phase_id(binding.binding_digest, "terminal"), "failed", 7,
        binding.algorithm_ref, "e" * 64, binding.input_digest,
        None, None, None, None, None, "0" * 64,
    )
    return InternalWorkTerminalProofV1(
        binding, claim, terminal, "claim-receipt", "a" * 64,
        "terminal-receipt", "b" * 64,
        JournalHead("execution", 2, "sha256:" + "c" * 64),
    )


@pytest.mark.asyncio
async def test_c04_terminal_requires_installed_service_over_real_mtls(tmp_path):
    files = _cert_fixture.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    cert_der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text(encoding="ascii"))
    peer = MtlsPeerCredential(hashlib.sha256(cert_der).hexdigest())
    proof = _locator()
    namespace = proof.binding.namespace
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=namespace,
        journal_id="execution", create=True)
    deletion_head = deletion.latest_head()
    original_deletion = JournalHead(
        deletion_head.journal_id, deletion_head.seq, deletion_head.chain_digest)
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda credential, action, ns, holder:
            credential == peer and ns == namespace
            and action in {"install", "seal_v2_only", "current"},
        deletion_verifier=lambda ns, before, current, phase:
            current == original_deletion and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            current == execution.verified_head(),
        effect_verifier=lambda *args: False,
        dispatch_verifier=lambda *args: False,
    )
    listener = None
    transport = None
    try:
        core.register_namespace(peer, namespace, "host:one", original_deletion,
                                JournalHead("execution", 0, "genesis"))
        core.seal_v2_only(peer)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        protected = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion_guard,
            execution=execution, namespace=namespace)
        server = AuthorityRpcServer(
            core, v2_fences=protected,
            administrator_authorizer=lambda credential, action, ns, holder:
                credential == peer and action == "pair"
                and ns == "authority:enrollment",
            publisher_manifest_verifier=lambda *args: True,
            installations_v2={
                (peer.certificate_sha256, "installed"):
                    AdministratorInstallationV2(
                        "installation-a", "host:one", "publisher-policy-a",
                        "capabilities-v2", "a" * 64),
            },
            namespace_bindings_v2={
                (peer.certificate_sha256, "installed", NamespaceId("bot", "persona")):
                    namespace,
            },
        )
        listener = await server.start(
            "127.0.0.1", 0,
            AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=1,
                max_message_bytes=16_384))
        profile = AuthorityTlsProfile(
            "installed", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", server._authority_id(), files["ca.pem"],
            files["client.pem"], files["client.key"], timeout_seconds=1,
            max_message_bytes=16_384)
        transport = MtlsAuthorityTransport({"installed": profile})
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("a" * 64))
        handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await transport.installation_grant_v2(request, handshake)
        with pytest.raises(RuntimeError, match="unavailable"):
            await transport.c04_terminal_verify_v1(
                request, handshake, grant, namespace=namespace, proof=proof)
        with pytest.raises(RuntimeError, match="identity differs"):
            await transport.c04_terminal_verify_v1(
                request, handshake, replace(grant, channel_binding_sha256="0" * 64),
                namespace=namespace, proof=proof)
    finally:
        if transport is not None:
            await transport.close()
        if listener is not None:
            listener.close()
            await listener.wait_closed()
        core.close()
        execution.close()
        deletion.close()


def test_c04_wire_rejects_nested_and_terminal_receipt_forgery():
    proof = _locator()
    assert from_wire(to_wire(proof), InternalWorkTerminalProofV1) == proof
    malformed = asdict(proof)
    malformed["binding"]["resource_quote_digest"] = "0" * 64
    with pytest.raises(ValueError, match="invalid"):
        from_wire(malformed, InternalWorkTerminalProofV1)
    binding = proof.binding
    receipt = AuthorityInternalWorkVerifiedReceiptV1(
        canonical_digest(proof), binding.namespace, binding.activity_id,
        binding.operation_id, binding.execution_id, binding.input_digest,
        binding.resource_quote_ref, binding.resource_quote_version,
        binding.resource_quote_digest, proof.terminal_receipt_ref,
        proof.terminal_receipt_digest, 2, proof.journal_head,
        "failed", 7, False,
    )
    assert from_wire(to_wire(receipt), AuthorityInternalWorkVerifiedReceiptV1) == receipt
    false_completion = to_wire(receipt)
    false_completion["component_completed"] = True
    with pytest.raises(ValueError, match="invalid"):
        from_wire(false_completion, AuthorityInternalWorkVerifiedReceiptV1)
