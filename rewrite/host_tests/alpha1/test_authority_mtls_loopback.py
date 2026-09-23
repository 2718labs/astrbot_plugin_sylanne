"""Ephemeral loopback mTLS evidence; generated keys never leave temp storage."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
from pathlib import Path
import ssl
import sys
import tempfile
import types
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2,
    AuthorityRpcServer,
    AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
# Import the transport without requiring an installed AstrBot host.
_host_package = sys.modules.get("sylanne3.host")
if _host_package is None:
    _host_package = types.ModuleType("sylanne3.host")
    _host_package.__path__ = [str(Path(__file__).resolve().parents[2] / "sylanne3" / "host")]
    sys.modules["sylanne3.host"] = _host_package
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL,
    AuthorityEnrollmentGrant,
    AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
if not hasattr(_host_package, "__file__"):
    sys.modules.pop("sylanne3.host", None)
from sylanne3.runtime.deletion import DeletionJournal


class AuthorityMtlsLoopbackTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def _certificates(cls, root: Path) -> dict[str, Path]:
        import datetime

        now = datetime.datetime.now(datetime.UTC)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sylanne Test CA")])
        ca_cert = (
            x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        def issue(name: str, usage, san=None, *, issuer_key=ca_key, issuer=ca_name):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            builder = (
                x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), critical=True)
                .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                    critical=False,
                )
            )
            if san is not None:
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
            return key, builder.sign(issuer_key, hashes.SHA256())

        server_key, server_cert = issue("localhost", ExtendedKeyUsageOID.SERVER_AUTH, "localhost")
        client_key, client_cert = issue("sylanne-test-client", ExtendedKeyUsageOID.CLIENT_AUTH)
        second_key, second_cert = issue("sylanne-second-client", ExtendedKeyUsageOID.CLIENT_AUTH)
        bad_key, bad_cert = issue(
            "untrusted-client", ExtendedKeyUsageOID.CLIENT_AUTH,
            issuer_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
            issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")]),
        )

        def write_pair(name: str, key, certificate) -> None:
            (root / f"{name}.key").write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
            (root / f"{name}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

        write_pair("ca", ca_key, ca_cert)
        write_pair("server", server_key, server_cert)
        write_pair("client", client_key, client_cert)
        write_pair("second", second_key, second_cert)
        write_pair("bad", bad_key, bad_cert)
        return {f"{name}{suffix}": root / f"{name}{suffix}"
                for name in ("ca", "server", "client", "second", "bad")
                for suffix in (".pem", ".key")}

    async def test_loopback_mutual_tls_content_fence_and_closed_server(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = self._certificates(root)
            client_der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text(encoding="ascii"))
            credential = MtlsPeerCredential(hashlib.sha256(client_der).hexdigest())

            def core_authorizer(candidate, action, namespace, holder):
                return (
                    candidate == credential and namespace == "ns:role"
                    and action in {"install", "current", "anchor", "read", "release"}
                )

            core = AuthorityServiceCore(
                root / "authority.db", authorizer=core_authorizer,
                deletion_verifier=lambda *args: True,
                execution_verifier=lambda *args: True,
                effect_verifier=lambda *args: True,
                dispatch_verifier=lambda *args: True,
                create=True,
            )
            core.register_namespace(
                credential, "ns:role", "host:one",
                JournalHead("deletion", 0, "genesis"),
                JournalHead("execution", 0, "genesis"),
            )
            service = AuthorityRpcServer(
                core,
                administrator_authorizer=lambda candidate, action, namespace, holder:
                    candidate == credential and action == "pair" and namespace == "authority:enrollment",
                publisher_manifest_verifier=lambda *args: True,
            )
            listener = await service.start(
                "127.0.0.1", 0,
                AuthorityServerTlsConfig(
                    str(files["server.pem"]), str(files["server.key"]), str(files["ca.pem"]),
                    timeout_seconds=1, max_message_bytes=16_384,
                ),
            )
            port = listener.sockets[0].getsockname()[1]
            expected_authority_id = service._authority_id()
            profile = AuthorityTlsProfile(
                "test", "127.0.0.1", port, "localhost", expected_authority_id,
                files["ca.pem"],
                files["client.pem"], files["client.key"], timeout_seconds=1,
                max_message_bytes=16_384,
            )
            bad_profile = AuthorityTlsProfile(
                "bad", "127.0.0.1", port, "localhost", expected_authority_id,
                files["ca.pem"],
                files["bad.pem"], files["bad.key"], timeout_seconds=1,
                max_message_bytes=16_384,
            )
            request = AuthorityProvisioningRequest(
                AUTHORITY_PROTOCOL, "test", "astrbot_plugin_sylanne", "4.28.1",
                root, root, PublisherPackageIdentity("a" * 64),
            )
            try:
                transport = MtlsAuthorityTransport({"test": profile})
                handshake = await transport.handshake(request)
                enrollment = await transport.capability_grant(request, handshake)
                self.assertIsInstance(enrollment, AuthorityEnrollmentGrant)
                self.assertEqual(enrollment.capabilities, ("enrollment",))
                concurrent = await asyncio.gather(*(
                    transport.current(request, handshake, "ns:role")
                    if index % 2 == 0 else
                    transport.current_anchor(request, handshake, "ns:role")
                    for index in range(20)
                ))
                self.assertEqual(len(concurrent), 20)
                self.assertTrue(all(item.namespace == "ns:role" for item in concurrent))
                self.assertEqual((await transport.current(request, handshake, "ns:role")).generation, 1)
                anchor = await transport.current_anchor(request, handshake, "ns:role")
                self.assertEqual(anchor.deletion_seq, 0)
                self.assertEqual(
                    (await transport.check(
                        request, handshake, namespace="ns:role", holder="host:one",
                        generation=1, operation="read",
                    )).generation,
                    1,
                )
                self.assertFalse(await transport.verify_current(
                    request, handshake, replace(anchor, proof="forged-proof")
                ))
                execution_anchor = await transport.verify_execution_chain(
                    request, handshake, "ns:role"
                )
                self.assertEqual(execution_anchor.execution_seq, 0)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await transport.check(
                        request, handshake, namespace="ns:role", holder="host:one",
                        generation=2, operation="read",
                    )
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await transport.check(
                        request, handshake, namespace="ns:role", holder="host:one",
                        generation=1, operation="model_egress",
                    )
                permit = await transport.begin_content_operation(
                    request, handshake, namespace="ns:role", holder="host:one",
                    generation=1, operation="read",
                )
                await transport.end_content_operation(request, handshake, permit)
                await transport.close()
                await transport.close()
                self.assertEqual(transport._sessions, {})
                with self.assertRaisesRegex(RuntimeError, "handshake channel"):
                    await transport.current(request, handshake, "ns:role")

                handshake = await transport.handshake(request)
                transport._sessions["test"].writer.transport.abort()
                with self.assertRaisesRegex(RuntimeError, "handshake channel|transport unavailable"):
                    await transport.current(request, handshake, "ns:role")
                self.assertEqual(transport._sessions, {})
                with self.assertRaisesRegex(RuntimeError, "handshake channel"):
                    await transport.current(request, handshake, "ns:role")

                wrong_pin_profile = AuthorityTlsProfile(
                    "wrong-pin", "127.0.0.1", port, "localhost", "authority-other",
                    files["ca.pem"], files["client.pem"], files["client.key"],
                    timeout_seconds=1, max_message_bytes=16_384,
                )
                wrong_pin_request = AuthorityProvisioningRequest(
                    AUTHORITY_PROTOCOL, "wrong-pin", "astrbot_plugin_sylanne", "4.28.1",
                    root, root, PublisherPackageIdentity("a" * 64),
                )
                with self.assertRaisesRegex(RuntimeError, "identity"):
                    await MtlsAuthorityTransport({"wrong-pin": wrong_pin_profile}).handshake(
                        wrong_pin_request
                    )

                bad_request = AuthorityProvisioningRequest(
                    AUTHORITY_PROTOCOL, "bad", "astrbot_plugin_sylanne", "4.28.1",
                    root, root, PublisherPackageIdentity("a" * 64),
                )
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await MtlsAuthorityTransport({"bad": bad_profile}).handshake(bad_request)

                listener.close()
                await listener.wait_closed()
                core.close()
                await asyncio.sleep(0)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await transport.current(request, handshake, "ns:role")
            finally:
                if "transport" in locals():
                    await transport.close()
                listener.close()
                await listener.wait_closed()
                core.close()

    async def test_v2_read_fence_uses_tls_peer_and_survives_reconnect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = self._certificates(root)
            peers = {
                name: MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                    files[f"{name}.pem"].read_text(encoding="ascii"))).hexdigest())
                for name in ("client", "second")
            }
            deletion_journal = DeletionJournal(root / "deletion.db", create=True)
            deletion_guard = AuthorityV2DeletionGuard(root / "deletion.db")
            execution = AuthorityV2ExecutionJournal(
                root / "execution.db", namespace="ns:role", journal_id="execution",
                create=True)
            deletion_head = deletion_journal.latest_head()
            initial_deletion = JournalHead(
                deletion_head.journal_id, deletion_head.seq, deletion_head.chain_digest)

            def core_authorizer(candidate, action, namespace, holder):
                return (candidate in peers.values() and namespace == "ns:role"
                        and action in {"install", "seal_v2_only", "current", "read", "write"}
                        and (holder is None or holder == "host:one"))

            core = AuthorityServiceCore(
                root / "authority.db", authorizer=core_authorizer,
                deletion_verifier=lambda ns, before, current, phase:
                    current == initial_deletion and phase == "clear",
                execution_verifier=lambda ns, before, current, phase:
                    current == JournalHead("execution", 0, "genesis"),
                effect_verifier=lambda *args: True,
                dispatch_verifier=lambda *args: True, create=True)
            listener = None
            transports = []
            try:
                core.register_namespace(
                    peers["client"], "ns:role", "host:one", initial_deletion,
                    JournalHead("execution", 0, "genesis"))
                core.seal_v2_only(peers["client"])
                fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
                protected = AuthorityV2FenceService(
                    core=core, fences=fences, deletion=deletion_guard,
                    execution=execution, namespace="ns:role")
                server = AuthorityRpcServer(
                    core, v2_fences=protected,
                    administrator_authorizer=lambda candidate, action, namespace, holder:
                        candidate in peers.values() and action == "pair"
                        and namespace == "authority:enrollment",
                    publisher_manifest_verifier=lambda *args: True,
                    installations_v2={
                        (peers["client"].certificate_sha256, "first"):
                            AdministratorInstallationV2(
                                "installation-a", "host:one", "publisher-policy-a",
                                "capabilities-v2", "a" * 64),
                    })
                listener = await server.start(
                    "127.0.0.1", 0,
                    AuthorityServerTlsConfig(
                        str(files["server.pem"]), str(files["server.key"]),
                        str(files["ca.pem"]), timeout_seconds=1,
                        max_message_bytes=16_384))
                port = listener.sockets[0].getsockname()[1]

                def client(name, profile_id):
                    profile = AuthorityTlsProfile(
                        profile_id, "127.0.0.1", port, "localhost",
                        server._authority_id(), files["ca.pem"],
                        files[f"{name}.pem"], files[f"{name}.key"],
                        timeout_seconds=1, max_message_bytes=16_384)
                    transport = MtlsAuthorityTransport({profile_id: profile})
                    transports.append(transport)
                    request = AuthorityProvisioningRequest(
                        AUTHORITY_PROTOCOL, profile_id, "astrbot_plugin_sylanne",
                        "4.28.1", root, root, PublisherPackageIdentity("a" * 64))
                    return transport, request

                first, first_request = client("client", "first")
                first_handshake = await first.handshake(
                    first_request, protocol=AUTHORITY_V2_PROTOCOL)
                installation = await first.installation_grant_v2(
                    first_request, first_handshake)
                self.assertEqual(installation.installation_id, "installation-a")
                self.assertEqual(installation.administrator_holder, "host:one")
                self.assertEqual(installation.authority_id, server._authority_id())
                self.assertEqual(installation.subject, first_handshake.installation_identity_ref)
                self.assertEqual(installation.manifest_digest, "a" * 64)
                self.assertEqual(installation.channel_binding_sha256,
                                 first_handshake.channel_binding_sha256)
                anchor = await first.v2_current_anchor(
                    first_request, first_handshake, "ns:role")
                permit = await first.v2_begin_read_fence(
                    first_request, first_handshake, namespace="ns:role",
                    holder="host:one", operation_id="read-a", expected_anchor=anchor)
                self.assertEqual(permit.subject,
                                 "mtls:sha256:" + peers["client"].certificate_sha256)
                self.assertEqual(await first.v2_validate_fence(
                    first_request, first_handshake, permit), permit)

                second, second_request = client("second", "second")
                second_handshake = await second.handshake(
                    second_request, protocol=AUTHORITY_V2_PROTOCOL)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await second.installation_grant_v2(second_request, second_handshake)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await second.v2_validate_fence(
                        second_request, second_handshake, permit)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await first.v2_validate_fence(
                        first_request, first_handshake, replace(permit, revision=1))
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await first._content_rpc(
                        first_request, first_handshake, "validate_fence",
                        {"permit": {}, "subject": permit.subject},
                        protocol=AUTHORITY_V2_PROTOCOL)

                finish_digest = "sha256:" + "f" * 64
                await first.v2_finish_fence(
                    first_request, first_handshake, permit,
                    request_id="finish-a", request_digest=finish_digest)
                await first.close()
                first_handshake = await first.handshake(
                    first_request, protocol=AUTHORITY_V2_PROTOCOL)
                await first.v2_finish_fence(
                    first_request, first_handshake, permit,
                    request_id="finish-a", request_digest=finish_digest)
                self.assertEqual(fences.get_operation(
                    "read-a", subject=permit.subject, namespace="ns:role")[1], "finished")
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await first.v2_validate_fence(
                        first_request, first_handshake, permit)

                write_permit = await first.v2_begin_content_fence(
                    first_request, first_handshake, namespace="ns:role",
                    holder="host:one", operation="write", operation_id="write-a",
                    expected_anchor=anchor)
                self.assertEqual(write_permit.operation, "write")
                self.assertEqual(write_permit.subject, permit.subject)
                self.assertEqual(await first.v2_validate_fence(
                    first_request, first_handshake, write_permit), write_permit)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await second.v2_validate_fence(
                        second_request, second_handshake, write_permit)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await second.v2_finish_fence(
                        second_request, second_handshake, write_permit,
                        request_id="finish-write-a", request_digest=finish_digest)

                await first.v2_finish_fence(
                    first_request, first_handshake, write_permit,
                    request_id="finish-write-a", request_digest=finish_digest)
                await first.close()
                first_handshake = await first.handshake(
                    first_request, protocol=AUTHORITY_V2_PROTOCOL)
                await first.v2_finish_fence(
                    first_request, first_handshake, write_permit,
                    request_id="finish-write-a", request_digest=finish_digest)
                self.assertEqual(fences.get_operation(
                    "write-a", subject=write_permit.subject, namespace="ns:role")[1],
                    "finished")
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await first.v2_validate_fence(
                        first_request, first_handshake, write_permit)

                legacy, legacy_request = client("client", "legacy")
                legacy_handshake = await legacy.handshake(legacy_request)
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    await legacy.current(legacy_request, legacy_handshake, "ns:role")
            finally:
                for transport in transports:
                    await transport.close()
                if listener is not None:
                    listener.close()
                    await listener.wait_closed()
                core.close()
                execution.close()
                deletion_guard.close()
                deletion_journal.close()


if __name__ == "__main__":
    unittest.main()
