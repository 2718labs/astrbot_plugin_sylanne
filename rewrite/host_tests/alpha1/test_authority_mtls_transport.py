"""Tests for the administrator-configured Authority TLS transport.

The test server calls the real AuthorityServiceCore authorizer. It exercises
the protocol handler directly because repository tests must not manufacture
deployment certificates or private keys.
"""

from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.mtls_server import AuthorityRpcServer, MtlsPeerCredential
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL,
    AuthorityClient,
    AuthorityEnrollmentGrant,
    AuthorityHandshake,
    AuthorityProvisioningRequest,
    AuthoritySelection,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport


class AuthorityMtlsTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.authorizer_calls = []
        self.publisher_calls = []
        self.core = AuthorityServiceCore(
            self.root / "authority.db",
            authorizer=self._core_authorize,
            deletion_verifier=lambda *args: True,
            execution_verifier=lambda *args: True,
            effect_verifier=lambda *args: True,
            dispatch_verifier=lambda *args: True,
            create=True,
        )
        self.server = AuthorityRpcServer(
            self.core,
            administrator_authorizer=self._pair_authorize,
            publisher_manifest_verifier=self._publisher_trust,
        )
        self.request = AuthorityProvisioningRequest(
            protocol=AUTHORITY_PROTOCOL,
            profile_id="production",
            plugin_name="astrbot_plugin_sylanne",
            host_api_version="4.28.1",
            package_root=self.root,
            data_dir=self.root,
            publisher_package=PublisherPackageIdentity("a" * 64),
        )
        self.peer = MtlsPeerCredential("b" * 64)
        self.core.register_namespace(
            self.peer, "ns:role", "host:one",
            JournalHead("deletion", 0, "genesis"),
            JournalHead("execution", 0, "genesis"),
        )

    def tearDown(self) -> None:
        self.core.close()
        self.temp.cleanup()

    def _pair_authorize(self, credential, action, namespace, holder):
        self.authorizer_calls.append((credential, action, namespace, holder))
        return isinstance(credential, MtlsPeerCredential) and action == "pair"

    @staticmethod
    def _core_authorize(credential, action, namespace, holder):
        return (
            isinstance(credential, MtlsPeerCredential)
            and action in {"install", "current", "anchor", "read", "release"}
            and namespace == "ns:role"
        )

    def _publisher_trust(self, profile_id, plugin_name, host_api_version, manifest_sha256):
        self.publisher_calls.append(
            (profile_id, plugin_name, host_api_version, manifest_sha256)
        )
        return profile_id == "production" and manifest_sha256 == "a" * 64

    def test_profile_is_independent_admin_configuration(self) -> None:
        profile = AuthorityTlsProfile(
            profile_id="production",
            host="authority.example",
            port=443,
            server_name="authority.example",
            expected_authority_id="authority-1",
            trust_root=self.root / "admin" / "authority-ca.pem",
            client_certificate=self.root / "admin" / "plugin-client.pem",
            client_private_key=self.root / "admin" / "plugin-client.key",
        )
        transport = MtlsAuthorityTransport({"production": profile})
        self.assertIs(transport.profile_for("production"), profile)
        with self.assertRaisesRegex(ValueError, "profile"):
            transport.profile_for("chat-supplied")

    def test_transport_rejects_a_second_event_loop(self) -> None:
        profile = AuthorityTlsProfile(
            "production", "authority.example", 443, "authority.example",
            "authority-1", self.root / "admin" / "authority-ca.pem",
            self.root / "admin" / "client.pem", self.root / "admin" / "client.key",
        )
        transport = MtlsAuthorityTransport({"production": profile})
        self.loop_run(transport.close())
        with self.assertRaisesRegex(RuntimeError, "another event loop"):
            self.loop_run(transport.close())

    def test_handshake_calls_server_authorizer_and_publisher_verifier(self) -> None:
        response = self.server.dispatch(
            "handshake", self.request, self.peer, b"same-tls-channel"
        )
        self.assertEqual(response["state"], "paired")
        self.assertTrue(response["publisher_trusted"])
        self.assertEqual(len(self.authorizer_calls), 1)
        self.assertEqual(len(self.publisher_calls), 1)
        self.assertNotIn(str(self.request.package_root), str(response))

    def test_grant_rejects_different_request_or_channel_binding(self) -> None:
        handshake = self.server._dispatch_for_test(
            "handshake", self.request, self.peer, b"channel-a"
        )
        grant = self.server._dispatch_for_test(
            "capability_grant", self.request, self.peer, b"channel-a",
            handshake_binding=handshake["channel_binding_sha256"],
        )
        self.assertEqual(grant["authority_id"], handshake["installation_authority_id"])
        self.assertEqual(grant["capabilities"], ["enrollment"])
        self.assertNotIn("activation_generation", grant)
        self.assertNotIn("revocation_epoch", grant)
        changed = AuthorityProvisioningRequest(
            protocol=AUTHORITY_PROTOCOL,
            profile_id="production",
            plugin_name="astrbot_plugin_sylanne",
            host_api_version="4.28.1",
            package_root=self.root,
            data_dir=self.root,
            publisher_package=PublisherPackageIdentity("c" * 64),
        )
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            self.server._dispatch_for_test(
                "capability_grant", changed, self.peer, b"channel-a",
                handshake_binding=handshake["channel_binding_sha256"],
            )
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            self.server._dispatch_for_test(
                "capability_grant", self.request, self.peer, b"channel-b",
                handshake_binding=handshake["channel_binding_sha256"],
            )

    def test_unknown_or_oversize_rpc_never_returns_content_diagnostics(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            self.server._dispatch_for_test("unknown", self.request, self.peer, b"channel")
        secret = "credential and signing key: /role/content"
        try:
            try:
                raise ValueError(secret)
            except ValueError as cause:
                raise RuntimeError(secret) from cause
        except RuntimeError as failure:
            with self.assertLogs("sylanne3.authority_service.mtls_server", level="ERROR") as captured:
                response = AuthorityRpcServer.error_payload(failure)
        self.assertEqual(response, {"ok": False, "error": "authority_unavailable"})
        self.assertNotIn(secret, "\n".join(captured.output))
        diagnostic = json.loads(captured.records[0].getMessage().split(": ", 1)[1])
        self.assertEqual([entry["type"] for entry in diagnostic], ["RuntimeError", "ValueError"])
        for entry in diagnostic:
            self.assertTrue(entry["frames"])
            self.assertEqual(set(entry["frames"][-1]), {"file", "line", "function"})

    def test_production_dispatch_rejects_non_mtls_credential(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "mTLS"):
            self.server.dispatch("handshake", self.request, object(), b"channel")

    def test_content_rpc_calls_core_with_bound_namespace_holder_and_generation(self) -> None:
        handshake = self.server._dispatch_for_test(
            "handshake", self.request, self.peer, b"content-channel"
        )
        bound = handshake["channel_binding_sha256"]
        current = self.server._dispatch_for_test(
            "current", self.request, self.peer, b"content-channel",
            handshake_binding=bound, command={"namespace": "ns:role"},
        )
        self.assertEqual(current["namespace"], "ns:role")
        self.assertEqual(current["holder"], "host:one")
        checked = self.server._dispatch_for_test(
            "check", self.request, self.peer, b"content-channel",
            handshake_binding=bound,
            command={
                "namespace": "ns:role", "holder": "host:one", "generation": 1,
                "operation": "read",
            },
        )
        self.assertEqual(checked["generation"], 1)
        anchor = self.server._dispatch_for_test(
            "current_anchor", self.request, self.peer, b"content-channel",
            handshake_binding=bound, command={"namespace": "ns:role"},
        )
        self.assertEqual(anchor["activation_generation"], 1)
        forged_anchor = {
            key: value for key, value in anchor.items()
            if key != "channel_binding_sha256"
        }
        forged_anchor["proof"] = "forged-proof"
        verified = self.server._dispatch_for_test(
            "verify_current", self.request, self.peer, b"content-channel",
            handshake_binding=bound, command={"anchor": forged_anchor},
        )
        self.assertFalse(verified["verified"])
        execution = self.server._dispatch_for_test(
            "verify_execution_chain", self.request, self.peer, b"content-channel",
            handshake_binding=bound, command={"namespace": "ns:role"},
        )
        self.assertEqual(execution["execution_seq"], 0)
        self.assertTrue(execution["verified"])
        permit = self.server._dispatch_for_test(
            "begin_content_operation", self.request, self.peer, b"content-channel",
            handshake_binding=bound,
            command={
                "namespace": "ns:role", "holder": "host:one", "generation": 1,
                "operation": "read",
            },
        )
        self.assertEqual(permit["namespace"], "ns:role")
        self.assertTrue(permit["token"])
        permit_request = {
            key: permit[key]
            for key in ("token", "namespace", "holder", "generation", "operation")
        }
        ended = self.server._dispatch_for_test(
            "end_content_operation", self.request, self.peer, b"content-channel",
            handshake_binding=bound, command={"permit": permit_request},
        )
        self.assertEqual(ended["ended"], True)
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            self.server._dispatch_for_test(
                "begin_content_operation", self.request, self.peer, b"content-channel",
                handshake_binding=bound,
                command={
                    "namespace": "ns:role", "holder": "host:one", "generation": 2,
                    "operation": "read",
                },
            )

    def test_enrollment_grant_cannot_be_used_as_runtime_capability_grant(self) -> None:
        class EnrollmentOnlyTransport:
            async def handshake(self, request):
                return AuthorityHandshake(
                    "paired", "authority-1", "mtls:sha256:" + "b" * 64,
                    "c" * 64, True,
                )

            async def capability_grant(self, request, handshake):
                return AuthorityEnrollmentGrant(
                    "enrollment-1", "authority-1", handshake.installation_identity_ref,
                    ("enrollment",),
                )

        package_root = self.root / "package"
        package_root.mkdir()
        (package_root / "release-manifest.json").write_text("{}", encoding="utf-8")
        client = AuthorityClient(
            AuthoritySelection("production"), package_root=package_root,
            data_dir=self.root, transport=EnrollmentOnlyTransport(),
        )
        self.assertEqual(self.loop_run(client.status()).state, "paired")
        self.assertIsNotNone(self.loop_run(client.enrollment_grant()))
        self.assertIsNone(self.loop_run(client.capability_grant()))

    def test_client_rejects_current_reply_without_exact_bound_fields(self) -> None:
        profile = AuthorityTlsProfile(
            "production", "authority.example", 443, "authority.example",
            "authority-1",
            self.root / "admin" / "authority-ca.pem",
            self.root / "admin" / "client.pem",
            self.root / "admin" / "client.key",
        )

        class ReplyTransport(MtlsAuthorityTransport):
            async def _content_rpc(self, request, handshake, method, command):
                return {
                    "authority_id": "authority-1", "namespace": "ns:role",
                    "holder": "host:one", "generation": 1, "phase": "active",
                    "operation_id": None,
                }

        transport = ReplyTransport({"production": profile})
        handshake = AuthorityHandshake(
            "paired", "authority-1", "mtls:sha256:" + "b" * 64, "c" * 64, True
        )
        with self.assertRaisesRegex(RuntimeError, "current response"):
            self.loop_run(transport.current(self.request, handshake, "ns:role"))

    def test_profile_rejects_missing_or_invalid_pinned_authority_identity(self) -> None:
        fields = dict(
            profile_id="production", host="authority.example", port=443,
            server_name="authority.example", trust_root=self.root / "admin" / "ca.pem",
            client_certificate=self.root / "admin" / "client.pem",
            client_private_key=self.root / "admin" / "client.key",
        )
        with self.assertRaises(TypeError):
            AuthorityTlsProfile(**fields)
        for value in ("", "authority id", "../authority"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "authority identity"):
                AuthorityTlsProfile(**fields, expected_authority_id=value)

    @staticmethod
    def loop_run(coroutine):
        import asyncio
        return asyncio.run(coroutine)


if __name__ == "__main__":
    unittest.main()


def test_shared_channel_preserves_existing_contract_identity_and_type_hints():
    import inspect
    from typing import get_type_hints
    from sylanne3.host import authority_client, authority_transport_contract, mtls_channel, mtls_transport

    for name in (
        "PublisherPackageIdentity", "AuthorityProvisioningRequest", "AuthorityHandshake",
        "AuthorityEnrollmentGrant", "AuthorityCapabilityGrant",
    ):
        shared = getattr(authority_transport_contract, name)
        assert getattr(authority_client, name) is shared
        assert shared.__module__ == "sylanne3.host.authority_transport_contract"
        get_type_hints(shared)
    assert mtls_transport.AuthorityTlsProfile is authority_transport_contract.AuthorityTlsProfile
    assert get_type_hints(authority_transport_contract.AuthorityTlsProfile)["trust_root"] is Path
    assert get_type_hints(authority_transport_contract.AuthorityProvisioningRequest)["publisher_package"] is PublisherPackageIdentity
    assert authority_client.AUTHORITY_PROTOCOL is authority_transport_contract.AUTHORITY_PROTOCOL
    assert authority_client.AUTHORITY_V2_PROTOCOL is authority_transport_contract.AUTHORITY_V2_PROTOCOL
    assert authority_client.REQUIRED_AUTHORITY_CAPABILITIES is authority_transport_contract.REQUIRED_AUTHORITY_CAPABILITIES
    for name in (
        "AuthorityChannelUnavailable", "V2OwnerAuthorizationBarrier",
        "V2PlatformObservationVerifierUnavailable",
    ):
        assert getattr(mtls_transport, name) is getattr(mtls_channel, name)
    assert issubclass(MtlsAuthorityTransport, mtls_channel.MtlsAuthorityChannel)
    for owner in (mtls_channel.MtlsAuthorityChannel, MtlsAuthorityTransport):
        for method in vars(owner).values():
            if isinstance(method, staticmethod):
                method = method.__func__
            if inspect.isfunction(method):
                get_type_hints(method)
    for name in ("_rpc", "_content_rpc", "handshake", "installation_grant_v2", "close"):
        assert getattr(MtlsAuthorityTransport, name) is getattr(mtls_channel.MtlsAuthorityChannel, name)
