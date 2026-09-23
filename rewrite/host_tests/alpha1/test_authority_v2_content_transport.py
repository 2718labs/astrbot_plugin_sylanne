"""Host transport keeps typed v2 content permits bound to their request."""

import asyncio
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import types
import unittest

from sylanne3.authority_service.contract import CONTENT_OPERATIONS
from sylanne3.authority_service.v2_contract import FencePermitV2, SCHEMA, to_wire
# Import the transport without requiring an installed AstrBot host.
_host_package = sys.modules.get("sylanne3.host")
if _host_package is None:
    _host_package = types.ModuleType("sylanne3.host")
    _host_package.__path__ = [str(Path(__file__).resolve().parents[2] / "sylanne3" / "host")]
    sys.modules["sylanne3.host"] = _host_package
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityHandshake, AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import (
    AuthorityTlsProfile, MtlsAuthorityTransport, _Session, _canonical, _request_payload,
)
if not hasattr(_host_package, "__file__"):
    sys.modules.pop("sylanne3.host", None)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    InstallationGrantV2, NamespaceBootstrapV2, NamespaceId, NamespaceRuntimeState,
)


class ContentTransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "authority", "astrbot_plugin_sylanne", "4.28.1",
            root, root, PublisherPackageIdentity("a" * 64),
        )
        self.handshake = AuthorityHandshake(
            "paired", "authority-1", "mtls:sha256:" + "b" * 64, "c" * 64, True,
        )
        self.anchor = RestoreAnchor(
            "authority-1", "ns:role", 1, "deletion", 0, "genesis",
            "execution", 0, "genesis", 0, "proof-a",
        )
        profile = AuthorityTlsProfile(
            "authority", "localhost", 443, "localhost", "authority-1",
            root / "ca.pem", root / "client.pem", root / "client.key",
        )
        self.transport = MtlsAuthorityTransport({"authority": profile})
        self.calls = []

        async def content_rpc(request, handshake, method, command, *, protocol=AUTHORITY_PROTOCOL):
            self.calls.append((method, command, protocol))
            if method == "finish_fence":
                return {"finished": True, "channel_binding_sha256": handshake.channel_binding_sha256}
            if method == "begin_fence":
                operation = command["operation"]
                permit = self._permit(operation, command["operation_id"])
            else:
                permit = self._permit_from_wire(command["permit"])
            return {"permit": to_wire(permit),
                    "channel_binding_sha256": handshake.channel_binding_sha256}

        self.transport._content_rpc = content_rpc

    def tearDown(self):
        self.temp.cleanup()

    def _permit(self, operation, operation_id="operation-a"):
        return FencePermitV2(
            "authority-1", "ns:role", "mtls:sha256:" + "d" * 64,
            "holder-a", 1, operation, operation_id, "t" * 32, 0, 0, self.anchor,
        )

    @staticmethod
    def _permit_from_wire(value):
        from sylanne3.authority_service.v2_contract import from_wire
        return from_wire(value)

    async def test_all_non_dispatch_content_operations_round_trip(self):
        for operation in sorted(CONTENT_OPERATIONS - {"dispatch"}):
            with self.subTest(operation=operation):
                permit = await self.transport.v2_begin_content_fence(
                    self.request, self.handshake, namespace="ns:role", holder="holder-a",
                    operation=operation, operation_id="operation-a", expected_anchor=self.anchor,
                )
                self.assertEqual(permit.operation, operation)
                self.assertEqual(await self.transport.v2_validate_fence(
                    self.request, self.handshake, permit), permit)
                await self.transport.v2_finish_fence(
                    self.request, self.handshake, permit,
                    request_id="finish-a", request_digest="sha256:" + "e" * 64,
                )
        self.assertTrue(all(protocol == SCHEMA for _, _, protocol in self.calls))

    async def test_read_compatibility_and_non_content_permits_fail_before_rpc(self):
        permit = await self.transport.v2_begin_read_fence(
            self.request, self.handshake, namespace="ns:role", holder="holder-a",
            operation_id="operation-a", expected_anchor=self.anchor,
        )
        self.assertEqual(permit.operation, "read")
        before = len(self.calls)
        for operation in ("dispatch", "delete", "unknown"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                await self.transport.v2_begin_content_fence(
                    self.request, self.handshake, namespace="ns:role", holder="holder-a",
                    operation=operation, operation_id="operation-a", expected_anchor=self.anchor,
                )
        self.assertEqual(len(self.calls), before)
        dispatch = replace(permit, operation="dispatch", effect_id="effect-a",
                           command_digest="sha256:" + "a" * 64,
                           footprint_digest="sha256:" + "b" * 64)
        for method in ("v2_validate_fence", "v2_finish_fence"):
            with self.subTest(method=method), self.assertRaises(TypeError):
                if method == "v2_validate_fence":
                    await self.transport.v2_validate_fence(self.request, self.handshake, dispatch)
                else:
                    await self.transport.v2_finish_fence(
                        self.request, self.handshake, dispatch,
                        request_id="finish-a", request_digest="sha256:" + "e" * 64,
                    )
        self.assertEqual(len(self.calls), before)

    async def test_v1_session_and_wrong_handshake_binding_cannot_send_v2_rpc(self):
        class Writer:
            def is_closing(self):
                return False

        self.transport._content_rpc = MtlsAuthorityTransport._content_rpc.__get__(self.transport)
        self.transport._owner_loop = asyncio.get_running_loop()
        v1_digest = hashlib.sha256(_canonical(_request_payload(self.request))).hexdigest()
        self.transport._sessions["authority"] = _Session(
            None, Writer(), self.handshake.channel_binding_sha256, v1_digest,
        )
        with self.assertRaisesRegex(RuntimeError, "handshake channel"):
            await self.transport.v2_begin_content_fence(
                self.request, self.handshake, namespace="ns:role", holder="holder-a",
                operation="write", operation_id="operation-a", expected_anchor=self.anchor,
            )
        v2_request = _request_payload(self.request)
        v2_request["protocol"] = SCHEMA
        self.transport._sessions["authority"].request_digest = hashlib.sha256(
            _canonical(v2_request)).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "handshake channel"):
            await self.transport.v2_begin_content_fence(
                self.request, replace(self.handshake, channel_binding_sha256="f" * 64),
                namespace="ns:role", holder="holder-a", operation="write",
                operation_id="operation-a", expected_anchor=self.anchor,
            )

    async def test_installation_grant_checks_exact_v2_response_and_bindings(self):
        grant = InstallationGrantV2(
            authority_id="authority-1", subject=self.handshake.installation_identity_ref,
            administrator_holder="admin-holder", installation_id="installation-a",
            manifest_digest="a" * 64, publisher_policy_ref="policy-a",
            service_capability_version="capabilities-v2",
            channel_binding_sha256=self.handshake.channel_binding_sha256,
        )
        response = asdict(grant)
        calls = []

        async def rpc(request, handshake, method, command, *, protocol):
            calls.append((method, command, protocol))
            return response

        self.transport._content_rpc = rpc
        self.assertEqual(
            await self.transport.installation_grant_v2(self.request, self.handshake), grant,
        )
        self.assertEqual(calls, [("installation_grant_v2", {}, SCHEMA)])
        for changed in (
            {**response, "extra": "forged"},
            {**response, "subject": "mtls:sha256:" + "d" * 64},
            {**response, "authority_id": "other-authority"},
            {**response, "manifest_digest": "d" * 64},
            {**response, "channel_binding_sha256": "d" * 64},
            {**response, "schema": "sylanne3.authority.v1"},
        ):
            response = changed
            with self.assertRaises(RuntimeError):
                await self.transport.installation_grant_v2(self.request, self.handshake)

    async def test_v1_session_cannot_request_installation_grant(self):
        class Writer:
            def is_closing(self):
                return False

        self.transport._content_rpc = MtlsAuthorityTransport._content_rpc.__get__(self.transport)
        self.transport._owner_loop = asyncio.get_running_loop()
        digest = hashlib.sha256(_canonical(_request_payload(self.request))).hexdigest()
        self.transport._sessions["authority"] = _Session(
            None, Writer(), self.handshake.channel_binding_sha256, digest,
        )
        with self.assertRaisesRegex(RuntimeError, "handshake channel"):
            await self.transport.installation_grant_v2(self.request, self.handshake)

    async def test_namespace_bootstrap_parses_exact_observation_and_rejects_forgery(self):
        namespace = NamespaceId("bot-a", "persona-a")
        observed = NamespaceBootstrapV2(
            "authority-1", namespace, "ns:role", "holder-a", 1, "active",
            NamespaceRuntimeState.ACTIVE, self.anchor, (),
        )
        response = {
            **asdict(observed), "state": "active", "blocking_reasons": [],
            "channel_binding_sha256": self.handshake.channel_binding_sha256,
        }
        calls = []

        async def rpc(request, handshake, method, command, *, protocol):
            calls.append((method, command, protocol))
            return response

        self.transport._content_rpc = rpc
        self.assertEqual(await self.transport.v2_namespace_bootstrap(
            self.request, self.handshake, namespace), observed)
        self.assertEqual(calls, [(
            "namespace_bootstrap", {"namespace": asdict(namespace)}, SCHEMA)])
        original = response
        for response in (
            {**original, "extra": "permit"},
            {**original, "namespace": {"bot_id": "bot-a", "persona_id": "persona-b"}},
            {**original, "authority_id": "other-authority"},
            {**original, "state": "unknown"},
            {**original, "anchor": {**original["anchor"], "proof": ""}},
            {**original, "anchor": {**original["anchor"], "extra": True}},
        ):
            with self.assertRaises(RuntimeError):
                await self.transport.v2_namespace_bootstrap(
                    self.request, self.handshake, namespace)
