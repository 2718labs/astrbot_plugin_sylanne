"""The model RPC exposes identity and one CAS, never a provider result."""

import asyncio
from dataclasses import replace
import hashlib
import json
import ssl

import pytest

from rewrite.tests.alpha1.model_broker.test_broker import request as broker_request
from rewrite.host_tests.alpha1.test_authority_mtls_loopback import AuthorityMtlsLoopbackTests
from rewrite.tests.alpha1.runtime.test_authority_v2_rpc_content_fences import (
    _PEER_A, _PEER_B, _REQUEST, paired, rpc,
)
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.mtls_server import AuthorityRpcServer
from sylanne3.authority_service.mtls_server import AuthorityServerTlsConfig, MtlsPeerCredential
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
)
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.v2_model_egress_wire import from_wire, to_wire
from sylanne3.host.authority_profile import AdminIngressModelPolicy, installed_model_config_ref
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.runtime_contracts import NamespaceId


def test_real_mtls_generic_model_begin_cannot_leave_orphan_fence(tmp_path, monkeypatch):
    import rewrite.tests.alpha1.runtime.test_authority_v2_rpc_content_fences as fixture_module

    files = AuthorityMtlsLoopbackTests._certificates(tmp_path)
    certificate = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text("ascii"))
    peer = MtlsPeerCredential(hashlib.sha256(certificate).hexdigest())
    monkeypatch.setattr(fixture_module, "_PEER_A", peer)
    fixture = fixture_module.rpc.__wrapped__(tmp_path)
    server = next(fixture)

    async def exercise():
        listener = await server.start(
            "127.0.0.1", 0,
            AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]), str(files["ca.pem"]),
                timeout_seconds=2),
        )
        profile = AuthorityTlsProfile(
            "profile-a", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", server._authority_id(), files["ca.pem"],
            files["client.pem"], files["client.key"], timeout_seconds=2,
        )
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "profile-a",
            "astrbot_plugin_sylanne", "4.28.1", tmp_path, tmp_path,
            PublisherPackageIdentity("c" * 64),
        )
        transport = MtlsAuthorityTransport({"profile-a": profile})
        try:
            handshake = await transport.handshake(
                request, protocol=AUTHORITY_V2_PROTOCOL)
            anchor = await transport.v2_current_anchor(request, handshake, "ns-a")
            with pytest.raises(RuntimeError, match="unavailable"):
                # Send the old generic command through the actual TLS channel,
                # bypassing any current host-side operation allowlist.
                await transport._content_rpc(
                    request, handshake, "begin_fence", {
                        "namespace": "ns-a", "holder": "holder-a",
                        "operation": "model_egress", "operation_id": "orphan-model",
                        "expected_anchor": server._anchor_payload(anchor),
                    }, protocol=AUTHORITY_V2_PROTOCOL)
            assert server._v2_fences["ns-a"].fences._row(
                server._core._db, "orphan-model") is None
            permit = await transport.v2_begin_content_fence(
                request, handshake, namespace="ns-a", holder="holder-a",
                operation="read", operation_id="ordinary-read",
                expected_anchor=anchor)
            await transport.v2_finish_fence(
                request, handshake, permit, request_id="finish-read",
                request_digest="sha256:" + "e" * 64)
            assert server._v2_fences["ns-a"].fences._row(
                server._core._db, "ordinary-read")[6] == "finished"
        finally:
            await transport.close()
            listener.close()
            await listener.wait_closed()
            await server.aclose()

    try:
        asyncio.run(exercise())
    finally:
        try:
            next(fixture)
        except StopIteration:
            pass


def test_mtls_model_prepare_admit_recover_exact_identity(tmp_path, monkeypatch):
    fixture = rpc.__wrapped__(tmp_path)
    base = next(fixture)
    server = None
    try:
        fences = base._v2_fences["ns-a"]
        store = AuthorityV2ModelEgressStore(
            fences.core._db, create=True, lock=fences.core._lock)
        subject = "mtls:sha256:" + _PEER_A.certificate_sha256
        anchor = fences.current_anchor(credential=_PEER_A, subject=subject)
        base_request = broker_request()
        envelope = replace(
            base_request.envelope,
            identity=replace(base_request.identity, operation_id="job-operation"),
            authority=replace(
                base_request.envelope.authority, actor=subject,
                issuer_domain="d11", namespace=NamespaceId("bot-a", "persona-a"),
                worker_fence=7),
            version_guard=replace(base_request.envelope.version_guard,
                                  read_versions=(), query_epochs=()),
        )
        request = replace(
            base_request, envelope=envelope, call_id="call-1",
            provider_id="provider-1", model_id="model-1",
            required_capabilities=frozenset({"text"}), timeout_seconds=20.0,
            max_output_tokens=256)
        draft = ModelEgressDraftV1.from_intent(intent(
            authority_id=anchor.authority_id, namespace="ns-a", subject=subject,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq,
            request_digest=request.digest,
            budget_ceiling=(("output_tokens", 256),)))
        config_digest = "d" * 64
        policy = AdminIngressModelPolicy(
            "provider-1", "model-1",
            installed_model_config_ref("provider-1", "model-1", config_digest),
            config_digest, 20.0, 256, ("text",), "private",
            ("proposal",), ("owner",), ("private",))
        verifier = object.__new__(PinnedCurrentModelEgressGraphVerifier)
        observed = []

        def graph_current(candidate):
            # Test-only stub checks lock placement and CAS; production pins a DB.
            assert not fences.core._db.in_transaction
            observed.append(candidate)
            return True

        monkeypatch.setattr(verifier, "complete_graph_current", graph_current)
        model = AuthorityV2ModelEgressService(
            store, fences, graph_verifier=verifier, admin_model_policy=policy)
        server = AuthorityRpcServer(
            base._core,
            administrator_authorizer=base._administrator_authorizer,
            publisher_manifest_verifier=base._publisher_manifest_verifier,
            v2_fences=fences, v2_model_egress={"ns-a": model},
            installations_v2=base._installations_v2,
            namespace_bindings_v2=base._namespace_bindings_v2,
        )
        call = paired(server, _PEER_A, b"model-channel-a")
        other = paired(server, _PEER_B, b"model-channel-b")
        anchor_wire = server._anchor_payload(anchor)
        prepared_command = {
            "namespace": "ns-a", "holder": "holder-a", "draft": to_wire(draft),
            "expected_anchor": anchor_wire,
        }
        with pytest.raises(RuntimeError, match="authority unavailable"):
            paired(base, _PEER_A, b"no-model-install")(
                "model_prepare_fenced_v1", prepared_command)
        for changed_request in (
                {**_REQUEST, "profile_id": "other-profile"},
                {**_REQUEST, "manifest_sha256": "e" * 64}):
            channel = b"wrong-model-install"
            handshake = server._dispatch_for_test(
                "handshake", changed_request, _PEER_A, channel)
            with pytest.raises(RuntimeError, match="authority unavailable"):
                server._dispatch_for_test(
                    "model_prepare_fenced_v1", changed_request, _PEER_A, channel,
                    handshake_binding=handshake["channel_binding_sha256"],
                    command=prepared_command)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            other("model_prepare_fenced_v1", prepared_command)
        for change in ({"holder": "other-holder"}, {"namespace": "ns-b"},
                       {"graph_current": True}):
            with pytest.raises(RuntimeError, match="authority unavailable"):
                call("model_prepare_fenced_v1", {**prepared_command, **change})
        prepared = call("model_prepare_fenced_v1", json.loads(json.dumps(prepared_command)))
        assert call("model_prepare_fenced_v1", prepared_command)["record"] == prepared["record"]
        record = from_wire(prepared["record"], ModelEgressRecoveryV1)
        assert record.state == "prepared" and record.intent.subject == subject
        assert to_wire(record.intent) == prepared["record"]["intent"]
        assert prepared["record"]["state"] == "prepared"
        assert "result" not in prepared
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_prepare_fenced_v1", {
                **prepared_command, "draft": {**to_wire(draft), "request_digest": "e" * 64}})
        with pytest.raises(RuntimeError, match="authority unavailable"):
            other("model_recover_fenced_v1", {
                "namespace": "ns-a", "holder": "holder-a", "intent": to_wire(record.intent)})
        recover = {"namespace": "ns-a", "holder": "holder-a",
                   "intent": to_wire(record.intent)}
        assert call("model_recover_fenced_v1", recover)["record"] == prepared["record"]
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_recover_fenced_v1", {**recover, "holder": "other-holder"})
        admit = {**recover, "expected_anchor": anchor_wire, "request": to_wire(request)}
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", {**admit, "graph_current": True})
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", {
                **admit, "request": {**to_wire(request), "graph_current": True}})
        result = call("model_admit_dispatch_once_v1", json.loads(json.dumps(admit)))
        assert result["record"]["state"] == "dispatch_started"
        assert "result" not in result and len(observed) == 1
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", admit)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", {
                **admit, "request": {**to_wire(request), "provider_id": "other"}})
        assert len(observed) == 1
        assert call("model_recover_fenced_v1", recover)["record"]["state"] == "dispatch_started"
        for method in ("model_finish_v1", "model_execute_call_v1"):
            with pytest.raises(RuntimeError, match="authority unavailable"):
                call(method, admit)
        assert from_wire(to_wire(request), ModelCallRequest).digest == request.digest
        assert from_wire(to_wire(record.intent), ModelEgressIntentV1) == record.intent
        malformed = to_wire(request)
        malformed["envelope"]["authority"]["namespace"]["persona_id"] = "persona-b"
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", {**admit, "request": malformed})
    finally:
        if server is not None:
            asyncio.run(server.aclose())
        try:
            next(fixture)
        except StopIteration:
            pass
