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
from sylanne3.authority_service.v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from sylanne3.authority_service.v2_accounting_service import AuthorityV2AccountingMaintenanceService
from sylanne3.authority_service.v2_accounting_wire import (
    from_wire as accounting_from_wire, to_wire as accounting_to_wire,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.mtls_server import AuthorityRpcServer
from sylanne3.authority_service.mtls_server import AuthorityServerTlsConfig, MtlsPeerCredential
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelAdmissionV2, HostObservedModelCompletionV2, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.v2_model_egress_wire import from_wire, to_wire
from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, TerminalRecoveryReadRequestV1,
    TerminalRecoveryReadAttemptV1,
    from_wire as terminal_c02_from_wire, to_wire as terminal_c02_to_wire,
)
from sylanne3.host.authority_profile import AdminIngressModelPolicy, installed_model_config_ref
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.deletion import DeletionJournal


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
                await transport._content_rpc(
                    request, handshake, "model_read_observation_v2", {
                        "namespace": "ns-a", "call_id": "forged-call",
                        "graph_current": True, "owner_current": True,
                        "receipt": {"admission_id": "a" * 64},
                    }, protocol=AUTHORITY_V2_PROTOCOL)
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
        accounting = AuthorityV2AccountingMaintenanceService(
            store=store, fences=fences, subject=subject, holder="holder-a")
        server = AuthorityRpcServer(
            base._core,
            administrator_authorizer=base._administrator_authorizer,
            publisher_manifest_verifier=base._publisher_manifest_verifier,
            v2_fences=fences, v2_model_egress={"ns-a": model},
            model_observers_v2={"ns-a": (_PEER_A.certificate_sha256, "profile-a")},
            v2_accounting={"ns-a": accounting},
            accounting_observers_v2={"ns-a": (_PEER_A.certificate_sha256, "profile-a")},
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
        # Versioned admission binds one host observer. A later v1 admission
        # cannot acquire a v2 terminal receipt.
        request2 = replace(
            request, call_id="call-2",
            envelope=replace(request.envelope,
                             identity=replace(request.identity,
                                              operation_id="job-operation-2")))
        draft2 = replace(draft, call_id="call-2", job_id="job-2",
                         operation_id="job-operation-2", request_digest=request2.digest,
                         acquire_operation_id="job-operation-2",
                         binding_digest="e" * 64)
        prepared2 = call("model_prepare_fenced_v1", {
            **prepared_command, "draft": to_wire(draft2)})
        intent2 = from_wire(prepared2["record"], ModelEgressRecoveryV1).intent
        lookup = {
            "namespace": "ns-a",
            "installation_id": base._installations_v2[
                (_PEER_A.certificate_sha256, "profile-a")].installation_id,
            "job_id": draft2.job_id,
            "acquire_operation_id": draft2.acquire_operation_id,
            "original_model_operation_id": draft2.operation_id,
            "call_id": draft2.call_id,
            "request_digest": draft2.request_digest,
            "binding_digest": draft2.binding_digest,
        }
        recovery_identity = {
            **lookup, "business_namespace": {"bot_id": "bot-a", "persona_id": "persona-a"},
            "original_operation_id": draft2.budget_reservation_operation_id,
        }
        assert call("model_original_intent_lookup_v1", lookup)["status"] == "prepared"
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_terminal_recovery_identity_v1", recovery_identity)
        assert call("model_original_intent_lookup_v1", {
            **lookup, "call_id": "absent-call"})["status"] == "absent"
        for changed in ({"binding_digest": "f" * 64},
                        {"job_id": "other-job"},
                        {"installation_id": "other-installation"},
                        {"namespace": "ns-b"}):
            with pytest.raises(RuntimeError, match="authority unavailable"):
                call("model_original_intent_lookup_v1", {**lookup, **changed})
        with pytest.raises(RuntimeError, match="authority unavailable"):
            other("model_original_intent_lookup_v1", lookup)
        admit2 = {"namespace": "ns-a", "holder": "holder-a",
                  "intent": to_wire(intent2), "expected_anchor": anchor_wire,
                  "request": to_wire(request2), "host_incarnation": "a" * 64}
        with pytest.raises(RuntimeError, match="authority unavailable"):
            other("model_admit_dispatch_once_v2", admit2)
        admitted2 = call("model_admit_dispatch_once_v2", admit2)
        admission = from_wire(admitted2["admission"], ModelAdmissionV2)
        assert admission.provider_config_digest == intent2.provider_config_digest
        assert admission.host_incarnation == "a" * 64
        assert admitted2["record"]["state"] == "dispatch_started"
        assert call("model_original_intent_lookup_v1", lookup)["status"] == "dispatch_started"
        accounting_request = AccountingMaintenanceRequestV1(
            "accounting-original-call", intent2, anchor)
        with pytest.raises(AuthorityUnavailable, match="unresolved"):
            accounting.begin(credential=_PEER_A, request=accounting_request)
        assert fences.fences._row(fences.core._db, intent2.operation_id)[6] == "active"
        terminal_query = {"namespace": "ns-a", "holder": "holder-a",
                          "intent": to_wire(intent2)}
        unresolved = call("model_terminal_fact_v2", terminal_query)
        assert unresolved["record"]["state"] == "dispatch_started"
        assert unresolved["admission"] == to_wire(admission)
        assert unresolved["receipt"] is None
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v2", admit2)
        report = HostObservedModelCompletionV2(
            admission.admission_id, admission.host_incarnation,
            intent2.call_id, intent2.request_digest, intent2.provider_id,
            intent2.model_id, intent2.provider_config_digest,
            '{"answer":"ok"}', (("input_tokens", 1),),
            (("micro_usd", 2),), "provider-ref")
        complete = {"namespace": "ns-a", "holder": "holder-a",
                    "intent": to_wire(intent2), "expected_anchor": anchor_wire,
                    "admission": to_wire(admission), "report": to_wire(report)}
        with pytest.raises(RuntimeError, match="authority unavailable"):
            other("model_complete_observed_v2", complete)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_complete_observed_v2", {
                **complete, "report": to_wire(replace(report, host_incarnation="b" * 64))})
        original_finish = fences.fences.finish_terminal_model_egress_locked

        def fail_after_finish(*args, **kwargs):
            original_finish(*args, **kwargs)
            raise RuntimeError("lost terminal commit")

        monkeypatch.setattr(fences.fences, "finish_terminal_model_egress_locked",
                            fail_after_finish)
        with pytest.raises(RuntimeError, match="lost terminal commit"):
            call("model_complete_observed_v2", complete)
        assert call("model_recover_fenced_v1", {
            "namespace": "ns-a", "holder": "holder-a",
            "intent": to_wire(intent2)})["record"]["state"] == "dispatch_started"
        assert fences.fences._row(fences.core._db, intent2.operation_id)[6] == "active"
        monkeypatch.setattr(fences.fences, "finish_terminal_model_egress_locked",
                            original_finish)
        completed = call("model_complete_observed_v2", complete)
        receipt = from_wire(completed["receipt"], ModelTerminalReceiptV2)
        assert completed["record"]["state"] == "observed"
        assert receipt.report_digest == report.digest
        assert fences.fences._row(fences.core._db, intent2.operation_id)[6] == "finished"
        recovered_lookup = call("model_original_intent_lookup_v1", lookup)
        assert recovered_lookup["status"] == "terminal"
        assert recovered_lookup["terminal"] == to_wire(receipt)
        assert "result_json" not in json.dumps(recovered_lookup)
        terminal_identity = call("model_terminal_recovery_identity_v1", recovery_identity)
        original_key = terminal_c02_from_wire(
            terminal_identity["original_key"], OriginalC02ResultKeyV1)
        assert original_key.original_model_operation_id == intent2.operation_id
        assert len(original_key.terminal_receipt_digest) == 64
        assert terminal_identity["stable_result_digest"] == original_key.stable_result_digest
        assert "result_json" not in json.dumps(terminal_identity)
        attempt_a = TerminalRecoveryReadRequestV1(original_key, "c02-operation", "read-attempt-a")
        attempt_b = TerminalRecoveryReadRequestV1(original_key, "c02-operation", "read-attempt-b")
        assert attempt_a.digest != attempt_b.digest
        assert attempt_a.original_key.stable_result_digest == attempt_b.original_key.stable_result_digest
        assert terminal_c02_from_wire(
            terminal_c02_to_wire(attempt_a), TerminalRecoveryReadRequestV1) == attempt_a
        finished_attempt = TerminalRecoveryReadAttemptV1(
            attempt_a, "a" * 64, "finished", original_key.stable_result_digest)
        assert terminal_c02_from_wire(
            terminal_c02_to_wire(finished_attempt),
            TerminalRecoveryReadAttemptV1) == finished_attempt
        with pytest.raises(ValueError, match="differs"):
            TerminalRecoveryReadAttemptV1(attempt_a, "a" * 64, "finished", "b" * 64)
        for changed in ({"binding_digest": "f" * 64},
                        {"original_operation_id": "other-operation"},
                        {"installation_id": "other-installation"},
                        {"business_namespace": {"bot_id": "bot-b", "persona_id": "persona-a"}}):
            with pytest.raises(RuntimeError, match="authority unavailable"):
                call("model_terminal_recovery_identity_v1", {
                    **recovery_identity, **changed})
        terminal = call("model_terminal_fact_v2", terminal_query)
        assert terminal["record"]["state"] == "observed"
        assert terminal["record"]["usage"] == [["input_tokens", 1]]
        assert terminal["record"]["cost"] == [["micro_usd", 2]]
        assert terminal["receipt"] == to_wire(receipt)
        assert "result_json" not in json.dumps(terminal)
        original_body_read = store._read_observation_locked
        monkeypatch.setattr(store, "_read_observation_locked",
                            lambda *_: (_ for _ in ()).throw(
                                AssertionError("accounting read provider body")))
        accounting_command = {
            "namespace": "ns-a", "request": accounting_to_wire(accounting_request)}
        with pytest.raises(AuthorityUnavailable, match="special"):
            fences.begin_fence(
                credential=_PEER_A, subject=subject, holder="holder-a",
                operation="accounting", operation_id="generic-accounting",
                expected_anchor=anchor)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            other("accounting_begin_v1", accounting_command)
        accounting_grant = accounting_from_wire(
            call("accounting_begin_v1", accounting_command)["grant"],
            AccountingMaintenanceGrantV1)
        assert accounting_grant.permit.operation == "accounting"
        assert accounting_grant.reservation_digest == intent2.budget_reservation_digest
        assert accounting_grant.observation_digest == receipt.observation_digest
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("accounting_validate_v1", {
                **accounting_command,
                "grant": accounting_to_wire(replace(
                    accounting_grant,
                    reservation_digest="f" * 64))})
        assert call("accounting_validate_v1", {
            **accounting_command, "grant": accounting_to_wire(accounting_grant)})["valid"] is True
        with pytest.raises(AuthorityUnavailable, match="active"):
            fences.begin_fence(
                credential=_PEER_A, subject=subject, holder="holder-a",
                operation="read", operation_id="read-during-accounting",
                expected_anchor=anchor)
        with pytest.raises(AuthorityUnavailable, match="dedicated"):
            fences.finish_fence(
                credential=_PEER_A, subject=subject,
                permit=accounting_grant.permit,
                request_id="generic-finish", request_digest="sha256:" + "e" * 64)
        original_accounting_finish = fences.fences.finish_fence_locked

        def lose_accounting_finish(*args, **kwargs):
            original_accounting_finish(*args, **kwargs)
            raise RuntimeError("lost accounting commit")

        monkeypatch.setattr(fences.fences, "finish_fence_locked",
                            lose_accounting_finish)
        with pytest.raises(RuntimeError, match="lost accounting commit"):
            call("accounting_finish_v1", {
                **accounting_command, "grant": accounting_to_wire(accounting_grant)})
        assert fences.fences._row(fences.core._db,
                                  accounting_request.operation_id)[6] == "active"
        monkeypatch.setattr(fences.fences, "finish_fence_locked",
                            original_accounting_finish)
        assert call("accounting_finish_v1", {
            **accounting_command, "grant": accounting_to_wire(accounting_grant)})["finished"] is True
        assert call("accounting_recover_finish_v1", accounting_command)["finished"] is True
        assert fences.fences._row(fences.core._db,
                                  accounting_request.operation_id)[6] == "finished"
        monkeypatch.setattr(store, "_read_observation_locked", original_body_read)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            other("model_terminal_fact_v2", terminal_query)
        # The terminal receipt is not a current Owner read grant, even for the
        # observer that submitted the complete response.
        with pytest.raises(AuthorityUnavailable, match="Owner-qualified"):
            model.read_observation_fenced(
                credential=_PEER_A, subject=subject, intent=intent2)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_read_observation_v2", {
                "namespace": "ns-a", "holder": "holder-a",
                "intent": to_wire(intent2), "receipt": to_wire(receipt),
                "graph_current": True, "owner_current": True})
        assert call("model_complete_observed_v2", complete) == completed
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_complete_observed_v2", {
                **complete, "report": to_wire(replace(report, result_json='{"answer":"other"}'))})
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_complete_observed_v2", {
                **complete, "report": {**to_wire(report), "status": "unknown"}})
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
        assert "result" not in result and len(observed) == 2
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", admit)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", {
                **admit, "request": {**to_wire(request), "provider_id": "other"}})
        assert len(observed) == 2
        assert call("model_recover_fenced_v1", recover)["record"]["state"] == "dispatch_started"
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_complete_observed_v2", {
                **complete, "intent": to_wire(record.intent)})
        for method in ("model_finish_v1", "model_execute_call_v1"):
            with pytest.raises(RuntimeError, match="authority unavailable"):
                call(method, admit)
        assert from_wire(to_wire(request), ModelCallRequest).digest == request.digest
        assert from_wire(to_wire(record.intent), ModelEgressIntentV1) == record.intent
        malformed = to_wire(request)
        malformed["envelope"]["authority"]["namespace"]["persona_id"] = "persona-b"
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("model_admit_dispatch_once_v1", {**admit, "request": malformed})
        deletion = DeletionJournal(tmp_path / "deletion.db")
        try:
            deletion.append_intent(
                namespace="ns-a", operation_id="delete-accounting",
                closure_roots=("source-a",), epoch=1, policy_ref="policy-a")
            with pytest.raises(AuthorityUnavailable, match="deletion pending"):
                accounting.begin(
                    credential=_PEER_A,
                    request=replace(accounting_request,
                                    operation_id="accounting-after-delete-pending"))
        finally:
            deletion.close()


    finally:
        if server is not None:
            asyncio.run(server.aclose())
        try:
            next(fixture)
        except StopIteration:
            pass


def test_admin_v3_c02_encoding_policy_matches_request_and_refuses_foreign_model(tmp_path):
    """C02's normal encoding policy must remain usable beside named V6 routes."""
    from rewrite.tests.alpha1.authority.test_v2_model_egress_store import connection
    from sylanne3.host.authority_profile import AdminModelWorkflowV2
    from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
    from sylanne3.model_broker.first_ingress_encoding import (
        FIRST_INGRESS_ENCODING_TEMPLATE_VERSION, FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    )
    from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION

    ceiling = {"input_tokens": 1000, "output_tokens": 256,
               "model_tokens": 1256, "model_microusd": 100}
    common = dict(provider_id="provider-1", model_id="model-1",
        provider_config_ref=installed_model_config_ref("provider-1", "model-1", "d" * 64),
        provider_config_digest="d" * 64, audiences=("owner",), privacy_tier="private",
        required_capabilities=("text",), timeout_seconds=20.0,
        max_output_tokens=256, quote_ceiling=ceiling)
    encode = AdminModelWorkflowV2(work_kind="d06.encode_source", purpose="consolidation",
        template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION, **common)
    reply = AdminModelWorkflowV2(work_kind="reply", purpose="proposal",
        template_version=REPLY_TEMPLATE_VERSION, **common)
    policy = AdminModelWorkflowsV3(3, encode, reply)
    base = broker_request()
    envelope = replace(base.envelope,
        identity=replace(base.identity, phase="encode", operation_id="job-operation"),
        authority=replace(base.envelope.authority, actor="worker", issuer_domain="d11",
            purpose="consolidation", audience=("owner",), worker_fence=7))
    request = replace(base, envelope=envelope, call_id="call-1",
        provider_id=encode.provider_id, model_id=encode.model_id,
        prompt_template_digest=FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
        privacy_tier=encode.privacy_tier, required_capabilities=frozenset(encode.required_capabilities),
        timeout_seconds=encode.timeout_seconds, max_output_tokens=encode.max_output_tokens)
    original = intent(request_digest=request.digest,
                      budget_ceiling=tuple(sorted(ceiling.items())))
    with connection(tmp_path / "c02-policy-authority.db") as db:
        service = AuthorityV2ModelEgressService(
            AuthorityV2ModelEgressStore(db, create=True), admin_model_policy=policy)
        assert service._admin_model_matches(original, request)
        foreign = replace(request, model_id="other-model")
        foreign_intent = replace(original, model_id=foreign.model_id, request_digest=foreign.digest)
        assert not service._admin_model_matches(foreign_intent, foreign)
