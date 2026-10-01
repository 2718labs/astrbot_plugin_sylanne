"""Reopen true Owner/C02 ledgers, then pay twice through the new mTLS Core."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import socket
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from rewrite.tests.alpha1.runtime.test_post_c02_reply_assembly_v2 import (
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)
from sylanne3.authority_service.daemon import open_authority_daemon
from sylanne3.authority_service.installed_platform_observation import HostOneBotObservationInstallationV2
from sylanne3.authority_service.local_bridge import constraint_keys_from_footprint
from sylanne3.authority_service.deployment_config import (
    AuthorityDeploymentConfig, ExecutionJournalInstallation,
    InstalledNaturalModelAuthorityV2,
)
from sylanne3.authority_service.installed_core_verifiers import (
    installed_core_verifier_factory,
)
from sylanne3.authority_service.mtls_server import AuthorityServerTlsConfig
from sylanne3.authority_service.v2_clock import AuthorityClockReadingV2
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityClient, AuthorityProvisioningRequest,
    AuthoritySelection, PublisherPackageIdentity,
)
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.model_broker.natural_reply import TEMPLATE_VERSION
from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from test_natural_p2_true_owner_handoff import (
    _pay_generation, _complete_generation, _prepare_review, _pay_review,
    _complete_review_and_final, _commit_final, _revoke_owner_after_final,
    _host_one_shot,
)


class _PaidModelRpcFacade:
    """Test adapter to the installed client's real channel-bound mTLS methods."""

    def __init__(self, client, bundle, grant, loop, store):
        self._client = client
        self._bundle = bundle
        self._grant = grant
        self._loop = loop
        self._store = store

    def _call(self, coroutine):
        return asyncio.run_coroutine_threadsafe(
            coroutine, self._loop).result(timeout=30)

    def prepare_fenced(self, **values):
        return self._call(self._client.model_prepare_fenced_v1(
            self._bundle, self._grant, draft=values["draft"],
            expected_anchor=values["expected_anchor"]))

    def admit_dispatch_once_v2(self, **values):
        return self._call(self._client.model_admit_dispatch_once_v2(
            self._bundle, self._grant, intent=values["intent"],
            expected_anchor=values["expected_anchor"],
            model_request=values["request"],
            host_incarnation=values["host_incarnation"]))

    def complete_observed_v2(self, **values):
        return self._call(self._client.model_complete_observed_v2(
            self._bundle, self._grant, intent=values["intent"],
            expected_anchor=values["expected_anchor"],
            admission=values["admission"], report=values["report"]))


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("onebot_outcome", (
    "accepted", "unknown", "revoked", "missing_observation"))
async def test_true_owner_c02_reopens_daemon_for_dual_paid_final_and_p2(
        tmp_path, monkeypatch, onebot_outcome):
    def workflows(base, _shared):
        return replace(
            base,
            natural_generation=replace(
                base.reply, work_kind="natural_generation",
                template_version=TEMPLATE_VERSION),
            natural_review=replace(
                base.reply, work_kind="natural_review",
                template_version=REVIEW_TEMPLATE_VERSION))

    async def after_c02(case):
        old_core = case["core"]
        old_listener = case["listener"]
        old_server = case["server"]
        old_loop = case["authority_loop"]

        async def close_old_listener():
            old_listener.close()
            await old_listener.wait_closed()
            await old_server.aclose()

        await asyncio.to_thread(case["admin_port"].close)
        await asyncio.to_thread(case["port"].close)
        await case["admin_transport"].close()
        await case["transport"].close()
        await case["client_transport"].close()
        await asyncio.to_thread(lambda: asyncio.run_coroutine_threadsafe(
            close_old_listener(), old_loop).result(timeout=30))
        old_core.close()
        case["execution"].close()
        case["deletion_guard"].close()
        case["deletion_journal"].close()

        files = case["files"]
        namespace = case["namespace"]
        authority_namespace = case["authority_namespace"]
        peer = case["peer"]
        policies = old_server._installations_v2
        bindings = old_server._namespace_bindings_v2
        installed = case["installed_bundle"]
        lock_file = tmp_path / "reopened-authority.lock"
        lock_file.write_bytes(b"\0")

        config = AuthorityDeploymentConfig(
            authority_db=tmp_path / "authority.db",
            deletion_db=tmp_path / "deletion.db",
            graph_db=tmp_path / "business.db",
            instance_lock=lock_file,
            execution_journals={authority_namespace:
                ExecutionJournalInstallation(
                    tmp_path / "execution.db", "execution")},
            tls=AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]),
                str(files["ca.pem"]), timeout_seconds=30,
                max_message_bytes=65_536),
            bind_host="127.0.0.1", bind_port=_free_port(),
            installations_v2=policies,
            namespace_bindings_v2=bindings,
            reverse_handoff_profiles={authority_namespace:
                case["reverse_client"].profile},
            reverse_handoff_issuers={authority_namespace: "issuer:reply"},
            core_authorizer=case["core_authorizer"],
            core_verifier_factory=installed_core_verifier_factory,
            administrator_authorizer=old_server._administrator_authorizer,
            publisher_manifest_verifier=old_server._publisher_manifest_verifier,
            utc_clock=lambda: datetime.now(timezone.utc),
            local_administrator_credential=lambda *_: None,
            natural_model_authorities_v2={authority_namespace:
                InstalledNaturalModelAuthorityV2(
                    case["d11_issuer"], installed.model_workflows,
                    (peer.certificate_sha256, "reply"))},
            clock_provider=lambda: AuthorityClockReadingV2(
                "clock:reply", time.time(), time.monotonic(),
                "epoch:reply", True, 0.1),
            self_identity_readers_v2={authority_namespace:
                (peer.certificate_sha256, "reply")},
            worker_result_fact_committers_v2={authority_namespace:
                (peer.certificate_sha256, "reply")},
            host_onebot_observations_v2=(
                {} if onebot_outcome == "missing_observation" else {
                    authority_namespace: HostOneBotObservationInstallationV2(
                        peer.certificate_sha256, "reply", "adapter:platform-1",
                        '["platform-1","aiocqhttp","10001"]', "clock:reply")}),
        )
        daemon = open_authority_daemon(config)
        try:
            assert daemon.core is not old_core
            assert daemon.server._core is daemon.core
            assert daemon.server._v2_model_egress[authority_namespace]._fences.core is daemon.core
            listener = await asyncio.to_thread(lambda:
                asyncio.run_coroutine_threadsafe(
                    daemon.start(), old_loop).result(timeout=30))
            assert listener.is_serving()
            profile = AuthorityTlsProfile(
                "reply", "127.0.0.1", config.bind_port, "localhost",
                daemon.server._authority_id(), files["ca.pem"],
                files["client.pem"], files["client.key"],
                timeout_seconds=30, max_message_bytes=65_536)
            transport = MtlsAuthorityTransport({"reply": profile})
            try:
                request = AuthorityProvisioningRequest(
                    AUTHORITY_PROTOCOL, "reply", "astrbot_plugin_sylanne",
                    "4.28.1", tmp_path, tmp_path,
                    PublisherPackageIdentity(
                        installed.installation_policy.manifest_digest))
                handshake = await transport.handshake(
                    request, protocol=AUTHORITY_V2_PROTOCOL)
                grant = await transport.installation_grant_v2(request, handshake)
                assert grant.subject == case["client_grant"].subject
                assert grant.authority_id == case["client_grant"].authority_id
                sample = await transport.ingress_clock_sample_v2(
                    request, handshake, grant.installation_id)
                assert sample.source_id == "clock:reply"
                new_port = await asyncio.to_thread(
                    V2FencePort, request, {"reply": profile}, grant)
                client_transport = MtlsAuthorityTransport({"reply": profile})
                try:
                    client = AuthorityClient(
                        AuthoritySelection("reply"), package_root=tmp_path,
                        data_dir=tmp_path, transport=client_transport)
                    assert (await client.status_v2()).state == "paired"
                    client_grant = await client.installation_grant_v2()
                    bundle = replace(case["installed_bundle"], tls_profile=profile)
                    graph = case["graph"]
                    graph._GraphCoordinator__content_fence_v2 = new_port
                    graph._GraphCoordinator__model_terminal_cost_port = (
                        InstalledModelTerminalCostPort(
                            client=client, bundle=bundle, grant=client_grant,
                            owner_loop=asyncio.get_running_loop()))
                    graph._GraphCoordinator__accounting_maintenance_port = (
                        InstalledAccountingMaintenancePort(
                            client=client, bundle=bundle, grant=client_grant,
                            owner_loop=asyncio.get_running_loop()))

                    def principal_for(actor, current_namespace):
                        binding = daemon.owner_pairings.current_actor_binding(
                            authority_namespace=authority_namespace,
                            installation_id=case["policy"].installation_id,
                            actor_id=actor)
                        return (binding.principal if binding is not None
                                and binding.namespace == current_namespace
                                else None)

                    graph._GraphCoordinator__owner_principal_resolver = principal_for
                    model = daemon.server._v2_model_egress[authority_namespace]
                    active_case = {
                        **case, "port": new_port, "client_grant": client_grant,
                        "installed_bundle": bundle,
                        "protected": model._fences,
                        "model_service": _PaidModelRpcFacade(
                            client, bundle, client_grant,
                            asyncio.get_running_loop(), model._store),
                    }
                    held = []
                    try:
                        with monkeypatch.context() as consumers:
                            consumers.setattr(
                                new_port, "natural_paid_consumer_ready_v2",
                                lambda *, namespace, template_version:
                                    namespace == case["namespace"]
                                    and template_version == TEMPLATE_VERSION,
                                raising=False)
                            consumers.setattr(
                                new_port, "natural_review_paid_consumer_ready_v2",
                                lambda *, namespace, template_version:
                                    namespace == case["namespace"]
                                    and template_version == REVIEW_TEMPLATE_VERSION,
                                raising=False)
                            saved = await asyncio.to_thread(
                                graph.prepare_post_c02_natural_generation_v2,
                                case["bootstrap"], case["namespace"],
                                case["c02"].operation_id, case["source_ref"],
                                bundle)
                            paid = await asyncio.to_thread(
                                _pay_generation, active_case, saved)
                            held.append(paid[1])
                            completed = await asyncio.to_thread(
                                _complete_generation, active_case, saved, paid)
                            held.append(completed[2])
                            _, review = await asyncio.to_thread(
                                _prepare_review, active_case, saved, completed)
                            review_paid = await asyncio.to_thread(
                                _pay_review, active_case, review)
                            held.append(review_paid[1])
                            candidate = await asyncio.to_thread(
                                _complete_review_and_final, active_case,
                                completed[0], review, review_paid)
                            final = await asyncio.to_thread(
                                _commit_final, active_case, candidate)
                            held.append(final[1])
                            assert final[2].status == "committed"
                            assert paid[5].call_id != review_paid[5].call_id
                            request = final[3][1]
                            dispatch_verifier = daemon.server._v2_execution[
                                authority_namespace]._v2_dispatch_verifier
                            keys = constraint_keys_from_footprint(request.footprint)
                            assert dispatch_verifier(
                                authority_namespace, request.effect_id, keys)
                            assert not dispatch_verifier(
                                authority_namespace, request.effect_id,
                                keys + ("tampered:constraint",))
                            login = await asyncio.to_thread(
                                new_port.begin_owner_session,
                                namespace=case["namespace"],
                                authority_namespace=authority_namespace,
                                request=case["owner_session_request"])
                            active_case["owner_session_token"] = (
                                await asyncio.to_thread(
                                    new_port.accept_owner_session,
                                    namespace=case["namespace"],
                                    authority_namespace=authority_namespace,
                                    challenge=login,
                                    signature=case["owner_key"].sign(
                                        login.signed_bytes())))
                            # The helper owns and closes its GraphWorker store.
                            # Give that worker a separate connection to this
                            # same graph file; the installed graph remains live
                            # for the subsequent P2 denial check.
                            if onebot_outcome == "revoked":
                                active_case["store"] = ProductionGraphStore(
                                    tmp_path / "business.db", case["store"]._registry)
                                try:
                                    await _revoke_owner_after_final(active_case, final)
                                finally:
                                    active_case["store"] = case["store"]
                                assert not dispatch_verifier(
                                    authority_namespace, request.effect_id, keys)
                            sends = []
                            active_case["store"] = ProductionGraphStore(
                                tmp_path / "business.db", case["store"]._registry)
                            try:
                                await _host_one_shot(
                                    active_case, final, paid[7],
                                    ("revoked_restarted" if onebot_outcome == "revoked"
                                     else "pending" if onebot_outcome
                                     == "missing_observation" else onebot_outcome),
                                    sends=sends)
                            finally:
                                active_case["store"] = case["store"]
                            assert len(sends) == (0 if onebot_outcome in {
                                "revoked", "missing_observation"} else 1)
                    finally:
                        for lease in reversed(held):
                            await asyncio.to_thread(
                                graph.release_authority_lease,
                                case["bootstrap"], lease)
                finally:
                    await asyncio.to_thread(new_port.close)
                    await client_transport.close()
            finally:
                await transport.close()
        finally:
            await asyncio.to_thread(lambda:
                asyncio.run_coroutine_threadsafe(
                    daemon.aclose(), old_loop).result(timeout=30))

    await real_owner_case(
        tmp_path, "owned", natural_workflow_builder=workflows,
        after_c02=after_c02)
