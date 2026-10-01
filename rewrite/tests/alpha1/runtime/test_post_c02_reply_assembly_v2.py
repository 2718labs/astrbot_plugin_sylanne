"""Same-installation Authority and graph path toward public reply assembly.

The first ingress and original encoding/cost/C02 use real installed signing
paths. Controlled AstrBot model text is test input; no synthetic Authority
terminal, Owner guard, or result-read fact is grafted into this chain.
"""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import httpx
import json
import sqlite3
import ssl
from threading import Thread
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from astrbot.api.star import Context
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import (
    AiocqhttpAdapter,
)
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from openai import AsyncOpenAI
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from rewrite.host_tests.alpha1 import test_installed_scene_identity as scene_fixture
from rewrite.host_tests.alpha1.test_reply_suppression import _LiveEvent
from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_clock import AuthorityClockReadingV2
from sylanne3.authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, DispatchGraphClaimReceiptV1,
    MutationReceiptV2,
    SCHEMA as AUTHORITY_V2_PROTOCOL,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import (
    AuthorityV2ExecutionJournal,
)
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_service import (
    AuthorityV2ModelEgressService,
)
from sylanne3.authority_service.v2_model_egress_store import (
    AuthorityV2ModelEgressStore,
)
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.v2_owner_contract import (
    OwnerActorBindingV1, OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerClaimTicketV1, OwnerPrincipalV1,
)
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
)
from sylanne3.authority_service.v2_self_identity_contract import SelfIdentityMutationV1
from sylanne3.authority_service.reverse_handoff import (
    AdministratorReverseHandoffProfile, ReverseGraphClaimClient,
)
from sylanne3.authority_service.local_composition import (
    compose_local_owner_authority,
)
from sylanne3.authority_service.installed_platform_observation import (
    HostOneBotObservationInstallationV2,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_worker import GraphWorker
from sylanne3.graph_types import owner_grant_policy_digest_v1
from sylanne3.domain_registry import discover_domain_registry
from sylanne3.graph_coordinator import (
    GraphCoordinator, IngressHostFacts, IngressLineage,
    UnavailableGuard, first_ingress_encoding_acquire_operation_id, namespace_ref,
)
from sylanne3.domains.d01 import PersonaBlock, PersonaPlan
from sylanne3.domains.d02.body_quote_original import D02BodyQuoteAuthority
from sylanne3.runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyAuthorityV1
from sylanne3.domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.domains.d03 import (
    ContextProvider, RoleBindingRequest, RoleBindingResolution,
)
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityClient, AuthorityProvisioningRequest,
    AuthoritySelection, PublisherPackageIdentity,
)
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy, AdminIngressClockPolicy,
    AdminD06FirstIngressC02Policy, AdminD07AttentionPolicy,
    AdminD06PrivateReplySourcePolicy, AdminIngressEncodingPolicy,
    AdminInstallationBundle, AdminModelWorkflowV2, AdminModelWorkflowsV2,
    AdminPrivateReplyDispatchPolicy,
    installed_model_config_ref,
)
from sylanne3.host.installed_model_capability import InstalledModelCapabilityPort
from sylanne3.host.self_identity_current_port import InstalledCurrentSelfIdentityPort
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
from sylanne3.host.worker_result_read_fact_port import InstalledWorkerResultReadFactPort
from sylanne3.host.worker_result_identity import first_ingress_worker_result_request_v1
from sylanne3.host.identity import astrbot_namespace
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.reply_suppression import HostReplySuppressionRegistryV1
from sylanne3.host.reply_takeover import rendezvous_private_reply_v1
from sylanne3.host.reverse_handoff import (
    AdministratorHostReverseProfile, HostReverseGraphClaimServer,
    begin_handoff_with_reverse_claim,
)
from sylanne3.host.installed_dispatch_route import InstalledDispatchRoutePort
from sylanne3.host.private_reply_dispatch_driver import (
    _FrozenGraphTextResolver, _read_original,
)
from sylanne3.host.astrbot_dispatch import (
    AstrBotV2TextSender, GraphTextPayloadResolver, ResolvedTextPayload,
)
from sylanne3.host.current_dispatch_handoff_port import (
    InstalledCurrentDispatchHandoffPort,
)
from sylanne3.runtime.dispatch_binding_v2 import (
    authority_dispatch_footprint_v2,
    build_non_authorizing_execution_binding_v2,
)
from sylanne3.host.installed_scene_identity import InstalledSceneIdentityPort
from sylanne3.host.scene_candidates import SceneCandidateCatalog
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.host.mtls_transport import (
    AuthorityTlsProfile, MtlsAuthorityTransport,
    V2PlatformObservationVerifierUnavailable,
)
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.host.v2_fence_port import V2FencePort, VerifiedIngressClockV2
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
    issue_first_ingress_encoding_request_v2,
)
from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
from sylanne3.model_broker.broker import ModelProviderDescriptor
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.dispatch_graph_claim import dispatch_claim_key
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime.installed_dispatch_admission_issuer import (
    InstalledDispatchAdmissionIssuer,
)
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.host.installed_reply_model_driver import (
    InstalledReplyProgressV1, parse_authority_reply_observation_v1,
    prepare_and_run_installed_reply_model_v1, reply_model_operation_id_v1,
)
from sylanne3.runtime.first_ingress_v2 import trusted_upper
from sylanne3.runtime.issuers import BudgetLeaseGrant, build_runtime_issuers
from sylanne3.runtime_contracts import (
    AuthorityContext, FenceScope, NamespaceId, QueryEpoch, canonical_digest,
)
from test_role_initialization_v2 import _resources
from rewrite.host_tests.alpha1.test_astrbot_model_call import Manager


@pytest.mark.asyncio
@pytest.mark.parametrize("takeover_case", (
    "owned", "owned_no_observation_verifier", "timeout", "unknown"))
async def test_paired_reply_assembly_uses_real_c02_and_reply_admission(
        tmp_path, takeover_case, *, natural_workflow_builder=None,
        after_c02=None, authority_server_builder=None,
        enable_d09_workbench=False, enable_c04_body_work=False,
        register_c04_domains=False,
        extra_owner_capabilities=(), extra_owner_purposes=(),
        ingress_text="hello", installed_package_root=None,
        after_role_initialization=None, continue_to_ingress=False,
        enable_d04_semantic_drive=False, enable_d04_joint_numeric=False,
        d04_numeric_budget_cpu_ms=120000,
        enable_d04_root_cpu=False, enable_d12_package_maintenance=False,
        enable_d10_offline_ticks=False, enable_d11_life_source_note=False):
    namespace = astrbot_namespace("platform-1", "10001", "persona-reply")
    authority_namespace = namespace_ref(namespace)
    installation_id = "installation-reply"
    source_id = "clock:reply"
    from pathlib import Path
    package_root = Path(installed_package_root) if installed_package_root is not None else tmp_path
    manifest_path = package_root / "release-manifest.json"
    if installed_package_root is None:
        manifest_path.write_text('{"test":true}', encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    peer = MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files["client.pem"].read_text(encoding="ascii"))).hexdigest())
    admin_peer = MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files["second.pem"].read_text(encoding="ascii"))).hexdigest())
    principal = OwnerPrincipalV1("paired-idp", "account", "incarnation-1")
    expected_creation = {}
    conversation_ref = '["platform-1:FriendMessage:123456","conversation-1"]'
    d02, d11 = build_runtime_issuers(b"reply-issuer-key-" * 2)
    provider_config = {
        "id": "provider-1", "type": "openai_chat_completion",
        "model": "model-1"}
    config_digest = canonical_digest(provider_config)
    model_shared = dict(
        provider_id="provider-1", model_id="model-1",
        provider_config_ref=installed_model_config_ref(
            "provider-1", "model-1", config_digest),
        provider_config_digest=config_digest, audiences=(conversation_ref,),
        privacy_tier="private", required_capabilities=("text",),
        timeout_seconds=10.0)
    workflows = AdminModelWorkflowsV2(
        2,
        AdminModelWorkflowV2(
            work_kind="d06.encode_source", purpose="consolidation",
            template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
            max_output_tokens=128, quote_ceiling={"output_tokens": 128},
            **model_shared),
        AdminModelWorkflowV2(
            work_kind="reply", purpose="proposal",
            template_version=REPLY_TEMPLATE_VERSION,
            max_output_tokens=32, quote_ceiling={"output_tokens": 32},
            **model_shared))
    if natural_workflow_builder is not None:
        workflows = natural_workflow_builder(workflows, model_shared)
    deletion_journal = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=authority_namespace,
        journal_id="execution", create=True)
    deletion_head = deletion_journal.latest_head()
    initial_deletion = JournalHead(
        deletion_head.journal_id, deletion_head.seq, deletion_head.chain_digest)
    bootstrap_deletion = DeletionJournal(
        tmp_path / "bootstrap-deletion.db", create=True)
    bootstrap_execution = AuthorityV2ExecutionJournal(
        tmp_path / "bootstrap-execution.db", namespace="ns:bootstrap",
        journal_id="bootstrap-execution", create=True)
    bootstrap_head = bootstrap_deletion.latest_head()
    bootstrap_deletion_head = JournalHead(
        bootstrap_head.journal_id, bootstrap_head.seq,
        bootstrap_head.chain_digest)
    bootstrap_execution_head = bootstrap_execution.verified_head()

    def authorizer(candidate, action, selected_namespace, holder):
        if enable_d10_offline_ticks and action == "migrate_deletion":
            return candidate == peer and selected_namespace == authority_namespace
        if enable_d12_package_maintenance and selected_namespace==authority_namespace:
            if candidate==admin_peer and action in {"d12_operation_install","d12_lifecycle_install","d12_package_install"}:return True
            if candidate==peer and action in {"d12_operation_status","d12_lifecycle_control","d12_lifecycle_bootstrap",
                    "d12_package_control","d12_package_supervisor","d12_package_bootstrap","d12_package_activate"}:return holder is None or holder=="host:reply"
        if action == "owner_pair":
            return (candidate in {peer, admin_peer}
                    and selected_namespace == authority_namespace)
        if action in {"owner_identity_pair", "owner_identity_revoke"}:
            return candidate == admin_peer and selected_namespace == authority_namespace
        if action == "owner_claim":
            return candidate == peer and selected_namespace == authority_namespace
        if action == "owner_session":
            return candidate == peer and selected_namespace == authority_namespace
        if action == "self_identity_mutate":
            return candidate == admin_peer and selected_namespace == authority_namespace
        if action == "current" and candidate == admin_peer:
            return selected_namespace == authority_namespace
        return (candidate == peer
                and selected_namespace in {authority_namespace, "ns:bootstrap"}
                and action in {"install", "seal_v2_only", "namespace_genesis",
                               "current", "read",
                               "write", "dispatch", "execution",
                               "owner_guard_read", "self_identity_read",
                               "model_egress", "accounting",
                               "owner_authorization_revoke"}
                and (holder is None or holder == "host:reply"))

    core = AuthorityServiceCore(
        tmp_path / "authority.db", authorizer=authorizer,
        deletion_verifier=lambda ns, before, current, phase:
            current == (bootstrap_deletion_head if ns == "ns:bootstrap"
                        else initial_deletion) and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            (bootstrap_execution.verified_head() if ns == "ns:bootstrap"
             else execution.verified_head()) == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True, create=True)
    listener = None
    authority_loop = None
    authority_thread = None
    reverse_listener = None
    reverse_server = None
    graph_worker = None
    server = None
    transport = None
    client_transport = None
    port = None
    admin_transport = None
    admin_port = None
    domain_registry = discover_domain_registry(active_affect_scheme=AffectScheme(
        "d04.affect.scheme.v1", "scheme-1", "operator-1",
        "parameter:reply", "coupling:reply",
        (AffectAxis("care", "normalized", "care"),), ()))
    if installed_package_root is not None:
        from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
        verified_affect = load_verified_affect_scheme(package_root, manifest_digest)
        domain_registry = verified_affect.registry
    graph_store = ProductionGraphStore(
        tmp_path / "business.db", domain_registry.type_registry)
    model_http_client = None
    installed_model_selection = None
    encoding_workflow = workflows.encode

    def encoding_request_issuer(context):
        selection = installed_model_selection
        if (selection is None
                or context.authority.namespace != namespace
                or context.authority.purpose != encoding_workflow.purpose
                or not set(context.authority.audience).issubset(
                    encoding_workflow.audiences)
                or not selection.verify_admin_config(namespace, encoding_workflow)
                or not selection.verify_admin_selection(namespace, encoding_workflow)):
            raise ValueError("current installed encoding selection unavailable")
        return issue_first_ingress_encoding_request_v2(
            context, provider_id=encoding_workflow.provider_id,
            model_id=encoding_workflow.model_id,
            provider_config_ref=encoding_workflow.provider_config_ref,
            provider_config_digest=encoding_workflow.provider_config_digest,
            required_capabilities=frozenset(
                encoding_workflow.required_capabilities),
            privacy_tier=encoding_workflow.privacy_tier,
            timeout_seconds=encoding_workflow.timeout_seconds,
            max_output_tokens=encoding_workflow.max_output_tokens)

    try:
        reverse_server = HostReverseGraphClaimServer(
            AdministratorHostReverseProfile(
                "reply", installation_id, authority_namespace,
                peer.certificate_sha256,
                files["server.pem"], files["server.key"], files["ca.pem"]))
        reverse_listener = await reverse_server.start("127.0.0.1", 0)
        reverse_port = reverse_listener.sockets[0].getsockname()[1]
        reverse_client = ReverseGraphClaimClient(
            AdministratorReverseHandoffProfile(
                authority_namespace, "reply", installation_id,
                "127.0.0.1", reverse_port, "localhost",
                hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                    files["server.pem"].read_text(encoding="ascii"))).hexdigest(),
                files["ca.pem"], files["client.pem"], files["client.key"]))
        if enable_d10_offline_ticks:
            core.register_namespace(peer, authority_namespace, "host:reply", initial_deletion,
                execution.verified_head())
        else:
            core.register_namespace(
                peer, "ns:bootstrap", "host:reply", bootstrap_deletion_head,
                bootstrap_execution_head)
        core.seal_v2_only(peer)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        if enable_d10_offline_ticks:
            from sylanne3.authority_service.v2_deletion_migration import AuthorityV2DeletionMigration
            from sylanne3.authority_service.v2_deletion_tail_migration import AuthorityV2DeletionTailMigration
            from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
            for migration in (AuthorityV2DeletionMigration, AuthorityV2DeletionTailMigration):
                migration(core=core, fences=fences, deletion=deletion_guard, execution=execution,
                    namespace=authority_namespace).run(credential=peer)
            AuthorityV2ScopedErasureStore(core=core, fences=fences, deletion=deletion_guard,
                execution=execution, namespace=authority_namespace).migrate_zero_history(credential=peer)
        protected = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion_guard,
            execution=execution, namespace=authority_namespace)
        pairing_source = AuthorityOwnerPairingSource(
            core, utc_clock=lambda: datetime.now(timezone.utc), create=True)
        deployment = OwnerDeploymentVerifier(
            pairing_source, lambda: datetime.now(timezone.utc))
        owner_proofs = AuthorityV2OwnerProofStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            pairing_verifier=deployment.pair_credential, create=True)
        owner_sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            current_pairing_source=pairing_source, create=True)
        model_store = AuthorityV2ModelEgressStore(
            core._db, create=True, lock=core._lock)
        model_verifier = PinnedCurrentModelEgressGraphVerifier(
            tmp_path / "business.db", d11_issuer=d11,
            trusted_now_utc=time.time,
            trusted_paired_clock=lambda: (time.time() + 0.2, "epoch:reply"))
        model_service = AuthorityV2ModelEgressService(
            model_store, protected, graph_verifier=model_verifier,
            admin_model_policy=workflows)
        def first_claim(candidate, ticket, selected_namespace):
            if (candidate != peer
                    or selected_namespace != authority_namespace
                    or ticket.principal != principal
                    or ticket.installation_id != installation_id
                    or ticket.creation_operation_id != expected_creation.get("operation_id")
                    or ticket.creation_digest != expected_creation.get("digest")):
                return False
            with sqlite3.connect(tmp_path / "business.db") as db:
                row = db.execute(
                    "SELECT operation_id,digest FROM graph_namespace_provisioning_v2 "
                    "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
            return (row == (ticket.creation_operation_id,
                            ticket.creation_digest.removeprefix("sha256:"))
                    and deployment.first_claim(
                        peer, ticket, selected_namespace))

        server_kwargs = dict(
            core=core, v2_fences={authority_namespace: protected},
            graph_db_path=tmp_path / "business.db",
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=first_claim,
            claimant_verifier=None,
            administrator_authorizer=lambda candidate, action, selected, holder:
                (candidate in {peer, admin_peer} and action == "pair"
                 and selected == "authority:enrollment")
                or (candidate == admin_peer and action == "self_identity_mutate"
                    and selected == authority_namespace
                    and holder == installation_id),
            publisher_manifest_verifier=lambda *args: True,
            installations_v2={
                (peer.certificate_sha256, "reply"): AdministratorInstallationV2(
                    installation_id, "host:reply", "policy:reply", "v2",
                    manifest_digest, source_id, 0.5),
                (admin_peer.certificate_sha256, "reply"):
                    AdministratorInstallationV2(
                        "installation-admin", "host:reply", "policy:reply",
                        "v2", manifest_digest),
            },
            namespace_bindings_v2={
                (peer.certificate_sha256, "reply", namespace):
                    authority_namespace,
                (admin_peer.certificate_sha256, "reply", namespace):
                    authority_namespace,
            },
            clock_provider=lambda: AuthorityClockReadingV2(
                source_id, time.time(), time.monotonic(), "epoch:reply",
                True, 0.1),
            create_owner_schema=True,
            create_self_identity_schema=True,
            create_worker_result_schema=True,
            owner_proofs=owner_proofs, owner_sessions=owner_sessions,
            creation_pairing_source=pairing_source,
            self_identity_readers_v2={authority_namespace:
                (peer.certificate_sha256, "reply")},
            v2_model_egress={authority_namespace: model_service},
            model_observers_v2={authority_namespace:
                (peer.certificate_sha256, "reply")},
            accounting_observers_v2={authority_namespace:
                (peer.certificate_sha256, "reply")},
            worker_result_readers_v2={authority_namespace:
                (peer.certificate_sha256, "reply")},
            worker_result_fact_committers_v2={authority_namespace:
                (peer.certificate_sha256, "reply")},
            model_result_source_purposes={authority_namespace: "audit"},
            v2_final_handoff_reverse={authority_namespace: reverse_client},
            v2_final_handoff_issuers={authority_namespace: "issuer:reply"},
            host_onebot_observations_v2=(
                {} if takeover_case == "owned_no_observation_verifier" else {
                    authority_namespace: HostOneBotObservationInstallationV2(
                        peer.certificate_sha256, "reply",
                        "adapter:platform-1",
                        '["platform-1","aiocqhttp","10001"]', source_id)}),
        )
        # An integration fixture may replace the server before any listener
        # starts. It receives this exact same DB/Core/Owner installation,
        # rather than splicing receipts from an unrelated authority process.
        server = (compose_local_owner_authority(**server_kwargs)
                  if authority_server_builder is None else
                  await authority_server_builder(
                      server_kwargs=server_kwargs,
                      context={
                          "graph_path": tmp_path / "business.db",
                          "authority_path": tmp_path / "authority.db",
                          "core": core, "fences": fences,
                          "protected": protected, "peer": peer,
                          "admin_peer": admin_peer, "files": files,
                          "namespace": namespace,
                          "authority_namespace": authority_namespace,
                          "installation_id": installation_id,
                          "workflows": workflows,
                          "model_store": model_store,
                          "model_service": model_service,
                          "owner_proofs": owner_proofs,
                          "owner_sessions": owner_sessions,
                          "pairing_source": pairing_source,
                          "reverse_client": reverse_client,
                          "deletion_journal": deletion_journal,
                          "execution_journal": execution,
                      }))
        initial_offline_storage = None
        if enable_d10_offline_ticks:
            from d11_offline_authority_acceptance_support_v1 import install_fresh_offline_storage_case_v1
            initial_offline_storage = install_fresh_offline_storage_case_v1(
                core=core, protected=protected, execution=execution, graph_store=graph_store,
                root=tmp_path, server_kwargs=server_kwargs, peer=peer, namespace=namespace,
                authority_namespace=authority_namespace, registry=domain_registry.type_registry)
        authority_loop = asyncio.new_event_loop()
        authority_thread = Thread(
            target=authority_loop.run_forever,
            name="reply-authority-test", daemon=True)
        authority_thread.start()
        listener = await asyncio.to_thread(
            lambda: asyncio.run_coroutine_threadsafe(
                server.start(
                    "127.0.0.1", 0,
                    AuthorityServerTlsConfig(
                        str(files["server.pem"]), str(files["server.key"]),
                        str(files["ca.pem"]), timeout_seconds=30,
                        max_message_bytes=65_536)),
                authority_loop).result(timeout=30))
        address = listener.sockets[0].getsockname()[1]
        profile = AuthorityTlsProfile(
            "reply", "127.0.0.1", address, "localhost",
            server._authority_id(), files["ca.pem"], files["client.pem"],
            files["client.key"], timeout_seconds=30,
            max_message_bytes=65_536)
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "reply", "astrbot_plugin_sylanne", "4.28.1",
            package_root, tmp_path, PublisherPackageIdentity(manifest_digest))
        transport = MtlsAuthorityTransport({"reply": profile})
        handshake = await transport.handshake(
            request, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await transport.installation_grant_v2(request, handshake)
        assert grant.installation_id == installation_id
        port = await asyncio.to_thread(
            V2FencePort, request, {"reply": profile}, grant)
        root_lease = BudgetLease(
            "lease-" + namespace.persona_id, None, *namespace.as_tuple, "USD",
            {"cpu_ms": d04_numeric_budget_cpu_ms if enable_d04_joint_numeric else 200, "output_tokens": 512,
             **({"thread_cpu_ms": (60000 if enable_d04_root_cpu else 1000) + (1000 if enable_d10_offline_ticks else 0) + (1000 if enable_d11_life_source_note else 0)} if enable_d09_workbench else {})},
            {}, {}, {}, 1, "active")
        root_work_kinds = (
            "encode", "d06.encode_source", "d03.message_received",
            "d03.self_identity_projection", "d04.encoding_baseline",
            "d06.first_ingress_c02", "d07.attention", "message", "reply")
        if natural_workflow_builder is not None:
            root_work_kinds += ("natural_generation", "natural_review")
        if workflows.appraisal is not None:
            root_work_kinds += (workflows.appraisal.work_kind,)
        if workflows.d07_cognition is not None:
            root_work_kinds += (workflows.d07_cognition.work_kind,)
        if enable_d04_joint_numeric:
            from sylanne3.authority_service.d04_numeric_contract_v3 import WORK_KIND as D04_JOINT_WORK_KIND
            root_work_kinds += (D04_JOINT_WORK_KIND,)
        if enable_d04_semantic_drive:
            from sylanne3.runtime.d04_semantic_policy import WORK_KIND as D04_SEMANTIC_WORK_KIND
            root_work_kinds += (D04_SEMANTIC_WORK_KIND,)
        if enable_d09_workbench:
            root_work_kinds += ("scheme_compile", "scheme_preview")
        if enable_c04_body_work:
            root_work_kinds += (C04_INTERNAL_CPU_WORK_KIND,)
        if enable_d10_offline_ticks:
            root_work_kinds += ("d10.offline_observed_tick.v1",)
        if enable_d11_life_source_note:
            root_work_kinds += ("d10.life.source_note.v1",)
        root_grant = BudgetLeaseGrant(
            "grant-reply", 1, *namespace.as_tuple, root_lease.lease_id,
            "USD", {"cpu_ms": d04_numeric_budget_cpu_ms if enable_d04_joint_numeric else 100, "output_tokens": 256,
                    **({"thread_cpu_ms": (60000 if enable_d04_root_cpu else 1000) + (1000 if enable_d10_offline_ticks else 0) + (1000 if enable_d11_life_source_note else 0)}
                       if enable_d09_workbench else {})},
            root_work_kinds,
            time.time() + 3600,
            "d11-policy")
        policy = AdminInstallationPolicy(
            namespace, authority_namespace, installation_id, manifest_digest,
            "host:reply", grant.authority_id,
            graph_store._registry.catalogue_hash,
            verified_affect.scheme.scheme_version if installed_package_root is not None else "scheme-1",
            verified_affect.scheme.operator_version if installed_package_root is not None else "operator-1",
            "policy-1", root_lease, root_grant)
        client_transport = MtlsAuthorityTransport({"reply": profile})
        authority_client = AuthorityClient(
            AuthoritySelection("reply"), package_root=package_root,
            data_dir=tmp_path, transport=client_transport)
        assert (await authority_client.status_v2()).state == "paired"
        client_grant = await authority_client.installation_grant_v2()
        assert (client_grant.authority_id, client_grant.installation_id,
                client_grant.manifest_digest) == (
                    grant.authority_id, grant.installation_id,
                    grant.manifest_digest)
        accounting_bundle = AdminInstallationBundle(
            profile, policy, b"k" * 32, b"d" * 32,
            model_workflows=workflows)
        bootstrap = object()
        suppression_registry = HostReplySuppressionRegistryV1()
        graph = GraphCoordinator(
            graph_store, bootstrap, holder="host:reply",
            content_fence_v2=port, d02_issuer=d02, d11_issuer=d11,
            body_quote_authority=(D02BodyQuoteAuthority(hmac.digest(
                accounting_bundle.d02_signing_key,
                b"sylanne3.d02.body_quote_original.v1\0"
                + policy.installation_id.encode("utf-8"), "sha256"))
                if enable_c04_body_work else None),
            c04_cpu_quote_authority=(
                C04InternalCpuQuotePolicyAuthorityV1(hmac.digest(
                    accounting_bundle.d11_signing_key,
                    b"sylanne3.c04.internal_cpu_quote_policy.v1\0"
                    + policy.installation_id.encode("utf-8"), "sha256"))
                if enable_c04_body_work else None),
            encoding_request_issuer=encoding_request_issuer,
            reply_suppression_ack_verifier=suppression_registry.verify_and_consume,
            accounting_maintenance_port=InstalledAccountingMaintenancePort(
                client=authority_client, bundle=accounting_bundle,
                grant=client_grant, owner_loop=asyncio.get_running_loop()),
            owner_principal_resolver=lambda actor, current_namespace: (
                (binding.principal if binding is not None
                 and binding.namespace == current_namespace else None)
                if (binding := pairing_source.current_actor_binding(
                    authority_namespace=authority_namespace,
                    installation_id=installation_id,
                    actor_id=actor)) is not None else None))
        if initial_offline_storage is not None:
            graph._initial_offline_storage_case_v1 = initial_offline_storage
        creation = await asyncio.to_thread(
            graph.provision_namespace_v2, bootstrap, policy,
            operation_id="reply-owner-creation")
        assert creation.namespace == namespace
        expected_creation.update(
            operation_id=creation.operation_id,
            digest="sha256:" + creation.input_digest)
        clock = await asyncio.to_thread(
            port.read_ingress_clock,
            AdminIngressClockPolicy(source_id, 0.5, 2.0))
        assert type(clock) is VerifiedIngressClockV2
        assert clock.sample.installation_id == installation_id
        assert clock.sample.source_id == source_id
        anchor = await asyncio.to_thread(
            port.current_anchor, namespace=namespace,
            authority_namespace=authority_namespace)
        assert anchor.authority_id == grant.authority_id
        assert anchor.namespace == authority_namespace
        permit = await asyncio.to_thread(
            port.begin_fence, namespace=namespace,
            authority_namespace=authority_namespace, holder="host:reply",
            generation=anchor.activation_generation, operation="write",
            operation_id="reply-assembly-probe", expected_anchor=anchor)
        effect_snapshot = await asyncio.to_thread(
            port.read_current_effect_snapshot_for_write_fence,
            namespace=namespace, authority_namespace=authority_namespace,
            permit=permit)
        assert type(effect_snapshot) is AuthorityCurrentEffectSnapshotV2
        assert effect_snapshot.anchor == permit.pinned_anchor
        owner_guard, guarded_permit = await asyncio.to_thread(
            port.get_current_owner_guard_for_fence,
            namespace=namespace, authority_namespace=authority_namespace,
            permit=permit)
        assert guarded_permit == permit
        assert owner_guard is None  # No Owner grant has been issued yet.
        with graph_store._lock:
            metadata, epoch = graph._v2_graph_stamp(namespace)
        scope = FenceScope(
            namespace, authority_namespace, anchor.activation_generation,
            "write", "reply-assembly-probe", permit, anchor, epoch,
            metadata.graph_revision)
        await asyncio.to_thread(
            port.finish_fence, scope, request_id="finish:reply-assembly-probe",
            request_digest="sha256:" + "f" * 64)

        admin_profile = replace(
            profile, client_certificate=files["second.pem"],
            client_private_key=files["second.key"])
        admin_transport = MtlsAuthorityTransport({"reply": admin_profile})
        admin_handshake = await admin_transport.handshake(
            request, protocol=AUTHORITY_V2_PROTOCOL)
        admin_grant = await admin_transport.installation_grant_v2(
            request, admin_handshake)
        admin_port = await asyncio.to_thread(
            V2FencePort, request, {"reply": admin_profile}, admin_grant)
        ticket = OwnerClaimTicketV1(
            grant.authority_id, installation_id, namespace, principal,
            "ticket:reply", creation.operation_id,
            "sha256:" + creation.input_digest,
            "sha256:" + creation.input_digest, "a" * 32,
            "2099-01-01T00:00:00Z")
        grant_value = {
            "schema": "sylanne3.graph.owner_grant.v1",
            "authority_id": grant.authority_id,
            "installation_id": installation_id,
            "grant_id": "first-owner-reply",
            "principal": {
                "identity_provider": principal.identity_provider,
                "account_ref": principal.account_ref,
                "account_incarnation": principal.account_incarnation,
            },
            "ticket_id": ticket.ticket_id,
            "creation_operation_id": ticket.creation_operation_id,
            "creation_digest": ticket.creation_digest,
            "issue_operation_id": "owner-issue-reply",
            "grant_revision": 1,
            "state": "pending_authority",
            "scope": "/".join(namespace.as_tuple),
            "issuer_ref": "authority:paired-installation",
            "capabilities": sorted({
                "workbench.bind_scene", "workbench.create", "workbench.read",
                *(["workbench.compile", "workbench.experiment",
                   "workbench.activate"] if enable_d09_workbench else []),
                *(["d02.body_policy.install", "c04.cpu_policy.install",
                   "c04.internal_work.prepare"]
                  if enable_c04_body_work else []),
                *extra_owner_capabilities,
            }),
            "purposes": sorted({"expression", "workbench_user_action",
                                 "workbench_view", *extra_owner_purposes}),
            "audiences": [conversation_ref, "owner"],
            "activation_generation": anchor.activation_generation,
            "graph_incarnation": creation.graph_incarnation,
        }
        ticket = replace(
            ticket, policy_digest=owner_grant_policy_digest_v1(
                grant_value, bot=namespace.bot_id,
                persona=namespace.persona_id))
        operation = OwnerAuthorizationOperationV1(
            "issue", "owner-issue-reply", grant.authority_id,
            installation_id, namespace, principal, "first-owner-reply",
            "sha256:" + canonical_digest(grant_value), 0,
            OwnerAuthorizationGuardV1(
                grant.authority_id, installation_id, namespace,
                0, "genesis", 0, 0), ticket)
        expires = datetime(2099, 1, 1, tzinfo=timezone.utc)
        pairing_source.pair_creation(
            administrator_credential=admin_peer,
            authority_namespace=authority_namespace, ticket=ticket,
            client_certificate_sha256=peer.certificate_sha256,
            valid_until_utc=expires)
        owner_key = Ed25519PrivateKey.generate()
        registration = OwnerCredentialRegistrationV1(
            grant.authority_id, authority_namespace, installation_id,
            principal, "owner-key-reply", 1,
            owner_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "enroll-reply")
        pairing_source.pair_credential(
            administrator_credential=admin_peer,
            registration=registration,
            client_certificate_sha256=peer.certificate_sha256,
            valid_until_utc=expires)
        owner_proofs.register_credential(
            transport_credential=peer, registration=registration)
        session_request = OwnerSessionLoginRequestV1(
            grant.authority_id, authority_namespace, installation_id,
            principal, registration.credential_id,
            registration.credential_epoch, "sylanne-owner-console",
            "http://localhost:6185")
        challenge = await asyncio.to_thread(
            port.begin_owner_session, namespace=namespace,
            authority_namespace=authority_namespace, request=session_request)
        owner_session_token = await asyncio.to_thread(
            port.accept_owner_session, namespace=namespace,
            authority_namespace=authority_namespace, challenge=challenge,
            signature=owner_key.sign(challenge.signed_bytes()))
        assert await asyncio.to_thread(
            port.register_owner_ticket,
            namespace=namespace, authority_namespace=authority_namespace,
            ticket=ticket) == ticket
        pending = await asyncio.to_thread(
            port.reserve_owner_issue, namespace=namespace,
            authority_namespace=authority_namespace, operation=operation,
            owner_session_token=owner_session_token,
            owner_session_request=session_request)
        assert pending.phase == "pending"
        proof = await asyncio.to_thread(
            graph.commit_first_owner_grant_v2, bootstrap,
            namespace=namespace, operation_id=operation.operation_id,
            grant_value=grant_value)
        committed = await asyncio.to_thread(
            port.finalize_owner_issue, namespace=namespace,
            authority_namespace=authority_namespace,
            operation=operation, proof=proof,
            owner_session_token=owner_session_token,
            owner_session_request=session_request)
        assert committed.phase == "committed"
        pairing_source.pair_actor(
            administrator_credential=admin_peer,
            binding=OwnerActorBindingV1(
                grant.authority_id, installation_id, namespace,
                "owner-actor-reply", principal, 1))
        owner_guard_request = replace(session_request, audience="owner")
        guard_challenge = await asyncio.to_thread(
            port.begin_owner_session, namespace=namespace,
            authority_namespace=authority_namespace,
            request=owner_guard_request)
        owner_guard_token = await asyncio.to_thread(
            port.accept_owner_session, namespace=namespace,
            authority_namespace=authority_namespace,
            challenge=guard_challenge,
            signature=owner_key.sign(guard_challenge.signed_bytes()))
        current_anchor = await asyncio.to_thread(
            port.current_anchor, namespace=namespace,
            authority_namespace=authority_namespace)
        owner_permit = await asyncio.to_thread(
            port.begin_fence, namespace=namespace,
            authority_namespace=authority_namespace, holder="host:reply",
            generation=current_anchor.activation_generation,
            operation="write", operation_id="reply-owner-check",
            expected_anchor=current_anchor)
        current_guard, checked_permit = await asyncio.to_thread(
            port.get_current_owner_guard_for_fence,
            namespace=namespace, authority_namespace=authority_namespace,
            permit=owner_permit, owner_actor_id="owner-actor-reply",
            owner_session_token=owner_guard_token,
            owner_session_request=owner_guard_request)
        assert checked_permit == owner_permit
        assert type(current_guard) is OwnerAuthorizationGuardV1
        assert current_guard.installation_id == installation_id
        current_effect = await asyncio.to_thread(
            port.read_current_effect, namespace=namespace,
            authority_namespace=authority_namespace,
            effect_id="effect:reply-assembly-probe")
        assert current_effect.state == "absent"
        assert current_effect.authority_id == grant.authority_id
        with graph_store._lock:
            owner_metadata, owner_epoch = graph._v2_graph_stamp(namespace)
        owner_scope = FenceScope(
            namespace, authority_namespace,
            current_anchor.activation_generation, "write",
            "reply-owner-check", owner_permit, current_anchor,
            owner_epoch, owner_metadata.graph_revision)
        await asyncio.to_thread(
            port.finish_fence, owner_scope,
            request_id="finish:reply-owner-check",
            request_digest="sha256:" + "e" * 64)
        plan = PersonaPlan(
            "plan:reply", namespace, 1,
            (PersonaBlock("identity", "semantic_identity",
                          "reliable companion", "read_only"),), (), True)
        role_receipt = await asyncio.to_thread(
            graph.commit_role_initialization_v2,
            namespace=namespace, operation_id="role-init-reply", plan=plan,
            principal=principal,
            request_digest="sha256:" + canonical_digest({
                "role": "reply", "plan_id": plan.plan_id}),
            resources=_resources(graph_store, namespace, plan),
            actor_id="owner-actor-reply",
            owner_session_token=owner_guard_token,
            owner_session_request=owner_guard_request)
        assert role_receipt.operation_id == "role-init-reply"
        if after_role_initialization is not None:
            # Permanent first-use product acceptance hook: real signed Owner,
            # actual independent Authority/mTLS fence and committed D01 root.
            # No C02/model call has happened at this boundary.
            graph._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(source_id, 0.5, 2.0)
            await after_role_initialization({
                "graph": graph, "store": graph_store, "namespace": namespace,
                "authority_namespace": authority_namespace, "bootstrap": bootstrap,
                "port": port, "core": core, "server": server, "fences": fences,
                "protected": protected, "domain_registry": domain_registry,
                "package_root": package_root, "manifest_digest": manifest_digest,
                "policy": policy, "grant": grant, "client_grant": client_grant,
                "installed_bundle": accounting_bundle, "d02_issuer": d02, "d11_issuer": d11,
                "principal": principal, "pairing_source": pairing_source,
                "peer": peer, "admin_peer": admin_peer, "owner_key": owner_key,
                "owner_sessions": owner_sessions, "owner_proofs": owner_proofs,
                "owner_session_token": owner_guard_token,
                "owner_session_request": owner_guard_request,
                "ingress_clock": AdminIngressClockPolicy(source_id, 0.5, 2.0),
                "authority_client": authority_client, "files": files,
                "owner_loop": asyncio.get_running_loop(), "enable_d04_root_cpu": enable_d04_root_cpu,
                "core_authorizer":authorizer,"server_kwargs":server_kwargs,"model_store":model_store,
            })
            if not continue_to_ingress:
                return
            # First-use Owner operations use their independently owned V2FencePort
            # and may outlast this client's bounded idle TLS channel. Resume the
            # actual Host/model path with a fresh real handshake and grant.
            assert (await authority_client.status_v2()).state == "paired"
            client_grant = await authority_client.installation_grant_v2()
            assert client_grant is not None
            assert (client_grant.authority_id, client_grant.installation_id, client_grant.manifest_digest) == (
                grant.authority_id, grant.installation_id, grant.manifest_digest)
            graph._GraphCoordinator__accounting_maintenance_port = InstalledAccountingMaintenancePort(
                client=authority_client, bundle=accounting_bundle, grant=client_grant,
                owner_loop=asyncio.get_running_loop())
        self_registration = server._v2_self_identity[authority_namespace].mutate(
            credential=admin_peer,
            subject="mtls:sha256:" + admin_peer.certificate_sha256,
            mutation=SelfIdentityMutationV1(
                grant.authority_id, authority_namespace, namespace,
                installation_id, manifest_digest, "entity:self-reply", "set",
                "register-self-reply", 0))
        assert self_registration.state == "active"
        adapter = AiocqhttpAdapter(
            {"id": "platform-1", "ws_reverse_host": "127.0.0.1",
             "ws_reverse_port": 6199}, {}, asyncio.Queue())
        adapter.bot.call_action = AsyncMock(return_value={"user_id": "10001"})
        host_context = Context(
            asyncio.Queue(), {}, None, None,
            SimpleNamespace(platform_insts=[adapter]), None, None, None,
            SimpleNamespace(get_conf=lambda umo: {}), None, None)
        host_context.conversation_manager = scene_fixture.Conversations()
        host_context.persona_manager = scene_fixture.Personas()
        host_context.persona_manager.selected = "persona-reply"
        observed = SceneCandidateCatalog()
        ingress_utc = time.time()
        ingress = HostIngressEnvelope(
            namespace, '["platform-1","aiocqhttp","10001"]',
            '["platform-1:FriendMessage:123456","conversation-1"]',
            '["platform-1","user-1"]', "message:reply", ingress_text,
            ingress_utc, ingress_utc + 0.001, "private",
            SourceLineage("a" * 64, "reported", "onebot",
                          "external_report", "reported_claim"))
        candidate_scene = observed.observe(ingress)
        assert candidate_scene is not None
        scene_port = InstalledSceneIdentityPort(
            context=host_context, host_loop=asyncio.get_running_loop(),
            candidates=observed)
        verified_scene = await asyncio.to_thread(
            scene_port.verify, namespace, candidate_scene.scene_ref, "private")
        assert verified_scene is not None
        graph._GraphCoordinator__scene_identity_port = scene_port
        graph._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
            source_id, 0.5, 2.0)
        d03 = ContextProvider()
        d03.compile_scheme({
            "schema": "d03.context.scheme.v1",
            "roles": ("scene_participant",), "norms": (),
        }, None)
        graph.register_provider(
            bootstrap, "d03", d03, "d03.proposal.v1",
            d03.descriptor.request_schema_hash)
        with graph_store._lock:
            _, scene_epoch = graph._v2_graph_stamp(namespace)
        binding_request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", None, None,
            verified_scene.scene_ref, "bind_scene",
            "workbench_user_action", 2.0, True)
        prior = RoleBindingResolution(
            "no_applicable_binding", (), (), (), (),
            QueryEpoch(namespace, "d03.role_binding", scene_epoch.revision),
            None, binding_request)
        scene_receipt = await asyncio.to_thread(
            graph.commit_scene_binding_v2,
            namespace=namespace, operation_id="scene-bind-reply",
            scene=verified_scene, prior=prior, principal=principal,
            actor_id="owner-actor-reply",
            request_digest="sha256:" + canonical_digest({
                "scene": verified_scene.scene_ref}),
            owner_session_token=owner_guard_token,
            owner_session_request=owner_guard_request)
        assert scene_receipt.operation_id == "scene-bind-reply"
        domains = ("d04", "d05", "d06", "d07", "d08", "d09", "d11")
        if enable_d09_workbench:
            domains += ("d12",)
        if enable_c04_body_work or register_c04_domains:
            domains += ("d02", "d12")
        for domain in dict.fromkeys(domains):
            registration = domain_registry.registrations[domain]
            prior = graph._GraphCoordinator__providers.get(domain)
            expected = (registration.provider, registration.proposal_schema, registration.proposal_schema_hash)
            if prior is not None:
                assert prior == expected
                continue
            graph.register_provider(
                bootstrap, domain, registration.provider,
                registration.proposal_schema,
                registration.proposal_schema_hash)
        graph._GraphCoordinator__dispatch_admission_issuer = (
            InstalledDispatchAdmissionIssuer(
                context=d03, d11_issuer=d11, d02_issuer=d02))
        observed.observe(ingress)
        host = IngressHostFacts(
            namespace, ingress.platform_ref, ingress.conversation_ref,
            ingress.sender_ref, ingress.message_id, ingress.text,
            ingress.occurred_at, ingress.learned_at, ingress.visibility,
            IngressLineage("a" * 64, "reported", "onebot",
                           "external_report", "reported_claim",
                           "not_applicable"))
        ingress_clock = AdminIngressClockPolicy(source_id, 0.5, 2.0)
        encoding = AdminIngressEncodingPolicy(
            120.0, {"output_tokens": 128},
            "snapshot:reply-ingress", "resource:reply-ingress",
            "character:reply")
        model_reply_mode = {"content": (
            '{"event_summary":"A person said hello.",'
            '"quoted_details":[{"quote":"hello",'
            '"salience":0.5}],"possible_meanings":[],'
            '"possible_feelings":[]}').replace("hello", ingress_text)}
        model_http_client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={
                "id": "original-encoding-reply", "object": "chat.completion",
                "created": 1, "model": "model-1", "choices": [{
                    "index": 0, "finish_reason": "stop", "message": {
                        "role": "assistant",
                        "content": model_reply_mode["content"]},
                }], "usage": {"prompt_tokens": 3,
                              "completion_tokens": 5, "total_tokens": 8}})))
        installed_provider = object.__new__(ProviderOpenAIOfficial)
        installed_provider.provider_config = provider_config
        installed_provider.model_name = "model-1"
        installed_provider.client = AsyncOpenAI(
            api_key="test-only", base_url="https://mock.invalid/v1",
            http_client=model_http_client)
        model_context = Context(
            asyncio.Queue(), {}, None, Manager(installed_provider),
            None, None, None, None, None, None, None)
        installed_bundle = AdminInstallationBundle(
            profile, policy, b"k" * 32, b"d" * 32,
            ingress_clock=ingress_clock,
            ingress_encoding=encoding, model_workflows=workflows)
        installed_model_selection = InstalledModelCapabilityPort(
            context=model_context, host_loop=asyncio.get_running_loop(),
            installed_namespace=namespace,
            installation_bundle=installed_bundle)
        assert await asyncio.to_thread(
            installed_model_selection.verify_admin_selection,
            namespace, encoding_workflow)
        graph._GraphCoordinator__self_identity_port = InstalledCurrentSelfIdentityPort(
            client=authority_client, bundle=installed_bundle, grant=client_grant,
            owner_loop=asyncio.get_running_loop())
        async def _commit_c02_message(host, ingress):
            first_ingress = await asyncio.to_thread(
                graph.commit_first_ingress_v2, bootstrap, host, policy,
                ingress_clock, encoding,
                AdminD06PrivateReplySourcePolicy(
                    1, "private_conversation", True))
            assert first_ingress.status == "committed"
            arrival = await asyncio.to_thread(
                graph.commit_d03_message_arrival_v2, bootstrap, namespace,
                host.lineage.source_ref, policy,
                AdminD03ArrivalPolicy(
                    30.0, {"cpu_ms": 3}, "snapshot:reply-arrival",
                    "resource:reply-arrival"), ingress_clock)
            assert arrival.status == "committed"
            with graph_store._lock:
                job_id, ingress_operation_id = graph_store._db.execute(
                    "SELECT job_id,operation_id FROM runtime_jobs WHERE operation_id=?",
                    (first_ingress.operation_id,),
                ).fetchone()
            projection = await asyncio.to_thread(
                graph.commit_d03_self_identity_projection_v1,
                bootstrap, namespace, job_id, ingress_operation_id,
                policy, AdminD03SelfIdentityProjectionPolicy(
                    30.0, {"cpu_ms": 4}, "snapshot:reply-projection",
                    "resource:reply-projection"), ingress_clock)
            assert projection.status == "committed"
            baseline = await asyncio.to_thread(
                graph.commit_d04_encoding_baseline_v1,
                bootstrap, namespace, job_id, ingress_operation_id,
                policy, AdminD04EncodingBaselinePolicy(
                    30.0, {"cpu_ms": 2}, "snapshot:reply-baseline",
                    "resource:reply-baseline"), ingress_clock)
            assert baseline.status == "committed"
            acquire_operation_id = first_ingress_encoding_acquire_operation_id(
                namespace, job_id, ingress_operation_id, client_grant.subject,
                current_anchor.activation_generation, "a" * 32)
            worker_lease, worker_capability = graph.grant(
                bootstrap, actor=client_grant.subject, issuer_domain="d11",
                namespace=namespace, domains=("d11",),
                activation_generation=current_anchor.activation_generation,
                operation_id=acquire_operation_id)
            worker_authority = AuthorityContext(
                client_grant.subject, "d11", worker_capability, namespace,
                ("activity",), encoding_workflow.purpose, (conversation_ref,),
                encoding_workflow.provider_config_ref,
                current_anchor.activation_generation)
            acquired = await asyncio.to_thread(
                graph.acquire_first_ingress_encoding_job_v3,
                worker_authority, worker_lease, job_id,
                acquire_operation_id, lease_seconds=30)
            assert acquired.job_id == job_id
            worker_authority = replace(worker_authority, worker_fence=acquired.fence)
            model_preparation = await asyncio.to_thread(
                graph.read_first_ingress_model_egress_preparation_v2,
                worker_authority, worker_lease, job_id,
                acquire_operation_id)
            assert model_preparation[1].job_id == job_id
            binding, draft, model_anchor = model_preparation
            installed_adapter = AstrBotModelProvider(
                context=model_context, host_loop=asyncio.get_running_loop(),
                trusted_umo="platform-1:FriendMessage:123456",
                descriptor=ModelProviderDescriptor(
                    "provider-1", "astrbot-4.28.1", "model-1",
                    frozenset({"text"}), frozenset({"consolidation"}),
                    frozenset({"private"}), "credential:astrbot-installed",
                    "unknown", False, False),
                admin_model=encoding_workflow,
                installation_bundle=installed_bundle)
            model_executor = HostModelEgressExecutor(
                authority=authority_client, bundle=installed_bundle,
                grant=client_grant, adapter=installed_adapter)
            frozen_request = model_executor._frozen_encoding_request(
                binding, draft, model_anchor)
            assert frozen_request.call_id == binding.call_id
            model_prepared, _ = await authority_client.model_prepare_fenced_v1(
                installed_bundle, client_grant, draft=draft,
                expected_anchor=model_anchor)
            assert model_prepared.state == "prepared"
            terminal = await model_executor.execute_once(
                intent=model_prepared.intent, expected_anchor=model_anchor,
                request=frozen_request)
            assert terminal is not None
            graph._GraphCoordinator__model_terminal_cost_port = (
                InstalledModelTerminalCostPort(
                    client=authority_client, bundle=installed_bundle,
                    grant=client_grant, owner_loop=asyncio.get_running_loop()))
            graph._GraphCoordinator__accounting_maintenance_port = (
                InstalledAccountingMaintenancePort(
                    client=authority_client, bundle=installed_bundle,
                    grant=client_grant, owner_loop=asyncio.get_running_loop()))
            with graph_store._lock:
                original_job = get_job(graph_store._db, job_id)
            quote_id, quote_version = original_job.operator_versions[
                "resource_quote"].rsplit(":", 1)
            cost = await asyncio.to_thread(
                graph.commit_first_ingress_model_cost_v1,
                bootstrap, namespace, model_prepared.intent,
                quote_id=quote_id, quote_version=int(quote_version))
            assert cost.status == "committed"
            with graph_store._lock:
                settled_state = graph_store._db.execute(
                    "SELECT state FROM runtime_budget_reservations WHERE lease_id=? "
                    "AND operation_id=?",
                    (original_job.budget_ref, original_job.operation_id)).fetchone()
                settle_operation = graph_store._db.execute(
                    "SELECT phase FROM runtime_budget_operations WHERE bot_id=? "
                    "AND persona_id=? AND operation_id=? AND phase='settle'",
                    namespace.as_tuple + (original_job.operation_id,)).fetchone()
            assert (settled_state, settle_operation) == (("settled",), ("settle",))
            original_context = await asyncio.to_thread(
                graph.read_first_ingress_original_model_result_context_v1,
                worker_authority, worker_lease, job_id, acquire_operation_id)
            worker_read = await model_executor.read_original_for_worker(
                read_request=first_ingress_worker_result_request_v1(original_context),
                intent=model_prepared.intent, terminal=terminal)
            assert worker_read is not None
            graph._GraphCoordinator__worker_result_fact_port = (
                InstalledWorkerResultReadFactPort(
                    client=authority_client, bundle=installed_bundle,
                    grant=client_grant, owner_loop=asyncio.get_running_loop()))
            c02 = await asyncio.to_thread(
                graph.commit_first_ingress_c02_v2,
                bootstrap, model_prepared.intent, worker_read, policy,
                AdminD06FirstIngressC02Policy(
                    30.0, {"cpu_ms": 2}, "snapshot:reply-c02",
                    "resource:reply-c02"), ingress_clock)
            assert c02.status == "committed"
            graph.release_authority_lease(bootstrap, worker_lease)
            return first_ingress, c02

        first_ingress, c02 = await _commit_c02_message(
            host, ingress)
        reply_bundle = replace(
            installed_bundle,
            d07_attention=AdminD07AttentionPolicy(
                300.0 if enable_c04_body_work and enable_d04_joint_numeric else 30.0,
                {"cpu_ms": 1}, "snapshot:reply-attention",
                "resource:reply-attention"),
            private_reply_dispatch=AdminPrivateReplyDispatchPolicy(
                120.0, {"cpu_ms": 1}, "snapshot:reply-dispatch",
                "resource:reply-dispatch", 800, 120.0))
        graph._GraphCoordinator__dispatch_clock_policy = ingress_clock
        async def commit_c02_attention(receipt):
            attention_inputs = await asyncio.to_thread(
                graph.read_post_c02_attention_inputs_v1,
                bootstrap, namespace, receipt.operation_id, None, reply_bundle)
            assert attention_inputs[0].operation_id == receipt.operation_id
            (current_c02, attention_snapshot, attention_qualification,
             attention_audience, attention_guard, attention_anchor,
             attention_clock, attention_policy, attention_competitor) = attention_inputs
            attention_source = attention_qualification.source_refs[0]
            attention_operation = post_c02_attention_operation_id(
                current_c02.operation_id, attention_source)
            attention_lease, attention_capability = graph.grant(
                bootstrap, actor=client_grant.subject, issuer_domain="d11",
                namespace=namespace, domains=("d07",),
                activation_generation=attention_anchor.activation_generation,
                operation_id=attention_operation)
            try:
                attention_authority = AuthorityContext(
                    client_grant.subject, "d11", attention_capability, namespace,
                    ("persona",), "expression", (attention_audience,),
                    policy.root_grant.policy_ref,
                    attention_anchor.activation_generation)
                attention_now = trusted_upper(attention_clock)
                attention_lifetime = (
                    reply_bundle.d07_attention.deadline_after_seconds
                    - 2 * ingress_clock.max_utc_error_seconds
                    - ingress_clock.max_round_trip_seconds)
                attention_candidate = prepare_post_c02_attention_v1(
                    c02_receipt=current_c02, source_ref=attention_source,
                    snapshot=attention_snapshot,
                    qualification=attention_qualification,
                    authority=attention_authority, guard=attention_guard,
                    parent_budget_lease_ref=policy.root_grant.lease_id,
                    conversation_ref=attention_audience, now_utc=attention_now,
                    monotonic_deadline=(attention_clock.monotonic_after_seconds
                                        + attention_lifetime),
                    ticket_lifetime_seconds=attention_lifetime,
                    current_policy=attention_policy.policy,
                    active_head_ref=attention_policy.active_head_ref,
                    current_competitor=attention_competitor)
                attention_receipt = await asyncio.to_thread(
                    graph.commit_post_c02_attention_v1,
                    attention_candidate.bundle, attention_lease, reply_bundle)
                assert attention_receipt.status == "committed"
            finally:
                graph.release_authority_lease(bootstrap, attention_lease)
            return attention_source, attention_receipt, attention_inputs

        attention_source, attention_receipt, attention_inputs = await commit_c02_attention(c02)
        (current_c02, attention_snapshot, attention_qualification,
         attention_audience, attention_guard, attention_anchor,
         attention_clock, attention_policy, attention_competitor) = attention_inputs

        async def commit_second_c02(message_id: str, text: str, *, commit_attention=False):
            """Run a distinct observed ingress through the same paid C02 path."""
            nonlocal client_grant
            if message_id == ingress.message_id or not text:
                raise ValueError("second ingress needs a distinct message")
            # Each installed first-ingress invocation owns a fresh paired model
            # channel. This direct permanent fixture does the same after the
            # previous long-running work, without retrying any business RPC.
            from dataclasses import asdict
            previous_identity = asdict(client_grant)
            assert (await authority_client.status_v2()).state == "paired"
            current_grant = await authority_client.installation_grant_v2()
            assert current_grant is not None
            current_identity = asdict(current_grant)
            previous_identity.pop("channel_binding_sha256")
            current_identity.pop("channel_binding_sha256")
            assert previous_identity == current_identity
            client_grant = current_grant
            graph._GraphCoordinator__self_identity_port = InstalledCurrentSelfIdentityPort(
                client=authority_client, bundle=installed_bundle, grant=client_grant,
                owner_loop=asyncio.get_running_loop())
            graph._GraphCoordinator__accounting_maintenance_port = InstalledAccountingMaintenancePort(
                client=authority_client, bundle=installed_bundle, grant=client_grant,
                owner_loop=asyncio.get_running_loop())
            observed_at = time.time()
            source_id = hashlib.sha256(
                (message_id + "\0" + text).encode("utf-8")).hexdigest()
            second_ingress = replace(
                ingress, message_id=message_id, text=text,
                occurred_at=observed_at, learned_at=observed_at + 0.001,
                lineage=SourceLineage(
                    source_id, "reported", "onebot", "external_report",
                    "reported_claim"))
            second_scene = observed.observe(second_ingress)
            assert second_scene is not None
            assert await asyncio.to_thread(
                scene_port.verify, namespace, second_scene.scene_ref,
                "private") is not None
            second_host = IngressHostFacts(
                namespace, second_ingress.platform_ref,
                second_ingress.conversation_ref, second_ingress.sender_ref,
                second_ingress.message_id, second_ingress.text,
                second_ingress.occurred_at, second_ingress.learned_at,
                second_ingress.visibility,
                IngressLineage(source_id, "reported", "onebot",
                               "external_report", "reported_claim",
                               "not_applicable"))
            model_reply_mode["content"] = json.dumps({
                "event_summary": text, "quoted_details": [],
                "possible_meanings": [], "possible_feelings": [],
            }, sort_keys=True, separators=(",", ":"))
            first, second = await _commit_c02_message(second_host, second_ingress)
            if commit_attention:
                await commit_c02_attention(second)
            return first, second

        if after_c02 is not None:
            await after_c02({
                "graph": graph, "store": graph_store,
                "namespace": namespace, "authority_namespace": authority_namespace,
                "bootstrap": bootstrap, "c02": c02,
                "commit_second_c02": commit_second_c02,
                "source_ref": attention_source, "attention_receipt": attention_receipt,
                "port": port, "core": core, "fences": fences,
                "core_authorizer": authorizer,
                "protected": protected, "execution": execution,
                "server": server, "reverse_server": reverse_server,
                "reverse_client": reverse_client,
                "files": files, "listener": listener,
                "authority_loop": authority_loop,
                "admin_port": admin_port,
                "admin_transport": admin_transport,
                "transport": transport,
                "client_transport": client_transport,
                "deletion_journal": deletion_journal,
                "deletion_guard": deletion_guard,
                "owner_sessions": owner_sessions,
                "owner_proofs": owner_proofs,
                "model_store": model_store,
                "observed": observed, "grant": grant,
                "peer": peer, "owner_key": owner_key,
                "owner_issue_operation": operation,
                "owner_issue_committed": committed,
                "owner_issue_grant_value": grant_value,
                "d02_issuer": d02, "d11_issuer": d11,
                "pairing_source": pairing_source,
                "authority_client": authority_client,
                "client_grant": client_grant, "installed_bundle": reply_bundle,
                "policy": policy, "principal": principal,
                "owner_session_token": owner_guard_token,
                "owner_session_request": owner_guard_request,
                "owner_console_session_token": owner_session_token,
                "owner_console_session_request": session_request,
                "host_context": host_context, "scene_port": scene_port,
                "adapter": adapter,
                "verified_scene": verified_scene,
                "ingress": ingress, "ingress_clock": ingress_clock,
                "model_service": model_service,
                "model_terminal_cost_port": graph._GraphCoordinator__model_terminal_cost_port,
                "accounting_maintenance_port": graph._GraphCoordinator__accounting_maintenance_port,
                "model_context": model_context,
                "model_reply_mode": model_reply_mode,
                "model_http_client": model_http_client,
            })
            return
        reply_job = await asyncio.to_thread(
            graph.prepare_post_c02_reply_model_job_v1,
            bootstrap, namespace, c02.operation_id, attention_source,
            reply_bundle)
        assert reply_job.job.phase == "queued"
        model_reply_mode["content"] = (
            '{"schema":"sylanne.d09.source_reply_output.v1",'
            '"body":"hello","spans":[{"start":0,"end":5,'
            '"source_quote":"hello"}]}')
        reply_acquire_operation = reply_model_operation_id_v1(
            c02.operation_id, attention_source)
        reply_lease, reply_capability = graph.grant(
            bootstrap, actor=client_grant.subject, issuer_domain="d11",
            namespace=namespace, domains=("d11",),
            activation_generation=attention_anchor.activation_generation,
            operation_id=reply_acquire_operation)
        reply_authority = AuthorityContext(
            client_grant.subject, "d11", reply_capability, namespace,
            ("activity",), workflows.reply.purpose, (conversation_ref,),
            workflows.reply.provider_config_ref,
            attention_anchor.activation_generation)
        acquired_reply_job = await asyncio.to_thread(
            graph.acquire_post_c02_reply_model_job_v1,
            reply_authority, reply_lease, c02.operation_id,
            attention_source, reply_bundle, lease_seconds=30)
        assert acquired_reply_job.phase == "running"
        reply_authority = replace(reply_authority,
                                  worker_fence=acquired_reply_job.fence)
        reply_model_preparation = await asyncio.to_thread(
            graph.read_post_c02_reply_model_egress_preparation_v1,
            reply_authority, reply_lease, c02.operation_id,
            attention_source, reply_bundle)
        assert reply_model_preparation[5].job_id == reply_job.job.job_id
        (reply_c02, reply_envelope, reply_source, reply_attention,
         reply_focus_revision, reply_draft, reply_model_anchor) = (
            reply_model_preparation)
        reply_adapter = AstrBotModelProvider(
            context=model_context, host_loop=asyncio.get_running_loop(),
            trusted_umo="platform-1:FriendMessage:123456",
            descriptor=ModelProviderDescriptor(
                "provider-1", "astrbot-4.28.1", "model-1",
                frozenset({"text"}), frozenset({"proposal"}),
                frozenset({"private"}), "credential:astrbot-installed",
                "unknown", False, False),
            admin_model=workflows.reply, installation_bundle=reply_bundle)
        reply_executor = HostModelEgressExecutor(
            authority=authority_client, bundle=reply_bundle,
            grant=client_grant, adapter=reply_adapter)
        assert all(amount <= workflows.reply.quote_ceiling.get(dimension, 0)
                   for dimension, amount in reply_job.quote.ceiling.items())
        from sylanne3.model_broker.reply_language import freeze_installed_reply_request_v1
        frozen_reply_request = freeze_installed_reply_request_v1(
            reply_envelope, reply_source, bundle=reply_bundle).request
        assert reply_adapter._request_allowed(frozen_reply_request)
        reply_run = await prepare_and_run_installed_reply_model_v1(
            c02_receipt=reply_c02, envelope=reply_envelope,
            source=reply_source, attention=reply_attention,
            focus_revision=reply_focus_revision, draft=reply_draft,
            expected_anchor=reply_model_anchor, executor=reply_executor)
        assert (reply_run is not None
                and reply_run.terminal.terminal is not None)
        reply_read_request = await asyncio.to_thread(
            graph.read_post_c02_reply_model_result_request_v1,
            reply_authority, reply_lease, c02.operation_id,
            attention_source, reply_bundle)
        selected_reply_read = await authority_client.reply_worker_model_result_select_attempt_v1(
            reply_bundle, client_grant, first_request=reply_read_request)
        assert selected_reply_read == reply_read_request
        reply_result_read = await authority_client.reply_worker_model_result_read_v1(
            reply_bundle, client_grant, read_request=selected_reply_read)
        assert reply_result_read.terminal_receipt == reply_run.terminal.terminal
        reply_candidate = parse_authority_reply_observation_v1(
            reply_run.preparation, observation=reply_result_read.observation,
            terminal=reply_result_read.terminal_receipt)
        reply_cost = await asyncio.to_thread(
            graph.commit_post_c02_reply_model_cost_v1,
            bootstrap, namespace, reply_run.preparation.intent,
            quote_id=reply_job.quote.quote_id,
            quote_version=reply_job.quote.version)
        assert reply_cost.status == "committed"
        progress = InstalledReplyProgressV1(
            reply_run, reply_cost, reply_candidate, reply_result_read)
        assert progress.result_read.request.consumer_operation_id
        reply_dispatch_operation = post_c02_reply_operation_id(
            c02.operation_id, attention_source)
        reply_dispatch_lease, reply_dispatch_capability = graph.grant(
            bootstrap, actor=client_grant.subject, issuer_domain="d11",
            namespace=namespace, domains=("d08", "d09", "d11"),
            activation_generation=attention_anchor.activation_generation,
            operation_id=reply_dispatch_operation)
        try:
            reply_dispatch_authority = AuthorityContext(
                client_grant.subject, "d11", reply_dispatch_capability,
                namespace, ("activity",), "expression", (conversation_ref,),
                policy.root_grant.policy_ref,
                attention_anchor.activation_generation)
            handler_deadline_utc = time.time() + 90.0
            sealed = await asyncio.to_thread(
                graph.assemble_post_c02_reply_v2,
                reply_dispatch_authority, reply_dispatch_lease, progress,
                reply_bundle, handler_invocation_id="handler:reply-original",
                handler_deadline_utc=handler_deadline_utc)
            assert (sealed.status, sealed.operation_id) == (
                "committed", reply_dispatch_operation)
            ready_probe = await asyncio.to_thread(
                graph.wait_for_durable_admission_v1,
                reply_dispatch_authority, reply_dispatch_lease,
                ingress_operation_id=first_ingress.operation_id,
                handler_invocation_id="handler:reply-original")
            assert ready_probe is not None
            assert ready_probe.ingress_operation_id == first_ingress.operation_id
            assert ready_probe.installation_id == installation_id
            assert ready_probe.account_ref == ingress.platform_ref
            assert ready_probe.destination_ref == ingress.conversation_ref
            assert (len(ready_probe.admission_digest) == 64
                    and all(character in "0123456789abcdef"
                            for character in ready_probe.admission_digest))

            takeover_calls = []
            class GraphReplyTakeoverPort:
                async def wait_for_durable_admission_v1(self, **identity):
                    try:
                        result = await asyncio.to_thread(
                            graph.wait_for_durable_admission_v1,
                            reply_dispatch_authority, reply_dispatch_lease,
                            **identity)
                    except Exception as exc:
                        takeover_calls.append(("wait_error", repr(exc)))
                        raise
                    takeover_calls.append(("wait", result))
                    return result

                async def close_host_default_v1(self, **identity):
                    takeover_calls.append(("close", identity))
                    return await asyncio.to_thread(
                        graph.close_host_default_v1,
                        reply_dispatch_authority, reply_dispatch_lease,
                        **identity)

                async def activate_reply_ownership_v1(self, **identity):
                    takeover_calls.append(("activate", identity))
                    activated = await asyncio.to_thread(
                        graph.activate_reply_ownership_v1,
                        reply_dispatch_authority, reply_dispatch_lease,
                        **identity)
                    if takeover_case == "unknown":
                        raise RuntimeError("original handler lost the CAS response")
                    return activated

                async def recover_reply_ownership_v1(self, **identity):
                    takeover_calls.append(("recover", identity))
                    if takeover_case == "unknown":
                        return None
                    return await asyncio.to_thread(
                        graph.read_reply_ownership_v1,
                        reply_dispatch_authority, reply_dispatch_lease,
                        **identity)

            original_event = _LiveEvent()
            takeover = await rendezvous_private_reply_v1(
                event=original_event, envelope=ingress,
                ingress_receipt=IngressReceipt(
                    "accepted", first_ingress.operation_id),
                installation_id=installation_id,
                handler_invocation_id="handler:reply-original",
                handler_nonce="nonce:reply-original",
                port=GraphReplyTakeoverPort(),
                deadline_monotonic=(
                    asyncio.get_running_loop().time() - 0.001
                    if takeover_case == "timeout" else
                    asyncio.get_running_loop().time() + 60.0),
                close_timeout_seconds=5.0,
                activation_timeout_seconds=5.0,
                suppression_registry=suppression_registry,
                handler_deadline_utc=handler_deadline_utc)
            assert takeover.status == {
                "owned": "sylanne_owned",
                "owned_no_observation_verifier": "sylanne_owned",
                "timeout": "host_default",
                "unknown": "takeover_unknown",
            }[takeover_case], (
                takeover_calls, original_event.stops,
                original_event.is_stopped())
            ownership = await asyncio.to_thread(
                graph.read_reply_ownership_v1,
                reply_dispatch_authority, reply_dispatch_lease,
                ingress_operation_id=first_ingress.operation_id,
                handler_invocation_id="handler:reply-original")
            assert ownership.ingress_operation_id == first_ingress.operation_id
            assert ownership.handler_invocation_id == "handler:reply-original"
            if takeover_case == "timeout":
                assert not original_event.is_stopped() and original_event.stops == 0
                assert ownership.state == "host_default"
                assert not any(name == "activate" for name, _ in takeover_calls)
            else:
                assert original_event.is_stopped() and original_event.stops == 1
                assert (ownership.state, ownership.reply_operation_id,
                        ownership.admission_ref, ownership.admission_digest,
                        ownership.account_ref, ownership.destination_ref) == (
                            "sylanne_owned", sealed.operation_id,
                            ready_probe.admission_ref, ready_probe.admission_digest,
                            ingress.platform_ref, ingress.conversation_ref)
                assert ownership.ack_digest is not None
                if takeover_case.startswith("owned"):
                    with graph_store._lock:
                        graph_store._db.execute(
                            "UPDATE graph_post_c02_reply_dispatch_attempts_v2 "
                            "SET bundle_digest=? WHERE bot=? AND persona=? "
                            "AND operation_id=?",
                            ("corrupted-seal", *namespace.as_tuple,
                             sealed.operation_id))
                    with pytest.raises(UnavailableGuard,
                                       match="recovered reply bundle seal differs"):
                        await asyncio.to_thread(
                            graph.read_reply_ownership_v1,
                            reply_dispatch_authority, reply_dispatch_lease,
                            ingress_operation_id=first_ingress.operation_id,
                            handler_invocation_id="handler:reply-original")
                    with graph_store._lock:
                        graph_store._db.execute(
                            "UPDATE graph_post_c02_reply_dispatch_attempts_v2 "
                            "SET bundle_digest=(SELECT digest FROM "
                            "graph_bundle_operations WHERE bot=? AND persona=? "
                            "AND operation_id=?) WHERE bot=? AND persona=? "
                            "AND operation_id=?",
                            (*namespace.as_tuple, sealed.operation_id,
                             *namespace.as_tuple, sealed.operation_id))
                    lease_count = len(graph._GraphCoordinator__leases)
                    with pytest.raises(UnavailableGuard, match="ownership or route"):
                        await asyncio.to_thread(
                            graph.grant_owned_reply_dispatch_scope_v1,
                            bootstrap, reply_bundle,
                            ingress_operation_id=first_ingress.operation_id,
                            handler_invocation_id="handler:wrong-reply")
                    assert len(graph._GraphCoordinator__leases) == lease_count
                    scoped_authority, scoped_lease, scoped_ownership = (
                        await asyncio.to_thread(
                            graph.grant_owned_reply_dispatch_scope_v1,
                            bootstrap, reply_bundle,
                            ingress_operation_id=first_ingress.operation_id,
                            handler_invocation_id="handler:reply-original"))
                    try:
                        assert scoped_authority.purpose == "expression"
                        assert scoped_authority.audience == (ingress.conversation_ref,)
                        graph._authorize(
                            scoped_lease, scoped_authority,
                            frozenset(("d08", "d09", "d11")))
                        assert (scoped_ownership.reply_operation_id,
                                scoped_ownership.effect_id,
                                scoped_ownership.admission_ref) == (
                                    sealed.operation_id, ownership.effect_id,
                                    ready_probe.admission_ref)
                        scoped_original = await asyncio.to_thread(
                            _read_original, graph, scoped_authority,
                            scoped_lease, first_ingress.operation_id,
                            "handler:reply-original")
                        assert (scoped_original.operation_id,
                                scoped_original.admission_ref) == (
                                    sealed.operation_id, ready_probe.admission_ref)
                    finally:
                        graph.release_authority_lease(bootstrap, scoped_lease)
                    assert len(graph._GraphCoordinator__leases) == lease_count
                    original = await asyncio.to_thread(
                        _read_original, graph, reply_dispatch_authority,
                        reply_dispatch_lease, first_ingress.operation_id,
                        "handler:reply-original")
                    assert (original.operation_id, original.admission_ref,
                            original.admission_digest, original.outbox_ref) == (
                                sealed.operation_id, ready_probe.admission_ref,
                                ready_probe.admission_digest,
                                sealed.outbox_refs[0])
                    frozen_text = await asyncio.to_thread(
                        lambda: GraphTextPayloadResolver(
                            graph, reply_dispatch_authority,
                            reply_dispatch_lease).resolve(original.request))
                    assert type(frozen_text) is ResolvedTextPayload
                    dispatch_clock = await asyncio.to_thread(
                        port.read_ingress_clock, ingress_clock)
                    dispatch_now = trusted_upper(dispatch_clock)
                    original.admission.admission.require_current(dispatch_now)
                    dispatch_anchor = await asyncio.to_thread(
                        port.current_anchor, namespace=namespace,
                        authority_namespace=authority_namespace)
                    dispatch_footprint = authority_dispatch_footprint_v2(
                        namespace, original.request)
                    dispatch_permit = await asyncio.to_thread(
                        port.begin_dispatch_fence,
                        namespace=namespace,
                        authority_namespace=authority_namespace,
                        holder=policy.administrator_holder,
                        generation=original.request.activation_generation,
                        operation_id=original.operation_id,
                        expected_anchor=dispatch_anchor,
                        effect_id=original.effect_id,
                        command_digest="sha256:" + original.request.command_digest,
                        footprint=dispatch_footprint)
                    assert dispatch_permit.operation_id == original.operation_id
                    dispatch_binding = build_non_authorizing_execution_binding_v2(
                        namespace=namespace,
                        admission_receipt=original.admission,
                        recovered_request=original.request,
                        original_dispatch_permit=dispatch_permit,
                        adapter_ref="adapter:platform-1",
                        now_utc=dispatch_now)
                    dispatch_identity = hashlib.sha256(
                        (original.operation_id + "\0" + original.effect_id).encode(
                            "utf-8")).hexdigest()
                    dispatch_prepared, _ = await asyncio.to_thread(
                        port.execution_prepare,
                        namespace=namespace,
                        authority_namespace=authority_namespace,
                        permit=dispatch_permit,
                        mutation_id="dispatch:" + dispatch_identity,
                        footprint=dispatch_footprint)
                    dispatch_claimed, _ = await asyncio.to_thread(
                        port.execution_claim_v2,
                        namespace=namespace,
                        authority_namespace=authority_namespace,
                        prepared_receipt=dispatch_prepared,
                        binding=dispatch_binding)
                    assert (dispatch_claimed.pending.permit.operation_id,
                            dispatch_claimed.pending.phase,
                            dispatch_claimed.durable_state) == (
                                original.operation_id, "claimed", "committed")
                    route_port = InstalledDispatchRoutePort(
                        context=host_context,
                        host_loop=asyncio.get_running_loop(),
                        candidates=observed, coordinator=graph,
                        authority=reply_dispatch_authority,
                        lease=reply_dispatch_lease, policy=policy,
                        grant=grant)
                    graph_worker = await GraphWorker.start(
                        lambda: graph_store, lambda _store: graph)
                    claim_writer = await graph_worker.call(
                        lambda current_graph:
                            current_graph.register_dispatch_final_claim_writer_v1(
                                bootstrap, route_port=route_port,
                                issuer_id="issuer:reply"))
                    handoff_id = "handoff:" + dispatch_identity
                    prepared_writer = await graph_worker.call(
                        lambda current_graph: claim_writer.prepare_for_handoff(
                            current_graph, dispatch_claimed, handoff_id))
                    port_grant = await asyncio.to_thread(
                        lambda: port.installation_grant)
                    handoff = await asyncio.to_thread(
                        InstalledCurrentDispatchHandoffPort,
                        fence_port=port, policy=policy, grant=port_grant,
                        claimed_receipt=dispatch_claimed)
                    onebot_sends = []

                    async def controlled_onebot(action, **kwargs):
                        if action == "send_private_msg":
                            onebot_sends.append((action, kwargs))
                            return {"message_id": 9042}
                        return {"user_id": "10001"}

                    adapter.bot.call_action.side_effect = controlled_onebot
                    recorded_observations = []

                    async def record_observation(start, observation):
                        receipt = await handoff.record_observation(
                            start, observation)
                        recorded_observations.append(receipt)
                        return receipt

                    sender = AstrBotV2TextSender(
                        context=host_context, candidates=observed,
                        resolver=_FrozenGraphTextResolver(
                            original.request, frozen_text),
                        authority=handoff, clock_policy=ingress_clock,
                        record_observation=record_observation)

                    async def begin_dispatch_handoff(claimed, handoff_id):
                        return await asyncio.to_thread(
                            port.execution_begin_handoff_v2,
                            namespace=namespace,
                            authority_namespace=authority_namespace,
                            claimed_receipt=claimed,
                            handoff_id=handoff_id)

                    if takeover_case == "owned_no_observation_verifier":
                        with pytest.raises(
                                V2PlatformObservationVerifierUnavailable):
                            await begin_dispatch_handoff(
                                dispatch_claimed, handoff_id)
                        assert onebot_sends == []
                        assert recorded_observations == []
                        return

                    async with begin_handoff_with_reverse_claim(
                            worker=graph_worker, server=reverse_server,
                            claimed=dispatch_claimed,
                            handoff_id=handoff_id,
                            claim_writer=prepared_writer,
                            begin=begin_dispatch_handoff) as decision:
                        assert not decision.replay
                        observation = await sender.send(
                            decision=decision, binding=dispatch_binding,
                            claimed_receipt=dispatch_claimed,
                            request=original.request)
                        assert observation.outcome == "accepted"
                        assert observation.platform_message_id == "9042"
                        assert len(recorded_observations) == 1
                        receipt, _ = recorded_observations[0]
                        assert type(receipt) is MutationReceiptV2
                        assert receipt.durable_state == "committed"
                        assert receipt.pending.phase == "observed"
                        assert receipt.pending.platform_observation == observation
                    assert len(onebot_sends) == 1
                    assert onebot_sends[0][0] == "send_private_msg"
                    assert onebot_sends[0][1]["user_id"] == 123456
                    if takeover_case == "owned":
                        effect_read = await asyncio.to_thread(
                            port.read_current_effect,
                            namespace=namespace,
                            authority_namespace=authority_namespace,
                            effect_id=original.effect_id)
                        assert effect_read.state == "observed"
                        assert effect_read.observation_id == observation.observation_id
                    replay_start = await asyncio.to_thread(
                        port.execution_begin_handoff_v2,
                        namespace=namespace,
                        authority_namespace=authority_namespace,
                        claimed_receipt=dispatch_claimed,
                        handoff_id=handoff_id)
                    assert replay_start.replay
                    claim_receipt = replay_start.graph_claim_receipt
                    assert type(claim_receipt) is DispatchGraphClaimReceiptV1
                    async with begin_handoff_with_reverse_claim(
                            worker=graph_worker, server=reverse_server,
                            claimed=dispatch_claimed, handoff_id=handoff_id,
                            claim_writer=prepared_writer,
                            begin=begin_dispatch_handoff) as replay_decision:
                        assert replay_decision.replay
                    assert len(onebot_sends) == 1
                    with sqlite3.connect(tmp_path / "business.db") as claim_db:
                        claim_row = claim_db.execute(
                            "SELECT revision,valid FROM graph_atoms "
                            "WHERE token=? AND bot=? AND persona=?",
                            (dispatch_claim_key(namespace, original.effect_id).token,
                             *namespace.as_tuple),
                        ).fetchone()
                    assert claim_receipt.graph_claim_ref == (
                        "dispatch-claim:" + original.effect_id)
                    assert claim_row == (1, 1)
        finally:
            graph.release_authority_lease(bootstrap, reply_dispatch_lease)
    finally:
        if graph_worker is not None:
            await graph_worker.close()
        if reverse_listener is not None:
            reverse_listener.close()
            await reverse_listener.wait_closed()
        if model_http_client is not None:
            await model_http_client.aclose()
        if admin_port is not None:
            await asyncio.to_thread(admin_port.close)
        if port is not None:
            await asyncio.to_thread(port.close)
        if admin_transport is not None:
            await admin_transport.close()
        if transport is not None:
            await transport.close()
        if client_transport is not None:
            await client_transport.close()
        if authority_loop is not None:
            async def close_authority():
                if listener is not None:
                    listener.close()
                    await listener.wait_closed()
                if server is not None:
                    await server.aclose()
            await asyncio.to_thread(
                lambda: asyncio.run_coroutine_threadsafe(
                    close_authority(), authority_loop).result(timeout=30))
            authority_loop.call_soon_threadsafe(authority_loop.stop)
            await asyncio.to_thread(authority_thread.join, 30)
            authority_loop.close()
        graph_store.close()
        core.close()
        if "graph" in locals():
            actual_d04 = getattr(graph, "_actual_d04_authority_acceptance_v3", None)
            if actual_d04 is not None:
                actual_d04.close()
            elif getattr(graph, "_initial_offline_storage_case_v1", None) is not None:
                graph._initial_offline_storage_case_v1.close()
