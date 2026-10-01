"""A natural paid original survives replacement of the installation Core."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import threading
import time

import pytest

from rewrite.tests.alpha1.authority.test_authority_daemon_cold_open import (
    _installed_config,
)
from rewrite.tests.alpha1.authority.test_natural_generation_real_authority_output import (
    _real_authority_case, c02_case, context_reply_c02_case,
)
from sylanne3.authority_service.daemon import open_authority_daemon
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.deployment_config import (
    ExecutionJournalInstallation, InstalledNaturalModelAuthorityV2,
)
from sylanne3.authority_service.installed_core_verifiers import (
    installed_core_verifier_factory,
)
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore
from sylanne3.authority_service.v2_owner_session import AuthorityV2OwnerSessionStore
from sylanne3.authority_service.v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from sylanne3.authority_service.v2_worker_model_result_attempts import (
    AuthorityV2WorkerModelResultAttempts,
)
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime_contracts import AuthorityContext


def _reopen_installed_paid_authority(tmp_path: Path):
    installation = tmp_path / "daemon-install"
    installation.mkdir()
    base, files, bootstrap_server = _installed_config(installation)
    asyncio.run(bootstrap_server.aclose())
    peer = next(iter(base.installations_v2))

    def install(*, case, saved, natural, core, fences, deletion, guard,
                execution, graph_path, authority_namespace, original_anchor):
        policy = AdministratorInstallationV2(
            saved.seal.installation_id, "administrator", "policy:daemon-test",
            "v2", "2" * 64, "clock:daemon-test", 1.0)
        frozen_now = saved.frozen.input.frozen_at_utc + 1.0

        class FrozenClock:
            def __call__(self):
                from sylanne3.authority_service.v2_clock import AuthorityClockReadingV2
                return AuthorityClockReadingV2(
                    policy.source_id, frozen_now, frozen_now,
                    "daemon-paid-epoch", True, 0.1)

        pairing = AuthorityOwnerPairingSource(
            core, utc_clock=lambda: datetime.now(timezone.utc), create=True)
        proofs = AuthorityV2OwnerProofStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            pairing_verifier=lambda *_: False, create=True)
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            current_pairing_source=pairing, create=True)
        AuthorityV2OwnerTicketStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            owner_sessions=sessions, creation_pairing_source=pairing,
            create=True)
        AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock)
        AuthorityV2WorkerModelResultAttempts(core._db, create=True, lock=core._lock)
        del proofs, fences, original_anchor
        core.close()
        execution.close()
        guard.close()
        deletion.close()

        namespace = case["namespace"]
        reverse = replace(next(iter(base.reverse_handoff_profiles.values())),
                          namespace=authority_namespace,
                          installation_id=saved.seal.installation_id)
        config = replace(
            base,
            authority_db=tmp_path / "authority.db",
            deletion_db=tmp_path / "deletion.db",
            graph_db=Path(graph_path),
            execution_journals={authority_namespace:
                ExecutionJournalInstallation(tmp_path / "execution.db", "execution")},
            installations_v2={peer: policy},
            namespace_bindings_v2={(peer[0], peer[1], namespace):
                                   authority_namespace},
            reverse_handoff_profiles={authority_namespace: reverse},
            reverse_handoff_issuers={authority_namespace: "graph-issuer"},
            core_authorizer=lambda credential, *_: (
                credential == "ok" or
                getattr(credential, "certificate_sha256", None) == peer[0]),
            core_verifier_factory=installed_core_verifier_factory,
            publisher_manifest_verifier=lambda profile, plugin, version, digest:
                (profile == peer[1] and plugin == "astrbot_plugin_sylanne"
                 and version == "4.28.1" and digest == policy.manifest_digest),
            natural_model_authorities_v2={authority_namespace:
                InstalledNaturalModelAuthorityV2(
                    case["graph"]._GraphCoordinator__d11_issuer,
                    natural.model_workflows, peer, installation_bundle=natural)},
            clock_provider=FrozenClock(),
        )
        daemon = open_authority_daemon(config)
        service = daemon.server._v2_model_egress[authority_namespace]
        protected = daemon.server._v2_fences[authority_namespace]
        assert daemon.core is service._fences.core
        assert daemon.core is protected.core
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()

        async def check_listener():
            listener = await daemon.start()
            assert listener.is_serving()
            profile = AuthorityTlsProfile(
                peer[1], "127.0.0.1", config.bind_port, "localhost",
                daemon.server._authority_id(), files["ca.pem"],
                files["client.pem"], files["client.key"])
            transport = MtlsAuthorityTransport({peer[1]: profile})
            request = AuthorityProvisioningRequest(
                AUTHORITY_PROTOCOL, peer[1], "astrbot_plugin_sylanne",
                "4.28.1", tmp_path, tmp_path,
                PublisherPackageIdentity(policy.manifest_digest))
            handshake = await transport.handshake(
                request, protocol=AUTHORITY_V2_PROTOCOL)
            sample = await transport.ingress_clock_sample_v2(
                request, handshake, policy.installation_id)
            assert sample.source_id == policy.source_id

        def cleanup():
            try:
                asyncio.run_coroutine_threadsafe(
                    daemon.aclose(), loop).result(timeout=30)
            finally:
                loop.call_soon_threadsafe(loop.stop)
                thread.join(timeout=30)
                loop.close()

        try:
            asyncio.run_coroutine_threadsafe(
                check_listener(), loop).result(timeout=30)
        except BaseException:
            cleanup()
            raise

        return daemon.core, protected, service, cleanup

    return install


def test_daemon_reopened_core_handles_generation_and_review_paid_originals(
        request, tmp_path, monkeypatch):
    def commit_final(value):
        case = value["case"]
        graph, namespace = case["graph"], case["namespace"]
        material = value["final_candidate"].material
        assert material is not None
        port = graph._GraphCoordinator__content_fence_v2
        policy = graph._GraphCoordinator__dispatch_clock_policy
        original_clock = port.read_ingress_clock
        anchor = port.current_anchor(
            namespace=namespace,
            authority_namespace=graph._v2_graph_stamp(namespace)[0]
            .requirements.authority_namespace)
        now = value["now_utc"]
        monotonic = time.monotonic()
        clock = VerifiedIngressClockV2(
            IngressClockSampleV2(
                anchor.authority_id,
                value["installed"].installation_policy.installation_id,
                policy.source_id, now, monotonic, "daemon-final-commit", 0.0),
            monotonic, monotonic, now)
        monkeypatch.setattr(
            port, "read_ingress_clock",
            lambda requested: clock if requested == policy else original_clock(requested))
        lease, capability = graph.grant(
            case["c02_case"]["case"][2],
            actor=case["c02_case"]["case"][4].administrator_holder,
            issuer_domain="d11", namespace=namespace,
            domains=("d08", "d09", "d11"),
            activation_generation=graph._v2_graph_stamp(namespace)[0]
            .requirements.activation_generation,
            operation_id=material.final_operation_id)
        authority = AuthorityContext(
            case["c02_case"]["case"][4].administrator_holder,
            "d11", capability, namespace, ("activity",), "expression",
            (material.audience_id,),
            value["installed"].installation_policy.root_grant.policy_ref,
            graph._v2_graph_stamp(namespace)[0]
            .requirements.activation_generation)
        try:
            receipt = graph.commit_post_c02_natural_final_v2(
                authority, lease, value["parent_original_id"],
                value["installed"])
            assert receipt.status == "committed"
            assert graph.read_committed_natural_dispatch_v2(
                authority, lease, material.final_operation_id) is not None
        finally:
            graph.release_authority_lease(case["c02_case"]["case"][2], lease)

    _real_authority_case(
        request, tmp_path, monkeypatch, "review_current",
        before_revoke=commit_final,
        daemon_reopen=_reopen_installed_paid_authority(tmp_path))
