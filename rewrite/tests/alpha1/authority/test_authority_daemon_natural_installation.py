"""Cold-open only: installed model capabilities require original durable ledgers."""

from dataclasses import replace
import time

import pytest

from rewrite.tests.alpha1.authority.test_authority_daemon_cold_open import (
    NAMESPACE, _installed_config,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.daemon import open_authority_daemon
from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
from sylanne3.authority_service.deployment_config import InstalledNaturalModelAuthorityV2
from sylanne3.authority_service.v2_clock import AuthorityClockReadingV2
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.v2_worker_model_result_attempts import (
    AuthorityV2WorkerModelResultAttempts,
)
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.authority_profile import (
    AdminModelWorkflowV2, AdminModelWorkflowsV2, installed_model_config_ref,
)
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
from sylanne3.model_broker.natural_reply import TEMPLATE_VERSION
from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION
from sylanne3.runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer


class InstalledClock:
    """Controlled in-process clock provider; no physical UTC attestation."""

    def __init__(self, source_id: str):
        self.source_id = source_id
        self.healthy = True

    def __call__(self) -> AuthorityClockReadingV2:
        return AuthorityClockReadingV2(
            self.source_id, time.time(), time.monotonic(),
            "controlled-test-epoch", self.healthy, 0.1)


def _workflows() -> AdminModelWorkflowsV2:
    def one(kind: str, purpose: str, version: str) -> AdminModelWorkflowV2:
        provider, model, digest = "installed-provider", "installed-model", "a" * 64
        return AdminModelWorkflowV2(
            work_kind=kind, provider_id=provider, model_id=model,
            provider_config_ref=installed_model_config_ref(provider, model, digest),
            provider_config_digest=digest, purpose=purpose,
            audiences=("owner",), privacy_tier="private",
            template_version=version, required_capabilities=("text",),
            timeout_seconds=20.0, max_output_tokens=64,
            quote_ceiling={"output_tokens": 64, "USD": 2})

    return AdminModelWorkflowsV2(
        2, one("d06.encode_source", "consolidation",
               FIRST_INGRESS_ENCODING_TEMPLATE_VERSION),
        one("reply", "proposal", REPLY_TEMPLATE_VERSION),
        natural_generation=one("natural_generation", "proposal", TEMPLATE_VERSION),
        natural_review=one("natural_review", "proposal", REVIEW_TEMPLATE_VERSION))


def _initialize_model_ledgers(config) -> None:
    deletion = AuthorityV2DeletionGuard(config.deletion_db)
    journal = AuthorityV2ExecutionJournal(
        config.execution_journals[NAMESPACE].path, namespace=NAMESPACE,
        journal_id=config.execution_journals[NAMESPACE].journal_id, create=False)
    core = None
    try:
        verifiers = config.core_verifier_factory(deletion, {NAMESPACE: journal})
        core = AuthorityServiceCore(
            config.authority_db, authorizer=config.core_authorizer,
            deletion_verifier=verifiers.deletion,
            execution_verifier=verifiers.execution,
            effect_verifier=verifiers.effect,
            dispatch_verifier=verifiers.dispatch, create=False)
        AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock)
        AuthorityV2WorkerModelResultAttempts(core._db, create=True, lock=core._lock)
    finally:
        if core is not None:
            core.close()
        journal.close()
        deletion.close()


@pytest.mark.asyncio
async def test_natural_services_reopen_original_ledger_and_reject_missing_or_changed_identity(tmp_path):
    base, files, bootstrap_server = _installed_config(tmp_path)
    await bootstrap_server.aclose()
    peer = next(iter(base.installations_v2))
    clock = InstalledClock("installed-clock")
    installed = replace(next(iter(base.installations_v2.values())),
                        source_id=clock.source_id, max_utc_error_seconds=1.0)
    issuer = D11BudgetJobIssuer(D02ResourceIssuer(b"d" * 32), b"j" * 32)
    config = replace(
        base, installations_v2={peer: installed}, clock_provider=clock,
        core_verifier_factory=installed_core_verifier_factory,
        natural_model_authorities_v2={NAMESPACE: InstalledNaturalModelAuthorityV2(
            issuer, _workflows(), peer)})

    with pytest.raises(AuthorityUnavailable, match="model egress|worker result"):
        open_authority_daemon(config)

    _initialize_model_ledgers(config)
    daemon = open_authority_daemon(config)
    try:
        model = daemon.server._v2_model_egress[NAMESPACE]
        assert model._fences.core is daemon.core
        assert model._store._db is daemon.core._db
        assert model._graph_verifier._issuer is issuer
        assert daemon.server._v2_model_result_reads[NAMESPACE]._store is model._store
        assert daemon.server._v2_natural_generation_output_reads[NAMESPACE]._store is model._store
        assert daemon.server._v2_natural_review_output_reads[NAMESPACE]._store is model._store
        assert daemon.server._v2_natural_paid_review_reads[NAMESPACE]._generation is (
            daemon.server._v2_natural_generation_output_reads[NAMESPACE])
        assert daemon.server._clock_provider().source_id == clock.source_id
        listener = await daemon.start()
        assert listener.is_serving()
        profile = AuthorityTlsProfile(
            peer[1], "127.0.0.1", base.bind_port, "localhost",
            daemon.server._authority_id(), files["ca.pem"],
            files["client.pem"], files["client.key"])
        transport = MtlsAuthorityTransport({peer[1]: profile})
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, peer[1], "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity(installed.manifest_digest))
        handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
        sample = await transport.ingress_clock_sample_v2(
            request, handshake, installed.installation_id)
        assert sample.source_id == clock.source_id
        assert sample.installation_id == installed.installation_id
        clock.healthy = False
        with pytest.raises(AuthorityUnavailable, match="unhealthy"):
            daemon.server._clock_provider()
        clock.healthy = True
        clock.source_id = "different-clock"
        with pytest.raises(AuthorityUnavailable, match="source or error bound"):
            daemon.server._clock_provider()
    finally:
        await daemon.aclose()

    with pytest.raises(AuthorityUnavailable, match="installation identity"):
        replace(config, natural_model_authorities_v2={NAMESPACE:
                InstalledNaturalModelAuthorityV2(issuer, _workflows(),
                                                 ("f" * 64, peer[1]))})
