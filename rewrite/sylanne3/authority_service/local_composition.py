"""Install a first-Owner Authority RPC with a pinned, current local graph.

Deployment supplies the graph path and authenticators; no RPC field selects
the database or substitutes evidence for an independently finished write fence.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping

from .contract import AuthorityUnavailable
from .core import AuthorityServiceCore
from .current_graph_verifier import PinnedCurrentGraphVerifier
from .current_owner_revoke_graph_verifier import PinnedCurrentOwnerRevokeGraphVerifier
from .mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer,
)
from .reverse_handoff import ReverseGraphClaimClient
from .v2_clock import AuthorityClockReadingV2
from .v2_contract import FencePermitV2
from .v2_fence_service import AuthorityV2FenceService
from .v2_fence_store import AuthorityV2FenceStore
from .v2_migration_rpc import MigrationRpcHandlerV2
from .v2_migration_service import AuthorityV2MigrationService
from .v2_accounting_service import AuthorityV2AccountingMaintenanceService
from .v2_model_egress_service import AuthorityV2ModelEgressService
from .v2_model_result_read_service import AuthorityV2ModelResultReadService
from .current_model_result_read_graph_verifier import PinnedCurrentModelResultReadGraphVerifier
from .current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
from .current_worker_model_result_graph_verifier import PinnedCurrentWorkerModelResultGraphVerifier
from .current_reply_worker_model_result_graph_verifier import PinnedCurrentReplyWorkerModelResultGraphVerifier
from .v2_worker_model_result_attempts import AuthorityV2WorkerModelResultAttempts
from .v2_worker_model_result_read_service import AuthorityV2WorkerModelResultReadService
from .current_context_reply_original_verifier import PinnedCurrentContextReplyOriginalVerifier
from .v2_context_reply_result_service import AuthorityV2ContextReplyResultReadService
from .v2_natural_generation_output_service import (
    AuthorityV2NaturalGenerationOutputService,
    PinnedNaturalGenerationOriginalPaidVerifierV2,
)
from .v2_natural_generation_content_service import (
    AuthorityV2NaturalGenerationContentService,
    PinnedCurrentNaturalGenerationContentVerifierV2,
)
from .v2_natural_review_output_service import (
    AuthorityV2NaturalReviewOutputService,
    PinnedNaturalReviewOriginalPaidVerifierV2,
)
from .v2_natural_paid_review_service import (
    AuthorityV2NaturalPaidReviewService,
    PinnedCurrentNaturalPaidReviewVerifierV2,
)
from .v2_worker_result_read_fact_service import AuthorityV2WorkerResultReadFactService
from .v2_owner_contract import OwnerAuthorizationOperationV1, OwnerClaimTicketV1
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .v2_owner_proof import AuthorityV2OwnerProofStore, OwnerProofAcceptanceV1
from .v2_owner_session import AuthorityV2OwnerSessionStore
from .v2_self_identity_service import AuthorityV2SelfIdentityService
from .current_self_identity_graph_verifier import PinnedCurrentSelfIdentityGraphVerifier
from .installed_platform_observation import (
    HostOneBotObservationInstallationV2,
    InstalledHostOneBotObservationVerifierV2,
)
from ..runtime_contracts import NamespaceId


def compose_installed_owner_ticket_store_v3(*, core, services, graph_db_path, utc_clock,
        first_claim_verifier, verified_claimant, owner_sessions, creation_pairing_source,
        create_owner_schema=False):
    """Share the real finished-fence and Graph verifiers without an RPC server."""
    def finished_fence(permit: FencePermitV2, finish_id: str,
                       finish_digest: str) -> bool:
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or type(finish_id) is not str or type(finish_digest) is not str):
            return False
        service = services.get(permit.namespace)
        if service is None:
            return False
        with service._frozen() as (db, deletion_head, execution_head,
                                   deletion_history):
            current = service._current_locked(db, deletion_head, execution_head)
            if current != permit.pinned_anchor:
                return False
            AuthorityV2FenceStore._check_schema(db)
            AuthorityV2FenceStore._require_no_migration(db)
            row = AuthorityV2FenceStore._row(db, permit.operation_id)
            # The epoch is fixed in this fence row. Later finished fences advance
            # the issuance counter without invalidating this durable receipt.
            return (row is not None
                    and row[:6] == (
                        permit.operation_id, permit.namespace, permit.subject,
                        permit.token, permit.fence_epoch, permit.revision)
                    and row[6] == "finished"
                    and row[8:11] == (finish_id, finish_digest, None)
                    and AuthorityV2FenceStore._permit(row) == permit
                    and permit.authority_id == core._id(db))

    graph_verifier = PinnedCurrentGraphVerifier(
        graph_db_path, finished_fence_verifier=finished_fence)
    revoke_graph_verifier = PinnedCurrentOwnerRevokeGraphVerifier(
        graph_db_path, finished_fence_verifier=finished_fence)
    return AuthorityV2OwnerTicketStore(
        core, utc_clock=utc_clock,
        first_claim_verifier=first_claim_verifier,
        claimant_verifier=verified_claimant,
        graph_commit_verifier=graph_verifier,
        revoke_graph_commit_verifier=revoke_graph_verifier,
        owner_sessions=owner_sessions,
        creation_pairing_source=creation_pairing_source,
        create=create_owner_schema,
    )


def compose_local_owner_authority(
    *, core: AuthorityServiceCore,
    v2_fences: Mapping[str, AuthorityV2FenceService],
    graph_db_path: str | Path,
    utc_clock: Callable[[], datetime],
    first_claim_verifier: Callable[[object, OwnerClaimTicketV1, str], bool],
    claimant_verifier: Callable[[object, OwnerAuthorizationOperationV1], bool] | None,
    administrator_authorizer: Callable[[object, str, str, str | None], bool],
    publisher_manifest_verifier: Callable[[str, str, str, str], bool],
    installations_v2: Mapping[tuple[str, str], AdministratorInstallationV2],
    namespace_bindings_v2: Mapping[tuple[str, str, NamespaceId], str],
    v2_migration_rpc: MigrationRpcHandlerV2 | None = None,
    v2_migration_rpc_factory: Callable[[AuthorityV2OwnerTicketStore], MigrationRpcHandlerV2] | None = None,
    v2_final_handoff_reverse: Mapping[str, ReverseGraphClaimClient] | None = None,
    v2_final_handoff_issuers: Mapping[str, str] | None = None,
    v2_dispatch_verifiers: Mapping[str, Callable] | None = None,
    host_onebot_observations_v2: Mapping[
        str, HostOneBotObservationInstallationV2] | None = None,
    v2_model_egress: Mapping[str, AuthorityV2ModelEgressService] | None = None,
    model_observers_v2: Mapping[str, tuple[str, str]] | None = None,
    accounting_observers_v2: Mapping[str, tuple[str, str]] | None = None,
    worker_result_readers_v2: Mapping[str, tuple[str, str]] | None = None,
    worker_result_fact_committers_v2: Mapping[str, tuple[str, str]] | None = None,
    self_identity_readers_v2: Mapping[str, tuple[str, str]] | None = None,
    model_result_source_purposes: Mapping[str, str] | None = None,
    clock_provider: Callable[[], AuthorityClockReadingV2] | None = None,
    create_owner_schema: bool = False,
    create_worker_result_schema: bool = False,
    create_self_identity_schema: bool = False,
    owner_proofs: AuthorityV2OwnerProofStore | None = None,
    current_claimant_verifier: Callable[[object, OwnerAuthorizationOperationV1,
                                        OwnerProofAcceptanceV1], bool] | None = None,
    owner_sessions: AuthorityV2OwnerSessionStore | None = None,
    creation_pairing_source: object | None = None,
) -> AuthorityRpcServer:
    """Build the independent local Authority endpoint from trusted install config.

    The finished-fence check reads the durable Authority row under both journal
    freezes. Owner finalization calls the graph verifier outside Core's lock.
    No service is started and no ownership is issued by this factory.
    """
    if type(core) is not AuthorityServiceCore:
        raise TypeError("independent Authority core is required")
    services = dict(v2_fences)
    if (not services or any(
            type(namespace) is not str or type(service) is not AuthorityV2FenceService
            or service.core is not core or service.namespace != namespace
            for namespace, service in services.items())):
        raise AuthorityUnavailable("trusted v2 fence services are required")
    if (not callable(utc_clock) or not callable(first_claim_verifier)
            or not callable(administrator_authorizer)
            or not callable(publisher_manifest_verifier)):
        raise AuthorityUnavailable("trusted Authority callbacks are required")
    if (owner_sessions is not None
            and (type(owner_sessions) is not AuthorityV2OwnerSessionStore
                 or owner_sessions._core is not core)):
        raise AuthorityUnavailable("Owner sessions require this Authority core")
    if creation_pairing_source is not None:
        from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
        if (type(creation_pairing_source) is not AuthorityOwnerPairingSource
                or creation_pairing_source._core is not core):
            raise AuthorityUnavailable("creation pairing requires this Authority core")
    if owner_sessions is not None:
        if (owner_proofs is not None and (
                type(owner_proofs) is not AuthorityV2OwnerProofStore
                or owner_proofs._core is not core)):
            raise AuthorityUnavailable("Owner proof store requires this Authority core")
        if claimant_verifier is not None or current_claimant_verifier is not None:
            raise AuthorityUnavailable("Owner session is the sole current claimant verifier")
        verified_claimant = None
    elif owner_proofs is None:
        if not callable(claimant_verifier) or current_claimant_verifier is not None:
            raise AuthorityUnavailable("trusted Owner claimant verifier is required")
        verified_claimant = claimant_verifier
    else:
        if (type(owner_proofs) is not AuthorityV2OwnerProofStore
                or owner_proofs._core is not core or claimant_verifier is not None
                or not callable(current_claimant_verifier)):
            raise AuthorityUnavailable("Owner proof must be the sole claimant verifier")

        def verified_claimant(credential: object,
                             operation: OwnerAuthorizationOperationV1) -> bool:
            accepted = owner_proofs.get_accepted_for_operation(
                transport_credential=credential, operation=operation)
            return (accepted is not None
                    and current_claimant_verifier(credential, operation, accepted) is True)
    if not installations_v2 or not namespace_bindings_v2:
        raise AuthorityUnavailable("installed peer and namespace bindings are required")
    if set(namespace_bindings_v2.values()) != set(services):
        raise AuthorityUnavailable("owner namespace bindings must cover the installed services")

    owner_tickets = compose_installed_owner_ticket_store_v3(core=core, services=services,
        graph_db_path=graph_db_path, utc_clock=utc_clock, first_claim_verifier=first_claim_verifier,
        verified_claimant=verified_claimant, owner_sessions=owner_sessions,
        creation_pairing_source=creation_pairing_source, create_owner_schema=create_owner_schema)
    if v2_migration_rpc is not None and v2_migration_rpc_factory is not None:
        raise AuthorityUnavailable("migration handler has two installation sources")
    if v2_migration_rpc_factory is not None:
        if not callable(v2_migration_rpc_factory):
            raise AuthorityUnavailable("migration handler factory is unavailable")
        v2_migration_rpc = v2_migration_rpc_factory(owner_tickets)
    if v2_migration_rpc is not None:
        if (type(v2_migration_rpc) is not MigrationRpcHandlerV2
                or not v2_migration_rpc._services
                or any(type(service) is not AuthorityV2MigrationService
                       or service.core is not core
                       or service.fences is not services.get(namespace)
                       or service._owner_tickets is not owner_tickets
                       for namespace, service in v2_migration_rpc._services.items())):
            raise AuthorityUnavailable("migration handler differs from installed Owner Authority")
    self_readers = dict(self_identity_readers_v2 or {})
    self_services = {}
    if self_readers:
        self_graph = PinnedCurrentSelfIdentityGraphVerifier(graph_db_path)
        for namespace, observer in self_readers.items():
            installed = (installations_v2.get(observer)
                         if type(observer) is tuple and len(observer) == 2 else None)
            roles = [role for (peer, profile, role), mapped in
                     namespace_bindings_v2.items()
                     if (peer, profile) == observer and mapped == namespace]
            if (namespace not in services or installed is None
                    or len(roles) != 1):
                raise AuthorityUnavailable("self identity reader installation differs")
            self_services[namespace] = AuthorityV2SelfIdentityService(
                core=core, fences=services[namespace], owner_tickets=owner_tickets,
                graph=self_graph, namespace_id=roles[0],
                installation_id=installed.installation_id,
                manifest_digest=installed.manifest_digest,
                read_subject="mtls:sha256:" + observer[0],
                holder=installed.administrator_holder,
                administrator_authorizer=administrator_authorizer,
                create=create_self_identity_schema)
    purposes = dict(model_result_source_purposes or {})
    models = dict(v2_model_egress or {})
    observers = dict(model_observers_v2 or {})
    if (any(type(namespace) is not str or namespace not in models
            or type(purpose) is not str
            or purpose not in {"context", "expression", "consolidation", "audit"}
            for namespace, purpose in purposes.items())
            or (purposes and (owner_sessions is None
                             or creation_pairing_source is None))):
        raise AuthorityUnavailable("Owner model result read requires installed dependencies")
    result_graph = (PinnedCurrentModelResultReadGraphVerifier(graph_db_path)
                    if purposes else None)
    result_reads = {}
    for namespace, purpose in purposes.items():
        observer = observers.get(namespace)
        installed = (installations_v2.get(observer)
                     if observer is not None else None)
        model = models[namespace]
        if (installed is None or type(model) is not AuthorityV2ModelEgressService
                or model._fences is not services[namespace]
                or not any(peer == observer[0] and profile == observer[1]
                               and mapped == namespace
                               for (peer, profile, _), mapped in
                               namespace_bindings_v2.items())):
            raise AuthorityUnavailable("model result read observer installation differs")
        result_reads[namespace] = AuthorityV2ModelResultReadService(
            store=model._store, fences=services[namespace],
            owner_tickets=owner_tickets, owner_sessions=owner_sessions,
            graph_verifier=result_graph,
            installation_id=installed.installation_id,
            read_subject="mtls:sha256:" + observer[0],
            holder=installed.administrator_holder,
            source_purpose=purpose)
    worker_readers = dict(worker_result_readers_v2 or {})
    worker_result_reads = {}
    context_reply_result_reads = {}
    natural_generation_output_reads = {}
    natural_generation_content_reads = {}
    natural_review_output_reads = {}
    natural_paid_review_reads = {}

    def trusted_worker_now_utc() -> float:
        reading = utc_clock()
        if (type(reading) is not datetime or reading.tzinfo is None
                or reading.utcoffset() is None
                or reading.utcoffset().total_seconds() != 0):
            raise AuthorityUnavailable("worker result needs an aware UTC clock")
        return reading.timestamp()

    attempts = (AuthorityV2WorkerModelResultAttempts(
        core._db, create=create_worker_result_schema, lock=core._lock)
        if worker_readers else None)
    for namespace, observer in worker_readers.items():
        model = models.get(namespace)
        installed = (installations_v2.get(observer)
                     if type(observer) is tuple and len(observer) == 2 else None)
        model_graph = (model._graph_verifier
                       if type(model) is AuthorityV2ModelEgressService else None)
        if (installed is None or model_graph is None
                or type(model_graph) is not PinnedCurrentModelEgressGraphVerifier
                or model._fences is not services.get(namespace)
                or not any(peer == observer[0] and profile == observer[1]
                               and mapped == namespace
                               for (peer, profile, _), mapped in namespace_bindings_v2.items())):
            raise AuthorityUnavailable("worker result reader installation differs")
        worker_graph = PinnedCurrentWorkerModelResultGraphVerifier(
            graph_db_path, d11_issuer=model_graph._issuer,
            trusted_now_utc=trusted_worker_now_utc)
        reply_graph = PinnedCurrentReplyWorkerModelResultGraphVerifier(
            graph_db_path, d11_issuer=model_graph._issuer,
            trusted_now_utc=trusted_worker_now_utc)
        worker_result_reads[namespace] = AuthorityV2WorkerModelResultReadService(
            store=model._store, fences=services[namespace], attempts=attempts,
            graph_verifier=worker_graph, reply_graph_verifier=reply_graph,
            installation_id=installed.installation_id,
            read_subject="mtls:sha256:" + observer[0],
            holder=installed.administrator_holder)
        context_reply_result_reads[namespace] = AuthorityV2ContextReplyResultReadService(
            store=model._store, fences=services[namespace],
            graph_verifier=PinnedCurrentContextReplyOriginalVerifier(graph_db_path),
            installation_id=installed.installation_id,
            read_subject="mtls:sha256:" + observer[0],
            holder=installed.administrator_holder,
            trusted_now_utc=trusted_worker_now_utc)
        natural_generation_output_reads[namespace] = (
            AuthorityV2NaturalGenerationOutputService(
                store=model._store, fences=services[namespace],
                graph_verifier=PinnedNaturalGenerationOriginalPaidVerifierV2(
                    graph_db_path),
                installation_id=installed.installation_id,
                read_subject="mtls:sha256:" + observer[0],
                holder=installed.administrator_holder,
                trusted_now_utc=trusted_worker_now_utc))
        natural_generation_content_reads[namespace] = (
            AuthorityV2NaturalGenerationContentService(
                original=natural_generation_output_reads[namespace],
                graph=PinnedCurrentNaturalGenerationContentVerifierV2(
                    graph_db_path, natural_history_verifier=model_graph._natural_history),
                trusted_now_utc=trusted_worker_now_utc))
        natural_review_output_reads[namespace] = (
            AuthorityV2NaturalReviewOutputService(
                store=model._store, fences=services[namespace],
                graph_verifier=PinnedNaturalReviewOriginalPaidVerifierV2(
                    graph_db_path),
                installation_id=installed.installation_id,
                read_subject="mtls:sha256:" + observer[0],
                holder=installed.administrator_holder,
                trusted_now_utc=trusted_worker_now_utc))
        natural_paid_review_reads[namespace] = (
            AuthorityV2NaturalPaidReviewService(
                generation=natural_generation_output_reads[namespace],
                review=natural_review_output_reads[namespace],
                graph=PinnedCurrentNaturalPaidReviewVerifierV2(
                    graph_db_path, natural_history_verifier=model_graph._natural_history),
                trusted_now_utc=trusted_worker_now_utc))
    fact_committers = dict(worker_result_fact_committers_v2 or {})
    fact_services = {}
    for namespace, committer in fact_committers.items():
        installed = (installations_v2.get(committer)
                     if type(committer) is tuple and len(committer) == 2 else None)
        if (namespace not in worker_result_reads or installed is None
                or not any(peer == committer[0] and profile == committer[1]
                               and mapped == namespace
                               for (peer, profile, _), mapped in
                               namespace_bindings_v2.items())):
            raise AuthorityUnavailable("C02 fact committer installation differs")
        fact_services[namespace] = AuthorityV2WorkerResultReadFactService(
            worker_reads=worker_result_reads[namespace],
            committer_subject="mtls:sha256:" + committer[0],
            committer_holder=installed.administrator_holder)
    accounting_observers = dict(accounting_observers_v2 or {})
    accounting_services = {}
    for namespace, observer in accounting_observers.items():
        model = models.get(namespace)
        installed = (installations_v2.get(observer)
                     if type(observer) is tuple and len(observer) == 2 else None)
        if (type(namespace) is not str or type(model) is not AuthorityV2ModelEgressService
                or model._fences is not services.get(namespace)
                or installed is None
                or not any(peer == observer[0] and profile == observer[1]
                               and mapped == namespace
                               for (peer, profile, _), mapped in namespace_bindings_v2.items())):
            raise AuthorityUnavailable("D11 accounting observer installation differs")
        accounting_services[namespace] = AuthorityV2AccountingMaintenanceService(
            store=model._store, fences=services[namespace],
            subject="mtls:sha256:" + observer[0],
            holder=installed.administrator_holder)
    observation_verifiers = {}
    for namespace, config in dict(host_onebot_observations_v2 or {}).items():
        if type(config) is not HostOneBotObservationInstallationV2:
            raise AuthorityUnavailable("OneBot observation installation is invalid")
        peer = (config.peer_certificate_sha256, config.profile_id)
        installed = installations_v2.get(peer)
        reverse = (v2_final_handoff_reverse or {}).get(namespace)
        profile = reverse.profile if type(reverse) is ReverseGraphClaimClient else None
        if (namespace not in services or installed is None or profile is None
                or installed.source_id != config.clock_source_ref
                or profile.namespace != namespace
                or profile.profile_id != config.profile_id
                or profile.installation_id != installed.installation_id
                or not any((certificate, profile_id) == peer
                           and mapped == namespace
                           for (certificate, profile_id, _), mapped
                           in namespace_bindings_v2.items())):
            raise AuthorityUnavailable("OneBot observation installation differs")
        observation_verifiers[namespace] = InstalledHostOneBotObservationVerifierV2(
            namespace=namespace,
            peer_certificate_sha256=config.peer_certificate_sha256,
            adapter_ref=config.adapter_ref, account_ref=config.account_ref,
            clock_source_ref=config.clock_source_ref)
    return AuthorityRpcServer(
        core, v2_fences=services, v2_migration_rpc=v2_migration_rpc,
        v2_model_egress=v2_model_egress,
        v2_model_result_reads=result_reads,
        v2_worker_model_result_reads=worker_result_reads,
        v2_context_reply_result_reads=context_reply_result_reads,
        v2_natural_generation_output_reads=natural_generation_output_reads,
        v2_natural_generation_content_reads=natural_generation_content_reads,
        v2_natural_review_output_reads=natural_review_output_reads,
        v2_natural_paid_review_reads=natural_paid_review_reads,
        worker_result_readers_v2=worker_result_readers_v2,
        v2_worker_result_read_facts=fact_services,
        worker_result_fact_committers_v2=fact_committers,
        model_observers_v2=model_observers_v2,
        v2_accounting=accounting_services,
        accounting_observers_v2=accounting_observers,
        v2_owner_tickets=owner_tickets,
        v2_owner_proofs=owner_proofs,
        v2_owner_sessions=owner_sessions,
        v2_owner_pairings=creation_pairing_source,
        v2_self_identity=self_services,
        self_identity_readers_v2=self_readers,
        v2_final_handoff_reverse=v2_final_handoff_reverse,
        v2_final_handoff_issuers=v2_final_handoff_issuers,
        v2_dispatch_verifiers=v2_dispatch_verifiers,
        v2_platform_observation_verifiers=observation_verifiers,
        administrator_authorizer=administrator_authorizer,
        publisher_manifest_verifier=publisher_manifest_verifier,
        installations_v2=installations_v2,
        namespace_bindings_v2=namespace_bindings_v2,
        clock_provider=clock_provider,
    )


__all__ = ("compose_local_owner_authority",)
