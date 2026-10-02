"""Stdlib mTLS JSON-RPC adapter for a separately installed Authority.

Model admission carries a complete candidate request so Authority can verify
its digest and policy. No provider response or result is accepted on this port.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import secrets
import ssl
import threading
import time
from typing import TYPE_CHECKING, Callable

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime.graph_write_attempt import domain_bundle_write_attempt_id_v1
from ..runtime_journal import (
    BudgetConstraint, QuotaOccupancy, RecoveryConstraintFootprint,
    ReservationConstraint,
)
from ..runtime_contracts import InstallationGrantV2, NamespaceBootstrapV2, NamespaceId
from .core import AuthorityServiceCore
from .contract import AuthorityUnavailable, CONTENT_OPERATIONS, ContentPermit, identifier
from .v2_clock import AuthorityClockReadingV2, IngressClockSampleV2
from .v2_contract import (
    ExecutionBindingV1, ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    PlatformObservationV2,
    SCHEMA as AUTHORITY_V2_PROTOCOL, from_wire, to_wire,
)
from .v2_fence_service import AuthorityV2FenceService
from .v2_deletion_graph_read import AuthorityV2DeletionGraphReadService
from .current_erasure_service import CurrentErasureAuthority
from .current_accepted_erasure_read import CurrentAcceptedErasureReadService
from .current_accepted_erasure_wire import accepted_to_wire
from .internal_work_contract import InternalWorkTerminalProofV1, InternalWorkTerminalV2
from .internal_work_service import AuthorityInternalWorkService
from .internal_work_contract import InternalWorkBindingV1
from .internal_work_rpc_wire import from_wire as c04_from_wire, to_wire as c04_to_wire
from .v2_migration_rpc import MigrationRpcHandlerV2
from .v2_accounting_contract import (
    AccountingMaintenanceGrantV1, AccountingMaintenanceRequestV1,
)
from .v2_accounting_service import AuthorityV2AccountingMaintenanceService
from .v2_accounting_wire import (
    from_wire as accounting_from_wire, to_wire as accounting_to_wire,
)
from .v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelAdmissionV2,
    HostObservedModelCompletionV2,
)
from .v2_model_egress_service import AuthorityV2ModelEgressService
from .current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
from .v2_model_egress_wire import from_wire as model_from_wire, to_wire as model_to_wire
from .v2_terminal_c02_recovery_contract import (
    TerminalRecoveryReadRequestV1,
    from_wire as terminal_c02_from_wire, to_wire as terminal_c02_to_wire,
)
from .v2_terminal_c02_recovery_read_service import (
    AuthorityV2TerminalC02RecoveryReadService, TerminalC02RecoveryDeliveryV1,
)
from .v2_model_result_read_contract import ModelResultReadRequestV1
from .v2_model_result_read_service import AuthorityV2ModelResultReadService
from .current_model_result_read_graph_verifier import PinnedCurrentModelResultReadGraphVerifier
from .v2_model_result_read_wire import (
    from_wire as result_from_wire, to_wire as result_to_wire,
)
from .v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, to_wire as worker_result_to_wire,
    from_wire as worker_result_from_wire,
)
from .v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1,
    to_wire as reply_worker_result_to_wire,
    from_wire as reply_worker_result_from_wire,
)
from .v2_worker_model_result_read_service import (
    AuthorityV2WorkerModelResultReadService, WorkerResultDeliveryV1,
)
from .v2_context_reply_result_contract import (
    ContextReplyResultReadRequestV1, to_wire as context_reply_result_to_wire,
    from_wire as context_reply_result_from_wire,
)
from .v2_context_reply_result_service import (
    AuthorityV2ContextReplyResultReadService, ContextReplyResultDeliveryV2,
)
from .v2_natural_generation_output_contract import (
    NaturalGenerationOutputReadRequestV2,
    from_wire as natural_output_from_wire,
    to_wire as natural_output_to_wire,
)
from .v2_natural_generation_output_service import (
    AuthorityV2NaturalGenerationOutputService,
)
from .v2_natural_generation_content_contract import (
    NaturalGenerationContentReadRequestV2,
    from_wire as natural_content_from_wire,
    to_wire as natural_content_to_wire,
)
from .v2_natural_generation_content_service import (
    AuthorityV2NaturalGenerationContentService,
)
from .v2_natural_review_output_contract import (
    NaturalReviewOutputReadRequestV2,
    from_wire as natural_review_output_from_wire,
    to_wire as natural_review_output_to_wire,
)
from .v2_natural_review_output_service import (
    AuthorityV2NaturalReviewOutputService,
)
from .v2_natural_paid_review_contract import (
    NaturalPaidReviewCurrentReadRequestV2,
    from_wire as natural_paid_review_from_wire,
    to_wire as natural_paid_review_to_wire,
)
from .v2_natural_paid_review_service import AuthorityV2NaturalPaidReviewService
from .v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV1, WorkerResultReadFactRequestV2,
    from_wire as worker_fact_from_wire,
    to_wire as worker_fact_to_wire,
)
from .v2_worker_result_read_fact_service import AuthorityV2WorkerResultReadFactService
from .current_worker_model_result_graph_verifier import (
    PinnedCurrentWorkerModelResultGraphVerifier,
    PinnedTerminalRecoveryGraphVerifierV1,
)
from .current_reply_worker_model_result_graph_verifier import (
    PinnedCurrentReplyWorkerModelResultGraphVerifier,
)
from .v2_execution_bridge import (
    AuthorityV2ExecutionBridge, HandoffStartV2,
    PlatformObservationVerifierUnavailable,
)
from .reverse_handoff import ReverseGraphClaimClient
from .final_handoff_pairing import FinalHandoffPairingV1
from .v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerClaimTicketV1, OwnerGraphCommitProofV1,
    OwnerPrincipalV1,
    from_wire as owner_from_wire, to_wire as owner_to_wire,
)
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore, OwnerAuthorizationBarrier
from .v2_self_identity_contract import (
    SelfIdentityCurrentRequestV1, SelfIdentityMutationV1,
    from_wire as self_identity_from_wire, to_wire as self_identity_to_wire,
)
from .v2_self_identity_service import AuthorityV2SelfIdentityService
from .current_self_identity_graph_verifier import PinnedCurrentSelfIdentityGraphVerifier
from .v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
    OwnerProofChallengeV1, OwnerProofRequestV1,
    from_wire as proof_from_wire, to_wire as proof_to_wire,
)
from .v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginChallengeV1,
    OwnerSessionLoginRequestV1, from_wire as session_from_wire,
    to_wire as session_to_wire,
)
from ..graph_coordinator import namespace_ref

if TYPE_CHECKING:
    from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource


_MAX_SESSIONS = 256
_MAX_INFLIGHT_DISPATCHES = 32
_SESSION_TTL_SECONDS = 30.0
AUTHORITY_PROTOCOL = "sylanne3.authority.v1"
_ENROLLMENT_CAPABILITIES = ("enrollment",)
_V2_REMOTE_CONTENT_OPERATIONS = CONTENT_OPERATIONS - {"dispatch", "model_egress"}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


@dataclass(frozen=True)
class MtlsPeerCredential:
    """Opaque server credential derived from a verified client certificate."""

    certificate_sha256: str

    def __post_init__(self) -> None:
        if (not isinstance(self.certificate_sha256, str)
                or len(self.certificate_sha256) != 64
                or any(item not in "0123456789abcdef" for item in self.certificate_sha256)):
            raise ValueError("invalid mTLS peer credential")


@dataclass(slots=True)
class _DeferredWorkerDelivery:
    payload: dict[str, object]
    service: AuthorityV2WorkerModelResultReadService | AuthorityV2TerminalC02RecoveryReadService | AuthorityV2ContextReplyResultReadService
    credential: MtlsPeerCredential
    delivery: WorkerResultDeliveryV1 | TerminalC02RecoveryDeliveryV1 | ContextReplyResultDeliveryV2

    def finish(self):
        return self.service.finish_delivery(
            credential=self.credential, delivery=self.delivery)

    def abandon(self) -> None:
        self.service.abandon_delivery(delivery=self.delivery)


@dataclass(frozen=True)
class AdministratorInstallationV2:
    """Administrator-installed identity and trusted package for one mTLS profile."""

    installation_id: str
    administrator_holder: str
    publisher_policy_ref: str
    service_capability_version: str
    manifest_digest: str
    source_id: str | None = None
    max_utc_error_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.source_id is None and self.max_utc_error_seconds is None:
            return
        if (type(self.source_id) is not str or not self.source_id.strip()
                or type(self.max_utc_error_seconds) not in {int, float}
                or not math.isfinite(self.max_utc_error_seconds)
                or self.max_utc_error_seconds <= 0):
            raise ValueError("administrator clock registration is invalid")


@dataclass(frozen=True)
class AuthorityServerTlsConfig:
    certificate: str
    private_key: str
    client_trust_root: str
    timeout_seconds: float = 5.0
    max_message_bytes: int = 65_536

    def ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certificate, self.private_key)
        context.load_verify_locations(self.client_trust_root)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


@dataclass(frozen=True)
class _WireRequest:
    profile_id: str
    plugin_name: str
    host_api_version: str
    manifest_sha256: str
    protocol: str = AUTHORITY_PROTOCOL

    @classmethod
    def from_value(cls, value: object) -> "_WireRequest":
        if not isinstance(value, dict) or set(value) != {
            "protocol", "profile_id", "plugin_name", "host_api_version", "manifest_sha256"
        }:
            raise RuntimeError("authority request unavailable")
        if (value["protocol"] not in (AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL)
                or value["plugin_name"] != "astrbot_plugin_sylanne"
                or value["host_api_version"] != "4.28.1"):
            raise RuntimeError("authority request unavailable")
        profile_id = value["profile_id"]
        manifest = value["manifest_sha256"]
        if (not isinstance(profile_id, str) or not profile_id
                or not isinstance(manifest, str) or len(manifest) != 64
                or any(char not in "0123456789abcdef" for char in manifest)):
            raise RuntimeError("authority request unavailable")
        return cls(profile_id, value["plugin_name"], value["host_api_version"],
                   manifest, value["protocol"])

    def payload(self) -> dict[str, str]:
        return {
            "protocol": self.protocol,
            "profile_id": self.profile_id,
            "plugin_name": self.plugin_name,
            "host_api_version": self.host_api_version,
            "manifest_sha256": self.manifest_sha256,
        }


class AuthorityRpcServer:
    """RPC handler; deployment owns server TLS material and authorization policy."""

    def __init__(
        self,
        core: AuthorityServiceCore,
        *,
        administrator_authorizer: Callable[[object, str, str, str | None], bool],
        publisher_manifest_verifier: Callable[[str, str, str, str], bool],
        v2_fences: AuthorityV2FenceService | Mapping[str, AuthorityV2FenceService] | None = None,
        v2_migration_rpc: MigrationRpcHandlerV2 | None = None,
        v2_model_egress: Mapping[str, AuthorityV2ModelEgressService] | None = None,
        v2_internal_work_services: Mapping[str, AuthorityInternalWorkService] | None = None,
        v2_model_result_reads: Mapping[str, AuthorityV2ModelResultReadService] | None = None,
        v2_worker_model_result_reads: Mapping[str, AuthorityV2WorkerModelResultReadService] | None = None,
        v2_context_reply_result_reads: Mapping[str, AuthorityV2ContextReplyResultReadService] | None = None,
        v2_natural_generation_output_reads: Mapping[str, AuthorityV2NaturalGenerationOutputService] | None = None,
        v2_natural_generation_content_reads: Mapping[str, AuthorityV2NaturalGenerationContentService] | None = None,
        v2_natural_review_output_reads: Mapping[str, AuthorityV2NaturalReviewOutputService] | None = None,
        v2_natural_paid_review_reads: Mapping[str, AuthorityV2NaturalPaidReviewService] | None = None,
        worker_result_readers_v2: Mapping[str, tuple[str, str]] | None = None,
        v2_terminal_c02_recovery_reads: Mapping[str, AuthorityV2TerminalC02RecoveryReadService] | None = None,
        terminal_c02_recovery_readers_v2: Mapping[str, tuple[str, str]] | None = None,
        v2_worker_result_read_facts: Mapping[str, AuthorityV2WorkerResultReadFactService] | None = None,
        worker_result_fact_committers_v2: Mapping[str, tuple[str, str]] | None = None,
        model_observers_v2: Mapping[str, tuple[str, str]] | None = None,
        v2_accounting: Mapping[str, AuthorityV2AccountingMaintenanceService] | None = None,
        accounting_observers_v2: Mapping[str, tuple[str, str]] | None = None,
        v2_owner_tickets: AuthorityV2OwnerTicketStore | None = None,
        v2_owner_proofs: AuthorityV2OwnerProofStore | None = None,
        v2_owner_sessions: AuthorityV2OwnerSessionStore | None = None,
        v2_owner_pairings: AuthorityOwnerPairingSource | None = None,
        v2_self_identity: Mapping[str, AuthorityV2SelfIdentityService] | None = None,
        self_identity_readers_v2: Mapping[str, tuple[str, str]] | None = None,
        v2_final_handoff_authorizers: Mapping[str, Callable] | None = None,
        v2_final_handoff_issuers: Mapping[str, str] | None = None,
        v2_final_handoff_reverse: Mapping[str, ReverseGraphClaimClient] | None = None,
        v2_platform_observation_verifiers: Mapping[str, Callable] | None = None,
        v2_dispatch_verifiers: Mapping[str, Callable] | None = None,
        installations_v2: Mapping[tuple[str, str], AdministratorInstallationV2] | None = None,
        namespace_bindings_v2: Mapping[tuple[str, str, NamespaceId], str] | None = None,
        clock_provider: Callable[[], AuthorityClockReadingV2] | None = None,
        max_inflight_dispatches: int = _MAX_INFLIGHT_DISPATCHES,
    ) -> None:
        if not isinstance(core, AuthorityServiceCore):
            raise TypeError("AuthorityServiceCore is required")
        if not callable(administrator_authorizer) or not callable(publisher_manifest_verifier):
            raise TypeError("server-side authorizer and publisher verifier are required")
        if type(max_inflight_dispatches) is not int or max_inflight_dispatches < 1:
            raise ValueError("authority dispatch capacity is invalid")
        if v2_fences is None:
            services = {}
        elif type(v2_fences) is AuthorityV2FenceService:
            services = {v2_fences.namespace: v2_fences}
        elif isinstance(v2_fences, Mapping):
            services = dict(v2_fences)
        else:
            raise TypeError("AuthorityV2FenceService mapping is required")
        if any(type(namespace) is not str
               or type(service) is not AuthorityV2FenceService
               or service.namespace != namespace or service.core is not core
               for namespace, service in services.items()):
            raise TypeError("v2 fence services must match their namespace and Authority core")
        self._core = core
        self._administrator_authorizer = administrator_authorizer
        self._publisher_manifest_verifier = publisher_manifest_verifier
        self._v2_fences = services
        if v2_migration_rpc is not None:
            if (type(v2_migration_rpc) is not MigrationRpcHandlerV2
                    or any(namespace not in services
                           or migration.core is not core
                           or migration.fences is not services[namespace]
                           for namespace, migration in v2_migration_rpc._services.items())):
                raise TypeError("migration RPC must use installed Authority services")
        self._v2_migration_rpc = v2_migration_rpc
        if v2_model_egress is not None and not isinstance(v2_model_egress, Mapping):
            raise TypeError("Authority model egress service mapping required")
        model_services = dict(v2_model_egress or {})
        if any(type(namespace) is not str
               or type(service) is not AuthorityV2ModelEgressService
               or namespace not in services or service._fences is not services[namespace]
               or service._store._db is not core._db
               or service._graph_verifier is None or service._admin_model_policy is None
               for namespace, service in model_services.items()):
            raise TypeError("model egress services require installed Authority dependencies")
        self._v2_model_egress = model_services
        internal_work = dict(v2_internal_work_services or {})
        if any(type(namespace) is not str or namespace not in services
               or type(service) is not AuthorityInternalWorkService
               or service.journal is not services[namespace].execution
               or service.installed_algorithm_id !=
                  "d06.association_activation.v2"
               or not service.installed_runtime_verified
               or not callable(service._core_head_verifier)
               for namespace, service in internal_work.items()):
            raise TypeError("C04 service needs the installed journal and formal build")
        self._v2_internal_work_services = internal_work
        self._v2_internal_work_executors = {}
        self._v3_internal_work_services = {}
        self._d04_numeric_services_v3 = {}
        self._d04_series_services_v1 = {}
        self._d11_life_services_v1 = {}
        self._v3_internal_work_executors = {}
        if (v2_owner_tickets is not None
                and (type(v2_owner_tickets) is not AuthorityV2OwnerTicketStore
                     or v2_owner_tickets._core is not core)):
            raise TypeError("v2 owner tickets must use the same Authority core")
        self._v2_owner_tickets = v2_owner_tickets
        self._v2_deletion_graph_reads = (
            {namespace: AuthorityV2DeletionGraphReadService(
                fence_service=service, owner_tickets=v2_owner_tickets)
             for namespace, service in services.items()}
            if v2_owner_tickets is not None else {})
        self._current_erasure_prepares = {}
        self._current_accepted_erasure_reads = {}
        if (v2_owner_proofs is not None
                and (type(v2_owner_proofs) is not AuthorityV2OwnerProofStore
                     or v2_owner_proofs._core is not core)):
            raise TypeError("v2 Owner proofs must use the same Authority core")
        self._v2_owner_proofs = v2_owner_proofs
        if (v2_owner_sessions is not None
                and (type(v2_owner_sessions) is not AuthorityV2OwnerSessionStore
                     or v2_owner_sessions._core is not core)):
            raise TypeError("v2 Owner sessions must use the same Authority core")
        self._v2_owner_sessions = v2_owner_sessions
        from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
        if (v2_owner_pairings is not None
                and (type(v2_owner_pairings) is not AuthorityOwnerPairingSource
                     or v2_owner_pairings._core is not core)):
            raise TypeError("v2 Owner pairings must use the same Authority core")
        self._v2_owner_pairings = v2_owner_pairings
        handoff_authorizers = dict(v2_final_handoff_authorizers or {})
        handoff_issuers = dict(v2_final_handoff_issuers or {})
        reverse_handoffs = dict(v2_final_handoff_reverse or {})
        if (set(reverse_handoffs) & set(handoff_authorizers)
                or any(type(namespace) is not str or namespace not in services
                       or type(client) is not ReverseGraphClaimClient
                       or client.profile.namespace != namespace
                       for namespace, client in reverse_handoffs.items())):
            raise TypeError("reverse handoff must be administrator-installed per namespace")
        handoff_authorizers.update({namespace: client.claim
                                    for namespace, client in reverse_handoffs.items()})
        if any(namespace not in services or not callable(callback)
               for namespace, callback in handoff_authorizers.items()):
            raise TypeError("v2 final handoff authorizers must be installed per namespace")
        if (set(handoff_issuers) != set(handoff_authorizers)
                or any(type(issuer) is not str or not issuer
                       for issuer in handoff_issuers.values())):
            raise TypeError("v2 graph claim issuers must match installed authorizers")
        observation_verifiers = dict(v2_platform_observation_verifiers or {})
        if any(namespace not in services or not callable(verifier)
               for namespace, verifier in observation_verifiers.items()):
            raise TypeError("V2 platform observation verifiers must be installed per namespace")
        dispatch_verifiers = dict(v2_dispatch_verifiers or {})
        if any(namespace not in services or not callable(verifier)
               or services[namespace]._v2_dispatch_verifier is not verifier
               for namespace, verifier in dispatch_verifiers.items()):
            raise TypeError("V2 dispatch verifiers must match installed fence services")
        self._v2_execution = {
            namespace: AuthorityV2ExecutionBridge(
                core=core, fences=service.fences, journal=service.execution,
                namespace=namespace, deletion=service.deletion,
                final_handoff_authorizer=handoff_authorizers.get(namespace),
                final_handoff_issuer_id=handoff_issuers.get(namespace),
                observation_verifier=observation_verifiers.get(namespace),
                v2_dispatch_verifier=dispatch_verifiers.get(namespace),
                owner_tickets=v2_owner_tickets,
                owner_installation_id=(reverse_handoffs[namespace].profile.installation_id
                                       if namespace in reverse_handoffs else None),
            ) for namespace, service in services.items()
        }
        installed = dict(installations_v2 or {})
        if any(type(key) is not tuple or len(key) != 2
               or type(key[0]) is not str or len(key[0]) != 64
               or any(ch not in "0123456789abcdef" for ch in key[0])
               or type(key[1]) is not str or not key[1]
               or type(value) is not AdministratorInstallationV2
               for key, value in installed.items()):
            raise TypeError("administrator v2 installations are invalid")
        self._installations_v2 = installed
        if clock_provider is not None and not callable(clock_provider):
            raise TypeError("administrator clock provider must be callable")
        self._clock_provider = clock_provider
        bindings = dict(namespace_bindings_v2 or {})
        if any(type(key) is not tuple or len(key) != 3
               or (key[0], key[1]) not in installed
               or type(key[2]) is not NamespaceId
               or type(namespace) is not str or namespace not in services
               for key, namespace in bindings.items()):
            raise TypeError("administrator v2 namespace bindings are invalid")
        namespace_to_role = {}
        role_to_namespace = {}
        for (_, _, role), namespace in bindings.items():
            if (namespace_to_role.get(namespace, role) != role
                    or role_to_namespace.get(role, namespace) != namespace):
                raise ValueError("administrator v2 namespace bindings must be one-to-one")
            namespace_to_role[namespace] = role
            role_to_namespace[role] = namespace
        self._namespace_bindings_v2 = bindings
        self._final_handoff_reverse_v2 = reverse_handoffs
        self._final_handoff_issuers_v2 = handoff_issuers
        if any(not any(
                (peer, profile) in installed
                and profile == client.profile.profile_id
                and installed[(peer, profile)].installation_id ==
                    client.profile.installation_id
                and bound_namespace == namespace
                for (peer, profile, _role), bound_namespace in bindings.items())
               for namespace, client in reverse_handoffs.items()):
            raise TypeError("reverse handoff installation or namespace is not bound")
        self_identity_services = dict(v2_self_identity or {})
        self_identity_readers = dict(self_identity_readers_v2 or {})
        if (set(self_identity_services) != set(self_identity_readers)
                or any(type(namespace) is not str or namespace not in services
                       or type(service) is not AuthorityV2SelfIdentityService
                       or service._core is not core
                       or service._fences is not services[namespace]
                       or service._tickets is not v2_owner_tickets
                       or type(service._graph) is not PinnedCurrentSelfIdentityGraphVerifier
                       or type(service._namespace_id) is not NamespaceId
                       or type(self_identity_readers[namespace]) is not tuple
                       or len(self_identity_readers[namespace]) != 2
                       or self_identity_readers[namespace] not in installed
                       or not any(peer == self_identity_readers[namespace][0]
                                      and profile == self_identity_readers[namespace][1]
                                      and role == service._namespace_id
                                      and mapped == namespace
                                      for (peer, profile, _), mapped in bindings.items())
                       or (service._read_subject, service._installation_id,
                           service._manifest_digest, service._holder) != (
                               "mtls:sha256:" + self_identity_readers[namespace][0],
                               installed[self_identity_readers[namespace]].installation_id,
                               installed[self_identity_readers[namespace]].manifest_digest,
                               installed[self_identity_readers[namespace]].administrator_holder)
                       for namespace, service in self_identity_services.items())):
            raise TypeError("self identity requires an installed namespace-bound reader")
        self._v2_self_identity = self_identity_services
        self._self_identity_readers_v2 = self_identity_readers
        observers = dict(model_observers_v2 or {})
        if any(namespace not in model_services
               or type(observer) is not tuple or len(observer) != 2
               or observer not in installed
               or not any(peer == observer[0] and profile == observer[1]
                              and mapped == namespace
                              for (peer, profile, _), mapped in bindings.items())
               for namespace, observer in observers.items()):
            raise TypeError("model observers require an installed namespace-bound peer")
        self._model_observers_v2 = observers
        if (v2_model_result_reads is not None
                and not isinstance(v2_model_result_reads, Mapping)):
            raise TypeError("Authority model result read mapping required")
        result_reads = dict(v2_model_result_reads or {})
        if any(
                type(namespace) is not str or namespace not in model_services
                or type(service) is not AuthorityV2ModelResultReadService
                or v2_owner_tickets is None or v2_owner_sessions is None
                or v2_owner_pairings is None
                or service._store is not model_services[namespace]._store
                or service._fences is not services[namespace]
                or service._tickets is not v2_owner_tickets
                or service._sessions is not v2_owner_sessions
                or service._sessions._current_pairing_source is not v2_owner_pairings
                or type(service._graph) is not PinnedCurrentModelResultReadGraphVerifier
                or observers.get(namespace) is None
                or (service._read_subject, service._installation_id, service._holder) != (
                    "mtls:sha256:" + observers[namespace][0],
                    installed[observers[namespace]].installation_id,
                    installed[observers[namespace]].administrator_holder)
                for namespace, service in result_reads.items()):
            raise TypeError("result reads require the installed model and Owner composition")
        self._v2_model_result_reads = result_reads
        worker_reads = dict(v2_worker_model_result_reads or {})
        worker_readers = dict(worker_result_readers_v2 or {})
        if (set(worker_reads) != set(worker_readers)
                  or any(type(namespace) is not str or namespace not in model_services
                       or type(service) is not AuthorityV2WorkerModelResultReadService
                       or service._store is not model_services[namespace]._store
                       or service._fences is not services[namespace]
                         or type(service._graph) is not PinnedCurrentWorkerModelResultGraphVerifier
                         or (service._reply_graph is not None and
                             type(service._reply_graph) is not
                             PinnedCurrentReplyWorkerModelResultGraphVerifier)
                       or type(model_services[namespace]._graph_verifier)
                          is not PinnedCurrentModelEgressGraphVerifier
                       or service._graph._path != model_services[namespace]._graph_verifier._path
                       or service._graph._issuer is not model_services[namespace]._graph_verifier._issuer
                       or type(worker_readers[namespace]) is not tuple
                       or len(worker_readers[namespace]) != 2
                       or worker_readers[namespace] not in installed
                       or not any(peer == worker_readers[namespace][0]
                                      and profile == worker_readers[namespace][1]
                                      and mapped == namespace
                                      for (peer, profile, _), mapped in bindings.items())
                       or (service._read_subject, service._installation_id,
                           service._holder) != (
                               "mtls:sha256:" + worker_readers[namespace][0],
                               installed[worker_readers[namespace]].installation_id,
                               installed[worker_readers[namespace]].administrator_holder)
                       for namespace, service in worker_reads.items())):
            raise TypeError("worker results require installed original model and reader")
        self._v2_worker_model_result_reads = worker_reads
        self._worker_result_readers_v2 = worker_readers
        context_reply_reads = dict(v2_context_reply_result_reads or {})
        if (not set(context_reply_reads) <= set(worker_readers)
                or any(type(service) is not AuthorityV2ContextReplyResultReadService
                       or namespace not in model_services
                       or service._store is not model_services[namespace]._store
                       or service._fences is not services[namespace]
                       or service._graph._path != model_services[namespace]._graph_verifier._path
                       or (service._read_subject, service._installation_id,
                           service._holder) != (
                               "mtls:sha256:" + worker_readers[namespace][0],
                               installed[worker_readers[namespace]].installation_id,
                               installed[worker_readers[namespace]].administrator_holder)
                       for namespace, service in context_reply_reads.items())):
            raise TypeError("context reply result needs installed original model reader")
        self._v2_context_reply_result_reads = context_reply_reads
        natural_output_reads = dict(v2_natural_generation_output_reads or {})
        if (not set(natural_output_reads) <= set(worker_readers)
                or any(type(service) is not AuthorityV2NaturalGenerationOutputService
                       or namespace not in model_services
                       or service._store is not model_services[namespace]._store
                       or service._fences is not services[namespace]
                       or service._graph._path != model_services[namespace]._graph_verifier._path
                       or (service._read_subject, service._installation_id,
                           service._holder) != (
                               "mtls:sha256:" + worker_readers[namespace][0],
                               installed[worker_readers[namespace]].installation_id,
                               installed[worker_readers[namespace]].administrator_holder)
                       for namespace, service in natural_output_reads.items())):
            raise TypeError("natural output needs installed original model reader")
        self._v2_natural_generation_output_reads = natural_output_reads
        self._d04_appraisal_reads_v3 = {}
        self._d07_cognition_reads_v1 = {}
        self._contact_model_reads_v1 = {}
        self._contact_model_reads_v2 = {}
        self._internal_life_model_reads_v2 = {}
        self._life_numeric_model_reads_v1 = {}
        natural_content_reads = dict(v2_natural_generation_content_reads or {})
        if (not set(natural_content_reads) <= set(natural_output_reads)
                or any(type(service) is not AuthorityV2NaturalGenerationContentService
                       or service._original is not natural_output_reads[namespace]
                       for namespace, service in natural_content_reads.items())):
            raise TypeError("natural content needs paired original output reader")
        self._v2_natural_generation_content_reads = natural_content_reads
        review_output_reads = dict(v2_natural_review_output_reads or {})
        if (not set(review_output_reads) <= set(worker_readers)
                or any(type(service) is not AuthorityV2NaturalReviewOutputService
                       or namespace not in model_services
                       or service._store is not model_services[namespace]._store
                       or service._fences is not services[namespace]
                       or service._graph._path != model_services[namespace]._graph_verifier._path
                       or (service._read_subject, service._installation_id,
                           service._holder) != (
                               "mtls:sha256:" + worker_readers[namespace][0],
                               installed[worker_readers[namespace]].installation_id,
                               installed[worker_readers[namespace]].administrator_holder)
                       for namespace, service in review_output_reads.items())):
            raise TypeError("natural review output needs installed original reader")
        self._v2_natural_review_output_reads = review_output_reads
        paid_review_reads = dict(v2_natural_paid_review_reads or {})
        if (not set(paid_review_reads) <=
                (set(review_output_reads) & set(natural_output_reads))
                or any(type(service) is not AuthorityV2NaturalPaidReviewService
                       or service._generation is not natural_output_reads[namespace]
                       or service._review is not review_output_reads[namespace]
                       for namespace, service in paid_review_reads.items())):
            raise TypeError("natural paid review needs paired original readers")
        self._v2_natural_paid_review_reads = paid_review_reads
        recovery_reads = dict(v2_terminal_c02_recovery_reads or {})
        recovery_readers = dict(terminal_c02_recovery_readers_v2 or {})
        if (set(recovery_reads) != set(recovery_readers)
                or any(type(namespace) is not str or namespace not in model_services
                       or type(service) is not AuthorityV2TerminalC02RecoveryReadService
                       or service._store is not model_services[namespace]._store
                       or service._fences is not services[namespace]
                       or type(service._graph) is not PinnedTerminalRecoveryGraphVerifierV1
                       or type(model_services[namespace]._graph_verifier)
                          is not PinnedCurrentModelEgressGraphVerifier
                       or service._graph._path != model_services[namespace]._graph_verifier._path
                       or service._graph._issuer is not model_services[namespace]._graph_verifier._issuer
                       or type(recovery_readers[namespace]) is not tuple
                       or len(recovery_readers[namespace]) != 2
                       or recovery_readers[namespace] not in installed
                       or not any(peer == recovery_readers[namespace][0]
                                      and profile == recovery_readers[namespace][1]
                                      and mapped == namespace
                                      for (peer, profile, _), mapped in bindings.items())
                       or (service._read_subject, service._installation_id,
                           service._holder) != (
                               "mtls:sha256:" + recovery_readers[namespace][0],
                               installed[recovery_readers[namespace]].installation_id,
                               installed[recovery_readers[namespace]].administrator_holder)
                       for namespace, service in recovery_reads.items())):
            raise TypeError("terminal C02 recovery requires installed current graph reader")
        self._v2_terminal_c02_recovery_reads = recovery_reads
        self._terminal_c02_recovery_readers_v2 = recovery_readers
        fact_services = dict(v2_worker_result_read_facts or {})
        fact_committers = dict(worker_result_fact_committers_v2 or {})
        if (set(fact_services) != set(fact_committers)
                or any(type(namespace) is not str
                       or namespace not in worker_reads
                       or type(service) is not AuthorityV2WorkerResultReadFactService
                       or service._reads is not worker_reads[namespace]
                       or type(fact_committers[namespace]) is not tuple
                       or len(fact_committers[namespace]) != 2
                       or fact_committers[namespace] not in installed
                       or not any(peer == fact_committers[namespace][0]
                                      and profile == fact_committers[namespace][1]
                                      and mapped == namespace
                                      for (peer, profile, _), mapped in bindings.items())
                       or (service._committer_subject, service._committer_holder) != (
                           "mtls:sha256:" + fact_committers[namespace][0],
                           installed[fact_committers[namespace]].administrator_holder)
                       for namespace, service in fact_services.items())):
            raise TypeError("worker read fact requires designated installed C02 committer")
        self._v2_worker_result_read_facts = fact_services
        self._worker_result_fact_committers_v2 = fact_committers
        if v2_accounting is not None and not isinstance(v2_accounting, Mapping):
            raise TypeError("Authority accounting service mapping required")
        accounting_services = dict(v2_accounting or {})
        accounting_observers = dict(accounting_observers_v2 or {})
        if (set(accounting_services) != set(accounting_observers)
                or any(type(namespace) is not str or namespace not in model_services
                       or type(service) is not AuthorityV2AccountingMaintenanceService
                       or service._store is not model_services[namespace]._store
                       or service._fences is not services[namespace]
                       or type(accounting_observers[namespace]) is not tuple
                       or len(accounting_observers[namespace]) != 2
                       or accounting_observers[namespace] not in installed
                       or not any(peer == accounting_observers[namespace][0]
                                      and profile == accounting_observers[namespace][1]
                                      and mapped == namespace
                                      for (peer, profile, _), mapped in bindings.items())
                       or (service._subject, service._holder) != (
                           "mtls:sha256:" + accounting_observers[namespace][0],
                           installed[accounting_observers[namespace]].administrator_holder)
                       for namespace, service in accounting_services.items())):
            raise TypeError("accounting requires installed designated observer and original model")
        self._v2_accounting = accounting_services
        self._accounting_observers_v2 = accounting_observers
        self._sessions: dict[str, tuple[float, str, str]] = {}
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="authority-rpc")
        self._worker_slots = threading.BoundedSemaphore(max_inflight_dispatches)
        self._worker_lock = threading.Lock()
        self._worker_close_lock = asyncio.Lock()
        self._worker_closed = False
        self._worker_shutdown_task: asyncio.Task[None] | None = None
        self.c09_restart_requested_v1 = asyncio.Event()
        self._first_owner_slot_v1 = threading.BoundedSemaphore(1)
        self._first_owner_tasks_v1 = set()
        self._first_owner_closing_v1 = False


    @staticmethod
    def error_payload(exc: BaseException) -> dict[str, object]:
        """Wire failures deliberately reveal no content, paths, or authorization detail."""
        return {"ok": False, "error": "authority_unavailable"}

    @staticmethod
    def _binding(channel_binding: bytes, request: _WireRequest) -> str:
        if not isinstance(channel_binding, bytes) or not channel_binding:
            raise RuntimeError("authority channel binding unavailable")
        digest = hashlib.sha256(_canonical(request.payload())).digest()
        return hashlib.sha256(channel_binding + digest).hexdigest()

    def _authorize(self, credential: object, request: _WireRequest) -> None:
        try:
            allowed = self._administrator_authorizer(
                credential, "pair", "authority:enrollment", request.profile_id
            )
            trusted = self._publisher_manifest_verifier(
                request.profile_id, request.plugin_name, request.host_api_version,
                request.manifest_sha256,
            )
        except Exception as exc:
            raise RuntimeError("authority unavailable") from exc
        if allowed is not True or trusted is not True:
            raise RuntimeError("authority unavailable")

    def _authority_id(self) -> str:
        with self._core._lock:
            if self._core._db is None:
                raise RuntimeError("authority unavailable")
            return self._core._id(self._core._db)

    def _prune_sessions(self) -> None:
        cutoff = time.monotonic() - _SESSION_TTL_SECONDS
        for binding, (created, _, _) in tuple(self._sessions.items()):
            if created < cutoff:
                self._sessions.pop(binding, None)
        while len(self._sessions) > _MAX_SESSIONS:
            self._sessions.pop(next(iter(self._sessions)))

    def _paired_session(self, binding: str, peer: str, request: _WireRequest) -> None:
        self._prune_sessions()
        session = self._sessions.get(binding)
        expected_digest = hashlib.sha256(_canonical(request.payload())).hexdigest()
        if session is None or session[1] != peer or session[2] != expected_digest:
            raise RuntimeError("authority binding unavailable")

    @staticmethod
    def _proof_payload(proof) -> dict[str, object]:
        return {
            "authority_id": proof.authority_id,
            "namespace": proof.namespace,
            "holder": proof.holder,
            "generation": proof.generation,
            "phase": proof.phase,
            "operation_id": proof.operation_id,
        }

    @staticmethod
    def _anchor_payload(anchor) -> dict[str, object]:
        return {
            "authority_id": anchor.authority_id,
            "namespace": anchor.namespace,
            "activation_generation": anchor.activation_generation,
            "deletion_journal_id": anchor.deletion_journal_id,
            "deletion_seq": anchor.deletion_seq,
            "deletion_digest": anchor.deletion_digest,
            "execution_journal_id": anchor.execution_journal_id,
            "execution_seq": anchor.execution_seq,
            "execution_digest": anchor.execution_digest,
            "revocation_epoch": anchor.revocation_epoch,
            "proof": anchor.proof,
        }

    @staticmethod
    def _permit_payload(permit: ContentPermit) -> dict[str, object]:
        return {
            "token": permit.token,
            "namespace": permit.namespace,
            "holder": permit.holder,
            "generation": permit.generation,
            "operation": permit.operation,
        }

    @staticmethod
    def _namespace_command(command: object) -> str:
        if not isinstance(command, dict) or set(command) != {"namespace"}:
            raise RuntimeError("authority unavailable")
        return identifier(command["namespace"], "namespace")

    @staticmethod
    def _content_check_command(command: object) -> tuple[str, str, int, str]:
        if not isinstance(command, dict) or set(command) != {
            "namespace", "holder", "generation", "operation"
        }:
            raise RuntimeError("authority unavailable")
        namespace = identifier(command["namespace"], "namespace")
        holder = identifier(command["holder"], "holder")
        generation = command["generation"]
        operation = command["operation"]
        if type(generation) is not int or generation < 0 or not isinstance(operation, str):
            raise RuntimeError("authority unavailable")
        return namespace, holder, generation, operation

    @staticmethod
    def _anchor_from_command(command: object) -> RestoreAnchor:
        if not isinstance(command, dict) or set(command) != {"anchor"}:
            raise RuntimeError("authority unavailable")
        payload = command["anchor"]
        if not isinstance(payload, dict) or set(payload) != {
            "authority_id", "namespace", "activation_generation",
            "deletion_journal_id", "deletion_seq", "deletion_digest",
            "execution_journal_id", "execution_seq", "execution_digest",
            "revocation_epoch", "proof",
        }:
            raise RuntimeError("authority unavailable")
        return RestoreAnchor(
            payload["authority_id"], payload["namespace"],
            payload["activation_generation"], payload["deletion_journal_id"],
            payload["deletion_seq"], payload["deletion_digest"],
            payload["execution_journal_id"], payload["execution_seq"],
            payload["execution_digest"], payload["revocation_epoch"], payload["proof"],
        )

    def _content_command(self, method: str, credential: MtlsPeerCredential,
                         command: object) -> dict[str, object]:
        try:
            if method == "check":
                namespace, holder, generation, operation = self._content_check_command(command)
                return self._proof_payload(self._core.check(
                    credential, namespace=namespace, holder=holder,
                    generation=generation, operation=operation,
                ))
            if method == "current":
                return self._proof_payload(self._core.current(
                    credential, self._namespace_command(command)))
            if method == "current_anchor":
                return self._anchor_payload(self._core.current_anchor(
                    credential, self._namespace_command(command)))
            if method == "verify_execution_chain":
                # No caller-supplied head is accepted. Core re-runs its injected,
                # service-owned execution verifier against the currently stored head.
                return {"verified": True, **self._anchor_payload(self._core.current_anchor(
                    credential, self._namespace_command(command)))}
            if method == "begin_content_operation":
                namespace, holder, generation, operation = self._content_check_command(command)
                permit = self._core.begin_content_operation(
                    credential, namespace=namespace, holder=holder,
                    generation=generation, operation=operation,
                )
                return self._permit_payload(permit)
            if method == "end_content_operation":
                if not isinstance(command, dict) or set(command) != {"permit"}:
                    raise RuntimeError("authority unavailable")
                payload = command["permit"]
                if not isinstance(payload, dict) or set(payload) != {
                    "token", "namespace", "holder", "generation", "operation"
                }:
                    raise RuntimeError("authority unavailable")
                token = identifier(payload["token"], "token")
                namespace = identifier(payload["namespace"], "namespace")
                holder = identifier(payload["holder"], "holder")
                generation = payload["generation"]
                operation = payload["operation"]
                if type(generation) is not int or generation < 0 or not isinstance(operation, str):
                    raise RuntimeError("authority unavailable")
                self._core.end_content_operation(
                    credential, ContentPermit(token, namespace, holder, generation, operation)
                )
                return {"ended": True}
            if method == "verify_current":
                return {"verified": self._core.verify_current(
                    credential, self._anchor_from_command(command)
                )}
        except (AuthorityUnavailable, TypeError, ValueError) as exc:
            raise RuntimeError("authority unavailable") from exc
        raise RuntimeError("authority unavailable")

    def _v2_service(self, namespace: object) -> AuthorityV2FenceService:
        if type(namespace) is not str:
            raise AuthorityUnavailable("namespace unavailable")
        service = self._v2_fences.get(namespace)
        if service is None:
            raise AuthorityUnavailable("namespace unavailable")
        return service

    def install_d04_appraisal_result_reader_v3(self, namespace, service):
        from .d04_appraisal_result_service_v3 import AuthorityD04AppraisalResultServiceV3
        if (type(service) is not AuthorityD04AppraisalResultServiceV3
                or namespace in self._d04_appraisal_reads_v3
                or service._fences is not self._v2_fences.get(namespace)):
            raise AuthorityUnavailable("D04 installed result service differs")
        self._d04_appraisal_reads_v3[namespace] = service

    def install_d07_cognition_result_reader_v1(self, namespace, service):
        from .d07_cognition_result_service_v1 import AuthorityD07CognitionResultServiceV1
        if (type(service) is not AuthorityD07CognitionResultServiceV1
                or namespace in self._d07_cognition_reads_v1
                or service._fences is not self._v2_fences.get(namespace)):
            raise AuthorityUnavailable("D07 installed result service differs")
        self._d07_cognition_reads_v1[namespace] = service

    def install_contact_model_result_reader_v1(self, namespace, service):
        from .contact_model_result_service_v1 import InstalledContactModelResultServiceV1
        model = self._v2_model_egress.get(namespace)
        if (type(service) is not InstalledContactModelResultServiceV1
                or namespace in self._contact_model_reads_v1
                or service._fences is not self._v2_fences.get(namespace)
                or model is None or service._store is not model._store
                or service._path != model._graph_verifier._path):
            raise AuthorityUnavailable("contact actual model/result services differ")
        self._contact_model_reads_v1[namespace] = service

    def install_contact_model_result_reader_v2(self, namespace, service):
        from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2
        model = self._v2_model_egress.get(namespace)
        if (type(service) is not InstalledContactModelResultServiceV2
                or namespace in self._contact_model_reads_v2
                or service._fences is not self._v2_fences.get(namespace)
                or model is None or service._store is not model._store
                or service._path != model._graph_verifier._path):
            raise AuthorityUnavailable("contact actual model/result services differ")
        self._contact_model_reads_v2[namespace] = service

    def install_internal_life_model_result_reader_v2(self, namespace, service):
        from .internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
        model = self._v2_model_egress.get(namespace)
        if (type(service) is not InstalledInternalLifeModelResultServiceV2
                or namespace in self._internal_life_model_reads_v2
                or service._fences is not self._v2_fences.get(namespace)
                or model is None or service._store is not model._store
                or service._path != model._graph_verifier._path
                or service._graph_reader is not model._graph_verifier._internal_life_reader_v2):
            raise AuthorityUnavailable("Life actual model/result services differ")
        self._internal_life_model_reads_v2[namespace] = service

    def install_life_numeric_model_result_reader_v1(self, namespace, service):
        from .life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
        model = self._v2_model_egress.get(namespace)
        if (type(service) is not InstalledLifeNumericModelResultServiceV1
                or namespace in self._life_numeric_model_reads_v1
                or service._fences is not self._v2_fences.get(namespace)
                or model is None or service._store is not model._store
                or service._path != model._graph_verifier._path
                or service._graph_reader is not model._graph_verifier._life_numeric_reader_v1):
            raise AuthorityUnavailable("Life actual model/result services differ")
        self._life_numeric_model_reads_v1[namespace] = service

    def install_c04_executor_v2(self, namespace: str,
                                service: AuthorityInternalWorkService,
                                executor: object) -> None:
        """Attach a formal executor while the independent daemon is offline."""
        from .installed_c04_executor_v2 import InstalledC04ExecutorV2
        bridge = self._v2_execution.get(namespace)
        if (bridge is None or namespace in self._v2_internal_work_executors
                or type(service) is not AuthorityInternalWorkService
                or type(executor) is not InstalledC04ExecutorV2
                or executor._service is not service
                or service.journal is not bridge.journal
                or service.installed_algorithm_id !=
                   "d06.association_activation.v2"
                or not service.installed_runtime_verified
                or bridge._internal_work_terminal_verifier is None):
            raise AuthorityUnavailable("installed C04 executor identity differs")
        self._v2_internal_work_services[namespace] = service
        self._v2_internal_work_executors[namespace] = executor

    def install_c04_executor_v3(self, namespace: str,
                                service: AuthorityInternalWorkService,
                                executor: object) -> None:
        """Attach the separately pinned V3 executor before serving requests."""
        from .installed_c04_executor_v3 import InstalledC04ExecutorV3

        bridge = self._v2_execution.get(namespace)
        if (bridge is None or namespace in self._v3_internal_work_executors
                or type(service) is not AuthorityInternalWorkService
                or type(executor) is not InstalledC04ExecutorV3
                or executor._service is not service
                or service.journal is not bridge.journal
                or service.installed_algorithm_id !=
                   "d06.association_activation.v3"
                or not service.installed_runtime_verified
                or bridge._internal_work_terminal_verifier is None):
            raise AuthorityUnavailable("installed C04 V3 executor identity differs")
        self._v3_internal_work_services[namespace] = service
        self._v3_internal_work_executors[namespace] = executor

    def install_d04_numeric_service_v3(self, namespace, service):
        from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
        if (type(service) is not AuthorityD04NumericServiceV3
                or namespace in self._d04_numeric_services_v3
                or service.bridge is not self._v2_execution.get(namespace)
                or service.owner_tickets is not self._v2_owner_tickets):
            raise AuthorityUnavailable("D04 numeric service installation differs")
        self._d04_numeric_services_v3[namespace] = service
        self._core.install_execution_redaction_d04_numeric_service_v3(namespace, service)

    def install_current_erasure_prepare(self, namespace: str,
                                        installation_id: str,
                                        service: CurrentErasureAuthority) -> None:
        """Attach one paired, pinned prepare service before serving requests."""
        key = (namespace, installation_id)
        if (key in self._current_erasure_prepares
                or namespace not in self._v2_fences
                or type(service) is not CurrentErasureAuthority
                or service._prepare is None
                or service._plan_graph_verifier is None
                or service._prepare[0] is not self._v2_fences[namespace]
                or service._prepare[4] != installation_id
                or service._prepare[1] is not self._v2_owner_sessions
                or service._prepare[2] is not self._v2_owner_tickets):
            raise AuthorityUnavailable("installed C09 prepare identity differs")
        self._current_erasure_prepares[key] = service
        storage_reader = getattr(self, "_d12_owner_storage_services_v1", {}).get(key)
        if storage_reader is not None:
            service.install_current_owner_storage_reader_v1(storage_reader)

    def install_current_accepted_erasure_read(
            self, namespace: str, installation_id: str,
            reader: CurrentAcceptedErasureReadService) -> None:
        """Install only the reader paired to this namespace's original ledgers."""
        key = (namespace, installation_id)
        erasure = self._current_erasure_prepares.get(key)
        if (key in self._current_accepted_erasure_reads
                or type(reader) is not CurrentAcceptedErasureReadService
                or erasure is None or erasure._prepare is None
                or reader._service is not self._v2_fences.get(namespace)
                or reader._service is not erasure._prepare[0]
                or reader._owner_tickets is not self._v2_owner_tickets
                or reader._scoped is not erasure._prepare[5]):
            raise AuthorityUnavailable("installed accepted erasure reader differs")
        self._current_accepted_erasure_reads[key] = reader

    def _bound_v2_service(self, credential: MtlsPeerCredential, profile_id: str,
                          manifest_digest: str, namespace: object) -> AuthorityV2FenceService:
        installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
        if (installed is None or installed.manifest_digest != manifest_digest
                or not any(peer == credential.certificate_sha256
                           and profile == profile_id and mapped == namespace
                           for (peer, profile, _), mapped in self._namespace_bindings_v2.items())):
            raise AuthorityUnavailable("namespace unavailable")
        return self._v2_service(namespace)

    def _owner_session_kwargs(self, command: dict[str, object], namespace: str,
                              installation_id: str) -> dict[str, object]:
        fields = {"owner_session_token", "owner_session_request"}
        present = set(command) & fields
        if not present:
            return {}
        if present != fields:
            raise AuthorityUnavailable("Owner session fields must be paired")
        token = command["owner_session_token"]
        if (type(token) is not str or len(token) != 43
                or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                       for ch in token)):
            raise AuthorityUnavailable("Owner session token encoding differs")
        raw = command["owner_session_request"]
        request = session_from_wire(raw)
        if (type(request) is not OwnerSessionLoginRequestV1
                or session_to_wire(request) != raw
                or request.authority_id != self._authority_id()
                or request.authority_namespace != namespace
                or request.installation_id != installation_id):
            raise AuthorityUnavailable("Owner session request identity differs")
        return {"session_token": token, "session_request": request}

    @staticmethod
    def _dispatch_footprint(value: object) -> RecoveryConstraintFootprint:
        if type(value) is not dict:
            raise ValueError("invalid dispatch footprint")
        fields = RecoveryConstraintFootprint.__dataclass_fields__
        if set(value) != set(fields):
            raise ValueError("invalid dispatch footprint fields")
        shaped = dict(value)
        for name in ("conflict_keys", "object_gate_keys"):
            if type(shaped[name]) is not list:
                raise ValueError("invalid dispatch footprint identifiers")
            shaped[name] = tuple(shaped[name])
        for name, kind in (("quota_occupancies", QuotaOccupancy),
                           ("reservations", ReservationConstraint),
                           ("budgets", BudgetConstraint)):
            if type(shaped[name]) is not list or any(type(item) is not list for item in shaped[name]):
                raise ValueError("invalid dispatch footprint constraints")
            shaped[name] = tuple(kind(*item) for item in shaped[name])
        result = RecoveryConstraintFootprint(**shaped)
        if json.loads(result._json()) != value:
            raise ValueError("noncanonical dispatch footprint")
        return result

    def _v2_command(self, method: str, credential: MtlsPeerCredential,
                    profile_id: str, manifest_digest: str,
                    command: object) -> dict[str, object]:
        if type(command) is not dict:
            raise RuntimeError("authority unavailable")
        subject = "mtls:sha256:" + credential.certificate_sha256
        try:
            from .d12_operation_status_rpc_v1 import dispatch_d12_operation_status_v1
            from .d12_target_owner_rpc_v1 import dispatch_d12_target_owner_v1
            from .d12_installation_lifecycle_rpc_v1 import dispatch_d12_installation_lifecycle_v1
            from .d04_numeric_bridge_rpc_v3 import dispatch_d04_numeric_bridge_v3
            from .d04_series_rpc_v1 import dispatch_d04_series_rpc_v1
            from .d04_root_execution_rpc_v3 import dispatch_d04_root_execution_v3
            from .d11_offline_tick_rpc_v1 import dispatch_d11_offline_tick_v1
            from .d11_life_rpc_v1 import dispatch_d11_life_v1
            from .d10_contact_policy_rpc_v1 import dispatch_d10_contact_policy_v1
            from .d12_package_maintenance_rpc_v2 import dispatch_d12_package_maintenance_v2
            from .first_owner_reverse_v1 import dispatch_first_owner_issue_v1
            from .contact_owner_session_rpc_v3 import dispatch_contact_owner_session_v3
            from .contact_finished_owner_read_rpc_v1 import dispatch_contact_finished_owner_read_v1
            for dispatch in (dispatch_d12_operation_status_v1, dispatch_d12_target_owner_v1,
                             dispatch_d12_installation_lifecycle_v1, dispatch_d04_numeric_bridge_v3, dispatch_d04_series_rpc_v1,
                             dispatch_d04_root_execution_v3, dispatch_d11_offline_tick_v1, dispatch_d11_life_v1, dispatch_d10_contact_policy_v1,
                             dispatch_d12_package_maintenance_v2, dispatch_first_owner_issue_v1,
                             dispatch_contact_owner_session_v3, dispatch_contact_finished_owner_read_v1):
                handled = dispatch(self, method, credential, profile_id, manifest_digest, command)
                if handled is not None:
                    return handled
            if method in {"d04_numeric_claim_v3", "d04_numeric_inspect_v3",
                          "d04_numeric_terminal_v3"}:
                from .d04_numeric_contract_v3 import (
                    D04NumericBindingV3, D04NumericClaimV3, D04NumericMeasurementV3,
                    from_wire as numeric_from_wire, to_wire as numeric_to_wire,
                )
                expected = {"namespace", "binding"}
                if method == "d04_numeric_claim_v3":
                    expected.add("executor_incarnation")
                elif method == "d04_numeric_terminal_v3":
                    expected.update({"claim", "measurement"})
                if set(command) != expected:
                    raise AuthorityUnavailable("D04 numeric command shape differs")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[(credential.certificate_sha256, profile_id)]
                service = self._d04_numeric_services_v3.get(namespace)
                binding = numeric_from_wire(command["binding"], D04NumericBindingV3)
                if (service is None or service.installation_id != installed.installation_id
                        or binding.authority_namespace != namespace
                        or binding.installation_id != installed.installation_id):
                    raise AuthorityUnavailable("paired D04 executor installation differs")
                if method == "d04_numeric_claim_v3":
                    claim = service.claim_d04_numeric_v3(binding, command["executor_incarnation"])
                    return {"claim": numeric_to_wire(claim)}
                if method == "d04_numeric_terminal_v3":
                    terminal = service.record_d04_numeric_terminal_v3(binding,
                        numeric_from_wire(command["claim"], D04NumericClaimV3),
                        numeric_from_wire(command["measurement"], D04NumericMeasurementV3))
                    return {"terminal": numeric_to_wire(terminal)}
                claim, terminal = service.read_d04_numeric_originals_v3(binding)
                return {"claim": None if claim is None else numeric_to_wire(claim),
                        "terminal": None if terminal is None else numeric_to_wire(terminal)}
            if method == "prepare_current_erasure_v1" and set(command) == {
                    "namespace", "operation_id", "source_id", "owner_actor_id",
                    "owner_session_token"}:
                namespace = identifier(command["namespace"], "namespace")
                fence = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                erasure = self._current_erasure_prepares.get(
                    (namespace, installed.installation_id)) if installed else None
                if erasure is None or erasure._prepare[0] is not fence:
                    raise AuthorityUnavailable("installed C09 prepare unavailable")
                token = identifier(command["owner_session_token"],
                                   "owner_session_token")
                receipt, permit = erasure.prepare_request(
                    credential=credential, subject=subject,
                    holder=installed.administrator_holder,
                    installation_id=installed.installation_id,
                    owner_actor_id=identifier(command["owner_actor_id"],
                                              "owner_actor_id"),
                    owner_session_token=token,
                    deletion_operation_id=identifier(command["operation_id"],
                                                     "operation_id"),
                    source_id=identifier(command["source_id"], "source_id"))
                return {"receipt": to_wire(receipt), "permit": to_wire(permit)}
            if method in {"c04_execute_v2", "c04_inspect_v2",
                          "c04_execute_v3", "c04_inspect_v3"} and set(command) == {
                    "namespace", "binding"}:
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                v3 = method.endswith("_v3")
                executor = (self._v3_internal_work_executors if v3 else
                            self._v2_internal_work_executors).get(namespace)
                if executor is None:
                    raise AuthorityUnavailable("installed C04 executor unavailable")
                binding = c04_from_wire(command["binding"], InternalWorkBindingV1)
                if (binding.namespace != namespace or
                        binding.algorithm_ref !=
                        ("d06.association_activation.v3" if v3 else
                         "d06.association_activation.v2")):
                    raise AuthorityUnavailable("installed C04 binding scope differs")
                inspection = (executor.execute(binding)
                              if method.startswith("c04_execute_")
                              else executor.inspect(binding))
                return {"inspection": c04_to_wire(inspection)}
            if method == "c04_terminal_verify_v1" and set(command) == {
                    "namespace", "proof"}:
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                proof = c04_from_wire(command["proof"], InternalWorkTerminalProofV1)
                services = {
                    "d06.association_activation.v2":
                    self._v2_internal_work_services.get(namespace),
                    "d06.association_activation.v3":
                    self._v3_internal_work_services.get(namespace),
                }
                service = services.get(proof.binding.algorithm_ref)
                if service is None:
                    raise AuthorityUnavailable("installed C04 terminal service unavailable")
                if (proof.binding.namespace != namespace
                        or type(proof.terminal) is not InternalWorkTerminalV2
                        or proof.terminal.status not in {"completed", "failed"}):
                    raise AuthorityUnavailable("installed C04 terminal scope differs")
                verified = service.verify_original_internal_work_terminal(proof)
                if (verified.status != proof.terminal.status
                        or verified.actual_cpu_ms != proof.terminal.actual_cpu_ms
                        or not service.verify_installed_terminal(
                            proof.binding, proof.claim, proof.terminal)):
                    raise AuthorityUnavailable("installed C04 terminal is unverified")
                return {"verified": c04_to_wire(verified)}
            if method == "get_pending_deletion_for_graph_write" and set(command) == {
                    "namespace", "deletion_operation_id", "permit"}:
                namespace = identifier(command["namespace"], "namespace")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                reader = self._v2_deletion_graph_reads.get(namespace)
                permit = from_wire(command["permit"])
                if (installed is None or reader is None
                        or type(permit) is not FencePermitV2
                        or permit.operation != "delete"
                        or permit.namespace != namespace
                        or permit.subject != subject
                        or service is not reader._service):
                    raise AuthorityUnavailable("installed deletion graph read unavailable")
                receipt = reader.get_pending_deletion_for_graph_write(
                    credential=credential, subject=subject,
                    installation_id=installed.installation_id,
                    deletion_operation_id=identifier(
                        command["deletion_operation_id"], "deletion_operation_id"),
                    permit=permit)
                return {"receipt": to_wire(receipt)}
            if method == "read_current_accepted_erasure_v1" and set(command) == {
                    "namespace", "deletion_operation_id", "scope_digest", "permit"}:
                namespace = identifier(command["namespace"], "namespace")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                reader = (self._current_accepted_erasure_reads.get(
                    (namespace, installed.installation_id)) if installed else None)
                permit = from_wire(command["permit"])
                if (reader is None or type(permit) is not FencePermitV2
                        or reader._service is not service):
                    raise AuthorityUnavailable("installed accepted erasure read unavailable")
                original = reader.read_current_accepted_erasure_v1(
                    credential=credential, subject=subject,
                    installation_id=installed.installation_id,
                    deletion_operation_id=identifier(
                        command["deletion_operation_id"], "deletion_operation_id"),
                    scope_digest=command["scope_digest"], permit=permit)
                return {"original": accepted_to_wire(original)}
            if method == "read_final_handoff_pairing_v1":
                if set(command) != {"namespace", "installation_id"}:
                    raise AuthorityUnavailable("final handoff pairing fields differ")
                namespace = identifier(command["namespace"], "namespace")
                installation_id = identifier(
                    command["installation_id"], "installation_id")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                reverse = self._final_handoff_reverse_v2.get(namespace)
                issuer_id = self._final_handoff_issuers_v2.get(namespace)
                if (reverse is None or issuer_id is None
                        or installed.installation_id != installation_id
                        or reverse.profile.installation_id != installation_id
                        or reverse.profile.profile_id != profile_id):
                    raise AuthorityUnavailable("final handoff pairing unavailable")
                profile = reverse.profile
                fields = {
                    "authority_id": self._authority_id(),
                    "namespace": namespace,
                    "installation_id": installation_id,
                    "issuer_id": issuer_id,
                    "reverse_profile_id": profile.profile_id,
                    "reverse_host": profile.host,
                    "reverse_port": profile.port,
                    "reverse_server_name": profile.server_name,
                    "reverse_expected_host_certificate_sha256":
                        profile.expected_host_certificate_sha256,
                    "reverse_client_certificate_sha256":
                        reverse.client_certificate_sha256,
                    "installation_manifest_digest": installed.manifest_digest,
                }
                return FinalHandoffPairingV1(
                    **fields,
                    configuration_digest=FinalHandoffPairingV1.digest_public_fields(fields),
                ).to_wire()
            if method in {"self_identity_mutate_v1", "self_identity_current_v1"}:
                expected = ({"namespace", "mutation"}
                            if method == "self_identity_mutate_v1" else
                            {"namespace", "current_request"})
                if set(command) != expected:
                    raise AuthorityUnavailable("self identity command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                service = self._v2_self_identity.get(namespace)
                if service is None:
                    raise AuthorityUnavailable("self identity service is unavailable")
                if method == "self_identity_mutate_v1":
                    mutation = self_identity_from_wire(
                        command["mutation"])
                    if (type(mutation) is not SelfIdentityMutationV1
                            or mutation.authority_id != self._authority_id()
                            or mutation.authority_namespace != namespace
                            or mutation.namespace != service._namespace_id):
                        raise AuthorityUnavailable("self identity mutation differs")
                    receipt = service.mutate(
                        credential=credential, subject=subject, mutation=mutation)
                    return {"receipt": asdict(receipt)}
                if self._self_identity_readers_v2.get(namespace) != (
                        credential.certificate_sha256, profile_id):
                    raise AuthorityUnavailable("designated self identity reader differs")
                request = self_identity_from_wire(
                    command["current_request"])
                if (type(request) is not SelfIdentityCurrentRequestV1
                        or request.authority_id != self._authority_id()
                        or request.authority_namespace != namespace
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            request.namespace)) != namespace):
                    raise AuthorityUnavailable("self identity read installation differs")
                current = service.current(
                    credential=credential, subject=subject, request=request)
                return {"current": None if current is None
                        else self_identity_to_wire(current)}
            if method in {"terminal_c02_recovery_read_v1",
                          "terminal_c02_recovery_query_v1"}:
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("terminal C02 recovery command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                peer = (credential.certificate_sha256, profile_id)
                installed = self._installations_v2[peer]
                service = self._v2_terminal_c02_recovery_reads.get(namespace)
                if (service is None or service._read_subject != subject
                        or self._terminal_c02_recovery_readers_v2.get(namespace) != peer):
                    raise AuthorityUnavailable("installed terminal C02 recovery reader unavailable")
                request = terminal_c02_from_wire(
                    command["read_request"], TerminalRecoveryReadRequestV1)
                key = request.original_key
                if (key.authority_id != self._authority_id()
                        or key.authority_namespace != namespace
                        or key.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            key.namespace)) != namespace):
                    raise AuthorityUnavailable("terminal C02 recovery installation differs")
                if method == "terminal_c02_recovery_query_v1":
                    attempt, fact = service.query(
                        credential=credential, request=request)
                    return {
                        "attempt": None if attempt is None else terminal_c02_to_wire(attempt),
                        "read_fact": None if fact is None else terminal_c02_to_wire(fact),
                    }
                delivery = service.prepare(credential=credential, request=request)
                try:
                    result_wire = {
                        "request": terminal_c02_to_wire(delivery.request),
                        "observation": asdict(delivery.observation),
                    }
                except BaseException:
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(
                    {"result": result_wire}, service, credential, delivery)
            if method == "natural_generation_content_read_v2":
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("natural content command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                service = self._v2_natural_generation_content_reads.get(namespace)
                if (service is None
                        or service._original._read_subject != subject
                        or self._worker_result_readers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("installed natural content reader unavailable")
                read_request = natural_content_from_wire(
                    command["read_request"], NaturalGenerationContentReadRequestV2)
                if (read_request.authority_id != self._authority_id()
                        or read_request.authority_namespace != namespace
                        or read_request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            read_request.namespace)) != namespace):
                    raise AuthorityUnavailable("natural content installation differs")
                result = service.read_current_natural_generation_content_v2(
                    credential=credential, request=read_request,
                    now_utc=time.time())
                return {"result": natural_content_to_wire(result)}
            if method in {"d04_appraisal_result_read_v3", "d04_appraisal_result_recover_finish_v3"}:
                from .current_d04_appraisal_v3 import D04AppraisalResultReadRequestV3, from_wire as d04_from_wire, to_wire as d04_to_wire
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("D04 result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                service = self._d04_appraisal_reads_v3.get(namespace)
                request = d04_from_wire(command["read_request"], D04AppraisalResultReadRequestV3)
                installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
                if (service is None or installed is None or service._read_subject != "mtls:sha256:" + credential.certificate_sha256
                        or request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((credential.certificate_sha256, profile_id, request.namespace)) != namespace):
                    raise AuthorityUnavailable("D04 result installed reader differs")
                if method == "d04_appraisal_result_recover_finish_v3":
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                delivery = service.prepare(credential=credential, request=request)
                return _DeferredWorkerDelivery({"result": d04_to_wire(delivery.result)}, service, credential, delivery)
            if method in {"d07_cognition_result_read_v1", "d07_cognition_result_recover_finish_v1"}:
                from .d07_current_execution_v1 import D07CognitionResultReadRequestV1, from_wire as d07_from_wire, to_wire as d07_to_wire
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("D07 result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                service = self._d07_cognition_reads_v1.get(namespace)
                request = d07_from_wire(command["read_request"], D07CognitionResultReadRequestV1)
                installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
                if (service is None or installed is None or service._read_subject != "mtls:sha256:" + credential.certificate_sha256
                        or request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((credential.certificate_sha256, profile_id, request.namespace)) != namespace):
                    raise AuthorityUnavailable("D07 result installed reader differs")
                if method == "d07_cognition_result_recover_finish_v1":
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                delivery = service.prepare(credential=credential, request=request)
                return _DeferredWorkerDelivery({"result": d07_to_wire(delivery.result)}, service, credential, delivery)
            if method in {"internal_life_model_result_read_v2", "internal_life_model_result_recover_finish_v2"}:
                from .internal_life_model_result_contract_v2 import InternalLifeModelResultReadRequestV2, internal_life_result_from_wire_v2, internal_life_result_to_wire_v2
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("contact result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                service = self._internal_life_model_reads_v2.get(namespace)
                request = internal_life_result_from_wire_v2(command["read_request"], InternalLifeModelResultReadRequestV2)
                installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
                if (service is None or installed is None or service._read_subject != "mtls:sha256:" + credential.certificate_sha256
                        or request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((credential.certificate_sha256, profile_id, request.namespace)) != namespace):
                    raise AuthorityUnavailable("contact result installed reader differs")
                if method == "internal_life_model_result_recover_finish_v2":
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                delivery = service.prepare(credential=credential, request=request)
                try:
                    payload = {"result": internal_life_result_to_wire_v2(delivery.result)}
                except BaseException:
                    # Encoding did not deliver the result. Release only the
                    # process-local exclusion; the durable read fence remains
                    # unresolved for the authenticated recover-finish path.
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(payload, service, credential, delivery)
            if method in {"life_numeric_model_result_read_v1", "life_numeric_model_result_recover_finish_v1"}:
                from .current_life_numeric_v1 import LifeNumericModelResultReadRequestV1, life_numeric_result_from_wire_v1, life_numeric_result_to_wire_v1
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("Life numeric result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                service = self._life_numeric_model_reads_v1.get(namespace)
                request = life_numeric_result_from_wire_v1(command["read_request"], LifeNumericModelResultReadRequestV1)
                installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
                if (service is None or installed is None or service._read_subject != "mtls:sha256:" + credential.certificate_sha256
                        or request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((credential.certificate_sha256, profile_id, request.namespace)) != namespace):
                    raise AuthorityUnavailable("Life numeric result installed reader differs")
                if method == "life_numeric_model_result_recover_finish_v1":
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                delivery = service.prepare(credential=credential, request=request)
                try:
                    payload = {"result": life_numeric_result_to_wire_v1(delivery.result)}
                except BaseException:
                    # Encoding did not deliver the result. Release only the
                    # process-local exclusion; the durable read fence remains
                    # unresolved for the authenticated recover-finish path.
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(payload, service, credential, delivery)
            if method in {"contact_model_result_read_v2", "contact_model_result_recover_finish_v2"}:
                from .contact_model_result_contract_v2 import ContactModelResultReadRequestV2, contact_result_from_wire_v2, contact_result_to_wire_v2
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("contact result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                service = self._contact_model_reads_v2.get(namespace)
                request = contact_result_from_wire_v2(command["read_request"], ContactModelResultReadRequestV2)
                installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
                if (service is None or installed is None or service._read_subject != "mtls:sha256:" + credential.certificate_sha256
                        or request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((credential.certificate_sha256, profile_id, request.namespace)) != namespace):
                    raise AuthorityUnavailable("contact result installed reader differs")
                if method == "contact_model_result_recover_finish_v2":
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                delivery = service.prepare(credential=credential, request=request)
                try:
                    payload = {"result": contact_result_to_wire_v2(delivery.result)}
                except BaseException:
                    # Encoding did not deliver the result. Release only the
                    # process-local exclusion; the durable read fence remains
                    # unresolved for the authenticated recover-finish path.
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(payload, service, credential, delivery)
            if method in {"contact_model_result_read_v1", "contact_model_result_recover_finish_v1"}:
                from .contact_model_result_contract_v1 import ContactModelResultReadRequestV1, contact_result_from_wire_v1, contact_result_to_wire_v1
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("contact result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                service = self._contact_model_reads_v1.get(namespace)
                request = contact_result_from_wire_v1(command["read_request"], ContactModelResultReadRequestV1)
                installed = self._installations_v2.get((credential.certificate_sha256, profile_id))
                if (service is None or installed is None or service._read_subject != "mtls:sha256:" + credential.certificate_sha256
                        or request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((credential.certificate_sha256, profile_id, request.namespace)) != namespace):
                    raise AuthorityUnavailable("contact result installed reader differs")
                if method == "contact_model_result_recover_finish_v1":
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                delivery = service.prepare(credential=credential, request=request)
                return _DeferredWorkerDelivery({"result": contact_result_to_wire_v1(delivery.result)}, service, credential, delivery)
            if method in {"natural_generation_output_select_v2",
                          "natural_generation_output_recover_finish_v2"}:
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("natural output command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                service = self._v2_natural_generation_output_reads.get(namespace)
                if (service is None or service._read_subject != subject
                        or self._worker_result_readers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("installed natural output reader unavailable")
                read_request = natural_output_from_wire(
                    command["read_request"], NaturalGenerationOutputReadRequestV2)
                if (read_request.authority_id != self._authority_id()
                        or read_request.authority_namespace != namespace
                        or read_request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            read_request.namespace)) != namespace):
                    raise AuthorityUnavailable("natural output read installation differs")
                if method == "natural_generation_output_recover_finish_v2":
                    service.recover_finish(
                        credential=credential, request=read_request)
                    return {"finished": True}
                delivery = service.prepare(
                    credential=credential, request=read_request,
                    now_utc=time.time())
                try:
                    result_wire = natural_output_to_wire(delivery.result)
                except BaseException:
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(
                    {"result": result_wire}, service, credential, delivery)
            if method in {"natural_review_output_select_v2",
                          "natural_review_output_recover_finish_v2"}:
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("natural review output command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                service = self._v2_natural_review_output_reads.get(namespace)
                if (service is None or service._read_subject != subject
                        or self._worker_result_readers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("installed natural review reader unavailable")
                read_request = natural_review_output_from_wire(
                    command["read_request"], NaturalReviewOutputReadRequestV2)
                if (read_request.authority_id != self._authority_id()
                        or read_request.authority_namespace != namespace
                        or read_request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            read_request.namespace)) != namespace):
                    raise AuthorityUnavailable("natural review output installation differs")
                if method == "natural_review_output_recover_finish_v2":
                    service.recover_finish(
                        credential=credential, request=read_request)
                    return {"finished": True}
                delivery = service.prepare(
                    credential=credential, request=read_request,
                    now_utc=time.time())
                try:
                    result_wire = natural_review_output_to_wire(delivery.result)
                except BaseException:
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(
                    {"result": result_wire}, service, credential, delivery)
            if method == "natural_paid_review_current_read_v2":
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("natural paid review command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                service = self._v2_natural_paid_review_reads.get(namespace)
                if (service is None
                        or service._generation._read_subject != subject
                        or self._worker_result_readers_v2.get(namespace) !=
                           (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("installed natural paid review unavailable")
                read_request = natural_paid_review_from_wire(
                    command["read_request"],
                    NaturalPaidReviewCurrentReadRequestV2)
                generation = read_request.generation_content_request
                review = read_request.review_output_request
                if (generation.authority_id != self._authority_id()
                        or generation.authority_namespace != namespace
                        or generation.installation_id != installed.installation_id
                        or review.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            read_request.namespace)) != namespace):
                    raise AuthorityUnavailable("natural paid review installation differs")
                result = service.read_current_natural_paid_review_v2(
                    credential=credential, request=read_request,
                    now_utc=time.time())
                return {"result": natural_paid_review_to_wire(result)}
            if method in {"context_reply_result_read_v2",
                          "context_reply_result_recover_finish_v2"}:
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("context reply result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                service = self._v2_context_reply_result_reads.get(namespace)
                if (service is None or service._read_subject != subject
                        or self._worker_result_readers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("installed context reply reader unavailable")
                read_request = context_reply_result_from_wire(
                    command["read_request"], ContextReplyResultReadRequestV1)
                if (read_request.authority_id != self._authority_id()
                        or read_request.authority_namespace != namespace
                        or read_request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            read_request.namespace)) != namespace):
                    raise AuthorityUnavailable("context reply read installation differs")
                if method == "context_reply_result_recover_finish_v2":
                    service.recover_finish(
                        credential=credential, request=read_request)
                    return {"finished": True}
                delivery = service.prepare(
                    credential=credential, request=read_request,
                    now_utc=time.time())
                try:
                    result_wire = context_reply_result_to_wire(delivery.result)
                except BaseException:
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(
                    {"result": result_wire}, service, credential, delivery)
            if method in {"worker_model_result_select_attempt_v1",
                          "worker_model_result_read_v1",
                          "worker_model_result_recover_finish_v1",
                          "reply_worker_model_result_select_attempt_v1",
                          "reply_worker_model_result_read_v1",
                          "reply_worker_model_result_recover_finish_v1"}:
                if set(command) != {"namespace", "read_request"}:
                    raise AuthorityUnavailable("worker result command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                service = self._v2_worker_model_result_reads.get(namespace)
                if (service is None or service._read_subject != subject
                        or self._worker_result_readers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("installed worker reader unavailable")
                reply = method.startswith("reply_")
                if reply and type(service._reply_graph) is not (
                        PinnedCurrentReplyWorkerModelResultGraphVerifier):
                    raise AuthorityUnavailable("installed reply graph reader unavailable")
                wire_from = (reply_worker_result_from_wire if reply
                             else worker_result_from_wire)
                wire_to = (reply_worker_result_to_wire if reply
                           else worker_result_to_wire)
                request = wire_from(
                    command["read_request"],
                    ReplyWorkerModelResultReadRequestV1 if reply
                    else WorkerModelResultReadRequestV1)
                if (request.authority_id != self._authority_id()
                        or request.authority_namespace != namespace
                        or request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            request.namespace)) != namespace):
                    raise AuthorityUnavailable("worker result installation differs")
                if method.endswith("select_attempt_v1"):
                    selected = service.select_attempt(
                        credential=credential, first_request=request)
                    return {"selected_request": wire_to(selected)}
                if method.endswith("recover_finish_v1"):
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                delivery = service.prepare(credential=credential, request=request)
                try:
                    result_wire = wire_to(delivery.result)
                except BaseException:
                    service.abandon_delivery(delivery=delivery)
                    raise
                return _DeferredWorkerDelivery(
                    {"result": result_wire},
                    service, credential, delivery)
            if method in {"worker_result_read_fact_v1", "worker_result_read_fact_v2"}:
                if set(command) != {"namespace", "fact_request"}:
                    raise AuthorityUnavailable("worker read fact command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                peer = (credential.certificate_sha256, profile_id)
                service = self._v2_worker_result_read_facts.get(namespace)
                if (service is None
                        or self._worker_result_fact_committers_v2.get(namespace) != peer
                        or service._committer_subject != subject):
                    raise AuthorityUnavailable("designated C02 committer unavailable")
                request = worker_fact_from_wire(
                    command["fact_request"],
                    (WorkerResultReadFactRequestV2 if method == "worker_result_read_fact_v2"
                     else WorkerResultReadFactRequestV1))
                if (request.read_request.authority_id != self._authority_id()
                        or request.read_request.authority_namespace != namespace
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            request.read_request.namespace)) != namespace):
                    raise AuthorityUnavailable("C02 committer installation differs")
                if method == "worker_result_read_fact_v2":
                    if request.write_permit.operation_id != domain_bundle_write_attempt_id_v1(
                            request.read_request.namespace,
                            request.read_request.consumer_operation_id,
                            request.bundle_digest):
                        raise AuthorityUnavailable("C02 bundle write fence differs")
                    fact = service.current_v2(credential=credential, request=request)
                else:
                    fact = service.current(credential=credential, request=request)
                return {"fact": worker_fact_to_wire(fact)}
            if method in {"internal_accounting_begin_v1", "internal_accounting_validate_v1",
                          "internal_accounting_finish_v1", "internal_accounting_recover_finish_v1"}:
                from .internal_accounting_v1 import (
                    HistoricalInternalCostRequestV1, HistoricalInternalCostGrantV1,
                    InstalledHistoricalInternalAccountingServiceV1,
                    from_wire as internal_from_wire, to_wire as internal_to_wire,
                )
                action = method.removeprefix("internal_accounting_").removesuffix("_v1")
                expected = {"namespace", "request"}
                if action in {"validate", "finish"}:
                    expected.add("grant")
                if set(command) != expected:
                    raise AuthorityUnavailable("internal accounting command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[(credential.certificate_sha256, profile_id)]
                accounting = self._v2_accounting.get(namespace)
                internal_work = self._v3_internal_work_services.get(namespace)
                if (accounting is None or internal_work is None
                        or self._accounting_observers_v2.get(namespace) != (credential.certificate_sha256, profile_id)
                        or accounting._subject != subject
                        or accounting._holder != installed.administrator_holder):
                    raise AuthorityUnavailable("designated historical internal observer unavailable")
                request = internal_from_wire(command["request"], HistoricalInternalCostRequestV1)
                service = InstalledHistoricalInternalAccountingServiceV1(
                    accounting=accounting, internal_work=internal_work, installation_id=installed.installation_id)
                result = service.operate(credential=credential, request=request, action=action,
                    grant=internal_from_wire(command["grant"], HistoricalInternalCostGrantV1)
                          if "grant" in command else None)
                return ({"grant": internal_to_wire(result)} if action == "begin"
                        else {"valid" if action == "validate" else "finished": result})
            if method in {"accounting_begin_v1", "accounting_validate_v1",
                          "accounting_finish_v1", "accounting_recover_finish_v1"}:
                expected = ({"namespace", "request"} if method in {
                    "accounting_begin_v1", "accounting_recover_finish_v1"} else
                    {"namespace", "request", "grant"})
                if set(command) != expected:
                    raise AuthorityUnavailable("accounting command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                service = self._v2_accounting.get(namespace)
                if (service is None or self._accounting_observers_v2.get(namespace)
                        != (credential.certificate_sha256, profile_id)
                        or service._subject != subject):
                    raise AuthorityUnavailable("designated accounting observer unavailable")
                request = accounting_from_wire(
                    command["request"], AccountingMaintenanceRequestV1)
                if (request.intent.authority_id != self._authority_id()
                        or request.intent.namespace != namespace):
                    raise AuthorityUnavailable("accounting request installation differs")
                if method == "accounting_begin_v1":
                    grant = service.begin(credential=credential, request=request)
                    return {"grant": accounting_to_wire(grant)}
                if method == "accounting_recover_finish_v1":
                    service.recover_finish(credential=credential, request=request)
                    return {"finished": True}
                grant = accounting_from_wire(
                    command["grant"], AccountingMaintenanceGrantV1)
                if method == "accounting_validate_v1":
                    service.validate(credential=credential, request=request, grant=grant)
                    return {"valid": True}
                service.finish(credential=credential, request=request, grant=grant)
                return {"finished": True}
            if method in {"model_result_read_v1", "model_result_read_recover_finish_v1"}:
                expected = ({"namespace", "read_request", "owner_session_token"}
                            if method == "model_result_read_v1" else
                            {"namespace", "read_request"})
                if set(command) != expected:
                    raise AuthorityUnavailable("model result read command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                service = self._v2_model_result_reads.get(namespace)
                if (service is None or service._read_subject != subject
                        or self._model_observers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("installed result reader unavailable")
                read_request = result_from_wire(
                    command["read_request"], ModelResultReadRequestV1)
                if (read_request.authority_id != self._authority_id()
                        or read_request.authority_namespace != namespace
                        or read_request.installation_id != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            read_request.namespace)) != namespace):
                    raise AuthorityUnavailable("model result read installation differs")
                if method == "model_result_read_recover_finish_v1":
                    service.recover_finish(
                        credential=credential, request=read_request)
                    return {"finished": True}
                session = self._owner_session_kwargs(
                    {"owner_session_token": command["owner_session_token"],
                     "owner_session_request": session_to_wire(
                         read_request.owner_session_request)},
                    namespace, installed.installation_id)
                result = service.read_completed(
                    credential=credential,
                    owner_session_token=session["session_token"],
                    request=read_request)
                return {"result": result_to_wire(result)}
            if method == "model_terminal_fact_v2":
                if set(command) != {"namespace", "holder", "intent"}:
                    raise AuthorityUnavailable("terminal fact command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                holder = identifier(command["holder"], "holder")
                model = self._v2_model_egress.get(namespace)
                if (model is None or holder != installed.administrator_holder
                        or self._model_observers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("designated model observer unavailable")
                intent = model_from_wire(command["intent"], ModelEgressIntentV1)
                record, permit = model.recover_fenced(
                    credential=credential, subject=subject, intent=intent)
                if permit.holder != holder:
                    raise AuthorityUnavailable("model terminal holder differs")
                # All returned accounting facts come from one Authority snapshot.
                with self._core._tx() as db:
                    if model._store.read_locked(db, intent) != record:
                        raise AuthorityUnavailable("model terminal changed during query")
                    admission, report_digest, receipt = model._store.read_admission_locked(
                        db, intent)
                    row = model._fences.fences._row(db, intent.operation_id)
                    if (row is None or model._fences.fences._permit(row) != permit
                            or admission.installation_id != installed.installation_id
                            or admission.observer_peer_sha256 != credential.certificate_sha256
                            or admission.observer_profile_id != profile_id
                            or admission.manifest_digest != manifest_digest
                            or (receipt is None) != (report_digest is None)
                            or (record.state == "observed" and receipt is None)
                            or (receipt is not None and (
                                receipt.admission_id != admission.admission_id
                                or receipt.observation_digest != record.observation_digest
                                or receipt.report_digest != report_digest
                                or record.state != "observed"
                                or row[6] != "finished"
                                or row[8:10] != (intent.call_id, receipt.finish_digest)))):
                        raise AuthorityUnavailable("original model terminal facts differ")
                return {"record": model_to_wire(record), "permit": to_wire(permit),
                        "admission": model_to_wire(admission),
                        "receipt": None if receipt is None else model_to_wire(receipt)}
            if method in {"model_admit_dispatch_once_v2", "model_complete_observed_v2"}:
                expected = ({"namespace", "holder", "intent", "expected_anchor",
                             "request", "host_incarnation"}
                            if method == "model_admit_dispatch_once_v2" else
                            {"namespace", "holder", "intent", "expected_anchor",
                             "admission", "report"})
                if set(command) != expected:
                    raise AuthorityUnavailable("model v2 command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[(credential.certificate_sha256, profile_id)]
                holder = identifier(command["holder"], "holder")
                model = self._v2_model_egress.get(namespace)
                if (model is None or holder != installed.administrator_holder
                        or self._model_observers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)):
                    raise AuthorityUnavailable("designated model observer unavailable")
                intent = model_from_wire(command["intent"], ModelEgressIntentV1)
                anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                if method == "model_admit_dispatch_once_v2":
                    from ..model_broker.broker import ModelCallRequest
                    request = model_from_wire(command["request"], ModelCallRequest)
                    if not any(peer == credential.certificate_sha256
                               and profile == profile_id
                               and role == request.envelope.authority.namespace
                               and mapped == namespace
                               for (peer, profile, role), mapped in self._namespace_bindings_v2.items()):
                        raise AuthorityUnavailable("model request namespace differs")
                    record, permit, admission = model.admit_dispatch_once_v2(
                        credential=credential, subject=subject, holder=holder,
                        intent=intent, expected_anchor=anchor, request=request,
                        installation_id=installed.installation_id,
                        observer_peer_sha256=credential.certificate_sha256,
                        observer_profile_id=profile_id,
                        manifest_digest=manifest_digest,
                        host_incarnation=command["host_incarnation"])
                    return {"record": model_to_wire(record), "permit": to_wire(permit),
                            "admission": model_to_wire(admission)}
                admission = model_from_wire(command["admission"], ModelAdmissionV2)
                report = model_from_wire(command["report"], HostObservedModelCompletionV2)
                record, permit, receipt = model.complete_observed_v2(
                    credential=credential, subject=subject, holder=holder,
                    intent=intent, expected_anchor=anchor, admission=admission,
                    report=report, installation_id=installed.installation_id,
                    observer_peer_sha256=credential.certificate_sha256,
                    observer_profile_id=profile_id, manifest_digest=manifest_digest)
                return {"record": model_to_wire(record), "permit": to_wire(permit),
                        "receipt": model_to_wire(receipt)}
            if method == "model_terminal_recovery_identity_v1":
                expected = {"namespace", "business_namespace", "installation_id",
                            "job_id", "original_operation_id",
                            "acquire_operation_id", "call_id",
                            "original_model_operation_id", "request_digest",
                            "binding_digest"}
                if set(command) != expected:
                    raise AuthorityUnavailable("terminal C02 identity fields differ")
                namespace = identifier(command["namespace"], "namespace")
                raw_business = command["business_namespace"]
                if (type(raw_business) is not dict
                        or set(raw_business) != {"bot_id", "persona_id"}):
                    raise AuthorityUnavailable("terminal C02 business namespace differs")
                namespace_id = NamespaceId(**raw_business)
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                model = self._v2_model_egress.get(namespace)
                if (model is None or self._model_observers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)
                        or command["installation_id"] != installed.installation_id
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            namespace_id)) != namespace):
                    raise AuthorityUnavailable("designated terminal C02 observer differs")
                key = model.terminal_recovery_identity_v1(
                    credential=credential, subject=subject,
                    holder=installed.administrator_holder,
                    authority_id=self._authority_id(), namespace=namespace,
                    namespace_id=namespace_id,
                    installation_id=installed.installation_id,
                    job_id=command["job_id"],
                    original_operation_id=command["original_operation_id"],
                    acquire_operation_id=command["acquire_operation_id"],
                    original_model_operation_id=
                        command["original_model_operation_id"],
                    call_id=command["call_id"],
                    request_digest=command["request_digest"],
                    binding_digest=command["binding_digest"])
                return {"original_key": terminal_c02_to_wire(key),
                        "stable_result_digest": key.stable_result_digest}
            if method in {"model_original_intent_lookup_v1", "model_accounting_intent_lookup_v1"}:
                expected = {"namespace", "installation_id", "job_id",
                            "acquire_operation_id", "call_id",
                            "original_model_operation_id", "request_digest",
                            "binding_digest"}
                if set(command) != expected:
                    raise AuthorityUnavailable("original model lookup fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                model = self._v2_model_egress.get(namespace)
                if (model is None or self._model_observers_v2.get(namespace) !=
                        (credential.certificate_sha256, profile_id)
                        or command["installation_id"] != installed.installation_id):
                    raise AuthorityUnavailable("designated original model observer differs")
                found = model.lookup_original_intent_v1(
                    credential=credential, subject=subject,
                    holder=installed.administrator_holder,
                    authority_id=self._authority_id(), namespace=namespace,
                    installation_id=installed.installation_id,
                    job_id=command["job_id"],
                    acquire_operation_id=command["acquire_operation_id"],
                    original_model_operation_id=
                        command["original_model_operation_id"],
                    call_id=command["call_id"],
                    request_digest=command["request_digest"],
                    binding_digest=command["binding_digest"],
                    historical_accounting=method == "model_accounting_intent_lookup_v1")
                if found is None:
                    return {"status": "absent"}
                record, permit, admission, terminal = found
                return {
                    "status": ("terminal" if terminal is not None else
                               "unknown" if record.state == "unknown" else
                               record.state),
                    "record": model_to_wire(record), "permit": to_wire(permit),
                    "admission": None if admission is None else model_to_wire(admission),
                    "terminal": None if terminal is None else model_to_wire(terminal),
                }
            if method in {"model_prepare_fenced_v1", "model_admit_dispatch_once_v1",
                          "model_recover_fenced_v1"}:
                expected = ({"namespace", "holder", "draft", "expected_anchor"}
                            if method == "model_prepare_fenced_v1" else
                            {"namespace", "holder", "intent", "expected_anchor", "request"}
                            if method == "model_admit_dispatch_once_v1" else
                            {"namespace", "holder", "intent"})
                if set(command) != expected:
                    raise AuthorityUnavailable("model command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2[(credential.certificate_sha256, profile_id)]
                holder = identifier(command["holder"], "holder")
                model = self._v2_model_egress.get(namespace)
                if holder != installed.administrator_holder or model is None:
                    raise AuthorityUnavailable("installed model service or holder unavailable")
                if method == "model_prepare_fenced_v1":
                    draft = model_from_wire(command["draft"], ModelEgressDraftV1)
                    anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                    record, permit = model.prepare_fenced(
                        credential=credential, subject=subject, holder=holder,
                        draft=draft, expected_anchor=anchor,
                        installation_id=installed.installation_id)
                elif method == "model_admit_dispatch_once_v1":
                    from ..model_broker.broker import ModelCallRequest
                    intent = model_from_wire(command["intent"], ModelEgressIntentV1)
                    request = model_from_wire(command["request"], ModelCallRequest)
                    anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                    if not any(peer == credential.certificate_sha256
                               and profile == profile_id and role == request.envelope.authority.namespace
                               and mapped == namespace
                               for (peer, profile, role), mapped in self._namespace_bindings_v2.items()):
                        raise AuthorityUnavailable("model request namespace differs")
                    record, permit = model.admit_dispatch_once(
                        credential=credential, subject=subject, holder=holder,
                        intent=intent, expected_anchor=anchor, request=request)
                else:
                    intent = model_from_wire(command["intent"], ModelEgressIntentV1)
                    record, permit = model.recover_fenced(
                        credential=credential, subject=subject, intent=intent)
                    if permit.holder != holder:
                        raise AuthorityUnavailable("model recovery holder differs")
                return {"record": model_to_wire(record), "permit": to_wire(permit)}
            if method in {"current_owner_actor_binding_v1",
                          "current_owner_principal_binding_v1"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                pairings = self._v2_owner_pairings
                if installed is None or pairings is None:
                    raise AuthorityUnavailable("Owner actor binding service is unavailable")
                if method == "current_owner_actor_binding_v1":
                    if set(command) != {"namespace", "actor_id"}:
                        raise AuthorityUnavailable("Owner actor query fields differ")
                    binding = pairings.current_actor_binding(
                        authority_namespace=namespace,
                        installation_id=installed.installation_id,
                        actor_id=identifier(command["actor_id"], "actor_id"))
                else:
                    if set(command) != {"namespace", "principal"}:
                        raise AuthorityUnavailable("Owner principal query fields differ")
                    raw = command["principal"]
                    principal = owner_from_wire(raw)
                    if type(principal) is not OwnerPrincipalV1 or owner_to_wire(principal) != raw:
                        raise AuthorityUnavailable("Owner principal query differs")
                    binding = pairings.current_principal_binding(
                        authority_namespace=namespace,
                        installation_id=installed.installation_id,
                        principal=principal)
                if (binding is not None
                        and (binding.authority_id != self._authority_id()
                             or binding.installation_id != installed.installation_id
                             or namespace_ref(binding.namespace) != namespace)):
                    raise AuthorityUnavailable("Owner actor binding identity differs")
                return {"binding": None if binding is None else owner_to_wire(binding)}
            if method == "describe_owner_session_v1":
                if set(command) != {"namespace", "token"}:
                    raise AuthorityUnavailable("Owner session description fields differ")
                namespace = identifier(command["namespace"], "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                sessions = self._v2_owner_sessions
                if installed is None or sessions is None:
                    raise AuthorityUnavailable("Owner session service is unavailable")
                request = sessions.describe_current(
                    transport_credential=credential, token=command["token"],
                    namespace=namespace, installation_id=installed.installation_id)
                return {"request": session_to_wire(request)}
            if method in {"begin_owner_session_v1", "accept_owner_session_v1",
                          "current_owner_session_v1", "logout_owner_session_v1",
                          "revoke_all_owner_sessions_v1", "revoke_owner_session_key_v1"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                sessions = self._v2_owner_sessions
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if sessions is None or installed is None:
                    raise AuthorityUnavailable("Owner session service is unavailable")
                required = ({"namespace", "request"} if method == "begin_owner_session_v1"
                            else {"namespace", "challenge", "signature"}
                            if method == "accept_owner_session_v1"
                            else {"namespace", "request", "token"})
                if set(command) != required:
                    raise AuthorityUnavailable("Owner session command fields differ")
                field = "challenge" if method == "accept_owner_session_v1" else "request"
                raw = command[field]
                decoded = session_from_wire(raw)
                expected = (OwnerSessionLoginChallengeV1 if field == "challenge"
                            else OwnerSessionLoginRequestV1)
                if type(decoded) is not expected or session_to_wire(decoded) != raw:
                    raise AuthorityUnavailable("Owner session command is not canonical")
                request = decoded.request if type(decoded) is OwnerSessionLoginChallengeV1 else decoded
                if (request.authority_id != self._authority_id()
                        or request.authority_namespace != namespace
                        or request.installation_id != installed.installation_id):
                    raise AuthorityUnavailable("Owner session installation identity differs")
                if method == "begin_owner_session_v1":
                    challenge = sessions.begin_login(
                        transport_credential=credential, request=request)
                    return {"challenge": session_to_wire(challenge)}
                if method == "accept_owner_session_v1":
                    signature = self._owner_proof_signature(command["signature"])
                    token = sessions.accept_login(
                        transport_credential=credential, challenge=decoded,
                        signature=signature)
                    return {"token": token}
                token = command["token"]
                if method == "current_owner_session_v1":
                    sessions.require_current(
                        transport_credential=credential, token=token, request=request)
                    return {"current": True}
                if method == "logout_owner_session_v1":
                    sessions.logout(
                        transport_credential=credential, token=token, request=request)
                elif method == "revoke_all_owner_sessions_v1":
                    sessions.revoke_all(
                        transport_credential=credential, token=token, request=request)
                else:
                    sessions.revoke_credential(
                        transport_credential=credential, token=token, request=request)
                return {"revoked": True}
            if method in {"register_owner_credential_v1", "begin_owner_proof_v1",
                          "accept_owner_proof_v1", "get_owner_proof_v1"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                proofs = self._v2_owner_proofs
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if proofs is None or installed is None:
                    raise AuthorityUnavailable("Owner proof service is unavailable")
                required = {
                    "register_owner_credential_v1": {"namespace", "registration", "rotation_signature"},
                    "begin_owner_proof_v1": {"namespace", "request", "operation"},
                    "accept_owner_proof_v1": {"namespace", "challenge", "signature"},
                    "get_owner_proof_v1": {"namespace", "operation"},
                }[method]
                if set(command) != required:
                    raise AuthorityUnavailable("Owner proof command fields differ")

                def proof_value(field: str, expected: type):
                    raw = command[field]
                    decoded = proof_from_wire(raw)
                    if type(decoded) is not expected or proof_to_wire(decoded) != raw:
                        raise AuthorityUnavailable("Owner proof command is not canonical")
                    return decoded

                def owner_operation() -> OwnerAuthorizationOperationV1:
                    raw = command["operation"]
                    decoded = owner_from_wire(raw)
                    if (type(decoded) is not OwnerAuthorizationOperationV1
                            or owner_to_wire(decoded) != raw
                            or decoded.authority_id != self._authority_id()
                            or decoded.installation_id != installed.installation_id
                            or namespace_ref(decoded.namespace) != namespace
                            or self._namespace_bindings_v2.get((
                                credential.certificate_sha256, profile_id,
                                decoded.namespace)) != namespace):
                        raise AuthorityUnavailable("Owner proof operation identity differs")
                    return decoded

                if method == "register_owner_credential_v1":
                    registration = proof_value("registration", OwnerCredentialRegistrationV1)
                    if (registration.authority_id != self._authority_id()
                            or registration.authority_namespace != namespace
                            or registration.installation_id != installed.installation_id):
                        raise AuthorityUnavailable("Owner credential identity differs")
                    signature_hex = command["rotation_signature"]
                    if signature_hex is not None:
                        signature = self._owner_proof_signature(signature_hex)
                    else:
                        signature = None
                    registered = proofs.register_credential(
                        transport_credential=credential, registration=registration,
                        rotation_signature=signature)
                    return {"registration": proof_to_wire(registered)}
                if method == "begin_owner_proof_v1":
                    operation = owner_operation()
                    request = proof_value("request", OwnerProofRequestV1)
                    if request.installation_id != installed.installation_id:
                        raise AuthorityUnavailable("Owner proof installation differs")
                    challenge = proofs.begin_challenge(
                        transport_credential=credential, request=request,
                        operation=operation)
                    return {"challenge": proof_to_wire(challenge)}
                if method == "accept_owner_proof_v1":
                    challenge = proof_value("challenge", OwnerProofChallengeV1)
                    request = challenge.request
                    if (request.authority_id != self._authority_id()
                            or request.authority_namespace != namespace
                            or request.installation_id != installed.installation_id):
                        raise AuthorityUnavailable("Owner challenge identity differs")
                    signature = self._owner_proof_signature(command["signature"])
                    acceptance = proofs.accept_proof(
                        transport_credential=credential,
                        challenge=challenge, signature=signature)
                    return {"acceptance": proof_to_wire(acceptance)}
                operation = owner_operation()
                acceptance = proofs.get_accepted_for_operation(
                    transport_credential=credential, operation=operation)
                return {"acceptance": None if acceptance is None else proof_to_wire(acceptance)}
            if method == "get_current_owner_guard_for_fence":
                base_fields = {"namespace", "permit"}
                owner_fields = {"owner_actor_id", "owner_session_token",
                                "owner_session_request"}
                if set(command) not in (base_fields, base_fields | owner_fields):
                    raise AuthorityUnavailable("owner guard command fields differ")
                namespace = identifier(command["namespace"], "namespace")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                tickets = self._v2_owner_tickets
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if tickets is None or installed is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2
                        or permit.operation not in {"read", "write"}
                        or permit.namespace != namespace or permit.subject != subject):
                    raise AuthorityUnavailable("owner guard read requires a content fence")
                owner_kwargs = {}
                if owner_fields <= set(command):
                    actor = identifier(command["owner_actor_id"], "owner_actor_id")
                    session_kwargs = self._owner_session_kwargs(
                        command, namespace, installed.installation_id)
                    owner_kwargs = {
                        "owner_actor_id": actor,
                        "owner_session_token": session_kwargs["session_token"],
                        "owner_session_request": session_kwargs["session_request"],
                    }
                current = service.validate_fence(
                    credential=credential, subject=subject, permit=permit)
                guard = tickets.get_current_guard(
                    credential=credential, authority_namespace=namespace,
                    installation_id=installed.installation_id,
                    subject=subject, permit=current, **owner_kwargs)
                if guard is not None and (
                    type(guard) is not OwnerAuthorizationGuardV1
                    or guard.authority_id != self._authority_id()
                    or guard.installation_id != installed.installation_id
                    or namespace_ref(guard.namespace) != namespace
                    or self._namespace_bindings_v2.get((
                        credential.certificate_sha256, profile_id,
                        guard.namespace)) != namespace
                ):
                    raise AuthorityUnavailable("owner guard identity mismatch")
                return {"guard": None if guard is None else owner_to_wire(guard),
                        "permit": to_wire(current)}
            if method in {"register_owner_ticket", "reserve_owner_issue",
                          "finalize_owner_issue"}:
                namespace = identifier(command.get("namespace"), "namespace")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                tickets = self._v2_owner_tickets
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if tickets is None or installed is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                expected = ({"namespace", "ticket"} if method == "register_owner_ticket"
                            else {"namespace", "operation", "proof"}
                            if method == "finalize_owner_issue"
                            else {"namespace", "operation"})
                session_fields = {"owner_session_token", "owner_session_request"}
                if set(command) != expected and not (
                        method != "register_owner_ticket"
                        and set(command) == expected | session_fields):
                    raise AuthorityUnavailable("owner command is invalid")
                field = "ticket" if method == "register_owner_ticket" else "operation"
                raw = command[field]
                value = owner_from_wire(raw)
                if owner_to_wire(value) != raw:
                    raise AuthorityUnavailable("owner command is not canonical")
                required_type = (OwnerClaimTicketV1 if field == "ticket"
                                 else OwnerAuthorizationOperationV1)
                if (type(value) is not required_type
                        or value.authority_id != self._authority_id()
                        or (method != "register_owner_ticket"
                            and value.installation_id != installed.installation_id)
                        or namespace_ref(value.namespace) != namespace
                        or self._namespace_bindings_v2.get((
                            credential.certificate_sha256, profile_id,
                            value.namespace)) != namespace):
                    raise AuthorityUnavailable("owner command identity mismatch")
                if method == "register_owner_ticket":
                    ticket = tickets.register_ticket(
                        credential=credential, authority_namespace=namespace,
                        ticket=value)
                    return {"ticket": owner_to_wire(ticket)}
                if method == "reserve_owner_issue":
                    session_kwargs = self._owner_session_kwargs(
                        command, namespace, installed.installation_id)
                    receipt = tickets.reserve_issue(
                        credential=credential, authority_namespace=namespace,
                        operation=value, **session_kwargs)
                    return {"receipt": owner_to_wire(receipt)}
                raw_proof = command["proof"]
                proof = owner_from_wire(raw_proof)
                if (type(proof) is not OwnerGraphCommitProofV1
                        or owner_to_wire(proof) != raw_proof):
                    raise AuthorityUnavailable("owner graph proof is invalid")
                # This is only a candidate. Store invokes its trusted, independent
                # graph verifier and rechecks the Authority snapshot before CAS.
                receipt = tickets.finalize_issue(
                    credential=credential, authority_namespace=namespace,
                    operation=value, proof=proof,
                    **self._owner_session_kwargs(
                        command, namespace, installed.installation_id))
                return {"receipt": owner_to_wire(receipt)}
            if method == "get_pending_owner_issue_for_graph_write" and set(command) == {
                    "namespace", "operation_id", "permit"}:
                namespace = identifier(command["namespace"], "namespace")
                operation_id = identifier(command["operation_id"], "operation_id")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                if self._v2_owner_tickets is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2 or permit.operation != "write"
                        or permit.namespace != namespace or permit.subject != subject):
                    raise AuthorityUnavailable("owner graph read requires a write fence")
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if installed is None:
                    raise AuthorityUnavailable("installation is unavailable")
                service.validate_fence(
                    credential=credential, subject=subject, permit=permit)
                receipt = self._v2_owner_tickets.get_pending_for_graph_write(
                    credential=credential, authority_namespace=namespace,
                    operation_id=operation_id, installation_id=installed.installation_id,
                    subject=subject, permit=permit)
                return {"receipt": None if receipt is None else owner_to_wire(receipt)}
            if method == "get_pending_owner_issue" and (
                    set(command) == {"namespace", "operation_id"}
                    or set(command) == {"namespace", "operation_id",
                                        "owner_session_token", "owner_session_request"}):
                namespace = identifier(command["namespace"], "namespace")
                operation_id = identifier(command["operation_id"], "operation_id")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                if self._v2_owner_tickets is None:
                    raise AuthorityUnavailable("owner ticket service is unavailable")
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if installed is None:
                    raise AuthorityUnavailable("installation is unavailable")
                receipt = self._v2_owner_tickets.get_pending(
                    credential=credential, authority_namespace=namespace,
                    operation_id=operation_id,
                    **self._owner_session_kwargs(
                        command, namespace, installed.installation_id))
                if receipt is not None and (
                    type(receipt) is not OwnerAuthorizationReceiptV1
                    or receipt.phase != "pending"
                    or receipt.operation.operation_id != operation_id
                    or receipt.operation.authority_id != self._authority_id()
                ):
                    raise AuthorityUnavailable("owner receipt identity mismatch")
                return {"receipt": None if receipt is None else owner_to_wire(receipt)}
            if method in {"reserve_owner_revoke", "finalize_owner_revoke",
                          "get_pending_owner_revoke", "get_committed_owner_revoke",
                          "get_pending_owner_revoke_for_graph_write"}:
                namespace = identifier(command.get("namespace"), "namespace")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                tickets = self._v2_owner_tickets
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if tickets is None or installed is None:
                    raise AuthorityUnavailable("owner revoke service is unavailable")
                session_fields = {"owner_session_token", "owner_session_request"}
                if method in {"reserve_owner_revoke", "finalize_owner_revoke"}:
                    expected = ({"namespace", "operation", "proof"}
                                if method == "finalize_owner_revoke"
                                else {"namespace", "operation"})
                    if set(command) not in (expected, expected | session_fields):
                        raise AuthorityUnavailable("owner revoke command fields differ")
                    raw = command["operation"]
                    operation = owner_from_wire(raw)
                    if (type(operation) is not OwnerAuthorizationOperationV1
                            or owner_to_wire(operation) != raw
                            or operation.action != "revoke"
                            or operation.authority_id != self._authority_id()
                            or operation.installation_id != installed.installation_id
                            or namespace_ref(operation.namespace) != namespace
                            or self._namespace_bindings_v2.get((
                                credential.certificate_sha256, profile_id,
                                operation.namespace)) != namespace):
                        raise AuthorityUnavailable("owner revoke identity differs")
                    kwargs = self._owner_session_kwargs(
                        command, namespace, installed.installation_id)
                    if method == "reserve_owner_revoke":
                        receipt = tickets.reserve_revoke(
                            credential=credential, authority_namespace=namespace,
                            operation=operation, **kwargs)
                    else:
                        raw_proof = command["proof"]
                        proof = owner_from_wire(raw_proof)
                        if (type(proof) is not OwnerGraphCommitProofV1
                                or owner_to_wire(proof) != raw_proof):
                            raise AuthorityUnavailable("owner revoke graph proof differs")
                        receipt = tickets.finalize_revoke(
                            credential=credential, authority_namespace=namespace,
                            operation=operation, proof=proof, **kwargs)
                    if (type(receipt) is not OwnerAuthorizationReceiptV1
                            or receipt.operation != operation
                            or receipt.phase != ("pending" if method ==
                                "reserve_owner_revoke" else "committed")):
                        raise AuthorityUnavailable("owner revoke receipt differs")
                    return {"receipt": owner_to_wire(receipt)}
                if method == "get_pending_owner_revoke_for_graph_write":
                    if set(command) != {"namespace", "operation_id", "permit"}:
                        raise AuthorityUnavailable("owner revoke graph read fields differ")
                    permit = from_wire(command["permit"])
                    if (type(permit) is not FencePermitV2 or permit.operation != "write"
                            or permit.namespace != namespace or permit.subject != subject):
                        raise AuthorityUnavailable("owner revoke graph read needs write fence")
                    service.validate_fence(
                        credential=credential, subject=subject, permit=permit)
                    receipt = tickets.get_revoke_pending_for_graph_write(
                        credential=credential, authority_namespace=namespace,
                        operation_id=identifier(command["operation_id"], "operation_id"),
                        installation_id=installed.installation_id,
                        subject=subject, permit=permit)
                else:
                    expected = {"namespace", "operation_id"}
                    if set(command) not in (expected, expected | session_fields):
                        raise AuthorityUnavailable("owner revoke read fields differ")
                    read = (tickets.get_revoke_pending if method ==
                            "get_pending_owner_revoke" else tickets.get_revoke_committed)
                    receipt = read(
                        credential=credential, authority_namespace=namespace,
                        operation_id=identifier(command["operation_id"], "operation_id"),
                        **self._owner_session_kwargs(
                            command, namespace, installed.installation_id))
                if receipt is not None and (
                        type(receipt) is not OwnerAuthorizationReceiptV1
                        or receipt.operation.action != "revoke"
                        or receipt.operation.operation_id != command["operation_id"]
                        or receipt.operation.authority_id != self._authority_id()
                        or receipt.operation.installation_id != installed.installation_id
                        or namespace_ref(receipt.operation.namespace) != namespace
                        or receipt.phase != ("committed" if method ==
                            "get_committed_owner_revoke" else "pending")):
                    raise AuthorityUnavailable("owner revoke read identity differs")
                return {"receipt": None if receipt is None else owner_to_wire(receipt)}
            if method == "begin_dispatch_fence" and set(command) == {
                    "namespace", "holder", "operation_id", "expected_anchor",
                    "effect_id", "command_digest", "footprint"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                footprint = self._dispatch_footprint(command["footprint"])
                permit = service.begin_fence(
                    credential=credential, subject=subject, holder=command["holder"],
                    operation="dispatch", operation_id=command["operation_id"],
                    expected_anchor=anchor, effect_id=command["effect_id"],
                    command_digest=command["command_digest"], footprint=footprint)
                return {"permit": to_wire(permit)}
            if method == "execution_read_current_effect" and set(command) == {
                    "namespace", "effect_id"}:
                namespace = identifier(command["namespace"], "namespace")
                effect_id = identifier(command["effect_id"], "effect_id")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                return asdict(self._v2_execution[namespace].read_current_effect(
                    credential=credential, subject=subject, effect_id=effect_id))
            if method == "execution_read_current_observation_receipt_v1" and set(command) == {
                    "namespace", "effect_id"}:
                namespace = identifier(command["namespace"], "namespace")
                effect_id = identifier(command["effect_id"], "effect_id")
                self._bound_v2_service(credential, profile_id, manifest_digest, namespace)
                receipt = self._v2_execution[namespace].read_current_observation_receipt_v1(
                    credential=credential, subject=subject, effect_id=effect_id)
                return {"receipt": to_wire(receipt)}
            if method == "execution_read_current_effect_snapshot_for_write_fence" and set(command) == {
                    "permit"}:
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2 or permit.operation != "write"
                        or to_wire(permit) != command["permit"]):
                    raise AuthorityUnavailable("canonical ordinary write permit required")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, permit.namespace)
                snapshot = self._v2_execution[
                    permit.namespace].read_current_effect_snapshot_for_write_fence(
                        credential=credential, subject=subject, permit=permit)
                return {"snapshot": to_wire(snapshot)}
            if method == "execution_prepare" and set(command) == {
                    "permit", "mutation_id", "footprint"}:
                permit = from_wire(command["permit"])
                if type(permit) is not FencePermitV2 or permit.operation != "dispatch":
                    raise AuthorityUnavailable("dispatch permit required")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, permit.namespace)
                footprint = self._dispatch_footprint(command["footprint"])
                receipt, updated = self._v2_execution[permit.namespace].execution_prepare(
                    credential=credential, subject=subject, permit=permit,
                    mutation_id=command["mutation_id"], footprint=footprint)
                return {"receipt": to_wire(receipt), "permit": to_wire(updated)}
            if method in ("execution_claim", "execution_claim_v2") and set(command) == {
                    "prepared_receipt", "binding"}:
                prepared = from_wire(command["prepared_receipt"])
                binding = from_wire(command["binding"])
                if (type(prepared) is not MutationReceiptV2
                        or prepared.pending.phase != "prepared"
                        or type(binding) is not (
                            ExecutionBindingV2 if method == "execution_claim_v2"
                            else ExecutionBindingV1)
                        or to_wire(prepared) != command["prepared_receipt"]
                        or to_wire(binding) != command["binding"]
                        or binding.permit != prepared.pending.permit
                        or binding.permit.subject != subject):
                    raise AuthorityUnavailable("prepared execution claim identity is invalid")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, binding.namespace)
                claim = (self._v2_execution[binding.namespace].execution_claim_v2
                         if method == "execution_claim_v2"
                         else self._v2_execution[binding.namespace].execution_claim)
                receipt, updated = claim(
                    credential=credential, subject=subject,
                    prepared_receipt=prepared, binding=binding)
                return {"receipt": to_wire(receipt), "permit": to_wire(updated)}
            if method in ("execution_begin_handoff", "execution_begin_handoff_v2") and set(command) == {
                    "claimed_receipt", "handoff_id"}:
                claimed = from_wire(command["claimed_receipt"])
                handoff_id = identifier(command["handoff_id"], "handoff_id")
                if (type(claimed) is not MutationReceiptV2
                        or claimed.pending.phase != "claimed"
                        or claimed.durable_state != "committed"
                        or type(claimed.pending.binding) is not (
                            ExecutionBindingV2 if method == "execution_begin_handoff_v2"
                            else ExecutionBindingV1)
                        or claimed.pending.permit.subject != subject):
                    raise AuthorityUnavailable("committed claim required")
                namespace = claimed.pending.permit.namespace
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                if method == "execution_begin_handoff_v2":
                    installed = self._installations_v2.get(
                        (credential.certificate_sha256, profile_id))
                    if (installed is None or installed.installation_id
                            != self._v2_execution[namespace]._owner_installation_id):
                        raise AuthorityUnavailable(
                            "handoff installation differs from pinned Owner authority")
                begin = (self._v2_execution[namespace].begin_handoff_v2
                         if method == "execution_begin_handoff_v2"
                         else self._v2_execution[namespace].begin_handoff)
                start = begin(
                    credential=credential, subject=subject,
                    claimed_receipt=claimed, handoff_id=handoff_id)
                return {"start": start.to_wire()}
            if method == "execution_observe_v2" and set(command) == {
                    "claimed_receipt", "observation"}:
                claimed = from_wire(command["claimed_receipt"])
                observation = from_wire(command["observation"])
                if (type(claimed) is not MutationReceiptV2
                        or claimed.pending.phase != "claimed"
                        or claimed.durable_state != "committed"
                        or type(claimed.pending.binding) is not ExecutionBindingV2
                        or type(observation) is not PlatformObservationV2
                        or observation.binding != claimed.pending.binding
                        or claimed.pending.permit.subject != subject
                        or to_wire(observation) != command["observation"]):
                    raise AuthorityUnavailable("V2 platform observation identity differs")
                namespace = claimed.pending.permit.namespace
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, namespace)
                receipt, updated = self._v2_execution[namespace].execution_observe_v2(
                    credential=credential, subject=subject,
                    claimed_receipt=claimed, observation=observation)
                return {"receipt": to_wire(receipt), "permit": to_wire(updated)}
            if method == "execution_read_current_dispatch_handoff" and set(command) == {
                    "start", "claimed_receipt"}:
                start = HandoffStartV2.from_wire(command["start"])
                claimed = from_wire(command["claimed_receipt"])
                if (type(claimed) is not MutationReceiptV2
                        or type(claimed.pending.binding) is not ExecutionBindingV2
                        or start.namespace != claimed.pending.permit.namespace
                        or claimed.pending.permit.subject != subject):
                    raise AuthorityUnavailable("V2 current handoff claim differs")
                self._bound_v2_service(
                    credential, profile_id, manifest_digest, start.namespace)
                installed = self._installations_v2.get(
                    (credential.certificate_sha256, profile_id))
                if (installed is None or installed.installation_id
                        != self._v2_execution[start.namespace]._owner_installation_id):
                    raise AuthorityUnavailable("current handoff installation differs")
                permit, anchor, effect = self._v2_execution[
                    start.namespace].read_current_dispatch_handoff(
                        credential=credential, subject=subject,
                        start=start, claimed_receipt=claimed)
                return {"permit": to_wire(permit),
                        "anchor": self._anchor_payload(anchor),
                        "effect": asdict(effect)}
            if method == "current_anchor" and set(command) == {"namespace"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                return self._anchor_payload(service.current_anchor(
                    credential=credential, subject=subject))
            if method == "begin_fence" and set(command) == {
                    "namespace", "holder", "operation", "operation_id", "expected_anchor"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                operation = command["operation"]
                if (type(operation) is not str
                        or operation not in _V2_REMOTE_CONTENT_OPERATIONS):
                    raise AuthorityUnavailable("content fence unavailable")
                anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                permit = service.begin_fence(
                    credential=credential, subject=subject, holder=command["holder"],
                    operation=operation, operation_id=command["operation_id"],
                    expected_anchor=anchor)
                return {"permit": to_wire(permit)}
            if method == "reject_unbegun_content_fence_v2" and set(command) == {
                    "namespace", "holder", "generation", "operation_id",
                    "expected_anchor", "request_id", "request_digest"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                installed = self._installations_v2[
                    (credential.certificate_sha256, profile_id)]
                if command["holder"] != installed.administrator_holder:
                    raise AuthorityUnavailable("installed write holder differs")
                anchor = self._anchor_from_command({"anchor": command["expected_anchor"]})
                receipt = service.reject_unbegun_content_fence_v2(
                    credential=credential, subject=subject,
                    installation_id=installed.installation_id,
                    holder=command["holder"], generation=command["generation"],
                    operation_id=command["operation_id"],
                    expected_anchor=anchor, request_id=command["request_id"],
                    request_digest=command["request_digest"])
                return {"receipt": to_wire(receipt)}
            if method == "get_fence_operation" and set(command) == {
                    "namespace", "operation_id"}:
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, command["namespace"])
                permit, state = service.get_fence_operation(
                    credential=credential, subject=subject,
                    operation_id=command["operation_id"])
                return {"permit": to_wire(permit), "state": state}
            if method == 'read_contact_finished_original_v3' and set(command)=={'permit'}:
                from .contact_fence_finished_v3 import contact_finished_to_wire_v3
                permit=from_wire(command['permit'])
                if type(permit) is not FencePermitV2 or permit.operation!='write':
                    raise AuthorityUnavailable('Contact original write permit required')
                service=self._bound_v2_service(credential,profile_id,manifest_digest,permit.namespace)
                original=service.read_contact_finished_original_v3(credential=credential,subject=subject,permit=permit)
                return {'original':contact_finished_to_wire_v3(original)}
            if method == "validate_fence" and set(command) == {"permit"}:
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2
                        or permit.operation not in _V2_REMOTE_CONTENT_OPERATIONS):
                    raise AuthorityUnavailable("content fence required")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, permit.namespace)
                return {"permit": to_wire(service.validate_fence(
                    credential=credential, subject=subject, permit=permit))}
            if method == "finish_fence" and set(command) == {
                    "permit", "request_id", "request_digest"}:
                permit = from_wire(command["permit"])
                if (type(permit) is not FencePermitV2
                        or permit.operation not in _V2_REMOTE_CONTENT_OPERATIONS):
                    raise AuthorityUnavailable("content fence required")
                service = self._bound_v2_service(
                    credential, profile_id, manifest_digest, permit.namespace)
                service.finish_fence(
                    credential=credential, subject=subject, permit=permit,
                    request_id=command["request_id"],
                    request_digest=command["request_digest"])
                return {"finished": True}
        except OwnerAuthorizationBarrier as exc:
            if method == "execution_begin_handoff_v2":
                raise
            raise RuntimeError("authority unavailable") from exc
        except PlatformObservationVerifierUnavailable as exc:
            if method == "execution_begin_handoff_v2":
                raise
            raise RuntimeError("authority unavailable") from exc
        except (AuthorityUnavailable, TypeError, ValueError) as exc:
            raise RuntimeError("authority unavailable") from exc
        raise RuntimeError("authority unavailable")

    @staticmethod
    def _owner_proof_signature(value: object) -> bytes:
        if (type(value) is not str or len(value) != 128
                or any(char not in "0123456789abcdef" for char in value)):
            raise AuthorityUnavailable("Owner signature encoding differs")
        return bytes.fromhex(value)

    def install_current_c09_maintenance_v1(self, maintenance):
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        if (type(maintenance) is not InstalledC09MaintenanceV1
                or maintenance.core is not self._core
                or getattr(self, "_c09_maintenance_v1", None) is not None):
            raise AuthorityUnavailable("installed C09 RPC maintenance binding differs")
        self._c09_maintenance_v1 = maintenance
        self._c09_process_incarnation_v1 = "authority-process-" + secrets.token_hex(24)

    def _dispatch(self, method, request, credential, channel_binding: bytes, *,
                  handshake_binding: str | None = None, command: object = None):
        maintenance = getattr(self, "_c09_maintenance_v1", None)
        wire = (_WireRequest(request.profile_id, request.plugin_name,
                request.host_api_version, request.publisher_package.manifest_sha256)
                if hasattr(request, "publisher_package") else _WireRequest.from_value(request))
        peer = (credential.certificate_sha256, wire.profile_id)
        installation = self._installations_v2.get(peer)
        lifecycle = tuple(service for service in getattr(
            self, "_d12_installation_lifecycle_services_v1", {}).values()
            if installation is not None and service.peer == peer
            and service.installation_id == installation.installation_id
            and installation.manifest_digest == wire.manifest_sha256)
        # These paired routes carry no general content authority. Their own
        # dispatchers still verify exact current signed Owner/session or actual
        # supervised process birth, package, storage and resume original.
        management_methods = {
            "d12_installation_control_v1", "d12_lifecycle_host_bootstrap_v1",
            "d12_package_maintenance_v2",
            "d12_read_operation_v1", "d12_resolve_operation_v1",
            "begin_owner_session_v1", "accept_owner_session_v1",
            "describe_owner_session_v1", "current_owner_session_v1",
            "logout_owner_session_v1",
        }
        management = bool(lifecycle) and method in management_methods
        if management and (type(command) is not dict or command.get("namespace") not in
                           {service.namespace for service in lifecycle}):
            raise AuthorityUnavailable("independent lifecycle management scope differs")
        enrollment = method in {"handshake", "installation_grant_v2", "c09_storage_maintenance_v1"}
        with ExitStack() as stack:
            if not management and not enrollment:
                for service in lifecycle:
                    stack.enter_context(service.rpc_activity_v1())
            if maintenance is not None and not management and not enrollment:
                stack.enter_context(maintenance.gate.admit_peer_v1(peer=peer))
            return self._dispatch_admitted(method, request, credential, channel_binding,
                handshake_binding=handshake_binding, command=command)

    def _dispatch_admitted(self, method, request, credential, channel_binding: bytes, *,
                  handshake_binding: str | None = None,
                  command: object = None) -> dict[str, object]:
        """Internal RPC core; public dispatch supplies only verified mTLS peers."""
        if hasattr(request, "publisher_package"):
            wire = _WireRequest(
                request.profile_id, request.plugin_name, request.host_api_version,
                request.publisher_package.manifest_sha256,
            )
        else:
            wire = _WireRequest.from_value(request)
        binding = self._binding(channel_binding, wire)
        self._authorize(credential, wire)
        peer = credential.certificate_sha256
        if method == "handshake":
            self._prune_sessions()
            self._sessions[binding] = (
                time.monotonic(), peer, hashlib.sha256(_canonical(wire.payload())).hexdigest()
            )
            return {
                "state": "paired",
                "installation_authority_id": self._authority_id(),
                "installation_identity_ref": "mtls:sha256:" + peer,
                "channel_binding_sha256": binding,
                "publisher_trusted": True,
            }
        if handshake_binding != binding:
            raise RuntimeError("authority unavailable")
        self._paired_session(binding, peer, wire)
        if method == "c09_storage_maintenance_v1":
            maintenance = getattr(self, "_c09_maintenance_v1", None)
            if (maintenance is None or wire.protocol != AUTHORITY_V2_PROTOCOL
                    or type(command) is not dict or set(command) != {"action", "operation_id"}
                    or command["action"] not in {"status", "resume"}
                    or self._namespace_bindings_v2.get((peer, wire.profile_id, maintenance.namespace_id)) != maintenance.closure.namespace):
                raise AuthorityUnavailable("installed C09 maintenance request differs")
            operation_id = command["operation_id"]
            identifier(operation_id, "operation_id")
            installed = self._installations_v2[(peer, wire.profile_id)]
            if installed.installation_id != maintenance.control.installation_id:
                raise AuthorityUnavailable("C09 maintenance installation differs")
            maintenance.core._require(credential, "execution_redaction_install", maintenance.closure.namespace)
            context = maintenance.control.read_verified_current_storage_v1()
            with maintenance.control._db() as db:
                current = maintenance.control._current(db)
                if (current["stage"] not in {"READY", "RELEASED"}
                        and current["active_operation_id"] not in {None, operation_id}):
                    raise AuthorityUnavailable("C09 other operation currently active")
            if command["action"] == "resume":
                context = maintenance.resume_storage_maintenance_v1(operation_id=operation_id)
            return {"schema": "sylanne3.c09.maintenance-status.v1", "operation_id": operation_id,
                "stage": context.stage, "manifest_digest": context.manifest_digest,
                "pointer_version": context.pointer_version, "storage_generation": context.storage_generation,
                "restart_required": maintenance.restart_required,
                "channel_binding_sha256": binding}
        if method == "migration_v2":
            if wire.protocol != AUTHORITY_V2_PROTOCOL or self._v2_migration_rpc is None:
                raise RuntimeError("authority migration route unavailable")
            result = self._v2_migration_rpc.handle(
                credential=credential, profile_id=wire.profile_id,
                channel_binding_sha256=binding, command=command,
            )
            return {**result, "channel_binding_sha256": binding}
        if method == "installation_grant_v2":
            if wire.protocol != AUTHORITY_V2_PROTOCOL or command != {}:
                raise RuntimeError("authority unavailable")
            installed = self._installations_v2.get((peer, wire.profile_id))
            if installed is None or installed.manifest_digest != wire.manifest_sha256:
                raise RuntimeError("authority unavailable")
            return asdict(InstallationGrantV2(
                authority_id=self._authority_id(),
                subject="mtls:sha256:" + peer,
                administrator_holder=installed.administrator_holder,
                installation_id=installed.installation_id,
                manifest_digest=wire.manifest_sha256,
                publisher_policy_ref=installed.publisher_policy_ref,
                service_capability_version=installed.service_capability_version,
                channel_binding_sha256=binding,
            ))
        if method == "ingress_clock_sample_v2":
            if wire.protocol != AUTHORITY_V2_PROTOCOL or type(command) is not dict or command:
                raise RuntimeError("authority unavailable")
            installed = self._installations_v2.get((peer, wire.profile_id))
            if (installed is None or installed.manifest_digest != wire.manifest_sha256
                    or installed.source_id is None or self._clock_provider is None):
                raise RuntimeError("authority unavailable")
            try:
                reading = self._clock_provider()
                if (type(reading) is not AuthorityClockReadingV2
                        or reading.source_id != installed.source_id
                        or reading.healthy is not True
                        or reading.utc_error_seconds > installed.max_utc_error_seconds):
                    raise RuntimeError("authority unavailable")
                sample = IngressClockSampleV2(
                    authority_id=self._authority_id(),
                    installation_id=installed.installation_id,
                    source_id=reading.source_id,
                    utc_seconds=reading.utc_seconds,
                    monotonic_seconds=reading.monotonic_seconds,
                    epoch=reading.epoch,
                    utc_error_seconds=reading.utc_error_seconds,
                )
            except Exception as exc:
                raise RuntimeError("authority unavailable") from exc
            return {**asdict(sample), "channel_binding_sha256": binding}
        if method in {"namespace_bootstrap", "namespace_genesis"}:
            if (wire.protocol != AUTHORITY_V2_PROTOCOL or type(command) is not dict
                    or set(command) != ({"namespace"} if method == "namespace_bootstrap"
                                        else {"namespace", "request_id"})
                    or type(command["namespace"]) is not dict
                    or set(command["namespace"]) != {"bot_id", "persona_id"}):
                raise RuntimeError("authority unavailable")
            installed = self._installations_v2.get((peer, wire.profile_id))
            if installed is None or installed.manifest_digest != wire.manifest_sha256:
                raise RuntimeError("authority unavailable")
            try:
                namespace_id = NamespaceId(**command["namespace"])
            except (TypeError, ValueError) as exc:
                raise RuntimeError("authority unavailable") from exc
            namespace = self._namespace_bindings_v2.get((peer, wire.profile_id, namespace_id))
            if namespace is None:
                raise RuntimeError("authority unavailable")
            service = self._v2_service(namespace)
            if method == "namespace_genesis":
                result = service.activate_namespace(
                    credential=credential, subject="mtls:sha256:" + peer,
                    holder=installed.administrator_holder,
                    namespace_id=namespace_id, request_id=command["request_id"],
                )
            else:
                result = service.namespace_bootstrap(
                    credential=credential, subject="mtls:sha256:" + peer,
                    namespace_id=namespace_id,
                )
            if (type(result) is not NamespaceBootstrapV2
                    or result.authority_id != self._authority_id()
                    or result.namespace != namespace_id
                    or result.authority_namespace != namespace):
                raise RuntimeError("authority unavailable")
            return {**asdict(result), "channel_binding_sha256": binding}
        if method == "capability_grant":
            if command is not None:
                raise RuntimeError("authority unavailable")
            return {
                "grant_id": secrets.token_hex(16),
                "authority_id": self._authority_id(),
                "installation_identity_ref": "mtls:sha256:" + peer,
                "capabilities": list(_ENROLLMENT_CAPABILITIES),
                "channel_binding_sha256": binding,
            }
        result = (self._v2_command(
            method, credential, wire.profile_id, wire.manifest_sha256, command)
                  if wire.protocol == AUTHORITY_V2_PROTOCOL else
                  self._content_command(method, credential, command))
        from .first_owner_reverse_v1 import _PreparedFirstOwnerIssueV1
        if type(result) is _PreparedFirstOwnerIssueV1:
            result.channel_binding = binding
            return result
        if type(result) is _DeferredWorkerDelivery:
            result.payload["channel_binding_sha256"] = binding
            return result
        result["channel_binding_sha256"] = binding
        return result

    def dispatch(self, method, request, credential, channel_binding: bytes, *,
                 handshake_binding: str | None = None,
                 command: object = None) -> dict[str, object]:
        """Production RPC entrypoint; only an mTLS peer reaches authorization."""
        if not isinstance(credential, MtlsPeerCredential):
            raise RuntimeError("mTLS peer credential required")
        return self._dispatch(
            method, request, credential, channel_binding,
            handshake_binding=handshake_binding,
            command=command,
        )

    def _dispatch_for_test(self, method, request, credential: MtlsPeerCredential,
                           channel_binding: bytes, *,
                           handshake_binding: str | None = None,
                           command: object = None) -> dict[str, object]:
        """Private deterministic seam; tests still provide an mTLS-shaped peer."""
        if not isinstance(credential, MtlsPeerCredential):
            raise TypeError("MtlsPeerCredential is required for test dispatch")
        return self._dispatch(
            method, request, credential, channel_binding,
            handshake_binding=handshake_binding,
            command=command,
        )

    async def _dispatch_on_worker(self, method, request, credential, binding,
                                  handshake_binding, command, *, _first_owner_phase=False) -> dict[str, object]:
        if method == 'first_owner_issue_v1' and not _first_owner_phase:
            if self._worker_closed or self._first_owner_closing_v1 or not self._first_owner_slot_v1.acquire(blocking=False):
                raise RuntimeError('first Owner orchestration unavailable')
            task = asyncio.create_task(self._run_first_owner_pipeline_v1(
                method,request,credential,binding,handshake_binding,command))
            self._first_owner_tasks_v1.add(task)
            def completed(done):
                self._first_owner_tasks_v1.discard(done)
                self._first_owner_slot_v1.release()
                if not done.cancelled():done.exception()
            task.add_done_callback(completed)
            return await asyncio.shield(task)
        # Release only when the concurrent future actually completes. Cancelling
        # the awaiting connection does not release a still-running service call.
        with self._worker_lock:
            if self._worker_closed or not self._worker_slots.acquire(blocking=False):
                raise RuntimeError("authority unavailable")
            try:
                future = self._worker.submit(
                    self.dispatch, method, request, credential, binding,
                    handshake_binding=handshake_binding, command=command,
                )
            except Exception:
                self._worker_slots.release()
                raise
            future.add_done_callback(lambda _: self._worker_slots.release())
        wrapped = asyncio.wrap_future(future)
        try:
            return await asyncio.shield(wrapped)
        except asyncio.CancelledError:
            # The synchronous worker may still complete after the TLS caller
            # disappears. Release only its in-process handoff reservation.
            def abandoned(done):
                try:
                    result = done.result()
                    if type(result) is _DeferredWorkerDelivery:
                        result.abandon()
                except Exception:
                    pass
            future.add_done_callback(abandoned)
            raise

    async def _run_first_owner_pipeline_v1(self,method,request,credential,binding,handshake_binding,command):
        from .first_owner_reverse_v1 import _PreparedFirstOwnerIssueV1,_await_actual_completion_v1
        preparing=asyncio.create_task(self._dispatch_on_worker(method,request,credential,binding,
            handshake_binding,command,_first_owner_phase=True))
        try:
            prepared=await _await_actual_completion_v1(preparing)
        except asyncio.CancelledError:
            if not preparing.cancelled() and preparing.exception() is None:
                abandoned=preparing.result()
                if type(abandoned) is _PreparedFirstOwnerIssueV1:abandoned.close()
            raise
        if type(prepared) is dict:
            return prepared  # Exact already-finalized original, no new Graph call.
        if type(prepared) is not _PreparedFirstOwnerIssueV1:
            raise RuntimeError('actual first Owner prepared continuation unavailable')
        try:
            return await self._finish_first_owner_pipeline_v1(prepared)
        finally:
            prepared.close()

    async def _finish_first_owner_pipeline_v1(self,prepared):
        from .first_owner_reverse_v1 import _await_actual_completion_v1
        reverse=asyncio.create_task(asyncio.to_thread(prepared.reverse_call))
        proof=await _await_actual_completion_v1(reverse)
        # Return finalization to the original serialized worker; no general
        # parallel Authority writer pool and no externally callable finalize.
        with self._worker_lock:
            if self._worker_closed or not self._worker_slots.acquire(blocking=False):
                raise RuntimeError('first Owner finalization unavailable; replay same operation')
            try:
                future = self._worker.submit(prepared.finalize,proof)
            except BaseException:
                self._worker_slots.release()
                raise
            future.add_done_callback(lambda _:self._worker_slots.release())
        return await _await_actual_completion_v1(asyncio.wrap_future(future))

    async def aclose(self) -> None:
        """Stop accepting dispatches and wait for submitted service work to finish.

        Deployment closes its asyncio listener first, then awaits this method.
        Closing the listener alone does not own the RPC worker's lifecycle.
        """
        # First-Owner reverse waits need the ordinary worker for Host callbacks.
        # Drain their bounded tasks before retiring that worker or its stores.
        self._first_owner_closing_v1 = True
        pending = tuple(self._first_owner_tasks_v1)
        if pending:
            await asyncio.shield(asyncio.gather(*pending, return_exceptions=True))
        async with self._worker_close_lock:
            if self._worker_shutdown_task is None:
                with self._worker_lock:
                    self._worker_closed = True
                self._worker_shutdown_task = asyncio.create_task(
                    asyncio.to_thread(self._worker.shutdown, wait=True)
                )
            shutdown = self._worker_shutdown_task
        await asyncio.shield(shutdown)

    async def serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        *, timeout_seconds: float, max_message_bytes: int,
    ) -> None:
        ssl_object = writer.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        binding = ssl_object.get_channel_binding("tls-unique") if ssl_object else None
        if not certificate or not binding:
            writer.close()
            await writer.wait_closed()
            return
        credential = MtlsPeerCredential(hashlib.sha256(certificate).hexdigest())
        try:
            while True:
                line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout_seconds)
                if len(line) > max_message_bytes:
                    raise RuntimeError("authority unavailable")
                payload = json.loads(line)
                if not isinstance(payload, dict) or set(payload) - {
                    "protocol", "request_id", "method", "request", "handshake_binding_sha256",
                    "command"
                }:
                    raise RuntimeError("authority unavailable")
                if (payload.get("protocol") not in (AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL)
                        or not isinstance(payload.get("request_id"), str)
                        or not isinstance(payload.get("method"), str)):
                    raise RuntimeError("authority unavailable")
                result = None
                try:
                    if (type(payload.get("request")) is not dict
                            or payload["request"].get("protocol") != payload["protocol"]):
                        raise RuntimeError("authority unavailable")
                    result = await self._dispatch_on_worker(
                        payload["method"], payload.get("request"), credential, binding,
                        payload.get("handshake_binding_sha256"), payload.get("command"),
                    )
                    response = {"request_id": payload["request_id"], "ok": True,
                                "result": (result.payload if type(result) is _DeferredWorkerDelivery
                                           else result)}
                except Exception as exc:
                    if (payload["method"] == "execution_begin_handoff_v2"
                            and type(exc) is OwnerAuthorizationBarrier):
                        response = {"request_id": payload["request_id"],
                                    "ok": False, "error": "owner_authorization_barrier"}
                    elif (payload["method"] == "execution_begin_handoff_v2"
                          and type(exc) is PlatformObservationVerifierUnavailable):
                        response = {"request_id": payload["request_id"],
                                    "ok": False,
                                    "error": "platform_observation_verifier_unavailable"}
                    else:
                        response = {"request_id": payload["request_id"],
                                    **self.error_payload(exc)}
                try:
                    encoded = _canonical(response)
                    if len(encoded) + 1 > max_message_bytes:
                        raise RuntimeError("authority unavailable")
                    writer.write(encoded + b"\n")
                    await asyncio.wait_for(writer.drain(), timeout_seconds)
                except BaseException:
                    if response["ok"] is True and type(result) is _DeferredWorkerDelivery:
                        result.abandon()
                    raise
                maintenance = getattr(self, "_c09_maintenance_v1", None)
                if maintenance is not None and maintenance.restart_required:
                    self.c09_restart_requested_v1.set()
                    break
                if response["ok"] is True and type(result) is _DeferredWorkerDelivery:
                    if type(result.delivery) is TerminalC02RecoveryDeliveryV1:
                        # Local writer.drain() does not prove that the pinned host
                        # consumed the result. Only its ACK on this mTLS channel,
                        # after parsing the exact response, can finish the fact.
                        try:
                            ack_line = await asyncio.wait_for(
                                reader.readuntil(b"\n"), timeout_seconds)
                            if len(ack_line) > max_message_bytes:
                                raise RuntimeError("terminal C02 ACK exceeds limit")
                            ack = json.loads(ack_line)
                            expected = {
                                "kind": "terminal_c02_recovery_drain_ack_v1",
                                "request_id": payload["request_id"],
                                "channel_binding_sha256":
                                    result.payload["channel_binding_sha256"],
                                "response_digest": hashlib.sha256(encoded).hexdigest(),
                                "original_key_digest":
                                    result.delivery.request.original_key.digest,
                                "read_request_digest": result.delivery.request.digest,
                            }
                            if type(ack) is not dict or ack != expected:
                                raise RuntimeError("terminal C02 transport ACK differs")
                        except BaseException:
                            result.abandon()
                            raise
                        fact = await asyncio.shield(asyncio.to_thread(result.finish))
                        terminal_response = {
                            "request_id": payload["request_id"], "ok": True,
                            "result": {
                                "read_fact": terminal_c02_to_wire(fact),
                                "channel_binding_sha256":
                                    result.payload["channel_binding_sha256"],
                            },
                        }
                        final_bytes = _canonical(terminal_response)
                        if len(final_bytes) + 1 > max_message_bytes:
                            raise RuntimeError("terminal C02 fact exceeds limit")
                        writer.write(final_bytes + b"\n")
                        await asyncio.wait_for(writer.drain(), timeout_seconds)
                    else:
                        await asyncio.shield(asyncio.to_thread(result.finish))
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, RuntimeError,
                TimeoutError, TypeError, ValueError, ConnectionError):
            pass
        finally:
            maintenance = getattr(self, "_c09_maintenance_v1", None)
            if maintenance is not None and maintenance.restart_required:
                # SWITCHED is durable even when the acknowledgement was lost.
                # Do not leave the old process alive holding retired caches.
                self.c09_restart_requested_v1.set()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(
        self, host: str, port: int, config: AuthorityServerTlsConfig,
    ) -> asyncio.AbstractServer:
        if type(config.max_message_bytes) is not int or not 512 <= config.max_message_bytes <= 1_048_576:
            raise ValueError("authority message limit is invalid")
        if not isinstance(config.timeout_seconds, (int, float)) or not 0 < config.timeout_seconds <= 30:
            raise ValueError("authority timeout is invalid")
        return await asyncio.start_server(
            lambda reader, writer: self.serve_connection(
                reader, writer, timeout_seconds=float(config.timeout_seconds),
                max_message_bytes=config.max_message_bytes,
            ),
            host, port, ssl=config.ssl_context(), ssl_handshake_timeout=config.timeout_seconds,
            limit=config.max_message_bytes,
        )


__all__ = ("AdministratorInstallationV2", "AuthorityRpcServer",
           "AuthorityServerTlsConfig", "MtlsPeerCredential")
