"""Synchronous graph-worker bridge to the authenticated v2 Authority channel."""

from __future__ import annotations

import asyncio
from .model_workflows_v3 import AdminModelWorkflowsV3
from .model_workflows_v4 import AdminModelWorkflowsV4
from .model_workflows_v5 import AdminModelWorkflowsV5
from .model_workflows_v6 import AdminModelWorkflowsV6
from .model_workflows_v7 import AdminModelWorkflowsV7
from .model_workflows_v8 import AdminModelWorkflowsV8
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import asdict, dataclass
from weakref import WeakSet
import hashlib
import math
from threading import Event, RLock, Thread
import time
from typing import Awaitable, Callable, Coroutine, Mapping, TypeVar

from ..authority_service.contract import CONTENT_OPERATIONS, identifier
from ..authority_service.final_handoff_pairing import FinalHandoffPairingV1
from ..authority_service.v2_clock import IngressClockSampleV2
from ..authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, ExecutionBindingV1, ExecutionBindingV2,
    FencePermitV2, FenceNeverBegunReceiptV2, MutationReceiptV2,
    DeletionMutationReceiptV1,
    PlatformObservationV2,
    SCHEMA as AUTHORITY_V2_PROTOCOL,
    canonical_digest as authority_canonical_digest,
)
from ..authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerClaimTicketV1, OwnerGraphCommitProofV1,
    OwnerActorBindingV1, OwnerPrincipalV1,
)
from ..authority_service.v2_owner_proof import (
    OwnerCredentialRegistrationV1, OwnerProofAcceptanceV1,
    OwnerProofChallengeV1, OwnerProofRequestV1,
)
from ..authority_service.v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1,
)
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2, HandoffStartV2
from ..runtime_contracts import namespace_ref
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (
    FenceScope, InstallationGrantV2, NamespaceBootstrapV2, NamespaceId, NamespaceRuntimeState,
    RecoveryConstraintFootprint,
)
from .authority_client import AuthorityHandshake, AuthorityProvisioningRequest
from .authority_profile import AdminIngressClockPolicy
from .installation_grant_identity import same_installed_grant_identity_v2
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport


_T = TypeVar("_T")
_CONTENT_OPERATIONS = CONTENT_OPERATIONS - {"dispatch"}
_REPAIRABLE_ERRORS = frozenset({
    "authority handshake channel is unavailable",
    "authority transport unavailable",
    "authority service unavailable",
})


class V2FenceOutcomeUnknown(RuntimeError):
    """The Authority may have committed a request whose response was lost."""


@dataclass(frozen=True, slots=True)
class VerifiedIngressClockV2:
    """Paired Authority sample bounded at the end of a local monotonic round trip."""

    sample: IngressClockSampleV2
    monotonic_before_seconds: float
    monotonic_after_seconds: float
    utc_upper_bound_seconds: float


_CLOCK_ORIGINAL_ISSUER_V4 = object()
_CLOCK_ORIGINALS_V4 = WeakSet()


class _VerifiedIngressClockOriginalV4:
    """Only the successful paired port check can issue this transient original."""
    def __init__(self, issuer, *, port, reading, policy, prior, next_watermark):
        if issuer is not _CLOCK_ORIGINAL_ISSUER_V4:
            raise TypeError("actual paired clock verification required")
        self.port, self.reading, self.policy = port, reading, policy
        self.prior, self.next_watermark = prior, next_watermark
        self.uses = []
        self.used = False
        _CLOCK_ORIGINALS_V4.add(self)

    def upper_for(self, purpose):
        from ..runtime.first_ingress_v2 import trusted_upper_at_v4
        if (self not in _CLOCK_ORIGINALS_V4 or self.used
                or purpose not in {"natural_basis", "natural_dispatch"}):
            raise RuntimeError("actual natural clock consumer required")
        monotonic_now = time.monotonic()
        upper = trusted_upper_at_v4(self.reading, monotonic_now)
        self.uses.append({"purpose": purpose, "monotonic_now": monotonic_now,
                          "utc_upper": upper})
        return upper

    def consume_for(self, *, port, reading, policy, basis_now):
        if (self not in _CLOCK_ORIGINALS_V4 or self.used or self.port is not port
                or self.reading is not reading or self.policy != policy
                or not self.uses or self.uses[0]["purpose"] != "natural_basis"
                or self.uses[0]["utc_upper"] != basis_now
                or any(use["purpose"] != "natural_dispatch" for use in self.uses[1:])):
            raise RuntimeError("natural clock original crossed its actual port/reading/consumer")
        names = ("source_id", "epoch", "source_monotonic", "local_after", "lower")
        value = {
            "schema": "sylanne.natural-clock-validation.v4",
            "authority_id": reading.sample.authority_id,
            "installation_id": reading.sample.installation_id,
            "sample": asdict(reading.sample), "policy": asdict(policy),
            "monotonic_before": reading.monotonic_before_seconds,
            "monotonic_after": reading.monotonic_after_seconds,
            "prior_watermark": None if self.prior is None else dict(zip(names, self.prior, strict=True)),
            "next_watermark": dict(zip(names, self.next_watermark, strict=True)),
            "utc_upper": reading.utc_upper_bound_seconds,
        }
        uses = tuple(dict(use) for use in self.uses)
        self.used = True
        _CLOCK_ORIGINALS_V4.discard(self)
        return value, uses


@dataclass
class _PendingBegin:
    namespace: NamespaceId
    authority_namespace: str
    holder: str
    generation: int
    operation: str
    operation_id: str
    expected_anchor: RestoreAnchor
    permit: FencePermitV2 | None = None

    @property
    def finish_identity(self) -> tuple[str, str]:
        digest = hashlib.sha256(
            ("sylanne3.abandoned_begin.v2:" + self.operation_id).encode("utf-8")
        ).hexdigest()
        return "abandoned-" + digest[:32], "sha256:" + digest


@dataclass(frozen=True)
class _PendingFinish:
    scope: FenceScope
    request_id: str
    request_digest: str


@dataclass(frozen=True)
class _NaturalPaidConsumerBinding:
    graph: object
    bundle: object
    grant: InstallationGrantV2
    adapters: tuple[object, object, object, object]
    generation: object
    review: object
    executor_method: object
    provider_check_method: object


class V2FencePort:
    """Use only on a dedicated graph worker, never on an asyncio loop thread.

    The port creates and owns its transport, event loop, TLS session and worker
    thread. Namespace identity is checked against the Authority's authenticated
    mapping on each call, rather than accepted from the graph caller.
    """

    def __init__(
        self,
        request: AuthorityProvisioningRequest,
        profiles: Mapping[str, AuthorityTlsProfile],
        installation_grant: InstallationGrantV2,
        *,
        transport_factory: Callable[[Mapping[str, AuthorityTlsProfile]], MtlsAuthorityTransport] = MtlsAuthorityTransport,
    ) -> None:
        self._reject_event_loop()
        if type(request) is not AuthorityProvisioningRequest:
            raise TypeError("AuthorityProvisioningRequest is required")
        profile = profiles.get(request.profile_id)
        if type(profile) is not AuthorityTlsProfile:
            raise ValueError("request profile is not installed")
        if type(installation_grant) is not InstallationGrantV2:
            raise TypeError("verified InstallationGrantV2 is required")
        if (installation_grant.authority_id != profile.expected_authority_id
                or installation_grant.manifest_digest != request.publisher_package.manifest_sha256):
            raise RuntimeError("installation grant does not match the installed profile or package")
        self._request = request
        self._installation_grant = installation_grant
        self._timeout = 4 * profile.timeout_seconds + 1
        self._lock = RLock()
        self._ready = Event()
        self._loop = asyncio.new_event_loop()
        self._transport = transport_factory(profiles)
        self._handshake: AuthorityHandshake | None = None
        self._grant: InstallationGrantV2 | None = None
        self._mapped_namespaces: dict[NamespaceId, str] = {}
        self._pending_begin: _PendingBegin | None = None
        self._pending_finish: _PendingFinish | None = None
        self._natural_paid_consumer_binding: _NaturalPaidConsumerBinding | None = None
        # Process-local lower UTC bound at the last accepted source monotonic sample.
        # Keep it across session repair; a new port process has no durable watermark.
        self._clock_watermark: tuple[str, str, float, float, float] | None = None
        self._closed = False
        self._thread = Thread(target=self._run_loop, name="sylanne-v2-authority", daemon=True)
        self._thread.start()
        self._ready.wait()
        try:
            self._submit(self._pair())
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _reject_event_loop() -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        raise RuntimeError("synchronous v2 fence port cannot run on an event loop thread")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.close()

    def _submit(self, coroutine: Coroutine[object, object, _T]) -> _T:
        try:
            self._reject_event_loop()
        except RuntimeError:
            coroutine.close()
            raise
        with self._lock:
            if self._closed:
                coroutine.close()
                raise RuntimeError("v2 fence port is closed")
            future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
            try:
                return future.result(timeout=self._timeout)
            except FutureTimeout as exc:
                future.cancel()
                raise V2FenceOutcomeUnknown(
                    "v2 authority result unknown after timeout; reconcile or retry only "
                    "with the original operation_id or finish request_id and digest"
                ) from exc

    async def _pair(self) -> None:
        self._handshake = None
        self._grant = None
        self._mapped_namespaces.clear()
        handshake = await self._transport.handshake(self._request, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await self._transport.installation_grant_v2(self._request, handshake)
        if not handshake.valid_pairing() or grant.channel_binding_sha256 != handshake.channel_binding_sha256:
            raise RuntimeError("v2 authority pairing is invalid")
        original = self._installation_grant
        for field in (
            "authority_id", "subject", "administrator_holder", "installation_id",
            "manifest_digest", "publisher_policy_ref", "service_capability_version", "schema",
        ):
            if getattr(grant, field) != getattr(original, field):
                raise RuntimeError("v2 authority installation identity changed")
        self._handshake = handshake
        self._grant = grant

    async def _with_session_repair(self, call: Callable[[], Awaitable[_T]]) -> _T:
        """Replay the same command once after session expiry or transport loss."""
        try:
            return await call()
        except RuntimeError as exc:
            if str(exc) not in _REPAIRABLE_ERRORS:
                raise
        await self._pair()
        return await call()

    def _identity(self) -> tuple[AuthorityHandshake, InstallationGrantV2]:
        if self._handshake is None or self._grant is None:
            raise RuntimeError("v2 authority pairing is unavailable")
        return self._handshake, self._grant

    @property
    def installation_grant(self) -> InstallationGrantV2:
        """The current paired grant, whose installation facts match the installed profile."""
        self._reject_event_loop()
        with self._lock:
            _, grant = self._identity()
            return grant

    @staticmethod
    def _natural_adapter_specs() -> tuple[tuple[str, type, str], ...]:
        from .natural_generation_content_port import (
            InstalledNaturalGenerationContentPortV2,
        )
        from .natural_generation_output_port import (
            InstalledNaturalGenerationOutputPortV2,
        )
        from .natural_paid_review_port import InstalledNaturalPaidReviewPortV2
        from .natural_review_output_port import InstalledNaturalReviewOutputPortV2

        return (
            ("_GraphCoordinator__natural_generation_output_port",
             InstalledNaturalGenerationOutputPortV2,
             "read_original_natural_generation_output_v2"),
            ("_GraphCoordinator__natural_generation_content_port",
             InstalledNaturalGenerationContentPortV2,
             "read_current_natural_generation_content_v2"),
            ("_GraphCoordinator__natural_review_output_port",
             InstalledNaturalReviewOutputPortV2,
             "read_original_natural_review_output_v2"),
            ("_GraphCoordinator__natural_paid_review_current_port",
             InstalledNaturalPaidReviewPortV2,
             "read_current_natural_paid_review_v2"),
        )

    def _natural_paid_consumer_facts_current(
        self, binding: _NaturalPaidConsumerBinding, *, mapped: bool,
    ) -> bool:
        from ..graph_coordinator import GraphCoordinator
        from .astrbot_model_call import AstrBotModelProvider
        from .authority_client import AuthorityClient
        from .authority_profile import (
            AdminInstallationBundle, AdminModelWorkflowV2,
            AdminModelWorkflowsV2, NATURAL_GENERATION_TEMPLATE_VERSION,
            NATURAL_GENERATION_TEMPLATE_VERSION_V3,
            NATURAL_GENERATION_TEMPLATE_VERSION_V4,
            NATURAL_GENERATION_TEMPLATE_VERSION_V5,
            REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION_V2,
        )
        from .model_egress_executor import HostModelEgressExecutor

        graph, bundle, grant = binding.graph, binding.bundle, binding.grant
        if (self._closed or type(graph) is not GraphCoordinator
                or type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or getattr(graph, "_GraphCoordinator__content_fence_v2", None)
                   is not self
                or type(self._grant) is not InstallationGrantV2
                or not same_installed_grant_identity_v2(
                    grant, self._grant)
                or self._installation_grant != grant
                or self._handshake is None
                or not self._handshake.valid_pairing()
                or self._handshake.channel_binding_sha256
                   != self._grant.channel_binding_sha256
                or bundle.tls_profile.profile_id != self._request.profile_id
                or bundle.tls_profile.expected_authority_id != grant.authority_id
                or bundle.installation_policy.installation_id
                   != grant.installation_id
                or bundle.installation_policy.manifest_digest
                   != grant.manifest_digest
                or type(bundle.model_workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8)
                or type(bundle.model_workflows.natural_generation)
                   is not AdminModelWorkflowV2
                or type(bundle.model_workflows.natural_review)
                   is not AdminModelWorkflowV2
                or bundle.model_workflows.natural_generation
                   is not binding.generation
                or bundle.model_workflows.natural_review is not binding.review
                or (binding.generation.work_kind,
                    binding.generation.purpose,
                    binding.generation.template_version) not in (
                    ("natural_generation", "proposal", NATURAL_GENERATION_TEMPLATE_VERSION),
                    ("natural_generation", "proposal", NATURAL_GENERATION_TEMPLATE_VERSION_V3),
                    ("natural_generation", "proposal", NATURAL_GENERATION_TEMPLATE_VERSION_V4),
                    ("natural_generation", "proposal", NATURAL_GENERATION_TEMPLATE_VERSION_V5))
                or (binding.review.work_kind, binding.review.purpose,
                    binding.review.template_version) not in (
                    ("natural_review", "proposal", REVIEW_TEMPLATE_VERSION),
                    ("natural_review", "proposal", REVIEW_TEMPLATE_VERSION_V2))
                or ((binding.generation.template_version == NATURAL_GENERATION_TEMPLATE_VERSION_V5)
                    != (binding.review.template_version == REVIEW_TEMPLATE_VERSION_V2))
                or HostModelEgressExecutor.execute_frozen_natural_once
                   is not binding.executor_method
                or AstrBotModelProvider._request_allowed
                   is not binding.provider_check_method):
            return False
        policy = bundle.installation_policy
        if mapped and self._mapped_namespaces.get(policy.namespace) != (
                policy.authority_namespace):
            return False
        client = None
        client_grant = None
        loop = None
        for adapter, (name, kind, method_name) in zip(
                binding.adapters, self._natural_adapter_specs(), strict=True):
            owner = getattr(adapter, "__self__", None)
            if (type(owner) is not kind
                    or getattr(adapter, "__func__", None)
                       is not getattr(kind, method_name)
                    or getattr(graph, name, None) != adapter
                    or owner._bundle is not bundle
                    or type(owner._grant) is not InstallationGrantV2
                    or not same_installed_grant_identity_v2(
                        grant, owner._grant)
                    or type(owner._client) is not AuthorityClient
                    or not owner._loop.is_running()):
                return False
            if client is None:
                client, client_grant, loop = (
                    owner._client, owner._grant, owner._loop)
            elif (owner._client is not client or owner._loop is not loop
                  or owner._grant != client_grant):
                return False
        return (client is not None
                and client._selection.profile_id == self._request.profile_id
                and client._v2_request == self._request
                and client._v2_handshake is not None
                and client._v2_handshake.valid_pairing()
                and client._v2_handshake.channel_binding_sha256
                    == client_grant.channel_binding_sha256)

    def bind_natural_paid_consumers_v2(
        self, graph: object, bundle: object, grant: InstallationGrantV2,
    ) -> bool:
        """Bind actual graph readers to the paired installed paid workflow."""
        from .astrbot_model_call import AstrBotModelProvider
        from .model_egress_executor import HostModelEgressExecutor

        adapters = tuple(getattr(graph, name, None) for name, _, _ in
                         self._natural_adapter_specs())
        workflows = getattr(bundle, "model_workflows", None)
        binding = _NaturalPaidConsumerBinding(
            graph, bundle, grant, adapters,
            getattr(workflows, "natural_generation", None),
            getattr(workflows, "natural_review", None),
            HostModelEgressExecutor.execute_frozen_natural_once,
            AstrBotModelProvider._request_allowed)
        with self._lock:
            if not self._natural_paid_consumer_facts_current(
                    binding, mapped=False):
                raise RuntimeError("natural paid consumer installation differs")
            if (self._natural_paid_consumer_binding is not None
                    and self._natural_paid_consumer_binding != binding):
                raise RuntimeError("natural paid consumer already bound")
            self._natural_paid_consumer_binding = binding
            return True

    def _natural_consumer_ready_v2(
        self, *, namespace: NamespaceId, template_version: str,
        stage: str, installation_id: str | None,
        provider_id: str | None, model_id: str | None,
        provider_config_digest: str | None,
    ) -> bool:
        with self._lock:
            binding = self._natural_paid_consumer_binding
            if (binding is None or type(namespace) is not NamespaceId
                    or type(template_version) is not str
                    or not self._natural_paid_consumer_facts_current(
                        binding, mapped=True)):
                return False
            workflow = (binding.generation if stage == "generation"
                        else binding.review)
            if (binding.bundle.installation_policy.namespace != namespace
                    or workflow.template_version != template_version):
                return False
            optional = (installation_id, provider_id, model_id,
                        provider_config_digest)
            if all(value is None for value in optional):
                return True
            return (all(type(value) is str and value for value in optional)
                    and optional == (
                        binding.bundle.installation_policy.installation_id,
                        workflow.provider_id, workflow.model_id,
                        workflow.provider_config_digest))

    def natural_paid_consumer_ready_v2(
        self, *, namespace: NamespaceId, template_version: str,
        installation_id: str | None = None, provider_id: str | None = None,
        model_id: str | None = None,
        provider_config_digest: str | None = None,
    ) -> bool:
        return self._natural_consumer_ready_v2(
            namespace=namespace, template_version=template_version,
            stage="generation", installation_id=installation_id,
            provider_id=provider_id, model_id=model_id,
            provider_config_digest=provider_config_digest)

    def natural_review_paid_consumer_ready_v2(
        self, *, namespace: NamespaceId, template_version: str,
        installation_id: str | None = None, provider_id: str | None = None,
        model_id: str | None = None,
        provider_config_digest: str | None = None,
    ) -> bool:
        return self._natural_consumer_ready_v2(
            namespace=namespace, template_version=template_version,
            stage="review", installation_id=installation_id,
            provider_id=provider_id, model_id=model_id,
            provider_config_digest=provider_config_digest)

    def read_final_handoff_pairing_v1(
        self, *, namespace: str, installation_id: str,
    ) -> FinalHandoffPairingV1:
        """Read P2 configuration through this port's existing paired mTLS session."""
        return self._submit(self._with_session_repair(
            lambda: self._read_final_handoff_pairing_v1(namespace, installation_id)))

    async def _read_final_handoff_pairing_v1(
        self, namespace: str, installation_id: str,
    ) -> FinalHandoffPairingV1:
        handshake, grant = self._identity()
        if installation_id != grant.installation_id:
            raise RuntimeError("final handoff installation differs")
        return await self._transport.read_final_handoff_pairing_v1(
            self._request, handshake,
            namespace=namespace, installation_id=installation_id)

    def read_ingress_clock(self, policy: AdminIngressClockPolicy) -> VerifiedIngressClockV2:
        """Read a bounded Authority clock on the dedicated synchronous graph worker."""
        if type(policy) is not AdminIngressClockPolicy:
            raise RuntimeError("v2 ingress clock policy is unavailable")
        return self._submit(self._with_session_repair(lambda: self._read_ingress_clock(policy)))

    def read_ingress_clock_with_original_v4(self, policy: AdminIngressClockPolicy):
        """Use the same paired validation and preserve its actual prior watermark."""
        if type(policy) is not AdminIngressClockPolicy:
            raise RuntimeError("v2 ingress clock policy is unavailable")
        return self._submit(self._with_session_repair(
            lambda: self._read_ingress_clock(policy, with_original=True)))

    async def _read_ingress_clock(self, policy: AdminIngressClockPolicy, *, with_original=False):
        handshake, grant = self._identity()
        before = time.monotonic()
        sample = await self._transport.ingress_clock_sample_v2(
            self._request, handshake, grant.installation_id)
        after = time.monotonic()
        if (type(sample) is not IngressClockSampleV2
                or sample.authority_id != grant.authority_id
                or sample.installation_id != grant.installation_id
                or sample.source_id != policy.source_id
                or sample.utc_error_seconds > policy.max_utc_error_seconds
                or after < before
                or after - before > policy.max_round_trip_seconds):
            raise RuntimeError("v2 ingress clock response is unqualified")
        upper = math.nextafter(math.fsum((
            sample.utc_seconds, sample.utc_error_seconds, after - before,
        )), math.inf)
        if not math.isfinite(upper):
            raise RuntimeError("v2 ingress clock response is unqualified")
        prior = self._clock_watermark
        lower = math.fsum((sample.utc_seconds, -sample.utc_error_seconds))
        if prior is not None:
            source_id, epoch, source_monotonic, local_after, prior_lower = prior
            if (sample.source_id != source_id or sample.epoch != epoch
                    or sample.monotonic_seconds < source_monotonic
                    or before < local_after):
                raise RuntimeError("v2 ingress clock response is unqualified")
            # Both source monotonic and the gap between local round trips are
            # lower bounds on elapsed time between the two atomic readings.
            elapsed = max(sample.monotonic_seconds - source_monotonic,
                          before - local_after)
            projected_lower = math.fsum((prior_lower, elapsed))
            sample_upper = math.fsum((sample.utc_seconds, sample.utc_error_seconds))
            if (not math.isfinite(projected_lower)
                    or math.nextafter(sample_upper, math.inf) < projected_lower):
                raise RuntimeError("v2 ingress clock response is unqualified")
            lower = max(lower, projected_lower)
        next_watermark = (
            sample.source_id, sample.epoch, sample.monotonic_seconds, after, lower,
        )
        self._clock_watermark = next_watermark
        reading = VerifiedIngressClockV2(sample, before, after, upper)
        if with_original:
            return reading, _VerifiedIngressClockOriginalV4(
                _CLOCK_ORIGINAL_ISSUER_V4, port=self, reading=reading,
                policy=policy, prior=prior, next_watermark=next_watermark)
        return reading

    def provision_namespace(self, *, namespace: NamespaceId,
                            request_id: str) -> NamespaceBootstrapV2:
        """Ask the administrator's paired Authority to create one v2 namespace."""
        with self._lock:
            self.recover_pending_finish()
            self.recover_pending_begin()
            try:
                return self._submit(self._with_session_repair(
                    lambda: self._provision_namespace(namespace, request_id)))
            except RuntimeError as exc:
                if isinstance(exc, V2FenceOutcomeUnknown) or str(exc) in _REPAIRABLE_ERRORS:
                    raise V2FenceOutcomeUnknown(
                        "v2 namespace genesis outcome unknown for request_id=" + request_id
                        + "; retry only with the original request_id"
                    ) from exc
                raise

    async def _provision_namespace(self, namespace: NamespaceId,
                                   request_id: str) -> NamespaceBootstrapV2:
        if type(namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        identifier(request_id, "request_id")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_genesis(
            self._request, handshake, namespace, request_id)
        anchor = observed.anchor if type(observed) is NamespaceBootstrapV2 else None
        if (type(observed) is not NamespaceBootstrapV2
                or observed.namespace != namespace
                or observed.authority_id != grant.authority_id
                or observed.holder != grant.administrator_holder
                or observed.phase != "active"
                or observed.state is not NamespaceRuntimeState.ACTIVE
                or observed.generation != 1
                or observed.blocking_reasons
                or type(anchor) is not RestoreAnchor
                or anchor.authority_id != grant.authority_id
                or anchor.namespace != observed.authority_namespace
                or anchor.activation_generation != 1
                or anchor.deletion_seq != 0 or anchor.deletion_digest != "genesis"
                or anchor.execution_seq != 0 or anchor.execution_digest != "genesis"
                or anchor.revocation_epoch != 0):
            raise RuntimeError("v2 namespace genesis response is invalid")
        return observed

    async def _mapped(self, namespace: NamespaceId, authority_namespace: str):
        if type(namespace) is not NamespaceId or type(authority_namespace) is not str or not authority_namespace:
            raise ValueError("v2 namespace identity is invalid")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_bootstrap(self._request, handshake, namespace)
        if (observed.authority_namespace != authority_namespace
                or observed.authority_id != grant.authority_id
                or observed.state is not NamespaceRuntimeState.ACTIVE
                or observed.anchor is None):
            raise RuntimeError("v2 namespace is not active or mapped")
        self._mapped_namespaces[namespace] = authority_namespace
        return observed

    def current_anchor(self, *, namespace: NamespaceId, authority_namespace: str) -> RestoreAnchor:
        return self._submit(self._with_session_repair(
            lambda: self._current_anchor(namespace, authority_namespace)))

    async def _current_anchor(self, namespace: NamespaceId, authority_namespace: str) -> RestoreAnchor:
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        anchor = await self._transport.v2_current_anchor(self._request, handshake, authority_namespace)
        if anchor.authority_id != grant.authority_id or anchor.namespace != authority_namespace:
            raise RuntimeError("v2 anchor identity mismatch")
        return anchor

    def observe_content_write_attempt_v1(self, *, namespace, authority_namespace, operation_id, expected_anchor):
        """Paired negative or existing attempt facts; absence grants no write permission."""
        return self._submit(self._with_session_repair(lambda: self._observe_content_write_attempt_v1(
            namespace, authority_namespace, operation_id, expected_anchor)))

    async def _observe_content_write_attempt_v1(self, namespace, authority_namespace, operation_id, expected_anchor):
        from ..authority_service.v2_contract import ContentWriteAttemptObservationV1
        identifier(operation_id, "operation_id")
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        observed = await self._transport.v2_observe_content_write_attempt_v1(self._request, handshake,
            namespace=authority_namespace, holder=grant.administrator_holder,
            operation_id=operation_id, expected_anchor=expected_anchor)
        if (type(observed) is not ContentWriteAttemptObservationV1 or observed.current_anchor != expected_anchor
                or (observed.authority_id, observed.namespace, observed.subject, observed.holder, observed.operation_id) != (
                    grant.authority_id, authority_namespace, grant.subject, grant.administrator_holder, operation_id)):
            raise RuntimeError("paired write attempt observation identity differs")
        return observed

    def get_fence_operation(self, *, namespace: NamespaceId,
                            authority_namespace: str,
                            operation_id: str) -> tuple[FencePermitV2, str]:
        """Query a durable own-subject fence through the paired Authority channel."""
        return self._submit(self._with_session_repair(lambda: self._get_fence_operation(
            namespace, authority_namespace, operation_id)))

    async def _get_fence_operation(self, namespace: NamespaceId,
                                   authority_namespace: str,
                                   operation_id: str) -> tuple[FencePermitV2, str]:
        identifier(operation_id, "operation_id")
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        permit, state = await self._transport.v2_get_content_fence_operation(
            self._request, handshake, namespace=authority_namespace,
            operation_id=operation_id)
        if (type(permit) is not FencePermitV2
                or permit.operation not in _CONTENT_OPERATIONS
                or permit.namespace != authority_namespace
                or permit.operation_id != operation_id
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject
                or state not in ("active", "finished")):
            raise RuntimeError("v2 fence status identity mismatch")
        return permit, state

    def read_d13_paid_terminal_fact_v3(self, *, scope, intent):
        """Observe an exact paid terminal through this installation's paired channel."""
        return self._submit(self._with_session_repair(
            lambda: self._read_d13_paid_terminal_fact_v3(scope, intent)))

    async def _read_d13_paid_terminal_fact_v3(self, scope, intent):
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        if (type(scope) is not FenceScope or scope.operation != "read"
                or type(intent) is not ModelEgressIntentV1
                or intent.namespace != scope.authority_namespace):
            raise RuntimeError("D13 terminal observation requires its current exact READ")
        handshake, grant = await self._check_scope(scope)
        if (intent.authority_id, intent.subject) != (grant.authority_id, grant.subject):
            raise RuntimeError("D13 terminal observation crossed the installed model identity")
        if await self._transport.v2_validate_fence(self._request, handshake, scope.permit) != scope.permit:
            raise RuntimeError("D13 terminal observation READ changed")
        result = await self._transport.model_terminal_fact_v2(
            self._request, handshake, grant, namespace=scope.authority_namespace,
            holder=grant.administrator_holder, intent=intent)
        if await self._transport.v2_validate_fence(self._request, handshake, scope.permit) != scope.permit:
            raise RuntimeError("D13 terminal observation READ ended during query")
        return result

    def read_contact_finished_original_v3(self,scope,*,request_id,request_digest):
        """Authenticate exact finished identity and converge only its local ACK."""
        from ..authority_service.contact_fence_finished_v3 import ContactFenceFinishedOriginalV3
        from ..runtime_contracts import canonical_serialize
        with self._lock:
            original=self._submit(self._with_session_repair(lambda:self._read_contact_finished_original_v3(scope)))
            if (type(original) is not ContactFenceFinishedOriginalV3 or original.permit!=scope.permit
                    or (original.finish_request_id,original.finish_request_digest)!=(request_id,request_digest)):
                raise RuntimeError('Contact finished identity differs from its original request; HOLD')
            pending=self._pending_finish
            if pending is not None:
                if canonical_serialize(pending.scope)==canonical_serialize(scope):
                    if (pending.request_id,pending.request_digest)!=(request_id,request_digest):
                        raise RuntimeError('Contact pending ACK has another original finish identity; HOLD')
                    # The protected RPC confirmed this exact original. No
                    # finish RPC or deletion of a durable receipt occurs.
                    self._pending_finish=None
                else:
                    raise RuntimeError('another pending finish blocks Contact finished recovery; HOLD')
            return original

    async def _read_contact_finished_original_v3(self,scope):
        handshake,grant=await self._check_scope(scope)
        original=await self._transport.read_contact_finished_original_v3(self._request,handshake,scope.permit)
        if (original.permit!=scope.permit or original.permit.holder!=scope.permit.holder
                or original.permit.generation!=scope.generation
                or original.permit.pinned_anchor!=scope.pinned_anchor
                or original.permit.authority_id!=grant.authority_id or original.permit.subject!=grant.subject):
            raise RuntimeError('Contact finished original current installation/scope differs')
        return original

    def reject_unbegun_content_fence_v2(
        self, namespace: NamespaceId, authority_namespace: str, *,
        holder: str, generation: int, operation_id: str,
        expected_anchor: RestoreAnchor, request_id: str, request_digest: str,
    ) -> FenceNeverBegunReceiptV2:
        """Request an Authority-atomic tombstone for the original write operation."""
        with self._lock:
            return self._submit(self._with_session_repair(lambda:
                self._reject_unbegun_content_fence_v2(
                    namespace, authority_namespace, holder, generation,
                    operation_id, expected_anchor, request_id, request_digest)))

    async def _reject_unbegun_content_fence_v2(
        self, namespace: NamespaceId, authority_namespace: str,
        holder: str, generation: int, operation_id: str,
        expected_anchor: RestoreAnchor, request_id: str, request_digest: str,
    ) -> FenceNeverBegunReceiptV2:
        identifier(holder, "holder")
        identifier(operation_id, "operation_id")
        identifier(request_id, "request_id")
        if (type(generation) is not int or generation < 0
                or type(expected_anchor) is not RestoreAnchor
                or expected_anchor.namespace != authority_namespace
                or expected_anchor.activation_generation != generation):
            raise ValueError("never-begun fence activation or anchor is invalid")
        observed = await self._mapped(namespace, authority_namespace)
        if (observed.holder != holder or observed.generation != generation
                or observed.anchor != expected_anchor):
            raise RuntimeError("never-begun fence activation or anchor changed")
        handshake, grant = self._identity()
        receipt = await self._transport.v2_reject_unbegun_content_fence_v2(
            self._request, handshake, namespace=authority_namespace,
            holder=holder, generation=generation, operation_id=operation_id,
            expected_anchor=expected_anchor, request_id=request_id,
            request_digest=request_digest)
        if (receipt.installation_id != grant.installation_id
                or receipt.subject != grant.subject
                or receipt.authority_id != grant.authority_id):
            raise RuntimeError("never-begun fence installation mismatch")
        return receipt

    def _owner_identity(self, namespace: NamespaceId, authority_namespace: str,
                        value: OwnerClaimTicketV1 | OwnerAuthorizationOperationV1,
                        *, pairing: bool = False) -> None:
        _, grant = self._identity()
        if (value.namespace != namespace
                or namespace_ref(namespace) != authority_namespace
                or value.authority_id != grant.authority_id
                or (not pairing and value.installation_id != grant.installation_id)):
            raise RuntimeError("v2 owner identity mismatch")

    def _owner_session_identity(self, namespace: NamespaceId,
                                authority_namespace: str,
                                request: OwnerSessionLoginRequestV1) -> None:
        _, grant = self._identity()
        if (type(namespace) is not NamespaceId
                or namespace_ref(namespace) != authority_namespace
                or type(request) is not OwnerSessionLoginRequestV1
                or request.authority_id != grant.authority_id
                or request.authority_namespace != authority_namespace
                or request.installation_id != grant.installation_id):
            raise RuntimeError("v2 Owner session identity mismatch")

    def current_owner_actor_binding(self, *, namespace: NamespaceId,
                                    authority_namespace: str,
                                    actor_id: str) -> OwnerActorBindingV1 | None:
        return self._submit(self._with_session_repair(lambda: self._owner_binding(
            namespace, authority_namespace, actor_id=actor_id)))

    def current_owner_principal_binding(self, *, namespace: NamespaceId,
                                        authority_namespace: str,
                                        principal: OwnerPrincipalV1) -> OwnerActorBindingV1 | None:
        return self._submit(self._with_session_repair(lambda: self._owner_binding(
            namespace, authority_namespace, principal=principal)))

    async def _owner_binding(self, namespace: NamespaceId,
                             authority_namespace: str, *,
                             actor_id: str | None = None,
                             principal: OwnerPrincipalV1 | None = None,
                             ) -> OwnerActorBindingV1 | None:
        if (type(namespace) is not NamespaceId
                or namespace_ref(namespace) != authority_namespace
                or (actor_id is None) == (principal is None)):
            raise ValueError("Owner binding query identity is invalid")
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        if actor_id is not None:
            binding = await self._transport.v2_current_owner_actor_binding(
                self._request, handshake, namespace=authority_namespace,
                actor_id=actor_id)
        else:
            binding = await self._transport.v2_current_owner_principal_binding(
                self._request, handshake, namespace=authority_namespace,
                principal=principal)
        if (binding is not None
                and (binding.authority_id != grant.authority_id
                     or binding.installation_id != grant.installation_id
                     or binding.namespace != namespace
                     or (actor_id is not None and binding.actor_id != actor_id)
                     or (principal is not None and binding.principal != principal))):
            raise RuntimeError("Owner binding installation identity differs")
        return binding

    def begin_owner_session(self, *, namespace: NamespaceId,
                            authority_namespace: str,
                            request: OwnerSessionLoginRequestV1,
                            ) -> OwnerSessionLoginChallengeV1:
        return self._submit(self._with_session_repair(lambda: self._begin_owner_session(
            namespace, authority_namespace, request)))

    async def _begin_owner_session(self, namespace: NamespaceId,
                                   authority_namespace: str,
                                   request: OwnerSessionLoginRequestV1,
                                   ) -> OwnerSessionLoginChallengeV1:
        await self._mapped(namespace, authority_namespace)
        self._owner_session_identity(namespace, authority_namespace, request)
        handshake, _ = self._identity()
        return await self._transport.v2_begin_owner_session(
            self._request, handshake, namespace=authority_namespace,
            login_request=request)

    def accept_owner_session(self, *, namespace: NamespaceId,
                             authority_namespace: str,
                             challenge: OwnerSessionLoginChallengeV1,
                             signature: bytes,
                             session_expires_no_later_than_utc: str | None = None) -> str:
        return self._submit(self._accept_owner_session(
            namespace, authority_namespace, challenge, signature,
            session_expires_no_later_than_utc))

    async def _accept_owner_session(self, namespace: NamespaceId,
                                    authority_namespace: str,
                                    challenge: OwnerSessionLoginChallengeV1,
                                    signature: bytes,
                                    session_expires_no_later_than_utc: str | None = None) -> str:
        await self._mapped(namespace, authority_namespace)
        if type(challenge) is not OwnerSessionLoginChallengeV1:
            raise TypeError("Owner login challenge is required")
        self._owner_session_identity(namespace, authority_namespace, challenge.request)
        handshake, _ = self._identity()
        return await self._transport.v2_accept_owner_session(
            self._request, handshake, namespace=authority_namespace,
            challenge=challenge, signature=signature,
            session_expires_no_later_than_utc=session_expires_no_later_than_utc)

    def current_owner_session(self, *, namespace: NamespaceId,
                              authority_namespace: str,
                              request: OwnerSessionLoginRequestV1, token: str) -> bool:
        return self._submit(self._with_session_repair(lambda: self._owner_session_action(
            "current", namespace, authority_namespace, request, token)))

    def describe_owner_session(self, *, namespace: NamespaceId,
                               authority_namespace: str,
                               token: str) -> OwnerSessionLoginRequestV1:
        return self._submit(self._with_session_repair(lambda: self._describe_owner_session(
            namespace, authority_namespace, token)))

    async def _describe_owner_session(self, namespace: NamespaceId,
                                      authority_namespace: str,
                                      token: str) -> OwnerSessionLoginRequestV1:
        await self._mapped(namespace, authority_namespace)
        handshake, _ = self._identity()
        described = await self._transport.v2_describe_owner_session(
            self._request, handshake, namespace=authority_namespace, token=token)
        self._owner_session_identity(namespace, authority_namespace, described)
        return described

    def installation_management_v1(self, *, namespace, authority_namespace,
                                    operation, owner_token, payload):
        # A lost write response is unknown: do not replay it through repair.
        return self._submit(self._installation_management_v1(namespace, authority_namespace,
            operation, owner_token, payload))

    async def _installation_management_v1(self, namespace, authority_namespace,
                                          operation, owner_token, payload):
        await self._mapped(namespace, authority_namespace)
        handshake, _ = self._identity()
        return await self._transport.v2_installation_management(self._request, handshake,
            namespace=authority_namespace, operation=operation, owner_token=owner_token, payload=payload)

    def installation_management_startup_v1(self, *, namespace, authority_namespace):
        return self._submit(self._installation_management_startup_v1(namespace, authority_namespace))

    async def _installation_management_startup_v1(self, namespace, authority_namespace):
        await self._mapped(namespace, authority_namespace)
        handshake, _ = self._identity()
        return await self._transport.v2_installation_management_startup(self._request, handshake,
            namespace=authority_namespace)

    def logout_owner_session(self, *, namespace: NamespaceId,
                             authority_namespace: str,
                             request: OwnerSessionLoginRequestV1, token: str) -> None:
        self._submit(self._owner_session_action(
            "logout", namespace, authority_namespace, request, token))

    def revoke_all_owner_sessions(self, *, namespace: NamespaceId,
                                  authority_namespace: str,
                                  request: OwnerSessionLoginRequestV1, token: str) -> None:
        self._submit(self._owner_session_action(
            "revoke_all", namespace, authority_namespace, request, token))

    def revoke_owner_session_key(self, *, namespace: NamespaceId,
                                 authority_namespace: str,
                                 request: OwnerSessionLoginRequestV1, token: str) -> None:
        self._submit(self._owner_session_action(
            "revoke_key", namespace, authority_namespace, request, token))

    async def _owner_session_action(self, action: str, namespace: NamespaceId,
                                    authority_namespace: str,
                                    request: OwnerSessionLoginRequestV1,
                                    token: str) -> bool | None:
        await self._mapped(namespace, authority_namespace)
        self._owner_session_identity(namespace, authority_namespace, request)
        handshake, _ = self._identity()
        method = {
            "current": self._transport.v2_current_owner_session,
            "logout": self._transport.v2_logout_owner_session,
            "revoke_all": self._transport.v2_revoke_all_owner_sessions,
            "revoke_key": self._transport.v2_revoke_owner_session_key,
        }[action]
        return await method(
            self._request, handshake, namespace=authority_namespace,
            login_request=request, token=token)

    def register_owner_credential(self, *, namespace: NamespaceId,
                                  authority_namespace: str,
                                  registration: OwnerCredentialRegistrationV1,
                                  rotation_signature: bytes | None = None,
                                  ) -> OwnerCredentialRegistrationV1:
        return self._submit(self._with_session_repair(lambda: self._register_owner_credential(
            namespace, authority_namespace, registration, rotation_signature)))

    async def _register_owner_credential(self, namespace: NamespaceId,
                                         authority_namespace: str,
                                         registration: OwnerCredentialRegistrationV1,
                                         rotation_signature: bytes | None,
                                         ) -> OwnerCredentialRegistrationV1:
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        if (type(registration) is not OwnerCredentialRegistrationV1
                or registration.authority_id != grant.authority_id
                or registration.authority_namespace != authority_namespace
                or registration.installation_id != grant.installation_id):
            raise RuntimeError("v2 Owner credential identity mismatch")
        return await self._transport.v2_register_owner_credential(
            self._request, handshake, namespace=authority_namespace,
            registration=registration, rotation_signature=rotation_signature)

    def begin_owner_proof(self, *, namespace: NamespaceId,
                          authority_namespace: str, request: OwnerProofRequestV1,
                          operation: OwnerAuthorizationOperationV1,
                          ) -> OwnerProofChallengeV1:
        return self._submit(self._with_session_repair(lambda: self._begin_owner_proof(
            namespace, authority_namespace, request, operation)))

    async def _begin_owner_proof(self, namespace: NamespaceId,
                                 authority_namespace: str, request: OwnerProofRequestV1,
                                 operation: OwnerAuthorizationOperationV1,
                                 ) -> OwnerProofChallengeV1:
        await self._mapped(namespace, authority_namespace)
        self._owner_identity(namespace, authority_namespace, operation)
        handshake, grant = self._identity()
        if (type(request) is not OwnerProofRequestV1
                or request.authority_namespace != authority_namespace
                or request.installation_id != grant.installation_id):
            raise RuntimeError("v2 Owner proof identity mismatch")
        request.assert_matches_operation(operation)
        return await self._transport.v2_begin_owner_proof(
            self._request, handshake, namespace=authority_namespace,
            proof_request=request, operation=operation)

    def accept_owner_proof(self, *, namespace: NamespaceId,
                           authority_namespace: str, challenge: OwnerProofChallengeV1,
                           signature: bytes) -> OwnerProofAcceptanceV1:
        return self._submit(self._with_session_repair(lambda: self._accept_owner_proof(
            namespace, authority_namespace, challenge, signature)))

    async def _accept_owner_proof(self, namespace: NamespaceId,
                                  authority_namespace: str,
                                  challenge: OwnerProofChallengeV1,
                                  signature: bytes) -> OwnerProofAcceptanceV1:
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        if (type(challenge) is not OwnerProofChallengeV1
                or challenge.request.authority_id != grant.authority_id
                or challenge.request.authority_namespace != authority_namespace
                or challenge.request.installation_id != grant.installation_id):
            raise RuntimeError("v2 Owner challenge identity mismatch")
        return await self._transport.v2_accept_owner_proof(
            self._request, handshake, namespace=authority_namespace,
            challenge=challenge, signature=signature)

    def get_owner_proof(self, *, namespace: NamespaceId,
                        authority_namespace: str,
                        operation: OwnerAuthorizationOperationV1,
                        ) -> OwnerProofAcceptanceV1 | None:
        return self._submit(self._with_session_repair(lambda: self._get_owner_proof(
            namespace, authority_namespace, operation)))

    async def _get_owner_proof(self, namespace: NamespaceId,
                               authority_namespace: str,
                               operation: OwnerAuthorizationOperationV1,
                               ) -> OwnerProofAcceptanceV1 | None:
        await self._mapped(namespace, authority_namespace)
        self._owner_identity(namespace, authority_namespace, operation)
        handshake, _ = self._identity()
        return await self._transport.v2_get_owner_proof(
            self._request, handshake, namespace=authority_namespace,
            operation=operation)

    def register_owner_ticket(self, *, namespace: NamespaceId,
                              authority_namespace: str,
                              ticket: OwnerClaimTicketV1) -> OwnerClaimTicketV1:
        """Register a separately verified first-creation pairing as this mTLS peer."""
        return self._submit(self._with_session_repair(
            lambda: self._register_owner_ticket(namespace, authority_namespace, ticket)))

    async def _register_owner_ticket(self, namespace: NamespaceId,
                                     authority_namespace: str,
                                     ticket: OwnerClaimTicketV1) -> OwnerClaimTicketV1:
        if type(ticket) is not OwnerClaimTicketV1:
            raise TypeError("owner claim ticket is required")
        await self._mapped(namespace, authority_namespace)
        self._owner_identity(namespace, authority_namespace, ticket, pairing=True)
        handshake, _ = self._identity()
        result = await self._transport.v2_register_owner_ticket(
            self._request, handshake, namespace=authority_namespace, ticket=ticket)
        if result != ticket:
            raise RuntimeError("v2 owner ticket response differs")
        return result

    def reserve_owner_issue(self, *, namespace: NamespaceId,
                            authority_namespace: str,
                            operation: OwnerAuthorizationOperationV1,
                            owner_session_token: str | None = None,
                            owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1:
        return self._submit(self._with_session_repair(
            lambda: self._reserve_owner_issue(
                namespace, authority_namespace, operation,
                owner_session_token, owner_session_request)))

    async def _reserve_owner_issue(self, namespace: NamespaceId,
                                   authority_namespace: str,
                                   operation: OwnerAuthorizationOperationV1,
                                   owner_session_token: str | None,
                                   owner_session_request: OwnerSessionLoginRequestV1 | None,
    ) -> OwnerAuthorizationReceiptV1:
        if type(operation) is not OwnerAuthorizationOperationV1:
            raise TypeError("owner issue operation is required")
        await self._mapped(namespace, authority_namespace)
        self._owner_identity(namespace, authority_namespace, operation)
        if owner_session_request is not None:
            self._owner_session_identity(namespace, authority_namespace, owner_session_request)
        handshake, _ = self._identity()
        result = await self._transport.v2_reserve_owner_issue(
            self._request, handshake, namespace=authority_namespace,
            operation=operation, owner_session_token=owner_session_token,
            owner_session_request=owner_session_request)
        if result.operation != operation or result.phase != "pending":
            raise RuntimeError("v2 owner pending response differs")
        return result

    def finalize_owner_issue(self, *, namespace: NamespaceId,
                             authority_namespace: str,
                             operation: OwnerAuthorizationOperationV1,
                             proof: OwnerGraphCommitProofV1,
                             owner_session_token: str | None = None,
                             owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1:
        return self._submit(self._with_session_repair(
            lambda: self._finalize_owner_issue(
                namespace, authority_namespace, operation, proof,
                owner_session_token, owner_session_request)))

    async def _finalize_owner_issue(self, namespace: NamespaceId,
                                    authority_namespace: str,
                                    operation: OwnerAuthorizationOperationV1,
                                    proof: OwnerGraphCommitProofV1,
                                    owner_session_token: str | None,
                                    owner_session_request: OwnerSessionLoginRequestV1 | None,
    ) -> OwnerAuthorizationReceiptV1:
        if (type(operation) is not OwnerAuthorizationOperationV1
                or type(proof) is not OwnerGraphCommitProofV1):
            raise TypeError("owner issue operation and graph proof are required")
        await self._mapped(namespace, authority_namespace)
        self._owner_identity(namespace, authority_namespace, operation)
        if owner_session_request is not None:
            self._owner_session_identity(namespace, authority_namespace, owner_session_request)
        if (proof.namespace != namespace
                or proof.operation_id != operation.operation_id
                or proof.request_digest != operation.request_digest):
            raise RuntimeError("v2 owner graph proof identity mismatch")
        handshake, _ = self._identity()
        result = await self._transport.v2_finalize_owner_issue(
            self._request, handshake, namespace=authority_namespace,
            operation=operation, proof=proof,
            owner_session_token=owner_session_token,
            owner_session_request=owner_session_request)
        if result.operation != operation or result.phase != "committed":
            raise RuntimeError("v2 owner commit response differs")
        return result

    def reserve_owner_revoke(self, *, namespace: NamespaceId,
                             authority_namespace: str,
                             operation: OwnerAuthorizationOperationV1,
                             owner_session_token: str | None = None,
                             owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1:
        return self._submit(self._with_session_repair(lambda: self._owner_revoke_write(
            namespace, authority_namespace, operation, None,
            owner_session_token, owner_session_request)))

    def finalize_owner_revoke(self, *, namespace: NamespaceId,
                              authority_namespace: str,
                              operation: OwnerAuthorizationOperationV1,
                              proof: OwnerGraphCommitProofV1,
                              owner_session_token: str | None = None,
                              owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1:
        return self._submit(self._with_session_repair(lambda: self._owner_revoke_write(
            namespace, authority_namespace, operation, proof,
            owner_session_token, owner_session_request)))

    async def _owner_revoke_write(
        self, namespace: NamespaceId, authority_namespace: str,
        operation: OwnerAuthorizationOperationV1,
        proof: OwnerGraphCommitProofV1 | None,
        owner_session_token: str | None,
        owner_session_request: OwnerSessionLoginRequestV1 | None,
    ) -> OwnerAuthorizationReceiptV1:
        if (type(operation) is not OwnerAuthorizationOperationV1
                or operation.action != "revoke"
                or proof is not None and type(proof) is not OwnerGraphCommitProofV1):
            raise TypeError("typed owner revoke operation and proof required")
        await self._mapped(namespace, authority_namespace)
        self._owner_identity(namespace, authority_namespace, operation)
        if owner_session_request is not None:
            self._owner_session_identity(
                namespace, authority_namespace, owner_session_request)
        handshake, _ = self._identity()
        if proof is None:
            result = await self._transport.v2_reserve_owner_revoke(
                self._request, handshake, namespace=authority_namespace,
                operation=operation, owner_session_token=owner_session_token,
                owner_session_request=owner_session_request)
        else:
            if (proof.namespace != namespace
                    or proof.operation_id != operation.operation_id
                    or proof.request_digest != operation.request_digest
                    or proof.grant_digest != operation.grant_digest):
                raise RuntimeError("v2 owner revoke graph proof differs")
            result = await self._transport.v2_finalize_owner_revoke(
                self._request, handshake, namespace=authority_namespace,
                operation=operation, proof=proof,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request)
        if (result.operation != operation or result.phase != (
                "pending" if proof is None else "committed")):
            raise RuntimeError("v2 owner revoke response differs")
        return result

    def get_pending_owner_revoke(self, *, namespace: NamespaceId,
                                 authority_namespace: str, operation_id: str,
                                 owner_session_token: str | None = None,
                                 owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1 | None:
        return self._submit(self._with_session_repair(lambda: self._owner_revoke_read(
            namespace, authority_namespace, operation_id, "pending", None,
            owner_session_token, owner_session_request)))

    def get_committed_owner_revoke(self, *, namespace: NamespaceId,
                                   authority_namespace: str, operation_id: str,
                                   owner_session_token: str | None = None,
                                   owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1 | None:
        return self._submit(self._with_session_repair(lambda: self._owner_revoke_read(
            namespace, authority_namespace, operation_id, "committed", None,
            owner_session_token, owner_session_request)))

    def get_pending_owner_revoke_for_graph_write(
        self, *, namespace: NamespaceId, authority_namespace: str,
        operation_id: str, permit: FencePermitV2,
    ) -> OwnerAuthorizationReceiptV1 | None:
        return self._submit(self._with_session_repair(lambda: self._owner_revoke_read(
            namespace, authority_namespace, operation_id, "pending", permit,
            None, None)))

    def get_pending_deletion_for_graph_write(
        self, *, namespace: NamespaceId, authority_namespace: str,
        deletion_operation_id: str, permit: FencePermitV2,
    ) -> DeletionMutationReceiptV1:
        return self._submit(self._with_session_repair(lambda:
            self._pending_deletion_for_graph_write(
                namespace, authority_namespace, deletion_operation_id, permit)))

    async def _pending_deletion_for_graph_write(
        self, namespace: NamespaceId, authority_namespace: str,
        deletion_operation_id: str, permit: FencePermitV2,
    ) -> DeletionMutationReceiptV1:
        # The ordinary namespace bootstrap requires a clear deletion phase.
        # The server checks this installation's exact namespace mapping.
        if (type(namespace) is not NamespaceId
                or namespace_ref(namespace) != authority_namespace):
            raise RuntimeError("deletion graph namespace differs")
        identifier(deletion_operation_id, "deletion_operation_id")
        handshake, grant = self._identity()
        if (type(permit) is not FencePermitV2 or permit.operation != "delete"
                or permit.namespace != authority_namespace
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject):
            raise RuntimeError("deletion graph read permit differs")
        receipt = await self._transport.v2_get_pending_deletion_for_graph_write(
            self._request, handshake, namespace=authority_namespace,
            deletion_operation_id=deletion_operation_id, permit=permit)
        if (type(receipt) is not DeletionMutationReceiptV1
                or receipt.pending.deletion_operation_id != deletion_operation_id
                or receipt.pending.source_phase != "absent"
                or receipt.pending.target_phase != "pending"
                or receipt.pending.permit.operation_id != permit.operation_id
                or receipt.pending.permit.token != permit.token
                or receipt.after_anchor != permit.pinned_anchor
                or receipt.updated_revision != permit.revision):
            raise RuntimeError("deletion graph read receipt differs")
        return receipt

    async def _owner_revoke_read(
        self, namespace: NamespaceId, authority_namespace: str,
        operation_id: str, phase: str, permit: FencePermitV2 | None,
        owner_session_token: str | None,
        owner_session_request: OwnerSessionLoginRequestV1 | None,
    ) -> OwnerAuthorizationReceiptV1 | None:
        identifier(operation_id, "operation_id")
        await self._mapped(namespace, authority_namespace)
        if owner_session_request is not None:
            self._owner_session_identity(
                namespace, authority_namespace, owner_session_request)
        handshake, grant = self._identity()
        if permit is not None:
            if (type(permit) is not FencePermitV2 or permit.operation != "write"
                    or permit.namespace != authority_namespace
                    or permit.authority_id != grant.authority_id
                    or permit.subject != grant.subject):
                raise RuntimeError("v2 owner revoke graph read permit differs")
            result = await self._transport.v2_get_pending_owner_revoke_for_graph_write(
                self._request, handshake, namespace=authority_namespace,
                operation_id=operation_id, permit=permit)
        else:
            read = (self._transport.v2_get_pending_owner_revoke if phase == "pending"
                    else self._transport.v2_get_committed_owner_revoke)
            result = await read(
                self._request, handshake, namespace=authority_namespace,
                operation_id=operation_id,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request)
        if result is not None and (
                type(result) is not OwnerAuthorizationReceiptV1
                or result.phase != phase or result.operation.action != "revoke"
                or result.operation.operation_id != operation_id
                or result.operation.namespace != namespace
                or result.operation.authority_id != grant.authority_id
                or result.operation.installation_id != grant.installation_id):
            raise RuntimeError("v2 owner revoke read identity differs")
        return result

    def get_current_background_owner_authority_for_fence_v1(self, **request):
        from .d12_target_owner_port_v1 import get_current_background_owner_authority_for_fence_v1
        return get_current_background_owner_authority_for_fence_v1(self, **request)

    def admit_conditioned_child_for_fence_v1(self,*,scope,request):
        return self._submit(self._with_session_repair(lambda:self._conditioned_child_v1(
            'conditioned_child_admit_v1',scope=scope,request=request)))

    def read_current_conditioned_child_for_fence_v1(self,*,scope,original_request):
        return self._submit(self._with_session_repair(lambda:self._conditioned_child_v1(
            'conditioned_child_current_v1',scope=scope,request=original_request)))

    async def _conditioned_child_v1(self,method,*,scope,request):
        from ..authority_service.conditioned_child_contract_v1 import (ConditionedChildSelectorV1,
            ConditionedChildEvidenceV1,conditioned_child_fence_operation_id_v1,
            conditioned_child_to_wire_v1,conditioned_child_from_wire_v1)
        from ..authority_service.v2_contract import from_wire,to_wire
        if(type(scope)is not FenceScope or type(request)is not ConditionedChildSelectorV1
                or scope.namespace!=request.namespace):
            raise RuntimeError('conditioned child exact selector and scope namespace differ')
        await self._mapped(scope.namespace,scope.authority_namespace)
        handshake,grant=self._identity();permit=scope.permit
        if(permit.operation!='write'or(permit.authority_id,permit.namespace,permit.subject,permit.holder)!=
                (grant.authority_id,scope.authority_namespace,grant.subject,grant.administrator_holder)
                or request.installation_id!=grant.installation_id
                or permit.operation_id!=conditioned_child_fence_operation_id_v1(request)):
            raise RuntimeError('conditioned child changed its actual paired installation or fresh WRITE permit')
        response=await self._transport._content_rpc(self._request,handshake,method,
            {'namespace':scope.authority_namespace,'permit':to_wire(permit),
                'request':conditioned_child_to_wire_v1(request)},protocol=AUTHORITY_V2_PROTOCOL)
        if set(response)!={'evidence','permit','channel_binding_sha256'}:
            raise RuntimeError('conditioned child paired response fields differ')
        evidence=conditioned_child_from_wire_v1(response['evidence'],ConditionedChildEvidenceV1)
        observed=from_wire(response['permit'])
        if observed!=permit or evidence.selector!=request or evidence.current_self.permit!=permit:
            raise RuntimeError('conditioned child response changed its exact selector, current Self or permit')
        return evidence,observed

    def admit_owner_source_note_task_for_fence_v1(self, *, scope, request):
        return self._submit(self._with_session_repair(lambda: self._owner_source_note_task_v1(
            'owner_source_note_task_admit_v1', scope=scope, request=request)))

    def read_current_owner_source_note_task_for_fence_v1(self, *, scope, original_request):
        return self._submit(self._with_session_repair(lambda: self._owner_source_note_task_v1(
            'owner_source_note_task_current_v1', scope=scope, request=original_request)))

    async def _owner_source_note_task_v1(self, method, *, scope, request):
        from ..authority_service.current_owner_source_note_task_v1 import (OwnerTaskActivityRequestV1, OwnerTaskActivityValuesChildRequestV1,
            OwnerTaskActivityEvidenceV1, owner_task_fence_operation_id_v1,
            owner_task_activity_to_wire_v1, owner_task_activity_from_wire_v1)
        from ..authority_service.v2_contract import from_wire, to_wire
        if (type(scope) is not FenceScope or type(request) not in {OwnerTaskActivityRequestV1,OwnerTaskActivityValuesChildRequestV1}
                or scope.namespace != request.namespace):
            raise RuntimeError('Owner task request/fence namespace differs')
        await self._mapped(scope.namespace, scope.authority_namespace)
        handshake, grant = self._identity()
        permit = scope.permit
        if (permit.operation != 'write' or (permit.authority_id, permit.namespace, permit.subject, permit.holder) !=
                (grant.authority_id, scope.authority_namespace, grant.subject, grant.administrator_holder)
                or request.installation_id != grant.installation_id
                or permit.operation_id != owner_task_fence_operation_id_v1(request)):
            raise RuntimeError('Owner task actual paired installation/Host/write permit differs')
        response = await self._transport._content_rpc(self._request, handshake, method,
            {'namespace': scope.authority_namespace, 'permit': to_wire(permit),
                'request': owner_task_activity_to_wire_v1(request)}, protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {'evidence', 'permit', 'channel_binding_sha256'}:
            raise RuntimeError('Owner task paired response fields differ')
        evidence = owner_task_activity_from_wire_v1(response['evidence'], OwnerTaskActivityEvidenceV1)
        observed = from_wire(response['permit'])
        if observed != permit or evidence.request != request or evidence.current_self.permit != permit:
            raise RuntimeError('Owner task response changed its actual request/permit/Self')
        return evidence, observed

    def admit_foreground_mesh_activity_for_fence_v1(self, *, scope, request):
        from .foreground_mesh_activity_port_v1 import personal_mesh_activity_rpc_v1
        return self._submit(self._with_session_repair(lambda: personal_mesh_activity_rpc_v1(
            self,'foreground_mesh_activity_admit_v1',scope=scope,request=request)))

    def read_current_foreground_mesh_activity_for_fence_v1(self, *, scope, original_request):
        from .foreground_mesh_activity_port_v1 import personal_mesh_activity_rpc_v1
        return self._submit(self._with_session_repair(lambda: personal_mesh_activity_rpc_v1(
            self,'foreground_mesh_activity_current_v1',scope=scope,request=original_request)))

    def admit_owner_task_mesh_activity_for_fence_v1(self, *, scope, request):
        from .foreground_mesh_activity_port_v1 import personal_mesh_activity_rpc_v1
        return self._submit(self._with_session_repair(lambda: personal_mesh_activity_rpc_v1(
            self,'owner_task_mesh_activity_admit_v1',scope=scope,request=request)))

    def read_current_owner_task_mesh_activity_for_fence_v1(self, *, scope, original_request):
        from .foreground_mesh_activity_port_v1 import personal_mesh_activity_rpc_v1
        return self._submit(self._with_session_repair(lambda: personal_mesh_activity_rpc_v1(
            self,'owner_task_mesh_activity_current_v1',scope=scope,request=original_request)))

    def admit_foreground_activity_for_fence_v1(self, *, scope, request):
        return self._submit(self._with_session_repair(lambda: self._foreground_activity_v1(
            "foreground_activity_admit_v1", scope=scope, request=request)))

    def read_current_foreground_activity_for_fence_v1(self, *, scope, original_request):
        return self._submit(self._with_session_repair(lambda: self._foreground_activity_v1(
            "foreground_activity_current_v1", scope=scope, request=original_request)))

    def admit_draft_root_registration_for_fence_v1(self, *, scope, request,
            owner_actor_ref, owner_session_token, owner_session_request):
        return self._submit(self._with_session_repair(lambda: self._foreground_activity_v1(
            "draft_root_registration_admit_v1", scope=scope, request=request,
            owner_actor_ref=owner_actor_ref, owner_session_token=owner_session_token,
            owner_session_request=owner_session_request)))

    async def _foreground_activity_v1(self, method, *, scope, request,
            owner_actor_ref=None, owner_session_token=None, owner_session_request=None):
        from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV1,
            ForegroundActivityEvidenceV1, DraftRootRegistrationRequestV1, DraftRootRegistrationEvidenceV1,
            foreground_from_wire_v1, foreground_to_wire_v1, foreground_fence_operation_id_v1,
            ForegroundActivityRequestV2, ForegroundActivityPreparationParentRequestV2, ForegroundActivityEvidenceV2,
            foreground_from_wire_v2, foreground_to_wire_v2, foreground_fence_operation_id_v2)
        from ..authority_service.v2_contract import from_wire, to_wire
        from ..authority_service.v2_owner_session import to_wire as session_to_wire
        root_setup = method == "draft_root_registration_admit_v1"
        internal_v2 = not root_setup and type(request) in {ForegroundActivityRequestV2, ForegroundActivityPreparationParentRequestV2}
        expected_request = DraftRootRegistrationRequestV1 if root_setup else type(request) if internal_v2 else ForegroundActivityRequestV1
        expected_result = DraftRootRegistrationEvidenceV1 if root_setup else ForegroundActivityEvidenceV2 if internal_v2 else ForegroundActivityEvidenceV1
        encode = foreground_to_wire_v2 if internal_v2 else foreground_to_wire_v1
        decode = foreground_from_wire_v2 if internal_v2 else foreground_from_wire_v1
        fence_id = foreground_fence_operation_id_v2 if internal_v2 else foreground_fence_operation_id_v1
        if type(scope) is not FenceScope or type(request) is not expected_request or scope.namespace != request.namespace:
            raise RuntimeError("foreground exact request/fence namespace differs")
        await self._mapped(scope.namespace, scope.authority_namespace)
        handshake, grant = self._identity()
        permit = scope.permit
        if (permit.operation != "write" or (permit.authority_id, permit.namespace, permit.subject, permit.holder) !=
                (grant.authority_id, scope.authority_namespace, grant.subject, grant.administrator_holder)
                or not root_setup and (request.installation_id != grant.installation_id
                    or permit.operation_id != fence_id(request))):
            raise RuntimeError("foreground actual paired installation/Host/write permit differs")
        command = {"namespace": scope.authority_namespace, "permit": to_wire(permit), "request": encode(request)}
        if root_setup:
            if type(owner_session_request) is not OwnerSessionLoginRequestV1 or not owner_actor_ref or not owner_session_token:
                raise RuntimeError("explicit root setup needs the actual Owner session")
            self._owner_session_identity(scope.namespace, scope.authority_namespace, owner_session_request)
            command.update(owner_actor_ref=owner_actor_ref, owner_session_token=owner_session_token,
                owner_session_request=session_to_wire(owner_session_request))
        response = await self._transport._content_rpc(self._request, handshake, method, command, protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {"evidence", "permit", "channel_binding_sha256"}:
            raise RuntimeError("foreground exact paired response fields differ")
        evidence = decode(response["evidence"], expected_result)
        observed = from_wire(response["permit"])
        if type(observed) is not FencePermitV2 or observed != permit or evidence.request != request:
            raise RuntimeError("foreground paired response changed its original request/permit")
        actual_permit = evidence.permit if root_setup else evidence.current_self.permit
        if actual_permit != permit:
            raise RuntimeError("foreground independent self/root proof uses another permit")
        return evidence, observed

    def read_natural_current_graph_identity_v1(self, *, namespace, authority_namespace):
        return self._submit(self._with_session_repair(lambda:self._natural_current_graph_metadata_v1(
            namespace=namespace,authority_namespace=authority_namespace)))

    def read_natural_roster_prepared_for_parent_v1(self, *, namespace, authority_namespace, parent_original_id):
        return self._submit(self._with_session_repair(lambda:self._natural_current_graph_metadata_v1(
            namespace=namespace,authority_namespace=authority_namespace,parent_original_id=parent_original_id)))

    async def _natural_current_graph_metadata_v1(self, *, namespace, authority_namespace, parent_original_id=None):
        from ..authority_service.natural_disposition_maintenance_v1 import core_original_from_wire_v1,natural_graph_identity_from_wire_v1
        await self._mapped(namespace,authority_namespace)
        handshake,grant=self._identity()
        command={"namespace":authority_namespace,"holder":grant.administrator_holder}
        if parent_original_id is None:
            method="natural_current_graph_identity_v1";key="identity"
        else:
            method="natural_roster_prepared_for_parent_v1";key="original";command["parent_original_id"]=parent_original_id
        response=await self._transport._content_rpc(self._request,handshake,method,command,protocol=AUTHORITY_V2_PROTOCOL)
        if (type(response) is not dict or set(response)!={key,"channel_binding_sha256"}
                or response["channel_binding_sha256"]!=handshake.channel_binding_sha256):
            raise RuntimeError("natural current metadata crossed its exact authenticated channel")
        if parent_original_id is None:
            value=natural_graph_identity_from_wire_v1(response[key])
            if (value.namespace,value.installation_id)!=(namespace,grant.installation_id):
                raise RuntimeError("natural current C09 identity crossed its actual installed namespace")
        else:
            if response[key] is None:return None
            value=core_original_from_wire_v1(response[key])
            if ((value.authority_namespace,value.installation_id,value.parent_original_id)!=(authority_namespace,grant.installation_id,parent_original_id)
                    or value.kind!="roster_prepared"):
                raise RuntimeError("natural Core preparation lookup crossed its actual parent/installation")
        return value

    def reject_natural_unprepared_write_v1(self, *, scope, request):
        return self._submit(self._with_session_repair(lambda:self._natural_unprepared_write_closure_v1(scope=scope,request=request)))

    async def _natural_unprepared_write_closure_v1(self, *, scope, request):
        from ..authority_service.natural_disposition_maintenance_v1 import core_original_from_wire_v1,require_unprepared_family_permit_v1
        from ..authority_service.v2_contract import from_wire,to_wire
        if type(scope) is not FenceScope or scope.operation!="write" or request.namespace!=scope.namespace:
            raise TypeError("natural unprepared closure requires its exact actual write scope")
        require_unprepared_family_permit_v1(request,scope.permit)
        await self._mapped(scope.namespace,scope.authority_namespace)
        handshake,grant=self._identity()
        if (request.installation_id!=grant.installation_id or (scope.permit.authority_id,scope.permit.namespace,scope.permit.subject,scope.permit.holder)
                !=(grant.authority_id,scope.authority_namespace,grant.subject,grant.administrator_holder)):
            raise RuntimeError("natural unprepared closure crossed its actual installed write identity")
        response=await self._transport._content_rpc(self._request,handshake,"natural_disposition_reject_unprepared_write_v1",
            {"namespace":scope.authority_namespace,"holder":grant.administrator_holder,"request":request.to_wire(),"permit":to_wire(scope.permit)},protocol=AUTHORITY_V2_PROTOCOL)
        if (type(response) is not dict or set(response)!={"original","channel_binding_sha256"}
                or response["channel_binding_sha256"]!=handshake.channel_binding_sha256):
            raise RuntimeError("natural unprepared closure crossed its authenticated channel")
        value=core_original_from_wire_v1(response["original"])
        if ((value.authority_namespace,value.installation_id)!=(scope.authority_namespace,grant.installation_id)
                or from_wire(value.payload["permit"])!=scope.permit
                or value.kind not in {"rejected_no_commit","roster_committed","maintenance_committed"}):
            raise RuntimeError("natural unprepared closure returned another original actual permit")
        return value

    def prepare_natural_roster_original_v1(self, *, scope, paid_request):
        return self._submit(self._with_session_repair(lambda:self._natural_disposition_original_v1(scope=scope,paid_request=paid_request)))

    def confirm_natural_disposition_original_v1(self, *, scope, original_ref):
        return self._submit(self._with_session_repair(lambda:self._natural_disposition_original_v1(scope=scope,original_ref=original_ref,confirm=True)))

    def reject_natural_disposition_no_commit_v1(self, *, scope, original_ref):
        return self._submit(self._with_session_repair(lambda:self._natural_disposition_original_v1(
            scope=scope,original_ref=original_ref,reject=True)))

    def read_natural_disposition_original_v1(self, *, namespace, authority_namespace, original_ref):
        return self._submit(self._with_session_repair(lambda:self._natural_disposition_original_v1(namespace=namespace,
            authority_namespace=authority_namespace,original_ref=original_ref)))

    async def _natural_disposition_original_v1(self, *, namespace=None, authority_namespace=None,scope=None,paid_request=None,original_ref=None,confirm=False,reject=False):
        from ..authority_service.natural_disposition_maintenance_v1 import core_original_from_wire_v1
        from ..authority_service.v2_contract import from_wire, to_wire
        from ..authority_service.v2_natural_paid_review_contract import to_wire as paid_to_wire
        if scope is not None:
            if type(scope) is not FenceScope or scope.operation!="write":
                raise TypeError("natural Core original requires its actual first/maintenance write scope")
            namespace,authority_namespace=scope.namespace,scope.authority_namespace
        await self._mapped(namespace,authority_namespace)
        handshake,grant=self._identity()
        command={"namespace":authority_namespace,"holder":grant.administrator_holder}
        if scope is not None:
            if (scope.permit.authority_id,scope.permit.namespace,scope.permit.subject,scope.permit.holder)!=(grant.authority_id,authority_namespace,grant.subject,grant.administrator_holder):
                raise RuntimeError("natural original crossed its actual installed write identity")
            command["permit"]=to_wire(scope.permit)
        if paid_request is not None:
            method="natural_roster_prepare_for_final_v1";command["request"]=paid_to_wire(paid_request)
        else:
            method=("natural_disposition_reject_no_commit_v1" if reject else "natural_disposition_confirm_original_v1" if confirm else "natural_disposition_read_original_v1")
            command["original_ref"]=original_ref
        response=await self._transport._content_rpc(self._request,handshake,method,command,protocol=AUTHORITY_V2_PROTOCOL)
        if type(response) is not dict or set(response)!={"original","channel_binding_sha256"}:
            raise RuntimeError("natural signed original exact response differs")
        if response["channel_binding_sha256"] != handshake.channel_binding_sha256:
            raise RuntimeError("natural signed original crossed its authenticated channel")
        value=core_original_from_wire_v1(response["original"])
        if (paid_request is not None and value.kind != "roster_prepared"
                or confirm and value.kind not in {"roster_committed", "maintenance_committed"}
                or reject and value.kind != "rejected_no_commit"):
            raise RuntimeError("natural original response changed its named operation kind")
        if (value.authority_namespace,value.installation_id)!=(authority_namespace,grant.installation_id):
            raise RuntimeError("natural signed original crossed its current paired installation")
        if scope is not None and from_wire(value.payload["permit"])!=scope.permit:
            raise RuntimeError("natural signed original uses another actual write permit")
        if original_ref is not None and not (confirm or reject) and value.original_ref!=original_ref:
            raise RuntimeError("natural original lookup changed its exact identity")
        if (confirm or reject) and value.payload["prepared_original_ref"]!=original_ref:
            raise RuntimeError("natural confirmed original changed its exact prepared lineage")
        return value

    def plan_natural_disposition_maintenance_v1(self, *, namespace, authority_namespace, parent_original_id):
        return self._submit(self._with_session_repair(lambda:
            self._natural_disposition_metadata_v1(namespace=namespace, authority_namespace=authority_namespace,
                parent_original_id=parent_original_id)))

    def observe_natural_disposition_maintenance_v1(self, *, scope, request):
        return self._submit(self._with_session_repair(lambda:
            self._natural_disposition_metadata_v1(namespace=scope.namespace, authority_namespace=scope.authority_namespace,
                request=request, scope=scope)))

    async def _natural_disposition_metadata_v1(self, *, namespace, authority_namespace,
            parent_original_id=None, request=None, scope=None):
        from ..authority_service.natural_disposition_maintenance_v1 import (
            plan_from_wire_v1, observed_from_wire_v1, NaturalDispositionMaintenanceRequestV1,
        )
        from ..authority_service.v2_contract import to_wire
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        command = {"namespace":authority_namespace,"holder":grant.administrator_holder}
        if scope is None:
            command["parent_original_id"] = parent_original_id
            method = "natural_disposition_plan_v1"
        else:
            if (type(scope) is not FenceScope or scope.operation != "write"
                    or type(request) is not NaturalDispositionMaintenanceRequestV1
                    or (scope.permit.authority_id,scope.permit.namespace,scope.permit.subject,scope.permit.holder)
                        != (grant.authority_id,authority_namespace,grant.subject,grant.administrator_holder)
                    or (request.namespace,request.installation_id,request.operation_id)
                        != (namespace,grant.installation_id,scope.operation_id)):
                raise RuntimeError("natural disposition private observation crossed its installed write identity")
            command.update(request=request.to_wire(),permit=to_wire(scope.permit))
            method = "natural_disposition_observe_v1"
        response = await self._transport._content_rpc(self._request,handshake,method,command,protocol=AUTHORITY_V2_PROTOCOL)
        field = "plan" if scope is None else "observation"
        if type(response) is not dict or set(response) != {field,"channel_binding_sha256"}:
            raise RuntimeError("natural disposition private response exact fields differ")
        if response[field] is None and scope is None:
            return None
        value = plan_from_wire_v1(response[field]) if scope is None else observed_from_wire_v1(response[field])
        plan = value if scope is None else value.plan
        if (plan.request.namespace,plan.request.installation_id,plan.requirements.authority_namespace) != (namespace,grant.installation_id,authority_namespace):
            raise RuntimeError("natural disposition private plan crossed its installed namespace")
        if scope is not None and (value.permit!=scope.permit or plan.request!=request
                or plan.graph_revision!=scope.graph_revision or plan.graph_epoch!=scope.graph_epoch.revision):
            raise RuntimeError("natural disposition private witness differs from its fixed Graph read/write stamp")
        return value

    def read_current_artifact_no_dispatch_metadata_v1(self, *, bundle, request):
        return self._submit(self._with_session_repair(lambda:self._artifact_no_dispatch_metadata_rpc_v1(
            method="artifact_no_dispatch_metadata_issue_v1",bundle=bundle,request=request)))

    def validate_current_artifact_no_dispatch_metadata_v1(self, *, bundle, grant):
        return self._submit(self._with_session_repair(lambda:self._artifact_no_dispatch_metadata_rpc_v1(
            method="artifact_no_dispatch_metadata_validate_v1",bundle=bundle,grant=grant)))

    def read_current_artifact_no_dispatch_cancellation_v1(self, *, bundle, grant, prepared, prepared_signature):
        return self._submit(self._with_session_repair(lambda:self._artifact_no_dispatch_metadata_rpc_v1(
            method="artifact_no_dispatch_metadata_cancel_v1",bundle=bundle,grant=grant,
            prepared=prepared,prepared_signature=prepared_signature)))

    async def _artifact_no_dispatch_metadata_rpc_v1(self, *, method, bundle, request=None,
            grant=None, prepared=None, prepared_signature=None):
        from ..authority_service.artifact_no_dispatch_metadata_contract_v1 import (
            ModelNoDispatchMetadataRequestV1,ModelNoDispatchMetadataGrantV1,to_wire_v1,from_wire_v1)
        from ..authority_service.owner_goal_cancellation_contract_v1 import (
            OwnerGoalCancellationOriginalV1,owner_goal_cancellation_from_wire_v1)
        from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import (
            _accept_verified_artifact_metadata_rpc_v1,_ARTIFACT_METADATA_RPC_ISSUER_V1,
            require_verified_artifact_metadata_grant_v1)
        from ..domains.d01.production_operations_v1 import plain_v1
        policy=bundle.installation_policy
        await self._mapped(policy.namespace,policy.authority_namespace)
        handshake,installed=self._identity()
        if (installed.installation_id,installed.manifest_digest,installed.administrator_holder)!=(
                policy.installation_id,policy.manifest_digest,policy.administrator_holder):
            raise RuntimeError("financial metadata crossed its actual paired installation")
        command={"namespace":policy.authority_namespace}
        if method=="artifact_no_dispatch_metadata_issue_v1":
            if type(request) is not ModelNoDispatchMetadataRequestV1:
                raise TypeError("actual typed original financial metadata request required")
            command["request"]=to_wire_v1(request)
        else:
            require_verified_artifact_metadata_grant_v1(grant,port=self,bundle=bundle)
            command["grant"]=to_wire_v1(grant)
        if method=="artifact_no_dispatch_metadata_cancel_v1":
            command.update(prepared=plain_v1(prepared),prepared_signature=prepared_signature)
        response=await self._transport._content_rpc(self._request,handshake,method,command,protocol=AUTHORITY_V2_PROTOCOL)
        required=({"original","grant_digest","channel_binding_sha256"} if method=="artifact_no_dispatch_metadata_cancel_v1"
            else {"grant","channel_binding_sha256"})
        if (type(response) is not dict or set(response)!=required
                or response["channel_binding_sha256"]!=handshake.channel_binding_sha256):
            raise RuntimeError("financial metadata response crossed its authenticated channel")
        if method=="artifact_no_dispatch_metadata_cancel_v1":
            if response["grant_digest"]!=grant.digest:raise RuntimeError("cancel metadata changed actual original financial grant")
            return None if response["original"] is None else owner_goal_cancellation_from_wire_v1(
                response["original"],OwnerGoalCancellationOriginalV1)
        if response["grant"] is None:
            if method!="artifact_no_dispatch_metadata_issue_v1":raise RuntimeError("financial grant validation became absent")
            return None
        observed=from_wire_v1(response["grant"],ModelNoDispatchMetadataGrantV1)
        if (method=="artifact_no_dispatch_metadata_issue_v1" and observed.request!=request
                or method=="artifact_no_dispatch_metadata_validate_v1" and observed.digest!=grant.digest):
            raise RuntimeError("financial metadata changed the actual read operation/original target")
        return _accept_verified_artifact_metadata_rpc_v1(_ARTIFACT_METADATA_RPC_ISSUER_V1,
            port=self,bundle=bundle,grant=observed,channel_binding=response["channel_binding_sha256"])

    def observe_owner_stop_reply_projection_for_fence_v1(self, *, scope, original_ref):
        return self._submit(self._with_session_repair(lambda:
            self._observe_owner_stop_reply_projection_v1(scope=scope, original_ref=original_ref)))

    async def _observe_owner_stop_reply_projection_v1(self, *, scope, original_ref):
        from ..authority_service.owner_stop_reply_v1 import owner_stop_reply_projection_observed_from_wire_v1
        from ..authority_service.v2_contract import to_wire
        if type(scope) is not FenceScope or scope.operation != "write":
            raise TypeError("StopReply projection needs its actual installed write scope")
        await self._mapped(scope.namespace, scope.authority_namespace)
        handshake, grant = self._identity()
        permit = scope.permit
        if (permit.authority_id, permit.namespace, permit.subject, permit.holder) != (
                grant.authority_id, scope.authority_namespace, grant.subject, grant.administrator_holder):
            raise RuntimeError("StopReply projection crossed its actual paired installation/subject")
        response = await self._transport._content_rpc(self._request, handshake,
            "owner_stop_reply_projection_observe_v1", {"namespace": scope.authority_namespace,
                "holder": grant.administrator_holder, "original_ref": original_ref, "permit": to_wire(permit)},
            protocol=AUTHORITY_V2_PROTOCOL)
        if type(response) is not dict or set(response) != {"observation", "channel_binding_sha256"}:
            raise RuntimeError("StopReply permit-bound observation exact response differs")
        value = owner_stop_reply_projection_observed_from_wire_v1(response["observation"])
        if (value.permit != permit or value.request.namespace != scope.namespace
                or value.request.installation_id != grant.installation_id
                or scope.operation_id != "owner-stop-projection:" + value.initial_original.operation_id
                or value.requirements.authority_id != grant.authority_id
                or value.requirements.authority_namespace != scope.authority_namespace
                or value.requirements.activation_generation != scope.generation):
            raise RuntimeError("StopReply observed original/permit/installation/stamp binding differs")
        return value

    def observe_owner_artifact_for_fence_v1(self, **request):
        from .d12_owner_artifact_read_port_v1 import observe_owner_artifact_for_fence_v1
        return observe_owner_artifact_for_fence_v1(self, **request)

    def get_current_owner_authority_for_fence_v1(self, **request):
        from .d12_target_owner_port_v1 import get_current_owner_authority_for_fence_v1
        return get_current_owner_authority_for_fence_v1(self, **request)

    def capture_contact_background_invocation_v1(self, **request):
        from ..authority_service.contact_background_rpc_v1 import METHOD
        return self._contact_background_observation_v1(METHOD, **request)

    def read_contact_background_observation_v1(self, **request):
        from ..authority_service.contact_background_rpc_v1 import READ_METHOD
        return self._contact_background_observation_v1(READ_METHOD, **request)

    def _contact_background_observation_v1(self, method, *, namespace, authority_namespace, permit, selector):
        from ..authority_service.contact_background_rpc_v1 import METHOD, validate_background_observation_v1
        from ..authority_service.d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1
        from ..authority_service.v2_contract import SCHEMA, to_wire, from_wire
        from ..runtime_contracts import canonical_digest
        async def read():
            await self._mapped(namespace, authority_namespace)
            handshake, grant = self._identity()
            if permit.authority_id != grant.authority_id or permit.subject != grant.subject:
                raise PermissionError('Contact background permit belongs to another installation')
            response = await self._transport._content_rpc(self._request, handshake, method,
                {'namespace':authority_namespace,'permit':to_wire(permit),'selector':selector}, protocol=SCHEMA)
            if set(response) != {'observation','authority','channel_binding_sha256'}:
                raise RuntimeError('Contact background observation response fields differ')
            observation = validate_background_observation_v1(response['observation'])
            authority = response['authority']
            current = current_owner_authority_from_wire_v1({k:v for k,v in authority.items() if k != 'permit'})
            if (from_wire(authority['permit']) != permit or current.guard.namespace != namespace
                    or observation['authority_id'] != grant.authority_id
                    or observation['installation_id'] != grant.installation_id
                    or method == METHOD and (observation['owner_authority_digest'] != canonical_digest(authority)
                        or observation['permit_digest'] != canonical_digest(to_wire(permit)))
                    or current.guard.authorization_head != observation['owner_head_digest']
                    or current.guard.authorization_revision != observation['owner_revision']
                    or observation['inputs']['operation_id'] != selector['operation_id']
                    or observation['inputs']['request_digest'] != selector['request_digest']):
                raise PermissionError('Contact background exact current authority/selector differs')
            return {'observation':observation,'authority':authority}
        return self._submit(self._with_session_repair(read))

    def capture_current_contact_owner_session_v3(self, **request):
        from ..authority_service.contact_owner_session_rpc_v3 import CAPTURE
        return self._contact_owner_session_v3(CAPTURE, **request)

    def associate_contact_finished_owner_read_v1(self, **request):
        from .contact_finished_owner_read_port_v1 import associate_contact_finished_owner_read_v1
        return associate_contact_finished_owner_read_v1(self, **request)

    def associate_contact_owner_recovery_v3(self, **request):
        from ..authority_service.contact_owner_session_rpc_v3 import ASSOCIATE
        return self._contact_owner_session_v3(ASSOCIATE, **request)

    def _contact_owner_session_v3(self, method, *, namespace, authority_namespace,
            permit, owner_actor_id, owner_session_token, owner_session_request,
            original=None, use=None, signature=None):
        from ..authority_service.contact_owner_session_rpc_v3 import CAPTURE, ASSOCIATE
        from ..authority_service.contact_owner_session_v3 import (
            ContactOwnerSessionObservationV3, OwnerContactRecoveryUseV3,
            to_wire as contact_to_wire, from_wire as contact_from_wire, digest,
            validate_association_v3)
        from ..authority_service.d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1
        from ..authority_service.v2_owner_session import to_wire as session_to_wire
        from ..authority_service.v2_contract import SCHEMA, to_wire, from_wire
        if method not in {CAPTURE, ASSOCIATE}:
            raise ValueError('unknown Contact Owner session operation')
        if method == CAPTURE and any(v is not None for v in (original, use, signature)):
            raise ValueError('Contact capture cannot carry recovery authority')
        if method == ASSOCIATE and (type(original) is not ContactOwnerSessionObservationV3
                or type(use) is not OwnerContactRecoveryUseV3 or type(signature) is not bytes):
            raise ValueError('Contact recovery requires exact original and signed use')
        async def read():
            await self._mapped(namespace, authority_namespace)
            self._owner_session_identity(namespace, authority_namespace, owner_session_request)
            handshake, grant = self._identity()
            if permit.authority_id != grant.authority_id or permit.subject != grant.subject:
                raise PermissionError('Contact Owner permit belongs to another installation')
            command = {'namespace': authority_namespace, 'permit': to_wire(permit),
                'owner_actor_id': owner_actor_id, 'owner_session_token': owner_session_token,
                'owner_session_request': session_to_wire(owner_session_request)}
            if method == ASSOCIATE:
                command.update(original=contact_to_wire(original),use=contact_to_wire(use),signature=signature.hex())
            response = await self._transport._content_rpc(self._request, handshake, method,
                command, protocol=SCHEMA)
            if set(response) != {'observation', 'authority', 'channel_binding_sha256'}:
                raise RuntimeError('Contact Owner session response fields differ')
            authority = response['authority']
            if type(authority) is not dict or set(authority) not in (
                    {'guard', 'target_admission', 'permit'},
                    {'guard', 'target_admission', 'storage_admission', 'permit'}):
                raise RuntimeError('Contact current Owner authority response differs')
            current = current_owner_authority_from_wire_v1({k:v for k,v in authority.items() if k != 'permit'})
            if (from_wire(authority['permit']) != permit or current.guard.namespace != namespace
                    or current.guard.authority_id != grant.authority_id):
                raise PermissionError('Contact Owner authority fence differs')
            observed = response['observation']
            if method == CAPTURE:
                value = contact_from_wire(observed)
                if (type(value) is not ContactOwnerSessionObservationV3
                        or value.principal != owner_session_request.principal
                        or value.actor != owner_actor_id or value.installation_id != grant.installation_id
                        or value.authority_id != grant.authority_id or value.authority_namespace != authority_namespace
                        or value.permit_digest != digest(to_wire(permit))
                        or value.authority_observation_digest != digest(authority)):
                    raise PermissionError('Contact captured session identity differs')
            else:
                value = validate_association_v3(observed, original=original, use=use,
                    authority_observation_digest=digest(authority))
                if (value.principal != owner_session_request.principal
                        or value.actor != owner_actor_id or value.installation_id != grant.installation_id
                        or value.authority_id != grant.authority_id or value.authority_namespace != authority_namespace
                        or value.permit_digest != digest(to_wire(permit))):
                    raise PermissionError('Contact associated session identity differs')
            return {'observation': observed, 'authority': authority}
        return self._submit(self._with_session_repair(read))

    def observe_paid_owner_guard_for_fence_v3(self, *, namespace: NamespaceId,
            authority_namespace: str, permit: FencePermitV2, business_operation_id: str,
            request_digest: str, phase: str):
        return self._submit(self._with_session_repair(lambda: self._observe_paid_owner_guard_for_fence_v3(
            namespace,authority_namespace,permit,business_operation_id,request_digest,phase)))

    async def _observe_paid_owner_guard_for_fence_v3(self,namespace,authority_namespace,permit,
            business_operation_id,request_digest,phase):
        await self._mapped(namespace,authority_namespace)
        handshake,grant=self._identity()
        if (type(permit) is not FencePermitV2 or permit.operation!="write"
                or permit.namespace!=authority_namespace or permit.authority_id!=grant.authority_id
                or permit.subject!=grant.subject):
            raise RuntimeError("paid Owner observation permit installation identity differs")
        original,current=await self._transport.v3_observe_paid_owner_guard_for_fence(
            self._request,handshake,namespace=authority_namespace,permit=permit,
            business_operation_id=business_operation_id,request_digest=request_digest,phase=phase)
        if (current!=permit or original.guard.namespace!=namespace
                or original.guard.authority_id!=grant.authority_id
                or original.guard.installation_id!=grant.installation_id):
            raise RuntimeError("paid Owner observation namespace or original write differs")
        return original,current

    def get_current_owner_guard_for_fence(
        self, *, namespace: NamespaceId, authority_namespace: str,
        permit: FencePermitV2,
        owner_actor_id: str | None = None,
        owner_session_token: str | None = None,
        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> tuple[OwnerAuthorizationGuardV1 | None, FencePermitV2]:
        return self._submit(self._with_session_repair(
            lambda: self._get_current_owner_guard_for_fence(
                namespace, authority_namespace, permit, owner_actor_id,
                owner_session_token, owner_session_request)))

    async def _get_current_owner_guard_for_fence(
        self, namespace: NamespaceId, authority_namespace: str,
        permit: FencePermitV2,
        owner_actor_id: str | None,
        owner_session_token: str | None,
        owner_session_request: OwnerSessionLoginRequestV1 | None,
    ) -> tuple[OwnerAuthorizationGuardV1 | None, FencePermitV2]:
        await self._mapped(namespace, authority_namespace)
        if owner_session_request is not None:
            self._owner_session_identity(
                namespace, authority_namespace, owner_session_request)
        handshake, grant = self._identity()
        if (type(permit) is not FencePermitV2
                or permit.operation not in {"read", "write"}
                or permit.namespace != authority_namespace
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject):
            raise RuntimeError("v2 owner guard read permit identity mismatch")
        guard, current = await self._transport.v2_get_current_owner_guard_for_fence(
            self._request, handshake, namespace=authority_namespace,
            permit=permit, owner_actor_id=owner_actor_id,
            owner_session_token=owner_session_token,
            owner_session_request=owner_session_request)
        if current != permit:
            raise RuntimeError("v2 owner guard read permit changed")
        if guard is not None and (
            guard.namespace != namespace or guard.authority_id != grant.authority_id
            or guard.installation_id != grant.installation_id):
            raise RuntimeError("v2 owner guard identity mismatch")
        return guard, current

    def get_pending_owner_issue(self, *, namespace: NamespaceId,
                                authority_namespace: str,
                                operation_id: str,
                                owner_session_token: str | None = None,
                                owner_session_request: OwnerSessionLoginRequestV1 | None = None,
                                ) -> OwnerAuthorizationReceiptV1 | None:
        """Read a pending owner issue as this installation's real mTLS peer."""
        return self._submit(self._with_session_repair(lambda: self._get_pending_owner_issue(
            namespace, authority_namespace, operation_id,
            owner_session_token, owner_session_request)))

    async def _get_pending_owner_issue(self, namespace: NamespaceId,
                                       authority_namespace: str,
                                       operation_id: str,
                                       owner_session_token: str | None,
                                       owner_session_request: OwnerSessionLoginRequestV1 | None,
                                       ) -> OwnerAuthorizationReceiptV1 | None:
        identifier(operation_id, "operation_id")
        await self._mapped(namespace, authority_namespace)
        if owner_session_request is not None:
            self._owner_session_identity(namespace, authority_namespace, owner_session_request)
        handshake, grant = self._identity()
        receipt = await self._transport.v2_get_pending_owner_issue(
            self._request, handshake, namespace=authority_namespace,
            operation_id=operation_id, owner_session_token=owner_session_token,
            owner_session_request=owner_session_request)
        if receipt is not None and (
            type(receipt) is not OwnerAuthorizationReceiptV1
            or receipt.phase != "pending"
            or receipt.operation.operation_id != operation_id
            or receipt.operation.namespace != namespace
            or receipt.operation.authority_id != grant.authority_id
            or receipt.operation.installation_id != grant.installation_id
        ):
            raise RuntimeError("v2 pending owner issue identity mismatch")
        return receipt

    def get_pending_owner_issue_for_graph_write(
        self, *, namespace: NamespaceId, authority_namespace: str,
        operation_id: str, permit: FencePermitV2,
    ) -> OwnerAuthorizationReceiptV1 | None:
        """Read the original pending issue under this active v2 write permit."""
        return self._submit(self._with_session_repair(
            lambda: self._get_pending_owner_issue_for_graph_write(
                namespace, authority_namespace, operation_id, permit)))

    async def _get_pending_owner_issue_for_graph_write(
        self, namespace: NamespaceId, authority_namespace: str,
        operation_id: str, permit: FencePermitV2,
    ) -> OwnerAuthorizationReceiptV1 | None:
        identifier(operation_id, "operation_id")
        await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or permit.namespace != authority_namespace
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject):
            raise RuntimeError("v2 owner graph read permit identity mismatch")
        receipt = await self._transport.v2_get_pending_owner_issue_for_graph_write(
            self._request, handshake, namespace=authority_namespace,
            operation_id=operation_id, permit=permit)
        if receipt is not None and (
            type(receipt) is not OwnerAuthorizationReceiptV1
            or receipt.phase != "pending"
            or receipt.operation.operation_id != operation_id
            or receipt.operation.namespace != namespace
            or receipt.operation.authority_id != grant.authority_id
            or receipt.operation.installation_id != grant.installation_id
        ):
            raise RuntimeError("v2 pending owner graph read identity mismatch")
        return receipt

    def begin_fence(
        self, *, namespace: NamespaceId, authority_namespace: str, holder: str,
        generation: int, operation: str, operation_id: str, expected_anchor: RestoreAnchor,
        effect_id: str | None = None, command_digest: str | None = None,
        footprint: RecoveryConstraintFootprint | None = None,
        retain_on_unknown: bool = False,
    ) -> FencePermitV2:
        with self._lock:
            self.recover_pending_finish()
            self.recover_pending_begin()
            try:
                return self._submit(self._with_session_repair(lambda: self._begin_fence(
                    namespace, authority_namespace, holder, generation, operation,
                    operation_id, expected_anchor, effect_id, command_digest, footprint)))
            except RuntimeError as exc:
                if not isinstance(exc, V2FenceOutcomeUnknown) and str(exc) not in _REPAIRABLE_ERRORS:
                    raise
                if not retain_on_unknown and operation in _CONTENT_OPERATIONS and all(
                    value is None for value in (effect_id, command_digest, footprint)
                ):
                    self._pending_begin = _PendingBegin(
                        namespace, authority_namespace, holder, generation,
                        operation, operation_id, expected_anchor,
                    )
                if isinstance(exc, V2FenceOutcomeUnknown):
                    raise
                raise V2FenceOutcomeUnknown(
                    "v2 begin result unknown after transport loss for operation_id="
                    + operation_id + "; reconcile or retry only with the original operation_id"
                ) from exc

    def recover_pending_begin(self) -> None:
        """Reclaim an uncertain begin before admitting a different operation ID."""
        with self._lock:
            pending = self._pending_begin
            if pending is None:
                return
            try:
                if pending.permit is None:
                    pending.permit = self._submit(self._with_session_repair(lambda: self._begin_fence(
                        pending.namespace, pending.authority_namespace, pending.holder,
                        pending.generation, pending.operation, pending.operation_id,
                        pending.expected_anchor, None, None, None,
                    )))
                request_id, request_digest = pending.finish_identity
                self._submit(self._with_session_repair(lambda: self._transport.v2_finish_fence(
                    self._request, self._identity()[0], pending.permit,
                    request_id=request_id, request_digest=request_digest,
                )))
            except BaseException as exc:
                raise V2FenceOutcomeUnknown(
                    "v2 begin outcome remains unknown for operation_id="
                    + pending.operation_id + "; a new operation ID is blocked"
                ) from exc
            self._pending_begin = None

    def recover_pending_finish(self) -> None:
        """Replay the exact finish request before admitting another fence."""
        with self._lock:
            pending = self._pending_finish
            if pending is None:
                return
            try:
                self._submit(self._with_session_repair(lambda: self._finish_fence(
                    pending.scope, pending.request_id, pending.request_digest,
                )))
            except BaseException as exc:
                raise V2FenceOutcomeUnknown(
                    "v2 finish outcome remains unknown for operation_id="
                    + pending.scope.operation_id + "; a new operation ID is blocked"
                ) from exc
            self._pending_finish = None

    async def _begin_fence(
        self, namespace: NamespaceId, authority_namespace: str, holder: str,
        generation: int, operation: str, operation_id: str, expected_anchor: RestoreAnchor,
        effect_id: str | None, command_digest: str | None,
        footprint: RecoveryConstraintFootprint | None,
    ) -> FencePermitV2:
        if type(operation) is not str or operation not in _CONTENT_OPERATIONS or any(
            value is not None for value in (effect_id, command_digest, footprint)
        ):
            raise ValueError("unsupported v2 content fence; dispatch requires a separate Authority RPC")
        identifier(holder, "holder")
        identifier(operation_id, "operation_id")
        if (type(generation) is not int or generation < 0
                or type(expected_anchor) is not RestoreAnchor
                or expected_anchor.namespace != authority_namespace
                or expected_anchor.activation_generation != generation):
            raise ValueError("v2 begin activation or anchor is invalid")
        observed = await self._mapped(namespace, authority_namespace)
        if (observed.holder != holder or observed.generation != generation
                or expected_anchor != observed.anchor):
            raise RuntimeError("v2 namespace activation or anchor changed")
        handshake, grant = self._identity()
        permit = await self._transport.v2_begin_content_fence(
            self._request, handshake, namespace=authority_namespace, holder=holder,
            operation=operation, operation_id=operation_id, expected_anchor=expected_anchor,
        )
        if permit.subject != grant.subject or permit.generation != generation:
            raise RuntimeError("v2 permit installation or generation mismatch")
        return permit

    def begin_dispatch_fence(
        self, *, namespace: NamespaceId, authority_namespace: str, holder: str,
        generation: int, operation_id: str, expected_anchor: RestoreAnchor,
        effect_id: str, command_digest: str, footprint: RecoveryConstraintFootprint,
    ) -> FencePermitV2:
        """Begin one effect-bound dispatch fence; the port sends no platform command."""
        with self._lock:
            self.recover_pending_finish()
            self.recover_pending_begin()
            try:
                return self._submit(self._with_session_repair(lambda: self._begin_dispatch_fence(
                    namespace, authority_namespace, holder, generation, operation_id,
                    expected_anchor, effect_id, command_digest, footprint)))
            except RuntimeError as exc:
                if isinstance(exc, V2FenceOutcomeUnknown) or str(exc) in _REPAIRABLE_ERRORS:
                    raise V2FenceOutcomeUnknown(
                        "v2 dispatch begin outcome unknown for operation_id=" + operation_id
                        + "; retry only with the original operation_id and footprint") from exc
                raise

    async def _begin_dispatch_fence(
        self, namespace: NamespaceId, authority_namespace: str, holder: str,
        generation: int, operation_id: str, expected_anchor: RestoreAnchor,
        effect_id: str, command_digest: str, footprint: RecoveryConstraintFootprint,
    ) -> FencePermitV2:
        identifier(operation_id, "operation_id")
        if (type(expected_anchor) is not RestoreAnchor
                or expected_anchor.namespace != authority_namespace
                or expected_anchor.activation_generation != generation
                or type(footprint) is not RecoveryConstraintFootprint
                or footprint.namespace != authority_namespace
                or footprint.effect_id != effect_id):
            raise ValueError("v2 dispatch identity is invalid")
        observed = await self._mapped(namespace, authority_namespace)
        if (observed.holder != holder or observed.generation != generation
                or observed.anchor != expected_anchor):
            raise RuntimeError("v2 dispatch activation or anchor changed")
        handshake, grant = self._identity()
        permit = await self._transport.v2_begin_dispatch_fence(
            self._request, handshake, namespace=authority_namespace, holder=holder,
            operation_id=operation_id, expected_anchor=expected_anchor,
            effect_id=effect_id, command_digest=command_digest, footprint=footprint)
        if permit.subject != grant.subject or permit.generation != generation:
            raise RuntimeError("v2 dispatch permit installation or generation mismatch")
        return permit

    def read_natural_final_effect_observation_v4(self, *, namespace: NamespaceId, authority_namespace: str,
            permit: FencePermitV2, effect_id: str):
        """Read the Core's immutable target/negative-inventory original under the current write fence."""
        return self._submit(self._with_session_repair(lambda: self._read_natural_final_effect_observation_v4(
            namespace, authority_namespace, permit, effect_id)))

    async def _read_natural_final_effect_observation_v4(self, namespace, authority_namespace, permit, effect_id):
        from ..authority_service.v2_contract import NaturalFinalEffectObservationReadV4
        identifier(effect_id, "effect_id")
        if type(permit) is not FencePermitV2 or permit.operation != "write" or permit.namespace != authority_namespace:
            raise ValueError("natural final observation requires actual ordinary write fence")
        current = await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        if (permit.authority_id != grant.authority_id or permit.subject != grant.subject
                or permit.holder != current.holder or permit.generation != current.generation or permit.pinned_anchor != current.anchor):
            raise RuntimeError("natural final observation permit is stale or unpaired")
        observed = await self._transport.v2_execution_read_natural_final_effect_observation_v4(
            self._request, handshake, permit=permit, effect_id=effect_id)
        if (type(observed) is not NaturalFinalEffectObservationReadV4 or observed.observation.permit != permit
                or observed.observation.installation_id != grant.installation_id
                or observed.observation.target_effect_id != effect_id):
            raise RuntimeError("natural final observation differs from actual paired installation/permit/target")
        return observed

    def read_current_effect_snapshot_for_write_fence(
        self, *, namespace: NamespaceId, authority_namespace: str,
        permit: FencePermitV2,
    ) -> AuthorityCurrentEffectSnapshotV2:
        """Read a complete, pinned Authority effect index without admitting dispatch."""
        return self._submit(self._with_session_repair(
            lambda: self._read_current_effect_snapshot_for_write_fence(
                namespace, authority_namespace, permit)))

    async def _read_current_effect_snapshot_for_write_fence(
        self, namespace: NamespaceId, authority_namespace: str,
        permit: FencePermitV2,
    ) -> AuthorityCurrentEffectSnapshotV2:
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or permit.namespace != authority_namespace):
            raise ValueError("current effect snapshot requires an ordinary write fence")
        observed = await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        if (permit.authority_id != grant.authority_id
                or permit.subject != grant.subject
                or permit.holder != observed.holder
                or permit.generation != observed.generation
                or permit.pinned_anchor != observed.anchor):
            raise RuntimeError("current effect snapshot permit is stale or unpaired")
        read = getattr(
            self._transport,
            "v2_execution_read_current_effect_snapshot_for_write_fence", None)
        if not callable(read):
            raise RuntimeError("current effect snapshot transport is unavailable")
        snapshot = await read(self._request, handshake, permit=permit)
        if (type(snapshot) is not AuthorityCurrentEffectSnapshotV2
                or snapshot.authority_id != grant.authority_id
                or snapshot.namespace != authority_namespace
                or snapshot.anchor != permit.pinned_anchor
                or snapshot.permit_digest != authority_canonical_digest(permit)
                or snapshot.execution_head_seq != permit.pinned_anchor.execution_seq
                or snapshot.execution_head_digest != permit.pinned_anchor.execution_digest
                or snapshot.coverage != "complete"):
            raise RuntimeError("current effect snapshot is stale or incomplete")
        return snapshot

    def prepare_current_d13_frame_v7(self,selector):
        return self._submit(self._with_session_repair(lambda:self._d13_core_counter_rpc_v1('prepare_current_d13_frame_v7',selector)))

    def count_current_d13_wire_v1(self,selector,*,frame):
        return self._submit(self._with_session_repair(lambda:self._d13_core_counter_rpc_v1('count_current_d13_wire_v1',selector,frame=frame)))

    async def _d13_core_counter_rpc_v1(self,method,selector,*,frame=None):
        from dataclasses import asdict
        from ..authority_service.d13_core_counter_contract_v1 import (D13CurrentFramePrepareSelectorV7,
            D13CurrentWireCountSelectorV1,D13CoreFrameIntentHeaderV7,D13CoreFullWireEnvelopeV1,D13CounterCPUPrepareInstructionV1,
            D13CounterAwaitingAccountingV1,d13_core_counter_from_wire_v1)
        if method=='prepare_current_d13_frame_v7':
            if type(selector) is not D13CurrentFramePrepareSelectorV7:raise TypeError('actual V7 frame selector required')
            namespace=selector.namespace;authority_namespace=selector.authority_namespace
        else:
            if type(selector) is not D13CurrentWireCountSelectorV1 or type(frame) is not D13CoreFrameIntentHeaderV7:
                raise TypeError('exact count selector and original frame required')
            namespace=frame.namespace;authority_namespace=frame.authority_namespace
        observed=await self._mapped(namespace,authority_namespace)
        handshake,grant=self._identity()
        if (selector.install_id,authority_namespace)!=(grant.installation_id,namespace_ref(namespace)):
            raise RuntimeError('Core counter selector crossed actual paired installation/namespace')
        response=await self._transport._content_rpc(self._request,handshake,method,
            {'namespace':authority_namespace,'selector':asdict(selector)},protocol=AUTHORITY_V2_PROTOCOL)
        terminal_key='frame' if method=='prepare_current_d13_frame_v7' else 'evidence'
        if (type(response) is not dict or set(response) not in (
                {terminal_key,'channel_binding_sha256'},{'progress','channel_binding_sha256'})
                or response['channel_binding_sha256']!=handshake.channel_binding_sha256):
            raise RuntimeError('Core counter response crossed exact authenticated channel')
        if 'progress' in response:
            cls=D13CounterCPUPrepareInstructionV1 if method=='prepare_current_d13_frame_v7' else D13CounterAwaitingAccountingV1
            progress=d13_core_counter_from_wire_v1(response['progress'],cls)
            if type(progress) is D13CounterCPUPrepareInstructionV1:
                if ((progress.namespace,progress.install_id,progress.authority_namespace,progress.activation_generation,
                        progress.c02_operation_id,progress.plan_ref,progress.counter_operation_id)!=(namespace,
                        grant.installation_id,authority_namespace,observed.generation,selector.c02_operation_id,
                        selector.plan_ref,selector.counter_operation_id)):
                    raise RuntimeError('Core CPU instruction crossed current actual channel/parent/prospective scope')
            elif ((progress.namespace,progress.frame_intent_id,progress.frame_intent_digest,progress.counter_operation_id)
                    !=(frame.namespace,frame.frame_intent_id,frame.frame_intent_digest,frame.counter_operation_id)):
                raise RuntimeError('Core CPU accounting locator replaced immutable original operation')
            return progress
        cls=D13CoreFrameIntentHeaderV7 if terminal_key=='frame' else D13CoreFullWireEnvelopeV1
        result=d13_core_counter_from_wire_v1(response[terminal_key],cls)
        header=result if terminal_key=='frame' else result.payload.frame
        if (header.namespace,header.authority_namespace,header.install_id,header.authority_id,header.activation_generation)!= (
                namespace,authority_namespace,grant.installation_id,grant.authority_id,observed.generation):
            raise RuntimeError('Core counter original crossed current actual channel/scope')
        if terminal_key=='frame':
            if (header.c02_operation_id,header.plan_ref,header.counter_operation_id)!=(
                    selector.c02_operation_id,selector.plan_ref,selector.counter_operation_id):
                raise RuntimeError('Core frame changed original cause/prospective plan/count operation')
        elif header!=frame:raise RuntimeError('Core counter replaced immutable original frame')
        return result

    def read_current_contact_observation_for_projection_v1(self, *, namespace, authority_namespace,
            installation_id, holder, effect_id):
        return self._submit(self._with_session_repair(lambda:self._contact_observation_projection_v1(
            namespace=namespace,authority_namespace=authority_namespace,installation_id=installation_id,
            holder=holder,effect_id=effect_id)))

    async def _contact_observation_projection_v1(self, *, namespace, authority_namespace,
            installation_id, holder, effect_id):
        from ..authority_service.contact_p2_contract_v1 import contact_observation_projection_from_wire_v1
        observed=await self._mapped(namespace,authority_namespace)
        handshake,grant=self._identity()
        if (installation_id,holder)!=(grant.installation_id,grant.administrator_holder):
            raise RuntimeError("Contact observation private installation selector differs")
        response=await self._transport._content_rpc(self._request,handshake,
            "contact_current_observation_projection_v1",{"namespace":authority_namespace,
                "installation_id":installation_id,"holder":holder,"effect_id":effect_id},protocol=AUTHORITY_V2_PROTOCOL)
        if (type(response) is not dict or set(response)!={"read","channel_binding_sha256"}
                or response["channel_binding_sha256"]!=handshake.channel_binding_sha256):
            raise RuntimeError("Contact observation crossed its exact authenticated channel")
        result=contact_observation_projection_from_wire_v1(response["read"])
        permit=result.observed_permit
        if ((result.namespace,result.installation_id,permit.authority_id,permit.subject,permit.holder,
                permit.namespace,permit.effect_id,permit.generation)!=(namespace,installation_id,
                grant.authority_id,grant.subject,holder,authority_namespace,effect_id,observed.generation)):
            raise RuntimeError("Contact observation actual original crossed its paired namespace/effect")
        return result

    def read_current_observation_receipt_v1(self, *, namespace, authority_namespace, effect_id):
        return self._submit(self._with_session_repair(lambda:
            self._read_current_observation_receipt_v1(namespace, authority_namespace, effect_id)))

    def read_d11_offline_tick_original_v1(self, *, binding):
        return self._submit(self._with_session_repair(lambda: self._offline_tick_v1(
            binding, "d11_offline_tick_original_v1")))

    def execute_d11_offline_tick_v1(self, *, binding):
        # Refresh through a harmless mapped read first. The actual once-call
        # is issued once; transport uncertainty is resolved by original reads.
        self._submit(self._with_session_repair(lambda: self._mapped(
            binding.namespace, binding.authority_namespace)))
        try:
            return self._submit(self._offline_tick_v1(binding, "d11_offline_tick_execute_v1"))
        except (RuntimeError, FutureTimeout) as exc:
            raise V2FenceOutcomeUnknown("offline tick execute outcome requires original inspection") from exc

    async def _offline_tick_v1(self, binding, method):
        from ..authority_service.d11_offline_tick_contract_v1 import D11OfflineTickBindingV1
        if type(binding) is not D11OfflineTickBindingV1:
            raise TypeError("actual fixed offline tick binding required")
        await self._mapped(binding.namespace, binding.authority_namespace)
        handshake, grant = self._identity()
        return await self._transport.d11_offline_tick_v1(self._request, handshake, grant,
            binding=binding, method=method)

    def read_historical_d11_offline_tick_original_v1(self, *, binding):
        return self._submit(self._with_session_repair(lambda: self._historical_offline_tick_original_v1(
            binding, "d11_offline_tick_historical_original_v1")))

    def recover_claimed_d11_offline_tick_v1(self, *, binding):
        # Session repair repeats the same consumed identity; this RPC has no
        # first-claim branch and cannot start a computation.
        return self._submit(self._with_session_repair(lambda: self._historical_offline_tick_original_v1(
            binding, "d11_offline_tick_recover_claimed_v1")))

    async def _historical_offline_tick_original_v1(self, binding, method):
        handshake, grant = self._identity()
        return await self._transport.d11_offline_tick_v1(self._request, handshake, grant, binding=binding, method=method)

    def offline_tick_unstarted_cancellation_v1(self, *, binding, action, gate=None):
        return self._submit(self._with_session_repair(lambda: self._offline_tick_unstarted_cancellation_v1(binding, action, gate)))

    async def _offline_tick_unstarted_cancellation_v1(self, binding, action, gate):
        handshake, grant = self._identity()
        return await self._transport.d11_offline_tick_unstarted_cancellation_v1(self._request, handshake, grant,
            binding=binding, action=action, gate=gate)

    def offline_tick_historical_accounting_v1(self, *, binding, action, gate=None):
        return self._submit(self._with_session_repair(lambda: self._offline_tick_historical_accounting_v1(
            binding, action, gate)))

    async def _offline_tick_historical_accounting_v1(self, binding, action, gate):
        # The dedicated Authority service authenticates the retained binding.
        # A current content bootstrap would incorrectly gate historical cost
        # and even an exact finished ACK on today's source readiness.
        handshake, grant = self._identity()
        return await self._transport.d11_offline_tick_historical_accounting_v1(self._request, handshake, grant,
            binding=binding, action=action, gate=gate)

    def offline_tick_adoption_bridge_v1(self, *, binding, action, gate=None, outcome=None):
        # Each operation is exact-original idempotent. Repair only the paired
        # session; no bridge operation can issue a computation claim.
        return self._submit(self._with_session_repair(lambda: self._offline_tick_bridge_v1(
            binding, action, gate, outcome)))

    async def _offline_tick_bridge_v1(self, binding, action, gate, outcome):
        if action in {"begin", "validate"}:
            await self._mapped(binding.namespace, binding.authority_namespace)
        handshake, grant = self._identity()
        return await self._transport.d11_offline_tick_bridge_v1(self._request, handshake, grant,
            binding=binding, action=action, gate=gate, outcome=outcome)

    async def _read_current_observation_receipt_v1(self, namespace, authority_namespace, effect_id):
        observed = await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        receipt = await self._transport.v2_execution_read_current_observation_receipt_v1(
            self._request, handshake, namespace=authority_namespace, effect_id=effect_id)
        permit = receipt.pending.permit
        if (permit.authority_id != grant.authority_id or permit.subject != grant.subject
                or permit.generation != observed.generation):
            raise RuntimeError("platform observation receipt installation differs")
        return receipt

    def read_current_effect(
        self, *, namespace: NamespaceId, authority_namespace: str,
        effect_id: str,
    ) -> CurrentEffectReadV2:
        """Return exact Authority evidence; an unavailable read remains unavailable."""
        return self._submit(self._with_session_repair(
            lambda: self._read_current_effect(
                namespace, authority_namespace, effect_id)))

    async def _read_current_effect(
        self, namespace: NamespaceId, authority_namespace: str, effect_id: str,
    ) -> CurrentEffectReadV2:
        identifier(effect_id, "effect_id")
        observed = await self._mapped(namespace, authority_namespace)
        handshake, grant = self._identity()
        reading = await self._transport.v2_execution_read_current_effect(
            self._request, handshake, namespace=authority_namespace,
            effect_id=effect_id)
        if (reading.authority_id != grant.authority_id
                or reading.namespace != authority_namespace
                or reading.effect_id != effect_id
                or reading.activation_generation != observed.generation):
            raise RuntimeError("v2 current effect identity changed")
        return reading

    def execution_read_current_dispatch_handoff(
        self, *, namespace: NamespaceId, authority_namespace: str,
        start: HandoffStartV2, claimed_receipt: MutationReceiptV2,
    ) -> tuple[FencePermitV2, RestoreAnchor, CurrentEffectReadV2]:
        return self._submit(self._with_session_repair(
            lambda: self._execution_read_current_dispatch_handoff(
                namespace, authority_namespace, start, claimed_receipt)))

    async def _execution_read_current_dispatch_handoff(
        self, namespace: NamespaceId, authority_namespace: str,
        start: HandoffStartV2, claimed_receipt: MutationReceiptV2,
    ) -> tuple[FencePermitV2, RestoreAnchor, CurrentEffectReadV2]:
        if (type(start) is not HandoffStartV2 or start.replay
                or type(claimed_receipt) is not MutationReceiptV2
                or type(claimed_receipt.pending.binding) is not ExecutionBindingV2
                or claimed_receipt.pending.permit.namespace != authority_namespace
                or start.namespace != authority_namespace):
            raise ValueError("current V2 handoff identity differs")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_bootstrap(
            self._request, handshake, namespace)
        if (observed.authority_namespace != authority_namespace
                or observed.authority_id != grant.authority_id
                or start.permit.subject != grant.subject
                or start.permit.authority_id != grant.authority_id
                or start.permit.generation != observed.generation):
            raise RuntimeError("current V2 handoff installation differs")
        return await self._transport.v2_execution_read_current_dispatch_handoff(
            self._request, handshake, start=start, claimed_receipt=claimed_receipt)

    def execution_observe_v2(
        self, *, namespace: NamespaceId, authority_namespace: str,
        claimed_receipt: MutationReceiptV2, observation: PlatformObservationV2,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        try:
            return self._submit(self._with_session_repair(
                lambda: self._execution_observe_v2(
                    namespace, authority_namespace, claimed_receipt, observation)))
        except RuntimeError as exc:
            if isinstance(exc, V2FenceOutcomeUnknown) or str(exc) in _REPAIRABLE_ERRORS:
                raise V2FenceOutcomeUnknown(
                    "V2 observation outcome unknown for observation_id="
                    + observation.observation_id
                    + "; retry only the exact claimed receipt and observation") from exc
            raise

    async def _execution_observe_v2(
        self, namespace: NamespaceId, authority_namespace: str,
        claimed_receipt: MutationReceiptV2, observation: PlatformObservationV2,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        if (type(claimed_receipt) is not MutationReceiptV2
                or type(observation) is not PlatformObservationV2
                or type(claimed_receipt.pending.binding) is not ExecutionBindingV2
                or observation.binding != claimed_receipt.pending.binding
                or claimed_receipt.pending.permit.namespace != authority_namespace):
            raise ValueError("V2 observation identity differs")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_bootstrap(
            self._request, handshake, namespace)
        if (observed.authority_namespace != authority_namespace
                or observed.authority_id != grant.authority_id
                or claimed_receipt.pending.permit.subject != grant.subject
                or claimed_receipt.pending.permit.authority_id != grant.authority_id):
            raise RuntimeError("V2 observation installation differs")
        return await self._transport.v2_execution_observe_v2(
            self._request, handshake, claimed_receipt=claimed_receipt,
            observation=observation)

    def execution_prepare(
        self, *, namespace: NamespaceId, authority_namespace: str,
        permit: FencePermitV2, mutation_id: str,
        footprint: RecoveryConstraintFootprint,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        """Record only the durable prepared phase, never a platform send."""
        with self._lock:
            try:
                return self._submit(self._with_session_repair(lambda: self._execution_prepare(
                    namespace, authority_namespace, permit, mutation_id, footprint)))
            except RuntimeError as exc:
                if isinstance(exc, V2FenceOutcomeUnknown) or str(exc) in _REPAIRABLE_ERRORS:
                    raise V2FenceOutcomeUnknown(
                        "v2 prepared outcome unknown for mutation_id=" + mutation_id
                        + "; retry only with the original permit and footprint") from exc
                raise

    async def _execution_prepare(
        self, namespace: NamespaceId, authority_namespace: str,
        permit: FencePermitV2, mutation_id: str,
        footprint: RecoveryConstraintFootprint,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        identifier(mutation_id, "mutation_id")
        if (type(namespace) is not NamespaceId or type(permit) is not FencePermitV2
                or permit.operation != "dispatch" or permit.namespace != authority_namespace
                or type(footprint) is not RecoveryConstraintFootprint
                or footprint.namespace != authority_namespace
                or footprint.effect_id != permit.effect_id):
            raise ValueError("v2 prepared dispatch identity is invalid")
        handshake, grant = self._identity()
        # A lost response can leave a durable pending marker. Bootstrap still proves
        # the installed mapping while its state is RECOVERING and anchor is absent.
        observed = await self._transport.v2_namespace_bootstrap(
            self._request, handshake, namespace)
        if (observed.authority_namespace != authority_namespace
                or observed.authority_id != grant.authority_id
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject):
            raise RuntimeError("v2 prepared dispatch mapping changed")
        return await self._transport.v2_execution_prepare(
            self._request, handshake, permit=permit,
            mutation_id=mutation_id, footprint=footprint)

    def execution_claim(
        self, *, namespace: NamespaceId, authority_namespace: str,
        prepared_receipt: MutationReceiptV2, binding: ExecutionBindingV1,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        return self._claim(namespace=namespace, authority_namespace=authority_namespace,
                           prepared_receipt=prepared_receipt, binding=binding,
                           v2=False)

    def execution_claim_v2(
        self, *, namespace: NamespaceId, authority_namespace: str,
        prepared_receipt: MutationReceiptV2, binding: ExecutionBindingV2,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        return self._claim(namespace=namespace, authority_namespace=authority_namespace,
                           prepared_receipt=prepared_receipt, binding=binding,
                           v2=True)

    def _claim(
        self, *, namespace: NamespaceId, authority_namespace: str,
        prepared_receipt: MutationReceiptV2,
        binding: ExecutionBindingV1 | ExecutionBindingV2, v2: bool,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        """Persist a claimed operation; a separate current start is still required."""
        try:
            return self._submit(self._with_session_repair(lambda: self._execution_claim(
                namespace, authority_namespace, prepared_receipt, binding, v2)))
        except RuntimeError as exc:
            if isinstance(exc, V2FenceOutcomeUnknown) or str(exc) in _REPAIRABLE_ERRORS:
                raise V2FenceOutcomeUnknown(
                    "v2 claim outcome unknown for operation_id=" + binding.operation_id
                    + "; replay only the exact prepared receipt and binding") from exc
            raise

    async def _execution_claim(
        self, namespace: NamespaceId, authority_namespace: str,
        prepared_receipt: MutationReceiptV2,
        binding: ExecutionBindingV1 | ExecutionBindingV2, v2: bool,
    ) -> tuple[MutationReceiptV2, FencePermitV2]:
        if (type(namespace) is not NamespaceId
                or type(prepared_receipt) is not MutationReceiptV2
                or type(binding) is not (ExecutionBindingV2 if v2 else ExecutionBindingV1)
                or binding.namespace != authority_namespace
                or binding.permit != prepared_receipt.pending.permit):
            raise ValueError("v2 execution claim identity is invalid")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_bootstrap(
            self._request, handshake, namespace)
        if (observed.authority_namespace != authority_namespace
                or observed.authority_id != grant.authority_id
                or binding.permit.authority_id != grant.authority_id
                or binding.permit.subject != grant.subject):
            raise RuntimeError("v2 execution claim mapping changed")
        claim = (self._transport.v2_execution_claim_v2 if v2
                 else self._transport.v2_execution_claim)
        return await claim(
            self._request, handshake,
            prepared_receipt=prepared_receipt, binding=binding)

    def execution_begin_handoff(
        self, *, namespace: NamespaceId, authority_namespace: str,
        claimed_receipt: MutationReceiptV2, handoff_id: str,
    ) -> HandoffStartV2:
        return self._begin_handoff(namespace=namespace,
                                   authority_namespace=authority_namespace,
                                   claimed_receipt=claimed_receipt,
                                   handoff_id=handoff_id, v2=False)

    def execution_begin_handoff_v2(
        self, *, namespace: NamespaceId, authority_namespace: str,
        claimed_receipt: MutationReceiptV2, handoff_id: str,
    ) -> HandoffStartV2:
        return self._begin_handoff(namespace=namespace,
                                   authority_namespace=authority_namespace,
                                   claimed_receipt=claimed_receipt,
                                   handoff_id=handoff_id, v2=True)

    def _begin_handoff(
        self, *, namespace: NamespaceId, authority_namespace: str,
        claimed_receipt: MutationReceiptV2, handoff_id: str, v2: bool,
    ) -> HandoffStartV2:
        """Record one final handoff start; never a platform send operation."""
        try:
            return self._submit(self._with_session_repair(
                lambda: self._execution_begin_handoff(
                    namespace, authority_namespace, claimed_receipt, handoff_id, v2)))
        except RuntimeError as exc:
            if isinstance(exc, V2FenceOutcomeUnknown) or str(exc) in _REPAIRABLE_ERRORS:
                raise V2FenceOutcomeUnknown(
                    "v2 handoff start outcome unknown for handoff_id=" + handoff_id
                    + "; replay only the exact committed claim and handoff ID") from exc
            raise

    async def _execution_begin_handoff(
        self, namespace: NamespaceId, authority_namespace: str,
        claimed_receipt: MutationReceiptV2, handoff_id: str, v2: bool,
    ) -> HandoffStartV2:
        identifier(handoff_id, "handoff_id")
        if (type(namespace) is not NamespaceId
                or type(claimed_receipt) is not MutationReceiptV2
                or claimed_receipt.durable_state != "committed"
                or claimed_receipt.pending.phase != "claimed"
                or type(claimed_receipt.pending.binding) is not (
                    ExecutionBindingV2 if v2 else ExecutionBindingV1)
                or claimed_receipt.pending.permit.namespace != authority_namespace):
            raise ValueError("v2 handoff start identity is invalid")
        handshake, grant = self._identity()
        observed = await self._transport.v2_namespace_bootstrap(
            self._request, handshake, namespace)
        permit = claimed_receipt.pending.permit
        if (observed.authority_namespace != authority_namespace
                or observed.authority_id != grant.authority_id
                or permit.authority_id != grant.authority_id
                or permit.subject != grant.subject):
            raise RuntimeError("v2 handoff start mapping changed")
        begin = (self._transport.v2_execution_begin_handoff_v2 if v2
                 else self._transport.v2_execution_begin_handoff)
        return await begin(
            self._request, handshake,
            claimed_receipt=claimed_receipt, handoff_id=handoff_id)

    def validate_fence(self, scope: FenceScope) -> FencePermitV2:
        return self._submit(self._with_session_repair(lambda: self._validate_fence(scope)))

    async def _check_scope(self, scope: FenceScope) -> tuple[AuthorityHandshake, InstallationGrantV2]:
        if type(scope) is not FenceScope or scope.operation not in _CONTENT_OPERATIONS:
            raise ValueError("unsupported v2 content fence scope")
        if self._mapped_namespaces.get(scope.namespace) != scope.authority_namespace:
            await self._mapped(scope.namespace, scope.authority_namespace)
        handshake, grant = self._identity()
        if (scope.permit.subject != grant.subject
                or scope.permit.authority_id != grant.authority_id):
            raise RuntimeError("v2 fence scope installation or activation mismatch")
        return handshake, grant

    async def _validate_fence(self, scope: FenceScope) -> FencePermitV2:
        handshake, _ = await self._check_scope(scope)
        return await self._transport.v2_validate_fence(self._request, handshake, scope.permit)

    def finish_fence(self, scope: FenceScope, *, request_id: str, request_digest: str) -> None:
        with self._lock:
            self.recover_pending_finish()
            try:
                self._submit(self._with_session_repair(
                    lambda: self._finish_fence(scope, request_id, request_digest)))
            except RuntimeError:
                if type(scope) is FenceScope:
                    self._pending_finish = _PendingFinish(scope, request_id, request_digest)
                raise

    async def _finish_fence(self, scope: FenceScope, request_id: str, request_digest: str) -> None:
        handshake, _ = await self._check_scope(scope)
        await self._transport.v2_finish_fence(
            self._request, handshake, scope.permit,
            request_id=request_id, request_digest=request_digest,
        )

    def close(self) -> None:
        self._reject_event_loop()
        recovery_failure: V2FenceOutcomeUnknown | None = None
        try:
            self.recover_pending_finish()
            self.recover_pending_begin()
        except V2FenceOutcomeUnknown as exc:
            recovery_failure = exc
        failure: BaseException | None = None
        with self._lock:
            if self._closed:
                return
            try:
                future = asyncio.run_coroutine_threadsafe(self._transport.close(), self._loop)
                future.result(timeout=self._timeout)
            except FutureTimeout as exc:
                future.cancel()
                failure = RuntimeError("v2 authority close timed out")
                failure.__cause__ = exc
            except BaseException as exc:
                failure = exc
            finally:
                self._closed = True
                self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=self._timeout)
        if self._thread.is_alive():
            raise RuntimeError("v2 authority thread did not stop")
        if failure is not None:
            raise failure
        if recovery_failure is not None:
            raise recovery_failure

    def __enter__(self) -> V2FencePort:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def observe_current_owner_goal_cancellation_projection_v1(self,*,scope,cancel_operation_id,original_ref):
        return self._submit(self._with_session_repair(lambda:self._observe_current_owner_goal_cancellation_projection_v1(
            scope=scope,cancel_operation_id=cancel_operation_id,original_ref=original_ref)))

    async def _observe_current_owner_goal_cancellation_projection_v1(self,*,scope,cancel_operation_id,original_ref):
        from ..runtime_contracts import FenceScope
        from ..authority_service.v2_contract import to_wire as fence_to_wire
        from ..authority_service.owner_goal_projection_contract_v1 import goal_projection_from_wire_v1
        if type(scope) is not FenceScope or scope.operation not in {"read","write"}:
            raise TypeError("actual independent Goal projection WRITE scope required")
        await self._mapped(scope.namespace,scope.authority_namespace)
        handshake,installed=self._identity()
        observed=await self._transport._content_rpc(self._request,handshake,
            "owner_goal_cancellation_projection_observe_v1",
            {"namespace":scope.authority_namespace,"cancel_operation_id":cancel_operation_id,
                "original_ref":original_ref,"permit":fence_to_wire(scope.permit)},protocol=AUTHORITY_V2_PROTOCOL)
        if type(observed) is not dict or set(observed)!={"observation"}:
            raise RuntimeError("actual Goal projection response fields differ")
        value=goal_projection_from_wire_v1(observed["observation"])
        if (value.original.request.namespace!=scope.namespace
                or value.original.request.installation_id!=installed.installation_id
                or value.original.request.cancel_operation_id!=cancel_operation_id or value.original.original_ref!=original_ref
                or value.permit!=scope.permit
                or scope.operation!={"projection_write":"write","projection_lookup":"read"}[value.scope_kind]
                or value.scope_kind=="projection_write" and value.committed_bridge is None and (value.metadata.graph_revision!=scope.graph_revision
                    or value.metadata.graph_epoch!=scope.graph_epoch.revision)):
            raise RuntimeError("actual Goal projection response changed its held WRITE/causal/metadata scope")
        return value

    def read_next_owner_goal_cancellation_projection_v1(self,*,bundle,after_cancel_operation_id):
        return self._submit(self._with_session_repair(lambda:self._read_next_owner_goal_cancellation_projection_v1(
            bundle=bundle,after_cancel_operation_id=after_cancel_operation_id)))

    async def _read_next_owner_goal_cancellation_projection_v1(self,*,bundle,after_cancel_operation_id):
        from ..authority_service.owner_goal_cancellation_contract_v1 import OwnerGoalCancellationOriginalV1,owner_goal_cancellation_from_wire_v1
        policy=bundle.installation_policy
        await self._mapped(policy.namespace,policy.authority_namespace)
        handshake,installed=self._identity()
        response=await self._transport._content_rpc(self._request,handshake,"owner_goal_cancellation_projection_next_v1",
            {"namespace":policy.authority_namespace,"after_cancel_operation_id":after_cancel_operation_id},
            protocol=AUTHORITY_V2_PROTOCOL)
        if type(response) is not dict or set(response)!={"original"}:
            raise RuntimeError("Goal metadata cursor response fields differ")
        if response["original"] is None:return None
        original=owner_goal_cancellation_from_wire_v1(response["original"],OwnerGoalCancellationOriginalV1)
        if (original.request.namespace!=policy.namespace or original.request.installation_id!=installed.installation_id
                or original.request.cancel_operation_id<=after_cancel_operation_id):
            raise RuntimeError("Goal metadata cursor changed its exact original installation/order")
        return original



__all__ = ("V2FenceOutcomeUnknown", "V2FencePort", "VerifiedIngressClockV2")
