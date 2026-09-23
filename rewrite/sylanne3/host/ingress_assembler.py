from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import Protocol

from ..domains.d06 import D06DomainAdapter, SourceAdmission, SourceAdmissionProposal
from ..graph_coordinator import GraphCoordinator
from ..runtime.d11_types import runtime_job_key, runtime_outbox_key
from ..runtime.first_ingress_bundle import build_first_ingress_bundle
from ..runtime.ingress_contracts import (
    CanonicalIngressObservation,
    CommittedIngressReplay,
    IngressAuthoritySession,
    IngressObservationContext,
)
from ..runtime.jobs import PersistentJob
from .d06_ingress import (
    AuthorizedIngressCommit, ingress_content_fingerprint, ingress_source_identity,
)
from .ingress import HostIngressEnvelope


class IngressObservationAuthority(Protocol):
    """Durable first-observation and replay authority.

    W01 must hold the content fence for the exact namespace and activation
    generation while storing the first fingerprint/learned_at or sealing the
    bundle digest. Namespace+operation uniqueness must span generations; the
    generation selects the current fence and must not partition replay state.
    It must reject a different fingerprint for the same operation and return
    the same canonical values after restart. Its operation
    lookup must use GraphCoordinator.get_operation before rebuilding an already
    committed bundle. A process-local cache or chat configuration is not an
    implementation.
    """

    async def lookup_committed(
        self,
        context: IngressObservationContext,
        session: IngressAuthoritySession,
        content_fingerprint: str,
    ) -> CommittedIngressReplay | None: ...

    async def observe_first(
        self,
        context: IngressObservationContext,
        session: IngressAuthoritySession,
        content_fingerprint: str,
        learned_at: float,
    ) -> CanonicalIngressObservation: ...

    async def seal_bundle(
        self,
        context: IngressObservationContext,
        session: IngressAuthoritySession,
        observation: CanonicalIngressObservation,
        bundle_digest: str,
    ) -> str: ...


@dataclass(frozen=True)
class IngressAssemblyRequest:
    host: HostIngressEnvelope
    admission: SourceAdmission
    candidate: SourceAdmissionProposal
    activity_id: str
    operation_id: str
    job_id: str
    job_ref: str
    outbox_id: str
    outbox_ref: str
    payload_ref: str
    idempotency_key: str


@dataclass(frozen=True)
class IngressRuntimeAuthorization:
    """Result of trusted bootstrap plus real D02/D11 issuer qualification."""

    envelope: object
    lease: object
    job: PersistentJob

    def __post_init__(self) -> None:
        from ..runtime_contracts import CommandEnvelope

        if not isinstance(self.envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if self.lease is None:
            raise ValueError("coordinator lease is required")
        if not isinstance(self.job, PersistentJob):
            raise TypeError("job must be PersistentJob")


class TrustedIngressIssuer(Protocol):
    """Host-only adapter over bootstrap, D02/D11 issuers and the shared DB.

    The implementation must obtain the coordinator lease through the injected
    bootstrap, bind a signed resource quote and budget grant to ``request``,
    and derive ``job`` with ``D11BudgetJobIssuer.job_for``. It must return
    revision-0 proofs for source, access, job and outbox in the command
    envelope. It must derive deadlines, quote/grant refs and other signed
    values from the durable canonical observation, reusing them on an
    uncommitted retry; fresh wall-clock values would change DomainBundle.digest.
    Chat input cannot implement this interface.
    """

    async def begin_authority(
        self,
        host: HostIngressEnvelope,
        operation_id: str,
        coordinator: GraphCoordinator,
        bootstrap: object,
    ) -> IngressAuthoritySession: ...

    async def authorize(
        self,
        request: IngressAssemblyRequest,
        session: IngressAuthoritySession,
        coordinator: GraphCoordinator,
        bootstrap: object,
    ) -> IngressRuntimeAuthorization: ...


class LocalIngressAssembler:
    """Build the atomic D06 source plus internal D11 encoding work bundle."""

    def __init__(
        self,
        bootstrap: object,
        issuer: TrustedIngressIssuer,
        observation_authority: IngressObservationAuthority,
    ) -> None:
        if bootstrap is None or isinstance(bootstrap, (str, bytes, int, float)):
            raise TypeError("bootstrap must be an opaque host capability")
        if not callable(getattr(issuer, "begin_authority", None)) or not callable(
            getattr(issuer, "authorize", None)
        ):
            raise TypeError("issuer requires begin_authority and authorize")
        if not callable(getattr(observation_authority, "observe_first", None)):
            raise TypeError("observation_authority requires observe_first")
        if not callable(getattr(observation_authority, "lookup_committed", None)):
            raise TypeError("observation_authority requires lookup_committed")
        if not callable(getattr(observation_authority, "seal_bundle", None)):
            raise TypeError("observation_authority requires seal_bundle")
        self._bootstrap = bootstrap
        self._issuer = issuer
        self._observation_authority = observation_authority

    async def assemble(
        self,
        envelope: HostIngressEnvelope,
        admission: SourceAdmission,
        candidate: SourceAdmissionProposal,
        coordinator: GraphCoordinator,
    ) -> AuthorizedIngressCommit | CommittedIngressReplay:
        if not isinstance(envelope, HostIngressEnvelope):
            raise TypeError("envelope must be HostIngressEnvelope")
        if not isinstance(admission, SourceAdmission):
            raise TypeError("admission must be SourceAdmission")
        if not isinstance(candidate, SourceAdmissionProposal):
            raise TypeError("candidate must be SourceAdmissionProposal")
        if not isinstance(coordinator, GraphCoordinator):
            raise TypeError("coordinator must be GraphCoordinator")
        expected = D06DomainAdapter(envelope.namespace).admit_source(admission)
        if candidate != expected or admission.source_id != envelope.lineage.source_ref:
            raise ValueError("D06 source candidate differs from host lineage")

        digest = ingress_source_identity(envelope.lineage.source_ref)
        activity_id = "ingress-" + digest[:24]
        operation_id = "host-ingress-" + digest[:32]
        job_id = "encode-" + digest[:24]
        outbox_id = "encode-outbox-" + digest[:24]
        session = await self._issuer.begin_authority(
            envelope, operation_id, coordinator, self._bootstrap
        )
        if not isinstance(session, IngressAuthoritySession):
            raise TypeError("issuer returned invalid ingress authority session")
        session_authority = session.authority
        if (
            session_authority.namespace != envelope.namespace
            or session_authority.issuer_domain != "d06"
            or session_authority.purpose != "context"
            or session_authority.audience != (envelope.conversation_ref,)
            or not {"event", "activity"}.issubset(session_authority.owner_scope)
        ):
            raise ValueError("ingress authority session changed host scope")
        observation_context = IngressObservationContext(
            session_authority.namespace,
            session_authority.activation_generation,
            session_authority.actor,
            session_authority.capability_ref,
            operation_id,
        )
        observation_context.require_session(session)
        fingerprint = ingress_content_fingerprint(envelope)
        replay = await self._observation_authority.lookup_committed(
            observation_context, session, fingerprint
        )
        if replay is not None:
            if (
                not isinstance(replay, CommittedIngressReplay)
                or replay.receipt.operation_id != operation_id
                or replay.receipt.activity_id != activity_id
                or replay.observation.content_fingerprint != fingerprint
                or replay.session is not session
            ):
                raise ValueError("committed ingress replay changed host identity")
            current = await asyncio.to_thread(
                coordinator.get_operation, session.authority, session.lease,
                operation_id,
            )
            if current != replay.receipt:
                raise ValueError("committed ingress replay has no current coordinator receipt")
            return replay
        observation = await self._observation_authority.observe_first(
            observation_context, session, fingerprint, envelope.learned_at
        )
        if (
            not isinstance(observation, CanonicalIngressObservation)
            or observation.operation_id != operation_id
            or observation.content_fingerprint != fingerprint
        ):
            raise ValueError("first-observation authority rejected ingress identity")
        canonical_host = replace(envelope, learned_at=observation.learned_at)
        canonical_admission = SourceAdmission(
            admission.source_id,
            admission.text,
            admission.speaker_id,
            admission.source_kind,
            admission.content_reality,
            admission.evidence_eligibility,
            admission.internal_activity_actuality,
            admission.occurred_at,
            observation.learned_at,
            admission.provenance_family,
            admission.audiences,
            admission.purposes,
            admission.parent_source_ids,
            admission.subjective_confidence,
        )
        canonical_candidate = D06DomainAdapter(envelope.namespace).admit_source(
            canonical_admission
        )
        job_key = runtime_job_key(
            envelope.namespace.bot_id, envelope.namespace.persona_id,
            activity_id, job_id,
        )
        outbox_key = runtime_outbox_key(
            envelope.namespace.bot_id, envelope.namespace.persona_id,
            activity_id, outbox_id,
        )
        request = IngressAssemblyRequest(
            canonical_host,
            canonical_admission,
            canonical_candidate,
            activity_id,
            operation_id,
            job_id,
            job_key.token,
            outbox_id,
            outbox_key.token,
            canonical_host.lineage.source_ref,
            "host-ingress:" + digest,
        )
        authorization = await self._issuer.authorize(
            request, session, coordinator, self._bootstrap
        )
        if not isinstance(authorization, IngressRuntimeAuthorization):
            raise TypeError("issuer returned invalid ingress authorization")
        command = authorization.envelope
        if (
            command.authority.namespace != envelope.namespace
            or command.authority != session.authority
            or command.authority.issuer_domain != "d06"
            or command.authority.purpose != "context"
            or command.authority.audience != (envelope.conversation_ref,)
            or not {"event", "activity"}.issubset(command.authority.owner_scope)
        ):
            raise ValueError("trusted ingress authorization changed host identity or scope")
        if authorization.lease is not session.lease:
            raise ValueError("trusted ingress authorization changed coordinator lease")
        bundle = build_first_ingress_bundle(
            command, authorization.job, canonical_admission,
            source_identity=digest, payload_ref=request.payload_ref,
            idempotency_key=request.idempotency_key,
        )
        sealed_digest = await self._observation_authority.seal_bundle(
            observation_context, session, observation, bundle.digest
        )
        if sealed_digest != bundle.digest:
            raise ValueError("retry changed the canonical ingress bundle")
        return AuthorizedIngressCommit(bundle, authorization.lease)


__all__ = (
    "IngressAssemblyRequest",
    "IngressAuthoritySession",
    "CanonicalIngressObservation",
    "IngressObservationAuthority",
    "IngressObservationContext",
    "IngressRuntimeAuthorization",
    "LocalIngressAssembler",
    "TrustedIngressIssuer",
    "ingress_content_fingerprint",
)
