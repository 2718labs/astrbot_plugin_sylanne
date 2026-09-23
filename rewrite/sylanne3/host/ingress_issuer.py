"""Host-side ingress authority bound to a coordinator bootstrap.

W01 owns the signed D02/D11 issuance transaction.  This module translates
host facts into its pure data contract without exposing the host package or
the coordinator's private SQLite connection to W01.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph_coordinator import (
    GraphCoordinator,
    IngressAuthorizationResult,
    IngressHostFacts,
    IngressIssuanceRequest,
    IngressLineage,
    UnavailableGuard,
)
from ..runtime_contracts import AuthorityContext
from .ingress import HostIngressEnvelope
from .ingress_assembler import (
    IngressAssemblyRequest,
    IngressAuthoritySession,
    IngressRuntimeAuthorization,
)


@dataclass(frozen=True)
class TrustedIngressIdentity:
    """Installation-owned identity; never constructed from a chat envelope."""

    actor: str
    provider_policy_ref: str
    activation_generation: int

    def __post_init__(self) -> None:
        if not isinstance(self.actor, str) or not self.actor:
            raise ValueError("trusted ingress actor is required")
        if not isinstance(self.provider_policy_ref, str) or not self.provider_policy_ref:
            raise ValueError("trusted provider policy is required")
        if type(self.activation_generation) is not int or self.activation_generation < 0:
            raise ValueError("trusted activation generation must be nonnegative")


class CoordinatorIngressIssuer:
    """Acquire a scoped D06+D11 lease, then delegate signed issuance to W01."""

    def __init__(self, identity: TrustedIngressIdentity) -> None:
        if not isinstance(identity, TrustedIngressIdentity):
            raise TypeError("trusted ingress identity is required")
        self._identity = identity

    async def begin_authority(
        self,
        host: HostIngressEnvelope,
        operation_id: str,
        coordinator: GraphCoordinator,
        bootstrap: object,
    ) -> IngressAuthoritySession:
        if not isinstance(host, HostIngressEnvelope):
            raise TypeError("host ingress envelope is required")
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError("ingress operation ID is required")
        if not isinstance(coordinator, GraphCoordinator):
            raise TypeError("GraphCoordinator is required")
        lease, capability_ref = coordinator.grant(
            bootstrap,
            actor=self._identity.actor,
            issuer_domain="d06",
            namespace=host.namespace,
            domains=("d06", "d11"),
            activation_generation=self._identity.activation_generation,
            operation_id=operation_id,
        )
        authority = AuthorityContext(
            self._identity.actor,
            "d06",
            capability_ref,
            host.namespace,
            ("event", "activity"),
            "context",
            (host.conversation_ref,),
            self._identity.provider_policy_ref,
            self._identity.activation_generation,
        )
        return IngressAuthoritySession(authority, lease)

    async def authorize(
        self,
        request: IngressAssemblyRequest,
        session: IngressAuthoritySession,
        coordinator: GraphCoordinator,
        bootstrap: object,
    ) -> IngressRuntimeAuthorization:
        if not isinstance(request, IngressAssemblyRequest):
            raise TypeError("ingress assembly request is required")
        if not isinstance(session, IngressAuthoritySession):
            raise TypeError("ingress authority session is required")
        if not isinstance(coordinator, GraphCoordinator):
            raise TypeError("GraphCoordinator is required")
        authority = session.authority
        if (
            authority.namespace != request.host.namespace
            or authority.actor != self._identity.actor
            or authority.issuer_domain != "d06"
            or authority.owner_scope != ("event", "activity")
            or authority.purpose != "context"
            or authority.audience != (request.host.conversation_ref,)
            or authority.provider_policy_ref != self._identity.provider_policy_ref
            or authority.activation_generation != self._identity.activation_generation
        ):
            raise ValueError("ingress authorization differs from trusted host scope")

        issue = getattr(coordinator, "issue_ingress_authorization", None)
        if not callable(issue):
            raise UnavailableGuard(
                "W01 public ingress issuance transaction is unavailable"
            )
        host = request.host
        lineage = host.lineage
        w01_request = IngressIssuanceRequest(
            IngressHostFacts(
                host.namespace,
                host.platform_ref,
                host.conversation_ref,
                host.sender_ref,
                host.message_id,
                host.text,
                host.occurred_at,
                host.learned_at,
                host.visibility,
                IngressLineage(
                    lineage.source_ref,
                    lineage.source_kind,
                    lineage.provenance_family,
                    lineage.content_reality,
                    lineage.evidence_eligibility,
                    lineage.internal_activity_actuality,
                ),
            ),
            request.admission,
            request.candidate,
            request.activity_id,
            request.operation_id,
            request.job_id,
            request.job_ref,
            request.outbox_id,
            request.outbox_ref,
            request.payload_ref,
            request.idempotency_key,
        )
        result = issue(bootstrap, w01_request, session)
        if type(result) is not IngressAuthorizationResult:
            raise TypeError("W01 returned an invalid ingress authorization")
        if result.lease is not session.lease or result.envelope.authority != authority:
            raise ValueError("W01 changed the ingress authority or lease")
        return IngressRuntimeAuthorization(result.envelope, result.lease, result.job)


__all__ = ("CoordinatorIngressIssuer", "TrustedIngressIdentity")
