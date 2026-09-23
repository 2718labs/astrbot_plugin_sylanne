from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import hashlib
from typing import Protocol

from ..domains.d06 import D06DomainAdapter, SourceAdmission, SourceAdmissionProposal
from ..graph_coordinator import GraphCoordinator
from ..runtime.ingress_contracts import CommittedIngressReplay
from ..runtime_contracts import CommitReceipt, DomainBundle, canonical_digest
from .ingress import HostIngressEnvelope, IngressReceipt


def ingress_source_identity(source_ref: str) -> str:
    return hashlib.sha256(
        ("sylanne3.host-ingress.v1:" + source_ref).encode("ascii")
    ).hexdigest()


def ingress_content_fingerprint(envelope: HostIngressEnvelope) -> str:
    """Fingerprint immutable host content while excluding local receive time."""

    if not isinstance(envelope, HostIngressEnvelope):
        raise TypeError("envelope must be HostIngressEnvelope")
    return canonical_digest({
        "namespace": envelope.namespace,
        "platform_ref": envelope.platform_ref,
        "conversation_ref": envelope.conversation_ref,
        "sender_ref": envelope.sender_ref,
        "message_id": envelope.message_id,
        "text": envelope.text,
        "occurred_at": envelope.occurred_at,
        "visibility": envelope.visibility,
        "lineage": envelope.lineage,
    })


def source_admission_from_host(envelope: HostIngressEnvelope) -> SourceAdmission:
    """Preserve host lineage while producing a bounded D06 source candidate."""

    if not isinstance(envelope, HostIngressEnvelope):
        raise TypeError("envelope must be HostIngressEnvelope")
    reality = {"external_report": "reported"}.get(envelope.lineage.content_reality)
    if reality is None:
        raise ValueError("host lineage cannot be represented by D06")
    return SourceAdmission(
        source_id=envelope.lineage.source_ref,
        text=envelope.text,
        speaker_id=envelope.sender_ref,
        source_kind=envelope.lineage.source_kind,
        content_reality=reality,
        evidence_eligibility=envelope.lineage.evidence_eligibility,
        internal_activity_actuality=envelope.lineage.internal_activity_actuality,
        occurred_at=envelope.occurred_at,
        learned_at=envelope.learned_at,
        provenance_family=envelope.lineage.provenance_family,
        audiences=(envelope.conversation_ref,),
        purposes=("context", "consolidation"),
    )


@dataclass(frozen=True)
class AuthorizedIngressCommit:
    """Complete D06+D11 bundle and opaque coordinator lease from trusted setup."""

    bundle: DomainBundle
    lease: object

    def __post_init__(self) -> None:
        if not isinstance(self.bundle, DomainBundle):
            raise TypeError("bundle must be DomainBundle")
        if self.lease is None:
            raise ValueError("coordinator lease is required")


class IngressBundleAssembler(Protocol):
    """Trusted local seam owning bootstrap access and D02/D11 issuer calls.

    It must build the CommandEnvelope, obtain exact revision-0 source/access
    proofs, compile the D06 proposal, and add the required D11 persistent job,
    outbox and idempotency records to the same DomainBundle. Implementations
    must receive their lease from GraphCoordinator.grant through trusted host
    bootstrap; neither the event nor chat configuration may supply it.
    """

    async def assemble(
        self,
        envelope: HostIngressEnvelope,
        admission: SourceAdmission,
        candidate: SourceAdmissionProposal,
        coordinator: GraphCoordinator,
    ) -> AuthorizedIngressCommit | CommittedIngressReplay: ...


def build_d06_ingress_handler(assembler: IngressBundleAssembler):
    if not callable(getattr(assembler, "assemble", None)):
        raise TypeError("assembler requires assemble")

    async def handle(
        envelope: HostIngressEnvelope,
        coordinator: GraphCoordinator,
    ) -> IngressReceipt:
        if not isinstance(envelope, HostIngressEnvelope):
            raise TypeError("envelope must be HostIngressEnvelope")
        if not isinstance(coordinator, GraphCoordinator):
            raise TypeError("coordinator must be GraphCoordinator")
        admission = source_admission_from_host(envelope)
        candidate = D06DomainAdapter(envelope.namespace).admit_source(admission)
        prepared = await assembler.assemble(
            envelope, admission, candidate, coordinator
        )
        if isinstance(prepared, CommittedIngressReplay):
            identity = ingress_source_identity(envelope.lineage.source_ref)
            authority = prepared.session.authority
            if (
                authority.namespace != envelope.namespace
                or authority.issuer_domain != "d06"
                or authority.purpose != "context"
                or authority.audience != (envelope.conversation_ref,)
                or prepared.receipt.operation_id != "host-ingress-" + identity[:32]
                or prepared.receipt.activity_id != "ingress-" + identity[:24]
                or prepared.observation.content_fingerprint != ingress_content_fingerprint(envelope)
            ):
                raise ValueError("committed ingress replay changed host scope or content")
            current = await asyncio.to_thread(
                coordinator.get_operation, prepared.session.authority,
                prepared.session.lease, prepared.receipt.operation_id,
            )
            if current != prepared.receipt:
                raise ValueError("committed ingress replay has no current coordinator receipt")
            return IngressReceipt("duplicate", prepared.receipt.operation_id)
        if not isinstance(prepared, AuthorizedIngressCommit):
            raise TypeError("assembler returned an invalid ingress commit")
        bundle = prepared.bundle
        if bundle.envelope.authority.namespace != envelope.namespace:
            raise ValueError("ingress bundle changed namespace")
        canonical_qualification = replace(
            candidate.qualification,
            learned_at=bundle.envelope.source_qualification.learned_at,
        )
        if bundle.envelope.source_qualification != canonical_qualification:
            raise ValueError("ingress bundle changed source qualification")
        if not any(proposal.domain == "d06" for proposal in bundle.proposals):
            raise ValueError("ingress bundle has no D06 proposal")
        receipt = await asyncio.to_thread(
            coordinator.commit_domain_bundle, bundle, prepared.lease
        )
        if not isinstance(receipt, CommitReceipt):
            raise TypeError("coordinator returned an invalid commit receipt")
        if receipt.operation_id != bundle.envelope.identity.operation_id:
            raise ValueError("commit receipt operation differs from ingress bundle")
        if receipt.status == "committed":
            return IngressReceipt("accepted", receipt.operation_id)
        if receipt.status == "duplicate":
            return IngressReceipt("duplicate", receipt.operation_id)
        return IngressReceipt("rejected")

    return handle


__all__ = (
    "AuthorizedIngressCommit",
    "IngressBundleAssembler",
    "build_d06_ingress_handler",
    "ingress_content_fingerprint",
    "ingress_source_identity",
    "source_admission_from_host",
)
