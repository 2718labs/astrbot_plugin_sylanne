"""Translate host observations into the graph's typed v2 ingress input."""

from __future__ import annotations

from dataclasses import dataclass

from ..domains.d06.attachment_contract_v2 import SourceAdmissionV2
from ..graph_coordinator import IngressHostFacts, IngressLineage
from .authority_profile import AdminD06PrivateReplySourcePolicy
from .d06_ingress import source_admission_from_host
from .ingress import HostIngressEnvelope


@dataclass(frozen=True)
class VerifiedMediaIngressV2:
    host: IngressHostFacts
    source_admission_v2: SourceAdmissionV2


def ingress_host_facts(
    envelope: HostIngressEnvelope,
    *, reply_source_policy: AdminD06PrivateReplySourcePolicy | None = None,
) -> IngressHostFacts | VerifiedMediaIngressV2:
    lineage = envelope.lineage
    host = IngressHostFacts(
        envelope.namespace,
        envelope.platform_ref,
        envelope.conversation_ref,
        envelope.sender_ref,
        envelope.message_id,
        envelope.text,
        envelope.occurred_at,
        # This host clock value is only an untrusted candidate required by the
        # DTO. The coordinator must replace it with its Authority clock sample.
        envelope.learned_at,
        envelope.visibility,
        IngressLineage(
            lineage.source_ref,
            lineage.source_kind,
            lineage.provenance_family,
            lineage.content_reality,
            lineage.evidence_eligibility,
            lineage.internal_activity_actuality,
        ),
    )
    if not envelope.attachments:
        return host
    return VerifiedMediaIngressV2(
        host,
        SourceAdmissionV2(
            source_admission_from_host(
                envelope, reply_source_policy,
                allow_verified_media_v2=True,
            ), envelope.attachments,
        ),
    )


__all__ = ("VerifiedMediaIngressV2", "ingress_host_facts")
