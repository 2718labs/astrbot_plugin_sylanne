"""Translate host observations into the graph's typed v2 ingress input."""

from __future__ import annotations

from ..graph_coordinator import IngressHostFacts, IngressLineage
from .ingress import HostIngressEnvelope


def ingress_host_facts(envelope: HostIngressEnvelope) -> IngressHostFacts:
    lineage = envelope.lineage
    return IngressHostFacts(
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


__all__ = ("ingress_host_facts",)
