"""Commit a prepared passive reply through the ordinary graph operation ledger."""

from __future__ import annotations

from ..graph_coordinator import GraphCoordinator
from ..runtime_contracts import AuthorityContext, CommitReceipt, DomainBundle
from ..host.post_c02_reply_driver import (
    PostC02ReplyCandidate, post_c02_reply_operation_id,
)


def commit_prepared_domain_bundle_v1(
    graph: GraphCoordinator, authority: AuthorityContext, lease: object,
    bundle: DomainBundle,
) -> CommitReceipt:
    """Resolve a frozen operation before attempting its graph write."""
    recorded = graph.get_operation(
        authority, lease, bundle.envelope.identity.operation_id)
    if recorded is not None:
        if recorded.operation_digest != bundle.digest:
            raise ValueError("operation replay changed its frozen bundle")
        return recorded
    return graph.commit_domain_bundle(bundle, lease)


def commit_post_c02_reply_bundle_v1(
    graph: GraphCoordinator, authority: AuthorityContext, lease: object,
    *, c02_operation_id: str, source_ref: str,
    candidate: PostC02ReplyCandidate, bundle: DomainBundle,
) -> CommitReceipt:
    """Recover before commit, then let D11 and GraphCoordinator admit the write.

    The installed host must prepare ``candidate`` and ``bundle`` from current
    graph/domain reads under this same lease.  Recovery reads the durable
    ledger before any model or expression generation on a retry.
    """
    if not isinstance(graph, GraphCoordinator) or not isinstance(authority, AuthorityContext):
        raise TypeError("installed graph authority required")
    if not isinstance(candidate, PostC02ReplyCandidate) or not isinstance(bundle, DomainBundle):
        raise TypeError("typed reply candidate and domain bundle required")
    operation_id = post_c02_reply_operation_id(c02_operation_id, source_ref)
    if (candidate.envelope != bundle.envelope
            or candidate.envelope.authority != authority
            or candidate.envelope.identity.operation_id != operation_id
            or tuple(bundle.proposals[:3]) != candidate.proposals
            or source_ref not in bundle.envelope.source_qualification.source_refs
            or c02_operation_id not in bundle.envelope.causation):
        raise ValueError("reply bundle differs from the original C02 candidate")
    c02 = graph.get_operation(authority, lease, c02_operation_id)
    if (c02 is None or c02.status not in {"committed", "duplicate"}
            or not {"memory.episode.v1", "memory.subjective_trace.v2"}
               <= {item.key.type_name for item in c02.write_versions}):
        raise ValueError("original C02 graph operation is not committed")
    return commit_prepared_domain_bundle_v1(graph, authority, lease, bundle)


__all__ = (
    "commit_prepared_domain_bundle_v1", "commit_post_c02_reply_bundle_v1",
)
