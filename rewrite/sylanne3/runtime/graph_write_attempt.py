"""Canonical Authority fence identity for a domain bundle graph write."""

from __future__ import annotations

import re

from ..runtime_contracts import NamespaceId, canonical_digest


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def domain_bundle_write_attempt_id_v1(
    namespace: NamespaceId, consumer_operation_id: str, bundle_digest: str,
) -> str:
    """Derive the write attempt used by Graph for this exact bundle."""
    if type(namespace) is not NamespaceId:
        raise TypeError("typed business namespace required")
    if type(consumer_operation_id) is not str or not consumer_operation_id:
        raise ValueError("consumer operation ID required")
    if type(bundle_digest) is not str or _SHA256.fullmatch(bundle_digest) is None:
        raise ValueError("invalid bundle digest")
    return "graph-write-" + canonical_digest({
        "namespace": list(namespace.as_tuple),
        "operation_id": consumer_operation_id,
        "bundle_digest": bundle_digest,
    })[:48]


__all__ = ("domain_bundle_write_attempt_id_v1",)
