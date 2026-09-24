"""Business operation identity for a retried first D04 baseline stage."""

from __future__ import annotations

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest


def d04_baseline_retry_operation_id_v2(
    namespace: NamespaceId, source_ref: str, event_ref: str,
    perspective_ref: str, perspective_revision: int,
    previous_operation_id: str, retry_index: int,
) -> str:
    if type(namespace) is not NamespaceId:
        raise TypeError("typed D04 namespace required")
    for token, type_name in (
            (source_ref, "memory.source"), (event_ref, "d03.world_event"),
            (perspective_ref, "d03.self_perspective.v1")):
        key = AtomKey.from_token(token)
        if key.type_name != type_name or NamespaceId.from_key(key) != namespace:
            raise ValueError("D04 retry graph identity differs")
    if (type(perspective_revision) is not int or perspective_revision < 1
            or type(retry_index) is not int or retry_index < 1
            or type(previous_operation_id) is not str
            or not previous_operation_id.startswith("d04-baseline-")):
        raise ValueError("D04 retry needs prior operation and positive ordinal")
    return "d04-baseline-" + canonical_digest({
        "schema": "sylanne3.d04.encoding-baseline-retry.v2",
        "namespace": namespace.as_tuple,
        "source_ref": source_ref,
        "event_ref": event_ref,
        "perspective_ref": perspective_ref,
        "perspective_revision": perspective_revision,
        "previous_operation_id": previous_operation_id,
        "retry_index": retry_index,
    })[:40]


__all__ = ("d04_baseline_retry_operation_id_v2",)
