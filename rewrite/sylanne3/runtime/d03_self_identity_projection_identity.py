"""Stable D03 projection operations for one Authority registration and source."""

from __future__ import annotations

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest


def _source(namespace: NamespaceId, source_ref: str) -> None:
    if type(namespace) is not NamespaceId:
        raise TypeError("typed D03 namespace required")
    key = AtomKey.from_token(source_ref)
    if (key.type_name != "memory.source"
            or NamespaceId.from_key(key) != namespace):
        raise ValueError("same-namespace source graph token required")


def d03_self_identity_projection_operation_id_v1(
    namespace: NamespaceId, source_ref: str, certification_ref: str,
) -> str:
    _source(namespace, source_ref)
    if (type(certification_ref) is not str
            or not certification_ref.startswith("authority:self-identity:")):
        raise ValueError("stable Authority registration reference required")
    return "d03-self-projection-" + canonical_digest({
        "schema": "sylanne3.d03.self-identity-projection-operation.v1",
        "namespace": namespace.as_tuple,
        "source_ref": source_ref,
        "certification_ref": certification_ref,
    })[:40]


def d03_self_identity_projection_activity_id_v1(
    namespace: NamespaceId, source_ref: str,
) -> str:
    _source(namespace, source_ref)
    return "d03-self-activity-" + canonical_digest({
        "schema": "sylanne3.d03.self-identity-projection-activity.v1",
        "namespace": namespace.as_tuple,
        "source_ref": source_ref,
    })[:40]


__all__ = (
    "d03_self_identity_projection_operation_id_v1",
    "d03_self_identity_projection_activity_id_v1",
)
