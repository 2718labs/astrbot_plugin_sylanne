"""A changed Authority registration gets a new D03 stage operation."""

from sylanne3.memory_types import source_key
from sylanne3.runtime.d03_self_identity_projection_identity import (
    d03_self_identity_projection_activity_id_v1,
    d03_self_identity_projection_operation_id_v1,
)
from sylanne3.runtime_contracts import NamespaceId


def test_projection_operation_tracks_registration_without_changing_activity():
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "source").token
    first = d03_self_identity_projection_operation_id_v1(
        namespace, source, "authority:self-identity:first")
    assert first == d03_self_identity_projection_operation_id_v1(
        namespace, source, "authority:self-identity:first")
    assert first != d03_self_identity_projection_operation_id_v1(
        namespace, source, "authority:self-identity:replacement")
    assert d03_self_identity_projection_activity_id_v1(namespace, source).startswith(
        "d03-self-activity-")
