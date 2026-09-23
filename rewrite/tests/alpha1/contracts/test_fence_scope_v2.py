"""A graph scope carries the exact v2 permit and admission stamp."""

from dataclasses import FrozenInstanceError, replace

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.graph_types import NamespaceEpoch
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import ContentFencePortV2, FenceScope, NamespaceId


def _scope() -> FenceScope:
    anchor = RestoreAnchor(
        authority_id="authority-A", namespace="authority-namespace-A",
        activation_generation=3, deletion_journal_id="deletion-A",
        deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution-A", execution_seq=0,
        execution_digest="genesis", revocation_epoch=0, proof="opaque-proof",
    )
    permit = FencePermitV2(
        authority_id=anchor.authority_id, namespace=anchor.namespace,
        subject="subject-A", holder="holder-A", generation=3,
        operation="read", operation_id="operation-A", token="t" * 32,
        fence_epoch=7, revision=2, pinned_anchor=anchor,
    )
    return FenceScope(
        namespace=NamespaceId("bot-A", "persona-A"),
        authority_namespace=anchor.namespace, generation=3, operation="read",
        operation_id="operation-A", permit=permit, pinned_anchor=anchor,
        graph_epoch=NamespaceEpoch("bot-A", "persona-A", 5), graph_revision=11,
    )


def test_scope_keeps_real_v2_permit_and_full_anchor_immutable():
    scope = _scope()
    assert scope.permit.pinned_anchor is scope.pinned_anchor
    assert (scope.permit.fence_epoch, scope.permit.revision) == (7, 2)
    assert (scope.graph_epoch.revision, scope.graph_revision) == (5, 11)
    with pytest.raises(FrozenInstanceError):
        scope.permit = None


@pytest.mark.parametrize("change", (
    {"authority_namespace": "authority-namespace-B"},
    {"generation": 4},
    {"operation": "write"},
    {"operation_id": "operation-B"},
    {"pinned_anchor": replace(_scope().pinned_anchor, revocation_epoch=1)},
))
def test_scope_rejects_permit_binding_changes(change):
    with pytest.raises(ValueError, match="scope does not match v2 permit"):
        replace(_scope(), **change)


def test_scope_rejects_unbound_graph_stamp_and_non_v2_permit():
    scope = _scope()
    with pytest.raises(ValueError, match="graph epoch namespace mismatch"):
        replace(scope, graph_epoch=NamespaceEpoch("bot-B", "persona-A", 5))
    with pytest.raises(ValueError, match="graph_revision"):
        replace(scope, graph_revision=True)
    with pytest.raises(TypeError, match="FencePermitV2"):
        replace(scope, permit=object())
    assert getattr(ContentFencePortV2, "_is_runtime_protocol", False)
