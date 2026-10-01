"""The public V2 route cannot start a write without an installed output issuer."""

from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.d04_joint_advance_v2 import (
    ProductAdvanceEvidenceV2, ProductAdvanceMemberV2,
)
from sylanne3.runtime_contracts import NamespaceId


def _evidence() -> ProductAdvanceEvidenceV2:
    ns = NamespaceId("bot:one", "alice")
    owner = Owner("persona", *ns.as_tuple)
    digest = "a" * 64
    members = []
    for name in ("a", "b"):
        checkpoint = AtomKey(owner, "d04.numeric_checkpoint.v1", name).token
        state = AtomKey(owner, "d04.feeling_state.v1", name).token
        members.append(ProductAdvanceMemberV2(
            checkpoint, "root", 1, digest, state, 1, digest, digest,
            0.0, 2, digest, 0.01, state, 2, digest,
        ))
    return ProductAdvanceEvidenceV2(
        "d11.product_advance_evidence.v2", ns, "advance:one", digest,
        "process:one", "replay:one", 0.0, 1.0, tuple(members),
        digest, "incarnation:one", 1, 1, 0, 0,
        digest, digest, digest, digest, digest, digest, digest,
        digest, digest, digest, digest, (("family:one", digest),),
        digest, digest,
    )


def test_v2_joint_advance_holds_before_store_or_fence_without_replay():
    # The guard precedes every store, fence, or Authority call. A coordinator
    # without installed dependencies therefore cannot mutate an operation.
    graph = object.__new__(GraphCoordinator)
    bundle = SimpleNamespace(product_advance=_evidence())
    with pytest.raises(UnavailableGuard, match="installed D04 joint output unavailable"):
        graph._commit_domain_bundle_v2(bundle, object())


def test_v2_public_route_holds_without_installed_output_issuer():
    graph = object.__new__(GraphCoordinator)
    graph._GraphCoordinator__d04_installed_joint_assembly = None
    graph._GraphCoordinator__d04_installed_joint_output_policy = None
    with pytest.raises(UnavailableGuard, match="installed D04 joint replay unavailable"):
        graph.commit_d04_joint_advance_v2(None, object(), object())
