"""A completed worker lease can leave memory without losing original identity."""

from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import AuthorityDenied, GraphCoordinator
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId


def test_plain_job_lease_release_revokes_object_only():
    bootstrap = object()
    namespace = NamespaceId("bot", "persona")
    coordinator = object.__new__(GraphCoordinator)
    coordinator._GraphCoordinator__bootstrap = bootstrap
    coordinator._GraphCoordinator__store = SimpleNamespace(_registry=SimpleNamespace(
        specs=(SimpleNamespace(writer_domain="d11", owner_kinds=("activity",)),)))
    coordinator._GraphCoordinator__providers = {"d11": (object(), "schema", "hash")}
    coordinator._GraphCoordinator__leases = {}
    coordinator._GraphCoordinator__owner_leases = {}
    coordinator._GraphCoordinator__owner_session_proofs = {}
    coordinator._GraphCoordinator__deletion_read_leases = set()
    lease, ref = coordinator.grant(
        bootstrap, actor="worker", issuer_domain="d11", namespace=namespace,
        domains=("d11",), activation_generation=1, operation_id="acquire")
    authority = AuthorityContext(
        "worker", "d11", ref, namespace, ("activity",),
        "consolidation", ("conversation",), "policy", 1)
    coordinator._authorize(lease, authority, frozenset({"d11"}))
    with pytest.raises(AuthorityDenied, match="host bootstrap"):
        coordinator.release_authority_lease(object(), lease)
    coordinator.release_authority_lease(bootstrap, lease)
    with pytest.raises(AuthorityDenied, match="unknown process"):
        coordinator._authorize(lease, authority, frozenset({"d11"}))
    replacement, same_ref = coordinator.grant(
        bootstrap, actor="worker", issuer_domain="d11", namespace=namespace,
        domains=("d11",), activation_generation=1, operation_id="acquire")
    assert replacement is not lease
    assert same_ref == ref
    coordinator._authorize(replacement, authority, frozenset({"d11"}))
    coordinator.release_authority_lease(bootstrap, replacement)
