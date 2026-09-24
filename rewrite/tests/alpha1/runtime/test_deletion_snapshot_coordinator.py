"""D06 deletion evidence must traverse the production v2 read fence."""

from dataclasses import replace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphCandidate, GraphWrite

from test_graph_coordinator_v2_read import NAMESPACE, install, setup


def _enable_owner_epochs(store):
    with store._lock:
        store._db.execute(
            "INSERT INTO graph_authority_epochs(bot,persona,access_epoch,delete_epoch) "
            "VALUES('bot','persona',1,0)")


def _write(store, key, event_id):
    capability = store._coordinator_capability
    snapshot = GraphStore.graph_snapshot(store, (key,), _capability=capability)
    candidate = GraphCandidate(
        Event(Scope("bot", "persona", "session"), event_id, 1.0,
              "test", {"event": event_id}), snapshot.versions,
        (GraphWrite(key, {"event": event_id}),), snapshot.epochs)
    GraphStore.graph_commit(store, candidate, _capability=capability)


def _deletion_lease(coordinator, bootstrap):
    return coordinator.grant_deletion_read(
        bootstrap, actor="d06-service", namespace=NAMESPACE,
        activation_generation=1)


def _allow_written_epoch(port, expected):
    def validate(scope):
        assert not port.store._lock._is_owned()
        assert scope.permit is port.active and scope.pinned_anchor == port.anchor
        assert scope.namespace == NAMESPACE and scope.graph_epoch.revision == expected
        port.validations += 1
        if port.on_validate is not None:
            port.on_validate(port.validations)
        return port.active
    port.validate_fence = validate


def test_generic_lease_and_claimed_purpose_cannot_read_deletion_history(setup):
    store, coordinator, bootstrap, port, target, authority, lease, key = setup
    install(store, target)
    _enable_owner_epochs(store)
    with pytest.raises(AuthorityDenied, match="deletion read lease"):
        coordinator.read_deletion_snapshot_candidate(
            replace(authority, purpose="deletion_cleanup"), lease, (key,))
    assert port.validations == 0


def test_coordinator_owns_pages_and_reports_partial_without_external_cursor(setup):
    store, coordinator, bootstrap, port, target, _, _, key = setup
    install(store, target)
    _enable_owner_epochs(store)
    _write(store, key, "first")
    _write(store, key, "second")
    _allow_written_epoch(port, 2)
    authority, lease = _deletion_lease(coordinator, bootstrap)

    partial = coordinator.read_deletion_snapshot_candidate(
        authority, lease, (key,), page_limit=1, max_pages=1)
    assert not partial.complete and partial.pages_scanned == 1
    assert not hasattr(partial, "next_after")
    assert len(partial.history_rows) == 1
    assert port.validations == 3 and len(port.finishes) == 1

    complete = coordinator.read_deletion_snapshot_candidate(
        authority, lease, (key,), page_limit=1, max_pages=2)
    assert complete.complete and complete.pages_scanned == 2
    assert [row.atom.revision for row in complete.history_rows] == [1, 2]
    assert (complete.access_epoch, complete.delete_epoch) == (1, 0)
    assert complete.epoch.revision == 2
    assert port.validations == 6 and len(port.finishes) == 2
    with pytest.raises(TypeError):
        coordinator.read_deletion_snapshot_candidate(
            authority, lease, (key,), after="caller-cursor")


def test_missing_or_changed_access_delete_epochs_hold(setup):
    store, coordinator, bootstrap, port, target, _, _, key = setup
    install(store, target)
    authority, lease = _deletion_lease(coordinator, bootstrap)
    with pytest.raises(UnavailableGuard, match="access/delete epochs"):
        coordinator.read_deletion_snapshot_candidate(authority, lease, (key,))
    _enable_owner_epochs(store)
    prior_validations = port.validations

    def revoke_during_read(validation):
        if validation == prior_validations + 3:
            with store._lock:
                store._db.execute(
                    "UPDATE graph_authority_epochs SET delete_epoch=delete_epoch+1 "
                    "WHERE bot='bot' AND persona='persona'")

    port.on_validate = revoke_during_read
    with pytest.raises(UnavailableGuard, match="access/delete epochs changed"):
        coordinator.read_deletion_snapshot_candidate(authority, lease, (key,))


def test_incomplete_owner_scope_and_released_lease_hold(setup):
    store, coordinator, bootstrap, port, target, _, _, key = setup
    install(store, target)
    _enable_owner_epochs(store)
    authority, lease = _deletion_lease(coordinator, bootstrap)
    with pytest.raises(AuthorityDenied, match="owner scope is incomplete"):
        coordinator.read_deletion_snapshot_candidate(
            replace(authority, owner_scope=()), lease, (key,))
    coordinator.release_deletion_read_lease(bootstrap, lease)
    with pytest.raises(AuthorityDenied, match="deletion read lease"):
        coordinator.read_deletion_snapshot_candidate(authority, lease, (key,))
    assert port.validations == 0


def test_deletion_read_requires_current_activation_and_recovery(setup):
    store, coordinator, bootstrap, port, target, _, _, key = setup
    authority, lease = _deletion_lease(coordinator, bootstrap)
    with pytest.raises(UnavailableGuard, match="metadata is absent"):
        coordinator.read_deletion_snapshot_candidate(authority, lease, (key,))
    assert port.validations == 0
    install(store, target)
    _enable_owner_epochs(store)
    with pytest.raises(AuthorityDenied, match="deletion read lease"):
        coordinator.read_deletion_snapshot_candidate(
            replace(authority, activation_generation=2), lease, (key,))
