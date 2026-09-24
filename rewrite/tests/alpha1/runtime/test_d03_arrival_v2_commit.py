"""An installed D03 price admits only the exact committed host arrival."""

from dataclasses import replace
import json

import pytest

from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.host.authority_profile import AdminD03ArrivalPolicy
from sylanne3.memory_types import access_key
from sylanne3.runtime_contracts import DependencySet

from test_first_ingress_v2 import _ingress_inputs
from test_scene_binding_v2 import _bind_scene, _scene_case


@pytest.fixture
def arrival_case(tmp_path):
    case = _scene_case(tmp_path, enable_ingress=True, arrival_allowed=True)
    store, authority_db, _, coordinator, namespace, _, _, installation, bootstrap = case
    _bind_scene(case)
    host, clock, encoding = _ingress_inputs(namespace)
    coordinator.commit_first_ingress_v2(bootstrap, host, installation, clock, encoding)
    arrival = AdminD03ArrivalPolicy(30.0, {"cpu_ms": 3},
                                    "arrival-snapshot", "arrival-resource")
    try:
        yield case, host, clock, arrival
    finally:
        store.close()
        authority_db.close()


def _commit(case, host, clock, arrival):
    store, _, _, coordinator, namespace, _, _, installation, bootstrap = case
    return coordinator.commit_d03_message_arrival_v2(
        bootstrap, namespace, host.lineage.source_ref,
        installation, arrival, clock)


def test_real_v2_arrival_commits_exact_graph_fact_and_replays(arrival_case):
    case, host, clock, arrival = arrival_case
    store, _, port, coordinator, namespace, *_ = case
    before = coordinator._v2_graph_stamp(namespace)[0].graph_revision
    receipt = _commit(case, host, clock, arrival)
    assert receipt.status == "committed"
    assert coordinator._v2_graph_stamp(namespace)[0].graph_revision == before + 1
    with store._lock:
        row = store._db.execute(
            "SELECT quote_id,policy_digest,bundle_digest FROM "
            "graph_d03_arrival_issuance_v2 WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (receipt.operation_id,),
        ).fetchone()
        assert row[2] == receipt.operation_digest
        quote = coordinator._GraphCoordinator__d02_issuer._load_quote(
            store._db, row[0], 1)
        assert quote.ceiling == {"cpu_ms": 3}
        assert store._db.execute(
            "SELECT state,ceiling_json FROM runtime_budget_reservations "
            "WHERE operation_id=?", (receipt.operation_id,),
        ).fetchone() == ("reserved", '{"cpu_ms":3}')
        assert store._db.execute(
            "SELECT count(*) FROM runtime_resource_outcomes WHERE quote_id=?",
            (quote.quote_id,),
        ).fetchone()[0] == 0
        assert store._db.execute(
            "SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.world_event' AND valid=1", namespace.as_tuple,
        ).fetchone()[0] == 1
    replay = _commit(case, host, clock, arrival)
    assert replay.status == "duplicate"
    assert replay.operation_digest == receipt.operation_digest
    assert coordinator._v2_graph_stamp(namespace)[0].graph_revision == before + 1
    assert len(port.finishes) >= 1


def test_changed_owner_holds_without_quote(arrival_case, monkeypatch):
    case, host, clock, arrival = arrival_case
    store, _, port, coordinator, namespace, *_ = case
    original = port.get_current_owner_guard_for_fence

    def changed_guard(**kwargs):
        guard, permit = original(**kwargs)
        return replace(guard, authorization_revision=guard.authorization_revision + 1), permit

    monkeypatch.setattr(port, "get_current_owner_guard_for_fence", changed_guard)
    with pytest.raises(UnavailableGuard, match="Owner head lacks matching"):
        _commit(case, host, clock, arrival)
    with store._lock:
        assert store._db.execute(
            "SELECT count(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-arrival-q-%'"
        ).fetchone()[0] == 0


def test_revoked_access_during_fence_holds_without_quote(arrival_case, monkeypatch):
    case, host, clock, arrival = arrival_case
    store, _, port, coordinator, namespace, *_ = case
    original = port.get_current_owner_guard_for_fence

    def revoke_access(**kwargs):
        guard, permit = original(**kwargs)
        key = access_key(*namespace.as_tuple, host.lineage.source_ref)
        with store._lock:
            current = json.loads(store._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?", (key.token,),
            ).fetchone()[0])
            current["status"] = "revoked"
            store._db.execute(
                "UPDATE graph_atoms SET value=? WHERE token=?",
                (json.dumps(current, sort_keys=True, separators=(",", ":")), key.token),
            )
        return guard, permit

    monkeypatch.setattr(port, "get_current_owner_guard_for_fence", revoke_access)
    with pytest.raises((AuthorityDenied, ValueError, UnavailableGuard), match="access|source"):
        _commit(case, host, clock, arrival)
    assert store._db.execute(
        "SELECT count(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-arrival-q-%'"
    ).fetchone()[0] == 0


def test_current_signed_grant_loses_arrival_kind_during_fence(arrival_case, monkeypatch):
    case, host, clock, arrival = arrival_case
    store, _, port, coordinator, namespace, _, _, installation, _ = case
    original = port.get_current_owner_guard_for_fence

    def revoke_kind(**kwargs):
        guard, permit = original(**kwargs)
        issuer = coordinator._GraphCoordinator__d11_issuer
        with store._lock:
            issuer.issue_budget_grant(store._db, replace(
                installation.root_grant, version=2,
                allowed_work_kinds=("d06.encode_source",)))
        return guard, permit

    monkeypatch.setattr(port, "get_current_owner_guard_for_fence", revoke_kind)
    with pytest.raises(PermissionError, match="signed grant"):
        _commit(case, host, clock, arrival)
    assert store._db.execute(
        "SELECT count(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-arrival-q-%'"
    ).fetchone()[0] == 0


def test_sealed_arrival_rejects_extra_proposal_before_quote(arrival_case, monkeypatch):
    case, host, clock, arrival = arrival_case
    store, _, _, coordinator, *_ = case
    original = coordinator._commit_domain_bundle_v2

    def add_extra(bundle, lease, *, arrival_issuance=None):
        extra = replace(bundle.proposals[0], typed_writes=(),
                        dependencies=DependencySet(),
                        contribution_keys=("extra",))
        return original(replace(bundle, proposals=bundle.proposals + (extra,)), lease,
                        arrival_issuance=arrival_issuance)

    monkeypatch.setattr(coordinator, "_commit_domain_bundle_v2", add_extra)
    with pytest.raises(AuthorityDenied, match="issuance identity differs"):
        _commit(case, host, clock, arrival)
    assert store._db.execute(
        "SELECT count(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-arrival-q-%'"
    ).fetchone()[0] == 0


def test_lost_finish_replays_original_receipt_and_policy_change_holds(
        arrival_case):
    case, host, clock, arrival = arrival_case
    store, _, port, coordinator, namespace, *_ = case
    before = coordinator._v2_graph_stamp(namespace)[0].graph_revision
    port.lose_finish_after_durable = True
    with pytest.raises(RuntimeError, match="finish response lost"):
        _commit(case, host, clock, arrival)
    assert coordinator._v2_graph_stamp(namespace)[0].graph_revision == before + 1
    assert _commit(case, host, clock, arrival).status == "duplicate"
    with pytest.raises(UnavailableGuard, match="replay receipt differs"):
        _commit(case, host, clock,
                replace(arrival, quote_ceiling={"cpu_ms": 4}))
    assert store._db.execute(
        "SELECT count(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-arrival-q-%'"
    ).fetchone()[0] == 1


def test_missing_arrival_policy_holds(arrival_case):
    case, host, clock, _ = arrival_case
    store, _, _, coordinator, namespace, _, _, installation, bootstrap = case
    with pytest.raises(UnavailableGuard, match="installed D03 arrival policies"):
        coordinator.commit_d03_message_arrival_v2(
            bootstrap, namespace, host.lineage.source_ref,
            installation, None, clock)
    assert store._db.execute(
        "SELECT count(*) FROM runtime_resource_quotes WHERE quote_id LIKE 'd03-arrival-q-%'"
    ).fetchone()[0] == 0
