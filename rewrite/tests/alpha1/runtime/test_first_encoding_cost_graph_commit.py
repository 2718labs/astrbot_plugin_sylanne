"""An original observed model expense commits without a content result."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.authority_service.v2_accounting_contract import AccountingMaintenanceGrantV1
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, get_budget_lease, reserve_budget
from sylanne3.runtime.d11_types import D11RuntimeProvider, runtime_job_key
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, D11BudgetJobIssuer, IssuerAuthorityDenied,
    ResourceQuote, install_schema,
)
from sylanne3.runtime.model_cost_settlement import ModelCostUnavailable
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest


class AccountingPort:
    def __init__(self, store, fact):
        self.store, self.fact = store, fact
        self.started, self.finished = [], []

    def _outside(self):
        assert not self.store._lock._is_owned()

    def begin(self, request):
        self._outside()
        self.started.append(request.operation_id)
        permit = FencePermitV2(
            request.intent.authority_id, request.intent.namespace,
            "accounting-observer", "holder", 1, "accounting",
            request.operation_id, "z" * 48, 2, 0, request.expected_anchor,
            command_digest="sha256:" + "a" * 64)
        return AccountingMaintenanceGrantV1(
            permit, request.intent.call_id, self.fact[2].admission_id,
            request.intent.budget_reservation_digest,
            self.fact[0].observation_digest,
            canonical_digest(asdict(self.fact[3])))

    def validate(self, request, grant):
        self._outside()
        assert grant.permit.operation_id == request.operation_id

    def finish(self, request, grant):
        self._outside()
        assert grant.permit.operation_id == request.operation_id
        self.finished.append(request.operation_id)

    def recover_finish(self, request):
        self._outside()
        self.finished.append(request.operation_id)


class AnchorPort:
    def __init__(self, store, anchor):
        self.store, self.anchor = store, anchor

    def current_anchor(self, *, namespace, authority_namespace):
        assert not self.store._lock._is_owned()
        assert namespace == NamespaceId("bot", "persona")
        assert authority_namespace == self.anchor.namespace
        return self.anchor

    def begin_fence(self, **kwargs):
        raise AssertionError("ordinary content fence cannot settle cost")

    def validate_fence(self, scope):
        raise AssertionError("ordinary content fence cannot settle cost")

    def finish_fence(self, scope, **kwargs):
        raise AssertionError("ordinary content fence cannot settle cost")


def _case(tmp_path, *, unknown=False, deleted=False):
    registry = TypeRegistry()
    for spec in D11RuntimeProvider().type_specs():
        registry.register(spec)
    store = ProductionGraphStore(tmp_path / "business.db", registry)
    db = store._db
    install_schema(db)
    namespace = NamespaceId("bot", "persona")
    genesis = RestoreAnchor(
        "authority", "authority-ns", 1, "deletions", 0, "genesis",
        "executions", 0, "genesis", 0, "proof")
    anchor = replace(genesis, deletion_seq=1,
                     deletion_digest="sha256:" + "9" * 64,
                     revocation_epoch=1) if deleted else genesis
    target = SnapshotRequirementsV2(
        namespace, genesis.authority_id, genesis.namespace, 1,
        genesis.deletion_journal_id, 0, "genesis",
        genesis.execution_journal_id, 0, "genesis", 0, "graph-incarnation")
    bootstrap = object()
    store._coordinator_capability = object()
    store.install_graph_recovery_genesis(
        target, _capability=store._coordinator_capability)
    store._coordinator_capability = None
    # Production constructor owns the capability used to install genesis.
    content = AnchorPort(store, anchor)
    d02 = D02ResourceIssuer(b"k" * 32)
    d11 = D11BudgetJobIssuer(d02, b"j" * 32)
    ceiling = {"output_tokens": 80, "cpu_ms": 20} if unknown else {"output_tokens": 80}
    create_budget_lease(db, BudgetLease(
        "lease", None, "bot", "persona", "USD",
        {key: 100 for key in ceiling}, {}, {}, {}, 1, "active"),
        "create", "a" * 64)
    reserve_budget(db, "lease", "original", "b" * 64, ceiling)
    quote = ResourceQuote(
        "quote", 1, "bot", "persona", "activity", "original", None,
        "lease", "d06.encode_source", "snapshot", 100.0, "resource",
        runtime_job_key("bot", "persona", "activity", "job").token,
        (), (), ceiling, None, 100.0)
    d02.issue_quote(db, quote)
    db.commit()
    intent = ModelEgressIntentV1(
        "authority", "authority-ns", "worker", "model-op", "call",
        "c" * 64, "job", 1, "m" * 32, 1, 0,
        canonical_digest(asdict(genesis)), ("source",), (("source", 1),),
        (("source", 1),), 1, 0, 1, 1, 1, 0, 0, 0,
        "lease", "original", "b" * 64,
        tuple(sorted(ceiling.items())), "provider", "model", "d" * 64, 32)
    record = ModelEgressRecoveryV1(
        intent, "observed", "e" * 64, (("output_tokens", 90),), ())
    admission = ModelAdmissionV2(
        "f" * 64, "authority", "authority-ns", "worker", "model-op",
        "call", "c" * 64, "d" * 64, "install", "1" * 64,
        "observer", "2" * 64, "3" * 64)
    receipt = ModelTerminalReceiptV2(
        admission.admission_id, "call", "c" * 64, "4" * 64,
        "e" * 64, "sha256:" + "5" * 64, "install", "3" * 64)
    permit = FencePermitV2(
        "authority", "authority-ns", "worker", "holder", 1,
        "model_egress", "model-op", "m" * 32, 1, 0, genesis)
    fact = (record, permit, admission, receipt)
    accounting = AccountingPort(store, fact)
    coordinator = GraphCoordinator(
        store, bootstrap, holder="holder", content_fence_v2=content,
        d02_issuer=d02, d11_issuer=d11,
        model_terminal_cost_port=lambda _intent: fact,
        accounting_maintenance_port=accounting)
    db.execute("INSERT INTO graph_bundle_operations"
               "(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) "
               "VALUES('bot','persona','original','original','activity',NULL,1,'{}')")
    db.execute("INSERT INTO graph_bundle_sequence VALUES('bot','persona',1)")
    db.commit()
    return store, coordinator, bootstrap, namespace, intent, accounting


@pytest.mark.parametrize("unknown", [False, True])
@pytest.mark.parametrize("deleted", [False, True])
def test_cost_bundle_commits_after_content_hold_and_replays(tmp_path, unknown, deleted):
    store, coordinator, bootstrap, namespace, intent, accounting = _case(
        tmp_path, unknown=unknown, deleted=deleted)
    try:
        store._db.execute("UPDATE runtime_resource_quotes SET status='revoked'")
        store._db.commit()
        first = coordinator.commit_first_ingress_model_cost_v1(
            bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert first.status == "committed"
        assert first.cost_ref == store._db.execute(
            "SELECT token FROM graph_atoms WHERE type_name='runtime.cost_settlement'"
        ).fetchone()[0]
        lease = get_budget_lease(store._db, "lease")
        assert lease.used["output_tokens"] == 90
        assert lease.unconfirmed == ({"cpu_ms": 20} if unknown else {})
        replay = coordinator.commit_first_ingress_model_cost_v1(
            bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert replay.status == "duplicate"
        assert replay.operation_id == first.operation_id
        assert get_budget_lease(store._db, "lease") == lease
        assert len(accounting.started) == 1
        assert accounting.finished == accounting.started * 2
        if deleted:
            row = store._db.execute(
                "SELECT requirements_json FROM graph_recovery_metadata_v2"
            ).fetchone()
            assert json.loads(row[0])["deletion_seq"] == 1
    finally:
        store.close()


def test_cost_bundle_rollback_retains_original_reservation(tmp_path):
    store, coordinator, bootstrap, namespace, intent, accounting = _case(tmp_path)
    try:
        store._db.execute("UPDATE runtime_resource_quotes SET status='revoked'")
        store._db.commit()
        # A different original reservation digest forces the in-transaction
        # quote/reservation check to reject without emitting a cost atom.
        store._db.execute(
            "UPDATE runtime_budget_reservations SET digest='changed' "
            "WHERE lease_id='lease' AND operation_id='original'")
        store._db.commit()
        with pytest.raises(ModelCostUnavailable):
            coordinator.commit_first_ingress_model_cost_v1(
                bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert get_budget_lease(store._db, "lease").reserved == {"output_tokens": 80}
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='runtime.cost_settlement'"
        ).fetchone()[0] == 0
        assert len(accounting.started) == len(accounting.finished) == 1
    finally:
        store.close()


def test_graph_failure_rolls_back_budget_and_retries_with_new_fence(tmp_path, monkeypatch):
    store, coordinator, bootstrap, namespace, intent, accounting = _case(tmp_path)
    original = GraphStore._graph_commit_in_transaction
    try:
        def fail_after_settlement(self, *args, **kwargs):
            assert get_budget_lease(self._db, "lease").used == {"output_tokens": 90}
            raise RuntimeError("injected graph rejection")

        monkeypatch.setattr(GraphStore,
                            "_graph_commit_in_transaction", fail_after_settlement)
        with pytest.raises(RuntimeError, match="injected graph rejection"):
            coordinator.commit_first_ingress_model_cost_v1(
                bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert get_budget_lease(store._db, "lease").reserved == {"output_tokens": 80}
        assert get_budget_lease(store._db, "lease").used == {}
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations "
            "WHERE operation_id LIKE 'model-cost-%'").fetchone()[0] == 0
        monkeypatch.setattr(GraphStore,
                            "_graph_commit_in_transaction", original)
        receipt = coordinator.commit_first_ingress_model_cost_v1(
            bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert receipt.status == "committed"
        assert len(accounting.started) == 2
        assert accounting.started[0] != accounting.started[1]
    finally:
        store.close()


def test_lost_finish_reply_recovers_fixed_business_receipt(tmp_path, monkeypatch):
    store, coordinator, bootstrap, namespace, intent, accounting = _case(tmp_path)
    original_finish = accounting.finish
    try:
        def lost_reply(request, grant):
            original_finish(request, grant)
            raise RuntimeError("finish reply lost")

        monkeypatch.setattr(accounting, "finish", lost_reply)
        with pytest.raises(RuntimeError, match="finish reply lost"):
            coordinator.commit_first_ingress_model_cost_v1(
                bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert get_budget_lease(store._db, "lease").used == {"output_tokens": 90}
        monkeypatch.setattr(accounting, "finish", original_finish)
        recovered = coordinator.commit_first_ingress_model_cost_v1(
            bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert recovered.status == "duplicate"
        assert len(accounting.started) == 1
        assert get_budget_lease(store._db, "lease").used == {"output_tokens": 90}
    finally:
        store.close()


def test_unobserved_terminal_keeps_original_budget_ceiling(tmp_path):
    store, coordinator, bootstrap, namespace, intent, accounting = _case(tmp_path)
    try:
        record, permit, admission, _receipt = accounting.fact
        coordinator._GraphCoordinator__model_terminal_cost_port = (
            lambda _intent: (replace(record, state="unknown"), permit,
                             admission, None))
        with pytest.raises(ModelCostUnavailable):
            coordinator.commit_first_ingress_model_cost_v1(
                bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert get_budget_lease(store._db, "lease").reserved == {"output_tokens": 80}
        assert accounting.started == []
    finally:
        store.close()


def test_deleted_original_quote_is_hold_even_with_accounting_grant(tmp_path):
    store, coordinator, bootstrap, namespace, intent, accounting = _case(
        tmp_path, deleted=True)
    try:
        store._db.execute("DELETE FROM runtime_resource_quotes WHERE quote_id='quote'")
        store._db.commit()
        with pytest.raises(IssuerAuthorityDenied):
            coordinator.commit_first_ingress_model_cost_v1(
                bootstrap, namespace, intent, quote_id="quote", quote_version=1)
        assert get_budget_lease(store._db, "lease").reserved == {"output_tokens": 80}
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='runtime.cost_settlement'"
        ).fetchone()[0] == 0
        assert len(accounting.started) == len(accounting.finished) == 1
    finally:
        store.close()
