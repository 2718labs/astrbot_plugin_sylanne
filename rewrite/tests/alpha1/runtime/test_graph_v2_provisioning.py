"""Administrator namespace genesis uses one fenced, atomic business write."""

from dataclasses import replace
import shutil
import sqlite3
import time
from unittest.mock import patch

import pytest

from sylanne3.contracts import EventConflict, StaleRead
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.graph_coordinator import (
    AuthorityDenied, BudgetAdmission, GraphCoordinator, RuntimeAdmission,
    UnavailableGuard,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import AtomKey, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease, get_budget_lease
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D11BudgetGrantIssuer, build_runtime_issuers,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, InstallationGrantV2, NamespaceBootstrapV2, NamespaceId,
    NamespaceRuntimeState, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, canonical_digest,
)
import sylanne3.graph_coordinator as coordinator_module


class AuthorityPort:
    def __init__(self, store, db):
        self.store = store
        self.fences = AuthorityV2FenceStore(db, create=True)
        self.installation_grant = InstallationGrantV2(
            "authority", "subject", "administrator", "installation",
            "a" * 64, "publisher-trust", "2", "b" * 64)
        self.anchors = {}
        self.genesis_requests = []
        self.validations = []
        self.finishes = []
        self.lose_finish_after_durable = False
        self.lose_begin_after_durable = False
        self.lose_genesis_after_durable = False

    def outside_graph_lock(self):
        assert not self.store._lock._is_owned()

    def provision_namespace(self, *, namespace, request_id):
        self.outside_graph_lock()
        self.genesis_requests.append((namespace, request_id))
        anchor = self.anchors.setdefault(namespace, RestoreAnchor(
            "authority", "opaque:" + namespace.persona_id, 1,
            "deletion:" + namespace.persona_id, 0, "genesis",
            "execution:" + namespace.persona_id, 0, "genesis", 0,
            "authority-proof"))
        result = NamespaceBootstrapV2(
            "authority", namespace, anchor.namespace, "administrator", 1,
            "active", NamespaceRuntimeState.ACTIVE, anchor, ())
        if self.lose_genesis_after_durable:
            self.lose_genesis_after_durable = False
            raise RuntimeError("genesis response lost")
        return result

    def current_anchor(self, *, namespace, authority_namespace):
        self.outside_graph_lock()
        anchor = self.anchors[namespace]
        assert anchor.namespace == authority_namespace
        return anchor

    def get_fence_operation(self, *, namespace, authority_namespace, operation_id):
        self.outside_graph_lock()
        assert self.anchors[namespace].namespace == authority_namespace
        permit, state, pending = self.fences.get_operation(
            operation_id, subject="subject", namespace=authority_namespace)
        assert pending is None
        return permit, state

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **_):
        self.outside_graph_lock()
        assert expected_anchor == self.anchors[namespace]
        assert expected_anchor.namespace == authority_namespace
        assert generation == 1
        permit = self.fences.begin_fence(
            subject="subject", holder=holder, operation=operation,
            operation_id=operation_id, current_anchor=expected_anchor)
        if operation == "write" and self.lose_begin_after_durable:
            self.lose_begin_after_durable = False
            raise RuntimeError("begin response lost")
        return permit

    def validate_fence(self, scope):
        self.outside_graph_lock()
        self.validations.append(scope.operation)
        return self.fences.validate_fence(
            scope.permit, subject="subject",
            current_anchor=self.anchors[scope.namespace])

    def finish_fence(self, scope, *, request_id, request_digest):
        self.outside_graph_lock()
        self.fences.finish_fence(
            scope.permit, subject="subject",
            current_anchor=self.anchors[scope.namespace],
            request_id=request_id, request_digest=request_digest)
        self.finishes.append((scope.operation, request_id, request_digest))
        if self.lose_finish_after_durable:
            self.lose_finish_after_durable = False
            raise RuntimeError("finish response lost")


def policy_for(store, persona="persona", *, scheme="scheme-1"):
    namespace = NamespaceId("bot", persona)
    lease = BudgetLease(
        "lease-" + persona, None, *namespace.as_tuple, "USD",
        {"cpu_ms": 200}, {}, {}, {}, 1, "active")
    grant = BudgetLeaseGrant(
        "grant-" + persona, 1, *namespace.as_tuple, lease.lease_id,
        "USD", {"cpu_ms": 100}, ("encode",), time.time() + 3600,
        "d11-policy")
    return AdminInstallationPolicy(
        namespace, "opaque:" + persona, "installation", "a" * 64,
        "administrator", "authority", store._registry.catalogue_hash,
        scheme, "operator-1", "policy-1", lease, grant)


@pytest.fixture
def system(tmp_path):
    store = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(
        tmp_path / "authority.db", isolation_level=None)
    port = AuthorityPort(store, authority_db)
    _, d11 = build_runtime_issuers(b"issuer-key-" * 4)
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="administrator", content_fence_v2=port,
        d11_issuer=d11)
    try:
        yield store, coordinator, bootstrap, port, d11
    finally:
        store.close()
        authority_db.close()


def row_counts(store):
    tables = {row[0] for row in store._db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    return {table: (store._db.execute(
        f"SELECT COUNT(*) FROM {table}").fetchone()[0] if table in tables else 0)
        for table in (
            "graph_recovery_metadata_v2", "graph_guard_versions",
            "runtime_budget_leases", "runtime_budget_operations",
            "runtime_budget_grants", "graph_namespace_provisioning_v2",
            "graph_namespace_provision_intents_v2")}


@pytest.fixture
def bundle_system(tmp_path):
    registry = TypeRegistry()
    registry.register(TypeSpec(
        "state", ("persona",), "state", lambda value: None,
        writer_domain="d06", schema_hash="a" * 64))
    store = ProductionGraphStore(tmp_path / "business.db", registry)
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    port = AuthorityPort(store, authority_db)
    _, d11 = build_runtime_issuers(b"issuer-key-" * 4)
    d11.admit_runtime = lambda bundle, db: RuntimeAdmission(BudgetAdmission(
        "lease-persona", get_budget_lease(db, "lease-persona").version,
        {"cpu_ms": 1}))
    d02 = type("D02Admission", (), {"authorize_resources":
                lambda self, bundle, db: True})()
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="administrator", content_fence_v2=port,
        d02_issuer=d02, d11_issuer=d11)
    policy = policy_for(store)
    coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    provider = type("Provider", (), {"validate":
                    lambda self, proposal, snapshot: True})()
    coordinator.register_provider(
        bootstrap, "d06", provider, "d06.contract.v1", "b" * 64)
    lease, capability = coordinator.grant(
        bootstrap, actor="host", issuer_domain="d06", namespace=policy.namespace,
        domains=("d06",), activation_generation=1, operation_id="write-a")
    authority = AuthorityContext(
        "host", "d06", capability, policy.namespace, ("persona",),
        "remember", ("internal",), "policy-1", 1)

    def bundle(operation="write-a", value=1):
        key = AtomKey(Owner("persona", "bot", "persona"), "state", "mood")
        snapshot = coordinator.read_snapshot(authority, lease, (key,))
        envelope = CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity("activity", None, "attempt", "commit", operation,
                              canonical_digest({"input_refs": []})),
            authority,
            VersionGuard(
                snapshot.versions,
                (QueryEpoch(policy.namespace, "all", snapshot.epochs[0].revision),),
                0, 0, registry.catalogue_hash, "scheme-1", "operator-1",
                "policy-1", (), (), ()),
            SourceQualification(
                (), "reported", 1.0, 1.0, "external_report", "qualified", 0.5,
                "not_applicable"),
            (), "lease-persona", 4_102_444_800.0, 100.0, "character-v1", (),
        )
        proposal = DomainProposal(
            "d06", "d06.contract.v1", "b" * 64, envelope,
            (GraphWrite(key, {"n": value}),), DependencySet(), (), ())
        return DomainBundle(envelope, (proposal,), (), (), (), (), (), (), ())

    try:
        yield store, coordinator, bootstrap, port, policy, lease, bundle, d02, d11, provider
    finally:
        store.close()
        authority_db.close()


def restart_bundle_system(bundle_system, tmp_path):
    store, _, _, port, policy, _, _, d02, d11, provider = bundle_system
    anchor = port.anchors[policy.namespace]
    store.close()
    port.fences._db.close()
    reopened = ProductionGraphStore(tmp_path / "business.db", store._registry)
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors[policy.namespace] = anchor
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=next_port, d02_issuer=d02, d11_issuer=d11)
    next_coordinator.register_provider(
        next_bootstrap, "d06", provider, "d06.contract.v1", "b" * 64)
    next_lease, next_ref = next_coordinator.grant(
        next_bootstrap, actor="host", issuer_domain="d06",
        namespace=policy.namespace, domains=("d06",), activation_generation=1,
        operation_id="write-a")
    return reopened, next_coordinator, next_port, next_lease, next_ref, authority_db


def test_v2_bundle_commit_advances_business_stamp_and_duplicate_is_read_only(bundle_system):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    first = make_bundle()
    receipt = coordinator.commit_domain_bundle(first, lease)
    assert receipt.status == "committed"
    metadata = coordinator._v2_graph_stamp(policy.namespace)[0]
    assert metadata.graph_revision == 1
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_fences_v2").fetchone() == (1,)
    second = make_bundle("write-b", 2)
    coordinator.commit_domain_bundle(second, lease)
    duplicate = coordinator.commit_domain_bundle(first, lease)
    assert duplicate.status == "duplicate"
    assert coordinator._v2_graph_stamp(policy.namespace)[0].graph_revision == 2
    assert len([item for item in port.finishes
                if item[1].startswith("finish:graph-write-")]) == 2


def test_v2_bundle_precommit_rollback_reuses_active_attempt(bundle_system):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    candidate = make_bundle()
    port.lose_begin_after_durable = True
    with pytest.raises(RuntimeError, match="begin response lost"):
        coordinator.commit_domain_bundle(candidate, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (0,)
    assert not [item for item in port.finishes if item[0] == "write"
                and item[1].startswith("finish:graph-write-")]
    receipt = coordinator.commit_domain_bundle(candidate, lease)
    assert receipt.status == "committed"
    assert coordinator._v2_graph_stamp(policy.namespace)[0].graph_revision == 1


def test_v2_bundle_lost_finish_recovers_from_durable_receipt(bundle_system):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    candidate = make_bundle()
    port.lose_finish_after_durable = True
    with pytest.raises(RuntimeError, match="finish response lost"):
        coordinator.commit_domain_bundle(candidate, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (1,)
    assert coordinator.commit_domain_bundle(candidate, lease).status == "duplicate"
    assert coordinator._v2_graph_stamp(policy.namespace)[0].graph_revision == 1


def test_v2_bundle_cold_restart_finishes_only_after_durable_business_receipt(
        bundle_system, tmp_path):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    candidate = make_bundle()
    port.finish_fence = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("simulated crash before finish"))
    with pytest.raises(RuntimeError, match="simulated crash"):
        coordinator.commit_domain_bundle(candidate, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (1,)
    reopened, next_coordinator, next_port, next_lease, next_ref, authority_db = (
        restart_bundle_system(bundle_system, tmp_path))
    assert next_ref == candidate.envelope.authority.capability_ref
    try:
        assert next_coordinator.commit_domain_bundle(candidate, next_lease).status == "duplicate"
        assert next_coordinator._v2_graph_stamp(policy.namespace)[0].graph_revision == 1
        assert next_port.finishes[0][1].startswith("finish:graph-write-")
    finally:
        reopened.close()
        authority_db.close()


def test_v2_bundle_unknown_begin_cold_restart_reuses_intent(bundle_system, tmp_path):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    candidate = make_bundle()
    port.lose_begin_after_durable = True
    with pytest.raises(RuntimeError, match="begin response lost"):
        coordinator.commit_domain_bundle(candidate, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_intents_v2").fetchone() == (1,)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (0,)
    reopened, next_coordinator, next_port, next_lease, next_ref, authority_db = (
        restart_bundle_system(bundle_system, tmp_path))
    assert next_ref == candidate.envelope.authority.capability_ref
    try:
        assert next_coordinator.commit_domain_bundle(candidate, next_lease).status == "committed"
        assert reopened._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (1,)
        assert len([item for item in next_port.finishes
                    if item[1].startswith("finish:graph-write-")]) == 1
    finally:
        reopened.close()
        authority_db.close()


def test_v2_bundle_changed_candidate_after_finished_uncommitted_attempt_holds(bundle_system):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    original = make_bundle()
    changed = make_bundle(value=2)
    port.lose_begin_after_durable = True
    with pytest.raises(RuntimeError, match="begin response lost"):
        coordinator.commit_domain_bundle(original, lease)
    intent = store._db.execute(
        "SELECT fence_attempt_id FROM graph_bundle_intents_v2 WHERE bot=? AND persona=? "
        "AND operation_id=?", policy.namespace.as_tuple + ("write-a",)).fetchone()
    permit, state = port.get_fence_operation(
        namespace=policy.namespace, authority_namespace=policy.authority_namespace,
        operation_id=intent[0])
    assert state == "active"
    port.fences.finish_fence(
        permit, subject="subject", current_anchor=port.anchors[policy.namespace],
        request_id="external-finish", request_digest="sha256:" + "f" * 64)
    with pytest.raises(EventConflict, match="different bundle"):
        coordinator.commit_domain_bundle(changed, lease)
    with pytest.raises(AuthorityUnavailable, match="completed fence"):
        coordinator.commit_domain_bundle(original, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (0,)


def test_v2_bundle_changed_authority_head_writes_nothing(bundle_system):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    candidate = make_bundle()
    port.anchors[policy.namespace] = replace(
        port.anchors[policy.namespace], execution_seq=1,
        execution_digest="sha256:" + "a" * 64)
    with pytest.raises(UnavailableGuard, match="anchor differs"):
        coordinator.commit_domain_bundle(candidate, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (0,)
    assert coordinator._v2_graph_stamp(policy.namespace)[0].graph_revision == 0


def test_v2_bundle_d11_failure_rolls_back_graph_and_stamp(bundle_system):
    store, coordinator, _, port, policy, lease, make_bundle, _, d11, _ = bundle_system
    candidate = make_bundle()
    original = d11.admit_runtime
    d11.admit_runtime = lambda *_: (_ for _ in ()).throw(RuntimeError("D11 unavailable"))
    with pytest.raises(RuntimeError, match="D11 unavailable"):
        coordinator.commit_domain_bundle(candidate, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (0,)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_fences_v2").fetchone() == (0,)
    assert coordinator._v2_graph_stamp(policy.namespace)[0].graph_revision == 0
    d11.admit_runtime = original
    assert coordinator.commit_domain_bundle(candidate, lease).status == "committed"


def test_v2_bundle_changed_graph_stamp_after_permit_writes_nothing(bundle_system):
    store, coordinator, _, port, policy, lease, make_bundle, *_ = bundle_system
    candidate = make_bundle()
    original = port.validate_fence

    def advance_stamp(scope):
        result = original(scope)
        if scope.operation == "write":
            store._db.execute(
                "UPDATE graph_recovery_metadata_v2 SET graph_revision=graph_revision+1 "
                "WHERE bot=? AND persona=?", policy.namespace.as_tuple)
            port.validate_fence = original
        return result

    port.validate_fence = advance_stamp
    with pytest.raises(StaleRead, match="stamp changed"):
        coordinator.commit_domain_bundle(candidate, lease)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (0,)
    assert store._db.execute("SELECT COUNT(*) FROM graph_bundle_fences_v2").fetchone() == (0,)


def test_genesis_uses_d11_grant_capability_without_d02(tmp_path):
    store = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    try:
        port = AuthorityPort(store, authority_db)
        issuer = D11BudgetGrantIssuer(b"K" * 32)
        bootstrap = object()
        coordinator = GraphCoordinator(
            store, bootstrap, holder="administrator", content_fence_v2=port,
            d11_issuer=issuer)
        policy = policy_for(store)
        receipt = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
        assert issuer.current_budget_grant(store._db, receipt.root_lease_id) == policy.root_grant
        assert coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona") == receipt
    finally:
        store.close()
        authority_db.close()


def test_success_stages_recovery_guards_real_budget_and_reconcilable_receipt(system):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    assert row_counts(store) == {
        "graph_recovery_metadata_v2": 1, "graph_guard_versions": 4,
        "runtime_budget_leases": 1, "runtime_budget_operations": 1,
        "runtime_budget_grants": 1, "graph_namespace_provisioning_v2": 1,
        "graph_namespace_provision_intents_v2": 1}
    metadata = store.graph_recovery_metadata(
        policy.namespace, _capability=store._coordinator_capability)
    assert metadata.requirements.graph_incarnation == receipt.graph_incarnation
    assert metadata.requirements.deletion_seq == metadata.requirements.execution_seq == 0
    assert get_budget_lease(store._db, receipt.root_lease_id).limits == {"cpu_ms": 200}
    assert d11.current_budget_grant(store._db, receipt.root_lease_id) == policy.root_grant
    assert receipt.fence_attempt_id in receipt.finish_request_id
    assert receipt.permit_wire["operation_id"] == receipt.fence_attempt_id
    assert port.validations == ["write", "write"]
    assert len(port.finishes) == 1 and port.finishes[0][0] == "write"

    duplicate = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    assert duplicate == receipt
    assert row_counts(store)["runtime_budget_leases"] == 1
    assert len(port.genesis_requests) == 1
    assert port.validations == ["write", "write", "read", "read"]


def test_expired_installation_grant_reloads_and_reconciles_existing_receipt(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    with patch.object(coordinator_module.time, "time",
                      return_value=policy.root_grant.valid_until_utc + 1):
        reloaded = replace(policy)
        assert reloaded.digest_payload() == policy.digest_payload()
        assert coordinator.provision_namespace_v2(
            bootstrap, reloaded, operation_id="install-persona") == receipt
    assert len(port.genesis_requests) == 1


def test_expired_grant_cannot_start_new_genesis(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    with patch.object(coordinator_module.time, "time",
                      return_value=policy.root_grant.valid_until_utc + 1):
        with pytest.raises(UnavailableGuard, match="root grant expired"):
            coordinator.provision_namespace_v2(
                bootstrap, policy, operation_id="install-persona")
    assert row_counts(store)["graph_namespace_provision_intents_v2"] == 0
    assert not port.genesis_requests


def test_expired_grant_can_resume_only_the_original_pending_intent(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    port.lose_genesis_after_durable = True
    with pytest.raises(RuntimeError, match="genesis response lost"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    intent = coordinator._provision_intent_row(store._db, policy.namespace)
    assert intent.anchor_json is None
    with patch.object(coordinator_module.time, "time",
                      return_value=policy.root_grant.valid_until_utc + 1):
        with pytest.raises(AuthorityDenied, match="identity differs"):
            coordinator.provision_namespace_v2(
                bootstrap, policy, operation_id="another-install")
        receipt = coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    assert receipt.fence_attempt_id == intent.fence_attempt_id
    assert port.genesis_requests == [
        (policy.namespace, intent.genesis_request_id)] * 2


def test_receipt_reconciles_after_signed_grant_renewal(system):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    renewed = replace(policy.root_grant, grant_id="grant-renewed", version=2,
                      valid_until_utc=policy.root_grant.valid_until_utc + 3600)
    d11.issue_budget_grant(store._db, renewed)
    assert d11.current_budget_grant(store._db, policy.root_lease.lease_id) == renewed
    assert coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona") == receipt
    assert len(port.genesis_requests) == 1


def test_renewed_grant_does_not_mask_tampered_bootstrap_signature(system):
    store, coordinator, bootstrap, _, d11 = system
    policy = policy_for(store)
    coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    d11.issue_budget_grant(store._db, replace(
        policy.root_grant, grant_id="grant-renewed", version=2))
    store._db.execute(
        "UPDATE runtime_budget_grants SET signature=? "
        "WHERE lease_id=? AND version=1",
        ("tampered", policy.root_lease.lease_id))
    with pytest.raises(UnavailableGuard, match="D11 budget grant is invalid"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")


def test_issuer_failure_rolls_back_genesis_but_keeps_exact_intent_and_fence(system):
    store, coordinator, bootstrap, port, d11 = system
    def unavailable(*_args):
        raise RuntimeError("issuer unavailable")
    d11.issue_budget_grant = unavailable
    with pytest.raises(RuntimeError, match="issuer unavailable"):
        coordinator.provision_namespace_v2(
            bootstrap, policy_for(store), operation_id="install-persona")
    counts = row_counts(store)
    assert counts["graph_namespace_provision_intents_v2"] == 1
    assert all(count == 0 for table, count in counts.items()
               if table != "graph_namespace_provision_intents_v2")
    assert not port.finishes
    intent = coordinator._provision_intent_row(store._db, policy_for(store).namespace)
    _, state = port.get_fence_operation(
        namespace=intent.namespace, authority_namespace="opaque:persona",
        operation_id=intent.fence_attempt_id)
    assert state == "active"


def test_same_business_id_with_different_policy_digest_is_rejected(system):
    store, coordinator, bootstrap, port, _ = system
    first = policy_for(store)
    coordinator.provision_namespace_v2(bootstrap, first, operation_id="install-persona")
    with pytest.raises(AuthorityDenied, match="identity differs"):
        coordinator.provision_namespace_v2(
            bootstrap, policy_for(store, scheme="scheme-2"),
            operation_id="install-persona")
    assert len(port.genesis_requests) == 1
    assert row_counts(store)["runtime_budget_leases"] == 1


def test_old_unsealed_history_rejects_before_authority_genesis(system):
    store, coordinator, bootstrap, port, _ = system
    store._db.execute(
        "INSERT INTO atoms(bot,persona,session,name,revision,value) "
        "VALUES(?,?,?,?,?,?)", ("bot", "persona", "s", "legacy", 1, "{}"))
    with pytest.raises(UnavailableGuard, match="unsealed"):
        coordinator.provision_namespace_v2(
            bootstrap, policy_for(store), operation_id="install-persona")
    assert not port.genesis_requests
    assert row_counts(store)["graph_recovery_metadata_v2"] == 0


def test_existing_other_persona_grant_does_not_block_second_genesis(system):
    store, coordinator, bootstrap, port, _ = system
    first = coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "one"), operation_id="install-one")
    second = coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "two"), operation_id="install-two")
    assert first.namespace != second.namespace
    assert row_counts(store)["graph_recovery_metadata_v2"] == 2
    assert row_counts(store)["runtime_budget_grants"] == 2


def test_other_sealed_graph_dependency_is_attributed_to_its_owner(system):
    store, coordinator, bootstrap, _, _ = system
    coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "one"), operation_id="install-one")
    key = AtomKey(Owner("persona", "bot", "one"), "legacy-state", "a")
    store._db.execute(
        "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,"
        "name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (key.token, "bot", "one", "persona", None, "legacy-state",
         "a", 1, "{}", 1))
    store._db.execute(
        "INSERT INTO graph_dependencies(dependent_token,dependency_token,"
        "dependency_revision) VALUES(?,?,?)", (key.token, key.token, 1))
    assert coordinator.provision_namespace_v2(
        bootstrap, policy_for(store, "two"),
        operation_id="install-two").namespace == NamespaceId("bot", "two")


def test_competing_authority_write_fence_leaves_business_db_empty(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    anchor = port.provision_namespace(
        namespace=policy.namespace, request_id="external-genesis").anchor
    foreign = port.fences.begin_fence(
        subject="subject", holder="administrator", operation="write",
        operation_id="foreign-active", current_anchor=anchor)
    try:
        with pytest.raises(UnavailableGuard, match="HOLD"):
            coordinator.provision_namespace_v2(
                bootstrap, policy, operation_id="install-persona")
        assert row_counts(store)["graph_namespace_provision_intents_v2"] == 1
        assert row_counts(store)["graph_namespace_provisioning_v2"] == 0
        assert row_counts(store)["runtime_budget_leases"] == 0
    finally:
        port.fences.finish_fence(
            foreign, subject="subject", current_anchor=anchor,
            request_id="finish-foreign", request_digest="sha256:" + "a" * 64)


def test_lost_finish_response_keeps_durable_reconciliation_identity(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    port.lose_finish_after_durable = True
    with pytest.raises(RuntimeError, match="finish response lost"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    assert row_counts(store)["graph_namespace_provisioning_v2"] == 1
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    assert receipt.finish_request_id == port.finishes[0][1]
    assert receipt.finish_request_digest == port.finishes[0][2]
    assert len(port.genesis_requests) == 1


def test_cold_restart_finishes_exact_durable_write_fence_then_reads(system, tmp_path):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    anchor = None

    def crash_before_finish(*_args, **_kwargs):
        raise RuntimeError("simulated process crash before Authority finish")

    port.finish_fence = crash_before_finish
    with pytest.raises(RuntimeError, match="simulated process crash"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    row = coordinator._provision_row(store._db, policy.namespace)
    assert row is not None
    anchor = port.anchors[policy.namespace]
    receipt = coordinator._decode_provision_receipt(row)
    _, state = port.get_fence_operation(
        namespace=policy.namespace, authority_namespace=anchor.namespace,
        operation_id=receipt.fence_attempt_id)
    assert state == "active"

    store.close()
    port.fences._db.close()
    reopened = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(
        tmp_path / "authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors[policy.namespace] = anchor
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=next_port, d11_issuer=d11)
    try:
        assert next_coordinator.provision_namespace_v2(
            next_bootstrap, policy, operation_id="install-persona") == receipt
        _, state = next_port.get_fence_operation(
            namespace=policy.namespace, authority_namespace=anchor.namespace,
            operation_id=receipt.fence_attempt_id)
        assert state == "finished"
        assert next_port.finishes[0] == (
            "write", receipt.finish_request_id, receipt.finish_request_digest)
        assert next_port.finishes[1][0] == "read"
        assert not next_port.genesis_requests
        assert row_counts(reopened)["runtime_budget_leases"] == 1
    finally:
        reopened.close()
        authority_db.close()


def test_mismatched_authority_permit_cannot_finish_old_active_fence(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)

    def crash_before_finish(*_args, **_kwargs):
        raise RuntimeError("simulated process crash before Authority finish")

    port.finish_fence = crash_before_finish
    with pytest.raises(RuntimeError, match="simulated process crash"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    port.finish_fence = AuthorityPort.finish_fence.__get__(port)
    original_status = port.get_fence_operation

    def altered_status(**kwargs):
        permit, state = original_status(**kwargs)
        return replace(permit, token="z" * 48), state

    port.get_fence_operation = altered_status
    with pytest.raises(UnavailableGuard, match="status differs"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    assert not port.finishes
    assert row_counts(store)["runtime_budget_leases"] == 1


def test_cold_restart_after_unknown_begin_replays_exact_attempt(system, tmp_path):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    port.lose_begin_after_durable = True
    with pytest.raises(UnavailableGuard, match="HOLD"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    intent = coordinator._provision_intent_row(store._db, policy.namespace)
    assert intent.anchor_json is not None
    assert row_counts(store)["graph_namespace_provisioning_v2"] == 0
    _, state = port.get_fence_operation(
        namespace=policy.namespace, authority_namespace=policy.authority_namespace,
        operation_id=intent.fence_attempt_id)
    assert state == "active"
    anchor = port.anchors[policy.namespace]

    store.close()
    port.fences._db.close()
    reopened = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors[policy.namespace] = anchor
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=next_port, d11_issuer=d11)
    try:
        receipt = next_coordinator.provision_namespace_v2(
            next_bootstrap, policy, operation_id="install-persona")
        assert receipt.fence_attempt_id == intent.fence_attempt_id
        assert receipt.graph_incarnation == intent.graph_incarnation
        assert not next_port.genesis_requests
        assert row_counts(reopened)["graph_namespace_provisioning_v2"] == 1
    finally:
        reopened.close()
        authority_db.close()


def test_d11_rollback_cold_restart_keeps_active_attempt(system, tmp_path):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    original = d11.issue_budget_grant
    d11.issue_budget_grant = lambda *_: (_ for _ in ()).throw(RuntimeError("D11 fail"))
    with pytest.raises(RuntimeError, match="D11 fail"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    intent = coordinator._provision_intent_row(store._db, policy.namespace)
    anchor = port.anchors[policy.namespace]
    assert not port.finishes
    d11.issue_budget_grant = original

    store.close()
    port.fences._db.close()
    reopened = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors[policy.namespace] = anchor
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=next_port, d11_issuer=d11)
    try:
        receipt = next_coordinator.provision_namespace_v2(
            next_bootstrap, policy, operation_id="install-persona")
        assert receipt.fence_attempt_id == intent.fence_attempt_id
        assert not next_port.genesis_requests
    finally:
        reopened.close()
        authority_db.close()


def test_subject_and_authority_namespace_change_reject_before_rpc(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    port.lose_begin_after_durable = True
    with pytest.raises(UnavailableGuard, match="HOLD"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    initial_calls = len(port.genesis_requests)
    port.installation_grant = replace(port.installation_grant, subject="other-subject")
    with pytest.raises(AuthorityDenied, match="identity differs"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    port.installation_grant = replace(port.installation_grant, subject="subject")
    with pytest.raises(AuthorityDenied, match="identity differs"):
        coordinator.provision_namespace_v2(
            bootstrap, replace(policy, authority_namespace="opaque:other"),
            operation_id="install-persona")
    assert len(port.genesis_requests) == initial_calls


def test_finished_fence_without_business_receipt_holds(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    port.lose_begin_after_durable = True
    with pytest.raises(UnavailableGuard, match="HOLD"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    intent = coordinator._provision_intent_row(store._db, policy.namespace)
    anchor = port.anchors[policy.namespace]
    permit, state = port.get_fence_operation(
        namespace=policy.namespace, authority_namespace=policy.authority_namespace,
        operation_id=intent.fence_attempt_id)
    assert state == "active"
    port.fences.finish_fence(
        permit, subject="subject", current_anchor=anchor,
        request_id="external-finish", request_digest="sha256:" + "b" * 64)
    with pytest.raises(UnavailableGuard, match="HOLD"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    assert not port.finishes
    assert row_counts(store)["graph_namespace_provisioning_v2"] == 0


def test_lost_genesis_response_retries_same_request(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    port.lose_genesis_after_durable = True
    with pytest.raises(RuntimeError, match="genesis response lost"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    intent = coordinator._provision_intent_row(store._db, policy.namespace)
    assert intent.anchor_json is None
    assert port.genesis_requests == [(policy.namespace, intent.genesis_request_id)]
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    assert receipt.fence_attempt_id == intent.fence_attempt_id
    assert port.genesis_requests == [
        (policy.namespace, intent.genesis_request_id)] * 2


@pytest.mark.parametrize("column,wrong_id", [
    ("genesis_request_id", "namespace-genesis-" + "f" * 48),
    ("fence_attempt_id", "provision-write-" + "f" * 48),
    ("graph_incarnation", "graph:" + "f" * 64),
])
def test_corrupt_persisted_attempt_identity_holds_before_authority_rpc(
        system, column, wrong_id):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    port.lose_genesis_after_durable = True
    with pytest.raises(RuntimeError, match="genesis response lost"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    initial_calls = len(port.genesis_requests)
    store._db.execute("DROP TRIGGER graph_namespace_provision_intent_anchor_once_v2")
    store._db.execute(
        f"UPDATE graph_namespace_provision_intents_v2 SET {column}=? "
        "WHERE bot=? AND persona=?", (wrong_id,) + policy.namespace.as_tuple)
    with pytest.raises(UnavailableGuard, match="intent is invalid"):
        coordinator.provision_namespace_v2(
            bootstrap, policy, operation_id="install-persona")
    assert len(port.genesis_requests) == initial_calls
    assert row_counts(store)["graph_namespace_provisioning_v2"] == 0


def test_legacy_receipt_without_intent_reconciles_without_backfill(system):
    store, coordinator, bootstrap, port, _ = system
    policy = policy_for(store)
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    store._db.execute("DROP TRIGGER graph_namespace_provision_intent_no_delete_v2")
    store._db.execute("DELETE FROM graph_namespace_provision_intents_v2")
    assert coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona") == receipt
    assert coordinator._provision_intent_row(store._db, policy.namespace) is None
    assert len(port.genesis_requests) == 1


def test_restored_pre_intent_business_db_reuses_finished_attempt_and_holds(
        system, tmp_path):
    store, coordinator, bootstrap, port, d11 = system
    policy = policy_for(store)
    before_path = tmp_path / "business-before.db"
    before = sqlite3.connect(before_path)
    store._db.backup(before)
    before.close()
    receipt = coordinator.provision_namespace_v2(
        bootstrap, policy, operation_id="install-persona")
    first_intent = coordinator._provision_intent_row(store._db, policy.namespace)
    anchor = port.anchors[policy.namespace]

    store.close()
    port.fences._db.close()
    shutil.copyfile(before_path, tmp_path / "business.db")
    reopened = ProductionGraphStore(tmp_path / "business.db", TypeRegistry())
    authority_db = sqlite3.connect(tmp_path / "authority.db", isolation_level=None)
    next_port = AuthorityPort(reopened, authority_db)
    next_port.anchors[policy.namespace] = anchor
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=next_port, d11_issuer=d11)
    try:
        with pytest.raises(UnavailableGuard, match="HOLD"):
            next_coordinator.provision_namespace_v2(
                next_bootstrap, policy, operation_id="install-persona")
        restored = next_coordinator._provision_intent_row(reopened._db, policy.namespace)
        assert restored.genesis_request_id == first_intent.genesis_request_id
        assert restored.fence_attempt_id == receipt.fence_attempt_id
        assert restored.graph_incarnation == receipt.graph_incarnation
        assert row_counts(reopened)["runtime_budget_leases"] == 0
        assert row_counts(reopened)["graph_namespace_provisioning_v2"] == 0
        assert not next_port.finishes
    finally:
        reopened.close()
        authority_db.close()
