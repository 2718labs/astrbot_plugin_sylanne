"""The claim atom is one immutable recovery identity per effect."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.dispatch.test_final_claim_namespace_mapping import _chain
from sylanne3.authority_service.v2_contract import canonical_digest as authority_digest
from sylanne3.graph_coordinator import GraphCoordinator, namespace_ref
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime.d11_types import D11RuntimeProvider, validate_d11_writes
from sylanne3.runtime.dispatch_graph_claim import (
    CLAIM_TYPE, DispatchGraphClaimValueV1, dispatch_claim_graph_write,
    dispatch_claim_key,
)
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2


def _claim(**changes):
    namespace = NamespaceId("bot", "persona")
    digest = "sha256:" + "a" * 64
    fields = dict(
        bot_id="bot", persona_id="persona", graph_incarnation="graph:one",
        activity_id="activity:one", effect_id="effect:one",
        operation_id="operation:one", handoff_id="handoff:one",
        admission_ref="admission:one", authority_namespace=namespace_ref(namespace),
        p2_permit_digest=digest, p2_fence_epoch=1, p2_revision=2,
        p2_execution_seq=2, p2_execution_digest=digest,
        context_digest=digest, owner_witness_digest=digest,
        binding_digest=digest, claimed_receipt_digest=digest,
        current_evidence_digest=digest,
    )
    fields.update(changes)
    return DispatchGraphClaimValueV1(**fields)


def test_private_claim_type_has_stable_effect_key_and_strict_immutable_spec():
    value = _claim()
    first = dispatch_claim_graph_write(value)
    replay = dispatch_claim_graph_write(replace(value, handoff_id="handoff:other"))
    assert first.key == replay.key == dispatch_claim_key(
        NamespaceId("bot", "persona"), "effect:one")
    assert first.value["context_digest"] == value.context_digest
    assert "payload" not in first.value
    spec = next(item for item in D11RuntimeProvider().type_specs()
                if item.name == CLAIM_TYPE)
    assert spec.immutable is True
    assert spec.owner_kinds == ("persona",)
    assert spec.validator(first.value) == value
    with pytest.raises(ValueError, match="fields differ"):
        spec.validator({**first.value, "caller_passed": True})
    with pytest.raises(ValueError, match="wrong type, namespace, or activity owner"):
        validate_d11_writes(
            (first,), NamespaceId("bot", "persona"),
            operation_id=value.operation_id, activity_id=value.activity_id,
            effect_id=value.effect_id,
        )


@pytest.mark.parametrize("change", (
    {"authority_namespace": "bot/persona"},
    {"bot_id": "bad/bot"},
    {"p2_revision": 1},
    {"current_evidence_digest": "unknown"},
))
def test_claim_value_rejects_unbound_namespace_or_unclaimed_p2(change):
    with pytest.raises(ValueError):
        _claim(**change)


def test_final_snapshot_requires_one_held_transaction_and_covers_all_rows(tmp_path):
    registry = TypeRegistry()
    for spec in D11RuntimeProvider().type_specs():
        registry.register(spec)
    store = GraphStore(tmp_path / "graph.db", registry)
    try:
        coordinator = GraphCoordinator(store, object())
        namespace = NamespaceId("bot", "persona")
        with pytest.raises(RuntimeError, match="held write transaction"):
            coordinator._dispatch_full_graph_snapshot_locked(namespace)
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                snapshot, query = coordinator._dispatch_full_graph_snapshot_locked(namespace)
                assert snapshot.atoms == ()
                assert query.namespace == namespace
                assert query.scope_ref == "all"
                assert query.revision == snapshot.epochs[0].revision == 0
            finally:
                store._db.execute("ROLLBACK")
    finally:
        store.close()


def test_claim_atom_and_recovery_stamp_rollback_together(tmp_path):
    namespace = NamespaceId("bot", "persona")
    binding, claimed = _chain(namespace)
    registry = TypeRegistry()
    for spec in D11RuntimeProvider().type_specs():
        registry.register(spec)
    store = GraphStore(tmp_path / "graph.db", registry)
    try:
        coordinator = GraphCoordinator(store, object())
        capability = coordinator._GraphCoordinator__graph_capability
        store._coordinator_capability = capability
        anchor = binding.permit.pinned_anchor
        genesis = SnapshotRequirementsV2(
            namespace, anchor.authority_id, anchor.namespace,
            anchor.activation_generation, anchor.deletion_journal_id,
            anchor.deletion_seq, anchor.deletion_digest,
            anchor.execution_journal_id, anchor.execution_seq,
            anchor.execution_digest, anchor.revocation_epoch,
            binding.graph_incarnation,
        )
        store.install_graph_recovery_genesis(genesis, _capability=capability)
        value = _claim(
            graph_incarnation=binding.graph_incarnation,
            activity_id=binding.origin.activity_id,
            effect_id=binding.origin.effect_id,
            operation_id=binding.operation_id,
            admission_ref=binding.origin.admission_ref,
            p2_fence_epoch=claimed.pending.permit.fence_epoch,
            p2_revision=claimed.updated_revision,
            p2_execution_seq=claimed.after_anchor.execution_seq,
            p2_execution_digest=claimed.after_anchor.execution_digest,
            p2_permit_digest=authority_digest(replace(
                claimed.pending.permit, revision=claimed.updated_revision,
                pinned_anchor=claimed.after_anchor)),
            binding_digest=authority_digest(binding),
            claimed_receipt_digest=authority_digest(claimed),
        )
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            version, epoch, created = coordinator._commit_dispatch_claim_atom_in_transaction(
                namespace, value, claimed)
            assert (version.revision, epoch, created) == (1, 1, True)
            assert store.graph_recovery_metadata(
                namespace, _capability=capability).requirements.execution_seq == 2
            store._db.execute("ROLLBACK")
        assert store.graph_recovery_metadata(
            namespace, _capability=capability).requirements.execution_seq == 0
        assert store._db.execute("SELECT COUNT(*) FROM graph_atoms").fetchone()[0] == 0
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            original = coordinator._commit_dispatch_claim_atom_in_transaction(
                namespace, value, claimed)
            store._db.execute("COMMIT")
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                replay = coordinator._commit_dispatch_claim_atom_in_transaction(
                    namespace, value, claimed)
                assert replay == (original[0], original[1], False)
                with pytest.raises(Exception, match="different graph claim"):
                    coordinator._commit_dispatch_claim_atom_in_transaction(
                        namespace, replace(value, handoff_id="handoff:other"),
                        claimed)
            finally:
                store._db.execute("ROLLBACK")
        assert store.graph_recovery_metadata(
            namespace, _capability=capability).graph_revision == 1
    finally:
        store.close()
