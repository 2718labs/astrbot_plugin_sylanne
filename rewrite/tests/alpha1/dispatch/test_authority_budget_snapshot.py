"""A complete Authority effect set is screened without issuing a budget check."""

from dataclasses import replace
import hashlib

import pytest

from rewrite.tests.alpha1.dispatch.test_final_claim_namespace_mapping import _chain
from sylanne3.authority_service.v2_contract import (
    AuthorityDispatchSnapshotV1, AuthorityUnresolvedEffectV1,
    DispatchHandoffContextV1, OwnerDispatchWitnessV1,
    canonical_digest as authority_digest,
)
from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.runtime.dispatch_budget_check import (
    evaluate_dispatch_budget_authority_snapshot,
)
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime_journal import (
    BudgetConstraint, QuotaOccupancy, RecoveryConstraintFootprint,
)


def _case(*, contact=None, other=None):
    namespace = NamespaceId("bot", "persona")
    binding, claimed = _chain(namespace)
    footprint = _with_budget(binding.origin.footprint, contact=contact)
    p2 = replace(claimed.pending.permit,
                 revision=claimed.updated_revision,
                 pinned_anchor=claimed.after_anchor,
                 footprint_digest="sha256:" + hashlib.sha256(
                     footprint._json().encode()).hexdigest())
    context = DispatchHandoffContextV1(
        p2, authority_digest(claimed), authority_digest(binding), "handoff:test")
    guard = OwnerAuthorizationGuardV1(
        p2.authority_id, "installation:test", namespace, 1,
        "sha256:" + "a" * 64, 0, 0)
    witness = OwnerDispatchWitnessV1(
        authority_digest(context), p2.namespace, binding.graph_namespace,
        guard, "issue:test", "grant:test", "sha256:" + "b" * 64)
    own = AuthorityUnresolvedEffectV1(
        p2.effect_id, p2.operation_id, claimed.pending.mutation_id,
        "claimed", claimed.after_anchor.execution_seq,
        claimed.after_anchor.execution_digest, footprint)
    effects = tuple(sorted((own,) if other is None else (own, other),
                           key=lambda item: item.effect_id))
    snapshot = AuthorityDispatchSnapshotV1(
        authority_digest(context), p2.authority_id, p2.namespace,
        p2.pinned_anchor, authority_digest(witness), 0, 1,
        p2.operation_id, (), effects)
    return namespace, context, witness, snapshot, footprint


def _with_budget(footprint, *, parent="lease:test", contact=None):
    return replace(footprint, contact_id=contact,
                   communication_action="action:test" if contact else None,
                   budgets=(BudgetConstraint(parent, "0", "1", "2"),))


def test_complete_snapshot_with_only_own_claim_has_no_budget_conflict():
    namespace, context, witness, snapshot, footprint = _case()
    assert evaluate_dispatch_budget_authority_snapshot(
        context, witness, snapshot, namespace=namespace,
        proposed_footprint=footprint) == ()


@pytest.mark.parametrize("other_budget, expected", (
    ("lease:test", "other_unresolved_effect_budget_overlap"),
    ("lease:other", "other_unresolved_effect_contact_overlap"),
))
def test_other_unresolved_effect_blocks_overlap(other_budget, expected):
    namespace, context, witness, snapshot, footprint = _case(contact="contact:test")
    other_footprint = RecoveryConstraintFootprint(
        context.permit.namespace, "activity:other", "effect:other",
        communication_action="action:other", contact_id="contact:test",
        budgets=(BudgetConstraint(other_budget, "0", "1", "2"),))
    other = AuthorityUnresolvedEffectV1(
        "effect:other", "operation:other", "mutation:other", "prepared",
        1, "sha256:" + "c" * 64, other_footprint)
    snapshot = replace(snapshot, unresolved_effects=tuple(sorted((
        snapshot.unresolved_effects[0], other),
        key=lambda item: item.effect_id)))
    assert expected in evaluate_dispatch_budget_authority_snapshot(
        context, witness, snapshot, namespace=namespace,
        proposed_footprint=footprint)


def test_snapshot_cannot_be_rebound_to_another_owner_witness():
    namespace, context, witness, snapshot, footprint = _case()
    with pytest.raises(RuntimeError, match="snapshot differs"):
        evaluate_dispatch_budget_authority_snapshot(
            context, replace(witness, grant_id="grant:other"), snapshot,
            namespace=namespace,
            proposed_footprint=footprint)


def test_other_unresolved_effect_without_budget_scope_stays_unknown():
    namespace, context, witness, snapshot, footprint = _case()
    other = AuthorityUnresolvedEffectV1(
        "effect:other", "operation:other", "mutation:other", "prepared",
        1, "sha256:" + "c" * 64,
        RecoveryConstraintFootprint(
            context.permit.namespace, "activity:other", "effect:other"),
    )
    snapshot = replace(snapshot, unresolved_effects=tuple(sorted((
        snapshot.unresolved_effects[0], other), key=lambda item: item.effect_id)))
    assert "other_unresolved_effect_budget_unknown" in (
        evaluate_dispatch_budget_authority_snapshot(
            context, witness, snapshot, namespace=namespace,
            proposed_footprint=footprint))


def test_other_effect_with_same_gate_and_quota_blocks():
    namespace, context, witness, snapshot, footprint = _case(contact="contact:test")
    own = replace(footprint, object_gate_keys=("gate:test",),
                  quota_occupancies=(QuotaOccupancy("bucket:test", "window:test", 1),))
    p2 = replace(context.permit, footprint_digest="sha256:" + hashlib.sha256(
        own._json().encode()).hexdigest())
    context = replace(context, permit=p2)
    witness = replace(witness, context_digest=authority_digest(context))
    other = AuthorityUnresolvedEffectV1(
        "effect:other", "operation:other", "mutation:other", "prepared",
        1, "sha256:" + "c" * 64,
        RecoveryConstraintFootprint(
            p2.namespace, "activity:other", "effect:other",
            communication_action="action:other", contact_id="contact:other",
            object_gate_keys=("gate:test",),
            quota_occupancies=(QuotaOccupancy("bucket:test", "window:test", 1),),
            budgets=(BudgetConstraint("lease:other", "0", "1", "2"),)),
    )
    snapshot = replace(
        snapshot, context_digest=authority_digest(context),
        owner_witness_digest=authority_digest(witness),
        unresolved_effects=tuple(sorted((
            replace(snapshot.unresolved_effects[0], footprint=own), other),
            key=lambda item: item.effect_id)),
    )
    reasons = evaluate_dispatch_budget_authority_snapshot(
        context, witness, snapshot, namespace=namespace,
        proposed_footprint=own)
    assert "other_unresolved_effect_gate_overlap" in reasons
    assert "other_unresolved_effect_quota_overlap" in reasons
