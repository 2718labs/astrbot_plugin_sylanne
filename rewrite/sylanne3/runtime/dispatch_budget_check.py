"""D11 dispatch-budget check over the durable business budget ledger.

This produces a candidate RequiredCheck. Final admission must call it again
inside its write fence and separately join the independent execution journal;
the business ledger alone cannot prove that every unknown handoff is present.
"""

from __future__ import annotations

import json
import math
from typing import Mapping

from ..authority_service.v2_contract import (
    AuthorityDispatchSnapshotV1, DispatchHandoffContextV1,
    OwnerDispatchWitnessV1,
)
from ..authority_service.reverse_handoff import require_exact_authority_snapshot
from ..domains.d08.execution import ActionIntent
from ..runtime_contracts import CheckReceipt, NamespaceId, VersionedRef
from ..runtime_journal import (
    ExecutionJournal, RecoveryConstraintFootprint, TrustedRestoreAnchor,
    WatermarkUnavailable,
)
from .budget import BudgetError, BudgetLease, get_budget_lease
from .issuers import D11BudgetGrantIssuer, IssuerAuthorityDenied


def _observed_versions(db, lease: BudgetLease, operation_id: str,
                       digest: str) -> tuple[VersionedRef, ...]:
    """Read the exact lease ancestry and the reservation's durable state."""
    versions = []
    seen = set()
    current = lease
    while True:
        if current.lease_id in seen or current.state != "active":
            raise BudgetError("budget ancestry is cyclic or inactive")
        seen.add(current.lease_id)
        versions.append(VersionedRef(f"d11.budget.lease:{current.lease_id}", current.version))
        if current.parent_id is None:
            break
        parent = get_budget_lease(db, current.parent_id)
        if (parent.bot_id, parent.persona_id, parent.currency) != (
                lease.bot_id, lease.persona_id, lease.currency):
            raise BudgetError("budget ancestry crosses namespace or currency")
        if any(parent.reserved.get(k, 0) < v for k, v in current.limits.items()):
            raise BudgetError("parent has lost the child lease encumbrance")
        current = parent
    row = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, operation_id),
    ).fetchone()
    if row is None or row[0] != digest or row[2] != "reserved":
        raise BudgetError("dispatch has no current matching reservation")
    ceiling = json.loads(row[1])
    if not isinstance(ceiling, dict) or not ceiling:
        raise BudgetError("reservation ceiling is invalid")
    if any(type(v) is not int or v <= 0 or lease.reserved.get(k, 0) < v
           for k, v in ceiling.items()):
        raise BudgetError("reservation is not held by the lease")
    # The reservation row has no revision column. Its state must be queried
    # again at final admission, even when this version set has not changed.
    versions.append(VersionedRef(
        f"d11.budget.reservation:{lease.lease_id}:{operation_id}:{digest}", 1,
    ))
    return tuple(versions)


def provide_dispatch_budget_check(
    intent: ActionIntent, db, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, lease_id: str, reservation_operation_id: str,
    reservation_digest: str,
    required_ceiling: Mapping[str, int], work_kind: str, policy_ref: str,
    now_utc: float, valid_until: float,
) -> CheckReceipt:
    """Read a signed grant, current lease chain and held reservation.

    ``required_ceiling`` is the cost ceiling of the action being dispatched,
    never a reported actual charge. Its exact value must match the durable
    reservation. A caller cannot make an absent reservation pass by supplying
    a balance or a zero cost. D11 must re-run this within final admission.
    """
    if (not isinstance(intent, ActionIntent)
            or not isinstance(issuer, D11BudgetGrantIssuer)
            or not isinstance(namespace, NamespaceId)):
        raise TypeError("typed action and D11 grant issuer are required")
    if any(type(value) not in (int, float) or not math.isfinite(value)
           for value in (now_utc, valid_until)):
        raise ValueError("check time must be finite")
    specs = [item for item in intent.required_checks if item.check_kind == "dispatch_budget"]
    if len(specs) != 1 or specs[0].provider_id != "d11.dispatch_budget":
        raise ValueError("action must require exactly one D11 budget check")
    spec = specs[0]
    if (spec.action_ref != intent.action_id or spec.purpose != intent.purpose
            or spec.subject_ref.removeprefix("persona:") == spec.subject_ref):
        raise ValueError("budget check scope differs from action")
    if reservation_operation_id != intent.identity.operation_id:
        raise ValueError("reservation must belong to the action operation")

    def receipt(result: str, coverage: str,
                versions: tuple[VersionedRef, ...] = ()) -> CheckReceipt:
        return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref,
                            spec.purpose, versions, coverage, result,
                            float(valid_until), spec.provider_id)

    try:
        lease = get_budget_lease(db, lease_id)
        grant = issuer.current_budget_grant(db, lease_id)
        observed = _observed_versions(db, lease, reservation_operation_id,
                                      reservation_digest)
        row = db.execute(
            "SELECT ceiling_json FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (lease_id, reservation_operation_id),
        ).fetchone()
        ceiling = json.loads(row[0])
    except (BudgetError, IssuerAuthorityDenied, ValueError, TypeError,
            json.JSONDecodeError):
        return receipt("unknown", "partial")
    observed += (VersionedRef(f"d11.budget.grant:{lease_id}", grant.version),)
    expected = tuple(item for item in spec.required_input_versions
                     if item.ref != spec.criteria_version)
    scope_matches = (
        (lease.bot_id, lease.persona_id) == namespace.as_tuple
        and (lease.bot_id, lease.persona_id, lease.currency)
        == (grant.bot_id, grant.persona_id, grant.currency)
        and lease.persona_id == spec.subject_ref.removeprefix("persona:")
        and grant.lease_id == lease_id
        and work_kind in grant.allowed_work_kinds
        and policy_ref == grant.policy_ref
        and ceiling == dict(required_ceiling)
        and all(0 < amount <= grant.max_ceiling.get(name, 0)
                for name, amount in ceiling.items())
        and grant.valid_until_utc >= valid_until > now_utc
    )
    if not scope_matches or set(observed) != set(expected) or len(observed) != len(expected):
        return receipt("unknown", "partial", observed)
    # The criteria reference remains caller-defined and must be revalidated by
    # final admission alongside this independently read budget state.
    return receipt("pass", "full", spec.required_input_versions)


def _check_dispatch_journal_constraints(
    candidate: CheckReceipt, journal: ExecutionJournal, *,
    restore_anchor: TrustedRestoreAnchor, minimum_execution_seq: int,
    namespace: NamespaceId, lease_id: str,
    proposed_footprint: RecoveryConstraintFootprint,
    expected_command_digest: str,
) -> CheckReceipt:
    """Conservatively join a budget candidate with current pending effects.

    The caller must supply the actual D11 admitted footprint, not a model/UI
    reconstruction. This is still a candidate: the final authority must hold
    its cross-store execution fence through graph claim and journal prepare.
    """
    if (not isinstance(candidate, CheckReceipt)
            or candidate.check_kind != "dispatch_budget"
            or candidate.issuer != "d11.dispatch_budget"
            or not isinstance(journal, ExecutionJournal)
            or not isinstance(namespace, NamespaceId)
            or not isinstance(proposed_footprint, RecoveryConstraintFootprint)):
        raise TypeError("typed budget candidate, journal and footprint are required")
    scoped_namespace = f"{namespace.bot_id}/{namespace.persona_id}"

    def hold() -> CheckReceipt:
        return CheckReceipt(
            candidate.check_kind, candidate.subject_ref, candidate.action_ref,
            candidate.purpose, candidate.input_versions, "partial", "unknown",
            candidate.valid_until, candidate.issuer,
        )

    if (candidate.result != "pass" or candidate.coverage != "full"
            or proposed_footprint.namespace != scoped_namespace
            or not any(item.parent_budget_ref == lease_id
                       and item.upper_bound is not None
                       for item in proposed_footprint.budgets)):
        return hold()
    try:
        pending = journal.unresolved_constraints(
            minimum_execution_seq=minimum_execution_seq,
            restore_anchor=restore_anchor,
        )
    except WatermarkUnavailable:
        return hold()
    lease_refs = {lease_id}
    lease_refs.update(item.ref.removeprefix("d11.budget.lease:")
                      for item in candidate.input_versions
                      if item.ref.startswith("d11.budget.lease:"))
    quota = {(item.bucket_key, item.window_key)
             for item in proposed_footprint.quota_occupancies}
    gates = set(proposed_footprint.object_gate_keys)
    own_entries = tuple(item for item in pending
                        if item.effect_id == proposed_footprint.effect_id)
    if (len(own_entries) != 1
            or own_entries[0].command_digest != expected_command_digest
            or own_entries[0].footprint != proposed_footprint
            or own_entries[0].latest_phase != "claimed"):
        return hold()
    for item in pending:
        if item.effect_id == proposed_footprint.effect_id:
            continue
        footprint = item.footprint
        if footprint.namespace != scoped_namespace:
            continue
        # An unresolved effect without a locatable budget cannot establish
        # that this namespace's parent lease is free.
        if not footprint.budgets:
            return hold()
        if any(budget.parent_budget_ref in lease_refs for budget in footprint.budgets):
            return hold()
        if (proposed_footprint.contact_id is not None
                and proposed_footprint.contact_id == footprint.contact_id):
            return hold()
        if gates.intersection(footprint.object_gate_keys):
            return hold()
        if quota.intersection((q.bucket_key, q.window_key)
                              for q in footprint.quota_occupancies):
            return hold()
    return candidate


def evaluate_dispatch_budget_authority_snapshot(
    context: DispatchHandoffContextV1,
    witness: OwnerDispatchWitnessV1,
    snapshot: AuthorityDispatchSnapshotV1, *,
    namespace: NamespaceId,
    proposed_footprint: RecoveryConstraintFootprint,
) -> tuple[str, ...]:
    """Check every Authority unresolved footprint against this one P2 effect.

    The reverse mTLS callback must supply the snapshot; this pure comparison
    cannot authenticate a caller-supplied DTO or issue a budget receipt.
    Empty blockers mean only that this conflict set is clear. The graph
    transaction still has to re-read the D11 grant, lease and reservation.
    """
    if (type(context) is not DispatchHandoffContextV1
            or type(witness) is not OwnerDispatchWitnessV1
            or type(snapshot) is not AuthorityDispatchSnapshotV1
            or type(namespace) is not NamespaceId
            or type(proposed_footprint) is not RecoveryConstraintFootprint):
        raise TypeError("typed Authority dispatch budget evidence is required")
    require_exact_authority_snapshot(context, witness, snapshot)
    permit = context.permit
    from ..graph_coordinator import namespace_ref

    if (snapshot.namespace != namespace_ref(namespace)
            or proposed_footprint.namespace != snapshot.namespace
            or proposed_footprint.effect_id != permit.effect_id
            or not any(item.upper_bound is not None
                       for item in proposed_footprint.budgets)):
        return ("own_budget_footprint_or_namespace_unproven",)
    own = tuple(item for item in snapshot.unresolved_effects
                if item.effect_id == permit.effect_id)
    if (len(own) != 1 or own[0].operation_id != permit.operation_id
            or own[0].phase != "claimed"
            or own[0].execution_seq != snapshot.anchor.execution_seq
            or own[0].append_digest != snapshot.anchor.execution_digest
            or own[0].footprint != proposed_footprint):
        return ("claimed_p2_footprint_or_append_unproven",)
    quotas = {(item.bucket_key, item.window_key)
              for item in proposed_footprint.quota_occupancies}
    gates = set(proposed_footprint.object_gate_keys)
    conflicts = set(proposed_footprint.conflict_keys)
    missing = []
    for item in snapshot.unresolved_effects:
        if item.effect_id == permit.effect_id:
            continue
        footprint = item.footprint
        # AuthorityDispatchSnapshotV1 requires every item to be in its opaque
        # namespace and to carry a decoded durable footprint.
        if not footprint.budgets:
            missing.append("other_unresolved_effect_budget_unknown")
        else:
            # No untrusted list of parent lease refs may narrow the overlap
            # set. Until the current ledger ancestry is joined by the graph
            # coordinator, every other namespace budget is a conflict.
            missing.append("other_unresolved_effect_budget_overlap")
        if (proposed_footprint.contact_id is not None
                and proposed_footprint.contact_id == footprint.contact_id):
            missing.append("other_unresolved_effect_contact_overlap")
        if gates.intersection(footprint.object_gate_keys):
            missing.append("other_unresolved_effect_gate_overlap")
        if quotas.intersection((q.bucket_key, q.window_key)
                               for q in footprint.quota_occupancies):
            missing.append("other_unresolved_effect_quota_overlap")
        if conflicts.intersection(footprint.conflict_keys):
            missing.append("other_unresolved_effect_conflict_key_overlap")
    return tuple(dict.fromkeys(missing))


def provide_dispatch_budget_check_with_journal(
    intent: ActionIntent, db, issuer: D11BudgetGrantIssuer, *,
    namespace: NamespaceId, lease_id: str, reservation_operation_id: str,
    reservation_digest: str, required_ceiling: Mapping[str, int],
    work_kind: str, policy_ref: str, now_utc: float, valid_until: float,
    journal: ExecutionJournal, restore_anchor: TrustedRestoreAnchor,
    minimum_execution_seq: int,
    proposed_footprint: RecoveryConstraintFootprint,
    expected_command_digest: str,
) -> CheckReceipt:
    """Re-read both stores for a current candidate under a caller-held fence.

    Production final admission must additionally keep the trusted journal and
    business fences current through claim and prepare. Neither store alone
    grants a send permit.
    """
    candidate = provide_dispatch_budget_check(
        intent, db, issuer, namespace=namespace, lease_id=lease_id,
        reservation_operation_id=reservation_operation_id,
        reservation_digest=reservation_digest, required_ceiling=required_ceiling,
        work_kind=work_kind, policy_ref=policy_ref, now_utc=now_utc,
        valid_until=valid_until,
    )
    return _check_dispatch_journal_constraints(
        candidate, journal, restore_anchor=restore_anchor,
        minimum_execution_seq=minimum_execution_seq, namespace=namespace,
        lease_id=lease_id, proposed_footprint=proposed_footprint,
        expected_command_digest=expected_command_digest,
    )


__all__ = [
    "evaluate_dispatch_budget_authority_snapshot",
    "provide_dispatch_budget_check", "provide_dispatch_budget_check_with_journal",
]
