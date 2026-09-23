"""D11 budget admission reads real lease/grant/reservation rows."""

import sqlite3
import tempfile
from pathlib import Path

from sylanne3.domains.d08.execution import (
    ActionIntent, GoalPredicate, RequiredCheckSpec,
)
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, reserve_budget, settle_budget,
    install_schema as install_budget_schema,
)
from sylanne3.runtime.dispatch_budget_check import (
    provide_dispatch_budget_check, provide_dispatch_budget_check_with_journal,
)
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D11BudgetGrantIssuer, install_schema as install_issuer_schema,
)
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, VersionedRef, canonical_digest,
)
from sylanne3.runtime_journal import (
    BudgetConstraint, ExecutionJournal, QuotaOccupancy,
    RecoveryConstraintFootprint, TrustedRestoreAnchor,
)


OPERATION = "operation:dispatch-1"
DIGEST = "b" * 64
CEILING = {"model_microusd": 300}
NAMESPACE = NamespaceId("bot", "persona")


def _intent(*, lease_version=2, include_reservation=True):
    versions = [VersionedRef("criteria:budget-1", 1),
                VersionedRef("d11.budget.lease:parent", lease_version)]
    if include_reservation:
        versions.append(VersionedRef(
            f"d11.budget.reservation:parent:{OPERATION}:{DIGEST}", 1,
        ))
    versions.append(VersionedRef("d11.budget.grant:parent", 1))
    spec = RequiredCheckSpec(
        "dispatch_budget", "d11.dispatch_budget", "persona:persona",
        "action:dispatch-1", "respond", "criteria:budget-1", tuple(versions),
    )
    return ActionIntent(
        "action:dispatch-1", 1, "goal:reply", (), "entity:user", "message",
        "respond", "reversible", canonical_digest({"message": "hello"}),
        OperationIdentity("activity:reply", "effect:reply", "attempt:1",
                          "prepare", OPERATION, canonical_digest({"input_refs": []})),
        "schema:reply", (spec,), GoalPredicate("communicated", "d11.delivery",
                                                 (), 0.0, None),
        ("message:entity:user",), None, ("source:message-1",),
    )


def _db():
    db = sqlite3.connect(":memory:")
    install_budget_schema(db)
    install_issuer_schema(db)
    create_budget_lease(db, BudgetLease(
        "parent", None, "bot", "persona", "USD", {"model_microusd": 500},
        {}, {}, {}, 1, "active",
    ), "create-parent", "a" * 64)
    issuer = D11BudgetGrantIssuer(b"k" * 32)
    issuer.issue_budget_grant(db, BudgetLeaseGrant(
        "grant-1", 1, "bot", "persona", "parent", "USD",
        {"model_microusd": 400}, ("message",), 100.0, "policy-1",
    ))
    return db, issuer


def _check(db, issuer, intent=None, **changes):
    kwargs = dict(namespace=NAMESPACE, lease_id="parent",
                  reservation_operation_id=OPERATION, reservation_digest=DIGEST,
                  required_ceiling=CEILING, work_kind="message",
                  policy_ref="policy-1", now_utc=10.0, valid_until=20.0)
    kwargs.update(changes)
    return provide_dispatch_budget_check(intent or _intent(), db, issuer, **kwargs)


def _journal_check(db, issuer, journal, anchor, footprint, *,
                   digest="digest:own"):
    return provide_dispatch_budget_check_with_journal(
        _intent(), db, issuer, namespace=NAMESPACE, lease_id="parent",
        reservation_operation_id=OPERATION, reservation_digest=DIGEST,
        required_ceiling=CEILING, work_kind="message", policy_ref="policy-1",
        now_utc=10.0, valid_until=20.0, journal=journal,
        restore_anchor=anchor, minimum_execution_seq=1,
        proposed_footprint=footprint,
        expected_command_digest=digest,
    )


def test_only_durable_reserved_cost_can_be_candidate_pass():
    db, issuer = _db()
    assert _check(db, issuer).result == "unknown"
    reserve_budget(db, "parent", OPERATION, DIGEST, CEILING)
    receipt = _check(db, issuer)
    assert (receipt.result, receipt.coverage) == ("pass", "full")
    assert receipt.input_versions == _intent().required_checks[0].required_input_versions
    db.close()


def test_unknown_cost_stays_occupied_and_reservation_cannot_be_reused():
    db, issuer = _db()
    reserve_budget(db, "parent", OPERATION, DIGEST, CEILING)
    settle_budget(db, "parent", OPERATION, DIGEST, None)
    assert _check(db, issuer, _intent(lease_version=3)).result == "unknown"
    assert db.execute("SELECT unconfirmed_json FROM runtime_budget_leases").fetchone()[0] == (
        '{"model_microusd":300}'
    )
    db.close()


def test_version_cost_and_signed_grant_must_all_match():
    db, issuer = _db()
    reserve_budget(db, "parent", OPERATION, DIGEST, CEILING)
    assert _check(db, issuer, _intent(lease_version=1)).result == "unknown"
    assert _check(db, issuer, required_ceiling={"model_microusd": 1}).result == "unknown"
    assert _check(db, issuer, policy_ref="different").result == "unknown"
    assert _check(db, issuer, namespace=NamespaceId("other", "persona")).result == "unknown"
    db.execute("UPDATE runtime_budget_grants SET signature='tampered'")
    assert _check(db, issuer).result == "unknown"
    db.close()


def _footprint(*, effect="effect:new", budget="parent", contact=None):
    return RecoveryConstraintFootprint(
        namespace="bot/persona", activity_id="activity:reply", effect_id=effect,
        communication_action="communication:reply" if contact else None,
        contact_id=contact,
        quota_occupancies=(QuotaOccupancy("proactive", "window-1", 1),)
        if contact else (),
        budgets=(BudgetConstraint(budget, "0", "300", "300"),),
    )


def test_current_independent_journal_blocks_unknown_budget_and_contact():
    db, issuer = _db()
    reserve_budget(db, "parent", OPERATION, DIGEST, CEILING)
    proposed = _footprint(contact="contact:user")
    trusted = set()
    with tempfile.TemporaryDirectory() as directory:
        journal = ExecutionJournal(Path(directory) / "execution.db",
                                   restore_anchor_verifier=trusted.__contains__)
        try:
            journal.prepare(
                effect_id="effect:old", command_digest="digest:old",
                dispatch_generation=1, activation_generation=1,
                admission_ref="admission:old",
                footprint=_footprint(effect="effect:old", budget="other",
                                     contact="contact:user"),
            )
            head = journal.latest_watermark()
            anchor = TrustedRestoreAnchor(head.journal_id, head.execution_seq,
                                          head.chain_digest, "authority:restore")
            trusted.add(anchor)
            blocked = _journal_check(db, issuer, journal, anchor, proposed)
            assert (blocked.result, blocked.coverage) == ("unknown", "partial")
            # A stale head must not silently permit a second action.
            journal.observe("effect:old", "digest:old", "unknown", "timeout:old")
            stale = _journal_check(db, issuer, journal, anchor, proposed)
            assert stale.result == "unknown"
        finally:
            journal.close()
    db.close()


def test_final_journal_requires_the_current_effect_even_without_other_conflicts():
    db, issuer = _db()
    reserve_budget(db, "parent", OPERATION, DIGEST, CEILING)
    trusted = set()
    with tempfile.TemporaryDirectory() as directory:
        journal = ExecutionJournal(Path(directory) / "execution.db",
                                   restore_anchor_verifier=trusted.__contains__)
        try:
            journal.prepare(
                effect_id="effect:other", command_digest="digest:other",
                dispatch_generation=1, activation_generation=1,
                admission_ref="admission:other",
                footprint=_footprint(effect="effect:other", budget="other"),
            )
            head = journal.latest_watermark()
            anchor = TrustedRestoreAnchor(head.journal_id, head.execution_seq,
                                          head.chain_digest, "authority:restore")
            trusted.add(anchor)
            checked = _journal_check(db, issuer, journal, anchor, _footprint())
            assert (checked.result, checked.coverage) == ("unknown", "partial")
        finally:
            journal.close()
    db.close()


def test_final_handoff_skips_only_its_exact_claimed_footprint():
    db, issuer = _db()
    reserve_budget(db, "parent", OPERATION, DIGEST, CEILING)
    own = _footprint(effect="effect:reply", contact="contact:user")
    trusted = set()
    with tempfile.TemporaryDirectory() as directory:
        journal = ExecutionJournal(Path(directory) / "execution.db",
                                   restore_anchor_verifier=trusted.__contains__)
        try:
            journal.prepare(
                effect_id=own.effect_id, command_digest="digest:own",
                dispatch_generation=1, activation_generation=1,
                admission_ref="admission:own", footprint=own,
            )

            def current_anchor():
                head = journal.latest_watermark()
                anchor = TrustedRestoreAnchor(head.journal_id, head.execution_seq,
                                              head.chain_digest, "authority:restore")
                trusted.add(anchor)
                return anchor

            anchor = current_anchor()
            assert _journal_check(db, issuer, journal, anchor, own,
                                  digest="digest:own").result == "unknown"
            journal.observe(own.effect_id, "digest:own", "claimed", "admission:own")
            anchor = current_anchor()
            assert _journal_check(db, issuer, journal, anchor, own,
                                  digest="digest:own").result == "pass"
            assert _journal_check(db, issuer, journal, anchor, own,
                                  digest="digest:wrong").result == "unknown"
            assert _journal_check(db, issuer, journal, anchor,
                                  _footprint(effect="effect:reply",
                                             contact="contact:another"),
                                  digest="digest:own").result == "unknown"
            journal.prepare(
                effect_id="effect:other", command_digest="digest:other",
                dispatch_generation=1, activation_generation=1,
                admission_ref="admission:other",
                footprint=_footprint(effect="effect:other", budget="parent"),
            )
            anchor = current_anchor()
            assert _journal_check(db, issuer, journal, anchor, own,
                                  digest="digest:own").result == "unknown"
        finally:
            journal.close()
    db.close()
