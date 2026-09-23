import tempfile
import threading
import unittest
from pathlib import Path
import shutil

from sylanne3.runtime_journal import (
    BudgetConstraint,
    EffectConflict,
    ExecutionJournal,
    QuotaOccupancy,
    RecoveryConstraintFootprint,
    ReservationConstraint,
    SettlementAuthority,
    SettlementAuthorityRequired,
    TrustedRestoreAnchor,
    WatermarkUnavailable,
)


class ExecutionJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "execution-journal.db"
        self.trusted_anchors = set()
        self.valid_settlements = set()
        self.journal = ExecutionJournal(
            self.path,
            restore_anchor_verifier=self.trusted_anchors.__contains__,
            settlement_verifier=self.valid_settlements.__contains__,
        )

    def tearDown(self):
        self.journal.close()
        self.temp.cleanup()

    def footprint(self):
        return RecoveryConstraintFootprint(
            namespace="bot/persona",
            activity_id="activity-1",
            effect_id="effect-1",
            external_idempotency_ref="provider-key-1",
            external_query_ref="provider-query-1",
            conflict_keys=("recipient:user-7",),
            communication_action="communication-1",
            contact_id="contact-1",
            segment_id="segment-1",
            object_gate_keys=("no-response:user-7",),
            quota_occupancies=(QuotaOccupancy("proactive-contact", "2026-W39", 1),),
            reservations=(ReservationConstraint("reservation-1", "component-1", "4.5"),),
            budgets=(BudgetConstraint("parent-budget-1", "1.25", "0.75", "5"),),
        )

    def prepare(self, *, digest="sha256:command-a"):
        return self.journal.prepare(
            effect_id="effect-1",
            command_digest=digest,
            dispatch_generation=7,
            activation_generation=11,
            admission_ref="admission-1",
            footprint=self.footprint(),
        )

    def trust_current_watermark(self):
        local = self.journal.latest_watermark()
        anchor = TrustedRestoreAnchor(
            local.journal_id, local.execution_seq, local.chain_digest,
            "restore-authority-1")
        self.trusted_anchors.add(anchor)
        return anchor

    def test_prepared_half_commit_survives_reopen_as_unresolved(self):
        prepared = self.prepare()
        self.assertEqual((prepared.execution_seq, prepared.phase), (1, "prepared"))
        anchor = self.trust_current_watermark()
        self.journal.close()

        self.journal = ExecutionJournal(
            self.path, restore_anchor_verifier=self.trusted_anchors.__contains__,
            settlement_verifier=self.valid_settlements.__contains__)
        pending = self.journal.unresolved_constraints(
            minimum_execution_seq=1, restore_anchor=anchor)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].latest_phase, "prepared")
        self.assertEqual(pending[0].footprint.contact_id, "contact-1")
        self.assertEqual(pending[0].footprint.object_gate_keys,
                         ("no-response:user-7",))

    def test_same_effect_and_command_is_idempotent_but_changed_binding_conflicts(self):
        first = self.prepare()
        duplicate = self.prepare()
        self.assertEqual(duplicate, first)
        self.assertEqual(self.journal.latest_execution_seq(), 1)

        with self.assertRaises(EffectConflict):
            self.prepare(digest="sha256:command-b")
        with self.assertRaises(EffectConflict):
            self.journal.prepare(
                effect_id="effect-1",
                command_digest="sha256:command-a",
                dispatch_generation=8,
                activation_generation=11,
                admission_ref="admission-1",
                footprint=self.footprint(),
            )

    def test_observations_append_with_monotonic_sequence_and_unknown_does_not_release(self):
        self.prepare()
        handed_off = self.journal.observe(
            "effect-1", "sha256:command-a", "handed_off", "platform-call-1")
        unknown = self.journal.observe(
            "effect-1", "sha256:command-a", "unknown", "timeout-1")
        self.assertEqual((handed_off.execution_seq, unknown.execution_seq), (2, 3))
        anchor = self.trust_current_watermark()

        pending = self.journal.unresolved_constraints(
            minimum_execution_seq=3, restore_anchor=anchor)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].latest_phase, "unknown")
        self.assertEqual(pending[0].footprint.reservations[0].upper_bound, "4.5")
        self.assertEqual(pending[0].footprint.budgets[0].pending_amount, "0.75")

    def test_old_business_backup_still_recovers_contact_claim_and_gate(self):
        self.prepare()
        self.journal.observe(
            "effect-1", "sha256:command-a", "claimed", "business-claim-1")
        anchor = self.trust_current_watermark()

        constraints = self.journal.unresolved_constraints(
            minimum_execution_seq=2, restore_anchor=anchor)
        recovered = constraints[0].footprint
        self.assertEqual(recovered.communication_action, "communication-1")
        self.assertEqual(recovered.contact_id, "contact-1")
        self.assertEqual(recovered.quota_occupancies[0].occupied, 1)
        self.assertEqual(recovered.object_gate_keys, ("no-response:user-7",))

    def test_explicit_proven_release_resolves_but_unknown_never_does(self):
        self.prepare()
        self.journal.observe(
            "effect-1", "sha256:command-a", "unknown", "timeout-1")
        anchor = self.trust_current_watermark()
        self.assertEqual(len(self.journal.unresolved_constraints(
            minimum_execution_seq=2, restore_anchor=anchor)), 1)

        with self.assertRaises(ValueError):
            self.journal.observe(
                "effect-1", "sha256:command-a", "constraints_released",
                "domain-release-receipt-1")
        settlement = SettlementAuthority(
            "bot/persona", "effect-1", "constraints_released",
            "domain-release-receipt-1")
        with self.assertRaises(SettlementAuthorityRequired):
            self.journal.release_constraints(
                "effect-1", "sha256:command-a", settlement)
        self.valid_settlements.add(settlement)
        released = self.journal.release_constraints(
            "effect-1", "sha256:command-a", settlement)
        anchor = self.trust_current_watermark()
        self.assertEqual(self.journal.unresolved_constraints(
            minimum_execution_seq=released.execution_seq,
            restore_anchor=anchor), ())

    def test_missing_or_stale_minimum_watermark_fails_closed(self):
        self.prepare()
        local = self.journal.latest_watermark()
        self.assertEqual(local.execution_seq, 1)
        with self.assertRaises(WatermarkUnavailable):
            self.journal.unresolved_constraints(
                minimum_execution_seq=1, restore_anchor=None)
        untrusted = TrustedRestoreAnchor(
            local.journal_id, local.execution_seq, local.chain_digest,
            "unknown-authority")
        with self.assertRaises(WatermarkUnavailable):
            self.journal.unresolved_constraints(
                minimum_execution_seq=1, restore_anchor=untrusted)

        trusted = self.trust_current_watermark()
        self.journal.observe(
            "effect-1", "sha256:command-a", "unknown", "timeout-1")
        with self.assertRaises(WatermarkUnavailable):
            self.journal.unresolved_constraints(
                minimum_execution_seq=1, restore_anchor=trusted)

    def test_whole_file_rollback_fails_against_independent_current_anchor(self):
        self.prepare()
        self.journal.close()
        backup = Path(self.temp.name) / "old-copy.db"
        shutil.copy2(self.path, backup)
        self.journal = ExecutionJournal(
            self.path, restore_anchor_verifier=self.trusted_anchors.__contains__,
            settlement_verifier=self.valid_settlements.__contains__)
        self.journal.observe(
            "effect-1", "sha256:command-a", "unknown", "timeout-1")
        current = self.trust_current_watermark()
        self.journal.close()
        shutil.copy2(backup, self.path)
        self.journal = ExecutionJournal(
            self.path, restore_anchor_verifier=self.trusted_anchors.__contains__,
            settlement_verifier=self.valid_settlements.__contains__)

        with self.assertRaises(WatermarkUnavailable):
            self.journal.unresolved_constraints(
                minimum_execution_seq=1, restore_anchor=current)

    def test_footprint_rejects_content_shaped_or_incomplete_contact_data(self):
        with self.assertRaises(ValueError):
            RecoveryConstraintFootprint(
                namespace="bot/persona", activity_id="activity-1",
                effect_id="effect-1", contact_id="contact-1")
        with self.assertRaises(ValueError):
            RecoveryConstraintFootprint(
                namespace="bot/persona", activity_id="activity-1",
                effect_id="effect-1", communication_action="communication-1",
                contact_id="contact-1", object_gate_keys=("hello\nraw body",))

    def test_serialized_calls_are_safe_from_runtime_worker_threads(self):
        result = []
        failure = []

        def work():
            try:
                result.append(self.prepare())
            except BaseException as exc:
                failure.append(exc)

        thread = threading.Thread(target=work)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failure, [])
        self.assertEqual(result[0].phase, "prepared")


if __name__ == "__main__":
    unittest.main()
