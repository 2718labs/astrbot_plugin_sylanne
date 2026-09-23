"""Real journal bytes with test-only auth/domain issuers; no TLS claim."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from sylanne3.authority_service import (
    AuthorityUnavailable, LocalJournalBridge, constraint_keys_from_footprint,
)
from sylanne3.runtime_journal import RecoveryConstraintFootprint


class LocalBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.credential = object()
        self.signed_dispatch = {}
        self.bridge = LocalJournalBridge(
            namespace="ns:role", authority_path=root / "installer" / "authority.db",
            deletion_path=root / "installer" / "deletion.db",
            execution_path=root / "installer" / "execution.db",
            authorizer=lambda credential, action, namespace, holder:
                credential is self.credential,
            dispatch_verifier=lambda namespace, effect, keys:
                self.signed_dispatch.get((namespace, effect)) == keys,
            business_barrier=lambda intent: True,
            cleanup_verifier=lambda intent: True,
            create=True,
        )
        self.bridge.register_namespace(self.credential, "source-host")

    def tearDown(self):
        self.bridge.close()
        self.temp.cleanup()

    def _footprint(self, effect="effect-1", contact="contact-7"):
        return RecoveryConstraintFootprint(
            namespace="ns:role", activity_id="activity-1", effect_id=effect,
            conflict_keys=(contact,),
        )

    def _permit(self):
        return self.bridge.core.begin_content_operation(
            self.credential, namespace="ns:role", holder="source-host",
            generation=1, operation="dispatch")

    def test_service_owned_deletion_append_updates_current_anchor(self):
        original = self.bridge.core.current_anchor(self.credential, "ns:role")
        pending = self.bridge.append_deletion_intent(
            self.credential, operation_id="erase-1", closure_roots=("root-1",),
            epoch=1, policy_ref="policy-1")
        self.assertEqual(pending.deletion_seq, 1)
        self.assertFalse(self.bridge.core.verify_current(self.credential, original))
        with self.assertRaises(AuthorityUnavailable):
            self.bridge.core.check(self.credential, namespace="ns:role",
                                   holder="source-host", generation=1,
                                   operation="model_egress")
        accepted = self.bridge.advance_deletion(self.credential, "erase-1", "accepted")
        self.assertEqual(accepted.deletion_seq, 2)
        with self.assertRaises(AuthorityUnavailable):
            self.bridge.core.check(self.credential, namespace="ns:role",
                                   holder="source-host", generation=1,
                                   operation="read")
        closed = self.bridge.advance_deletion(self.credential, "erase-1", "closed")
        self.assertEqual(closed.deletion_seq, 3)
        self.assertTrue(self.bridge.deletion.verify_chain(
            self.bridge.deletion.latest_head()))

    def test_service_owned_execution_append_keeps_unresolved_effect(self):
        footprint = self._footprint()
        keys = constraint_keys_from_footprint(footprint)
        self.signed_dispatch[("ns:role", "effect-1")] = keys
        permit = self._permit()
        entry = self.bridge.prepare_execution(
            self.credential, permit=permit, effect_id="effect-1",
            command_digest="command-1", dispatch_generation=1,
            activation_generation=1, admission_ref="claim-1",
            footprint=footprint)
        self.assertEqual(entry.execution_seq, 1)
        self.assertEqual(self.bridge.core.current_anchor(
            self.credential, "ns:role").execution_seq, 1)
        self.bridge.core.end_content_operation(self.credential, permit)
        permit2 = self._permit()
        self.signed_dispatch[("ns:role", "effect-2")] = keys
        with self.assertRaises(AuthorityUnavailable):
            self.bridge.core.admit_dispatch(
                self.credential, namespace="ns:role", holder="source-host",
                generation=1, effect_id="effect-2", conflict_keys=keys,
                permit=permit2)
        self.bridge.core.end_content_operation(self.credential, permit2)

    def test_deletion_fsync_before_authority_commit_fails_closed_then_reconciles(self):
        core = self.bridge.core
        core._db.execute(
            "CREATE TRIGGER fail_bridge_event BEFORE INSERT ON authority_events "
            "BEGIN SELECT RAISE(ABORT, 'injected authority commit fault'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.bridge.append_deletion_intent(
                self.credential, operation_id="erase-fault",
                closure_roots=("root-1",), epoch=1, policy_ref="policy-1")
        self.assertEqual(self.bridge.deletion.latest_head().seq, 1)
        with self.assertRaises(AuthorityUnavailable):
            core.current_anchor(self.credential, "ns:role")
        with self.assertRaises(AuthorityUnavailable):
            core.begin_content_operation(
                self.credential, namespace="ns:role", holder="source-host",
                generation=1, operation="read")
        core._db.execute("DROP TRIGGER fail_bridge_event")
        anchor = self.bridge.reconcile_one(self.credential, "deletion")
        self.assertEqual(anchor.deletion_seq, 1)
        with self.assertRaises(AuthorityUnavailable):
            core.check(self.credential, namespace="ns:role", holder="source-host",
                       generation=1, operation="read")

    def test_execution_fsync_before_authority_commit_recovers_constraint(self):
        core = self.bridge.core
        footprint = self._footprint()
        keys = constraint_keys_from_footprint(footprint)
        self.signed_dispatch[("ns:role", "effect-1")] = keys
        permit = self._permit()
        core._db.execute(
            "CREATE TRIGGER fail_bridge_event BEFORE INSERT ON authority_events "
            "BEGIN SELECT RAISE(ABORT, 'injected authority commit fault'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.bridge.prepare_execution(
                self.credential, permit=permit, effect_id="effect-1",
                command_digest="command-1", dispatch_generation=1,
                activation_generation=1, admission_ref="claim-1",
                footprint=footprint)
        self.assertEqual(self.bridge.execution.latest_execution_seq(), 1)
        with self.assertRaises(AuthorityUnavailable):
            core.current_anchor(self.credential, "ns:role")
        core._db.execute("DROP TRIGGER fail_bridge_event")
        anchor = self.bridge.reconcile_one(self.credential, "execution")
        self.assertEqual(anchor.execution_seq, 1)
        with self.assertRaises(AuthorityUnavailable):
            core.admit_dispatch(
                self.credential, namespace="ns:role", holder="source-host",
                generation=1, effect_id="effect-1", conflict_keys=keys,
                permit=permit)
        core.end_content_operation(self.credential, permit)


if __name__ == "__main__":
    unittest.main()
