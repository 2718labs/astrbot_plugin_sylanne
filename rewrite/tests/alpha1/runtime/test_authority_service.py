"""Kernel tests use explicit test verifiers, never a production trust claim."""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sylanne3.authority_service import (
    AuthorityServiceCore, AuthorityUnavailable, JournalHead,
)
from sylanne3.runtime.activation import TransferPlan


class TestAuthorityService(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.authority_path = self.root / "installer" / "authority.db"
        self.business_path = self.root / "business" / "snapshot.db"
        self.business_path.parent.mkdir()
        with closing(sqlite3.connect(self.business_path)) as db:
            with db:
                db.execute("CREATE TABLE content(value TEXT)")
                db.execute("INSERT INTO content VALUES('old business snapshot')")
        self.business_backup = self.business_path.read_bytes()
        self.credential = object()
        self.approved_deletion = {JournalHead("deletion-journal", 0, "genesis")}
        self.approved_execution = {JournalHead("execution-journal", 0, "genesis")}
        self.latest_deletion = JournalHead("deletion-journal", 0, "genesis")
        self.latest_execution = JournalHead("execution-journal", 0, "genesis")
        self.service = self._open(create=True)
        self.deletion0 = JournalHead("deletion-journal", 0, "genesis")
        self.execution0 = JournalHead("execution-journal", 0, "genesis")
        self.service.register_namespace(self.credential, "ns:role", "source-host",
                                        self.deletion0, self.execution0)

    def _open(self, *, create=False):
        return AuthorityServiceCore(
            self.authority_path,
            authorizer=lambda credential, action, namespace, holder:
                credential is self.credential,
            deletion_verifier=lambda namespace, previous, current, phase:
                current in self.approved_deletion and current == self.latest_deletion,
            execution_verifier=lambda namespace, previous, current, phase:
                current in self.approved_execution and current == self.latest_execution,
            effect_verifier=lambda namespace, effect, state, keys, head:
                head in self.approved_execution,
            dispatch_verifier=lambda namespace, effect, keys: True,
            create=create,
        )

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    @staticmethod
    def head(journal, seq, digit):
        return JournalHead(journal, seq, "sha256:" + digit * 64)

    def test_persistent_permit_blocks_transfer_until_explicit_release(self):
        permit = self.service.begin_content_operation(
            self.credential, namespace="ns:role", holder="source-host",
            generation=1, operation="read")
        plan = TransferPlan("ns:role", "source-host", "target-host", "move-1")
        self.service.begin_transfer(self.credential, plan, expected_generation=1)
        self.service.close()
        self.service = self._open()
        with self.assertRaises(AuthorityUnavailable):
            self.service.revoke_source(self.credential, "move-1",
                                       expected_generation=1)
        with self.assertRaises(AuthorityUnavailable):
            self.service.activate_target(
                self.credential, "move-1", expected_revoked_generation=2,
                deletion=self.deletion0, execution=self.execution0)
        self.service.end_content_operation(self.credential, permit)
        revoked = self.service.revoke_source(
            self.credential, "move-1", expected_generation=1)
        self.assertEqual((revoked.holder, revoked.generation, revoked.phase),
                         (None, 2, "revoked"))
        for holder, generation in (("source-host", 1), ("target-host", 2)):
            with self.assertRaises(AuthorityUnavailable):
                self.service.check(self.credential, namespace="ns:role",
                                   holder=holder, generation=generation,
                                   operation="read")
        with self.assertRaises(AuthorityUnavailable):
            self.service.activate_target(
                self.credential, "move-1", expected_revoked_generation=2,
                deletion=self.head("deletion-journal", 1, "a"),
                execution=self.execution0)
        active = self.service.activate_target(
            self.credential, "move-1", expected_revoked_generation=2,
            deletion=self.deletion0, execution=self.execution0)
        self.assertEqual((active.holder, active.generation), ("target-host", 3))
        with self.assertRaises(AuthorityUnavailable):
            self.service.activate_target(
                self.credential, "move-1", expected_revoked_generation=2,
                deletion=self.head("deletion-journal", 1, "a"),
                execution=self.execution0)
        self.business_path.write_bytes(self.business_backup)
        self.service.close()
        self.service = self._open()
        self.assertEqual(self.service.current(self.credential, "ns:role").generation, 3)
        with self.assertRaises(AuthorityUnavailable):
            self.service.check(self.credential, namespace="ns:role",
                               holder="source-host", generation=1,
                               operation="model_egress")
        self.service.check(self.credential, namespace="ns:role",
                           holder="target-host", generation=3,
                           operation="read")

    def test_deletion_head_cas_and_pending_barrier_survive_business_rollback(self):
        old_anchor = self.service.current_anchor(self.credential, "ns:role")
        pending = self.head("deletion-journal", 1, "a")
        self.approved_deletion.add(pending)
        self.latest_deletion = pending
        with self.assertRaises(AuthorityUnavailable):
            self.service.begin_content_operation(
                self.credential, namespace="ns:role", holder="source-host",
                generation=1, operation="model_egress")
        anchor = self.service.observe_deletion_head(
            self.credential, "ns:role", self.deletion0, pending, "pending")
        self.assertFalse(self.service.verify_current(self.credential, old_anchor))
        self.assertTrue(self.service.verify_current(self.credential, anchor))
        with self.assertRaises(AuthorityUnavailable):
            self.service.check(self.credential, namespace="ns:role",
                               holder="source-host", generation=1,
                               operation="read")
        with self.assertRaises(AuthorityUnavailable):
            self.service.observe_deletion_head(
                self.credential, "ns:role", self.deletion0, pending, "pending")
        cleared = self.head("deletion-journal", 2, "b")
        self.approved_deletion.add(cleared)
        self.latest_deletion = cleared
        self.service.observe_deletion_head(
            self.credential, "ns:role", pending, cleared, "clear")
        self.business_path.write_bytes(self.business_backup)
        self.service.check(self.credential, namespace="ns:role",
                           holder="source-host", generation=1,
                           operation="read")
        self.assertEqual(self.service.current_anchor(
            self.credential, "ns:role").deletion_seq, 2)

    def test_unresolved_effect_blocks_original_and_conflicting_new_effect(self):
        dispatch_permit = self.service.begin_content_operation(
            self.credential, namespace="ns:role", holder="source-host",
            generation=1, operation="dispatch")
        self.service.admit_dispatch(
            self.credential, namespace="ns:role", holder="source-host",
            generation=1, effect_id="effect-1",
            conflict_keys=("contact-7", "budget-1"), permit=dispatch_permit)
        head1 = self.head("execution-journal", 1, "c")
        self.approved_execution.add(head1)
        self.latest_execution = head1
        self.service.observe_execution_head(
            self.credential, "ns:role", self.execution0, head1,
            effect_id="effect-1", state="unresolved",
            conflict_keys=("contact-7", "budget-1"))
        self.latest_execution = self.execution0  # Simulated journal rollback.
        with self.assertRaises(AuthorityUnavailable):
            self.service.current_anchor(self.credential, "ns:role")
        with self.assertRaises(AuthorityUnavailable):
            self.service.admit_dispatch(
                self.credential, namespace="ns:role", holder="source-host",
                generation=1, effect_id="effect-4", conflict_keys=("other",),
                permit=dispatch_permit)
        self.latest_execution = head1
        for effect, keys in (("effect-1", ("other",)),
                             ("effect-2", ("contact-7",))):
            with self.assertRaises(AuthorityUnavailable):
                self.service.admit_dispatch(
                    self.credential, namespace="ns:role", holder="source-host",
                    generation=1, effect_id=effect, conflict_keys=keys,
                    permit=dispatch_permit)
        self.business_path.write_bytes(self.business_backup)
        self.service.close()
        self.service = self._open()
        with self.assertRaises(AuthorityUnavailable):
            self.service.admit_dispatch(
                self.credential, namespace="ns:role", holder="source-host",
                generation=1, effect_id="effect-3",
                conflict_keys=("contact-7",), permit=dispatch_permit)
        head2 = self.head("execution-journal", 2, "d")
        self.approved_execution.add(head2)
        self.latest_execution = head2
        self.service.observe_execution_head(
            self.credential, "ns:role", head1, head2, effect_id="effect-1",
            state="resolved", conflict_keys=("contact-7", "budget-1"))
        self.service.admit_dispatch(
            self.credential, namespace="ns:role", holder="source-host",
            generation=1, effect_id="effect-3",
            conflict_keys=("contact-7",), permit=dispatch_permit)
        with self.assertRaises(AuthorityUnavailable):
            self.service.admit_dispatch(
                self.credential, namespace="ns:role", holder="source-host",
                generation=1, effect_id="effect-1",
                conflict_keys=("contact-7",), permit=dispatch_permit)
        self.service.end_content_operation(self.credential, dispatch_permit)

    def test_authentication_and_transaction_faults_fail_closed(self):
        with self.assertRaises(AuthorityUnavailable):
            self.service.current(object(), "ns:role")
        first = self.head("execution-journal", 1, "e")
        self.approved_execution.add(first)
        self.latest_execution = first
        self.service._db.execute(
            "CREATE TRIGGER fail_authority_event BEFORE INSERT ON authority_events "
            "BEGIN SELECT RAISE(ABORT, 'injected authority event fault'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.service.observe_execution_head(
                self.credential, "ns:role", self.execution0, first,
                effect_id="effect-fault", state="unresolved",
                conflict_keys=("contact-1",))
        self.latest_execution = self.execution0
        self.assertEqual(self.service.current_anchor(
            self.credential, "ns:role").execution_seq, 0)
        self.assertEqual(self.service._db.execute(
            "SELECT count(*) FROM authority_effects").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
