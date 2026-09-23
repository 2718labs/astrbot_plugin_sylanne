"""Failure cases for independent deletion/recovery/activation primitives."""

from __future__ import annotations

import sqlite3

import pytest

from rewrite.sylanne3.runtime.activation import (
    ActivationDenied, SqliteMigrationAuthority, TransferPlan,
)
from rewrite.sylanne3.runtime.deletion import (
    DeletionBlocked, DeletionJournal, DeletionJournalUnavailable,
)
from rewrite.sylanne3.runtime.restore_anchor import (
    RestoreAnchor, RestoreQuarantined, SnapshotRequirements,
    _execution_head_and_continuity, validate_restore,
)
from rewrite.sylanne3.runtime_journal import (
    ExecutionJournal, RecoveryConstraintFootprint,
)


class ExternalAuthorityStub:
    """Test double only: production must use an independent current authority."""

    def __init__(self, anchor):
        self.anchor = anchor

    def current_anchor(self, namespace):
        return self.anchor

    def verify_current(self, anchor):
        return anchor is self.anchor


class ServiceExecutionJournalStub:
    """Test-only stand-in for a service-owned journal, never a client claim."""

    def __init__(self, path, *, namespace="bot/persona"):
        self.path = path
        self.namespace = namespace
        self.calls = []

    def verify_current_chain(self, namespace, expected_head):
        self.calls.append((namespace, expected_head))
        return (namespace == self.namespace
                and _execution_head_and_continuity(self.path) == expected_head)


def _anchor(deletion, execution, *, generation=1, revocation=0):
    d = deletion.latest_head()
    e = execution.latest_watermark()
    return RestoreAnchor(
        "installer", "bot/persona", generation, d.journal_id, d.seq,
        d.chain_digest, e.journal_id if e else "empty-execution",
        e.execution_seq if e else 0, e.chain_digest if e else "genesis",
        revocation, "external-proof",
    )


def _snapshot():
    return SnapshotRequirements("bot/persona", 1, 0, 0, 0)


def _execution(path):
    journal = ExecutionJournal(path)
    journal.prepare(effect_id="effect-1", command_digest="sha256:command",
                    dispatch_generation=1, activation_generation=1,
                    admission_ref="admission-1",
                    footprint=RecoveryConstraintFootprint(
                        namespace="bot/persona", activity_id="activity-1",
                        effect_id="effect-1"))
    return journal


def test_pending_deletion_is_durable_and_blocks_before_acceptance(tmp_path):
    path = tmp_path / "independent-deletion.sqlite"
    with pytest.raises(DeletionJournalUnavailable):
        DeletionJournal(path)
    journal = DeletionJournal(path, create=True)
    intent = journal.append_intent(namespace="bot/persona", operation_id="erase-1",
                                   closure_roots=("root-1",), epoch=1,
                                   policy_ref="policy-1")
    assert intent.phase == "pending"
    with pytest.raises(DeletionBlocked):
        journal.assert_access("bot/persona")
    with pytest.raises(DeletionBlocked):
        journal.advance("erase-1", "accepted", business_barrier=lambda _: False)
    head = journal.latest_head()
    journal.close()
    reopened = DeletionJournal(path)
    assert reopened.verify_chain(head)
    with pytest.raises(DeletionBlocked):
        reopened.assert_access("bot/persona")
    assert reopened.advance("erase-1", "accepted",
                            business_barrier=lambda item: item.seq == intent.seq).phase == "accepted"
    with pytest.raises(DeletionBlocked):
        reopened.assert_access("bot/persona", content_refs=("unrelated",))
    with pytest.raises(DeletionBlocked):
        reopened.assert_access(
            "bot/persona", content_refs=("root-1",),
            closure_verifier=lambda item, refs: not set(refs).intersection(item.closure_roots))
    reopened.assert_access(
        "bot/persona", content_refs=("unrelated",),
        closure_verifier=lambda item, refs: not set(refs).intersection(item.closure_roots))
    with pytest.raises(DeletionBlocked):
        reopened.advance("erase-1", "closed")
    reopened.close()


def test_restore_rejects_old_deletion_or_execution_journal(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.sqlite", create=True)
    execution = _execution(tmp_path / "execution.sqlite")
    first = deletion.append_intent(namespace="bot/persona", operation_id="erase-1",
                                   closure_roots=("root-1",), epoch=1,
                                   policy_ref="policy-1")
    old_deletion_path = tmp_path / "old-deletion.sqlite"
    with sqlite3.connect(old_deletion_path) as target:
        deletion._db.backup(target)
    old_execution_path = tmp_path / "old-execution.sqlite"
    with sqlite3.connect(old_execution_path) as target:
        execution._db.backup(target)
    deletion.append_intent(namespace="bot/persona", operation_id="erase-2",
                           closure_roots=("root-2",), epoch=2,
                           policy_ref="policy-1")
    execution.observe("effect-1", "sha256:command", "unknown", "query-1")
    authority = ExternalAuthorityStub(_anchor(deletion, execution))
    assert validate_restore(snapshot=_snapshot(), authority=authority,
                            deletion_journal=deletion,
                            execution_journal_port=ServiceExecutionJournalStub(execution.path),
                            active_generation=1) is authority.anchor
    old_deletion = DeletionJournal(old_deletion_path)
    with pytest.raises(RestoreQuarantined):
        validate_restore(snapshot=_snapshot(), authority=authority,
                         deletion_journal=old_deletion,
                         execution_journal_port=ServiceExecutionJournalStub(execution.path),
                         active_generation=1)
    with pytest.raises(RestoreQuarantined):
        validate_restore(snapshot=_snapshot(), authority=authority,
                         deletion_journal=deletion,
                         execution_journal_port=ServiceExecutionJournalStub(old_execution_path),
                         active_generation=1)
    assert first.seq == 1
    old_deletion.close()
    deletion.close()
    execution.close()


def test_restore_rejects_old_authority_generation_and_chain_tamper(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.sqlite", create=True)
    execution = _execution(tmp_path / "execution.sqlite")
    authority = ExternalAuthorityStub(_anchor(deletion, execution))
    with pytest.raises(RestoreQuarantined):
        validate_restore(snapshot=_snapshot(), authority=authority,
                         deletion_journal=deletion,
                         execution_journal_port=ServiceExecutionJournalStub(execution.path),
                         active_generation=2)
    authority.anchor = _anchor(deletion, execution, generation=2)
    with pytest.raises(RestoreQuarantined):
        validate_restore(snapshot=SnapshotRequirements("bot/persona", 1, 0, 0, 3),
                         authority=authority, deletion_journal=deletion,
                         execution_journal_port=ServiceExecutionJournalStub(execution.path),
                         active_generation=2)
    authority.anchor = _anchor(deletion, execution)
    damaged_path = tmp_path / "damaged-execution.sqlite"
    with sqlite3.connect(damaged_path) as target:
        execution._db.backup(target)
    with sqlite3.connect(damaged_path) as damaged:
        damaged.execute("DROP TRIGGER execution_entries_no_update")
        damaged.execute("UPDATE execution_entries SET phase='forged' WHERE execution_seq=1")
    with pytest.raises(RestoreQuarantined, match="chain invalid"):
        validate_restore(snapshot=_snapshot(), authority=authority,
                         deletion_journal=deletion,
                         execution_journal_path=damaged_path,
                         allow_local_execution_journal=True,
                         active_generation=1)
    deletion.close()
    execution.close()


def test_restore_requires_trusted_execution_port_even_when_anchor_matches(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.sqlite", create=True)
    execution = _execution(tmp_path / "execution.sqlite")
    authority = ExternalAuthorityStub(_anchor(deletion, execution))
    with pytest.raises(RestoreQuarantined, match="trusted execution journal port"):
        validate_restore(snapshot=_snapshot(), authority=authority,
                         deletion_journal=deletion,
                         execution_journal_path=execution.path,
                         active_generation=1)
    with pytest.raises(RestoreQuarantined, match="trusted execution journal port"):
        validate_restore(snapshot=_snapshot(), authority=authority,
                         deletion_journal=deletion, active_generation=1)
    port = ServiceExecutionJournalStub(execution.path)
    assert validate_restore(snapshot=_snapshot(), authority=authority,
                            deletion_journal=deletion, execution_journal_port=port,
                            active_generation=1) is authority.anchor
    assert port.calls == [("bot/persona", (
        authority.anchor.execution_journal_id, authority.anchor.execution_seq,
        authority.anchor.execution_digest))]
    deletion.close()
    execution.close()


def test_restore_rejects_client_report_when_service_chain_is_stale_or_missing(tmp_path):
    deletion = DeletionJournal(tmp_path / "deletion.sqlite", create=True)
    execution = _execution(tmp_path / "execution.sqlite")
    old_execution_path = tmp_path / "old-execution.sqlite"
    with sqlite3.connect(old_execution_path) as target:
        execution._db.backup(target)
    stale_client_anchor = ExternalAuthorityStub(_anchor(deletion, execution))
    execution.observe("effect-1", "sha256:command", "unknown", "query-1")
    for port in (ServiceExecutionJournalStub(execution.path),
                 ServiceExecutionJournalStub(tmp_path / "missing-execution.sqlite")):
        with pytest.raises(RestoreQuarantined):
            validate_restore(snapshot=_snapshot(), authority=stale_client_anchor,
                             deletion_journal=deletion, execution_journal_port=port,
                             active_generation=1)
        assert len(port.calls) == 1
    current_authority = ExternalAuthorityStub(_anchor(deletion, execution))
    with pytest.raises(RestoreQuarantined, match="execution journal does not match"):
        validate_restore(snapshot=_snapshot(), authority=current_authority,
                         deletion_journal=deletion,
                         execution_journal_port=ServiceExecutionJournalStub(old_execution_path),
                         active_generation=1)
    deletion.close()
    execution.close()


def test_transfer_fences_all_content_paths_and_cannot_timeout_resurrect(tmp_path):
    secret = object()
    current_anchor = None
    with pytest.raises(ActivationDenied):
        SqliteMigrationAuthority(tmp_path / "installer-authority.sqlite")
    authority = SqliteMigrationAuthority(
        tmp_path / "installer-authority.sqlite",
        installer_verifier=lambda credential, *_: credential is secret,
        transfer_verifier=lambda credential, _: credential is secret,
        anchor_verifier=lambda anchor: anchor is current_anchor,
        create=True,
    )
    with pytest.raises(ActivationDenied):
        authority.bootstrap("bot/persona", "source")
    source = authority.bootstrap("bot/persona", "source", installer_credential=secret)
    for op in ("startup", "read", "subscribe", "download", "model_egress",
               "adopt", "write", "dispatch"):
        assert authority.check(namespace="bot/persona", holder="source",
                               generation=source.generation, operation=op) == source
    plan = TransferPlan("bot/persona", "source", "target", "move-1")
    with pytest.raises(ActivationDenied):
        authority.begin_transfer(plan)
    planned = authority.begin_transfer(plan, credential=secret)
    with pytest.raises(ActivationDenied):
        authority.revoke_source(planned)
    revoked = authority.revoke_source(planned, credential=secret)
    assert revoked.generation == source.generation + 1
    assert authority.recover_transfer("move-1") == revoked
    for op in ("startup", "read", "subscribe", "download", "model_egress",
               "adopt", "write", "dispatch"):
        with pytest.raises(ActivationDenied):
            authority.check(namespace="bot/persona", holder="source",
                            generation=source.generation, operation=op)
    authority.close()
    authority = SqliteMigrationAuthority(
        tmp_path / "installer-authority.sqlite",
        anchor_verifier=lambda anchor: anchor is current_anchor,
        transfer_verifier=lambda credential, _: credential is secret,
    )
    with pytest.raises(ActivationDenied):
        authority.check(namespace="bot/persona", holder="source",
                        generation=source.generation, operation="read")
    with pytest.raises(ActivationDenied):
        authority.activate_target(revoked, _fake_anchor(generation=1), credential=secret)
    current_anchor = _fake_anchor(generation=revoked.generation)
    with pytest.raises(ActivationDenied):
        authority.activate_target(revoked, current_anchor)
    target = authority.activate_target(revoked, current_anchor, credential=secret)
    assert target.holder == "target"
    assert authority.check(namespace="bot/persona", holder="target",
                           generation=target.generation, operation="read") == target
    with pytest.raises(ActivationDenied):
        authority.check(namespace="bot/persona", holder="source",
                        generation=source.generation, operation="read")
    authority.close()


def _fake_anchor(*, generation):
    return RestoreAnchor("installer", "bot/persona", generation,
                         "deletion-journal", 1, "sha256:deletion", "execution-journal",
                         1, "sha256:execution", 0, "external-proof")
