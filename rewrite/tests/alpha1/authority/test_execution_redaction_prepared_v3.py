"""PREPARED seal mechanics on real Core/journal files; accepted fixture is internal.

The ledger-fixture barrier is not a W01 product proof. This test establishes
only the migration blocker and its crash/replay behavior.
"""

from dataclasses import replace
import sqlite3

import pytest

from rewrite.tests.alpha1.authority.test_internal_work_terminal_v2 import (
    BUILD_FINGERPRINT, FORMAL_ATTESTATION, _binding, _completed,
)
from rewrite.tests.alpha1.authority.test_current_erasure_service import (
    _close_ledger, _open_ledger, _phase,
)
from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.erasure_closure_inventory import (
    AuthorityErasureClosureInventory, SURFACES_V1, SurfaceTargetV1,
)
from sylanne3.authority_service.erasure_closure_redaction_v3 import (
    ExecutionRedactionPreparedV3, execution_row_commitment_v3,
    read_execution_redaction_seal_locked,
)
from sylanne3.authority_service.erasure_closure_sidecar_v3 import (
    AuthorityExecutionRedactionSidecarV3, _certificate, _sanitize,
    _write_or_verify_sidecar,
    read_execution_sidecar_recovery_v3, sidecar_path_v3,
)
from sylanne3.authority_service.execution_physical_cleanup_v3 import (
    inspect_execution_physical_cleanup_v3,
)
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkTerminalV2, _phase_id, claim_internal_work_v1,
)
from sylanne3.authority_service.internal_work_service import (
    AuthorityInternalWorkService,
)
from sylanne3.authority_service.v2_contract import (
    DeletionEvidenceV1, DeletionPendingV1, FencePermitV2,
    PendingMutationV2, canonical_bytes, deletion_scope_digest,
)
from sylanne3.authority_service.v2_deletion_recovery_service import (
    AuthorityV2DeletionPendingRecovery,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_deletion_migration import AuthorityV2DeletionMigration
from sylanne3.authority_service.v2_deletion_tail_migration import AuthorityV2DeletionTailMigration
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_scoped_erasure_store import (
    AuthorityV2ScopedErasureStore,
)
from sylanne3.authority_service.v2_execution_journal import (
    AuthorityV2ExecutionJournal,
)
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.c04_v3_contracts import AssociationWorkResultV3
from sylanne3.contracts import canonical_json
from dataclasses import asdict


def _nonempty_execution(parts):
    """Controlled journal/Core setup, not a production effect admission."""
    core, _, _, _, execution = parts
    with core._tx() as db:
        before = core._anchor(db, "ns-a", core._row(db, "ns-a"))
    permit = FencePermitV2(
        before.authority_id, "ns-a", "subject-a", "holder-a",
        before.activation_generation, "dispatch", "operation-effect",
        "A" * 43, 1, 0, before, effect_id="effect-a",
        command_digest="sha256:" + "a" * 64,
        footprint_digest="sha256:" + "b" * 64)
    draft = PendingMutationV2(
        permit=permit, mutation_id="mutation-effect",
        request_digest="sha256:" + "c" * 64, phase="prepared",
        before_anchor=before, expected_append_id="append-effect",
        expected_append_digest="sha256:" + "0" * 64)
    pending = replace(
        draft, expected_append_digest=execution.expected_digest(draft))
    appended = execution.append_once(pending)
    with core._tx() as db:
        db.execute(
            "UPDATE authority_namespaces SET execution_seq=?,execution_digest=? "
            "WHERE namespace='ns-a'", (appended.seq, appended.chain_digest))
    return pending


def test_nonempty_prepared_seal_blocks_old_journal_after_cold_open(tmp_path):
    parts = _open_ledger(tmp_path, create=True)
    try:
        core, fences, _, deletion, execution = parts
        original = _nonempty_execution(parts)
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        assert scoped.migrate_zero_history(credential="ok").aggregate_phase == "clear"
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a")
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="delete", operation_id="fence-a",
            expected_anchor=anchor)
        pending = _phase(parts, permit, "absent", "pending", ordinal=1)
        with core._tx() as db:
            scoped.reserve_locked(db, pending)
            fences.record_deletion_pending_locked(
                db, pending, subject="subject-a", current_anchor=anchor)
        deletion.append_pending(pending, core=core, fences=fences)
        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=deletion, execution=execution,
            namespace="ns-a", scoped_store=scoped)
        pending_receipt = recovery.recover(
            credential="ok", subject="subject-a",
            mutation_id=pending.mutation_id)
        assert pending_receipt is not None
        _, _, _, updated_permit = fences.get_mutation(
            pending.mutation_id, subject="subject-a", namespace="ns-a")
        accepted_draft = _phase(
            parts, updated_permit, "pending", "accepted", ordinal=2)
        accepted_draft = replace(
            accepted_draft,
            evidence=replace(
                accepted_draft.evidence,
                issuer_id="authority-pinned-graph-barrier-v1"),
            expected_append_digest="sha256:" + "0" * 64)
        accepted = replace(
            accepted_draft,
            expected_append_digest=deletion.expected_digest(accepted_draft))
        with core._tx() as db:
            fences.record_deletion_pending_locked(
                db, accepted, subject="subject-a",
                current_anchor=pending_receipt.after_anchor)
        deletion.append_transition(accepted, core=core, fences=fences)
        accepted_receipt = recovery.recover(
            credential="ok", subject="subject-a",
            mutation_id=accepted.mutation_id)
        assert accepted_receipt is not None
        closure = AuthorityErasureClosureInventory(
            scoped=scoped, installation_id="installation")
        targets = tuple(SurfaceTargetV1(
            surface, "sqlite_execution_journal" if surface ==
            "execution_journal_payloads" else "unresolved_inventory",
            str(execution.path.resolve()) if surface ==
            "execution_journal_payloads" else "unresolved",
            "inventory-v1" if surface == "execution_journal_payloads"
            else "unavailable",
            execution.journal_id if surface == "execution_journal_payloads"
            else "unbound",
            "installed" if surface == "execution_journal_payloads"
            else "unresolved_hold") for surface in SURFACES_V1)
        closure.install_registry(credential="ok", targets=targets)
        run = closure.begin_run(
            credential="ok", subject="subject-a",
            accepted_mutation_id=accepted.mutation_id)
        assert run.execution_seq == 1
        inventory = closure.issue_execution_payload_inventory(
            credential="ok", subject="subject-a", operation_id="deletion-a")
        assert inventory.entry_count == 1
        with core._tx() as db:
            db.execute(
                "UPDATE authority_namespaces SET execution_digest=? "
                "WHERE namespace='ns-a'", ("sha256:" + "f" * 64,))
        with pytest.raises(AuthorityUnavailable):
            core.begin_execution_redaction_v3(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        with core._tx() as db:
            db.execute(
                "UPDATE authority_namespaces SET execution_digest=? "
                "WHERE namespace='ns-a'", (original.expected_append_digest,))
        with pytest.raises(AuthorityUnavailable, match="authentication denied"):
            core.begin_execution_redaction_v3(
                credential="bad", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        seal = core.begin_execution_redaction_v3(
            credential="ok", closure=closure, subject="subject-a",
            operation_id="deletion-a")
        assert seal.stage == "prepared"
        assert seal.rows[0].entry_kind == "mutation_prepared"
        assert seal.rows[0].body_bytes > 0
        assert core.begin_execution_redaction_v3(
            credential="ok", closure=closure, subject="subject-a",
            operation_id="deletion-a") == seal
        with pytest.raises(AuthorityUnavailable, match="conflicts"):
            core.begin_execution_redaction_v3(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="other-operation")
        with pytest.raises(AuthorityUnavailable, match="PREPARED"):
            execution.verified_head()
        with pytest.raises(AuthorityUnavailable, match="PREPARED"):
            execution.append_once(original)
        with pytest.raises(AuthorityUnavailable, match="PREPARED"):
            service.current_anchor(credential="ok", subject="subject-a")
        with pytest.raises(AuthorityUnavailable, match="PREPARED"):
            with execution.freeze_writes():
                execution.append_once_guarded(original)
        with pytest.raises(AuthorityUnavailable, match="PREPARED"):
            type(execution)(
                execution.path, namespace="ns-a",
                journal_id=execution.journal_id)
        with sqlite3.connect(execution.path) as db:
            body = db.execute(
                "SELECT pending FROM authority_v2_execution_entries WHERE seq=1"
            ).fetchone()[0]
            assert body == canonical_bytes(original)
            assert len(body) == seal.rows[0].body_bytes
        with sqlite3.connect(core.path) as db:
            saved = db.execute(
                "SELECT seal_json FROM authority_execution_redaction_seals_v3 "
                "WHERE namespace='ns-a'").fetchone()[0]
            assert '"pending":' not in saved
            assert '"output_json":' not in saved
        sidecar = AuthorityExecutionRedactionSidecarV3(closure)
        assert sidecar.read_recovery_state(
            credential="ok", operation_id="deletion-a"
        ).stage == "prepared_only_hold"
        maintenance = AuthorityV2ExecutionJournal.open_prepared_redaction_v3(
            execution.path, namespace="ns-a",
            journal_id=execution.journal_id, core=core, credential="ok")
        try:
            with maintenance.freeze_prepared_redaction_v3() as raw:
                candidate_rows = _sanitize(maintenance, seal, raw)
            candidate_cert = _certificate(seal, candidate_rows)
            _write_or_verify_sidecar(
                sidecar_path_v3(execution.path, seal),
                seal, candidate_rows, candidate_cert)
        finally:
            maintenance.close()
        assert sidecar.read_recovery_state(
            credential="ok", operation_id="deletion-a"
        ).stage == "sidecar_unpinned_hold"
        pinned = sidecar.build_and_pin(
            credential="ok", subject="subject-a", operation_id="deletion-a")
        assert pinned.stage == "sidecar_pinned_hold"
        assert pinned.certificate.row_count == 1
        with pytest.raises(AuthorityUnavailable, match="PREPARED"):
            execution.append_once(original)
        assert sidecar.build_and_pin(
            credential="ok", subject="subject-a",
            operation_id="deletion-a") == pinned
        assert sidecar.read_recovery_state(
            credential="ok", operation_id="deletion-a") == pinned
        sidecar_path = sidecar_path_v3(execution.path, seal)
        with sqlite3.connect(sidecar_path) as db:
            sanitized = db.execute(
                "SELECT row_json FROM authority_execution_sanitized_rows_v3"
            ).fetchone()[0]
            assert '"pending":' not in sanitized
            assert '"output_json":' not in sanitized
            assert original.mutation_id in sanitized
            assert db.execute(
                "SELECT count(*) FROM authority_execution_sidecar_certificate_v3"
            ).fetchone() == (1,)
        cold_core = AuthorityServiceCore(
            core.path, create=False,
            authorizer=lambda credential, *_: credential == "ok",
            deletion_verifier=core._deletion_verifier,
            execution_verifier=core._execution_verifier,
            effect_verifier=core._effect_verifier,
            dispatch_verifier=core._dispatch_verifier)
        try:
            with cold_core._tx() as db:
                assert read_execution_redaction_seal_locked(db, "ns-a") == seal
            assert read_execution_sidecar_recovery_v3(
                core=cold_core, credential="ok", namespace="ns-a",
                operation_id="deletion-a",
                old_journal_path=execution.path) == pinned
        finally:
            cold_core.close()
        with sqlite3.connect(sidecar_path) as db:
            trigger = db.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE name='authority_execution_sanitized_rows_v3_update_immutable'"
            ).fetchone()[0]
            db.execute(
                "DROP TRIGGER authority_execution_sanitized_rows_v3_update_immutable")
            db.execute(
                "UPDATE authority_execution_sanitized_rows_v3 "
                "SET row_json='{}' WHERE seq=1")
            db.execute(trigger)
            db.commit()
        with pytest.raises(AuthorityUnavailable, match="sanitized execution sidecar"):
            sidecar.read_recovery_state(
                credential="ok", operation_id="deletion-a")
    finally:
        _close_ledger(parts)


def test_v2_terminal_projection_keeps_measured_cost_and_open_claim(tmp_path):
    """Projection only: it never issues a Core seal or a cleanup receipt."""
    binding = _binding()
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "internal.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True)
    try:
        service = AuthorityInternalWorkService(
            journal, component_signing_key=b"k" * 32,
            installed_build_digest=BUILD_FINGERPRINT,
            installed_build_attestation=FORMAL_ATTESTATION,
            trusted_manifest_sha256="f" * 64)
        claim = claim_internal_work_v1(binding)
        terminal = _completed(service, binding)
        with journal.freeze_writes():
            journal.append_internal_work_claim_v1(
                binding, claim, JournalHead("journal", 0, "genesis"))
        with journal.freeze_writes():
            journal.append_internal_work_terminal_v1(
                binding, claim, terminal, journal.verified_head())
        later = replace(
            binding, operation_id="later-operation",
            execution_id="later-execution")
        later_claim = claim_internal_work_v1(later)
        with journal.freeze_writes():
            journal.append_internal_work_claim_v1(
                later, later_claim, journal.verified_head())
            head, raw = journal._scan_locked()
            commitments = tuple(
                execution_row_commitment_v3(journal, row) for row in raw)
            shape = (
                "authority", binding.namespace, "installation", "erase-operation",
                "a" * 64, "b" * 64, "c" * 64, "d" * 64,
                head.journal_id, head.seq, head.digest, commitments)
            seal = ExecutionRedactionPreparedV3(
                *shape, canonical_digest((
                    "sylanne3.authority.execution_redaction_seal.v3",
                    *shape, "prepared")))
            rows = _sanitize(journal, seal, tuple(raw))
        assert rows[1].entry_kind == "internal_terminal"
        assert rows[1].terminal_status == "completed"
        assert rows[1].actual_cpu_ms == 7
        assert rows[1].result_digest == "d" * 64
        assert rows[2].unknown_constraint == "internal_claim_open"
        assert _certificate(
            seal, rows).unresolved_mutation_ids == (later_claim.mutation_id,)
        assert terminal.output_json not in canonical_serialize(
            tuple(asdict(row) for row in rows))
    finally:
        journal.close()


def test_signed_c04_terminal_and_open_claim_switch_is_cold_recoverable(tmp_path):
    """Mixed signed V2/V3 rows and open claim; accepted barrier is controlled."""
    binding = _binding()
    namespace = binding.namespace
    deletion_journal = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=namespace,
        journal_id="execution-a", create=True)
    signer = AuthorityInternalWorkService(
        execution, component_signing_key=b"k" * 32,
        installed_build_digest=BUILD_FINGERPRINT,
        installed_build_attestation=FORMAL_ATTESTATION,
        trusted_manifest_sha256="f" * 64)
    v3_binding = replace(
        binding, operation_id="v3-operation", execution_id="v3-execution",
        algorithm_ref="d06.association_activation.v3")
    v3_attestation = {
        **FORMAL_ATTESTATION,
        "algorithm_id": v3_binding.algorithm_ref,
    }
    v3_signer = AuthorityInternalWorkService(
        execution, component_signing_key=b"v" * 32,
        installed_build_digest=BUILD_FINGERPRINT,
        installed_build_attestation=v3_attestation,
        trusted_manifest_sha256="f" * 64)
    v3_claim = claim_internal_work_v1(v3_binding)
    v3_result = AssociationWorkResultV3(
        NamespaceId("bot", "persona"), v3_binding.operation_id,
        "sha256:" + v3_binding.input_digest, v3_binding.algorithm_ref,
        "sha256:" + BUILD_FINGERPRINT, (), 0, 0, 0, False, "complete")
    v3_output = canonical_json({
        "schema": "sylanne.d06.association-work-terminal-output.v3",
        "algorithm_id": v3_binding.algorithm_ref,
        "algorithm_build_digest": "sha256:" + BUILD_FINGERPRINT,
        "input_digest": "sha256:" + v3_binding.input_digest,
        "result_digest": v3_result.result_digest,
        "result_json": v3_result.to_json(),
    })
    v3_terminal = InternalWorkTerminalV2(
        v3_binding.binding_digest, v3_claim.mutation_id,
        _phase_id(v3_binding.binding_digest, "terminal"), "completed", 9,
        v3_binding.algorithm_ref, BUILD_FINGERPRINT, v3_binding.input_digest,
        v3_result.result_digest.removeprefix("sha256:"), v3_output,
        "internal-work:component:" + v3_binding.binding_digest,
        "0" * 64, "0" * 64, "0" * 64)
    v3_digest, v3_signature = v3_signer.sign_component_completion(
        v3_binding, v3_terminal)
    v3_terminal = replace(
        v3_terminal, component_receipt_digest=v3_digest,
        component_receipt_signature=v3_signature)
    v3_terminal = replace(
        v3_terminal,
        execution_signature=v3_signer.sign_execution_terminal(v3_terminal))
    assert v3_signer.verify_installed_terminal(v3_binding, v3_claim, v3_terminal)
    first = deletion_journal.latest_head()
    deletion_head = JournalHead(first.journal_id, first.seq,
                                first.chain_digest)
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda credential, *_: credential == "ok",
        deletion_verifier=lambda ns, before, current, phase: (
            current == deletion_head and phase == "clear"),
        execution_verifier=lambda ns, before, current, phase: (
            execution.verified_head() == current),
        effect_verifier=lambda *_: False,
        dispatch_verifier=lambda *_: False,
        execution_redaction_c04_service=signer)
    try:
        core.register_namespace("ok", namespace, "holder-a", deletion_head,
                                JournalHead(execution.journal_id, 0, "genesis"))
        core.seal_v2_only("ok")
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        AuthorityV2DeletionMigration(
            core=core, fences=fences, deletion=deletion,
            execution=execution, namespace=namespace).run(credential="ok")
        AuthorityV2DeletionTailMigration(
            core=core, fences=fences, deletion=deletion,
            execution=execution, namespace=namespace).run(credential="ok")
        claim = claim_internal_work_v1(binding)
        terminal = _completed(signer, binding)
        later = replace(binding, operation_id="later-operation",
                        execution_id="later-execution")
        later_claim = claim_internal_work_v1(later)
        unknown_terminal = InternalWorkTerminalV2(
            later.binding_digest, later_claim.mutation_id,
            _phase_id(later.binding_digest, "terminal"), "unknown", None,
            later.algorithm_ref, BUILD_FINGERPRINT, later.input_digest,
            None, None, None, None, None, None)
        open_binding = replace(
            binding, operation_id="open-operation", execution_id="open-execution")
        open_claim = claim_internal_work_v1(open_binding)
        with execution.freeze_writes():
            execution.append_internal_work_claim_v1(
                binding, claim, JournalHead(execution.journal_id, 0, "genesis"))
            execution.append_internal_work_terminal_v1(
                binding, claim, terminal, execution.verified_head())
            execution.append_internal_work_claim_v1(
                v3_binding, v3_claim, execution.verified_head())
            execution.append_internal_work_terminal_v1(
                v3_binding, v3_claim, v3_terminal, execution.verified_head())
            execution.append_internal_work_claim_v1(
                later, later_claim, execution.verified_head())
            execution.append_internal_work_terminal_v1(
                later, later_claim, unknown_terminal, execution.verified_head())
            execution.append_internal_work_claim_v1(
                open_binding, open_claim, execution.verified_head())
        original_head = execution.verified_head()
        with core._tx() as db:
            db.execute(
                "UPDATE authority_namespaces SET execution_seq=?,execution_digest=? "
                "WHERE namespace=?",
                (original_head.seq, original_head.digest, namespace))
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=fences, deletion=deletion,
            execution=execution, namespace=namespace)
        scoped.migrate_zero_history(credential="ok")
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion,
            execution=execution, namespace=namespace)
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="delete", operation_id="fence-a",
            expected_anchor=anchor)

        def phase(permit, source, target, ordinal):
            evidence = DeletionEvidenceV1(
                authority_id=permit.authority_id, namespace=namespace,
                deletion_operation_id="deletion-a",
                kind="request_authorized" if target == "pending"
                else "barrier_installed",
                issuer_id="ledger-fixture" if target == "pending"
                else "authority-pinned-graph-barrier-v1",
                evidence_id=f"evidence-{ordinal}",
                bound_anchor=permit.pinned_anchor,
                request_digest="sha256:" + "a" * 64,
                scope_digest=deletion_scope_digest(("root-a",), 1, "policy-a"),
                proof_digest="sha256:" + "d" * 64,
                **({} if target == "pending" else dict(
                    graph_version="graph-a", incarnation="graph-incarnation-a",
                    access_epoch=1, deletion_epoch=1,
                    barrier_scope_digest="sha256:" + "b" * 64)))
            draft = DeletionPendingV1(
                permit=permit, mutation_id=f"mutation-{ordinal}",
                request_digest="sha256:" + "a" * 64,
                deletion_operation_id="deletion-a", source_phase=source,
                target_phase=target, closure_roots=("root-a",),
                deletion_epoch=1, policy_ref="policy-a",
                before_anchor=permit.pinned_anchor, evidence=evidence,
                expected_append_id=f"append-{ordinal}",
                expected_append_digest="sha256:" + "0" * 64)
            return replace(draft,
                           expected_append_digest=deletion.expected_digest(draft))

        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=deletion,
            execution=execution, namespace=namespace,
            scoped_store=scoped)
        pending = phase(permit, "absent", "pending", 1)
        with core._tx() as db:
            scoped.reserve_locked(db, pending)
            fences.record_deletion_pending_locked(
                db, pending, subject="subject-a", current_anchor=anchor)
        deletion.append_pending(pending, core=core, fences=fences)
        receipt = recovery.recover(
            credential="ok", subject="subject-a",
            mutation_id=pending.mutation_id)
        assert receipt is not None
        _, _, _, permit = fences.get_mutation(
            pending.mutation_id, subject="subject-a", namespace=namespace)
        accepted = phase(permit, "pending", "accepted", 2)
        with core._tx() as db:
            fences.record_deletion_pending_locked(
                db, accepted, subject="subject-a",
                current_anchor=receipt.after_anchor)
        deletion.append_transition(accepted, core=core, fences=fences)
        assert recovery.recover(
            credential="ok", subject="subject-a",
            mutation_id=accepted.mutation_id) is not None
        closure = AuthorityErasureClosureInventory(
            scoped=scoped, installation_id="installation")
        targets = tuple(SurfaceTargetV1(
            surface,
            "sqlite_execution_journal" if surface == "execution_journal_payloads"
            else "unresolved_inventory",
            str(execution.path.resolve()) if surface ==
            "execution_journal_payloads" else "unresolved",
            "inventory-v1" if surface == "execution_journal_payloads"
            else "unavailable",
            execution.journal_id if surface == "execution_journal_payloads"
            else "unbound",
            "installed" if surface == "execution_journal_payloads"
            else "unresolved_hold") for surface in SURFACES_V1)
        closure.install_registry(credential="ok", targets=targets)
        closure.begin_run(
            credential="ok", subject="subject-a",
            accepted_mutation_id=accepted.mutation_id)
        closure.issue_execution_payload_inventory(
            credential="ok", subject="subject-a", operation_id="deletion-a")
        with pytest.raises(AuthorityUnavailable,
                           match="installed C04 terminal verifier"):
            core.begin_execution_redaction_v3(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        core.install_execution_redaction_c04_services(
            namespace, {v3_binding.algorithm_ref: v3_signer})
        seal = core.begin_execution_redaction_v3(
            credential="ok", closure=closure, subject="subject-a",
            operation_id="deletion-a")
        sidecar = AuthorityExecutionRedactionSidecarV3(closure)
        pinned = sidecar.build_and_pin(
            credential="ok", subject="subject-a", operation_id="deletion-a")
        assert pinned.certificate.row_count == 7
        with pytest.raises(AuthorityUnavailable,
                           match="trusted V4 recovery originals unavailable"):
            core.pin_execution_recovery_facts_v4(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")

        class IncompleteV4Originals:
            def read_current_anchor_v4(self, *, namespace, operation_id):
                from sylanne3.runtime.c09_sanitized_recovery_extractor_v4 import (
                    C09RecoveryAnchorOriginalV4,
                )

                return C09RecoveryAnchorOriginalV4(
                    core._id(core._db), "installation", namespace, operation_id,
                    seal.execution_digest, "0" * 64)

            def read_current_execution_originals_v4(self, **_):
                return None

            def read_current_d02_originals_v4(self, **_):
                return None

            def read_current_d11_originals_v4(self, **_):
                return None

            def read_current_unknown_originals_v4(self, **_):
                return None

            def read_current_graph_originals_v4(self, **_):
                return None

        core.install_execution_recovery_facts_port_v4(
            namespace, IncompleteV4Originals())
        with pytest.raises(AuthorityUnavailable,
                           match="V4 recovery originals unavailable: execution, d02, d11, unknown, graph"):
            core.pin_execution_recovery_facts_v4(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        with core._tx() as db:
            assert db.execute(
                "SELECT count(*) FROM authority_execution_recovery_facts_pins_v4"
            ).fetchone() == (0,)
        with pytest.raises(AuthorityUnavailable, match="V4 PREPARED facts pin required"):
            core.verify_execution_recovery_facts_v4_for_rebase(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        with pytest.raises(AuthorityUnavailable, match="V3 identity switch required"):
            inspect_execution_physical_cleanup_v3(
                closure, credential="ok", subject="subject-a",
                operation_id="deletion-a")
        cold_before = read_execution_sidecar_recovery_v3(
            core=core, credential="ok", namespace=namespace,
            operation_id="deletion-a", old_journal_path=execution.path)
        assert cold_before.stage == "sidecar_pinned_hold"
        core._execution_redaction_c04_service = None
        with pytest.raises(AuthorityUnavailable,
                           match="installed C04 terminal verifier"):
            core.switch_execution_redaction_v3(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        core._execution_redaction_c04_service = AuthorityInternalWorkService(
            execution, component_signing_key=b"x" * 32,
            installed_build_digest=BUILD_FINGERPRINT,
            installed_build_attestation=FORMAL_ATTESTATION,
            trusted_manifest_sha256="f" * 64)
        with pytest.raises(AuthorityUnavailable,
                           match="C04 terminal signature differs"):
            core.switch_execution_redaction_v3(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        core._execution_redaction_c04_service = signer
        wrong_v3 = AuthorityInternalWorkService(
            execution, component_signing_key=b"w" * 32,
            installed_build_digest=BUILD_FINGERPRINT,
            installed_build_attestation=v3_attestation,
            trusted_manifest_sha256="f" * 64)
        core._execution_redaction_c04_services[namespace][
            v3_binding.algorithm_ref] = wrong_v3
        with pytest.raises(AuthorityUnavailable, match="C04 terminal signature differs"):
            core.switch_execution_redaction_v3(
                credential="ok", closure=closure, subject="subject-a",
                operation_id="deletion-a")
        core._execution_redaction_c04_services[namespace][
            v3_binding.algorithm_ref] = v3_signer
        assert read_execution_sidecar_recovery_v3(
            core=core, credential="ok", namespace=namespace,
            operation_id="deletion-a", old_journal_path=execution.path
        ).stage == "sidecar_pinned_hold"
        switch = core.switch_execution_redaction_v3(
            credential="ok", closure=closure, subject="subject-a",
            operation_id="deletion-a")
        assert switch.old_digest == original_head.digest
        assert switch.signed_terminal_digests == (
            seal.rows[1].request_digest, seal.rows[3].request_digest)
        assert core.switch_execution_redaction_v3(
            credential="ok", closure=closure, subject="subject-a",
            operation_id="deletion-a") == switch
        cold_core = AuthorityServiceCore(
            core.path, create=False,
            authorizer=lambda credential, *_: credential == "ok",
            deletion_verifier=core._deletion_verifier,
            execution_verifier=core._execution_verifier,
            effect_verifier=core._effect_verifier,
            dispatch_verifier=core._dispatch_verifier)
        try:
            state = read_execution_sidecar_recovery_v3(
                core=cold_core, credential="ok", namespace=namespace,
                operation_id="deletion-a", old_journal_path=execution.path)
            assert state.stage == "identity_switched_hold"
            assert state.switch == switch
            assert state.certificate.unresolved_mutation_ids == tuple(sorted((
                unknown_terminal.mutation_id, open_claim.mutation_id)))
        finally:
            cold_core.close()
        with pytest.raises(AuthorityUnavailable, match="PREPARED"):
            execution.verified_head()
        gate = inspect_execution_physical_cleanup_v3(
            closure, credential="ok", subject="subject-a",
            operation_id="deletion-a")
        assert gate.status == "hold"
        assert gate.old_row_count == 7
        assert gate.switch_digest == switch.switch_digest
        assert "controlled_backup_inventory_unresolved" in gate.blockers
        with sqlite3.connect(execution.path) as db:
            assert db.execute(
                "SELECT count(*) FROM authority_v2_execution_entries"
            ).fetchone() == (7,)
            db.execute("DROP TRIGGER authority_v2_execution_no_update")
            db.execute(
                "UPDATE authority_v2_execution_entries SET pending=? WHERE seq=1",
                (b"tampered",))
            db.commit()
        with pytest.raises(AuthorityUnavailable,
                           match="old execution body differs"):
            inspect_execution_physical_cleanup_v3(
                closure, credential="ok", subject="subject-a",
                operation_id="deletion-a")
    finally:
        core.close()
        deletion_journal.close()
        deletion.close()
        execution.close()
