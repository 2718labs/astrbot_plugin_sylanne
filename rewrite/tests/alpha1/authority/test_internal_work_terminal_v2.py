"""Only the installed, same-chain V2 terminal can prove C04 completion."""

from dataclasses import replace
import hashlib

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.installed_c04_executor_v2 import (
    ALGORITHM_ID, InstalledC04ExecutorV2,
)
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalProofV1, InternalWorkTerminalV2,
    _phase_id, claim_internal_work_v1,
)
from sylanne3.authority_service.internal_work_service import AuthorityInternalWorkService
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, Owner
from tests.alpha1.runtime.test_authority_v2_execution_journal import anchor, pending


BUILD_FINGERPRINT = "e" * 64  # Installer manifest fixture; never a runtime file read.
FORMAL_ATTESTATION = {
    "schema": "sylanne.d06.algorithm-build.v1",
    "algorithm_id": ALGORITHM_ID,
    "manifest_sha256": "f" * 64,
    "package_mode": "formal-alpha1",
    "status": "formal_package_bytes_only",
    "build_digest": "sha256:" + BUILD_FINGERPRINT,
}


def _binding() -> InternalWorkBindingV1:
    namespace = "ns:sha256:" + hashlib.sha256(
        canonical_json(["bot", "persona"]).encode()).hexdigest()
    reservation = AtomKey(
        Owner("activity", "bot", "persona", "activity"),
        "d02.reservation.v1", "reservation").token
    return InternalWorkBindingV1(
        namespace, "activity", "operation", "execution", "a" * 64,
        "quote", 1, "b" * 64, "body-quote", 1, "c" * 64,
        reservation, "association-component", "budget", 1,
        ALGORITHM_ID, "policy-1", BUILD_FINGERPRINT)


def _completed(service, binding):
    claim = claim_internal_work_v1(binding)
    output = canonical_json({"input_digest": "sha256:" + binding.input_digest,
                             "result_digest": "sha256:" + "d" * 64})
    terminal = InternalWorkTerminalV2(
        binding.binding_digest, claim.mutation_id,
        _phase_id(binding.binding_digest, "terminal"), "completed", 7,
        ALGORITHM_ID, BUILD_FINGERPRINT, binding.input_digest,
        "d" * 64, output,
        "internal-work:component:" + binding.binding_digest,
        "0" * 64, "0" * 64, "0" * 64)
    digest, signature = service.sign_component_completion(binding, terminal)
    terminal = replace(terminal, component_receipt_digest=digest,
                       component_receipt_signature=signature)
    return replace(terminal,
                   execution_signature=service.sign_execution_terminal(terminal))


def test_v2_terminal_reopen_signed_component_and_forged_output(tmp_path):
    binding = _binding()
    path = tmp_path / "execution.sqlite"
    before = JournalHead("journal", 0, "genesis")
    key = b"k" * 32
    journal = AuthorityV2ExecutionJournal(
        path, namespace=binding.namespace, journal_id="journal", create=True)
    service = AuthorityInternalWorkService(
        journal, core_head_verifier=lambda _: True,
        component_signing_key=key, installed_build_digest=BUILD_FINGERPRINT,
        installed_build_attestation=FORMAL_ATTESTATION,
        trusted_manifest_sha256="f" * 64)
    claim = claim_internal_work_v1(binding)
    terminal = _completed(service, binding)
    assert service.verify_installed_terminal(binding, claim, terminal)
    assert not service.verify_installed_terminal(
        binding, claim, replace(terminal, actual_cpu_ms=0))
    assert not service.verify_installed_terminal(
        binding, claim, replace(terminal,
                                output_json=canonical_json({
                                    "input_digest": "sha256:" + binding.input_digest,
                                    "result_digest": "sha256:" + "d" * 64,
                                    "forged": True})))
    with journal.freeze_writes():
        claim_append = journal.append_internal_work_claim_v1(binding, claim, before)
    dispatch_before = replace(anchor(
        seq=1, chain=claim_append.chain_digest, namespace=binding.namespace),
        execution_journal_id="journal")
    journal.append_once(pending(before=dispatch_before,
                                mutation_id="interleaved-dispatch",
                                append_id="interleaved-append"))
    with journal.freeze_writes():
        terminal_append = journal.append_internal_work_terminal_v1(
            binding, claim, terminal, journal.verified_head())
    journal.close()
    reopened = AuthorityV2ExecutionJournal(
        path, namespace=binding.namespace, journal_id="journal", create=False)
    try:
        service = AuthorityInternalWorkService(
            reopened, core_head_verifier=lambda head: head == reopened.verified_head(),
            component_signing_key=key, installed_build_digest=BUILD_FINGERPRINT,
            installed_build_attestation=FORMAL_ATTESTATION,
            trusted_manifest_sha256="f" * 64)
        proof = InternalWorkTerminalProofV1(
            binding, claim, terminal,
            claim_append.receipt_ref, claim_append.content_digest,
            terminal_append.receipt_ref, terminal_append.content_digest,
            reopened.verified_head())
        verified = service.verify_original_internal_work_terminal(proof)
        assert verified.status == "completed"
        assert verified.actual_cpu_ms == 7
        assert verified.component_completed
        # A later same-chain append must not invalidate an original terminal.
        following = replace(binding, execution_id="later-execution",
                            operation_id="later-operation")
        with reopened.freeze_writes():
            reopened.append_internal_work_claim_v1(
                following, claim_internal_work_v1(following),
                reopened.verified_head())
        assert service.verify_original_internal_work_terminal(
            proof).component_completed
        no_key = AuthorityInternalWorkService(
            reopened, core_head_verifier=lambda head: head == reopened.verified_head())
        assert not no_key.verify_original_internal_work_terminal(
            proof).component_completed
    finally:
        reopened.close()


def test_failed_work_keeps_signed_cpu_without_component(tmp_path):
    binding = _binding()
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True)
    try:
        service = AuthorityInternalWorkService(
            journal, component_signing_key=b"k" * 32,
            installed_build_digest=BUILD_FINGERPRINT,
            installed_build_attestation=FORMAL_ATTESTATION,
            trusted_manifest_sha256="f" * 64)
        claim = claim_internal_work_v1(binding)
        terminal = InternalWorkTerminalV2(
            binding.binding_digest, claim.mutation_id,
            _phase_id(binding.binding_digest, "terminal"), "failed", 9,
            ALGORITHM_ID, BUILD_FINGERPRINT, binding.input_digest,
            None, None, None, None, None, "0" * 64)
        terminal = replace(terminal,
                           execution_signature=service.sign_execution_terminal(terminal))
        assert service.verify_installed_terminal(binding, claim, terminal)
        assert not terminal.component_completed
        assert not service.verify_installed_terminal(
            binding, claim, replace(terminal, actual_cpu_ms=1))
    finally:
        journal.close()


def test_diagnostic_digest_cannot_install_executor(tmp_path):
    binding = _binding()
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True)
    try:
        service = AuthorityInternalWorkService(
            journal, component_signing_key=b"k" * 32,
            installed_build_digest=BUILD_FINGERPRINT)
        with pytest.raises(AuthorityUnavailable, match="formal installed"):
            InstalledC04ExecutorV2(service, frozen_input_reader=lambda _: None)
    finally:
        journal.close()
