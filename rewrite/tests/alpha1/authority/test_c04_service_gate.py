"""The service itself denies unpinned claims and caller-built terminals."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.internal_work_contract import (
    claim_internal_work_v1, terminal_internal_work_v1,
)
from sylanne3.authority_service.internal_work_service import AuthorityInternalWorkService
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from tests.alpha1.authority.test_internal_work_terminal_v2 import (
    BUILD_FINGERPRINT, FORMAL_ATTESTATION, _binding,
)


def test_diagnostic_service_never_forwards_claim(tmp_path):
    binding = _binding()
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True)
    calls = []
    try:
        service = AuthorityInternalWorkService(
            journal, current_prepared_reader=lambda _: calls.append("read"),
            claim_port=lambda *_: calls.append("claim"),
            core_head_verifier=lambda _: True,
            component_signing_key=b"k" * 32,
            installed_build_digest=BUILD_FINGERPRINT)
        with pytest.raises(AuthorityUnavailable, match="fixed C04 algorithm"):
            service.claim(binding, before_head=JournalHead("journal", 0, "genesis"))
        assert calls == []
    finally:
        journal.close()


def test_formal_service_rejects_other_algorithm_and_caller_terminal(tmp_path):
    binding = _binding()
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True)
    calls = []
    try:
        service = AuthorityInternalWorkService(
            journal, current_prepared_reader=lambda _: calls.append("read"),
            claim_port=lambda *_: calls.append("claim"),
            terminal_port=lambda *_: calls.append("terminal"),
            core_head_verifier=lambda _: True,
            component_signing_key=b"k" * 32,
            installed_build_digest=BUILD_FINGERPRINT,
            installed_build_attestation=FORMAL_ATTESTATION,
            trusted_manifest_sha256="f" * 64)
        with pytest.raises(AuthorityUnavailable, match="fixed C04 algorithm"):
            service.claim(replace(binding, algorithm_ref="caller.function"),
                          before_head=JournalHead("journal", 0, "genesis"))
        assert calls == []
        claim = claim_internal_work_v1(binding)
        forged = terminal_internal_work_v1(
            binding, claim, status="completed", actual_cpu_ms=5,
            result_digest="d" * 64, component_receipt_ref="caller-receipt",
            component_receipt_digest="e" * 64)
        with pytest.raises(AuthorityUnavailable, match="untrusted C04 terminal"):
            service.terminal(binding, claim, forged,
                             before_head=JournalHead("journal", 1, "sha256:" + "a" * 64))
        assert calls == []
    finally:
        journal.close()
