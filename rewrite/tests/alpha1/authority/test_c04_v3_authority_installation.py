"""V3 Authority terminal validation; no formal package pin is simulated."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority.test_authority_daemon_cold_open import (
    JOURNAL_ID, NAMESPACE, _installed_config,
)
from rewrite.tests.alpha1.authority.test_internal_work_terminal_v2 import (
    BUILD_FINGERPRINT, _binding,
)
from rewrite.tests.alpha1.authority.test_installed_c04_executor_v3 import (
    _binding as v3_binding,
)
from rewrite.tests.alpha1.contracts.test_c04_v3_contracts import work
from sylanne3.authority_service.installed_c04_executor_v3 import (
    InstalledC04ExecutorV3,
)
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkTerminalV2, _phase_id, claim_internal_work_v1,
)
from sylanne3.authority_service.internal_work_service import (
    AuthorityInternalWorkService, InternalWorkJournalInspectionV1,
)
from sylanne3.authority_service.internal_work_rpc_wire import (
    from_wire as c04_from_wire, to_wire as c04_to_wire,
)
from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.mtls_server import MtlsPeerCredential
from sylanne3.authority_service.v2_execution_journal import (
    AuthorityV2ExecutionJournal,
)
from sylanne3.contracts import canonical_json
from sylanne3.runtime.c04_v3_contracts import AssociationWorkResultV3
from sylanne3.runtime.c04_internal_work_original_v1 import C04InternalWorkPreparedV1
from sylanne3.runtime_contracts import NamespaceId


def test_v3_signed_terminal_requires_exact_result_envelope_and_version(tmp_path):
    binding = replace(_binding(), algorithm_ref="d06.association_activation.v3")
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True)
    attestation = {
        "schema": "sylanne.d06.algorithm-build.v1",
        "algorithm_id": binding.algorithm_ref,
        "manifest_sha256": "f" * 64,
        "package_mode": "formal-alpha1",
        "status": "formal_package_bytes_only",
        "build_digest": "sha256:" + BUILD_FINGERPRINT,
    }
    try:
        service = AuthorityInternalWorkService(
            journal, component_signing_key=b"k" * 32,
            installed_build_digest=BUILD_FINGERPRINT,
            installed_build_attestation=attestation,
            trusted_manifest_sha256="f" * 64)
        claim = claim_internal_work_v1(binding)
        result = AssociationWorkResultV3(
            NamespaceId("bot", "persona"), binding.operation_id,
            "sha256:" + binding.input_digest, binding.algorithm_ref,
            "sha256:" + BUILD_FINGERPRINT, (), 0, 0, 0, False, "complete")

        def signed(output):
            terminal = InternalWorkTerminalV2(
                binding.binding_digest, claim.mutation_id,
                _phase_id(binding.binding_digest, "terminal"),
                "completed", 7, binding.algorithm_ref, BUILD_FINGERPRINT,
                binding.input_digest, result.result_digest.removeprefix("sha256:"),
                output, "internal-work:component:" + binding.binding_digest,
                "0" * 64, "0" * 64, "0" * 64)
            digest, signature = service.sign_component_completion(binding, terminal)
            terminal = replace(
                terminal, component_receipt_digest=digest,
                component_receipt_signature=signature)
            return replace(
                terminal, execution_signature=service.sign_execution_terminal(terminal))

        envelope = {
            "schema": "sylanne.d06.association-work-terminal-output.v3",
            "algorithm_id": binding.algorithm_ref,
            "algorithm_build_digest": "sha256:" + BUILD_FINGERPRINT,
            "input_digest": "sha256:" + binding.input_digest,
            "result_digest": result.result_digest,
            "result_json": result.to_json(),
        }
        good = signed(canonical_json(envelope))
        assert service.verify_installed_terminal(binding, claim, good)
        assert not service.verify_installed_terminal(
            binding, claim, signed(canonical_json({
                **envelope, "forged": True})))
        other_result = replace(result, operation_id="other-operation")
        assert not service.verify_installed_terminal(
            binding, claim, signed(canonical_json({
                **envelope, "result_json": other_result.to_json()})))
        assert not service.verify_installed_terminal(
            replace(binding, algorithm_ref="d06.association_activation.v2"),
            claim, good)
    finally:
        journal.close()


@pytest.mark.asyncio
async def test_v3_rpc_route_requires_separate_installer_and_exact_version(tmp_path):
    """Route-only probe; it does not fabricate a formal V3 installation."""
    config, _, server = _installed_config(tmp_path)
    peer = MtlsPeerCredential(next(iter(config.installations_v2))[0])
    binding = replace(_binding(), algorithm_ref="d06.association_activation.v3")
    command = {"namespace": NAMESPACE, "binding": c04_to_wire(binding)}
    try:
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command("c04_inspect_v3", peer, "test", "a" * 64, command)
        expected = InternalWorkJournalInspectionV1(
            binding, None, None, None, None,
            JournalHead(JOURNAL_ID, 0, "genesis"))

        class ControlledRoute:
            def inspect(self, candidate):
                assert candidate == binding
                return expected

            execute = inspect

        server._v3_internal_work_executors[NAMESPACE] = ControlledRoute()
        for method in ("c04_inspect_v3", "c04_execute_v3"):
            observed = server._v2_command(
                method, peer, "test", "a" * 64, command)
            assert c04_from_wire(
                observed["inspection"], InternalWorkJournalInspectionV1) == expected
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command("c04_execute_v2", peer, "test", "a" * 64,
                               command)
    finally:
        await server.aclose()


def test_v3_algorithm_claim_terminal_replay_keeps_signed_result(tmp_path):
    """Real algorithm and journal; prepared-reader is a controlled fixture."""
    frozen = work()
    binding = v3_binding(frozen)
    journal = AuthorityV2ExecutionJournal(
        tmp_path / "execution.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True)
    prepared = C04InternalWorkPreparedV1(
        binding, "body-profile", 1, "body-state", 1, 1,
        "owner-grant", 1, "a" * 64, "budget-operation", "b" * 64,
        (), 1, 1, 0)
    attestation = {
        "schema": "sylanne.d06.algorithm-build.v1",
        "algorithm_id": binding.algorithm_ref,
        "manifest_sha256": "f" * 64,
        "package_mode": "formal-alpha1",
        "status": "formal_package_bytes_only",
        "build_digest": "sha256:" + binding.algorithm_build_digest,
    }

    def claim_port(original, claim, before_head, observed):
        assert observed == prepared
        with journal.freeze_writes():
            return journal.append_internal_work_claim_v1(
                original, claim, before_head)

    def terminal_port(original, claim, terminal, before_head):
        with journal.freeze_writes():
            return journal.append_internal_work_terminal_v1(
                original, claim, terminal, before_head)

    try:
        service = AuthorityInternalWorkService(
            journal, current_prepared_reader=lambda _: prepared,
            claim_port=claim_port, terminal_port=terminal_port,
            core_head_verifier=lambda head: head == journal.verified_head(),
            component_signing_key=b"k" * 32,
            installed_build_digest=binding.algorithm_build_digest,
            installed_build_attestation=attestation,
            trusted_manifest_sha256="f" * 64)
        executor = InstalledC04ExecutorV3(
            service, frozen_input_reader=lambda _: frozen)
        completed = executor.execute(binding)
        assert completed.terminal is not None
        assert completed.terminal.status == "completed"
        assert service.verify_installed_terminal(
            binding, completed.claim, completed.terminal)
        assert executor.execute(binding) == completed
        assert journal.verified_head().seq == 2
        assert not service.verify_installed_terminal(
            binding, completed.claim,
            replace(completed.terminal,
                    actual_cpu_ms=completed.terminal.actual_cpu_ms + 1))
    finally:
        journal.close()
