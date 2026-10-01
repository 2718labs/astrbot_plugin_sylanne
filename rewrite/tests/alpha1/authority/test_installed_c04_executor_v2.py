"""Installed C04 runs once across claim races and terminal response loss."""

from dataclasses import replace
import hashlib
import threading
import time

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.installed_c04_executor_v2 import (
    ALGORITHM_ID, InstalledC04ExecutorV2, compose_installed_c04_executor_v2,
)
from sylanne3.authority_service.internal_work_contract import InternalWorkBindingV1
from sylanne3.authority_service.internal_work_service import AuthorityInternalWorkService
from sylanne3.domains.d06.c04_work_input_v2 import AssociationWorkInputV2
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.c04_internal_work_original_v1 import C04InternalWorkPreparedV1
from sylanne3.runtime.deletion import DeletionJournal
from tests.alpha1.d06.test_c04_work_input_v2 import _input
from tests.alpha1.authority.test_internal_work_core_head import opened, close


BUILD = "e" * 64


def _binding(work):
    reservation = AtomKey(Owner("activity", "bot", "persona", "activity"),
                          "d02.reservation.v1", "reservation").token
    from sylanne3.graph_coordinator import namespace_ref

    return InternalWorkBindingV1(
        namespace_ref(work.namespace), "activity", "operation", "execution",
        work.input_digest.removeprefix("sha256:"), "resource-quote", 1,
        "b" * 64, "body-quote", 1, "c" * 64, reservation,
        "association-component", "budget", 1, ALGORITHM_ID, "body-policy", BUILD)


def _service(journal, bridge, binding, *, terminal_ack_lost=False):
    prepared = C04InternalWorkPreparedV1(
        binding, "profile", 1, "state", 1, 1, "owner", 1,
        "d" * 64, "budget-operation", "f" * 64, (), 1, 0, 0)
    service = None

    def claim_port(work, claim, before, original):
        assert original == prepared
        return bridge.append_internal_work_claim_v1(
            credential="ok", binding=work, claim=claim,
            before_head=before, prepared=original)

    def terminal_port(work, claim, terminal, before):
        append = bridge.append_internal_work_terminal_v1(
            credential="ok", binding=work, claim=claim,
            terminal=terminal, before_head=before)
        if terminal_ack_lost:
            raise ConnectionError("terminal ACK lost after durable append")
        return append

    service = AuthorityInternalWorkService(
        journal, current_prepared_reader=lambda _: prepared,
        claim_port=claim_port, terminal_port=terminal_port,
        core_head_verifier=lambda head: bridge.is_current_internal_work_head_v1(
            credential="ok", head=head),
        component_signing_key=b"k" * 32,
        installed_build_digest=BUILD,
        installed_build_attestation={
            "schema": "sylanne.d06.algorithm-build.v1",
            "algorithm_id": ALGORITHM_ID,
            "manifest_sha256": "f" * 64,
            "package_mode": "formal-alpha1",
            "status": "formal_package_bytes_only",
            "build_digest": "sha256:" + BUILD,
        }, trusted_manifest_sha256="f" * 64)
    bridge._internal_work_terminal_verifier = service.verify_installed_terminal
    return service


def test_execute_once_and_terminal_ack_recovery(tmp_path, monkeypatch):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.close()
    core, deletion, journal, bridge = opened(tmp_path, create=True)
    work = _input()
    binding = _binding(work)
    reads = 0
    calls = 0
    from sylanne3.authority_service import installed_c04_executor_v2 as installed

    original = installed.algorithm.activate_association_work_v2

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    def frozen(_):
        nonlocal reads
        reads += 1
        return AssociationWorkInputV2.from_json(work.to_json())

    monkeypatch.setattr(installed.algorithm, "activate_association_work_v2", counted)
    try:
        service = _service(journal, bridge, binding, terminal_ack_lost=True)
        executor = InstalledC04ExecutorV2(service, frozen_input_reader=frozen)
        with pytest.raises(ConnectionError, match="ACK lost"):
            executor.execute(binding)
        assert calls == reads == 1
        inspected = executor.inspect(binding)
        assert inspected.terminal is not None
        assert inspected.terminal.status == "completed"
        assert service.verify_installed_terminal(
            binding, inspected.claim, inspected.terminal)
        assert executor.execute(binding) == inspected
        assert calls == reads == 1
    finally:
        close(core, deletion, journal)


def test_claim_only_restart_is_unknown_and_never_reads_input(tmp_path):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.close()
    core, deletion, journal, bridge = opened(tmp_path, create=True)
    work = _input()
    binding = _binding(work)
    service = _service(journal, bridge, binding)
    claim = service.begin(binding)
    try:
        service.claim(binding, before_head=JournalHead(journal.journal_id, 0, "genesis"))
        executor = InstalledC04ExecutorV2(
            service, frozen_input_reader=lambda _: (_ for _ in ()).throw(
                AssertionError("claim-only replay read input")))
        inspected = executor.execute(binding)
        assert inspected.claim == claim and inspected.terminal is None
    finally:
        close(core, deletion, journal)


def test_concurrent_same_id_has_one_activation(tmp_path, monkeypatch):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.close()
    core, deletion, journal, bridge = opened(tmp_path, create=True)
    work = _input()
    binding = _binding(work)
    service = _service(journal, bridge, binding)
    executor = InstalledC04ExecutorV2(
        service, frozen_input_reader=lambda _:
        AssociationWorkInputV2.from_json(work.to_json()))
    from sylanne3.authority_service import installed_c04_executor_v2 as installed

    original = installed.algorithm.activate_association_work_v2
    entered = threading.Event()
    resume = threading.Event()
    calls = 0

    def paused(value):
        nonlocal calls
        calls += 1
        entered.set()
        assert resume.wait(2)
        return original(value)

    monkeypatch.setattr(installed.algorithm, "activate_association_work_v2", paused)
    outcomes = []

    def run():
        try:
            outcomes.append(executor.execute(binding))
        except AuthorityUnavailable:
            outcomes.append(executor.inspect(binding))

    first = threading.Thread(target=run)
    second = threading.Thread(target=run)
    try:
        first.start()
        assert entered.wait(2)
        second.start()
        second.join(2)
        resume.set()
        first.join(2)
        assert not first.is_alive() and not second.is_alive()
        assert calls == 1
        assert len(outcomes) == 2
        assert executor.inspect(binding).terminal.status == "completed"
    finally:
        resume.set()
        first.join(2)
        second.join(2)
        close(core, deletion, journal)


def test_historical_terminal_records_after_owner_revocation(tmp_path, monkeypatch):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.close()
    core, deletion, journal, bridge = opened(tmp_path, create=True)
    work = _input()
    binding = _binding(work)
    service = _service(journal, bridge, binding)
    executor = InstalledC04ExecutorV2(
        service, frozen_input_reader=lambda _: work)
    from sylanne3.authority_service import installed_c04_executor_v2 as installed

    original = installed.algorithm.activate_association_work_v2

    def revoked_during_work(value):
        # Isolate the terminal boundary after a Core state transition. The
        # integrated Owner revocation API is covered by its own service tests.
        with core._tx() as db:
            db.execute(
                "UPDATE authority_namespaces SET holder=NULL,phase='revoked',"
                "generation=generation+1 WHERE namespace=?",
                (binding.namespace,))
        return original(value)

    monkeypatch.setattr(installed.algorithm, "activate_association_work_v2",
                        revoked_during_work)
    try:
        inspected = executor.execute(binding)
        assert inspected.terminal.status == "completed"
        assert inspected.terminal.actual_cpu_ms >= 0
        with core._tx() as db:
            assert core._row(db, binding.namespace)[2] == "revoked"
        with pytest.raises(AuthorityUnavailable, match="Core owner"):
            later = replace(binding, operation_id="later-operation",
                            execution_id="later-execution")
            bridge.append_internal_work_claim_v1(
                credential="ok", binding=later,
                claim=service.begin(later),
                before_head=journal.verified_head(),
                prepared=replace(service._current_prepared_reader(binding),
                                 binding=later))
    finally:
        close(core, deletion, journal)


def test_formal_factory_refuses_missing_external_manifest_pin(tmp_path):
    deletion_log = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_log.close()
    core, deletion, journal, bridge = opened(tmp_path, create=True)
    graph_db = tmp_path / "graph.sqlite"
    graph_db.touch()
    from sylanne3.runtime_contracts import NamespaceId

    try:
        with pytest.raises(AuthorityUnavailable, match="external manifest pin"):
            compose_installed_c04_executor_v2(
                bridge=bridge, namespace=NamespaceId("bot", "persona"),
                graph_db_path=graph_db, package_root=tmp_path,
                trusted_manifest_sha256="", component_signing_key=b"k" * 32,
                credential="ok")
    finally:
        close(core, deletion, journal)
