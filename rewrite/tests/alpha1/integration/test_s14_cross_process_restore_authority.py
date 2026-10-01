"""S14 recovery slice across fresh processes and separate durable files.

The graph row and would-be model/dispatch inputs are controlled fixtures. No
provider call, platform effect, or deletion completion is simulated.
"""

from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest

from rewrite.tests.alpha1.integration.test_s14_stale_graph_restore import ROLE, _graph
from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressDraftV1
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceRuntimeState, SnapshotRequirementsV2
from sylanne3.runtime_journal import RecoveryConstraintFootprint


def _head(journal: DeletionJournal) -> JournalHead:
    current = journal.latest_head()
    return JournalHead(current.journal_id, current.seq, current.chain_digest)


def _open(root: Path, *, create: bool):
    deletions = {
        name: DeletionJournal(root / f"{name}-deletion.db", create=create)
        for name in ("seed", "ns-a")
    }
    guard = AuthorityV2DeletionGuard(root / "ns-a-deletion.db")
    executions = {
        name: AuthorityV2ExecutionJournal(
            root / f"{name}-execution.db", namespace=name,
            journal_id=f"{name}-execution", create=create)
        for name in ("seed", "ns-a")
    }
    core = AuthorityServiceCore(
        root / "authority.db", create=create,
        authorizer=lambda credential, *_: credential == "ok",
        deletion_verifier=lambda namespace, _before, current, phase: (
            current == _head(deletions[namespace]) and phase == "clear"),
        execution_verifier=lambda namespace, _before, current, _phase: (
            current == executions[namespace].verified_head()),
        effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True,
    )
    fences = AuthorityV2FenceStore(core._db, create=create, lock=core._lock)
    model_store = AuthorityV2ModelEgressStore(
        core._db, create=create, lock=core._lock)
    return core, fences, model_store, deletions, guard, executions


def _close(core, deletions, guard, executions):
    core.close()
    guard.close()
    for journal in deletions.values():
        journal.close()
    for journal in executions.values():
        journal.close()


def _service(core, fences, guard, executions):
    return AuthorityV2FenceService(
        core=core, fences=fences, deletion=guard,
        execution=executions["ns-a"], namespace="ns-a")


def _draft(anchor: RestoreAnchor) -> ModelEgressDraftV1:
    return ModelEgressDraftV1(
        authority_id=anchor.authority_id, namespace="ns-a", subject="subject-a",
        operation_id="old-model-operation", call_id="old-model-call",
        request_digest="a" * 64, job_id="old-model-job", worker_fence=1,
        source_refs=("source-a",), source_revisions=(("source-a", 1),),
        access_revisions=(("access-a", 1),), access_epoch=1, delete_epoch=0,
        graph_epoch=1, graph_revision=1,
        authority_activation_generation=anchor.activation_generation,
        authority_revocation_epoch=anchor.revocation_epoch,
        authority_deletion_seq=anchor.deletion_seq,
        authority_execution_seq=anchor.execution_seq,
        budget_lease_id="lease-a", budget_reservation_operation_id="reserve-a",
        budget_reservation_digest="b" * 64,
        budget_ceiling=(("output_tokens", 1),), provider_id="provider-a",
        model_id="model-a", provider_config_digest="c" * 64,
        max_output_tokens=1,
    )


def _stage(name: str, root: Path):
    if name == "prepare":
        opened = _open(root, create=True)
        core, fences, _model_store, deletions, guard, executions = opened
        graph = None
        try:
            # A separate seed namespace permits a v2-only Authority backup
            # before ns-a is activated. The restored backup genuinely has no
            # ns-a row, while the independent ns-a journals survive.
            core.register_namespace(
                "ok", "seed", "seed-holder", _head(deletions["seed"]),
                executions["seed"].verified_head())
            core.seal_v2_only("ok")
            service = _service(core, fences, guard, executions)
            with sqlite3.connect(root / "old-authority.db") as backup:
                core._db.backup(backup)
            activated = service.activate_namespace(
                credential="ok", subject="subject-a", holder="holder-a",
                namespace_id=ROLE, request_id="activate-a")
            assert activated.state is NamespaceRuntimeState.ACTIVE
            anchor = activated.anchor
            (root / "old-anchor.json").write_text(
                json.dumps(asdict(anchor)), encoding="utf-8")

            graph, coordinator, lease, authority, key, _port = _graph(
                root / "business.db", service)
            requirements = SnapshotRequirementsV2(
                ROLE, anchor.authority_id, anchor.namespace,
                anchor.activation_generation, anchor.deletion_journal_id,
                anchor.deletion_seq, anchor.deletion_digest,
                anchor.execution_journal_id, anchor.execution_seq,
                anchor.execution_digest, anchor.revocation_epoch,
                "graph-incarnation")
            graph.install_graph_recovery_genesis(
                requirements, _capability=graph._coordinator_capability)
            graph._db.execute(
                "INSERT INTO graph_atoms"
                "(token,bot,persona,owner_kind,subject,type_name,name,revision,value,valid) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (key.token, "bot", "persona", "persona", None,
                 "private_note", "one", 1, '{"text":"private fixture"}', 1))
            assert coordinator.read_snapshot(authority, lease, (key,)).get(key).value == (
                {"text": "private fixture"})
            with sqlite3.connect(root / "old-business.db") as backup:
                graph._db.backup(backup)
            deletions["ns-a"].append_intent(
                namespace="ns-a", operation_id="delete-source-a",
                closure_roots=(key.token,), epoch=1, policy_ref="policy-a")
            assert _head(deletions["ns-a"]).seq == 1
            assert executions["ns-a"].verified_head().seq == 0
            (root / "prepare-result.json").write_text(
                json.dumps({"pid": os.getpid(), "deletion_seq": 1}),
                encoding="utf-8")
        finally:
            if graph is not None:
                graph.close()
            _close(core, deletions, guard, executions)
        return

    if name == "reopen":
        opened = _open(root, create=False)
        core, fences, model_store, deletions, guard, executions = opened
        graph = None
        try:
            service = _service(core, fences, guard, executions)
            anchor = RestoreAnchor(**json.loads(
                (root / "old-anchor.json").read_text(encoding="utf-8")))
            bootstrap = service.namespace_bootstrap(
                credential="ok", subject="subject-a", namespace_id=ROLE)
            assert bootstrap.state is NamespaceRuntimeState.QUARANTINED
            assert bootstrap.blocking_reasons == ("orphaned_journal_history",)
            assert bootstrap.anchor is None
            with pytest.raises(AuthorityUnavailable, match="namespace is not registered"):
                service.current_anchor(credential="ok", subject="subject-a")

            graph, coordinator, lease, authority, key, port = _graph(
                root / "business.db", service)
            assert graph._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?", (key.token,)
            ).fetchone() is not None
            with pytest.raises(UnavailableGuard):
                coordinator.read_snapshot(authority, lease, (key,))
            assert port.validation_count == 0

            egress = AuthorityV2ModelEgressService(model_store, service)
            with pytest.raises(AuthorityUnavailable, match="namespace is not registered"):
                egress.prepare_fenced(
                    credential="ok", subject="subject-a", holder="holder-a",
                    draft=_draft(anchor), expected_anchor=anchor)
            assert core._db.execute(
                "SELECT count(*) FROM authority_model_egress_v1").fetchone() == (0,)

            footprint = RecoveryConstraintFootprint(
                namespace="ns-a", activity_id="would-be-activity",
                effect_id="would-be-effect")
            with pytest.raises(AuthorityUnavailable, match="namespace is not registered"):
                service.begin_fence(
                    credential="ok", subject="subject-a", holder="holder-a",
                    operation="dispatch", operation_id="would-be-dispatch",
                    expected_anchor=anchor, effect_id="would-be-effect",
                    command_digest="sha256:" + "d" * 64,
                    footprint=footprint)
            assert core._db.execute(
                "SELECT count(*) FROM authority_v2_fences").fetchone() == (0,)
            (root / "reopen-result.json").write_text(json.dumps({
                "pid": os.getpid(), "state": bootstrap.state.value,
                "reasons": bootstrap.blocking_reasons,
                "read_blocked": True, "model_blocked": True,
                "dispatch_blocked": True,
            }), encoding="utf-8")
        finally:
            if graph is not None:
                graph.close()
            _close(core, deletions, guard, executions)
        return
    raise ValueError(name)


def _run(name: str, root: Path):
    environment = os.environ.copy()
    rewrite_root = Path(__file__).resolve().parents[3]
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (
        str(rewrite_root.parent), str(rewrite_root),
        environment.get("PYTHONPATH", ""))))
    process = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), name, str(root)],
        cwd=rewrite_root, env=environment, capture_output=True, text=True,
        timeout=30, check=False)
    assert process.returncode == 0, process.stdout + process.stderr


def test_old_authority_and_business_backups_quarantine_after_deletion(tmp_path):
    _run("prepare", tmp_path)
    prepared = json.loads((tmp_path / "prepare-result.json").read_text(encoding="utf-8"))
    assert prepared["pid"] != os.getpid() and prepared["deletion_seq"] == 1
    shutil.copyfile(tmp_path / "old-authority.db", tmp_path / "authority.db")
    shutil.copyfile(tmp_path / "old-business.db", tmp_path / "business.db")
    _run("reopen", tmp_path)
    reopened = json.loads((tmp_path / "reopen-result.json").read_text(encoding="utf-8"))
    assert reopened["pid"] not in {os.getpid(), prepared["pid"]}
    assert reopened == {
        "pid": reopened["pid"], "state": "quarantined",
        "reasons": ["orphaned_journal_history"],
        "read_blocked": True, "model_blocked": True,
        "dispatch_blocked": True,
    }


if __name__ == "__main__":
    _stage(sys.argv[1], Path(sys.argv[2]))
