"""Independent Authority journals outlive a stale caller or Core DB backup."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId, NamespaceRuntimeState
from sylanne3.runtime_journal import RecoveryConstraintFootprint

from test_execution_binding_v2_claim import (
    AUTH_NS, _binding_v2, _digest, _prepared, _service,
)


def _service_fence(core, fences, bridge, journal):
    return AuthorityV2FenceService(
        core=core, fences=fences, deletion=bridge.deletion,
        execution=journal, namespace=AUTH_NS)


def _stage(stage: str, root: Path) -> None:
    if stage == "claim":
        core, fences, journal, bridge = _service(root)
        service = _service_fence(core, fences, bridge, journal)
        old_anchor = service.current_anchor(
            credential="ok", subject="subject-a")
        (root / "old_client_anchor.json").write_text(
            json.dumps(asdict(old_anchor)), encoding="utf-8")
        # SQLite's backup API takes a consistent persisted Core snapshot before
        # the independent execution journal advances to prepared and claimed.
        with sqlite3.connect(root / "authority-before-claim.db") as backup:
            core._db.backup(backup)
        prepared, origin = _prepared(core, fences, bridge)
        claimed, _ = bridge.execution_claim_v2(
            credential="ok", subject="subject-a", prepared_receipt=prepared,
            binding=_binding_v2(origin))
        with core._tx() as db:
            dispatch_permit = fences._permit(fences._row(db, "operation-a"))
        fences.finish_fence(
            dispatch_permit, subject="subject-a",
            current_anchor=claimed.after_anchor,
            request_id="finish-dispatch-a", request_digest=_digest("e"))
        (root / "claim_result.json").write_text(json.dumps({
            "pid": os.getpid(), "seq": claimed.after_anchor.execution_seq,
            "digest": claimed.after_anchor.execution_digest,
        }), encoding="utf-8")
        core.close()
        journal.close()
        bridge.deletion.close()
        return

    if stage == "reopen-current":
        core, fences, journal, bridge = _service(root, create=False)
        service = _service_fence(core, fences, bridge, journal)
        old_anchor = RestoreAnchor(**json.loads(
            (root / "old_client_anchor.json").read_text(encoding="utf-8")))
        old_rejected = False
        try:
            service.begin_fence(
                credential="ok", subject="subject-a", holder="holder-a",
                operation="write", operation_id="stale-write",
                expected_anchor=old_anchor)
        except AuthorityUnavailable:
            old_rejected = True
        assert old_rejected, "stale client anchor obtained a write fence"
        current = service.current_anchor(credential="ok", subject="subject-a")
        footprint = RecoveryConstraintFootprint(
            namespace=AUTH_NS, activity_id="activity-a", effect_id="effect-a",
            conflict_keys=("resource-a",))
        duplicate_rejected = False
        try:
            service.begin_fence(
                credential="ok", subject="subject-a", holder="holder-a",
                operation="dispatch", operation_id="duplicate-dispatch",
                expected_anchor=current, effect_id="effect-a",
                command_digest=_digest("a"), footprint=footprint)
        except AuthorityUnavailable:
            duplicate_rejected = True
        assert duplicate_rejected, "previously claimed effect was re-admitted"
        # A restored business graph may assign a fresh effect ID. The durable
        # conflict footprint must still block another execution append.
        new_footprint = RecoveryConstraintFootprint(
            namespace=AUTH_NS, activity_id="activity-b", effect_id="effect-b",
            conflict_keys=("resource-a",))
        new_permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="dispatch", operation_id="new-effect-dispatch",
            expected_anchor=current, effect_id="effect-b",
            command_digest=_digest("b"), footprint=new_footprint)
        conflicting_prepare_rejected = False
        try:
            bridge.execution_prepare(
                credential="ok", subject="subject-a", permit=new_permit,
                mutation_id="mutation-b", footprint=new_footprint)
        except AuthorityUnavailable:
            conflicting_prepare_rejected = True
        assert conflicting_prepare_rejected, "conflicting new effect was prepared"
        service.finish_fence(
            credential="ok", subject="subject-a", permit=new_permit,
            request_id="finish-conflicting-dispatch",
            request_digest=_digest("f"))
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="write", operation_id="current-write",
            expected_anchor=current)
        snapshot = bridge.read_current_effect_snapshot_for_write_fence(
            credential="ok", subject="subject-a", permit=permit)
        assert snapshot.coverage == "complete"
        assert len(snapshot.unresolved_effects) == 1
        effect = snapshot.unresolved_effects[0]
        assert (effect.effect_id, effect.phase) == ("effect-a", "claimed")
        (root / "reopen_result.json").write_text(json.dumps({
            "pid": os.getpid(), "seq": snapshot.execution_head_seq,
            "digest": snapshot.execution_head_digest,
            "effect_id": effect.effect_id, "phase": effect.phase,
        }), encoding="utf-8")
        core.close()
        journal.close()
        bridge.deletion.close()
        return

    if stage == "reopen-rolled-back-core":
        core, fences, journal, bridge = _service(root, create=False)
        service = _service_fence(core, fences, bridge, journal)
        bootstrap = service.namespace_bootstrap(
            credential="ok", subject="subject-a",
            namespace_id=NamespaceId("bot", "persona"))
        assert bootstrap.state is NamespaceRuntimeState.RECOVERING
        assert "journal_head_mismatch" in bootstrap.blocking_reasons
        anchor_rejected = False
        try:
            service.current_anchor(credential="ok", subject="subject-a")
        except AuthorityUnavailable:
            anchor_rejected = True
        assert anchor_rejected, "old Core DB advertised a current anchor"
        old_anchor = RestoreAnchor(**json.loads(
            (root / "old_client_anchor.json").read_text(encoding="utf-8")))
        fence_rejected = False
        try:
            service.begin_fence(
                credential="ok", subject="subject-a", holder="holder-a",
                operation="write", operation_id="rolled-back-write",
                expected_anchor=old_anchor)
        except AuthorityUnavailable:
            fence_rejected = True
        assert fence_rejected, "old Core DB admitted a write against newer journal"
        (root / "rollback_result.json").write_text(json.dumps({
            "pid": os.getpid(), "anchor_rejected": anchor_rejected,
            "fence_rejected": fence_rejected,
        }), encoding="utf-8")
        core.close()
        journal.close()
        bridge.deletion.close()
        return
    raise ValueError(stage)


def _run_stage(stage: str, root: Path) -> None:
    env = os.environ.copy()
    rewrite_root = Path(__file__).resolve().parents[3]
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (
        str(rewrite_root), env.get("PYTHONPATH", ""))))
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), stage, str(root)],
        cwd=rewrite_root, env=env, capture_output=True, text=True, timeout=30,
        check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_reopened_authority_preserves_claim_and_rejects_older_core_backup(tmp_path):
    _run_stage("claim", tmp_path)
    claim = json.loads((tmp_path / "claim_result.json").read_text(encoding="utf-8"))
    assert claim["seq"] == 2
    _run_stage("reopen-current", tmp_path)
    current = json.loads((tmp_path / "reopen_result.json").read_text(encoding="utf-8"))
    assert (current["seq"], current["digest"], current["effect_id"], current["phase"]) == (
        claim["seq"], claim["digest"], "effect-a", "claimed")
    assert claim["pid"] != os.getpid() and current["pid"] != os.getpid()
    # A restored pre-claim Core file cannot pull the two service-owned journal
    # files back. A third interpreter must quarantine this mixed persisted set.
    shutil.copyfile(tmp_path / "authority-before-claim.db", tmp_path / "authority.db")
    _run_stage("reopen-rolled-back-core", tmp_path)
    rollback = json.loads((tmp_path / "rollback_result.json").read_text(encoding="utf-8"))
    assert rollback["pid"] != os.getpid()
    assert rollback["anchor_rejected"] and rollback["fence_rejected"]


if __name__ == "__main__":
    _stage(sys.argv[1], Path(sys.argv[2]))
