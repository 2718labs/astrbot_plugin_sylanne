"""A typed final claim summary cannot become a send or claim authorization."""

from dataclasses import replace
import json
from pathlib import Path
import sys
import time

import pytest

# Reuse the real committed-admission/P0-P2 fixture in the adjacent runtime tests.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_dispatch_current_source_budget import _admitted  # noqa: E402
from test_dispatch_final_claim_v2 import _chain  # noqa: E402

from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.domains.d08.execution import GoalExecutionProvider
from sylanne3.runtime.dispatch_admission import load_admission
from sylanne3.runtime.dispatch_current_commitments import CurrentD08ActionConflictEvidenceV1
from sylanne3.runtime.dispatch_current_projection import CurrentDispatchProjectionV1
from sylanne3.runtime.dispatch_current_segment import CurrentDispatchSegmentV1
from sylanne3.runtime.dispatch_current_social_checks import CurrentSocialChecksV1
from sylanne3.runtime.dispatch_current_source_budget import CurrentDispatchHold
from sylanne3.runtime.dispatch_final_claim import (
    assemble_final_claim_evidence, read_final_claim_prerequisite,
)
from sylanne3.runtime_contracts import QueryEpoch


def _current_inputs(db, namespace, binding, claimed, prerequisite):
    admission = load_admission(db, namespace, prerequisite.admission_ref).admission
    row = db.execute(
        "SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d08.action_intent.v1' AND valid=1",
        namespace.as_tuple,
    ).fetchone()
    spec = next(item for item in GoalExecutionProvider().register_types()
                if item.name == "d08.action_intent.v1")
    intent = spec.validator(json.loads(row[0]))
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       namespace.as_tuple).fetchone()[0]
    query = QueryEpoch(namespace, "all", epoch)
    projection = CurrentDispatchProjectionV1(namespace, epoch, (), (), "projection:test")
    effect = CurrentEffectReadV2(
        binding.permit.authority_id, binding.namespace, binding.origin.effect_id,
        binding.permit.generation, "unresolved",
        claimed.after_anchor.execution_seq, claimed.after_anchor.execution_digest,
    )
    action = CurrentD08ActionConflictEvidenceV1(
        intent.action_id, intent.identity.effect_id, intent.identity.operation_id,
        QueryEpoch(namespace, "d08.conflict_graph", epoch), "unresolved",
        "unknown", "unknown", None, None, None, effect,
    )
    segment = CurrentDispatchSegmentV1(
        "hold", prerequisite.admission_ref, prerequisite.operation_id,
        prerequisite.effect_id, epoch, "batch:test", 1,
        admission.batch_digest, admission.payload_digest, "route:test",
    )
    social = CurrentSocialChecksV1("verified", True, "current_d03_d05_checks")
    return (query, intent, projection, social, action, segment)


def test_final_claim_correlates_real_committed_chain_but_remains_hold(tmp_path):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(db, namespace)
                now = time.time()
                prerequisite = read_final_claim_prerequisite(
                    db, namespace, binding, claimed, "handoff:one", now_utc=now)
                inputs = _current_inputs(db, namespace, binding, claimed, prerequisite)
                result = assemble_final_claim_evidence(
                    namespace, binding, claimed, prerequisite, *inputs, now_utc=now)
                assert result.status == "hold"
                assert result.evidence_digest == assemble_final_claim_evidence(
                    namespace, binding, claimed, prerequisite, *inputs,
                    now_utc=now).evidence_digest
                assert "trusted_current_reader_provenance" in result.missing_guards
                assert "same_p2_graph_claim_and_recovery_stamp" in result.missing_guards
                assert result.checked_kinds == tuple(sorted(
                    spec.check_kind for spec in inputs[1].required_checks))
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()


@pytest.mark.parametrize("change,match", (
    ("epoch", "graph epoch"),
    ("effect", "graph epoch or action identity"),
    ("coverage", "required check coverage"),
))
def test_final_claim_rejects_mixed_epoch_effect_or_partial_checks(tmp_path, change, match):
    store, namespace = _admitted(tmp_path)
    try:
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                binding, claimed = _chain(db, namespace)
                now = time.time()
                prerequisite = read_final_claim_prerequisite(
                    db, namespace, binding, claimed, "handoff:one", now_utc=now)
                query, intent, projection, social, action, segment = _current_inputs(
                    db, namespace, binding, claimed, prerequisite)
                if change == "epoch":
                    segment = replace(segment, graph_epoch=segment.graph_epoch + 1)
                elif change == "effect":
                    action = replace(action, effect_id="different-effect")
                else:
                    prerequisite = replace(prerequisite, check_receipts=prerequisite.check_receipts[:-1])
                with pytest.raises(CurrentDispatchHold, match=match):
                    assemble_final_claim_evidence(
                        namespace, binding, claimed, prerequisite, query, intent,
                        projection, social, action, segment, now_utc=now)
            finally:
                db.execute("ROLLBACK")
    finally:
        store.close()
