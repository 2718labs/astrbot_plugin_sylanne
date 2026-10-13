"""Local frame-unit tests: real wire/provider codecs, synthetic installed port.

These do not claim production tokenizer/budget installation or Graph admission.
"""
from dataclasses import replace
import json
import sqlite3
import pytest

from test_natural_reply import frozen
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime_contracts import CompletedTurnV1, ConversationWindowProjectionV1, VersionedRef, canonical_digest
from sylanne3.domains.d13.precompression import compile_deterministic_candidate
from sylanne3.domains.d13.provider import block_graph_value
from sylanne3.runtime.d13_precompression_job import prepare_precompression_intent_v1
from sylanne3.runtime import installed_d13_natural_frame_v4 as frame


def case(monkeypatch):
    base = frozen()
    def ref(kind, name):
        return VersionedRef(AtomKey(Owner("persona", "bot", "persona"), kind, name).token, 1)
    scene, audience = ref("scene.test", "scene"), ref("audience.test", "audience")
    plan = replace(base.input.plan, scene_ref=scene, audience_ref=audience)
    question = replace(base.input.question, audience_ref=audience)
    turns = tuple(CompletedTurnV1(plan.audience_id, audience, i,
        ref("raw.test", str(i)), ref("source.test", str(i)), ref("access.test", str(i)),
        f"speaker:{i % 2}", "Keep this exact detail. Another important sentence. " + "x" * 180,
        80.0 + i, "confirmed", "not_applicable") for i in range(6))
    deps = tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))
    window = ConversationWindowProjectionV1(plan.namespace, "owner", plan.audience_id,
        scene, audience, turns, 5, 100.0, deps, (scene, audience, *deps), 0, 0, 1)
    intent = prepare_precompression_intent_v1(window, history_token_budget=2000,
        background_capacity=True, outstanding_candidate=False,
        attempted_input_digests=frozenset(), parent_budget_lease_ref="budget:test",
        resource_ref="resource:test", ceiling={"d13_compute_units": 1}, deadline_utc=150.0)
    assert intent is not None
    block = replace(compile_deterministic_candidate(window, intent.plan), status="standby")
    key = AtomKey(Owner("persona", "bot", "persona"), "d13.compressed_turn_block.v2", block.block_ref)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_atoms(token TEXT, revision INTEGER, value TEXT, valid INTEGER, bot TEXT, persona TEXT, type_name TEXT, owner_kind TEXT)")
    db.execute("CREATE TABLE graph_d13_retirements_v1(bot TEXT, persona TEXT, block_token TEXT)")
    db.execute("INSERT INTO graph_atoms VALUES (?,?,?,1,'bot','persona','d13.compressed_turn_block.v2','persona')",
        (key.token, 1, json.dumps(block_graph_value(block))))
    state = {"window": window}
    monkeypatch.setattr(frame, "read_current_d13_window_for_authority_v1",
                        lambda *a, **kw: replace(state["window"], trusted_utc=a[5]))
    import sylanne3.runtime.jobs as jobs
    monkeypatch.setattr(jobs, "get_job", lambda *a: intent.job)
    args = dict(namespace=plan.namespace, plan=plan, question=question,
        installation=base.installation, now_utc=100.0, expires_at_utc=130.0,
        activation_generation=1)
    return db, args, state, key


class InstalledTestPort:
    policy_digest = "9" * 64
    choice = "compressed"
    def evaluate_natural_pair_v4(self, *, raw, compressed, current_window, **kwargs):
        self.pair = raw, compressed
        return frame.D13NaturalWireDecisionV1(self.choice, "exact_full_wire", "8" * 64,
            raw.model_request_digest, compressed.model_request_digest,
            canonical_digest(current_window), self.policy_digest, 135.0)


def test_no_installed_count_keeps_real_raw_and_replays_without_write(monkeypatch):
    db, args, state, key = case(monkeypatch)
    result, reads, decision = frame.freeze_current_natural_frame_v4(db, **args)
    assert len(result.input.recent_history) == 6
    assert not result.input.stable_history and decision.activation_write is None
    assert decision.token_evidence == "token_evidence_unverified"
    again = frame.freeze_current_natural_frame_v4(db, **dict(args, now_utc=101.0), original=result)
    assert again[0] == result
    state["window"] = replace(state["window"], delete_epoch=1)
    with pytest.raises(ValueError):
        frame.freeze_current_natural_frame_v4(db, **dict(args, now_utc=101.0), original=result)


def test_prepares_activation_and_replays_exact_active_target(monkeypatch):
    db, args, state, key = case(monkeypatch)
    port = InstalledTestPort()
    result, reads, decision = frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port)
    assert result.input.stable_history
    assert decision.activation_write.key == key
    assert decision.activation_expected.revision == 1
    assert result.input.history_selection.block_ref.version == 2
    assert [r.revision for r in reads if r.key == key] == [1]
    first_pair = port.pair
    # Simulate only the cache CAS effect; full Graph admission is covered elsewhere.
    db.execute("UPDATE graph_atoms SET revision=2,value=? WHERE token=?",
               (json.dumps(decision.activation_write.value), key.token))
    again, reads2, decision2 = frame.freeze_current_natural_frame_v4(
        db, **dict(args, now_utc=101.0), installed_wire_port=port, original=result)
    assert again == result and port.pair == first_pair
    assert decision2.activation_write is None
    assert [r.revision for r in reads2 if r.key == key] == [2]
    db.execute("UPDATE graph_atoms SET revision=3")
    with pytest.raises(ValueError):
        frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port, original=result)


@pytest.mark.parametrize("choice", ["raw", "hold"])
def test_verified_raw_fit_and_explicit_hold(monkeypatch, choice):
    db, args, state, key = case(monkeypatch)
    port = InstalledTestPort()
    port.choice = choice
    if choice == "hold":
        with pytest.raises(ValueError, match="requires HOLD"):
            frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port)
    else:
        result, _, decision = frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port)
        assert not result.input.stable_history
        assert decision.activation_write is None


def test_forged_pair_proof_cannot_activate(monkeypatch):
    db, args, state, key = case(monkeypatch)
    class Forged(InstalledTestPort):
        def evaluate_natural_pair_v4(self, **kwargs):
            return replace(super().evaluate_natural_pair_v4(**kwargs), compressed_request_digest="0" * 64)
    result, _, decision = frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=Forged())
    assert not result.input.stable_history and decision.activation_write is None


def test_query_details_remain_dynamic_and_source_corruption_holds(monkeypatch):
    db, args, state, key = case(monkeypatch)
    args["question"] = replace(args["question"], text="Which important sentence?")
    port = InstalledTestPort()
    result, _, decision = frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port)
    assert result.input.detail_history
    assert "detail_history" not in json.loads(result.messages[1].content)
    assert json.loads(result.messages[2].content)["detail_history"]
    db.execute("UPDATE graph_atoms SET revision=2,value=?", (json.dumps(decision.activation_write.value),))
    w = state["window"]
    state["window"] = replace(w, turns=(replace(w.turns[0], text="Changed source"), *w.turns[1:]))
    with pytest.raises(ValueError):
        frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port, original=result)


def test_original_compression_cannot_fall_back_after_port_disappears(monkeypatch):
    db, args, state, key = case(monkeypatch)
    result, _, decision = frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=InstalledTestPort())
    db.execute("UPDATE graph_atoms SET revision=2,value=?", (json.dumps(decision.activation_write.value),))
    with pytest.raises(ValueError):
        frame.freeze_current_natural_frame_v4(db, **args, original=result)


def test_semantic_history_v5_replays_exact_wire_and_rejects_template_change(monkeypatch):
    from sylanne3.model_broker.natural_reply_history_v4 import (
        INPUT_SCHEMA_V5, FROZEN_SCHEMA_V5, TEMPLATE_DIGEST_V5)
    from sylanne3.runtime.natural_original_v3 import natural_generation_template_digest
    db, args, _, _ = case(monkeypatch)
    result, _, decision = frame.freeze_current_natural_frame_v4(
        db, **args, input_schema=INPUT_SCHEMA_V5)
    assert result.schema == FROZEN_SCHEMA_V5
    assert natural_generation_template_digest(result) == TEMPLATE_DIGEST_V5
    assert decision.activation_write is None
    recovered, _, _ = frame.freeze_current_natural_frame_v4(
        db, **dict(args, now_utc=101.0), original=result,
        input_schema=INPUT_SCHEMA_V5)
    assert recovered == result
    with pytest.raises(ValueError, match="original input schema"):
        frame.freeze_current_natural_frame_v4(
            db, **dict(args, now_utc=101.0), original=result)


def test_old_history_original_cannot_be_reinterpreted_as_semantic_v5(monkeypatch):
    from sylanne3.model_broker.natural_reply_history_v4 import INPUT_SCHEMA_V5
    db, args, _, _ = case(monkeypatch)
    original, _, _ = frame.freeze_current_natural_frame_v4(db, **args)
    with pytest.raises(ValueError, match="original input schema"):
        frame.freeze_current_natural_frame_v4(
            db, **dict(args, now_utc=101.0), original=original,
            input_schema=INPUT_SCHEMA_V5)
