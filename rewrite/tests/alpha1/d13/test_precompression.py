from dataclasses import replace
import json

import pytest

from sylanne3.domains.d13.precompression import (
    adopt_candidate, compile_deterministic_candidate, decide_activation,
    plan_precompression, accept_model_candidate, accept_model_or_deterministic,
    select_detail_slots, EXTRACTIVE_MODEL_VERSION,
    EXTRACTIVE_OUTPUT_SCHEMA, compile_extractive_model_output,
    D13CurrentMainPressureV2, plan_paid_precompression_v2,
    accept_verified_model_candidate_v2,
)
from sylanne3.runtime.d13_precompression_job import (
    D13PrecompressionHold, prepare_activation_intent_v1,
    prepare_model_adoption_intent_v2,
    prepare_precompression_intent_v1,
)
from sylanne3.domains.d13.paid_lifecycle import D13ExactActivationEvidenceV1
from sylanne3.domains.d13.provider import (
    D13ShortContextProvider, ShortContextProjectionQueryV1,
    block_graph_value, validate_block_graph_value, render_active_slice,
    retirement_reason, prepare_retirement, validate_slice_for_consumption,
)
from sylanne3.domains.d13.prefix import stable_segment_digest
from sylanne3.model_broker.d13_context_frame import (
    build_d13_context_input_frame_v1,
)
from sylanne3.model_broker.d13_precompression import (
    D13PrecompressionInstallationV1,
)
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime_contracts import (
    CompletedTurnV1, ConversationWindowProjectionV1, NamespaceId,
    ShortContextRequestV1, TurnDetailSlotV1, TurnTimelineItemV1, VersionedRef,
    canonical_digest,
)


def ref(name, version=1):
    return VersionedRef(name, version)


def window(now=100_000):
    scene, audience = ref("scene"), ref("audience")
    texts = (
        "不要发送地址。这个限制仍然有效。" + "x" * 90,
        "我更正了日期。原来那天不对。" + "x" * 90,
        "工具结果 unknown。不能当作成功。" + "x" * 90,
        "新问题是什么？请说明。" + "x" * 90,
        "请继续。还有补充。" + "x" * 90,
        "确认收到。随后再答。" + "x" * 90,
    )
    turns = tuple(CompletedTurnV1(
        "conversation", audience, i, ref(f"raw:{i}"), ref(f"source:{i}"),
        ref(f"access:{i}"), f"speaker:{i % 2}", text, now - 60 + i,
        "confirmed", "not_applicable",
    ) for i, text in enumerate(texts))
    deps = tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))
    return ConversationWindowProjectionV1(
        NamespaceId("bot", "persona"), "owner", "conversation", scene, audience,
        turns, 5, now, deps, (scene, audience, *deps), 0, 0, 0,
    )


def planned():
    w = window()
    plan = plan_precompression(w, 1000, background_capacity=True,
                               outstanding_candidate=False)
    assert plan is not None
    return w, plan


def test_precompression_refuses_missing_source_inside_prefix():
    w, plan = planned()
    incomplete = replace(w, missing_ranges=((plan.first_sequence,
                                              plan.first_sequence),))
    assert plan_precompression(incomplete, 1000, background_capacity=True,
                               outstanding_candidate=False) is None
    with pytest.raises(ValueError, match="stale or incomplete"):
        compile_deterministic_candidate(incomplete, plan)


def test_active_slice_reports_unseen_turn_between_block_and_raw_tail():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    assert plan.last_sequence < 3
    turns = tuple(turn for turn in w.turns if turn.sequence != 2)
    deps = tuple(dict.fromkeys(ref for turn in turns for ref in (
        turn.raw_ref, turn.source_ref, turn.access_ref)))
    incomplete = replace(w, turns=turns, source_dependencies=deps,
                         read_set=(w.scene_ref, w.audience_ref, *deps))
    result = D13ShortContextProvider().project(ShortContextProjectionQueryV1(
        incomplete, request(incomplete), active, plan))
    assert any(start <= 2 <= end for start, end in result.missing_ranges)
    assert 2 not in {turn.sequence for turn in result.raw_tail}


def test_paid_prebuild_needs_exact_current_main_pressure_and_one_pending_slot():
    w = window()
    main = D13PrecompressionInstallationV1(
        "install", "provider", "model", "a" * 64, 256)
    pressure = D13CurrentMainPressureV2(
        canonical_digest(w), "b" * 64, "install", "provider", "model",
        "a" * 64, 600, "exact-tokenizer")

    def plan(count=pressure, **changes):
        args = dict(background_capacity=True, outstanding_candidate=False,
                    attempted_input_digests=frozenset())
        args.update(changes)
        return plan_paid_precompression_v2(w, count, main, 1000, **args)

    selected = plan()
    assert selected is not None
    assert selected.first_sequence == 0 and selected.last_sequence < 5
    assert plan(None) is None
    assert plan(replace(pressure, input_tokens=599)) is None
    assert plan(replace(pressure, provider_config_digest="c" * 64)) is None
    assert plan(replace(pressure, window_digest="d" * 64)) is None
    assert plan(outstanding_candidate=True) is None
    assert plan(attempted_input_digests=frozenset({selected.input_digest})) is None


def test_one_bounded_plan_and_anchored_fold():
    w, plan = planned()
    assert plan.first_sequence == 0
    assert plan.last_sequence < 5
    assert plan_precompression(w, 1000, background_capacity=True,
        outstanding_candidate=False, attempted_input_digests=frozenset({plan.input_digest})) is None
    assert plan_precompression(w, 1000, background_capacity=True,
        outstanding_candidate=True) is None
    assert plan_precompression(w, 1000, background_capacity=False,
        outstanding_candidate=False) is None
    block = compile_deterministic_candidate(w, plan)
    assert block.status == "candidate"
    assert block.turns[0].raw_ref == w.turns[0].raw_ref
    assert block.source_dependencies == plan.source_dependencies
    assert block.omitted_ranges == ((0, plan.last_sequence),)
    assert "不要发送地址。" in block.rendered_text
    assert "我更正了日期。" in block.rendered_text
    assert w.turns[0].text not in block.rendered_text
    assert "unknown" not in block.rendered_text or "工具结果 unknown。" in block.rendered_text
    assert block.expires_at_utc == w.turns[0].trusted_utc + 72 * 3600


def test_structural_fold_preserves_exact_order_and_marks_only_partial_turns():
    w = window()
    first = replace(w.turns[0], text="周五提交。")
    second = replace(w.turns[1], text="不，改到下周一。仍需确认。" + "补充" * 45)
    w = replace(w, turns=(first, second, *w.turns[2:]))
    plan = plan_precompression(w, 1200, background_capacity=True,
                               outstanding_candidate=False)
    assert plan is not None and plan.first_sequence == 0 and plan.last_sequence >= 1
    block = compile_deterministic_candidate(w, plan)
    assert block.timeline[0].text == "周五提交。"
    assert block.timeline[1].text == "不，改到下周一。"
    assert tuple(item.sequence for item in block.timeline) == tuple(
        range(plan.first_sequence, plan.last_sequence + 1))
    assert all(item.text in w.turns[item.sequence].text for item in block.timeline)
    assert not any(start <= 0 <= end for start, end in block.omitted_ranges)
    assert any(start <= 1 <= end for start, end in block.omitted_ranges)
    assert block.turns[1].source_ref == second.source_ref


def test_real_repeated_user_words_keep_distinct_raw_source_anchors():
    w = window()
    repeated = "请记住周一。" + "补充" * 30
    w = replace(w, turns=(replace(w.turns[0], text=repeated),
                          replace(w.turns[1], text=repeated), *w.turns[2:]))
    plan = plan_precompression(w, 1500, background_capacity=True,
                               outstanding_candidate=False)
    assert plan is not None and plan.last_sequence >= 1
    block = compile_deterministic_candidate(w, plan)
    assert block.turns[0].raw_ref != block.turns[1].raw_ref
    assert block.timeline[0].text == block.timeline[1].text == "请记住周一。"
    assert block.timeline[0].source_ref != block.timeline[1].source_ref


def test_unknown_later_in_turn_stays_in_stable_spine_and_duplicate_ref_is_rejected():
    w = window()
    first = replace(w.turns[0], text="工具已成功。结果 unknown。" + "补充" * 30)
    w = replace(w, turns=(first, *w.turns[1:]))
    plan = plan_precompression(w, 1300, background_capacity=True,
                               outstanding_candidate=False)
    assert plan is not None
    block = compile_deterministic_candidate(w, plan)
    assert "unknown" in block.timeline[0].text
    assert "工具已成功" not in block.timeline[0].text
    duplicate = replace(w.turns[1], raw_ref=first.raw_ref)
    turns = (first, duplicate, *w.turns[2:])
    deps = tuple(dict.fromkeys(ref for turn in turns for ref in (
        turn.raw_ref, turn.source_ref, turn.access_ref)))
    repeated_delivery = replace(w, turns=turns, source_dependencies=deps,
                                read_set=(w.scene_ref, w.audience_ref, *deps))
    assert plan_precompression(repeated_delivery, 1300, background_capacity=True,
                               outstanding_candidate=False) is None
    with pytest.raises(ValueError, match="stale or incomplete"):
        compile_deterministic_candidate(repeated_delivery, plan)


def test_query_conditional_slots_use_current_words_and_real_remention_only():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    provider = D13ShortContextProvider()

    def project(**changes):
        return provider.project(ShortContextProjectionQueryV1(
            w, request(w), active, plan, **changes))

    a = project(query_text="限制仍然有效吗")
    b = project(query_text="原来那天不对吗")
    assert a.selected_detail_slots == ("turn:0",)
    assert b.selected_detail_slots == ("turn:1",)
    assert a.stable_prefix_digest == b.stable_prefix_digest
    assert project(rementioned_sources=(w.turns[1].source_ref,)).selected_detail_slots == (
        "turn:1",)
    assert project(query_text="原来那天不对吗", evidence_sources=(
        w.turns[1].source_ref,)).selected_detail_slots == ()
    assert project(query_text="原来那天不对吗") == b  # selection has no feedback score


def test_stale_revision_fence_and_expiry_rejected():
    w, plan = planned()
    candidate = compile_deterministic_candidate(w, plan)
    assert adopt_candidate(candidate, plan, w, job_fence_valid=True).status == "standby"
    with pytest.raises(ValueError):
        adopt_candidate(candidate, plan, w, job_fence_valid=False)
    with pytest.raises(ValueError):
        compile_deterministic_candidate(replace(w, delete_epoch=1), plan)
    with pytest.raises(ValueError):
        compile_deterministic_candidate(replace(w, trusted_utc=plan.expires_at_utc), plan)
    changed = replace(w.turns[0], source_ref=ref("source:0", 2))
    turns = (changed, *w.turns[1:])
    deps = tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))
    changed_window = replace(w, turns=turns, source_dependencies=deps,
                             read_set=(w.scene_ref, w.audience_ref, *deps))
    with pytest.raises(ValueError):
        adopt_candidate(candidate, plan, changed_window, job_fence_valid=True)


def test_standby_activation_is_pure_and_expires():
    w, plan = planned()
    standby = adopt_candidate(compile_deterministic_candidate(w, plan), plan, w,
                              job_fence_valid=True)
    assert decide_activation(standby, plan, w, raw_window_fits=True,
                             proven_future_saving=False) == "keep_raw"
    assert decide_activation(standby, plan, w, raw_window_fits=False,
                             proven_future_saving=False) == "activate"
    assert decide_activation(standby, plan, w, raw_window_fits=True,
                             proven_future_saving=True) == "activate"
    assert decide_activation(standby, plan, replace(w, trusted_utc=standby.expires_at_utc),
                             raw_window_fits=False, proven_future_saving=False) == "invalid"
    assert decide_activation(standby, plan, replace(w, access_epoch=1),
                             raw_window_fits=False, proven_future_saving=False) == "invalid"


def test_activation_rejects_tampered_or_unsupported_standby_before_cas():
    w, plan = planned()
    standby = adopt_candidate(compile_deterministic_candidate(w, plan), plan, w,
                              job_fence_valid=True)
    assert decide_activation(standby, plan, w, raw_window_fits=False,
                             proven_future_saving=False) == "activate"

    altered_beat = replace(standby.timeline[0], text="已经完成")
    tampered = replace(standby, timeline=(altered_beat, *standby.timeline[1:]))
    assert decide_activation(tampered, plan, w, raw_window_fits=False,
                             proven_future_saving=False) == "invalid"

    unsupported = replace(standby, compiler_version=EXTRACTIVE_MODEL_VERSION)
    assert decide_activation(unsupported, plan, w, raw_window_fits=False,
                             proven_future_saving=False) == "invalid"


def request(w):
    return ShortContextRequestV1(
        "d09", "reply", w.conversation_ref, w.scene_ref, w.audience_ref,
        "query-ref", None, 1000, "provider", "model", "template", "tools",
        "parent-lease", True,
    )


def test_current_d13_model_frame_binds_main_installation_and_raw_72h_window():
    w = window()
    query = ShortContextProjectionQueryV1(w, request(w))
    selected = D13PrecompressionInstallationV1(
        "installation", "provider", "model", "a" * 64, 256,
    )
    frame, context_slice = build_d13_context_input_frame_v1(
        query, current_window=w, selected_main_model=selected,
    )
    assert frame.status == "candidate_requires_exact_token_count"
    assert not frame.stable_history and len(frame.history) == len(context_slice.raw_tail)
    assert all(part.kind == "d13_history" and part.dependencies
               for part in frame.history)
    assert frame.expires_at_utc <= min(turn.trusted_utc + 72 * 3600
                                      for turn in context_slice.raw_tail)
    assert frame.provider_config_digest == selected.provider_config_digest
    changed_config, _ = build_d13_context_input_frame_v1(
        query, current_window=w,
        selected_main_model=replace(selected, provider_config_digest="b" * 64),
    )
    assert changed_config.frame_digest != frame.frame_digest
    with pytest.raises(ValueError, match="installed conversation model"):
        build_d13_context_input_frame_v1(
            query, current_window=w,
            selected_main_model=replace(selected, model_id="other"),
        )
    with pytest.raises(ValueError, match="installed conversation model"):
        build_d13_context_input_frame_v1(
            query, current_window=replace(w, access_epoch=1),
            selected_main_model=selected,
        )
    old = replace(w, trusted_utc=w.trusted_utc + 72 * 3600 + 1)
    old_query = ShortContextProjectionQueryV1(old, request(old))
    retired, _ = build_d13_context_input_frame_v1(
        old_query, current_window=old, selected_main_model=selected,
    )
    assert not retired.history and not retired.stable_history


def test_deterministic_active_d13_frame_requires_graph_cache_proof():
    w, plan = planned()
    selected = D13PrecompressionInstallationV1(
        "installation", "provider", "model", "a" * 64, 256,
    )
    block = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                    plan, w, job_fence_valid=True), status="active")
    standby = replace(block, status="standby")
    with pytest.raises(ValueError, match="active block"):
        build_d13_context_input_frame_v1(
            ShortContextProjectionQueryV1(w, request(w), standby, plan),
            current_window=w, selected_main_model=selected,
        )
    query = ShortContextProjectionQueryV1(w, request(w), block, plan)
    with pytest.raises(ValueError, match="graph cache head"):
        build_d13_context_input_frame_v1(
            query, current_window=w, selected_main_model=selected,
        )
    cache_key = AtomKey(Owner("persona", "bot", "persona"),
                        "d13.compressed_turn_block.v2", "block:one")
    frame, _ = build_d13_context_input_frame_v1(
        query, current_window=w, selected_main_model=selected,
        active_block_graph_ref=VersionedRef(cache_key.token, 1),
    )
    assert frame.stable_history[0].ref.ref == cache_key.token
    assert frame.stable_history[0].expires_at_utc == block.expires_at_utc
    assert frame.history and frame.source_dependencies


def test_frozen_raw_slice_requires_current_egress_window():
    w = window()
    query = ShortContextProjectionQueryV1(w, request(w))
    frozen = D13ShortContextProvider().project(query)
    validate_slice_for_consumption(query, frozen, replace(w, trusted_utc=w.trusted_utc + 1))
    with pytest.raises(ValueError, match="72-hour"):
        validate_slice_for_consumption(query, frozen,
                                       replace(w, trusted_utc=frozen.expires_at_utc))
    with pytest.raises(ValueError, match="read set changed"):
        validate_slice_for_consumption(query, frozen, replace(w, access_epoch=1))
    with pytest.raises(ValueError, match="read set changed"):
        validate_slice_for_consumption(query, frozen,
                                       replace(w, read_set=(*w.read_set, ref("extra"))))
    with pytest.raises(ValueError, match="backwards"):
        validate_slice_for_consumption(query, frozen, replace(w, trusted_utc=w.trusted_utc - 1))


def test_frozen_active_slice_rejects_changed_source_and_cache():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    query = ShortContextProjectionQueryV1(w, request(w), active, plan)
    frozen = D13ShortContextProvider().project(query)
    validate_slice_for_consumption(query, frozen, replace(w, trusted_utc=w.trusted_utc + 1))
    changed = replace(w.turns[0], source_ref=ref("source:0", 2))
    turns = (changed, *w.turns[1:])
    deps = tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))
    current = replace(w, turns=turns, source_dependencies=deps,
                      read_set=(w.scene_ref, w.audience_ref, *deps))
    with pytest.raises(ValueError, match="read set changed"):
        validate_slice_for_consumption(query, frozen, current)
    with pytest.raises(ValueError, match="read set changed"):
        validate_slice_for_consumption(query, frozen, replace(w, activation_epoch=1))


def test_provider_raw_projection_is_typed_and_rejects_wrong_snapshot():
    w = window()
    provider = D13ShortContextProvider()
    raw = provider.project(ShortContextProjectionQueryV1(w, request(w)), w)
    assert raw.blocks == ()
    assert tuple(t.sequence for t in raw.raw_tail) == tuple(range(6))
    assert raw.evidence_eligibility == "ineligible"
    with pytest.raises(ValueError):
        provider.project(ShortContextProjectionQueryV1(w, request(w)), object())
    with pytest.raises(TypeError):
        provider.project((w, request(w)))
    assert provider.register_types()[0].writer_domain == "d13"


def test_provider_active_block_keeps_raw_tail_and_rejects_stale_source():
    w, plan = planned()
    provider = D13ShortContextProvider()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    value = block_graph_value(active)
    validate_block_graph_value(value)
    value["turns"][0]["source_ref"]["version"] += 1
    with pytest.raises(ValueError):
        validate_block_graph_value(value)
    query = ShortContextProjectionQueryV1(w, request(w), active, plan)
    result = provider.project(query, w)
    assert result.blocks == (active,)
    assert result.raw_tail[0].sequence > active.turns[-1].sequence
    assert result.missing_ranges[0] == (0, active.turns[-1].sequence)
    assert result.evidence_eligibility == "ineligible"
    with pytest.raises(ValueError):
        provider.project(replace(query, window=replace(w, delete_epoch=1)))


def test_active_query_selects_dynamic_source_anchored_values_without_rewriting_prefix():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    provider = D13ShortContextProvider()
    first = provider.project(ShortContextProjectionQueryV1(
        w, request(w), active, plan, ("turn:0",)))
    second = provider.project(ShortContextProjectionQueryV1(
        w, replace(request(w), query_ref="another-query"), active, plan,
        ("turn:1",)))
    assert first.stable_prefix_digest == second.stable_prefix_digest
    assert first.blocks == second.blocks == (active,)
    assert first.raw_tail == second.raw_tail
    assert first.selected_detail_slots == ("turn:0",)
    assert second.selected_detail_slots == ("turn:1",)
    rendered = render_active_slice(first)
    assert "turn:0" not in rendered  # lookup keys never enter model text
    assert "source:0@1" in rendered
    assert rendered.index("speaker:") < rendered.index("[detail 0")
    assert len(rendered.encode("utf-8")) == first.estimated_tokens


def test_active_block_timeline_is_stable_across_new_raw_tail():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    provider = D13ShortContextProvider()
    before = provider.project(ShortContextProjectionQueryV1(w, request(w), active, plan))
    extra = replace(w.turns[-1], sequence=6, raw_ref=ref("raw:6"),
                    source_ref=ref("source:6"), access_ref=ref("access:6"),
                    text="Later raw answer.", trusted_utc=w.trusted_utc)
    turns = (*w.turns, extra)
    deps = tuple(r for turn in turns for r in (
        turn.raw_ref, turn.source_ref, turn.access_ref))
    later = replace(w, turns=turns, order_watermark=6,
                    source_dependencies=deps,
                    read_set=(w.scene_ref, w.audience_ref, *deps))
    after = provider.project(ShortContextProjectionQueryV1(
        later, request(later), active, plan))
    assert before.stable_prefix_digest == after.stable_prefix_digest
    assert render_active_slice(before) != render_active_slice(after)
    assert before != after
    assert before.stable_prefix_digest != stable_segment_digest(
        w, request(w), "[0 speaker:0] different stable text")


def test_detail_selection_uses_only_remainder_and_expired_block_is_rejected():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    provider = D13ShortContextProvider()
    base = provider.project(ShortContextProjectionQueryV1(w, request(w), active, plan))
    stable_bytes = len(render_active_slice(base).encode("utf-8"))
    tight = provider.project(ShortContextProjectionQueryV1(
        w, replace(request(w), history_token_budget=stable_bytes), active, plan,
        ("turn:0", "turn:1")))
    assert tight.blocks == (active,) and tight.raw_tail == base.raw_tail
    assert tight.selected_detail_slots == ()
    assert tight.estimated_tokens == stable_bytes
    with pytest.raises(ValueError, match="expired"):
        provider.project(ShortContextProjectionQueryV1(
            replace(w, trusted_utc=active.expires_at_utc), request(w), active, plan,
            ("turn:0",)))


def test_retirement_intent_at_72h_keeps_original_expiry_and_blocks_projection():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    before = replace(w, trusted_utc=active.expires_at_utc - 1)
    assert retirement_reason(active, plan, before) is None
    with pytest.raises(ValueError, match="not due"):
        prepare_retirement(active, plan, before, cache_revision=3)
    expired = replace(w, trusted_utc=active.expires_at_utc)
    assert retirement_reason(active, plan, expired) == "72h_expired"
    intent = prepare_retirement(active, plan, expired, cache_revision=3)
    assert intent.action == "retire"
    assert intent.reason == "72h_expired"
    assert intent.expected_cache_revision == 3
    assert intent.block.status == "retired"
    assert intent.block.expires_at_utc == active.expires_at_utc
    with pytest.raises(ValueError, match="72h_expired"):
        D13ShortContextProvider().project(
            ShortContextProjectionQueryV1(expired, request(w), active, plan))


def test_source_deletion_generates_retirement_intent_without_raw_fallback():
    w, plan = planned()
    active = replace(adopt_candidate(compile_deterministic_candidate(w, plan),
                                     plan, w, job_fence_valid=True), status="active")
    current = replace(w, turns=(), source_dependencies=(),
                      read_set=(w.scene_ref, w.audience_ref), delete_epoch=1)
    assert retirement_reason(active, plan, current) == "source_invalidated"
    intent = prepare_retirement(active, plan, current, cache_revision=4)
    assert intent.reason == "source_invalidated"
    assert not set(intent.source_dependencies).issubset(intent.read_set)
    with pytest.raises(ValueError, match="source_invalidated"):
        D13ShortContextProvider().project(
            ShortContextProjectionQueryV1(current, request(w), active, plan))


def test_settled_model_excerpt_preserves_sensitive_turns_and_query_only_selects_details():
    w, plan = planned()
    raw = tuple(t for t in w.turns if plan.first_sequence <= t.sequence <= plan.last_sequence)
    base = compile_deterministic_candidate(w, plan)
    timeline = tuple(TurnTimelineItemV1(t.sequence, t.source_ref, t.speaker_ref, t.text)
                     for t in raw)
    slots = tuple(TurnDetailSlotV1(f"topic:{t.sequence}", t.sequence, t.source_ref,
                                   t.text.split("。", 1)[0]) for t in raw)
    model = replace(base, compiler_version=EXTRACTIVE_MODEL_VERSION, timeline=timeline,
                    detail_slots=slots, omitted_ranges=())
    accepted = accept_model_candidate(model, plan, w, settled_job_ref=plan.job_ref,
                                      job_fence_valid=True)
    assert accepted.status == "standby"
    assert select_detail_slots(accepted, query_keys=(slots[0].key,), detail_byte_budget=100) == (slots[0],)
    assert select_detail_slots(accepted, query_keys=(slots[-1].key,), detail_byte_budget=100) == (slots[-1],)
    assert accepted.timeline == timeline  # query changes detail selection, not the stable spine
    with pytest.raises(ValueError, match="not settled"):
        accept_model_candidate(model, plan, w, settled_job_ref="other", job_fence_valid=True)


def test_model_paraphrase_unknown_and_wrong_speaker_fall_back_to_current_raw_excerpt():
    w, plan = planned()
    raw = tuple(t for t in w.turns if plan.first_sequence <= t.sequence <= plan.last_sequence)
    base = compile_deterministic_candidate(w, plan)
    timeline = tuple(TurnTimelineItemV1(t.sequence, t.source_ref, t.speaker_ref, t.text)
                     for t in raw)
    model = replace(base, compiler_version=EXTRACTIVE_MODEL_VERSION, timeline=timeline,
                    detail_slots=(), omitted_ranges=())
    with pytest.raises(ValueError):
        replace(model, timeline=(replace(timeline[0], speaker_ref="another"), *timeline[1:]))
    unknown = next((item for item in timeline if "unknown" in item.text), timeline[-1])
    invented = replace(model, timeline=tuple(
        replace(item, text="工具已经成功完成") if item is unknown else item for item in timeline
    ))
    with pytest.raises(ValueError):
        accept_model_candidate(invented, plan, w, settled_job_ref=plan.job_ref,
                               job_fence_valid=True)
    fallback = accept_model_or_deterministic(invented, plan, w,
                                             settled_job_ref=plan.job_ref, job_fence_valid=True)
    assert fallback.compiler_version == base.compiler_version
    assert fallback.status == "standby"
    with pytest.raises(ValueError, match="not settled"):
        accept_model_or_deterministic(invented, plan, w,
                                      settled_job_ref="other", job_fence_valid=True)


def test_english_unknown_and_not_cannot_be_cut_from_extractive_stable_beat():
    w = window()
    first = replace(w.turns[0], text=(
        "Upload was submitted. Outcome unknown; do not mark complete. " + "x" * 90))
    w = replace(w, turns=(first, *w.turns[1:]))
    plan = plan_precompression(w, 1200, background_capacity=True,
                               outstanding_candidate=False)
    assert plan is not None and plan.first_sequence == 0
    base = compile_deterministic_candidate(w, plan)
    raw = tuple(t for t in w.turns
                if plan.first_sequence <= t.sequence <= plan.last_sequence)
    timeline = tuple(TurnTimelineItemV1(
        t.sequence, t.source_ref, t.speaker_ref,
        "Upload was submitted." if t.sequence == 0 else t.text) for t in raw)
    model = replace(base, compiler_version=EXTRACTIVE_MODEL_VERSION,
                    timeline=timeline, detail_slots=(), omitted_ranges=((0, 0),))
    with pytest.raises(ValueError, match="unknown requires exact stable beat"):
        accept_model_candidate(model, plan, w, settled_job_ref=plan.job_ref,
                               job_fence_valid=True)


def extractive_fixture():
    w = window()
    second = replace(w.turns[1], text="The weather is sunny. " + "x" * 90)
    w = replace(w, turns=(w.turns[0], second, *w.turns[2:]))
    plan = plan_precompression(w, 1000, background_capacity=True,
                               outstanding_candidate=False)
    assert plan is not None and plan.last_sequence >= 1
    planned_turns = tuple(t for t in w.turns
                          if plan.first_sequence <= t.sequence <= plan.last_sequence)
    rows = [{"sequence": t.sequence, "beat": t.text if t.sequence != 1 else
             "The weather is sunny.", "details": []} for t in planned_turns]
    return w, plan, rows


def test_extractive_model_parser_compiles_only_candidate_with_original_anchors():
    w, plan, rows = extractive_fixture()
    candidate = compile_extractive_model_output(w, plan, json.dumps({
        "schema": EXTRACTIVE_OUTPUT_SCHEMA, "turns": rows,
    }))
    assert candidate.status == "candidate"
    assert candidate.compiler_version == EXTRACTIVE_MODEL_VERSION
    assert candidate.timeline[0].text == w.turns[0].text  # Negation retained whole.
    assert candidate.timeline[1].speaker_ref == w.turns[1].speaker_ref
    assert candidate.timeline[1].source_ref == w.turns[1].source_ref
    assert candidate.omitted_ranges == ((1, 1),)
    with pytest.raises(ValueError, match="not settled"):
        accept_model_candidate(candidate, plan, w, settled_job_ref="unpaid",
                               job_fence_valid=False)
    assert accept_model_candidate(candidate, plan, w,
                                  settled_job_ref=plan.job_ref,
                                  job_fence_valid=True).status == "standby"


def test_extractive_model_parser_rejects_invention_omission_and_stale_source():
    w, plan, rows = extractive_fixture()

    def compile_rows(items):
        return compile_extractive_model_output(w, plan, json.dumps({
            "schema": EXTRACTIVE_OUTPUT_SCHEMA, "turns": items,
        }))

    with pytest.raises(ValueError, match="outside original"):
        compile_rows([{**rows[0], "beat": "Invented success"}, *rows[1:]])
    with pytest.raises(ValueError, match="exact stable beat"):
        compile_rows([{**rows[0], "beat": "不要发送地址。"}, *rows[1:]])
    with pytest.raises(ValueError, match="cover each planned turn"):
        compile_rows(rows[:-1])
    with pytest.raises(ValueError, match="turn shape or order"):
        compile_rows([rows[1], rows[0], *rows[2:]])
    with pytest.raises(ValueError, match="repeats a field"):
        compile_extractive_model_output(w, plan, (
            '{"schema":"d13.extractive_model_output.v1","schema":"duplicate","turns":[]}'))
    stale = replace(w, delete_epoch=w.delete_epoch + 1)
    with pytest.raises(ValueError, match="stale or incomplete"):
        compile_extractive_model_output(stale, plan, json.dumps({
            "schema": EXTRACTIVE_OUTPUT_SCHEMA, "turns": rows,
        }))


def test_model_candidate_standby_and_active_projection_need_current_paid_port():
    w, plan, rows = extractive_fixture()
    candidate = compile_extractive_model_output(w, plan, json.dumps({
        "schema": EXTRACTIVE_OUTPUT_SCHEMA, "turns": rows,
    }))

    class VerifiedOriginal:
        def verify_current_paid_model_block_v2(self, block, *, plan: object,
                                               window: ConversationWindowProjectionV1):
            return block == candidate and window == w

    paid = VerifiedOriginal()  # synthetic installed-port contract, not a paid receipt
    with pytest.raises(ValueError, match="paid model proof"):
        accept_verified_model_candidate_v2(candidate, plan, w, paid_verifier=None)
    standby = accept_verified_model_candidate_v2(candidate, plan, w,
                                                 paid_verifier=paid)
    assert standby.status == "standby"
    assert decide_activation(standby, plan, w, raw_window_fits=False,
                             proven_future_saving=False) == "invalid"
    assert decide_activation(standby, plan, w, raw_window_fits=False,
                             proven_future_saving=False,
                             paid_verifier=paid) == "hold"
    active = replace(standby, status="active")
    query = ShortContextProjectionQueryV1(w, request(w), active, plan)
    with pytest.raises(ValueError, match="paid/source proof"):
        D13ShortContextProvider().project(query)
    projected = D13ShortContextProvider().project(query, paid_verifier=paid)
    assert projected.blocks == (active,)
    validate_slice_for_consumption(query, projected, w, paid_verifier=paid)
    with pytest.raises(ValueError, match="paid/source proof"):
        validate_slice_for_consumption(query, projected, w)
    revoked = replace(w, access_epoch=w.access_epoch + 1)
    assert decide_activation(standby, plan, revoked, raw_window_fits=False,
                             proven_future_saving=False,
                             paid_verifier=paid) == "invalid"
    with pytest.raises(ValueError):
        D13ShortContextProvider().project(replace(query, window=revoked),
                                          paid_verifier=paid)
    expired = replace(w, trusted_utc=plan.expires_at_utc)
    assert decide_activation(standby, plan, expired, raw_window_fits=False,
                             proven_future_saving=False,
                             paid_verifier=paid) == "invalid"

    original = prepare_precompression_intent_v1(
        w, history_token_budget=1000, background_capacity=True,
        outstanding_candidate=False, attempted_input_digests=frozenset(),
        parent_budget_lease_ref="budget:root", resource_ref="d13:cpu",
        ceiling={"d13_compute_units": 1}, deadline_utc=w.trusted_utc + 100,
    )
    assert original is not None and original.plan == plan
    running = replace(original.job, phase="running", lease_holder="worker",
                      lease_expires_utc="1970-01-02T03:48:20Z", fence=1)
    intent = prepare_model_adoption_intent_v2(
        running, holder="worker", fence=1, now_utc=w.trusted_utc,
        plan=plan, candidate=candidate, current_window=w,
        paid_verifier=paid)
    assert intent.action == "adopt" and intent.block == standby

    exact = D13ExactActivationEvidenceV1(
        "main-install", "provider", "main-model", "a" * 64,
        "exact-tokenizer", "b" * 64, "c" * 64, 1100, 800, 1000)

    class VerifiedWires:
        def verify_current_exact_activation_v1(
                self, found, *, standby: object, plan: object, current_window):
            return (found == exact and standby == standby_expected and
                    plan == plan_expected and current_window == window_expected and
                    (found.installation_id, found.provider_id, found.model_id,
                     found.provider_config_digest, found.tokenizer_fingerprint) ==
                    ("main-install", "provider", "main-model", "a" * 64,
                     "exact-tokenizer"))

    standby_expected, plan_expected, window_expected = standby, plan, w
    wires = VerifiedWires()  # W09 must supply this from installed exact counters
    with pytest.raises(D13PrecompressionHold, match="not activatable"):
        prepare_activation_intent_v1(
            standby, plan, w, cache_revision=1, history_token_budget=1000,
            raw_window_input_tokens=1100, raw_tail_input_tokens=250,
            raw_window_fits=False, proven_future_saving=False,
            paid_verifier=paid)
    activation = prepare_activation_intent_v1(
        standby, plan, w, cache_revision=1, history_token_budget=1000,
        raw_window_input_tokens=1100, raw_tail_input_tokens=250,
        raw_window_fits=True, proven_future_saving=True,
        paid_verifier=paid, exact_activation_evidence=exact,
        exact_activation_verifier=wires)
    assert activation.action == "activate" and activation.block.status == "active"
    assert activation.reason == "exact_window_pressure"
    with pytest.raises(D13PrecompressionHold, match="not activatable"):
        prepare_activation_intent_v1(
            standby, plan, w, cache_revision=1, history_token_budget=1000,
            raw_window_input_tokens=1100, raw_tail_input_tokens=250,
            raw_window_fits=False, proven_future_saving=False,
            paid_verifier=paid,
            exact_activation_evidence=replace(exact, compressed_input_tokens=1100),
            exact_activation_verifier=wires)
    with pytest.raises(D13PrecompressionHold, match="paid model candidate"):
        prepare_model_adoption_intent_v2(
            running, holder="worker", fence=1, now_utc=w.trusted_utc,
            plan=plan, candidate=candidate, current_window=w,
            paid_verifier=None)
