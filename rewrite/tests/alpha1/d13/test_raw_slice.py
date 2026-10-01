from sylanne3.domains.d13.raw_slice import assemble_raw_slice, render_raw_slice
from sylanne3.runtime_contracts import (
    CompletedTurnV1,
    ConversationWindowProjectionV1,
    NamespaceId,
    ShortContextRequestV1,
    VersionedRef,
)


def ref(name):
    return VersionedRef(name, 1)


def fixture():
    audience, scene = ref("audience"), ref("scene")
    now = 1_000 + 80 * 3600
    turns = tuple(CompletedTurnV1(
        "conversation", audience, i, ref(f"raw-{i}"), ref(f"source-{i}"),
        ref(f"access-{i}"), f"speaker-{i % 2}", text, stamp, "confirmed", "not_applicable"
    ) for i, (text, stamp) in enumerate([
        ("old", now - 74 * 3600), ("recent one", now - 73 * 3600),
        ("recent two", now - 71 * 3600),
    ]))
    dependencies = tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))
    window = ConversationWindowProjectionV1(
        NamespaceId("bot", "persona"), "owner", "conversation", scene, audience,
        turns, 9, now, dependencies, (scene, audience, *dependencies), 0, 0, 0,
    )
    request = ShortContextRequestV1(
        "d09", "reply", "conversation", scene, audience, "query-one", None,
        1000, "provider", "model", "template", "tools", "lease", True,
    )
    return window, request


def test_71h_selected_and_73h_expired():
    window, request = fixture()
    result = assemble_raw_slice(window, request)
    assert [turn.sequence for turn in result.raw_tail] == [2]
    assert result.expires_at_utc == window.trusted_utc + 3600
    # Advance only trusted clock; both turns now exceed the strict age window.
    from dataclasses import replace
    expired_window = replace(window, trusted_utc=window.trusted_utc + 2 * 3600)
    expired = assemble_raw_slice(expired_window, request)
    assert expired.raw_tail == ()
    assert expired.missing_ranges == ((0, 2),)


def test_audience_mismatch_and_opt_in_fail_closed():
    from dataclasses import replace
    import pytest
    window, request = fixture()
    with pytest.raises(ValueError):
        assemble_raw_slice(window, replace(request, audience_ref=ref("other")))
    with pytest.raises(ValueError):
        assemble_raw_slice(window, replace(request, opt_in=False))


def test_budget_keeps_recent_contiguous_suffix_and_reports_gap():
    from dataclasses import replace
    window, request = fixture()
    rendered = "speaker-0: recent two"
    result = assemble_raw_slice(window, replace(request, history_token_budget=len(rendered.encode())))
    assert [turn.sequence for turn in result.raw_tail] == [2]
    assert result.estimated_tokens == len(rendered.encode())
    assert result.missing_ranges == ((0, 1),)


def test_sequence_gap_stops_suffix_without_expanding_missing_interval():
    from dataclasses import replace
    window, request = fixture()
    first, last = window.turns[1], window.turns[2]
    first = replace(first, trusted_utc=window.trusted_utc - 70 * 3600)
    last = replace(last, sequence=3)
    turns = (first, last)
    window = replace(window, turns=turns,
                     source_dependencies=tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref)),
                     read_set=(window.scene_ref, window.audience_ref,
                               *(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))))
    result = assemble_raw_slice(window, request)
    assert [turn.sequence for turn in result.raw_tail] == [3]
    assert result.missing_ranges == ((1, 2),)


def test_query_does_not_change_stable_prefix_and_render_is_raw_only():
    from dataclasses import replace
    window, request = fixture()
    one = assemble_raw_slice(window, request)
    two = assemble_raw_slice(window, replace(request, query_ref="different-query"))
    assert one.stable_prefix_digest == two.stable_prefix_digest
    assert one.stable_prefix_digest == assemble_raw_slice(
        replace(window, access_epoch=window.access_epoch + 1), request
    ).stable_prefix_digest
    assert "speaker-0: recent two" in render_raw_slice(one)
    assert "query" not in render_raw_slice(one)


def test_raw_tail_changes_full_slice_but_has_no_stable_history_prefix():
    from dataclasses import replace
    window, request = fixture()
    before = assemble_raw_slice(window, request)
    new_turn = replace(window.turns[-1], sequence=3, raw_ref=ref("raw-3"),
                       source_ref=ref("source-3"), access_ref=ref("access-3"),
                       text="a new answer", trusted_utc=window.trusted_utc)
    turns = (*window.turns, new_turn)
    deps = tuple(r for turn in turns for r in (
        turn.raw_ref, turn.source_ref, turn.access_ref))
    after_window = replace(window, turns=turns, source_dependencies=deps,
                           read_set=(window.scene_ref, window.audience_ref, *deps))
    after = assemble_raw_slice(after_window, request)
    assert before.stable_prefix_digest == after.stable_prefix_digest
    assert render_raw_slice(before) != render_raw_slice(after)
    assert before != after  # Full request identity must still change.
    assert after.stable_prefix_digest != assemble_raw_slice(
        after_window, replace(request, model_id="another-model")
    ).stable_prefix_digest
