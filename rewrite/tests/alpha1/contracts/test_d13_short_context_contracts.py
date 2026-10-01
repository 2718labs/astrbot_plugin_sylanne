import dataclasses
import unittest

from sylanne3.runtime_contracts import (
    CompressedTurnBlockV2,
    CompletedTurnV1,
    ConversationWindowProjectionV1,
    ModelInputFrameV1,
    NamespaceId,
    ShortContextRequestV1,
    ShortContextSliceV1,
    TurnAnchorV1,
    TurnDetailSlotV1,
    TurnTimelineItemV1,
    VersionedRef,
)


def ref(name, version=1):
    return VersionedRef(name, version)


def turn(sequence, *, conversation="conversation:1", audience=None, clock=100.0):
    return CompletedTurnV1(
        conversation_ref=conversation,
        audience_ref=audience or ref("audience:1"),
        sequence=sequence,
        raw_ref=ref(f"raw:{sequence}"),
        source_ref=ref(f"source:{sequence}"),
        access_ref=ref(f"access:{sequence}"),
        speaker_ref="speaker:user", text=f"Turn {sequence} source text",
        trusted_utc=clock,
        delivery_state="confirmed",
        tool_state="not_applicable",
    )


def closure(turns):
    return tuple(dependency for item in turns for dependency in
                 (item.raw_ref, item.source_ref, item.access_ref))


def block(turns=None):
    raw_turns = tuple(turns or (turn(4), turn(5)))
    turns = tuple(TurnAnchorV1.from_turn(item) for item in raw_turns)
    return CompressedTurnBlockV2(
        block_ref="d13:block:1", conversation_ref="conversation:1",
        audience_ref=ref("audience:1"), turns=turns,
        source_dependencies=closure(turns),
        timeline=tuple(TurnTimelineItemV1(item.sequence, item.source_ref,
                                          item.speaker_ref, f"Timeline {item.sequence}") for item in turns),
        detail_slots=(TurnDetailSlotV1("deadline", turns[-1].sequence,
                                       turns[-1].source_ref, "deadline detail"),),
        omitted_ranges=(),
        compiler_version="compiler:1", job_ref="job:1", candidate_ref="candidate:1",
        expires_at_utc=100.0 + 72 * 3600, status="active",
    )


def request(**changes):
    values = dict(
        requesting_domain="d09", purpose="respond", conversation_ref="conversation:1",
        scene_ref=ref("scene:1"), audience_ref=ref("audience:1"), query_ref="query:1",
        committed_focus_ref=None, history_token_budget=100, provider_id="provider:1",
        model_id="model:1", template_version="template:1", tool_profile_version="tools:1",
        parent_budget_lease_ref="budget:1", opt_in=True,
    )
    values.update(changes)
    return ShortContextRequestV1(**values)


class D13ShortContextContractTests(unittest.TestCase):
    def test_window_closes_source_revisions_and_rejects_unfinished_or_cross_audience_turns(self):
        turns = (turn(4), turn(5))
        window = ConversationWindowProjectionV1(
            namespace=NamespaceId("bot", "persona"), owner_ref="owner:1",
            conversation_ref="conversation:1", scene_ref=ref("scene:1"),
            audience_ref=ref("audience:1"), turns=turns, order_watermark=5,
            trusted_utc=200.0, source_dependencies=closure(turns),
            read_set=(ref("scene:1"), ref("audience:1"), *closure(turns)),
            access_epoch=1, delete_epoch=2, activation_epoch=3,
        )
        self.assertEqual(window.turns, turns)
        with self.assertRaises(ValueError):
            dataclasses.replace(window, source_dependencies=closure(turns)[:-1])
        with self.assertRaises(ValueError):
            dataclasses.replace(window, turns=(turn(4), turn(5, audience=ref("audience:other"))))
        with self.assertRaises(ValueError):
            dataclasses.replace(turn(4), tool_state="unknown")
        with self.assertRaises(ValueError):
            dataclasses.replace(turn(4), delivery_state="unconfirmed")

    def test_block_requires_consecutive_raw_turns_and_cannot_extend_72_hours(self):
        active = block()
        self.assertEqual(active.turns[0].sequence, 4)
        with self.assertRaises(ValueError):
            block((turn(4), turn(6)))
        with self.assertRaises(ValueError):
            dataclasses.replace(active, source_dependencies=active.source_dependencies[:-1])
        with self.assertRaises(ValueError):
            dataclasses.replace(active, expires_at_utc=active.expires_at_utc + 1)
        self.assertIn("Timeline 4", active.rendered_text)
        self.assertFalse(hasattr(active.turns[0], "text"))
        self.assertNotIn("Turn 4 source text", str(dataclasses.asdict(active)))
        with self.assertRaises(TypeError):
            dataclasses.replace(active, timeline=("unanchored summary",))
        with self.assertRaises(ValueError):
            dataclasses.replace(active, timeline=(TurnTimelineItemV1(
                4, ref("source:other"), "speaker:user", "invented"),))
        with self.assertRaises(ValueError):
            dataclasses.replace(active, detail_slots=(TurnDetailSlotV1(
                "deadline", 5, ref("source:other"), "invented"),))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            active.status = "retired"

    def test_slice_is_expiring_ineligible_context_with_complete_block_and_tail_closure(self):
        active = block()
        tail = turn(6, clock=120.0)
        dependencies = (*active.source_dependencies, *closure((tail,)))
        selected = ShortContextSliceV1(
            conversation_ref="conversation:1", audience_ref=ref("audience:1"),
            blocks=(active,), raw_tail=(tail,), selected_detail_slots=("deadline",),
            source_dependencies=dependencies, missing_ranges=(),
            expires_at_utc=active.expires_at_utc, stable_prefix_digest="a" * 64,
            estimated_tokens=50,
        )
        self.assertEqual(selected.evidence_eligibility, "ineligible")
        with self.assertRaises(ValueError):
            dataclasses.replace(selected, evidence_eligibility="eligible")
        with self.assertRaises(ValueError):
            dataclasses.replace(selected, source_dependencies=dependencies[:-1])
        with self.assertRaises(ValueError):
            dataclasses.replace(selected, expires_at_utc=active.expires_at_utc + 1)
        with self.assertRaises(ValueError):
            dataclasses.replace(selected, audience_ref=ref("audience:other"))
        with self.assertRaises(ValueError):
            dataclasses.replace(selected, selected_detail_slots=("unanchored",))
        with self.assertRaises(ValueError):
            dataclasses.replace(selected, raw_tail=(turn(5),))
        external_ranges = [[7, 8]]
        detached = dataclasses.replace(selected, missing_ranges=external_ranges)
        external_ranges[0][0] = 9
        self.assertEqual(detached.missing_ranges, ((7, 8),))

    def test_compression_request_cannot_opt_in_and_frame_keeps_evidence_separate(self):
        with self.assertRaises(ValueError):
            request(requesting_domain="d13", purpose="d13.compress")
        with self.assertRaises(ValueError):
            request(requesting_domain="d11", purpose="d13.compress")
        active = block()
        selected = ShortContextSliceV1(
            conversation_ref="conversation:1", audience_ref=ref("audience:1"),
            blocks=(active,), raw_tail=(), selected_detail_slots=(),
            source_dependencies=active.source_dependencies, missing_ranges=(),
            expires_at_utc=active.expires_at_utc, stable_prefix_digest="b" * 64,
            estimated_tokens=20,
        )
        req = request()
        reads = (ref("context:1"), req.scene_ref, req.audience_ref,
                 ref("evidence:1"), ref("projection:1"), ref("check:1"),
                 *selected.source_dependencies)
        frame = ModelInputFrameV1(
            request=req, context_frame_ref=ref("context:1"), short_context=selected,
            required_evidence_refs=(ref("evidence:1"),),
            current_projection_refs=(ref("projection:1"),),
            required_check_refs=(ref("check:1"),), read_set=reads,
            current_input_ref="input:1", available_input_tokens=100,
            actual_input_tokens=80, frozen_input_digest="c" * 64,
        )
        self.assertEqual(frame.short_context, selected)
        with self.assertRaises(ValueError):
            dataclasses.replace(frame, request=request(opt_in=False))
        with self.assertRaises(ValueError):
            dataclasses.replace(frame, required_evidence_refs=(ref("d13:block:1"),))
        with self.assertRaises(ValueError):
            dataclasses.replace(frame, read_set=reads[:-1])


if __name__ == "__main__":
    unittest.main()
