"""Narrow contract checks for the held future-at-encoding baseline."""

from dataclasses import replace
import unittest

from sylanne3.domains.d04.encoding_baseline_v2 import (
    EncodingBaselineCandidateV2, EncodingProjectionReceiptCandidateV2,
    ExactGraphRefV2, ProjectionMemberV2, ProjectionNumericErrorV2,
    encoding_input_binding_digest_v2,
)
from sylanne3.domains.d04.interval_projection_v2 import (
    D04IntervalProjectionCandidateV2, D04ProjectionMemberBindingV2,
)
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, Owner
from sylanne3.runtime_contracts import NamespaceId


def _ref(kind: str, type_name: str, name: str, subject: str | None = None,
         revision: int = 1) -> ExactGraphRefV2:
    return ExactGraphRefV2(
        AtomKey(Owner(kind, "bot", "persona", subject), type_name, name).token,
        revision,
    )


SOURCE = _ref("event", "memory.source", "record", "event:1", 2)
PERSPECTIVE = _ref("persona", "d03.self_perspective.v1", "perspective:1", revision=3)
INTERPRETATION = _ref("activity", "d07.current_interpretation.v1", "current",
                      "activity:1", 4)
FEELING = _ref("persona", "d04.feeling_state.v1", "feeling:1", revision=5)
FEELING2 = _ref("persona", "d04.feeling_state.v1", "feeling:2", revision=6)
HASH = "a" * 64


def _baseline(*, with_projection: bool = True) -> EncodingBaselineCandidateV2:
    sources = (SOURCE,)
    interpretations = (INTERPRETATION,)
    feelings = (FEELING, FEELING2)
    receipt = None
    if with_projection:
        receipt = EncodingProjectionReceiptCandidateV2(
            input_binding_digest=encoding_input_binding_digest_v2(
                "baseline:1", sources, PERSPECTIVE, interpretations, feelings, 10.0,
            ),
            members=(
                ProjectionMemberV2(FEELING,
                    _ref("persona", "d04.numeric_checkpoint.v1", "feeling:1").ref, 7),
                ProjectionMemberV2(FEELING2,
                    _ref("persona", "d04.numeric_checkpoint.v1", "feeling:2").ref, 8),
            ),
            component_digest=HASH,
            joint_numeric_receipt_digest=HASH,
            joint_adoption_operation_id="joint-operation:1",
            joint_adoption_receipt_digest=HASH,
            projection_policy_ref="policy:1",
            projection_policy_version="d04.interval-projection.v2",
            policy_digest=HASH,
            readout_asset_id="readout:1",
            readout_asset_version="readout:v2",
            readout_asset_sha256=HASH,
            native_manifest_sha256=HASH,
            native_sha256=HASH,
            native_abi_version=2,
            full_transcript_sha256=HASH,
            projection_proof_digest=HASH,
            mood_receipt_digest=None,
            graph_incarnation="incarnation:1",
            graph_revision=9,
            graph_epoch=2,
            access_epoch=3,
            delete_epoch=4,
            role_start=9.0,
            role_end=10.0,
            salience_interval=(0.2, 0.4),
            tone_interval=(-0.5, 0.1),
            numeric_error=ProjectionNumericErrorV2(0.01, 0.02, 0.03, 0.04, HASH),
        )
    return EncodingBaselineCandidateV2(
        "baseline:1", sources, PERSPECTIVE, interpretations, feelings,
        10.0, receipt, () if with_projection else ("projection_not_adopted",),
    )


class EncodingBaselineV2Tests(unittest.TestCase):
    def test_exact_refs_and_candidate_only_projection(self):
        baseline = _baseline()
        self.assertEqual(baseline.salience_interval, (0.2, 0.4))
        self.assertEqual(baseline.tone_interval, (-0.5, 0.1))
        self.assertEqual(baseline.semantic_calibration, "unvalidated")
        self.assertEqual(baseline.status, "candidate_unadopted")
        self.assertEqual(len(baseline.projection_receipt.receipt_digest), 64)
        snapshot = GraphSnapshot(tuple(
            GraphAtom(item.key, item.revision, {}) for item in
            (SOURCE, PERSPECTIVE, INTERPRETATION, FEELING, FEELING2)
        ), ())
        baseline.verify_refs_in_snapshot(snapshot)
        with self.assertRaisesRegex(ValueError, "stale"):
            baseline.verify_refs_in_snapshot(GraphSnapshot(tuple(
                GraphAtom(item.key, item.revision - 1 if item == SOURCE else item.revision, {})
                for item in (SOURCE, PERSPECTIVE, INTERPRETATION, FEELING, FEELING2)
            ), ()))

    def test_projection_binds_exact_historical_inputs(self):
        baseline = _baseline()
        with self.assertRaisesRegex(ValueError, "bind exact"):
            replace(baseline, as_known_at=11.0)
        with self.assertRaisesRegex(ValueError, "bind exact"):
            replace(baseline, then_feeling_versions=(replace(FEELING, revision=6),))
        with self.assertRaisesRegex(ValueError, "bind exact"):
            replace(baseline, then_feeling_versions=(FEELING,))
        with self.assertRaisesRegex(ValueError, "calibration"):
            replace(baseline, semantic_calibration="validated")
        with self.assertRaisesRegex(ValueError, "adoption"):
            replace(baseline, status="issued")
        with self.assertRaisesRegex(ValueError, "adoption"):
            replace(baseline.projection_receipt, status="adopted")
        with self.assertRaisesRegex(ValueError, "recall-time mood"):
            replace(baseline.projection_receipt, mood_receipt_digest=HASH)

    def test_projection_receipt_matches_held_math_identity(self):
        receipt = _baseline().projection_receipt
        candidate = D04IntervalProjectionCandidateV2(
            namespace=NamespaceId("bot", "persona"),
            member_bindings=tuple(D04ProjectionMemberBindingV2(
                item.checkpoint_ref, item.checkpoint_revision,
                item.feeling_version.ref, item.feeling_version.revision,
            ) for item in receipt.members),
            then_feeling_versions=tuple(GraphVersion(
                item.feeling_version.key, item.feeling_version.revision,
            ) for item in receipt.members),
            numeric_receipt_digest=receipt.joint_numeric_receipt_digest,
            component_digest=receipt.component_digest,
            graph_incarnation=receipt.graph_incarnation,
            graph_revision=receipt.graph_revision,
            graph_epoch=receipt.graph_epoch,
            access_epoch=receipt.access_epoch,
            delete_epoch=receipt.delete_epoch,
            role_start=receipt.role_start,
            role_end=receipt.role_end,
            readout_id=receipt.readout_asset_id,
            readout_version=receipt.readout_asset_version,
            readout_sha256=receipt.readout_asset_sha256,
            policy_id=receipt.projection_policy_ref,
            policy_version=receipt.projection_policy_version,
            policy_digest=receipt.policy_digest,
            normalized_axes=(),
            salience_interval=receipt.salience_interval,
            tone_interval=receipt.tone_interval,
            proof_digest=receipt.projection_proof_digest,
        )
        receipt.verify_projection_candidate(candidate)
        with self.assertRaisesRegex(ValueError, "differs"):
            receipt.verify_projection_candidate(replace(candidate, policy_digest="b" * 64))
        with self.assertRaisesRegex(ValueError, "differs"):
            receipt.verify_projection_candidate(replace(
                candidate, member_bindings=candidate.member_bindings[:1],
                then_feeling_versions=candidate.then_feeling_versions[:1],
            ))

    def test_unknown_is_explicit_and_no_direct_interval_field_exists(self):
        baseline = _baseline(with_projection=False)
        self.assertIsNone(baseline.salience_interval)
        self.assertIsNone(baseline.tone_interval)
        with self.assertRaisesRegex(ValueError, "unknown reason"):
            replace(baseline, unknown_reasons=())
        with self.assertRaises(TypeError):
            EncodingBaselineCandidateV2(
                baseline.baseline_id, baseline.source_versions,
                baseline.perspective_version, baseline.interpretation_versions,
                baseline.then_feeling_versions, baseline.as_known_at, None,
                salience_interval=(0.1, 0.2),
            )


if __name__ == "__main__":
    unittest.main()
