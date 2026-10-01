"""Narrow, unsigned D04 interval projection math checks."""

from dataclasses import replace
import unittest

from sylanne3.domains.d04.interval_projection_v2 import (
    D04IntervalProjectionHold, D04IntervalProjectionPolicyV2,
    D04ProjectionMemberBindingV2, D04VerifiedBaselineIntervalPremiseV2,
    D04VerifiedMoodIntervalPremiseV2, condition_verified_baseline_for_recollection_v2,
    project_joint_interval_candidate_v2,
)
from sylanne3.domains.d04.joint_numeric_receipt import (
    D04JointMemberNumericResultV1, D04JointNumericReceiptCandidateV1,
    D04NumericOutputIntervalV1,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    D04LoadedTanhReadoutAsset, D04TanhReadoutRow,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


def _case(values=None, second_values=None):
    axes = REGISTERED_AXIS_IDS
    if values is None:
        values = ((0.5, 0.5),) * len(axes)
    rows = tuple(D04TanhReadoutRow(
        f"p:{axis}", axis, "normalized", "readout:1", "p=C*tanh(z)",
        tuple(1.0 if column == index else 0.0 for column in range(len(axes))),
    ) for index, axis in enumerate(axes))
    asset = D04LoadedTanhReadoutAsset(
        "readout:1", "readout:1", "scheme:1", axes,
        ("normalized",) * len(axes), rows, "a" * 64,
    )
    full = tuple(D04NumericOutputIntervalV1(
        axis, f"p:{axis}", *bounds,
    ) for axis, bounds in zip(axes, values))
    owner = Owner("persona", "bot", "persona")
    refs = tuple(AtomKey(owner, "d04.numeric_checkpoint.v1", f"block:{index}").token
                 for index in (1, 2))
    second_full = full if second_values is None else tuple(D04NumericOutputIntervalV1(
        axis, f"p:{axis}", *bounds,
    ) for axis, bounds in zip(axes, second_values))
    members = (D04JointMemberNumericResultV1(refs[0], full, ()),
               D04JointMemberNumericResultV1(refs[1], second_full, ()))
    identity = dict(
        namespace=NamespaceId("bot", "persona"), component_digest="b" * 64,
        read_values_digest="c" * 64, graph_incarnation="incarnation:1",
        graph_revision=8, graph_epoch=7, access_epoch=6, delete_epoch=5,
        role_start=1.0, role_end=2.0, operator_version="operator:1",
        native_manifest_sha256="d" * 64, native_sha256="e" * 64,
        native_abi_version=2, source_versions=(), member_refs=refs,
        full_transcript_sha256="f" * 64, family_transcripts=(),
        math_transcript_sha256="0" * 64, members=members,
    )
    receipt = D04JointNumericReceiptCandidateV1(
        **identity, receipt_digest=canonical_digest(identity),
    )
    policy = D04IntervalProjectionPolicyV2(
        "projection:1", asset.readout_id, asset.readout_version,
        asset.asset_sha256, 2.0, 1.0,
    )
    return receipt, asset, policy


def _selection(receipt, count=1):
    owner = Owner("persona", "bot", "persona")
    bindings = tuple(D04ProjectionMemberBindingV2(
        ref, 1, AtomKey(owner, "d04.feeling_state.v1", f"block:{index}").token, 2,
    ) for index, ref in enumerate(receipt.member_refs[:count], 1))
    versions = tuple(GraphVersion(AtomKey.from_token(binding.feeling_ref),
                                  binding.feeling_revision) for binding in bindings)
    return dict(member_bindings=bindings, then_feeling_versions=versions)


class IntervalProjectionTests(unittest.TestCase):
    def test_cross_zero_absolute_salience_and_gain_loss_contrast(self):
        values = ((-0.25, 0.5), (0.25, 0.5), (0.25, 0.5),
                  (0.5, 0.5), (0.5, 0.5), (0.5, 0.5)) + ((0.5, 0.5),) * 18
        receipt, asset, policy = _case(values)
        candidate = project_joint_interval_candidate_v2(
            receipt=receipt, asset=asset, policy=policy, **_selection(receipt),
        )
        self.assertEqual(candidate.normalized_axes[0].lower, -0.25)
        self.assertEqual(candidate.salience_interval, (11.0 / 24.0, 12.0 / 24.0))
        self.assertEqual(candidate.tone_interval, (-5.0 / 24.0, 0.0))
        self.assertEqual(candidate.semantic_calibration, "unvalidated")
        self.assertEqual(candidate.status, "unsigned_hold_for_w01_projection_issuer")

    def test_encoding_baseline_is_stable_across_two_recall_moods(self):
        receipt, asset, policy = _case()
        policy = replace(policy, mood_salience_gain=-1.0, mood_tone_gain=-1.0)
        encoding = project_joint_interval_candidate_v2(
            receipt=receipt, asset=asset, policy=policy, **_selection(receipt),
        )
        baseline = D04VerifiedBaselineIntervalPremiseV2(
            receipt.namespace, "baseline:one", 1, "2" * 64,
            encoding.proof_digest, encoding.policy_digest, asset.asset_sha256,
            encoding.salience_interval, encoding.tone_interval,
        )
        mood = D04VerifiedMoodIntervalPremiseV2(
            receipt.namespace, "checkpoint:mood", "1" * 64,
            receipt.graph_incarnation, receipt.graph_revision,
            receipt.graph_epoch, receipt.access_epoch, receipt.delete_epoch,
            receipt.role_start, receipt.role_end, (0.75, 1.0), (0.75, 1.0),
        )
        first = condition_verified_baseline_for_recollection_v2(
            baseline=baseline, mood=mood, policy=policy,
        )
        second_mood = replace(mood, numeric_receipt_digest="3" * 64,
                              salience_interval=(0.25, 0.25),
                              tone_interval=(-0.5, -0.5))
        second = condition_verified_baseline_for_recollection_v2(
            baseline=baseline, mood=second_mood, policy=policy,
        )
        self.assertEqual(encoding.salience_interval, (0.5, 0.5))
        self.assertEqual(encoding.tone_interval, (0.0, 0.0))
        self.assertEqual(first.salience_interval, (0.0, 0.0))
        self.assertEqual(first.tone_interval, (-1.0, -0.75))
        self.assertEqual(second.salience_interval, (0.25, 0.25))
        self.assertEqual(second.tone_interval, (0.5, 0.5))
        self.assertNotEqual(first.proof_digest, second.proof_digest)
        self.assertEqual(baseline.projection_proof_digest, encoding.proof_digest)
        self.assertEqual(encoding.stage, "encoding_baseline")
        self.assertEqual(first.stage, "recollection_current_mood_conditioned")
        with self.assertRaisesRegex(D04IntervalProjectionHold, "identity differs"):
            condition_verified_baseline_for_recollection_v2(
                baseline=replace(baseline, policy_digest="0" * 64),
                mood=mood, policy=policy,
            )

    def test_preclip_width_and_identity_hold(self):
        values = ((-5.0, 5.0),) + ((0.5, 0.5),) * 23
        receipt, asset, policy = _case(values)
        with self.assertRaisesRegex(D04IntervalProjectionHold, "axis interval is too wide"):
            project_joint_interval_candidate_v2(
                receipt=receipt, asset=asset, policy=policy,
                **_selection(receipt),
            )
        receipt, asset, policy = _case(((0.0, 1.0),) * 24)
        with self.assertRaisesRegex(D04IntervalProjectionHold, "projected interval is too wide"):
            project_joint_interval_candidate_v2(
                receipt=receipt, asset=asset,
                policy=replace(policy, max_projection_width=0.5),
                **_selection(receipt),
            )
        with self.assertRaisesRegex(D04IntervalProjectionHold, "identity differs"):
            project_joint_interval_candidate_v2(
                receipt=replace(receipt, access_epoch=10), asset=asset,
                policy=policy, **_selection(receipt),
            )

    def test_readout_row_l1_norm_is_applied_before_aggregation(self):
        receipt, asset, policy = _case(((1.0, 1.0),) + ((0.0, 0.0),) * 23)
        row = replace(asset.rows[0], coefficients=(2.0,) + (0.0,) * 23)
        asset = replace(asset, rows=(row,) + asset.rows[1:])
        candidate = project_joint_interval_candidate_v2(
            receipt=receipt, asset=asset, policy=policy,
            **_selection(receipt),
        )
        self.assertEqual(candidate.normalized_axes[0].lower, 0.5)
        self.assertLessEqual(candidate.salience_interval[0], 0.5 / 24)
        self.assertGreaterEqual(candidate.salience_interval[1], 0.5 / 24)

    def test_all_baseline_blocks_aggregate_and_omission_holds(self):
        first = ((0.0, 0.0),) * 24
        second = ((1.0, 1.0),) * 3 + ((0.0, 0.0),) * 21
        receipt, asset, policy = _case(first, second)
        one = project_joint_interval_candidate_v2(
            receipt=receipt, asset=asset, policy=policy, **_selection(receipt),
        )
        two = project_joint_interval_candidate_v2(
            receipt=receipt, asset=asset, policy=policy, **_selection(receipt, 2),
        )
        self.assertEqual(one.salience_interval, (0.0, 0.0))
        self.assertEqual(one.tone_interval, (0.0, 0.0))
        self.assertEqual(two.salience_interval, (3.0 / 48.0, 3.0 / 48.0))
        self.assertEqual(two.tone_interval, (3.0 / 12.0, 3.0 / 12.0))
        self.assertEqual(len(two.normalized_axes), 48)
        self.assertEqual(tuple(row.checkpoint_ref for row in two.normalized_axes[::24]),
                         receipt.member_refs)
        self.assertEqual(tuple(item.checkpoint_revision for item in two.member_bindings),
                         (1, 1))
        self.assertNotEqual(one.proof_digest, two.proof_digest)
        selection = _selection(receipt, 2)
        with self.assertRaisesRegex(D04IntervalProjectionHold, "omit or reorder"):
            project_joint_interval_candidate_v2(
                receipt=receipt, asset=asset, policy=policy,
                member_bindings=selection["member_bindings"][:1],
                then_feeling_versions=selection["then_feeling_versions"],
            )


if __name__ == "__main__":
    unittest.main()
