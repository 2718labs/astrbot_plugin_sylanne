"""Pure C04 V3 counterexamples; synthetic premises grant no W01 authority."""

from dataclasses import asdict, replace
import json
from pathlib import Path
import unittest

from sylanne3.domains.d04.affect import FeelingState, MoodField
from sylanne3.domains.d04.c04_projection_issuer_v3 import (
    D04C04ProjectionHold, issue_encoding_baseline_proof_v3,
    issue_current_conditioned_projection_v3,
    verify_encoding_baseline_proof_v3,
    verify_current_conditioned_projection_v3,
    conditional_encoding_baseline_contract_v3,
    conditional_current_salience_contract_v3,
)
from sylanne3.domains.d04.encoding_baseline_v2 import (
    ExactGraphRefV2, ProjectionNumericErrorV2,
)
from sylanne3.domains.d04.interval_projection_v2 import D04IntervalProjectionPolicyV2
from sylanne3.domains.d04.joint_numeric_receipt import D04JointNumericReceiptCandidateV1
from sylanne3.domains.d04.joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateOutputMemberV1, JointStateOutputOriginalV1,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d04.numeric_drive import (
    SourcedNumericDrive, numeric_drive_id, sourced_numeric_drive_write,
)
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    D04LoadedTanhReadoutAsset, D04TanhReadoutRow,
)
from sylanne3.runtime.d04_joint_advance_v2 import (
    JointNumericOriginalV1, JointNumericOriginalVerificationV1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


class C04V3PureIssuerTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[4]
        self.policy = D04IntervalProjectionPolicyV2(**json.loads((
            root / "resources/catalogue/d04-interval-projection-policy.v2.json"
        ).read_text()))
        rows = tuple(D04TanhReadoutRow(
            f"output:{index}", axis, "normalized", self.policy.readout_version,
            "p=C*tanh(z)", tuple(float(pos == index) for pos in range(24)),
        ) for index, axis in enumerate(REGISTERED_AXIS_IDS))
        self.asset = D04LoadedTanhReadoutAsset(
            self.policy.readout_id, self.policy.readout_version, "scheme:test",
            REGISTERED_AXIS_IDS, ("normalized",) * 24, rows,
            self.policy.readout_sha256,
        )
        self.namespace = NamespaceId("bot", "persona")
        self.owner = Owner("persona", "bot", "persona")
        self.source_a = source_key("bot", "persona", "a").token
        self.source_b = source_key("bot", "persona", "b").token

    def _drive(self, checkpoint: str, source: str) -> SourcedNumericDrive:
        return SourcedNumericDrive(
            numeric_drive_id(checkpoint, source, 0.0, 1.0), 1,
            checkpoint, 1, source, 1,
            access_key("bot", "persona", AtomKey.from_token(source).owner.subject).token,
            1, "mapping:test", "compiler:test", SCHEME_VERSION,
            0.0, 1.0, REGISTERED_AXIS_IDS, (0.0,) * 24,
        )

    def _member(self, name: str, source: str, level: float,
                *, mood: bool = False) -> tuple[JointStateOutputMemberV1, SourcedNumericDrive]:
        cp = AtomKey(self.owner, "d04.numeric_checkpoint.v1", name).token
        state_ref = AtomKey(self.owner, "d04.mood_field.v1" if mood
                            else "d04.feeling_state.v1", name).token
        drive = self._drive(cp, source)
        token = sourced_numeric_drive_write(drive).key.token
        coordinates = tuple((axis, level if index < 3 else -level if index < 6
                             else 0.0) for index, axis in enumerate(REGISTERED_AXIS_IDS))
        if mood:
            state = MoodField(name, "scheme:test", coordinates, (source,),
                              "parameter:test", "coupling:test", 1.0, 2)
        else:
            state = FeelingState(
                name, "entity:test", "scheme:test", "operator:test", coordinates,
                ("meaning:test",), ("interpretation:test",), (token,), (source,),
                "parameter:test", "coupling:test", 1.0, 2,
            )
        axes = tuple(JointStateAxisOutputV1(
            axis, f"output:{index}", value, value, value, 0.0,
        ) for index, (axis, value) in enumerate(coordinates))
        return JointStateOutputMemberV1(
            cp, 1, "a" * 64, state_ref, 1, "b" * 64,
            "mood" if mood else "feeling", {}, state, axes, 0.0,
        ), drive

    def _pair(self, members: tuple[JointStateOutputMemberV1, ...],
              drives: tuple[SourcedNumericDrive, ...], operation: str):
        refs = tuple(member.checkpoint_ref for member in members)
        source_rows = tuple(sorted((
            sourced_numeric_drive_write(drive).key.token, drive.drive_version,
            drive.source_ref, drive.source_revision, drive.access_ref,
            drive.access_revision, "family:test",
        ) for drive in drives))
        receipt_data = dict(
            namespace=self.namespace, component_digest="c" * 64,
            read_values_digest="0" * 64, graph_incarnation="incarnation:test",
            graph_revision=1, graph_epoch=1, access_epoch=1, delete_epoch=1,
            role_start=0.0, role_end=1.0, operator_version="operator:test",
            native_manifest_sha256="1" * 64, native_sha256="2" * 64,
            native_abi_version=2, source_versions=source_rows,
            member_refs=refs, full_transcript_sha256="d" * 64,
            family_transcripts=(), math_transcript_sha256="e" * 64,
            members=(),
        )
        receipt = D04JointNumericReceiptCandidateV1(
            **receipt_data, receipt_digest=canonical_digest(receipt_data),
        )
        error = ProjectionNumericErrorV2(0.125, 0.25, 0.0, 0.0, "f" * 64)
        verification = JointNumericOriginalVerificationV1(
            self.policy.policy_id, self.policy.version,
            canonical_digest(asdict(self.policy)), self.asset.readout_id,
            self.asset.readout_version, self.asset.asset_sha256,
            receipt.math_transcript_sha256, error,
        )
        numeric = JointNumericOriginalV1(
            refs[0], 1, operation, "9" * 64, receipt, verification,
        )
        output_data = dict(
            schema="d04.joint-state-output.v1", namespace=self.namespace,
            operation_id=operation, component_digest=receipt.component_digest,
            graph_incarnation=receipt.graph_incarnation,
            graph_revision=1, graph_epoch=1, access_epoch=1, delete_epoch=1,
            role_start=0.0, role_end=1.0, member_refs=refs,
            axis_ids=REGISTERED_AXIS_IDS,
            full_transcript_sha256=receipt.full_transcript_sha256,
            family_transcripts=(), math_transcript_sha256=receipt.math_transcript_sha256,
            full_output_sha256="3" * 64,
            native_manifest_sha256=receipt.native_manifest_sha256,
            native_sha256=receipt.native_sha256, native_abi_version=2,
            policy_id="output:test", policy_version="v1",
            policy_digest="4" * 64, policy_sha256="5" * 64,
            readout_id=self.asset.readout_id,
            readout_version=self.asset.readout_version,
            readout_sha256=self.asset.asset_sha256,
            native_trajectory_error_2norm=0.0, members=members,
            write_set_digest="6" * 64, binary64_bits_digest="7" * 64,
        )
        output = JointStateOutputOriginalV1(
            **output_data, original_digest=canonical_digest(output_data),
        )
        return output, numeric

    def _baseline(self, output, numeric, drives, source, source_revision=1):
        perspective = ExactGraphRefV2(
            AtomKey(self.owner, "d03.self_perspective.v1", "perspective:test").token, 1,
        )
        interpretation = ExactGraphRefV2(
            AtomKey(self.owner, "d07.current_interpretation.v1", "interpretation:test").token, 1,
        )
        return issue_encoding_baseline_proof_v3(
            joint_operation_id=output.operation_id,
            baseline_id="baseline:test",
            source_version=ExactGraphRefV2(source, source_revision),
            perspective_version=perspective,
            interpretation_versions=(interpretation,), as_known_at=1.0,
            output_original=output, numeric_original=numeric, drives=drives,
            asset=self.asset, policy=self.policy,
        )

    def test_source_member_selection_and_error_are_original_bound(self):
        a, da = self._member("block:a", self.source_a, 0.25)
        b, db = self._member("block:b", self.source_b, 0.5)
        output, numeric = self._pair((a, b), (da, db), "operation:encoding")
        baseline = self._baseline(output, numeric, (da, db), self.source_a)
        self.assertEqual(tuple(item.checkpoint_ref for item in baseline.feeling_bindings),
                         (a.checkpoint_ref,))
        self.assertEqual(baseline.projection.salience_interval, (0.0625, 0.0625))
        self.assertEqual(baseline.numeric_error.inherited_state_error_2norm, 0.125)
        wire = conditional_encoding_baseline_contract_v3(
            baseline, encoding_operation_id="operation:baseline", owner_epoch=1,
            access_epoch=1, delete_epoch=1,
        )
        self.assertEqual(wire.source.ref, self.source_a)
        self.assertEqual(wire.numeric_error.inherited_state_error_2norm, 0.125)
        self.assertEqual(wire.proof_digest, "sha256:" + baseline.proof_digest)
        self.assertTrue(verify_encoding_baseline_proof_v3(
            baseline, joint_operation_id=output.operation_id,
            output_original=output, numeric_original=numeric,
            drives=(da, db), asset=self.asset, policy=self.policy,
        ))
        self.assertFalse(verify_encoding_baseline_proof_v3(
            baseline, joint_operation_id="operation:other",
            output_original=output, numeric_original=numeric,
            drives=(da, db), asset=self.asset, policy=self.policy,
        ))
        with self.assertRaisesRegex(D04C04ProjectionHold, "drive index"):
            self._baseline(output, numeric, (da,), self.source_a)
        with self.assertRaisesRegex(D04C04ProjectionHold, "ordered Feeling set"):
            self._baseline(output, numeric, (da, db), self.source_b)
        with self.assertRaisesRegex(D04C04ProjectionHold, "source revision"):
            self._baseline(output, numeric, (da, db), self.source_a,
                           source_revision=2)
        self.assertFalse(verify_encoding_baseline_proof_v3(
            baseline, joint_operation_id=output.operation_id,
            output_original=output, numeric_original=numeric,
            drives=(da, db), asset=self.asset,
            policy=replace(self.policy, readout_sha256="0" * 64),
        ))
        self.assertFalse(verify_encoding_baseline_proof_v3(
            replace(baseline, numeric_error=ProjectionNumericErrorV2(
                0.0, 0.25, 0.0, 0.0, "f" * 64)),
            joint_operation_id=output.operation_id,
            output_original=output, numeric_original=numeric,
            drives=(da, db), asset=self.asset, policy=self.policy,
        ))

    def test_current_mood_changes_conditioning_not_historical_baseline(self):
        feeling, drive = self._member("block:a", self.source_a, 0.25)
        output, numeric = self._pair((feeling,), (drive,), "operation:encoding")
        baseline = self._baseline(output, numeric, (drive,), self.source_a)
        mood_low, dlow = self._member("block:mood", self.source_a, 0.0, mood=True)
        low_output, low_numeric = self._pair((mood_low,), (dlow,), "operation:mood-low")
        low = issue_current_conditioned_projection_v3(
            mood_joint_operation_id=low_output.operation_id,
            baseline=baseline, baseline_receipt_ref="receipt:baseline",
            baseline_receipt_revision=1, baseline_receipt_digest="8" * 64,
            mood_ref=mood_low.predecessor_state_ref, mood_revision=2,
            mood_output_original=low_output, mood_numeric_original=low_numeric,
            asset=self.asset, policy=self.policy,
        )
        mood_high, dhigh = self._member("block:mood", self.source_a, 0.5, mood=True)
        high_output, high_numeric = self._pair((mood_high,), (dhigh,), "operation:mood-high")
        high = issue_current_conditioned_projection_v3(
            mood_joint_operation_id=high_output.operation_id,
            baseline=baseline, baseline_receipt_ref="receipt:baseline",
            baseline_receipt_revision=1, baseline_receipt_digest="8" * 64,
            mood_ref=mood_high.predecessor_state_ref, mood_revision=2,
            mood_output_original=high_output, mood_numeric_original=high_numeric,
            asset=self.asset, policy=self.policy,
        )
        self.assertEqual(low.base_salience_interval, high.base_salience_interval)
        self.assertNotEqual(low.conditioned_salience_interval,
                            high.conditioned_salience_interval)
        self.assertTrue(verify_current_conditioned_projection_v3(
            low, mood_joint_operation_id=low_output.operation_id,
            baseline=baseline, mood_output_original=low_output,
            mood_numeric_original=low_numeric, asset=self.asset, policy=self.policy,
        ))
        self.assertFalse(verify_current_conditioned_projection_v3(
            low, mood_joint_operation_id=high_output.operation_id,
            baseline=baseline, mood_output_original=high_output,
            mood_numeric_original=high_numeric, asset=self.asset, policy=self.policy,
        ))
        baseline_wire = conditional_encoding_baseline_contract_v3(
            baseline, encoding_operation_id="operation:baseline", owner_epoch=1,
            access_epoch=1, delete_epoch=1,
        )
        current_wire = conditional_current_salience_contract_v3(
            high, baseline_contract=baseline_wire,
            operation_id="operation:recollection",
            source_closure_digest="0" * 64, audience="persona", purpose="recall",
            owner_epoch=2, access_epoch=1, delete_epoch=1,
        )
        self.assertEqual(current_wire.baseline_digest, baseline_wire.digest)
        self.assertEqual(current_wire.conditioned_tone_interval,
                         high.conditioned_tone_interval)


if __name__ == "__main__":
    unittest.main()
