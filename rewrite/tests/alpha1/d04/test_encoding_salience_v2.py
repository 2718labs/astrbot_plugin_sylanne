"""Conditional numeric feature tests; no synthetic credential is treated as W01."""

from dataclasses import replace
import json
from pathlib import Path
import unittest

from sylanne3.domains.d04.affect import FeelingState
from sylanne3.domains.d04.encoding_salience_v2 import (
    D04EncodingSalienceHold, project_encoding_salience_from_joint_output_v2,
    verify_encoding_salience_from_joint_output_v2,
)
from sylanne3.domains.d04.interval_projection_v2 import (
    D04IntervalProjectionPolicyV2, D04ProjectionMemberBindingV2,
)
from sylanne3.domains.d04.joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateOutputMemberV1, JointStateOutputOriginalV1,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.native_runtime.d04_tanh_readout_asset import (
    D04LoadedTanhReadoutAsset, D04TanhReadoutRow,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


class EncodingSalienceV2Tests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[4]
        policy_data = json.loads((root / "resources/catalogue/"
                                  "d04-interval-projection-policy.v2.json").read_text())
        self.policy = D04IntervalProjectionPolicyV2(**policy_data)
        rows = tuple(D04TanhReadoutRow(
            f"output:{index}", axis, "normalized", self.policy.readout_version,
            "p=C*tanh(z)", tuple(float(position == index) for position in range(24)),
        ) for index, axis in enumerate(REGISTERED_AXIS_IDS))
        self.asset = D04LoadedTanhReadoutAsset(
            self.policy.readout_id, self.policy.readout_version, "scheme:test",
            REGISTERED_AXIS_IDS, ("normalized",) * 24, rows,
            self.policy.readout_sha256,
        )
        owner = Owner("persona", "bot", "persona")
        checkpoint = AtomKey(owner, "d04.numeric_checkpoint.v1", "block:one").token
        feeling = AtomKey(owner, "d04.feeling_state.v1", "block:one").token
        self.binding = D04ProjectionMemberBindingV2(checkpoint, 2, feeling, 2)
        coords = tuple((axis, 0.25 if index < 3 else -0.25 if index < 6 else 0.0)
                       for index, axis in enumerate(REGISTERED_AXIS_IDS))
        state = FeelingState(
            "block:one", "entity:one", "scheme:test", "operator:test", coords,
            ("meaning:one",), ("interpretation:one",), ("driver:one",),
            ("source:one",), "parameter:test", "coupling:test", 1.0, 2,
        )
        axes = tuple(JointStateAxisOutputV1(
            axis, f"output:{index}", value, value, value, 0.0,
        ) for index, (axis, value) in enumerate(coords))
        member = JointStateOutputMemberV1(
            checkpoint, 1, "a" * 64, feeling, 1, "b" * 64,
            "feeling", {}, state, axes, 0.0,
        )
        values = dict(
            schema="d04.joint-state-output.v1", namespace=NamespaceId("bot", "persona"),
            operation_id="operation:one", component_digest="c" * 64,
            graph_incarnation="incarnation:one", graph_revision=1, graph_epoch=1,
            access_epoch=1, delete_epoch=1, role_start=0.0, role_end=1.0,
            member_refs=(checkpoint,), axis_ids=REGISTERED_AXIS_IDS,
            full_transcript_sha256="d" * 64, family_transcripts=(),
            math_transcript_sha256="e" * 64, full_output_sha256="f" * 64,
            native_manifest_sha256="1" * 64, native_sha256="2" * 64,
            native_abi_version=2, policy_id="output:test", policy_version="v1",
            policy_digest="3" * 64, policy_sha256="4" * 64,
            readout_id=self.policy.readout_id,
            readout_version=self.policy.readout_version,
            readout_sha256=self.policy.readout_sha256,
            native_trajectory_error_2norm=0.0, members=(member,),
            write_set_digest="5" * 64, binary64_bits_digest="6" * 64,
        )
        self.original = JointStateOutputOriginalV1(
            **values, original_digest=canonical_digest(values),
        )

    def test_derives_fixed_features_without_caller_intervals(self):
        result = project_encoding_salience_from_joint_output_v2(
            output_original=self.original, asset=self.asset, policy=self.policy,
            member_bindings=(self.binding,),
        )
        self.assertEqual(result.salience_interval, (0.0625, 0.0625))
        self.assertEqual(result.tone_interval, (0.25, 0.25))
        self.assertTrue(verify_encoding_salience_from_joint_output_v2(
            result, output_original=self.original, asset=self.asset,
            policy=self.policy, member_bindings=(self.binding,),
        ))
        self.assertFalse(verify_encoding_salience_from_joint_output_v2(
            replace(result, tone_interval=(0.0, 0.0)),
            output_original=self.original, asset=self.asset,
            policy=self.policy, member_bindings=(self.binding,),
        ))

    def test_rejects_unbound_axis_and_readout(self):
        changed = replace(self.asset.rows[0], coefficients=(0.5, 0.5) + (0.0,) * 22)
        with self.assertRaisesRegex(D04EncodingSalienceHold, "identity tanh"):
            project_encoding_salience_from_joint_output_v2(
                output_original=self.original,
                asset=replace(self.asset, rows=(changed,) + self.asset.rows[1:]),
                policy=self.policy, member_bindings=(self.binding,),
            )
        bad_member = replace(self.original.members[0], axes=(
            replace(self.original.members[0].axes[0], certified_upper=0.75),
            *self.original.members[0].axes[1:],
        ))
        bad_values = {field: getattr(self.original, field)
                      for field in self.original.__dataclass_fields__
                      if field not in {"original_digest", "status"}}
        bad_values["members"] = (bad_member,)
        bad_original = replace(self.original, members=(bad_member,),
                               original_digest=canonical_digest(bad_values))
        with self.assertRaisesRegex(D04EncodingSalienceHold, "certified axis"):
            project_encoding_salience_from_joint_output_v2(
                output_original=bad_original, asset=self.asset, policy=self.policy,
                member_bindings=(self.binding,),
            )


if __name__ == "__main__":
    unittest.main()
