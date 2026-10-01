"""The joint receipt preserves every member and one dose per source family."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from sylanne3.domains.d04.joint_numeric_receipt import (
    compile_joint_numeric_receipt_candidate_v1,
    verify_joint_numeric_receipt_candidate_v1,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d04.trusted_joint_replay import (
    D04TrustedJointReplayHold, replay_package_bound_joint_numeric_candidate_v1,
)
from sylanne3.domains.d04.numeric_drive import (
    SourcedNumericDrive, numeric_drive_id, sourced_numeric_drive_write,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.native_runtime.d04_joint_product_math import (
    D04FamilyAssignment, D04JointMemberReadout, D04JointProductMathCandidate,
)
from sylanne3.native_runtime.tanh_asset_readout import (
    D04ConditionalTanhOutputInterval, D04ConditionalTanhReadoutMath,
)
from sylanne3.runtime.joint_numeric_component import (
    JointBlockDrives, JointNumericComponentCandidate,
)
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch
from sylanne3.host.v2_installation import V2InstallationAssembly


def _case():
    namespace = NamespaceId("bot:test", "persona:test")
    owner = Owner("persona", *namespace.as_tuple)
    refs = tuple(AtomKey(owner, "d04.numeric_checkpoint.v1", f"block:{index}").token
                 for index in (1, 2))
    drives = []
    blocks = []
    for index, ref in enumerate(refs):
        source = source_key(*namespace.as_tuple, f"source:{index}").token
        access = access_key(*namespace.as_tuple, f"source:{index}").token
        drive = SourcedNumericDrive(
            numeric_drive_id(ref, source, 1.0, 2.0), 1, ref, 1,
            source, 1, access, 1, "mapping:1", "compiler:1",
            SCHEME_VERSION, 1.0, 2.0, REGISTERED_AXIS_IDS,
            (0.125,) + (0.0,) * 23,
        )
        drives.append(drive)
        blocks.append(JointBlockDrives(
            ref, GraphVersion(AtomKey.from_token(ref), 1),
            GraphVersion(AtomKey(owner, "d04.feeling_state.v1", f"block:{index}"), 1),
            (0.0,) * 24, (GraphVersion(sourced_numeric_drive_write(drive).key, 1),),
            (drive.drive,),
        ))
    source_versions = tuple(GraphVersion(AtomKey.from_token(ref), 1)
                            for drive in drives for ref in (drive.source_ref, drive.access_ref))
    component = JointNumericComponentCandidate(
        namespace, "a" * 64, QueryEpoch(namespace, "all", 4), "incarnation:1",
        8, 2, 3, 1.0, 2.0, refs, (), tuple(blocks), source_versions,
        "b" * 64, "c" * 64,
    )
    outputs = tuple(D04ConditionalTanhOutputInterval(
        f"output:{index}", axis, 0.0, 1.0,
    ) for index, axis in enumerate(REGISTERED_AXIS_IDS))
    readout = D04ConditionalTanhReadoutMath(
        "e" * 64, "readout:1", (0.0,) * 24, 0.1, (), outputs,
    )
    # Identical full/without-family intervals yield the sound [-1, 1] dose.
    effects = tuple((-1.0, 1.0) for _ in outputs)
    members = tuple(D04JointMemberReadout(
        ref, readout, (("family:shared", readout),),
        (("family:shared", effects),),
    ) for ref in refs)
    math_result = D04JointProductMathCandidate(
        component.candidate_digest, refs, None, 0.1, "1" * 64,
        (("family:shared", "2" * 64),), members, "3" * 64,
    )
    families = tuple(D04FamilyAssignment(drive.source_ref, "family:shared")
                     for drive in drives)
    return component, math_result, tuple(drives), families


class JointNumericReceiptTests(unittest.TestCase):
    def test_lock_free_replay_rejects_missing_formal_installation(self):
        component, _, drives, families = _case()
        policy = SimpleNamespace(
            namespace=component.namespace, expected_authority_id="authority:one",
            installation_id="install:one", administrator_holder="admin:one",
            manifest_digest="4" * 64,
        )
        grant = SimpleNamespace(
            authority_id=policy.expected_authority_id,
            installation_id=policy.installation_id,
            administrator_holder=policy.administrator_holder,
            manifest_digest=policy.manifest_digest,
        )
        with tempfile.TemporaryDirectory() as temporary:
            # This constructed assembly is only a negative fixture. It has no
            # administrator profile or formal release bytes to authenticate.
            installation = V2InstallationAssembly(
                policy, grant, b"", b"", lambda: None, Path(temporary),
                Path(temporary),
            )
            with self.assertRaisesRegex(D04TrustedJointReplayHold, "formal installed package"):
                replay_package_bound_joint_numeric_candidate_v1(
                    installation, component, checkpoints=(), drives=drives,
                    families=families, readout_id="readout:one",
                    max_iterations=40, tolerance=1e-5,
                )
            wrong = replace(installation, installation_grant=SimpleNamespace(
                **{**vars(grant), "manifest_digest": "5" * 64},
            ))
            with self.assertRaisesRegex(D04TrustedJointReplayHold, "grant differs"):
                replay_package_bound_joint_numeric_candidate_v1(
                    wrong, component, checkpoints=(), drives=drives,
                    families=families, readout_id="readout:one",
                    max_iterations=40, tolerance=1e-5,
                )

    def test_canonical_full_loo_and_family_dedup_with_pure_replay(self):
        component, math_result, drives, families = _case()
        inputs = dict(component=component, math_result=math_result, drives=drives,
                      families=families, operator_version="operator:1",
                      native_manifest_sha256="4" * 64, native_sha256="5" * 64,
                      native_abi_version=2)
        receipt = compile_joint_numeric_receipt_candidate_v1(**inputs)
        self.assertEqual(len(receipt.members), 2)
        self.assertEqual(len(receipt.members[0].full), 24)
        self.assertEqual(len(receipt.members[0].families), 1)
        self.assertEqual(receipt.members[0].families[0].source_refs,
                         tuple(sorted(drive.source_ref for drive in drives)))
        self.assertEqual(len(receipt.members[0].families[0].without_family), 24)
        self.assertEqual(len(receipt.members[0].families[0].contribution_doses), 24)
        self.assertEqual((receipt.graph_epoch, receipt.access_epoch, receipt.delete_epoch),
                         (4, 2, 3))
        self.assertTrue(verify_joint_numeric_receipt_candidate_v1(receipt, **inputs))
        changed = replace(receipt, access_epoch=3)
        self.assertFalse(verify_joint_numeric_receipt_candidate_v1(changed, **inputs))
        with self.assertRaisesRegex(ValueError, "cannot grant trusted adoption"):
            replace(receipt, status="trusted_current_numeric")
        self.assertFalse(verify_joint_numeric_receipt_candidate_v1(
            receipt, **{**inputs, "native_sha256": "6" * 64},
        ))


if __name__ == "__main__":
    unittest.main()
