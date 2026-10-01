"""Focused two-member operator and exact-drive gates for joint D04 math."""

from dataclasses import replace
from contextlib import ExitStack
from fractions import Fraction
import _ctypes
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from sylanne3.domains.d04.numeric_coupling import (
    FACTOR_KIND, SCHEME_VERSION, TEMPLATE, NumericCoupling, coupling_id,
    REGISTERED_AXIS_IDS,
)
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.graph_types import GraphVersion
from sylanne3.memory_types import access_key, source_key
from sylanne3.domains.d04.affect import AffectAxis, AffectScheme
from sylanne3.domains.d04.encoding_baseline import CommittedRef
from sylanne3.domains.d04.numeric_drive import SourcedNumericDrive, numeric_drive_id, sourced_numeric_drive_write
from sylanne3.domains.d04.root import NumericCheckpoint, RootAssetBindings, RootBlockIdentity
from sylanne3.native_runtime.d04_engineering_scheme import build_d04_engineering_candidate
from sylanne3.native_runtime.d04_joint_product_math import (
    D04FamilyAssignment, D04JointProductMathHold, compile_joint_matrices,
    quantize_joint_drive, run_d04_joint_product_math,
)
from sylanne3.native_runtime.loader import _runtime_target, load_production_native
from sylanne3.runtime.joint_numeric_component import JointBlockDrives, JointNumericComponentCandidate
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


def _case():
    owner = Owner("persona", "bot:one", "alice")
    left = AtomKey(owner, "d04.numeric_checkpoint.v1", "block:one").token
    right = AtomKey(owner, "d04.numeric_checkpoint.v1", "block:two").token
    refs = tuple(sorted((left, right)))
    axis = REGISTERED_AXIS_IDS[0]
    edge = NumericCoupling(
        coupling_id(refs[0], axis, refs[1], axis), 1, SCHEME_VERSION,
        refs[0], axis, refs[1], axis, TEMPLATE, FACTOR_KIND, 0.125,
        source_key("bot:one", "alice", "source:one").token, 0.0, 2.0,
    )
    operator = build_d04_engineering_candidate()
    return refs, edge, (operator.k, operator.r, operator.j, operator.a)


def _at(matrix, row, column):
    return sum((Fraction.from_float(matrix.values[pos])
                for pos in range(matrix.offsets[row], matrix.offsets[row + 1])
                if matrix.indices[pos] == column), Fraction())


class JointProductMathTests(unittest.TestCase):
    def test_two_member_psd_difference_factor_and_full_block_diagonal(self):
        refs, edge, installed = _case()
        k, r, j, a = compile_joint_matrices(installed, refs, (edge,), 0.0, 1.0)
        self.assertEqual((k.rows, r.rows, j.rows, a.rows), (48,) * 4)
        beta = Fraction(1, 8)
        self.assertEqual(_at(k, 0, 0), _at(installed[0], 0, 0) + beta)
        self.assertEqual(_at(k, 24, 24), _at(installed[0], 0, 0) + beta)
        self.assertEqual(_at(k, 0, 24), -beta)
        self.assertEqual(_at(k, 24, 0), -beta)
        # The added quadratic energy is beta*(x_left-x_right)^2.
        for left, right in ((0, 0), (1, 1), (2, -3)):
            added = beta * (left * left + right * right - 2 * left * right)
            self.assertEqual(added, beta * (left - right) ** 2)
            self.assertGreaterEqual(added, 0)
        self.assertEqual((_at(r, 0, 24), _at(j, 0, 24), _at(a, 0, 24)), (0, 0, 0))
        self.assertEqual(_at(r, 24, 24), _at(installed[1], 0, 0))

    def test_omitted_or_partial_edge_holds(self):
        refs, edge, installed = _case()
        with self.assertRaisesRegex(D04JointProductMathHold, "omits"):
            compile_joint_matrices(installed, refs, (), 0.0, 1.0)
        with self.assertRaisesRegex(D04JointProductMathHold, "interval"):
            compile_joint_matrices(installed, refs, (replace(edge, effective_until=0.5),), 0.0, 1.0)

    def test_drive_sum_quantizes_once_and_exposes_nonzero_residual(self):
        exact = quantize_joint_drive(((0.125, 0.0), (0.25, 0.0)), 2)
        self.assertEqual(exact.coordinates, (0.375, 0.0))
        self.assertEqual(exact.residuals, (0, 0))
        rounded = quantize_joint_drive(((0.1,), (0.2,)), 1)
        self.assertEqual(rounded.coordinates, (0.30000000000000004,))
        self.assertNotEqual(rounded.residuals[0], 0)

    def test_real_abi2_full_and_family_loo_with_checkpoint_bound_tanh(self):
        repository = Path(__file__).resolve().parents[4]
        native = repository / "rewrite/native/target/debug/sylanne3_kernel.dll"
        if not native.is_file():
            self.skipTest("existing ABI2 DLL is unavailable")
        source_catalogue = repository / "resources/catalogue"
        affect_raw = (source_catalogue / "d04-affect-scheme.json").read_bytes()
        operator_raw = (source_catalogue / "d04-fixed-block-operator.json").read_bytes()
        readout_raw = (source_catalogue / "d04-tanh-readout.v1.json").read_bytes()
        affect = json.loads(affect_raw)
        readout = json.loads(readout_raw)
        scheme = AffectScheme(
            affect["schema"], affect["scheme_version"], affect["operator_version"],
            affect["parameter_version"], affect["coupling_version"],
            tuple(AffectAxis(**axis) for axis in affect["axes"]),
            tuple(tuple(bounds) for bounds in affect["parameter_bounds"]),
        )
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as native_stack:
            root = Path(temporary)
            os_name, arch, libc = _runtime_target()
            native_rel = f"rewrite/sylanne3/_native/{os_name}-{arch}/sylanne3_kernel.dll"
            paths = {native_rel: native,
                     "resources/catalogue/d04-affect-scheme.json": source_catalogue / "d04-affect-scheme.json",
                     "resources/catalogue/d04-fixed-block-operator.json": source_catalogue / "d04-fixed-block-operator.json",
                     "resources/catalogue/d04-tanh-readout.v1.json": source_catalogue / "d04-tanh-readout.v1.json"}
            catalogue_rel = "resources/catalogue/current.json"
            catalogue = root / catalogue_rel
            catalogue.parent.mkdir(parents=True)
            catalogue.write_text(json.dumps({"activation_status": "candidate_only",
                "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]}}), encoding="utf-8")
            entries = []
            for relative, source in paths.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                entries.append({"path": relative, "bytes": target.stat().st_size,
                                "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
            entries.append({"path": catalogue_rel, "bytes": catalogue.stat().st_size,
                            "sha256": hashlib.sha256(catalogue.read_bytes()).hexdigest()})
            by_path = {entry["path"]: entry for entry in entries}
            manifest = {"schema_version": 1,
                "native_math": {"contract": "abi2.fixed-block-interval.v1", "capability_flags": 1},
                "platform": {"os": os_name, "arch": arch, "abi_version": 2,
                             "native_filename": native.name, "libc": libc, "cpu_features": []},
                "native": by_path[native_rel],
                "affect_scheme": {**by_path["resources/catalogue/d04-affect-scheme.json"],
                    "catalogue_capability": "d04.affect.scheme.v1",
                    **{name: affect[name] for name in ("scheme_version", "operator_version",
                                                     "parameter_version", "coupling_version")}},
                "files": entries}
            manifest_raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            (root / "release-manifest.json").write_bytes(manifest_raw)
            handle = load_production_native(root, trusted_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest())
            def unload():
                library = handle._library
                _ctypes.FreeLibrary(library._handle)
                library._handle = 0
            native_stack.callback(unload)
            bindings = RootAssetBindings(
                scheme.scheme_version, scheme.operator_version, scheme.parameter_version,
                scheme.coupling_version, readout["readout_version"],
                hashlib.sha256(affect_raw).hexdigest(), hashlib.sha256(operator_raw).hexdigest(),
                "c" * 64, "d" * 64, hashlib.sha256(readout_raw).hexdigest(),
            )
            refs, edge, _ = _case()
            namespace = NamespaceId("bot:one", "alice")
            checkpoints = []
            drives = []
            blocks = []
            for index, ref in enumerate(refs):
                block_id = AtomKey.from_token(ref).name
                state_ref = AtomKey(Owner("persona", "bot:one", "alice"),
                                    "d04.feeling_state.v1", block_id).token
                cp = NumericCheckpoint(
                    f"checkpoint:{index}", namespace.as_tuple,
                    RootBlockIdentity(block_id, "template:one", "feeling",
                                      "person:one", "meaning:one", f"source:{index}"),
                    bindings, bindings.digest, REGISTERED_AXIS_IDS, (1.0,) * 24,
                    ((1.0, 1.0),) * 24, 0.0, "trusted_initial_box", "f" * 64,
                    0.0, CommittedRef(state_ref, 1), "1" * 64, "operation:test",
                    "none", None,
                )
                source_ref = source_key(*namespace.as_tuple, f"source:{index}").token
                values = (0.125,) + (0.0,) * 23
                drive = SourcedNumericDrive(
                    numeric_drive_id(ref, source_ref, 0.0, 0.01), 1, ref, 1,
                    source_ref, 1, access_key(*namespace.as_tuple, f"source:{index}").token,
                    1, "mapping:one", "compiler:one", scheme.scheme_version,
                    0.0, 0.01, REGISTERED_AXIS_IDS, values,
                )
                checkpoints.append(cp)
                drives.append(drive)
                blocks.append(JointBlockDrives(
                    ref, GraphVersion(AtomKey.from_token(ref), 1),
                    GraphVersion(AtomKey.from_token(state_ref), 1), cp.latent_state,
                    (GraphVersion(sourced_numeric_drive_write(drive).key, 1),), (values,),
                ))
            component = JointNumericComponentCandidate(
                namespace, "a" * 64, QueryEpoch(namespace, "all", 1), "incarnation:test",
                1, 1, 1, 0.0, 0.01, refs, (edge,), tuple(blocks), (),
                "b" * 64, "c" * 64,
            )
            result = run_d04_joint_product_math(
                handle, root, scheme, component, checkpoints=tuple(checkpoints),
                drives=tuple(drives),
                families=(D04FamilyAssignment(drives[0].source_ref, "family:one"),
                          D04FamilyAssignment(drives[1].source_ref, "family:two")),
                readout_id=readout["readout_id"], max_iterations=40, tolerance=1e-5,
            )
            self.assertEqual(len(result.full_step.previous), 48)
            self.assertIsNotNone(result.full_transcript)
            self.assertNotEqual(result.full_transcript.output,
                                result.full_step.iterate)
            self.assertEqual(result.full_transcript.output[:24],
                             result.members[0].full.state_centers)
            self.assertEqual(result.full_transcript.output[24:],
                             result.members[1].full.state_centers)
            self.assertEqual(len(result.family_transcripts), 2)
            self.assertEqual(len(result.members), 2)
            self.assertTrue(all(len(member.full.outputs) == 24 and len(member.effects) == 2
                                for member in result.members))
            self.assertEqual(result.status, "conditional_math_hold_for_fenced_graph_and_joint_adoption")
