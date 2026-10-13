"""Pure cold verification of authenticated D04 native transcripts.

No native loader, solver or initial-box FFI is called here. Native outputs and
bounds must first be authenticated by the independent execution terminal;
this module reconstructs their exact models and every deterministic readout.
The result is still an unregistered candidate, never a content/write permit.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from ..domains.d04.numeric_drive import sourced_numeric_drive_write
from ..domains.d04.joint_numeric_receipt import compile_joint_numeric_receipt_candidate_v1
from ..domains.d04.joint_state_output_v1 import (
    _derive_joint_state_outputs_v1, joint_checkpoint_payload_v1,
)
from ..domains.d04.projection_issuer_v2 import load_installed_d04_projection_assets_v2
from ..domains.d04.trusted_joint_replay import D04InstalledJointNumericReplayV1, _numeric_error_from_replay
from ..graph_types import AtomKey
from ..host.affect_scheme_asset import load_verified_affect_scheme
from ..host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
from ..host.installed_d04_output_policy import load_installed_d04_output_policy_v1
from ..host.installed_package import _safe_file
from ..host.v2_installation import V2InstallationAssembly
from ..memory_types import SourceRecord
from ..runtime.d04_joint_product_assembly_v3 import D04InstalledJointProductV3
from ..runtime.d04_numeric_artifact_v3 import (
    D04NumericArtifactHold, decode_d04_numeric_prepared_input_v3, verify_d04_numeric_artifact_commitments_v3,
    numeric_artifact_payload_v3,
)
from ..runtime.d04_semantic_mapping_v3 import evidence_payload_v3
from ..runtime_contracts import NamespaceId, canonical_digest
from .abi2 import ABI2_FIXED_BLOCK_INTERVAL_V1
from .d04_candidate import _matrix
from .d04_joint_product_math import (
    D04JointMemberReadout, D04JointProductMathCandidate, compile_joint_matrices, quantize_joint_drive,
)
from .fixed_block_transcript import FixedBlockStep, _digest, _same_float_bits
from .loader import NativeLoadBinding
from .tanh_asset_readout import run_d04_conditional_tanh_readout_math
from .tanh_interval import _outward_binary64


@dataclass(frozen=True, slots=True)
class D04PinnedReplayAssetsV3:
    """Public mathematical premises, never an installation/Owner credential.

    Useful to independently revalidate a durable artifact in a cold process.
    This does not register its output with the trusted-replay issuer.
    """
    package_root: Path
    namespace: NamespaceId
    installation_id: str
    manifest_sha256: str
    available_cpu_features: frozenset[str] | None = None

    def __post_init__(self):
        if (not isinstance(self.package_root, Path) or not self.package_root.is_absolute()
                or type(self.namespace) is not NamespaceId or not self.installation_id
                or type(self.manifest_sha256) is not str or len(self.manifest_sha256) != 64
                or any(char not in "0123456789abcdef" for char in self.manifest_sha256)):
            raise D04NumericArtifactHold("cold mathematical asset premises differ")


def _same(left, right):
    return evidence_payload_v3(left) == evidence_payload_v3(right)


def _listed_json(root, manifest, relative):
    path = _safe_file(root, relative)
    matches = [row for row in manifest["files"] if row["path"] == relative]
    if path is None or len(matches) != 1:
        raise D04NumericArtifactHold("cold numeric asset is absent or unsafe")
    raw = path.read_bytes()
    if len(raw) != matches[0]["bytes"] or hashlib.sha256(raw).hexdigest() != matches[0]["sha256"]:
        raise D04NumericArtifactHold("cold numeric asset changed after verification")
    return json.loads(raw), matches[0]["sha256"]


def _check_component(preparation):
    current, snapshot = preparation.current, preparation.snapshot
    component = current.component
    atoms = {atom.key.token: atom for atom in snapshot.atoms}
    selected = []
    for version in component.read_versions:
        atom = atoms.get(version.key.token)
        if atom is None or atom.revision != version.revision:
            raise D04NumericArtifactHold("cold component dependency is missing")
        selected.append((atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid))
    if len({row[0] for row in selected}) != len(selected):
        raise D04NumericArtifactHold("cold component has duplicate dependencies")
    values_digest = canonical_digest(tuple(sorted(selected)))
    binding = (component.namespace.as_tuple, component.catalogue_hash, component.query_epoch.revision,
        component.graph_incarnation, component.graph_revision, component.access_epoch, component.delete_epoch,
        component.role_start, component.role_end, tuple(sorted(component.checkpoint_refs)),
        tuple(edge.edge_id for edge in component.edges), values_digest, component.root_original_digest)
    if component.root_original_digest is not None:
        binding += (tuple((block.checkpoint_ref, block.predecessor_receipt_digest) for block in component.block_drives),)
    if (component.query_epoch.namespace != component.namespace or component.query_epoch.scope_ref != "all"
            or component.read_values_digest != values_digest or component.candidate_digest != canonical_digest(binding)
            or component.checkpoint_refs != tuple(sorted(set(component.checkpoint_refs)))
            or len(component.checkpoint_refs) < 2 or component.status != "hold"
            or len(current.checkpoints) != len(component.checkpoint_refs)
            or tuple(block.checkpoint_ref for block in component.block_drives) != component.checkpoint_refs):
        raise D04NumericArtifactHold("cold component complete frozen identity differs")
    for ref, cp, block in zip(component.checkpoint_refs, current.checkpoints, component.block_drives):
        atom = atoms.get(ref)
        if (atom is None or not atom.valid or atom.revision != block.checkpoint_version.revision
                or atom.value != joint_checkpoint_payload_v1(cp)
                or cp.namespace != component.namespace.as_tuple or cp.axes != REGISTERED_AXIS_IDS
                or cp.cursor != component.role_start or not _same_float_bits(cp.latent_state, block.initial_state)):
            raise D04NumericArtifactHold("cold checkpoint differs from frozen graph original")
    expected = {(version.key.token, version.revision): (block, drive)
                for block in component.block_drives for version, drive in zip(block.drive_versions, block.drives)}
    if (any(len(block.drive_versions) != len(block.drives) for block in component.block_drives)
            or len(expected) != sum(len(block.drives) for block in component.block_drives)
            or len(current.drives) != len(expected) or not current.drives):
        raise D04NumericArtifactHold("cold drive inventory is incomplete")
    seen = set()
    for drive in current.drives:
        write = sourced_numeric_drive_write(drive)
        key = (write.key.token, drive.drive_version)
        if key not in expected or key in seen:
            raise D04NumericArtifactHold("cold drive identity is duplicated or foreign")
        seen.add(key)
        block, values = expected[key]
        atom = atoms.get(write.key.token)
        if (atom is None or not atom.valid or atom.revision != drive.drive_version or atom.value != write.value
                or drive.checkpoint_ref != block.checkpoint_ref or drive.checkpoint_revision != block.checkpoint_version.revision
                or (drive.role_start, drive.role_end) != (component.role_start, component.role_end)
                or not _same_float_bits(drive.drive, values)):
            raise D04NumericArtifactHold("cold drive differs from frozen original")
    family_map = {row.source_ref: row.family_id for row in current.families}
    if len(family_map) != len(current.families) or set(family_map) != {drive.source_ref for drive in current.drives}:
        raise D04NumericArtifactHold("cold source-family coverage differs")
    for ref, family in family_map.items():
        atom = atoms.get(ref)
        if atom is None or not atom.valid or SourceRecord.from_dict(atom.value).provenance_root != family:
            raise D04NumericArtifactHold("cold source family differs from original")
    return family_map


def _verify_transcript(transcript, expected_step, native_binding):
    if (transcript is None or not _same(transcript.input, expected_step)
            or transcript.production_binding != native_binding
            or transcript.input_sha256 != expected_step.digest()
            or len(transcript.output) != len(expected_step.previous)
            or not all(type(value) is float and math.isfinite(value) for value in transcript.output)
            or transcript.output_sha256 != _digest(transcript.output)):
        raise D04NumericArtifactHold("cold native transcript model/output binding differs")
    bounds = transcript.bounds
    if (type(bounds.status) is not int or bounds.status != 0
            or type(bounds.certificate_flags) is not int or bounds.certificate_flags != ABI2_FIXED_BLOCK_INTERVAL_V1
            or type(bounds.iterations) is not int or not 0 <= bounds.iterations <= expected_step.max_iterations
            or any(type(getattr(bounds, name)) not in (float, int) or not math.isfinite(getattr(bounds, name))
                   or getattr(bounds, name) < 0 for name in ("residual", "iteration_error", "time_defect",
                       "trajectory_error", "energy_balance_defect", "q_upper", "boundary_eta"))
            or not math.isfinite(bounds.energy_before) or not math.isfinite(bounds.energy_after)
            or bounds.q_upper > 0.8 or bounds.boundary_eta != 0):
        raise D04NumericArtifactHold("cold native interval bounds/status are invalid")
    digest = _digest({"schema": "abi2.fixed-block-math-transcript.v1",
        "input_sha256": transcript.input_sha256, "output_sha256": transcript.output_sha256,
        "manifest_sha256": native_binding.manifest_sha256, "native_sha256": native_binding.native_sha256,
        "bounds": {field.name: getattr(bounds, field.name) for field in fields(bounds)}})
    if transcript.transcript_sha256 != digest:
        raise D04NumericArtifactHold("cold native transcript digest differs")


def revalidate_d04_numeric_artifact_v3(prepared, terminal, raw, installation):
    """Reconstruct an UNREGISTERED product from terminal-bound complete bytes.

    This pure verifier does not authenticate a supplied terminal or register
    its return. Only the concrete service/paired-port restoration factory may
    turn this result into a process-local trusted replay witness.
    """
    from ..authority_service.d04_numeric_contract_v3 import D04NumericTerminalV3
    if (type(installation) not in {V2InstallationAssembly, D04PinnedReplayAssetsV3}
            or type(terminal) is not D04NumericTerminalV3
            or terminal.binding != prepared.binding or terminal.measurement.status != "completed"):
        raise D04NumericArtifactHold("cold numeric installation/terminal differs")
    binding = prepared.binding
    root = installation.package_root
    if type(installation) is V2InstallationAssembly:
        premises = (installation.installation_policy.namespace, installation.installation_policy.installation_id,
                    installation.installation_policy.manifest_digest, installation.installation_grant.manifest_digest)
    else:
        premises = (installation.namespace, installation.installation_id, installation.manifest_sha256, installation.manifest_sha256)
    if premises != (binding.namespace, binding.installation_id, binding.native_manifest_sha256, binding.native_manifest_sha256):
        raise D04NumericArtifactHold("cold numeric installation is not the original executor")
    identity = read_installed_d04_numeric_identity_v3(root, binding.native_manifest_sha256)
    if any(getattr(binding, key) != value for key, value in identity.items()):
        raise D04NumericArtifactHold("cold numeric algorithm/native/output build differs")
    artifact = verify_d04_numeric_artifact_commitments_v3(prepared, terminal.claim, terminal.measurement, raw)
    decoded = decode_d04_numeric_prepared_input_v3(prepared)
    preparation = decoded.preparation
    current, component = preparation.current, preparation.current.component
    family_map = _check_component(preparation)
    family_ids = tuple(sorted(set(family_map.values())))
    if family_ids != binding.family_roots:
        raise D04NumericArtifactHold("cold complete family set differs from signed binding")
    manifest_raw = (root / "release-manifest.json").read_bytes()
    if hashlib.sha256(manifest_raw).hexdigest() != binding.native_manifest_sha256:
        raise D04NumericArtifactHold("cold manifest changed after qualification")
    manifest = json.loads(manifest_raw)
    affect, affect_sha = _listed_json(root, manifest, "resources/catalogue/d04-affect-scheme.json")
    operator, operator_sha = _listed_json(root, manifest, "resources/catalogue/d04-fixed-block-operator.json")
    scheme = load_verified_affect_scheme(root, binding.native_manifest_sha256,
        available_cpu_features=installation.available_cpu_features).scheme
    cp_assets = current.checkpoints[0].assets
    versions = ("scheme_version", "operator_version", "parameter_version", "coupling_version")
    if (len({cp.assets for cp in current.checkpoints}) != 1 or len({cp.asset_digest for cp in current.checkpoints}) != 1
            or cp_assets.scheme_sha256 != affect_sha or cp_assets.operator_sha256 != operator_sha
            or cp_assets.parameter_sha256 != canonical_digest(affect.get("parameter_bounds"))
            or cp_assets.coupling_sha256 != canonical_digest(operator.get("operator", {}).get("j"))
            or any(getattr(scheme, key) != affect.get(key) or getattr(scheme, key) != operator.get(key)
                   or getattr(cp_assets, key) != getattr(scheme, key) for key in versions)
            or operator.get("axis_ids") != list(REGISTERED_AXIS_IDS)
            or operator.get("parameter_bounds") != [list(row) for row in scheme.parameter_bounds]):
        raise D04NumericArtifactHold("cold checkpoint/operator/scheme assets differ")
    raw_operator = operator.get("operator")
    if type(raw_operator) is not dict or set(raw_operator) != {"k", "r", "j", "a", "alpha"}:
        raise D04NumericArtifactHold("cold installed operator is incomplete")
    matrices = compile_joint_matrices(tuple(_matrix(raw_operator[key]) for key in ("k", "r", "j", "a")),
        component.checkpoint_refs, component.edges, component.role_start, component.role_end)
    alpha = tuple(float(value) for value in raw_operator["alpha"])
    if len(alpha) != 24 or any(not math.isfinite(value) or value < 0 for value in alpha):
        raise D04NumericArtifactHold("cold installed nonlinear coefficients differ")
    projection_policy, readout = load_installed_d04_projection_assets_v2(root, binding.native_manifest_sha256,
        installation.available_cpu_features)
    output_policy = load_installed_d04_output_policy_v1(root, binding.native_manifest_sha256,
        require_formal=False, require_backend_runtime=True)
    if (readout.asset_sha256 != cp_assets.readout_sha256 or readout.readout_version != cp_assets.readout_version
            or readout.scheme_version != scheme.scheme_version or readout.axis_ids != REGISTERED_AXIS_IDS
            or output_policy.policy.digest != binding.output_policy_digest):
        raise D04NumericArtifactHold("cold readout/output policy differs")
    result = artifact.math_result
    refs = component.checkpoint_refs
    if (result.component_digest != component.candidate_digest or result.member_refs != refs
            or result.full_step is None or result.full_transcript is None
            or tuple(family for family, _ in result.family_transcript_originals) != family_ids):
        raise D04NumericArtifactHold("cold full/LOO native coverage differs")
    previous = tuple(value for cp in current.checkpoints for value in cp.latent_state)
    radius_squared = Fraction()
    for cp in current.checkpoints:
        for center, (lower, upper) in zip(cp.latent_state, cp.certified_box):
            radius = max(abs(Fraction.from_float(float(center)) - Fraction.from_float(float(lower))),
                         abs(Fraction.from_float(float(upper)) - Fraction.from_float(float(center))))
            radius_squared += radius * radius
    inherited_squared = sum((Fraction.from_float(float(cp.numeric_error_bound)) ** 2 for cp in current.checkpoints), Fraction())
    if (type(result.initial_error) is not float or not math.isfinite(result.initial_error) or result.initial_error < 0
            or Fraction.from_float(result.initial_error) ** 2 < max(radius_squared, inherited_squared)):
        raise D04NumericArtifactHold("cold initial/inherited error does not enclose original boxes")
    offsets = {ref: index * 24 for index, ref in enumerate(refs)}
    source_rows = []
    for drive in current.drives:
        values = [0.0] * len(previous)
        values[offsets[drive.checkpoint_ref]:offsets[drive.checkpoint_ref] + 24] = drive.drive
        source_rows.append((family_map[drive.source_ref], tuple(values)))
    def aggregate(omitted):
        quantized = quantize_joint_drive(tuple(values for family, values in source_rows if family != omitted), len(previous))
        if any(quantized.residuals):
            raise D04NumericArtifactHold("cold drive sum needs an unsupported input-error bound")
        return quantized.coordinates
    request = json.loads(prepared.input_payload_json)["numeric_request"]
    if request["max_iterations"] != decoded.numeric_policy.max_iterations:
        raise D04NumericArtifactHold("cold numeric iteration policy differs")
    from .d04_fixed_trajectory_v2 import fixed_d04_step_plan_v2, verify_d04_fixed_trajectory_v2
    plan = fixed_d04_step_plan_v2(component.role_start, component.role_end)
    step = FixedBlockStep(*matrices, alpha * len(refs), previous, aggregate(None), previous,
        plan[0], result.initial_error,
        decoded.numeric_policy.max_iterations, decoded.numeric_policy.tolerance)
    native = NativeLoadBinding(binding.native_manifest_sha256, binding.native_sha256,
        manifest["platform"]["os"], manifest["platform"]["arch"], manifest["platform"].get("libc"), 2)
    def verify_chain(chain, first):
        verify_d04_fixed_trajectory_v2(chain, first=first, step_plan=plan)
        expected = first
        for actual, duration in zip(chain.steps, plan):
            expected = replace(expected, h=duration)
            _verify_transcript(actual, expected, native)
            expected = replace(first, h=duration, previous=actual.output, iterate=actual.output,
                previous_error=actual.bounds.trajectory_error)
        # The structural verifier above checks the exact next duration and
        # inherited state/error; no detached result can reset an interior step.
    verify_chain(result.full_transcript, step)
    if not _same(result.full_step, step):
        raise D04NumericArtifactHold("cold declared first full model differs")
    for family, transcript in result.family_transcript_originals:
        verify_chain(transcript, replace(step, drive=aggregate(family)))
    full, branches = result.full_transcript, result.family_transcript_originals
    members = []
    for index, ref in enumerate(refs):
        section = slice(index * 24, (index + 1) * 24)
        full_read = run_d04_conditional_tanh_readout_math(readout, full.output[section], full.final_error)
        absent = tuple((family, run_d04_conditional_tanh_readout_math(readout,
            branch.output[section], branch.final_error)) for family, branch in branches)
        effects = tuple((family, tuple((
            _outward_binary64(Fraction.from_float(lhs.lower) - Fraction.from_float(rhs.upper), lower=True),
            _outward_binary64(Fraction.from_float(lhs.upper) - Fraction.from_float(rhs.lower), lower=False))
            for lhs, rhs in zip(full_read.outputs, missing.outputs))) for family, missing in absent)
        members.append(D04JointMemberReadout(ref, full_read, absent, effects))
    math_digest = _digest({"schema": "d04.joint-product-conditional-math.v2", "component": component.candidate_digest,
        "members": refs, "assets": current.checkpoints[0].asset_digest, "readout": readout.asset_sha256,
        "step": step.digest(), "initial_error": result.initial_error, "full": full.transcript_sha256,
        "without": tuple((family, branch.transcript_sha256) for family, branch in branches),
        "effects": tuple((member.checkpoint_ref, member.effects) for member in members)})
    expected = D04JointProductMathCandidate(component.candidate_digest, refs, step, result.initial_error,
        full.transcript_sha256, tuple((family, branch.transcript_sha256) for family, branch in branches),
        tuple(members), math_digest, full_transcript=full, family_transcript_originals=branches)
    # Both sides retain the fully verified fixed-model chains. Compare their
    # formal compact codec instead of expanding every shared matrix per step.
    if numeric_artifact_payload_v3(result) != numeric_artifact_payload_v3(expected):
        raise D04NumericArtifactHold("cold deterministic full/LOO readouts or effects differ")
    candidate = compile_joint_numeric_receipt_candidate_v1(component=component, math_result=expected,
        drives=current.drives, families=current.families, operator_version=scheme.operator_version,
        native_manifest_sha256=binding.native_manifest_sha256, native_sha256=binding.native_sha256, native_abi_version=2)
    error = _numeric_error_from_replay(candidate, expected, projection_policy, readout.rows)
    replay = D04InstalledJointNumericReplayV1(root, component, current.checkpoints, current.drives, current.families,
        candidate, expected, projection_policy, readout, error)
    output = _derive_joint_state_outputs_v1(replay, preparation.predecessors, output_policy.policy, output_policy.policy_sha256)
    if not _same(output, artifact.output) or output.original_digest != terminal.measurement.output_original_digest:
        raise D04NumericArtifactHold("cold deterministic state output differs from actual terminal")
    return D04InstalledJointProductV3(preparation, replay, output)
