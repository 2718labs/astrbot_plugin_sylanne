"""Lock-free D04 joint replay from an already authenticated installation.

W01 supplies the frozen graph read and the V2 installation assembly obtained
from the administrator profile and Authority channel. This function verifies
the installed formal package again, runs full/LOO ABI2 math, and returns only
an unsigned candidate. W01 must recheck the read set and adopt atomically.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from weakref import WeakValueDictionary, finalize
from typing import TYPE_CHECKING

from ...host.affect_scheme_asset import load_verified_affect_scheme
from ...host.installed_package import verify_installed_backend_runtime_v1
from ...host.v2_installation import V2InstallationAssembly
from ...native_runtime.d04_joint_product_math import (
    D04FamilyAssignment, D04JointProductMathCandidate, D04JointProductMathHold,
    run_d04_joint_product_math,
)
from ...native_runtime.loader import NativeLoadError, load_production_native
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ...native_runtime.tanh_interval import _outward_binary64
from ...runtime.joint_numeric_component import JointNumericComponentCandidate
from ...runtime_contracts import canonical_digest
from .encoding_baseline_v2 import ProjectionNumericErrorV2
from .interval_projection_v2 import D04IntervalProjectionPolicyV2
from .joint_numeric_receipt import (
    D04JointNumericReceiptCandidateV1, D04JointNumericReceiptHold,
    compile_joint_numeric_receipt_candidate_v1,
)
from .numeric_drive import SourcedNumericDrive
from .projection_issuer_v2 import (
    D04ProjectionIssuerHold, load_installed_d04_projection_assets_v2,
)
from .root import NumericCheckpoint

if TYPE_CHECKING:
    from .authored_lineage_v3 import AuthoredNumericCheckpointV2


class D04TrustedJointReplayHold(ValueError):
    """The installed package or frozen component cannot yield a replay."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class D04InstalledJointNumericReplayV1:
    """Installed math result, still pending W01's final graph/Owner adoption."""

    package_root: Path
    component: JointNumericComponentCandidate
    checkpoints: tuple[NumericCheckpoint | AuthoredNumericCheckpointV2, ...]
    drives: tuple[SourcedNumericDrive, ...]
    families: tuple[D04FamilyAssignment, ...]
    candidate: D04JointNumericReceiptCandidateV1
    math_result: D04JointProductMathCandidate
    policy: D04IntervalProjectionPolicyV2
    readout: D04LoadedTanhReadoutAsset
    numeric_error: ProjectionNumericErrorV2
    status: str = "installed_replay_pending_w01_atomic_adoption"


_ISSUED_REPLAYS: WeakValueDictionary[int, D04InstalledJointNumericReplayV1] = WeakValueDictionary()
_ISSUED_DIGESTS: dict[int, str] = {}


def _replay_seal(value: D04InstalledJointNumericReplayV1) -> str:
    data = asdict(value)
    data["package_root"] = str(value.package_root)
    return canonical_digest(data)


def is_package_bound_joint_numeric_replay_v1(value: object) -> bool:
    """Accept only a live replay returned by this process's installed runner."""
    if type(value) is not D04InstalledJointNumericReplayV1:
        return False
    key = id(value)
    if _ISSUED_REPLAYS.get(key) is not value:
        return False
    try:
        return _ISSUED_DIGESTS.get(key) == _replay_seal(value)
    except (TypeError, ValueError):
        return False


def _replay_package_bound_joint_numeric(
    installation: V2InstallationAssembly,
    component: JointNumericComponentCandidate,
    *,
    checkpoints: tuple[NumericCheckpoint | AuthoredNumericCheckpointV2, ...],
    drives: tuple[SourcedNumericDrive, ...],
    families: tuple[D04FamilyAssignment, ...],
    readout_id: str,
    max_iterations: int,
    tolerance: float,
) -> tuple[D04JointNumericReceiptCandidateV1, D04JointProductMathCandidate]:
    """Run real installed ABI2 full/LOO math outside W01's graph transaction.

    The assembly is a caller premise, not a transferable proof of installation
    authority. Only W01 may use this result, with an independently authenticated
    assembly and a fresh write-fence comparison of the complete frozen read.
    """
    if (type(installation) is not V2InstallationAssembly
            or type(component) is not JointNumericComponentCandidate
            or component.status != "hold"
            or installation.installation_policy.namespace != component.namespace
            or not isinstance(installation.package_root, Path)
            or not installation.package_root.is_absolute()):
        raise D04TrustedJointReplayHold("authenticated installation and frozen component are required")
    policy = installation.installation_policy
    grant = installation.installation_grant
    if (grant.authority_id != policy.expected_authority_id
            or grant.installation_id != policy.installation_id
            or grant.administrator_holder != policy.administrator_holder
            or grant.manifest_digest != policy.manifest_digest):
        raise D04TrustedJointReplayHold("Authority installation grant differs from administrator policy")
    package = verify_installed_backend_runtime_v1(
        installation.package_root, policy.manifest_digest,
        available_cpu_features=installation.available_cpu_features,
    )
    if (not package.verified
            or package.manifest_digest != policy.manifest_digest):
        raise D04TrustedJointReplayHold("formal installed package verification is unavailable")
    try:
        handle = load_production_native(
            installation.package_root,
            trusted_manifest_sha256=policy.manifest_digest,
        )
        verified_scheme = load_verified_affect_scheme(
            installation.package_root, policy.manifest_digest,
            available_cpu_features=installation.available_cpu_features,
        )
        binding = handle.production_binding
        if (binding is None or binding.manifest_sha256 != package.manifest_digest
                or verified_scheme.manifest_sha256 != package.manifest_digest
                or binding.abi_version != 2
                or not handle.capabilities.supports_fixed_block_interval_math_v1
                or verified_scheme.scheme.scheme_version != policy.scheme_version
                or verified_scheme.scheme.operator_version != policy.operator_version):
            raise D04TrustedJointReplayHold("native, Scheme and installation identities differ")
        math_result = run_d04_joint_product_math(
            handle, installation.package_root, verified_scheme.scheme, component,
            checkpoints=checkpoints, drives=drives, families=families,
            readout_id=readout_id, max_iterations=max_iterations,
            tolerance=tolerance,
        )
        candidate = compile_joint_numeric_receipt_candidate_v1(
            component=component, math_result=math_result, drives=drives,
            families=families, operator_version=policy.operator_version,
            native_manifest_sha256=binding.manifest_sha256,
            native_sha256=binding.native_sha256,
            native_abi_version=binding.abi_version,
        )
        return candidate, math_result
    except (D04JointProductMathHold, D04JointNumericReceiptHold,
            NativeLoadError, OSError, TypeError, ValueError) as exc:
        raise D04TrustedJointReplayHold("package-bound joint replay is unavailable") from exc


def replay_package_bound_joint_numeric_candidate_v1(
    installation: V2InstallationAssembly,
    component: JointNumericComponentCandidate,
    *, checkpoints: tuple[NumericCheckpoint | AuthoredNumericCheckpointV2, ...],
    drives: tuple[SourcedNumericDrive, ...],
    families: tuple[D04FamilyAssignment, ...], readout_id: str,
    max_iterations: int, tolerance: float,
) -> D04JointNumericReceiptCandidateV1:
    """Compatibility entry returning only an unsigned full/LOO candidate."""
    candidate, _ = _replay_package_bound_joint_numeric(
        installation, component, checkpoints=checkpoints, drives=drives,
        families=families, readout_id=readout_id,
        max_iterations=max_iterations, tolerance=tolerance,
    )
    return candidate


def _numeric_error_from_replay(
    candidate: D04JointNumericReceiptCandidateV1,
    result: D04JointProductMathCandidate,
    policy: D04IntervalProjectionPolicyV2,
    readout_rows: tuple,
) -> ProjectionNumericErrorV2:
    """Conservative projection spread from actual ABI2 and C*tanh intervals."""
    if (result.full_step is None or result.full_step.previous_error != result.initial_error
            or len(result.members) != len(candidate.members)
            or len(readout_rows) != 24):
        raise D04TrustedJointReplayHold("ABI2 numeric error premise is incomplete")
    salience = Fraction()
    tone = Fraction()
    state_errors = set()
    for member in result.members:
        readout = member.full
        if (readout.asset_sha256 != policy.readout_sha256
                or readout.readout_id != policy.readout_id
                or len(readout.outputs) != 24):
            raise D04TrustedJointReplayHold("readout error identity differs")
        state_errors.add(readout.state_error_2norm)
        for index, (output, row) in enumerate(zip(readout.outputs, readout_rows)):
            if output.axis_id != row.axis_id or output.output_id != row.output_id:
                raise D04TrustedJointReplayHold("readout error axis differs")
            norm = sum((Fraction.from_float(weight) for weight in row.coefficients),
                       Fraction())
            if norm <= 0:
                raise D04TrustedJointReplayHold("readout error normalization is invalid")
            width = (Fraction.from_float(output.upper)
                     - Fraction.from_float(output.lower)) / norm
            salience += width
            if index in (0, 1, 2, 3, 4, 5):
                tone += width
    if len(state_errors) != 1:
        raise D04TrustedJointReplayHold("joint ABI2 state errors differ by member")
    count = len(result.members)
    salience_bound = _outward_binary64(salience / (24 * count), lower=False)
    tone_bound = _outward_binary64(tone / (6 * count), lower=False)
    total_state_bound = state_errors.pop()
    proof = canonical_digest({
        "schema": "d04.installed-joint-numeric-error.v1",
        "candidate": candidate.receipt_digest,
        "math": result.transcript_sha256,
        "initial_error": result.initial_error,
        "total_state_error": total_state_bound,
        "salience_spread": salience_bound,
        "tone_spread": tone_bound,
        "policy": canonical_digest(asdict(policy)),
        "readout": policy.readout_sha256,
    })
    return ProjectionNumericErrorV2(
        result.initial_error, total_state_bound, salience_bound, tone_bound, proof,
    )


def replay_package_bound_joint_numeric_original_v1(
    installation: V2InstallationAssembly,
    component: JointNumericComponentCandidate,
    *, checkpoints: tuple[NumericCheckpoint | AuthoredNumericCheckpointV2, ...],
    drives: tuple[SourcedNumericDrive, ...],
    families: tuple[D04FamilyAssignment, ...], readout_id: str,
    max_iterations: int, tolerance: float,
) -> D04InstalledJointNumericReplayV1:
    """Produce installed replay evidence outside W01's final SQLite write lock."""
    candidate, result = _replay_package_bound_joint_numeric(
        installation, component, checkpoints=checkpoints, drives=drives,
        families=families, readout_id=readout_id,
        max_iterations=max_iterations, tolerance=tolerance,
    )
    try:
        policy, readout = load_installed_d04_projection_assets_v2(
            installation.package_root,
            installation.installation_policy.manifest_digest,
            installation.available_cpu_features,
        )
        if (policy.readout_id != readout_id
                or checkpoints[0].assets.readout_sha256 != readout.asset_sha256
                or checkpoints[0].assets.readout_version != readout.readout_version
                or any(member.full.asset_sha256 != readout.asset_sha256
                       or member.full.readout_id != readout.readout_id
                       for member in result.members)):
            raise D04TrustedJointReplayHold("installed policy/readout differs from ABI2 replay")
        error = _numeric_error_from_replay(candidate, result, policy, readout.rows)
    except (D04ProjectionIssuerHold, OSError, TypeError, ValueError, OverflowError) as exc:
        raise D04TrustedJointReplayHold("installed policy or numeric error is unavailable") from exc
    replay = D04InstalledJointNumericReplayV1(
        installation.package_root, component, checkpoints, drives, families,
        candidate, result, policy,
        readout, error,
    )
    key = id(replay)
    _ISSUED_REPLAYS[key] = replay
    _ISSUED_DIGESTS[key] = _replay_seal(replay)
    finalize(replay, _ISSUED_DIGESTS.pop, key, None)
    return replay


def restore_installed_d04_numeric_product_v3(authority, binding, installation):
    """Cold reconstruction only after an actual installed content-recovery read.

    Neither an arbitrary terminal DTO nor a decoder callback is authority. The
    concrete service or paired Host port rereads the independent signed journal
    and fixed Graph artifacts under its current storage/Owner qualification.
    No native solver is invoked, and this witness still grants no Graph write.
    """
    from ...authority_service.d04_numeric_service_v3 import AuthorityD04NumericServiceV3
    from ...authority_service.d04_numeric_claim_bridge_v3 import D04NumericRestoreOriginalV3
    from ...authority_service.d04_numeric_contract_v3 import D04NumericBindingV3
    from ...runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from ...runtime.d04_numeric_cost_v3 import D04NumericPreparedV3
    from ...runtime_contracts import canonical_serialize
    from ...native_runtime.d04_joint_replay_validation_v3 import revalidate_d04_numeric_artifact_v3

    if type(binding) is not D04NumericBindingV3 or type(installation) is not V2InstallationAssembly:
        raise D04TrustedJointReplayHold("installed numeric restoration identities required")
    if type(authority) is AuthorityD04NumericServiceV3:
        original = authority.read_d04_numeric_restore_original_v3(binding)
    elif type(authority) is InstalledC04AuthorityPortV3:
        original = authority.numeric_restore_original(binding)
    else:
        raise D04TrustedJointReplayHold("cold restoration requires the concrete paired Authority reader")
    if (type(original) is not D04NumericRestoreOriginalV3
            or type(original.prepared) is not D04NumericPreparedV3
            or original.prepared.binding != binding or original.terminal.binding != binding
            or original.artifact_json != canonical_serialize(original.artifact_payload)
            or type(original.qualification_digest) is not str or len(original.qualification_digest) != 64
            or any(char not in "0123456789abcdef" for char in original.qualification_digest)):
        raise D04TrustedJointReplayHold("actual numeric restoration original differs")
    product = revalidate_d04_numeric_artifact_v3(
        original.prepared, original.terminal, original.artifact_payload, installation)
    # This is the only cold issuance site. The complete deterministic check
    # above and the concrete independent read cannot be replaced by a DTO hash.
    replay = product.replay
    key = id(replay)
    _ISSUED_REPLAYS[key] = replay
    _ISSUED_DIGESTS[key] = _replay_seal(replay)
    finalize(replay, _ISSUED_DIGESTS.pop, key, None)
    return product


__all__ = [
    "D04TrustedJointReplayHold", "D04InstalledJointNumericReplayV1",
    "replay_package_bound_joint_numeric_candidate_v1",
    "replay_package_bound_joint_numeric_original_v1",
    "is_package_bound_joint_numeric_replay_v1",
    "restore_installed_d04_numeric_product_v3",
]
