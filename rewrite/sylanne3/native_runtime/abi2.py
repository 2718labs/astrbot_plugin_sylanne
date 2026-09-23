from __future__ import annotations

import ctypes
from dataclasses import dataclass
import math


ABI_VERSION = 2
ABI2_FIXED_BLOCK_INTERVAL_V1 = 0x1


class ABI2CSR(ctypes.Structure):
    _fields_ = [
        ("rows", ctypes.c_uint32),
        ("cols", ctypes.c_uint32),
        ("nnz", ctypes.c_uint32),
        ("offsets", ctypes.POINTER(ctypes.c_uint32)),
        ("indices", ctypes.POINTER(ctypes.c_uint32)),
        ("values", ctypes.POINTER(ctypes.c_double)),
    ]


class ABI2StepInput(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("n", ctypes.c_uint32),
        ("k", ABI2CSR),
        ("r", ABI2CSR),
        ("j", ABI2CSR),
        ("a", ABI2CSR),
        ("alpha", ctypes.POINTER(ctypes.c_double)),
        ("previous", ctypes.POINTER(ctypes.c_double)),
        ("drive", ctypes.POINTER(ctypes.c_double)),
        ("iterate", ctypes.POINTER(ctypes.c_double)),
        ("h", ctypes.c_double),
        ("previous_error", ctypes.c_double),
        ("max_iterations", ctypes.c_uint32),
        ("tolerance", ctypes.c_double),
        ("boundary_eta", ctypes.c_double),
    ]


class ABI2StepResult(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("status", ctypes.c_int32),
        ("iterations", ctypes.c_uint32),
        ("certificate_flags", ctypes.c_uint32),
        ("residual", ctypes.c_double),
        ("iteration_error", ctypes.c_double),
        ("time_defect", ctypes.c_double),
        ("trajectory_error", ctypes.c_double),
        ("energy_before", ctypes.c_double),
        ("energy_after", ctypes.c_double),
        ("energy_balance_defect", ctypes.c_double),
        ("q_upper", ctypes.c_double),
        ("boundary_eta", ctypes.c_double),
    ]


@dataclass(frozen=True)
class DiagnosticStepResult:
    status: int
    iterations: int
    certificate_flags: int
    residual: float
    iteration_error: float
    time_defect: float
    trajectory_error: float
    energy_before: float
    energy_after: float
    energy_balance_defect: float
    q_upper: float
    boundary_eta: float
    certified: bool = False


@dataclass(frozen=True)
class NativeReportedFixedBlockIntervalBounds:
    """Native-reported conditional bounds for the received fixed complete joint block.

    These mathematical bounds do not establish source, build, or previous-step
    error eligibility, and do not authorize D04 product adoption.

    iteration_error is an endpoint bound; time_defect is a reconstruction
    defect bound; trajectory_error is an inherited bound; and
    energy_balance_defect is an absolute balance bound. energy_before and
    energy_after are point values.
    """

    status: int
    iterations: int
    certificate_flags: int
    residual: float
    iteration_error: float
    time_defect: float
    trajectory_error: float
    energy_before: float
    energy_after: float
    energy_balance_defect: float
    q_upper: float
    boundary_eta: float


class ABI2ResultError(RuntimeError):
    pass


def diagnostic_step_result(raw: ABI2StepResult) -> DiagnosticStepResult:
    """Translate ABI2 output without upgrading diagnostics into a certificate."""
    if raw.struct_size != ctypes.sizeof(ABI2StepResult) or raw.abi_version != ABI_VERSION:
        raise ABI2ResultError("ABI2 result layout or version mismatch")
    if raw.status not in (0, 1):
        raise ABI2ResultError(f"ABI2 step did not return a usable diagnostic: {raw.status}")
    if raw.certificate_flags != 0:
        raise ABI2ResultError("unsupported native certificate flags")
    values = (
        raw.residual,
        raw.iteration_error,
        raw.time_defect,
        raw.trajectory_error,
        raw.energy_before,
        raw.energy_after,
        raw.energy_balance_defect,
        raw.q_upper,
        raw.boundary_eta,
    )
    if not all(math.isfinite(value) for value in values):
        raise ABI2ResultError("non-finite ABI2 diagnostic")
    return DiagnosticStepResult(
        status=raw.status,
        iterations=raw.iterations,
        certificate_flags=0,
        residual=raw.residual,
        iteration_error=raw.iteration_error,
        time_defect=raw.time_defect,
        trajectory_error=raw.trajectory_error,
        energy_before=raw.energy_before,
        energy_after=raw.energy_after,
        energy_balance_defect=raw.energy_balance_defect,
        q_upper=raw.q_upper,
        boundary_eta=raw.boundary_eta,
    )


def parse_fixed_block_interval_result(raw: ABI2StepResult) -> NativeReportedFixedBlockIntervalBounds:
    """Parse native-reported conditional mathematical bounds, not a product receipt."""
    if raw.struct_size != ctypes.sizeof(ABI2StepResult) or raw.abi_version != ABI_VERSION:
        raise ABI2ResultError("ABI2 result layout or version mismatch")
    if raw.status != 0:
        raise ABI2ResultError(f"ABI2 fixed-block interval step did not succeed: {raw.status}")
    if raw.certificate_flags != ABI2_FIXED_BLOCK_INTERVAL_V1:
        raise ABI2ResultError("unsupported native certificate flags")
    bounds = (
        raw.residual,
        raw.iteration_error,
        raw.time_defect,
        raw.trajectory_error,
        raw.energy_balance_defect,
        raw.q_upper,
        raw.boundary_eta,
    )
    if not all(math.isfinite(value) and value >= 0 for value in bounds):
        raise ABI2ResultError("ABI2 fixed-block interval bounds must be finite and nonnegative")
    if not math.isfinite(raw.energy_before) or not math.isfinite(raw.energy_after):
        raise ABI2ResultError("ABI2 energy point values must be finite")
    if raw.q_upper > 0.8 or raw.boundary_eta != 0:
        raise ABI2ResultError("ABI2 fixed-block interval preconditions not met")
    return NativeReportedFixedBlockIntervalBounds(
        status=raw.status,
        iterations=raw.iterations,
        certificate_flags=raw.certificate_flags,
        residual=raw.residual,
        iteration_error=raw.iteration_error,
        time_defect=raw.time_defect,
        trajectory_error=raw.trajectory_error,
        energy_before=raw.energy_before,
        energy_after=raw.energy_after,
        energy_balance_defect=raw.energy_balance_defect,
        q_upper=raw.q_upper,
        boundary_eta=raw.boundary_eta,
    )
