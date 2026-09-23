from __future__ import annotations

import ctypes
from dataclasses import dataclass
import math


ABI_VERSION = 2


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
