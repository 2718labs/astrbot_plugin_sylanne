"""Version 1 native arithmetic report for mathematical inputs only.

No report here is a product certificate or proof of source/build provenance,
prior-state error provenance, event closure, or a complete application state.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import math
import struct


VERSION = 1


class ReportCSR(ctypes.Structure):
    _fields_ = [("rows", ctypes.c_uint32), ("cols", ctypes.c_uint32),
                ("nnz", ctypes.c_uint32), ("offsets", ctypes.POINTER(ctypes.c_uint32)),
                ("indices", ctypes.POINTER(ctypes.c_uint32)),
                ("values", ctypes.POINTER(ctypes.c_double))]


class ReportInput(ctypes.Structure):
    _fields_ = [("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
                ("n", ctypes.c_uint32), ("k", ReportCSR), ("r", ReportCSR),
                ("j", ReportCSR), ("a", ReportCSR),
                ("alpha", ctypes.POINTER(ctypes.c_double)),
                ("x", ctypes.POINTER(ctypes.c_double)),
                ("y", ctypes.POINTER(ctypes.c_double)),
                ("drive", ctypes.POINTER(ctypes.c_double)),
                ("readout", ctypes.POINTER(ctypes.c_double)),
                ("h", ctypes.c_double), ("inherited_error_upper", ctypes.c_double),
                ("threshold", ctypes.c_double), ("cancelled", ctypes.c_uint32)]


class ReportInterval(ctypes.Structure):
    _fields_ = [("lower", ctypes.c_double), ("upper", ctypes.c_double)]


INTERVAL_FIELDS = (
    "energy_difference", "gradient_displacement", "dissipation", "drive_work",
    "residual_work", "gradient_identity_defect", "energy_balance_defect",
    "residual_norm", "endpoint_error", "reconstruction_defect", "time_error",
    "readout_point", "readout_enclosure",
)


class RawArithmeticReport(ctypes.Structure):
    _fields_ = [("struct_size", ctypes.c_uint32), ("version", ctypes.c_uint32),
                ("status", ctypes.c_int32), ("product_certificate_flags", ctypes.c_uint32),
                ("input_sha256", ctypes.c_ubyte * 32)] + [
                    (name, ReportInterval) for name in INTERVAL_FIELDS
                ] + [("threshold_relation", ctypes.c_int32)]


@dataclass(frozen=True)
class ArithmeticReport:
    input_sha256: str
    intervals: dict[str, tuple[float, float]]
    threshold_relation: int
    product_certified: bool = False


def parse_arithmetic_report(raw: RawArithmeticReport, expected_sha256: bytes) -> ArithmeticReport:
    if raw.struct_size != ctypes.sizeof(RawArithmeticReport) or raw.version != VERSION:
        raise ValueError("arithmetic report layout or version mismatch")
    if raw.status != 0 or raw.product_certificate_flags != 0:
        raise ValueError("arithmetic report failed or claimed product certification")
    if not isinstance(expected_sha256, bytes) or len(expected_sha256) != 32:
        raise ValueError("expected input SHA-256 is required")
    if bytes(raw.input_sha256) != expected_sha256:
        raise ValueError("arithmetic report input mismatch")
    intervals = {}
    for name in INTERVAL_FIELDS:
        interval = getattr(raw, name)
        if not (math.isfinite(interval.lower) and math.isfinite(interval.upper)
                and interval.lower <= interval.upper):
            raise ValueError(f"invalid arithmetic interval: {name}")
        intervals[name] = (interval.lower, interval.upper)
    if raw.threshold_relation not in (-1, 0, 1):
        raise ValueError("invalid threshold relation")
    return ArithmeticReport(expected_sha256.hex(), intervals, raw.threshold_relation)


def _u32(digest, value):
    digest.update(struct.pack("<I", value))


def _f64(digest, value):
    digest.update(struct.pack("<d", value))


def _vector_hash(digest, values):
    _u32(digest, len(values))
    for value in values:
        _f64(digest, value)


class ArithmeticReportLibrary:
    """Synchronous ctypes bridge holding all source buffers through the call."""

    def __init__(self, library):
        self._library = library
        version = library.sylanne3_arithmetic_report_version
        version.argtypes = []
        version.restype = ctypes.c_uint32
        if version() != VERSION:
            raise ValueError("arithmetic report version mismatch")
        self._call = library.sylanne3_arithmetic_report_v1
        self._call.argtypes = [ctypes.POINTER(ReportInput), ctypes.c_uint32,
                               ctypes.POINTER(RawArithmeticReport), ctypes.c_uint32]
        self._call.restype = ctypes.c_int32

    def report(self, *, n, k, r, j, a, alpha, x, y, drive, readout,
               h, inherited_error_upper, threshold, cancelled=False):
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 64:
            raise ValueError("report dimension must be 1..64")
        keepalive = []
        digest = hashlib.sha256(b"sylanne3-arithmetic-report-v1\0")
        _u32(digest, n)

        def make_vector(values, length):
            values = tuple(float(value) for value in values)
            if len(values) != length:
                raise ValueError("report vector length mismatch")
            array = (ctypes.c_double * max(length, 1))(*values)
            keepalive.append(array)
            return values, ctypes.cast(array, ctypes.POINTER(ctypes.c_double))

        def make_csr(data, rows, cols):
            offsets, indices, values = data
            offsets, indices, values = tuple(offsets), tuple(indices), tuple(float(v) for v in values)
            if len(offsets) != rows + 1 or len(indices) != len(values) or len(values) > 4096:
                raise ValueError("report CSR lengths invalid")
            if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > 0xffffffff
                   for v in offsets + indices):
                raise ValueError("report CSR index invalid")
            _u32(digest, rows); _u32(digest, cols); _u32(digest, len(values))
            for value in offsets: _u32(digest, value)
            for value in indices: _u32(digest, value)
            _vector_hash(digest, values)
            oa = (ctypes.c_uint32 * len(offsets))(*offsets)
            ia = (ctypes.c_uint32 * max(len(indices), 1))(*indices)
            va = (ctypes.c_double * max(len(values), 1))(*values)
            keepalive.extend((oa, ia, va))
            return ReportCSR(rows, cols, len(values), oa, ia, va)

        if len(a[0]) < 1 or len(a[0]) > 65:
            raise ValueError("report A rows invalid")
        a_rows = len(a[0]) - 1
        matrices = [make_csr(k, n, n), make_csr(r, n, n),
                    make_csr(j, n, n), make_csr(a, a_rows, n)]
        vectors = [make_vector(values, length) for values, length in
                   ((alpha, a_rows), (x, n), (y, n), (drive, n), (readout, n))]
        for values, _ in vectors: _vector_hash(digest, values)
        for value in (h, inherited_error_upper, threshold): _f64(digest, float(value))
        raw_input = ReportInput(ctypes.sizeof(ReportInput), VERSION, n, *matrices,
                                *(pointer for _, pointer in vectors), float(h),
                                float(inherited_error_upper), float(threshold), int(bool(cancelled)))
        raw = RawArithmeticReport()
        status = self._call(ctypes.byref(raw_input), ctypes.sizeof(ReportInput),
                            ctypes.byref(raw), ctypes.sizeof(RawArithmeticReport))
        if status != 0:
            raise ArithmeticError(f"arithmetic report rejected input (status {status})")
        return parse_arithmetic_report(raw, digest.digest())
