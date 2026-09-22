"""Bounded ctypes bridge. No fallback; error bounds certify only A*x=b.

Native calls run synchronously in scheduler-owned workers. Cancellation is checked
on both sides of each call. Each call is capped at 64 sweeps over at most 256
variables. ctypes owns disjoint input/output allocations with exact ABI lengths.
"""
from concurrent.futures import CancelledError
import ctypes
from dataclasses import dataclass
import math
from pathlib import Path
import sys
import threading
from .contracts import StepResult


class AccuracyNotMet(ArithmeticError):
    """The immutable interval exhausted its refinement allowance."""


@dataclass(frozen=True)
class SolveResult:
    solution: tuple[float, ...]
    residual_l2: float
    error_bound: float
    energy_delta: float
    sweeps: int


def _positive(value, name):
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f'{name} must be finite and positive')
    return value


def _vector(values, n, name):
    result = tuple(float(x) for x in values)
    if len(result) != n or not all(math.isfinite(x) for x in result):
        raise ValueError(f'{name} must have {n} finite entries')
    return result


class NativeKernel:
    def __init__(self, library_path=None):
        if library_path is None:
            filename = ('sylanne3_kernel.dll' if sys.platform == 'win32' else
                        'libsylanne3_kernel.dylib' if sys.platform == 'darwin' else
                        'libsylanne3_kernel.so')
            root = Path(__file__).resolve().parents[1] / 'native' / 'target'
            library_path = next((root / kind / filename for kind in ('release','debug')
                                 if (root / kind / filename).is_file()), None)
            if library_path is None:
                raise FileNotFoundError('Build rewrite/native using cargo build --release')
        self._library = ctypes.CDLL(str(Path(library_path).resolve()))
        version = self._library.sylanne3_abi_version
        version.argtypes = []
        version.restype = ctypes.c_uint32
        if version() != 1:
            raise RuntimeError('Unsupported sylanne3 native ABI')
        self._refine = self._library.sylanne3_refine
        ptr = ctypes.POINTER(ctypes.c_double)
        self._refine.argtypes = [ctypes.c_size_t,ptr,ptr,ptr,ptr,ptr,ctypes.c_double,
                                ptr,ctypes.c_size_t,ctypes.c_double,ptr,ptr]
        self._refine.restype = ctypes.c_int32

    def job(self, *, mass, recovery, edges, previous, drive, dt,
            tolerance=1e-8, max_total_sweeps=10000):
        return SolveJob(self, mass, recovery, edges, previous, drive, dt,
                        tolerance, max_total_sweeps)


class SolveJob:
    def __init__(self, kernel, mass, recovery, edges, previous, drive, dt,
                 tolerance, max_total_sweeps):
        mass = tuple(float(x) for x in mass)
        n = len(mass)
        if not 1 <= n <= 256:
            raise ValueError('native dimension must be 1..256')
        m = _vector(mass,n,'mass')
        r = _vector(recovery,n,'recovery')
        if min(m) <= 0 or min(r) <= 0:
            raise ValueError('mass and recovery must be positive')
        rows = tuple(_vector(row,n,'edge row') for row in edges)
        if len(rows) != n:
            raise ValueError('edges must be n by n')
        if any(rows[i][j] < 0 or rows[i][j] != rows[j][i] or
               (i == j and rows[i][j] != 0) for i in range(n) for j in range(n)):
            raise ValueError('edges must be nonnegative symmetric and zero diagonal')
        p = _vector(previous,n,'previous')
        d = _vector(drive,n,'drive')
        self._dt = _positive(dt,'dt')
        self._tolerance = _positive(tolerance,'tolerance')
        if isinstance(max_total_sweeps,bool) or not isinstance(max_total_sweeps,int) or max_total_sweeps < 1:
            raise ValueError('max_total_sweeps must be a positive integer')
        self._maximum = max_total_sweeps
        self._kernel = kernel
        self._n = n
        arr = ctypes.c_double*n
        self._m, self._r, self._p, self._d = arr(*m), arr(*r), arr(*p), arr(*d)
        self._e = (ctypes.c_double*(n*n))(*(x for row in rows for x in row))
        self._x = arr(*p)
        self._sweeps = 0
        self._result = None
        self._lock = threading.Lock()

    def step(self, budget, cancelled):
        if isinstance(budget,bool) or not isinstance(budget,int) or budget < 1:
            raise ValueError('budget must be a positive integer')
        if not self._lock.acquire(blocking=False):
            raise RuntimeError('Concurrent steps of one solve are forbidden')
        try:
            if cancelled.is_set():
                raise CancelledError()
            if self._result is not None:
                return StepResult(True,self._result)
            remaining = self._maximum-self._sweeps
            if remaining <= 0:
                raise AccuracyNotMet('Discrete-system tolerance not met')
            output = (ctypes.c_double*self._n)()
            metrics = (ctypes.c_double*4)()
            status = self._kernel._refine(self._n,self._m,self._r,self._e,self._p,self._d,
                self._dt,self._x,min(budget,64,remaining),self._tolerance,output,metrics)
            if cancelled.is_set():
                raise CancelledError()
            if status < 0:
                raise ArithmeticError(f'Native input/computation rejected (status {status})')
            if status not in (0,1) or not all(math.isfinite(v) for v in (*output,*metrics)):
                raise ArithmeticError('Invalid native result')
            self._x = output
            self._sweeps += int(metrics[3])
            if status == 0:
                self._result = SolveResult(tuple(output),metrics[0],metrics[1],metrics[2],self._sweeps)
                return StepResult(True,self._result)
            if self._sweeps >= self._maximum:
                raise AccuracyNotMet(f'Tolerance not met after {self._sweeps} sweeps; bound={metrics[1]}')
            return StepResult(False)
        finally:
            self._lock.release()
