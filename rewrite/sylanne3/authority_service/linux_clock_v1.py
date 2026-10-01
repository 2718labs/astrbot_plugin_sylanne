"""Read Linux kernel time discipline; never invent a synchronized clock flag."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import time

from .contract import AuthorityUnavailable
from .v2_clock import AuthorityClockReadingV2


class _Timeval(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long)]


class _Timex(ctypes.Structure):
    _fields_ = [("modes", ctypes.c_uint), ("offset", ctypes.c_long),
        ("freq", ctypes.c_long), ("maxerror", ctypes.c_long), ("esterror", ctypes.c_long),
        ("status", ctypes.c_int), ("constant", ctypes.c_long), ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long), ("time", _Timeval), ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long), ("jitter", ctypes.c_long), ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long), ("jitcnt", ctypes.c_long), ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long), ("stbcnt", ctypes.c_long), ("tai", ctypes.c_int),
        ("padding", ctypes.c_int * 11)]


class LinuxKernelClockProviderV1:
    def __init__(self, *, source_id, maximum_error_seconds):
        if (os.name != "posix" or not Path("/proc/sys/kernel/random/boot_id").is_file()
                or not source_id or type(maximum_error_seconds) not in (int, float)
                or maximum_error_seconds <= 0):
            raise AuthorityUnavailable("installed Linux kernel clock policy required")
        self.source_id, self.maximum_error_seconds = source_id, maximum_error_seconds
        self._epoch = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._read = self._libc.adjtimex
        self._read.argtypes, self._read.restype = (ctypes.POINTER(_Timex),), ctypes.c_int

    def __call__(self):
        sample = _Timex()  # modes=0: a read, never a clock adjustment.
        before = time.monotonic()
        state = self._read(ctypes.byref(sample))
        utc, after = time.time(), time.monotonic()
        if state < 0:
            raise AuthorityUnavailable("Linux kernel time discipline read failed")
        error = sample.maxerror / 1_000_000 + (after - before) + time.get_clock_info("time").resolution
        synchronized = state != 5 and not sample.status & (0x0040 | 0x1000)
        if not synchronized or sample.maxerror < 0 or error > self.maximum_error_seconds:
            raise AuthorityUnavailable("Linux kernel clock is unsynchronized or outside installed error bound")
        return AuthorityClockReadingV2(self.source_id, utc, after, self._epoch, True, error)
