"""Actual OS process birth identity for C09 admission and cache retirement."""
from __future__ import annotations

import os
from pathlib import Path

from .contract import AuthorityUnavailable


def read_process_identity_v1(pid):
    if type(pid) is not int or pid < 1:
        raise AuthorityUnavailable("actual C09 process ID required")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = (wintypes.HANDLE, *(ctypes.POINTER(wintypes.FILETIME),) * 4)
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            code = ctypes.get_last_error()
            if code == 87:
                return None
            raise AuthorityUnavailable("C09 process identity inaccessible")
        try:
            wait = kernel.WaitForSingleObject(handle, 0)
            if wait == 0:
                return None
            if wait != 258:
                raise AuthorityUnavailable("C09 process liveness inaccessible")
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(item) for item in times)):
                raise AuthorityUnavailable("C09 process birth time unavailable")
            birth = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        finally:
            kernel.CloseHandle(handle)
        return {"pid": pid, "platform": "windows", "birth": str(birth)}
    if os.name == "posix" and Path("/proc/sys/kernel/random/boot_id").is_file():
        try:
            value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AuthorityUnavailable("C09 process identity inaccessible") from exc
        tail = value.rsplit(")", 1)[1].split()
        if len(tail) < 20:
            raise AuthorityUnavailable("C09 Linux process birth fields differ")
        if tail[0] in {"Z", "X"}:
            return None
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        return {"pid": pid, "platform": "linux", "birth": boot + ":" + tail[19]}
    raise AuthorityUnavailable("C09 installed process identity platform unsupported")


def require_process_retired_v1(original):
    if (type(original) is not dict or set(original) != {"pid", "platform", "birth"}
            or type(original["birth"]) is not str or not original["birth"]):
        raise AuthorityUnavailable("C09 original OS process birth identity required")
    if read_process_identity_v1(original["pid"]) == original:
        raise AuthorityUnavailable("C09 original process remains alive; cold restart required")
    return {"original_process": original, "state": "retired"}
