"""Fail-closed macOS extended-ACL check for an already opened profile object.

The descriptor must come from no-follow traversal.  Mode bits alone do not
describe macOS extended ACL grants, including inherited entries.
"""

from __future__ import annotations

import ctypes
import errno
import platform


# Darwin <sys/acl.h>: ACL_TYPE_EXTENDED and ACL_FIRST_ENTRY.  A target macOS
# cold install must exercise these libc calls before platform qualification.
_ACL_TYPE_EXTENDED = 0x00000100
_ACL_FIRST_ENTRY = 0


class MacOSProfileSecurityUnavailable(OSError):
    """An opened object's macOS ACL could not be verified."""


def reject_extended_acl(fd: int) -> None:
    """Reject every extended ACE; unknown ACL semantics cannot grant access."""
    if platform.system() != "Darwin":
        raise MacOSProfileSecurityUnavailable("macOS ACL API is unavailable")
    try:
        libc = ctypes.CDLL("libc.dylib", use_errno=True)
        get_acl = libc.acl_get_fd_np
        get_acl.argtypes = (ctypes.c_int, ctypes.c_int)
        get_acl.restype = ctypes.c_void_p
        get_entry = libc.acl_get_entry
        get_entry.argtypes = (ctypes.c_void_p, ctypes.c_int,
                              ctypes.POINTER(ctypes.c_void_p))
        get_entry.restype = ctypes.c_int
        valid_acl = libc.acl_valid_fd_np
        valid_acl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        valid_acl.restype = ctypes.c_int
        free_acl = libc.acl_free
        free_acl.argtypes = (ctypes.c_void_p,)
        free_acl.restype = ctypes.c_int
    except (OSError, AttributeError, TypeError) as exc:
        raise MacOSProfileSecurityUnavailable("macOS ACL API is unavailable") from exc
    ctypes.set_errno(0)
    acl = get_acl(fd, _ACL_TYPE_EXTENDED)
    if not acl:
        raise MacOSProfileSecurityUnavailable("macOS ACL query failed")
    try:
        if valid_acl(fd, _ACL_TYPE_EXTENDED, acl) != 0:
            raise MacOSProfileSecurityUnavailable("macOS ACL validation failed")
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = get_entry(acl, _ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result == 0:
            raise PermissionError("administrator profile extended ACL is unsafe")
        if result != -1 or ctypes.get_errno() != errno.EINVAL:
            raise MacOSProfileSecurityUnavailable("macOS ACL entry query failed")
    finally:
        if free_acl(acl) != 0:
            raise MacOSProfileSecurityUnavailable("macOS ACL release failed")


__all__ = ("MacOSProfileSecurityUnavailable", "reject_extended_acl")
