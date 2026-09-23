"""Conservative Windows security gate for installed Authority profiles.

This module verifies the path and its security descriptors at a point in time.
The caller must still protect the interval between verification and opening
the files: a path-based check cannot make later TLS file opens atomic.
"""

from __future__ import annotations

import ctypes
from pathlib import Path
import os
import re
import uuid


_PROFILE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_PROGRAMDATA = uuid.UUID("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97")
_REPARSE_POINT = 0x400
_DIRECTORY = 0x10
_INVALID_ATTRIBUTES = 0xFFFFFFFF
_MATERIAL = ("profile.json", "trust-root.pem", "client-cert.pem", "client-key.pem")

# File/standard rights which permit changing an object, its ACL, or a child.
# Generic rights are included because ACLs need not store mapped file masks.
_WRITE_RIGHTS = (
    0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000040  # FILE_DELETE_CHILD
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x02000000  # MAXIMUM_ALLOWED: cannot bound the granted access
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)
# Existing protected entries can be replaced if an untrusted principal may
# delete a child of their parent, delete the parent itself, or change the
# parent's security/attributes. Ordinary create rights on ProgramData do not
# confer any of those powers over an already installed Sylanne directory.
_REPLACE_RIGHTS = _WRITE_RIGHTS & ~(0x00000002 | 0x00000004)
_READ_KEY_RIGHTS = 0x00000001 | 0x80000000  # FILE_READ_DATA / GENERIC_READ
_TRUSTED_OWNERS = frozenset(("S-1-5-18", "S-1-5-32-544"))


class WindowsProfileSecurityUnavailable(RuntimeError):
    """Windows could not prove that the installed profile is protected."""


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8),
    ]


def programdata_profile_root() -> Path:
    """Resolve the OS ProgramData Known Folder, ignoring environment values."""
    if os.name != "nt":
        raise WindowsProfileSecurityUnavailable("Windows Known Folders are unavailable")
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes = (
        ctypes.POINTER(_GUID), ctypes.c_uint32, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
    ole.CoTaskMemFree.restype = None
    known_folder = _GUID.from_buffer_copy(_PROGRAMDATA.bytes_le)
    address = ctypes.c_void_p()
    result = shell.SHGetKnownFolderPath(ctypes.byref(known_folder), 0, None,
                                        ctypes.byref(address))
    if result < 0 or not address.value:
        raise WindowsProfileSecurityUnavailable(
            f"ProgramData Known Folder lookup failed (HRESULT 0x{result & 0xffffffff:08x})"
        )
    try:
        base = Path(ctypes.wstring_at(address.value))
    finally:
        ole.CoTaskMemFree(address)
    if not base.is_absolute():
        raise WindowsProfileSecurityUnavailable("ProgramData Known Folder is not absolute")
    return base / "Sylanne" / "client" / "profiles"


def _attributes(path: Path) -> int:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = (ctypes.c_wchar_p,)
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    attributes = kernel.GetFileAttributesW(str(path))
    if attributes == _INVALID_ATTRIBUTES:
        raise WindowsProfileSecurityUnavailable(
            f"cannot inspect Authority profile path: {path} "
            f"(Win32 error {ctypes.get_last_error()})"
        )
    return attributes


def _runtime_token_sids(security: object) -> tuple[str, set[str]]:
    import win32api  # type: ignore[import-not-found]
    import win32con  # type: ignore[import-not-found]

    token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        user, _ = security.GetTokenInformation(token, security.TokenUser)
        groups = security.GetTokenInformation(token, security.TokenGroups)
        user_sid = security.ConvertSidToStringSid(user)
        enabled = {user_sid}
        enabled.update(
            security.ConvertSidToStringSid(sid)
            for sid, flags in groups if flags & 0x4  # SE_GROUP_ENABLED; excludes deny-only
        )
        # These privileges can be enabled by the process and bypass a DACL's
        # apparent lack of write access. A service using this profile must
        # run with a token that does not carry them at all.
        privileges = security.GetTokenInformation(token, security.TokenPrivileges)
        for luid, _flags in privileges:
            if security.LookupPrivilegeName(None, luid) in {
                "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"
            }:
                raise PermissionError("runtime token can bypass private-key DACL")
        return user_sid, enabled
    finally:
        token.Close()


def _check_security_descriptor(path: Path, runtime_user_sid: str,
                               runtime_sids: set[str], security: object,
                               *, key: bool, protected: bool = True) -> None:
    info = security.GetNamedSecurityInfo(
        str(path), security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION,
    )
    owner = info.GetSecurityDescriptorOwner()
    if owner is None or security.ConvertSidToStringSid(owner) not in _TRUSTED_OWNERS:
        raise PermissionError(f"Authority profile owner is not SYSTEM or Administrators: {path}")
    dacl = info.GetSecurityDescriptorDacl()
    if dacl is None:
        raise PermissionError(f"Authority profile has a null DACL: {path}")
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if len(ace) != 3 or not isinstance(ace[0], tuple) or len(ace[0]) != 2:
            raise WindowsProfileSecurityUnavailable("unsupported Authority profile ACE")
        kind, _flags = ace[0]
        if kind not in (security.ACCESS_ALLOWED_ACE_TYPE, security.ACCESS_DENIED_ACE_TYPE):
            raise WindowsProfileSecurityUnavailable("unsupported Authority profile ACE type")
        mask, sid = ace[1], ace[2]
        if not isinstance(mask, int):
            raise WindowsProfileSecurityUnavailable("invalid Authority profile ACE mask")
        principal = security.ConvertSidToStringSid(sid)
        # Inherited ACEs are intentionally included. Ignore neither inherit-only
        # grants nor deny ACEs when classifying an unsupported ACE shape.
        if kind == security.ACCESS_ALLOWED_ACE_TYPE:
            forbidden = _WRITE_RIGHTS if protected else _REPLACE_RIGHTS
            if mask & forbidden and principal not in _TRUSTED_OWNERS:
                raise PermissionError(f"Authority profile grants non-admin write: {path}")
            if key:
                if mask & _WRITE_RIGHTS and principal in runtime_sids:
                    raise PermissionError("runtime account can write Authority private key")
                if (mask & _READ_KEY_RIGHTS and principal not in _TRUSTED_OWNERS
                        and principal != runtime_user_sid):
                    raise PermissionError("Authority private key grants broad read")
    if key and security.ConvertSidToStringSid(owner) in runtime_sids:
        # An owner may change its object's DACL even without an explicit ACE.
        raise PermissionError("runtime account owns Authority private key")


def _verify_tree(profile_dir: Path) -> None:
    """Internal test seam; production must derive the root from Known Folders."""
    if os.name != "nt":
        raise WindowsProfileSecurityUnavailable("Windows DACL verification is unavailable")
    try:
        import win32security  # type: ignore[import-not-found]
        runtime_user_sid, runtime_sids = _runtime_token_sids(win32security)
        if not runtime_sids:
            raise WindowsProfileSecurityUnavailable("runtime token has no user SID")
        directories = tuple(reversed(profile_dir.parents)) + (profile_dir,)
        protected_root = profile_dir.parents[2]  # ProgramData / Sylanne
        files = tuple(profile_dir / name for name in _MATERIAL)
        for path in directories + files:
            attributes = _attributes(path)
            if attributes & _REPARSE_POINT:
                raise PermissionError(f"Authority profile path is a reparse point: {path}")
            if bool(attributes & _DIRECTORY) != (path in directories):
                raise PermissionError(f"Authority profile path type is unsafe: {path}")
            _check_security_descriptor(
                path, runtime_user_sid, runtime_sids, win32security,
                key=path == profile_dir / "client-key.pem",
                protected=path in files or path == protected_root
                or protected_root in path.parents,
            )
        # This is an actual read under the runtime token, not a claim inferred
        # from a SID name or from an ACL that might contain a deny ACE.
        with (profile_dir / "client-key.pem").open("rb"):
            pass
    except PermissionError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, ImportError) as exc:
        raise WindowsProfileSecurityUnavailable("Windows profile verification failed") from exc


def verify_admin_profile(profile_id: str) -> Path:
    """Verify an installed profile and return its directory for a prompt open."""
    if not isinstance(profile_id, str) or _PROFILE_ID.fullmatch(profile_id) is None:
        raise ValueError("authority profile identifier is invalid")
    profile_dir = programdata_profile_root() / profile_id
    _verify_tree(profile_dir)
    return profile_dir


__all__ = ("WindowsProfileSecurityUnavailable", "programdata_profile_root",
           "verify_admin_profile")
