"""Load a separately installed, administrator-owned Authority TLS profile.

The chat-facing value is only a bounded profile identifier. Deployment owns
the endpoint, expected TLS server identity, Authority ID, trust root and client
credential. POSIX material is opened through verified descriptors before TLS
consumes it. Windows keeps checked handles pinned while OpenSSL reads paths.
"""

from __future__ import annotations

import errno
import ctypes
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import ssl
import stat
from typing import Iterator

from ..installation_policy import AdminInstallationPolicy
from ..runtime.budget import BudgetLease
from ..runtime_contracts import NamespaceId
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport


_PROFILE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_PROFILE_FIELDS_V1 = frozenset({
    "schema", "host", "port", "server_name", "expected_authority_id",
})
_PROFILE_FIELDS_V2 = _PROFILE_FIELDS_V1 | {"installation_policy"}
_INSTALLATION_FIELDS = frozenset({
    "namespace", "authority_namespace", "installation_id", "manifest_digest",
    "administrator_holder", "expected_authority_id", "catalogue_hash",
    "scheme_version", "operator_version", "policy_version", "root_lease",
    "root_grant",
})
_LEASE_FIELDS = frozenset({
    "lease_id", "parent_id", "bot_id", "persona_id", "currency", "limits",
    "used", "reserved", "unconfirmed", "version", "state",
})
_GRANT_FIELDS = frozenset({
    "grant_id", "version", "bot_id", "persona_id", "lease_id", "currency",
    "max_ceiling", "allowed_work_kinds", "valid_until_utc", "policy_ref",
})
_MATERIAL = ("trust-root.pem", "client-cert.pem", "client-key.pem")
_D11_SIGNING_KEY = "d11-signing.key"
_D11_SIGNING_KEY_BYTES = 32
_MAX_PROFILE_BYTES = 8192
_MAX_MATERIAL_BYTES = 1_048_576
_WIN_GENERIC_READ = 0x80000000
_WIN_SHARE_READ = 0x00000001
_WIN_OPEN_EXISTING = 3
_WIN_BACKUP_SEMANTICS = 0x02000000
_WIN_OPEN_REPARSE_POINT = 0x00200000
_WIN_REPARSE_POINT = 0x00000400
_WIN_DIRECTORY = 0x00000010


class _Filetime(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = (
        ("attributes", ctypes.c_uint32),
        ("created", _Filetime), ("accessed", _Filetime), ("written", _Filetime),
        ("volume_serial", ctypes.c_uint32), ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32), ("links", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32), ("index_low", ctypes.c_uint32),
    )


class AuthorityProfileUnavailable(RuntimeError):
    """The host cannot establish the installed-profile trust boundary."""


@dataclass(frozen=True, slots=True)
class AdminInstallationBundle:
    """One verified installation snapshot for Authority client assembly."""

    tls_profile: AuthorityTlsProfile
    installation_policy: AdminInstallationPolicy
    d11_signing_key: bytes


def _check_profile_id(profile_id: str) -> None:
    if not isinstance(profile_id, str) or _PROFILE_ID.fullmatch(profile_id) is None:
        raise ValueError("authority profile identifier is invalid")


def _check_posix_tree(profile_dir: Path) -> None:
    """Check each ancestor and every consumed file before TLS uses its paths.

    A root-owned, non-writable parent prevents an unprivileged process from
    replacing a checked descendant. Administrators remain trusted by design.
    """
    if not profile_dir.is_absolute():
        raise ValueError("administrator profile root must be absolute")
    chain = tuple(reversed(profile_dir.parents)) + (profile_dir,)
    for path in chain:
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise PermissionError("administrator profile directory is unsafe")
    for name in ("profile.json",) + _MATERIAL:
        info = os.lstat(profile_dir / name)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise PermissionError("administrator profile file is unsafe")
        if name == "client-key.pem" and info.st_mode & 0o007:
            raise PermissionError("administrator private key is exposed")
        if name == "client-key.pem" and info.st_mode & 0o040:
            effective_group = getattr(os, "getegid", None)
            if effective_group is None or info.st_gid != effective_group():
                raise PermissionError("administrator private key group is unsafe")


def _check_linux_acl_tree(profile_dir: Path) -> None:
    """Reject ACLs on the entire trusted path; mode bits alone are insufficient."""
    if not hasattr(os, "getxattr"):
        raise AuthorityProfileUnavailable("Linux POSIX ACL verification is unavailable")
    directories = tuple(reversed(profile_dir.parents)) + (profile_dir,)
    for path in directories + tuple(profile_dir / name for name in ("profile.json",) + _MATERIAL):
        names = ("system.posix_acl_access", "system.posix_acl_default") \
            if path in directories else ("system.posix_acl_access",)
        for name in names:
            try:
                os.getxattr(path, name, follow_symlinks=False)
            except OSError as exc:
                if exc.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
                    continue
                raise AuthorityProfileUnavailable("Linux POSIX ACL verification failed") from exc
            raise PermissionError("administrator profile ACL is unsafe")


def _check_linux_acl_fd(fd: int, *, directory: bool) -> None:
    if not hasattr(os, "getxattr"):
        raise AuthorityProfileUnavailable("Linux POSIX ACL verification is unavailable")
    names = ("system.posix_acl_access", "system.posix_acl_default") if directory \
        else ("system.posix_acl_access",)
    for name in names:
        try:
            os.getxattr(fd, name)
        except OSError as exc:
            if exc.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
                continue
            raise AuthorityProfileUnavailable("Linux POSIX ACL verification failed") from exc
        raise PermissionError("administrator profile ACL is unsafe")


def _check_opened(fd: int, *, directory: bool, key: bool, system: str) -> None:
    info = os.fstat(fd)
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise PermissionError("administrator profile object is unsafe")
    if not directory:
        if info.st_nlink != 1 or info.st_size > _MAX_MATERIAL_BYTES:
            raise PermissionError("administrator profile file is unsafe")
        if key and info.st_mode & 0o007:
            raise PermissionError("administrator private key is exposed")
        if key and info.st_mode & 0o040 and info.st_gid != os.getegid():
            raise PermissionError("administrator private key group is unsafe")
    if system == "Darwin":
        from .macos_profile_security import reject_extended_acl
        reject_extended_acl(fd)
    elif system == "Linux":
        _check_linux_acl_fd(fd, directory=directory)
    else:
        raise AuthorityProfileUnavailable("POSIX profile verification is unavailable")


@contextmanager
def _opened_profile(profile_dir: Path, system: str, *, signing_key: bool = False
                    ) -> Iterator[dict[str, int]]:
    """Pin every path component and consumed file before inspecting either."""
    if not profile_dir.is_absolute() or os.open not in os.supports_dir_fd:
        raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, flag) for flag in required):
        raise AuthorityProfileUnavailable("POSIX no-follow open is unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        current = os.open("/", directory_flags)
        stack.callback(os.close, current)
        _check_opened(current, directory=True, key=False, system=system)
        for part in profile_dir.parts[1:]:
            if part in {"", ".", ".."}:
                raise ValueError("administrator profile path is invalid")
            child = os.open(part, directory_flags, dir_fd=current)
            stack.callback(os.close, child)
            _check_opened(child, directory=True, key=False, system=system)
            current = child
        files: dict[str, int] = {}
        names = ("profile.json",) + _MATERIAL + ((_D11_SIGNING_KEY,) if signing_key else ())
        for name in names:
            fd = os.open(name, file_flags, dir_fd=current)
            stack.callback(os.close, fd)
            _check_opened(fd, directory=False,
                          key=name in {"client-key.pem", _D11_SIGNING_KEY}, system=system)
            files[name] = fd
        yield files


def _read_fd_bounded(fd: int, limit: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, limit + 1)
    if len(raw) > limit:
        raise ValueError("administrator profile file is too large")
    return raw


def _tls_fd_path(fd: int, system: str) -> str:
    """Check the OS descriptor alias before passing it to OpenSSL's path API."""
    base = "/dev/fd" if system == "Darwin" else "/proc/self/fd"
    alias = f"{base}/{fd}"
    try:
        original = os.fstat(fd)
        opened = os.open(alias, os.O_RDONLY | os.O_CLOEXEC)
        try:
            duplicate = os.fstat(opened)
        finally:
            os.close(opened)
    except OSError as exc:
        raise AuthorityProfileUnavailable("TLS descriptor alias is unavailable") from exc
    if (original.st_dev, original.st_ino) != (duplicate.st_dev, duplicate.st_ino):
        raise AuthorityProfileUnavailable("TLS descriptor alias did not preserve identity")
    return alias


def _prepared_ssl_context(files: dict[str, int], system: str) -> ssl.SSLContext:
    trust = _read_fd_bounded(files["trust-root.pem"], _MAX_MATERIAL_BYTES)
    try:
        cadata = trust.decode("ascii")
    except UnicodeError as exc:
        raise ValueError("administrator trust root is not PEM text") from exc
    cert = _tls_fd_path(files["client-cert.pem"], system)
    key = _tls_fd_path(files["client-key.pem"], system)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=cadata)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    os.lseek(files["client-cert.pem"], 0, os.SEEK_SET)
    os.lseek(files["client-key.pem"], 0, os.SEEK_SET)
    context.load_cert_chain(cert, key)
    return context


@contextmanager
def _opened_windows_profile(profile_dir: Path, *, signing_key: bool = False
                            ) -> Iterator[dict[Path, int]]:
    """Pin the whole path while pathname-only OpenSSL loads the same objects.

    FILE_SHARE_READ denies write/delete opens, including rename, until all
    handles close. Existing conflicting handles make CreateFile fail closed.
    """
    if os.name != "nt" or not profile_dir.is_absolute():
        raise AuthorityProfileUnavailable("Windows profile handle gate is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    )
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation),
    )
    kernel.GetFileInformationByHandle.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel.CloseHandle.restype = ctypes.c_int
    invalid = ctypes.c_void_p(-1).value
    directories = tuple(reversed(profile_dir.parents)) + (profile_dir,)
    names = ("profile.json",) + _MATERIAL + ((_D11_SIGNING_KEY,) if signing_key else ())
    paths = directories + tuple(profile_dir / name for name in names)
    with ExitStack() as stack:
        handles: dict[Path, int] = {}
        for path in paths:
            directory = path in directories
            flags = _WIN_OPEN_REPARSE_POINT | (_WIN_BACKUP_SEMANTICS if directory else 0)
            handle = kernel.CreateFileW(
                str(path), _WIN_GENERIC_READ,
                _WIN_SHARE_READ, None, _WIN_OPEN_EXISTING, flags, None,
            )
            if handle is None or handle == invalid:
                if ctypes.get_last_error() in {2, 3}:
                    raise FileNotFoundError("administrator Authority profile is not installed")
                raise AuthorityProfileUnavailable("Windows profile handle open failed")
            stack.callback(kernel.CloseHandle, ctypes.c_void_p(handle))
            info = _ByHandleFileInformation()
            if not kernel.GetFileInformationByHandle(
                ctypes.c_void_p(handle), ctypes.byref(info)
            ):
                raise AuthorityProfileUnavailable("Windows profile handle inspection failed")
            if (info.attributes & _WIN_REPARSE_POINT
                    or bool(info.attributes & _WIN_DIRECTORY) != directory
                    or not directory and info.links != 1):
                raise PermissionError("administrator Authority profile object is unsafe")
            if not directory and (info.size_high << 32 | info.size_low) > _MAX_MATERIAL_BYTES:
                raise PermissionError("administrator Authority profile file is too large")
            handles[path] = handle
        yield handles


class _HandleSecurityView:
    """Adapt the existing DACL policy checker to a pinned Win32 handle."""

    def __init__(self, security: object, handle: int):
        self._security = security
        self._handle = handle

    def GetNamedSecurityInfo(self, _path: str, object_type: int, flags: int):
        return self._security.GetSecurityInfo(self._handle, object_type, flags)

    def __getattr__(self, name: str):
        return getattr(self._security, name)


def _check_windows_handles(profile_dir: Path, handles: dict[Path, int]) -> None:
    """Apply the existing owner/DACL policy to each held object itself."""
    from . import windows_profile_security as security_gate
    try:
        import win32security  # type: ignore[import-not-found]
        runtime_user, runtime_sids = security_gate._runtime_token_sids(win32security)
        protected_root = profile_dir.parents[2]
        key_paths = {profile_dir / "client-key.pem", profile_dir / _D11_SIGNING_KEY}
        for path, handle in handles.items():
            security_gate._check_security_descriptor(
                path, runtime_user, runtime_sids,
                _HandleSecurityView(win32security, handle),
                key=path in key_paths,
                protected=path == protected_root or protected_root in path.parents,
            )
    except PermissionError:
        raise
    except (security_gate.WindowsProfileSecurityUnavailable,
            OSError, ValueError, TypeError, AttributeError, ImportError) as exc:
        raise AuthorityProfileUnavailable("Windows handle DACL verification failed") from exc


def _read_profile_json(path: Path | int) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate authority profile field")
            result[key] = value
        return result

    if isinstance(path, int):
        descriptor = path
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROFILE_BYTES:
            raise ValueError("authority profile is not a bounded regular file")
        raw = _read_fd_bounded(descriptor, _MAX_PROFILE_BYTES)
    else:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROFILE_BYTES:
                raise ValueError("authority profile is not a bounded regular file")
            raw = os.read(descriptor, _MAX_PROFILE_BYTES + 1)
        finally:
            os.close(descriptor)
    if len(raw) > _MAX_PROFILE_BYTES:
        raise ValueError("authority profile is too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    except UnicodeError as exc:
        raise ValueError("authority profile is not UTF-8") from exc
    if (not isinstance(value, dict) or type(value.get("schema")) is not int
            or value["schema"] not in {1, 2}
            or set(value) != (_PROFILE_FIELDS_V1 if value["schema"] == 1
                              else _PROFILE_FIELDS_V2)):
        raise ValueError("authority profile schema is invalid")
    return value


def _endpoint_name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("authority endpoint identity is invalid")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not all(_DNS_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValueError("authority endpoint identity is invalid")
    return value


def _profile_from_payload(profile_id: str, profile_dir: Path,
                          payload: dict[str, object],
                          prepared: ssl.SSLContext | None = None) -> AuthorityTlsProfile:
    if type(payload["schema"]) is not int or payload["schema"] not in {1, 2}:
        raise ValueError("authority profile schema is invalid")
    if type(payload["port"]) is not int or not 1 <= payload["port"] <= 65535:
        raise ValueError("authority profile port is invalid")
    if payload["schema"] == 2:
        _policy_from_payload(payload)
    authority_id = payload["expected_authority_id"]
    if not isinstance(authority_id, str):
        raise ValueError("expected Authority identity is invalid")
    return AuthorityTlsProfile(
        profile_id=profile_id,
        host=_endpoint_name(payload["host"]),
        port=payload["port"],
        server_name=_endpoint_name(payload["server_name"]),
        expected_authority_id=authority_id,
        trust_root=profile_dir / "trust-root.pem",
        client_certificate=profile_dir / "client-cert.pem",
        client_private_key=profile_dir / "client-key.pem",
        prepared_ssl_context=prepared,
    )


def _exact_object(value: object, expected: frozenset[str], name: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"{name} schema is invalid")
    return value


def _policy_from_payload(payload: dict[str, object]) -> AdminInstallationPolicy:
    """Parse schema 2 after the enclosing profile passed its trusted read gate."""
    from ..runtime.issuers import BudgetLeaseGrant

    if (type(payload.get("schema")) is not int or payload["schema"] != 2
            or set(payload) != _PROFILE_FIELDS_V2):
        raise ValueError("administrator installation policy requires profile schema 2")
    values = _exact_object(payload["installation_policy"], _INSTALLATION_FIELDS,
                           "installation policy")
    namespace = _exact_object(values["namespace"], frozenset({"bot_id", "persona_id"}),
                              "installation namespace")
    lease = _exact_object(values["root_lease"], _LEASE_FIELDS, "root lease")
    grant = _exact_object(values["root_grant"], _GRANT_FIELDS, "root grant")
    if values["expected_authority_id"] != payload["expected_authority_id"]:
        raise ValueError("installation Authority identity differs from TLS profile")
    if type(lease["version"]) is not int or type(grant["version"]) is not int:
        raise ValueError("root budget version must be an exact integer")
    if (type(lease["limits"]) is not dict or not lease["limits"]
            or any(type(value) is not int or value <= 0
                   for value in lease["limits"].values())):
        raise ValueError("root lease requires explicit positive limits")
    if type(grant["allowed_work_kinds"]) is not list:
        raise ValueError("root grant work kinds must be a list")
    return AdminInstallationPolicy(
        namespace=NamespaceId(**namespace),
        authority_namespace=values["authority_namespace"],
        installation_id=values["installation_id"],
        manifest_digest=values["manifest_digest"],
        administrator_holder=values["administrator_holder"],
        expected_authority_id=values["expected_authority_id"],
        catalogue_hash=values["catalogue_hash"],
        scheme_version=values["scheme_version"],
        operator_version=values["operator_version"],
        policy_version=values["policy_version"],
        root_lease=BudgetLease(**lease),
        root_grant=BudgetLeaseGrant(**{
            **grant, "allowed_work_kinds": tuple(grant["allowed_work_kinds"]),
        }),
    )


def _load_profile_from_root(profile_id: str, profile_root: Path,
                            *, prepare_tls: bool = False) -> AuthorityTlsProfile:
    """Internal schema-test seam; production requires prepare_tls=True."""
    _check_profile_id(profile_id)
    profile_root = Path(profile_root)
    if not profile_root.is_absolute():
        raise ValueError("administrator profile root must be absolute")
    profile_dir = profile_root / profile_id
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        with _opened_profile(profile_dir, system) as files:
            payload = _read_profile_json(files["profile.json"])
            prepared = _prepared_ssl_context(files, system) if prepare_tls else None
    else:
        # Internal schema-test seam only. Production Windows uses pinned handles.
        _check_posix_tree(profile_dir)
        payload = _read_profile_json(profile_dir / "profile.json")
        prepared = None
    return _profile_from_payload(profile_id, profile_dir, payload, prepared)


def _build_transport_from_root(profile_id: str, profile_root: Path) -> MtlsAuthorityTransport:
    profile = _load_profile_from_root(profile_id, profile_root, prepare_tls=True)
    if platform.system() in {"Linux", "Darwin"} and profile.prepared_ssl_context is None:
        raise AuthorityProfileUnavailable("verified TLS context was not prepared")
    return MtlsAuthorityTransport({profile_id: profile})


def _build_windows_admin_transport(profile_id: str) -> MtlsAuthorityTransport:
    from .windows_profile_security import programdata_profile_root

    profile_dir = programdata_profile_root() / profile_id
    with _opened_windows_profile(profile_dir) as handles:
        _check_windows_handles(profile_dir, handles)
        profile = _profile_from_payload(
            profile_id, profile_dir, _read_profile_json(profile_dir / "profile.json")
        )
        # CPython/OpenSSL currently accepts paths only for client cert/key.
        # Every object and ancestor stays pinned against write/delete while
        # this synchronous call reopens the paths. The SSLContext then holds
        # the loaded material independently of the filesystem paths.
        profile = replace(profile, prepared_ssl_context=profile.ssl_context())
    return MtlsAuthorityTransport({profile_id: profile})


def build_admin_authority_transport(profile_id: str) -> MtlsAuthorityTransport:
    """Construct the real mTLS client only from the OS administrator root.

    Darwin has a conservative fd/ACL gate, but macOS platform qualification
    still requires native ACL and fd-alias tests plus cold installation.
    Windows pins every object with read-only sharing during handle-based
    owner/DACL checks and the subsequent synchronous OpenSSL file loads.
    Platform qualification still requires a real administrator installation.
    """
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"} and os.name != "posix":
        raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
    if system in {"Linux", "Darwin"} and os.geteuid() == 0:
        raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
    if system == "Linux":
        root = Path("/etc/sylanne/client/profiles")
    elif system == "Darwin":
        root = Path("/Library/Application Support/Sylanne/client/profiles")
    elif system == "Windows":
        return _build_windows_admin_transport(profile_id)
    else:
        raise AuthorityProfileUnavailable("unsupported Authority profile platform")
    return _build_transport_from_root(profile_id, root)


def load_admin_installation_policy(profile_id: str) -> AdminInstallationPolicy:
    """Read schema-2 policy only through the real administrator profile gate.

    This returns a value, not an authorization capability. Callers must still
    match the separately authenticated Authority installation and namespace.
    """
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.name != "posix":
            raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
        if os.geteuid() == 0:
            raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
        root = (Path("/etc/sylanne/client/profiles") if system == "Linux" else
                Path("/Library/Application Support/Sylanne/client/profiles"))
        with _opened_profile(root / profile_id, system) as files:
            payload = _read_profile_json(files["profile.json"])
            return _policy_from_payload(payload)
    if system == "Windows":
        from .windows_profile_security import programdata_profile_root

        profile_dir = programdata_profile_root() / profile_id
        with _opened_windows_profile(profile_dir) as handles:
            _check_windows_handles(profile_dir, handles)
            payload = _read_profile_json(profile_dir / "profile.json")
            return _policy_from_payload(payload)
    raise AuthorityProfileUnavailable("unsupported Authority profile platform")


def _read_windows_signing_key(handle: int) -> bytes:
    """Read the pinned object itself; reopening its pathname would break the gate."""
    if os.name != "nt":
        raise AuthorityProfileUnavailable("Windows signing-key handle is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ReadFile.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
    )
    kernel.ReadFile.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(_D11_SIGNING_KEY_BYTES + 1)
    count = ctypes.c_uint32()
    if not kernel.ReadFile(ctypes.c_void_p(handle), buffer, len(buffer),
                           ctypes.byref(count), None):
        raise AuthorityProfileUnavailable("Windows signing-key handle read failed")
    return bytes(buffer[:count.value])


def _checked_signing_key(raw: bytes) -> bytes:
    if len(raw) != _D11_SIGNING_KEY_BYTES:
        raise ValueError("administrator D11 signing key must be exactly 32 bytes")
    return raw


def _load_installation_bundle_from_root(
    profile_id: str, profile_root: Path, system: str,
) -> AdminInstallationBundle:
    """Load a POSIX installation through one pinned directory and file set."""
    _check_profile_id(profile_id)
    if system not in {"Linux", "Darwin"} or os.name != "posix":
        raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
    profile_dir = Path(profile_root) / profile_id
    with _opened_profile(profile_dir, system, signing_key=True) as files:
        payload = _read_profile_json(files["profile.json"])
        policy = _policy_from_payload(payload)
        prepared = _prepared_ssl_context(files, system)
        profile = _profile_from_payload(profile_id, profile_dir, payload, prepared)
        signing_key = _checked_signing_key(
            _read_fd_bounded(files[_D11_SIGNING_KEY], _D11_SIGNING_KEY_BYTES)
        )
    return AdminInstallationBundle(profile, policy, signing_key)


def _load_windows_installation_bundle(
    profile_id: str, profile_root: Path,
) -> AdminInstallationBundle:
    """Keep every checked Windows handle pinned until TLS and key reads finish."""
    _check_profile_id(profile_id)
    profile_dir = Path(profile_root) / profile_id
    with _opened_windows_profile(profile_dir, signing_key=True) as handles:
        _check_windows_handles(profile_dir, handles)
        payload = _read_profile_json(profile_dir / "profile.json")
        policy = _policy_from_payload(payload)
        profile = _profile_from_payload(profile_id, profile_dir, payload)
        profile = replace(profile, prepared_ssl_context=profile.ssl_context())
        signing_key = _checked_signing_key(
            _read_windows_signing_key(handles[profile_dir / _D11_SIGNING_KEY])
        )
    return AdminInstallationBundle(profile, policy, signing_key)


def load_admin_installation_bundle(profile_id: str) -> AdminInstallationBundle:
    """Load schema-2 TLS, policy and D11 key from one administrator snapshot."""
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.name != "posix":
            raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
        if os.geteuid() == 0:
            raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
        root = (Path("/etc/sylanne/client/profiles") if system == "Linux" else
                Path("/Library/Application Support/Sylanne/client/profiles"))
        return _load_installation_bundle_from_root(profile_id, root, system)
    if system == "Windows":
        from .windows_profile_security import programdata_profile_root

        return _load_windows_installation_bundle(profile_id, programdata_profile_root())
    raise AuthorityProfileUnavailable("unsupported Authority profile platform")


def load_admin_d11_signing_key(profile_id: str) -> bytes:
    """Read a schema-2 installation's separate 32-byte administrator D11 key."""
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.name != "posix":
            raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
        if os.geteuid() == 0:
            raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
        root = (Path("/etc/sylanne/client/profiles") if system == "Linux" else
                Path("/Library/Application Support/Sylanne/client/profiles"))
        with _opened_profile(root / profile_id, system, signing_key=True) as files:
            _policy_from_payload(_read_profile_json(files["profile.json"]))
            raw = _read_fd_bounded(files[_D11_SIGNING_KEY], _D11_SIGNING_KEY_BYTES)
    elif system == "Windows":
        from .windows_profile_security import programdata_profile_root

        profile_dir = programdata_profile_root() / profile_id
        with _opened_windows_profile(profile_dir, signing_key=True) as handles:
            _check_windows_handles(profile_dir, handles)
            _policy_from_payload(_read_profile_json(profile_dir / "profile.json"))
            raw = _read_windows_signing_key(handles[profile_dir / _D11_SIGNING_KEY])
    else:
        raise AuthorityProfileUnavailable("unsupported Authority profile platform")
    if len(raw) != _D11_SIGNING_KEY_BYTES:
        raise ValueError("administrator D11 signing key must be exactly 32 bytes")
    return raw


__all__ = (
    "AdminInstallationBundle", "AdminInstallationPolicy", "AuthorityProfileUnavailable",
    "build_admin_authority_transport", "load_admin_installation_policy",
    "load_admin_d11_signing_key", "load_admin_installation_bundle",
)
