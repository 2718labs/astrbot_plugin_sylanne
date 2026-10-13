"""Descriptor-pinned administrator-owned Linux installation assets."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import stat

from .contract import AuthorityUnavailable


def require_linux_administrator_v1():
    if os.name != "posix" or not Path("/proc/sys/kernel/random/boot_id").is_file() or os.geteuid() != 0:
        raise AuthorityUnavailable("Linux installation administration requires effective UID 0")


def _probe_acl_size_v1(fd,key):
    # ACL bytes are never consumed: existence alone is a rejection predicate.
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    probe=libc.fgetxattr;probe.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t)
    probe.restype=ctypes.c_ssize_t
    size=probe(fd,key.encode('ascii'),None,0)
    if size<0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
    return size


def _check(fd, *, directory, private=False, allowed_gid=None, meter=None):
    if meter is not None:meter.require_available(4096)
    info = os.fstat(fd)
    if meter is not None:meter.charge_read(len(json.dumps(tuple(info),separators=(",",":")).encode("ascii")))
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise AuthorityUnavailable("installed Linux object is not administrator-owned and immutable to Host")
    if not directory and (info.st_nlink != 1 or private and (info.st_mode & 0o007
            or info.st_mode & 0o040 and info.st_gid != allowed_gid)):
        raise AuthorityUnavailable("installed Linux private object permissions differ")
    for key in (("system.posix_acl_access", "system.posix_acl_default") if directory else ("system.posix_acl_access",)):
        try:
            if meter is None:os.getxattr(fd,key)
            else:
                meter.require_available(8)
                _probe_acl_size_v1(fd,key);meter.charge_read(8)
        except OSError as exc:
            if exc.errno == errno.ENODATA:
                continue
            raise AuthorityUnavailable("installed Linux ACL could not be verified") from exc
        raise AuthorityUnavailable("installed Linux extended ACL is not permitted")


@contextmanager
def opened_installed_file_v1(path, *, private=False, allowed_gid=None, meter=None):
    path = Path(path)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise AuthorityUnavailable("absolute installed Linux path required")
    descriptors = []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(fd)
        _check(fd, directory=True, meter=meter)
        for part in path.parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            descriptors.append(fd)
            _check(fd, directory=True, meter=meter)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        descriptors.append(fd)
        _check(fd, directory=False, private=private, allowed_gid=allowed_gid, meter=meter)
        yield fd
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def read_installed_bytes_v1(path, *, limit=1048576, private=False, allowed_gid=None):
    with opened_installed_file_v1(path, private=private, allowed_gid=allowed_gid) as fd:
        if os.fstat(fd).st_size > limit:
            raise AuthorityUnavailable("installed Linux file exceeds limit")
        value = os.read(fd, limit + 1)
        if len(value) > limit or os.read(fd, 1):
            raise AuthorityUnavailable("installed Linux file exceeds limit")
        return value


def read_installed_json_v1(path, *, limit=1048576):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate installed field")
            result[key] = value
        return result
    try:
        value = json.loads(read_installed_bytes_v1(path, limit=limit), object_pairs_hook=unique,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite installed value")))
    except (ValueError, UnicodeError) as exc:
        raise AuthorityUnavailable("installed Linux JSON is invalid") from exc
    if type(value) is not dict:
        raise AuthorityUnavailable("installed Linux object required")
    return value
