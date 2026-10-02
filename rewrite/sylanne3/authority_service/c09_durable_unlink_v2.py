"""Durable Linux disposal of one already-authorized, closed inventory member.

This helper supplies no deletion authority. The installed surface cleaner owns
the signed plan, instance lease, retired-process and recovery qualifications.
"""
import hashlib
import os
from pathlib import Path
import stat

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import _directory_path


def unlink_inventory_member_durably_v2(before):
    """Hold the exact inode lock through unlink and parent fsync, or refuse.

    An absent member is crash-resumable only after fsync of its actual parent.
    Hard links refuse: removing one name cannot prove disposal of that inode.
    """
    if os.name != 'posix':
        raise AuthorityUnavailable('C09 durable unlink needs an installed OS implementation; HOLD')
    import fcntl
    path = Path(before['resolved_path'])
    parent = _directory_path(path.parent)
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        parent_stat = os.stat(parent, follow_symlinks=False)
        opened_parent = os.fstat(directory)
        if (parent_stat.st_dev, parent_stat.st_ino) != (opened_parent.st_dev, opened_parent.st_ino):
            raise AuthorityUnavailable('C09 disposal parent changed')
        try:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            os.fsync(directory)
            return
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise AuthorityUnavailable('C09 disposal requires an unaliased regular inode; HOLD')
        hasher = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            hasher.update(block)
        final = os.fstat(descriptor)
        observed = dict(resolved_path=str(path), device=final.st_dev, file_id=final.st_ino,
            prepared_size=final.st_size, prepared_mtime_ns=final.st_mtime_ns,
            prepared_sha256=hasher.hexdigest())
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if (observed != before or any(getattr(initial, k) != getattr(final, k) for k in stable)
                or final.st_nlink != 1
                or (named.st_dev, named.st_ino) != (final.st_dev, final.st_ino)):
            raise AuthorityUnavailable('C09 managed file changed before durable unlink')
        os.unlink(path.name, dir_fd=directory)
        os.fsync(directory)
        if os.fstat(descriptor).st_nlink != 0:
            raise AuthorityUnavailable('C09 disposed inode retains an unregistered link; HOLD')
    except OSError as exc:
        raise AuthorityUnavailable('C09 OS disposal or directory durability unavailable; HOLD') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)
