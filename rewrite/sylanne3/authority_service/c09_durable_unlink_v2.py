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


class InstalledDurableUnlinkProgressV3:
    """Keep one exact retired inode locked while its chunks share real quanta."""
    def __init__(self, before):
        if os.name != 'posix':
            raise AuthorityUnavailable('installed durable disposal requires its real OS implementation')
        import fcntl
        self.before = dict(before)
        self.path = Path(before['resolved_path'])
        self.parent = _directory_path(self.path.parent)
        self.directory = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.descriptor = None
        self.hasher = hashlib.sha256()
        self.offset = 0
        self.last_chunk_digest = None
        self.verified = False
        self.absent = False
        try:
            actual, opened = os.stat(self.parent, follow_symlinks=False), os.fstat(self.directory)
            if (actual.st_dev, actual.st_ino) != (opened.st_dev, opened.st_ino):
                raise AuthorityUnavailable('actual disposal directory changed')
            try:
                self.descriptor = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory)
            except FileNotFoundError:
                # The caller has already authenticated the signed one-file plan.
                os.fsync(self.directory)
                self.absent = self.verified = True
                return
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.initial = os.fstat(self.descriptor)
            if (not stat.S_ISREG(self.initial.st_mode) or self.initial.st_nlink != 1
                    or (self.initial.st_dev, self.initial.st_ino, self.initial.st_size, self.initial.st_mtime_ns) !=
                       (before['device'], before['file_id'], before['prepared_size'], before['prepared_mtime_ns'])):
                raise AuthorityUnavailable('actual disposal inode differs from authenticated plan')
        except BaseException:
            self.close()
            raise

    def _stable(self):
        current = os.fstat(self.descriptor)
        named = os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if (any(getattr(current, key) != getattr(self.initial, key) for key in fields)
                or (named.st_dev, named.st_ino) != (current.st_dev, current.st_ino)):
            raise AuthorityUnavailable('actual retired inode changed during reserved disposal')

    def advance(self, *, meter):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        if meter is not current_c09_sql_meter_v2():
            raise AuthorityUnavailable('actual installed disposal quantum required')
        if self.verified:
            return True
        self._stable()
        size = min(16384, self.initial.st_size - self.offset)
        meter.require_available(size + 512)
        data = os.read(self.descriptor, size)
        meter.charge_read(len(data) + 64)
        if len(data) != size:
            raise AuthorityUnavailable('actual retired file ended before its authenticated boundary')
        self.last_chunk_digest = hashlib.sha256(data).hexdigest()
        self.hasher.update(data)
        self.offset += len(data)
        self._stable()
        if self.offset == self.initial.st_size:
            if os.read(self.descriptor, 1) or self.before['prepared_sha256'] is not None and self.hasher.hexdigest() != self.before['prepared_sha256']:
                raise AuthorityUnavailable('actual retired content differs from signed plan')
            self.verified = True
        return self.verified

    def finish(self, *, meter):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        if meter is not current_c09_sql_meter_v2() or not self.verified:
            raise AuthorityUnavailable('actual complete reserved disposal proof required')
        if not self.absent:
            self._stable()
            meter.charge_write(128)
            os.unlink(self.path.name, dir_fd=self.directory)
            os.fsync(self.directory)
            if os.fstat(self.descriptor).st_nlink != 0:
                raise AuthorityUnavailable('actual disposed inode retains an unregistered hard link')
        self.close()
        return {'kind': 'removed_file', 'resolved_path': str(self.path), 'state': 'absent'}

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
