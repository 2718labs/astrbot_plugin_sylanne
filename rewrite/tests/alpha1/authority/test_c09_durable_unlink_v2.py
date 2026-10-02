"""Isolated synthetic inode disposal; no four-store/recovery PASS claim."""
import os

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_control_v1 import file_observation_v1
from sylanne3.authority_service.c09_durable_unlink_v2 import unlink_inventory_member_durably_v2


pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Linux durable unlink implementation')


def test_real_nonempty_unlink_and_absent_crash_resume(tmp_path):
    path = tmp_path / 'synthetic-retired.db'
    path.write_bytes(b'synthetic private payload' * 1024)
    before = file_observation_v1(path)
    unlink_inventory_member_durably_v2(before)
    assert not path.exists()
    unlink_inventory_member_durably_v2(before)


def test_changed_member_is_preserved(tmp_path):
    path = tmp_path / 'synthetic-retired.db'; path.write_bytes(b'old')
    before = file_observation_v1(path)
    path.write_bytes(b'changed')
    with pytest.raises(AuthorityUnavailable):
        unlink_inventory_member_durably_v2(before)
    assert path.read_bytes() == b'changed'


def test_hardlinked_member_is_preserved(tmp_path):
    path = tmp_path / 'synthetic-retired.db'; path.write_bytes(b'synthetic')
    before = file_observation_v1(path)
    os.link(path, tmp_path / 'unregistered-copy')
    with pytest.raises(AuthorityUnavailable, match='unaliased'):
        unlink_inventory_member_durably_v2(before)
    assert path.exists()


def test_symlink_replacement_is_preserved(tmp_path):
    path = tmp_path / 'synthetic-retired.db'; path.write_bytes(b'synthetic')
    before = file_observation_v1(path)
    path.unlink()
    target = tmp_path / 'survivor'; target.write_bytes(b'survivor')
    path.symlink_to(target)
    with pytest.raises(AuthorityUnavailable):
        unlink_inventory_member_durably_v2(before)
    assert target.read_bytes() == b'survivor' and path.is_symlink()


def test_fsync_failure_cannot_report_success_and_resume_is_durable(tmp_path, monkeypatch):
    path = tmp_path / 'synthetic-retired.db'; path.write_bytes(b'synthetic')
    before = file_observation_v1(path)
    actual = os.fsync
    calls = []
    def failed(fd):
        calls.append(fd)
        raise OSError('synthetic power-loss boundary')
    monkeypatch.setattr(os, 'fsync', failed)
    with pytest.raises(AuthorityUnavailable, match='durability'):
        unlink_inventory_member_durably_v2(before)
    assert not path.exists() and len(calls) == 1
    monkeypatch.setattr(os, 'fsync', actual)
    unlink_inventory_member_durably_v2(before)


def test_inode_lock_is_held_at_unlink_and_directory_fsync_follows(tmp_path, monkeypatch):
    import fcntl
    import stat
    path = tmp_path / 'synthetic-retired.db'; path.write_bytes(b'synthetic')
    before = file_observation_v1(path)
    actual_unlink, actual_fsync = os.unlink, os.fsync
    events = []
    def checked_unlink(name, *, dir_fd):
        fd = os.open(name, os.O_RDONLY, dir_fd=dir_fd)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        events.append('locked-unlink')
        actual_unlink(name, dir_fd=dir_fd)
    def checked_fsync(fd):
        assert stat.S_ISDIR(os.fstat(fd).st_mode)
        assert not path.exists()
        events.append('directory-fsync')
        actual_fsync(fd)
    monkeypatch.setattr(os, 'unlink', checked_unlink)
    monkeypatch.setattr(os, 'fsync', checked_fsync)
    unlink_inventory_member_durably_v2(before)
    assert events == ['locked-unlink', 'directory-fsync']


def test_active_os_lock_prevents_disposal(tmp_path):
    import fcntl
    path = tmp_path / 'synthetic-retired.db'; path.write_bytes(b'synthetic')
    before = file_observation_v1(path)
    with path.open('rb') as live:
        fcntl.flock(live, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(AuthorityUnavailable, match='OS disposal'):
            unlink_inventory_member_durably_v2(before)
    assert path.read_bytes() == b'synthetic'
