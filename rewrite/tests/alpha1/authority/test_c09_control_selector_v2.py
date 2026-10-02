"""Isolated synthetic V2 selector fault boundaries; no installed backend PASS."""
import json
import os
from pathlib import Path
import stat

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
from sylanne3.authority_service.c09_control_selector_v2 import InstalledC09ControlSelectorV2

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX selector implementation")


def _open_control(root):
    lease = InstalledC09InstanceLeaseV1(root / "lease")
    control = C09StorageControlV1(control_path=root / "control.db", key_path=root / "key",
        installation_id="selector-install", authority_id="selector-authority",
        control_store_id="selector-control", key_id="selector-key", lease=lease,
        resource_roots=(root / "state",))
    return control, lease


def _selector(control):
    return InstalledC09ControlSelectorV2(control, str(control.path) + ".selector-v2",
                                         str(control.path) + ".selector-v2.journal")


@pytest.fixture
def empty_control(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "key").write_bytes(b"synthetic-selector-key-only-32bytes!")
    control, lease = _open_control(tmp_path)
    try:
        yield control
    finally:
        lease.close()


def test_no_intent_is_hold_and_never_creates_control(empty_control):
    selector = _selector(empty_control)
    for action in (selector.current, selector.switch, selector.dispose):
        with pytest.raises(AuthorityUnavailable, match="HOLD"):
            action()
    assert not empty_control.path.exists()


def test_alternate_paths_cannot_create_double_current(empty_control):
    with pytest.raises(AuthorityUnavailable, match="unique installed"):
        InstalledC09ControlSelectorV2(empty_control, empty_control.path.parent / "other-current",
                                      empty_control.path.parent / "other-journal")


def test_actual_lease_required_and_inode_replacement_refused(empty_control):
    selector = _selector(empty_control)
    lease_path = empty_control.lease.path
    lease_path.rename(str(lease_path) + ".old")
    lease_path.write_bytes(b"unrelated replacement")
    with pytest.raises(AuthorityUnavailable, match="lock inode replaced"):
        selector.current()


def test_expired_lease_refuses_all_operations(empty_control):
    selector = _selector(empty_control)
    empty_control.lease.close()
    for action in (selector.current, selector.switch, selector.dispose):
        with pytest.raises(AuthorityUnavailable, match="lease expired"):
            action()


def test_unregistered_existing_current_is_preserved(empty_control):
    selector = _selector(empty_control)
    selector.selector_path.write_bytes(b"existing real or staging file")
    with pytest.raises(AuthorityUnavailable, match="without journal"):
        selector.current()
    assert selector.selector_path.read_bytes() == b"existing real or staging file"


def test_torn_journal_is_hold_and_preserved(empty_control):
    selector = _selector(empty_control)
    selector.journal_path.write_bytes(b'{"partial":')
    with pytest.raises(AuthorityUnavailable, match="torn journal"):
        selector.current()
    assert selector.journal_path.read_bytes() == b'{"partial":'


def test_symlink_and_hardlink_journals_refuse_without_deletion(empty_control):
    selector = _selector(empty_control)
    survivor = empty_control.path.parent / "survivor"
    survivor.write_bytes(b"untouched")
    selector.journal_path.symlink_to(survivor)
    with pytest.raises(AuthorityUnavailable):
        selector.current()
    selector.journal_path.unlink()
    os.link(survivor, selector.journal_path)
    with pytest.raises(AuthorityUnavailable, match="unaliased"):
        selector.current()
    assert survivor.read_bytes() == b"untouched"


def _prepare_fixture(root):
    from c09_history_fixture_v2 import make_history_fixture
    control, gate, inventory = make_history_fixture(root)
    selector = _selector(control)
    selector.prepare(Path(root) / 'history-v2.json')
    return control


@pytest.fixture
def prepared_live(tmp_path):
    control = _prepare_fixture(tmp_path)
    try:
        yield control, _selector(control), tmp_path / 'history-v2.json'
    finally:
        control.lease.close()


@pytest.fixture
def prepared_retired(tmp_path):
    """Actual finite child producer exit; no mocked retirement or signing DTO."""
    import subprocess
    import sys
    from c09_history_fixture_v2 import reopen_control
    test_dir = Path(__file__).parent
    source_dir = Path(__file__).parents[3]
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join((str(source_dir), str(test_dir))))
    run = subprocess.run([sys.executable, '-c',
        'import sys; from test_c09_control_selector_v2 import _prepare_fixture; '
        'control = _prepare_fixture(sys.argv[1]); control.lease.close()', str(tmp_path)],
        capture_output=True, text=True, env=environment, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    control = reopen_control(tmp_path)
    try:
        yield control, _selector(control), tmp_path / 'history-v2.json'
    finally:
        control.lease.close()


def _stages(selector):
    return [json.loads(line)['stage'] for line in selector.journal_path.read_bytes().splitlines()]


def test_signed_prepare_repeat_and_same_producer_stays_hold(prepared_live):
    control, selector, candidate = prepared_live
    assert selector.control is control
    first = selector.prepare(candidate)
    assert first['stage'] == 'INTENT'
    assert selector.prepare(candidate) == first
    with pytest.raises(AuthorityUnavailable, match='process remains alive'):
        selector.switch()
    with pytest.raises(AuthorityUnavailable, match='unfinished'):
        selector.current()
    assert control.path.exists() and _stages(selector) == ['INTENT']


def test_replaced_candidate_inode_is_rejected(prepared_live):
    control, selector, candidate = prepared_live
    replacement = candidate.with_suffix('.replacement')
    replacement.write_bytes(candidate.read_bytes())
    os.replace(replacement, candidate)
    with pytest.raises(AuthorityUnavailable, match='exact inode'):
        selector.prepare(candidate)
    assert control.path.exists()


def test_partial_history_and_wrong_generation_reject_actual_reader(tmp_path):
    from c09_history_fixture_v2 import make_history_fixture
    from sylanne3.runtime_contracts import canonical_serialize
    control, _, _ = make_history_fixture(tmp_path)
    try:
        selector = _selector(control)
        candidate = tmp_path / 'history-v2.json'
        original = json.loads(candidate.read_bytes())
        for field in ('carrier_inventory', 'generation'):
            value = json.loads(json.dumps(original))
            if field == 'carrier_inventory':
                value[field]['families'].pop()
            else:
                value[field] = 0
            candidate.write_text(canonical_serialize(value))
            with pytest.raises(AuthorityUnavailable):
                selector.prepare(candidate)
        assert not selector.journal_path.exists() and control.path.exists()
    finally:
        control.lease.close()


def test_real_retired_switch_dispose_repeat_and_independent_reader(prepared_retired):
    from sylanne3.authority_service.c09_sanitized_history_v2 import InstalledC09StorageReaderV2
    control, selector, candidate = prepared_retired
    switched = selector.switch()
    assert switched['stage'] == 'SWITCHED' and control.path.exists()
    assert selector.switch() == switched
    with pytest.raises(AuthorityUnavailable, match='unfinished'):
        selector.current()
    disposed = selector.dispose()
    assert disposed['stage'] == 'DISPOSED' and not control.path.exists()
    assert selector.dispose() == disposed and selector.prepare(candidate)['stage'] == 'INTENT'
    assert selector.switch() == switched
    current = selector.current()
    assert current['candidate_path'] == str(candidate)
    assert _stages(selector) == ['INTENT', 'SWITCHED', 'DISPOSED']
    reader = InstalledC09StorageReaderV2(control=control, selector=selector)
    context, frames = reader.read_verified_frames_v2()
    assert frames == () and context.history_digest == current['history_digest']
    context.require_current('recovery')
    with pytest.raises(AuthorityUnavailable, match='business/accounting'):
        context.require_current('business')
    with pytest.raises(AuthorityUnavailable, match='absent'):
        control.read_verified_current_storage_v1()


@pytest.mark.parametrize('point', ['before_replace', 'after_replace', 'selector_file_fsync',
                                   'selector_parent_fsync', 'unlink_parent_fsync', 'proof_fsync'])
def test_actual_failure_boundaries_hold_then_resume(prepared_retired, monkeypatch, point):
    control, selector, _ = prepared_retired
    real_replace, real_fsync = os.replace, os.fsync
    fired = False
    if point in {'unlink_parent_fsync', 'proof_fsync'}:
        selector.switch()
    def replace(source, target, **kwargs):
        nonlocal fired
        if point == 'before_replace' and not fired:
            fired = True
            raise OSError('synthetic before atomic replacement')
        result = real_replace(source, target, **kwargs)
        if point == 'after_replace' and not fired:
            fired = True
            raise OSError('synthetic immediately after atomic replacement')
        return result
    def fsync(fd):
        nonlocal fired
        opened = os.fstat(fd)
        directory = stat.S_ISDIR(opened.st_mode)
        selected = selector.selector_path.exists()
        selected_inode = selector.selector_path.stat().st_ino if selected else None
        journal_inode = selector.journal_path.stat().st_ino
        fail = ((point == 'selector_file_fsync' and opened.st_ino == selected_inode and not directory)
            or (point == 'selector_parent_fsync' and directory and selected)
            or (point == 'unlink_parent_fsync' and directory and not control.path.exists())
            or (point == 'proof_fsync' and opened.st_ino == journal_inode and _stages(selector)[-1] == 'DISPOSED'))
        if fail and not fired:
            fired = True
            raise OSError('synthetic actual fsync failure')
        return real_fsync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os, 'replace', replace)
        patch.setattr(os, 'fsync', fsync)
        action = selector.dispose if point in {'unlink_parent_fsync', 'proof_fsync'} else selector.switch
        with pytest.raises(AuthorityUnavailable, match='HOLD'):
            action()
        assert fired
        # A failed proof fsync may leave a complete visible record; a fresh
        # current() explicitly fsyncs that record before returning it.
        if point != 'proof_fsync':
            with pytest.raises(AuthorityUnavailable, match='unfinished'):
                selector.current()
    assert selector.switch()['stage'] == 'SWITCHED'
    assert selector.dispose()['stage'] == 'DISPOSED'
    assert selector.current()['generation'] == 1
    assert not control.path.exists()
    assert _stages(selector) == ['INTENT', 'SWITCHED', 'DISPOSED']


@pytest.mark.parametrize('point', ['before_switch', 'before_dispose'])
def test_changed_old_control_is_preserved(prepared_retired, point):
    control, selector, _ = prepared_retired
    if point == 'before_dispose':
        selector.switch()
    with control.path.open('ab') as stream:
        stream.write(b'synthetic unexpected mutation')
    changed = control.path.read_bytes()
    action = selector.dispose if point == 'before_dispose' else selector.switch
    with pytest.raises(AuthorityUnavailable, match='old Control changed'):
        action()
    assert control.path.read_bytes() == changed


def test_unregistered_companion_is_preserved(prepared_retired):
    control, selector, _ = prepared_retired
    selector.switch()
    companion = Path(str(control.path) + '-journal')
    companion.write_bytes(b'unregistered synthetic companion')
    with pytest.raises(AuthorityUnavailable, match='unregistered companion'):
        selector.dispose()
    assert control.path.exists() and companion.exists()


@pytest.mark.parametrize('target', ['selector', 'journal'])
def test_wrong_installed_inode_is_hold(prepared_retired, target):
    control, selector, _ = prepared_retired
    selector.switch()
    path = selector.selector_path if target == 'selector' else selector.journal_path
    replacement = path.with_suffix('.replacement')
    replacement.write_bytes(path.read_bytes())
    os.replace(replacement, path)
    with pytest.raises(AuthorityUnavailable, match='inode'):
        selector.dispose()
    assert control.path.exists()


def test_journal_rollback_and_double_current_hold(prepared_retired):
    control, selector, _ = prepared_retired
    selector.switch()
    journal = selector.journal_path.read_bytes()
    selector.journal_path.write_bytes(journal.splitlines(keepends=True)[0])
    with pytest.raises(AuthorityUnavailable, match='unfinished'):
        selector.current()
    selector._pending.write_bytes(selector.selector_path.read_bytes())
    with pytest.raises(AuthorityUnavailable, match='double current'):
        selector.switch()
    assert control.path.exists()
