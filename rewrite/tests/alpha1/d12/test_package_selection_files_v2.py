"""Actual filesystem CAS, not privileged deployment or maintenance acceptance."""
from dataclasses import asdict
import os
from uuid import uuid4
import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d12_package_files_v2 import (
    PackageSelectionV2, RegisteredPackageV2, SELECTION_SCHEMA,
    _canonical, _digest, _compare_replace_pointer_at, _read_at,
    decode_package_selection_v2, next_package_selection_v2,
    InstalledPackageSelectionFilesV2,
)


def original():
    body = dict(schema=SELECTION_SCHEMA, installation_id='installation:test', revision=0, package_epoch=0,
        operation_id=str(uuid4()), release_ref='release:old', manifest_sha256='a'*64,
        prior_selection_digest=None, cohort_ref='cohort:old', cohort_digest='c'*64)
    return PackageSelectionV2(**body, selection_digest=_digest(body))


def candidate():
    return RegisteredPackageV2('release:new', '/opt/sylanne/releases/new', 'b'*64, '3.0.0-alpha1')


def test_selection_transition_is_exact_and_tamper_evident():
    old = original()
    new = next_package_selection_v2(old, operation_id=str(uuid4()), package=candidate(), cohort_ref='cohort:new', cohort_digest='d'*64)
    assert new.revision == 1 and new.prior_selection_digest == old.selection_digest
    assert decode_package_selection_v2(asdict(new)) == new
    with pytest.raises(ValueError): decode_package_selection_v2({**asdict(new), 'revision':2})
    with pytest.raises(ValueError): decode_package_selection_v2({**asdict(new), 'unused':True})
    with pytest.raises(ValueError): next_package_selection_v2(old, operation_id='not-uuid', package=candidate(), cohort_ref='cohort:new', cohort_digest='d'*64)
    with pytest.raises(ValueError): RegisteredPackageV2('legacy', '/opt/sylanne/releases/old', 'a'*64, '2.5.1')


def test_real_atomic_pointer_exact_recovery_and_third_value_hold(tmp_path):
    old = original(); new = next_package_selection_v2(old, operation_id=str(uuid4()), package=candidate(), cohort_ref='cohort:new', cohort_digest='d'*64)
    (tmp_path/'selection.json').write_bytes(_canonical(asdict(old)))
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert _compare_replace_pointer_at(fd, expected=old, desired=new) == new
        assert _read_at(fd, 'selection.json') == new
        # Lost ACK replay never allocates another revision or changes the file.
        inode = (tmp_path/'selection.json').stat().st_ino
        assert _compare_replace_pointer_at(fd, expected=old, desired=new) == new
        assert (tmp_path/'selection.json').stat().st_ino == inode
        third = next_package_selection_v2(new, operation_id=str(uuid4()), package=candidate(), cohort_ref='cohort:new', cohort_digest='d'*64)
        (tmp_path/'selection.json').write_bytes(_canonical(asdict(third)))
        with pytest.raises(AuthorityUnavailable, match='pointer changed'):
            _compare_replace_pointer_at(fd, expected=old, desired=new)
        assert _read_at(fd, 'selection.json') == third
    finally: os.close(fd)


def test_selection_symlink_and_unprotected_production_path_are_rejected(tmp_path):
    old=original(); new=next_package_selection_v2(old, operation_id=str(uuid4()), package=candidate(), cohort_ref='cohort:new', cohort_digest='d'*64)
    target=tmp_path/'target'; target.write_bytes(_canonical(asdict(old)))
    (tmp_path/'selection.json').symlink_to(target)
    fd=os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError): _compare_replace_pointer_at(fd, expected=old, desired=new)
    finally: os.close(fd)
    # This task is intentionally not a privileged production installation.
    with pytest.raises(AuthorityUnavailable): InstalledPackageSelectionFilesV2(control_directory=tmp_path)
    assert target.read_bytes() == _canonical(asdict(old))
