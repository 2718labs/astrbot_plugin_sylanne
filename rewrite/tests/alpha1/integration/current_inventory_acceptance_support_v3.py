"""Verify real final scan originals and closed-codec negative mutations."""
from copy import deepcopy
from sylanne3.authority_service.current_filesystem_inventory_v3 import (
    verify_current_inventory_evidence_v3,require_prepared_inventory_evidence_v3,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.runtime_contracts import canonical_digest


def assert_actual_current_inventory_v3(control):
    context=control.read_verified_current_storage_v1()
    assert context.stage=='RELEASED' and context.storage_generation==2
    operation=context.prepared_original['operation_id']
    original=control.read_build_original_v1(operation_id=operation,kind='current_inventory_scan_v3')
    assert original is not None
    evidence=verify_current_inventory_evidence_v3(original['details'])
    with control._db() as db:
        assert require_prepared_inventory_evidence_v3(control,db,context.prepared_original)==evidence
    assert evidence['view']['original_manifest']==context.prepared_original['frozen_inventory_original']
    assert len(evidence['view']['mappings'])==4
    assert len(evidence['closed_predecessor']['logical_roots'])==4
    assert evidence['retired_absence']
    for mutation in ('wrong_role_path','omit_retired','omit_directory_coverage'):
        changed=deepcopy(evidence)
        if mutation=='wrong_role_path':
            changed['view']['mappings'][0]['selected_db']=changed['view']['mappings'][1]['selected_db']
            changed['view_digest']=canonical_digest(changed['view'])
        elif mutation=='omit_retired':changed['retired_absence']=changed['retired_absence'][1:]
        else:
            assert changed['directory_coverage']
            changed['directory_coverage']=changed['directory_coverage'][1:]
        changed['scan_digest']=canonical_digest({k:v for k,v in changed.items() if k!='scan_digest'})
        try:verify_current_inventory_evidence_v3(changed)
        except (AuthorityUnavailable,ValueError,TypeError):pass
        else:raise AssertionError('recommitted invalid current inventory accepted: '+mutation)
    return True


def instrument_actual_inventory_negatives_v3(maintenance):
    """Inspect the real issued view; forward every valid scan unchanged."""
    from dataclasses import replace
    from pathlib import Path
    original=maintenance.current_source_location.scan_installation_inventory_v1
    tested=False
    def scan(view):
        nonlocal tested
        if tested:return original(view)
        tested=True
        try:original(replace(view))
        except AuthorityUnavailable:pass
        else:raise AssertionError('copied inventory capability accepted')
        retired=next(Path(row[2]) for mapping in view.mappings for row in mapping.ancestry if row[2]!=mapping.selected_db)
        assert not retired.exists() and not retired.is_symlink()
        retired.write_bytes(b'isolated recreated retired resource negative')
        try:
            try:original(view)
            except AuthorityUnavailable:pass
            else:raise AssertionError('recreated retired database accepted')
        finally:retired.unlink()
        retired.symlink_to(retired.with_name('absent-negative-target'))
        try:
            try:original(view)
            except AuthorityUnavailable:pass
            else:raise AssertionError('dangling retired database symlink accepted')
        finally:retired.unlink()
        directory=Path(next(r.path for r in view.manifest.resources if r.kind=='rebuild_temp'))
        extra=directory/'unrecognized-extra-negative.bin'
        assert not extra.exists();extra.write_bytes(b'coverage must retain all managed children')
        try:assert str(extra) in {r['path'] for r in original(view)['scan']['observed']}
        finally:extra.unlink()
        return original(view)
    maintenance.current_source_location.scan_installation_inventory_v1=scan
