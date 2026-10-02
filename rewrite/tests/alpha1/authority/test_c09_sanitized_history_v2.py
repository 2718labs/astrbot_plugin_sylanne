"""Real synthetic source producer; selector/process disposal tested separately."""
import copy
import json

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_sanitized_history_v2 import (
    build_sanitized_history_v2,read_sanitized_history_v2,verify_sanitized_history_v2,
)
from c09_history_fixture_v2 import make_history_fixture


@pytest.fixture
def source(tmp_path):
    control,gate,inventory=make_history_fixture(tmp_path,build=False)
    try:yield control,gate,inventory,tmp_path/'history-v2.json'
    finally:control.lease.close()


def test_actual_source_signed_opaque_history_and_independent_read(source):
    control,gate,inventory,target=source
    value=build_sanitized_history_v2(control,target,gate=gate,inventory_manifest=inventory)
    assert value==read_sanitized_history_v2(control,target)
    assert value['frames']==[] and value['generation']==1
    assert value['old_control_files'][0]['resolved_path']==str(control.path)
    assert value['writer_quiescence']['active_writers']==0
    assert control.path.exists()
    assert sum(len(f['row_commitments']) for f in value['source_inventory']['families'])==7


@pytest.mark.parametrize('field',['family','snapshot','partial_history','generation','signature'])
def test_missing_carriers_partial_history_and_rollback_refuse(source,field):
    control,gate,inventory,target=source
    value=build_sanitized_history_v2(control,target,gate=gate,inventory_manifest=inventory)
    bad=copy.deepcopy(value)
    if field=='family':bad['carrier_inventory']['families'].pop()
    elif field=='snapshot':bad['carrier_inventory']['directories'].pop()
    elif field=='partial_history':bad['frames'].append({})
    elif field=='generation':bad['generation']=0
    else:bad['signature']='0'*64
    with pytest.raises(AuthorityUnavailable):verify_sanitized_history_v2(control,bad)
    assert control.path.exists()


def test_nonempty_registered_snapshot_refuses_without_deleting(source):
    control,gate,inventory,target=source
    snapshot=next(r for r in inventory.resources if r.kind=='controlled_backup')
    from pathlib import Path
    saved=Path(snapshot.path)/'synthetic-full-old-control-copy'
    saved.write_bytes(b'synthetic retained full carrier')
    with pytest.raises(AuthorityUnavailable,match='nonempty external carrier'):
        build_sanitized_history_v2(control,target,gate=gate,inventory_manifest=inventory)
    assert saved.read_bytes()==b'synthetic retained full carrier' and not target.exists()


def test_ordinary_dto_and_noncanonical_candidate_never_issue_rights(source):
    control,gate,inventory,target=source
    with pytest.raises(AuthorityUnavailable,match='actual installed writer gate'):
        build_sanitized_history_v2(control,target,gate=object(),inventory_manifest=inventory)
    value=build_sanitized_history_v2(control,target,gate=gate,inventory_manifest=inventory)
    target.write_text(json.dumps(value,indent=2))
    with pytest.raises(AuthorityUnavailable,match='canonical'):
        read_sanitized_history_v2(control,target)
