"""New synthetic C09 source installation; no real environment state is read."""
from pathlib import Path
import sqlite3

from sylanne3.runtime_contracts import canonical_digest
from sylanne3.runtime.c09_installation_inventory_v2 import InstalledResourceV2, InstallationFilesystemManifestV2
from sylanne3.authority_service.c09_storage_control_v1 import (
    C09StorageControlV1,InstalledC09InstanceLeaseV1,ROLES,digest,file_observation_v1,
)
from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1


def reopen_control(root):
    root=Path(root)
    lease=InstalledC09InstanceLeaseV1(root/'lease')
    return C09StorageControlV1(control_path=root/'control.db',key_path=root/'key',
        installation_id='selector-install',authority_id='selector-authority',
        control_store_id='selector-control',key_id='selector-key',lease=lease,resource_roots=(root/'state',))


def make_history_fixture(root,*,build=True):
    root=Path(root);root.mkdir(exist_ok=True)
    state=root/'state';state.mkdir()
    (root/'key').write_bytes(b'synthetic-selector-key-only-32bytes!')
    control=reopen_control(root)
    resources=[];members=[]
    for role in ROLES:
        path=state/(role+'.db')
        with sqlite3.connect(path) as db:
            db.execute('VACUUM')
        for kind,suffix in (('sqlite_db',''),('sqlite_wal','-wal'),('sqlite_shm','-shm')):
            resources.append(InstalledResourceV2(role+':'+kind,kind,str(path)+suffix,
                'fixture/persona',role,1,0,'fixture-owner','sqlite',('sqlite_wal_free_pages',),'fixture-v1'))
        members.append(dict(role=role,**file_observation_v1(path),store_id='fixture:'+role,
            schema_version='1',namespace='fixture/persona',storage_generation=0,
            incarnation_or_journal_id='fixture:'+role,logical_data_root='a'*64,
            schema_objects_digest='b'*64,cold_read_digest='c'*64,wal_policy='closed',companion_resource_ids=[]))
    for kind in ('controlled_backup','export','rebuild_temp','cache'):
        path=state/kind;path.mkdir()
        resources.append(InstalledResourceV2(kind,kind,str(path),'fixture/persona',kind,1,0,
            'fixture-owner','directory',('controlled_backups',),'fixture-v1'))
    resources=tuple(sorted(resources,key=lambda r:r.path))
    schema='sylanne3.c09.installation_filesystem_manifest.v2'
    inventory=InstallationFilesystemManifestV2(control.authority_id,control.installation_id,'fixture/persona',resources,
        canonical_digest((schema,control.authority_id,control.installation_id,'fixture/persona',resources)))
    manifest=dict(schema='sylanne3.c09.storage_manifest.v1',authority_id=control.authority_id,
        installation_id=control.installation_id,cohort_namespaces=['fixture/persona'],generation=0,
        prior_manifest_digest=None,members=members,inventory_manifest_digest=inventory.manifest_digest,
        certificate_digest=None,graph_issue_digest=None,recovery_pin_digest=None,
        cumulative_tombstone_root='e'*64,deletion_watermark=0)
    manifest['manifest_digest']=digest(manifest)
    control.bootstrap_installed_storage_v1(manifest=manifest)
    gate=InstalledC09WriterGateV1(control=control)
    if build:
        from sylanne3.authority_service.c09_sanitized_history_v2 import build_sanitized_history_v2
        build_sanitized_history_v2(control,root/'history-v2.json',gate=gate,inventory_manifest=inventory)
    return control,gate,inventory
