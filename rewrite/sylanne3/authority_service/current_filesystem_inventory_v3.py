"""Issuer-bound current projection of an unchanged installer filesystem manifest.

The view carries no new resource registration. All original directory children
remain inventoried, including hardlink aliases and unrecognized files.
"""
from __future__ import annotations
from dataclasses import dataclass,asdict
import os
from pathlib import Path
import stat
import weakref

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..runtime.c09_installation_inventory_v2 import (
    InstallationFilesystemManifestV2,InstallationFilesystemScanV2,_observe,
)

SCHEMA='sylanne3.c09.current-filesystem-scan.v3'
ROLES=('core','deletion','execution','graph')

@dataclass(frozen=True,slots=True)
class _RoleMappingV3:
    role: str
    store_id: str
    original_db: str
    selected_db: str
    resource_ids: tuple[str,str,str]
    ancestry: tuple[tuple[int,str,str,str,str,str,str,int,int],...]

@dataclass(frozen=True,slots=True,weakref_slot=True)
class _IssuedFilesystemInventoryV3:
    manifest: InstallationFilesystemManifestV2
    location: object
    mappings: tuple[_RoleMappingV3,...]
    view_digest: str


def _body(manifest,location,mappings):
    from .current_source_location_v1 import _material
    return dict(schema='sylanne3.c09.current-filesystem-view.v3',
        original_manifest=asdict(manifest),location=_material(location),mappings=tuple(asdict(v) for v in mappings))


def _require(qualifier,view):
    if type(view) is not _IssuedFilesystemInventoryV3:
        raise AuthorityUnavailable('actual issued filesystem view required')
    with qualifier._issued_lock:issued=qualifier._inventory_views.get(id(view))
    if (issued is None or issued() is not view
            or view.view_digest!=canonical_digest(_body(view.manifest,view.location,view.mappings))):
        raise AuthorityUnavailable('copied or altered filesystem view')
    qualifier._require_issued(view.location,'accepted_erasure')
    if qualifier._pointer(view.location.context)!=view.location.control_operation_id:
        raise AuthorityUnavailable('filesystem view predecessor changed')
    return view


def issue_current_inventory_v3(qualifier,manifest,location):
    qualifier._require_issued(location,'accepted_erasure')
    if (type(manifest) is not InstallationFilesystemManifestV2
            or manifest.authority_id!=location.core_anchor.authority_id
            or manifest.installation_id!=location.installation_id
            or manifest.namespace!=location.authority_namespace
            or location.context.manifest['inventory_manifest_digest']!=manifest.manifest_digest):
        raise AuthorityUnavailable('original filesystem manifest differs from selected installed authority')
    mappings = derive_current_inventory_mappings_v3(manifest, storage_ancestors=location.storage_ancestors,
        storage_generation=location.storage_generation)
    mappings=tuple(mappings);value=_IssuedFilesystemInventoryV3(manifest,location,mappings,
        canonical_digest(_body(manifest,location,mappings)));key=id(value)
    def retire(_):
        with qualifier._issued_lock:qualifier._inventory_views.pop(key,None)
    with qualifier._issued_lock:qualifier._inventory_views[key]=weakref.ref(value,retire)
    return value


def require_inventory_graph_source_v3(qualifier,view,path):
    view=_require(qualifier,view)
    selected=next(v for v in view.mappings if v.role=='graph')
    if str(Path(path).resolve(strict=True))!=selected.selected_db:
        raise AuthorityUnavailable('candidate source is not the selected GRAPH role')
    return view


def _absent(path):
    # Inspect every ancestor without following it: ENOENT through a dangling
    # parent symlink is not evidence that the registered path is safely absent.
    path=Path(path)
    if not path.is_absolute():raise AuthorityUnavailable('retired path must be absolute')
    for parent in reversed(path.parents):
        try:info=parent.lstat()
        except FileNotFoundError:return
        except OSError as exc:raise AuthorityUnavailable('retired ancestor cannot be inspected') from exc
        if not stat.S_ISDIR(info.st_mode):
            raise AuthorityUnavailable('retired ancestor is a symlink or non-directory')
    try:path.lstat()
    except FileNotFoundError:return
    except OSError as exc:raise AuthorityUnavailable('retired resource cannot be inspected') from exc
    raise AuthorityUnavailable('retired ancestor resource was recreated: '+str(path))


def _observe_inventory_paths_v3(mappings,resources):
    selected={};retired=set()
    for mapping in mappings:
        for suffix,resource_id in zip(('','-wal','-shm'),mapping.resource_ids):
            path=mapping.selected_db+suffix
            if path in selected:raise AuthorityUnavailable('selected resource pathname collision')
            selected[path]=resource_id
        for ancestor in mapping.ancestry:
            if ancestor[2]!=mapping.selected_db:
                retired.update(ancestor[2]+suffix for suffix in ('','-wal','-shm','-journal'))
    for path in sorted(retired):_absent(path)
    observed={};coverage=[]
    for path,resource_id in sorted(selected.items()):
        try:info=Path(path).lstat()
        except FileNotFoundError:
            if path.endswith(('-wal','-shm')):continue
            raise AuthorityUnavailable('selected SQLite file missing')
        if not stat.S_ISREG(info.st_mode):raise AuthorityUnavailable('selected SQLite member is not a regular file')
        observed[path]=_observe(Path(path),resource_id)
    directory_kinds={'controlled_backup','export','rebuild_temp','cache'}
    for resource in resources:
        if resource.kind not in directory_kinds:continue
        root=Path(resource.path);item=_observe(root,resource.resource_id)
        if item.file_type!='directory':raise AuthorityUnavailable('original registered directory changed type')
        if str(root) in observed:raise AuthorityUnavailable('selected DB overlaps registered directory root')
        observed[str(root)]=item
        def unreadable(exc):raise AuthorityUnavailable('original managed tree unreadable') from exc
        for folder,dirs,files in os.walk(root,followlinks=False,onerror=unreadable):
            dirs.sort();files.sort()
            for name in (*dirs,*files):
                child=Path(folder)/name
                if child.resolve(strict=False)!=child:raise AuthorityUnavailable('unresolved managed child')
                current=_observe(child,resource.resource_id);prior=observed.get(str(child))
                if prior is not None:
                    if str(child) not in selected or asdict(current)|{'resource_id':prior.resource_id}!=asdict(prior):
                        raise AuthorityUnavailable('overlapping inventory file changed')
                    coverage.append((str(child),prior.resource_id,resource.resource_id))
                else:observed[str(child)]=current
    for path in sorted(retired):_absent(path)
    return observed,coverage,retired


def reread_closed_inventory_v3(value):
    """Reread the whole original managed tree after its actual process retired."""
    from ..runtime.c09_installation_inventory_v2 import InstalledResourceV2
    raw=verify_current_inventory_evidence_v3(value)
    if raw['closed_predecessor'] is None:
        raise AuthorityUnavailable('retired continuation has no actual closed inventory')
    mappings=tuple(_RoleMappingV3(**{**row,'resource_ids':tuple(row['resource_ids']),
        'ancestry':tuple(tuple(item) for item in row['ancestry'])}) for row in raw['view']['mappings'])
    resources=tuple(InstalledResourceV2(**{**row,'content_coverage':tuple(row['content_coverage'])})
        for row in raw['view']['original_manifest']['resources'])
    observed,coverage,retired=_observe_inventory_paths_v3(mappings,resources)
    actual=[asdict(observed[path]) for path in sorted(observed)]
    if (actual!=raw['scan']['observed'] or [list(row) for row in sorted(coverage)]!=raw['directory_coverage']
            or sorted(retired)!=raw['retired_absence']):
        raise AuthorityUnavailable('retired final inventory files or directory coverage changed')
    for mapping in mappings:
        for suffix in ('-wal','-shm','-journal'):_absent(mapping.selected_db+suffix)
    return raw['scan_digest']


def scan_current_inventory_v3(qualifier,view):
    view=_require(qualifier,view);location=view.location
    observed,coverage,retired=_observe_inventory_paths_v3(view.mappings,view.manifest.resources)
    _require(qualifier,view)
    for member in location.context.manifest['members']:qualifier._control.verify_member_v1(member,prepared=False)
    rows=tuple(observed[path] for path in sorted(observed))
    # The embedded V2 scan preserves its established preimage unchanged.
    v2schema='sylanne3.c09.installation_filesystem_scan.v2'
    scan=InstallationFilesystemScanV2(view.manifest.manifest_digest,rows,
        canonical_digest((v2schema,view.manifest.manifest_digest,rows)),v2schema)
    body=dict(schema=SCHEMA,view=_body(view.manifest,location,view.mappings),view_digest=view.view_digest,
        scan=asdict(scan),retired_absence=tuple(sorted(retired)),directory_coverage=tuple(sorted(coverage)),closed_predecessor=None)
    result={**body,'scan_digest':canonical_digest(body)}
    verify_current_inventory_evidence_v3(result)
    return result


def verify_current_inventory_evidence_v3(value):
    """Closed passive codec; authenticity still comes from protected control."""
    import json
    from ..runtime.c09_installation_inventory_v2 import InstalledResourceV2,ObservedFileV2
    from ..runtime_contracts import canonical_serialize
    raw=json.loads(canonical_serialize(value))
    if set(raw)!={'schema','view','view_digest','scan','retired_absence','directory_coverage','closed_predecessor','scan_digest'} or raw['schema']!=SCHEMA:
        raise AuthorityUnavailable('current inventory evidence schema differs')
    body={k:v for k,v in raw.items() if k!='scan_digest'}
    if raw['scan_digest']!=canonical_digest(body) or raw['view_digest']!=canonical_digest(raw['view']):
        raise AuthorityUnavailable('current inventory evidence commitment differs')
    view=raw['view']
    if set(view)!={'schema','original_manifest','location','mappings'} or view['schema']!='sylanne3.c09.current-filesystem-view.v3':
        raise AuthorityUnavailable('current inventory view schema differs')
    original=dict(view['original_manifest']);original['resources']=tuple(InstalledResourceV2(**{**r,'content_coverage':tuple(r['content_coverage'])}) for r in original['resources'])
    manifest=InstallationFilesystemManifestV2(**original)
    scan=dict(raw['scan']);scan['observed']=tuple(ObservedFileV2(**r) for r in scan['observed'])
    scan=InstallationFilesystemScanV2(**scan)
    if scan.manifest_digest!=manifest.manifest_digest or [v['role'] for v in view['mappings']]!=list(ROLES):
        raise AuthorityUnavailable('current inventory original role/manifest differs')
    from .current_source_location_v1 import _IssuedCurrentSourceLocationV1
    location=view['location']
    if set(location)!=(set(_IssuedCurrentSourceLocationV1.__dataclass_fields__)-{'context'})|{'context_commitment'}:
        raise AuthorityUnavailable('inventory location fields differ')
    if (location['purpose']!='accepted_erasure' or location['installation_id']!=manifest.installation_id
            or location['authority_namespace']!=manifest.namespace or location['stage']!='INTENT'
            or type(location['storage_generation']) is not int or location['storage_generation']<0):
        raise AuthorityUnavailable('inventory current operation scope differs')
    selected={};expected_retired=set();used=set()
    for mapping in view['mappings']:
        if set(mapping)!=set(_RoleMappingV3.__dataclass_fields__):raise AuthorityUnavailable('inventory role mapping fields differ')
        ancestors=[row for row in location['storage_ancestors'] if row[1]==mapping['role']]
        if (mapping['ancestry']!=ancestors or len(ancestors)!=location['storage_generation']+1
                or [row[0] for row in ancestors]!=list(range(location['storage_generation']+1))
                or any(len(row)!=9 or row[3]!=mapping['store_id'] or row[4]!=manifest.namespace
                    or row[5]!=manifest.installation_id for row in ancestors)
                or mapping['selected_db']!=ancestors[-1][2]
                or mapping['original_db'] not in [row[2] for row in ancestors]):
            raise AuthorityUnavailable('inventory full role ancestry differs')
        resources={r.kind:r for r in manifest.resources if r.store_id==mapping['store_id']}
        if (set(resources)!={'sqlite_db','sqlite_wal','sqlite_shm'}
                or resources['sqlite_db'].path!=mapping['original_db']
                or mapping['resource_ids']!=[resources[k].resource_id for k in ('sqlite_db','sqlite_wal','sqlite_shm')]
                or resources['sqlite_db'].resource_id in used):
            raise AuthorityUnavailable('inventory original role/companions differ')
        used.add(resources['sqlite_db'].resource_id)
        for suffix,resource in zip(('','-wal','-shm'),mapping['resource_ids']):
            target=mapping['selected_db']+suffix
            if target in selected:raise AuthorityUnavailable('inventory selected path collision')
            selected[target]=resource
        for row in ancestors:
            if row[2]!=mapping['selected_db']:expected_retired.update(row[2]+suffix for suffix in ('','-wal','-shm','-journal'))
    if used!={r.resource_id for r in manifest.resources if r.kind=='sqlite_db'} or raw['retired_absence']!=sorted(expected_retired):
        raise AuthorityUnavailable('inventory retired paths or SQLite groups differ')
    directories=[r for r in manifest.resources if r.kind in {'controlled_backup','export','rebuild_temp','cache'}]
    observed={r.path:r for r in scan.observed};coverage=[]
    for resource in directories:
        root=observed.get(resource.path)
        if root is None or root.resource_id!=resource.resource_id or root.file_type!='directory':
            raise AuthorityUnavailable('original managed directory omitted')
    for row in scan.observed:
        if row.path in expected_retired or row.file_type not in {'file','directory'}:
            raise AuthorityUnavailable('inventory contains retired or unsupported path')
        containing=[r for r in directories if row.path==r.path or Path(row.path).is_relative_to(r.path)]
        if row.path in selected:
            if row.resource_id!=selected[row.path] or row.file_type!='file':raise AuthorityUnavailable('selected path role differs')
            coverage.extend((row.path,row.resource_id,r.resource_id) for r in containing)
        elif len(containing)!=1 or row.resource_id!=containing[0].resource_id:
            raise AuthorityUnavailable('observation lies outside original directory scope')
    if any(m['selected_db'] not in observed for m in view['mappings']) or raw['directory_coverage']!=[list(v) for v in sorted(coverage)]:
        raise AuthorityUnavailable('selected database or directory coverage omitted')
    closed=raw['closed_predecessor']
    if closed is not None:
        if (set(closed)!={'operation_id','accepted_receipt_digest','pointer_version','manifest_digest','quiescence_original','logical_roots','before_physical','after_physical','candidate_source_originals','candidate_digest','graph_candidate_digest','closed_connections','continuous_exclusion'}
                or closed['operation_id']!=location['control_operation_id']
                or closed['pointer_version']!=location['pointer_version']
                or closed['manifest_digest']!=location['manifest_digest']
                or set(closed['logical_roots'])!=set(ROLES)
                or set(closed['before_physical'])!=set(ROLES) or set(closed['after_physical'])!=set(ROLES)
                or set(closed['candidate_source_originals'])!=set(ROLES)):
            raise AuthorityUnavailable('closed inventory predecessor differs')
        exclusion=closed['continuous_exclusion']
        if (set(exclusion)!={'operation_id','admission_epoch','thread_id','lease_path','process_id'}
                or exclusion['operation_id']!=closed['operation_id']
                or exclusion['admission_epoch']!=closed['quiescence_original']['revoked_admission_epoch']
                or exclusion['lease_path']!=closed['quiescence_original']['lock_path']
                or exclusion['process_id']!=closed['quiescence_original']['lock_process_id']
                or not closed['closed_connections']):
            raise AuthorityUnavailable('continuous close exclusion differs')
        for proof in closed['closed_connections']:
            if (set(proof)!={'handle_type','connection_id','path','process_id','thread_id'}
                    or proof['process_id']!=exclusion['process_id'] or proof['thread_id']!=exclusion['thread_id']):
                raise AuthorityUnavailable('actual connection close completion differs')
        for role,roots in closed['logical_roots'].items():
            mapping=next(m for m in view['mappings'] if m['role']==role)
            if (set(roots)!={'algorithm','store_id','namespace','installation_id','application_rows_root','all_rows_root','ddl_root','persistent_metadata'}
                    or roots['algorithm']!='sylanne3.c09.all-sqlite-rows-ddl.v3'
                    or roots['store_id']!=mapping['store_id'] or roots['namespace']!=manifest.namespace
                    or roots['installation_id']!=manifest.installation_id
                    or any(type(roots[n]) is not str or len(roots[n])!=64 for n in ('application_rows_root','all_rows_root','ddl_root'))
                    or set(roots['persistent_metadata'])!={'user_version','application_id','encoding','page_size','auto_vacuum','schema_version'}):
                raise AuthorityUnavailable('complete scoped four-store roots differ')
            if len(closed['after_physical'][role])!=1 or closed['after_physical'][role][0]['resolved_path']!=mapping['selected_db']:
                raise AuthorityUnavailable('closed final source/companion set differs')
    return raw


def require_prepared_inventory_evidence_v3(control,db,prepared,*,require_present=False):
    """Join durable final evidence to the exact signed PREPARED original."""
    import json
    from ..runtime_contracts import canonical_serialize
    from ..runtime.restore_anchor import RestoreAnchor
    from .c09_close_apply_v1 import _prepared_deletion_receipt_original_v1
    original=control._build_original_locked(db,prepared['operation_id'],'current_inventory_scan_v3')
    if original is None:
        prior=db.execute('SELECT prepared_original_json FROM c09_storage_operations_v1 WHERE operation_id=?',
            (prepared['operation_id'],)).fetchone()
        from .c09_storage_control_v1 import canonical
        if require_present or prior!=(canonical(prepared),):
            raise AuthorityUnavailable('durable current-generation inventory evidence absent')
        control.verify_original_v1(prepared,'prepared_digest')
        return None  # Only byte-exact already persisted historical originals. 
    value=verify_current_inventory_evidence_v3(original['details']);location=value['view']['location'];closed=value['closed_predecessor']
    receipt=_prepared_deletion_receipt_original_v1(prepared['accepted_receipt_original'])
    if canonical_digest(receipt)!=prepared['accepted_receipt_digest']:
        raise AuthorityUnavailable('PREPARED accepted receipt digest differs')
    if (closed is None or original['old_manifest_digest']!=prepared['old_manifest_digest']
            or original['expected_pointer_version']!=prepared['expected_pointer_version']
            or value['scan_digest']!=prepared['frozen_scan_digest']
            or value['view']['original_manifest']!=json.loads(canonical_serialize(prepared['frozen_inventory_original']))
            or closed['operation_id']!=prepared['operation_id']
            or closed['accepted_receipt_digest']!=prepared['accepted_receipt_digest']
            or closed['quiescence_original']!=json.loads(canonical_serialize(prepared['writer_quiescence_original']))
            or location['manifest_digest']!=prepared['old_manifest_digest']
            or location['pointer_version']!=prepared['expected_pointer_version']
            or location['storage_generation']+1!=prepared['maintenance_generation']
            or location['core_anchor']!=json.loads(canonical_serialize(RestoreAnchor(**prepared['old_core_anchor_original'])))
            or location['accepted_receipt']!=json.loads(canonical_serialize(receipt))):
        raise AuthorityUnavailable('PREPARED differs from exact final inventory evidence')
    control.verify_original_v1(closed['quiescence_original'],'quiescence_digest')
    graph_original=control._build_original_locked(db,prepared['operation_id'],'graph_candidate')
    storage_original=control._build_original_locked(db,prepared['operation_id'],'storage_candidate')
    if (graph_original is None or storage_original is None
            or graph_original['details']['candidate']!=closed['candidate_source_originals']['graph']
            or graph_original['details']['candidate']['candidate_digest']!=closed['graph_candidate_digest']
            or storage_original['details']['candidate']['candidate_digest']!=closed['candidate_digest']
            or storage_original['details']['transition']!=prepared['anchor_transition_original']
            or storage_original['details']['bindings_digest']!=prepared['recovery_bindings_digest']
            or storage_original['details']['issue_digest']!=prepared['graph_issue_original']['issue_digest']):
        raise AuthorityUnavailable('final checkpoint bridge differs from immutable candidate originals')
    from .c09_authority_storage_rebase import _digest as file_digest
    for role in ROLES:
        source=closed['candidate_source_originals'][role]
        if role!='graph':
            saved=control._build_original_locked(db,prepared['operation_id'],'file_'+role)
            if (saved is None or saved['details']['file']!=source
                    or storage_original['details']['candidate'][role]!=source
                    or closed['logical_roots'][role]['application_rows_root']!=source['source_data_root']):
                raise AuthorityUnavailable('final checkpoint source differs from actual role candidate')
        parts=[]
        for item in closed['before_physical'][role]:
            suffix=item['resolved_path'].removeprefix(source['source_path'])
            if suffix not in ('','-wal','-shm'):raise AuthorityUnavailable('unexpected candidate source companion')
            identity=(item['device'],item['file_id'],item['prepared_size'],item['prepared_mtime_ns'])
            if suffix=='' and list(identity)!=source['source_identity']:
                raise AuthorityUnavailable('candidate source physical identity changed before close')
            parts.append((suffix,identity,item['prepared_sha256']))
        if not parts or parts[0][0]!='':raise AuthorityUnavailable('candidate source main file omitted')
        fingerprint=(canonical_digest((source['source_path'],tuple((suffix or 'db',identity[0],identity[1],identity[2],sha) for suffix,identity,sha in parts)))
            if role=='graph' else file_digest(parts))
        if fingerprint!=source['source_files_fingerprint' if role=='graph' else 'source_files_sha256']:
            raise AuthorityUnavailable('candidate snapshot is not the exact preclose source')
    manifests=[];selected=prepared['old_manifest_digest'];seen=set()
    while selected is not None:
        if selected in seen or len(seen)>=1024:raise AuthorityUnavailable('persisted inventory ancestry cycles')
        seen.add(selected);manifest=control._read_manifest(db,selected);manifests.append(manifest)
        selected=manifest['prior_manifest_digest']
    manifests.reverse()
    expected_ancestors=[[m['generation'],v['role'],v['resolved_path'],v['store_id'],v['namespace'],m['installation_id'],v['incarnation_or_journal_id'],v['device'],v['file_id']]
        for m in manifests for v in m['members']]
    if (location['storage_ancestors']!=expected_ancestors
            or len(manifests)!=prepared['maintenance_generation']
            or [m['generation'] for m in manifests]!=list(range(len(manifests)))):
        raise AuthorityUnavailable('persisted inventory differs from actual signed role ancestry')
    observed={row['path']:row for row in value['scan']['observed']}
    selected={item['selected_db'] for item in value['view']['mappings']}
    final=prepared['source_final_fingerprints']
    if len(final)!=4 or len(selected)!=4 or {row['resolved_path'] for row in final}!=selected:
        raise AuthorityUnavailable('final inventory source fingerprint role set differs')
    file_fields={'resolved_path','device','file_id','prepared_size','prepared_mtime_ns','prepared_sha256'}
    for mapping in value['view']['mappings']:
        role,path=mapping['role'],mapping['selected_db']
        source=next(row for row in final if row['resolved_path']==path)
        after=closed['after_physical'][role]
        item=observed.get(path)
        if (set(source)!=file_fields or len(after)!=1 or after[0]!=source
                or item is None or item['path']!=source['resolved_path']
                or (item['device'],item['inode'],item['size'],item['mtime_ns'],item['content_sha256'])!=(
                    source['device'],source['file_id'],source['prepared_size'],source['prepared_mtime_ns'],source['prepared_sha256'])):
            raise AuthorityUnavailable('checkpoint AFTER, scan and PREPARED final fingerprints differ')
    return value


def derive_current_inventory_mappings_v3(manifest, *, storage_ancestors, storage_generation):
    mappings=[];claimed=set()
    for role in ROLES:
        ancestors=tuple(row for row in storage_ancestors if row[1]==role)
        if (len(ancestors)!=storage_generation+1
                or tuple(row[0] for row in ancestors)!=tuple(range(storage_generation+1))
                or any((row[4],row[5])!=(manifest.namespace,manifest.installation_id) for row in ancestors)
                or len({row[3] for row in ancestors})!=1):
            raise AuthorityUnavailable('complete same-role storage ancestry required')
        possible=[]
        for resource in manifest.resources:
            if resource.kind!='sqlite_db':continue
            if any(resource.path==row[2] and resource.store_id==row[3] for row in ancestors):possible.append(resource)
        if len(possible)!=1:raise AuthorityUnavailable('original SQLite group does not bind one authenticated role')
        resource=possible[0]
        if resource.resource_id in claimed:raise AuthorityUnavailable('original SQLite group maps twice')
        claimed.add(resource.resource_id)
        companions={r.kind:r for r in manifest.resources if r.store_id==resource.store_id}
        if set(companions)!={'sqlite_db','sqlite_wal','sqlite_shm'}:
            raise AuthorityUnavailable('original SQLite companions differ')
        mappings.append(_RoleMappingV3(role,resource.store_id,resource.path,ancestors[-1][2],
            tuple(companions[k].resource_id for k in ('sqlite_db','sqlite_wal','sqlite_shm')),ancestors))
    if claimed!={r.resource_id for r in manifest.resources if r.kind=='sqlite_db'}:
        raise AuthorityUnavailable('unmapped installer SQLite group')
    return tuple(mappings)
