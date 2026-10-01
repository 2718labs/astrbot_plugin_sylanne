"""Closed provenance for a pinned alpha1 test snapshot, separate from release CI."""
import json
import re
from ..runtime_contracts import canonical_digest

MODE = 'snapshot-alpha1-test'
VERSION = '3.0.0-alpha1'
SCHEMA = 'sylanne.alpha1-test-snapshot.v1'
QUALIFICATION_SCHEMA = 'sylanne.alpha1-test-snapshot-qualification.v1'


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def qualify_test_snapshot_v1(candidate):
    value=dict(candidate)
    value.update(schema=QUALIFICATION_SCHEMA,status='alpha1_test_snapshot',product_status='test_snapshot')
    return value


def validate_test_snapshot_manifest_v1(manifest):
    value=manifest.get('test_snapshot')
    fields={'schema','label','handoff_archive_sha256','handoff_manifest_sha256','source_inventory_sha256',
        'native_sha256','source_delta','engineering_source_inventory','engineering_source_delta',
        'verification_evidence','verification_evidence_digest','public_release'}
    if (manifest.get('build_mode')!=MODE or manifest.get('package_version')!=VERSION
            or manifest.get('candidate_scope')!='alpha1-test' or type(value) is not dict or set(value)!=fields
            or value['schema']!=SCHEMA or value['label']!='Embodiment-3.0.0-alpha1 test snapshot'
            or value['public_release'] is not False or not _sha(value['handoff_archive_sha256'])
            or not _sha(value['handoff_manifest_sha256'])
            or value['source_inventory_sha256']!=manifest.get('source_inventory',{}).get('sha256')
            or value['native_sha256']!=manifest.get('native',{}).get('sha256')
            or value['handoff_manifest_sha256']!=manifest.get('source',{}).get('handoff_snapshot',{}).get('handoff_manifest_sha256')
            or manifest.get('source',{}).get('handoff_snapshot',{}).get('origin_head_is_baseline_only') is not True
            or manifest.get('source',{}).get('dirty') is not True):
        raise ValueError('alpha1 test snapshot provenance differs')
    delta=value['source_delta']
    if type(delta) is not dict or set(delta)!={'added','changed','removed'}:
        raise ValueError('test snapshot source delta schema differs')
    entries={row['path']:row for row in manifest['source_inventory']['files']}
    for kind in ('added','changed'):
        rows=delta[kind]
        if type(rows) is not list or len({r.get('path') for r in rows})!=len(rows):
            raise ValueError('test snapshot source delta repeats a path')
        for row in rows:
            if type(row) is not dict or set(row)!={'path','bytes','sha256','previous_sha256'} or row['path'] not in entries:
                raise ValueError('test snapshot source delta row differs')
            if any(row[k]!=entries[row['path']][k] for k in ('path','bytes','sha256')):
                raise ValueError('test snapshot delta is not actual packaged bytes')
            if (row['previous_sha256'] is not None if kind=='added' else not _sha(row['previous_sha256'])):
                raise ValueError('test snapshot baseline delta differs')
    if type(delta['removed']) is not list or delta['removed']!=sorted(set(delta['removed'])):
        raise ValueError('test snapshot removed source inventory differs')
    import hashlib
    inventory=value['engineering_source_inventory']
    if (type(inventory) is not dict or set(inventory)!={'schema','files','sha256'}
            or inventory['schema']!='sylanne.engineering-source-inventory.v1'
            or type(inventory['files']) is not list or not inventory['files'] or len(inventory['files'])>20000
            or hashlib.sha256(json.dumps(inventory['files'],ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=inventory['sha256']):
        raise ValueError('test snapshot full engineering source inventory differs')
    from pathlib import PurePosixPath
    actual={}
    for row in inventory['files']:
        if (type(row) is not dict or set(row)!={'path','bytes','sha256'} or type(row['path']) is not str
                or row['path'] in actual or PurePosixPath(row['path']).is_absolute()
                or any(part in {'','.','..'} for part in row['path'].split('/')) or '\\' in row['path']
                or type(row['bytes']) is not int or row['bytes']<0 or not _sha(row['sha256'])):
            raise ValueError('test snapshot engineering source row differs')
        actual[row['path']]=row
    if list(actual)!=sorted(actual):raise ValueError('test snapshot engineering inventory is not ordered')
    if any(actual.get(path)!=row for path,row in entries.items()):
        raise ValueError('test snapshot source changed while freezing the actual payload')
    engineering=value['engineering_source_delta']
    if type(engineering) is not dict or set(engineering)!={'added','changed','removed'}:
        raise ValueError('test snapshot engineering delta fields differ')
    for kind in ('added','changed'):
        rows=engineering[kind]
        if type(rows) is not list or len(rows)>20000:raise ValueError('test snapshot engineering delta unbounded')
        seen=set()
        for row in rows:
            if (type(row) is not dict or set(row)!={'path','bytes','sha256','previous_sha256'}
                    or row['path'] in seen or actual.get(row['path'])!={key:row[key] for key in ('path','bytes','sha256')}
                    or (row['previous_sha256'] is not None if kind=='added' else not _sha(row['previous_sha256']))):
                raise ValueError('test snapshot engineering delta is not actual source bytes')
            seen.add(row['path'])
    if (type(engineering['removed']) is not list or engineering['removed']!=sorted(set(engineering['removed']))
            or any(path in actual for path in engineering['removed'])):
        raise ValueError('test snapshot removed engineering source differs')
    evidence=value['verification_evidence']
    if (type(evidence) is not dict or evidence.get('schema')!='sylanne.alpha1-test-evidence.v1'
            or type(evidence.get('checks')) is not list or not evidence['checks']
            or len(evidence['checks'])>256 or canonical_digest(evidence)!=value['verification_evidence_digest']):
        raise ValueError('test snapshot actual evidence inventory differs')
    for item in evidence['checks']:
        if (type(item) is not dict or set(item)!={'name','status','log_sha256','scope','source_pin'}
                or item['status'] not in {'passed','failed','not_run'} or not item['name'] or not item['scope']
                or item['status']!='not_run' and not _sha(item['log_sha256'])
                or item['status']=='not_run' and item['log_sha256'] is not None
                or item['source_pin'] is not None and not _sha(item['source_pin'])):
            raise ValueError('test snapshot evidence row is not an exact scoped test receipt')
    if not {'resources/workbench/index.html','resources/workbench/workbench-manifest.json'} <= entries.keys():
        raise ValueError('alpha1 test snapshot must include the actual existing W09 bundle')
    return value
