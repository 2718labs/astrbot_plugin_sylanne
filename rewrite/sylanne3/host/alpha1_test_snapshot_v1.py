"""Closed provenance for a pinned alpha1 test snapshot, separate from release CI."""
import json
import re
from ..runtime_contracts import canonical_digest

MODE = 'snapshot-alpha1-test'
VERSION = '3.0.0-alpha1'
SCHEMA = 'sylanne.alpha1-test-snapshot.v1'
QUALIFICATION_SCHEMA = 'sylanne.alpha1-test-snapshot-qualification.v1'
ALPHA2_MODE = 'alpha2-candidate'
ALPHA2_VERSION = '3.0.0-alpha2'
ALPHA2_SCHEMA = 'sylanne.alpha2-local-candidate.v1'
ALPHA2_QUALIFICATION_SCHEMA = 'sylanne.alpha2-local-qualification.v1'
ALPHA2_RUNTIME_SCOPE = 'backend-local-alpha2-acceptance'
BETA1_MODE = 'beta1-candidate'
BETA1_VERSION = '3.0.0-beta1'
BETA1_SCHEMA = 'sylanne.beta1-server-test-candidate.v1'
BETA1_QUALIFICATION_SCHEMA = 'sylanne.beta1-server-test-qualification.v1'
BETA1_RUNTIME_SCOPE = 'backend-beta1-server-test'
BETA1_UNMET_GATES = ['catalogue_runtime_verified', 'migration_validated',
    'beta1_server_acceptance', 'full_product_acceptance']
BETA1_LOCAL_CHECKS = ('beta1_source_closure', 'beta1_python_compile')
BETA1_NATIVE = {
    'path': 'rewrite/sylanne3/_native/linux-x86_64/libsylanne3_kernel.so',
    'bytes': 596248,
    'sha256': '2883b3bd4af107a953fe86c6ee785da1fc51688e36e7a9f5fef7d7016d91d56c',
}
ALPHA2_UNMET_GATES = ['catalogue_runtime_verified', 'migration_validated',
    'alpha2_source_freeze', 'full_v3_39_local_acceptance']
ALPHA2_SPECIFICATION = {
    'schema': 'sylanne.alpha2-v3-specification.v1', 'spec_version': 3, 'task_count': 39,
    'input_sha256': {
        'prompt': '0fd7d7415e40182303e85970c921dbb67a812ef54d6ecd2f4cbb059e78849acf',
        'json': 'a4d715d8a155fecd54eaff80b471a27196ebeffa7fd287cac4600f17e727f884',
        'csv': '43ed34bc5ee8def6dc7d93ad46be47ebed6f0a2943be039033c8e9c894561222',
        'html': '3abf41bafa414679bd774d52186428b2acd60612eb7aa871b78d0bfc2a3bf218'},
    'resource_contract': {'cpu_count': 2, 'process_group_memory_max_bytes': 2000000000,
        'app_memory_max_bytes': 1342177280, 'app_memory_high_bytes': 1073741824},
}


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def qualify_test_snapshot_v1(candidate):
    value=dict(candidate)
    value.update(schema=QUALIFICATION_SCHEMA,status='alpha1_test_snapshot',product_status='test_snapshot')
    return value


def qualify_alpha2_candidate_v1(candidate):
    value = dict(candidate)
    value.update(schema=ALPHA2_QUALIFICATION_SCHEMA, status='alpha2_candidate',
        product_status='candidate_only', runtime_scope=ALPHA2_RUNTIME_SCOPE,
        unmet_product_gates=list(ALPHA2_UNMET_GATES))
    return value


def qualify_beta1_candidate_v1(candidate):
    value = dict(candidate)
    value.update(schema=BETA1_QUALIFICATION_SCHEMA, status='beta1_candidate',
        product_status='candidate_only', runtime_scope=BETA1_RUNTIME_SCOPE,
        unmet_product_gates=list(BETA1_UNMET_GATES))
    return value


def validate_beta1_candidate_manifest_v1(manifest):
    value = _validate_candidate_manifest_v1(manifest, BETA1_MODE)
    platform = manifest.get('platform', {})
    if (tuple(platform.get(name) for name in ('os', 'arch', 'libc', 'abi_version')) !=
            ('linux', 'x86_64', 'glibc', 2) or manifest.get('native') != BETA1_NATIVE):
        raise ValueError('Beta1 requires the unchanged pinned Linux x86_64/glibc ABI2 binary')
    checks = value['verification_evidence']['checks']
    by_name = {row['name']: row for row in checks}
    source_pin = value['engineering_source_inventory']['sha256']
    if (len(by_name) != len(checks)
            or any(row['source_pin'] != source_pin for row in checks)
            or any(name not in by_name or by_name[name]['status'] != 'passed' for name in BETA1_LOCAL_CHECKS)
            or 'beta1_server_acceptance' not in by_name
            or by_name['beta1_server_acceptance']['status'] != 'not_run'):
        raise ValueError('Beta1 requires current source closure/compile receipts and server NOT_RUN')
    return value


def validate_test_snapshot_manifest_v1(manifest):
    return _validate_candidate_manifest_v1(manifest, MODE)


def validate_alpha2_candidate_manifest_v1(manifest):
    return _validate_candidate_manifest_v1(manifest, ALPHA2_MODE)


def _validate_candidate_manifest_v1(manifest, expected_mode):
    contracts = {
        MODE: (VERSION, SCHEMA, 'alpha1-test', 'Embodiment-3.0.0-alpha1 test snapshot',
            'sylanne.alpha1-test-evidence.v1'),
        ALPHA2_MODE: (ALPHA2_VERSION, ALPHA2_SCHEMA, 'alpha2-local', 'Sylanne 3.0.0-alpha2 local candidate',
            'sylanne.alpha2-local-evidence.v1'),
        BETA1_MODE: (BETA1_VERSION, BETA1_SCHEMA, 'beta1-server-test', 'Sylanne 3.0.0-beta1 server test candidate',
            'sylanne.beta1-source-evidence.v1'),
    }
    version, schema, scope, label, evidence_schema = contracts[expected_mode]
    value=manifest.get('test_snapshot')
    fields={'schema','label','handoff_archive_sha256','handoff_manifest_sha256','source_inventory_sha256',
        'native_sha256','source_delta','engineering_source_inventory','engineering_source_delta',
        'verification_evidence','verification_evidence_digest','public_release'}
    if expected_mode == ALPHA2_MODE:
        fields.add('specification')
    if (manifest.get('build_mode')!=expected_mode or manifest.get('package_version')!=version
            or manifest.get('candidate_scope')!=scope or type(value) is not dict or set(value)!=fields
            or value['schema']!=schema or value['label']!=label
            or value['public_release'] is not False or not _sha(value['handoff_archive_sha256'])
            or not _sha(value['handoff_manifest_sha256'])
            or value['source_inventory_sha256']!=manifest.get('source_inventory',{}).get('sha256')
            or value['native_sha256']!=manifest.get('native',{}).get('sha256')
            or value['handoff_manifest_sha256']!=manifest.get('source',{}).get('handoff_snapshot',{}).get('handoff_manifest_sha256')
            or manifest.get('source',{}).get('handoff_snapshot',{}).get('origin_head_is_baseline_only') is not True
            or manifest.get('source',{}).get('dirty') is not True):
        raise ValueError('alpha1 test snapshot provenance differs')
    if expected_mode == ALPHA2_MODE and value['specification'] != ALPHA2_SPECIFICATION:
        raise ValueError('alpha2 candidate does not bind the exact v3 design/resource contract')
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
    if (type(evidence) is not dict or evidence.get('schema')!=evidence_schema
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
