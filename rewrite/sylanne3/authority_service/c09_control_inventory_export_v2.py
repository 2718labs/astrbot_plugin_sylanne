"""Read-only authenticated, complete opaque Control inventory for V2 conversion.

This is the source inventory producer, not a storage selector, recovery frame or
physical-disposal receipt. V1 originals remain intact. Unknown schema, overfull
inventory or unauthenticated originals refuse the entire export.
"""
import hashlib
import hmac
import json
import sqlite3

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1, _DDL, _BUILD_TABLE, _BUILD_DDL, _PREPARED_FIELDS

SCHEMA = 'sylanne3.c09.authenticated-control-inventory-export.v2'
MAX_ROWS = 100000
MAX_BYTES = 32 * 1024 * 1024
FAMILIES = tuple(sorted((*_DDL, _BUILD_TABLE)))
FIELDS = frozenset(('schema', 'authority_commitment', 'installation_commitment', 'key_commitment',
    'control_commitment', 'pointer_commitment', 'families', 'inventory_digest', 'signature'))


def _identity(control):
    if type(control) is not C09StorageControlV1:
        raise AuthorityUnavailable('C09 source export requires installed control')
    control.lease.require_held()
    return dict(authority_commitment=canonical_digest(('authority', control.authority_id)),
        installation_commitment=canonical_digest(('installation', control.installation_id)),
        key_commitment=canonical_digest(('c09.key', control.key_id)),
        control_commitment=canonical_digest(('control', control.control_store_id)))


def _objects(db):
    rows = tuple(tuple(r) for r in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name LIMIT 129'))
    if len(rows) > 128:
        raise AuthorityUnavailable('C09 complete Control schema exceeds bound; HOLD')
    return rows


def capture_control_inventory_export_v2(control):
    identity = _identity(control)
    with control._db() as db:
        actual = _objects(db)
        with sqlite3.connect(':memory:') as expected:
            for name, ddl in _DDL.items():
                expected.execute(ddl)
                if name != 'c09_storage_current_v1':
                    for action in ('UPDATE', 'DELETE'):
                        expected.execute(control._immutable_ddl(name, action))
            has_build = any(r[0] == 'table' and r[1] == _BUILD_TABLE for r in actual)
            if has_build:
                expected.execute(_BUILD_DDL)
                for action in ('UPDATE', 'DELETE'):
                    expected.execute(control._immutable_ddl(_BUILD_TABLE, action))
            if actual != _objects(expected):
                raise AuthorityUnavailable('C09 complete Control schema inventory differs; HOLD')
        # Bound every cell before _current decodes/replays any historical JSON.
        # Counts cover the whole tables, never a truncated accepted prefix.
        total_rows = total_bytes = 0
        for table in FAMILIES:
            if table == _BUILD_TABLE and not has_build:
                continue
            columns = tuple(r[1] for r in db.execute(f'PRAGMA table_info({table})'))
            sizes = '+'.join(f'COALESCE(length(CAST("{name}" AS BLOB)),0)' for name in columns)
            rows, size = db.execute(f'SELECT COUNT(*),COALESCE(SUM({sizes}),0) FROM {table}').fetchone()
            total_rows += rows; total_bytes += size
            if total_rows > MAX_ROWS or total_bytes > MAX_BYTES:
                raise AuthorityUnavailable('C09 complete Control inventory exceeds bound; HOLD')
        current = control._current(db)
        if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise AuthorityUnavailable('C09 complete Control reference inventory differs; HOLD')
        count = size = 0
        families = []
        for table in FAMILIES:
            present = table != _BUILD_TABLE or has_build
            columns = tuple(r[1] for r in db.execute(f'PRAGMA table_info({table})')) if present else ()
            commitments = []
            if present:
                for row in db.execute(f'SELECT * FROM {table}'):
                    count += 1
                    size += len(canonical_serialize(tuple(row)).encode('utf-8'))
                    if count > MAX_ROWS or size > MAX_BYTES:
                        raise AuthorityUnavailable('C09 complete Control inventory exceeds bound; HOLD')
                    if table == 'c09_storage_manifests_v1':
                        control._read_manifest(db, row['manifest_digest'])
                    elif table in {'c09_storage_operations_v1', 'c09_storage_surface_evidence_v1', _BUILD_TABLE}:
                        encoded, field = {
                            'c09_storage_operations_v1': ('prepared_original_json', 'prepared_digest'),
                            'c09_storage_surface_evidence_v1': ('evidence_json', 'evidence_digest'),
                            _BUILD_TABLE: ('original_json', 'original_digest'),
                        }[table]
                        value = json.loads(row[encoded])
                        control.verify_original_v1(value, field)
                        if (value[field] != row[field] or value.get('installation_id') != control.installation_id
                                or value.get('operation_id') != row['operation_id']):
                            raise AuthorityUnavailable('C09 signed Control row association differs; HOLD')
                        if table == 'c09_storage_operations_v1' and set(value) != _PREPARED_FIELDS:
                            raise AuthorityUnavailable('C09 full PREPARED fields differ; HOLD')
                    commitments.append(canonical_digest((table, columns, tuple(row))))
            families.append(dict(table=table, present=present,
                schema_commitment=canonical_digest(tuple(r for r in actual if r[2] == table)),
                row_commitments=sorted(commitments)))
        body = dict(schema=SCHEMA, **identity, pointer_commitment=canonical_digest(dict(current)), families=families)
        body['inventory_digest'] = canonical_digest(body)
        body['signature'] = hmac.new(control._key,
            (SCHEMA + '\n' + body['inventory_digest']).encode(), hashlib.sha256).hexdigest()
    return verify_control_inventory_export_v2(control, body)


def verify_control_inventory_export_v2(control, value):
    identity = _identity(control)
    if (type(value) is not dict or set(value) != FIELDS or value['schema'] != SCHEMA
            or any(value[k] != v for k, v in identity.items())):
        raise AuthorityUnavailable('C09 opaque Control export closed identity differs')
    families = value['families']
    if type(families) is not list or len(families) != len(FAMILIES):
        raise AuthorityUnavailable('C09 complete Control export families differ')
    count = 0
    for family, table in zip(families, FAMILIES):
        if (type(family) is not dict or set(family) != {'table','present','schema_commitment','row_commitments'}
                or family['table'] != table or type(family['present']) is not bool
                or table != _BUILD_TABLE and not family['present']):
            raise AuthorityUnavailable('C09 Control export family differs')
        rows = family['row_commitments']
        if type(rows) is not list or rows != sorted(set(rows)) or not family['present'] and rows:
            raise AuthorityUnavailable('C09 Control export exact finite rows differ')
        count += len(rows)
        for committed in (*rows, family['schema_commitment']):
            if type(committed) is not str or len(committed) != 64 or any(c not in '0123456789abcdef' for c in committed):
                raise AuthorityUnavailable('C09 Control export opaque commitment differs')
    if count > MAX_ROWS or len(canonical_serialize(value).encode('utf-8')) > MAX_BYTES:
        raise AuthorityUnavailable('C09 complete Control export exceeds bound; HOLD')
    body = {k:v for k,v in value.items() if k not in {'inventory_digest','signature'}}
    committed = canonical_digest(body)
    expected = hmac.new(control._key, (SCHEMA + '\n' + committed).encode(), hashlib.sha256).hexdigest()
    if (value['inventory_digest'] != committed or type(value['signature']) is not str
            or not hmac.compare_digest(value['signature'], expected)):
        raise AuthorityUnavailable('C09 Control export actual installed signature differs')
    return value
