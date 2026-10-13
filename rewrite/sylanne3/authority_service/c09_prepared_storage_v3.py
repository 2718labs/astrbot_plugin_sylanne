"""Actual segmented role originals and their separate V3 PREPARED domain."""
from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

from dataclasses import asdict
from pathlib import Path
import json

from .contract import AuthorityUnavailable
from .c09_prepared_storage_v2 import PREPARED_FIELDS_V2, _build_original
from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2, _read_one
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import (
    C09CaptureScopeV2, C09FrozenRoleSourceV2, C09StreamIdentityV2, C09CountOriginalV2,
    C09PageCursorV2, C09CompleteStreamV2, C09SealedStreamLocatorV2,
    c09_paged_value_from_wire_v2, verify_c09_complete_stream_v2,
)
from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2, read_c09_table_shape_v2, c09_row_commitment_v2
from ..segmented_sql_cell_v1 import LAYOUTS, LAYOUT_SCHEMA_DIGEST, TRANSITION_SCHEMA

SCHEMA_V3 = 'sylanne3.c09.storage_prepared_original.v3'
TABLE_V3 = 'c09_storage_operations_v3'
PREPARED_FIELDS_V3 = PREPARED_FIELDS_V2 | frozenset((
    'segmented_storage_transition_original_digest', 'segmented_role_complete_original_digests',
    'natural_core_obligations_complete_original_digest', 'provider_scope_complete_original_digest'))
DDL_V3 = """CREATE TABLE c09_storage_operations_v3(
 operation_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, namespace TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0), expected_pointer_version INTEGER NOT NULL CHECK(expected_pointer_version>=0),
 old_manifest_digest TEXT NOT NULL REFERENCES c09_storage_manifests_v1(manifest_digest),
 new_manifest_digest TEXT NOT NULL UNIQUE REFERENCES c09_storage_manifests_v1(manifest_digest),
 prepared_original_json TEXT NOT NULL, prepared_digest TEXT NOT NULL UNIQUE, key_id TEXT NOT NULL, signature TEXT NOT NULL) STRICT"""
_ROLE = object()
_CHILDREN = (
    ('headers', 'cell_headers_complete_original_digest', 'segmented_cell_headers_complete_v1_',
        'sylanne3.c09.segmented-cell-headers-complete.v1', 'c09_segmented_headers_v3'),
    ('segments', 'segments_complete_original_digest', 'segmented_segments_complete_v1_',
        'sylanne3.c09.segmented-segments-complete.v1', 'c09_segmented_segments_v3'),
    ('logical_refs', 'logical_refs_complete_original_digest', 'segmented_logical_refs_complete_v1_',
        'sylanne3.c09.segmented-logical-refs-complete.v1', 'c09_segmented_logical_refs_v3'),
    ('orphan_audit', 'orphan_census_complete_original_digest', 'segmented_orphan_audit_complete_v1_',
        'sylanne3.c09.segmented-orphan-audit-complete.v1', 'c09_segmented_orphan_audit_v3'),
)
_COMMON = ('operation_id', 'scope_digest', 'role', 'source_role_source_digest', 'target_identity',
    'layout_id', 'layout_schema_digest', 'storage_instance_id', 'role_complete_original_digest')


def _require_meter(meter):
    if meter is not current_c09_sql_meter_v2():
        raise AuthorityUnavailable('actual installed segmented original quantum required')


def _read_original(control, db, operation_id, kind, digest, meter):
    _require_meter(meter)
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    bounded = _BoundedReadConnectionV2(db, meter)
    def preread(size):
        meter.require_available(size * 7)
        if size * 8 > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('actual segmented original lacks its reserved decoder arena')
    bounded._natural_preflight_v3 = preread
    return _build_original(control, bounded, operation_id, kind, digest)


class VerifiedSegmentedRoleOriginalV3:
    """Private complete role proof; caller records and cursors cannot create one."""
    __slots__ = ('_issuer', 'control', 'scope', 'role', 'original_digest', 'base_original_digest',
        'layout_id', 'layout_schema_digest', 'storage_instance_id', 'target_path', 'target_identity',
        'target_stamp', 'child_original_digests', 'child_locators', 'details', 'selection', 'base_header')

    def __init__(self, token, reader):
        if token is not _ROLE or reader.child_index != len(_CHILDREN):
            raise AuthorityUnavailable('actual four-stream complete role issuer required')
        self._issuer, self.control, self.scope, self.role = token, reader.control, reader.scope, reader.role
        self.original_digest, self.base_original_digest = reader.original_digest, reader.base_digest
        self.details = dict(reader.details)
        self.base_header = dict(reader.base)
        self.layout_id, self.layout_schema_digest = self.details['layout_id'], self.details['layout_schema_digest']
        self.storage_instance_id = self.details['storage_instance_id']
        self.target_path, self.target_identity, self.target_stamp = reader.target_path, tuple(self.details['target_identity']), reader.target_stamp
        self.child_original_digests = {kind: self.details[field] for kind, field, *_ in _CHILDREN}
        self.child_locators = dict(reader.locators)
        self.selection = reader.selection

    def require_current(self, *, control, scope, meter):
        _require_meter(meter)
        if self._issuer is not _ROLE or control is not self.control or scope != self.scope:
            raise AuthorityUnavailable('actual complete segmented role scope changed')
        stat = Path(self.target_path).stat()
        if self.selection is None:
            if (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) != self.target_stamp:
                raise AuthorityUnavailable('complete segmented target changed before PREPARED')
        else:
            self.selection.require_current(meter=meter)
            if (stat.st_dev, stat.st_ino) != self.target_identity:
                raise AuthorityUnavailable('actual selected segmented role inode changed')
        with control._db() as db:
            row = _read_one(db, 'SELECT original_digest FROM c09_storage_build_originals_v1 '
                'WHERE installation_id=? AND operation_id=? AND original_kind=?',
                (control.installation_id, scope.operation_id, 'segmented_role_complete_v1_' + self.role), meter)
        if row != (self.original_digest,):
            raise AuthorityUnavailable('actual complete segmented role original changed')
        return self


class _SegmentedRoleOriginalReaderV3:
    def __init__(self, control, scope, role, base_digest, segmented_digest, selection=None):
        self.control, self.scope, self.role = control, scope, role
        self.selection = selection
        self.base_digest, self.original_digest = base_digest, segmented_digest
        self.base = self.details = None
        self.target_path = self.target_stamp = None
        self.child_index = 0
        self.child = self.stream_reader = self.shape = None
        self.counts = {}
        self.locators = {}
        self.result = None

    def _current_target(self):
        if self.target_path is not None:
            stat = Path(self.target_path).stat()
            if self.selection is None:
                if (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) != self.target_stamp:
                    raise AuthorityUnavailable('actual segmented target changed during original verification')
            else:
                self.selection.require_current(meter=current_c09_sql_meter_v2())
                member = self.selection.member(self.role)
                if (self.target_path != member['resolved_path']
                        or (stat.st_dev, stat.st_ino) != (member['device'], member['file_id'])):
                    raise AuthorityUnavailable('actual selected segmented target inode or registered path changed')

    def advance(self, *, meter):
        _require_meter(meter)
        self.control.lease.require_held()
        self._current_target()
        if self.result is not None:
            return self.result.require_current(control=self.control, scope=self.scope, meter=meter)
        with self.control._db() as db:
            if self.base is None:
                self.base = _read_original(self.control, db, self.scope.operation_id,
                    'capture_role_complete_v2_' + self.role, self.base_digest, meter)
                source = c09_paged_value_from_wire_v2(self.base['source_original'], C09FrozenRoleSourceV2)
                self.target_path = self.base['target_path']
                self.target_stamp = tuple(self.base['target_identity'] if self.role == 'graph' else self.base['target_file_identity'])
                if (self.base['scope_digest'] != self.scope.scope_digest or self.base['role'] != self.role
                        or source.scope_digest != self.scope.scope_digest or source.role != self.role
                        or len(self.target_stamp) != 4):
                    raise AuthorityUnavailable('actual segmented base role differs from its source or target')
                self._current_target()
                return {'status': 'progress', 'phase': 'segmented_role_base', 'role': self.role}
            if self.details is None:
                row = _read_one(db, 'SELECT original_digest FROM c09_storage_build_originals_v1 '
                    'WHERE installation_id=? AND operation_id=? AND original_kind=?',
                    (self.control.installation_id, self.scope.operation_id, 'segmented_role_complete_v1_' + self.role), meter)
                if row is None or self.original_digest is not None and row != (self.original_digest,):
                    raise AuthorityUnavailable('actual segmented role completion is absent or changed')
                self.original_digest = row[0]
                details = _read_original(self.control, db, self.scope.operation_id,
                    'segmented_role_complete_v1_' + self.role, self.original_digest, meter)
                source = c09_paged_value_from_wire_v2(self.base['source_original'], C09FrozenRoleSourceV2)
                if (details['schema'] != 'sylanne3.c09.segmented-role-complete.v1'
                        or details['operation_id'] != self.scope.operation_id or details['scope_digest'] != self.scope.scope_digest
                        or details['role'] != self.role or details['role_complete_original_digest'] != self.base_digest
                        or details['source_role_source_digest'] != source.role_source_digest
                        or tuple(details['target_identity']) != self.target_stamp[:2]
                        or details['layout_id'] != LAYOUTS[self.role] or details['layout_schema_digest'] != LAYOUT_SCHEMA_DIGEST
                        or details['storage_instance_id'] != canonical_digest({'schema': 'sylanne3.segmented-storage-instance.v1',
                            'scope': self.scope.scope_digest, 'role': self.role, 'target_identity': self.target_stamp[:2]})):
                    raise AuthorityUnavailable('actual segmented role completion differs from its base, layout or instance')
                self.details = details
                return {'status': 'progress', 'phase': 'segmented_role_original', 'role': self.role}
            if self.child_index == len(_CHILDREN):
                self.result = VerifiedSegmentedRoleOriginalV3(_ROLE, self)
                return self.result
            kind, field, prefix, schema, table = _CHILDREN[self.child_index]
            if self.child is None:
                child = _read_original(self.control, db, self.scope.operation_id,
                    prefix + self.role, self.details[field], meter)
                if (child['schema'] != schema or child['proof_store_id'] != self.control.control_store_id
                        or any(child[name] != self.details[name] for name in _COMMON)):
                    raise AuthorityUnavailable('actual segmented child completion crossed its registered role')
                identity = c09_paged_value_from_wire_v2(child['identity'], C09StreamIdentityV2)
                census = c09_paged_value_from_wire_v2(child['count_original'], C09CountOriginalV2)
                cursor = c09_paged_value_from_wire_v2(child['final_cursor'], C09PageCursorV2)
                complete = c09_paged_value_from_wire_v2(child['complete_stream'], C09CompleteStreamV2)
                self.shape = read_c09_table_shape_v2(db, table, meter=meter)
                if (identity.scope_digest != self.scope.scope_digest or identity.role_source_digest != self.details['source_role_source_digest']
                        or identity.family != table or identity.schema_digest != self.shape.schema_digest):
                    raise AuthorityUnavailable('actual segmented child stream schema or identity differs')
                verify_c09_complete_stream_v2(identity, cursor, census, complete,
                    data_eof_observation_digest=child['data_eof_observation_digest'])
                if kind != 'headers' and child['cell_headers_complete_original_digest'] != self.details['cell_headers_complete_original_digest']:
                    raise AuthorityUnavailable('actual segmented child lost its original header completion')
                if kind == 'orphan_audit':
                    if (child['segments_complete_original_digest'] != self.details['segments_complete_original_digest']
                            or child['logical_refs_complete_original_digest'] != self.details['logical_refs_complete_original_digest']
                            or child['violation_count'] != 0 or set(child['scan_counts']) != {'headers', 'segments', 'refs', 'write_progress'}
                            or set(child['scan_eof_digests']) != {'headers', 'segments', 'refs', 'write_progress'}
                            or child['scan_counts']['headers'] != self.counts['headers']
                            or child['scan_counts']['segments'] != self.counts['segments']
                            or child['scan_counts']['refs'] != self.counts['logical_refs']
                            or complete.record_count != sum(child['scan_counts'].values())):
                        raise AuthorityUnavailable('actual segmented orphan audit does not cover the complete physical basis')
                self.child = child
                self.locators[kind] = C09SealedStreamLocatorV2(self.role, identity, complete)
                self.stream_reader = C09HistoricalSealedStreamReaderV2(self.locators[kind])
                return {'status': 'progress', 'phase': 'segmented_child_original', 'role': self.role, 'kind': kind}
            def observe(record):
                if record.primary_key[:2] != (self.scope.scope_digest, self.role):
                    raise AuthorityUnavailable('actual segmented original page crossed its registered role')
                row = meter.read_row(db, self.shape, record.primary_key)
                if row is None or c09_row_commitment_v2(tuple(row)) != record.commitment:
                    raise AuthorityUnavailable('actual segmented projection differs from its complete original page')
                if self.selection is not None:
                    from hashlib import sha256
                    with self.selection.read_database(self.role, meter=meter) as target:
                        if kind == 'headers':
                            columns = ('cell_id', 'codec_id', 'erasure_owner_ref', 'producer_operation_id', 'total_bytes',
                                'segment_count', 'payload_sha256', 'ordered_segment_root', 'origin_scope_digest')
                            actual = meter.read_fixed_row(target, 'segmented_cells_v1', columns, 'cell_id=?', (row[2],))
                            if actual is None or tuple(json.loads(row[3])) != tuple(actual):
                                raise AuthorityUnavailable('actual selected cell header differs from its complete protected original')
                        elif kind == 'segments':
                            actual = meter.read_fixed_row(target, 'segmented_cell_segments_v1',
                                ('cell_id', 'ordinal', 'byte_offset', 'payload', 'payload_sha256'),
                                'cell_id=? AND ordinal=?', (row[2], row[3]))
                            if (actual is None or type(actual[3]) is not bytes
                                    or (actual[0], actual[1], actual[2], len(actual[3]), actual[4]) != tuple(row[2:])
                                    or sha256(actual[3]).hexdigest() != actual[4]):
                                raise AuthorityUnavailable('actual selected segment body, offset or SHA differs from its complete protected original')
                        elif kind == 'logical_refs' and self.selection.current['stage'] not in {'RELEASED', 'INTENT', 'PREPARED'}:
                            from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
                            shape = read_c09_table_shape_v2(target, row[2], meter=meter)
                            actual = meter.read_row(target, shape, tuple(json.loads(row[5])))
                            if actual is None or c09_row_commitment_v2(tuple(actual)) != row[9]:
                                raise AuthorityUnavailable('actual selected logical reference differs from its complete protected original')
            if self.stream_reader.advance(db, meter, observe):
                self.counts[kind] = self.stream_reader.locator.complete.record_count
                self.child_index += 1
                self.child = self.stream_reader = self.shape = None
            return {'status': 'progress', 'phase': 'segmented_child_pages', 'role': self.role, 'kind': kind}


def begin_segmented_role_original_read_v3(control, *, scope, role,
        base_complete_original_digest, segmented_complete_original_digest=None):
    from .c09_storage_control_v1 import C09StorageControlV1, InstalledC09StorageReaderV1, ROLES
    if (type(control) not in {C09StorageControlV1, InstalledC09StorageReaderV1}
            or type(scope) is not C09CaptureScopeV2 or role not in ROLES
            or (scope.authority_id, scope.installation_id) != (control.authority_id, control.installation_id)):
        raise AuthorityUnavailable('actual installed segmented role original factory required')
    control.lease.require_held()
    return _SegmentedRoleOriginalReaderV3(control, scope, role,
        base_complete_original_digest, segmented_complete_original_digest)


def install_prepared_schema_v3(control, db):
    found = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE_V3,)).fetchone()
    if found is None:
        db.execute(DDL_V3)
        for action in ('UPDATE', 'DELETE'):
            db.execute(control._immutable_ddl(TABLE_V3, action))
    validate_prepared_schema_v3(control, db)


def validate_prepared_schema_v3(control, db):
    found = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE_V3,)).fetchone()
    if found is None or found[0] != DDL_V3:
        raise AuthorityUnavailable('actual V3 PREPARED registered schema differs')
    for action in ('UPDATE', 'DELETE'):
        name = TABLE_V3 + '_no_' + action.lower()
        found = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if found is None or found[0] != control._immutable_ddl(TABLE_V3, action):
            raise AuthorityUnavailable('actual V3 PREPARED immutable trigger differs')


def _require_verified_roles(control, scope, verified_roles, meter):
    from .c09_storage_control_v1 import ROLES
    if (type(verified_roles) is not tuple or len(verified_roles) != len(ROLES)
            or any(type(proof) is not VerifiedSegmentedRoleOriginalV3 for proof in verified_roles)
            or tuple(sorted(proof.role for proof in verified_roles)) != ROLES):
        raise AuthorityUnavailable('four actual private segmented role originals required')
    for proof in verified_roles:
        proof.require_current(control=control, scope=scope, meter=meter)
    return {proof.role: proof for proof in verified_roles}


def verify_prepared_original_v3(control, db, original, manifest, *, verified_roles, meter):
    """Consume completed role proofs; this call never recreates all stream reads."""
    _require_meter(meter)
    from .c09_storage_manifest_v3 import require_manifest_provenance_shape_v3
    from .c09_storage_manifest_v2 import _require_manifest_actual_paged_provenance_v2
    from .c09_prepared_storage_v2 import _verify_paged_prepared_original_v2
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    require_manifest_provenance_shape_v3(manifest)
    bounded = _BoundedReadConnectionV2(db, meter)
    bounded._natural_preflight_v3 = lambda size: meter.require_available(size * 7)
    _verify_paged_prepared_original_v2(control, bounded, original, manifest,
        expected_schema=SCHEMA_V3, expected_fields=PREPARED_FIELDS_V3)
    _require_manifest_actual_paged_provenance_v2(control, bounded, manifest, original)
    scope = C09CaptureScopeV2(**_read_original(control, db, original['operation_id'],
        'capture_scope_v2', None, meter))
    expected = dict(schema=TRANSITION_SCHEMA, source_scope_digest=scope.scope_digest,
        authority_id=scope.authority_id, installation_id=scope.installation_id,
        authority_namespace=scope.authority_namespace, operation_id=scope.operation_id,
        source_manifest_digest=scope.old_manifest_digest, expected_pointer_version=scope.expected_pointer_version,
        target_storage_generation=scope.maintenance_generation, accepted_receipt_digest=scope.accepted_receipt_digest,
        barrier_digest=scope.barrier_digest, writer_freeze_digest=scope.writer_freeze_digest,
        layout_schema_digest=LAYOUT_SCHEMA_DIGEST, role_layouts=LAYOUTS)
    transition = _read_original(control, db, scope.operation_id, 'segmented_storage_transition_v1',
        original['segmented_storage_transition_original_digest'], meter)
    if transition != expected:
        raise AuthorityUnavailable('actual V3 PREPARED segmented transition differs from its installed capture')
    provider_scopes = _read_original(control, db, scope.operation_id, 'provider_scope_complete_v3',
        original['provider_scope_complete_original_digest'], meter)
    if provider_scopes['scope_digest'] != scope.scope_digest or provider_scopes['complete'] is not True:
        raise AuthorityUnavailable('actual V3 PREPARED provider scope coverage is incomplete or cross scope')
    core_obligations = _read_original(control, db, scope.operation_id, 'natural_final_core_obligations_complete_v4',
        original['natural_core_obligations_complete_original_digest'], meter)
    if (core_obligations['scope_digest'] != scope.scope_digest or core_obligations['pending_count'] != 0):
        raise AuthorityUnavailable('actual V3 PREPARED closing Core obligations are incomplete or cross scope')
    proofs = _require_verified_roles(control, scope, verified_roles, meter)
    core_header = proofs['core'].base_header
    core_source = c09_paged_value_from_wire_v2(core_header['source_original'], C09FrozenRoleSourceV2)
    if (core_obligations['core_source_original_digest'] != core_source.role_source_digest
            or core_obligations['cold_digest'] != core_header['cold_digest']):
        raise AuthorityUnavailable('actual closing Core source and cold completion differ from the selected role')
    if original['segmented_role_complete_original_digests'] != manifest['segmented_role_complete_original_digests']:
        raise AuthorityUnavailable('actual V3 PREPARED segmented roles differ from its manifest')
    for member in manifest['members']:
        role = member['role']
        proof = proofs[role]
        if (original['segmented_role_complete_original_digests'][role] != proof.original_digest
                or original['four_role_complete_original_digests'][role] != proof.base_original_digest
                or member['resolved_path'] != proof.target_path
                or (member['device'], member['file_id']) != proof.target_identity
                or manifest['segmented_layouts'][role] != dict(layout_id=proof.layout_id,
                    layout_schema_digest=proof.layout_schema_digest, storage_instance_id=proof.storage_instance_id)):
            raise AuthorityUnavailable('actual V3 selected role, target or layout differs from its complete originals')
    return original


def _read_selected_prepared_payload_v3(control, db, manifest, meter):
    """Read the bounded signed candidate descriptor; confer no storage admission."""
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    _require_meter(meter)
    if _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE_V3,), meter) is None:
        return None
    bounded = _BoundedReadConnectionV2(db, meter)
    bounded._natural_preflight_v3 = lambda size: meter.require_available(size * 7)
    validate_prepared_schema_v3(control, bounded)
    for version in (1, 2):
        table = 'c09_storage_operations_v' + str(version)
        if _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,), meter) is not None:
            if _read_one(db, 'SELECT 1 FROM ' + table + ' WHERE new_manifest_digest=?',
                    (manifest['manifest_digest'],), meter) is not None:
                raise AuthorityUnavailable('actual selected manifest has conflicting PREPARED versions')
    metadata = _read_one(db, 'SELECT operation_id,length(CAST(prepared_original_json AS BLOB)) FROM ' +
        TABLE_V3 + ' WHERE new_manifest_digest=?', (manifest['manifest_digest'],), meter)
    if metadata is None:
        return None
    if metadata[1] > 65536:
        raise AuthorityUnavailable('actual selected V3 PREPARED exceeds its compact descriptor bound')
    row = bounded.execute('SELECT operation_id,installation_id,namespace,generation,expected_pointer_version,'
        'old_manifest_digest,new_manifest_digest,prepared_original_json,prepared_digest,key_id,signature FROM ' +
        TABLE_V3 + ' WHERE operation_id=?', (metadata[0],)).fetchone()
    original = json.loads(row[7])
    from .c09_storage_control_v1 import canonical
    if (set(original) != PREPARED_FIELDS_V3 or original['schema'] != SCHEMA_V3 or canonical(original) != row[7]
            or tuple(original[name] for name in ('operation_id', 'installation_id', 'namespace',
                'maintenance_generation', 'expected_pointer_version', 'old_manifest_digest',
                'new_manifest_digest', 'prepared_digest', 'key_id', 'signature')) != (*row[:7], *row[8:])):
        raise AuthorityUnavailable('actual selected V3 PREPARED row or exact canonical bytes differ')
    control.verify_original_v1(original, 'prepared_digest')
    return original


def read_selected_prepared_v3(control, db, manifest, *, verified_roles, meter):
    original = _read_selected_prepared_payload_v3(control, db, manifest, meter)
    if original is None:
        return None
    return verify_prepared_original_v3(control, db, original, manifest,
        verified_roles=verified_roles, meter=meter)


def record_prepared_storage_v3(control, *, manifest, prepared_original, closing_continuation,
        verified_roles, meter):
    """Register genuine V3 segmented originals under the existing continuous gate."""
    _require_meter(meter)
    from .c09_storage_control_v1 import canonical
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    control.lease.require_held()
    control._manifest(manifest)
    operation = prepared_original['operation_id']
    gate = control._final_gate_v3
    gate.require_final_continuation_v3(closing_continuation, operation_id=operation, observe=False)
    with control._db(write=True) as db:
        current = control._current(db)
        install_prepared_schema_v3(control, db)
        verify_prepared_original_v3(control, db, prepared_original, manifest, verified_roles=verified_roles, meter=meter)
        bounded = _BoundedReadConnectionV2(db, meter)
        prior = bounded.execute('SELECT prepared_original_json FROM ' + TABLE_V3 + ' WHERE operation_id=?',
            (operation,)).fetchone()
        for version in (1, 2):
            table = 'c09_storage_operations_v' + str(version)
            if _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,), meter) is not None:
                if _read_one(db, 'SELECT 1 FROM ' + table + ' WHERE operation_id=? OR new_manifest_digest=?',
                        (operation, manifest['manifest_digest']), meter) is not None:
                    raise AuthorityUnavailable('actual V3 PREPARED conflicts with another signed operation version')
        if prior is not None:
            if prior[0] != canonical(prepared_original):
                raise AuthorityUnavailable('actual V3 PREPARED replay differs')
            return control._event(db, current, operation_id=operation, stage='PREPARED', details={
                'prepared_digest': prepared_original['prepared_digest'], 'new_manifest_digest': manifest['manifest_digest']})
        if (current['stage'] != 'INTENT' or current['active_operation_id'] != operation
                or current['pointer_version'] != prepared_original['expected_pointer_version']
                or current['current_manifest_digest'] != prepared_original['old_manifest_digest']):
            raise AuthorityUnavailable('actual V3 PREPARED predecessor changed')
        intent_row = bounded.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='INTENT'",
            (operation,)).fetchone()
        if intent_row is None:
            raise AuthorityUnavailable('actual V3 PREPARED signed INTENT is absent')
        intent = json.loads(intent_row[0])
        control.verify_original_v1(intent, 'event_digest')
        if (intent['details']['accepted_receipt_digest'] != prepared_original['accepted_receipt_digest']
                or intent['details']['quiescence_original']['quiescence_digest'] != prepared_original['writer_freeze_digest']
                or any(member['resolved_path'] != intent['details']['targets'][member['role']] for member in manifest['members'])):
            raise AuthorityUnavailable('actual V3 PREPARED acceptance, freeze or installed targets differ')
        from .c09_writer_peer_originals_v3 import require_writer_quiescence_original_v3
        require_writer_quiescence_original_v3(control,intent['details']['quiescence_original'],meter=meter,operation_id=operation)
        from .c09_prepared_inventory_v2 import require_prepared_inventory_v2
        require_prepared_inventory_v2(control, bounded, prepared_original, gate)
        old = control._read_manifest(db, prepared_original['old_manifest_digest'])
        if manifest['generation'] != old['generation'] + 1 or manifest['prior_manifest_digest'] != old['manifest_digest']:
            raise AuthorityUnavailable('actual V3 PREPARED storage generation does not follow its predecessor')
        control._store_manifest(db, manifest)
        columns = ('operation_id', 'installation_id', 'namespace', 'generation', 'expected_pointer_version',
            'old_manifest_digest', 'new_manifest_digest', 'prepared_original_json', 'prepared_digest', 'key_id', 'signature')
        meter.write_row(db, TABLE_V3, columns, (operation, control.installation_id, prepared_original['namespace'],
            manifest['generation'], prepared_original['expected_pointer_version'], old['manifest_digest'],
            manifest['manifest_digest'], canonical(prepared_original), prepared_original['prepared_digest'],
            control.key_id, prepared_original['signature']))
        return control._event(db, current, operation_id=operation, stage='PREPARED', details={
            'prepared_digest': prepared_original['prepared_digest'], 'new_manifest_digest': manifest['manifest_digest']})


def begin_selected_segmented_role_original_read_v3(selection, *, scope, role,
        base_complete_original_digest, segmented_complete_original_digest):
    from .c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    if type(selection) is not _InstalledSelectedStorageBasisV3:
        raise AuthorityUnavailable('actual installed selected storage basis required')
    selection.require_current(meter=current_c09_sql_meter_v2())
    if scope.scope_digest != selection.prepared['capture_scope_digest']:
        raise AuthorityUnavailable('selected segmented role belongs to another actual capture scope')
    return _SegmentedRoleOriginalReaderV3(selection.control, scope, role,
        base_complete_original_digest, segmented_complete_original_digest, selection=selection)


from .c09_paged_recovery_facts_v2 import C09VerifiedPagedPreparedSummaryV2


class C09VerifiedPagedPreparedSummaryV3(C09VerifiedPagedPreparedSummaryV2):
    """Authenticate V3 history under its own immutable table and signing schema."""
    __slots__ = ()

    def require_current(self, *, meter):
        with self._control._db() as db:
            current = self._control._current(db)
            selected = _read_one(db, 'SELECT generation FROM c09_storage_manifests_v1 WHERE manifest_digest=?',
                (current['current_manifest_digest'],), meter)
            row = _read_one(db, 'SELECT operation_id,generation,old_manifest_digest,new_manifest_digest,'
                'prepared_digest,key_id,signature FROM c09_storage_operations_v3 WHERE installation_id=? AND operation_id=?',
                (self._control.installation_id, self._header['operation_id']), meter)
        if (selected is None or (current['pointer_version'], current['current_manifest_digest'], selected[0]) != self._selection
                or row != self._row):
            raise AuthorityUnavailable('actual V3 historical PREPARED or selected pointer changed')
        return self


class _CompactPreparedReaderV3:
    """Read a signed historical V3 descriptor without opening retired old files."""
    def __init__(self, control, row, selection):
        self.control, self.row, self.selection = control, tuple(row), tuple(selection)
        self.result = None

    def advance(self, *, meter):
        _require_meter(meter)
        if self.result is not None:
            return self.result.require_current(meter=meter)
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2, _TOKEN
        from .c09_prepared_storage_v2 import _verify_paged_prepared_original_v2
        from .c09_storage_manifest_v2 import _require_manifest_actual_paged_provenance_v2
        with self.control._db() as db:
            bounded = _BoundedReadConnectionV2(db, meter)
            bounded._natural_preflight_v3 = lambda size: meter.require_available(size * 7)
            validate_prepared_schema_v3(self.control, bounded)
            stored = bounded.execute('SELECT prepared_original_json FROM c09_storage_operations_v3 '
                'WHERE installation_id=? AND operation_id=?', (self.control.installation_id, self.row[0])).fetchone()
            if stored is None or len(stored[0].encode()) > 65536:
                raise AuthorityUnavailable('actual V3 historical descriptor is absent or exceeds its registered bound')
            original = json.loads(stored[0])
            from .c09_storage_control_v1 import canonical
            if canonical(original) != stored[0]:
                raise AuthorityUnavailable('actual V3 historical descriptor canonical bytes differ')
            manifest = self.control._read_manifest(db, self.row[3])
            _verify_paged_prepared_original_v2(self.control, bounded, original, manifest,
                expected_schema=SCHEMA_V3, expected_fields=PREPARED_FIELDS_V3)
            _require_manifest_actual_paged_provenance_v2(self.control, bounded, manifest, original)
            if original['segmented_role_complete_original_digests'] != manifest['segmented_role_complete_original_digests']:
                raise AuthorityUnavailable('actual V3 historical role references differ from its signed manifest')
        if tuple(original[name] for name in ('operation_id', 'maintenance_generation', 'old_manifest_digest',
                'new_manifest_digest', 'prepared_digest', 'key_id', 'signature')) != self.row:
            raise AuthorityUnavailable('actual V3 historical original row differs')
        self.result = C09VerifiedPagedPreparedSummaryV3(_TOKEN, self.control, original, self.row, self.selection)
        return self.result.require_current(meter=meter)


class InstalledPreparedSwitchV3:
    """Actual same-operation four-store switch after bounded eight-file EOF."""
    def __init__(self, control, operation_id, quiescence_original):
        self.control, self.operation_id, self.quiescence = control, operation_id, quiescence_original
        self.phase = 'prepared'
        self.manifest = self.prepared = self.old = self.scope = None
        self.role_index = 0
        self.role_reader = None
        self.roles = {}
        self.files = None
        self.file_index = 0
        self.file = self.file_hash = self.file_stamp = None
        self.file_offset = 0
        self.failed = False

    def advance(self):
        if self.failed:
            raise AuthorityUnavailable('actual V3 switch preserves its first failed quantum')
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
        try:
            with self.control.reserve_control_read_v3() as budget:
                meter = require_c09_reserved_meter_v3(budget)
                with c09_sql_meter_quantum_v2(meter):
                    return self._advance(meter)
        except BaseException:
            self.failed = True
            if self.file is not None:
                self.file.close()
                self.file = None
            raise

    def _advance(self, meter):
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        from .c09_storage_control_v1 import ROLES, canonical, _regular_path
        with self.control._db() as db:
            current = self.control._current(db)
            replay = _read_one(db, "SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='SWITCHED'",
                (self.operation_id,), meter)
            if replay is not None:
                event = json.loads(replay[0])
                self.control.verify_original_v1(event, 'event_digest')
                return dict(status='complete', phase='SWITCHED', event=event)
            if current['stage'] != 'PREPARED' or current['active_operation_id'] != self.operation_id:
                raise AuthorityUnavailable('actual V3 switch requires its current PREPARED')
            if self.phase == 'prepared':
                row = _read_one(db, 'SELECT new_manifest_digest FROM c09_storage_operations_v3 WHERE operation_id=?',
                    (self.operation_id,), meter)
                if row is None:
                    raise AuthorityUnavailable('actual V3 switch original is absent')
                self.manifest = self.control._read_manifest(db, row[0])
                self.prepared = _read_selected_prepared_payload_v3(self.control, db, self.manifest, meter)
                self.old = self.control._read_manifest(db, self.prepared['old_manifest_digest'])
                self.scope = C09CaptureScopeV2(**_read_original(self.control, db, self.operation_id, 'capture_scope_v2', None, meter))
                from .c09_writer_peer_originals_v3 import require_writer_quiescence_original_v3
                require_writer_quiescence_original_v3(self.control,self.quiescence,meter=meter,operation_id=self.operation_id)
                if (self.quiescence['operation_id'] != self.operation_id or self.quiescence['active_writers'] != 0
                        or self.quiescence['pointer_version'] != current['pointer_version']
                        or (current['pointer_version'], current['current_manifest_digest']) !=
                            (self.prepared['expected_pointer_version'], self.prepared['old_manifest_digest'])):
                    raise AuthorityUnavailable('actual V3 switch quiescence or predecessor differs')
                self.phase = 'roles'
                return dict(status='progress', phase='switch_prepared')
        if self.phase == 'roles':
            if self.role_index < len(ROLES):
                role = ROLES[self.role_index]
                if self.role_reader is None:
                    self.role_reader = begin_segmented_role_original_read_v3(self.control, scope=self.scope, role=role,
                        base_complete_original_digest=self.prepared['four_role_complete_original_digests'][role],
                        segmented_complete_original_digest=self.prepared['segmented_role_complete_original_digests'][role])
                proof = self.role_reader.advance(meter=meter)
                if type(proof) is VerifiedSegmentedRoleOriginalV3:
                    self.roles[role] = proof
                    self.role_reader = None
                    self.role_index += 1
                return dict(status='progress', phase='switch_role_originals', role=role)
            with self.control._db() as db:
                verify_prepared_original_v3(self.control, db, self.prepared, self.manifest,
                    verified_roles=tuple(self.roles[role] for role in ROLES), meter=meter)
            self.files = tuple(self.manifest['members']) + tuple(self.prepared['source_final_fingerprints'])
            self.phase = 'files'
            return dict(status='progress', phase='switch_originals_complete')
        if self.phase == 'files':
            if self.file_index == len(self.files):
                self.phase = 'commit'
                return dict(status='progress', phase='switch_file_eof')
            item = self.files[self.file_index]
            path = _regular_path(item['resolved_path'])
            expected = (item['device'], item['file_id'], item['prepared_size'], item['prepared_mtime_ns'])
            if any(Path(str(path) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')):
                raise AuthorityUnavailable('actual V3 switch file retains an unclosed companion')
            import os
            if self.file is None:
                self.file = path.open('rb')
                self.file_hash = __import__('hashlib').sha256()
                self.file_offset = 0
                stat = os.fstat(self.file.fileno())
                self.file_stamp = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
            stat = os.fstat(self.file.fileno())
            if self.file_stamp != expected or self.file_stamp != (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns):
                raise AuthorityUnavailable('actual V3 switch same-handle fingerprint changed')
            amount = min(16384, meter.remaining_bytes)
            meter.require_available(amount)
            block = self.file.read(amount)
            meter.charge_read(len(block))
            if block:
                self.file_hash.update(block)
                self.file_offset += len(block)
            else:
                if self.file_offset != expected[2] or self.file_hash.hexdigest() != item['prepared_sha256']:
                    raise AuthorityUnavailable('actual V3 switch complete file SHA or EOF length differs')
                self.file.close()
                self.file = None
                self.file_index += 1
            return dict(status='progress', phase='switch_file_hash', file_index=self.file_index, byte_offset=self.file_offset)
        if self.phase == 'commit':
            with self.control._db(write=True) as db:
                current = self.control._current(db)
                if (current['stage'] != 'PREPARED' or current['active_operation_id'] != self.operation_id
                        or (current['pointer_version'], current['current_manifest_digest']) !=
                            (self.prepared['expected_pointer_version'], self.prepared['old_manifest_digest'])):
                    raise AuthorityUnavailable('actual V3 four-store pointer CAS changed')
                for item in self.files:
                    stat = _regular_path(item['resolved_path']).stat()
                    if (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) != (
                            item['device'], item['file_id'], item['prepared_size'], item['prepared_mtime_ns']):
                        raise AuthorityUnavailable('actual V3 switch file changed after complete SHA')
                details = dict(prepared_digest=self.prepared['prepared_digest'],
                    quiescence_digest=self.quiescence['quiescence_digest'], quiescence_original=self.quiescence)
                event = self.control._event(db, current, operation_id=self.operation_id, stage='SWITCHED', details=details, manifest=self.manifest)
                for member in self.old['members']:
                    source = next(item for item in self.prepared['source_final_fingerprints'] if item['resolved_path'] == member['resolved_path'])
                    values = (self.control.installation_id, member['role'], self.old['generation'], member['resolved_path'],
                        canonical(source), source['prepared_sha256'], event['event_digest'])
                    meter.charge_write(sum(len(str(value).encode()) for value in values))
                    db.execute('INSERT INTO c09_storage_retired_files_v1 VALUES(?,?,?,?,?,?,?)', values)
            self.phase = 'complete'
            return dict(status='complete', phase='SWITCHED', event=event)
        raise AuthorityUnavailable('actual V3 switch private phase differs')


def advance_prepared_switch_v3(control, *, operation_id, quiescence_original):
    switch = getattr(control, '_prepared_switch_v3', None)
    if switch is None:
        switch = InstalledPreparedSwitchV3(control, operation_id, quiescence_original)
        control._prepared_switch_v3 = switch
    elif switch.operation_id != operation_id or switch.quiescence != quiescence_original:
        raise AuthorityUnavailable('actual V3 switch continuation scope changed')
    return switch.advance()
