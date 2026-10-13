"""Private frozen physical Source reads for actual C09 capture; no business grant."""
from __future__ import annotations
from hashlib import sha256
from contextlib import contextmanager
from time import monotonic_ns
from pathlib import Path
import json
import threading
from weakref import WeakSet
from .contract import AuthorityUnavailable
from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

_ISSUER = object()
_SCOPES = WeakSet()
_HEADER = ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
    'payload_sha256','ordered_segment_root','origin_scope_digest')


class SourcePhysicalReadScopeV3:
    def __init__(self, token, session, pair, previous):
        if token is not _ISSUER:
            raise AuthorityUnavailable('actual frozen C09 Source issuer required')
        self.session, self.pair, self.role, self.source = session, pair, pair.source_original.role, pair.source
        self.source_original = pair.source_original
        self.actor = session._control.maintenance._maintenance_actor_v3
        self.previous_selected_basis = previous
        self.operation_id = session.scope.operation_id
        self.arena = session._source_parser_arena_v3
        self._header = None
        self.initial_owner_qualification=None;self.initial_physical_qualification=None
        _SCOPES.add(self)
    def _source_heap_bytes(self):
        return 1024 + (0 if self._header is None else sum(len(value.encode('utf8')) if type(value) is str else 32 for value in self._header))
    def require_current(self, *, meter):
        from .c09_maintenance_actor_v3 import InstalledC09MaintenanceActorV3
        actual = require_c09_reserved_meter_v3(meter.budget)
        if meter is not actual or self not in _SCOPES:
            raise AuthorityUnavailable('actual C09 Source quantum and private scope required')
        session, m = self.session, self.session._control.maintenance
        if (type(self.actor) is not InstalledC09MaintenanceActorV3 or self.actor is not m._maintenance_actor_v3
                or self.actor.operation_id != session.scope.operation_id or self.actor.owner_thread != threading.get_ident()):
            raise AuthorityUnavailable('actual current C09 Source actor and thread owner required')
        session._control._registered()
        session.require_current()
        producer = session._control._role_pairs.get(self.role)
        if producer is None or producer.pair is not self.pair or self.pair._producer.session is not session:
            raise AuthorityUnavailable('actual registered frozen Source pair required')
        self.pair.require_current()
        identity = json.loads(self.source_original.source_identity)
        stat = Path(self.source_original.source_path).stat()
        if (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns) != tuple(identity[name] for name in ('device','file_id','size','mtime_ns')):
            raise AuthorityUnavailable('actual frozen Source four-stamp changed')
        if self.previous_selected_basis is not None:
            self.previous_selected_basis.require_current(meter=meter)
            member = self.previous_selected_basis.member(self.role)
            if member['resolved_path'] != self.source_original.source_path or self.previous_selected_basis.manifest['manifest_digest'] != session.scope.old_manifest_digest:
                raise AuthorityUnavailable('actual V3 Source is outside the previous selected cut')
        return self
    @contextmanager
    def read_database_v3(self,*,meter):
        self.require_current(meter=meter)
        if self.source.in_transaction:
            raise AuthorityUnavailable('actual frozen Source physical census owns one bounded readonly transaction')
        started=monotonic_ns();self.source.execute('BEGIN')
        try:yield self.source
        finally:self.source.rollback()
        if monotonic_ns()-started>meter.budget.max_read_ns:
            raise AuthorityUnavailable('actual frozen physical Source transaction exceeded its unchanged duration')
        self.require_current(meter=meter)

    def read_owner_source_prepared_metadata_v3(self,prepared_digest,*,meter):
        self.require_current(meter=meter)
        if self.role!='graph':
            raise AuthorityUnavailable('actual Graph Source required')
        if self.previous_selected_basis is None:
            qualification=_initial_owner_source_qualification_v3(self,meter)
            original=_initial_owner_prepared_values_read_v3(qualification,prepared_digest,meter)
            if original is None:raise AuthorityUnavailable('actual initial Owner Source prepared metadata absent')
            return VerifiedSourceOwnerPreparedMetadataV3(_ISSUER,self,prepared_digest,original)
        from ..runtime.owner_material_source_storage_v3 import read_selected_owner_source_prepared_v3
        original=read_selected_owner_source_prepared_v3(self.source,basis=self.previous_selected_basis,
            prepared_digest=prepared_digest,meter=meter)
        if original is None:raise AuthorityUnavailable('actual Owner Source prepared metadata absent')
        self.require_current(meter=meter)
        return VerifiedSourceOwnerPreparedMetadataV3(_ISSUER,self,prepared_digest,original)

    def qualify_owner_source_storage_row_v3(self,table,key,*,meter):
        self.require_current(meter=meter)
        if self.role!='graph':
            raise AuthorityUnavailable('actual Graph metadata Source required')
        if self.previous_selected_basis is None:
            qualification=_initial_owner_source_qualification_v3(self,meter)
            original=_initial_owner_storage_values_read_v3(qualification,table,tuple(key),meter)
            if original is None:raise AuthorityUnavailable('actual initial Owner Source metadata row absent')
            return VerifiedSourceOwnerStorageMetadataV3(_ISSUER,self,table,tuple(key),original)
        from ..runtime.owner_material_source_storage_v3 import (read_selected_owner_source_prepared_v3,
            read_selected_owner_source_disposition_v3,read_selected_owner_source_command_seed_v3)
        from ..runtime_contracts import NamespaceId,namespace_ref
        key=tuple(key)
        if table=='graph_owner_source_command_seeds_v3':
            if len(key)!=3:raise AuthorityUnavailable('actual Owner Source command seed PK required')
            namespace=NamespaceId(key[0],key[1])
            if namespace_ref(namespace)!=self.session.scope.authority_namespace:
                raise AuthorityUnavailable('actual Source command seed belongs to another capture namespace')
            original=read_selected_owner_source_command_seed_v3(self.source,basis=self.previous_selected_basis,
                namespace=namespace,operation_id=key[2],meter=meter)
        elif table in ('graph_owner_source_prepared_v3','graph_owner_source_dispositions_v3'):
            if len(key)!=1:raise AuthorityUnavailable('actual Owner Source prepared digest PK required')
            reader=read_selected_owner_source_prepared_v3 if table=='graph_owner_source_prepared_v3' else read_selected_owner_source_disposition_v3
            original=reader(self.source,basis=self.previous_selected_basis,prepared_digest=key[0],meter=meter)
        else:raise AuthorityUnavailable('registered Owner Source metadata semantic family required')
        if original is None:raise AuthorityUnavailable('actual Owner Source metadata row absent')
        self.require_current(meter=meter)
        return VerifiedSourceOwnerStorageMetadataV3(_ISSUER,self,table,key,original)

    def begin_owner_source_output_v3(self,prepared_digest,cell_name,*,meter):
        self.require_current(meter=meter)
        if self.role!='graph':
            raise AuthorityUnavailable('actual frozen Graph Source required')
        if self.previous_selected_basis is None:_initial_owner_source_qualification_v3(self,meter)
        if cell_name not in ('input','source','original','stage_request','http_request','bundle'):
            raise AuthorityUnavailable('registered six Owner Source output name required')
        return PreparedOwnerOutputSourceReadV3(_ISSUER,self,prepared_digest,cell_name)

    def read_cell_header_v3(self, cell_id, *, meter):
        self.require_current(meter=meter)
        row = meter.read_fixed_row(self.source, 'segmented_cells_v1', _HEADER, 'cell_id=?', (cell_id,))
        if row is None or row[1] not in {'canonical-json.ascii.v1','canonical-json.utf8.v1','opaque-bytes.v1'}:
            raise AuthorityUnavailable('actual frozen mapped Source cell header absent or codec differs')
        if self.previous_selected_basis is None:
            qualification=_initial_owner_source_qualification_v3(self,meter)
            producer=_initial_owner_cell_values_read_v3(qualification,cell_id,tuple(row[1:]),meter)
            if producer is None or producer['phase']!='committed':
                raise AuthorityUnavailable('initial published Source cell lacks its actual committed Owner producer')
            self._header=tuple(row)
            meter.require_available(self._source_heap_bytes())
            return self._header
        basis = self.previous_selected_basis
        if row[8] == basis.prepared['capture_scope_digest']:
            from .c09_selected_history_v3 import _read_one
            from ..runtime_contracts import canonical_serialize
            with basis.control._db() as db:
                retained = _read_one(db, 'SELECT header_json FROM c09_segmented_headers_v3 WHERE scope_digest=? AND role=? AND cell_id=?',
                    (basis.prepared['capture_scope_digest'], self.role, cell_id), meter)
            if retained != (canonical_serialize(tuple(row)),):
                raise AuthorityUnavailable('actual frozen capture-cut cell differs from its protected header original')
        else:
            from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3
            producer = read_selected_runtime_cell_origin_v3(self.source, selected_basis=basis, role=self.role, cell_id=cell_id,
                header=tuple(row[1:]), meter=meter)
            if producer is None:
                raise AuthorityUnavailable('actual frozen mapped Source cell lacks a qualified runtime or Owner producer')
            if producer.get('producer_kind') == 'owner_material_source_prepared_v3' and producer['phase'] != 'committed':
                raise AuthorityUnavailable('actual uncommitted or aborted Source cell cannot qualify a published logical body')
        self._header = tuple(row)
        meter.require_available(self._source_heap_bytes())
        return self._header
    def read_cell_segment_v3(self, cell_id, ordinal, *, meter):
        self.require_current(meter=meter)
        header = self._header if self._header is not None and self._header[0] == cell_id else self.read_cell_header_v3(cell_id, meter=meter)
        if type(ordinal) is not int or ordinal < 0:
            raise AuthorityUnavailable('actual nonnegative Source segment ordinal required')
        row = meter.read_fixed_row(self.source, 'segmented_cell_segments_v1', ('byte_offset','payload','payload_sha256'),
            'cell_id=? AND ordinal=?', (cell_id, ordinal))
        if row is None:
            if ordinal < header[5]:
                raise AuthorityUnavailable('actual frozen Source segment disappeared before EOF')
            return None
        if (ordinal >= header[5] or type(row[1]) is not bytes or not 1 <= len(row[1]) <= 16384
                or sha256(row[1]).hexdigest() != row[2]):
            raise AuthorityUnavailable('actual frozen Source segment hash or declared boundary differs')
        return tuple(row)
    def require_cell_eof_v3(self, cell_id, ordinal, *, meter):
        self.require_current(meter=meter)
        header = self._header if self._header is not None and self._header[0] == cell_id else self.read_cell_header_v3(cell_id, meter=meter)
        extra = meter.read_fixed_row(self.source, 'segmented_cell_segments_v1', ('ordinal',),
            'cell_id=? AND ordinal>=? ORDER BY ordinal', (cell_id, ordinal))
        if ordinal != header[5] or extra is not None:
            raise AuthorityUnavailable('actual frozen Source cell segment count or SQL EOF differs')
        return header
    def read_cell_fragment_v3(self, cell_id, *, start, length, meter):
        self.require_current(meter=meter)
        header = self._header if self._header is not None and self._header[0] == cell_id else self.read_cell_header_v3(cell_id, meter=meter)
        if type(start) is not int or type(length) is not int or start < 0 or not 0 <= length <= 16384 or start > header[4]:
            raise AuthorityUnavailable('actual bounded Source fragment coordinates required')
        if length == 0 or start == header[4]:
            return b'', header[4]
        # Stable ordinal PK probes find the variable-length containing segment;
        # no offset scan, payload JOIN or complete-cell concatenation is used.
        low, high, ordinal = 0, header[5] - 1, None
        while low <= high:
            middle = (low + high) // 2
            from .c09_selected_history_v3 import _read_one
            meta = _read_one(self.source, 'SELECT byte_offset,length(payload) FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal=?', (cell_id, middle), meter)
            if meta is None:
                raise AuthorityUnavailable('actual frozen Source ordinal metadata is missing')
            if start < meta[0]:high = middle - 1
            elif start >= meta[0] + meta[1]:low = middle + 1
            else:ordinal = middle;break
        if ordinal is None:
            raise AuthorityUnavailable('actual frozen Source byte position has no containing segment')
        result = bytearray();position = start
        while len(result) < length and position < header[4]:
            row = self.read_cell_segment_v3(cell_id, ordinal, meter=meter)
            if row is None or not row[0] <= position < row[0] + len(row[1]):
                raise AuthorityUnavailable('actual frozen Source byte offsets are discontinuous')
            take = min(length - len(result), len(row[1]) - (position - row[0]), header[4] - position)
            meter.require_available(len(result) + take)
            result.extend(row[1][position-row[0]:position-row[0]+take]);position += take;ordinal += 1
        return bytes(result), header[4]


_OWNER_METADATA=WeakSet()


class VerifiedSourceOwnerPreparedMetadataV3:
    def __init__(self,token,scope,prepared_digest,original):
        if token is not _ISSUER or scope not in _SCOPES:
            raise AuthorityUnavailable('actual frozen Source Owner metadata issuer required')
        self.scope,self.prepared_digest,self.original=scope,prepared_digest,original
        self.metadata,self.row=original['metadata'],original['row']
        _OWNER_METADATA.add(self);scope.arena.add(self)
    def _source_heap_bytes(self):
        from ..runtime_contracts import canonical_serialize
        return 2048+len(canonical_serialize(self.original).encode('utf8'))*8
    def require_current(self,*,meter):
        if self not in _OWNER_METADATA:raise AuthorityUnavailable('registered frozen Source Owner metadata required')
        self.scope.require_current(meter=meter)
        return self


_OWNER_STORAGE_METADATA=WeakSet()


class VerifiedSourceOwnerStorageMetadataV3:
    def __init__(self,token,scope,table,key,original):
        if token is not _ISSUER or scope not in _SCOPES:
            raise AuthorityUnavailable('actual frozen Source Owner storage metadata issuer required')
        self.scope,self.table,self.primary_key,self.original=scope,table,key,original
        self.row=original['row'];self.metadata=(original['prepared']['metadata']
            if table=='graph_owner_source_dispositions_v3' else original['metadata'])
        _OWNER_STORAGE_METADATA.add(self);scope.arena.add(self)
    def _source_heap_bytes(self):
        from ..runtime_contracts import canonical_serialize
        return 2048+len(canonical_serialize(self.original).encode('utf8'))*8
    def require_current(self,*,meter):
        if self not in _OWNER_STORAGE_METADATA:raise AuthorityUnavailable('registered Source Owner storage metadata required')
        self.scope.require_current(meter=meter)
        return self


def source_owner_storage_catalogue_v3():
    from ..runtime_storage_v3 import selected_runtime_catalogue_v3
    names=('graph_owner_source_command_seeds_v3','graph_owner_source_prepared_v3','graph_owner_source_dispositions_v3')
    for kind,name,ddl in selected_runtime_catalogue_v3('graph'):
        if name in names or any(name.startswith(table+'_') for table in names) or name=='graph_owner_source_prepared_immutable_content_v3':
            yield kind,name,ddl


def begin_source_physical_read_v3(session, pair, *, meter):
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    if type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2 or pair._producer.session is not session:
        raise AuthorityUnavailable('actual installed capture session and Source pair required')
    view = getattr(session._control.maintenance.control, '_selected_history_read_v3', None)
    previous = view.basis if type(view) is VerifiedSelectedHistoryReadV3 else None
    scope = SourcePhysicalReadScopeV3(_ISSUER, session, pair, previous)
    scope.require_current(meter=meter)
    scope.arena.add(scope)
    return scope


_CONTAINER_PROOFS=WeakSet()


class VerifiedSourcePhysicalContainerCensusV3:
    def __init__(self,token,reader):
        if token is not _ISSUER or reader not in _CONTAINER_READS or not reader.complete:
            raise AuthorityUnavailable('actual complete frozen physical Source census required')
        self.scope,self.original=reader.scope,reader.original
        self.physical_proof=reader.absence_proof if reader.runtime is None else reader.runtime.proof
        self.pair,self.source_original=reader.scope.pair,reader.scope.source_original
        self.scope_digest=reader.scope.session.scope.scope_digest
        identity=json.loads(self.source_original.source_identity)
        self.source_stamp=tuple(identity[name] for name in ('device','file_id','size','mtime_ns'))
        _CONTAINER_PROOFS.add(self)
    def require_source_identity_v3(self,scope):
        if (type(self) is not VerifiedSourcePhysicalContainerCensusV3 or self not in _CONTAINER_PROOFS
                or type(scope) is not SourcePhysicalReadScopeV3 or scope not in _SCOPES or scope is not self.scope
                or scope.pair is not self.pair or scope.source_original is not self.source_original
                or scope.session.scope.scope_digest!=self.scope_digest):
            raise AuthorityUnavailable('same actual issued Source census, scope and pair required')
        actor=scope.session._control.maintenance._maintenance_actor_v3
        if (actor is not scope.actor or actor.operation_id!=scope.operation_id
                or actor.owner_thread!=threading.get_ident() or self.pair._producer.session is not scope.session):
            raise AuthorityUnavailable('Source census identity is outside its actual actor and frozen pair')
        stat=Path(self.source_original.source_path).stat()
        if (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)!=self.source_stamp:
            raise AuthorityUnavailable('Source census identity four-stamp changed')
        return self
    def require_current(self,*,meter):
        self.require_source_identity_v3(self.scope)
        self.scope.require_current(meter=meter)
        self.physical_proof.require_current(meter=meter)
        original=self.scope.session._control.maintenance.control.read_build_original_v1(
            operation_id=self.scope.operation_id,kind='source_physical_retirement_v3_'+self.scope.role)
        if original!=self.original:raise AuthorityUnavailable('actual Source physical retirement census original changed')
        return self


_CONTAINER_READS=WeakSet()


class SourcePhysicalContainerCensusV3:
    def __init__(self,token,scope):
        if token is not _ISSUER or scope not in _SCOPES:
            raise AuthorityUnavailable('actual frozen Source physical census factory required')
        self.scope,self.runtime=scope,None
        self.complete=False;self.proof=self.original=None
        self.container_index=0;self.container_present=0;self.container_root=None
        self.initial_qualification=self.absence_proof=None
        _CONTAINER_READS.add(self);scope.arena.add(self)
        scope.session._control.maintenance.control.register_c09_retained_state_v3(self)
    def _source_heap_bytes(self):return 4096
    def _c09_retained_heap_bytes_v3(self):return self._source_heap_bytes()
    def advance_prospective_v3(self,meter):
        from copy import copy
        if type(self) is not SourcePhysicalContainerCensusV3 or self not in _CONTAINER_READS:
            raise AuthorityUnavailable('actual registered physical Source progress required')
        self.scope.require_current(meter=meter)
        if self.complete:self.proof.require_current(meter=meter);return self
        control=self.scope.session._control.maintenance.control
        control.require_c09_retained_arena_v3(meter=meter,additional_bytes=self._source_heap_bytes())
        result=copy(self)
        if self.runtime is not None:result.runtime=self.runtime.copy_for_c09_quantum_v3(meter=meter)
        _CONTAINER_READS.add(result);self.scope.arena.add(result)
        control.register_c09_retained_state_v3(result)
        result._advance_in_place_v3(meter)
        control.require_c09_retained_arena_v3(meter=meter)
        return result
    def _advance_in_place_v3(self,meter):
        from .c09_selected_runtime_v3 import SelectedRuntimePhysicalReadV3,_ISSUER as runtime_issuer
        from ..runtime_contracts import canonical_digest
        scope=self.scope;scope.require_current(meter=meter)
        if self.complete:self.proof.require_current(meter=meter);return True
        if self.container_index<4:
            from ..segmented_sql_cell_v1 import DDLS
            names=('segmented_storage_layout_v1','segmented_cells_v1','segmented_cell_segments_v1','segmented_cell_writes_v1')
            if self.container_root is None:
                if scope.previous_selected_basis is None:
                    self.initial_qualification=_initial_physical_source_qualification_v3(scope,meter)
                self.container_root=canonical_digest(('sylanne3.c09.source-container-schema-genesis.v3',
                    scope.session.scope.scope_digest,scope.role,scope.source_original.role_source_digest))
            name=names[self.container_index]
            with scope.read_database_v3(meter=meter) as db:
                row=meter.read_fixed_row(db,'sqlite_master',('type','sql'),'name=?',(name,))
            if row is not None:
                expected=DDLS[name].replace('IF NOT EXISTS ','',1).strip().rstrip(';')
                if row!=('table',expected):raise AuthorityUnavailable('Source physical container differs from its registered exact DDL/type')
                self.container_present+=1
            self.container_root=canonical_digest((self.container_root,self.container_index,name,row))
            self.container_index+=1;return False
        if self.container_present not in (0,4):
            raise AuthorityUnavailable('Source physical container schema is partial')
        if self.container_present==0:
            if scope.previous_selected_basis is not None:
                raise AuthorityUnavailable('selected segmented Source lost its actual physical container schema')
            if self.absence_proof is None:
                self.absence_proof=InitialPhysicalSourceContainerAbsenceV3(_ISSUER,self)
            physical=self.absence_proof.require_current(meter=meter)
        else:
            if self.runtime is None:
                initial=None
                if scope.previous_selected_basis is None:initial=_initial_owner_source_qualification_v3(scope,meter)
                self.runtime=SelectedRuntimePhysicalReadV3(runtime_issuer,scope.previous_selected_basis,scope.session.scope,
                    roles=(scope.role,),source_scope=scope,initial_qualification=initial)
                return False
            if not self.runtime.advance(meter):return False
            physical=self.runtime.proof
        scope.require_current(meter=meter)
        control=scope.session._control.maintenance.control
        details=dict(schema='sylanne3.c09.source-physical-container-census.v3',scope_digest=scope.session.scope.scope_digest,
            operation_id=scope.operation_id,role=scope.role,source_role_digest=scope.source_original.role_source_digest,
            source_identity=scope.source_original.source_identity,container_schema_root=self.container_root,
            container_schema_count=self.container_index,physical_record_counts=physical.counts,physical_root=physical.root,
            physical_eof_digest=physical.eof_digest,complete=True)
        if scope.previous_selected_basis is None:
            qualification=self.initial_qualification.require_current(meter=meter)
            details['initial_source_anchor']=dict(initial_manifest_digest=qualification.initial_manifest_digest,
                initial_pointer_version=qualification.initial_pointer,source_original_digest=qualification.source_original_digest,
                capture_scope_digest=scope.session.scope.scope_digest)
            details['physical_source_state']='no_containers' if self.container_present==0 else 'verified_containers'
        else:details['previous_selection_digest']=scope.previous_selected_basis.selection_digest
        self.original=control.record_build_original_v1(operation_id=scope.operation_id,
            kind='source_physical_retirement_v3_'+scope.role,details=details)
        self.complete=True;self.proof=VerifiedSourcePhysicalContainerCensusV3(_ISSUER,self)
        return True


def begin_source_physical_container_census_v3(scope,*,meter):
    if type(scope) is not SourcePhysicalReadScopeV3 or scope not in _SCOPES:
        raise AuthorityUnavailable('actual registered frozen Source physical scope required')
    scope.require_current(meter=meter)
    return SourcePhysicalContainerCensusV3(_ISSUER,scope)


_OWNER_ABSENCE_READS=WeakSet()
_OWNER_ABSENCE_PROOFS=WeakSet()
_OWNER_FAMILY_NAMES=('graph_owner_source_prepared_v3','graph_owner_source_command_seeds_v3','graph_owner_source_dispositions_v3')


def _require_frozen_owner_source_catalogue_v3(scope,meter):
    from dataclasses import asdict
    from .c09_role_capture_pair_v2 import _RoleSourceProducerV2,_SCHEMA_ORDERING
    from ..runtime_contracts import canonical_digest
    scope.require_current(meter=meter)
    if type(scope) is not SourcePhysicalReadScopeV3 or scope.role!='graph':
        raise AuthorityUnavailable('actual registered frozen Graph Source required for Owner family absence')
    producer=scope.pair._producer
    if type(producer) is not _RoleSourceProducerV2 or producer.pair is not scope.pair or producer.session is not scope.session:
        raise AuthorityUnavailable('actual registered Graph RoleSource producer required')
    control=scope.session._control.maintenance.control
    original=control.read_build_original_v1(operation_id=scope.operation_id,kind='capture_role_source_v2_graph')
    stage=control.read_build_original_v1(operation_id=scope.operation_id,kind='capture_role_stage_v2_graph')
    schema_root=canonical_digest(('sylanne3.c09.role-schema-complete.v2',_SCHEMA_ORDERING,producer.stat,
        producer.file_digest,producer.schema_count,producer.schema_root,producer.schema_last))
    if (original is None or original['details']!=asdict(scope.source_original)
            or stage is None or stage['original_digest']!=scope.source_original.source_stage_original_digest
            or stage['details']['scope_digest']!=scope.session.scope.scope_digest
            or producer.schema_cell is not None or producer.schema_count<1
            or schema_root!=scope.source_original.schema_root or producer.file_digest!=scope.source_original.source_file_sha256):
        raise AuthorityUnavailable('Owner family absence requires the actual signed full file/schema EOF Source')
    return original


class VerifiedSourceOwnerMetadataAbsenceV3:
    def __init__(self,token,reader):
        if token is not _ISSUER or reader not in _OWNER_ABSENCE_READS or not reader.complete:
            raise AuthorityUnavailable('actual complete frozen Owner three-family absence issuer required')
        self.scope,self.original=reader.scope,reader.original
        self.family_names=_OWNER_FAMILY_NAMES;self.record_count=0;self.root=reader.root
        self.eof_digest=reader.eof_digest
        _OWNER_ABSENCE_PROOFS.add(self);self.scope.arena.add(self)
        self.scope.session._control.maintenance.control.register_c09_retained_state_v3(self)
    def _source_heap_bytes(self):return 8192
    def _c09_retained_heap_bytes_v3(self):return self._source_heap_bytes()
    def require_current(self,*,meter):
        if self not in _OWNER_ABSENCE_PROOFS:raise AuthorityUnavailable('issued Owner metadata absence proof required')
        _require_frozen_owner_source_catalogue_v3(self.scope,meter)
        actual=self.scope.session._control.maintenance.control.read_build_original_v1(
            operation_id=self.scope.operation_id,kind='source_owner_metadata_absence_v3_graph')
        if actual!=self.original:raise AuthorityUnavailable('actual signed Owner metadata absence original changed')
        return self


class SourceOwnerMetadataAbsenceReadV3:
    def __init__(self,token,scope,source_original):
        if token is not _ISSUER or scope not in _SCOPES:
            raise AuthorityUnavailable('actual frozen Source Owner absence factory required')
        from ..runtime_contracts import canonical_digest
        self.scope,self.source_original_digest=scope,source_original['original_digest']
        self.index=0;self.complete=False;self.proof=self.original=self.eof_digest=None
        self.root=canonical_digest(('sylanne3.c09.owner-source-family-absence-genesis.v3',
            scope.session.scope.scope_digest,scope.source_original.role_source_digest,self.source_original_digest))
        _OWNER_ABSENCE_READS.add(self);scope.arena.add(self)
        scope.session._control.maintenance.control.register_c09_retained_state_v3(self)
    def _source_heap_bytes(self):return 8192
    def _c09_retained_heap_bytes_v3(self):return self._source_heap_bytes()
    def advance(self,meter):
        from copy import copy
        from ..runtime_contracts import canonical_digest
        if self not in _OWNER_ABSENCE_READS or self.complete:
            raise AuthorityUnavailable('actual incomplete Owner metadata absence progress required')
        source=_require_frozen_owner_source_catalogue_v3(self.scope,meter)
        if source['original_digest']!=self.source_original_digest:
            raise AuthorityUnavailable('Owner absence progress changed its signed frozen Source anchor')
        control=self.scope.session._control.maintenance.control
        control.require_c09_retained_arena_v3(meter=meter,additional_bytes=self._source_heap_bytes())
        result=copy(self);_OWNER_ABSENCE_READS.add(result);self.scope.arena.add(result)
        control.register_c09_retained_state_v3(result)
        if self.index<len(_OWNER_FAMILY_NAMES):
            name=_OWNER_FAMILY_NAMES[self.index]
            with self.scope.read_database_v3(meter=meter) as db:
                row=meter.read_fixed_row(db,'sqlite_master',('type','sql'),'name=?',(name,))
            if row is not None:
                raise AuthorityUnavailable('Owner zero-family schema proof found an actual object; present/partial families require their registered positive Source reader')
            result.root=canonical_digest((self.root,self.index,name,'schema_object_absent'))
            result.index+=1
        else:
            result.eof_digest=canonical_digest(('sylanne3.c09.owner-source-family-absence-eof.v3',
                self.scope.session.scope.scope_digest,self.source_original_digest,_OWNER_FAMILY_NAMES,self.root,0))
            details=dict(schema='sylanne3.c09.owner-source-metadata-absence.v3',scope_digest=self.scope.session.scope.scope_digest,
                operation_id=self.scope.operation_id,role='graph',source_role_digest=self.scope.source_original.role_source_digest,
                source_identity=self.scope.source_original.source_identity,source_file_sha256=self.scope.source_original.source_file_sha256,
                source_schema_root=self.scope.source_original.schema_root,source_original_digest=self.source_original_digest,
                family_names=_OWNER_FAMILY_NAMES,schema_object_count=self.index,record_count=0,root=self.root,
                eof_digest=result.eof_digest,complete=True)
            result.original=control.record_build_original_v1(operation_id=self.scope.operation_id,
                kind='source_owner_metadata_absence_v3_graph',details=details)
            result.complete=True;result.proof=VerifiedSourceOwnerMetadataAbsenceV3(_ISSUER,result)
        control.require_c09_retained_arena_v3(meter=meter)
        return result


def begin_source_owner_metadata_absence_v3(scope,*,meter):
    if type(scope) is not SourcePhysicalReadScopeV3 or scope not in _SCOPES:
        raise AuthorityUnavailable('actual registered frozen Source scope required')
    original=_require_frozen_owner_source_catalogue_v3(scope,meter)
    return SourceOwnerMetadataAbsenceReadV3(_ISSUER,scope,original)


_OUTPUT_READS=WeakSet()
_OUTPUT_PROOFS=WeakSet()


class VerifiedPreparedOwnerOutputSourceV3:
    """Source-only Complete/Prefix/Retired; this object grants no publication."""
    def __init__(self,token,reader):
        if token is not _ISSUER or reader not in _OUTPUT_READS or not reader.complete:
            raise AuthorityUnavailable('actual complete prepared output Source issuer required')
        self.scope,self.prepared_digest,self.cell_name=reader.scope,reader.prepared_digest,reader.cell_name
        self.kind,self.metadata,self.prepared,self.disposition=reader.kind,reader.metadata,reader.prepared,reader.disposition
        self.factual_source_state=reader.factual_source_state
        self.original_deadline_utc=reader.metadata['original_deadline_utc']
        self.not_started_original=reader.not_started_original
        self.scope_original=reader.scope_original;self.previous_mapping_original_ref=reader.mapping_reference
        self.scope_original_digest=reader.scope_original['original_digest']
        self.source_descriptor_original=reader.scope_original['details']['source_descriptor']
        self._scope_original_heap_bytes=reader._scope_original_heap_bytes
        self._mapping_heap_bytes=0 if reader.mapped_output is None else len(reader.mapped_output.mapping_row[11])*12
        self.previous_not_started_original=reader.previous_not_started_original
        self.previous_mapping_output=reader.mapped_output
        self.previous_retirement_original=reader.previous_retirement_original
        self.original_owner_cell_id,self.current_cell_id=reader.original_owner_cell_id,reader.current_cell_id
        self.current_header9,self.current_cursor=reader.header9,reader.cursor
        self.expected_sha256,self.expected_total_bytes=reader.expected['payload_sha256'],reader.expected['total_bytes']
        self.observed_bytes,self.observed_segments,self.observed_sha256,self.observed_root=(
            (None,None,None,None) if reader.factual_source_state=='not_started' else
            (reader.offset,reader.ordinal,reader.digest.hexdigest(),reader.root))
        self.source_role_digest=reader.scope.source_original.role_source_digest
        self.source_identity=reader.scope.source_original.source_identity
        from ..runtime_contracts import canonical_digest
        self.source_original_digest=canonical_digest(dict(schema='sylanne3.c09.prepared-output-source.v3',
            scope_digest=reader.scope.session.scope.scope_digest,source_role_digest=self.source_role_digest,factual_source_state=self.factual_source_state,
            prepared_digest=self.prepared_digest,cell_name=self.cell_name,kind=self.kind,original_owner_cell_id=self.original_owner_cell_id,
            current_cell_id=self.current_cell_id,header9=self.current_header9,cursor=self.current_cursor,
            observed_bytes=self.observed_bytes,observed_segments=self.observed_segments,observed_sha256=self.observed_sha256,
            observed_root=self.observed_root,expected_sha256=self.expected_sha256,expected_total_bytes=self.expected_total_bytes))
        _OUTPUT_PROOFS.add(self);reader.scope.arena.add(self)
        reader.scope.session._control.maintenance.control.register_c09_retained_state_v3(self)
    def _source_heap_bytes(self):
        return 8192+len(json.dumps(self.metadata,ensure_ascii=True).encode())*8+self._scope_original_heap_bytes+self._mapping_heap_bytes
    def _c09_retained_heap_bytes_v3(self):return self._source_heap_bytes()
    def require_current(self,*,meter):
        if self not in _OUTPUT_PROOFS:raise AuthorityUnavailable('registered prepared output Source qualification required')
        self.scope.require_current(meter=meter)
        from ..runtime_contracts import canonical_digest
        original=self.scope.session._control.maintenance.control.read_build_original_v1(operation_id=self.scope.operation_id,
            kind='prepared_output_source_v3_'+canonical_digest((self.prepared_digest,self.cell_name)))
        if original!=self.scope_original:
            raise AuthorityUnavailable('prepared output Source protected scope original changed')
        return self
    def read_previous_retirement_original_v3(self,*,meter):
        from ..runtime.c09_selected_owner_source_outputs_v3 import VerifiedSelectedOwnerSourceRetiredOutputV3
        from ..runtime.c09_owner_source_output_mappings_v3 import VerifiedSelectedOwnerOutputMappingRowV3
        from ..runtime_contracts import canonical_digest
        self.require_current(meter=meter)
        output=self.previous_mapping_output
        if (self.kind!='Retired' or type(output) is not VerifiedSelectedOwnerSourceRetiredOutputV3
                or type(output._proof) is not VerifiedSelectedOwnerOutputMappingRowV3
                or output._proof.basis is not self.scope.previous_selected_basis
                or output.prepared_digest!=self.prepared_digest or output.cell_name!=self.cell_name
                or self.previous_mapping_original_ref is None):
            raise AuthorityUnavailable('actual prior retained retired mapping is required for this Source fact')
        with self.scope.read_database_v3(meter=meter) as db:
            output.require_database_current_v3(db=db,meter=meter)
            original=output._proof.original['retirement_original']
            signed=self.scope_original['details']
            if (output.mapping_row[12]!=self.previous_mapping_original_ref['original_digest']
                    or original!=self.previous_retirement_original
                    or original!=signed['previous_retirement_original']
                    or canonical_digest(original)!=signed['previous_retirement_original_digest']):
                raise AuthorityUnavailable('actual prior retirement original differs from the signed current Source provenance')
        return original

    def read_segment_v3(self,ordinal,*,meter):
        self.require_current(meter=meter)
        if self.kind=='Retired' or self.factual_source_state=='not_started' or type(ordinal) is not int or not 0<=ordinal<self.observed_segments:
            raise AuthorityUnavailable('prepared output Source has no qualified segment at this ordinal')
        with self.scope.read_database_v3(meter=meter):
            return _prepared_output_segment_v3(self.scope,self.current_cell_id,ordinal,meter)


def _prepared_output_segment_v3(scope,cell,ordinal,meter):
    from .c09_selected_history_v3 import _read_one
    scope.require_current(meter=meter)
    if not scope.source.in_transaction:
        raise AuthorityUnavailable('actual prepared-output Source short readonly transaction required')
    row=_read_one(scope.source,'SELECT length(payload) FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal=?',(cell,ordinal),meter)
    if row is None or not 0<row[0]<=16384:
        raise AuthorityUnavailable('prepared output Source segment length or presence differs')
    meter.require_available(32768)
    segment=meter.read_fixed_row(scope.source,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
        'cell_id=? AND ordinal=?',(cell,ordinal))
    if type(segment[1]) is not bytes or sha256(segment[1]).hexdigest()!=segment[2]:
        raise AuthorityUnavailable('prepared output Source segment SHA differs')
    return tuple(segment)


class PreparedOwnerOutputSourceReadV3:
    """Prospective copy per actual reserved quantum; no shared mutable digest."""
    def __init__(self,token,scope,prepared_digest,cell_name):
        if token is not _ISSUER or scope not in _SCOPES:
            raise AuthorityUnavailable('actual frozen Source prepared-output factory required')
        self.scope,self.prepared_digest,self.cell_name=scope,prepared_digest,cell_name
        self.phase='prepared';self.prepared=self.metadata=self.disposition=self.expected=None
        self.original_owner_cell_id=self.current_cell_id=self.header9=self.cursor=None
        self.kind=None;self.factual_source_state='material';self.not_started_original=None
        self.mapped_output=self.mapping_reference=self.previous_not_started_original=self.scope_original=None
        self._scope_original_heap_bytes=0
        self.previous_retirement_original=None
        self.absence_schema_index=0;self.absence_schema_root=None;self.required_source_state=None
        self.ordinal=self.offset=0;self.digest=sha256();self.root=None
        self.last_segment=None;self.complete=False;self.proof=None
        _OUTPUT_READS.add(self);scope.arena.add(self)
        scope.session._control.maintenance.control.register_c09_retained_state_v3(self)
    def _c09_retained_heap_bytes_v3(self):return self._source_heap_bytes()
    def _source_heap_bytes(self):
        amount=8192+ (0 if self.last_segment is None else len(self.last_segment[1])*2)
        if self.metadata is not None:amount+=len(json.dumps(self.metadata,ensure_ascii=True).encode())*8
        if self.mapped_output is not None:amount+=len(self.mapped_output.mapping_row[11])*12
        amount+=self._scope_original_heap_bytes
        return amount
    def advance(self,meter):
        from copy import copy
        from .c09_selected_history_v3 import _read_one
        from ..runtime_contracts import canonical_digest,canonical_serialize
        if self not in _OUTPUT_READS:raise AuthorityUnavailable('registered prepared-output Source progress required')
        self.scope.require_current(meter=meter)
        if self.complete:raise AuthorityUnavailable('prepared-output Source is already complete')
        control=self.scope.session._control.maintenance.control
        control.require_c09_retained_arena_v3(meter=meter,additional_bytes=self._source_heap_bytes())
        result=copy(self);result.digest=self.digest.copy();result.last_segment=None
        _OUTPUT_READS.add(result);self.scope.arena.add(result);control.register_c09_retained_state_v3(result)
        with self.scope.read_database_v3(meter=meter) as db:
            if result.phase=='prepared':
                result.prepared=self.scope.qualify_owner_source_storage_row_v3('graph_owner_source_prepared_v3',(self.prepared_digest,),meter=meter)
                result.metadata=result.prepared.metadata;result.expected=result.metadata['expected_outputs'][self.cell_name]
                result.original_owner_cell_id=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=result.metadata['storage_instance'],
                    prepared_digest=self.prepared_digest,name=self.cell_name,sha256=result.expected['payload_sha256']))
                layout=meter.read_fixed_row(db,'segmented_storage_layout_v1',('storage_instance_id',),'singleton=1',())
                if layout is None:
                    raise AuthorityUnavailable('prepared output Source has no actual physical layout')
                if layout[0]!=result.metadata['storage_instance']:
                    if self.scope.previous_selected_basis is None:
                        raise AuthorityUnavailable('cross-instance prepared Source requires its actual previous selected qualification')
                    result.phase='mapped'
                else:
                    result.current_cell_id=result.original_owner_cell_id
                    result.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',result.current_cell_id))
                    result.phase='disposition'
            elif result.phase=='mapped':
                from ..runtime.c09_selected_owner_source_outputs_v3 import (
                    resolve_selected_owner_source_output_v3,VerifiedSelectedOwnerSourceCompleteOutputV3,
                    VerifiedSelectedOwnerSourcePrefixOutputV3,VerifiedSelectedOwnerSourceRetiredOutputV3)
                from ..runtime.c09_owner_source_output_mappings_v3 import VerifiedSelectedOwnerOutputMappingRowV3
                basis=self.scope.previous_selected_basis
                output=resolve_selected_owner_source_output_v3(db,basis=basis,
                    prepared_digest=self.prepared_digest,cell_name=self.cell_name,meter=meter)
                if type(output) not in (VerifiedSelectedOwnerSourceCompleteOutputV3,
                        VerifiedSelectedOwnerSourcePrefixOutputV3,VerifiedSelectedOwnerSourceRetiredOutputV3):
                    raise AuthorityUnavailable('cross-instance Source has no exact issued prepared/name mapping outcome')
                mapping=output._proof
                if (type(mapping) is not VerifiedSelectedOwnerOutputMappingRowV3 or mapping.basis is not basis
                        or output.prepared_digest!=self.prepared_digest or output.cell_name!=self.cell_name
                        or output.metadata!=result.metadata or output.original_owner_cell_id!=result.original_owner_cell_id
                        or mapping.row!=output.mapping_row):
                    raise AuthorityUnavailable('prepared output Source mapping crossed its actual previous cut/metadata/initial identity')
                output.require_database_current_v3(db=db,meter=meter)
                result.mapped_output=output
                result.mapping_reference=dict(selection_digest=basis.selection_digest,capture_scope_digest=mapping.row[0],
                    prepared_digest=mapping.row[1],cell_name=mapping.row[2],original_digest=mapping.row[12],
                    origin_stream_id=mapping.row[13],origin_record_ordinal=mapping.row[14])
                previous_source=mapping.original['source_cell_descriptor']
                if previous_source['schema']=='sylanne3.c09.prepared-output-source-not-started.v3':
                    result.previous_not_started_original=previous_source
                if type(output) is VerifiedSelectedOwnerSourceRetiredOutputV3:
                    if self.required_source_state=='not_started':
                        raise AuthorityUnavailable('a mapped retired output is not a not-started Source fact')
                    result.previous_retirement_original=mapping.original['retirement_original']
                    result.kind='Retired';result.phase='seal_original'
                else:
                    result.current_cell_id=output.current_cell_id
                    result.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',result.current_cell_id))
                    result.phase='mapped_header'
            elif result.phase=='mapped_header':
                from ..runtime.c09_selected_owner_source_outputs_v3 import (
                    VerifiedSelectedOwnerSourceCompleteOutputV3,VerifiedSelectedOwnerSourcePrefixOutputV3)
                output=result.mapped_output;output.require_database_current_v3(db=db,meter=meter)
                basis=self.scope.previous_selected_basis
                if self.required_source_state=='not_started':
                    raise AuthorityUnavailable('mapped current material cannot claim Source header/cursor absence')
                if type(output) is VerifiedSelectedOwnerSourceCompleteOutputV3:
                    result.header9=meter.read_fixed_row(db,'segmented_cells_v1',_HEADER,'cell_id=?',(result.current_cell_id,))
                    if (result.header9!=output.current_header9 or result.header9[0]!=result.current_cell_id
                            or result.header9[2]!=result.metadata['source_ref']
                            or result.header9[3]!=basis.prepared['operation_id']
                            or result.header9[8]!=basis.prepared['capture_scope_digest']
                            or (result.header9[4],result.header9[6])!=(result.expected['total_bytes'],result.expected['payload_sha256'])):
                        raise AuthorityUnavailable('mapped Source complete physical header differs from its actual selected capture seal')
                    result.header9=tuple(result.header9);result.kind='Complete'
                elif type(output) is VerifiedSelectedOwnerSourcePrefixOutputV3:
                    result.cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',
                        ('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id','erasure_owner_ref','phase',
                         'next_ordinal','next_byte_offset','prefix_root','prefix_sha256','source_cursor_json','expected_total_bytes',
                         'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256','cursor_revision'),
                        'cell_id=?',(result.current_cell_id,))
                    if (result.cursor!=output.current_cursor or result.cursor[0]!=result.current_cell_id
                            or result.cursor[1]!=basis.prepared['capture_scope_digest']
                            or result.cursor[4]!=basis.prepared['operation_id']
                            or result.cursor[5]!=result.metadata['source_ref'] or result.cursor[6]!='staging'
                            or result.cursor[12]!=result.expected['total_bytes']
                            or not 0<=result.cursor[8]<=result.expected['total_bytes']
                            or _read_one(db,'SELECT cell_id FROM segmented_cells_v1 WHERE cell_id=?',
                                (result.current_cell_id,),meter) is not None):
                        raise AuthorityUnavailable('mapped Source prefix is not its actual finite selected cursor without a complete header')
                    result.cursor=tuple(result.cursor);result.kind='Prefix'
                else:raise AuthorityUnavailable('mapped Source body outcome changed')
                result.phase='segments'
            elif result.phase=='disposition':
                if result.prepared.original['phase']=='aborted':
                    result.disposition=self.scope.qualify_owner_source_storage_row_v3('graph_owner_source_dispositions_v3',(self.prepared_digest,),meter=meter)
                    result.kind='Retired';result.phase='seal_original'
                else:result.phase='header'
            elif result.phase=='header':
                result.header9=meter.read_fixed_row(db,'segmented_cells_v1',_HEADER,'cell_id=?',(result.current_cell_id,))
                result.cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',
                    ('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id','erasure_owner_ref','phase',
                    'next_ordinal','next_byte_offset','prefix_root','prefix_sha256','source_cursor_json','expected_total_bytes',
                    'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256','cursor_revision'),
                    'cell_id=?',(result.current_cell_id,))
                if result.required_source_state=='not_started' and (result.cursor is not None or result.header9 is not None):
                    raise AuthorityUnavailable('explicit not-started Source qualification found actual material')
                if result.cursor is None:
                    if result.header9 is not None or result.prepared.original['phase']!='prepared' or result.prepared.original['actual_committed']:
                        raise AuthorityUnavailable('missing prepared output cursor cannot qualify a completed or terminal Source')
                    result.kind='Prefix';result.factual_source_state='not_started'
                    result.absence_schema_root=canonical_digest(('sylanne3.c09.prepared-output-absence-schema.v3',
                        self.scope.source_original.role_source_digest,self.prepared_digest,self.cell_name))
                    result.phase='not_started_schema'
                    return result
                locator=json.loads(result.cursor[2])
                if (canonical_serialize(locator)!=result.cursor[2] or locator!=dict(schema='d06.owner-source-cell-locator.v3',
                        prepared_digest=self.prepared_digest,name=self.cell_name,source_ref=result.metadata['source_ref'])
                        or result.cursor[:2]!=(result.current_cell_id,self.prepared_digest)
                        or result.cursor[3]!='canonical-json.ascii.v1' or result.cursor[4]!=result.metadata['operation_id']
                        or result.cursor[5]!=result.metadata['source_ref'] or result.cursor[12]!=result.expected['total_bytes']):
                    raise AuthorityUnavailable('prepared-output Source cursor locator/producer/Owner/expected bytes differ')
                if result.header9 is None:
                    if result.cursor[6]!='staging' or result.prepared.original['actual_committed']:
                        raise AuthorityUnavailable('only a real uncommitted prepared cursor may qualify a Source prefix')
                    result.kind='Prefix'
                else:
                    from ..runtime.owner_material_source_storage_v3 import read_selected_owner_source_cell_v3
                    if self.scope.previous_selected_basis is None:
                        producer=_initial_owner_cell_values_read_v3(_initial_owner_source_qualification_v3(self.scope,meter),
                            result.current_cell_id,tuple(result.header9[1:]),meter)
                    else:
                        producer=read_selected_owner_source_cell_v3(db,basis=self.scope.previous_selected_basis,
                            cell_id=result.current_cell_id,header=tuple(result.header9[1:]),meter=meter)
                    if (producer is None or producer['prepared_digest']!=self.prepared_digest or producer['cell_name']!=self.cell_name
                            or result.header9[6]!=result.expected['payload_sha256'] or result.header9[4]!=result.expected['total_bytes']):
                        raise AuthorityUnavailable('prepared-output Source complete header has no actual same-name producer seal')
                    result.header9=tuple(result.header9);result.kind='Complete'
                result.phase='segments'
            elif result.phase=='not_started_schema':
                from ..segmented_sql_cell_v1 import DDLS,TRIGGERS
                descriptors=tuple(('table',name,ddl) for name,ddl in DDLS.items())+tuple(('trigger',name,ddl) for name,ddl in TRIGGERS.items())
                if result.absence_schema_index<len(descriptors):
                    kind,name,ddl=descriptors[result.absence_schema_index]
                    actual=_read_one(db,'SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name),meter)
                    if actual!=(ddl,):raise AuthorityUnavailable('not-started Source requires actual complete registered cell schema and PK')
                    result.absence_schema_root=canonical_digest((result.absence_schema_root,kind,name,ddl))
                    result.absence_schema_index+=1
                else:result.phase='not_started_eof'
            elif result.phase=='not_started_eof':
                if (_read_one(db,'SELECT cell_id FROM segmented_cells_v1 WHERE cell_id=?',(result.current_cell_id,),meter) is not None
                        or _read_one(db,'SELECT cell_id FROM segmented_cell_writes_v1 WHERE cell_id=?',(result.current_cell_id,),meter) is not None
                        or _read_one(db,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? ORDER BY ordinal LIMIT 1',
                            (result.current_cell_id,),meter) is not None):
                    raise AuthorityUnavailable('not-started Source contains actual cell/cursor/segment material')
                if result.prepared.original['actual_committed'] or result.prepared.original['phase']!='prepared':
                    raise AuthorityUnavailable('actual W01 or terminal Source cannot qualify as not started')
                ns=result.metadata['namespace'];operation=result.metadata['operation_id']
                if (_read_one(db,'SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
                        (ns['bot_id'],ns['persona_id'],operation),meter) is not None
                        or _read_one(db,'SELECT disposition_digest FROM graph_owner_source_dispositions_v3 WHERE prepared_digest=?',
                            (self.prepared_digest,),meter) is not None):
                    raise AuthorityUnavailable('not-started Source has an actual W01 or terminal disposition')
                details=dict(schema='sylanne3.c09.prepared-output-source-not-started.v3',scope_digest=self.scope.session.scope.scope_digest,
                    source_role_digest=self.scope.source_original.role_source_digest,source_identity=self.scope.source_original.source_identity,
                    prepared_digest=self.prepared_digest,prepared_metadata_digest=canonical_digest(result.metadata),cell_name=self.cell_name,
                    original_storage_instance=result.metadata['storage_instance'],original_owner_cell_id=result.original_owner_cell_id,
                    factual_source_state='not_started',expected_payload_sha256=result.expected['payload_sha256'],expected_total_bytes=result.expected['total_bytes'],
                    schema_eof_digest=result.absence_schema_root,absence_eof_digest=canonical_digest((result.current_cell_id,'header_absent','cursor_absent','segments_eof')),
                    no_w01_terminal_digest=canonical_digest((ns,operation,'bundle_absent','terminal_absent')),
                    original_deadline_utc=result.metadata['original_deadline_utc'])
                control=self.scope.session._control.maintenance.control
                result.not_started_original=control.record_build_original_v1(operation_id=self.scope.operation_id,
                    kind='prepared_output_not_started_v3_'+canonical_digest((self.prepared_digest,self.cell_name)),details=details)
                result.phase='seal_original'
            elif result.phase=='segments':
                limit=result.header9[5] if result.kind=='Complete' else result.cursor[7]
                if result.ordinal<limit:
                    segment=_prepared_output_segment_v3(self.scope,result.current_cell_id,result.ordinal,meter)
                    if segment[0]!=result.offset:raise AuthorityUnavailable('prepared-output Source segment byte offset differs')
                    result.root=canonical_digest(('sylanne3.segmented-cell-link.v1',result.root,result.current_cell_id,
                        result.ordinal,result.offset,len(segment[1]),segment[2]))
                    result.digest.update(segment[1]);result.last_segment=segment
                    result.ordinal+=1;result.offset+=len(segment[1])
                else:result.phase='eof'
            elif result.phase=='eof':
                if _read_one(db,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? ORDER BY ordinal LIMIT 1',
                        (result.current_cell_id,result.ordinal),meter) is not None:
                    raise AuthorityUnavailable('prepared-output Source includes extra segment material beyond its actual boundary')
                expected=(result.header9[5],result.header9[4],result.header9[7],result.header9[6]) if result.kind=='Complete' else tuple(result.cursor[7:11])
                if (result.ordinal,result.offset,result.root,result.digest.hexdigest())!=expected:
                    raise AuthorityUnavailable('prepared-output Source complete seal or actual prefix full EOF differs')
                if result.kind=='Prefix' and result.offset>result.expected['total_bytes']:
                    raise AuthorityUnavailable('prepared-output Source prefix exceeds its original expected byte count')
                result.phase='seal_original'
            elif result.phase=='seal_original':
                if result.mapped_output is not None:
                    result.mapped_output.require_database_current_v3(db=db,meter=meter)
                descriptor=dict(schema='sylanne3.c09.prepared-output-source.v3',
                    scope_digest=self.scope.session.scope.scope_digest,source_role_digest=self.scope.source_original.role_source_digest,
                    prepared_digest=self.prepared_digest,cell_name=self.cell_name,kind=result.kind,
                    original_owner_cell_id=result.original_owner_cell_id,current_cell_id=result.current_cell_id,
                    header9=result.header9,cursor=result.cursor,observed_bytes=result.offset,observed_segments=result.ordinal,
                    observed_sha256=result.digest.hexdigest(),observed_root=result.root,
                    expected_sha256=result.expected['payload_sha256'],expected_total_bytes=result.expected['total_bytes'])
                if result.factual_source_state=='not_started':
                    descriptor=result.not_started_original['details']
                details=dict(schema='sylanne3.c09.prepared-output-source-original.v3',operation_id=self.scope.operation_id,
                    scope_digest=self.scope.session.scope.scope_digest,source_role_digest=self.scope.source_original.role_source_digest,
                    source_identity=self.scope.source_original.source_identity,prepared_digest=self.prepared_digest,cell_name=self.cell_name,
                    prepared_metadata_digest=canonical_digest(result.metadata),source_descriptor=descriptor,
                    previous_mapping_original_ref=result.mapping_reference,previous_not_started_original=result.previous_not_started_original,
                    previous_retirement_original=result.previous_retirement_original,
                    previous_retirement_original_digest=(None if result.previous_retirement_original is None else
                        canonical_digest(result.previous_retirement_original)))
                control=self.scope.session._control.maintenance.control
                result.scope_original=control.record_build_original_v1(operation_id=self.scope.operation_id,
                    kind='prepared_output_source_v3_'+canonical_digest((self.prepared_digest,self.cell_name)),details=details)
                result._scope_original_heap_bytes=len(json.dumps(result.scope_original,ensure_ascii=True).encode())*8
                result.complete=True
            else:raise AuthorityUnavailable('unknown prepared-output Source phase')
        result.scope.require_current(meter=meter)
        if result.complete:result.proof=VerifiedPreparedOwnerOutputSourceV3(_ISSUER,result)
        result.scope.session._control.maintenance.control.require_c09_retained_arena_v3(meter=meter)
        return result



class PreGraphCoreSourcePhysicalReadScopeV3(SourcePhysicalReadScopeV3):
    """Distinct real preGraph Core Source; never a final authority role pair."""
    def __init__(self,token,session,verified_pre_source,previous):
        if token is not _ISSUER:raise AuthorityUnavailable('actual preGraph physical Source issuer required')
        self.session,self.pre_source,self.role=session,verified_pre_source,'core'
        self.source=None;self.source_original=verified_pre_source.source_original
        self.actor=session._control.maintenance._maintenance_actor_v3
        self.previous_selected_basis=previous;self.operation_id=session.scope.operation_id
        self.arena=session._source_parser_arena_v3;self._header=None
        _SCOPES.add(self);self.arena.add(self)
    def require_current(self,*,meter):
        from .c09_maintenance_actor_v3 import InstalledC09MaintenanceActorV3
        if self not in _SCOPES or require_c09_reserved_meter_v3(meter.budget) is not meter:
            raise AuthorityUnavailable('actual reserved preGraph physical Source quantum required')
        m=self.session._control.maintenance
        if (type(self.actor) is not InstalledC09MaintenanceActorV3 or self.actor is not m._maintenance_actor_v3
                or self.actor.owner_thread!=threading.get_ident() or self.actor.operation_id!=self.operation_id):
            raise AuthorityUnavailable('actual preGraph Source actor and owner thread required')
        self.session._control._registered();self.session.require_current()
        self.pre_source.require_current(session=self.session,graph_pair=self.pre_source.graph_pair,meter=meter)
        identity=json.loads(self.source_original.source_identity);stat=Path(self.source_original.source_path).stat()
        if (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)!=tuple(identity[name] for name in ('device','file_id','size','mtime_ns')):
            raise AuthorityUnavailable('actual preGraph Core physical Source four-stamp changed')
        if self.previous_selected_basis is not None:
            self.previous_selected_basis.require_current(meter=meter)
            if self.previous_selected_basis.member('core')['resolved_path']!=self.source_original.source_path:
                raise AuthorityUnavailable('actual preGraph Core Source differs from the prior selected Core member')
        return self
    @contextmanager
    def read_database_v3(self,*,meter):
        self.require_current(meter=meter)
        with self.pre_source.read_database_v3(meter=meter) as db:
            self.source=db
            try:yield db
            finally:self.source=None
        self.require_current(meter=meter)
    def _physical(self,method,*args,meter,**kwargs):
        if self.source is not None:
            return method(self,*args,meter=meter,**kwargs)
        with self.read_database_v3(meter=meter):
            return method(self,*args,meter=meter,**kwargs)
    def read_cell_header_v3(self,cell_id,*,meter):
        return self._physical(SourcePhysicalReadScopeV3.read_cell_header_v3,cell_id,meter=meter)
    def read_cell_segment_v3(self,cell_id,ordinal,*,meter):
        return self._physical(SourcePhysicalReadScopeV3.read_cell_segment_v3,cell_id,ordinal,meter=meter)
    def require_cell_eof_v3(self,cell_id,ordinal,*,meter):
        return self._physical(SourcePhysicalReadScopeV3.require_cell_eof_v3,cell_id,ordinal,meter=meter)
    def read_cell_fragment_v3(self,cell_id,*,start,length,meter):
        return self._physical(SourcePhysicalReadScopeV3.read_cell_fragment_v3,cell_id,start=start,length=length,meter=meter)


def begin_pre_graph_core_source_physical_read_v3(session,verified_pre_source,*,meter):
    from .c09_pre_graph_core_dependency_source_v3 import VerifiedPreGraphCoreDependencySourceV3
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    if (type(session) is not C09PagedCaptureSessionV2 or type(verified_pre_source) is not VerifiedPreGraphCoreDependencySourceV3
            or verified_pre_source.session is not session or verified_pre_source.source_original.role!='core'):
        raise AuthorityUnavailable('exact actual preGraph Core dependency Source issuer required')
    verified_pre_source.require_current(session=session,graph_pair=verified_pre_source.graph_pair,meter=meter)
    selected=getattr(session._control.maintenance.control,'_selected_history_read_v3',None)
    previous=selected.basis if type(selected) is VerifiedSelectedHistoryReadV3 else None
    result=PreGraphCoreSourcePhysicalReadScopeV3(_ISSUER,session,verified_pre_source,previous)
    return result.require_current(meter=meter)



def qualify_owner_prepared_output_not_started_v3(actual_prepared_source,cell_name,actual_source_scope,meter):
    if (type(actual_prepared_source) is not VerifiedSourceOwnerStorageMetadataV3 or actual_prepared_source not in _OWNER_STORAGE_METADATA
            or actual_prepared_source.scope is not actual_source_scope or actual_prepared_source.table!='graph_owner_source_prepared_v3'):
        raise AuthorityUnavailable('actual qualified prepared Source and same physical scope required for not-started facts')
    actual_prepared_source.require_current(meter=meter)
    if actual_prepared_source.original['actual_committed'] or actual_prepared_source.original['phase']!='prepared':
        raise AuthorityUnavailable('terminal or W01 adopted prepared Source is not a not-started obligation')
    result=actual_source_scope.begin_owner_source_output_v3(actual_prepared_source.primary_key[0],cell_name,meter=meter)
    result.required_source_state='not_started'
    return result


_INITIAL_PHYSICAL_SOURCE=WeakSet()
_INITIAL_ABSENCE_PROOFS=WeakSet()


class InitialPhysicalSourceReadQualificationV3:
    def __init__(self,token,scope,current,source_digest):
        if token is not _ISSUER or scope not in _SCOPES:
            raise AuthorityUnavailable('actual initial physical Source issuer required')
        self.scope,self.role,self.source_original=scope,scope.role,scope.source_original
        self.initial_manifest_digest,self.initial_pointer=current.manifest_digest,current.pointer_version
        self.source_original_digest=source_digest
        _INITIAL_PHYSICAL_SOURCE.add(self);scope.arena.add(self)
    def _source_heap_bytes(self):return 4096
    def require_current(self,*,meter):
        if self not in _INITIAL_PHYSICAL_SOURCE:raise AuthorityUnavailable('issued initial physical Source qualification required')
        current,intent=_require_initial_physical_source_pin_v3(self.scope,meter)
        if (self.role!=self.scope.role or self.source_original is not self.scope.source_original
                or current.manifest_digest!=self.initial_manifest_digest or current.pointer_version!=self.initial_pointer):
            raise AuthorityUnavailable('actual initial physical Source selection or role changed')
        return self


class InitialPhysicalSourceContainerAbsenceV3:
    def __init__(self,token,reader):
        if (token is not _ISSUER or reader not in _CONTAINER_READS or reader.container_index!=4
                or reader.container_present!=0 or reader.initial_qualification not in _INITIAL_PHYSICAL_SOURCE):
            raise AuthorityUnavailable('actual initial Source full four-table schema absence required')
        self.qualification,self.scope=reader.initial_qualification,reader.scope
        self.counts=(0,)*11;self.root=reader.container_root
        from ..runtime_contracts import canonical_digest
        self.eof_digest=canonical_digest(('sylanne3.c09.initial-source-no-containers-eof.v3',
            self.qualification.initial_manifest_digest,self.qualification.initial_pointer,self.qualification.source_original_digest,
            self.scope.session.scope.scope_digest,self.scope.role,self.scope.source_original.schema_root,self.root,self.counts))
        _INITIAL_ABSENCE_PROOFS.add(self)
    def require_current(self,*,meter):
        if self not in _INITIAL_ABSENCE_PROOFS:raise AuthorityUnavailable('issued initial physical Source absence proof required')
        self.qualification.require_current(meter=meter)
        return self


def _initial_physical_source_qualification_v3(scope,meter):
    if scope.initial_physical_qualification is not None:return scope.initial_physical_qualification.require_current(meter=meter)
    current,intent=_require_initial_physical_source_pin_v3(scope,meter)
    control=scope.session._control.maintenance.control
    original=control.read_build_original_v1(operation_id=scope.operation_id,kind='capture_role_source_v2_'+scope.role)
    result=InitialPhysicalSourceReadQualificationV3(_ISSUER,scope,current,original['original_digest'])
    scope.initial_physical_qualification=result
    return result.require_current(meter=meter)


_INITIAL_OWNER_SOURCE=WeakSet()
_PREPARED_COLUMNS=('prepared_digest','bot','persona','operation_id','attempt_id','request_claim_digest','metadata_json',
    'input_sha256','input_bytes','original_digest','original_bytes','source_sha256','source_bytes','phase')
_ATTEMPT_COLUMNS=('request_digest','attempt_id','graph_revision','graph_epoch','permit_json','receipt_json')


class InitialOwnerSourceReadQualificationV3:
    """Initial frozen Graph read qualification; never a selected/open capability."""
    def __init__(self,token,scope,manifest_digest,pointer,source_digest):
        if token is not _ISSUER or scope not in _SCOPES:raise AuthorityUnavailable('actual initial Source issuer required')
        self.scope,self.control=scope,scope.session._control.maintenance.control
        self.namespace=scope.session.scope.authority_namespace
        self.authority_id,self.installation_id=self.control.authority_id,self.control.installation_id
        self.path,self.source_original=scope.source_original.source_path,scope.source_original
        self.initial_manifest_digest,self.initial_pointer,self.source_original_digest=manifest_digest,pointer,source_digest
        self.physical_qualification=scope.initial_physical_qualification
        if (self.physical_qualification not in _INITIAL_PHYSICAL_SOURCE or self.physical_qualification.role!='graph'
                or self.physical_qualification.scope is not scope):
            raise AuthorityUnavailable('actual Graph initial physical qualification required before Owner qualification')
        _INITIAL_OWNER_SOURCE.add(self);scope.arena.add(self)
    def _source_heap_bytes(self):return 4096
    def require_current(self,*,meter):
        if self not in _INITIAL_OWNER_SOURCE:raise AuthorityUnavailable('registered initial Source qualification required')
        current,intent=_require_initial_owner_source_pin_v3(self.scope,meter)
        if current.manifest_digest!=self.initial_manifest_digest or current.pointer_version!=self.initial_pointer:
            raise AuthorityUnavailable('actual initial Source selection changed')
        return self


def _require_initial_physical_source_pin_v3(scope,meter):
    from dataclasses import asdict
    from .c09_role_capture_pair_v2 import _RoleSourceProducerV2,_SCHEMA_ORDERING
    from ..runtime_contracts import canonical_digest
    scope.require_current(meter=meter)
    if type(scope) is not SourcePhysicalReadScopeV3:
        raise AuthorityUnavailable('actual registered initial physical Source pair required')
    current,intent=scope.session._control._current(scope.operation_id)
    manifest=current.manifest;capture=scope.session.scope
    if (current.stage!='INTENT' or manifest['generation']!=0 or manifest['prior_manifest_digest'] is not None
            or current.manifest_digest!=capture.old_manifest_digest or current.pointer_version!=capture.expected_pointer_version
            or intent['details']['old_manifest_digest']!=capture.old_manifest_digest
            or intent['details']['expected_pointer_version']!=capture.expected_pointer_version):
        raise AuthorityUnavailable('initial Source does not match the actual installed first selection and active INTENT')
    members=tuple(member for member in manifest['members'] if member['role']==scope.role)
    if len(members)!=1:raise AuthorityUnavailable('actual initial Graph member must be unique')
    member=members[0];identity=json.loads(scope.source_original.source_identity)
    if (member['resolved_path']!=scope.source_original.source_path
            or (member['device'],member['file_id'])!=(identity['device'],identity['file_id'])):
        raise AuthorityUnavailable('initial Graph Source is outside the actual installed member')
    control=scope.session._control.maintenance.control;control.verify_member_v1(member,prepared=False)
    producer=scope.pair._producer
    if type(producer) is not _RoleSourceProducerV2 or producer.pair is not scope.pair or producer.session is not scope.session:
        raise AuthorityUnavailable('actual completed initial Graph Source producer required')
    original=control.read_build_original_v1(operation_id=scope.operation_id,kind='capture_role_source_v2_'+scope.role)
    stage=control.read_build_original_v1(operation_id=scope.operation_id,kind='capture_role_stage_v2_'+scope.role)
    schema_root=canonical_digest(('sylanne3.c09.role-schema-complete.v2',_SCHEMA_ORDERING,producer.stat,
        producer.file_digest,producer.schema_count,producer.schema_root,producer.schema_last))
    if (original is None or original['details']!=asdict(scope.source_original)
            or stage is None or stage['original_digest']!=scope.source_original.source_stage_original_digest
            or stage['details']['current_member']!=member or producer.schema_cell is not None
            or producer.schema_count<1 or schema_root!=scope.source_original.schema_root
            or producer.file_digest!=scope.source_original.source_file_sha256):
        raise AuthorityUnavailable('initial Graph Source lacks its signed full file/schema EOF and actual close stage')
    return current,intent


def _require_initial_owner_source_pin_v3(scope,meter):
    if scope.role!='graph':raise AuthorityUnavailable('initial Owner Source qualification is Graph-only')
    _initial_physical_source_qualification_v3(scope,meter)
    return _require_initial_physical_source_pin_v3(scope,meter)


def _initial_owner_source_qualification_v3(scope,meter):
    qualification=scope.initial_owner_qualification
    if qualification is not None:return qualification.require_current(meter=meter)
    current,intent=_require_initial_owner_source_pin_v3(scope,meter)
    # The signed whole schema EOF above binds every actual dependency object.
    # Fixed registered storage objects additionally retain their exact SQL.
    from .c09_selected_history_v3 import _read_one
    for kind,name,ddl in source_owner_storage_catalogue_v3():
        if _read_one(scope.source,'SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name),meter)!=(ddl,):
            raise AuthorityUnavailable('initial Owner metadata schema/PK/index is outside the registered catalogue')
    original=scope.session._control.maintenance.control.read_build_original_v1(operation_id=scope.operation_id,kind='capture_role_source_v2_graph')
    result=InitialOwnerSourceReadQualificationV3(_ISSUER,scope,current.manifest_digest,current.pointer_version,original['original_digest'])
    scope.initial_owner_qualification=result
    return result.require_current(meter=meter)


_INITIAL_CURSOR_READS=WeakSet()


class InitialOwnerSourceCursorReadV3:
    def __init__(self,token,qualification,cursor,prepared):
        if token is not _ISSUER or qualification not in _INITIAL_OWNER_SOURCE or prepared not in _OWNER_STORAGE_METADATA:
            raise AuthorityUnavailable('actual initial Source cursor and qualified prepared metadata required')
        self.qualification,self.scope=qualification,qualification.scope
        self.cursor,self.prepared,self.prepared_proof=tuple(cursor),tuple(prepared.original['row']),prepared
        self.cell_id=cursor[0];self.ordinal=self.offset=0;self.hash=sha256()
        from ..runtime_contracts import canonical_digest
        self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id));self.complete=False
        _INITIAL_CURSOR_READS.add(self);self.scope.arena.add(self)
    def _source_heap_bytes(self):return 8192+self.prepared_proof._source_heap_bytes()
    def copy_for_c09_quantum_v3(self,*,meter):
        from copy import copy
        if self not in _INITIAL_CURSOR_READS:raise AuthorityUnavailable('issued initial Source cursor required')
        self.qualification.require_current(meter=meter)
        result=copy(self);result.hash=self.hash.copy()
        _INITIAL_CURSOR_READS.add(result);self.scope.arena.add(result)
        return result
    def advance(self,meter):
        from .c09_selected_history_v3 import _read_one
        from ..runtime_contracts import canonical_digest
        result=self.copy_for_c09_quantum_v3(meter=meter)
        self.prepared_proof.require_current(meter=meter)
        with self.scope.read_database_v3(meter=meter) as db:
            current=meter.read_fixed_row(db,'segmented_cell_writes_v1',
                ('cell_id','origin_scope_digest','logical_locator_json','codec_id','producer_operation_id','erasure_owner_ref','phase',
                 'next_ordinal','next_byte_offset','prefix_root','prefix_sha256','source_cursor_json','expected_total_bytes',
                 'verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256','cursor_revision'),
                'cell_id=?',(self.cell_id,))
            if current!=self.cursor:raise AuthorityUnavailable('actual initial Source cursor changed during prefix census')
            if self.ordinal<self.cursor[7]:
                segment=_prepared_output_segment_v3(self.scope,self.cell_id,self.ordinal,meter)
                if segment[0]!=self.offset:raise AuthorityUnavailable('actual initial cursor segment offset differs')
                result.hash.update(segment[1]);result.root=canonical_digest(('sylanne3.segmented-cell-link.v1',
                    self.root,self.cell_id,self.ordinal,self.offset,len(segment[1]),segment[2]))
                result.ordinal+=1;result.offset+=len(segment[1])
            else:
                extra=_read_one(db,'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
                    (self.cell_id,self.ordinal),meter)
                if extra is not None or (self.ordinal,self.offset,self.root,self.hash.hexdigest())!=self.cursor[7:11]:
                    raise AuthorityUnavailable('actual initial cursor prefix SHA/root/count/extra EOF differs')
                result.complete=True
        return result


def begin_initial_owner_source_cursor_read_v3(qualification,cursor,*,meter):
    from ..runtime_contracts import canonical_digest,canonical_serialize
    if type(qualification) is not InitialOwnerSourceReadQualificationV3 or qualification not in _INITIAL_OWNER_SOURCE:
        raise AuthorityUnavailable('actual initial Graph Source qualification required')
    qualification.require_current(meter=meter);scope=qualification.scope
    prepared=scope.qualify_owner_source_storage_row_v3('graph_owner_source_prepared_v3',(cursor[1],),meter=meter)
    metadata=prepared.metadata;locator=json.loads(cursor[2]);name=locator.get('name')
    if name not in ('input','source','original','stage_request','http_request','bundle'):
        raise AuthorityUnavailable('initial Source cursor name has no registered Owner output')
    expected=metadata['expected_outputs'][name]
    cell=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=metadata['storage_instance'],
        prepared_digest=cursor[1],name=name,sha256=expected['payload_sha256']))
    layout=meter.read_fixed_row(scope.source,'segmented_storage_layout_v1',('storage_instance_id',),'singleton=1',())
    header=meter.read_fixed_row(scope.source,'segmented_cells_v1',_HEADER,'cell_id=?',(cursor[0],))
    if (header is None and (cursor[6]!='staging' or prepared.original['actual_committed'])
            or header is not None and (cursor[3:7]!=(header[1],header[3],header[2],'sealed')
                or cursor[7:11]!=(header[5],header[4],header[7],header[6])
                or cursor[12:17]!=(header[4],header[5],header[4],header[7],header[6]))):
        raise AuthorityUnavailable('initial cursor visibility/verification differs from its actual complete header')
    if (canonical_serialize(locator)!=cursor[2] or locator!=dict(schema='d06.owner-source-cell-locator.v3',
            prepared_digest=cursor[1],name=name,source_ref=metadata['source_ref']) or cursor[0]!=cell
            or layout!=(metadata['storage_instance'],) or cursor[3:6]!=('canonical-json.ascii.v1',metadata['operation_id'],metadata['source_ref'])
            or cursor[6] not in ('staging','sealed') or cursor[12]!=expected['total_bytes']
            or cursor[7]<0 or not 0<=cursor[8]<=expected['total_bytes']):
        raise AuthorityUnavailable('initial Source cursor differs from its real prepared Owner locator/instance')
    return InitialOwnerSourceCursorReadV3(_ISSUER,qualification,cursor,prepared)


def _initial_owner_seed_values_read_v3(qualification,namespace,operation,meter):
    from ..runtime.owner_material_source_storage_v3 import _qualify_owner_source_command_seed_values_v3
    from ..runtime_contracts import namespace_ref
    qualification.require_current(meter=meter)
    if namespace_ref(namespace)!=qualification.namespace:raise AuthorityUnavailable('initial Owner seed namespace differs from actual Source')
    db=qualification.scope.source
    row=meter.read_fixed_row(db,'graph_owner_source_command_seeds_v3',
        ('bot','persona','operation_id','attempt_id','request_digest','seed_digest','payload_json'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation))
    attempt=meter.read_fixed_row(db,'graph_owner_domain_attempts_v3',_ATTEMPT_COLUMNS[:4],
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation))
    return _qualify_owner_source_command_seed_values_v3(row,attempt,authority_id=qualification.authority_id,
        installation_id=qualification.installation_id,namespace=namespace,operation_id=operation)


def _initial_owner_prepared_values_read_v3(qualification,prepared_digest,meter):
    from ..runtime.owner_material_source_storage_v3 import _qualify_owner_source_prepared_values_v3
    from ..runtime_contracts import NamespaceId
    qualification.require_current(meter=meter);db=qualification.scope.source
    row=meter.read_fixed_row(db,'graph_owner_source_prepared_v3',_PREPARED_COLUMNS,'prepared_digest=?',(prepared_digest,))
    if row is None:return None
    namespace=NamespaceId(row[1],row[2]);seed=_initial_owner_seed_values_read_v3(qualification,namespace,row[3],meter)
    attempt=meter.read_fixed_row(db,'graph_owner_domain_attempts_v3',_ATTEMPT_COLUMNS,
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,row[3]))
    bundle=meter.read_fixed_row(db,'graph_bundle_operations',('digest',),'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,row[3]))
    result=_qualify_owner_source_prepared_values_v3(row,seed,attempt,bundle,authority_id=qualification.authority_id,
        installation_id=qualification.installation_id,authority_namespace=qualification.namespace,prepared_digest=prepared_digest)
    qualification.require_current(meter=meter);return result


def _initial_owner_storage_values_read_v3(qualification,table,key,meter):
    from ..runtime.owner_material_source_storage_v3 import _qualify_owner_source_disposition_values_v3
    from ..runtime_contracts import NamespaceId
    if table=='graph_owner_source_command_seeds_v3':
        if len(key)!=3:raise AuthorityUnavailable('actual initial seed PK required')
        return _initial_owner_seed_values_read_v3(qualification,NamespaceId(key[0],key[1]),key[2],meter)
    if table not in ('graph_owner_source_prepared_v3','graph_owner_source_dispositions_v3') or len(key)!=1:
        raise AuthorityUnavailable('registered initial Owner metadata family and PK required')
    prepared=_initial_owner_prepared_values_read_v3(qualification,key[0],meter)
    if table=='graph_owner_source_prepared_v3':return prepared
    if prepared is None:raise AuthorityUnavailable('initial Source terminal row lacks actual prepared evidence')
    db=qualification.scope.source
    row=meter.read_fixed_row(db,table,('prepared_digest','operation_id','attempt_id','phase','receipt_digest','disposition_digest','cell_ids_json'),
        'prepared_digest=?',key)
    receipt=None
    if row is not None and row[3]=='committed':
        receipt=meter.read_fixed_row(db,'graph_domain_production_originals_v3',('receipt_digest',),
            'bot=? AND persona=? AND operation_id=?',(*prepared['namespace'].as_tuple,row[1]))
    return _qualify_owner_source_disposition_values_v3(row,prepared,receipt,prepared_digest=key[0])


def _initial_owner_cell_values_read_v3(qualification,cell_id,header,meter):
    from ..runtime.owner_material_source_storage_v3 import _qualify_owner_source_cell_values_v3
    from ..runtime_contracts import NamespaceId
    qualification.require_current(meter=meter);db=qualification.scope.source
    row=meter.read_fixed_row(db,'graph_owner_source_prepared_v3',_PREPARED_COLUMNS,'prepared_digest=?',(header[7],))
    if row is None:return None
    namespace=NamespaceId(row[1],row[2]);metadata=json.loads(row[6])
    cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',
        ('origin_scope_digest','logical_locator_json','producer_operation_id','erasure_owner_ref','phase','next_ordinal','next_byte_offset',
        'prefix_root','prefix_sha256','expected_total_bytes','verify_next_ordinal','verify_next_byte_offset','verify_prefix_root','verify_prefix_sha256'),
        'cell_id=?',(cell_id,))
    attempt=meter.read_fixed_row(db,'graph_owner_domain_attempts_v3',_ATTEMPT_COLUMNS,
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,row[3]))
    bundle=meter.read_fixed_row(db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq','receipt_json'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,row[3]))
    original=history=event=None
    if bundle is not None:
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        history_shape=read_c09_table_shape_v2(db,'graph_history',meter=meter)
        if 'value_cell_id' not in history_shape.columns:
            raise AuthorityUnavailable('unregistered initial committed OwnerV3/legacy Graph mixed shape; actual V1 rebuilt Source retains its registered path')
        original=meter.read_fixed_row(db,'graph_domain_production_originals_v3',
            ('domain','operation_kind','original_digest','original_payload_cell_id','prepared_digest','bundle_digest'),
            'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,row[3]))
        history=meter.read_fixed_row(db,'graph_history',('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),
            'token=? AND revision=1',(metadata['source_ref'],))
        event=meter.read_fixed_row(db,'graph_events',('digest','reads','epoch_reads'),
            'bot=? AND persona=? AND session=? AND event_id=?',(*namespace.as_tuple,bundle[1],row[3]))
    result=_qualify_owner_source_cell_values_v3(row,cursor,attempt,bundle,original,history,event,cell_id=cell_id,header=header,
        authority_id=qualification.authority_id,installation_id=qualification.installation_id,authority_namespace=qualification.namespace)
    qualification.require_current(meter=meter);return result
