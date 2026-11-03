"""Two actual signed Owner installation columns, streamed without historical plan claims."""
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict
from threading import get_ident
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,OWNER_GRANT_TYPE
from ..runtime_contracts import canonical_digest,canonical_serialize
from .d01_ordinary_origin_stream_v3 import OrdinaryOriginMetadataStreamV3
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2

SEMANTIC_SCHEMA_V4 = 'd04.owner-semantic-installation-original.v4'
SEMANTIC_SIGN_KIND_V4 = 'd11.owner-selected-d04-semantic-installation.v4'
CLOCK_SCHEMA_V4 = 'd11.owner-role-clock-original.v4'
CLOCK_SIGN_KIND_V4 = 'd11.owner-role-clock-installation.v4'
_TABLE_KINDS = {
    'graph_d04_semantic_installations_v3': {
        'd04.owner-semantic-installation-original.v3':'d11.owner-selected-d04-semantic-installation.v3',
        SEMANTIC_SCHEMA_V4:SEMANTIC_SIGN_KIND_V4},
    'runtime_d11_owner_role_clock_originals_v1': {
        'd11.owner-role-clock-original.v1':'d11.owner-role-clock-installation.v1',
        CLOCK_SCHEMA_V4:CLOCK_SIGN_KIND_V4}}
_COMMON_FIELDS = frozenset({'schema','namespace','operation_id','revision','installation_ref',
    'manifest_sha256','owner','owner_guard','member_bindings','graph_revision','graph_epoch'})
_SEMANTIC_FIELDS = frozenset({'state','profile_json','profile_digest','bound_asset','block_shares'})
_CLOCK_FIELDS = frozenset({'mapping','clock_operation_id','clock_operation_digest'})
_ISSUER = object()
_COLUMNS = WeakKeyDictionary()
_SCOPE = ContextVar('role_control_signed_metadata_v4',default=None)
_NUMERIC_SCOPE = ContextVar('numeric_owner_role_originals_v4',default=None)


class _RoleSignedStreamV4(OrdinaryOriginMetadataStreamV3):
    def __init__(self, reserve):
        super().__init__(profile='adoption',ensure_ascii=True,reserve=reserve)
    def _retains(self,path):
        if not path:return True
        if path[0]=='role_rows':
            if len(path)<3:return True
            if path[2]!=2:return True
            rows=self.metadata.get('role_rows',())
            token=rows[path[1]][0] if len(rows)>path[1] and rows[path[1]] else None
            if token is None:raise ValueError('role original row value precedes its key')
            if AtomKey.from_token(token).type_name not in {'d01.persona_plan.v1','d01.persona_activation.v1',OWNER_GRANT_TYPE}:
                raise ValueError('legacy role row is outside actual three control families')
            if AtomKey.from_token(token).type_name=='d01.persona_plan.v1':
                return len(path)==3 or path[3]in{'namespace','plan_id','version'}
            return True
        if len(path)>=4 and path[:2]==('role_control_rows','rows')and path[3]==4:
            rows=self.metadata['role_control_rows']['rows'];token=rows[path[2]][0]
            kind=AtomKey.from_token(token).type_name
            if kind not in {'d01.persona_plan.v1','d01.persona_activation.v1',OWNER_GRANT_TYPE}:
                raise ValueError('selected role row is outside actual three control families')
            if kind=='d01.persona_plan.v1':return len(path)==4 or path[4]in{'namespace','plan_id','version'}
        return path[0]in(_COMMON_FIELDS|_SEMANTIC_FIELDS|_CLOCK_FIELDS|{'role_control_rows'})
    def _commits(self,path):
        return not path or len(path)==3 and path[0]=='role_rows' and path[2]==2
    def _append_decoded_codepoint(self,codepoint):
        # No protocol discovery is needed in a signed historical plan.
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        return C09CanonicalJSONStreamV2._append_decoded_codepoint(self,codepoint)


class _RoleOriginalMetadataV4(Mapping):
    def __init__(self,column):
        self._column=column
    def __getitem__(self,key):
        if key=='role_rows':raise AuthorityUnavailable('historical role Body is not a metadata projection')
        from .dispatch_current_inventory_v3 import _detach_value_v3
        return _detach_value_v3(dict(self._column.frozen.items)[key])
    def __iter__(self):return (k for k,_value in self._column.frozen.items if k!='role_rows')
    def __len__(self):return len(self._column.frozen.items)-int(any(k=='role_rows'for k,_value in self._column.frozen.items))


@contextmanager
def role_original_metadata_scope_v4(reader,scope,current):
    from ..host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
    graph=reader.graph
    if (type(reader)is not InstalledD04SemanticMappingReaderV3
            or getattr(graph,'_GraphCoordinator__d04_semantic_mapping_reader',None)is not reader
            or scope.namespace!=current.guard.namespace or current.guard.pending_revoke_operation_id is not None
            or scope.permit.authority_id!=current.guard.authority_id):
        raise AuthorityUnavailable('actual installed semantic reader/Owner fence required')
    port=graph._GraphCoordinator__content_fence_v2
    if reader._fence.get() is None:
        if graph._GraphCoordinator__store._db.in_transaction:
            raise AuthorityUnavailable('accepting-original observation must precede SQL')
        if port.get_current_background_owner_authority_for_fence_v1(namespace=scope.namespace,
                authority_namespace=scope.authority_namespace,permit=scope.permit)!=(current,scope.permit):
            raise AuthorityUnavailable('accepting-original actual Owner observation changed')
    elif reader._fence.get()[:2]!=(scope,current.guard) or reader._location.get()!=current:
        raise AuthorityUnavailable('role metadata scope differs from actual installed fence')
    from ..runtime_storage_v3 import runtime_storage_v3,_operation
    operation=_operation(runtime_storage_v3(graph._GraphCoordinator__store._db))
    token=_SCOPE.set((reader,scope,current,get_ident(),operation,operation.selection_digest,operation.deadline_utc))
    try:yield
    finally:_SCOPE.reset(token)


def _actual_column_owner_v4(owner,db):
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    if type(owner)is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(owner,db=db)
        if owner.kind!='offline' or not owner.role_clocks:
            raise AuthorityUnavailable('actual staged role-clock metadata Work required')
        return owner.graph._GraphCoordinator__d11_issuer._signer,owner.namespace
    numeric=_NUMERIC_SCOPE.get()
    if numeric is not None and owner is numeric:
        from ..authority_service.d04_numeric_owner_selectors_metadata_v4 import require_actual_numeric_owner_selectors_metadata_reader_v4
        require_actual_numeric_owner_selectors_metadata_reader_v4(numeric,db=db)
        return numeric.service.budget_issuer._signer,numeric.namespace
    state=_SCOPE.get()
    if state is None or state is not owner:
        raise AuthorityUnavailable('actual installed accepting-original metadata scope required')
    reader,scope,current,thread,operation,selection,deadline=state
    from ..runtime_storage_v3 import runtime_storage_v3,_operation
    if (_operation(runtime_storage_v3(db))is not operation or operation.closed
            or operation.selection_digest!=selection or operation.deadline_utc!=deadline):
        raise AuthorityUnavailable('role-original metadata left its actual operation/selection/deadline')
    if (thread!=get_ident() or not db.in_transaction or not reader.graph._GraphCoordinator__store._lock._is_owned()
            or reader.graph._GraphCoordinator__store._db is not db
            or getattr(reader.graph,'_GraphCoordinator__d04_semantic_mapping_reader',None)is not reader
            or scope.namespace!=current.guard.namespace):
        raise AuthorityUnavailable('installed role-original metadata identity changed')
    metadata,epoch=reader.graph._v2_graph_stamp(scope.namespace)
    if (metadata.graph_revision,epoch)!=(scope.graph_revision,scope.graph_epoch):
        raise AuthorityUnavailable('role-original metadata Graph stamp differs from its actual fence')
    return reader.graph._GraphCoordinator__d11_issuer._signer,scope.namespace


class _RoleControlSignedColumnV4:
    def __init__(self,issuer,owner,*,db,table,key,signer,signature):
        if issuer is not _ISSUER:raise TypeError('private role-original column issuer required')
        actual_signer,namespace=_actual_column_owner_v4(owner,db)
        if (table not in _TABLE_KINDS or tuple(key[:2])!=namespace.as_tuple
                or type(key[2])is not int or key[2]<1
                or signer is not actual_signer):
            raise AuthorityUnavailable('role-original fixed table/key/signer differs')
        self.owner,self.db,self.table,self.key=owner,db,table,tuple(key)
        self.column='original_json';self.key_columns=('bot','persona','revision')
        self.signer,self.signature=signer,signature
        self.complete=False;self.offset=0;self.total=None;self.fragment=b'';self.position=0
        self.reserved=0;self.parser=_RoleSignedStreamV4(self.reserve)
        self.nodes={};self.value=None;self.scalar=bytearray();self.text_parts=[];self.text_chars=[];self.frozen=None
        from .domain_background_read_v3 import BackgroundReadWorkV3
        if type(owner)is BackgroundReadWorkV3:owner.columns.add(self)
        self.verifiers={};self.signature_bytes=0;self.sha256=None
        _COLUMNS[self]=(owner,db,table,self.key,signer,signature)
        for kind in _TABLE_KINDS[table].values():
            self.verifiers[kind]=signer.begin_original_stream_verification_v3(kind,self)
    def reserve(self,extra=0):
        from .source_correction_read_v3 import _heap
        amount=_heap((self.parser.nodes,self.parser.metadata,self.parser.fields,
            self.parser.scalar,self.parser.active_hashes,self.parser.commitments,self.fragment))+extra+131072
        from .domain_background_read_v3 import BackgroundReadWorkV3
        if type(self.owner)is BackgroundReadWorkV3:
            self.nodes,self.value,self.scalar=self.parser.nodes,self.parser.metadata,self.parser.scalar
            self.owner.reserve_heap_v3(extra=amount)
        else:
            from ..runtime_storage_v3 import runtime_storage_v3,_operation
            operation=_operation(runtime_storage_v3(self.db))
            if amount>self.reserved:operation.retain(amount-self.reserved);self.reserved=amount
    def require_v4(self):
        if _COLUMNS.get(self)!=(self.owner,self.db,self.table,self.key,self.signer,self.signature):
            raise AuthorityUnavailable('role-original private column identity changed')
        _actual_column_owner_v4(self.owner,self.db)
        return self
    def release_v4(self):
        _COLUMNS.pop(self,None)
        self.original=self.parser=self.frozen=None;self.fragment=b''
        self.nodes.clear();self.value=None;self.scalar.clear();self.text_parts.clear();self.text_chars.clear()
        self.verifiers.clear()
    def advance(self,meter):
        self.require_v4()
        if self.complete:return True
        if self.position<len(self.fragment):
            end=min(self.position+1024,len(self.fragment));part=self.fragment[self.position:end]
            self.parser.advance_fragment_v3(part,meter)
            for state in self.verifiers.values():state.update(part)
            self.signature_bytes+=len(part);self.position=end;return False
        if self.total is None or self.offset<self.total:
            raw,total,kind=read_legacy_sql_cell_fragment_v2(self.db,table=self.table,column='original_json',
                where='bot=? AND persona=? AND revision=?',parameters=self.key,start=self.offset,
                length=16384 if self.total is None else min(16384,self.total-self.offset),meter=meter)
            if self.total is None:self.total=total
            if total!=self.total or kind!='text':raise AuthorityUnavailable('signed role-original column changed')
            self.offset+=len(raw);self.fragment,self.position=raw,0
            if raw:return False
        self.metadata,self.commitments,_ranges,fields,parsed=self.parser.finish_metadata_v3()
        schema=self.metadata.get('schema');kind=_TABLE_KINDS[self.table].get(schema)
        if kind is None:raise AuthorityUnavailable('unknown role installation original schema')
        role_field='role_control_rows' if schema in(SEMANTIC_SCHEMA_V4,CLOCK_SCHEMA_V4)else'role_rows'
        wanted=_COMMON_FIELDS|(_SEMANTIC_FIELDS if self.table=='graph_d04_semantic_installations_v3'else _CLOCK_FIELDS)|{role_field}
        if fields.get(())!=wanted or parsed.byte_count!=self.total:
            raise AuthorityUnavailable('role installation original fields/canonical EOF differ')
        if role_field=='role_rows':
            rows=self.metadata['role_rows']
            if len(rows)!=3 or any(len(row)!=4 or row[3]is not True for row in rows):
                raise AuthorityUnavailable('legacy role original requires three valid complete commitments')
            if {AtomKey.from_token(row[0]).type_name for row in rows}!={'d01.persona_activation.v1','d01.persona_plan.v1',OWNER_GRANT_TYPE}:
                raise AuthorityUnavailable('legacy role rows do not cover the actual three control families')
            self.legacy_rows=tuple((row[0],row[1],True,self.commitments[('role_rows',i,2)],row[2])for i,row in enumerate(rows))
        else:
            self.legacy_rows=None
            from .role_control_rows_metadata_v4 import _decode_control_rows_v4
            _decode_control_rows_v4(self.metadata['role_control_rows'])
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        self.frozen=_freeze_value_v3(self.metadata)
        self.sha256,self.byte_count=parsed.sha256,parsed.byte_count
        self.signature_kind=kind;self.complete=True
        self.signer.finish_original_stream_verification_v3(kind,self.signature,self,self.verifiers[kind])
        self.original=_RoleOriginalMetadataV4(self)
        self.fragment=b'';return True


def require_role_control_signature_column_v4(column,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(column)is not _RoleControlSignedColumnV4:raise AuthorityUnavailable('actual role-original column required')
    column.require_v4()
    if signer is not column.signer or kind not in _TABLE_KINDS[column.table].values():
        raise AuthorityUnavailable('role-original signer/domain differs')
    if complete and (not column.complete or column.signature_kind!=kind or signature!=column.signature
            or verifier is not column.verifiers[kind] or column.signature_bytes!=column.byte_count):
        raise AuthorityUnavailable('role-original signature requires exact full raw EOF')
    return column


def create_background_role_original_column_v4(owner,table,key,signature):
    signer,_namespace=_actual_column_owner_v4(owner,owner.db)
    return _RoleControlSignedColumnV4(_ISSUER,owner,db=owner.db,table=table,key=key,
        signer=signer,signature=signature)


def read_role_original_metadata_v4(db,issuer,table,namespace,*,operation_id=None,reader=None):
    if table not in _TABLE_KINDS:raise AuthorityUnavailable('unknown role-original table')
    from .domain_background_read_v3 import _active_v3,background_point_v3
    owner=_active_v3(db)
    numeric=_NUMERIC_SCOPE.get()
    if numeric is not None:
        if owner is not None:raise AuthorityUnavailable('numeric metadata cannot borrow Background Work')
        _actual_column_owner_v4(numeric,db)
    if owner is None and numeric is None and _SCOPE.get() is None:
        if reader is None:raise AuthorityUnavailable('actual installed role-original reader is absent')
        scope,_guard,_profile=reader._current(db,namespace)
        with role_original_metadata_scope_v4(reader,scope,reader._location.get()):
            return read_role_original_metadata_v4(db,issuer,table,namespace,operation_id=operation_id,reader=reader)
    where='bot=? AND persona=?';args=namespace.as_tuple
    if operation_id is not None:where+=' AND operation_id=?';args=(*args,operation_id)
    else:where+=' ORDER BY revision DESC LIMIT 1'
    row=db.execute('SELECT revision,operation_id,original_digest,signature FROM '+table+' WHERE '+where,args).fetchone()
    if row is None:return None
    revision,operation,digest,signature=row
    if numeric is not None:
        column=numeric.require_role_original_column_v4(table=table,revision=revision,signature=signature)
        if type(column)is not _RoleControlSignedColumnV4 or column.owner is not numeric or not column.complete:
            raise AuthorityUnavailable('numeric role-original metadata task has no actual complete column')
    elif owner is not None:
        selected=background_point_v3(db,table=table,columns=('original_json',),
            key_columns=('bot','persona','revision'),key=(*namespace.as_tuple,revision),legacy_reader=lambda:None)
        column=selected[0]
        if type(column)is not _RoleControlSignedColumnV4:raise AuthorityUnavailable('role-original metadata point was not prepared')
    else:
        column=_RoleControlSignedColumnV4(_ISSUER,_SCOPE.get(),db=db,table=table,
            key=(*namespace.as_tuple,revision),signer=issuer._signer,signature=signature)
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        while not column.complete:
            with runtime_storage_quantum_v3(db)as meter:column.advance(meter)
    column.require_v4()
    original=column.original
    if (column.sha256!=digest or column.signature!=signature or original['namespace']!=asdict(namespace)
            or original['revision']!=revision or original['operation_id']!=operation):
        raise AuthorityUnavailable('signed role-original row/namespace/full commitment changed')
    return original,digest


def require_role_control_rows_match_v4(original,inputs):
    from .role_control_rows_metadata_v4 import RoleControlRowsMetadataV4,_ROWS,_current_role_metadata_context_v4
    metadata=inputs.get('role_control_rows')
    if metadata is None:
        if type(original)is _RoleOriginalMetadataV4:
            expected=tuple((row[0],row[1],True,canonical_digest(row[2]),{name:row[2][name]for name in('namespace','plan_id','version')}if AtomKey.from_token(row[0]).type_name=='d01.persona_plan.v1'else row[2])for row in inputs['role_rows'])
            actual=original._column.legacy_rows
            if actual is None:raise AuthorityUnavailable('selected metadata original cannot be compared to legacy Body role')
        else:
            if canonical_serialize(original.get('role_rows'))!=canonical_serialize(inputs['role_rows']):
                raise AuthorityUnavailable('role original changed')
            return
    else:
        if type(metadata)is not RoleControlRowsMetadataV4:raise AuthorityUnavailable('actual role-control metadata required')
        if _ROWS.get(metadata)!=(inputs['reader'],inputs['db'],inputs['role'],
                _current_role_metadata_context_v4(inputs['reader'],inputs['db']),canonical_digest(metadata)):
            raise AuthorityUnavailable('role-control metadata lost its actual current issuing reader')
        expected=metadata.rows
        if type(original)is not _RoleOriginalMetadataV4:raise AuthorityUnavailable('signed whole-EOF role original required')
        actual=original._column.legacy_rows
        if actual is None:
            if canonical_serialize(original['role_control_rows'])!=canonical_serialize(asdict(metadata)):
                raise AuthorityUnavailable('selected role-control original changed')
            return
    # Legacy row order was token-sorted; metadata V4 is activation/plan/Owner.
    if {row[0]:canonical_serialize(row[1:])for row in actual}!={row[0]:canonical_serialize(row[1:])for row in expected}:
        raise AuthorityUnavailable('role-control original full values or identity changed')




@contextmanager
def bind_numeric_owner_role_originals_v4(reader):
    from ..authority_service.d04_numeric_owner_selectors_metadata_v4 import require_actual_numeric_owner_selectors_metadata_reader_v4
    require_actual_numeric_owner_selectors_metadata_reader_v4(reader,db=reader.db)
    if _NUMERIC_SCOPE.get() is not None or _SCOPE.get() is not None:
        raise AuthorityUnavailable('numeric role-original metadata scope is already bound')
    token=_NUMERIC_SCOPE.set(reader)
    try:yield reader
    finally:_NUMERIC_SCOPE.reset(token)


def create_numeric_owner_role_original_column_v4(reader,*,table,revision,signature):
    if _NUMERIC_SCOPE.get() is not reader:
        raise AuthorityUnavailable('actual independently bound numeric metadata reader required')
    signer,namespace=_actual_column_owner_v4(reader,reader.db)
    return _RoleControlSignedColumnV4(_ISSUER,reader,db=reader.db,table=table,
        key=(*namespace.as_tuple,revision),signer=signer,signature=signature)
