"""Exact historical Graph structural-store rows; never current authority.

The installed historical-scope service verifies the selected signed lineage.
These codecs verify fixed schemas, actual source PKs and signed original pages.
Uncertified operational worksets retire by the explicit registered rule below.
"""
from __future__ import annotations
from dataclasses import asdict
import json

from .c09_paged_sql_v2 import (C09PagedCaptureHold,read_c09_table_shape_v2,
    c09_row_commitment_v2,canonical_digest,canonical_serialize,require_c09_capture_member_v2)
from .c09_paged_capture_contract_v2 import (C09CaptureScopeV2,C09FrozenRoleSourceV2,
    GraphErasureRebaseCertificateV2,C09StreamIdentityV2,C09CompleteStreamV2,
    C09SealedStreamLocatorV2,C09CountOriginalV2,C09PageCursorV2,
    c09_paged_value_from_wire_v2,verify_c09_complete_stream_v2)

OPERATIONAL_RETIRE_TABLES_V2=frozenset({
    'c09_closure_state_v2','c09_domain_original_lookup_v2','c09_graph_build_progress_v2','c09_graph_stream_directory_v2',
    'c09_prior_graph_spans_v2','c09_prior_graph_types_v2','c09_prior_graph_rows_v2',
    'c09_prior_graph_keys_v2','c09_prior_graph_manifests_v2','c09_prior_graph_streams_v2'})


def historical_graph_proof_ddls_v2():
    from .c09_paged_sql_v2 import CAPTURE_DDLS_V2
    from .c09_closure_index_v2 import CLOSURE_DDLS_V2
    from .c09_domain_original_index_v2 import DOMAIN_INDEX_DDL_V2
    from .c09_graph_rebase_candidate_v2 import GRAPH_PROOF_DDLS_V2
    from .c09_graph_originals_read_v5 import PRIOR_GRAPH_VIEW_DDLS_V2
    return {**CAPTURE_DDLS_V2,**CLOSURE_DDLS_V2,
        'c09_domain_original_lookup_v2':DOMAIN_INDEX_DDL_V2,**GRAPH_PROOF_DDLS_V2,**PRIOR_GRAPH_VIEW_DDLS_V2}


def _scope_for_row(source,shape,row,meter):
    data=dict(zip(shape.columns,row,strict=True))
    if shape.table=='c09_contact_plan_prefix_history_v3':
        from .c09_contact_plan_prefix_history_v3 import decode_contact_prefix_history_row_v3
        decode_contact_prefix_history_row_v3(tuple(row))
        return data['capture_scope_digest']
    if 'scope_digest' in data:return data['scope_digest']
    if 'stream_id' not in data:raise C09PagedCaptureHold('historical structural row lacks its registered scope linkage')
    parent=meter.read_fixed_row(source,'c09_capture_streams_v2',('scope_digest',),'stream_id=?',(data['stream_id'],))
    if parent is None:raise C09PagedCaptureHold('historical structural row lost its actual parent stream')
    return parent[0]


def _actual_anchor(session,pair,scope_digest):
    if scope_digest==session.scope.scope_digest:raise C09PagedCaptureHold('current operation workset cannot be historical')
    anchor=session.require_historical_capture_scope_v2(scope_digest)
    from ..authority_service.c09_historical_capture_scope_v2 import VerifiedHistoricalCaptureScopeV2
    if type(anchor) is not VerifiedHistoricalCaptureScopeV2:raise C09PagedCaptureHold('installed historical scope anchor has another private type')
    anchor.require_current()
    scope=anchor.scope;source=anchor.source;certificate=anchor.certificate
    if (type(scope) is not C09CaptureScopeV2 or type(source) is not C09FrozenRoleSourceV2
            or type(certificate) is not GraphErasureRebaseCertificateV2
            or scope.scope_digest!=scope_digest or source.scope_digest!=scope_digest or source.role!='graph'
            or certificate.candidate.scope!=scope or certificate.candidate.source!=source
            or scope.graph_namespace!=session.scope.graph_namespace
            or scope.authority_namespace!=session.scope.authority_namespace
            or scope.installation_id!=session.scope.installation_id):
        raise C09PagedCaptureHold('historical structural row crossed its actual signed scope/source')
    pair.require_current();return anchor


def _require_signed_locator(source,anchor,identity,meter):
    certificate=anchor.certificate;candidate=certificate.candidate
    if identity.scope_digest!=anchor.scope.scope_digest or identity.role_source_digest!=anchor.source.role_source_digest:raise C09PagedCaptureHold('historical stream crossed its signed frozen role source')
    for field in ('schema_catalogue','disposition_directory','closure','tombstones','target_directory','generated_directory'):
        locator=getattr(candidate,field)
        if locator.identity==identity:return locator
    # A nested lookup is qualified only by its exact outer signed page member.
    for field in ('disposition_directory','closure','target_directory'):
        outer=getattr(candidate,field);shape=read_c09_table_shape_v2(source,outer.identity.family)
        if 'family' not in shape.columns or 'identity_json' not in shape.columns:continue
        row=meter.read_fixed_row(source,shape.table,shape.columns,'scope_digest=? AND family=?',
            (candidate.scope.scope_digest,identity.family))
        if row is None:continue
        data=dict(zip(shape.columns,row,strict=True))
        nested=c09_paged_value_from_wire_v2(json.loads(data['identity_json']),C09StreamIdentityV2)
        if nested!=identity:continue
        complete=c09_paged_value_from_wire_v2(json.loads(data['complete_json']),C09CompleteStreamV2)
        key=tuple(data[name] for name in shape.primary_key_columns)
        member=meter.read_fixed_row(source,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND key_digest=?',(outer.identity.stream_id,canonical_digest(key)))
        if member is None or member[1]!=c09_row_commitment_v2(row):raise C09PagedCaptureHold('historical nested directory has no identical signed outer member')
        require_c09_capture_member_v2(source,outer.identity,member[0],key,member[1],meter=meter)
        return C09SealedStreamLocatorV2('graph',nested,complete)
    if identity.stream_kind=='graph_facts':
        basis=_nested_locator_for_family(source,anchor,candidate.disposition_directory,identity.family,meter)
        from .c09_graph_rebase_candidate_v2 import (GRAPH_DISPOSITION_COLUMNS_V2,GRAPH_DISPOSITION_COLUMNS_V3,
            _read_graph_disposition_original_row_v3)
        witness=None
        for version,columns in (('c09_graph_dispositions_v2',GRAPH_DISPOSITION_COLUMNS_V2),('c09_graph_dispositions_v3',GRAPH_DISPOSITION_COLUMNS_V3)):
            present=meter.read_fixed_row(source,'sqlite_master',('name',),'type=? AND name=?',('table',version))
            if present is None:continue
            found=meter.read_fixed_row(source,version,columns,
                'scope_digest=? AND table_name=? AND origin_stream_id=?',(anchor.scope.scope_digest,identity.family,identity.stream_id))
            if found is not None:
                business_key=tuple(json.loads(found[3]))
                witness=_read_graph_disposition_original_row_v3(source,anchor.scope.scope_digest,identity.family,business_key,meter)
                break
        if witness is None:
            return _require_empty_source_index_locator_v2(source,anchor,identity,basis,meter)
        business_key=tuple(json.loads(witness[3]))
        _require_exact_structural_member(source,basis,business_key,witness,meter)
        require_c09_capture_member_v2(source,identity,witness[8],business_key,witness[4],meter=meter)
        row=meter.read_fixed_row(source,'c09_capture_streams_v2',('seal_json',),'stream_id=?',(identity.stream_id,))
        if row is None:raise C09PagedCaptureHold('historical source-index origin has no actual complete count/EOF original')
        complete=c09_paged_value_from_wire_v2(json.loads(row[0]),C09CompleteStreamV2)
        if complete.record_count!=basis.complete.record_count:raise C09PagedCaptureHold('source-index complete census omits or adds canonical origin rows')
        return C09SealedStreamLocatorV2('graph',identity,complete)
    raise C09PagedCaptureHold('historical stream is outside its actual signed complete directories')


def classify_historical_graph_proof_row_v2(session,pair,shape,key,row,*,meter,require_complete_stream):
    """One real source row. Callback requires an independently EOF-verified stream.

    The caller's private per-cold verification driver supplies that callback;
    persisted capture status or cursor is never a completion certificate.
    """
    from ..authority_service.c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from ..authority_service.c09_role_capture_pair_v2 import InstalledC09RolePairV2
    if type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2 or pair.source_original.role!='graph':
        raise TypeError('actual installed Graph source pair required')
    session.require_current();pair.require_current();ddls=historical_graph_proof_ddls_v2()
    if shape.table not in ddls:raise C09PagedCaptureHold('unregistered historical structural-store table')
    schema=meter.read_fixed_row(pair.source,'sqlite_master',('sql',),'type=? AND name=?',('table',shape.table))
    if schema!=(ddls[shape.table],):raise C09PagedCaptureHold('historical structural-store exact installed DDL differs')
    actual_shape=read_c09_table_shape_v2(pair.source,shape.table)
    if actual_shape!=shape or tuple(row[shape.columns.index(n)] for n in shape.primary_key_columns)!=key:
        raise C09PagedCaptureHold('historical structural row has another actual schema/PK')
    actual=meter.read_row(pair.source,shape,key)
    if actual!=tuple(row):raise C09PagedCaptureHold('historical structural row is not its frozen source PK value')
    historical_scope=_scope_for_row(pair.source,shape,row,meter);anchor=_actual_anchor(session,pair,historical_scope)
    data=dict(zip(shape.columns,row,strict=True))
    if shape.table in OPERATIONAL_RETIRE_TABLES_V2:
        # These exact registered kinds are noncanonical worksets. Their source
        # row and signed historical scope are recorded by the ordinary current
        # disposition/origin producer; no business original is deleted here.
        return 'derived_removed'
    if shape.table.startswith('c09_capture_'):
        parent=meter.read_fixed_row(pair.source,'c09_capture_streams_v2',('identity_json','status','seal_json'),
            'stream_id=?',(data['stream_id'],))
        if parent is None or parent[1]!='sealed':raise C09PagedCaptureHold('historical canonical stream lacks its complete original')
        identity=c09_paged_value_from_wire_v2(json.loads(parent[0]),C09StreamIdentityV2)
        locator=_require_signed_locator(pair.source,anchor,identity,meter)
        seal=c09_paged_value_from_wire_v2(json.loads(parent[2]),C09CompleteStreamV2)
        if seal!=locator.complete:raise C09PagedCaptureHold('historical stored complete original differs from signed locator')
        _require_independent_stream(session,pair,locator,require_complete_stream)
        if shape.table=='c09_capture_members_v2':
            require_c09_capture_member_v2(pair.source,identity,data['record_ordinal'],tuple(json.loads(data['primary_key_json'])),data['commitment'],meter=meter)
        elif shape.table=='c09_capture_pages_v2':
            from .c09_paged_sql_v2 import read_capture_page_v2
            page,records=read_capture_page_v2(pair.source,identity,data['page_index'])
            if page.page_index>=seal.page_count or page.stream_id!=identity.stream_id:raise C09PagedCaptureHold('historical page is outside its complete stream')
            if canonical_serialize(asdict(page))!=data['descriptor_json']:raise C09PagedCaptureHold('historical page descriptor differs from actual original')
        elif shape.table=='c09_capture_progress_v2':
            _require_canonical_complete_progress(pair.source,data,locator,meter)
        return 'preserved_exact'
    if shape.table in {'c09_graph_dispositions_v2','c09_graph_dispositions_v3'}:
        outer=anchor.certificate.candidate.disposition_directory
        locator=_nested_locator_for_family(pair.source,anchor,outer,data['table_name'],meter)
        _require_independent_stream(session,pair,locator,require_complete_stream)
        business_key=tuple(json.loads(data['source_primary_key_json']))
        if data['key_digest']!=canonical_digest((data['table_name'],business_key)):raise C09PagedCaptureHold('historical disposition has another exact business PK commitment')
        _require_exact_structural_member(pair.source,locator,business_key,row,meter)
        if shape.table=='c09_graph_dispositions_v3':
            from .c09_historical_logical_source_v3 import require_historical_logical_graph_disposition_v3
            require_historical_logical_graph_disposition_v3(session,pair,anchor,tuple(row),meter=meter)
        return 'preserved_exact'
    if shape.table=='c09_logical_source_rows_v3':
        from .c09_historical_logical_source_v3 import require_historical_logical_source_descriptor_row_v3
        locator=require_historical_logical_source_descriptor_row_v3(session,pair,anchor,shape,key,row,meter=meter)
        _require_independent_stream(session,pair,locator,require_complete_stream)
        return 'preserved_exact'
    if shape.table=='c09_contact_plan_prefix_history_v3':
        from .c09_contact_plan_prefix_history_v3 import decode_contact_prefix_history_row_v3
        decode_contact_prefix_history_row_v3(tuple(row))
        locator=_nested_locator_for_family(pair.source,anchor,anchor.certificate.candidate.target_directory,shape.table,meter)
        _require_independent_stream(session,pair,locator,require_complete_stream)
        _require_exact_structural_member(pair.source,locator,key,row,meter)
        return 'preserved_exact'
    if shape.table in {'c09_closure_members_v2','c09_closure_edges_v2'}:
        outer=anchor.certificate.candidate.closure
        locator=_nested_locator_for_family(pair.source,anchor,outer,shape.table,meter)
        _require_independent_stream(session,pair,locator,require_complete_stream)
        _require_exact_structural_member(pair.source,locator,key,row,meter)
        return 'preserved_exact'
    # Nonworkset structural rows must themselves occur inside one of the six
    # signed finite directories or their declared nested metadata streams.
    for field in ('schema_catalogue','disposition_directory','closure','tombstones','target_directory','generated_directory'):
        locator=getattr(anchor.certificate.candidate,field)
        if locator.identity.family!=shape.table:continue
        _require_independent_stream(session,pair,locator,require_complete_stream)
        member=meter.read_fixed_row(pair.source,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND key_digest=?',(locator.identity.stream_id,canonical_digest(key)))
        if member is None or member[1]!=c09_row_commitment_v2(row):raise C09PagedCaptureHold('historical structural row lost its signed directory member')
        require_c09_capture_member_v2(pair.source,locator.identity,member[0],key,member[1],meter=meter)
        return 'preserved_exact'
    raise C09PagedCaptureHold('historical canonical structural row lacks an actual signed member')


def _require_empty_source_index_locator_v2(source,anchor,identity,basis,meter):
    """No row witness exists only after the registered zero-content chain closes."""
    from .c09_paged_capture_contract_v2 import begin_c09_stream_v2
    from .c09_paged_sql_v2 import _load_census,_capture_data_state
    if (basis.identity.scope_digest!=anchor.scope.scope_digest
            or basis.identity.role_source_digest!=anchor.source.role_source_digest
            or basis.complete.record_count!=0 or basis.identity.family!=identity.family):
        raise C09PagedCaptureHold('empty source-index lacks its same-family signed zero disposition basis')
    shape=read_c09_table_shape_v2(source,identity.family,meter=meter)
    if (identity.schema_digest!=shape.schema_digest or identity.primary_key_columns!=shape.primary_key_columns
            or identity.primary_key_types!=shape.primary_key_types):
        raise C09PagedCaptureHold('empty source-index differs from its registered actual family schema')
    parent=meter.read_fixed_row(source,'c09_capture_streams_v2',('identity_json','status','seal_json'),
        'stream_id=?',(identity.stream_id,))
    if (parent is None or parent[1]!='sealed' or parent[0]!=canonical_serialize(asdict(identity))):
        raise C09PagedCaptureHold('empty source-index lacks its exact registered sealed stream')
    complete=c09_paged_value_from_wire_v2(json.loads(parent[2]),C09CompleteStreamV2)
    empty=begin_c09_stream_v2(identity)
    if ((complete.record_count,complete.page_count,complete.encoded_bytes)!=(0,0,0)
            or complete.record_root!=empty.record_chain or complete.page_root!=empty.previous_page_digest):
        raise C09PagedCaptureHold('source-index without row witness is not its canonical empty genesis')
    for table in ('c09_capture_pages_v2','c09_capture_members_v2'):
        if meter.read_fixed_row(source,table,('stream_id',),'stream_id=? LIMIT 1',(identity.stream_id,)) is not None:
            raise C09PagedCaptureHold('empty source-index contains extra actual page or member')
    census=_load_census(source,identity);data=_capture_data_state(source,identity)
    if census.record_count!=0 or census.last_key is not None:
        raise C09PagedCaptureHold('empty source-index actual census has content')
    verify_c09_complete_stream_v2(identity,empty,census,complete,data_eof_observation_digest=data['eof'])
    # This locator is consumed only after both independent stream sweeps finish.
    return C09SealedStreamLocatorV2('graph',identity,complete)


def _nested_locator_for_family(source,anchor,outer,family,meter):
    shape=read_c09_table_shape_v2(source,outer.identity.family)
    row=meter.read_fixed_row(source,shape.table,shape.columns,'scope_digest=? AND family=?',(anchor.scope.scope_digest,family))
    if row is None:raise C09PagedCaptureHold('historical canonical family lacks its signed outer directory')
    data=dict(zip(shape.columns,row,strict=True))
    identity=c09_paged_value_from_wire_v2(json.loads(data['identity_json']),C09StreamIdentityV2)
    return _require_signed_locator(source,anchor,identity,meter)


def _require_exact_structural_member(source,locator,key,row,meter):
    member=meter.read_fixed_row(source,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND key_digest=?',(locator.identity.stream_id,canonical_digest(key)))
    if member is None or member[1]!=c09_row_commitment_v2(row):raise C09PagedCaptureHold('historical canonical structural row has no identical signed member')
    require_c09_capture_member_v2(source,locator.identity,member[0],key,member[1],meter=meter)


def _require_independent_stream(session,pair,locator,lookup):
    verified=lookup(locator)
    if (type(verified) is not HistoricalGraphStreamVerificationV2
            or verified.session is not session or verified.pair is not pair):
        raise C09PagedCaptureHold('historical row requires its actual independently completed stream verifier')
    return verified.require_complete(locator)


def _require_canonical_complete_progress(source,data,locator,meter):
    raw=json.loads(data['progress_json']);complete=locator.complete
    if canonical_serialize(raw)!=data['progress_json']:raise C09PagedCaptureHold('historical complete progress bytes are not canonical')
    if data['phase']=='census':
        if type(raw) is not dict or set(raw)!={'count','last_key','chain','eof','original'}:raise C09PagedCaptureHold('historical census progress has unbound extra/missing fields')
        original=c09_paged_value_from_wire_v2(raw['original'],C09CountOriginalV2)
        if (raw['count']!=complete.record_count or raw['eof'] is None
                or original.digest!=complete.census_digest or original.original_digest!=complete.complete_count_original_digest
                or original.eof_observation_digest!=raw['eof'] or original.record_count!=raw['count']
                or original.last_key!=(None if raw['last_key'] is None else tuple(raw['last_key']))
                or original.original_digest!=canonical_digest(('sylanne3.c09.actual-count-original.v2',locator.identity.stream_id,
                    raw['count'],original.last_key,raw['chain'],raw['eof']))):raise C09PagedCaptureHold('historical census original is outside its signed complete commitment')
    elif data['phase']=='data':
        if type(raw) is not dict or set(raw)!={'cursor','eof'}:raise C09PagedCaptureHold('historical data progress has unbound extra/missing fields')
        cursor=c09_paged_value_from_wire_v2(raw['cursor'],C09PageCursorV2)
        if (cursor.stream_id!=complete.stream_id or cursor.record_offset!=complete.record_count
                or cursor.page_index!=complete.page_count or cursor.record_chain!=complete.record_root
                or cursor.previous_page_digest!=complete.page_root or cursor.encoded_bytes!=complete.encoded_bytes):raise C09PagedCaptureHold('historical complete EOF progress differs from its signed original')
        from .c09_paged_sql_v2 import _load_census
        original=_load_census(source,locator.identity)
        verify_c09_complete_stream_v2(locator.identity,cursor,original,complete,data_eof_observation_digest=raw['eof'])
    else:raise C09PagedCaptureHold('historical capture progress has an unknown phase')


_HISTORY_STREAM_TOKEN_V2=object()


class HistoricalGraphStreamVerificationV2:
    __slots__=('_token','session','pair','anchor','locator','reader','complete','basis','basis_reader','basis_complete')
    def __init__(self,token,session,pair,anchor,locator):
        if token is not _HISTORY_STREAM_TOKEN_V2:raise TypeError('actual historical stream verification required')
        from ..authority_service.c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        self._token=token;self.session=session;self.pair=pair;self.anchor=anchor;self.locator=locator
        self.reader=C09HistoricalSealedStreamReaderV2(locator);self.complete=False
        self.basis=None;self.basis_reader=None;self.basis_complete=True

    def require_complete(self,locator):
        self.session.require_current();self.pair.require_current();self.anchor.require_current()
        if self._token is not _HISTORY_STREAM_TOKEN_V2 or not self.complete or self.locator!=locator:
            raise C09PagedCaptureHold('historical stream has not independently verified its actual complete EOF')
        return self


def begin_historical_graph_stream_verification_v2(session,pair,locator,*,meter):
    """Fresh stream sweep; no persisted cursor or caller completion flag."""
    anchor=_actual_anchor(session,pair,locator.identity.scope_digest)
    actual=_require_signed_locator(pair.source,anchor,locator.identity,meter)
    if actual!=locator:raise C09PagedCaptureHold('historical verifier was given another signed complete locator')
    verified=HistoricalGraphStreamVerificationV2(_HISTORY_STREAM_TOKEN_V2,session,pair,anchor,actual)
    if actual.identity.stream_kind=='graph_facts':
        from ..authority_service.c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        verified.basis=_nested_locator_for_family(pair.source,anchor,anchor.certificate.candidate.disposition_directory,actual.identity.family,meter)
        verified.basis_reader=C09HistoricalSealedStreamReaderV2(verified.basis);verified.basis_complete=False
    return verified


def advance_historical_graph_stream_verification_v2(verification,*,budget,meter):
    from time import monotonic_ns
    from .c09_paged_sql_v2 import c09_sql_meter_quantum_v2
    if type(verification) is not HistoricalGraphStreamVerificationV2:raise TypeError('actual private historical stream verifier required')
    verification.session.require_current();verification.pair.require_current();verification.anchor.require_current()
    source=verification.pair.source
    if source.in_transaction:raise C09PagedCaptureHold('independent historical stream sweep requires its actual short read transaction')
    source.execute('BEGIN');started=monotonic_ns();records=0
    try:
        with c09_sql_meter_quantum_v2(meter):
            def observed(record):
                nonlocal records
                records+=1
                if verification.basis is not None:
                    from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
                    data=_read_graph_disposition_original_row_v3(source,verification.anchor.scope.scope_digest,
                        verification.locator.identity.family,record.primary_key,meter)
                    ordinal=verification.reader.cursor.record_offset+verification.reader.index+1
                    if (data is None or tuple(json.loads(data[3]))!=record.primary_key or data[4]!=record.commitment
                            or data[7]!=verification.locator.identity.stream_id or data[8]!=ordinal):
                        raise C09PagedCaptureHold('historical source-index record lost its exact canonical origin PK/ordinal/semantic commitment')
                    _require_exact_structural_member(source,verification.basis,record.primary_key,data,meter)
                    if len(data)==13:
                        from .c09_historical_logical_source_v3 import require_historical_logical_graph_disposition_v3
                        require_historical_logical_graph_disposition_v3(verification.session,verification.pair,verification.anchor,data,meter=meter)
                # Old immutable structural records prove history. Subsequent
                # mutable business rows are qualified by the separate current
                # Source sweep and only compared at a concrete retention point.
            def observed_basis(record):
                nonlocal records
                records+=1
            while not verification.complete and records<budget.max_records and monotonic_ns()-started<budget.max_local_ns and meter.remaining_bytes>32768:
                if not verification.basis_complete:
                    verification.basis_complete=verification.basis_reader.advance(source,meter,observed_basis)
                    continue
                verification.complete=verification.reader.advance(source,meter,observed)
    finally:source.rollback()
    elapsed=monotonic_ns()-started
    if elapsed>budget.max_read_ns:raise C09PagedCaptureHold('historical stream short read exceeded its actual duration')
    return {'complete':verification.complete,'completed_records':records,'elapsed_ns':elapsed,
        'resource_quantum_within_limit':elapsed<=budget.max_local_ns,
        'verification':verification if verification.complete else None}


def read_historical_graph_proof_row_locator_v2(session,pair,shape,row,*,meter):
    """The installed driver resolves one required stream before point classification."""
    session.require_current();pair.require_current()
    if shape.table not in historical_graph_proof_ddls_v2():raise C09PagedCaptureHold('unregistered historical proof row family')
    anchor=_actual_anchor(session,pair,_scope_for_row(pair.source,shape,row,meter))
    if shape.table in OPERATIONAL_RETIRE_TABLES_V2:return None
    data=dict(zip(shape.columns,row,strict=True))
    if shape.table=='c09_logical_source_rows_v3':
        from .c09_historical_logical_source_v3 import require_historical_logical_source_descriptor_row_v3
        return require_historical_logical_source_descriptor_row_v3(session,pair,anchor,shape,None,row,meter=meter)
    if shape.table.startswith('c09_capture_'):
        parent=meter.read_fixed_row(pair.source,'c09_capture_streams_v2',('identity_json',),'stream_id=?',(data['stream_id'],))
        if parent is None:raise C09PagedCaptureHold('historical row has no actual canonical stream identity')
        identity=c09_paged_value_from_wire_v2(json.loads(parent[0]),C09StreamIdentityV2)
        return _require_signed_locator(pair.source,anchor,identity,meter)
    if shape.table in {'c09_graph_dispositions_v2','c09_graph_dispositions_v3'}:
        return _nested_locator_for_family(pair.source,anchor,anchor.certificate.candidate.disposition_directory,data['table_name'],meter)
    if shape.table=='c09_contact_plan_prefix_history_v3':
        return _nested_locator_for_family(pair.source,anchor,anchor.certificate.candidate.target_directory,shape.table,meter)
    if shape.table in {'c09_closure_members_v2','c09_closure_edges_v2'}:
        return _nested_locator_for_family(pair.source,anchor,anchor.certificate.candidate.closure,shape.table,meter)
    for field in ('schema_catalogue','disposition_directory','closure','tombstones','target_directory','generated_directory'):
        locator=getattr(anchor.certificate.candidate,field)
        if locator.identity.family==shape.table:return locator
    raise C09PagedCaptureHold('historical canonical row has no signed physical-directory locator')
