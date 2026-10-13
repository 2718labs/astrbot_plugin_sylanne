"""Content-free, candidate-local lookup of actual captured domain originals."""
from __future__ import annotations

import json

from ..runtime_contracts import NamespaceId
from .c09_paged_sql_v2 import (C09PagedCaptureHold,_bounded_capture_row,read_c09_materialized_row_v2,
    canonical_digest,canonical_serialize,current_c09_sql_meter_v2,_capture_write_v2,_sql_scalar_size_v2,c09_row_commitment_v2)
from .c09_graph_row_codec_v2 import read_c09_domain_row_v2

DOMAIN_INDEX_DDL_V2="CREATE TABLE c09_domain_original_lookup_v2 (scope_digest TEXT NOT NULL, family TEXT NOT NULL, bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL, original_ref TEXT NOT NULL, source_primary_key_json TEXT NOT NULL, row_commitment TEXT NOT NULL, original_commitment TEXT NOT NULL, producing_operation_id TEXT, call_id TEXT, prepared_digest TEXT, origin_stream_id TEXT NOT NULL, origin_record_ordinal INTEGER NOT NULL, PRIMARY KEY(scope_digest,family,bot,persona,kind,original_ref))"
DOMAIN_INDEX_INDEXES_V2=(
    ('c09_domain_original_call_v2','CREATE INDEX c09_domain_original_call_v2 ON c09_domain_original_lookup_v2(scope_digest,family,bot,persona,kind,call_id)'),
    ('c09_domain_original_prepared_v2','CREATE INDEX c09_domain_original_prepared_v2 ON c09_domain_original_lookup_v2(scope_digest,family,bot,persona,kind,prepared_digest)'),
)
DOMAIN_INDEX_TABLES_V2=frozenset({'c09_domain_original_lookup_v2'})


def install_c09_domain_index_schema_v2(candidate):
    for kind,name,ddl in [('table','c09_domain_original_lookup_v2',DOMAIN_INDEX_DDL_V2),
            *(('index',name,ddl) for name,ddl in DOMAIN_INDEX_INDEXES_V2)]:
        found=candidate.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name)).fetchone()
        if found is None:candidate.execute(ddl)
        elif found[0]!=ddl:raise C09PagedCaptureHold('domain lookup installed schema differs')


class C09DomainOriginalIndexV2:
    __slots__=('candidate','source','scope_digest','family','shape','authority_namespace','issuer','budget','verify_origin','io_read_bytes')

    def __init__(self,*,candidate,source,scope_digest,family,shape,authority_namespace,issuer,budget,verify_origin):
        if family!=shape.table:raise C09PagedCaptureHold('domain index family differs from its actual source schema')
        self.candidate=candidate;self.source=source;self.scope_digest=scope_digest;self.family=family;self.shape=shape
        self.authority_namespace=authority_namespace;self.issuer=issuer;self.budget=budget;self.verify_origin=verify_origin;self.io_read_bytes=0

    def add_actual_row(self,key,row,decoded,*,row_commitment,origin_stream_id,origin_record_ordinal):
        if not self.candidate.in_transaction or decoded.family!=self.family:
            raise C09PagedCaptureHold('actual row lookup must commit with its captured source page')
        values=dict(zip(self.shape.columns,row,strict=True))
        namespace=NamespaceId(values['bot'],values['persona'])
        raw=decoded.payload
        call_id=raw.get('call_id') if type(raw) is dict else None
        prepared_digest=raw.get('prepared_digest') if type(raw) is dict else None
        for value in (call_id,prepared_digest):
            if value is not None and type(value) is not str:raise C09PagedCaptureHold('domain scalar lookup field type differs')
        _capture_write_v2(self.candidate,'INSERT INTO c09_domain_original_lookup_v2 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (self.scope_digest,self.family,*namespace.as_tuple,decoded.kind,decoded.original_ref,canonical_serialize(key),
             row_commitment,decoded.original_commitment,values.get('producing_operation_id'),call_id,prepared_digest,origin_stream_id,origin_record_ordinal))

    def _find(self,namespace,kind,field,value):
        if type(namespace) is not NamespaceId or field not in {'original_ref','call_id','prepared_digest'}:
            raise ValueError('closed actual domain lookup selector required')
        where='scope_digest=? AND family=? AND bot=? AND persona=? AND kind=? AND '+field+'=?'
        args=(self.scope_digest,self.family,*namespace.as_tuple,kind,value)
        # Two rows already disprove the unique actual parent; never materialize
        # the entire namespace to find one call or preparation.
        meter=current_c09_sql_meter_v2()
        refs=tuple(self.candidate.execute('SELECT CASE WHEN length(CAST(original_ref AS BLOB))<=65536 THEN original_ref ELSE NULL END FROM c09_domain_original_lookup_v2 WHERE '+where+' ORDER BY original_ref COLLATE BINARY LIMIT 2',args))
        if any(ref[0] is None for ref in refs):raise C09PagedCaptureHold('actual domain original locator exceeds its registered descriptor')
        meter.charge_read(sum(_sql_scalar_size_v2(ref[0]) for ref in refs))
        if len(refs)>1:raise C09PagedCaptureHold('actual domain identity has ambiguous original parents')
        if not refs:return None
        columns=('source_primary_key_json','row_commitment','original_commitment','producing_operation_id','origin_stream_id','origin_record_ordinal')
        item=_bounded_capture_row(self.candidate,'c09_domain_original_lookup_v2',columns,
            'scope_digest=? AND family=? AND bot=? AND persona=? AND kind=? AND original_ref=?',
            (self.scope_digest,self.family,*namespace.as_tuple,kind,refs[0][0]),(65536,64,64,65536,64,20))
        if item is None:raise C09PagedCaptureHold('actual original lookup disappeared')
        key=tuple(json.loads(item[0]))
        self.verify_origin(item[4],item[5],key,item[1])
        from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2,_quote
        where_source=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in self.shape.primary_key_columns)
        cells=','.join('typeof('+_quote(name)+'),length(CAST('+_quote(name)+' AS BLOB))' for name in self.shape.columns)
        meta=self.source.execute('SELECT '+cells+' FROM '+_quote(self.family)+' WHERE '+where_source+' LIMIT 1',key).fetchone()
        if meta is None:raise C09PagedCaptureHold('captured domain original is absent in the frozen source')
        meter.charge_read(sum(_sql_scalar_size_v2(value) for value in meta))
        metadata=tuple((meta[i],meta[i+1]) for i in range(0,len(meta),2))
        row=read_c09_materialized_row_v2(self.source,self.shape,key,metadata,self.budget)
        self.io_read_bytes+=sum(0 if length is None else length for _,length in metadata)
        decoded=read_c09_domain_row_v2(self.family,self.shape.columns,row,authority_namespace=self.authority_namespace,issuer=self.issuer)
        if (decoded.kind,decoded.original_ref,decoded.original_commitment,c09_row_commitment_v2(row))!=(kind,refs[0][0],item[2],item[1]):
            raise C09PagedCaptureHold('domain lookup does not match its actual signed source row')
        return item[3],decoded

    def get(self,namespace,kind,original_ref):return self._find(namespace,kind,'original_ref',original_ref)
    def by_call(self,namespace,kind,call_id):return self._find(namespace,kind,'call_id',call_id)
    def by_prepared_digest(self,namespace,kind,digest):return self._find(namespace,kind,'prepared_digest',digest)

    def life_point_original(self,key):
        namespace,kind,ref=key;saved=self.get(namespace,kind,ref)
        if saved is None:return None
        producing_operation_id,decoded=saved
        from .c09_life_originals_v1 import decode_life_original_content_v1
        value=decode_life_original_content_v1(kind,canonical_serialize(decoded.payload))
        return producing_operation_id,value,decoded.payload,decoded.original_commitment

    def life_prepared_by_call(self,namespace,kind,call_id):
        saved=self.by_call(namespace,kind,call_id)
        if saved is None:return None
        producing_operation_id,decoded=saved
        from .c09_life_originals_v1 import decode_life_original_content_v1
        return producing_operation_id,decode_life_original_content_v1(kind,canonical_serialize(decoded.payload)),decoded.payload,decoded.original_commitment
