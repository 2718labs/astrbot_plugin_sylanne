"""Durable Source/dependency fixed point in the registered C09 candidate.

Members, edges and round cursors are structural evidence. No Source text,
model output or domain body is copied into the closure index.
"""
from __future__ import annotations

import json
from time import monotonic_ns

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .c09_paged_capture_contract_v2 import C09CaptureScopeV2
from .c09_paged_sql_v2 import C09PagedCaptureHold, _bounded_capture_row

CLOSURE_DDLS_V2={
    'c09_closure_state_v2': "CREATE TABLE c09_closure_state_v2 (scope_digest TEXT PRIMARY KEY, round INTEGER NOT NULL, member_generation INTEGER NOT NULL, round_generation INTEGER NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('collect','expand','sealed')), cursor_json TEXT NOT NULL)",
    'c09_closure_members_v2': "CREATE TABLE c09_closure_members_v2 (scope_digest TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('atom','source_id','operation','domain_link','row')), ref TEXT NOT NULL, added_round INTEGER NOT NULL, origin_stream_id TEXT NOT NULL, origin_record_ordinal INTEGER NOT NULL, origin_commitment TEXT NOT NULL, PRIMARY KEY(scope_digest,kind,ref))",
    'c09_closure_edges_v2': "CREATE TABLE c09_closure_edges_v2 (scope_digest TEXT NOT NULL, dependent_ref TEXT NOT NULL, dependency_ref TEXT NOT NULL, origin_stream_id TEXT NOT NULL, origin_record_ordinal INTEGER NOT NULL, origin_commitment TEXT NOT NULL, PRIMARY KEY(scope_digest,dependent_ref,dependency_ref,origin_stream_id,origin_record_ordinal))",
}
CLOSURE_TABLES_V2=frozenset(CLOSURE_DDLS_V2)


def install_c09_closure_schema_v2(candidate):
    for name,ddl in CLOSURE_DDLS_V2.items():
        found=candidate.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
        if found is None: candidate.execute(ddl)
        elif found[0]!=ddl: raise C09PagedCaptureHold('C09 closure table schema differs')


class C09ClosureIndexV2:
    __slots__=('db','scope','namespace')

    def __init__(self,candidate,scope):
        if type(scope) is not C09CaptureScopeV2: raise TypeError('actual versioned capture scope required')
        decoded=json.loads(scope.graph_namespace)
        if type(decoded) is not list or len(decoded)!=2 or any(type(item) is not str for item in decoded):
            raise C09PagedCaptureHold('C09 closure Graph namespace descriptor differs')
        self.db=candidate;self.scope=scope;self.namespace=NamespaceId(*decoded)

    def begin(self):
        if not self.db.in_transaction: raise C09PagedCaptureHold('closure registration requires the candidate transaction')
        self.db.execute("INSERT INTO c09_closure_state_v2 VALUES (?,0,0,0,'collect','null') ON CONFLICT(scope_digest) DO NOTHING",(self.scope.scope_digest,))

    def contains(self,kind,ref):
        if kind not in {'atom','source_id','operation','domain_link','row'}: raise ValueError('closed C09 closure member kind required')
        return self.db.execute('SELECT 1 FROM c09_closure_members_v2 WHERE scope_digest=? AND kind=? AND ref=?',
            (self.scope.scope_digest,kind,ref)).fetchone() is not None

    def contains_atom(self,ref): return self.contains('atom',ref)
    def contains_source_id(self,source_id): return self.contains('source_id',source_id)
    def contains_operation(self,operation_id): return self.contains('operation',operation_id)

    def contains_domain_link(self,table,identity):
        return self.contains('domain_link',canonical_serialize((table,identity)))

    def contains_row(self,table,primary_key):
        return self.contains('row',canonical_serialize((table,primary_key)))

    def add_domain_link(self,table,identity,**origin):
        return self.add_member('domain_link',canonical_serialize((table,identity)),**origin)

    def add_row(self,table,primary_key,**origin):
        return self.add_member('row',canonical_serialize((table,primary_key)),**origin)

    def _state(self):
        row=_bounded_capture_row(self.db,'c09_closure_state_v2',('round','member_generation','round_generation','phase','cursor_json'),
            'scope_digest=?',(self.scope.scope_digest,),(20,20,20,16,65536))
        if row is None: raise C09PagedCaptureHold('closure progress absent')
        return row

    def add_member(self,kind,ref,*,origin_stream_id,origin_record_ordinal,origin_commitment):
        if not self.db.in_transaction: raise C09PagedCaptureHold('closure member must commit with its actual source page')
        state=self._state()
        if state[3]=='sealed': raise C09PagedCaptureHold('closure fixed point has already sealed')
        if kind not in {'atom','source_id','operation','domain_link','row'} or type(ref) is not str or not ref:
            raise ValueError('closed structural member required')
        if kind=='atom':
            key=AtomKey.from_token(ref)
            if NamespaceId.from_key(key)!=self.namespace: raise C09PagedCaptureHold('closure atom crossed its actual namespace')
        if len(canonical_serialize((kind,ref,origin_stream_id,origin_record_ordinal,origin_commitment)).encode('utf-8'))>65536:
            raise C09PagedCaptureHold('closure member exceeds its structural descriptor')
        cursor=self.db.execute('INSERT INTO c09_closure_members_v2 VALUES (?,?,?,?,?,?,?) ON CONFLICT(scope_digest,kind,ref) DO NOTHING',
            (self.scope.scope_digest,kind,ref,state[0],origin_stream_id,origin_record_ordinal,origin_commitment))
        if cursor.rowcount:
            self.db.execute('UPDATE c09_closure_state_v2 SET member_generation=member_generation+1 WHERE scope_digest=?',(self.scope.scope_digest,))
        return cursor.rowcount==1

    def add_atom(self,ref,**origin):
        added=self.add_member('atom',ref,**origin);key=AtomKey.from_token(ref)
        if key.type_name=='memory.source': self.add_member('source_id',key.owner.subject,**origin)
        return added

    def add_edge(self,dependent_ref,dependency_ref,*,origin_stream_id,origin_record_ordinal,origin_commitment):
        if not self.db.in_transaction: raise C09PagedCaptureHold('closure edge requires the source-page transaction')
        for ref in (dependent_ref,dependency_ref):
            if NamespaceId.from_key(AtomKey.from_token(ref))!=self.namespace:
                raise C09PagedCaptureHold('dependency edge crossed the erasure namespace')
        if self._state()[3]=='sealed': raise C09PagedCaptureHold('sealed closure edge cannot be appended')
        inserted=self.db.execute('INSERT INTO c09_closure_edges_v2 VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING',
            (self.scope.scope_digest,dependent_ref,dependency_ref,origin_stream_id,origin_record_ordinal,origin_commitment))
        if inserted.rowcount:
            self.db.execute('UPDATE c09_closure_state_v2 SET member_generation=member_generation+1 WHERE scope_digest=?',(self.scope.scope_digest,))
        return inserted.rowcount==1

    def iter_members(self,kind,after_ref,limit):
        if kind not in {'atom','source_id','operation','domain_link','row'} or type(limit) is not int or not 0<limit<=100:
            raise ValueError('bounded closed closure iterator required')
        after='' if after_ref is None else after_ref
        for ref,stream,ordinal,commitment in self.db.execute(
                'SELECT ref,origin_stream_id,origin_record_ordinal,origin_commitment FROM c09_closure_members_v2 WHERE scope_digest=? AND kind=? AND ref COLLATE BINARY > ? ORDER BY ref COLLATE BINARY LIMIT ?',
                (self.scope.scope_digest,kind,after,limit)):
            yield ref,stream,ordinal,commitment

    def begin_round(self):
        if not self.db.in_transaction: raise C09PagedCaptureHold('closure round requires the candidate transaction')
        state=self._state()
        if state[3]=='sealed': raise C09PagedCaptureHold('fixed point cannot reopen')
        self.db.execute("UPDATE c09_closure_state_v2 SET round=round+1,round_generation=member_generation,phase='expand',cursor_json='null' WHERE scope_digest=?",(self.scope.scope_digest,))

    def finish_round(self,*,actual_scan_eof_digest):
        # Producer supplies the complete typed provenance/edge stream EOF; a
        # short member page cannot make a fixed-point statement.
        if not self.db.in_transaction or type(actual_scan_eof_digest) is not str or len(actual_scan_eof_digest)!=64:
            raise C09PagedCaptureHold('actual complete closure scan required')
        state=self._state()
        if state[3]!='expand': raise C09PagedCaptureHold('closure round is not active')
        complete=state[1]==state[2]
        self.db.execute('UPDATE c09_closure_state_v2 SET phase=?,cursor_json=? WHERE scope_digest=?',
            ('sealed' if complete else 'collect',canonical_serialize({'scan_eof_digest':actual_scan_eof_digest,'member_generation':state[1]}),self.scope.scope_digest))
        return complete

    def scan_nested_value_page(self,value,*,kind,after_ref,budget):
        """Preserve V1 substring and serialized-json semantics per pattern page.

        A false result without eof is a continuation, never proof of no hits.
        Graph producer persists the original row locator and this pattern cursor,
        not the row value, when a round needs another quantum.
        """
        if kind not in {'atom','source_id'}: raise ValueError('nested reference pattern family required')
        started=monotonic_ns();last=after_ref;count=0;encoded=0
        iterator=self.iter_members(kind,after_ref,budget.max_records)
        for ref,stream,ordinal,commitment in iterator:
            size=len(canonical_serialize((ref,stream,ordinal,commitment)).encode('utf-8'))
            if encoded+size>budget.max_bytes or monotonic_ns()-started>=budget.max_local_ns: break
            hit=_nested_pattern_hit(value,ref,source_id=kind=='source_id')
            count+=1;encoded+=size;last=ref
            if hit: return {'hit':True,'eof':False,'last_ref':last,'completed_records':count,'encoded_bytes':encoded,'elapsed_ns':monotonic_ns()-started}
        eof=self.db.execute('SELECT 1 FROM c09_closure_members_v2 WHERE scope_digest=? AND kind=? AND ref COLLATE BINARY > ? LIMIT 1',
            (self.scope.scope_digest,kind,'' if last is None else last)).fetchone() is None
        return {'hit':False,'eof':eof,'last_ref':last,'completed_records':count,'encoded_bytes':encoded,'elapsed_ns':monotonic_ns()-started}


def _nested_pattern_hit(value,pattern,*,source_id,field=''):
    if type(value) is str:
        if field.endswith('_json'):
            try: decoded=json.loads(value)
            except (TypeError,ValueError) as exc: raise C09PagedCaptureHold('unreadable nested serialized original') from exc
            return _nested_pattern_hit(decoded,pattern,source_id=source_id)
        return ('source' in field.lower() and value==pattern) if source_id else pattern in value
    if type(value) is list:
        return any(_nested_pattern_hit(item,pattern,source_id=source_id,field=field) for item in value)
    if type(value) is dict:
        return any(_nested_pattern_hit(item,pattern,source_id=source_id,field=name) for name,item in value.items())
    return False
