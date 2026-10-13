"""Bounded keyset capture in the already registered C09 candidate.

This module proves data integrity. Installed Control owns permissions, source
freeze, candidate inode, profile reservation and the scheduler around each call.
Capture metadata contains keys, descriptors and commitments, never source payloads.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import inspect
from dataclasses import asdict, dataclass
import codecs
import hashlib
import json
import sqlite3
from time import monotonic_ns

from ..runtime_contracts import canonical_serialize as _canonical_serialize, current_canonical_output_meter
from .c09_paged_capture_contract_v2 import (
    C09StreamIdentityV2, C09CaptureRecordV2, C09CountOriginalV2,
    C09PageCursorV2, C09CapturePageV2, C09CompleteStreamV2,
    begin_c09_stream_v2, append_c09_page_v2, verify_c09_page_v2,
    seal_c09_stream_v2, verify_c09_complete_stream_v2,
    c09_paged_value_from_wire_v2, meter_c09_commitments_v2,
)

_QUANTUM_METER_V2=ContextVar('c09-sql-quantum-meter-v2',default=None)
_CAPTURE_ROW_POSITION_V2=ContextVar('c09-capture-row-position-v2',default=None)


def peek_current_c09_sql_meter_v3():
    """Return the existing quantum only; ordinary paths have no C09 meter."""
    return _QUANTUM_METER_V2.get()


def current_c09_sql_meter_v2():
    meter=_QUANTUM_METER_V2.get()
    if meter is None:raise C09PagedCaptureHold('actual reserved C09 quantum meter absent')
    return meter


def require_c09_reserved_meter_v3(budget):
    """Borrow the real reserved root; a reduced step ceiling never resets it."""
    if type(budget) is not C09BatchBudgetV2:
        raise TypeError('actual C09 step budget required')
    meter=current_c09_sql_meter_v2()
    if type(meter) is not C09SqlByteMeterV2:
        raise C09PagedCaptureHold('actual reserved SQL root meter required')
    if any(getattr(budget,name)>getattr(meter.budget,name) for name in (
            'max_records','max_bytes','max_local_ns','max_read_ns','reserved_arena_bytes')):
        raise C09PagedCaptureHold('child step exceeds its actual reserved root')
    return meter


@contextmanager
def c09_sql_meter_quantum_v2(meter):
    """Bind the installed caller's actual shared meter to named SQL codecs."""
    prior=_QUANTUM_METER_V2.get()
    if prior is not None and prior is not meter:
        raise C09PagedCaptureHold('nested C09 codec cannot replace the actual reserved root')
    token=_QUANTUM_METER_V2.set(meter)
    try:
        with meter_c09_commitments_v2(meter):yield meter
    finally:_QUANTUM_METER_V2.reset(token)


def current_c09_capture_row_position_v2():
    value=_CAPTURE_ROW_POSITION_V2.get()
    if value is None:raise C09PagedCaptureHold('actual capture-row position absent')
    return value


def canonical_serialize(value):
    return _canonical_serialize(value)


def canonical_digest(value):
    return hashlib.sha256(canonical_serialize(value).encode('utf-8')).hexdigest()


def c09_canonical_json_size_v3(value,*,ascii=True,spaced=False,typed=False,exact=False):
    """Encoding size without allocating an extra serialization."""
    from dataclasses import fields,is_dataclass
    def quoted(text):
        total=2
        for char in text:
            point=ord(char)
            total+=2 if point in (34,92,8,12,10,13,9) else 6 if point<32 else (
                6 if point<=65535 else 12) if ascii and point>=127 else (
                1 if point<128 else 2 if point<2048 else 3 if point<=65535 else 4)
        return total
    if value is None:return 4
    if type(value) is bool:return 4 if value else 5
    if type(value) is str:return quoted(value)
    if type(value) is int:return len(str(value)) if exact else (value.bit_length()*30103)//100000+3
    if type(value) is float:return len(str(value)) if exact else 128
    if is_dataclass(value):
        members=[(field.name,getattr(value,field.name)) for field in fields(value)]
        if typed:members.append(('$type',type(value).__module__+'.'+type(value).__qualname__))
    elif type(value) is dict:members=value.items()
    else:
        return 2+max(0,len(value)-1)*(2 if spaced else 1)+sum(
            c09_canonical_json_size_v3(item,ascii=ascii,spaced=spaced,typed=typed,exact=exact) for item in value)
    members=tuple(members)
    return 2+max(0,len(members)-1)*(2 if spaced else 1)+sum(quoted(key)+(2 if spaced else 1)+
        c09_canonical_json_size_v3(item,ascii=ascii,spaced=spaced,typed=typed,exact=exact) for key,item in members)


def _metered_c09_quantum_v2(function):
    signature=inspect.signature(function)
    @wraps(function)
    def run(*args,meter=None,**kwargs):
        bound=signature.bind(*args,**kwargs);budget=bound.arguments['budget']
        actual=require_c09_reserved_meter_v3(budget)
        if meter is not None and meter is not actual:
            raise C09PagedCaptureHold('codec meter differs from its actual reserved root')
        before=actual.consumed_bytes
        token=_QUANTUM_METER_V2.set(actual)
        try:
            with meter_c09_commitments_v2(actual):
                result=function(*args,**kwargs)
            if type(result) is dict:
                result['actual_meter_bytes']=actual.consumed_bytes-before
            return result
        finally:_QUANTUM_METER_V2.reset(token)
    return run


LOGICAL_SOURCE_DDL_V3 = "CREATE TABLE c09_logical_source_rows_v3 (scope_digest TEXT NOT NULL, role TEXT NOT NULL, table_name TEXT NOT NULL, key_digest TEXT NOT NULL, primary_key_json TEXT NOT NULL, descriptor_json TEXT NOT NULL, descriptor_digest TEXT NOT NULL, physical_row_commitment TEXT NOT NULL, logical_row_commitment TEXT NOT NULL, source_role_digest TEXT NOT NULL, physical_schema_digest TEXT NOT NULL, logical_shape_digest TEXT NOT NULL, origin_stream_id TEXT NOT NULL, origin_record_ordinal INTEGER NOT NULL, PRIMARY KEY(scope_digest,role,table_name,key_digest), UNIQUE(origin_stream_id,origin_record_ordinal), FOREIGN KEY(origin_stream_id,origin_record_ordinal) REFERENCES c09_capture_members_v2(stream_id,record_ordinal) DEFERRABLE INITIALLY DEFERRED)"
LOGICAL_SOURCE_COLUMNS_V3 = ('primary_key_json','descriptor_json','descriptor_digest',
    'physical_row_commitment','logical_row_commitment','source_role_digest',
    'physical_schema_digest','logical_shape_digest','origin_stream_id','origin_record_ordinal')


CAPTURE_DDLS_V2 = {
    "c09_logical_source_rows_v3": LOGICAL_SOURCE_DDL_V3,
    "c09_capture_streams_v2": "CREATE TABLE c09_capture_streams_v2 (stream_id TEXT PRIMARY KEY, scope_digest TEXT NOT NULL, role_source_digest TEXT NOT NULL, identity_json TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','sealed')), seal_json TEXT)",
    "c09_capture_pages_v2": "CREATE TABLE c09_capture_pages_v2 (stream_id TEXT NOT NULL, page_index INTEGER NOT NULL, descriptor_json TEXT NOT NULL, records_json TEXT NOT NULL, PRIMARY KEY(stream_id,page_index), FOREIGN KEY(stream_id) REFERENCES c09_capture_streams_v2(stream_id))",
    "c09_capture_members_v2": "CREATE TABLE c09_capture_members_v2 (stream_id TEXT NOT NULL, record_ordinal INTEGER NOT NULL, key_digest TEXT NOT NULL, primary_key_json TEXT NOT NULL, commitment TEXT NOT NULL, page_index INTEGER NOT NULL, PRIMARY KEY(stream_id,record_ordinal), UNIQUE(stream_id,key_digest), FOREIGN KEY(stream_id,page_index) REFERENCES c09_capture_pages_v2(stream_id,page_index) DEFERRABLE INITIALLY DEFERRED)",
    "c09_capture_progress_v2": "CREATE TABLE c09_capture_progress_v2 (stream_id TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('census','data')), progress_json TEXT NOT NULL, PRIMARY KEY(stream_id,phase), FOREIGN KEY(stream_id) REFERENCES c09_capture_streams_v2(stream_id))",
}
CAPTURE_TRIGGERS_V2 = tuple(
    (f"{table}_{action.lower()}_immutable", f"CREATE TRIGGER {table}_{action.lower()}_immutable BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'immutable C09 capture original'); END")
    for table in ("c09_capture_pages_v2", "c09_capture_members_v2", "c09_logical_source_rows_v3")
    for action in ("UPDATE", "DELETE")
)
CAPTURE_TABLES_V2 = frozenset(CAPTURE_DDLS_V2)


class C09PagedCaptureHold(RuntimeError):
    """No complete seal is available for this actual capture."""


@dataclass(frozen=True, slots=True)
class C09BatchBudgetV2:
    max_records: int
    max_bytes: int
    max_local_ns: int
    max_read_ns: int
    reserved_arena_bytes: int

    def __post_init__(self):
        for value, ceiling in ((self.max_records,100),(self.max_bytes,262144),
                (self.max_local_ns,25000000),(self.max_read_ns,250000000),
                (self.reserved_arena_bytes,8388608)):
            if type(value) is not int or not 0 < value <= ceiling:
                raise ValueError("actual installed C09 batch reservation exceeds its profile")
        if self.reserved_arena_bytes < self.max_bytes * 8:
            raise ValueError("C09 input/decoder/page copies lack a batch arena reservation")


class C09SqlByteMeterV2:
    """One installed reserved quantum; scalar SQL I/O and codec byte account."""
    __slots__=('budget','read_bytes','written_bytes','encoded_bytes','started_ns','sql_mutations')

    def __init__(self,budget):
        if type(budget) is not C09BatchBudgetV2: raise TypeError('actual reserved batch budget required')
        self.budget=budget;self.read_bytes=0;self.written_bytes=0;self.encoded_bytes=0;self.started_ns=monotonic_ns();self.sql_mutations=0

    @property
    def consumed_bytes(self): return self.read_bytes+self.written_bytes+self.encoded_bytes

    @property
    def available_bytes(self): return self.budget.max_bytes-self.consumed_bytes

    @property
    def remaining_bytes(self): return self.available_bytes

    def count_mutation(self): self.sql_mutations+=1

    def charge_encode(self,count): self.charge_encoded_bytes(count)

    def require_available(self,count):
        if type(count) is not int or count<0: raise ValueError('actual nonnegative byte size required')
        if count>self.available_bytes: raise C09PagedCaptureHold('actual codec quantum needs continuation before this I/O')

    def charge_read(self,count): self.require_available(count);self.read_bytes+=count
    def charge_write(self,count): self.require_available(count);self.written_bytes+=count
    def charge_encoded_bytes(self,count): self.require_available(count);self.encoded_bytes+=count

    def read_row(self,source,shape,key):
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
        return self.read_fixed_row(source,shape.table,shape.columns,where,key)

    def read_fixed_row(self,source,table,columns,where,args):
        # where is a named producer's fixed point-lookup expression, never an IPC
        # selector. Size is observed before SQLite transfers payload to Python.
        sizes=','.join('length(CAST('+_quote(name)+' AS BLOB))' for name in columns)
        lengths=source.execute('SELECT '+sizes+' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1',args).fetchone()
        if lengths is None: return None
        size=sum(0 if value is None else value for value in lengths)
        if size*6+32*len(columns)>self.budget.max_bytes or size*8>self.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('point-lookup cell requires its registered streaming codec')
        self.charge_read(size)
        return source.execute('SELECT '+','.join(_quote(name) for name in columns)+' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1',args).fetchone()

    def write_row(self,candidate,table,columns,row):
        if not candidate.in_transaction or len(columns)!=len(row): raise C09PagedCaptureHold('metered target row requires its page transaction')
        size=sum(_sql_scalar_size_v2(value) for value in row)
        self.charge_write(size);self.count_mutation()
        candidate.execute('INSERT INTO '+_quote(table)+' ('+','.join(_quote(name) for name in columns)+') VALUES ('+','.join('?' for _ in row)+')',row)
        return size

    def encode(self,value,*,reserved_max_bytes):
        self.require_available(reserved_max_bytes)
        if reserved_max_bytes*8>self.budget.reserved_arena_bytes: raise C09PagedCaptureHold('codec encoding lacks the actual arena reservation')
        wire=canonical_serialize(value);size=len(wire.encode('utf-8'))
        if size>reserved_max_bytes: raise C09PagedCaptureHold('actual codec exceeded its preread encoding reservation')
        if current_canonical_output_meter() is not self:self.charge_encoded_bytes(size)
        return wire


def c09_row_commitment_v2(row):
    """Exact V1 row bytes, with the actual local encoding meter applied."""
    return canonical_digest(tuple({'blob_sha256':hashlib.sha256(item).hexdigest(),'size':len(item)}
        if type(item) is bytes else item for item in row))


def _sql_scalar_size_v2(value):
    if value is None:return 0
    if type(value) is bytes:return len(value)
    if type(value) is str:return len(value.encode('utf-8'))
    if type(value) in {int,float}:return len(str(value).encode('ascii'))
    raise C09PagedCaptureHold('target SQL value requires its closed scalar codec')


@dataclass(frozen=True, slots=True)
class C09RowTransformResultV2:
    commitment: str
    related_read_bytes: int
    target_write_bytes: int

    def __post_init__(self):
        if any(type(value) is not int or value<0 for value in (self.related_read_bytes,self.target_write_bytes)):
            raise ValueError("actual codec I/O byte counters required")


@dataclass(frozen=True, slots=True)
class C09TableShapeV2:
    table: str
    columns: tuple[str,...]
    primary_key_columns: tuple[str,...]
    primary_key_types: tuple[str,...]
    schema_digest: str


def _quote(name):
    if type(name) is not str or not name or '\x00' in name:
        raise C09PagedCaptureHold("invalid installed SQL identifier")
    return '"' + name.replace('"','""') + '"'


def _capture_write_v2(candidate,sql,args=()):
    meter=_QUANTUM_METER_V2.get()
    if meter is not None:
        meter.charge_write(sum(_sql_scalar_size_v2(value) for value in args));meter.count_mutation()
    return candidate.execute(sql,args)


def _bounded_capture_row(candidate,table,columns,where,args,limits):
    sizes=','.join('length(CAST('+_quote(name)+' AS BLOB))' for name in columns)
    sizes_row=candidate.execute('SELECT '+sizes+' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1',args).fetchone()
    if sizes_row is None: return None
    if any(size is not None and size>limit for size,limit in zip(sizes_row,limits)):
        raise C09PagedCaptureHold("capture metadata exceeds its codec before materialization")
    active=_QUANTUM_METER_V2.get()
    if active is not None:active.charge_read(sum(0 if size is None else size for size in sizes_row))
    return candidate.execute('SELECT '+','.join(_quote(name) for name in columns)+' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1',args).fetchone()


def _capture_data_state(candidate,stream):
    row=_bounded_capture_row(candidate,'c09_capture_progress_v2',('progress_json',),"stream_id=? AND phase='data'",(stream.stream_id,),(65536,))
    if row is None: raise C09PagedCaptureHold("capture data progress absent")
    raw=json.loads(row[0])
    if set(raw)!= {'cursor','eof'}: raise C09PagedCaptureHold("capture data progress schema differs")
    return raw


def _wire(value):
    wire=json.dumps(asdict(value),sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
    meter=_QUANTUM_METER_V2.get()
    if meter is not None:meter.charge_encode(len(wire.encode('utf-8')))
    return wire


def _decoded(raw, cls):
    if len(raw.encode('utf-8')) > 262144:
        raise C09PagedCaptureHold("capture metadata exceeds its bounded codec")
    return c09_paged_value_from_wire_v2(json.loads(raw),cls)


@contextmanager
def capture_transaction_v2(candidate):
    if candidate.in_transaction:
        raise C09PagedCaptureHold("C09 page owns one candidate transaction")
    candidate.execute('BEGIN IMMEDIATE')
    try:
        yield
        candidate.commit()
    except BaseException:
        candidate.rollback()
        raise


@contextmanager
def capture_read_transaction_v2(candidate):
    if candidate.in_transaction: raise C09PagedCaptureHold('cold verifier owns its bounded read transaction')
    candidate.execute('BEGIN')
    try: yield
    finally: candidate.rollback()


def install_c09_capture_schema_v2(candidate):
    """Called only for the Control-registered candidate before any capture."""
    for name, ddl in CAPTURE_DDLS_V2.items():
        found=candidate.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
        if found is None:
            candidate.execute(ddl)
        elif found[0] != ddl:
            raise C09PagedCaptureHold("registered capture table schema differs: "+name)
    for name, ddl in CAPTURE_TRIGGERS_V2:
        found=candidate.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(name,)).fetchone()
        if found is None:
            candidate.execute(ddl)
        elif found[0] != ddl:
            raise C09PagedCaptureHold("registered capture original trigger differs")


def read_c09_table_shape_v2(source, table, *, meter=None):
    """Resolve actual frozen schema; optional meter is the caller's real quantum."""
    if meter is None:
        original=source.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
    else:
        meter.require_available(65536)
        statement="SELECT CASE WHEN length(sql)<=16384 THEN sql ELSE NULL END FROM sqlite_master WHERE type='table' AND name=?"
        meter.charge_encode(len(statement.encode('utf-8'))+len(table.encode('utf-8')))
        original=source.execute(statement,(table,)).fetchone()
        meter.charge_read(0 if original is None else sum(_sql_scalar_size_v2(v) for v in original))
    if original is None or original[0] is None or 'VIRTUAL TABLE' in original[0].upper():
        raise C09PagedCaptureHold("table requires a registered stable-key codec")
    statement=f'PRAGMA table_xinfo({_quote(table)})'
    if meter is not None:
        meter.require_available(65536);meter.charge_encode(len(statement.encode('utf-8')))
        metadata=tuple(source.execute(statement).fetchmany(101))
        if len(metadata)>100:raise C09PagedCaptureHold('actual metered schema exceeds fixed column bound')
        meter.charge_read(sum(sum(_sql_scalar_size_v2(v) for v in row) for row in metadata))
    else:
        metadata=tuple(source.execute(statement))
    if len(canonical_serialize(metadata).encode('utf-8')) > 65536 or any(row[6] for row in metadata):
        raise C09PagedCaptureHold("table schema is outside its descriptor codec")
    primary=tuple(sorted((row for row in metadata if row[5]),key=lambda row:row[5]))
    if not primary:
        raise C09PagedCaptureHold("table has no actual unique primary key")
    key_types=tuple('integer' if row[2].upper()=='INTEGER' else 'text' if row[2].upper()=='TEXT' else '' for row in primary)
    if not all(key_types):
        raise C09PagedCaptureHold("primary-key storage type needs a named codec")
    statement=f'PRAGMA index_list({_quote(table)})'
    if meter is not None:
        meter.require_available(65536);meter.charge_encode(len(statement.encode('utf-8')))
        indexes=source.execute(statement).fetchmany(101)
        if len(indexes)>100:raise C09PagedCaptureHold('actual metered schema exceeds fixed index bound')
        meter.charge_read(sum(sum(_sql_scalar_size_v2(v) for v in row) for row in indexes))
    else:indexes=source.execute(statement)
    for index in indexes:
        if index[3]=='pk':
            statement=f'PRAGMA index_xinfo({_quote(index[1])})'
            if meter is not None:
                meter.require_available(65536);meter.charge_encode(len(statement.encode('utf-8')))
                rows=source.execute(statement).fetchmany(101)
                if len(rows)>100:raise C09PagedCaptureHold('actual metered primary index exceeds fixed column bound')
                meter.charge_read(sum(sum(_sql_scalar_size_v2(v) for v in row) for row in rows))
            else:rows=source.execute(statement)
            for row in rows:
                if row[5] and (row[3] or row[4]!='BINARY'):
                    raise C09PagedCaptureHold("primary-key order is not registered BINARY ASC")
    return C09TableShapeV2(table,tuple(row[1] for row in metadata),tuple(row[1] for row in primary),key_types,
        canonical_digest(('sylanne3.c09.sql-schema.v2',table,original[0],metadata)))


def _physical_source_shape_v3(shape, *, source=None):
    """Keep physical SQL columns distinct from the issued logical stream identity."""
    if type(shape) is C09TableShapeV2:
        return shape
    from .c09_logical_source_v3 import require_logical_source_shape_v3
    return require_logical_source_shape_v3(shape, source=source)


def _keyset(shape,last_key):
    shape=_physical_source_shape_v3(shape)
    columns=shape.primary_key_columns
    if last_key is None:
        return '',()
    if type(last_key) is not tuple or len(last_key)!=len(columns):
        raise C09PagedCaptureHold("durable cursor primary-key shape differs")
    expected={'text':str,'integer':int}
    if any(type(value) is not expected[kind] for value,kind in zip(last_key,shape.primary_key_types)):
        raise C09PagedCaptureHold("durable cursor primary-key type differs")
    predicate=' OR '.join('('+' AND '.join([*(_quote(columns[j])+' COLLATE BINARY = ?' for j in range(i)),_quote(columns[i])+' COLLATE BINARY > ?'])+')' for i in range(len(columns)))
    parameters=tuple(last_key[j] for i in range(len(columns)) for j in range(i+1))
    return ' WHERE '+predicate,parameters


def read_c09_next_row_metadata_v2(source,shape,last_key):
    shape=_physical_source_shape_v3(shape,source=source)
    clause,args=_keyset(shape,last_key)
    key_size='+'.join('length(CAST('+_quote(name)+' AS BLOB))' for name in shape.primary_key_columns)
    keys=','.join('CASE WHEN ('+key_size+')<=65536 THEN '+_quote(name)+' ELSE NULL END' for name in shape.primary_key_columns)
    cells=','.join(f'typeof({_quote(name)}),length(CAST({_quote(name)} AS BLOB))' for name in shape.columns)
    order=','.join(_quote(name)+' COLLATE BINARY ASC' for name in shape.primary_key_columns)
    row=source.execute(f'SELECT {keys},{cells} FROM {_quote(shape.table)}{clause} ORDER BY {order} LIMIT 1',args).fetchone()
    if row is None:
        return None
    count=len(shape.primary_key_columns); key=tuple(row[:count]); _keyset(shape,key)
    metadata=tuple((row[i],row[i+1]) for i in range(count,len(row),2))
    if any(kind not in {'null','integer','real','text','blob'} for kind,_ in metadata):
        raise C09PagedCaptureHold("unknown SQLite cell representation")
    active=_QUANTUM_METER_V2.get()
    if active is not None:active.charge_read(sum(_sql_scalar_size_v2(value) for value in row))
    return key,metadata




def _read_c09_scoped_row_metadata_v3(source,shape,last_key,row_scope):
    """Private Control projection query; the namespace prefix is real PK data."""
    shape=_physical_source_shape_v3(shape,source=source)
    if row_scope is None:return read_c09_next_row_metadata_v2(source,shape,last_key)
    if (shape.primary_key_columns[:2]!=('scope_digest','role') or type(row_scope) is not tuple
            or len(row_scope)!=2 or any(type(value) is not str for value in row_scope)):
        raise C09PagedCaptureHold('registered actual Control projection scope required')
    clause,args=_keyset(shape,last_key)
    where=' WHERE scope_digest=? AND role=?'
    if clause:where+=' AND ('+clause[len(' WHERE '):]+')'
    key_size='+'.join('length(CAST('+_quote(name)+' AS BLOB))' for name in shape.primary_key_columns)
    keys=','.join('CASE WHEN ('+key_size+')<=65536 THEN '+_quote(name)+' ELSE NULL END' for name in shape.primary_key_columns)
    cells=','.join('typeof('+_quote(name)+'),length(CAST('+_quote(name)+' AS BLOB))' for name in shape.columns)
    order=','.join(_quote(name)+' COLLATE BINARY ASC' for name in shape.primary_key_columns)
    row=source.execute('SELECT '+keys+','+cells+' FROM '+_quote(shape.table)+where+' ORDER BY '+order+' LIMIT 1',(*row_scope,*args)).fetchone()
    if row is None:return None
    count=len(shape.primary_key_columns);key=tuple(row[:count]);_keyset(shape,key)
    if key[:2]!=row_scope:raise C09PagedCaptureHold('actual Control projection key crossed its registered scope')
    metadata=tuple((row[index],row[index+1]) for index in range(count,len(row),2))
    active=current_c09_sql_meter_v2()
    if active is not None:active.charge_read(sum(_sql_scalar_size_v2(value) for value in row))
    return key,metadata


def read_c09_materialized_row_v2(source,shape,key,metadata,budget):
    # Reserve before SQLite loads TEXT/BLOB and before any JSON decoder runs.
    raw_bytes=sum(0 if size is None else size for _,size in metadata)
    worst_encoded_bytes=6*raw_bytes+32*len(metadata)+2
    if worst_encoded_bytes>budget.max_bytes or worst_encoded_bytes*8>budget.reserved_arena_bytes:
        raise C09PagedCaptureHold("row requires its registered streaming cell codec")
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    active=_QUANTUM_METER_V2.get()
    if active is not None:active.charge_read(raw_bytes)
    row=source.execute(f'SELECT * FROM {_quote(shape.table)} WHERE {where} LIMIT 1',key).fetchone()
    if row is None:
        raise C09PagedCaptureHold("frozen census row disappeared")
    return tuple(row)


def begin_capture_stream_v2(candidate,stream):
    if type(stream) is not C09StreamIdentityV2:
        raise TypeError("versioned actual stream identity required")
    identity=_wire(stream); saved=_bounded_capture_row(candidate,'c09_capture_streams_v2',('identity_json',),'stream_id=?',(stream.stream_id,),(65536,))
    if saved is not None:
        if saved[0]!=identity:
            raise C09PagedCaptureHold("capture stream identity reused")
        return read_capture_cursor_v2(candidate,stream)
    if not candidate.in_transaction:
        raise C09PagedCaptureHold('stream registration must commit with its candidate progress')
    cursor=begin_c09_stream_v2(stream)
    _capture_write_v2(candidate,'INSERT INTO c09_capture_streams_v2 VALUES (?,?,?,?,?,NULL)',(stream.stream_id,stream.scope_digest,stream.role_source_digest,identity,'open'))
    _capture_write_v2(candidate,'INSERT INTO c09_capture_progress_v2 VALUES (?,?,?)',(stream.stream_id,'data',canonical_serialize({'cursor':asdict(cursor),'eof':None})))
    census={'count':0,'last_key':None,'chain':canonical_digest(('sylanne3.c09.census.v2',stream.stream_id)),'eof':None,'original':None}
    _capture_write_v2(candidate,'INSERT INTO c09_capture_progress_v2 VALUES (?,?,?)',(stream.stream_id,'census',canonical_serialize(census)))
    return cursor


def read_capture_cursor_v2(candidate,stream):
    raw=_capture_data_state(candidate,stream)
    cursor=c09_paged_value_from_wire_v2(raw['cursor'],C09PageCursorV2)
    if cursor.stream_id!=stream.stream_id:
        raise C09PagedCaptureHold("capture cursor belongs to another frozen source")
    return cursor


@_metered_c09_quantum_v2
def advance_c09_census_v2(source,candidate,stream,shape,budget,*,check_frozen_source):
    """Advance one actual reserved page with exclusive transaction ownership."""
    _require_stream_shape(stream,shape);check_frozen_source()
    if source.in_transaction or not source.execute('PRAGMA query_only').fetchone()[0]:
        raise C09PagedCaptureHold('census requires frozen readonly source outside SQL')
    with capture_transaction_v2(candidate):
        result=_advance_c09_census_in_transaction_v3(source,candidate,stream,shape,budget,check_frozen_source=check_frozen_source)
    check_frozen_source()
    return result


def _advance_c09_census_in_transaction_v3(source,candidate,stream,shape,budget,*,check_frozen_source,row_scope=None):
    """Internal body for an owner-issued protected Control transaction."""
    if not candidate.in_transaction:raise C09PagedCaptureHold('owned capture transaction required')
    _require_stream_shape(stream,shape);check_frozen_source()
    if source.in_transaction or not source.execute('PRAGMA query_only').fetchone()[0]:
        raise C09PagedCaptureHold('census requires frozen readonly source outside SQL')
    started=monotonic_ns()
    raw=_bounded_capture_row(candidate,'c09_capture_progress_v2',('progress_json',),"stream_id=? AND phase='census'",(stream.stream_id,),(65536,))
    if raw is None: raise C09PagedCaptureHold("independent census is unregistered")
    value=json.loads(raw[0]);last=None if value['last_key'] is None else tuple(value['last_key'])
    completed=0;encoded=0;source.execute('BEGIN');read_started=monotonic_ns()
    try:
        while value['eof'] is None and completed<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
            found=_read_c09_scoped_row_metadata_v3(source,shape,last,row_scope)
            if found is None:
                value['eof']=canonical_digest(('sylanne3.c09.census-eof.v2',stream.stream_id,value['count'],last,value['chain']))
                break
            key,metadata=found;size=len(canonical_serialize((key,metadata)).encode('utf-8'))
            if size>budget.max_bytes: raise C09PagedCaptureHold("one census descriptor exceeds its batch")
            if encoded+size>budget.max_bytes: break
            value['count']+=1;completed+=1;encoded+=size
            value['chain']=canonical_digest(('sylanne3.c09.census-row.v2',stream.stream_id,value['count'],value['chain'],key,metadata))
            last=key;value['last_key']=key
    finally: source.rollback()
    read_elapsed=monotonic_ns()-read_started
    if read_elapsed>budget.max_read_ns:
        raise C09PagedCaptureHold('actual census read transaction exceeded its installed duration')
    if value['eof'] is not None:
        ref='c09-count:'+canonical_digest((stream.stream_id,value['chain'],value['eof']))
        census=C09CountOriginalV2(stream.stream_id,value['count'],last,value['eof'],ref,
            canonical_digest(('sylanne3.c09.actual-count-original.v2',stream.stream_id,value['count'],last,value['chain'],value['eof'])))
        value['original']=asdict(census)
    _capture_write_v2(candidate,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='census'",(canonical_serialize(value),stream.stream_id))
    return {'completed_records': completed, 'encoded_bytes': encoded, 'read_transaction_ns': read_elapsed, 'resource_quantum_within_limit': monotonic_ns() - started <= budget.max_local_ns, 'elapsed_ns': monotonic_ns() - started, 'eof': value['eof'] is not None}


def _require_stream_shape(stream,shape):
    physical=_physical_source_shape_v3(shape)
    digest=shape.schema_digest if type(shape) is C09TableShapeV2 else shape.logical_shape_digest
    if (stream.schema_digest!=digest
            or stream.primary_key_columns!=physical.primary_key_columns
            or stream.primary_key_types!=physical.primary_key_types):
        raise C09PagedCaptureHold("stream identity does not bind its actual installed table")

def _load_census(candidate,stream):
    row=_bounded_capture_row(candidate,'c09_capture_progress_v2',('progress_json',),"stream_id=? AND phase='census'",(stream.stream_id,),(65536,))
    if row is None: raise C09PagedCaptureHold("independent census original absent")
    value=json.loads(row[0])
    if value['eof'] is None or value['original'] is None:
        raise C09PagedCaptureHold("independent census has not observed the real EOF")
    original=c09_paged_value_from_wire_v2(value['original'],C09CountOriginalV2)
    expected=canonical_digest(('sylanne3.c09.actual-count-original.v2',stream.stream_id,value['count'],
        value['last_key'],value['chain'],value['eof']))
    if (original.stream_id!=stream.stream_id or original.record_count!=value['count']
            or original.original_digest!=expected or original.eof_observation_digest!=value['eof']):
        raise C09PagedCaptureHold("independent census original differs from its actual persisted sweep")
    return original


def _page_metadata_size_v2(template,cursor,last_key,count,proof_bytes,records_json_bytes,member_bytes):
    # All commitments in this closed schema are 64 ASCII hex characters. Their
    # values do not change descriptor length. Only these position fields vary.
    descriptor=dict(template);position=dict(template['next_cursor'])
    descriptor.update(record_count=count,encoded_bytes=proof_bytes)
    position.update(record_offset=cursor.record_offset+count,encoded_bytes=cursor.encoded_bytes+proof_bytes,last_key=last_key)
    descriptor['next_cursor']=position
    wire=json.dumps(descriptor,sort_keys=True,separators=(',',':'),ensure_ascii=True)
    # Reserve the actual possible data EOF digest (not a future receipt).
    progress=canonical_serialize({'cursor':position,'eof':'0'*64})
    return len(wire.encode('utf-8'))+records_json_bytes+member_bytes+len(progress.encode('utf-8'))


@_metered_c09_quantum_v2
def advance_c09_rows_v2(source,candidate,stream,shape,budget,*,check_frozen_source,transform_row,stream_row_boundary=None):
    """Advance one actual reserved page with exclusive transaction ownership."""
    _require_stream_shape(stream,shape);check_frozen_source()
    if source.in_transaction or not source.execute('PRAGMA query_only').fetchone()[0]:
        raise C09PagedCaptureHold('capture requires frozen readonly source outside SQL')
    with capture_transaction_v2(candidate):
        result=_advance_c09_rows_in_transaction_v3(source,candidate,stream,shape,budget,check_frozen_source=check_frozen_source,transform_row=transform_row,stream_row_boundary=stream_row_boundary)
    check_frozen_source()
    return result


def _advance_c09_rows_in_transaction_v3(source,candidate,stream,shape,budget,*,check_frozen_source,transform_row,stream_row_boundary=None,max_page_records=None,row_scope=None):
    """Internal body for an owner-issued protected Control transaction."""
    if not candidate.in_transaction:raise C09PagedCaptureHold('owned capture transaction required')
    _require_stream_shape(stream,shape);check_frozen_source()
    if source.in_transaction or not source.execute('PRAGMA query_only').fetchone()[0]:
        raise C09PagedCaptureHold('capture requires frozen readonly source outside SQL')
    started=monotonic_ns()
    _load_census(candidate,stream)
    state=candidate.execute('SELECT status FROM c09_capture_streams_v2 WHERE stream_id=?',(stream.stream_id,)).fetchone()
    if state!=('open',): raise C09PagedCaptureHold("capture cannot append to a completed original")
    cursor=read_capture_cursor_v2(candidate,stream)
    data=_capture_data_state(candidate,stream)
    records=[];encoded=2;records_json_bytes=2;member_bytes=0;page_template=None;io_bytes=0;metadata_write_bytes=0;last=cursor.last_key;source.execute('BEGIN');read_started=monotonic_ns()
    try:
        while data['eof'] is None and len(records)<min(budget.max_records,max_page_records if max_page_records is not None else budget.max_records) and monotonic_ns()-started<budget.max_local_ns:
            found=_read_c09_scoped_row_metadata_v3(source,shape,last,row_scope)
            if found is None:
                data['eof']=canonical_digest(('sylanne3.c09.data-eof.v2',stream.stream_id,
                    cursor.record_offset+len(records),last))
                break
            key,metadata=found
            if stream_row_boundary is not None and stream_row_boundary(shape,key,metadata):
                if not records:raise C09PagedCaptureHold('registered streaming row must use its actual bounded producer')
                break
            source_bytes=sum(0 if size is None else size for _,size in metadata)
            metadata_bytes=len(canonical_serialize((key,metadata)).encode('utf-8'))
            if io_bytes+source_bytes+metadata_bytes+encoded>=budget.max_bytes:
                if not records: raise C09PagedCaptureHold('one source row requires its streaming codec')
                break
            io_bytes+=source_bytes+metadata_bytes
            row=read_c09_materialized_row_v2(source,shape,key,metadata,budget)
            candidate.execute('SAVEPOINT c09_record_v2')
            position_token=_CAPTURE_ROW_POSITION_V2.set((stream.stream_id,cursor.record_offset+len(records)+1))
            try:result=transform_row(candidate,shape,key,row,budget.max_bytes-io_bytes-encoded)
            finally:_CAPTURE_ROW_POSITION_V2.reset(position_token)
            if type(result) is not C09RowTransformResultV2:
                raise TypeError('actual typed row codec I/O accounting required')
            io_bytes+=result.related_read_bytes
            record=C09CaptureRecordV2(key,result.commitment)
            next_bytes=len(canonical_serialize(record).encode('utf-8'))
            if next_bytes>budget.max_bytes:
                raise C09PagedCaptureHold("one proof record exceeds the actual page budget")
            prospective=encoded+next_bytes+(1 if records else 0)
            if page_template is None: page_template=asdict(append_c09_page_v2(stream,cursor,(record,)))
            next_records_json=records_json_bytes+len(_wire(record).encode('utf-8'))+(1 if records else 0)
            next_member_bytes=member_bytes+len(canonical_serialize((stream.stream_id,cursor.record_offset+len(records)+1,
                canonical_digest(key),canonical_serialize(key),record.commitment,cursor.page_index)).encode('utf-8'))
            prospective_metadata=_page_metadata_size_v2(page_template,cursor,key,len(records)+1,prospective,next_records_json,next_member_bytes)
            if io_bytes+result.target_write_bytes+prospective_metadata>budget.max_bytes:
                candidate.execute('ROLLBACK TO c09_record_v2');candidate.execute('RELEASE c09_record_v2')
                if not records: raise C09PagedCaptureHold('actual row codec exceeds its complete quantum')
                break
            io_bytes+=result.target_write_bytes
            metadata_write_bytes=prospective_metadata;records_json_bytes=next_records_json;member_bytes=next_member_bytes
            candidate.execute('RELEASE c09_record_v2')
            records.append(record);encoded=prospective;last=key
    finally: source.rollback()
    read_elapsed=monotonic_ns()-read_started
    if read_elapsed>budget.max_read_ns:
        raise C09PagedCaptureHold('actual source read transaction exceeded its installed duration')
    page=None
    if records:
        page=append_c09_page_v2(stream,cursor,tuple(records))
        if page.encoded_bytes!=encoded or metadata_write_bytes+io_bytes>budget.max_bytes:
            raise C09PagedCaptureHold("actual encoded page exceeds its installed reservation")
        _capture_write_v2(candidate,'INSERT INTO c09_capture_pages_v2 VALUES (?,?,?,?)',
            (stream.stream_id,page.page_index,_wire(page),json.dumps([asdict(row) for row in records],sort_keys=True,separators=(',',':'))))
        for offset,record in enumerate(records,1):
            _capture_write_v2(candidate,'INSERT INTO c09_capture_members_v2 VALUES (?,?,?,?,?,?)',
                (stream.stream_id,cursor.record_offset+offset,canonical_digest(record.primary_key),
                 canonical_serialize(record.primary_key),record.commitment,page.page_index))
        cursor=page.next_cursor
    data['cursor']=asdict(cursor)
    _capture_write_v2(candidate,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",
        (canonical_serialize(data),stream.stream_id))
    return {'page': page, 'cursor': cursor, 'completed_records': len(records), 'encoded_bytes': 0 if page is None else page.encoded_bytes, 'actual_io_bytes': io_bytes + metadata_write_bytes, 'read_transaction_ns': read_elapsed, 'resource_quantum_within_limit': monotonic_ns() - started <= budget.max_local_ns, 'elapsed_ns': monotonic_ns() - started, 'eof': data['eof'] is not None}


def seal_capture_stream_v2(candidate,stream):
    """Only producer EOF plus the separate persisted census can complete."""
    if not candidate.in_transaction: raise C09PagedCaptureHold("stream seal requires the candidate transaction")
    cursor=read_capture_cursor_v2(candidate,stream);census=_load_census(candidate,stream)
    data=_capture_data_state(candidate,stream)
    if data['eof'] is None: raise C09PagedCaptureHold("data stream has not observed actual EOF")
    seal=seal_c09_stream_v2(stream,cursor,census,data_eof_observation_digest=data['eof'])
    saved=_bounded_capture_row(candidate,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,),(16,65536))
    if saved is None: raise C09PagedCaptureHold("unregistered stream seal")
    if saved[0]=='sealed' and saved[1]!=_wire(seal): raise C09PagedCaptureHold("completed stream seal was replaced")
    _capture_write_v2(candidate,"UPDATE c09_capture_streams_v2 SET status='sealed',seal_json=? WHERE stream_id=?",(_wire(seal),stream.stream_id))
    return seal


def read_capture_page_v2(candidate,stream,page_index):
    row=_bounded_capture_row(candidate,'c09_capture_pages_v2',('descriptor_json','records_json'),'stream_id=? AND page_index=?',(stream.stream_id,page_index),(65536,262144))
    if row is None: raise C09PagedCaptureHold("capture page is missing")
    if sum(len(value.encode('utf-8')) for value in row)>524288:
        raise C09PagedCaptureHold("persisted page exceeds its bounded codec")
    page=_decoded(row[0],C09CapturePageV2)
    values=json.loads(row[1])
    if len(values)>100: raise C09PagedCaptureHold("persisted page has excess records")
    records=tuple(c09_paged_value_from_wire_v2(raw,C09CaptureRecordV2) for raw in values)
    return page,records


class _C09StreamVerificationV2:
    __slots__=('candidate','stream_id','seal_digest','cursor','complete','census_count','census_last_key','census_chain','census_complete','pending_page_digest','pending_record_offset')

    def __init__(self,candidate,stream,seal):
        self.candidate=candidate;self.stream_id=stream.stream_id;self.seal_digest=seal.digest
        self.cursor=begin_c09_stream_v2(stream);self.complete=False
        self.pending_page_digest=None;self.pending_record_offset=0
        self.census_count=0;self.census_last_key=None;self.census_chain=canonical_digest(('sylanne3.c09.census.v2',stream.stream_id));self.census_complete=False


def begin_c09_stream_verification_v2(candidate,stream):
    saved=_bounded_capture_row(candidate,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,),(16,65536))
    if saved is None or saved[0]!='sealed':
        raise C09PagedCaptureHold("cold verification requires the original sealed stream")
    return _C09StreamVerificationV2(candidate,stream,_decoded(saved[1],C09CompleteStreamV2))


@_metered_c09_quantum_v2
def advance_verify_c09_census_v2(source,candidate,stream,shape,budget,*,verification,check_frozen_source):
    """Cold independently recounts the frozen source, not candidate assertions."""
    _require_stream_shape(stream,shape);check_frozen_source();started=monotonic_ns()
    if (type(verification) is not _C09StreamVerificationV2 or verification.candidate is not candidate
            or verification.stream_id!=stream.stream_id):
        raise C09PagedCaptureHold('cold census belongs to another actual read session')
    count=verification.census_count;last=verification.census_last_key;chain=verification.census_chain
    completed=0;encoded=0;complete=verification.census_complete
    if source.in_transaction or not source.execute('PRAGMA query_only').fetchone()[0]:
        raise C09PagedCaptureHold('cold census requires the actual frozen read-only source')
    source.execute('BEGIN');read_started=monotonic_ns()
    try:
        while not complete and completed<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
            found=read_c09_next_row_metadata_v2(source,shape,last)
            if found is None:
                eof=canonical_digest(('sylanne3.c09.census-eof.v2',stream.stream_id,count,last,chain))
                with capture_read_transaction_v2(candidate): original=_load_census(candidate,stream)
                digest=canonical_digest(('sylanne3.c09.actual-count-original.v2',stream.stream_id,count,last,chain,eof))
                if (original.record_count,original.last_key,original.eof_observation_digest,original.original_digest)!=(count,last,eof,digest):
                    raise C09PagedCaptureHold('candidate census differs from independent actual source count/EOF')
                complete=True;break
            key,metadata=found;size=len(canonical_serialize((key,metadata)).encode('utf-8'))
            if size>budget.max_bytes: raise C09PagedCaptureHold('cold census descriptor requires a named codec')
            if encoded+size>budget.max_bytes: break
            count+=1;completed+=1;encoded+=size
            chain=canonical_digest(('sylanne3.c09.census-row.v2',stream.stream_id,count,chain,key,metadata));last=key
    finally: source.rollback()
    read_elapsed=monotonic_ns()-read_started
    if read_elapsed>budget.max_read_ns: raise C09PagedCaptureHold('cold source census read exceeded its actual duration')
    check_frozen_source()
    verification.census_count=count;verification.census_last_key=last;verification.census_chain=chain;verification.census_complete=complete
    return {'complete':complete,'completed_records':completed,'encoded_bytes':encoded,'read_transaction_ns':read_elapsed,
        'elapsed_ns':monotonic_ns()-started,'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


@_metered_c09_quantum_v2
def advance_verify_c09_stream_v2(candidate,stream,budget,*,verification,verify_record):
    """Cold/membership verification is a bounded continuation, never index trust.

    verify_record(record) independently validates the actual row/domain proof.
    A page-key index only locates records and is itself checked against the page.
    """
    started=monotonic_ns()
    with capture_read_transaction_v2(candidate):
        saved=_bounded_capture_row(candidate,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,),(16,65536))
        if saved is None or saved[0]!='sealed': raise C09PagedCaptureHold("cold reader requires the actual complete seal")
        seal=_decoded(saved[1],C09CompleteStreamV2)
        if (type(verification) is not _C09StreamVerificationV2 or verification.candidate is not candidate
                or verification.stream_id!=stream.stream_id or verification.seal_digest!=seal.digest):
            raise C09PagedCaptureHold("verification continuation belongs to another actual read session")
        # A mutable persisted cursor is not evidence of prior verification. A
        # reopened process starts a new bounded sweep over the original pages.
        if not verification.census_complete:
            raise C09PagedCaptureHold('cold stream requires its independent frozen-source census')
        cursor=verification.cursor
        completed=0;encoded=0
        while cursor.page_index<seal.page_count and completed<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
            page,records=read_capture_page_v2(candidate,stream,cursor.page_index)
            if page.encoded_bytes>budget.max_bytes or completed+len(records)>budget.max_records or encoded+page.encoded_bytes>budget.max_bytes:
                if completed==0: raise C09PagedCaptureHold("stored page cannot fit this actual verification reservation")
                break
            next_cursor=verify_c09_page_v2(stream,cursor,page,records)
            if verification.pending_page_digest is not None and verification.pending_page_digest!=page.digest:
                raise C09PagedCaptureHold('unadopted streaming verification page changed its actual bytes')
            verification.pending_page_digest=page.digest
            for offset,record in enumerate(records,1):
                actual=_bounded_capture_row(candidate,'c09_capture_members_v2',('key_digest','primary_key_json','commitment','page_index'),'stream_id=? AND record_ordinal=?',
                    (stream.stream_id,cursor.record_offset+offset),(64,65536,64,20))
                if actual!=(canonical_digest(record.primary_key),canonical_serialize(record.primary_key),record.commitment,page.page_index):
                    raise C09PagedCaptureHold("capture membership index differs from its original page")
                if offset<=verification.pending_record_offset:continue
                if verify_record(record) is False:
                    # Prefix rows were independently verified in this private
                    # run. Recheck their unchanged page/member bytes above, but
                    # keep the entire page cursor unadopted until all rows finish.
                    verification.cursor=cursor;verification.complete=False
                    return {'complete':False,'cursor':cursor,'completed_records':completed,
                        'encoded_bytes':encoded,'elapsed_ns':monotonic_ns()-started,'seal':None,
                        'record_continuation':True}
                verification.pending_record_offset=offset
            verification.pending_record_offset=0;verification.pending_page_digest=None
            completed+=len(records);encoded+=page.encoded_bytes;cursor=next_cursor
        complete=cursor.page_index==seal.page_count
        if complete:
            if candidate.execute('SELECT page_index FROM c09_capture_pages_v2 WHERE stream_id=? AND page_index>=? LIMIT 1',(stream.stream_id,seal.page_count)).fetchone() is not None:
                raise C09PagedCaptureHold("capture includes an extra unsealed page")
            if candidate.execute('SELECT record_ordinal FROM c09_capture_members_v2 WHERE stream_id=? AND record_ordinal>? LIMIT 1',(stream.stream_id,seal.record_count)).fetchone() is not None:
                raise C09PagedCaptureHold("capture includes an extra unsealed member")
            data=_capture_data_state(candidate,stream)
            verify_c09_complete_stream_v2(stream,cursor,_load_census(candidate,stream),seal,data_eof_observation_digest=data['eof'])
    verification.cursor=cursor;verification.complete=complete
    return {'complete':complete,'cursor':cursor,'completed_records':completed,'encoded_bytes':encoded,'elapsed_ns':monotonic_ns()-started,'seal':seal if complete else None}


class _C09RowCommitmentCursorV2:
    __slots__=('source','schema_digest','key','metadata','column_index','cell_offset',
        'row_hash','blob_hash','utf8','text_open','complete','commitment','encoding_started')

    def __init__(self,source,shape,key,metadata):
        self.source=source;self.schema_digest=shape.schema_digest;self.key=key;self.metadata=metadata
        self.column_index=0;self.cell_offset=0;self.row_hash=hashlib.sha256();self.row_hash.update(b'[')
        self.blob_hash=None;self.utf8=None;self.text_open=False;self.complete=False;self.commitment=None;self.encoding_started=False


@contextmanager
def legacy_cell_read_transaction_v2(db):
    """Join an installed caller's snapshot or own this one bounded read."""
    if db.in_transaction:
        yield
    else:
        with capture_read_transaction_v2(db):
            yield


def _legacy_source_read_quantum_v2(function):
    @wraps(function)
    def read(source,*args,**kwargs):
        with legacy_cell_read_transaction_v2(source):
            return function(source,*args,**kwargs)
    return read



def begin_c09_row_commitment_v2(source,shape,key,metadata):
    """Opaque constant-memory state; a crash restarts the same row from byte 0."""
    return _C09RowCommitmentCursorV2(source,shape,key,metadata)


@_metered_c09_quantum_v2
@_legacy_source_read_quantum_v2
def advance_c09_row_commitment_v2(source,shape,budget,*,cursor):
    """Stream the exact V1 single-row canonical commitment without its body.

    TEXT is escaped exactly as canonical_serialize's ensure_ascii JSON string.
    BLOB retains V1's {blob_sha256,size} representation. This does not replace
    domain decoding or count a cell fragment as a complete record.
    """
    if (type(cursor) is not _C09RowCommitmentCursorV2 or cursor.source is not source
            or cursor.schema_digest!=shape.schema_digest):
        raise C09PagedCaptureHold('row commitment cursor crossed the actual frozen source')
    if cursor.complete:
        return {'complete':True,'commitment':cursor.commitment,'actual_io_bytes':0,'elapsed_ns':0}
    started=monotonic_ns();spent=0;meter=current_c09_sql_meter_v2()
    if not cursor.encoding_started:meter.charge_encode(1);cursor.encoding_started=True
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    while cursor.column_index<len(shape.columns) and monotonic_ns()-started<budget.max_local_ns:
        column=shape.columns[cursor.column_index];kind,size=cursor.metadata[cursor.column_index]
        if kind in {'text','blob'}:
            if cursor.cell_offset==0 and not cursor.text_open:
                if kind=='text':
                    meter.charge_encode(1);cursor.row_hash.update(b'"');cursor.text_open=True
                    cursor.utf8=codecs.getincrementaldecoder('utf-8')('strict')
                else: cursor.blob_hash=hashlib.sha256()
            remaining=size-cursor.cell_offset
            if remaining:
                chunk=min(16384,remaining,max(0,(budget.max_bytes-spent-256)//7),max(0,(meter.remaining_bytes-256)//7))
                if not chunk: break
                block,total,actual_kind=read_legacy_sql_cell_fragment_v2(source,table=shape.table,column=column,
                    where=where,parameters=cursor.key,start=cursor.cell_offset,length=chunk,meter=meter)
                if total!=size or actual_kind!=kind:
                    raise C09PagedCaptureHold('actual frozen cell length or kind changed')
                cursor.cell_offset+=chunk;spent+=chunk
                if kind=='text':
                    text=cursor.utf8.decode(block,final=cursor.cell_offset==size)
                    escaped=json.dumps(text,ensure_ascii=True,separators=(',',':'))[1:-1].encode('ascii')
                    meter.charge_encode(len(escaped));cursor.row_hash.update(escaped);spent+=len(escaped)
                else: cursor.blob_hash.update(block)
                if cursor.cell_offset<size: continue
            if kind=='text':
                if size==0: cursor.utf8.decode(b'',final=True)
                meter.charge_encode(1);cursor.row_hash.update(b'"');cursor.text_open=False;cursor.utf8=None
            else:
                wire=canonical_serialize({'blob_sha256':cursor.blob_hash.hexdigest(),'size':size}).encode('utf-8')
                if spent+len(wire)>budget.max_bytes: break
                cursor.row_hash.update(wire);spent+=len(wire);cursor.blob_hash=None
        else:
            if spent+(0 if size is None else size)+32>budget.max_bytes: break
            raw=source.execute('SELECT '+_quote(column)+' FROM '+_quote(shape.table)+' WHERE '+where+' LIMIT 1',cursor.key).fetchone()
            if raw is None or (kind=='null' and raw[0] is not None) or (kind=='integer' and type(raw[0]) is not int) or (kind=='real' and type(raw[0]) is not float):
                raise C09PagedCaptureHold('frozen scalar cell storage type changed')
            meter.charge_read(_sql_scalar_size_v2(raw[0]))
            wire=canonical_serialize(raw[0]).encode('utf-8');cursor.row_hash.update(wire)
            spent+=(0 if size is None else size)+len(wire)
        cursor.column_index+=1;cursor.cell_offset=0
        if cursor.column_index<len(shape.columns):meter.charge_encode(1);cursor.row_hash.update(b',')
    if cursor.column_index==len(shape.columns):
        meter.charge_encode(1);cursor.row_hash.update(b']');cursor.commitment=cursor.row_hash.hexdigest();cursor.complete=True
    return {'complete':cursor.complete,'commitment':cursor.commitment,'actual_io_bytes':spent,
        'elapsed_ns':monotonic_ns()-started,'cell_index':cursor.column_index,'cell_offset':cursor.cell_offset,
        'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


class _C09JSONCellCommitmentV2:
    __slots__=('source','shape_digest','key','column','size','revision','parser','offset','complete','digest')

    def __init__(self,source,shape,key,column,size,revision):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.source=source;self.shape_digest=shape.schema_digest;self.key=key;self.column=column
        self.size=size;self.revision=revision;self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.offset=0;self.complete=False;self.digest=None


def begin_c09_json_cell_commitment_v2(source,shape,key,column,*,expected_size,expected_revision):
    """Restartable constant-memory digest of an actual canonical Graph JSON cell.

    Graph's registered plain JSON codec uses ensure_ascii=True, as does the
    runtime canonical digest of that decoded plain value. The canonical parser
    proves the byte representation before the raw hash becomes value_digest.
    No partial digest or persisted cursor certifies a prefix after restart.
    """
    if (column not in shape.columns or 'revision' not in shape.columns or len(key)!=len(shape.primary_key_columns)
            or type(expected_size) is not int or expected_size<=0
            or type(expected_revision) is not int or expected_revision<=0):
        raise C09PagedCaptureHold('actual revision-bound canonical Graph cell required')
    return _C09JSONCellCommitmentV2(source,shape,key,column,expected_size,expected_revision)


@_metered_c09_quantum_v2
@_legacy_source_read_quantum_v2
def advance_c09_json_cell_commitment_v2(source,shape,budget,*,cursor):
    """Validate and hash at most 16 KiB per fragment in the reserved quantum."""
    if (type(cursor) is not _C09JSONCellCommitmentV2 or cursor.source is not source
            or cursor.shape_digest!=shape.schema_digest):
        raise C09PagedCaptureHold('JSON cell continuation crossed its actual frozen source')
    meter=current_c09_sql_meter_v2();started=monotonic_ns();before=cursor.offset
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    metadata=meter.read_fixed_row(source,shape.table,('revision',),where,cursor.key)
    _empty,total,kind=read_legacy_sql_cell_fragment_v2(source,table=shape.table,column=cursor.column,
        where=where,parameters=cursor.key,start=0,length=0,meter=meter)
    if metadata!=(cursor.revision,) or (kind,total)!=('text',cursor.size):
        raise C09PagedCaptureHold('actual canonical Graph cell revision or byte length changed')
    while not cursor.complete and monotonic_ns()-started<budget.max_local_ns:
        amount=min(16384,cursor.size-cursor.offset,meter.remaining_bytes)
        if amount<=0:break
        block,total,kind=read_legacy_sql_cell_fragment_v2(source,table=shape.table,column=cursor.column,
            where=where,parameters=cursor.key,start=cursor.offset,length=amount,meter=meter)
        if total!=cursor.size or kind!='text':
            raise C09PagedCaptureHold('frozen canonical JSON fragment changed')
        cursor.parser.feed(block,lambda event:None);cursor.offset+=amount
        if cursor.offset==cursor.size:
            result=cursor.parser.finish()
            if result.byte_count!=cursor.size:raise C09PagedCaptureHold('canonical JSON EOF byte count differs')
            cursor.digest=result.sha256;cursor.complete=True
    elapsed=monotonic_ns()-started
    if elapsed>budget.max_read_ns:raise C09PagedCaptureHold('actual canonical cell read exceeded its duration')
    return {'complete':cursor.complete,'value_digest':cursor.digest if cursor.complete else None,
        'byte_count':cursor.offset,'actual_io_bytes':cursor.offset-before,'completed_records':int(cursor.complete),
        'elapsed_ns':elapsed,'resource_quantum_within_limit':elapsed<=budget.max_local_ns}


@dataclass(frozen=True, slots=True)
class C09SqlSchemaObjectV2:
    object_type: str
    name: str
    table_name: str
    sql: str

    @property
    def primary_key(self): return self.object_type,self.name

    @property
    def commitment(self):
        return canonical_digest(('sylanne3.c09.sql-schema-object.v2',self.object_type,self.name,self.table_name,self.sql))


def read_c09_next_schema_object_v2(source,after_key,*,max_bytes):
    """Bounded schema-catalogue row; sqlite_master has a named stable codec."""
    if after_key is None: after_key=('','')
    if type(after_key) is not tuple or len(after_key)!=2 or any(type(item) is not str for item in after_key):
        raise ValueError('actual schema-catalogue keyset required')
    where="sql IS NOT NULL AND name NOT GLOB 'sqlite_*' AND (type COLLATE BINARY > ? OR (type COLLATE BINARY = ? AND name COLLATE BINARY > ?))"
    args=(after_key[0],after_key[0],after_key[1])
    metadata=source.execute('SELECT type,name,tbl_name,length(CAST(sql AS BLOB)) FROM sqlite_master WHERE '+where+' ORDER BY type COLLATE BINARY,name COLLATE BINARY LIMIT 1',args).fetchone()
    if metadata is None: return None
    if metadata[0] not in {'table','index','trigger'} or metadata[3] is None or metadata[3]*6>max_bytes:
        raise C09PagedCaptureHold('installed schema object requires its named streaming codec')
    row=source.execute('SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type=? AND name=? LIMIT 1',metadata[:2]).fetchone()
    if row is None: raise C09PagedCaptureHold('frozen schema object disappeared')
    return C09SqlSchemaObjectV2(*row)


def apply_c09_schema_object_v2(candidate,original,*,verify_installed_object):
    """Verify fixed installed DDL before executing it inside the actual candidate."""
    if not candidate.in_transaction or type(original) is not C09SqlSchemaObjectV2:
        raise C09PagedCaptureHold('registered schema object must commit with its original page')
    verify_installed_object(original)
    saved=candidate.execute('SELECT tbl_name,sql FROM sqlite_master WHERE type=? AND name=?',original.primary_key).fetchone()
    if saved is None: candidate.execute(original.sql)
    elif saved!=(original.table_name,original.sql): raise C09PagedCaptureHold('same-inode candidate schema object differs')
    return original.commitment


def require_c09_capture_member_v2(candidate,stream,ordinal,primary_key,commitment,*,meter):
    """Exact immutable page member, not a mutable lookup/index assertion.

    Complete-source qualification belongs to the installed producer/cold view.
    This point join additionally proves this row's identity and ordinal inside
    the actual persisted original page committed with its source row.
    """
    if type(ordinal) is not int or ordinal<1:raise C09PagedCaptureHold('actual capture member ordinal required')
    item=meter.read_fixed_row(candidate,'c09_capture_members_v2',('primary_key_json','commitment','page_index'),
        'stream_id=? AND record_ordinal=?',(stream.stream_id,ordinal))
    if item is None or tuple(json.loads(item[0]))!=primary_key or item[1]!=commitment:
        raise C09PagedCaptureHold('point lookup differs from its actual original capture member')
    with c09_sql_meter_quantum_v2(meter):page,records=read_capture_page_v2(candidate,stream,item[2])
    position=ordinal-page.record_offset-1
    if not 0<=position<len(records) or records[position] != C09CaptureRecordV2(primary_key,commitment):
        raise C09PagedCaptureHold('capture member index differs from its immutable original page')
    # The complete cold reader checks predecessor/page-chain and source EOF.
    # At a point join, both this descriptor and its actual records must retain
    # the exact committed payload, rather than merely sharing an index key.
    from .c09_paged_capture_contract_v2 import _commit_digest as kernel_digest
    with meter_c09_commitments_v2(meter):actual_payload=kernel_digest(records)
    if page.payload_digest!=actual_payload:raise C09PagedCaptureHold('point original page payload commitment differs')
    if page.stream_id!=stream.stream_id or page.page_index!=item[2]:raise C09PagedCaptureHold('point original page crossed its actual stream')
    return records[position]






def read_legacy_sql_cell_fragment_v2(db,*,table,column,where,parameters,start,length,meter):
    """Read actual TEXT/BLOB storage without CAST/substr whole-cell conversion.

    The installed caller owns the frozen Source and registered SQL locator.
    Each handle is readonly and closes inside this one short read transaction.
    """
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise C09PagedCaptureHold('incremental old cell read needs actual source read transaction')
    if (type(start) is not int or start<0 or type(length) is not int or not 0<=length<=65536):
        raise C09PagedCaptureHold('old cell descriptor read exceeds its fixed bound')
    encoding=db.execute('PRAGMA encoding').fetchone()
    meter.charge_read(sum(_sql_scalar_size_v2(item) for item in encoding))
    if encoding!=('UTF-8',):raise C09PagedCaptureHold('registered legacy cell requires actual UTF-8 SQLite storage')
    columns=tuple(row[1] for row in db.execute('PRAGMA table_xinfo('+_quote(table)+')').fetchmany(101))
    if len(columns)>100 or column not in columns:
        raise C09PagedCaptureHold('legacy column is outside its bounded actual table descriptor')
    meter.charge_read(sum(len(name.encode('utf-8')) for name in columns))
    aliases=[alias for alias in ('rowid','_rowid_','oid') if alias not in columns]
    if not aliases:raise C09PagedCaptureHold('legacy cell has no unshadowed physical row locator')
    sql='SELECT '+aliases[0]+',typeof('+_quote(column)+') FROM '+_quote(table)+' WHERE '+where+' LIMIT 2'
    meter.charge_encode(len(sql.encode('utf-8'))+sum(_sql_scalar_size_v2(v) for v in parameters))
    try:rows=db.execute(sql,parameters).fetchmany(2)
    except sqlite3.OperationalError as exc:
        raise C09PagedCaptureHold('registered legacy cell has no supported rowid incremental adapter') from exc
    meter.charge_read(sum(sum(_sql_scalar_size_v2(v) for v in row) for row in rows))
    if len(rows)!=1 or type(rows[0][0]) is not int or rows[0][1] not in ('text','blob'):
        raise C09PagedCaptureHold('legacy cell is absent, ambiguous or lacks a supported physical row locator')
    try:
        with db.blobopen(table,column,rows[0][0],readonly=True) as blob:
            total=len(blob)
            if start>total or length>total-start:raise C09PagedCaptureHold('actual legacy cell byte length changed')
            result=bytearray()
            blob.seek(start)
            remaining=length
            while remaining:
                size=min(16384,remaining)
                meter.require_available(size)
                chunk=blob.read(size)
                meter.charge_read(len(chunk))
                if len(chunk)!=size:raise C09PagedCaptureHold('actual legacy cell fragment ended early')
                result.extend(chunk);remaining-=size
            return bytes(result),total,rows[0][1]
    except sqlite3.Error as exc:
        raise C09PagedCaptureHold('actual incremental cell handle expired or is unsupported') from exc



def require_c09_logical_source_row_member_v3(candidate,stream,*,role,table_name,key,record_ordinal,meter):
    """Independently match one immutable descriptor to its sealed-page member."""
    root=require_c09_reserved_meter_v3(meter.budget)
    if meter is not root:
        from ..authority_service.c09_paged_recovery_facts_v2 import _C09ReadonlyPointMeterV3
        if type(meter) is not _C09ReadonlyPointMeterV3 or meter.parent is not root:
            raise C09PagedCaptureHold('logical descriptor verification requires the actual reserved quantum')
    saved=meter.read_fixed_row(candidate,'c09_logical_source_rows_v3',
        LOGICAL_SOURCE_COLUMNS_V3,
        'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
        (stream.scope_digest,role,table_name,canonical_digest(key)))
    if saved is None:
        raise C09PagedCaptureHold('actual logical Source descriptor is absent')
    pk,wire,digest,physical,logical,source,physical_schema,logical_shape,origin,ordinal=saved
    if (pk!=canonical_serialize(key) or source!=stream.role_source_digest
            or logical_shape!=stream.schema_digest or origin!=stream.stream_id
            or ordinal!=record_ordinal or hashlib.sha256(wire.encode('utf8')).hexdigest()!=digest):
        raise C09PagedCaptureHold('logical Source descriptor differs from its actual stream/member')
    descriptor=json.loads(wire)
    if (type(descriptor) is not dict
            or set(descriptor)!= {'schema','source_role_digest','physical_schema_digest',
                'logical_shape_digest','primary_key','physical_row_commitment',
                'cell_bindings','logical_row_commitment'}
            or descriptor['schema']!='sylanne3.c09.logical-source-row.v3'
            or descriptor['source_role_digest']!=source
            or descriptor['physical_schema_digest']!=physical_schema
            or descriptor['logical_shape_digest']!=logical_shape
            or descriptor['primary_key']!=list(key)
            or descriptor['physical_row_commitment']!=physical
            or descriptor['logical_row_commitment']!=logical):
        raise C09PagedCaptureHold('logical Source descriptor fields differ from their immutable columns')
    require_c09_capture_member_v2(candidate,stream,record_ordinal,key,digest,meter=root)
    return descriptor


def append_c09_logical_source_row_v3(candidate,stream,*,completed,record_ordinal,require_existing=False):
    """Bind a complete physical/logical row to its actual immutable capture member."""
    from .c09_logical_source_v3 import CompleteLogicalSourceRowV3
    if type(completed) is not CompleteLogicalSourceRowV3 or not candidate.in_transaction:
        raise C09PagedCaptureHold('complete logical Source and owned capture transaction required')
    meter=current_c09_sql_meter_v2()
    completed.scope.require_current(meter=meter)
    _require_stream_shape(stream,completed.shape)
    if (stream.scope_digest!=completed.scope.session.scope.scope_digest
            or stream.role_source_digest!=completed.source_role_digest):
        raise C09PagedCaptureHold('logical Source descriptor belongs to another capture scope')
    require_c09_capture_member_v2(candidate,stream,record_ordinal,
        completed.primary_key,completed.descriptor_digest,meter=meter)
    wire=canonical_serialize(completed.descriptor)
    if hashlib.sha256(wire.encode('utf8')).hexdigest()!=completed.descriptor_digest:
        raise C09PagedCaptureHold('complete logical Source descriptor changed after its producer EOF')
    key_digest=canonical_digest(completed.primary_key)
    expected=(canonical_serialize(completed.primary_key),wire,completed.descriptor_digest,
        completed.physical_row_commitment,completed.logical_row_commitment,
        completed.source_role_digest,completed.shape.physical_shape.schema_digest,
        completed.shape.logical_shape_digest,stream.stream_id,record_ordinal)
    where='scope_digest=? AND role=? AND table_name=? AND key_digest=?'
    key=(stream.scope_digest,completed.scope.role,completed.shape.table,key_digest)
    prior=meter.read_fixed_row(candidate,'c09_logical_source_rows_v3',
        LOGICAL_SOURCE_COLUMNS_V3,where,key)
    if prior is not None:
        if prior!=expected:
            raise C09PagedCaptureHold('logical Source descriptor replay differs from its actual member')
        return completed.descriptor_digest
    if require_existing:
        raise C09PagedCaptureHold('committed capture member lacks its same-transaction logical descriptor')
    _capture_write_v2(candidate,'INSERT INTO c09_logical_source_rows_v3 VALUES('+','.join('?' for _ in range(14))+')',
        (*key,*expected))
    return completed.descriptor_digest


@_metered_c09_quantum_v2
def append_completed_memory_source_capture_v3(build,stream,shape,budget,*,completed):
    """Same real capture page/member/cursor transaction for a streamed Source row."""
    from .c09_graph_row_codec_v2 import C09MemorySourceRowCaptureV3,C09MappedGraphRowCaptureV3
    from .c09_domain_original_source_v3 import C09MappedDomainOriginalCaptureV3
    mapped=(C09MappedGraphRowCaptureV3,C09MappedDomainOriginalCaptureV3)
    if type(completed) not in (C09MemorySourceRowCaptureV3,*mapped):
        raise C09PagedCaptureHold('actual private complete Source capture required')
    build.require_current()
    _require_stream_shape(stream,completed.logical_shape if type(completed) in mapped else shape)
    source,candidate=build.pair.source,build.pair.candidate
    meter=current_c09_sql_meter_v2();started=monotonic_ns()
    with capture_transaction_v2(candidate):
        _load_census(candidate,stream)
        if meter.read_fixed_row(candidate,'c09_capture_streams_v2',('status',),'stream_id=?',(stream.stream_id,))!=('open',):
            raise C09PagedCaptureHold('complete Source capture may not append to sealed stream')
        cursor=read_capture_cursor_v2(candidate,stream);data=_capture_data_state(candidate,stream)
        prior=meter.read_fixed_row(candidate,'c09_capture_members_v2',
            ('record_ordinal','primary_key_json','commitment','page_index'),
            'stream_id=? AND key_digest=?',(stream.stream_id,canonical_digest(completed.key)))
        if prior is not None:
            commitment=completed.require_complete(build,shape,completed.key,completed.metadata)
            if (prior[1]!=canonical_serialize(completed.key) or prior[2]!=commitment
                    or cursor.record_offset<prior[0]):
                raise C09PagedCaptureHold('Source capture replay differs from its actual committed member')
            require_c09_capture_member_v2(candidate,stream,prior[0],completed.key,commitment,meter=meter)
            if type(completed) in mapped:
                append_c09_logical_source_row_v3(candidate,stream,
                    completed=completed.row.result,record_ordinal=prior[0],require_existing=True)
            return {'page':None,'cursor':cursor,'completed_records':0,'eof':data['eof'] is not None,
                'already_committed':True,'actual_io_bytes':meter.consumed_bytes,
                'elapsed_ns':monotonic_ns()-started,'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}
        if data['eof'] is not None:raise C09PagedCaptureHold('Source capture data EOF already closed')
        with capture_read_transaction_v2(source):
            found=read_c09_next_row_metadata_v2(source,shape,cursor.last_key)
            if found is None:raise C09PagedCaptureHold('completed Source row is beyond actual source EOF')
            key,metadata=found
            commitment=completed.require_complete(build,shape,key,metadata)
        record=C09CaptureRecordV2(key,commitment)
        page=append_c09_page_v2(stream,cursor,(record,))
        _capture_write_v2(candidate,'INSERT INTO c09_capture_pages_v2 VALUES(?,?,?,?)',
            (stream.stream_id,page.page_index,_wire(page),json.dumps([asdict(record)],sort_keys=True,separators=(',',':'))))
        _capture_write_v2(candidate,'INSERT INTO c09_capture_members_v2 VALUES(?,?,?,?,?,?)',
            (stream.stream_id,cursor.record_offset+1,canonical_digest(key),canonical_serialize(key),commitment,page.page_index))
        if type(completed) in mapped:
            append_c09_logical_source_row_v3(candidate,stream,
                completed=completed.row.result,record_ordinal=cursor.record_offset+1)
        data['cursor']=asdict(page.next_cursor)
        _capture_write_v2(candidate,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",
            (canonical_serialize(data),stream.stream_id))
    build.require_current()
    return {'page':page,'cursor':page.next_cursor,'completed_records':1,'eof':False,
        'actual_io_bytes':meter.consumed_bytes,'elapsed_ns':monotonic_ns()-started,
        'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


@_metered_c09_quantum_v2
def _advance_verify_c09_scoped_census_v3(source,candidate,stream,shape,budget,*,verification,check_frozen_source,row_scope):
    """Cold independently recounts the frozen source, not candidate assertions."""
    _require_stream_shape(stream,shape);check_frozen_source();started=monotonic_ns()
    if (type(verification) is not _C09StreamVerificationV2 or verification.candidate is not candidate
            or verification.stream_id!=stream.stream_id):
        raise C09PagedCaptureHold('cold census belongs to another actual read session')
    count=verification.census_count;last=verification.census_last_key;chain=verification.census_chain
    completed=0;encoded=0;complete=verification.census_complete
    if source.in_transaction or not source.execute('PRAGMA query_only').fetchone()[0]:
        raise C09PagedCaptureHold('cold census requires the actual frozen read-only source')
    source.execute('BEGIN');read_started=monotonic_ns()
    try:
        while not complete and completed<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
            found=_read_c09_scoped_row_metadata_v3(source,shape,last,row_scope)
            if found is None:
                eof=canonical_digest(('sylanne3.c09.census-eof.v2',stream.stream_id,count,last,chain))
                with capture_read_transaction_v2(candidate): original=_load_census(candidate,stream)
                digest=canonical_digest(('sylanne3.c09.actual-count-original.v2',stream.stream_id,count,last,chain,eof))
                if (original.record_count,original.last_key,original.eof_observation_digest,original.original_digest)!=(count,last,eof,digest):
                    raise C09PagedCaptureHold('candidate census differs from independent actual source count/EOF')
                complete=True;break
            key,metadata=found;size=len(canonical_serialize((key,metadata)).encode('utf-8'))
            if size>budget.max_bytes: raise C09PagedCaptureHold('cold census descriptor requires a named codec')
            if encoded+size>budget.max_bytes: break
            count+=1;completed+=1;encoded+=size
            chain=canonical_digest(('sylanne3.c09.census-row.v2',stream.stream_id,count,chain,key,metadata));last=key
    finally: source.rollback()
    read_elapsed=monotonic_ns()-read_started
    if read_elapsed>budget.max_read_ns: raise C09PagedCaptureHold('cold source census read exceeded its actual duration')
    check_frozen_source()
    verification.census_count=count;verification.census_last_key=last;verification.census_chain=chain;verification.census_complete=complete
    return {'complete':complete,'completed_records':completed,'encoded_bytes':encoded,'read_transaction_ns':read_elapsed,
        'elapsed_ns':monotonic_ns()-started,'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}
