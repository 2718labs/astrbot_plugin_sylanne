"""Bounded, two-pass physical filesystem census for a Root-bound domain.

Root is the only authority. This module accepts its private bound, reads roots
through the bound, and stores content-free evidence in its existing Control DB.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from time import monotonic_ns

from .c09_physical_inventory_bound_v2 import InstalledC09PhysicalInventoryBoundV2
from ..runtime_contracts import canonical_serialize
from ..runtime.c09_paged_sql_v2 import C09BatchBudgetV2, C09SqlByteMeterV2

_ISSUER = object()
_VERIFY = object()
_CHUNK = 16 * 1024
_PAGE = 100
_PAGE_BYTES = 192 * 1024
_ZERO = '0' * 64
_ROOT_EOF = '\uffff'

PHYSICAL_INVENTORY_DDLS_V2 = {
 'c09_physical_inventory_streams_v2': "CREATE TABLE c09_physical_inventory_streams_v2 (stream_id TEXT PRIMARY KEY,source_domain_digest TEXT NOT NULL,phase TEXT NOT NULL CHECK(phase IN ('census1','pages1','census2','pages2','complete')),pass_index INTEGER NOT NULL,after_root_id TEXT NOT NULL,after_path BLOB NOT NULL,after_resource_id TEXT NOT NULL,record_count INTEGER NOT NULL,page_count INTEGER NOT NULL,record_chain TEXT NOT NULL,page_chain TEXT NOT NULL,first_record_root TEXT,first_page_root TEXT,first_record_count INTEGER,first_page_count INTEGER,census1_count INTEGER NOT NULL DEFAULT 0,census2_count INTEGER NOT NULL DEFAULT 0,first_eof TEXT,second_eof TEXT,result_json TEXT,active_path TEXT,active_identity TEXT,active_offset INTEGER NOT NULL)",
 'c09_physical_inventory_frontier_v2': "CREATE TABLE c09_physical_inventory_frontier_v2 (stream_id TEXT NOT NULL,pass_index INTEGER NOT NULL,path TEXT NOT NULL,resource_id TEXT NOT NULL,identity_json TEXT NOT NULL,PRIMARY KEY(stream_id,pass_index,path,resource_id),FOREIGN KEY(stream_id) REFERENCES c09_physical_inventory_streams_v2(stream_id))",
 'c09_physical_inventory_records_v2': "CREATE TABLE c09_physical_inventory_records_v2 (stream_id TEXT NOT NULL,pass_index INTEGER NOT NULL,resource_id TEXT NOT NULL,path TEXT NOT NULL,path_key BLOB NOT NULL,commitment TEXT NOT NULL,PRIMARY KEY(stream_id,pass_index,resource_id,path),UNIQUE(stream_id,pass_index,path_key),FOREIGN KEY(stream_id) REFERENCES c09_physical_inventory_streams_v2(stream_id))",
 'c09_physical_inventory_fragments_v2': "CREATE TABLE c09_physical_inventory_fragments_v2 (stream_id TEXT NOT NULL,pass_index INTEGER NOT NULL,resource_id TEXT NOT NULL,path TEXT NOT NULL,fragment_index INTEGER NOT NULL,fragment_digest TEXT NOT NULL,PRIMARY KEY(stream_id,pass_index,resource_id,path,fragment_index),FOREIGN KEY(stream_id) REFERENCES c09_physical_inventory_streams_v2(stream_id))",
 'c09_physical_inventory_pages_v2': "CREATE TABLE c09_physical_inventory_pages_v2 (stream_id TEXT NOT NULL,pass_index INTEGER NOT NULL,page_index INTEGER NOT NULL,first_path_key BLOB NOT NULL,last_path_key BLOB NOT NULL,record_count INTEGER NOT NULL,page_root TEXT NOT NULL,PRIMARY KEY(stream_id,pass_index,page_index),FOREIGN KEY(stream_id) REFERENCES c09_physical_inventory_streams_v2(stream_id))",
}
PHYSICAL_INVENTORY_TRIGGERS_V2 = tuple(
 (f'{table}_{action.lower()}_immutable',
  f"CREATE TRIGGER {table}_{action.lower()}_immutable BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'immutable physical inventory evidence'); END")
 for table in ('c09_physical_inventory_records_v2','c09_physical_inventory_fragments_v2','c09_physical_inventory_pages_v2')
 for action in ('UPDATE','DELETE'))
PHYSICAL_INVENTORY_TABLES_V2 = frozenset(PHYSICAL_INVENTORY_DDLS_V2)

class C09PhysicalInventoryHold(RuntimeError):
    """The actual registered filesystem changed or could not be completely read."""

@dataclass(slots=True)
class PhysicalInventoryProgressV2:
    _issuer: object
    bound: object
    stream_id: str
    source_domain_digest: str
    pass_index: int = 1
    directory_path: str | None = None
    directory_resource: str | None = None
    directory_identity: tuple | None = None
    directory_iterator: object = None
    active_file: object = None
    complete: object = None
    initialized: bool = False
    observed_records: int = 0
    baseline: object = None
    failed: bool = False
    pending_page: list = None
    pending_after: tuple = None
    pending_bytes: int = 0
    pending_sealable: bool = False
    pending_hash_index: int = 0
    pending_page_index: int = 0
    pending_record_chain: str | None = None
    pending_page_chain: str | None = None
    pending_stream_page_chain: str | None = None
    first_eof: str | None = None
    second_eof: str | None = None

@dataclass(frozen=True, slots=True, init=False)
class VerifiedPhysicalInventoryV2:
    _issuer: object
    _progress: object
    stream_id: str
    source_domain_digest: str
    record_count: int
    page_count: int
    record_root: str
    page_root: str
    eof_observation_digest: str

    def __init__(self,token,progress,record_count,page_count,record_root,page_root,eof):
        if token is not _VERIFY:raise C09PhysicalInventoryHold('verified inventory is engine-issued only')
        for name,value in (('_issuer',token),('_progress',progress),('stream_id',progress.stream_id),
                ('source_domain_digest',progress.source_domain_digest),('record_count',record_count),
                ('page_count',page_count),('record_root',record_root),('page_root',page_root),
                ('eof_observation_digest',eof)):
            object.__setattr__(self,name,value)

    def require_current(self):
        p=self._progress
        if (self._issuer is not _VERIFY or type(p) is not PhysicalInventoryProgressV2
                or p._issuer is not _ISSUER or p.complete is not self
                or p.pass_index!=2 or p.first_eof is None or p.second_eof is None):
            raise C09PhysicalInventoryHold('actual two-pass physical inventory token required')
        p.bound.require_current()
        with p.bound.control._db() as db:
            row=db.execute('SELECT phase,source_domain_digest,result_json,first_record_root,first_page_root,first_record_count,first_page_count,first_eof,second_eof FROM c09_physical_inventory_streams_v2 WHERE stream_id=?',(self.stream_id,)).fetchone()
        if row is None or row[0]!='complete' or row[1]!=self.source_domain_digest:
            raise C09PhysicalInventoryHold('current Control physical inventory original differs')
        result=json.loads(row[2])
        if (result.get('record_count'),result.get('page_count'),result.get('record_root'),result.get('page_root'),
                result.get('first_eof'),result.get('second_eof'),result.get('eof_observation_digest'))!=(self.record_count,self.page_count,self.record_root,
                self.page_root,p.first_eof,p.second_eof,self.eof_observation_digest) or (row[3],row[4],row[5],row[6],row[7],row[8])!=(
                self.record_root,self.page_root,self.record_count,self.page_count,p.first_eof,p.second_eof):
            raise C09PhysicalInventoryHold('signed physical inventory roots or dual EOF originals differ')
        p.bound.require_current()
        return self


def _wire(value,meter):
    reserved=_estimate(value)
    meter.require_available(reserved)
    if reserved*8>meter.budget.reserved_arena_bytes:raise C09PhysicalInventoryHold('physical inventory codec lacks its reserved arena')
    text=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
    meter.charge_encoded_bytes(len(text.encode('utf-8')))
    return text
def _identity(info): return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
def _key(path,resource_id): return os.fsencode(path)+b'\0'+resource_id.encode('utf-8')
def _size(value):
    if value is None:return 0
    if type(value) is bytes:return len(value)
    if type(value) is str:return len(value.encode('utf-8'))
    if type(value) in (int,float):return len(str(value).encode('ascii'))
    return 0

def _estimate(value):
    if type(value) is str:return len(value.encode('utf-8'))*6+2
    if type(value) in (int,float):return len(str(value))+1
    if value is None:return 4
    if type(value) in (tuple,list):return 2+sum(_estimate(item)+1 for item in value)
    if type(value) is dict:return 2+sum(_estimate(key)+_estimate(item)+2 for key,item in value.items())
    raise C09PhysicalInventoryHold('physical inventory codec value is outside its fixed scalar schema')

def _digest(value,meter):
    reserved=_estimate(value)
    meter.require_available(reserved)
    if reserved*8>meter.budget.reserved_arena_bytes:raise C09PhysicalInventoryHold('physical inventory digest lacks its reserved arena')
    wire=canonical_serialize(value).encode('utf-8')
    meter.charge_encoded_bytes(len(wire))
    return hashlib.sha256(wire).hexdigest()

def _read(db,meter,sql,args=()):
    select,rest=sql.split(' FROM ',1)
    columns=select[7:]
    if columns=='1' or columns=='COUNT(*)' or 'length(' in columns:
        size=8*(columns.count(',')+1)
        meter.require_available(size);meter.charge_read(size)
        return db.execute(sql,args).fetchone()
    names=tuple(name.strip() for name in columns.split(','))
    if any(not name.replace('_','').isalnum() for name in names):
        raise C09PhysicalInventoryHold('physical metadata query lacks a fixed scalar projection')
    lengths=','.join('length(CAST('+name+' AS BLOB))' for name in names)
    size_row=db.execute('SELECT '+lengths+' FROM ('+sql+') AS c09_bounded_row',args).fetchone()
    meter.charge_read(8*len(names))
    if size_row is None:return None
    size=sum(0 if value is None else value for value in size_row)
    meter.require_available(size);meter.charge_read(size)
    return db.execute(sql,args).fetchone()

def _write(db,meter,sql,args=()):
    meter.charge_write(sum(_size(v) for v in args))
    return db.execute(sql,args)

def _assert_absent(path,meter,budget,started):
    path=Path(path)
    parent=path.parent
    while True:
        if monotonic_ns()-started>=budget.max_local_ns:
            raise C09PhysicalInventoryHold('retired path ancestry exceeded its local quantum')
        try: info=parent.lstat()
        except FileNotFoundError:
            meter.charge_read(32);return
        except OSError as exc:raise C09PhysicalInventoryHold('absent path ancestor cannot be inspected') from exc
        meter.charge_read(32)
        if not stat.S_ISDIR(info.st_mode):raise C09PhysicalInventoryHold('absent path ancestor is symlink or non-directory')
        next_parent=parent.parent
        if next_parent==parent:break
        parent=next_parent
    try:path.lstat()
    except FileNotFoundError:
        meter.charge_read(32);return
    except OSError as exc:raise C09PhysicalInventoryHold('absent path cannot be inspected') from exc
    meter.charge_read(32)
    raise C09PhysicalInventoryHold('registered absent path was recreated')

def _record(db,meter,p,resource_id,path,commitment):
    key=_key(path,resource_id)
    if p.pass_index==2:
        first=_read(db,meter,"SELECT commitment FROM c09_physical_inventory_records_v2 WHERE stream_id=? AND pass_index=1 AND resource_id=? AND path=?",(p.stream_id,resource_id,path))
        if first is None or first[0]!=commitment:raise C09PhysicalInventoryHold('independent filesystem census differs')
    prior=_read(db,meter,"SELECT commitment FROM c09_physical_inventory_records_v2 WHERE stream_id=? AND pass_index=? AND resource_id=? AND path=?",(p.stream_id,p.pass_index,resource_id,path))
    if prior is not None:
        if prior[0]!=commitment:raise C09PhysicalInventoryHold('filesystem entry differs from persisted path prefix')
        p.observed_records+=1
        return
    _write(db,meter,"INSERT INTO c09_physical_inventory_records_v2 VALUES (?,?,?,?,?,?)",(p.stream_id,p.pass_index,resource_id,path,key,commitment))
    counter='census1_count' if p.pass_index==1 else 'census2_count'
    _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET "+counter+"="+counter+"+1 WHERE stream_id=?",(p.stream_id,))
    p.observed_records+=1

def _observe_path(db,meter,p,root,path,info):
    resource_id=root['resource_id'];kind='directory' if stat.S_ISDIR(info.st_mode) else 'file'
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise C09PhysicalInventoryHold('symlink or unsupported filesystem entry')
    expected=root['kind'] if path==root['path'] else kind
    if expected in ('directory','file') and expected!=kind:raise C09PhysicalInventoryHold('registered path type changed')
    identity=_identity(info);role=root['role']
    if kind=='directory':
        commit=_digest((kind,identity,None,role,resource_id,path),meter)
        _record(db,meter,p,resource_id,path,commit)
        existing=_read(db,meter,"SELECT identity_json FROM c09_physical_inventory_frontier_v2 WHERE stream_id=? AND pass_index=? AND resource_id=? AND path=?",(p.stream_id,p.pass_index,resource_id,path))
        if existing is None:_write(db,meter,"INSERT INTO c09_physical_inventory_frontier_v2 VALUES (?,?,?,?,?)",(p.stream_id,p.pass_index,path,resource_id,_wire(identity,meter)))
        elif tuple(json.loads(existing[0]))!=identity:raise C09PhysicalInventoryHold('directory identity differs from persisted frontier')
    else:
        p.active_file={'resource_id':resource_id,'path':path,'role':role,'identity':identity,
            'size':info.st_size,'offset':0,'index':0,'chain':_ZERO,
            'hasher':hashlib.sha256(),'expected_sha256':root['expected_sha256'] if path==root['path'] else None}
        _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET active_path=?,active_identity=?,active_offset=0 WHERE stream_id=?",
            (path,_wire(identity,meter),p.stream_id))

def _hash_fragment(db,meter,p,budget):
    f=p.active_file
    if f is None:return False
    if monotonic_ns()-meter.started_ns>=budget.max_read_ns:raise C09PhysicalInventoryHold('reserved filesystem read time exhausted')
    try:
        before=os.lstat(f['path'])
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or _identity(before)!=f['identity']:
            raise C09PhysicalInventoryHold('file changed during chunked hash')
        if f['offset']<f['size']:
            fragment_size=min(_CHUNK,f['size']-f['offset'])
            reserve=fragment_size+max(8192,len(os.fsencode(f['path']))*8+4096)
            if reserve>budget.max_bytes:raise C09PhysicalInventoryHold('file fragment and metadata exceed the fixed C09 batch ceiling')
            if reserve>meter.remaining_bytes:return False
            meter.require_available(reserve)
            fd=os.open(f['path'],os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0))
            try:
                if _identity(os.fstat(fd))!=f['identity']:raise C09PhysicalInventoryHold('file changed before hash fragment')
                os.lseek(fd,f['offset'],os.SEEK_SET)
                staging=bytearray()
                while len(staging)<fragment_size:
                    part=os.read(fd,fragment_size-len(staging))
                    if not part:break
                    meter.charge_read(len(part));staging.extend(part)
            finally:os.close(fd)
            if len(staging)!=fragment_size:raise C09PhysicalInventoryHold('file fragment ended before its fixed binary boundary')
            data=bytes(staging);digest=hashlib.sha256(data).hexdigest()
            old=_read(db,meter,"SELECT fragment_digest FROM c09_physical_inventory_fragments_v2 WHERE stream_id=? AND pass_index=? AND resource_id=? AND path=? AND fragment_index=?",
                (p.stream_id,p.pass_index,f['resource_id'],f['path'],f['index']))
            if old is not None and old[0]!=digest:raise C09PhysicalInventoryHold('restarted fragment differs from immutable prefix')
            if old is None:_write(db,meter,"INSERT INTO c09_physical_inventory_fragments_v2 VALUES (?,?,?,?,?,?)",
                (p.stream_id,p.pass_index,f['resource_id'],f['path'],f['index'],digest))
            f['hasher'].update(data);f['chain']=_digest((f['chain'],f['index'],f['offset'],len(data),digest),meter)
            f['offset']+=len(data);f['index']+=1
            _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET active_offset=? WHERE stream_id=?",(f['offset'],p.stream_id))
        after=os.lstat(f['path'])
        if _identity(after)!=f['identity']:raise C09PhysicalInventoryHold('file changed during hash fragment')
    except OSError as exc:raise C09PhysicalInventoryHold('registered file cannot be read') from exc
    if f['offset']==f['size']:
        content=f['hasher'].hexdigest()
        if f['expected_sha256'] is not None and content!=f['expected_sha256']:
            raise C09PhysicalInventoryHold('registered file SHA-256 differs')
        commit=_digest(('file',f['identity'],content,f['chain'],f['role'],f['resource_id'],f['path']),meter)
        _record(db,meter,p,f['resource_id'],f['path'],commit);p.active_file=None
        _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET active_path=NULL,active_identity=NULL,active_offset=0 WHERE stream_id=?",(p.stream_id,))
    return True

def _directory_quantum(db,meter,p,budget,started):
    if p.directory_iterator is None:
        row=_read(db,meter,"SELECT resource_id,path,identity_json FROM c09_physical_inventory_frontier_v2 WHERE stream_id=? AND pass_index=? ORDER BY path COLLATE BINARY,resource_id COLLATE BINARY LIMIT 1",(p.stream_id,p.pass_index))
        if row is None:return False
        p.directory_resource,p.directory_path=row[:2]
        p.directory_identity=tuple(json.loads(row[2]))
        try:directory_info=os.lstat(p.directory_path)
        except OSError as exc:raise C09PhysicalInventoryHold('frontier directory disappeared') from exc
        meter.charge_read(32)
        if not stat.S_ISDIR(directory_info.st_mode) or _identity(directory_info)!=p.directory_identity:
            raise C09PhysicalInventoryHold('frontier directory identity changed')
        try:p.directory_iterator=os.scandir(p.directory_path)
        except OSError as exc:raise C09PhysicalInventoryHold('managed directory cannot be enumerated') from exc
    count=0
    while count<min(_PAGE,budget.max_records) and monotonic_ns()-started<budget.max_local_ns:
        reserve=(len(os.fsencode(p.directory_path))+1024)*8+4096
        if reserve>budget.max_bytes:raise C09PhysicalInventoryHold('directory entry and commitment exceed the fixed C09 batch ceiling')
        if reserve>meter.remaining_bytes:return True
        meter.require_available(reserve)
        try:entry=next(p.directory_iterator)
        except StopIteration:
            p.directory_iterator.close();p.directory_iterator=None
            try:directory_after=os.lstat(p.directory_path)
            except OSError as exc:raise C09PhysicalInventoryHold('frontier directory disappeared during enumeration') from exc
            meter.charge_read(32)
            if not stat.S_ISDIR(directory_after.st_mode) or _identity(directory_after)!=p.directory_identity:
                raise C09PhysicalInventoryHold('frontier directory changed during enumeration')
            _write(db,meter,"DELETE FROM c09_physical_inventory_frontier_v2 WHERE stream_id=? AND pass_index=? AND resource_id=? AND path=?",
                (p.stream_id,p.pass_index,p.directory_resource,p.directory_path))
            p.directory_identity=None
            return True
        except OSError as exc:raise C09PhysicalInventoryHold('managed directory read failed') from exc
        path=os.path.join(p.directory_path,entry.name)
        try:info=entry.stat(follow_symlinks=False)
        except OSError as exc:raise C09PhysicalInventoryHold('managed entry cannot be inspected') from exc
        meter.charge_read(len(os.fsencode(entry.name))+32)
        if stat.S_ISLNK(info.st_mode):raise C09PhysicalInventoryHold('managed tree contains symlink')
        if Path(path).resolve(strict=False)!=Path(path):raise C09PhysicalInventoryHold('managed entry path is unresolved')
        _observe_path(db,meter,p,{'resource_id':p.directory_resource,'path':p.directory_path,'kind':'directory','role':None,'expected_sha256':None},path,info)
        count+=1
        if p.active_file is not None:break
    return True

def _root_quantum(db,meter,p,budget):
    p.bound.require_current()
    row=_read(db,meter,"SELECT after_root_id FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(p.stream_id,))
    if row[0]==_ROOT_EOF:return False
    root=p.bound.next_root(row[0],meter)
    if root is None:
        _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET after_root_id=? WHERE stream_id=?",(_ROOT_EOF,p.stream_id))
        return True
    required={'resource_id','path','kind','expected_identity','expected_sha256','role'}
    if type(root) is not dict or set(root)!=required:raise C09PhysicalInventoryHold('Root source-domain entry shape differs')
    if root['kind']=='absent':
        _assert_absent(root['path'],meter,budget,monotonic_ns());commit=_digest(('absent',root['resource_id'],root['path'],root['role']),meter)
        _record(db,meter,p,root['resource_id'],root['path'],commit)
    else:
        try:info=os.lstat(root['path'])
        except OSError as exc:raise C09PhysicalInventoryHold('registered root is inaccessible') from exc
        meter.charge_read(32)
        if root['expected_identity'] is not None and tuple(root['expected_identity'])!=_identity(info):
            raise C09PhysicalInventoryHold('registered root identity changed')
        if root['kind'] not in ('file','directory'):raise C09PhysicalInventoryHold('registered root type differs')
        _observe_path(db,meter,p,root,root['path'],info)
    _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET after_root_id=? WHERE stream_id=?",(root['resource_id'],p.stream_id))
    return True

def _census_eof_quantum(db,meter,p):
    p.bound.require_current()
    if p.bound.next_root(_ROOT_EOF,meter) is not None:
        raise C09PhysicalInventoryHold('registered source domain has a root beyond its binary EOF')
    counter='census1_count' if p.pass_index==1 else 'census2_count'
    total=_read(db,meter,"SELECT "+counter+" FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(p.stream_id,))[0]
    if total!=p.observed_records:raise C09PhysicalInventoryHold('current enumeration differs from persisted path set')
    eof=_digest(('sylanne3.c09.physical-inventory-census-eof.v2',p.source_domain_digest,p.pass_index,p.observed_records,_ROOT_EOF),meter)
    if p.pass_index==1:
        p.first_eof=eof;_write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET first_eof=? WHERE stream_id=?",(eof,p.stream_id))
    else:
        p.second_eof=eof;_write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET second_eof=? WHERE stream_id=?",(eof,p.stream_id))
    phase='pages1' if p.pass_index==1 else 'pages2'
    _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET phase=?,after_path=X'',after_resource_id='',record_count=0,page_count=0,record_chain=?,page_chain=? WHERE stream_id=?",(phase,_ZERO,_ZERO,p.stream_id))
    return True

def _seal_page(db,meter,p,budget,started):
    rows=p.pending_page
    if not rows:return False
    if p.pending_record_chain is None:
        state=_read(db,meter,"SELECT record_chain,page_chain,page_count FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(p.stream_id,))
        p.pending_record_chain,p.pending_stream_page_chain,p.pending_page_index=state
        p.pending_page_chain=_ZERO
    first_key,last_key=rows[0][0],rows[-1][0]
    write_values=(p.stream_id,p.pass_index,p.pending_page_index,first_key,last_key,len(rows),_ZERO)
    update_values=(last_key,rows[-1][1],len(rows),_ZERO,_ZERO,p.stream_id)
    write_reserve=(sum(_size(v) for v in write_values)+sum(_size(v) for v in update_values)
        +_estimate((p.pending_stream_page_chain,_ZERO))+len(first_key)+len(last_key)+1024)
    if write_reserve>budget.max_bytes:raise C09PhysicalInventoryHold('fixed page descriptor exceeds C09 batch byte ceiling')
    processed=0
    while p.pending_hash_index<len(rows) and processed<budget.max_records:
        if monotonic_ns()-started>=budget.max_local_ns:return True
        key,res,commit=rows[p.pending_hash_index];key_digest=key.hex()
        record_value=(p.pending_record_chain,key_digest,res,commit)
        page_value=(p.pending_page_chain,key_digest,res,commit)
        reserve=_estimate(record_value)+_estimate(page_value)+write_reserve
        if reserve>budget.max_bytes:raise C09PhysicalInventoryHold('one fixed page hash step exceeds the C09 batch byte ceiling')
        if reserve>meter.remaining_bytes:return True
        p.pending_record_chain=_digest(record_value,meter)
        p.pending_page_chain=_digest(page_value,meter)
        p.pending_hash_index+=1;processed+=1
    if p.pending_hash_index<len(rows):return True
    page=p.pending_page_chain;record=p.pending_record_chain
    values=(p.stream_id,p.pass_index,p.pending_page_index,first_key,last_key,len(rows),page)
    prior=_read(db,meter,"SELECT first_path_key,last_path_key,record_count,page_root FROM c09_physical_inventory_pages_v2 WHERE stream_id=? AND pass_index=? AND page_index=?",(p.stream_id,p.pass_index,p.pending_page_index))
    if prior is not None and tuple(prior)!=values[3:]:
        raise C09PhysicalInventoryHold('restarted deterministic page differs from immutable prefix')
    if prior is None:_write(db,meter,"INSERT INTO c09_physical_inventory_pages_v2 VALUES (?,?,?,?,?,?,?)",values)
    _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET after_path=?,after_resource_id=?,record_count=record_count+?,page_count=page_count+1,record_chain=?,page_chain=? WHERE stream_id=?",
        (last_key,rows[-1][1],len(rows),record,_digest((p.pending_stream_page_chain,page),meter),p.stream_id))
    p.pending_page=[];p.pending_after=(last_key,rows[-1][1]);p.pending_bytes=0
    p.pending_sealable=False;p.pending_hash_index=0;p.pending_page_index=0;p.pending_record_chain=None;p.pending_page_chain=None;p.pending_stream_page_chain=None
    return True

def _page_quantum(db,meter,p,budget,started):
    if p.pending_page is not None and p.pending_sealable:
        return _seal_page(db,meter,p,budget,started)
    if p.pending_page is None:
        cursor=_read(db,meter,"SELECT after_path,after_resource_id FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(p.stream_id,))
        p.pending_after=(cursor[0],cursor[1]);p.pending_page=[];p.pending_bytes=0
    while len(p.pending_page)<_PAGE and p.pending_bytes<_PAGE_BYTES:
        if monotonic_ns()-started>=budget.max_local_ns:return True
        cursor=p.pending_after
        lengths=_read(db,meter,"SELECT length(path_key),length(CAST(resource_id AS BLOB)),length(CAST(commitment AS BLOB)) FROM c09_physical_inventory_records_v2 WHERE stream_id=? AND pass_index=? AND (path_key>? OR (path_key=? AND resource_id COLLATE BINARY>?)) ORDER BY path_key COLLATE BINARY,resource_id COLLATE BINARY LIMIT 1",
            (p.stream_id,p.pass_index,cursor[0],cursor[0],cursor[1]))
        if lengths is None:
            if p.pending_page:
                p.pending_sealable=True;return _seal_page(db,meter,p,budget,started)
            break
        weight=lengths[0]*2+lengths[1]*6+lengths[2]*6+128
        if weight>_PAGE_BYTES:raise C09PhysicalInventoryHold('single physical record exceeds fixed page encoding ceiling')
        if p.pending_page and p.pending_bytes+weight>_PAGE_BYTES:
            p.pending_sealable=True;return _seal_page(db,meter,p,budget,started)
        if sum(lengths)>meter.remaining_bytes:return True
        row=_read(db,meter,"SELECT path_key,resource_id,commitment FROM c09_physical_inventory_records_v2 WHERE stream_id=? AND pass_index=? AND (path_key>? OR (path_key=? AND resource_id COLLATE BINARY>?)) ORDER BY path_key COLLATE BINARY,resource_id COLLATE BINARY LIMIT 1",
            (p.stream_id,p.pass_index,cursor[0],cursor[0],cursor[1]))
        if row is None:return True
        p.pending_page.append(row);p.pending_after=(row[0],row[1]);p.pending_bytes+=weight
        if p.pending_bytes>=_PAGE_BYTES or len(p.pending_page)>=_PAGE:
            p.pending_sealable=True;return _seal_page(db,meter,p,budget,started)
    if p.pending_page:return True
    state=_read(db,meter,"SELECT record_count,page_count,record_chain,page_chain,first_record_root,first_page_root,first_record_count,first_page_count FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(p.stream_id,))
    count,pages,record_root,page_root,fr,fp,fc,fpc=state
    if p.pass_index==1:
        if p.baseline is not None and (record_root,page_root,count,pages)!=p.baseline:
            raise C09PhysicalInventoryHold('current filesystem differs from completed physical inventory')
        _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET phase='census2',pass_index=2,after_root_id='',after_path=X'',after_resource_id='',record_count=0,page_count=0,record_chain=?,page_chain=?,first_record_root=?,first_page_root=?,first_record_count=?,first_page_count=? WHERE stream_id=?",
            (_ZERO,_ZERO,record_root,page_root,count,pages,p.stream_id))
        p.pass_index=2;p.observed_records=0;p.second_eof=None;p.pending_page=None;p.pending_after=None;p.pending_bytes=0
        p.pending_sealable=False;p.pending_hash_index=0;p.pending_page_index=0;p.pending_record_chain=None;p.pending_page_chain=None;p.pending_stream_page_chain=None;p.pending_stream_page_chain=None
        return True
    if (count,pages,record_root,page_root)!=(fc,fpc,fr,fp):raise C09PhysicalInventoryHold('independent second filesystem census differs')
    if p.first_eof is None or p.second_eof is None:raise C09PhysicalInventoryHold('independent current-process EOF proofs absent')
    eof=_digest(('sylanne3.c09.physical-inventory.eof.v2',p.source_domain_digest,p.first_eof,p.second_eof,count,record_root,page_root),meter)
    result=dict(record_count=count,page_count=pages,record_root=record_root,page_root=page_root,
        first_eof=p.first_eof,second_eof=p.second_eof,eof_observation_digest=eof)
    _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET phase='complete',result_json=? WHERE stream_id=?",(_wire(result,meter),p.stream_id))
    p.complete=VerifiedPhysicalInventoryV2(_VERIFY,p,count,pages,record_root,page_root,eof)
    return True

def begin_physical_inventory_v2(bound):
    """Start a private scan from Root's currently bound registered source domain."""
    if type(bound) is not InstalledC09PhysicalInventoryBoundV2:
        raise C09PhysicalInventoryHold('actual installed Root physical-domain binding required')
    bound.require_current();digest=bound.source_domain_digest
    stream=hashlib.sha256(canonical_serialize(('sylanne3.c09.physical-inventory.v2',bound.scope_digest,digest)).encode('utf-8')).hexdigest()
    return PhysicalInventoryProgressV2(_ISSUER,bound,stream,digest)

def _advance_quantum(progress,budget,meter):
    bound=progress.bound;bound.require_current();started=monotonic_ns()
    with bound.metadata_transaction() as db:
        if not progress.initialized:
            existing=_read(db,meter,"SELECT 1 FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(progress.stream_id,))
            if existing is None:
                _write(db,meter,"INSERT INTO c09_physical_inventory_streams_v2 (stream_id,source_domain_digest,phase,pass_index,after_root_id,after_path,after_resource_id,record_count,page_count,record_chain,page_chain,active_offset) VALUES (?,?,'census1',1,'',X'','',0,0,?,?,0)",(progress.stream_id,progress.source_domain_digest,_ZERO,_ZERO))
            else:
                prior=_read(db,meter,"SELECT phase,first_record_root,first_page_root,first_record_count,first_page_count FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(progress.stream_id,))
                if prior[0]=='complete':progress.baseline=(prior[1],prior[2],prior[3],prior[4])
                _write(db,meter,"UPDATE c09_physical_inventory_streams_v2 SET phase='census1',pass_index=1,after_root_id='',after_path=X'',after_resource_id='',record_count=0,page_count=0,record_chain=?,page_chain=?,first_eof=NULL,second_eof=NULL,result_json=NULL,active_path=NULL,active_identity=NULL,active_offset=0 WHERE stream_id=?",(_ZERO,_ZERO,progress.stream_id))
            progress.initialized=True
        if progress.active_file is not None:_hash_fragment(db,meter,progress,budget)
        else:
            state=_read(db,meter,"SELECT phase FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(progress.stream_id,))
            if state is None:raise C09PhysicalInventoryHold('physical inventory progress is absent')
            if state[0] in ('pages1','pages2'):_page_quantum(db,meter,progress,budget,started)
            else:
                root=_read(db,meter,"SELECT after_root_id FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(progress.stream_id,))[0]
                if root!=_ROOT_EOF:_root_quantum(db,meter,progress,budget)
                elif not _directory_quantum(db,meter,progress,budget,started):_census_eof_quantum(db,meter,progress)
        if monotonic_ns()-started>budget.max_local_ns or monotonic_ns()-meter.started_ns>budget.max_read_ns:
            raise C09PhysicalInventoryHold('physical inventory quantum exceeded its reserved time')
    bound.require_current()
    return progress.complete if progress.complete is not None else progress

def advance_physical_inventory_v2(progress,budget,meter):
    if type(progress) is not PhysicalInventoryProgressV2 or progress._issuer is not _ISSUER:
        raise C09PhysicalInventoryHold('actual private physical-inventory progress required')
    if type(budget) is not C09BatchBudgetV2 or type(meter) is not C09SqlByteMeterV2 or meter.budget!=budget:
        raise C09PhysicalInventoryHold('actual reserved C09 batch required')
    if progress.failed:raise C09PhysicalInventoryHold('failed in-memory scanner must be restarted from its stable Control prefix')
    try:
        if progress.complete is not None:return progress.complete.require_current()
        value=_advance_quantum(progress,budget,meter)
        return value.require_current() if type(value) is VerifiedPhysicalInventoryV2 else value
    except BaseException:
        progress.failed=True
        if progress.directory_iterator is not None:
            progress.directory_iterator.close();progress.directory_iterator=None
        progress.active_file=None;progress.complete=None;progress.initialized=False
        progress.observed_records=0;progress.pass_index=1;progress.pending_page=None
        progress.pending_after=None;progress.pending_bytes=0;progress.pending_sealable=False
        progress.pending_hash_index=0;progress.pending_page_index=0;progress.pending_record_chain=None
        progress.pending_page_chain=None;progress.pending_stream_page_chain=None
        progress.first_eof=None;progress.second_eof=None
        raise

__all__=['C09PhysicalInventoryHold','PhysicalInventoryProgressV2','VerifiedPhysicalInventoryV2',
 'PHYSICAL_INVENTORY_DDLS_V2','PHYSICAL_INVENTORY_TRIGGERS_V2','PHYSICAL_INVENTORY_TABLES_V2',
 'begin_physical_inventory_v2','advance_physical_inventory_v2']
