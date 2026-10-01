"""SQLite-native snapshot primitive for stopped, exclusively leased cohorts.

A copied snapshot is NOT a restore/compatibility/admission certificate. The
external supervisor must attach current typed journal/Owner/Graph qualification
before publishing backup_ready. No routine here restores or rewinds a source.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import file_observation_v1


def _quote(name):return '"'+name.replace('"','""')+'"'


def _encoded_cell(value):
    if type(value) in (bytes, str) and len(value)>16*1024*1024:
        raise AuthorityUnavailable('managed backup cell exceeds bounded inventory size')
    if type(value) is bytes:return {'sqlite_blob':base64.b64encode(value).decode('ascii')}
    if value is None or type(value) in (str,int,float):return value
    raise AuthorityUnavailable('unsupported SQLite value in backup inventory')


def sqlite_logical_inventory_v2(db,*,maximum_rows=1000000,deadline=None):
    """Hash all actual rows/DDL without copying arbitrary source DDL as code."""
    if type(maximum_rows) is not int or not 1<=maximum_rows<=1000000:
        raise AuthorityUnavailable('bounded backup row limit required')
    objects=tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"))
    tables=[];total=0
    for kind,name,_table,ddl in objects:
        if kind!='table':continue
        columns=tuple(row[1] for row in db.execute('PRAGMA table_info('+_quote(name)+')'))
        rows=[]
        for row in db.execute('SELECT * FROM '+_quote(name)):
            if deadline is not None and time.monotonic()>deadline:
                raise AuthorityUnavailable('managed backup inventory exceeded time bound')
            total+=1
            if total>maximum_rows:raise AuthorityUnavailable('managed backup row inventory exceeds installed bound')
            raw=json.dumps([_encoded_cell(value) for value in row],sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
            rows.append(hashlib.sha256(raw).digest())
        rows.sort()
        tables.append((name,columns,len(rows),hashlib.sha256(b''.join(rows)).hexdigest()))
    material={'schema':'sylanne3.d12.sqlite-logical-inventory.v2','objects':objects,'tables':tuple(tables),
        'user_version':db.execute('PRAGMA user_version').fetchone()[0],
        'application_id':db.execute('PRAGMA application_id').fetchone()[0]}
    raw=json.dumps(material,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    return {'inventory_digest':hashlib.sha256(raw).hexdigest(),'table_count':len(tables),'row_count':total,
        'schema_object_count':len(objects),'user_version':material['user_version'],'application_id':material['application_id']}


def sqlite_companions_present_v2(source):
    """Only a failed lstat proves absence; never follow a companion symlink."""
    present=[]
    for suffix in ('-wal','-shm','-journal'):
        path=Path(str(source)+suffix)
        try:
            before=path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuthorityUnavailable('SQLite companion cannot be inspected') from exc
        if not stat.S_ISREG(before.st_mode):
            raise AuthorityUnavailable('SQLite companion is a symlink or unsupported file')
        try:
            fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NONBLOCK',0))
            try:
                actual=os.fstat(fd);after=path.lstat()
                if (not stat.S_ISREG(actual.st_mode) or not stat.S_ISREG(after.st_mode)
                        or (before.st_dev,before.st_ino)!=(actual.st_dev,actual.st_ino)
                        or (after.st_dev,after.st_ino)!=(actual.st_dev,actual.st_ino)):
                    raise AuthorityUnavailable('SQLite companion identity changed during inspection')
            finally:
                os.close(fd)
        except OSError as exc:
            raise AuthorityUnavailable('SQLite companion is unreadable or changed') from exc
        present.append(suffix)
    return tuple(present)


def leased_sqlite_read_uri_v2(source,instance_lease=None):
    """Do not create WAL companions for an actually leased, closed source."""
    source=Path(source)
    immutable=False
    if instance_lease is not None:
        from .c09_storage_control_v1 import InstalledC09InstanceLeaseV1
        if type(instance_lease) is not InstalledC09InstanceLeaseV1:
            raise TypeError('actual held installation lease required')
        instance_lease.require_held()
    companions=sqlite_companions_present_v2(source)
    if instance_lease is not None:
        instance_lease.require_held()
        immutable=not companions
    return source.as_uri()+('?mode=ro&immutable=1' if immutable else '?mode=ro'),immutable


def snapshot_sqlite_file_v2(source,destination,*,maximum_bytes,maximum_rows=1000000,timeout_seconds=120,instance_lease=None):
    """Private effect component; outer actual supervisor owns all quiescence.

    SQLite backup includes committed WAL contents. No source checkpoint, copied
    DDL execution, source database/WAL write, or wholesale restore occurs.
    A sidecar-free source uses immutable RO only under an actual held lease;
    a source with any companion keeps ordinary WAL-aware snapshot semantics.
    Existing destinations are never overwritten, including interrupted attempts.
    """
    source,destination=Path(source),Path(destination)
    if (not source.is_absolute() or not destination.is_absolute() or source.is_symlink()
            or not source.is_file() or destination.exists() or destination.is_symlink()
            or type(maximum_bytes) is not int or not 1<=maximum_bytes<=8*1024**3
            or type(timeout_seconds) is not int or not 1<=timeout_seconds<=3600):
        raise AuthorityUnavailable('bounded exact new SQLite backup destination required')
    before=file_observation_v1(source)
    uri,immutable=leased_sqlite_read_uri_v2(source,instance_lease)
    wal=Path(str(source)+'-wal')
    wal_before=file_observation_v1(wal) if '-wal' in sqlite_companions_present_v2(source) else None
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);os.close(fd)
    start=time.monotonic()
    src=sqlite3.connect(uri,uri=True,timeout=5,isolation_level=None)
    dst=sqlite3.connect(destination,timeout=5,isolation_level=None)
    try:
        src.execute('PRAGMA query_only=ON');src.execute('PRAGMA temp_store=MEMORY');src.execute('BEGIN')
        if src.execute('PRAGMA quick_check').fetchone()!=('ok',):raise AuthorityUnavailable('source SQLite integrity differs')
        if src.execute('PRAGMA page_count').fetchone()[0]*src.execute('PRAGMA page_size').fetchone()[0]>maximum_bytes:
            raise AuthorityUnavailable('source SQLite snapshot exceeds installed byte bound')
        logical=sqlite_logical_inventory_v2(src,maximum_rows=maximum_rows,deadline=start+timeout_seconds)
        dst.execute('PRAGMA synchronous=FULL')
        def progress(_status,_remaining,total):
            if time.monotonic()-start>timeout_seconds or total*src.execute('PRAGMA page_size').fetchone()[0]>maximum_bytes:
                raise AuthorityUnavailable('SQLite backup exceeded installed time/size bound')
        src.backup(dst,pages=256,progress=progress,sleep=0.01)
        if dst.execute('PRAGMA quick_check').fetchone()!=('ok',):raise AuthorityUnavailable('copied SQLite integrity differs')
        if sqlite_logical_inventory_v2(dst,maximum_rows=maximum_rows,deadline=start+timeout_seconds)!=logical:
            raise AuthorityUnavailable('copied logical rows/DDL differ from source read snapshot')
        result=dst.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        if result is not None and result[0]!=0:raise AuthorityUnavailable('backup WAL checkpoint is busy')
        mode=dst.execute('PRAGMA journal_mode=DELETE').fetchone()[0]
        if mode.lower()!='delete':raise AuthorityUnavailable('backup must be independently closed without WAL')
    finally:
        dst.close();src.close()
    if instance_lease is not None:instance_lease.require_held()
    companions_after=sqlite_companions_present_v2(source)
    if immutable and companions_after:
        raise AuthorityUnavailable('closed source acquired a companion during frozen snapshot')
    after=file_observation_v1(source)
    if after!=before:raise AuthorityUnavailable('source database file changed during managed snapshot')
    wal_after=file_observation_v1(wal) if '-wal' in companions_after else None
    if wal_after!=wal_before:raise AuthorityUnavailable('source SQLite WAL changed during managed snapshot')
    if sqlite_companions_present_v2(destination):raise AuthorityUnavailable('closed backup still has a companion file')
    with destination.open('rb') as stream:os.fsync(stream.fileno())
    parent=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(parent)
    finally:os.close(parent)
    final=file_observation_v1(destination)
    if final['prepared_size']>maximum_bytes:raise AuthorityUnavailable('managed snapshot exceeds byte bound')
    return {'schema':'sylanne3.d12.sqlite-backup-file.v2','source_observation':before,
        'source_wal_observation':wal_before,
        'backup_observation':final,'logical_inventory':logical,'source_write_performed':False,
        'restore_authorized':False}
