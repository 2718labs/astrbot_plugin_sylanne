"""Fixed installed Linux worker for one Core-claimed D13 counter input.

The worker owns no key, claim issuance, CPU receipt, or caller-selected command.
It executes one manifest-pinned program in a unique leaf of Root's delegated
cgroup, sends bytes only after PID/cgroup identity checks, and observes the
result and resource usage for Core's signer.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from types import MappingProxyType

from ..runtime_contracts import canonical_serialize, canonical_digest
from .d13_core_counter_contract_v1 import ClaimedD13CounterInputV1
from .linux_installation_security_v1 import opened_installed_file_v1

MANIFEST_SCHEMA_V1='sylanne3.d13.counter-kernel-manifest.v1'
INPUT_SCHEMA_V1='sylanne3.d13.counter-kernel-input.v1'
OUTPUT_SCHEMA_V1='sylanne3.d13.counter-kernel-output.v1'
ALGORITHM_ID_V1='d13.full_http_counter.v1'
METRIC_ID_V1='sylanne3.local-sdk-mock.full-http-utf8-ceil4.v1'
_INPUT_MAX=16*1024*1024
_OUTPUT_MAX=64*1024
_STEP_CPU_NS=1_000_000_000
_JOB_WALL_SECONDS=60
_STDERR_CHUNK=8192
_OBSERVED=object()
_RUNTIME=object()
_SHA=re.compile(r'[0-9a-f]{64}\Z')


class D13CounterKernelHold(RuntimeError):
    """The fixed counter could not complete inside its original process/cgroup claim."""


def _sha(value,name):
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise D13CounterKernelHold('invalid pinned '+name)
    return value


def _unique_json(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise D13CounterKernelHold('duplicate field in protected counter JSON')
        value[key]=item
    return value


def _no_constant(value):
    raise D13CounterKernelHold('nonfinite counter JSON number')


def _parse_json(data):
    try:
        value=json.loads(data,object_pairs_hook=_unique_json,parse_constant=_no_constant)
    except (ValueError,UnicodeError,TypeError) as exc:
        raise D13CounterKernelHold('protected counter JSON is malformed') from exc
    if type(value) is not dict or canonical_serialize(value).encode('utf-8')!=data:
        raise D13CounterKernelHold('protected counter JSON is not closed canonical JSON')
    return value


def _hash_fd(fd):
    with os.fdopen(os.dup(fd),'rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def _installed_bytes(path,expected_digest,limit):
    with opened_installed_file_v1(path) as fd:
        info=os.fstat(fd)
        if info.st_size>limit:raise D13CounterKernelHold('protected counter asset exceeds its fixed byte limit')
        raw=os.pread(fd,limit+1,0)
        if len(raw)>limit or len(raw)!=info.st_size or hashlib.sha256(raw).hexdigest()!=expected_digest:
            raise D13CounterKernelHold('protected counter manifest hash or length differs')
        return raw


def _manifest(path,manifest_sha256,program_sha256,interpreter_sha256,memory_max_bytes,pids_max,profile_pins):
    raw=_installed_bytes(path,manifest_sha256,8192)
    return _validate_manifest_bytes_v1(raw,program_sha256,interpreter_sha256,memory_max_bytes,pids_max,profile_pins)


def _validate_manifest_bytes_v1(raw,program_sha256,interpreter_sha256,memory_max_bytes,pids_max,profile_pins):
    # Shared original ABI predicates; this function alone issues no runtime proof.
    value=_parse_json(raw)
    required={'schema','algorithm_id','program_sha256','input_schema','output_schema',
        'serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint',
        'max_input_bytes','max_stdout_bytes','max_stderr_bytes','cpu_ms_ceiling',
        'memory_max_bytes','pids_max','interpreter_sha256','metric_id','metric_source_sha256',
        'provider_id','model_id','provider_config_digest','template_digest','tokenizer_fingerprint',
        'wire_policy_fingerprint'}
    if set(value)!=required or value['schema']!=MANIFEST_SCHEMA_V1 or value['algorithm_id']!=ALGORITHM_ID_V1:
        raise D13CounterKernelHold('protected counter manifest schema or algorithm differs')
    if (value['program_sha256']!=program_sha256 or value['interpreter_sha256']!=interpreter_sha256
            or value['input_schema']!=INPUT_SCHEMA_V1
            or value['output_schema']!=OUTPUT_SCHEMA_V1
            or (value['max_input_bytes'],value['max_stdout_bytes'],value['max_stderr_bytes'],value['cpu_ms_ceiling'])
                !=(_INPUT_MAX,_OUTPUT_MAX,_OUTPUT_MAX,1000)
            or value['memory_max_bytes']!=memory_max_bytes or value['pids_max']!=pids_max
            or any(value[name]!=profile_pins[name] for name in ('metric_id','metric_source_sha256','provider_id',
                'model_id','provider_config_digest','template_digest','tokenizer_fingerprint','wire_policy_fingerprint'))):
        raise D13CounterKernelHold('protected counter manifest resource or ABI pin differs')
    for name in ('program_sha256','interpreter_sha256','serializer_fingerprint','applicability_fingerprint',
            'counter_policy_fingerprint','metric_source_sha256','provider_config_digest','template_digest',
            'tokenizer_fingerprint','wire_policy_fingerprint'):
        _sha(value[name],name)
    if (type(value['provider_id']) is not str or not value['provider_id']
            or type(value['model_id']) is not str or not value['model_id']):
        raise D13CounterKernelHold('protected provider/model profile identity differs')
    if (value['serializer_fingerprint']!=profile_pins['serializer_fingerprint']
            or value['counter_policy_fingerprint']!=profile_pins['counter_policy_fingerprint']
            or value['applicability_fingerprint']!=_local_mock_applicability(profile_pins)):
        raise D13CounterKernelHold('protected local Mock metric descriptor fingerprint differs')
    if any(type(value[name]) is not int for name in ('max_input_bytes','max_stdout_bytes','max_stderr_bytes',
            'cpu_ms_ceiling','memory_max_bytes','pids_max')):
        raise D13CounterKernelHold('protected counter manifest limit type differs')
    return value


def _local_mock_applicability(profile):
    descriptor={'schema':'sylanne3.d13.counter-local-mock-applicability.v1','metric_id':METRIC_ID_V1,
        'metric_source_sha256':profile['metric_source_sha256'],'provider_id':profile['provider_id'],
        'model_id':profile['model_id'],'provider_config_digest':profile['provider_config_digest'],
        'template_digest':profile['template_digest'],'serializer_fingerprint':profile['serializer_fingerprint'],
        'tokenizer_fingerprint':profile['tokenizer_fingerprint'],'wire_policy_fingerprint':profile['wire_policy_fingerprint'],
        'counted_bytes':'complete actual SDK HTTP request.content UTF-8 bytes',
        'metric':'max(1,(byte_count+3)//4)',
        'late_slot':{'path':['metadata','sylanne_request_digest'],'alphabet':'0123456789abcdef','characters':64},
        'profile_scope':'isolated-local-sdk-mock-only','production_tokenizer_supported':False}
    return canonical_digest(descriptor)


def _unescape_mount(value):
    return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),value)


def _metered_proc_lines_v1(path,encoding,meter):
    """Current proc file EOF, incremental decoder; no cached mount/membership."""
    import codecs
    decoder=codecs.getincrementaldecoder(encoding)();pending=''
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        while True:
            size=min(8192,meter.remaining_bytes)
            if size<=0:raise D13CounterKernelHold('current proc verification needs another actual quantum')
            meter.require_available(size)
            raw=os.read(fd,size);meter.charge_read(len(raw))
            pending+=decoder.decode(raw,final=not raw)
            while '\n' in pending:
                line,pending=pending.split('\n',1);yield line
            if not raw:
                if pending:yield pending
                return
    finally:os.close(fd)


def _cgroup_mount_for(path,*,meter=None):
    try:lines=Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines() if meter is None else _metered_proc_lines_v1('/proc/self/mountinfo','utf-8',meter)
    except OSError as exc:raise D13CounterKernelHold('Linux mount table is unavailable') from exc
    candidate=Path(path);selected=None
    for line in lines:
        before,separator,after=line.partition(' - ')
        if not separator:continue
        tail=after.split()
        if not tail or tail[0]!='cgroup2':continue
        fields=before.split()
        mount_root=Path(_unescape_mount(fields[3]));mountpoint=Path(_unescape_mount(fields[4]))
        try:relative=candidate.relative_to(mountpoint)
        except ValueError:continue
        group_root=PurePosixPath(str(mount_root))
        for part in relative.parts:group_root=group_root/part
        if meter is None:return mountpoint,str(group_root)
        if selected is None:selected=(mountpoint,str(group_root))
    if selected is not None:return selected
    raise D13CounterKernelHold('delegated path is outside a mounted cgroup2 filesystem')


def _open_directory(path,*,meter=None):
    path=Path(path)
    if not path.is_absolute() or any(part in {'.','..'} for part in path.parts):
        raise D13CounterKernelHold('absolute protected cgroup path required')
    flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)
    fd=os.open('/',flags)
    try:
        for part in path.parts[1:]:
            child=os.open(part,flags,dir_fd=fd)
            os.close(fd);fd=child
        if meter is not None:meter.require_available(4096)
        info=os.fstat(fd)
        if meter is not None:meter.charge_read(len(json.dumps(tuple(info),separators=(',',':')).encode('ascii')))
        if not stat.S_ISDIR(info.st_mode):raise D13CounterKernelHold('cgroup path is not a directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(directory_fd,name,limit=4096,*,meter=None):
    fd=os.open(name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0),dir_fd=directory_fd)
    try:
        chunks=[];total=0
        while total<=limit:
            size=min(8192,limit+1-total)
            if meter is not None:meter.require_available(size)
            part=os.read(fd,size)
            if meter is not None:meter.charge_read(len(part))
            if not part:break
            chunks.append(part);total+=len(part)
        if total>limit:raise D13CounterKernelHold('cgroup observation exceeds fixed bound')
        return b''.join(chunks).decode('ascii')
    finally:os.close(fd)


def _write_at(directory_fd,name,value):
    fd=os.open(name,os.O_WRONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0),dir_fd=directory_fd)
    try:
        data=(str(value)+'\n').encode('ascii')
        if os.write(fd,data)!=len(data):raise D13CounterKernelHold('short cgroup control write')
    finally:os.close(fd)


def _self_cgroup_path(*,meter=None):
    try:lines=Path('/proc/self/cgroup').read_text(encoding='ascii').splitlines() if meter is None else _metered_proc_lines_v1('/proc/self/cgroup','ascii',meter)
    except OSError as exc:raise D13CounterKernelHold('current Linux cgroup is unavailable') from exc
    rows=[line[3:] for line in lines if line.startswith('0::')]
    if len(rows)!=1:raise D13CounterKernelHold('current process is not in one unified cgroup')
    return rows[0]


def _proc_identity(pid):
    try:data=Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    except OSError as exc:raise D13CounterKernelHold('counter PID identity disappeared') from exc
    close=data.rfind(')')
    if close<0:raise D13CounterKernelHold('counter PID stat is malformed')
    fields=data[close+1:].split()
    if len(fields)<=19 or not fields[19].isdigit():raise D13CounterKernelHold('counter PID start time is malformed')
    return (pid,int(fields[19]))


def _proc_group_path(pid):
    try:lines=Path(f'/proc/{pid}/cgroup').read_text(encoding='ascii').splitlines()
    except OSError as exc:raise D13CounterKernelHold('counter PID cgroup membership unavailable') from exc
    rows=[line[3:] for line in lines if line.startswith('0::')]
    if len(rows)!=1:raise D13CounterKernelHold('counter PID is not in one unified cgroup')
    return rows[0]


def _usage_usec(leaf_fd):
    text=_read_at(leaf_fd,'cpu.stat',4096)
    values={}
    for line in text.splitlines():
        parts=line.split()
        if len(parts)!=2 or parts[0] in values or not parts[1].isdigit():
            raise D13CounterKernelHold('cgroup cpu.stat is malformed')
        values[parts[0]]=int(parts[1])
    if 'usage_usec' not in values:raise D13CounterKernelHold('cgroup cpu.stat lacks actual usage_usec')
    return values['usage_usec']


def _pids(leaf_fd):
    text=_read_at(leaf_fd,'cgroup.procs',65536)
    values=[]
    for line in text.splitlines():
        if not line.isdigit():raise D13CounterKernelHold('cgroup process list is malformed')
        values.append(int(line))
    return tuple(values)


def _memory_peak(leaf_fd):
    value=_read_at(leaf_fd,'memory.peak',128).strip()
    if not value.isdigit():raise D13CounterKernelHold('cgroup memory.peak is malformed')
    return int(value)


def _wait4_usage(pid,timeout):
    deadline=time.monotonic()+timeout
    while True:
        waited,status,usage=os.wait4(pid,os.WNOHANG)
        if waited:
            cpu_ns=int(round((usage.ru_utime+usage.ru_stime)*1_000_000_000))
            return os.waitstatus_to_exitcode(status),max(0,cpu_ns)
        if time.monotonic()>=deadline:return None,None
        time.sleep(min(0.005,deadline-time.monotonic()))


def _input_wire(claimed,manifest):
    raw=claimed.input_bytes
    if type(raw) is not bytes or not 0<len(raw)<=_INPUT_MAX:
        raise D13CounterKernelHold('exact bounded immutable counter input bytes required')
    digest=hashlib.sha256(raw).hexdigest()
    if digest!=claimed.input_digest or digest!=claimed.binding.input_digest:
        raise D13CounterKernelHold('counter input digest differs from actual Core claim')
    value=_parse_json(raw)
    fields={'schema','raw_http_template_digest','compressed_http_template_digest','raw_http_utf8',
        'compressed_http_utf8','serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint'}
    if set(value)!=fields or value['schema']!=INPUT_SCHEMA_V1:
        raise D13CounterKernelHold('counter input schema differs')
    for name in ('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint'):
        if value[name]!=manifest[name]:raise D13CounterKernelHold('counter input installed fingerprint differs')
    _sha(value['raw_http_template_digest'],'raw_http_template_digest')
    raw_value=value['raw_http_utf8']
    if type(raw_value) is not str or not raw_value:raise D13CounterKernelHold('actual raw counter wire absent')
    compressed_fields=('compressed_http_template_digest','compressed_http_utf8')
    if (value[compressed_fields[0]] is None)!=(value[compressed_fields[1]] is None):
        raise D13CounterKernelHold('compressed counter wire is only partially present')
    if value[compressed_fields[0]] is not None:
        _sha(value[compressed_fields[0]],compressed_fields[0])
        if type(value[compressed_fields[1]]) is not str or not value[compressed_fields[1]]:
            raise D13CounterKernelHold('compressed counter wire absent')
    return value,digest


def _counter_result(raw,manifest,input_digest):
    value=_parse_json(raw)
    fields={'schema','input_digest','raw_http_template_digest','compressed_http_template_digest',
        'raw_http_bytes','compressed_http_bytes','raw_lower_tokens','raw_upper_tokens',
        'compressed_lower_tokens','compressed_upper_tokens','token_evidence',
        'serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint'}
    if set(value)!=fields or value['schema']!=OUTPUT_SCHEMA_V1 or value['input_digest']!=input_digest:
        raise D13CounterKernelHold('counter stdout schema or input digest differs')
    for name in ('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint'):
        if value[name]!=manifest[name]:raise D13CounterKernelHold('counter stdout installed fingerprint differs')
    for name in ('raw_http_template_digest','compressed_http_template_digest'):
        if value[name] is not None:_sha(value[name],name)
    compressed=tuple(value[name] for name in ('compressed_http_template_digest','compressed_http_bytes',
        'compressed_lower_tokens','compressed_upper_tokens'))
    if any(item is None for item in compressed) and not all(item is None for item in compressed):
        raise D13CounterKernelHold('counter stdout compressed interval is partial')
    for name,minimum in (('raw_http_bytes',1),('raw_lower_tokens',0),('raw_upper_tokens',1)):
        if type(value[name]) is not int or value[name]<minimum:raise D13CounterKernelHold('counter stdout numeric field differs')
    if value['raw_http_bytes']>_INPUT_MAX or value['raw_lower_tokens']>value['raw_upper_tokens']:
        raise D13CounterKernelHold('counter stdout raw interval exceeds fixed bound')
    if compressed[0] is not None:
        for name,minimum in (('compressed_http_bytes',1),('compressed_lower_tokens',0),('compressed_upper_tokens',1)):
            if type(value[name]) is not int or value[name]<minimum:raise D13CounterKernelHold('counter stdout compressed field differs')
        if value['compressed_http_bytes']>_INPUT_MAX or value['compressed_lower_tokens']>value['compressed_upper_tokens']:
            raise D13CounterKernelHold('counter stdout compressed interval exceeds fixed bound')
    if value['token_evidence']!='bounded_full_wire':raise D13CounterKernelHold('counter stdout evidence kind differs')
    return canonical_serialize(value)


@dataclass(frozen=True,slots=True,init=False)
class ObservedD13CounterKernelV1:
    _issuer: object
    _claimed: object
    worker: object
    binding_digest: str
    claim_digest: str
    input_digest: str
    status: str
    actual_cpu_ns: int | None
    result_json: str | None
    pid_identity: tuple | None
    group_identity: tuple
    memory_peak_bytes: int | None
    exit_code: int | None

    def __init__(self,token,claimed,worker,*,status,actual_cpu_ns,result_json,pid_identity,group_identity,memory_peak_bytes,exit_code):
        if token is not _OBSERVED:raise D13CounterKernelHold('counter process observation is worker-issued only')
        from .internal_work_contract import InternalWorkBindingV1,InternalWorkClaimV1
        if type(claimed.binding) is not InternalWorkBindingV1 or type(claimed.claim) is not InternalWorkClaimV1:
            raise D13CounterKernelHold('actual Core work identity required')
        for name,value in (('_issuer',token),('_claimed',claimed),('worker',worker),
                ('binding_digest',claimed.binding.binding_digest),('claim_digest',canonical_digest(claimed.claim)),
                ('input_digest',claimed.input_digest),('status',status),('actual_cpu_ns',actual_cpu_ns),
                ('result_json',result_json),('pid_identity',pid_identity),('group_identity',group_identity),
                ('memory_peak_bytes',memory_peak_bytes),('exit_code',exit_code)):
            object.__setattr__(self,name,value)

    def require_origin(self,claimed,worker):
        if (self._issuer is not _OBSERVED or self._claimed is not claimed or self.worker is not worker
                or type(claimed) is not ClaimedD13CounterInputV1):
            raise D13CounterKernelHold('counter observation is detached from its original Core capsule/executor')
        claimed.require_recorded_execution_origin()
        return self


def _installed_asset_stamp_v1(fd,meter):
    meter.require_available(4096)
    value=os.fstat(fd)
    stamp=tuple(getattr(value,name) for name in ('st_dev','st_ino','st_size','st_mtime_ns',
        'st_ctime_ns','st_mode','st_uid','st_gid','st_nlink'))
    meter.charge_read(len(json.dumps(stamp,separators=(',',':')).encode('ascii')))
    return stamp


class _C09D13RuntimeCursorV1:
    """Private actual asset hashes; progress adopts only after reservation exit."""
    __slots__=('runtime','session','scope_digest','stack','assets','index','offset','digest',
        'manifest_raw','complete','closed','pending')

    def __init__(self,runtime,session,meter):
        from contextlib import ExitStack
        from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        if type(session) is not C09PagedCaptureSessionV2 or type(runtime) is not InstalledD13CounterRuntimeV1:
            raise D13CounterKernelHold('actual installed C09 runtime qualification required')
        runtime._require_bound_worker_v1(runtime._worker);session.require_current()
        if session.require_installed_d13_counter_service_v1()._installed_runtime is not runtime:
            raise D13CounterKernelHold('runtime qualification crossed actual installed session')
        self.runtime,self.session,self.scope_digest=runtime,session,session.scope.scope_digest
        self.stack=ExitStack();self.assets=[];self.index=0;self.offset=0;self.digest=hashlib.sha256()
        self.manifest_raw=b'';self.complete=False;self.closed=False;self.pending=None
        worker=runtime._worker
        try:
            for path,pin in ((worker.program_path,runtime.program_sha256),
                    (worker.interpreter_path,runtime.interpreter_sha256),(worker.manifest_path,runtime.manifest_sha256)):
                fd=self.stack.enter_context(opened_installed_file_v1(path,meter=meter))
                self.assets.append((path,fd,pin,_installed_asset_stamp_v1(fd,meter)))
            if self.assets[2][3][2]>8192:
                raise D13CounterKernelHold('protected counter manifest exceeds original bound')
        except BaseException:
            self.close();raise

    def _require_assets_v1(self,meter):
        if self.closed:raise D13CounterKernelHold('runtime qualification closed')
        self.session.require_current();self.runtime._require_bound_worker_v1(self.runtime._worker)
        if (self.session.scope.scope_digest!=self.scope_digest
                or self.session.require_installed_d13_counter_service_v1()._installed_runtime is not self.runtime):
            raise D13CounterKernelHold('runtime qualification scope/installation changed')
        worker=self.runtime._worker
        if tuple(item[0] for item in self.assets)!=(worker.program_path,worker.interpreter_path,worker.manifest_path):
            raise D13CounterKernelHold('protected worker asset paths changed during qualification')
        for path,fd,pin,stamp in self.assets:
            if _installed_asset_stamp_v1(fd,meter)!=stamp:
                raise D13CounterKernelHold('protected runtime asset changed during complete hash')
            with opened_installed_file_v1(path,meter=meter) as actual:
                if _installed_asset_stamp_v1(actual,meter)!=stamp:
                    raise D13CounterKernelHold('protected runtime asset path/permissions changed')

    def advance(self,meter):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        if current_c09_sql_meter_v2() is not meter:raise D13CounterKernelHold('runtime hash requires actual current reserved meter')
        if self.pending is not None:raise D13CounterKernelHold('runtime hash quantum awaiting actual successful adoption')
        self._require_assets_v1(meter)
        if self.complete:return True
        if self.index==3:
            self._require_cgroup_v1(meter)
            self._require_assets_v1(meter)
            self.pending=(self.index,self.offset,self.digest,self.manifest_raw,True)
            return False
        path,fd,pin,stamp=self.assets[self.index];remaining=stamp[2]-self.offset
        size=min(8192,remaining)
        meter.require_available(size+1)
        raw=os.pread(fd,size,self.offset);meter.charge_read(len(raw))
        if len(raw)!=size:raise D13CounterKernelHold('protected runtime asset read lost original length')
        digest=self.digest.copy();digest.update(raw)
        manifest=self.manifest_raw+raw if self.index==2 else self.manifest_raw
        offset=self.offset+size;index=self.index;complete=False
        if offset==stamp[2]:
            suffix=os.pread(fd,1,offset);meter.charge_read(len(suffix))
            if suffix or digest.hexdigest()!=pin:
                raise D13CounterKernelHold('protected runtime asset full SHA or EOF differs')
            index+=1;offset=0;digest=hashlib.sha256()
            if index==3:
                worker=self.runtime._worker
                value=_validate_manifest_bytes_v1(manifest,self.runtime.program_sha256,
                    self.runtime.interpreter_sha256,worker.memory_max_bytes,worker.pids_max,worker._profile_pins)
                if value!=worker._manifest:raise D13CounterKernelHold('protected manifest full original predicates differ')
                # Current cgroup checks remain mandatory before any qualification.
                # Their metered reader is the next state; bytes alone are not proof.
                complete=False
        self._require_assets_v1(meter)
        self.pending=(index,offset,digest,manifest,complete)
        return False

    def _require_cgroup_v1(self,meter):
        worker=self.runtime._worker
        identity,caps=worker._verify_delegated(meter=meter)
        if identity!=worker._delegated_identity or caps!=worker._delegated_caps:
            raise D13CounterKernelHold('protected current delegated cgroup identity/caps changed')

    def require_qualified(self,runtime,session,meter):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        if current_c09_sql_meter_v2() is not meter:raise D13CounterKernelHold('runtime consumer requires actual current reserved meter')
        if runtime is not self.runtime or session is not self.session or not self.complete or self.pending is not None:
            raise D13CounterKernelHold('actual complete installed C09 runtime qualification required')
        self._require_assets_v1(meter)
        worker=self.runtime._worker
        value=_validate_manifest_bytes_v1(self.manifest_raw,self.runtime.program_sha256,
            self.runtime.interpreter_sha256,worker.memory_max_bytes,worker.pids_max,worker._profile_pins)
        if value!=worker._manifest:raise D13CounterKernelHold('current protected manifest configuration differs')
        self._require_cgroup_v1(meter);self._require_assets_v1(meter)
        return self

    def _adopt_completed_quantum_v1(self,session):
        if session is not self.session:raise D13CounterKernelHold('runtime hash adoption crossed actual session')
        if self.pending is None:raise D13CounterKernelHold('no actual completed hash quantum to adopt')
        self.index,self.offset,self.digest,self.manifest_raw,self.complete=self.pending;self.pending=None

    def close(self):
        if not self.closed:
            self.stack.close();self.closed=True;self.pending=None


@dataclass(frozen=True,slots=True,init=False)
class InstalledD13CounterRuntimeV1:
    _issuer: object
    _worker: object
    program_sha256: str
    interpreter_sha256: str
    manifest_sha256: str
    installation_id: str
    worker_identity: object

    def __init__(self,token,worker):
        if token is not _RUNTIME:raise D13CounterKernelHold('installed counter runtime proof is worker-issued only')
        for name,value in (('_issuer',token),('_worker',worker),('program_sha256',worker.program_sha256),
                ('interpreter_sha256',worker.interpreter_sha256),('manifest_sha256',worker.manifest_sha256),
                ('installation_id',worker.installation_id),('worker_identity',worker)):
            object.__setattr__(self,name,value)

    def _require_bound_worker_v1(self,worker=None):
        if (self._issuer is not _RUNTIME or worker is not None and worker is not self._worker
                or self.worker_identity is not self._worker
                or self.program_sha256!=self._worker.program_sha256
                or self.interpreter_sha256!=self._worker.interpreter_sha256
                or self.manifest_sha256!=self._worker.manifest_sha256
                or self.installation_id!=self._worker.installation_id):
            raise D13CounterKernelHold('installed runtime proof is detached from its protected worker instance')
        return self

    def begin_c09_runtime_check_v1(self,session,meter):
        return _C09D13RuntimeCursorV1(self,session,meter)

    def require_current(self,worker=None,*,qualification=None,session=None,meter=None):
        self._require_bound_worker_v1(worker)
        if qualification is None:
            self._worker._verify_runtime()
        else:
            if type(qualification) is not _C09D13RuntimeCursorV1 or meter is None:
                raise D13CounterKernelHold('private complete metered installed runtime qualification required')
            qualification.require_qualified(self,session,meter)
        return self


class InstalledD13CounterKernelWorkerV1:
    """One fixed program runner; it accepts only the live Core-issued byte capsule."""
    __slots__=('program_path','program_sha256','interpreter_path','interpreter_sha256','manifest_path','manifest_sha256',
        'delegated_cgroup_path','installation_id','memory_max_bytes','pids_max','_profile_pins','_manifest',
        '_delegated_identity','_delegated_caps','_used','_lock')

    def __init__(self,*,program_path,program_sha256,interpreter_path,interpreter_sha256,
                 manifest_path,manifest_sha256,delegated_cgroup_path,installation_id,memory_max_bytes,pids_max,
                 metric_source_sha256,provider_id,model_id,provider_config_digest,template_digest,
                 serializer_fingerprint,tokenizer_fingerprint,wire_policy_fingerprint,counter_policy_fingerprint):
        if not sys.platform.startswith('linux'):
            raise D13CounterKernelHold('D13 kernel worker requires Linux cgroup v2')
        self.program_path=str(program_path);self.program_sha256=_sha(program_sha256,'program_sha256')
        self.interpreter_path=str(interpreter_path);self.interpreter_sha256=_sha(interpreter_sha256,'interpreter_sha256')
        self.manifest_path=str(manifest_path);self.manifest_sha256=_sha(manifest_sha256,'manifest_sha256')
        self.delegated_cgroup_path=str(delegated_cgroup_path)
        if (type(installation_id) is not str or not installation_id
                or type(memory_max_bytes) is not int or memory_max_bytes<1
                or type(pids_max) is not int or pids_max<1):
            raise D13CounterKernelHold('protected memory and pid caps required')
        self.installation_id=installation_id;self.memory_max_bytes=memory_max_bytes;self.pids_max=pids_max
        profile_pins={'metric_id':METRIC_ID_V1,'metric_source_sha256':_sha(metric_source_sha256,'metric_source_sha256'),
            'provider_id':provider_id,'model_id':model_id,'provider_config_digest':_sha(provider_config_digest,'provider_config_digest'),
            'template_digest':_sha(template_digest,'template_digest'),
            'serializer_fingerprint':_sha(serializer_fingerprint,'serializer_fingerprint'),
            'tokenizer_fingerprint':_sha(tokenizer_fingerprint,'tokenizer_fingerprint'),
            'wire_policy_fingerprint':_sha(wire_policy_fingerprint,'wire_policy_fingerprint'),
            'counter_policy_fingerprint':_sha(counter_policy_fingerprint,'counter_policy_fingerprint')}
        if any(type(profile_pins[name]) is not str or not profile_pins[name]
                for name in ('provider_id','model_id')):
            raise D13CounterKernelHold('protected provider/model profile identity required')
        self._profile_pins=MappingProxyType(profile_pins)
        self._manifest=_manifest(self.manifest_path,self.manifest_sha256,self.program_sha256,
            self.interpreter_sha256,memory_max_bytes,pids_max,self._profile_pins)
        self._used=set();self._lock=threading.Lock()
        self._delegated_identity,self._delegated_caps=self._verify_delegated()
        self._verify_runtime()

    def _verify_program(self):
        with opened_installed_file_v1(self.program_path) as fd:
            if _hash_fd(fd)!=self.program_sha256:raise D13CounterKernelHold('protected counter program bytes changed')
        with opened_installed_file_v1(self.interpreter_path) as fd:
            if _hash_fd(fd)!=self.interpreter_sha256:raise D13CounterKernelHold('protected counter interpreter bytes changed')
        value=_manifest(self.manifest_path,self.manifest_sha256,self.program_sha256,self.interpreter_sha256,
            self.memory_max_bytes,self.pids_max,self._profile_pins)
        if value!=self._manifest:raise D13CounterKernelHold('protected counter manifest changed')

    def _verify_delegated(self,*,meter=None):
        self._resolve_cgroup(self.delegated_cgroup_path,meter=meter)
        fd=_open_directory(self.delegated_cgroup_path,meter=meter)
        try:
            if meter is not None:meter.require_available(4096)
            identity=os.fstat(fd)
            if meter is not None:meter.charge_read(len(json.dumps(tuple(identity),separators=(',',':')).encode('ascii')))
            caps=(_read_at(fd,'memory.max',meter=meter).strip(),_read_at(fd,'pids.max',meter=meter).strip())
            if (caps[0].isdigit() and self.memory_max_bytes>int(caps[0])
                    or caps[1].isdigit() and self.pids_max>int(caps[1])):
                raise D13CounterKernelHold('protected counter cap exceeds the actual Root delegated group')
            return (identity.st_dev,identity.st_ino),caps
        finally:os.close(fd)

    def _verify_runtime(self):
        self._verify_program()
        identity,caps=self._verify_delegated()
        if identity!=self._delegated_identity or caps!=self._delegated_caps:
            raise D13CounterKernelHold('protected installed runtime or delegated cgroup identity changed')
        return self

    def require_installed_runtime_v1(self):
        self._verify_runtime()
        return InstalledD13CounterRuntimeV1(_RUNTIME,self)

    @staticmethod
    def _resolve_cgroup(path,*,meter=None):
        if type(path) is not str or not Path(path).is_absolute() or '..' in Path(path).parts:
            raise D13CounterKernelHold('protected delegated cgroup path required')
        mountpoint,group_path=_cgroup_mount_for(path,meter=meter)
        if group_path=='/':raise D13CounterKernelHold('D13 worker cannot use the global cgroup2 root')
        parent_fd=_open_directory(path,meter=meter)
        try:
            controllers=set(_read_at(parent_fd,'cgroup.controllers',meter=meter).split())
            enabled=set(_read_at(parent_fd,'cgroup.subtree_control',meter=meter).replace('+','').split())
            if not {'cpu','memory','pids'}.issubset(controllers & enabled):
                raise D13CounterKernelHold('Root delegated cgroup lacks fixed CPU/memory/pids controllers')
            actual=_self_cgroup_path(meter=meter)
            if actual!=group_path and not actual.startswith(group_path.rstrip('/')+'/'):
                raise D13CounterKernelHold('worker is outside its actual Root-delegated cgroup')
            return mountpoint,group_path
        finally:os.close(parent_fd)

    def _make_leaf(self,binding_digest):
        _mountpoint,group_path=self._resolve_cgroup(self.delegated_cgroup_path)
        parent_fd=_open_directory(self.delegated_cgroup_path);name=binding_digest
        try:
            parent_type=_read_at(parent_fd,'cgroup.type').strip()
            parent_memory=_read_at(parent_fd,'memory.max').strip()
            parent_pids=_read_at(parent_fd,'pids.max').strip()
        except BaseException:
            os.close(parent_fd)
            raise
        if parent_type!='domain':
            os.close(parent_fd)
            raise D13CounterKernelHold('Root delegated cgroup must be a domain resource group')
        if (parent_memory.isdigit() and self.memory_max_bytes>int(parent_memory)
                or parent_pids.isdigit() and self.pids_max>int(parent_pids)):
            os.close(parent_fd)
            raise D13CounterKernelHold('worker cap exceeds the existing Root resource profile')
        try:os.mkdir(name,0o700,dir_fd=parent_fd)
        except FileExistsError as exc:
            os.close(parent_fd)
            raise D13CounterKernelHold('original D13 binding already has a cgroup execution leaf') from exc
        except BaseException:
            os.close(parent_fd)
            raise
        try:leaf_fd=os.open(name,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0),dir_fd=parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
        group_path=posixpath.join(group_path,name)
        try:
            identity=os.fstat(leaf_fd)
            if _pids(leaf_fd):raise D13CounterKernelHold('claim-specific counter cgroup is not empty')
            _write_at(leaf_fd,'memory.max',self.memory_max_bytes)
            _write_at(leaf_fd,'pids.max',self.pids_max)
            _write_at(leaf_fd,'cpu.max','100000 100000')
            kill_fd=os.open('cgroup.kill',os.O_WRONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0),dir_fd=leaf_fd)
            try:
                if not stat.S_ISREG(os.fstat(kill_fd).st_mode):
                    raise D13CounterKernelHold('cgroup.kill is not a regular control file')
            finally:os.close(kill_fd)
            _usage_usec(leaf_fd)
            return parent_fd,leaf_fd,(identity.st_dev,identity.st_ino),group_path
        except BaseException:
            os.close(leaf_fd);os.close(parent_fd)
            raise

    @staticmethod
    def _kill_leaf(leaf_fd,pid):
        try:_write_at(leaf_fd,'cgroup.kill',1)
        except (OSError,D13CounterKernelHold):pass
        if pid is not None:
            try:os.killpg(pid,signal.SIGKILL)
            except ProcessLookupError:pass

    def run(self,claimed):
        if type(claimed) is not ClaimedD13CounterInputV1:
            raise D13CounterKernelHold('live exact Root-issued D13 counter capsule required')
        claimed.require_current()
        binding=claimed.binding
        if (claimed.cpu_ms_ceiling!=1000 or claimed.installation_id!=self.installation_id
                or claimed.authority_namespace!=binding.namespace
                or type(claimed.expires_at_utc) not in (int,float) or not math.isfinite(claimed.expires_at_utc)
                or type(claimed.input_bytes) is not bytes or len(claimed.input_bytes)>_INPUT_MAX):
            raise D13CounterKernelHold('D13 claim scope, step ceiling, lifetime or input differs')
        _,input_digest=_input_wire(claimed,self._manifest)
        if (input_digest!=claimed.input_digest or hashlib.sha256(claimed.input_bytes).hexdigest()!=input_digest):
            raise D13CounterKernelHold('D13 actual immutable input hash differs')
        self._verify_runtime()
        with self._lock:
            if binding.binding_digest in self._used:raise D13CounterKernelHold('original D13 CPU claim already ran in this worker process')
            self._used.add(binding.binding_digest)
        return self._execute(claimed,input_digest)

    def _execute(self,claimed,input_digest):
        parent_fd,leaf_fd,group_identity,group_path=self._make_leaf(claimed.binding.binding_digest)
        proc=None;program_context=None;interpreter_context=None;pid_identity=None;exit_code=None;wait4_cpu_ns=None
        stdout=bytearray();stderr_bytes=0;actual_cpu_ns=None;memory_peak=None;result_json=None
        status='unknown';baseline=None
        try:
            baseline=_usage_usec(leaf_fd)
            started=time.monotonic();remaining=claimed.expires_at_utc-time.time()
            deadline=min(started+_JOB_WALL_SECONDS,started+max(0.0,remaining))
            if remaining<=0:
                actual_cpu_ns=max(0,_usage_usec(leaf_fd)-baseline)*1000
                memory_peak=_memory_peak(leaf_fd)
                return self._observation(claimed,status='failed',actual_cpu_ns=actual_cpu_ns,result_json=None,
                    pid_identity=None,group_identity=group_identity,memory_peak_bytes=memory_peak,exit_code=None)
            program_context=opened_installed_file_v1(self.program_path)
            program_fd=program_context.__enter__()
            if _hash_fd(program_fd)!=self.program_sha256:
                raise D13CounterKernelHold('protected counter program changed before launch')
            interpreter_context=opened_installed_file_v1(self.interpreter_path)
            interpreter_fd=interpreter_context.__enter__()
            if _hash_fd(interpreter_fd)!=self.interpreter_sha256:
                raise D13CounterKernelHold('protected counter interpreter changed before launch')
            proc=subprocess.Popen([f'/proc/self/fd/{interpreter_fd}','-I','-S',f'/proc/self/fd/{program_fd}'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                shell=False,close_fds=True,pass_fds=(interpreter_fd,program_fd),start_new_session=True,cwd='/',
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
            pid_identity=_proc_identity(proc.pid)
            _write_at(leaf_fd,'cgroup.procs',proc.pid)
            if (_proc_group_path(proc.pid)!=group_path or _proc_identity(proc.pid)!=pid_identity
                    or proc.pid not in _pids(leaf_fd)):
                self._kill_leaf(leaf_fd,proc.pid)
                exit_code,wait4_cpu_ns=_wait4_usage(proc.pid,1.0);proc.returncode=exit_code
                return self._observation(claimed,status='unknown',actual_cpu_ns=None,result_json=None,
                    pid_identity=pid_identity,group_identity=group_identity,memory_peak_bytes=None,exit_code=exit_code)
            claimed.require_current()
            if time.monotonic()>=deadline or time.time()>=claimed.expires_at_utc:
                self._kill_leaf(leaf_fd,proc.pid)
                exit_code,wait4_cpu_ns=_wait4_usage(proc.pid,1.0);proc.returncode=exit_code
                pids=_pids(leaf_fd)
                if pids or exit_code is None:
                    return self._observation(claimed,status='unknown',actual_cpu_ns=None,result_json=None,
                        pid_identity=pid_identity,group_identity=group_identity,memory_peak_bytes=_memory_peak(leaf_fd),exit_code=exit_code)
                cpu=max(wait4_cpu_ns,max(0,_usage_usec(leaf_fd)-baseline)*1000)
                return self._observation(claimed,status='failed',actual_cpu_ns=cpu,result_json=None,
                    pid_identity=pid_identity,group_identity=group_identity,memory_peak_bytes=_memory_peak(leaf_fd),exit_code=exit_code)
            in_fd=proc.stdin.fileno();out_fd=proc.stdout.fileno();err_fd=proc.stderr.fileno()
            for fd in (in_fd,out_fd,err_fd):os.set_blocking(fd,False)
            selector=selectors.DefaultSelector();selector.register(in_fd,selectors.EVENT_WRITE,'stdin')
            selector.register(out_fd,selectors.EVENT_READ,'stdout');selector.register(err_fd,selectors.EVENT_READ,'stderr')
            view=memoryview(claimed.input_bytes);input_sent=0;failed=False
            try:
                while selector.get_map() or proc.returncode is None or _pids(leaf_fd):
                    if proc.returncode is None:
                        exit_code,measured=_wait4_usage(proc.pid,0.0)
                        if exit_code is not None:
                            proc.returncode=exit_code;wait4_cpu_ns=measured
                    if time.monotonic()>=deadline or time.time()>=claimed.expires_at_utc:
                        failed=True;self._kill_leaf(leaf_fd,proc.pid);break
                    used=_usage_usec(leaf_fd)-baseline
                    if used>1_000_000:
                        failed=True;self._kill_leaf(leaf_fd,proc.pid);break
                    for key,_ in selector.select(min(0.01,max(0.0,deadline-time.monotonic()))):
                        if key.data=='stdin':
                            try:sent=os.write(in_fd,view[input_sent:input_sent+65536])
                            except BlockingIOError:continue
                            except BrokenPipeError:
                                failed=True;selector.unregister(in_fd);proc.stdin.close();continue
                            if sent<=0:
                                failed=True;selector.unregister(in_fd);proc.stdin.close();continue
                            input_sent+=sent
                            if input_sent==len(view):selector.unregister(in_fd);proc.stdin.close()
                        else:
                            block=os.read(key.fd,_STDERR_CHUNK)
                            if not block:
                                selector.unregister(key.fd)
                                if key.data=='stdout':proc.stdout.close()
                                else:proc.stderr.close()
                            elif key.data=='stdout':
                                if len(stdout)+len(block)>_OUTPUT_MAX:
                                    failed=True;self._kill_leaf(leaf_fd,proc.pid);break
                                stdout.extend(block)
                            else:
                                stderr_bytes+=len(block)
                                if stderr_bytes>_OUTPUT_MAX:
                                    failed=True;self._kill_leaf(leaf_fd,proc.pid);break
                if input_sent!=len(view):failed=True
            finally:selector.close()
            if proc.returncode is None:
                exit_code,measured=_wait4_usage(proc.pid,max(0.0,min(deadline-time.monotonic(),0.5)))
                if exit_code is not None:
                    proc.returncode=exit_code;wait4_cpu_ns=measured
            if proc.returncode is None:
                self._kill_leaf(leaf_fd,proc.pid)
                exit_code,measured=_wait4_usage(proc.pid,0.5)
                if exit_code is not None:
                    proc.returncode=exit_code;wait4_cpu_ns=measured
            pids=_pids(leaf_fd)
            if pids:
                self._kill_leaf(leaf_fd,proc.pid);pids=_pids(leaf_fd)
            exit_code=proc.returncode
            if pids or exit_code is None:
                return self._observation(claimed,status='unknown',actual_cpu_ns=None,result_json=None,
                    pid_identity=pid_identity,group_identity=group_identity,
                    memory_peak_bytes=_memory_peak(leaf_fd),exit_code=exit_code)
            cpu_after=_usage_usec(leaf_fd)
            actual_cpu_ns=max(wait4_cpu_ns or 0,max(0,cpu_after-baseline)*1000)
            memory_peak=_memory_peak(leaf_fd)
            if (not failed and not pids and exit_code==0 and input_sent==len(view)
                    and actual_cpu_ns<=_STEP_CPU_NS):
                result_json=_counter_result(bytes(stdout),self._manifest,input_digest)
                status='completed'
            else:status='failed' if not pids and exit_code is not None else 'unknown'
            return self._observation(claimed,status=status,actual_cpu_ns=actual_cpu_ns,
                result_json=result_json,pid_identity=pid_identity,group_identity=group_identity,
                memory_peak_bytes=memory_peak,exit_code=exit_code)
        except BaseException:
            if proc is not None:
                self._kill_leaf(leaf_fd,proc.pid)
                exit_code,wait4_cpu_ns=_wait4_usage(proc.pid,0.5)
                if exit_code is not None:proc.returncode=exit_code
            try:
                pids=_pids(leaf_fd);exit_code=None if proc is None else proc.returncode
                if pids or proc is not None and exit_code is None:
                    return self._observation(claimed,status='unknown',actual_cpu_ns=None,result_json=None,
                        pid_identity=pid_identity,group_identity=group_identity,
                        memory_peak_bytes=_memory_peak(leaf_fd),exit_code=exit_code)
                cpu=max(wait4_cpu_ns or 0,max(0,_usage_usec(leaf_fd)-(0 if baseline is None else baseline))*1000)
                memory_peak=_memory_peak(leaf_fd)
                return self._observation(claimed,status='failed',actual_cpu_ns=cpu,
                    result_json=None,pid_identity=pid_identity,group_identity=group_identity,
                    memory_peak_bytes=memory_peak,exit_code=exit_code)
            except BaseException:
                return self._observation(claimed,status='unknown',actual_cpu_ns=None,result_json=None,
                    pid_identity=pid_identity,group_identity=group_identity,memory_peak_bytes=None,
                    exit_code=None if proc is None else proc.returncode)
        finally:
            if program_context is not None:program_context.__exit__(None,None,None)
            if interpreter_context is not None:interpreter_context.__exit__(None,None,None)
            if proc is not None:
                for stream in (proc.stdin,proc.stdout,proc.stderr):
                    if stream is not None and not stream.closed:stream.close()
            os.close(leaf_fd);os.close(parent_fd)

    def _observation(self,claimed,*,status,actual_cpu_ns,result_json,pid_identity,group_identity,memory_peak_bytes,exit_code):
        return ObservedD13CounterKernelV1(_OBSERVED,claimed,self,status=status,
            actual_cpu_ns=actual_cpu_ns,result_json=result_json,pid_identity=pid_identity,
            group_identity=group_identity,memory_peak_bytes=memory_peak_bytes,exit_code=exit_code)

    def release_group(self,observed,claimed):
        if type(observed) is not ObservedD13CounterKernelV1:
            raise D13CounterKernelHold('actual private CPU execution observation required')
        observed.require_origin(claimed,self)
        parent_fd=_open_directory(self.delegated_cgroup_path);leaf_fd=None
        try:
            leaf_fd=os.open(claimed.binding.binding_digest,
                os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0),dir_fd=parent_fd)
            info=os.fstat(leaf_fd)
            if (info.st_dev,info.st_ino)!=observed.group_identity or _pids(leaf_fd):
                raise D13CounterKernelHold('original CPU cgroup is not the same drained execution leaf')
            if 'populated 0' not in _read_at(leaf_fd,'cgroup.events',4096).splitlines():
                raise D13CounterKernelHold('original CPU cgroup still has processes')
            os.close(leaf_fd);leaf_fd=None
            os.rmdir(claimed.binding.binding_digest,dir_fd=parent_fd)
        finally:
            if leaf_fd is not None:os.close(leaf_fd)
            os.close(parent_fd)

__all__=['D13CounterKernelHold','InstalledD13CounterKernelWorkerV1','InstalledD13CounterRuntimeV1',
    'ObservedD13CounterKernelV1']
