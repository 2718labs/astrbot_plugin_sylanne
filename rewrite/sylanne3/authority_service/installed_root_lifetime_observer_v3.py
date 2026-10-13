"""Installed outer Root custody survives its measured PID1 namespace children."""
from __future__ import annotations
from dataclasses import asdict
from pathlib import Path
from weakref import WeakSet,WeakKeyDictionary
import array,ctypes,fcntl,hashlib,json,os,select,signal,socket,struct,subprocess,sys,time
from uuid import uuid4
from datetime import datetime,timezone
from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import read_process_identity_v1
from .linux_installation_security_v1 import (read_installed_bytes_v1,read_installed_json_v1,
    require_linux_administrator_v1,opened_installed_file_v1)
from ..runtime_contracts import canonical_digest,canonical_serialize

SPEC_PATH='/etc/sylanne/supervision/root-lifetime.json'
_SPEC='sylanne3.installed-root-lifetime.v3'
_LAUNCH='sylanne3.installed-root-launch-scope.v3'
_RESOURCE='sylanne3.installed-root-resource-approval.v3'
_RETIRE='sylanne3.installed-root-cohort-retirement.v3'
_SPEC_FIELDS={'schema','authority_id','installation_id','namespace_cohort','profile_id','outer_entry','python_executable',
    'inner_entry','host_spec','authority_spec','control_socket_path','protected_state_directory',
    'resource_scope_original_ref','resource_scope_original_digest','spec_digest'}
_RESOURCE_FIELDS={'schema','approval_basis','operation_ref','unit_name','authority_id','installation_id','launch_scope_digest',
    'kernel_boot_id','cgroup_path','cgroup_identity','cpu_max','memory_max','pids_max','deadline_utc',
    'administrator_process_original','administrator_uid','approval_original_digest'}
_ISSUER=object();_CAPS=WeakSet();_CAP_BINDINGS=WeakKeyDictionary()

def _boot():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def _utc(value):return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)
def _identity(fd):
    st=os.fstat(fd);return dict(device=st.st_dev,inode=st.st_ino)
def _read_at(fd,path,limit=65536):
    child=os.open(path,os.O_RDONLY|os.O_CLOEXEC,dir_fd=fd)
    try:
        with os.fdopen(child,'rb') as stream:raw=stream.read(limit+1)
    except BaseException:raise
    if len(raw)>limit:raise AuthorityUnavailable('bounded installed Root custody metadata required')
    return raw.decode()
def _packet(channel):
    raw=channel.recv(65537)
    if not raw or len(raw)>65536:raise AuthorityUnavailable('bounded actual outer Root packet required')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise AuthorityUnavailable('duplicate outer Root packet field')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique)
def _send_retirement(channel,value):
    pidfd=os.pidfd_open(os.getpid())
    try:
        channel.sendmsg([canonical_serialize(value).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[pidfd]))])
    finally:os.close(pidfd)
def _retirement_packet(channel):
    raw,ancillary,flags,_=channel.recvmsg(65537,socket.CMSG_SPACE(4))
    descriptors=[]
    for level,kind,data in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
            values=array.array('i');values.frombytes(data[:len(data)//values.itemsize*values.itemsize]);descriptors.extend(values)
    if not raw or len(raw)>65536 or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or len(descriptors)!=1:
        for fd in descriptors:os.close(fd)
        raise AuthorityUnavailable('one actual outer Root pidfd and bounded custody packet required')
    if os.readlink(f'/proc/self/fd/{descriptors[0]}')!='anon_inode:[pidfd]':
        os.close(descriptors[0]);raise AuthorityUnavailable('outer Root custody requires its actual kernel pidfd')
    return json.loads(raw),descriptors[0]
def _send(channel,value):channel.sendall(canonical_serialize(value).encode())
def _scope(spec):
    return canonical_digest({name:spec[name] for name in _SPEC_FIELDS-{'resource_scope_original_ref',
        'resource_scope_original_digest','spec_digest'}})
def _protected_parent(path):
    for item in (Path(path).parent,*Path(path).parent.parents):
        st=item.lstat()
        if item.is_symlink() or not item.is_dir() or st.st_uid!=0 or st.st_mode&0o022:
            raise AuthorityUnavailable('actual installed outer Root parent is not protected')
def _sync_original(path):
    with opened_installed_file_v1(path,private=True,allowed_gid=0) as fd:
        os.fsync(fd)
        parent=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)

def _create_original(path,value):
    _protected_parent(path)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb') as stream:
        stream.write(canonical_serialize(value).encode());stream.flush();os.fsync(stream.fileno())
    parent=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)

def _require_installed_root_lifetime_spec_v3(spec):
    if set(spec)!=_SPEC_FIELDS or spec['schema']!=_SPEC or len(spec['namespace_cohort'])!=1:
        raise AuthorityUnavailable('exact installed outer Root lifetime spec required')
    if canonical_digest({k:v for k,v in spec.items() if k!='spec_digest'})!=spec['spec_digest']:
        raise AuthorityUnavailable('installed outer Root spec digest differs')
    for name in ('outer_entry','python_executable','inner_entry','host_spec','authority_spec'):
        item=spec[name]
        if set(item)!={'path','sha256'} or hashlib.sha256(read_installed_bytes_v1(item['path'],limit=64*1024*1024)).hexdigest()!=item['sha256']:
            raise AuthorityUnavailable('installed outer Root fixed code/spec pin differs')
    from .installed_process_supervisor_v1 import load_process_supervisor_spec_v1
    host=load_process_supervisor_spec_v1(spec['host_spec']['path']);authority=load_process_supervisor_spec_v1(spec['authority_spec']['path'])
    for item in (host,authority):
        if (item.authority_id!=spec['authority_id'] or item.installation_id!=spec['installation_id']
                or item.profile_id!=spec['profile_id'] or list(item.namespace_cohort)!=spec['namespace_cohort']
                or item.launcher_code_ref!=spec['inner_entry']['path'] or item.launcher_build_digest!=spec['inner_entry']['sha256']):
            raise AuthorityUnavailable('outer Root launch scope differs from installed PID1 roles')
    _protected_parent(spec['control_socket_path']);_protected_parent(Path(spec['protected_state_directory'])/'lifetime.lock')
    return spec

def read_installed_root_lifetime_spec_v3(path=SPEC_PATH):
    return _require_installed_root_lifetime_spec_v3(read_installed_json_v1(path,limit=32768))

def install_root_lifetime_v3(launch_scope_path,*,resource_original_path,operation_ref,unit_name,cgroup_path,
        cpu_max,memory_max,pids_max,deadline_utc):
    """Explicit Root installation seals the approved resource original and final launch spec."""
    require_linux_administrator_v1()
    launch=read_installed_json_v1(launch_scope_path,limit=32768)
    if (set(launch)!=_SPEC_FIELDS-{'resource_scope_original_ref','resource_scope_original_digest','spec_digest'}
            or launch['schema']!=_LAUNCH):
        raise AuthorityUnavailable('exact protected installed Root launch scope required')
    resource_path=Path(resource_original_path)
    if not resource_path.is_absolute() or str(resource_path)==SPEC_PATH:
        raise AuthorityUnavailable('distinct absolute installed Root resource original path required')
    spec=dict(launch,schema=_SPEC,resource_scope_original_ref=str(resource_path),resource_scope_original_digest='')
    spec['spec_digest']=canonical_digest(spec)
    _require_installed_root_lifetime_spec_v3(spec)
    if Path(SPEC_PATH).exists():
        installed=read_installed_root_lifetime_spec_v3()
        if _scope(installed)!=_scope(spec) or installed['resource_scope_original_ref']!=spec['resource_scope_original_ref']:
            raise AuthorityUnavailable('installed Root lifetime has another launch scope or resource original')
    approval=install_root_lifetime_resource_approval_v3(resource_path,spec=spec,operation_ref=operation_ref,
        unit_name=unit_name,cgroup_path=cgroup_path,cpu_max=cpu_max,memory_max=memory_max,pids_max=pids_max,deadline_utc=deadline_utc)
    spec['resource_scope_original_digest']=approval['approval_original_digest']
    spec['spec_digest']=canonical_digest({k:v for k,v in spec.items() if k!='spec_digest'})
    _require_installed_root_lifetime_spec_v3(spec)
    if Path(SPEC_PATH).exists():
        if read_installed_root_lifetime_spec_v3()!=spec:
            raise AuthorityUnavailable('existing installed Root lifetime belongs to another original operation')
    else:_create_original(SPEC_PATH,spec)
    installed=read_installed_root_lifetime_spec_v3()
    if installed!=spec or _read_root_lifetime_resource_original_v3(installed)!=approval:
        raise AuthorityUnavailable('installed Root lifetime original chain is incomplete')
    _sync_original(resource_path);_sync_original(SPEC_PATH)
    return installed

def install_root_lifetime_resource_approval_v3(path,*,spec,operation_ref,unit_name,cgroup_path,
        cpu_max,memory_max,pids_max,deadline_utc):
    """An explicit future Root installer operation produces this approval."""
    require_linux_administrator_v1()
    if not Path(path).is_absolute() or str(Path(path))!=spec['resource_scope_original_ref']:
        raise AuthorityUnavailable('resource approval must use the exact installed launch original path')
    if not operation_ref or not unit_name or _utc(deadline_utc)<=datetime.now(timezone.utc):
        raise AuthorityUnavailable('explicit installed Root operation and original resource deadline required')
    group=Path(cgroup_path);st=group.stat()
    requested=dict(cpu_max=cpu_max,memory_max=memory_max,pids_max=pids_max)
    for field,file in (('cpu_max','cpu.max'),('memory_max','memory.max'),('pids_max','pids.max')):
        if requested[field]!=(group/file).read_text().strip():
            raise AuthorityUnavailable('Root resource approval must retain the actual existing unit limits')
    request=dict(operation_ref=operation_ref,unit_name=unit_name,authority_id=spec['authority_id'],installation_id=spec['installation_id'],
        launch_scope_digest=_scope(spec),kernel_boot_id=_boot(),cgroup_path=str(group.resolve()),
        cgroup_identity=dict(device=st.st_dev,inode=st.st_ino),**requested,deadline_utc=deadline_utc)
    if Path(path).exists():
        existing=read_installed_json_v1(path,limit=32768)
        if any(existing.get(name)!=value for name,value in request.items()):
            raise AuthorityUnavailable('existing Root resource approval differs from the original operation')
        original_spec=dict(spec,resource_scope_original_digest=existing.get('approval_original_digest'))
        retained=_read_root_lifetime_resource_original_v3(original_spec);_sync_original(path)
        return retained
    record=dict(schema=_RESOURCE,approval_basis='explicit_root_installer_operation',operation_ref=operation_ref,
        unit_name=unit_name,authority_id=spec['authority_id'],installation_id=spec['installation_id'],launch_scope_digest=_scope(spec),
        kernel_boot_id=_boot(),cgroup_path=str(group.resolve()),cgroup_identity=dict(device=st.st_dev,inode=st.st_ino),
        **requested,deadline_utc=deadline_utc,administrator_process_original=read_process_identity_v1(os.getpid()),administrator_uid=os.geteuid())
    record['approval_original_digest']=canonical_digest(record);_create_original(path,record)
    return record

def _read_root_lifetime_resource_original_v3(spec):
    raw=read_installed_bytes_v1(spec['resource_scope_original_ref'],private=True,allowed_gid=0,limit=32768)
    record=json.loads(raw)
    if (set(record)!=_RESOURCE_FIELDS or record['schema']!=_RESOURCE
            or record['approval_basis']!='explicit_root_installer_operation' or record['administrator_uid']!=0
            or not record['operation_ref'] or not record['unit_name']
            or record['authority_id']!=spec['authority_id'] or record['installation_id']!=spec['installation_id']
            or record['launch_scope_digest']!=_scope(spec) or record['kernel_boot_id']!=_boot()
            or canonical_digest({k:v for k,v in record.items() if k!='approval_original_digest'})!=record['approval_original_digest']
            or record['approval_original_digest']!=spec['resource_scope_original_digest']):
        raise AuthorityUnavailable('actual explicit installed Root resource approval original differs')
    group=Path(record['cgroup_path']);st=group.stat()
    if record['cgroup_identity']!=dict(device=st.st_dev,inode=st.st_ino):
        raise AuthorityUnavailable('actual approved Root resource cgroup incarnation changed')
    for field,file in (('cpu_max','cpu.max'),('memory_max','memory.max'),('pids_max','pids.max')):
        if (group/file).read_text().strip()!=record[field]:raise AuthorityUnavailable('actual approved Root resource limit changed')
    if _utc(record['deadline_utc'])<=datetime.now(timezone.utc):raise AuthorityUnavailable('original Root resource deadline expired')
    return record

def read_root_lifetime_resource_approval_v3(spec):
    record=_read_root_lifetime_resource_original_v3(spec);group=Path(record['cgroup_path'])
    relative=Path('/proc/self/cgroup').read_text().strip().removeprefix('0::')
    if str(Path('/sys/fs/cgroup')/relative.lstrip('/'))!=str(group):
        raise AuthorityUnavailable('outer Root must run within the same already approved unit cgroup')
    if _utc(record['deadline_utc'])<=datetime.now(timezone.utc):raise AuthorityUnavailable('original Root resource deadline expired')
    return record

def run_root_namespace_bootstrap_v3(spec):
    require_linux_administrator_v1();read_root_lifetime_resource_approval_v3(spec)
    if len(list(Path('/proc/self/task').iterdir()))!=1:
        raise AuthorityUnavailable('Root namespace creation requires its independent single-thread bootstrap process')
    libc=ctypes.CDLL(None,use_errno=True)
    actual_parent=os.getppid()
    if libc.prctl(1,int(signal.SIGTERM),0,0,0)!=0:
        raise OSError(ctypes.get_errno(),'bind Root bootstrap parent lifetime')
    if os.getppid()!=actual_parent:raise AuthorityUnavailable('actual outer Root ended before namespace creation')
    if libc.unshare(0x00020000|0x20000000)!=0:raise OSError(ctypes.get_errno(),'unshare Root PID/mount namespace')
    if libc.mount(None,b'/',None,16384|262144,None)!=0:raise OSError(ctypes.get_errno(),'make Root mount propagation private')
    bootstrap_pidfd=os.pidfd_open(os.getpid())
    pid=os.fork()
    if pid:
        os.close(bootstrap_pidfd)
        child_pidfd=os.pidfd_open(pid)
        def retire_measured_pid1(_signum,_frame):
            if not select.select([child_pidfd],[],[],0)[0]:signal.pidfd_send_signal(child_pidfd,signal.SIGKILL)
        signal.signal(signal.SIGTERM,retire_measured_pid1)
        try:_,status=os.waitpid(pid,0)
        finally:os.close(child_pidfd)
        raise SystemExit(os.waitstatus_to_exitcode(status))
    if select.select([bootstrap_pidfd],[],[],0)[0]:
        raise AuthorityUnavailable('actual bootstrap entity ended before measured PID1 lifetime binding')
    if libc.prctl(1,int(signal.SIGKILL),0,0,0)!=0:
        raise OSError(ctypes.get_errno(),'bind measured PID1 bootstrap parent lifetime')
    if select.select([bootstrap_pidfd],[],[],0)[0]:
        raise AuthorityUnavailable('actual bootstrap entity ended before measured PID1 exec')
    os.close(bootstrap_pidfd)
    if libc.mount(b'proc',b'/proc',b'proc',0,None)!=0:raise OSError(ctypes.get_errno(),'mount measured Root procfs')
    os.execve(spec['python_executable']['path'],[spec['python_executable']['path'],'-B',spec['inner_entry']['path'],'lifetime-v3'],
        {'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1','SYLANNE_ROOT_LIFETIME_SPEC':SPEC_PATH})

def _parent(pid):
    status=Path(f'/proc/{pid}/status').read_text();return int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
def _descends(pid,parent):
    while pid>1:
        if pid==parent:return True
        pid=_parent(pid)
    return False

def require_installed_root_lifetime_v3(host_spec,authority_spec):
    spec=read_installed_root_lifetime_spec_v3()
    if (host_spec.installed_spec_path!=spec['host_spec']['path'] or authority_spec.installed_spec_path!=spec['authority_spec']['path']
            or os.getpid()!=1 or os.geteuid()!=0):
        raise AuthorityUnavailable('actual installed PID1 lifetime handshake required before Authority launch')
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    channel.settimeout(60);channel.connect(spec['control_socket_path'])
    try:
        pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0 or pid!=0:raise AuthorityUnavailable('actual outer Root ancestor peer required from the child PID namespace')
        request=dict(action='register_root',spec_digest=spec['spec_digest'],local_root_process_original=read_process_identity_v1(1),
            pid_namespace_identity=os.readlink('/proc/self/ns/pid'),mount_namespace_identity=os.readlink('/proc/self/ns/mnt'))
        _send(channel,request);reply=_packet(channel)
        if reply.get('status')!='root_custody_go' or reply.get('spec_digest')!=spec['spec_digest']:
            raise AuthorityUnavailable('actual outer Root custody did not permit this measured namespace')
        return reply
    finally:channel.close()

class InstalledRootLifetimeObserverV3:
    def __init__(self,spec):
        require_linux_administrator_v1()
        if str(Path(sys.argv[0]).resolve())!=spec['outer_entry']['path']:
            raise AuthorityUnavailable('actual installed outer Root entry must own lifetime custody')
        self.spec=spec;self.resource=read_root_lifetime_resource_approval_v3(spec)
        from .installed_process_supervisor_v1 import load_process_supervisor_spec_v1
        self.drain=load_process_supervisor_spec_v1(spec['host_spec']['path']).drain_timeout
        remaining=(_utc(self.resource['deadline_utc'])-datetime.now(timezone.utc)).total_seconds()
        self.resource_end_monotonic=time.monotonic()+remaining
        self.operational_cutoff_monotonic=self.resource_end_monotonic-self.drain
        self.boot=_boot();self.original=read_process_identity_v1(os.getpid());self.lifetime_id=uuid4().hex
        self.lock=os.open(Path(spec['protected_state_directory'])/'lifetime.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.records={};self.child=None;self.launch_id=None;self.first_failure=None
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        # A stale endpoint is removed only under the actual exclusive installed lifetime lock.
        endpoint=Path(spec['control_socket_path'])
        if endpoint.exists():
            st=endpoint.lstat()
            if not endpoint.is_socket() or st.st_uid!=0 or st.st_mode&0o077:raise AuthorityUnavailable('outer Root endpoint is not protected')
            endpoint.unlink()
        self.listener.bind(str(endpoint));os.chmod(endpoint,0o600);self.listener.listen(8);self.listener.settimeout(.025)
    def require_current(self):
        if _boot()!=self.boot or read_process_identity_v1(os.getpid())!=self.original:
            raise AuthorityUnavailable('continuous outer Root kernel/process custody was lost')
        read_root_lifetime_resource_approval_v3(self.spec)
        if time.monotonic()>=self.operational_cutoff_monotonic:
            raise AuthorityUnavailable('original Root lifetime must now retire within its approved absolute end')
    def _packet_timeout_v3(self,channel):
        self.require_current()
        remaining=self.operational_cutoff_monotonic-time.monotonic()
        if remaining<=0:raise AuthorityUnavailable('original Root operational cutoff reached')
        channel.settimeout(min(60,remaining))
    def start_root_v3(self):
        self.require_current()
        if self.child is not None and self.child.poll() is None:raise AuthorityUnavailable('one actual Root launch is still active')
        for record in self.records.values():
            if not record['retired']:raise AuthorityUnavailable('old Root cohort EOF must precede another installed launch')
        self.launch_id=uuid4().hex
        self.child=subprocess.Popen([self.spec['python_executable']['path'],'-B',self.spec['outer_entry']['path'],'--namespace-bootstrap'],
            stdin=subprocess.DEVNULL,close_fds=True,shell=False,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
    def _register(self,pid,request):
        self.require_current()
        if (self.child is None or not _descends(pid,self.child.pid) or request['spec_digest']!=self.spec['spec_digest']
                or set(request)!={'action','spec_digest','local_root_process_original','pid_namespace_identity','mount_namespace_identity'}):
            raise AuthorityUnavailable('Root custody registration is not this installed bootstrap descendant')
        global_original=read_process_identity_v1(pid)
        status=Path(f'/proc/{pid}/status').read_text();nspid=next(line.split()[1:] for line in status.splitlines() if line.startswith('NSpid:'))
        relative=Path(f'/proc/{pid}/cgroup').read_text().strip().removeprefix('0::')
        if str(Path('/sys/fs/cgroup')/relative.lstrip('/'))!=self.resource['cgroup_path']:
            raise AuthorityUnavailable('new Root differs from the actual approved resource unit cgroup')
        argv=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1]
        expected=[x.encode() for x in (self.spec['python_executable']['path'],'-B',self.spec['inner_entry']['path'],'lifetime-v3')]
        if nspid[-1]!='1' or argv!=expected or global_original['birth']!=request['local_root_process_original']['birth']:
            raise AuthorityUnavailable('actual new PID1 fixed invocation/birth differs')
        fds={}
        try:
            fds['pidfd']=os.pidfd_open(pid)
            fds['pidns']=os.open(f'/proc/{pid}/ns/pid',os.O_RDONLY|os.O_CLOEXEC)
            fds['mntns']=os.open(f'/proc/{pid}/ns/mnt',os.O_RDONLY|os.O_CLOEXEC)
            fds['proc']=os.open(f'/proc/{pid}/root/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            if (read_process_identity_v1(pid)!=global_original or os.readlink(f'/proc/{pid}/ns/pid')!=request['pid_namespace_identity']
                    or os.readlink(f'/proc/{pid}/ns/mnt')!=request['mount_namespace_identity']):
                raise AuthorityUnavailable('Root kernel entity changed during pinned handle acquisition')
            class StatFS(ctypes.Structure):
                _fields_=[('type',ctypes.c_long),('size',ctypes.c_byte*112)]
            filesystem=StatFS();libc=ctypes.CDLL(None,use_errno=True)
            if libc.fstatfs(fds['proc'],ctypes.byref(filesystem))!=0 or filesystem.type!=0x9fa0:
                raise AuthorityUnavailable('pinned old Root directory is not its actual procfs instance')
            stat=_read_at(fds['proc'],'1/stat');tail=stat.rsplit(')',1)[1].split()
            if self.boot+':'+tail[19]!=global_original['birth']:
                raise AuthorityUnavailable('pinned old procfs does not contain this actual local Root birth')
            key=canonical_digest(request['local_root_process_original'])
            if key in self.records:raise AuthorityUnavailable('actual Root incarnation was already registered')
            record=dict(fds=fds,local=request['local_root_process_original'],ancestor=global_original,
                pidns=request['pid_namespace_identity'],mntns=request['mount_namespace_identity'],proc_identity=_identity(fds['proc']),
                pidns_identity=_identity(fds['pidns']),mntns_identity=_identity(fds['mntns']),launch_id=self.launch_id,retired=False)
            record['source_root']=canonical_digest({name:record[name] for name in ('local','ancestor','pidns','mntns','proc_identity',
                'pidns_identity','mntns_identity','launch_id')})
            self.records[key]=record
            return dict(status='root_custody_go',spec_digest=self.spec['spec_digest'],lifetime_id=self.lifetime_id,
                launch_id=self.launch_id,cohort_source_root=record['source_root'])
        except BaseException:
            for fd in fds.values():os.close(fd)
            raise
    def _census(self,record,*,terminating=False):
        if terminating:
            if _boot()!=self.boot or read_process_identity_v1(os.getpid())!=self.original:
                raise AuthorityUnavailable('old Root kernel custody was lost during actual retirement')
        else:self.require_current()
        if not select.select([record['fds']['pidfd']],[],[],0)[0]:return False
        for key in ('proc','pidns','mntns'):
            expected=record['proc_identity'] if key=='proc' else record[key+'_identity']
            if _identity(record['fds'][key])!=expected:raise AuthorityUnavailable('continuous old Root entity handle changed')
        entries=sorted(int(name) for name in os.listdir(record['fds']['proc']) if name.isdecimal())
        if len(entries)>258:raise AuthorityUnavailable('old installed Root cohort exceeds the original bounded role inventory')
        if entries:return False
        record['retired']=True;return True
    def observe_retired_cohort_v3(self,pending,hold_nonce):
        from .installed_process_supervisor_v1 import decode_process_supervisor_observation_v2
        self.require_current();baseline=decode_process_supervisor_observation_v2(pending['baseline_observation'])
        key=canonical_digest(pending['root_process_original']);record=self.records.get(key)
        if (record is None or pending['authority_id']!=self.spec['authority_id'] or pending['installation_id']!=self.spec['installation_id']
                or pending['namespace'] not in self.spec['namespace_cohort'] or baseline.pid_namespace_identity!=record['pidns']
                or baseline.mount_namespace_identity!=record['mntns'] or baseline.launcher_process_original!=record['local']):
            raise AuthorityUnavailable('pending old Root has no continuous actual installed custody entities')
        if not self._census(record):return dict(status='progress',phase='old_root_cohort_retirement')
        original=dict(schema=_RETIRE,pending_start_digest=pending['pending_start_digest'],old_baseline_digest=canonical_digest(pending['baseline_observation']),
            **{name:pending[name] for name in ('authority_id','installation_id','control_store_id','namespace','peer','manifest_digest',
                'pointer_version','storage_generation','supervisor_spec_digest')},old_root_process_original=record['local'],
            old_ancestor_root_process_original=record['ancestor'],old_pid_namespace_identity=record['pidns'],old_mount_namespace_identity=record['mntns'],
            old_procfs_identity=record['proc_identity'],observer_process_original=self.original,kernel_boot_id=self.boot,
            observer_spec_digest=self.spec['spec_digest'],lifetime_id=self.lifetime_id,launch_id=record['launch_id'],
            observer_hold_nonce=hold_nonce,cohort_source_root=record['source_root'],root_pidfd_exit=True,census_count=0,
            census_root=canonical_digest(()),eof_digest=canonical_digest((record['source_root'],self.boot,(),hold_nonce)),complete=True,
            resource_scope_original_digest=self.resource['approval_original_digest'])
        return dict(status='old_root_cohort_retired',original=original)
    def _serve_connection_v3(self,channel):
        self._packet_timeout_v3(channel);pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0:raise AuthorityUnavailable('installed outer Root caller must be the actual Root OS principal')
        request=_packet(channel)
        if request.get('action')=='register_root':
            reply=self._register(pid,request);self._packet_timeout_v3(channel);_send(channel,reply);return
        if request=={'action':'start_root','spec_digest':self.spec['spec_digest']}:
            self.start_root_v3();self._packet_timeout_v3(channel);_send(channel,dict(status='root_started',launch_id=self.launch_id));return
        if set(request)!={'action','spec_digest','pending_original'} or request['action']!='retire_old_root' or request['spec_digest']!=self.spec['spec_digest']:
            raise AuthorityUnavailable('closed actual installed Root lifetime request required')
        nonce=uuid4().hex;reply=self.observe_retired_cohort_v3(request['pending_original'],nonce)
        self._packet_timeout_v3(channel);_send_retirement(channel,reply)
        if reply['status']=='progress':return
        self._packet_timeout_v3(channel);release=_packet(channel)
        if release!={'action':'release_old_root_custody','observer_hold_nonce':nonce}:
            raise AuthorityUnavailable('actual outer Root retirement custody release differs')
        self._packet_timeout_v3(channel);_send(channel,dict(status='old_root_custody_released',observer_hold_nonce=nonce))
    def _retire_created_roots_v3(self):
        started=time.monotonic();end=min(started+self.drain,self.resource_end_monotonic)
        term_end=started+max(0,end-started)/2
        for record in self.records.values():
            if not select.select([record['fds']['pidfd']],[],[],0)[0]:
                signal.pidfd_send_signal(record['fds']['pidfd'],signal.SIGTERM)
        if self.child is not None and self.child.poll() is None:
            if not any(record['launch_id']==self.launch_id for record in self.records.values()):
                # This current pre-GO launch can be unregistered even when older
                # namespaces already have completed custody records.
                # Pre-GO registration failure still has a real owned bootstrap;
                # its installed signal handler retires its sole measured PID1.
                self.child.terminate()
            # The bootstrap owns only its measured PID1 child. Retire PID1 first.
            for record in self.records.values():
                if not select.select([record['fds']['pidfd']],[],[],max(0,term_end-time.monotonic()))[0]:
                    signal.pidfd_send_signal(record['fds']['pidfd'],signal.SIGKILL)
            self.child.wait(timeout=max(0,end-time.monotonic()))
        for record in self.records.values():
            while True:
                if time.monotonic()>=end:raise AuthorityUnavailable('actual old Root retirement remains unknown; preserve custody')
                if self._census(record,terminating=True):break
                time.sleep(min(.025,max(0,end-time.monotonic())))
    def run_installed_lifetime_v3(self):
        terminating_error=None
        try:
            self.start_root_v3()
            while True:
                self.require_current()
                if self.child is not None and self.child.poll() is not None:
                    for record in self.records.values():self._census(record)
                    if self.first_failure is None and self.child.returncode:self.first_failure=self.child.returncode
                remaining=self.operational_cutoff_monotonic-time.monotonic()
                if remaining<=0:raise AuthorityUnavailable('original Root operational cutoff reached before accept')
                self.listener.settimeout(min(.025,remaining))
                try:channel,_=self.listener.accept()
                except socket.timeout:continue
                with channel:
                    try:self._serve_connection_v3(channel)
                    except (AuthorityUnavailable,OSError,ValueError) as error:
                        # A lost Control commit/ACK is a connection outcome. All
                        # actual namespace entities remain owned for recovery.
                        if self.first_failure is None:self.first_failure=str(error)
                        try:
                            self._packet_timeout_v3(channel);_send(channel,dict(status='unavailable',reason=str(error)))
                        except (AuthorityUnavailable,OSError):pass
        except BaseException as error:
            terminating_error=error
        # Genuine lifetime termination never abandons a live measured namespace.
        self._retire_created_roots_v3()
        for record in self.records.values():
            for fd in record['fds'].values():os.close(fd)
        self.listener.close();os.close(self.lock)
        if terminating_error is not None:raise terminating_error

def request_installed_root_start_v3(spec):
    require_linux_administrator_v1()
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);channel.settimeout(60)
    try:
        channel.connect(spec['control_socket_path']);_,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0:raise AuthorityUnavailable('actual installed outer Root start authority required')
        _send(channel,dict(action='start_root',spec_digest=spec['spec_digest']))
        reply=_packet(channel)
        if reply.get('status')!='root_started':raise AuthorityUnavailable('explicit installed Root start was not accepted: '+str(reply))
        return reply
    finally:channel.close()

def run_installed_lifetime_v3(spec):return InstalledRootLifetimeObserverV3(spec).run_installed_lifetime_v3()

class VerifiedInstalledRootCohortRetirementV3:
    def __init__(self,issuer,*,control,gate,pending,channel,original,spec,observer,observer_pidfd):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual outer Root retirement channel issuer required')
        self.control,self.gate,self.pending_original,self.channel,self.original,self.spec=control,gate,pending,channel,original,spec
        self.observer,self.observer_pidfd=observer,observer_pidfd;self.closed=False
        _CAPS.add(self);_CAP_BINDINGS[self]=(control,gate,channel,canonical_digest(original),canonical_digest(pending))
    def require_current(self,*,control,gate,meter):
        if self not in _CAPS or _CAP_BINDINGS[self]!=(control,gate,self.channel,canonical_digest(self.original),canonical_digest(self.pending_original)):
            raise AuthorityUnavailable('actual issued outer Root retirement scope changed')
        if (self.closed or self.channel.fileno()<0 or select.select([self.channel],[],[],0)[0]
                or _boot()!=self.original['kernel_boot_id'] or select.select([self.observer_pidfd],[],[],0)[0]):
            raise AuthorityUnavailable('continuous outer Root old cohort custody ended')
        return self
    def close(self):
        if self.closed:return
        try:
            _send(self.channel,dict(action='release_old_root_custody',observer_hold_nonce=self.original['observer_hold_nonce']))
            if _packet(self.channel)!=dict(status='old_root_custody_released',observer_hold_nonce=self.original['observer_hold_nonce']):
                raise AuthorityUnavailable('actual outer Root retirement release ACK differs')
        finally:self.closed=True;self.channel.close();os.close(self.observer_pidfd)

def read_installed_old_root_retirement_v3(*,control,gate,pending):
    spec=read_installed_root_lifetime_spec_v3()
    if spec['authority_id']!=control.authority_id or spec['installation_id']!=control.installation_id:
        raise AuthorityUnavailable('actual installed outer Root scope differs from current Control')
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);channel.settimeout(60)
    try:
        channel.connect(spec['control_socket_path']);pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        # An ancestor in another PID namespace has credential PID 0 here. Its live identity is supplied by its custody reply.
        if uid!=0 or pid!=0:raise AuthorityUnavailable('actual installed outer Root ancestor credential required')
        _send(channel,dict(action='retire_old_root',spec_digest=spec['spec_digest'],pending_original=pending));reply,observer_pidfd=_retirement_packet(channel)
        if reply.get('status')=='progress':channel.close();os.close(observer_pidfd);return reply
        original=reply['original'];baseline=pending['baseline_observation']
        if (reply['status']!='old_root_cohort_retired' or original['schema']!=_RETIRE
                or original['pending_start_digest']!=pending['pending_start_digest']
                or original['old_baseline_digest']!=canonical_digest(baseline)
                or original['old_root_process_original']!=pending['root_process_original']
                or original['old_pid_namespace_identity']!=baseline['pid_namespace_identity']
                or original['old_mount_namespace_identity']!=baseline['mount_namespace_identity']
                or original['observer_spec_digest']!=spec['spec_digest'] or original['kernel_boot_id']!=_boot()
                or original['census_count']!=0 or original['complete'] is not True or original['root_pidfd_exit'] is not True):
            raise AuthorityUnavailable('actual outer Root retirement does not bind the original pending cohort')
        observer=original['observer_process_original']
        cap=VerifiedInstalledRootCohortRetirementV3(_ISSUER,control=control,gate=gate,pending=pending,
            channel=channel,original=original,spec=spec,observer=observer,observer_pidfd=observer_pidfd)
        # The inner procfs cannot address an ancestor's global PID; continuous credential channel binds it instead.
        return cap.require_current(control=control,gate=gate,meter=None)
    except BaseException:
        channel.close()
        if 'observer_pidfd' in locals():os.close(observer_pidfd)
        raise
