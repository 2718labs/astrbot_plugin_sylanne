"""Root-installed finite same-PID SDK cohort; never production Host admission."""
from __future__ import annotations
from pathlib import Path
from weakref import WeakSet,WeakKeyDictionary
import hashlib
import hmac
import json
import os
import sqlite3
import select
import socket
import struct
import threading
import time
from uuid import UUID

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.c09_process_identity_v1 import read_process_identity_v1,require_process_retired_v1
from ..runtime_contracts import canonical_digest,canonical_serialize

_DESCRIPTOR_SCHEMA='sylanne3.c09.controlled-sdk-peer-cohort.v3'
_ACTIVATION_SCHEMA='sylanne3.c09.writer-peer-registry-activation.controlled-sdk.v3'
_DESCRIPTORS=WeakSet()
_CLOSED=WeakSet()
_PROOFS=WeakSet()
_CENSUSES=WeakSet()
_CENSUS_BINDINGS=WeakKeyDictionary()
_ISSUER=object()


def _root_bytes(path,*,private=False):
    from ..authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    return read_installed_bytes_v1(path,private=private,allowed_gid=Path(path).lstat().st_gid,limit=65536)


def _scope(config,inventory,peer):
    from ..authority_service.deployment_config import AuthorityDeploymentConfig
    from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
    if (type(config) is not AuthorityDeploymentConfig or type(inventory) is not InstallationFilesystemManifestV2
            or config.c09_storage_v1 is None
            or tuple(key for key,value in config.installations_v2.items()
                if value.installation_id==inventory.installation_id)!=(peer,)
            or inventory.installation_id!=config.c09_storage_v1.installation_id
            or inventory.authority_id!=config.c09_storage_v1.authority_id
            or config.installations_v2[peer].installation_id!=inventory.installation_id
            or tuple(value for key,value in config.namespace_bindings_v2.items() if key[:2]==peer)!=(inventory.namespace,)):
        raise AuthorityUnavailable('actual fixed one-peer SDK installation cohort required')
    installed=config.c09_storage_v1
    return dict(schema=_DESCRIPTOR_SCHEMA,cohort_kind='controlled_same_pid_sdk',
        authority_id=installed.authority_id,installation_id=installed.installation_id,
        control_store_id=installed.control_store_id,namespace=inventory.namespace,
        sdk_peer_descriptor=list(peer),manifest_digest=config.installations_v2[peer].manifest_digest,
        inventory_manifest_digest=inventory.manifest_digest,control_path=str(Path(installed.control_path).resolve()),
        key_path=str(Path(installed.key_path).resolve()),instance_lock=str(Path(config.instance_lock).resolve()))


class VerifiedControlledSDKRootDescriptorV3:
    def __init__(self,issuer,*,path,payload,source_digest):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual protected SDK descriptor reader required')
        self.path,self.payload,self.source_digest=Path(path),payload,source_digest
        _DESCRIPTORS.add(self)
    def require_current(self,*,config,inventory,peer):
        if self not in _DESCRIPTORS or hashlib.sha256(_root_bytes(self.path)).hexdigest()!=self.source_digest:
            raise AuthorityUnavailable('Root-protected SDK cohort descriptor changed')
        expected=_scope(config,inventory,peer)
        signed={name:value for name,value in self.payload.items() if name not in ('descriptor_digest','signature','key_id')}
        if signed!=expected or self.payload['key_id']!=config.c09_storage_v1.key_id:
            raise AuthorityUnavailable('SDK descriptor belongs to another installed finite cohort')
        actual=canonical_digest({**signed,'key_id':self.payload['key_id']})
        key=_root_bytes(config.c09_storage_v1.key_path,private=True)
        signature=hmac.new(key,(_DESCRIPTOR_SCHEMA+'\n'+actual).encode(),'sha256').hexdigest()
        if actual!=self.payload['descriptor_digest'] or not hmac.compare_digest(signature,self.payload['signature']):
            raise AuthorityUnavailable('Root-installed SDK descriptor signature differs')
        return self


def read_controlled_sdk_root_descriptor_v3(path,*,config,inventory,peer):
    raw=_root_bytes(path)
    def unique(pairs):
        result={}
        for name,value in pairs:
            if name in result:raise AuthorityUnavailable('duplicate controlled SDK descriptor field')
            result[name]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique)
    expected=set(_scope(config,inventory,peer))|{'key_id','descriptor_digest','signature'}
    if type(value) is not dict or set(value)!=expected:
        raise AuthorityUnavailable('Root-installed SDK descriptor exact schema required')
    descriptor=VerifiedControlledSDKRootDescriptorV3(_ISSUER,path=path,payload=value,
        source_digest=hashlib.sha256(raw).hexdigest())
    return descriptor.require_current(config=config,inventory=inventory,peer=peer)


def _write_root_descriptor_v3(path,*,scope,key_id):
    from ..authority_service.linux_installation_security_v1 import require_linux_administrator_v1
    require_linux_administrator_v1()
    target=Path(path)
    for item in (target.parent,*target.parent.parents):
        st=item.lstat()
        if item.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:
            raise AuthorityUnavailable('SDK descriptor parent is not Root-protected')
    value={**scope,'key_id':key_id}
    value['descriptor_digest']=canonical_digest(value)
    key=_root_bytes(scope['key_path'],private=True)
    value['signature']=hmac.new(key,(_DESCRIPTOR_SCHEMA+'\n'+value['descriptor_digest']).encode(),'sha256').hexdigest()
    encoded=canonical_serialize(value).encode()
    fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),0,target.parent.lstat().st_gid)
        stream.write(encoded);stream.flush();os.fsync(stream.fileno())
    raw=_root_bytes(target)
    if raw!=encoded:raise AuthorityUnavailable('actual Root descriptor write differs from its signed bytes')
    return VerifiedControlledSDKRootDescriptorV3(_ISSUER,path=target,payload=value,
        source_digest=hashlib.sha256(raw).hexdigest())


def write_controlled_sdk_root_descriptor_v3(path,*,config,inventory,peer):
    descriptor=_write_root_descriptor_v3(path,scope=_scope(config,inventory,peer),
        key_id=config.c09_storage_v1.key_id)
    return descriptor.require_current(config=config,inventory=inventory,peer=peer)


def write_controlled_sdk_root_descriptor_from_assets_v3(path,*,installation_assets_path):
    """Install the fixed SDK cohort before business composition exists."""
    from ..authority_service.linux_installation_security_v1 import require_linux_administrator_v1
    require_linux_administrator_v1()
    def unique(pairs):
        result={}
        for name,value in pairs:
            if name in result:raise AuthorityUnavailable('duplicate controlled SDK installation asset field')
            result[name]=value
        return result
    assets=json.loads(_root_bytes(installation_assets_path),object_pairs_hook=unique)
    fields={'schema','authority_id','installation_id','control_store_id','key_id','namespace',
        'sdk_peer_descriptor','manifest_digest','inventory_manifest_digest','control_path','key_path','instance_lock'}
    if (type(assets) is not dict or set(assets)!=fields
            or assets['schema']!='sylanne3.c09.controlled-sdk-installation-assets.v3'
            or type(assets['sdk_peer_descriptor']) is not list or len(assets['sdk_peer_descriptor'])!=2
            or any(type(value) is not str or not value for value in assets['sdk_peer_descriptor'])
            or any(type(assets[name]) is not str or not assets[name] for name in fields-{'sdk_peer_descriptor'})):
        raise AuthorityUnavailable('actual protected controlled SDK installation assets exact schema required')
    scope={name:assets[name] for name in fields-{'schema','key_id'}}
    scope.update(schema=_DESCRIPTOR_SCHEMA,cohort_kind='controlled_same_pid_sdk')
    for name in ('control_path','key_path','instance_lock'):
        scope[name]=str(Path(scope[name]).resolve())
    return _write_root_descriptor_v3(path,scope=scope,key_id=assets['key_id'])


def _channel_process_v3(pid):
    original=read_process_identity_v1(pid)
    if original is None:raise AuthorityUnavailable('actual SDK Root channel process is not live')
    return dict(pid=pid,birth=original['birth'],mount_namespace=os.readlink(f'/proc/{pid}/ns/mnt'),
        pid_namespace=os.readlink(f'/proc/{pid}/ns/pid'))


class VerifiedControlledSDKProcessCensusV3:
    def __init__(self,issuer,*,channel,descriptor,request,original):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual Root SDK census channel issuer required')
        self.channel,self.descriptor,self.request,self.original=channel,descriptor,request,original
        self.owner_thread=threading.get_ident()
        self.channel_nonce=original['channel_nonce']
        self.root_process_original=read_process_identity_v1(original['root_process']['pid'])
        self.authority_process_original=read_process_identity_v1(os.getpid())
        self.closed=False
        self.digest=canonical_digest(original)
        _CENSUSES.add(self)
        _CENSUS_BINDINGS[self]=(channel,descriptor,self.digest)
    def require_installed_cohort_v3(self):
        if self not in _CENSUSES:
            raise AuthorityUnavailable('actual Root SDK census issuer changed')
        binding=_CENSUS_BINDINGS[self]
        if (self.channel is not binding[0] or self.descriptor is not binding[1]
                or self.digest!=binding[2] or canonical_digest(self.original)!=binding[2]):
            raise AuthorityUnavailable('actual issued Root SDK census original changed')
        observed=self.original
        if time.monotonic_ns()>=observed['run_deadline_monotonic_ns']:
            raise AuthorityUnavailable('actual original Root SDK resource window expired')
        root=read_process_identity_v1(observed['root_process']['pid'])
        if (root is None or root['birth']!=observed['root_process']['birth']
                or _channel_process_v3(os.getpid())!=observed['authority_process']
                or hashlib.sha256(_root_bytes(self.descriptor.path)).hexdigest()!=observed['descriptor_sha256']):
            raise AuthorityUnavailable('actual Root SDK process/descriptor scope changed')
        status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        if tuple(map(int,status['Uid'].split()))!=(1000,1000,1000,1000):
            raise AuthorityUnavailable('actual SDK phase OS principal changed')
        for name in ('run_cgroup','app_cgroup'):
            group=observed[name];st=Path(group['path']).stat()
            if (st.st_dev,st.st_ino)!=(group['device'],group['inode']):
                raise AuthorityUnavailable('actual Root SDK resource cgroup incarnation changed')
        group=observed['app_cgroup'];path=Path(group['path']);st=path.stat()
        if (st.st_dev,st.st_ino)!=(group['device'],group['inode']):
            raise AuthorityUnavailable('actual Root SDK cgroup incarnation changed')
        # This installed phase cohort has exactly one process and no subgroups.
        with (path/'cgroup.procs').open('rb') as stream:
            raw=stream.read(65)
        if len(raw)>64 or raw.decode().split()!=[str(os.getpid())] or any(item.is_dir() for item in path.iterdir()):
            raise AuthorityUnavailable('actual complete SDK phase cohort is not the sole Authority worker')
        return self
    def require_current(self):
        self.require_installed_cohort_v3()
        if threading.get_ident()!=self.owner_thread or self.closed or self.channel.fileno()<0 or select.select([self.channel],[],[],0)[0]:
            raise AuthorityUnavailable('continuous Root SDK role-start exclusion ended')
        return self
    def close(self):
        if self.closed:return
        if threading.get_ident()!=self.owner_thread:
            raise AuthorityUnavailable('actual Root SDK census must close on its owner thread')
        request=dict(schema='sylanne.root-controlled-sdk-census-request.v3',command='release',
            held_request_digest=self.original['request_digest'])
        try:
            self.channel.sendall(canonical_serialize(request).encode())
            raw=self.channel.recv(65537)
            result=json.loads(raw)
            if (len(raw)>65536 or result.get('schema')!='sylanne.root-controlled-sdk-census.v3'
                    or result.get('command')!='released' or result.get('request_digest')!=self.original['request_digest']
                    or result.get('hold_token')!=self.original['hold_token']
                    or result.get('channel_nonce')!=self.original['channel_nonce']):
                raise AuthorityUnavailable('Root SDK census release differs from its actual hold')
        finally:
            self.closed=True
            self.channel.close()


def hold_controlled_sdk_process_census_v3(*,root_descriptor,config,inventory,peer):
    root_descriptor.require_current(config=config,inventory=inventory,peer=peer)
    path=Path(os.environ['SYLANNE_QUAL_ROOT_CENSUS_SOCKET'])
    phase=os.environ['SYLANNE_QUAL_ROOT_CENSUS_PHASE']
    for parent in (path.parent,*path.parent.parents):
        st=parent.lstat()
        if parent.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:
            raise AuthorityUnavailable('Root SDK census endpoint parent is not protected')
    st=path.lstat()
    if not path.is_socket() or st.st_uid!=0 or st.st_mode&0o007:
        raise AuthorityUnavailable('actual protected Root SDK census endpoint required')
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        channel.settimeout(60)
        channel.connect(str(path))
        root_pid,root_uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if root_uid!=0:raise AuthorityUnavailable('actual Root SDK census owner required')
        scope={name:root_descriptor.payload[name] for name in ('authority_id','installation_id',
            'control_store_id','namespace','sdk_peer_descriptor','manifest_digest','inventory_manifest_digest','descriptor_digest')}
        request=dict(schema='sylanne.root-controlled-sdk-census-request.v3',command='hold',phase=phase,
            authority_process=_channel_process_v3(os.getpid()),descriptor_path=str(root_descriptor.path.resolve()),
            descriptor_sha256=root_descriptor.source_digest,selection_scope=scope)
        encoded=canonical_serialize(request).encode();channel.sendall(encoded)
        raw=channel.recv(65537)
        def unique(pairs):
            result={}
            for name,value in pairs:
                if name in result:raise AuthorityUnavailable('duplicate Root SDK census field')
                result[name]=value
            return result
        reply=json.loads(raw,object_pairs_hook=unique)
        fields={'schema','command','phase','resource_operation_id','root_process','authority_process','app_cgroup',
            'processes','cohort_eof','continuous_start_exclusion','descriptor_sha256','node','node_sha256',
            'package_sha256','manifest_sha256','dependency_sha256','setup_sha256','selection_scope','request_digest',
            'observed_monotonic_ns','root_uid','authority_uid','socket','run_cgroup','cohort_count',
            'cohort_root','channel_nonce','hold_token','profile_digest','run_deadline_monotonic_ns'}
        if (len(raw)>65536 or type(reply) is not dict or set(reply)!=fields
                or reply['schema']!='sylanne.root-controlled-sdk-census.v3' or reply['command']!='held'
                or reply['root_uid']!=0 or reply['authority_uid']!=1000 or os.getuid()!=1000
                or reply['cohort_count']!=1
                or reply['cohort_root']!=hashlib.sha256(canonical_serialize(reply['processes']).encode()).hexdigest()
                or reply['phase']!=phase or reply['root_process']['pid']!=root_pid
                or reply['root_process']['birth']!=read_process_identity_v1(root_pid)['birth']
                or any(reply['root_process'][name]!=request['authority_process'][name]
                    for name in ('mount_namespace','pid_namespace'))
                or reply['authority_process']!=request['authority_process']
                or reply['processes']!=[request['authority_process']]
                or reply['cohort_eof'] is not True or reply['continuous_start_exclusion'] is not True
                or reply['descriptor_sha256']!=root_descriptor.source_digest
                or reply['selection_scope']!=scope or reply['request_digest']!=hashlib.sha256(encoded).hexdigest()):
            raise AuthorityUnavailable('actual Root SDK full-cohort census binding differs')
        actual_socket=path.lstat()
        if (reply['socket']!=dict(path=str(path.resolve()),device=actual_socket.st_dev,inode=actual_socket.st_ino,
                owner_uid=actual_socket.st_uid,mode=actual_socket.st_mode&0o777)
                or type(reply['channel_nonce']) is not str or str(UUID(reply['channel_nonce']))!=reply['channel_nonce']
                or UUID(reply['channel_nonce']).version!=4
                or type(reply['hold_token']) is not str or str(UUID(reply['hold_token']))!=reply['hold_token']
                or UUID(reply['hold_token']).version!=4):
            raise AuthorityUnavailable('actual Root SDK held channel/socket identity differs')
        for name in ('node_sha256','package_sha256','manifest_sha256','dependency_sha256','setup_sha256','profile_digest'):
            if type(reply[name]) is not str or len(reply[name])!=64 or any(c not in '0123456789abcdef' for c in reply[name]):
                raise AuthorityUnavailable('Root SDK installed runner/source pins are incomplete')
        census=VerifiedControlledSDKProcessCensusV3(_ISSUER,channel=channel,descriptor=root_descriptor,
            request=request,original=reply)
        return census.require_current()
    except BaseException:
        channel.close()
        raise


class VerifiedControlledSDKClosedServicesOriginalV3:
    def __init__(self,issuer,*,services,connections,originals,authority,control):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual SDK service close issuer required')
        self.services,self.connections,self.originals=services,connections,originals
        self.authority,self.control=authority,control
        self.root=canonical_digest(originals)
        _CLOSED.add(self)
    def require_current(self):
        if self not in _CLOSED or read_process_identity_v1(os.getpid())!=self.authority:
            raise AuthorityUnavailable('actual closed SDK services belong to another Authority process')
        server=self.services[0]
        if (not server._worker_closed or server._worker_shutdown_task is None
                or not server._worker_shutdown_task.done() or server._first_owner_tasks_v1):
            raise AuthorityUnavailable('actual old SDK server still has live work')
        for owner,connection in zip(self.services[1:],self.connections):
            if owner._db is not None:raise AuthorityUnavailable('actual old SDK database reopened after close')
            try:connection.execute('SELECT 1')
            except sqlite3.ProgrammingError:pass
            else:raise AuthorityUnavailable('actual old SDK database connection remains open')
        if not self.control.lease._stream.closed:
            raise AuthorityUnavailable('actual old installation lease remains held')
        return self


async def close_controlled_sdk_authority_services_v3(*,server,core,execution,deletion,control):
    from ..authority_service.mtls_server import AuthorityRpcServer
    from ..authority_service.core import AuthorityServiceCore
    from ..authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
    from ..authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
    from ..authority_service.c09_storage_control_v1 import C09StorageControlV1
    if (type(server) is not AuthorityRpcServer or server.core is not core or type(core) is not AuthorityServiceCore
            or type(deletion) is not AuthorityV2DeletionGuard or type(control) is not C09StorageControlV1):
        raise AuthorityUnavailable('actual installed SDK Authority services required for close original')
    journals=(execution,) if type(execution) is AuthorityV2ExecutionJournal else tuple(execution.values())
    if not journals or any(type(journal) is not AuthorityV2ExecutionJournal for journal in journals):
        raise AuthorityUnavailable('actual complete installed execution journal cohort required')
    authority=read_process_identity_v1(os.getpid())
    owners=(core,*journals,deletion)
    connections=tuple(owner._db for owner in owners)
    if any(type(connection) is not sqlite3.Connection for connection in connections):
        raise AuthorityUnavailable('old services must close their actual owned live connections')
    before=tuple(dict(role=('core' if index==0 else 'deletion' if index==len(owners)-1 else 'execution'),
        type_name=type(owner).__name__,path=connection.execute('PRAGMA database_list').fetchone()[2])
        for index,(owner,connection) in enumerate(zip(owners,connections)))
    lease_stat=os.fstat(control.lease._stream.fileno())
    lease_original=dict(path=str(control.lease.path),device=lease_stat.st_dev,inode=lease_stat.st_ino)
    await server.aclose()
    for owner in owners:owner.close()
    control.lease.close()
    originals=tuple(dict(schema='sylanne3.c09.controlled-sdk-closed-service.v3',
        authority_process_original=authority,service=item,disposition='actual_connection_closed') for item in before)
    originals=(dict(schema='sylanne3.c09.controlled-sdk-closed-server.v3',authority_process_original=authority,
        disposition='actual_worker_shutdown_complete'),*originals,
        dict(schema='sylanne3.c09.controlled-sdk-closed-lease.v3',authority_process_original=authority,
            lease=lease_original,disposition='actual_installation_lease_closed'))
    proof=VerifiedControlledSDKClosedServicesOriginalV3(_ISSUER,services=(server,*owners),connections=connections,
        originals=originals,authority=authority,control=control)
    return proof.require_current()


def require_controlled_sdk_registry_assets_v3(*,root_descriptor,closed_services,inventory,peer):
    if (type(root_descriptor) is not VerifiedControlledSDKRootDescriptorV3 or root_descriptor not in _DESCRIPTORS
            or root_descriptor.payload['inventory_manifest_digest']!=inventory.manifest_digest
            or root_descriptor.payload['sdk_peer_descriptor']!=list(peer)):
        raise AuthorityUnavailable('actual Root-protected SDK installer descriptor required')
    if closed_services is not None:
        if type(closed_services) is not VerifiedControlledSDKClosedServicesOriginalV3:
            raise AuthorityUnavailable('actual closed SDK service original required')
        closed_services.require_current()


class VerifiedControlledSDKInstallerOriginalV3:
    def __init__(self,issuer,*,gate,control,config,descriptor,summary,process_census,original=None,closed=None):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual controlled SDK installer issuer required')
        self.gate,self.control,self.config=gate,control,config
        self.descriptor,self.summary,self.original,self.closed=descriptor,summary,original,closed
        self.process_census=process_census
        if type(process_census) is not VerifiedControlledSDKProcessCensusV3 or process_census not in _CENSUSES:
            raise AuthorityUnavailable('actual Root SDK complete process census required')
        self.hold_token=gate._peer_registry_activation_hold_v3
        self.current_authority_original=read_process_identity_v1(os.getpid())
        if self.current_authority_original is None:
            raise AuthorityUnavailable('actual current controlled SDK Authority process required')
        _PROOFS.add(self)
    def require_current(self,*,gate,control,config,meter):
        if (self not in _PROOFS or self.gate is not gate or self.control is not control or self.config is not config):
            raise AuthorityUnavailable('actual controlled SDK installer qualification scope changed')
        gate.require_peer_registry_activation_hold_v3(self.hold_token)
        self.process_census.require_current()
        if read_process_identity_v1(os.getpid())!=self.current_authority_original:
            raise AuthorityUnavailable('controlled SDK qualification changed its current Authority PID/birth')
        self.descriptor.require_current(config=config,inventory=config.c09_maintenance_factory.inventory,
            peer=config.c09_maintenance_factory.peer)
        control.lease.require_held()
        if self.closed is not None:self.closed.require_current()
        if self.original is not None:
            require_process_retired_v1(self.original['authority_process_original'])
        return self
    def activation_summary_v3(self,*,control,gate,meter):
        self.require_current(gate=gate,control=control,config=self.config,meter=meter)
        return self.summary
    def require_activation_original_for_gate_v3(self,original,*,control,gate,meter):
        if (self not in _PROOFS or self.gate is not gate or self.control is not control
                or original['schema']!=_ACTIVATION_SCHEMA
                or original['activation_basis']!=self.summary):
            raise AuthorityUnavailable('controlled SDK activation changed its actual finite installer proof')
        self.process_census.require_installed_cohort_v3()
        self.descriptor.require_current(config=self.config,inventory=self.config.c09_maintenance_factory.inventory,
            peer=self.config.c09_maintenance_factory.peer)
        if read_process_identity_v1(os.getpid())!=self.current_authority_original:
            raise AuthorityUnavailable('controlled SDK admission changed its current actual Authority PID/birth')
        if self.original is not None:require_process_retired_v1(self.original['authority_process_original'])
        elif read_process_identity_v1(os.getpid())!=self.summary['authority_process_original']:
            raise AuthorityUnavailable('actual current controlled SDK Authority process changed')


def issue_controlled_sdk_genesis_v3(*,gate,control,config,closed_services,root_descriptor,process_census,meter):
    from ..authority_service.c09_storage_control_v1 import C09StorageControlV1
    if type(control) is not C09StorageControlV1 or gate.control is not control or gate._installed_config_v3 is not config:
        raise AuthorityUnavailable('actual same-Control controlled SDK Gate required')
    factory=config.c09_maintenance_factory
    if type(process_census) is not VerifiedControlledSDKProcessCensusV3 or process_census not in _CENSUSES:
        raise AuthorityUnavailable('actual Root SDK full process cohort required')
    process_census.require_current()
    require_controlled_sdk_registry_assets_v3(root_descriptor=root_descriptor,closed_services=closed_services,
        inventory=factory.inventory,peer=factory.peer)
    if closed_services is None:raise AuthorityUnavailable('SDK genesis requires actual old service close originals')
    old=closed_services.control
    if ((old.authority_id,old.installation_id,old.control_store_id,old.key_id,old.path,old.key_path)!=
            (control.authority_id,control.installation_id,control.control_store_id,control.key_id,control.path,control.key_path)):
        raise AuthorityUnavailable('closed SDK services belong to another installed Control')
    actual_paths={str(Path(item['service']['path']).resolve()) for item in closed_services.originals if 'service' in item}
    expected_paths={str(Path(config.authority_db).resolve()),str(Path(config.deletion_db).resolve()),
        *(str(Path(item.path).resolve()) for item in config.execution_journals.values())}
    if actual_paths!=expected_paths:
        raise AuthorityUnavailable('actual closed SDK service cohort differs from the selected installed role paths')
    root_descriptor.require_current(config=config,inventory=factory.inventory,peer=factory.peer)
    gate.require_peer_registry_activation_hold_v3(gate._peer_registry_activation_hold_v3)
    metadata=control.read_verified_control_status_v3()
    if (metadata['status']!='complete' or metadata['stage']!='READY'
            or metadata['pointer_version']!=0 or metadata['storage_generation'] not in (None,0)):
        raise AuthorityUnavailable('controlled SDK genesis requires actual never-admitted READY0 Control')
    authority=read_process_identity_v1(os.getpid())
    if authority is None or authority!=closed_services.authority:
        raise AuthorityUnavailable('actual sole controlled SDK Authority PID/birth required')
    process_root=canonical_digest(dict(schema='sylanne3.c09.controlled-sdk-process-census.v3',
        descriptor_digest=root_descriptor.payload['descriptor_digest'],processes=(authority,),
        root_census_original_digest=process_census.digest))
    closed_root=closed_services.root
    controlled_digest=canonical_digest(dict(schema='sylanne3.c09.controlled-sdk-installer-original.v3',
        descriptor_digest=root_descriptor.payload['descriptor_digest'],authority_process_original=authority,
        process_root=process_root,closed_service_original_root=closed_root,
        root_census_original_digest=process_census.digest))
    summary=dict(schema='sylanne3.c09.writer-peer-registry-activation-input.v3',mode='controlled_sdk_genesis',
        installation_inventory_digest=factory.inventory.manifest_digest,process_count=1,process_root=process_root,
        process_eof_digest=canonical_digest(dict(descriptor_digest=root_descriptor.payload['descriptor_digest'],
            process_root=process_root,root_census_original_digest=process_census.digest)),legacy_quiescence_count=0,
        legacy_quiescence_root=canonical_digest(()),legacy_quiescence_eof_digest=canonical_digest(()),
        controlled_sdk_original_digest=controlled_digest,sdk_peer_descriptor=list(factory.peer),
        authority_process_original=authority,closed_service_original_root=closed_root,
        closed_service_original_count=len(closed_services.originals),
        controlled_sdk_root_census_original=process_census.original,
        controlled_sdk_root_census_original_digest=process_census.digest)
    proof=VerifiedControlledSDKInstallerOriginalV3(_ISSUER,gate=gate,control=control,config=config,
        descriptor=root_descriptor,summary=summary,process_census=process_census,closed=closed_services)
    return proof.require_current(gate=gate,control=control,config=config,meter=meter)


def read_controlled_sdk_activation_original_v3(*,gate,control,config,root_descriptor,process_census,original,meter):
    factory=config.c09_maintenance_factory
    root_descriptor.require_current(config=config,inventory=factory.inventory,peer=factory.peer)
    control.verify_original_v1(original,'activation_digest')
    if (original['schema']!=_ACTIVATION_SCHEMA or original['authority_id']!=control.authority_id
            or original['installation_id']!=control.installation_id or original['control_store_id']!=control.control_store_id
            or original['namespace']!=factory.inventory.namespace
            or original['activation_basis']['sdk_peer_descriptor']!=list(factory.peer)
            or original['activation_basis']['installation_inventory_digest']!=factory.inventory.manifest_digest):
        raise AuthorityUnavailable('cold controlled SDK original belongs to another Root-installed finite cohort')
    if type(process_census) is not VerifiedControlledSDKProcessCensusV3 or process_census not in _CENSUSES:
        raise AuthorityUnavailable('actual current Root SDK process census required for cold admission')
    process_census.require_current()
    basis=original['activation_basis']
    historical=basis['controlled_sdk_root_census_original']
    historical_digest=basis['controlled_sdk_root_census_original_digest']
    expected_scope={name:root_descriptor.payload[name] for name in ('authority_id','installation_id',
        'control_store_id','namespace','sdk_peer_descriptor','manifest_digest','inventory_manifest_digest','descriptor_digest')}
    if (canonical_digest(historical)!=historical_digest or historical['selection_scope']!=expected_scope
            or historical['descriptor_sha256']!=root_descriptor.source_digest
            or historical['cohort_count']!=1 or historical['processes']!=[historical['authority_process']]
            or historical['authority_process']['pid']!=original['authority_process_original']['pid']
            or historical['authority_process']['birth']!=original['authority_process_original']['birth']):
        raise AuthorityUnavailable('historical SDK activation lacks the actual complete Root cohort original')
    process_root=canonical_digest(dict(schema='sylanne3.c09.controlled-sdk-process-census.v3',
        descriptor_digest=root_descriptor.payload['descriptor_digest'],processes=(original['authority_process_original'],),
        root_census_original_digest=historical_digest))
    expected_controlled=canonical_digest(dict(schema='sylanne3.c09.controlled-sdk-installer-original.v3',
        descriptor_digest=root_descriptor.payload['descriptor_digest'],authority_process_original=original['authority_process_original'],
        process_root=process_root,closed_service_original_root=basis['closed_service_original_root'],
        root_census_original_digest=historical_digest))
    expected_eof=canonical_digest(dict(descriptor_digest=root_descriptor.payload['descriptor_digest'],
        process_root=process_root,root_census_original_digest=historical_digest))
    if (basis['mode']!='controlled_sdk_genesis' or basis['process_count']!=1
            or basis['process_root']!=process_root or basis['process_eof_digest']!=expected_eof
            or basis['controlled_sdk_original_digest']!=expected_controlled
            or basis['authority_process_original']!=original['authority_process_original']
            or basis['closed_service_original_count']<1):
        raise AuthorityUnavailable('cold SDK original does not commit to the same protected descriptor and physical close originals')
    require_process_retired_v1(original['authority_process_original'])
    current=read_process_identity_v1(os.getpid())
    if current is None:raise AuthorityUnavailable('actual current sole controlled SDK Authority process unavailable')
    proof=VerifiedControlledSDKInstallerOriginalV3(_ISSUER,gate=gate,control=control,config=config,
        descriptor=root_descriptor,summary=original['activation_basis'],process_census=process_census,original=original)
    return proof.require_current(gate=gate,control=control,config=config,meter=meter)
