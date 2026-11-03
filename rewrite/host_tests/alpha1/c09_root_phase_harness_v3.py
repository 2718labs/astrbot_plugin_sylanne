"""Root metadata observer for four genuine, serial installed C09 phase workers."""
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import sys
import time
from uuid import uuid4

PHASES = ('business_current_v3','prepare_switch_current_v3','release_current_v3','cold_current_v3')
NODE = 'tests/alpha1/integration/test_c09_installed_life_archive_v1.py::test_installed_completed_life_segmented_four_role_current_v3'

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()

def _require(value,message):
    if not value:raise ValueError(message)

def _process(pid,profile):
    return dict(pid=pid,birth=profile['_birth'](pid),mount_namespace=os.readlink(f'/proc/{pid}/ns/mnt'),
        pid_namespace=os.readlink(f'/proc/{pid}/ns/pid'))

def _uid(pid):
    row=next(line for line in Path(f'/proc/{pid}/status').read_text().splitlines() if line.startswith('Uid:'))
    values=tuple(map(int,row.split()[1:]));_require(len(set(values))==1,'actual phase UID identity differs')
    return values[0]

def _protected_descriptor(path):
    for item in (path,*path.parents):
        st=item.lstat();_require(not item.is_symlink() and st.st_uid==0 and not st.st_mode&0o022,
            'Root descriptor ancestry/owner differs')
    _require(stat.S_IMODE(path.stat().st_mode)==0o640,'Root descriptor file mode differs')
    raw=path.read_bytes();_require(len(raw)<=65536,'Root descriptor exceeds its original metadata bound')
    return raw,json.loads(raw)

class _RootCensusChannelV3:
    def __init__(self,spec,phase,index,app,run,pid,birth,deadline,control,profile,*,node=NODE,prior_root_receipts=()):
        self.spec,self.phase,self.index,self.app,self.run,self.pid,self.birth=spec,phase,index,app,run,pid,birth
        self.deadline,self.profile=deadline,profile
        _require(node in profile["FIXTURE_NODES"][spec.fixture_kind],"phase node is outside its fixed permanent family")
        self.node=node
        self.prior_root_receipts=tuple(prior_root_receipts)
        self.path=control/(str(index)+'.socket');self.nonce=str(uuid4());self.token=None;self.held=None
        self.root=_process(os.getpid(),profile);self.peer=None
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.listener.bind(str(self.path));os.chown(self.path,0,1000);os.chmod(self.path,0o660)
        self.listener.listen(1);self.listener.setblocking(False)
        self.originals=[]
        self.initial_storage_startup_v4=None
        self.host_graph_binding_v4=None;self.host_graph_custody_v4=None
    def descriptors(self):
        return [self.listener] if self.peer is None else [self.peer]
    def serve(self,readable):
        if self.listener in readable:
            _require(self.peer is None,'phase already owns its Root channel')
            self.peer,_=self.listener.accept();self.peer.setblocking(False)
            pid,uid,_=struct.unpack('3i',self.peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            _require(pid==self.pid and uid==1000 and self.profile['_birth'](pid)==self.birth,
                'Root channel peer is not the placed phase worker')
        if self.peer is None or self.peer not in readable:return
        raw=self.peer.recv(196609)
        if not raw and self.host_graph_custody_v4 is not None:
            self.peer.close();self.peer=None;self.host_graph_custody_v4=None;self.host_graph_binding_v4=None;return
        _require(raw and len(raw)<=196608,'Root phase channel ended or exceeded the fixed publication bound')
        request=json.loads(raw)
        if request.get('schema')=='sylanne.root-controlled-sdk-host-graph-request.v4':
            self._host_graph_storage_v4(request);return
        _require(self.host_graph_custody_v4 is None,'Host Graph custody cannot invoke startup or publication commands')
        if request.get('schema')=='sylanne.root-controlled-sdk-fresh-publication-request.v3':
            self._publish_fresh_d13_cohort_v3(request,raw)
            return
        _require(len(raw)<=65536,'original Root command metadata bound exceeded')
        if request.get('schema')=='sylanne.root-controlled-sdk-initial-storage-request.v4':
            self._initial_storage_v4(request)
            return
        if request.get('schema')=='sylanne.root-controlled-sdk-activation-retirement-request.v4':
            self._retire_sdk_activation_v4(request)
            return
        if request.get('schema')=='sylanne.root-controlled-sdk-core-retirement-request.v4':
            self._retire_core_authority_v4(request)
            return
        if request.get('schema')=='sylanne.test.beta1.root-forensic-request.v4':
            _require(set(request)=={'schema','command','phase','setup_sha256','manifest_sha256','graph_path','selector'}
                and request['command']=='snapshot_metadata','closed Root forensic request required')
            from rewrite.tests.alpha1.integration.beta1_root_forensic_channel_v4 import observe_root_fixture_metadata_v4
            try:
                answer=observe_root_fixture_metadata_v4(self,request,raw)
            except BaseException as error:
                import traceback
                target=Path(self.spec.evidence_directory)/'first-root-forensic-failure.json'
                trace=[dict(file=frame.filename,line=frame.lineno,function=frame.name)
                    for frame in traceback.extract_tb(error.__traceback__)]
                self.profile['_private_json'](target,dict(schema='sylanne.test.beta1.root-forensic-first-failure.v4',
                    phase=self.phase,exception_type=type(error).__name__,source_frames=trace,
                    request_sha256=sha256(raw).hexdigest(),observed_at_utc=time.time(),automatic_replay=False))
                raise
            self.peer.sendall(answer);self.peer.close();self.peer=None
            self.originals.append(dict(schema=request['schema'],phase=self.phase,request_sha256=sha256(raw).hexdigest(),
                response_sha256=sha256(answer).hexdigest(),scope='forensic_only'))
            return
        _require(request.get('schema')=='sylanne.root-controlled-sdk-census-request.v3','Root census request schema differs')
        if request.get('command')=='release':
            _require(self.held is not None and request==dict(schema=request['schema'],command='release',
                held_request_digest=self.held['request_digest']),'Root release is outside its original held channel')
            result=dict(self.held,command='released')
            self.peer.sendall(_canonical(result));self.originals.append(result);self.held=None
            self.peer.close();self.peer=None;self.host_graph_binding_v4=None;return
        _require(self.held is None and set(request)=={'schema','command','phase','authority_process',
            'descriptor_path','descriptor_sha256','selection_scope'} and request['command']=='hold'
            and request['phase']==self.phase,'Root hold request/phase differs')
        descriptor=Path(self.spec.phase_fixture_setup).parent/'c09-sdk/peer-cohort.json'
        _require(Path(request['descriptor_path'])==descriptor,'SDK descriptor is outside actual protected setup')
        raw_descriptor,value=_protected_descriptor(descriptor)
        _require(sha256(raw_descriptor).hexdigest()==request['descriptor_sha256'],'SDK protected descriptor bytes differ')
        scope_names=('authority_id','installation_id','control_store_id','namespace','sdk_peer_descriptor',
            'manifest_digest','inventory_manifest_digest','descriptor_digest')
        scope={name:value[name]for name in scope_names}
        _require(request['selection_scope']==scope,'SDK requested selection differs from protected descriptor')
        authority=_process(self.pid,self.profile)
        _require(authority==request['authority_process'] and _uid(self.pid)==1000,'actual phase Authority process changed')
        _require(not any(item.is_dir()for item in self.app.iterdir()),'SDK phase app has an unaccounted subgroup')
        members=self.profile['_members'](self.app)
        raw_members=self.profile['_read'](self.app/'cgroup.procs').split()
        _require(raw_members==[str(self.pid)] and len(members)==1 and members[0]['pid']==self.pid
            and members[0]['birth']==self.birth,'actual SDK cgroup census is not the sole placed worker')
        for group,controls in ((self.run,self.profile['RUN_CONTROLS']),(self.app,self.profile['APP_CONTROLS'])):
            _require(all(self.profile['_read'](group/name)==expected for name,expected in controls.items()),
                'actual fixed resource controls changed')
        self.token=str(uuid4());st=self.path.stat();run_st=self.run.stat();app_st=self.app.stat()
        result=dict(schema='sylanne.root-controlled-sdk-census.v3',command='held',phase=self.phase,
            resource_operation_id=self.spec.operation_id,root_process=self.root,authority_process=authority,
            app_cgroup=dict(path=str(self.app),device=app_st.st_dev,inode=app_st.st_ino),processes=[authority],
            cohort_eof=True,continuous_start_exclusion=True,descriptor_sha256=sha256(raw_descriptor).hexdigest(),
            node=self.node,node_sha256=self.spec.helper_sha256,package_sha256=self.spec.package_sha256,
            manifest_sha256=self.spec.manifest_sha256,dependency_sha256=self.spec.dependency_sha256,
            setup_sha256=self.spec.phase_fixture_setup_sha256,selection_scope=scope,
            request_digest=sha256(raw).hexdigest(),observed_monotonic_ns=time.monotonic_ns(),root_uid=_uid(os.getpid()),
            authority_uid=_uid(self.pid),socket=dict(path=str(self.path),device=st.st_dev,inode=st.st_ino,owner_uid=st.st_uid,
                mode=stat.S_IMODE(st.st_mode)),run_cgroup=dict(path=str(self.run),device=run_st.st_dev,inode=run_st.st_ino),
            cohort_count=len(members),cohort_root=sha256(_canonical([authority])).hexdigest(),channel_nonce=self.nonce,
            hold_token=self.token,profile_digest=sha256(_canonical(dict(run=self.profile['RUN_CONTROLS'],
                app=self.profile['APP_CONTROLS']))).hexdigest(),run_deadline_monotonic_ns=int(self.deadline*1_000_000_000))
        self.held=result;self.originals.append(result);self.peer.sendall(_canonical(result))
    def _host_graph_storage_v4(self,request):
        from sylanne3.host.c09_storage_admission_v1 import read_root_controlled_sdk_host_graph_material_v4
        from sylanne3.runtime_contracts import canonical_digest
        held=self.held if self.held is not None else self.host_graph_custody_v4['census']if self.host_graph_custody_v4 is not None else None
        _require(held is not None and request.get('held_request_digest')==held['request_digest']
            and request.get('hold_token')==held['hold_token'],'SDK Graph request has no actual same-channel Root census')
        _require(time.monotonic()<self.deadline and _process(self.pid,self.profile)==held['authority_process']
            and self.profile['_read'](self.app/'cgroup.procs').split()==[str(self.pid)]
            and not any(item.is_dir()for item in self.app.iterdir()),'SDK Graph custody actual process/resource changed')
        for group,controls in ((self.run,self.profile['RUN_CONTROLS']),(self.app,self.profile['APP_CONTROLS'])):
            _require(all(self.profile['_read'](group/name)==expected for name,expected in controls.items()),
                'SDK Graph custody actual fixed resource controls changed')
        setup_raw=Path(self.spec.phase_fixture_setup).read_bytes()
        _require(sha256(setup_raw).hexdigest()==self.spec.phase_fixture_setup_sha256,'SDK Graph Root fixed setup changed')
        setup=json.loads(setup_raw);_,assets=_protected_descriptor(Path(setup['c09_installation_assets']))
        profile_path=Path(setup['profile_root'])/setup['profile_id']/'profile.json'
        from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
        payload=json.loads(read_installed_bytes_v1(profile_path,limit=32768))
        command=request['command']
        base={'schema','command','held_request_digest','hold_token'}
        if command=='host_graph_storage_binding_v4':
            _require(set(request)==base and self.held is not None and self.host_graph_binding_v4 is None,
                'one actual same-channel SDK Graph binding required')
            binding=read_root_controlled_sdk_host_graph_material_v4(assets=assets,profile=payload,root_census=held)
            self.host_graph_binding_v4=binding
            self.peer.sendall(_canonical(dict(status='host_graph_storage_bound_v4',binding=binding)));return
        if command=='promote_host_graph_business_v4':
            _require(set(request)==base|{'binding_digest','peer_admission','gate_epoch'}
                and self.held is None and self.host_graph_custody_v4 is not None
                and self.host_graph_binding_v4['mode']=='controlled_sdk_bootstrap'
                and request['binding_digest']==self.host_graph_binding_v4['binding_digest']
                and type(request['gate_epoch'])is int and request['gate_epoch']>=0,
                'SDK business promotion needs its one actual transferred bootstrap custody')
            from sylanne3.host.c09_storage_admission_v1 import verify_root_controlled_sdk_host_business_admission_v4
            binding=verify_root_controlled_sdk_host_business_admission_v4(assets=assets,profile=payload,root_census=held,
                previous=self.host_graph_binding_v4,peer_admission=request['peer_admission'],gate_epoch=request['gate_epoch'])
            self.host_graph_binding_v4=binding;self.host_graph_custody_v4['binding']=binding
            self.peer.sendall(_canonical(dict(status='host_graph_business_bound_v4',binding=binding)));return
        _require(command=='release_host_graph_custody_v4' and set(request)==base|{'binding_digest','transfer_nonce'}
            and self.held is not None and self.host_graph_custody_v4 is None and self.host_graph_binding_v4 is not None
            and request['binding_digest']==self.host_graph_binding_v4['binding_digest'],
            'SDK Graph custody requires its one actual startup-to-Host transfer')
        current=read_root_controlled_sdk_host_graph_material_v4(assets=assets,profile=payload,root_census=held)
        _require(all(current[k]==v for k,v in self.host_graph_binding_v4.items()if k not in ('binding_nonce','binding_digest')),
            'SDK Graph actual signed selection changed before Root custody transfer')
        result=dict(schema='sylanne.root-controlled-sdk-host-graph-custody.v4',command='startup_released_host_custody_v4',
            process_census_digest=canonical_digest(held),descriptor_digest=held['selection_scope']['descriptor_digest'],
            binding_digest=request['binding_digest'],authority_process=held['authority_process'],app_cgroup=held['app_cgroup'],
            root_process=held['root_process'],run_deadline_monotonic_ns=held['run_deadline_monotonic_ns'],
            transfer_nonce=request['transfer_nonce'],request_digest=held['request_digest'],hold_token=held['hold_token'],channel_nonce=held['channel_nonce'])
        self.host_graph_custody_v4=dict(census=held,transfer=result,binding=self.host_graph_binding_v4)
        self.held=None;self.originals.append(result);self.peer.sendall(_canonical(result))

    def _initial_storage_v4(self,request):
        from sylanne3.runtime_contracts import canonical_digest
        from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
        from sylanne3.authority_service.c09_initial_segmented_genesis_v4 import require_published_initial_genesis_for_root_v4
        _require(self.held is not None and request.get('held_request_digest')==self.held['request_digest']
            and request.get('hold_token')==self.held['hold_token'],'initial storage requires its original held Root census')
        _require(time.monotonic()<self.deadline and _process(self.pid,self.profile)==self.held['authority_process']
            and self.profile['_read'](self.app/'cgroup.procs').split()==[str(self.pid)]
            and not any(item.is_dir()for item in self.app.iterdir()),'initial storage actual Root process/resource changed')
        for group,controls in ((self.run,self.profile['RUN_CONTROLS']),(self.app,self.profile['APP_CONTROLS'])):
            _require(all(self.profile['_read'](group/name)==expected for name,expected in controls.items()),
                'initial storage actual fixed resource controls changed')
        setup_raw=Path(self.spec.phase_fixture_setup).read_bytes()
        _require(sha256(setup_raw).hexdigest()==self.spec.phase_fixture_setup_sha256,'initial storage Root fixed setup changed')
        setup=json.loads(setup_raw);_,assets=_protected_descriptor(Path(setup['c09_installation_assets']))
        if request['command']=='initial_storage_hold_v4':
            _require(set(request)=={'schema','command','held_request_digest','hold_token'}
                and self.initial_storage_startup_v4 is None,'initial storage startup can issue only once per actual Root phase')
            profile_path=Path(setup['profile_root'])/setup['profile_id']/'profile.json'
            from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
            payload=json.loads(read_installed_bytes_v1(profile_path,limit=32768))
            namespace=payload['installation_policy']['namespace'];business=Path(setup['data_dir'])
            bindings=dict(authority_id=assets['authority_id'],installation_id=assets['installation_id'],
                control_store_id=assets['control_store_id'],namespace=assets['namespace'],graph_namespace=namespace,
                role_paths=dict(core=str(Path(setup['authority_store'])),deletion=str(business/'deletion.db'),
                    execution=str(business/'execution.db'),graph=str(business/'host-data/sylanne3.sqlite3')),
                control_path=assets['control_path'],key_path=assets['key_path'],instance_lock_path=assets['instance_lock'],
                inventory_manifest_digest=assets['inventory_manifest_digest'])
            _require(not any(Path(path).exists()for path in (*bindings['role_paths'].values(),bindings['control_path'])),
                'Root initial storage refuses all preexisting role/Control files')
            original=dict(schema='sylanne3.c09.initial-storage-startup-held.v4',command='initial_storage_held_v4',
                consumer_mode='controlled_sdk',bindings=bindings,root_process_original=read_process_identity_v1(os.getpid()),
                authority_process_original=read_process_identity_v1(self.pid),resource_original=self.held,
                selection_configuration_digest=sha256(setup_raw).hexdigest(),startup_nonce=str(uuid4()))
            self.initial_storage_startup_v4=original;self.originals.append(original);self.peer.sendall(_canonical(original));return
        _require(request['command']=='bind_initial_genesis_v4'and set(request)=={
            'schema','command','held_request_digest','hold_token','startup_nonce'}and self.initial_storage_startup_v4 is not None
            and request['startup_nonce']==self.initial_storage_startup_v4['startup_nonce'],
            'Root initial storage accepts only its exact same-channel bind')
        original=self.initial_storage_startup_v4
        _require(original['resource_original']==self.held,'Root initial storage lost its original continuous resource census')
        result=require_published_initial_genesis_for_root_v4(bindings=original['bindings'],startup_original=original)
        self.originals.append(result);self.peer.sendall(_canonical(result))

    def _prior_retired_phase_receipt_v4(self,old):
        candidates=[receipt for receipt in self.prior_root_receipts
            if old in receipt.get('root_census_originals',())]
        _require(len(candidates)==1,'signed old Core has no unique actual prior-phase Root receipt')
        receipt=candidates[0];identity=receipt['process_identity']
        _require(receipt['schema']=='sylanne.test.c09.current-phase-process.v3'
            and receipt['phase']==old['phase']and receipt['phase_index']<self.index
            and identity==old['authority_process']and receipt['observer_process_id']==os.getpid()
            and old['root_process']==self.root and old['resource_operation_id']==self.spec.operation_id
            and old['node']==self.node and old['setup_sha256']==self.spec.phase_fixture_setup_sha256
            and old['package_sha256']==self.spec.package_sha256 and old['manifest_sha256']==self.spec.manifest_sha256
            and old['dependency_sha256']==self.spec.dependency_sha256
            and old['selection_scope']==self.held['selection_scope']
            and old['run_cgroup']==self.held['run_cgroup']and old['app_cgroup']==self.held['app_cgroup']
            and old['run_deadline_monotonic_ns']==self.held['run_deadline_monotonic_ns'],
            'old Core retirement receipt crossed its actual Root/node/setup/resource/selected cohort')
        _require(receipt['original_pidfd_ready']is True and receipt['waitpid_reaped']is True
            and type(receipt['actual_exit_code'])is int and receipt['recursive_populated']=='0'
            and receipt['retirement']==dict(original_process=identity,state='retired'),
            'prior Root phase lacks actual waitpid/pidfd/cgroup EOF retirement')
        return receipt

    def _retire_core_authority_v4(self,request):
        import hmac
        from sylanne3.runtime_contracts import canonical_digest
        from sylanne3.authority_service.d13_cache_use_contract_v2 import (
            D13AuthorityCoreBirthReceiptV4,cache_use_from_wire_v2,validate_core_authority_retirement_original_v4)
        from sylanne3.authority_service.d13_core_authority_retirement_v4 import core_authority_retirement_common_v4
        _require(self.held is not None and set(request)=={'schema','command','held_request_digest','hold_token','birth_original'}
            and request['command']=='retire_core_authority_v4'and request['held_request_digest']==self.held['request_digest']
            and request['hold_token']==self.held['hold_token'],'Core retirement requires the same actual held Root census')
        _require(time.monotonic()<self.deadline and _process(self.pid,self.profile)==self.held['authority_process']
            and self.profile['_read'](self.app/'cgroup.procs').split()==[str(self.pid)]
            and not any(item.is_dir()for item in self.app.iterdir()),'Core retirement current actual Root process/resource changed')
        setup_raw=Path(self.spec.phase_fixture_setup).read_bytes()
        _require(sha256(setup_raw).hexdigest()==self.spec.phase_fixture_setup_sha256,'Core retirement fixed setup changed')
        setup=json.loads(setup_raw);_,assets=_protected_descriptor(Path(setup['c09_installation_assets']))
        key_path=Path(assets['key_path']);key=key_path.read_bytes()
        _require(key_path.lstat().st_uid==0 and not key_path.is_symlink()and len(key)==32,'actual installed Control key changed')
        wire=request['birth_original'];birth=cache_use_from_wire_v2(wire,D13AuthorityCoreBirthReceiptV4)
        unsigned={k:v for k,v in wire.items()if k not in {'birth_digest','signature'}}
        digest=sha256(json.dumps(unsigned,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
        _require(birth.birth_profile=='controlled_sdk'and birth.key_id==assets['key_id']and birth.birth_digest==digest
            and hmac.compare_digest(birth.signature,hmac.new(key,(birth.schema+'\n'+digest).encode(),'sha256').hexdigest())
            and (birth.authority_id,birth.installation_id,birth.control_store_id,birth.authority_namespace)==
                tuple(assets[k]for k in ('authority_id','installation_id','control_store_id','namespace')),
            'Root retirement selector is not the actual installed Control signed Core birth')
        old=birth.root_observation_original
        receipt=self._prior_retired_phase_receipt_v4(old);identity=receipt['process_identity']
        from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
        root_original=read_process_identity_v1(os.getpid())
        _require((root_original['pid'],root_original['birth'])==(old['root_process']['pid'],old['root_process']['birth']),
            'SDK old Root original is not this actual continuous Root process')
        nonce=str(uuid4());prior_digest=canonical_digest(receipt);current_digest=canonical_digest(self.held)
        original=dict(schema='sylanne3.d13.core-authority-retirement.controlled-sdk.v4',
            **core_authority_retirement_common_v4(birth,nonce),old_root_process_original=root_original,
            old_pid_namespace_identity=identity['pid_namespace'],old_mount_namespace_identity=identity['mount_namespace'],
            current_root_census_digest=current_digest,source_phase=receipt['phase'],source_node=self.node,
            source_setup_sha256=old['setup_sha256'],source_process_identity=identity,actual_exit_code=receipt['actual_exit_code'],
            original_pidfd_ready=True,recursive_populated=False,waitpid_reaped=True,
            resource_operation_id=self.spec.operation_id,root_process_original=root_original,prior_receipt_digest=prior_digest,
            eof_digest=canonical_digest((birth.birth_digest,prior_digest,current_digest,nonce)))
        validate_core_authority_retirement_original_v4(original,birth_profile='controlled_sdk')
        self.peer.sendall(_canonical(dict(status='core_authority_retired_v4',original=original)))

    def _retire_sdk_activation_v4(self,request):
        import hmac
        from sylanne3.runtime_contracts import canonical_digest
        from sylanne3.host.c09_controlled_sdk_bootstrap_v3 import validate_controlled_sdk_root_census_original_v4
        _require(self.held is not None and set(request)=={'schema','command','held_request_digest','hold_token','activation_original'}
            and request['command']=='retire_sdk_activation_v4'and request['held_request_digest']==self.held['request_digest']
            and request['hold_token']==self.held['hold_token'],'SDK activation retirement requires its actual held Root channel')
        _require(time.monotonic()<self.deadline and _process(self.pid,self.profile)==self.held['authority_process']
            and self.profile['_read'](self.app/'cgroup.procs').split()==[str(self.pid)]
            and not any(item.is_dir()for item in self.app.iterdir()),'actual current SDK census/resource changed')
        setup_raw=Path(self.spec.phase_fixture_setup).read_bytes()
        _require(sha256(setup_raw).hexdigest()==self.spec.phase_fixture_setup_sha256,'SDK retirement fixed setup differs')
        setup=json.loads(setup_raw);_,assets=_protected_descriptor(Path(setup['c09_installation_assets']))
        key_path=Path(assets['key_path']);key=key_path.read_bytes()
        _require(key_path.lstat().st_uid==0 and not key_path.is_symlink()and len(key)==32,'actual SDK Control key changed')
        wire=request['activation_original'];unsigned={k:v for k,v in wire.items()if k not in {'activation_digest','signature'}}
        digest=sha256(json.dumps(unsigned,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
        _require(wire['schema']=='sylanne3.c09.writer-peer-registry-activation.controlled-sdk.v3'
            and wire['key_id']==assets['key_id']and wire['activation_digest']==digest
            and hmac.compare_digest(wire['signature'],hmac.new(key,(wire['schema']+'\n'+digest).encode(),'sha256').hexdigest())
            and tuple(wire[k]for k in ('authority_id','installation_id','control_store_id','namespace'))==
                tuple(assets[k]for k in ('authority_id','installation_id','control_store_id','namespace')),
            'SDK retirement requires its exact actual Control-signed activation original')
        old=wire['activation_basis']['controlled_sdk_root_census_original']
        validate_controlled_sdk_root_census_original_v4(old)
        _require(canonical_digest(old)==wire['activation_basis']['controlled_sdk_root_census_original_digest']
            and (old['authority_process']['pid'],old['authority_process']['birth'])==
                (wire['authority_process_original']['pid'],wire['authority_process_original']['birth']),
            'SDK activation lacks its actual complete signed Root census')
        prior=self._prior_retired_phase_receipt_v4(old)
        result=dict(schema='sylanne3.c09.controlled-sdk-root-phase-retirement.v4',
            activation_digest=wire['activation_digest'],activation_selector_digest=canonical_digest(wire),
            old_root_census_digest=canonical_digest(old),current_root_census_digest=canonical_digest(self.held),
            prior_receipt_digest=canonical_digest(prior),source_process_identity=prior['process_identity'],
            source_phase=prior['phase'],source_node=self.node,source_setup_sha256=old['setup_sha256'],
            actual_exit_code=prior['actual_exit_code'],original_pidfd_ready=True,waitpid_reaped=True,recursive_populated=False,
            resource_operation_id=self.spec.operation_id,root_process=self.root,channel_nonce=self.nonce,hold_token=self.token)
        self.peer.sendall(_canonical(dict(status='sdk_activation_retired_v4',original=result)))

    def _publish_fresh_d13_cohort_v3(self,request,raw):
        import base64,hmac,sqlite3
        _require(self.held is None and not any(item.get('schema')=='sylanne.root-controlled-sdk-fresh-publication.v3'
            for item in self.originals),'fresh publication requires the actual released single preparation')
        _require(set(request)=={'schema','command','phase','witness','profile_base64','assets_base64'}
            and request['command']=='publish_fresh_d13_cohort_v3'and request['phase']==self.phase,
            'closed fresh publisher command/phase differs')
        _require(time.monotonic()<self.deadline and _process(self.pid,self.profile)==request['witness']['authority_process_original']
            and _uid(self.pid)==1000,'fresh publication lost its original actual process/deadline')
        _require(not any(item.is_dir()for item in self.app.iterdir())
            and self.profile['_read'](self.app/'cgroup.procs').split()==[str(self.pid)],
            'fresh publisher actual complete app census changed')
        for group,controls in ((self.run,self.profile['RUN_CONTROLS']),(self.app,self.profile['APP_CONTROLS'])):
            _require(all(self.profile['_read'](group/name)==expected for name,expected in controls.items()),
                'fresh publisher actual fixed resource controls changed')
        setup_path=Path(self.spec.phase_fixture_setup)
        setup_raw=setup_path.read_bytes();setup=json.loads(setup_raw)
        _require(sha256(setup_raw).hexdigest()==self.spec.phase_fixture_setup_sha256
            and setup['schema']in {'sylanne.artifact-phase-fixture-setup.v4','sylanne.artifact-phase-fixture-setup.v5'},'fresh publisher protected original setup differs')
        descriptor=setup_path.parent/'c09-sdk/peer-cohort.json'
        descriptor_raw,descriptor_value=_protected_descriptor(descriptor)
        _require(Path(setup['c09_sdk_peer_cohort'])==descriptor,'fixed SDK descriptor path differs')
        from sylanne3.runtime_contracts import canonical_digest
        witness=request['witness'];census=witness['root_census_original']
        held=next((item for item in self.originals if item.get('command')=='held'
            and item.get('request_digest')==census.get('request_digest')),None)
        released=next((item for item in self.originals if item.get('command')=='released'
            and item.get('request_digest')==census.get('request_digest')),None)
        _require(held==census and released==dict(census,command='released')
            and census['phase']==self.phase and census['resource_operation_id']==self.spec.operation_id
            and census['root_process']==self.root and census['channel_nonce']==self.nonce
            and census['node']==self.node and census['manifest_sha256']==self.spec.manifest_sha256
            and census['package_sha256']==self.spec.package_sha256
            and census['setup_sha256']==self.spec.phase_fixture_setup_sha256
            and census['dependency_sha256']==self.spec.dependency_sha256
            and census['descriptor_sha256']==sha256(descriptor_raw).hexdigest()
            and census['run_deadline_monotonic_ns']==int(self.deadline*1_000_000_000),
            'fresh publisher has no matching actual Root-held/released census original')
        for name,group in (('run_cgroup',self.run),('app_cgroup',self.app)):
            info=group.stat()
            _require((census[name]['path'],census[name]['device'],census[name]['inode'])==(str(group),info.st_dev,info.st_ino),
                'fresh publisher resource group incarnation changed')
        old_assets_path=Path(setup['c09_installation_assets'])
        _,installation=_protected_descriptor(old_assets_path)
        key_path=Path(installation['key_path']);key=key_path.read_bytes()
        _require(key_path.lstat().st_uid==0 and not key_path.is_symlink()and len(key)==32,
            'fresh publisher actual Control signing key differs')
        def committed(value):return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
        def signed(value,field):
            body={k:v for k,v in value.items()if k not in {field,'signature'}}
            digest=committed(body)
            _require(value['key_id']==installation['key_id']and value[field]==digest
                and hmac.compare_digest(value['signature'],hmac.new(key,(value['schema']+'\n'+digest).encode(),'sha256').hexdigest()),
                'actual Control signed publication/activation original differs')
        signed(witness,'publication_witness_digest')
        _require(witness['schema']=='sylanne3.d13.controlled-sdk-fresh-publication-witness.v3'
            and (witness['authority_id'],witness['installation_id'],witness['control_store_id'],witness['namespace'])==
                tuple(installation[k]for k in ('authority_id','installation_id','control_store_id','namespace'))
            and witness['resource_operation_id']==self.spec.operation_id
            and witness['descriptor_digest']==descriptor_value['descriptor_digest']
            and witness['closed_services_root']==canonical_digest(witness['closed_services_originals'])
            and witness['consumer_closure_root']==canonical_digest(witness['consumer_closures']),
            'publication actual installed closure/source identities differ')
        _require(witness['consumer_closures']and all(item['authority_process_original']==census['authority_process']
            and item['resource_operation_id']==self.spec.operation_id for item in witness['consumer_closures'])
            and all(item['authority_process_original']==census['authority_process']for item in witness['closed_services_originals']),
            'publication RAM-close producer witness crossed its original actual process')
        receipt=witness['prepared_receipt']
        from sylanne3.runtime_contracts import canonical_digest
        _require(canonical_digest(receipt)==witness['prepared_receipt_digest'], 'actual prepared receipt commitment changed')
        profile_path=Path(setup['profile_root'])/setup['profile_id']/'profile.json'
        assets_path=setup_path.parent/'c09-sdk/d13-installation-assets.json'
        _require(Path(setup['d13_installation_assets'])==assets_path,'fresh publisher cannot select an arbitrary asset path')
        for path in (profile_path,assets_path):
            for ancestor in (path,*path.parents):
                info=ancestor.lstat()
                _require(not ancestor.is_symlink()and info.st_uid==0 and not info.st_mode&0o022,
                    'fresh publication protected file ancestry changed')
        old_profile=profile_path.read_bytes();old_assets=assets_path.read_bytes()
        _require(sha256(old_profile).hexdigest()==witness['source_profile_sha256']
            and sha256(old_assets).hexdigest()==witness['source_assets_sha256'],'fresh publication original files changed')
        profile_bytes=base64.b64decode(request['profile_base64'],validate=True)
        assets_bytes=base64.b64decode(request['assets_base64'],validate=True)
        _require(len(profile_bytes)<=32768 and len(assets_bytes)<=65536
            and sha256(profile_bytes).hexdigest()==receipt['profile_sha256']
            and sha256(assets_bytes).hexdigest()==receipt['assets_sha256'],'actual fresh final file bytes differ')
        new_profile=json.loads(profile_bytes);new_assets=json.loads(assets_bytes)
        old_profile_value=json.loads(old_profile);old_assets_value=json.loads(old_assets)
        pair_names={'d13_cache_use_control_v2','d13_derived_cache_maintenance_v2'}
        _require({k:v for k,v in new_profile.items()if k not in pair_names}==
            {k:v for k,v in old_profile_value.items()if k not in pair_names}
            and {k:v for k,v in new_assets.items()if k!='d13_cache_use_assets_v2'}==
                {k:v for k,v in old_assets_value.items()if k!='d13_cache_use_assets_v2'},
            'fresh publication cannot change original Root/model/Counter assets')
        from sylanne3.host import authority_profile as profile_codec
        from sylanne3.runtime.d13_technical_policy import d13_cache_policy_pair_from_payload_v2,InstalledD13CacheUseAssetsV2
        from sylanne3.runtime_contracts import NamespaceId
        installation_policy=profile_codec._policy_from_payload(new_profile)
        use,maintenance=d13_cache_policy_pair_from_payload_v2(new_profile,installation_policy,d13_policies=(
            profile_codec._d13_precompression_from_payload(new_profile,installation_policy),
            profile_codec._d13_paid_precompression_from_payload(new_profile,installation_policy)))
        asset=dict(new_assets['d13_cache_use_assets_v2'][0]);asset['namespace']=NamespaceId(**asset['namespace'])
        pinned=InstalledD13CacheUseAssetsV2(**asset)
        _require(len(new_assets['d13_cache_use_assets_v2'])==1
            and (pinned.namespace,pinned.authority_namespace,pinned.installation_id,pinned.package_manifest_sha256,
                pinned.use_policy_ref,pinned.maintenance_policy_ref)==(installation_policy.namespace,
                    installation_policy.authority_namespace,installation_policy.installation_id,installation_policy.manifest_digest,
                    use.policy_ref,maintenance.link_ref)
            and (pinned.use_policy_digest,pinned.maintenance_policy_digest,pinned.policy_pair_digest,pinned.consumer_cohort_digest)==
                (use.digest,maintenance.digest,use.policy_pair_digest,use.consumer_cohort_digest)
            and maintenance.coverage_digest==canonical_digest(receipt['coverage_original']),
            'fresh published profile/assets lack the exact complete final policy pair')
        control_path=Path(installation['control_path'])
        with sqlite3.connect(control_path.as_uri()+'?mode=ro',uri=True)as db:
            row=db.execute('SELECT activation_json FROM c09_writer_peer_registry_activation_v3 WHERE installation_id=?',
                (installation['installation_id'],)).fetchone()
            _require(row is not None,'actual persisted activation original absent')
            activation=json.loads(row[0]);signed(activation,'activation_digest')
            _require(activation==witness['activation_original'],'publication persisted activation changed')
            _require(db.execute('SELECT 1 FROM c09_writer_peer_admissions_v3 LIMIT 1').fetchone()is None,
                'fresh publication has actual historical peer admission; HOLD')
            current=db.execute('SELECT pointer_version,current_manifest_digest,active_operation_id,stage FROM c09_storage_current_v1 WHERE installation_id=?',
                (installation['installation_id'],)).fetchone()
            _require(current==(0,witness['selected_manifest_digest'],None,'READY'), 'fresh publication selected pointer is no longer initial')
            selected=db.execute('SELECT manifest_json FROM c09_storage_manifests_v1 WHERE manifest_digest=?',
                (current[1],)).fetchone()
            _require(selected is not None and json.loads(selected[0])==witness['selected_manifest'],
                'fresh publication role census is not the actual durable selected manifest')
        role_paths={Path(member['resolved_path'])for member in witness['selected_manifest']['members']if member['role']in {'graph','core','deletion','execution'}}
        _require(len(role_paths)==4,'fresh publication actual complete selected role metadata missing')
        fd_targets={path for role in role_paths for path in (role,Path(str(role)+'-wal'),Path(str(role)+'-shm'))}
        identities={(path.stat().st_dev,path.stat().st_ino)for path in fd_targets if path.exists()}
        for fd in Path('/proc/'+str(self.pid)+'/fd').iterdir():
            try:info=fd.stat()
            except FileNotFoundError:continue
            _require((info.st_dev,info.st_ino)not in identities,
                'fresh publication actual old selected role/WAL/SHM FD remains open')
        core_path=Path(setup['authority_store'])
        with sqlite3.connect(core_path.as_uri()+'?mode=ro',uri=True)as db:
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_d13_cache_use_policies_v2'").fetchone()
            _require(exists is None or db.execute('SELECT 1 FROM authority_d13_cache_use_policies_v2 LIMIT 1').fetchone()is None,
                'fresh publication cannot replace an already signed policy pair')
        # The final profile is the commit selector. Every consumer loader verifies its asset pair.
        for path,data in ((assets_path,assets_bytes),(profile_path,profile_bytes)):
            stage=path.with_name(path.name+'.fresh-d13-'+self.nonce)
            try:
                with os.fdopen(os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL,stat.S_IMODE(path.stat().st_mode)),'wb')as stream:
                    os.fchown(stream.fileno(),0,path.stat().st_gid);stream.write(data);stream.flush();os.fsync(stream.fileno())
                os.replace(stage,path)
                directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(directory)
                finally:os.close(directory)
            finally:
                if stage.exists():stage.unlink()
        _require(profile_path.read_bytes()==profile_bytes and assets_path.read_bytes()==assets_bytes,
            'fresh publication final protected file readback differs')
        result=dict(schema='sylanne.root-controlled-sdk-fresh-publication.v3',status='published_closed',
            request_sha256=sha256(raw).hexdigest(),prepared_receipt_digest=witness['prepared_receipt_digest'],
            profile_sha256=sha256(profile_bytes).hexdigest(),assets_sha256=sha256(assets_bytes).hexdigest(),
            resource_operation_id=self.spec.operation_id,phase=self.phase,published_at_utc=time.time())
        self.originals.append(result);self.peer.sendall(_canonical(result));self.peer.close();self.peer=None

    def close(self):
        if self.peer is not None:self.peer.close()
        self.listener.close()
        self.path.unlink()


def _phase(spec,phase,index,command,environment,app,run,control,guard,started,deadline,totals,profile,*,node=NODE,prior_root_receipts=()):
    profile['_pin_inputs_in_child'](spec)
    _require(profile['_event'](app,'populated')=='0' and not profile['_read'](app/'cgroup.procs'),
        'previous phase has not reached actual cgroup retirement EOF')
    placement=os.open(app/'cgroup.procs',os.O_WRONLY);ready_r,ready_w=os.pipe();go_r,go_w=os.pipe()
    out_r,out_w=os.pipe();err_r,err_w=os.pipe();fds={placement,ready_r,ready_w,go_r,go_w,out_r,out_w,err_r,err_w}
    log_paths={out_r:guard/(phase+'.stdout.log'),err_r:guard/(phase+'.stderr.log')}
    logs={fd:os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)for fd,path in log_paths.items()}
    channel=handle=pid=None;phase_started=time.monotonic_ns();identity=None;status=None;result=None
    receipt=dict(schema='sylanne.test.c09.current-phase-process.v3',phase=phase,phase_index=index,
        observer_process_id=os.getpid(),command=command,stdout_path=str(log_paths[out_r]),stderr_path=str(log_paths[err_r]))
    try:
        pid=os.fork()
        if pid==0:
            try:
                for fd in (ready_r,go_w,out_r,err_r):os.close(fd)
                for fd in logs.values():os.close(fd)
                os.dup2(out_w,1);os.dup2(err_w,2);os.write(placement,str(os.getpid()).encode());os.write(ready_w,b'PLACED\n')
                if os.read(go_r,2)!=b'GO':os._exit(125)
                for fd in (placement,ready_w,go_r,out_w,err_w):os.close(fd)
                profile['_enter_phase_child_identity_v1']();os.chdir(guard)
                os.execve(sys.executable,command,environment)
            except BaseException as error:
                os.write(2,(type(error).__name__+' before genuine phase exec\n').encode());os._exit(126)
        handle=os.pidfd_open(pid);birth=profile['_birth'](pid);identity=_process(pid,profile)
        channel=_RootCensusChannelV3(spec,phase,index,app,run,pid,birth,deadline,control,profile,node=node,prior_root_receipts=prior_root_receipts)
        for fd in (placement,ready_w,go_r,out_w,err_w):os.close(fd);fds.remove(fd)
        _require(select.select([ready_r,handle],[],[],min(10,max(0,deadline-time.monotonic())))[0]
            and os.read(ready_r,7)==b'PLACED\n','phase placement did not reach its original GO gate')
        expected='0::'+profile['_read'](Path(f'/proc/{pid}/cgroup')).partition('0::')[2]
        _require(expected.endswith('/'+run.name+'/app') and profile['_read'](app/'cgroup.procs')==str(pid)
            and profile['_birth'](pid)==birth,'actual singleton phase placement differs')
        os.write(go_w,b'GO');os.close(go_w);fds.remove(go_w);os.close(ready_r);fds.remove(ready_r)
        for fd in (out_r,err_r):os.set_blocking(fd,False)
        phase_deadline=min(deadline,phase_started/1_000_000_000+600);last_sample=0
        while True:
            now=time.monotonic()
            if now>=phase_deadline:raise TimeoutError('original phase600s or whole run1000s deadline')
            if now>=last_sample:
                members=profile['_members'](app)
                for member in members:
                    _require(member['cgroup']==expected and all(v in (0,3,5)for v in member['scheduler_classes'].values()),
                        'actual phase subtree escaped its owned fair CPU membership')
                observed=dict(observed_time_ns=time.time_ns(),phase=phase,run=profile['_metrics'](run),app=profile['_metrics'](app),members=members)
                encoded=_canonical(observed)+b'\n';totals['metrics']+=len(encoded)
                _require(sum(totals[name]for name in ('stdout','stderr','metrics'))<=profile['LOG_LIMIT'],'original resource log limit exhausted')
                os.write(totals['metrics_fd'],encoded);last_sample=now+0.5
            readable=select.select([*logs,*channel.descriptors(),handle],[],[],0.1)[0];channel.serve(readable)
            for fd in list(logs):
                if fd not in readable:continue
                data=os.read(fd,65536)
                if not data:os.close(fd);fds.remove(fd);os.fsync(logs[fd]);os.close(logs.pop(fd));continue
                label='stdout'if fd==out_r else 'stderr';totals[label]+=len(data)
                _require(sum(totals[name]for name in ('stdout','stderr','metrics'))<=profile['LOG_LIMIT'],'original total private log limit exhausted')
                os.write(logs[fd],data)
            if handle in readable and status is None:
                _,status=os.waitpid(pid,0)
                _require(os.waitstatus_to_exitcode(status)==0,'current phase first process failure; preserve stderr')
                _require(profile['_event'](app,'populated')=='0','phase leader exited with a live owned descendant')
            if status is not None and not logs:break
        _require(os.waitstatus_to_exitcode(status)==0,'current phase first failure; preserve original stderr')
        _require(channel.held is None,'worker ended before its Root held exclusion was released')
        _require(profile['_event'](app,'populated')=='0' and not profile['_read'](app/'cgroup.procs'),
            'current phase descendants remain before next phase')
        raw=log_paths[out_r].read_bytes();result=json.loads(raw.strip().splitlines()[-1])
        _require(result['phase']==phase and result['pid']==pid,'actual phase stdout process identity differs')
        pin=json.loads((guard/('pin-'+str(pid)+'.json')).read_bytes())
        _require(pin['process_identity']['pid']==pid and pin['process_identity']['birth']==birth
            and pin['installed_root']==spec.installed_root and pin['manifest_sha256']==spec.manifest_sha256
            and pin['engineering_inventory_sha256']==spec.engineering_inventory_sha256
            and pin['entrypoint']['sha256']==spec.helper_sha256,'actual phase installed/source import pins differ')
    finally:
        first_error=sys.exc_info()[1];cleanup_errors=[]
        if go_w in fds:os.close(go_w);fds.remove(go_w)
        try:
            if handle is not None and not select.select([handle],[],[],0)[0]:
                signal.pidfd_send_signal(handle,signal.SIGTERM)
            cleanup_deadline=time.monotonic()+10
            if profile['_event'](run,'populated')!='0':profile['_write'](run/'cgroup.kill','1')
            while profile['_event'](app,'populated')!='0' and time.monotonic()<cleanup_deadline:time.sleep(0.05)
            _require(profile['_event'](app,'populated')=='0','failed phase owned subtree did not reach actual retirement EOF')
            if handle is not None:
                _require(select.select([handle],[],[],max(0,cleanup_deadline-time.monotonic()))[0],
                    'failed phase original process did not retire')
            while logs and time.monotonic()<cleanup_deadline:
                for fd in select.select(list(logs),[],[],0.1)[0]:
                    data=os.read(fd,65536)
                    if not data:os.close(fd);fds.remove(fd);os.fsync(logs[fd]);os.close(logs.pop(fd));continue
                    label='stdout'if fd==out_r else 'stderr'
                    _require(sum(totals[name]for name in ('stdout','stderr','metrics'))+len(data)<=profile['LOG_LIMIT'],
                        'original combined private log capture exhausted')
                    totals[label]+=len(data);os.write(logs[fd],data)
            if pid is not None and status is None:
                waited,status_now=os.waitpid(pid,os.WNOHANG)
                if waited:status=status_now
        except BaseException as error:cleanup_errors.append(dict(type=type(error).__name__,message=str(error)))
        ready=handle is not None and bool(select.select([handle],[],[],0)[0])
        receipt.update(process_identity=identity,actual_exit_code=None if status is None else os.waitstatus_to_exitcode(status),
            elapsed_ns=time.monotonic_ns()-phase_started,original_pidfd_ready=ready,waitpid_reaped=status is not None,cleanup_errors=cleanup_errors,
            recursive_populated=profile['_event'](app,'populated'),retirement=None if identity is None else dict(original_process=identity,state='retired'if ready else 'not_retired'),
            root_census_originals=[] if channel is None else channel.originals)
        profile['_private_json'](guard/(phase+'.process.json'),receipt)
        for fd in logs.values():os.fsync(fd);os.close(fd)
        for fd in fds:os.close(fd)
        if channel is not None:channel.close()
        if handle is not None:os.close(handle)
        if first_error is None and cleanup_errors:raise RuntimeError("phase cleanup failed: "+str(cleanup_errors))
    return result,receipt


def _verify(outcomes,receipts):
    _require(len(outcomes)==len(receipts)==4 and [v['phase']for v in outcomes]==list(PHASES),'actual four-phase sequence incomplete')
    business,switched,released,cold=outcomes;operation=business['operation_id']
    checks=dict(nonempty_producers=bool(business['producers']['c04_qualification_digests']and business['producers']['draft_qualification_digests'])
        and business['producers']['unit_count']>=2,distinct_processes=len({v['pid']for v in outcomes})==4,
        operation=all(v['operation_id']==operation for v in outcomes),source_execution=business['source_execution_commitment']==sha256(business['source_execution_id'].encode()).hexdigest()
        and cold['source_execution_commitment']==business['source_execution_commitment'],restart=switched['restart_required']is True
        and switched['execution_count']>0 and switched['model_count']>0,prepared=switched['prepared_digest']==released['prepared_digest']==cold['prepared_digest'],
        roles=switched['segmented_roles']==released['selected_roles']==cold['selected_roles'],manifest=released['manifest_digest']==cold['manifest_digest'],
        pointer=released['pointer_version']==cold['pointer_version'],generation=released['storage_generation']==cold['storage_generation']and cold['storage_generation']>0,
        family_eof=released['family_eof']==cold['family_eof']and cold['family_eof']['model']['record_count']>0,
        terminal=released['terminal_commitment']==cold['terminal_commitment'],selected_files=released['exact_selected_files_unchanged']is cold['exact_selected_files_unchanged']is True,
        factual_meter=released['factual_meter_bytes']>0 and cold['factual_meter_bytes']>0,
        no_cache_requests=released['provider_cache_request_count']==cold['provider_cache_request_count']==0,
        real_retirement=all(v['actual_exit_code']==0 and v['original_pidfd_ready']and v['recursive_populated']=='0'for v in receipts))
    for name,value in checks.items():_require(value,'current four-phase original assertion failed: '+name)
    return checks


def run_root_controlled_four_phase_v3(spec,*,app,run,environment,started,deadline,profile):
    _require(os.geteuid()==0 and profile['FIXTURE_NODES'][spec.fixture_kind]==(NODE,),'fixed Root current C09 harness required')
    fixture=Path(spec.basetemp);guard=fixture/'import-origin-evidence';guard.mkdir(mode=0o700);os.chown(guard,1000,1000)
    guard_file=guard/'sitecustomize.py';guard_file.write_text(_PRODUCT_IMPORT_GUARD,encoding='utf-8');os.chown(guard_file,1000,1000)
    control=fixture.parent/'root-phase-control';control.mkdir(mode=0o750);os.chown(control,0,1000);control.chmod(0o750)
    environment=dict(environment,PYTHONPATH=os.pathsep.join((str(guard),str(Path(spec.installed_root)/'rewrite'),spec.installed_root,spec.sdk_root)),
        PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',PYTHONFAULTHANDLER='1',SYLANNE_D04_INSTALLED_ROOT=spec.installed_root,
        SYLANNE_C09_IMPORT_EVIDENCE=str(guard),SYLANNE_C09_GUARD_SHA256=sha256(guard_file.read_bytes()).hexdigest())
    environment.pop('PYTHONHOME',None)
    script=Path(spec.frozen_rewrite_root)/NODE.partition('::')[0];outcomes=[];receipts=[]
    metrics=os.open(Path(spec.evidence_directory)/'resources.private.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    totals=dict(stdout=0,stderr=0,metrics=0,metrics_fd=metrics)
    output=Path(spec.evidence_directory)/'actualphase-outcomes.json'
    try:
        for index,phase in enumerate(PHASES):
            environment.update(SYLANNE_QUAL_ROOT_CENSUS_SOCKET=str(control/(str(index)+'.socket')),SYLANNE_QUAL_ROOT_CENSUS_PHASE=phase)
            arguments=([str(fixture),spec.phase_fixture_setup]if index==0 else [str(fixture),outcomes[0]['cold_fixture']['path'],
                outcomes[0]['cold_fixture']['fixture_digest'],outcomes[0]['operation_id'],outcomes[0]['source_execution_id']])
            result,receipt=_phase(spec,phase,index,[sys.executable,'-B',str(script),phase,*arguments],environment,app,run,control,guard,started,deadline,totals,profile,prior_root_receipts=tuple(receipts))
            outcomes.append(result);receipts.append(receipt)
        checks=_verify(outcomes,receipts)
        original=dict(schema='sylanne.actualphase-outcomes.v3',harness_kind='root_controlled_four_phase',node=NODE,
            node_sha256=spec.helper_sha256,package_sha256=spec.package_sha256,manifest_sha256=spec.manifest_sha256,
            operation_id=spec.operation_id,effective_exit_code=0,outcomes=outcomes,processes=receipts,checks=checks,
            run_started_monotonic_ns=int(started*1_000_000_000),run_ended_monotonic_ns=time.monotonic_ns(),log_bytes={k:totals[k]for k in ('stdout','stderr','metrics')})
        profile['_private_json'](output,original)
        profile['_private_json'](guard/'c09-current-complete.json',dict(outcomes=outcomes,processes=receipts,checks=checks))
        return dict(status='FIXTURE_EXIT_OBSERVED_NOT_QUALIFICATION',actual_exit=0,original_pidfd_ready=True,
            original_pidfd_ready_after_cleanup=all(v['original_pidfd_ready']for v in receipts),actual_phase_outcomes_path=str(output),
            harness_kind='root_controlled_four_phase',elapsed_seconds=time.monotonic()-started)
    finally:os.fsync(metrics);os.close(metrics)


_BETA1_NUMERIC_SCENARIOS=("numeric-positive","numeric-registration","numeric-mutation-prepare",
    "numeric-mutation-acquire","numeric-authorization-installation","numeric-authorization-lease",
    "numeric-authorization-reservation","numeric-authorization-configuration",
    "numeric-authorization-worker","numeric-authorization-time")
_BETA1_D13_SCENARIOS=("d13-positive","d13-expired","d13-admission","d13-derived","d13-derived-expiry")
_BETA1_PHASES=(*PHASES,"consumer_current_v3")


def read_protected_beta1_fixture_suite_v3(spec,profile):
    """One independently pinned Root-prepared setup per fixed permanent node."""
    _require(spec.fixture_kind in profile["BETA1_CURRENT_SUITE_KINDS"],"closed current Beta1 fixture family required")
    path=Path(spec.phase_fixture_setup)
    profile['_validate_phase_fixture_setup'](str(path),spec.phase_fixture_setup_sha256,spec.phase_setup_root)
    raw=path.read_bytes();_require(len(raw)<=65536,"Beta1 suite descriptor exceeds its finite metadata bound")
    value=json.loads(raw)
    fields={"schema","fixture_kind","package_sha256","manifest_sha256","nodes"}
    _require(type(value)is dict and set(value)==fields
        and value['schema']=='sylanne.beta1.protected-fixture-suite.v3'
        and value['fixture_kind']=='beta1_full_15'
        and value['package_sha256']==spec.package_sha256
        and value['manifest_sha256']==spec.manifest_sha256,"exact protected Beta1 suite/package binding required")
    nodes=(*profile['FIXTURE_NODES']['numeric'],*profile['FIXTURE_NODES']['d13_full'])
    scenarios=(*_BETA1_NUMERIC_SCENARIOS,*_BETA1_D13_SCENARIOS)
    families=('numeric',)*10+('d13_full',)*5
    items=value['nodes']
    _require(type(items)is list and len(items)==len(nodes)==len(scenarios),"complete full15 fixed Beta1 manifest required; family-only descriptors cannot establish independence")
    paths=[];hashes=[]
    for item,node,scenario,family in zip(items,nodes,scenarios,families,strict=True):
        _require(type(item)is dict and set(item)=={'fixture_kind','node','scenario','setup_file','setup_sha256'}
            and item['fixture_kind']==family and item['node']==node and item['scenario']==scenario,"Beta1 node/scenario selection differs")
        setup=Path(item['setup_file'])
        profile['_validate_phase_fixture_setup'](str(setup),item['setup_sha256'],spec.phase_setup_root)
        _require(setup!=path,"suite descriptor cannot be an initial setup")
        paths.append(setup);hashes.append(item['setup_sha256'])
    _require(len(set(paths))==len(paths) and len(set(hashes))==len(hashes),
        "all15 Beta1 nodes require globally distinct Root-prepared setup paths and byte pins")
    return tuple(items)


def _verify_beta1_node_v3(outcomes,receipts,*,scenario,node,setup_sha256):
    phases=(*_BETA1_PHASES,'paid_cold_current_v4')if scenario.startswith('d13-')else _BETA1_PHASES
    _require(len(outcomes)==len(receipts)==len(phases)
        and tuple(item['phase']for item in outcomes)==phases,"complete actual Beta1 process sequence required")
    business,switched,released,cold,consumer=outcomes[:5]
    operation=business['operation_id'];continuation=business['continuation']
    checks=dict(same_scenario=all(item['scenario']==scenario for item in outcomes),
        all_distinct_processes=len({item['pid']for item in outcomes})==len(phases),
        same_c09_operation=all(item['operation_id']==operation for item in outcomes),
        distinct_migration_source=business['scenario_source_ref']!=business['migration_source_ref'],
        same_continuation=all(item['continuation_digest']==continuation['continuation_digest']
            for item in outcomes[1:]),
        same_absolute_deadline=all(item['original_deadline_utc']==continuation['original_deadline_utc']
            for item in outcomes[1:]),
        prepared=switched['prepared_digest']==released['prepared_digest']==cold['prepared_digest'],
        switched=switched['restart_required']is True,
        released=released['stage']==cold['stage']=='RELEASED',
        four_roles=switched['segmented_roles']==released['selected_roles']==cold['selected_roles']
            and set(cold['selected_roles'])=={'core','deletion','execution','graph'},
        generation=released['storage_generation']==cold['storage_generation']
            ==consumer['storage_generation'] and consumer['storage_generation']>0,
        same_selected_manifest=released['manifest_digest']==cold['manifest_digest']==consumer['manifest_digest'],
        same_source_terminal=released['source_execution_commitment']==cold['source_execution_commitment']
            ==business['source_execution_commitment'],
        old_files_retired=all(item['original_pidfd_ready']and item['recursive_populated']=='0'
            and item['actual_exit_code']==0 for item in receipts),
        fixed_consumer=consumer['node']==node and consumer['setup_sha256']==setup_sha256
            and consumer['exit_code']==0 and consumer['source_kind']=='current_selected_v3',
        current_owner=consumer['fresh_original_key_capped_login']is True)
    if scenario.startswith('d13-'):
        paid_cold=outcomes[5]
        checks.update(paid_after_consumer_independent_process=paid_cold['pid']!=consumer['pid'],
            paid_cold_same_original=paid_cold['paid_cold_original_sha256']==consumer['paid_cold_original']['sha256'],
            paid_cold_current_generation=paid_cold['storage_generation']==consumer['storage_generation'],
            paid_cold_original_checks=paid_cold['paid_cold_checks_passed']is True)
    for name,accepted in checks.items():_require(accepted,'actual Beta1 node assertion failed: '+name)
    return checks


def run_root_controlled_beta1_suite_v3(spec,*,app,run,environment,started,deadline,profile):
    """Existing Root placement/retirement/cgroup envelope around the fifteen fixed nodes."""
    from dataclasses import replace
    _require(os.geteuid()==0,"actual Root Beta1 suite observer required")
    manifest_entries=read_protected_beta1_fixture_suite_v3(spec,profile)
    entries=tuple(item for item in manifest_entries if item['node']in profile['FIXTURE_NODES'][spec.fixture_kind])
    metrics=os.open(Path(spec.evidence_directory)/'resources.private.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    totals=dict(stdout=0,stderr=0,metrics=0,metrics_fd=metrics);observed=[];current_entry=None;current_phase=None;outcomes=[];receipts=[];failure=None
    try:
        for index,entry in enumerate(entries):
            current_entry=entry;current_phase=None;outcomes=[];receipts=[]
            node=entry['node'];scenario=entry['scenario']
            fixture=Path(spec.basetemp)/str(index);fixture.mkdir(mode=0o700);os.chown(fixture,1000,1000)
            evidence=Path(spec.evidence_directory)/str(index);evidence.mkdir(mode=0o700)
            node_spec=replace(spec,basetemp=str(fixture),evidence_directory=str(evidence),
                phase_fixture_setup=entry['setup_file'],phase_fixture_setup_sha256=entry['setup_sha256'])
            guard=fixture/'import-origin-evidence';guard.mkdir(mode=0o700);os.chown(guard,1000,1000)
            guard_file=guard/'sitecustomize.py';guard_file.write_text(_PRODUCT_IMPORT_GUARD,encoding='utf8');os.chown(guard_file,1000,1000)
            control=fixture.parent/('root-phase-control-'+str(index));control.mkdir(mode=0o750);os.chown(control,0,1000);control.chmod(0o750)
            child_env=dict(environment,PYTHONPATH=os.pathsep.join((str(guard),str(Path(spec.installed_root)/'rewrite'),
                spec.installed_root,spec.sdk_root)),PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',
                PYTHONFAULTHANDLER='1',SYLANNE_D04_INSTALLED_ROOT=spec.installed_root,
                SYLANNE_C09_IMPORT_EVIDENCE=str(guard),SYLANNE_C09_GUARD_SHA256=sha256(guard_file.read_bytes()).hexdigest(),
                SYLANNE_ARTIFACT_PHASE_FIXTURE_SETUP=entry['setup_file'],
                SYLANNE_ARTIFACT_PHASE_FIXTURE_SETUP_SHA256=entry['setup_sha256'])
            child_env.pop('PYTHONHOME',None)
            script=Path(spec.frozen_rewrite_root)/node.partition('::')[0]
            outcomes=[];receipts=[]
            phases=(*_BETA1_PHASES,'paid_cold_current_v4')if scenario.startswith('d13-')else _BETA1_PHASES
            for phase_index,phase in enumerate(phases):
                current_phase=phase
                child_env.update(SYLANNE_QUAL_ROOT_CENSUS_SOCKET=str(control/(str(phase_index)+'.socket')),
                    SYLANNE_QUAL_ROOT_CENSUS_PHASE=phase)
                continuation={} if not outcomes else outcomes[0]['continuation']
                command=[sys.executable,'-B',str(script),'--beta1-current-phase',phase,scenario,
                    entry['setup_file'],entry['setup_sha256'],str(fixture),node]
                if phase_index:command.extend((continuation['path'],continuation['sha256']))
                if phase=='paid_cold_current_v4':
                    original=outcomes[4]['paid_cold_original']
                    command.extend((original['path'],original['sha256']))
                result,receipt=_phase(node_spec,phase,phase_index,command,child_env,app,run,control,
                    guard,started,deadline,totals,profile,node=node,prior_root_receipts=tuple(receipts))
                outcomes.append(result);receipts.append(receipt)
            checks=_verify_beta1_node_v3(outcomes,receipts,scenario=scenario,node=node,setup_sha256=entry['setup_sha256'])
            item=dict(node=node,scenario=scenario,setup_sha256=entry['setup_sha256'],outcomes=outcomes,processes=receipts,checks=checks,
                status='OBSERVED_CURRENT_V3_EXIT',coverage=dict(finished_retirement_replay='OBSERVED_BY_PERMANENT_CONSUMER'if scenario=='d13-derived-expiry'else'NOT_SELECTED',
                    committed_active_core_finish_ack_loss='NOT_RUN'))
            profile['_private_json'](evidence/'actualphase-outcomes.json',item);observed.append(item)
        output=Path(spec.evidence_directory)/'actualphase-outcomes.json'
        profile['_private_json'](output,dict(schema='sylanne.beta1.actualphase-outcomes.v3',
            harness_kind='root_controlled_beta1_suite',fixture_kind=spec.fixture_kind,operation_id=spec.operation_id,
            suite_sha256=spec.phase_fixture_setup_sha256,package_sha256=spec.package_sha256,
            manifest_sha256=spec.manifest_sha256,node_count=len(observed),node_outcomes=observed,
            full_manifest_node_count=15,requested_node_count=len(entries),node_manifest=_beta1_node_observation_manifest_v3(manifest_entries,spec.fixture_kind,observed,selected_nodes=profile['FIXTURE_NODES'][spec.fixture_kind]),
            observation_status='CURRENT_FAMILY_OBSERVED_OTHER_FAMILY_NOT_RUN',
            effective_exit_code=0,run_started_monotonic_ns=int(started*1_000_000_000),
            run_ended_monotonic_ns=time.monotonic_ns(),log_bytes={name:totals[name]for name in('stdout','stderr','metrics')}))
        return dict(status='FIXTURE_EXIT_OBSERVED_NOT_QUALIFICATION',actual_exit=0,
            original_pidfd_ready=True,original_pidfd_ready_after_cleanup=True,harness_kind='root_controlled_beta1_suite',
            actual_phase_outcomes_path=str(output),observed_node_count=len(observed),elapsed_seconds=time.monotonic()-started)
    except BaseException as error:
        failure=dict(node=None if current_entry is None else current_entry['node'],phase=current_phase,
            reason_code=type(error).__name__,status='HOLD',outcome_availability='INCOMPLETE_CURRENT_OBSERVATION',
            process_receipt_path=None if current_entry is None or current_phase is None else str(
                Path(spec.basetemp)/str(entries.index(current_entry))/'import-origin-evidence'/(current_phase+'.process.json')))
        output=Path(spec.evidence_directory)/'actualphase-outcomes.json'
        profile['_private_json'](output,dict(schema='sylanne.beta1.actualphase-outcomes.v3',harness_kind='root_controlled_beta1_suite',
            fixture_kind=spec.fixture_kind,operation_id=spec.operation_id,suite_sha256=spec.phase_fixture_setup_sha256,
            package_sha256=spec.package_sha256,manifest_sha256=spec.manifest_sha256,node_count=len(observed),node_outcomes=observed,
            full_manifest_node_count=15,requested_node_count=len(entries),node_manifest=_beta1_node_observation_manifest_v3(
                manifest_entries,spec.fixture_kind,observed,selected_nodes=profile['FIXTURE_NODES'][spec.fixture_kind],failure=failure,partial_outcomes=outcomes,partial_processes=receipts),
            observation_status='HOLD_INCOMPLETE_CURRENT_OBSERVATION',first_failure=failure,effective_exit_code=2,
            run_started_monotonic_ns=int(started*1_000_000_000),run_ended_monotonic_ns=time.monotonic_ns(),
            log_bytes={name:totals[name]for name in('stdout','stderr','metrics')}))
        raise
    finally:os.fsync(metrics);os.close(metrics)


def _beta1_node_observation_manifest_v3(entries,requested_family,observed,*,selected_nodes,failure=None,partial_outcomes=(),partial_processes=()):
    completed={item['node']:item for item in observed};rows=[]
    for entry in entries:
        item=completed.get(entry['node']);selected=entry['node']in selected_nodes
        failed=failure is not None and failure['node']==entry['node']
        status=('OBSERVED_CURRENT_V3_EXIT'if item is not None else'HOLD'if failed else'UNKNOWN'if selected else'NOT_RUN')
        rows.append(dict(node=entry['node'],scenario=entry['scenario'],fixture_kind=entry['fixture_kind'],
            setup_file=entry['setup_file'],setup_sha256=entry['setup_sha256'],status=status,
            observed_phase_count=len(item['outcomes'])if item is not None else len(partial_outcomes)if failed else 0,
            process_receipt_count=len(item['processes'])if item is not None else len(partial_processes)if failed else 0,
            committed_active_core_finish_ack_loss='NOT_RUN'))
    return rows

_PRODUCT_IMPORT_GUARD = "\nimport atexit\nimport hashlib\nimport importlib.abc\nimport importlib.machinery\nimport importlib.util\nimport json\nimport os\nfrom pathlib import Path\nimport sys\n\n\ndef fail(message):\n    os.write(2, ('C09 installed-product import pin failed: ' + str(message) + '\\n').encode())\n    os._exit(86)\n\n\ntry:\n    installed = Path(os.environ['SYLANNE_C09_INSTALLED_ROOT']).resolve(strict=True)\n    expected_manifest = os.environ['SYLANNE_C09_MANIFEST_SHA256']\n    fixture = Path(os.environ['SYLANNE_C09_TEST_ROOT']).resolve(strict=True)\n    expected_engineering = os.environ['SYLANNE_C09_ENGINEERING_INVENTORY_SHA256']\n    output = Path(os.environ['SYLANNE_C09_IMPORT_EVIDENCE']).resolve(strict=True)\n    guard_path = output / 'sitecustomize.py'\n    if (Path(__file__).resolve(strict=True) != guard_path\n            or hashlib.sha256(guard_path.read_bytes()).hexdigest() != os.environ['SYLANNE_C09_GUARD_SHA256']):\n        fail('startup guard path or hash differs')\n    raw_manifest = (installed / 'release-manifest.json').read_bytes()\n    if hashlib.sha256(raw_manifest).hexdigest() != expected_manifest:\n        fail('release manifest digest differs')\n    file_pins = {row['path']: row for row in json.loads(raw_manifest)['files']}\n    engineering_path = fixture.parent / 'frozen-engineering-inventory.json'\n    engineering = json.loads(engineering_path.read_text())\n    actual_engineering = hashlib.sha256(json.dumps(engineering['files'], sort_keys=True,\n        separators=(',', ':')).encode()).hexdigest()\n    if (engineering['schema'] != 'sylanne.engineering-source-inventory.v1'\n            or engineering['sha256'] != actual_engineering or actual_engineering != expected_engineering):\n        fail('explicit frozen engineering inventory differs')\n    test_pins = {row['path']: row for row in engineering['files']\n        if row['path'].startswith(('rewrite/tests/', 'rewrite/host_tests/'))}\n    test_roots = (fixture / 'rewrite/tests', fixture / 'rewrite/host_tests')\n    checked = {}\n\n    def closed_test(name):\n        return any(name == 'rewrite.' + leaf or name.startswith('rewrite.' + leaf + '.')\n            for leaf in ('tests', 'host_tests'))\n\n    def product(name):\n        return (name == 'sylanne3' or name.startswith('sylanne3.') or name == 'rewrite'\n            or name.startswith('rewrite.') and not closed_test(name))\n\n    def verify_test_origin(name, origin):\n        path = Path(origin).resolve(strict=True)\n        if not any(path.is_relative_to(root) for root in test_roots):\n            fail('engineering test namespace escaped closed roots: ' + name)\n        relative = path.relative_to(fixture).as_posix()\n        pin = test_pins.get(relative)\n        data = path.read_bytes()\n        sha = hashlib.sha256(data).hexdigest()\n        if pin is None or pin['sha256'] != sha or pin['bytes'] != len(data):\n            fail('engineering test differs from frozen inventory: ' + relative)\n        return dict(path=str(path), sha256=sha)\n\n    # Validate both complete engineering test families before any fixture use.\n    for relative in test_pins:\n        verify_test_origin(relative, fixture / relative)\n\n    def verify_origin(name, origin, locations):\n        base = installed / ('rewrite' if name.startswith('sylanne3') else '')\n        stem = base.joinpath(*name.split('.'))\n        if origin is None:\n            if tuple(Path(p).resolve(strict=True) for p in locations or ()) != (stem,):\n                fail('namespace origin differs: ' + name)\n            return dict(path=None, namespace_path=str(stem))\n        path = Path(origin).resolve(strict=True)\n        if path not in (stem.with_suffix('.py'), stem / '__init__.py'):\n            fail('module __file__ or product alias differs: ' + name + ' -> ' + str(path))\n        relative = path.relative_to(installed).as_posix()\n        pin = file_pins.get(relative)\n        data = path.read_bytes()\n        sha = hashlib.sha256(data).hexdigest()\n        if pin is None or pin['sha256'] != sha or pin['bytes'] != len(data):\n            fail('module differs from pinned extracted manifest: ' + relative)\n        value = dict(path=str(path), sha256=sha)\n        checked[name] = value\n        return value\n\n    def verify_module(name, origin, locations):\n        if product(name):\n            return 'product', verify_origin(name, origin, locations)\n        if origin is None:\n            if closed_test(name):\n                expected = fixture.joinpath(*name.split('.'))\n                prefix = expected.relative_to(fixture).as_posix() + '/'\n                if (not any(relative.startswith(prefix) for relative in test_pins)\n                        or tuple(Path(p).resolve(strict=True) for p in locations or ()) != (expected,)):\n                    fail('closed test namespace path differs: ' + name)\n            return None, None\n        path = Path(origin).resolve(strict=True)\n        if 'sylanne3' in path.parts:\n            fail('product file imported under an unrecognized alias: ' + name)\n        if path.is_relative_to(fixture):\n            return 'test', verify_test_origin(name, path)\n        if closed_test(name):\n            fail('closed test module came from outside frozen fixture: ' + name)\n        return None, None\n\n    class PinnedProductFinder(importlib.abc.MetaPathFinder):\n        def find_spec(self, fullname, path=None, target=None):\n            spec = importlib.machinery.PathFinder.find_spec(fullname, path)\n            if spec is None:\n                if product(fullname) or closed_test(fullname):\n                    fail('installed product or frozen test module absent: ' + fullname)\n                return None\n            if spec.origin not in ('built-in', 'frozen'):\n                verify_module(fullname, spec.origin, spec.submodule_search_locations)\n            return spec if product(fullname) or closed_test(fullname) else None\n\n    sys.meta_path.insert(0, PinnedProductFinder())\n    import rewrite\n    import sylanne3\n    # ZIPs omit engineering tests. Bridge only these two pinned families,\n    # without appending source/rewrite to any product package search path.\n    for leaf in ('tests', 'host_tests'):\n        name = 'rewrite.' + leaf\n        spec = importlib.machinery.ModuleSpec(name, loader=None, is_package=True)\n        spec.submodule_search_locations = [str(fixture / 'rewrite' / leaf)]\n        module = importlib.util.module_from_spec(spec)\n        sys.modules[name] = module\n        setattr(rewrite, leaf, module)\n    sys.path.append(str(fixture / 'rewrite' / 'tests' / 'alpha1' / 'integration'))\n\n    def audit(phase='atexit'):\n        try:\n            if (type(phase) is not str or not phase or len(phase) > 64\n                    or any(not (char.isascii() and (char.isalnum() or char in '-_')) for char in phase)):\n                fail('closed import observation phase required')\n            from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1\n            identity = read_process_identity_v1(os.getpid())\n            if identity is None:\n                fail('actual current process birth identity unavailable')\n            modules, fixtures, namespaces = {}, {}, {}\n            for name, module in tuple(sys.modules.items()):\n                origin = getattr(module, '__file__', None)\n                if origin in ('built-in', 'frozen'):\n                    continue\n                kind, value = verify_module(name, origin, getattr(module, '__path__', None))\n                if kind == 'product':\n                    modules[name] = value\n                elif kind == 'test':\n                    fixtures[value['path']] = value['sha256']\n                elif closed_test(name) and origin is None:\n                    namespaces[name] = list(module.__path__)\n            main = getattr(sys.modules.get('__main__'), '__file__', None)\n            entrypoint = None\n            if main:\n                path = Path(main).resolve(strict=True)\n                if path.is_relative_to(fixture):\n                    verify_test_origin('__main__', path)\n                entrypoint = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())\n            value = dict(process_id=os.getpid(), process_identity=identity, observation_phase=phase,\n                installed_root=str(installed), manifest_sha256=expected_manifest,\n                engineering_inventory_sha256=expected_engineering, guard_sha256=os.environ['SYLANNE_C09_GUARD_SHA256'],\n                product_modules=modules, test_sources=fixtures, test_namespaces=namespaces, entrypoint=entrypoint)\n            encoded = json.dumps(value, sort_keys=True) + '\\n'\n            (output / ('pin-' + str(os.getpid()) + '.json')).write_text(encoded)\n            (output / ('pin-' + str(os.getpid()) + '-' + phase + '.json')).write_text(encoded)\n            return value\n        except BaseException as exc:\n            fail(exc)\n    atexit.register(audit)\nexcept BaseException as exc:\n    fail(exc)\n"


V10_COMPOSITE_SCHEMA='sylanne.beta1.protected-numeric-d13-v10-v7-256-suite.v1'
V10_COMPOSITE_ORDER=('numeric','d13_full','sdk_v10_d13_v7_256')


def _read_protected_composite_input_v1(path,pin):
    path=Path(path);raw=path.read_bytes()
    _require(path.resolve(strict=True)==path and sha256(raw).hexdigest()==pin,'exact externally pinned composite input required')
    for item in (path,*path.parents):
        info=item.lstat()
        _require(not item.is_symlink() and info.st_uid==0 and not info.st_mode&0o022,'composite input ancestry must remain Root protected')
    return json.loads(raw)


def _v10_composite_snapshot_pins_v1(spec):
    import zipfile
    package=Path(spec.package_path)
    _require(sha256(package.read_bytes()).hexdigest()==spec.package_sha256,'composite package changed')
    with zipfile.ZipFile(package)as archive:
        _require(archive.testzip()is None,'composite archive CRC differs')
        raw=archive.read('release-manifest.json')
        _require(sha256(raw).hexdigest()==spec.manifest_sha256,'composite manifest differs')
        manifest=json.loads(raw);native=manifest['native'];inventory=manifest['source_inventory']
        expected=sorted((row for row in manifest['files']if row['path']!=native['path']),key=lambda row:row['path'])
        _require(inventory['schema']=='sylanne.packaged-source-inventory.v1'and inventory['files']==expected
            and inventory['sha256']==sha256(_canonical(expected)).hexdigest(),'official packaged source inventory differs')
        _require(native in manifest['files'],'actual native member is absent from release files')
        for row in manifest['files']:
            data=archive.read(row['path'])
            _require(len(data)==row['bytes']and sha256(data).hexdigest()==row['sha256'],'actual archived member differs')
    return dict(package_sha256=spec.package_sha256,manifest_sha256=spec.manifest_sha256,
        native_sha256=native['sha256'],source_inventory_sha256=inventory['sha256'],
        engineering_inventory_sha256=spec.engineering_inventory_sha256)


def read_protected_beta1_v10_composite_v1(path,pin,profile):
    value=_read_protected_composite_input_v1(path,pin)
    fields={'schema','suite_id','pins','fixed_order','children','coverage','workflow_profiles','evidence_directory'}
    _require(type(value)is dict and set(value)==fields and value['schema']==V10_COMPOSITE_SCHEMA
        and value['fixed_order']==list(V10_COMPOSITE_ORDER)
        and value['coverage']=={'numeric':10,'d13_full':5,'sdk_v10_d13_v7_256':1,'screen_deep':'NOT_RUN'},'closed V10 composite contract required')
    from uuid import UUID
    _require(str(UUID(value['suite_id']))==value['suite_id']and UUID(value['suite_id']).version==4,'fresh composite UUID4 required')
    children=value['children'];_require(type(children)is list and len(children)==3,'three independently owned child runs required')
    specs=[]
    for child,kind in zip(children,V10_COMPOSITE_ORDER,strict=True):
        _require(type(child)is dict and set(child)=={'id','runner','spec_schema','spec','spec_sha256','timeout_seconds'}
            and child['id']==kind and child['runner']=='run_owned_resource_profile_v1'
            and child['spec_schema']=='sylanne.owned-resource-run.v1'
            and child['spec_sha256']==sha256(_canonical(child['spec'])).hexdigest()
            and type(child['timeout_seconds'])is int and 1<=child['timeout_seconds']<=1000,'exact child specification and original finite timeout required')
        spec=profile['OwnedResourceRunV1'](**child['spec'])
        _require(spec.fixture_kind==kind and spec.suite_contract==V10_COMPOSITE_SCHEMA,'exact child fixture selection required')
        profile['_pin_inputs_in_child'](spec)
        specs.append(spec)
    first=specs[0]
    _require(all((s.package_path,s.package_sha256,s.manifest_sha256,s.frozen_rewrite_root,s.engineering_inventory_sha256,
        s.dependency_manifest,s.dependency_sha256,s.sdk_root)==(first.package_path,first.package_sha256,first.manifest_sha256,
        first.frozen_rewrite_root,first.engineering_inventory_sha256,first.dependency_manifest,first.dependency_sha256,first.sdk_root)for s in specs),
        'composite children must use the same fresh snapshot and SDK dependency')
    _require(value['pins']==_v10_composite_snapshot_pins_v1(first),'actual composite snapshot pins differ')
    _require(specs[0].phase_fixture_setup==specs[1].phase_fixture_setup
        and specs[0].phase_fixture_setup_sha256==specs[1].phase_fixture_setup_sha256,'numeric and D13 must select disjoint nodes from the same fresh full15 descriptor')
    full=read_protected_beta1_fixture_suite_v3(first,profile)
    _require(len({s.operation_id for s in specs})==3 and len({s.basetemp for s in specs})==3
        and len({s.evidence_directory for s in specs})==3,'child resource identities and evidence must be independent')
    paths=[Path(s.basetemp)for s in specs]+[Path(s.evidence_directory)for s in specs]+[Path(value['evidence_directory'])]
    _require(all(p.is_absolute()and p.resolve()==p and not p.exists()for p in paths)
        and all(a!=b and not a.is_relative_to(b)and not b.is_relative_to(a)for i,a in enumerate(paths)for b in paths[i+1:]),'fresh disjoint composite/child evidence and basetemp paths required')
    _require(Path(value['evidence_directory']).is_relative_to(Path(first.fixture_root)),'composite evidence escapes the approved fixture root')
    profiles=value['workflow_profiles'];_require(type(profiles)is list and len(profiles)==15,'all fifteen fresh V10 profile identities required')
    for row,entry in zip(profiles,full,strict=True):
        _require(set(row)=={'node','path','sha256','workflow_sha256','type','version'}and row['node']==entry['node']
            and(row['type'],row['version'])==('AdminModelWorkflowsV10',10),'exact fresh typed V10 profile evidence required')
        setup=_read_protected_composite_input_v1(entry['setup_file'],entry['setup_sha256'])
        expected_path=Path(setup['profile_root'])/setup['profile_id']/'profile.json'
        _require(Path(row['path'])==expected_path,'V10 profile locator differs from the actual protected setup')
        payload=_read_protected_composite_input_v1(row['path'],row['sha256']);workflows=payload['model_workflows']
        _require(workflows['version']==10 and row['workflow_sha256']==sha256(_canonical(workflows)).hexdigest()
            and {'ordinary_continuity_screen','ordinary_continuity_deep'}<=set(workflows),'fresh V10 workflow commitment differs')
    return value,tuple(specs)


def run_root_controlled_beta1_numeric_d13_v10_v7_256_suite_v1(*,descriptor_path,descriptor_sha256,profile,cgroup_parent='/sys/fs/cgroup'):
    """Serial 10+5+1 software observations; this descriptor grants no extra attempts."""
    _require(os.geteuid()==0,'fresh isolated Linux Root observer required')
    value,specs=read_protected_beta1_v10_composite_v1(descriptor_path,descriptor_sha256,profile)
    evidence=Path(value['evidence_directory']);evidence.mkdir(mode=0o700)
    result=dict(schema='sylanne.beta1.numeric-d13-v10-v7-256-result.v1',suite_id=value['suite_id'],
        descriptor_sha256=descriptor_sha256,pins=value['pins'],status='NOT_RUN',first_failure=None,
        screen_deep_execution='NOT_RUN',children=[{'id':kind,'status':'NOT_RUN','node_count':0}for kind in V10_COMPOSITE_ORDER])
    for index,(child,spec)in enumerate(zip(value['children'],specs,strict=True)):
        item=result['children'][index]
        try:
            observed=profile['run_owned_resource_profile_v1'](spec,cgroup_parent=cgroup_parent,timeout_seconds=child['timeout_seconds'])
            item.update(resource_result=observed,resource_receipt=str(Path(spec.evidence_directory)/'resource-run-original.json'))
            _require(observed['status']=='FIXTURE_EXIT_OBSERVED_NOT_QUALIFICATION'and observed.get('actual_exit')==0
                and observed.get('original_pidfd_ready_after_cleanup')is True
                and observed.get('recursive_populated_after_cleanup')=='0'and observed.get('owned_groups_removed')is True
                and observed.get('cleanup_complete',True)is True and not observed.get('kernel_oom_observed',False),
                'child execution or owned-resource retirement did not complete')
            if index<2:
                outcome=Path(observed['actual_phase_outcomes_path']);body=json.loads(outcome.read_bytes());count=(10,5)[index]
                _require(body['effective_exit_code']==0 and body['node_count']==count
                    and body['requested_node_count']==count and all(n['status']=='OBSERVED_CURRENT_V3_EXIT'for n in body['node_outcomes']),
                    'complete current family evidence required')
                item.update(node_count=count,outcome_file=str(outcome),outcome_sha256=sha256(outcome.read_bytes()).hexdigest())
            else:
                receipts=list(Path(spec.basetemp).rglob('m1-receipt.json'))
                _require(len(receipts)==1,'one actual V10/V7-256 lifecycle receipt required')
                raw=receipts[0].read_bytes();body=json.loads(raw);actual=body['v10_workflow_evidence']
                _require(body['status']=='PASS'and body['scenario']=='sdk_v10_d13_v7_256_current_v1'
                    and(body['snapshot_sha256'],body['manifest_sha256'])==(spec.package_sha256,spec.manifest_sha256)
                    and len(body['episodes'])==256 and body['simulated_sender_calls']==256
                    and body['external_provider_requests']==0 and 1<=body['simulated_provider_calls']<=1536
                    and(actual['workflow_type'],actual['workflow_version'],actual['wire_type'])==('AdminModelWorkflowsV10',10,'InstalledD13WirePolicyV7')
                    and actual['screen_deep_execution']=='NOT_RUN','complete fresh V10/V7-256 evidence required')
                item.update(node_count=1,outcome_file=str(receipts[0]),outcome_sha256=sha256(raw).hexdigest(),workflow_evidence=actual)
            item['status']='OBSERVED_COMPLETE'
        except BaseException as error:
            item['status']='HOLD';result['status']='HOLD'
            result['first_failure']=dict(child=child['id'],type=type(error).__name__,reason=str(error),
                resource_failure=item.get('resource_result',{}).get('first_failure'))
            break
    else:
        result.update(status='PASS',observed_node_count=16,coverage={'numeric':10,'d13_full':5,'sdk_v10_d13_v7_256':1})
    result['qualification_scope']='fresh fixed software suite only; screen/deep functionality and project/server acceptance NOT_RUN'
    profile['_private_json'](evidence/'composite-result.json',result)
    return result
