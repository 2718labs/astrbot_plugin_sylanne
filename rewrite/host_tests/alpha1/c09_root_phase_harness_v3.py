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
    def __init__(self,spec,phase,index,app,run,pid,birth,deadline,control,profile,*,node=NODE):
        self.spec,self.phase,self.index,self.app,self.run,self.pid,self.birth=spec,phase,index,app,run,pid,birth
        self.deadline,self.profile=deadline,profile
        _require(node in profile["FIXTURE_NODES"][spec.fixture_kind],"phase node is outside its fixed permanent family")
        self.node=node
        self.path=control/(str(index)+'.socket');self.nonce=str(uuid4());self.token=None;self.held=None
        self.root=_process(os.getpid(),profile);self.peer=None
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.listener.bind(str(self.path));os.chown(self.path,0,1000);os.chmod(self.path,0o660)
        self.listener.listen(1);self.listener.setblocking(False)
        self.originals=[]
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
        raw=self.peer.recv(65537)
        _require(raw and len(raw)<=65536,'Root phase channel ended before release')
        request=json.loads(raw)
        _require(request.get('schema')=='sylanne.root-controlled-sdk-census-request.v3','Root census request schema differs')
        if request.get('command')=='release':
            _require(self.held is not None and request==dict(schema=request['schema'],command='release',
                held_request_digest=self.held['request_digest']),'Root release is outside its original held channel')
            result=dict(self.held,command='released')
            self.peer.sendall(_canonical(result));self.originals.append(result);self.held=None
            self.peer.close();self.peer=None;return
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
    def close(self):
        if self.peer is not None:self.peer.close()
        self.listener.close()
        self.path.unlink()


def _phase(spec,phase,index,command,environment,app,run,control,guard,started,deadline,totals,profile,*,node=NODE):
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
        channel=_RootCensusChannelV3(spec,phase,index,app,run,pid,birth,deadline,control,profile,node=node)
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
            elapsed_ns=time.monotonic_ns()-phase_started,original_pidfd_ready=ready,cleanup_errors=cleanup_errors,
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
            result,receipt=_phase(spec,phase,index,[sys.executable,'-B',str(script),phase,*arguments],environment,app,run,control,guard,started,deadline,totals,profile)
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
    _require(spec.fixture_kind in {"numeric","d13_full"},"closed full Beta1 fixture family required")
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
    _require(len(outcomes)==len(receipts)==5
        and tuple(item['phase']for item in outcomes)==_BETA1_PHASES,"complete actual Beta1 process sequence required")
    business,switched,released,cold,consumer=outcomes
    operation=business['operation_id'];continuation=business['continuation']
    checks=dict(same_scenario=all(item['scenario']==scenario for item in outcomes),
        five_distinct_processes=len({item['pid']for item in outcomes})==5,
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
    for name,accepted in checks.items():_require(accepted,'actual Beta1 node assertion failed: '+name)
    return checks


def run_root_controlled_beta1_suite_v3(spec,*,app,run,environment,started,deadline,profile):
    """Existing Root placement/retirement/cgroup envelope around the fifteen fixed nodes."""
    from dataclasses import replace
    _require(os.geteuid()==0,"actual Root Beta1 suite observer required")
    manifest_entries=read_protected_beta1_fixture_suite_v3(spec,profile)
    entries=tuple(item for item in manifest_entries if item['fixture_kind']==spec.fixture_kind)
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
                SYLANNE_ARTIFACT_PHASE_FIXTURE_SETUP=entry['setup_file'])
            child_env.pop('PYTHONHOME',None)
            script=Path(spec.frozen_rewrite_root)/node.partition('::')[0]
            outcomes=[];receipts=[]
            for phase_index,phase in enumerate(_BETA1_PHASES):
                current_phase=phase
                child_env.update(SYLANNE_QUAL_ROOT_CENSUS_SOCKET=str(control/(str(phase_index)+'.socket')),
                    SYLANNE_QUAL_ROOT_CENSUS_PHASE=phase)
                continuation={} if not outcomes else outcomes[0]['continuation']
                command=[sys.executable,'-B',str(script),'--beta1-current-phase',phase,scenario,
                    entry['setup_file'],entry['setup_sha256'],str(fixture),node]
                if phase_index:command.extend((continuation['path'],continuation['sha256']))
                result,receipt=_phase(node_spec,phase,phase_index,command,child_env,app,run,control,
                    guard,started,deadline,totals,profile,node=node)
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
            full_manifest_node_count=15,requested_node_count=len(entries),node_manifest=_beta1_node_observation_manifest_v3(manifest_entries,spec.fixture_kind,observed),
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
                manifest_entries,spec.fixture_kind,observed,failure=failure,partial_outcomes=outcomes,partial_processes=receipts),
            observation_status='HOLD_INCOMPLETE_CURRENT_OBSERVATION',first_failure=failure,effective_exit_code=2,
            run_started_monotonic_ns=int(started*1_000_000_000),run_ended_monotonic_ns=time.monotonic_ns(),
            log_bytes={name:totals[name]for name in('stdout','stderr','metrics')}))
        raise
    finally:os.fsync(metrics);os.close(metrics)


def _beta1_node_observation_manifest_v3(entries,requested_family,observed,*,failure=None,partial_outcomes=(),partial_processes=()):
    completed={item['node']:item for item in observed};rows=[]
    for entry in entries:
        item=completed.get(entry['node']);selected=entry['fixture_kind']==requested_family
        failed=failure is not None and failure['node']==entry['node']
        status=('OBSERVED_CURRENT_V3_EXIT'if item is not None else'HOLD'if failed else'UNKNOWN'if selected else'NOT_RUN')
        rows.append(dict(node=entry['node'],scenario=entry['scenario'],fixture_kind=entry['fixture_kind'],
            setup_file=entry['setup_file'],setup_sha256=entry['setup_sha256'],status=status,
            observed_phase_count=len(item['outcomes'])if item is not None else len(partial_outcomes)if failed else 0,
            process_receipt_count=len(item['processes'])if item is not None else len(partial_processes)if failed else 0,
            committed_active_core_finish_ack_loss='NOT_RUN'))
    return rows

_PRODUCT_IMPORT_GUARD = "\nimport atexit\nimport hashlib\nimport importlib.abc\nimport importlib.machinery\nimport importlib.util\nimport json\nimport os\nfrom pathlib import Path\nimport sys\n\n\ndef fail(message):\n    os.write(2, ('C09 installed-product import pin failed: ' + str(message) + '\\n').encode())\n    os._exit(86)\n\n\ntry:\n    installed = Path(os.environ['SYLANNE_C09_INSTALLED_ROOT']).resolve(strict=True)\n    expected_manifest = os.environ['SYLANNE_C09_MANIFEST_SHA256']\n    fixture = Path(os.environ['SYLANNE_C09_TEST_ROOT']).resolve(strict=True)\n    expected_engineering = os.environ['SYLANNE_C09_ENGINEERING_INVENTORY_SHA256']\n    output = Path(os.environ['SYLANNE_C09_IMPORT_EVIDENCE']).resolve(strict=True)\n    guard_path = output / 'sitecustomize.py'\n    if (Path(__file__).resolve(strict=True) != guard_path\n            or hashlib.sha256(guard_path.read_bytes()).hexdigest() != os.environ['SYLANNE_C09_GUARD_SHA256']):\n        fail('startup guard path or hash differs')\n    raw_manifest = (installed / 'release-manifest.json').read_bytes()\n    if hashlib.sha256(raw_manifest).hexdigest() != expected_manifest:\n        fail('release manifest digest differs')\n    file_pins = {row['path']: row for row in json.loads(raw_manifest)['files']}\n    engineering_path = fixture.parent / 'frozen-engineering-inventory.json'\n    engineering = json.loads(engineering_path.read_text())\n    actual_engineering = hashlib.sha256(json.dumps(engineering['files'], sort_keys=True,\n        separators=(',', ':')).encode()).hexdigest()\n    if (engineering['schema'] != 'sylanne.engineering-source-inventory.v1'\n            or engineering['sha256'] != actual_engineering or actual_engineering != expected_engineering):\n        fail('explicit frozen engineering inventory differs')\n    test_pins = {row['path']: row for row in engineering['files']\n        if row['path'].startswith(('rewrite/tests/', 'rewrite/host_tests/'))}\n    test_roots = (fixture / 'rewrite/tests', fixture / 'rewrite/host_tests')\n    checked = {}\n\n    def closed_test(name):\n        return any(name == 'rewrite.' + leaf or name.startswith('rewrite.' + leaf + '.')\n            for leaf in ('tests', 'host_tests'))\n\n    def product(name):\n        return (name == 'sylanne3' or name.startswith('sylanne3.') or name == 'rewrite'\n            or name.startswith('rewrite.') and not closed_test(name))\n\n    def verify_test_origin(name, origin):\n        path = Path(origin).resolve(strict=True)\n        if not any(path.is_relative_to(root) for root in test_roots):\n            fail('engineering test namespace escaped closed roots: ' + name)\n        relative = path.relative_to(fixture).as_posix()\n        pin = test_pins.get(relative)\n        data = path.read_bytes()\n        sha = hashlib.sha256(data).hexdigest()\n        if pin is None or pin['sha256'] != sha or pin['bytes'] != len(data):\n            fail('engineering test differs from frozen inventory: ' + relative)\n        return dict(path=str(path), sha256=sha)\n\n    # Validate both complete engineering test families before any fixture use.\n    for relative in test_pins:\n        verify_test_origin(relative, fixture / relative)\n\n    def verify_origin(name, origin, locations):\n        base = installed / ('rewrite' if name.startswith('sylanne3') else '')\n        stem = base.joinpath(*name.split('.'))\n        if origin is None:\n            if tuple(Path(p).resolve(strict=True) for p in locations or ()) != (stem,):\n                fail('namespace origin differs: ' + name)\n            return dict(path=None, namespace_path=str(stem))\n        path = Path(origin).resolve(strict=True)\n        if path not in (stem.with_suffix('.py'), stem / '__init__.py'):\n            fail('module __file__ or product alias differs: ' + name + ' -> ' + str(path))\n        relative = path.relative_to(installed).as_posix()\n        pin = file_pins.get(relative)\n        data = path.read_bytes()\n        sha = hashlib.sha256(data).hexdigest()\n        if pin is None or pin['sha256'] != sha or pin['bytes'] != len(data):\n            fail('module differs from pinned extracted manifest: ' + relative)\n        value = dict(path=str(path), sha256=sha)\n        checked[name] = value\n        return value\n\n    def verify_module(name, origin, locations):\n        if product(name):\n            return 'product', verify_origin(name, origin, locations)\n        if origin is None:\n            if closed_test(name):\n                expected = fixture.joinpath(*name.split('.'))\n                prefix = expected.relative_to(fixture).as_posix() + '/'\n                if (not any(relative.startswith(prefix) for relative in test_pins)\n                        or tuple(Path(p).resolve(strict=True) for p in locations or ()) != (expected,)):\n                    fail('closed test namespace path differs: ' + name)\n            return None, None\n        path = Path(origin).resolve(strict=True)\n        if 'sylanne3' in path.parts:\n            fail('product file imported under an unrecognized alias: ' + name)\n        if path.is_relative_to(fixture):\n            return 'test', verify_test_origin(name, path)\n        if closed_test(name):\n            fail('closed test module came from outside frozen fixture: ' + name)\n        return None, None\n\n    class PinnedProductFinder(importlib.abc.MetaPathFinder):\n        def find_spec(self, fullname, path=None, target=None):\n            spec = importlib.machinery.PathFinder.find_spec(fullname, path)\n            if spec is None:\n                if product(fullname) or closed_test(fullname):\n                    fail('installed product or frozen test module absent: ' + fullname)\n                return None\n            if spec.origin not in ('built-in', 'frozen'):\n                verify_module(fullname, spec.origin, spec.submodule_search_locations)\n            return spec if product(fullname) or closed_test(fullname) else None\n\n    sys.meta_path.insert(0, PinnedProductFinder())\n    import rewrite\n    import sylanne3\n    # ZIPs omit engineering tests. Bridge only these two pinned families,\n    # without appending source/rewrite to any product package search path.\n    for leaf in ('tests', 'host_tests'):\n        name = 'rewrite.' + leaf\n        spec = importlib.machinery.ModuleSpec(name, loader=None, is_package=True)\n        spec.submodule_search_locations = [str(fixture / 'rewrite' / leaf)]\n        module = importlib.util.module_from_spec(spec)\n        sys.modules[name] = module\n        setattr(rewrite, leaf, module)\n    sys.path.append(str(fixture / 'rewrite' / 'tests' / 'alpha1' / 'integration'))\n\n    def audit(phase='atexit'):\n        try:\n            if (type(phase) is not str or not phase or len(phase) > 64\n                    or any(not (char.isascii() and (char.isalnum() or char in '-_')) for char in phase)):\n                fail('closed import observation phase required')\n            from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1\n            identity = read_process_identity_v1(os.getpid())\n            if identity is None:\n                fail('actual current process birth identity unavailable')\n            modules, fixtures, namespaces = {}, {}, {}\n            for name, module in tuple(sys.modules.items()):\n                origin = getattr(module, '__file__', None)\n                if origin in ('built-in', 'frozen'):\n                    continue\n                kind, value = verify_module(name, origin, getattr(module, '__path__', None))\n                if kind == 'product':\n                    modules[name] = value\n                elif kind == 'test':\n                    fixtures[value['path']] = value['sha256']\n                elif closed_test(name) and origin is None:\n                    namespaces[name] = list(module.__path__)\n            main = getattr(sys.modules.get('__main__'), '__file__', None)\n            entrypoint = None\n            if main:\n                path = Path(main).resolve(strict=True)\n                if path.is_relative_to(fixture):\n                    verify_test_origin('__main__', path)\n                entrypoint = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())\n            value = dict(process_id=os.getpid(), process_identity=identity, observation_phase=phase,\n                installed_root=str(installed), manifest_sha256=expected_manifest,\n                engineering_inventory_sha256=expected_engineering, guard_sha256=os.environ['SYLANNE_C09_GUARD_SHA256'],\n                product_modules=modules, test_sources=fixtures, test_namespaces=namespaces, entrypoint=entrypoint)\n            encoded = json.dumps(value, sort_keys=True) + '\\n'\n            (output / ('pin-' + str(os.getpid()) + '.json')).write_text(encoded)\n            (output / ('pin-' + str(os.getpid()) + '-' + phase + '.json')).write_text(encoded)\n            return value\n        except BaseException as exc:\n            fail(exc)\n    atexit.register(audit)\nexcept BaseException as exc:\n    fail(exc)\n"
