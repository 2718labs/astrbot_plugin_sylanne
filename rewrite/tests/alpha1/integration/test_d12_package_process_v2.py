"""Actual C11 whole-process protocol with an explicit isolated OS boundary.

Requires two genuine freshly built registered packages. Systemd/root filesystem
locations are replaced by real subprocess groups and private test paths; Owner,
Core, independent journals, mTLS, copied SQLite data, candidate verification,
selection CAS, process/native readiness and all signed receipts are production.
"""
import asyncio
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
from uuid import uuid4
import pytest

import d12_package_process_acceptance_support_v2 as actual


def await_file(path,process,timeout=120):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if path.is_file():return actual.read(path)
        if process.poll() is not None:raise AssertionError('actual process exited; see '+str(path.parent/'source.log'))
        time.sleep(.1)
    raise AssertionError('actual process did not produce '+str(path))


@pytest.mark.parametrize('recovery',('forward','rollback','abort'))
def test_actual_package_switch_process_chain(tmp_path,recovery):
    source=os.environ.get('SYLANNE_D04_INSTALLED_ROOT')
    candidate=os.environ.get('SYLANNE_C11_INCOMPATIBLE_ROOT' if recovery=='abort' else 'SYLANNE_C11_CANDIDATE_ROOT')
    if not source or not candidate:pytest.skip('two actual qualified package roots required')
    source,candidate=Path(source).resolve(),Path(candidate).resolve()
    root=tmp_path;actual.save(root/'settings.json',{'source_root':str(source),'candidate_root':str(candidate),'fail_candidate_authority':recovery=='rollback'})
    actual.save(root/'processes.json',{role:{'pid':0,'identity':None,'invocation_id':''} for role in ('host','authority')})
    helper=Path(actual.__file__).resolve();environment=dict(os.environ,PYTHONPATH=str(source/'rewrite')+os.pathsep+str(source)+os.pathsep+str(actual.REPO/'rewrite')+os.pathsep+str(actual.REPO))
    children=[]
    with (root/'source.log').open('w') as output:
        process=subprocess.Popen([sys.executable,str(helper),'source',str(root)],env=environment,stdout=output,stderr=output,start_new_session=True)
    children.append(process);actual.record_process(root,'authority',process.pid)
    # Initial Host need only be genuinely running; it performs no content work.
    host=subprocess.Popen([sys.executable,'-c','import time; time.sleep(1200)'],start_new_session=True)
    children.append(host);actual.record_process(root,'host',host.pid)
    try:
        await_file(root/'source-ready.json',process)
        actual.install_os_boundary(root);actual.install_profile_boundary(root)
        setup=actual.read(root/'setup.json');selection=actual.read(root/'control'/'selection.json');operation=str(uuid4())
        command=dict(namespace=setup['authority_namespace'],action='accept',operation_id=operation,
            owner_actor_id=setup['owner_actor'],owner_session_token=setup['owner_token'],owner_session_request=setup['owner_request'],
            candidate_cohort_ref='cohort:candidate',expected_selection_digest=selection['selection_digest'],expected_lifecycle_epoch=0)
        accepted=asyncio.run(actual.paired_command(root,command))
        assert accepted['lifecycle_state']=='quiescing' and accepted['executor_state']=='awaiting_privileged_executor'
        # Same signed operation replays acceptance, never closes a second epoch.
        assert asyncio.run(actual.paired_command(root,command))['intent']==accepted['intent']
        with (root/'executor.log').open('w') as output:
            executor=subprocess.Popen([sys.executable,str(helper),'executor',str(root),operation],env=environment,stdout=output,stderr=output,start_new_session=True)
        children.append(executor)
        result=await_file(root/'executor-result.json',executor,timeout=300)
        expected={'forward':'active','rollback':'rollback_complete','abort':'abort_complete'}[recovery]
        assert result['stage']==expected;executor.wait(timeout=10);assert executor.returncode==0
        selected=actual.read(root/'control'/'selection.json')
        assert selected['package_epoch']=={'forward':1,'rollback':2,'abort':0}[recovery]
        assert selected['revision']==selected['package_epoch']
        with sqlite3.connect(setup['members']['core']) as db:
            state=db.execute('SELECT state,epoch,operation_id FROM authority_d12_lifecycle_heads_v1 WHERE namespace=?',(setup['authority_namespace'],)).fetchone()
            assert state==('active',1,operation)
            assert db.execute('SELECT COUNT(*) FROM authority_d12_package_activations_v2 WHERE namespace=? AND operation_id=?',(setup['authority_namespace'],operation)).fetchone()==(1,)
            import json
            activation=json.loads(db.execute('SELECT original_json FROM authority_d12_package_activations_v2 WHERE namespace=? AND operation_id=?',(setup['authority_namespace'],operation)).fetchone()[0])
        assert asyncio.run(actual.paired_command(root,dict(namespace=setup['authority_namespace'],action='finish_activation',operation_id=operation)))['activation_original']==activation
        assert process.poll() is not None and host.poll() is not None
        # Fresh one-shot executor reopens the actual signed journal and returns
        # the same final receipt without another pointer switch or process start.
        before=actual.read(root/'processes.json')
        with (root/'executor-replay.log').open('w') as output:
            replay=subprocess.run([sys.executable,str(helper),'executor',str(root),operation],env=environment,stdout=output,stderr=output,timeout=60)
        assert replay.returncode==0 and actual.read(root/'executor-result.json')==result
        assert actual.read(root/'processes.json')==before
    finally:
        for entry in actual.read(root/'processes.json').values():
            if entry['pid']:
                try:os.killpg(entry['pid'],signal.SIGTERM)
                except ProcessLookupError:pass
        for child in children:
            if child.poll() is None:
                try:os.killpg(child.pid,signal.SIGTERM)
                except ProcessLookupError:pass
            child.wait(timeout=10)
