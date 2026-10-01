"""Real repeated C09, exact deletion ancestry and immutable source Owner."""
import json
import os
from pathlib import Path
import subprocess
import sys


def test_two_actual_c09_releases_preserve_fresh_source_owner(tmp_path):
    support=Path(__file__).with_name('d12_repeated_c09_acceptance_support_v1.py')
    repository=Path(__file__).resolve().parents[4]
    environment=dict(os.environ,PYTHONPATH=str(repository)+os.pathsep+str(repository/'rewrite')+os.pathsep+os.environ.get('PYTHONPATH',''))
    results=[]
    for phase,stage,generation in (
        ('prepare','PREPARED',1),('switch','SWITCHED',1),('release','RELEASED',1),
        ('prepare_second','PREPARED',2),('switch','SWITCHED',2),('release','RELEASED',2),('verify','RELEASED',2)):
        process=subprocess.run([sys.executable,str(support),phase,str(tmp_path)],capture_output=True,text=True,env=environment,timeout=180)
        assert process.returncode==0,phase+'\n'+process.stderr
        result=json.loads(process.stdout.strip().splitlines()[-1])
        assert (result['stage'],result['generation'])==(stage,generation)
        results.append(result)
    assert len({result['process_id'] for result in results})==len(results)
    assert results[3]['first_fresh_owner_read']
    assert results[-1]['fresh_owner_read'] and results[-1]['fresh_owner_write']

    assert results[-1]['actual_mapped_inventory']
