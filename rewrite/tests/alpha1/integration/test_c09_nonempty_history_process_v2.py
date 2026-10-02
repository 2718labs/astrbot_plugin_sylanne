"""Actual Owner-created, nonempty PREPARED history conversion in new processes.

Only new synthetic installation files are used. No Life/Contact populated
disposal, business reopening through V2, or whole-backend claim is made.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def _convert_phase(root,phase):
    from c09_four_store_process_acceptance_support_v1 import _control
    from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    from sylanne3.authority_service.c09_control_selector_v2 import InstalledC09ControlSelectorV2
    from sylanne3.authority_service.c09_sanitized_history_v2 import (
        build_sanitized_history_v2,InstalledC09StorageReaderV2,
    )
    packet=json.loads((root/'packet.json').read_text())
    control,lease=_control(root,packet)
    selector=InstalledC09ControlSelectorV2(control,str(control.path)+'.selector-v2',str(control.path)+'.selector-v2.journal')
    target=root/'protected'/'sanitized-history-v2.json'
    try:
        if phase=='build':
            history=build_sanitized_history_v2(control,target,gate=InstalledC09WriterGateV1(control=control))
            assert len(history['frames'])>=1
            assert history['storage_stage']=='RELEASED'
            assert b'storage_prepared_original.v1' not in target.read_bytes()
            selector.prepare(target)
            return dict(phase=phase,frames=len(history['frames']),old_control_exists=control.path.exists(),process_id=os.getpid())
        if phase=='dispose':
            selector.switch();selector.dispose()
        else:
            selector.switch();selector.dispose()
        reader=InstalledC09StorageReaderV2(control=control,selector=selector)
        context,frames=reader.read_verified_frames_v2()
        assert len(frames)>=1 and context.storage_generation>=1
        context.require_current('recovery')
        from sylanne3.authority_service.contract import AuthorityUnavailable
        try:context.require_current('business')
        except AuthorityUnavailable:pass
        else:raise AssertionError('V2 recovery context invented business rights')
        assert not control.path.exists()
        assert b'storage_prepared_original.v1' not in target.read_bytes()
        return dict(phase=phase,frames=len(frames),old_control_exists=False,
            history_digest=context.history_digest,process_id=os.getpid())
    finally:lease.close()


def test_actual_released_history_control_conversion_v2(tmp_path):
    here=Path(__file__).resolve()
    old=here.with_name('c09_four_store_process_acceptance_support_v1.py')
    source=here.parents[4]
    env=dict(os.environ,PYTHONPATH=os.pathsep.join((str(source),str(source/'rewrite'),str(here.parent))))
    outcomes=[]
    for script,phase in ((old,'prepare'),(old,'switch'),(old,'release'),
            (here,'build'),(here,'dispose'),(here,'verify')):
        result=subprocess.run([sys.executable,str(script),phase,str(tmp_path)],env=env,
            capture_output=True,text=True,timeout=180)
        assert result.returncode==0, result.stderr
        outcomes.append(json.loads(result.stdout.strip().splitlines()[-1]))
    assert len({v['process_id'] for v in outcomes})==len(outcomes)
    assert outcomes[-1]['frames']>=1 and not outcomes[-1]['old_control_exists']
    assert outcomes[-1]['history_digest']==outcomes[-2]['history_digest']


if __name__=='__main__':
    print(json.dumps(_convert_phase(Path(sys.argv[2]),sys.argv[1]),sort_keys=True))
