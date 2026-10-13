"""L02 genuine installed C1/C3 restart and role-clock offline fixed nodes.

Finite local MockTransport only. These nodes require fresh Root-prepared
protected installations and never claim M1/C4 or real 72/96-hour waiting.
"""
import os
from pathlib import Path
import pytest
from test_m1_installed_artifact_draft_v1 import installed_d04_root
from l02_restart_host_support_v1 import run_installed_l02_case_v1


@pytest.fixture
def installed_l02_configuration_v1(installed_d04_root):
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    selected = os.environ.get('SYLANNE_L02_FIXTURE_SETUP')
    if not selected:
        pytest.skip('requires fresh Root-prepared L02 protected initial configuration')
    initial = M1PhaseFixtureInstallationV2.from_protected_setup_v2(Path(selected))
    assert initial.package_root == Path(installed_d04_root)
    return initial


@pytest.mark.asyncio
async def test_installed_l02_c3_waiting_process_restart_wakes_once(installed_l02_configuration_v1):
    result = await run_installed_l02_case_v1(installed_l02_configuration_v1, scenario='c3_restart')
    first, restarted = result['first'], result['restarted']
    assert first['actual_exit_code'] == restarted['actual_exit_code'] == 0
    assert first['process_identity'] != restarted['process_identity']
    assert first['outcome']['provider_call_count'] == 1
    assert restarted['outcome']['provider_call_count'] == 1
    assert restarted['outcome']['after']['child_phase'] == 'completed'
    assert restarted['outcome']['after']['signed_original_digests'] == restarted['outcome']['replay']['signed_original_digests']
    assert result['original_proof']


@pytest.mark.asyncio
async def test_installed_l02_offline_restart_tick_original_once(installed_l02_configuration_v1):
    result = await run_installed_l02_case_v1(installed_l02_configuration_v1, scenario='offline_restart')
    first, restarted = result['first'], result['restarted']
    assert first['actual_exit_code'] == restarted['actual_exit_code'] == 0
    assert first['process_identity'] != restarted['process_identity']
    assert first['outcome']['provider_call_count'] == restarted['outcome']['provider_call_count'] == 0
    assert restarted['outcome']['signed_adoptions']
    assert restarted['outcome']['signed_adoptions'] == restarted['outcome']['signed_replay_adoptions']
    assert result['original_proof']
