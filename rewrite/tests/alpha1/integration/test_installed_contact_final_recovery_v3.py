"""Installed Contact final COMMIT/ACK recovery and private-stage refusal.

The real Owner, TLS, GraphWorker, paid jobs and three-stage final pipeline
come from the installed donor. SQL mutations deliberately simulate damaged
inventory/current state; they are not Owner revocation commands. No sender
or platform is enabled.
"""
import pytest

from test_installed_contact_final_v3 import installed_d04_root,run_installed_contact_final3_case


@pytest.mark.asyncio
async def test_installed_contact3_post_cas_negative_inventory_rolls_back(tmp_path,installed_d04_root):
    await run_installed_contact_final3_case(tmp_path,installed_d04_root,validation_mode='post_cas_negative')


@pytest.mark.asyncio
async def test_installed_contact3_commit_pending_finish_cold_recovery_and_once_replay(tmp_path,installed_d04_root):
    await run_installed_contact_final3_case(tmp_path,installed_d04_root,validation_mode='recovery')


@pytest.mark.asyncio
async def test_installed_contact3_independent_graph_process_scoped_owner_recovery(tmp_path,installed_d04_root):
    await run_installed_contact_final3_case(tmp_path,installed_d04_root,validation_mode='restart')


@pytest.mark.asyncio
async def test_installed_contact3_finished_fresh_owner_session_readonly_exact_no_effects(tmp_path,installed_d04_root):
    await run_installed_contact_final3_case(tmp_path,installed_d04_root,validation_mode='finished_readonly')
