"""Actual installed Life occurrence -> content-only preparation COMMIT.

The donor performs real execution/artifact/adoption/Body/D10/Episode work.
This first content node proves preparation, not worker/model completion,
trace consumption, numeric before-state, comparison or affect.
"""
import asyncio
from dataclasses import fields
import sqlite3
import traceback
from pathlib import Path

import pytest

from test_d11_installed_life_source_note_v1 import installed_d04_root,run_installed_owner_life_case
from test_current_domain_production_v1 import command
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
from sylanne3.model_broker.internal_life_content_v1 import WORK_KIND,TEMPLATE_VERSION,internal_life_content_ids_for_occurrence_v1
from sylanne3.runtime.internal_life_content_preparation_v1 import PrepareInternalLifeContentRequestV1,read_committed_internal_life_prepared_v1
from sylanne3.runtime.d06_internal_life_episode_v2 import PROVENANCE,decode_internal_life_value_v2
from sylanne3.graph_types import AtomKey
from sylanne3.runtime.jobs import get_job


def life_content_workflows(base,shared):
    common={f.name:getattr(base,f.name) for f in fields(base) if f.name!='version'}
    return AdminModelWorkflowsV3(3,**common,life_content=AdminModelWorkflowV2(
        work_kind=WORK_KIND,purpose='consolidation',template_version=TEMPLATE_VERSION,
        max_output_tokens=128,quote_ceiling={'output_tokens':128},**shared))


async def run_installed_life_content_preparation_case(tmp_path,installed_d04_root, *, acquire=False, after_acquire=None, worker_v2=False, enable_c09_maintenance=False, host_process_runner=None, c09_protected_root=None):
    async def after_episode(case):
        def accept():
            graph,store,ns=case['graph'],case['store'],case['namespace']
            key=AtomKey.from_token(case['episode_ref'])
            with store._lock:
                import json
                proof_key=AtomKey(key.owner,PROVENANCE,'record')
                proof=decode_internal_life_value_v2(PROVENANCE,json.loads(store._db.execute(
                    'SELECT value FROM graph_atoms WHERE token=?',(proof_key.token,)).fetchone()[0]))
            ids=internal_life_content_ids_for_occurrence_v1(proof)
            request=PrepareInternalLifeContentRequestV1(case['episode_ref'],case['life_causal_operation_id'])
            try:
                result=command(case,'prepare_internal_life_content',request,operation_id=ids['prepare'],
                    activity_id=case['life_activity_id'],audience=case['life_audience'])
            except Exception:
                error=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
                if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
                raise
            assert result['coverage']=='deferred' and result['job_states']==[[ids['job'],'queued']]
            assert not store._db.in_transaction
            path=Path(store._db.execute('PRAGMA database_list').fetchone()[2])
            with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as cold:
                cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
                prepared=read_committed_internal_life_prepared_v1(cold,namespace=ns,issuer=case['d11_issuer'],job_id=ids['job'])
                assert prepared.episode_ref==case['episode_ref'] and get_job(cold,ids['job']).phase=='queued'
                assert cold.total_changes==0
            seq=result['receipt']['commit_seq']
            replay=command(case,'prepare_internal_life_content',request,operation_id=ids['prepare'],
                activity_id=case['life_activity_id'],audience=case['life_audience'])
            assert replay==result and replay['receipt']['commit_seq']==seq
            assert store._db.execute('SELECT count(*) FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase=?',
                (case['policy'].root_grant.lease_id,ids['prepare'],'reserve')).fetchone()==(1,)
            if acquire:
                from sylanne3.runtime.internal_life_content_worker_v1 import (
                    AcquireInternalLifeContentRequestV1, read_committed_internal_life_request_v1,
                )
                acquire_kind='acquire_internal_life_content'
                if worker_v2:
                    from sylanne3.runtime.internal_life_content_worker_v2 import (
                        AcquireInternalLifeContentRequestV2 as AcquireInternalLifeContentRequestV1,
                        read_committed_internal_life_request_v2 as read_committed_internal_life_request_v1)
                    acquire_kind='acquire_internal_life_content_v2'
                locator=AcquireInternalLifeContentRequestV1(case['episode_ref'],case['life_causal_operation_id'])
                try:
                    acquired=command(case,acquire_kind,locator,operation_id=ids['acquire'],
                        activity_id=case['life_activity_id'],audience=case['life_audience'])
                except Exception:
                    error=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
                    if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
                    raise
                assert acquired['coverage']=='deferred' and acquired['job_states']==[[ids['job'],'running']]
                with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as cold:
                    cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
                    durable=read_committed_internal_life_request_v1(cold,namespace=ns,
                        issuer=case['d11_issuer'],job_id=ids['job'])
                    if worker_v2:actual,binding,model=durable
                    else:actual,model=durable
                    job=get_job(cold,ids['job'])
                    assert actual==prepared and job.phase=='running' and job.fence==1
                    assert model.identity.phase==('internal_life_content_v2' if worker_v2 else 'internal_life_content') and model.call_id==ids['call']
                    if worker_v2:
                        grant=graph._GraphCoordinator__content_fence_v2.installation_grant
                        assert binding.worker_subject==grant.subject==job.lease_holder==model.envelope.authority.actor
                        assert binding.owner_actor==case['actor'] if 'actor' in case else binding.owner_actor!=binding.worker_subject
                        assert binding.manifest_digest==grant.manifest_digest
                    assert model.envelope.authority.purpose=='consolidation'
                    assert model.envelope.authority.audience==(case['life_audience'],)
                    assert model.envelope.authority.worker_fence==job.fence
                    assert cold.total_changes==0
                again=command(case,acquire_kind,locator,operation_id=ids['acquire'],
                    activity_id=case['life_activity_id'],audience=case['life_audience'])
                assert again==acquired
                assert store._db.execute('SELECT count(*) FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase=?',
                    (case['policy'].root_grant.lease_id,ids['prepare'],'reserve')).fetchone()==(1,)
                table='graph_internal_life_worker_originals_v2' if worker_v2 else 'graph_internal_life_content_originals_v1'
                assert store._db.execute('SELECT count(*) FROM '+table+' WHERE kind=?',
                    ('request',)).fetchone()==(1,)
                assert store._db.execute('SELECT count(*) FROM '+table+' WHERE kind=?',
                    ('acquire_commit',)).fetchone()==(1,)
        await asyncio.to_thread(accept)
        if after_acquire is not None:
            if not acquire: raise ValueError('after-acquire requires actual acquisition')
            await after_acquire(case)
    await run_installed_owner_life_case(tmp_path,installed_d04_root,
        natural_workflow_builder=life_content_workflows,after_episode_async=after_episode,
        enable_c09_maintenance=enable_c09_maintenance,
        host_process_runner=host_process_runner, c09_protected_root=c09_protected_root)


@pytest.mark.asyncio
async def test_installed_life_occurrence_content_preparation_commits_once(tmp_path,installed_d04_root):
    await run_installed_life_content_preparation_case(tmp_path,installed_d04_root)


@pytest.mark.asyncio
async def test_installed_life_content_acquires_actual_closed_input_once(tmp_path,installed_d04_root):
    """Real Owner/GCP acquisition; no provider/terminal/content-completed assertion."""
    await run_installed_life_content_preparation_case(tmp_path,installed_d04_root,acquire=True)
