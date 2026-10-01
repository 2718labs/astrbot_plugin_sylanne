"""Actual root CPU reservation, independent once-only terminal and atomic roots."""
import asyncio
from dataclasses import asdict
import json
from uuid import uuid4
import pytest

from test_d04_owner_semantic_initialization_v3 import (installed_d04_root,real_owner_case,
    install_d04_test_composition,current_owner)
from d04_numeric_authority_acceptance_support_v3 import install_actual_root_authority_case_v3
from sylanne3.domains.d04.authored_lineage_v3 import AuthoredRootBlockInputV3,RootAuthoredFacetV3
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.host.installed_d04_root_resources import load_installed_d04_root_preset_v3
from sylanne3.runtime.d04_root_execution_v3 import execute_current_root_execution_v3
from sylanne3.runtime.d04_root_adoption_execution_v3 import adopt_executed_root_v3
from sylanne3.runtime.d04_appraisal_driver_v3 import read_d04_original_v3
from sylanne3.authority_service.d04_root_execution_contract_v3 import D04RootExecutionTerminalV3


@pytest.mark.asyncio
@pytest.mark.parametrize("cpu_ceiling",(60000,900),ids=("within-reservation","overrun-history-only"))
async def test_actual_root_cpu_terminal_and_atomic_adoption(tmp_path,installed_d04_root,cpu_ceiling):
    resources=[]
    async def after_role(case):
        await asyncio.to_thread(install_d04_test_composition,case)
        support=await asyncio.to_thread(install_actual_root_authority_case_v3,case,owner_loop=asyncio.get_running_loop())
        resources.append(support)
        def run():
            graph,store,ns=case['graph'],case['store'],case['namespace']
            preset=load_installed_d04_root_preset_v3(case['package_root'],case['manifest_digest'])
            blocks=tuple(AuthoredRootBlockInputV3(RootAuthoredFacetV3('owner-block:'+str(i),t.template_id,t.kind,
                'owner-facet:'+str(i)),preset.axes,(0.5,)*24,((0.5,0.5),)*24,'owner-initial-box:'+str(i)) for i,t in enumerate(preset.block_templates))
            field={'candidate_id':'root-cpu-actual','cursor':0.0,'preset_digest':preset.digest,
                'asset_digest':preset.assets.digest,'blocks':json.loads(json.dumps([asdict(b) for b in blocks]))}
            with current_owner(case) as (authority,lease):
                graph.initialize_current_d04_root_draft_v3(authority,lease,operation_id=str(uuid4()),root_field=field)
                budget=graph.allocate_current_d04_root_budget_v3(authority,lease,operation_id=str(uuid4()),
                    parent_budget_lease_ref=case['policy'].root_grant.lease_id,ceiling={'thread_cpu_ms':cpu_ceiling})
                compiled=graph.compile_current_scheme_for_operation_v1(authority,lease,operation_id=str(uuid4()),
                    draft_ref=character_draft_key(ns).token,budget_ref=case['policy'].root_grant.lease_id)
                operation=str(uuid4())
                args=dict(operation_id=operation,compiled_digest=compiled.compiled.compiled_digest,parent_budget_lease_ref=budget['lease_id'],preset=preset)
                execution=execute_current_root_execution_v3(graph,authority,lease,**args)
                assert execution.status=='execution_terminal'
                assert type(execution.terminal) is D04RootExecutionTerminalV3
                measured=execution.terminal.measurement
                assert measured.status in {'completed','failed'} and measured.actual_cpu_ms>0
                if measured.status=="failed" or measured.actual_cpu_ms>cpu_ceiling:
                    assert cpu_ceiling==900
                    from sylanne3.runtime.d04_root_historical_cost_v3 import settle_historical_root_cpu_v3
                    from sylanne3.authority_service.contract import AuthorityUnavailable
                    with pytest.raises((AuthorityUnavailable,RuntimeError)):
                        support.port.root_adoption_bridge(execution.prepared.binding)
                    settled=settle_historical_root_cpu_v3(graph,case['bootstrap'],support.port._bundle,operation_id=operation)
                    assert settled['adoption_status']=='not_adopted'
                    cost=read_d04_original_v3(store._db,ns,'root_cost',operation)[0]
                    assert cost['actual_cpu_ns']==measured.actual_cpu_ns
                    assert json.loads(cost['settlement_json'])['status']=='overrun'
                    assert store._db.execute("SELECT COUNT(*) FROM graph_d04_root_originals_v3 WHERE bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,operation)).fetchone()==(0,)
                    assert settle_historical_root_cpu_v3(graph,case['bootstrap'],support.port._bundle,operation_id=operation)==settled
                    return
                assert cpu_ceiling==60000
                before,_=graph._v2_graph_stamp(ns)
                restored=support.port.root_restore_original(execution.prepared.binding)
                assert restored.terminal==execution.terminal and restored.prepared==execution.prepared
                import sylanne3.domains.d04.authored_root_recovery_v3 as math
                def forbidden(*args,**kwargs):raise AssertionError('root terminal replay reran native math')
                with pytest.MonkeyPatch.context() as patch:
                    patch.setattr(math,'execute_authored_root_math_once_v3',forbidden)
                    assert execute_current_root_execution_v3(graph,authority,lease,**args)==execution
                    adoption,receipt=adopt_executed_root_v3(graph,authority,lease,execution,preset=preset)
                    first_cost=read_d04_original_v3(store._db,ns,'root_cost',operation)
                    assert adopt_executed_root_v3(graph,authority,lease,execution,preset=preset)==(adoption,receipt)
                    assert read_d04_original_v3(store._db,ns,'root_cost',operation)==first_cost
                assert adoption.operation_id==operation and len(receipt.revisions)==6
                after,_=graph._v2_graph_stamp(ns)
                assert after.graph_revision==before.graph_revision+2
                from sylanne3.authority_service.d04_root_execution_bridge_v3 import D04RootAdoptionBridgeV3,root_bridge_from_wire_v3
                saved=read_d04_original_v3(store._db,ns,'root_adoption_bridge',operation)[0]
                original_gate=root_bridge_from_wire_v3(saved,D04RootAdoptionBridgeV3)
                assert support.port.root_gate_status(execution.prepared.binding,original_gate)=='finished'
                assert support.port.root_finish_gate(execution.prepared.binding,original_gate,outcome='committed') is True
                assert graph._v2_graph_stamp(ns)[0]==after
                cost=read_d04_original_v3(store._db,ns,'root_cost',operation)[0]
                assert (cost['actual_cpu_ns'],cost['actual_cpu_ms'])==(measured.actual_cpu_ns,measured.actual_cpu_ms)
                settlement=json.loads(cost['settlement_json'])
                assert settlement['status']=='settled'
                assert support.port.root_inspect(execution.prepared.binding)==(execution.terminal.claim,execution.terminal)
                assert store._db.execute("SELECT COUNT(*) FROM graph_d04_root_originals_v3 WHERE bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,operation)).fetchone()==(1,)
                assert store._db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",(budget['lease_id'],execution.prepared.binding.reservation_operation_id)).fetchone()==('settled',json.dumps({'thread_cpu_ms':measured.actual_cpu_ms},sort_keys=True,separators=(',',':')))
        await asyncio.to_thread(run)
    try:
        await real_owner_case(tmp_path,'owned',installed_package_root=installed_d04_root,
            after_role_initialization=after_role,enable_d09_workbench=True,enable_d04_root_cpu=True)
    finally:
        for resource in resources:resource.close()
