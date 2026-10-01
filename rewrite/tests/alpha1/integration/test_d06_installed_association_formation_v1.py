"""Two observed paid C02 messages and paid appraisals form one genuine edge.

The local model HTTP text is controlled; all inputs, Owner admission, costs,
appraisal adoption, Graph commits and retained provenance use product paths.
"""
import asyncio
import json
import time
from uuid import uuid4

import pytest

from test_d04_owner_semantic_initialization_v3 import (
    installed_d04_root, real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock,
)
from test_d04_installed_semantic_drive_v3 import (
    appraisal_workflows, compose_installed_appraisal, explicit_subjective_reply,
)
from test_current_domain_production_v1 import command
from sylanne3.host.installed_d04_appraisal_driver_v3 import run_installed_post_c02_appraisal_v3
from sylanne3.runtime.d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3
from sylanne3.runtime.d06_association_formation_v1 import FormCurrentAssociationRequestV1
from sylanne3.runtime.domain_production_erasure_v1 import validate_domain_production_schema_v1


@pytest.mark.asyncio
async def test_installed_two_paid_appraisals_form_current_association(tmp_path, installed_d04_root):
    initialized = {}

    async def after_role(case):
        def initialize():
            initialize_owner_root_v3(case)
            adopt_mapping_and_clock(case)
            initialized.update(case)
        await asyncio.to_thread(initialize)

    async def after_c02(case):
        graph, store, ns = case["graph"], case["store"], case["namespace"]
        bundle, assembly, runtime = compose_installed_appraisal(case, initialized)
        appraisals = []
        for member in range(2):
            if member == 0:
                c02, source = case["c02"], case["source_ref"]
            else:
                # Let the actual installed first attention ticket expire. Its
                # appraisal remains a real original; no observed send/served
                # state is fabricated to obtain the next focus.
                with store._lock:
                    focus = json.loads(store._db.execute("SELECT value FROM graph_atoms "
                        "WHERE type_name='d07.focus.v1' AND valid=1").fetchone()[0])
                    ticket = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?",
                        (focus["primary_ticket_ref"],)).fetchone()[0])
                await asyncio.sleep(max(0.0, ticket["valid_until"] - time.time() + 0.05))
                ingress, second_c02 = await case["commit_second_c02"](
                    "observed-association-2", "hello again", commit_attention=True)
                second_source = next(version.key.token for version in ingress.write_versions
                    if version.key.type_name == "memory.source")
                c02, source = second_c02, second_source
            args = {"c02_operation_id": c02.operation_id, "source_ref": source}
            prepared = await asyncio.to_thread(graph.prepare_post_c02_appraisal_v3, case["bootstrap"], bundle, **args)
            with store._lock:
                original = read_current_d04_appraisal_original_v3(store._db, ns, prepared["job_id"])
                frozen = json.loads(original.frozen_json)
            case["model_reply_mode"]["content"] = explicit_subjective_reply(frozen, 0.5)
            adopted = await run_installed_post_c02_appraisal_v3(runtime, assembly, context=case["model_context"],
                trusted_umo="platform-1:FriendMessage:123456", **args)
            assert adopted["status"] == "adopted", adopted
            appraisals.append(adopted["appraisal_ref"])

        request = FormCurrentAssociationRequestV1(case["source_ref"], case["c02"].operation_id,
            second_source, second_c02.operation_id, appraisals[0], "facet:inbound", appraisals[1], "facet:inbound",
            "relation_meaning")
        operation = str(uuid4())
        audience = '["platform-1:FriendMessage:123456","conversation-1"]'
        def form():
            result = command(initialized, "form_association", request, audience=audience, operation_id=operation)
            assert result["coverage"] == "complete", result
            with store._lock:
                edges = store._db.execute("SELECT token,value,valid FROM graph_atoms WHERE type_name='memory.association.v1'").fetchall()
                assert len(edges) == 1 and edges[0][2] == 1
                edge = json.loads(edges[0][1])
                assert edge["source_ref"] == case["source_ref"] and edge["target_ref"] == second_source
                assert edge["kind"] == "subjective_meaning" and edge["weight"] == 1.0
                assert edge["content_reality"] == "subjective"
                assert set(edge["basis_source_refs"]) >= {case["source_ref"], second_source}
                assert store._db.execute("SELECT COUNT(*) FROM graph_dependencies WHERE dependent_token=?", (edges[0][0],)).fetchone() == (0,)
                assert store._db.execute("SELECT COUNT(*) FROM graph_dependency_edges WHERE dependent_token=? AND edge_kind='historical_provenance'", (edges[0][0],)).fetchone()[0] >= 4
                assert validate_domain_production_schema_v1(store._db) is True
            repeated = command(initialized, "form_association", request, audience=audience, operation_id=operation)
            assert repeated["original_digest"] == result["original_digest"]
        await asyncio.to_thread(form)

    await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
        after_role_initialization=after_role, continue_to_ingress=True, after_c02=after_c02,
        natural_workflow_builder=appraisal_workflows, enable_d04_semantic_drive=True,
        enable_d09_workbench=True, enable_d04_root_cpu=True, enable_c04_body_work=True,
        extra_owner_purposes=("context", "consolidation"))
