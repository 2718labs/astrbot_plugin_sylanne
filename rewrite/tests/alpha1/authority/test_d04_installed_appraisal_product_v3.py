"""Actual paired C02 -> D07 unknown -> one paid appraisal -> adopted original.

The model HTTP reply is controlled. Owner signatures, Core/journals, mTLS,
D11 signed quotes, source reads, and Graph transactions are real implementations.
This acceptance makes no claim about a live provider or numeric adoption.
"""
import asyncio
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_post_c02_reply_assembly_v2 import test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.host.d04_appraisal_result_port_v3 import InstalledD04AppraisalResultPortV3
from sylanne3.host.installed_d04_appraisal_driver_v3 import run_installed_post_c02_appraisal_v3
from sylanne3.authority_service.d04_appraisal_result_service_v3 import AuthorityD04AppraisalResultServiceV3
from sylanne3.model_broker.d04_appraisal import TEMPLATE_VERSION, OUTPUT_SCHEMA
from sylanne3.runtime.d04_product_pipeline_v3 import ids
from sylanne3.runtime.d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3, read_d04_original_v3
from sylanne3.runtime.jobs import get_job


def workflows(base, shared):
    return replace(base, appraisal=AdminModelWorkflowV2(work_kind="d04.appraisal", purpose="proposal",
        template_version=TEMPLATE_VERSION, max_output_tokens=128, quote_ceiling={"output_tokens": 128}, **shared))


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery_mode", ("normal", "read_transport_loss", "source_revoked"))
async def test_current_d04_appraisal_uses_actual_paid_original_and_exact_replay(tmp_path, recovery_mode):
    async def after_c02(case):
        graph, store, bundle, namespace = (case[k] for k in ("graph", "store", "installed_bundle", "namespace"))
        assembly = V2InstallationAssembly(bundle.installation_policy, case["client_grant"],
            bundle.d11_signing_key, bundle.d02_signing_key, lambda: case["port"], tmp_path, tmp_path,
            ingress_clock=bundle.ingress_clock, ingress_encoding=bundle.ingress_encoding, admin_bundle=bundle)
        graph._GraphCoordinator__d04_installed_joint_assembly = assembly
        reader = AuthorityD04AppraisalResultServiceV3(store=case["model_store"], fences=case["protected"],
            graph_db_path=store._db.execute("PRAGMA database_list").fetchone()[2], d11_issuer=case["d11_issuer"],
            installation_id=bundle.installation_policy.installation_id,
            read_subject=case["client_grant"].subject, holder=bundle.installation_policy.administrator_holder,
            trusted_now_utc=__import__("time").time)
        case["server"].install_d04_appraisal_result_reader_v3(case["authority_namespace"], reader)
        graph._GraphCoordinator__d04_appraisal_result_port = InstalledD04AppraisalResultPortV3(
            client=case["authority_client"], bundle=bundle, grant=case["client_grant"], owner_loop=asyncio.get_running_loop())
        args = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        prepared = await asyncio.to_thread(graph.prepare_post_c02_appraisal_v3, case["bootstrap"], bundle, **args)
        assert prepared["status"] == "queued"
        original = read_current_d04_appraisal_original_v3(store._db, namespace, prepared["job_id"])
        frozen = json.loads(original.frozen_json)
        assert frozen["input"]["interpretations"][0]["candidate"]["stance"] == "suspend"
        source = frozen["input"]["sources"][0]["source_ref"]["ref"]
        interpretation = frozen["input"]["interpretations"][0]["ref"]["ref"]
        role_values = frozen["input"]["role"]["values"]
        case["model_reply_mode"]["content"] = json.dumps({"schema": OUTPUT_SCHEMA,
            "facets": [{"facet_id": "facet:inbound", "target_ref": frozen["input"]["target_ref"],
                "interpretation_ref": interpretation, "value_ref": role_values[0]["rule_id"] if role_values else frozen["input"]["role"]["blocks"][0]["block_id"],
                "responsibility_hypothesis": "unknown", "controllability": None, "anticipated_impact": None,
                "relation_meaning": "Possible wish to answer", "self_meaning": None, "confidence": None,
                "unknown_fields": ["responsibility_hypothesis", "controllability", "anticipated_impact", "self_meaning", "confidence"],
                "source_refs": [source]}],
            "mechanism_signals": [{"facet_id": "facet:inbound", "mechanism_id": "affiliative_approach",
                "rationale": "Possible connection, not a measured feeling", "source_refs": [source]}],
            "possible_feelings": ["possibly attentive"], "unknown_fields": ["speaker_intent"]})
        class Worker:
            async def call(self, call):
                return await asyncio.to_thread(call, graph)
        runtime = SimpleNamespace(_worker=Worker(), _v2_bootstrap=case["bootstrap"],
            _v2_natural_readiness_receipt=SimpleNamespace(installation=assembly,
                authority_client=case["authority_client"], client_grant=case["client_grant"]))
        paid_before_recovery = None
        if recovery_mode != "normal":
            result_port = graph._GraphCoordinator__d04_appraisal_result_port
            actual_read = result_port.read
            first = [True]
            def interrupted_read(request):
                if first[0]:
                    first[0] = False
                    if recovery_mode == "read_transport_loss":
                        raise RuntimeError("simulated result read transport loss")
                    from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
                    from sylanne3.graph_types import AtomKey
                    from uuid import uuid4
                    import time
                    owner, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply",
                        namespace=namespace, domains=("d06", "d11"), purpose="audit", audience="owner",
                        activation_generation=graph._v2_graph_stamp(namespace)[0].requirements.activation_generation,
                        owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
                    try:
                        graph.revoke_source_access_v1(owner, lease, SourceAccessRevocationRequest(
                            AtomKey.from_token(case["source_ref"]).owner.subject, owner.actor, str(uuid4()), time.time()))
                    finally:
                        graph.release_current_owner_lease(case["bootstrap"], lease)
                return actual_read(request)
            result_port.read = interrupted_read
            with pytest.raises(RuntimeError):
                await run_installed_post_c02_appraisal_v3(runtime, assembly, context=case["model_context"],
                    trusted_umo="platform-1:FriendMessage:123456", **args)
            from sylanne3.runtime.budget import get_budget_lease
            from sylanne3.runtime.model_cost_settlement import original_model_cost_operation_id_v1
            paid_before_recovery = dict(get_budget_lease(store._db, bundle.installation_policy.root_grant.lease_id).used)
            assert store._db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple, original_model_cost_operation_id_v1(namespace, original.call_id))).fetchone() == (1,)
            if recovery_mode == "source_revoked":
                assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE type_name='d04.appraisal_bundle.v1'").fetchone() == (0,)
                assert get_job(store._db, prepared["job_id"]).phase == "running"
                return
        outcome = await run_installed_post_c02_appraisal_v3(runtime, assembly, context=case["model_context"],
            trusted_umo="platform-1:FriendMessage:123456", **args)
        assert outcome["status"] == "adopted"
        assert get_job(store._db, prepared["job_id"]).phase == "completed"
        assert read_d04_original_v3(store._db, namespace, "appraisal_cost", prepared["job_id"])[0]["paid"] is True
        repeated = await run_installed_post_c02_appraisal_v3(runtime, assembly, context=case["model_context"],
            trusted_umo="platform-1:FriendMessage:123456", **args)
        assert repeated == outcome
        if paid_before_recovery is not None:
            assert dict(get_budget_lease(store._db, bundle.installation_policy.root_grant.lease_id).used) == paid_before_recovery
        assert store._db.execute("SELECT count(*) FROM graph_d04_originals_v3 WHERE kind='appraisal_call'").fetchone() == (1,)
    await real_owner_case(tmp_path, "owned", natural_workflow_builder=workflows, after_c02=after_c02,
        extra_owner_capabilities=("workbench.correct",), extra_owner_purposes=("audit",))
