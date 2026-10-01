"""Actual installed Owner first use -> C02 -> paid appraisal -> semantic drive.

Only the local provider's HTTP response is controlled. The paired Owner,
Authority, grants, model terminal accounting, source access and Graph CAS are
production paths. This suite does not run a live model or numeric integration.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_d04_owner_semantic_initialization_v3 import (
    installed_d04_root, real_owner_case, initialize_owner_root_v3,
    current_owner, current_mapping_read, adopt_mapping_and_clock,
)
from sylanne3.authority_service.d04_appraisal_result_service_v3 import AuthorityD04AppraisalResultServiceV3
from sylanne3.domains.d04.numeric_drive import decode_sourced_numeric_drive
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.host.d04_appraisal_result_port_v3 import InstalledD04AppraisalResultPortV3
from sylanne3.host.installed_d04_appraisal_driver_v3 import run_installed_post_c02_appraisal_v3
from sylanne3.model_broker.d04_appraisal import TEMPLATE_VERSION, OUTPUT_SCHEMA
from sylanne3.runtime.d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3, read_d04_original_v3
from sylanne3.runtime.d04_semantic_mapping_v3 import read_d04_mapping_acceptance_v3
from sylanne3.runtime.d04_semantic_policy import AdminD04SemanticDrivePolicyV1, MAPPING_VERSION, BASIS_VERSION, MECHANISMS
from sylanne3.runtime.jobs import get_job


def appraisal_workflows(base, shared):
    return replace(base, appraisal=AdminModelWorkflowV2(work_kind="d04.appraisal", purpose="proposal",
        template_version=TEMPLATE_VERSION, max_output_tokens=128,
        quote_ceiling={"output_tokens": 128}, **shared))


def compose_installed_appraisal(case, initialized):
    """Use the existing installed reader and real Host/Authority result port."""
    graph, store = case["graph"], case["store"]
    grant = case["policy"].root_grant
    policy = AdminD04SemanticDrivePolicyV1(case["namespace"], case["policy"].installation_id,
        grant.grant_id, grant.version, grant.lease_id, MAPPING_VERSION, BASIS_VERSION,
        {name: (0.125, 0.0625, 0.03125) for name in MECHANISMS}, {name: 1.0 for name in MECHANISMS})
    assert policy.work_kind in grant.allowed_work_kinds
    bundle = replace(case["installed_bundle"], d04_semantic_drive=policy)
    assembly = replace(graph._GraphCoordinator__d04_installed_joint_assembly,
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
    class Worker:
        async def call(self, call):
            return await asyncio.to_thread(call, graph)
    runtime = SimpleNamespace(_worker=Worker(), _v2_bootstrap=case["bootstrap"],
        _v2_natural_readiness_receipt=SimpleNamespace(installation=assembly,
            authority_client=case["authority_client"], client_grant=case["client_grant"]))
    assert graph._GraphCoordinator__d04_semantic_mapping_reader is initialized["mapping_reader"]
    return bundle, assembly, runtime


def explicit_subjective_reply(frozen, impact):
    """All eight mechanism suggestions are explicit; uncertainty is preserved."""
    source = frozen["input"]["sources"][0]["source_ref"]["ref"]
    interpretation = frozen["input"]["interpretations"][0]["ref"]["ref"]
    values = frozen["input"]["role"]["values"]
    unknown = ["responsibility_hypothesis", "controllability", "self_meaning", "confidence"]
    if impact is None:
        unknown.append("anticipated_impact")
    return json.dumps({"schema": OUTPUT_SCHEMA,
        "facets": [{"facet_id": "facet:inbound", "target_ref": frozen["input"]["target_ref"],
            "interpretation_ref": interpretation,
            "value_ref": values[0]["rule_id"] if values else frozen["input"]["role"]["blocks"][0]["block_id"],
            "responsibility_hypothesis": "unknown", "controllability": None, "anticipated_impact": impact,
            "relation_meaning": "Possible significance of this greeting", "self_meaning": None,
            "confidence": None, "unknown_fields": unknown, "source_refs": [source]}],
        "mechanism_signals": [{"facet_id": "facet:inbound", "mechanism_id": mechanism,
            "rationale": "Subjective possibility under this interpretation, not an observed feeling",
            "source_refs": [source]} for mechanism in MECHANISMS],
        "possible_feelings": ["possibly attentive"], "unknown_fields": ["speaker_intent"]})


@pytest.mark.asyncio
@pytest.mark.parametrize("impact", (0.5, None), ids=("explicit-impact", "unknown-impact-holds"))
async def test_installed_owner_c02_appraisal_semantic_drive(tmp_path, installed_d04_root, impact, *, after_drive=None, role_clock_rate="1"):
    initialized = {}
    async def after_role(case):
        if impact is not None:
            from d04_http_initialization_acceptance_v3 import initialize_via_actual_workbench_v3
            try:
                await initialize_via_actual_workbench_v3(case, role_clock_rate=role_clock_rate)
            finally:
                initialized.update(case)
            return
        def adopt():
            initialize_owner_root_v3(case)
            with current_owner(case) as (authority, lease):
                topology = case["graph"].adopt_current_d04_root_coupling_v3(authority, lease,
                    operation_id=str(uuid4()), root_operation_id=case["root_operation_id"], effective_until=86400.0)
            assert topology["edge_count"] == 48
            mapping, clock = adopt_mapping_and_clock(case, role_clock_rate=role_clock_rate)
            initialized.update(case, topology=topology, installed_mapping=mapping, installed_clock=clock)
        await asyncio.to_thread(adopt)

    async def after_c02(case):
        graph, store, ns = case["graph"], case["store"], case["namespace"]
        bundle, assembly, runtime = compose_installed_appraisal(case, initialized)
        args = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        prepared = await asyncio.to_thread(graph.prepare_post_c02_appraisal_v3, case["bootstrap"], bundle, **args)
        original = read_current_d04_appraisal_original_v3(store._db, ns, prepared["job_id"])
        frozen = json.loads(original.frozen_json)
        assert frozen["input"]["interpretations"][0]["candidate"]["stance"] == "suspend"
        case["model_reply_mode"]["content"] = explicit_subjective_reply(frozen, impact)
        adopted = await run_installed_post_c02_appraisal_v3(runtime, assembly, context=case["model_context"],
            trusted_umo="platform-1:FriendMessage:123456", **args)
        assert adopted["status"] == "adopted"
        assert get_job(store._db, prepared["job_id"]).phase == "completed"
        assert read_d04_original_v3(store._db, ns, "appraisal_cost", prepared["job_id"])[0]["paid"] is True
        appraisal = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?",
            (adopted["appraisal_ref"],)).fetchone()[0])
        accepted_appraisal = read_d04_original_v3(store._db, ns, "appraisal_acceptance", adopted["appraisal_ref"])[0]
        assert json.loads(accepted_appraisal["suggestion_json"])["status"] == "untrusted_subjective_suggestion"
        assert "confidence" in appraisal["meaning_facets"][0]["unknown_fields"]
        if impact is None:
            with pytest.raises(ValueError, match="required_semantic_field_unknown"):
                await asyncio.to_thread(graph.commit_post_c02_semantic_drive_v3, case["bootstrap"], bundle, **args)
            assert store._db.execute("SELECT COUNT(*) FROM graph_atoms WHERE type_name='d04.sourced_numeric_drive.v1'").fetchone() == (0,)
            assert store._db.execute("SELECT COUNT(*) FROM graph_d04_originals_v3 WHERE kind='semantic_mapping'").fetchone() == (0,)
            attempt, receipt = store._db.execute("SELECT attempt_id,receipt_json FROM graph_d04_installed_stage_attempts_v3 WHERE stage='drive'").fetchone()
            assert json.loads(receipt)["status"] == "held"
            refused = read_d04_original_v3(store._db, ns, "stage_refusal", attempt)
            assert refused[0]["status"] == "held"
            _, state = await asyncio.to_thread(case["port"].get_fence_operation, namespace=ns,
                authority_namespace=case["authority_namespace"], operation_id=attempt)
            assert state == "finished"
            with pytest.raises(ValueError, match="held|HOLD|rejected"):
                await asyncio.to_thread(graph.commit_post_c02_semantic_drive_v3, case["bootstrap"], bundle, **args)
            assert store._db.execute("SELECT COUNT(*) FROM graph_d04_originals_v3 WHERE kind='stage_refusal'").fetchone() == (1,)
            def fresh_read():
                with current_mapping_read(initialized) as db:
                    assert initialized["mapping_reader"](db, ns) == initialized["installed_mapping"]
            await asyncio.to_thread(fresh_read)
            return
        result = await asyncio.to_thread(graph.commit_post_c02_semantic_drive_v3, case["bootstrap"], bundle, **args)
        assert result["status"] == "drive_adopted"
        original, digest = read_d04_mapping_acceptance_v3(store._db, ns, result["mapping_ref"])
        assert digest == result["mapping_digest"]
        assert original["interpretation_level"] == "candidate"
        assert original["dose_policy"]["mechanism_max_abs_doses"] == {name: [0.125, 0.0625, 0.03125] for name in MECHANISMS}
        signed_grant = original["signed_budget_grant"]
        signed_policy = original["dose_policy_authority"]
        for proof in (signed_grant, signed_policy):
            case["d11_issuer"]._signer.verify(proof["kind"], proof["payload_json"], proof["signature"])
        authority_body = json.loads(signed_policy["payload_json"])
        assert authority_body["dose_policy"] == original["dose_policy"]
        assert authority_body["signed_budget_grant"] == signed_grant
        assert authority_body["mapping_original_ref"] == result["mapping_ref"]
        assert authority_body["manifest_digest"] == initialized["manifest_digest"]
        assert original["mapping_installation"]["acceptance_digest"] == initialized["mapping_acceptance"]["acceptance_digest"]
        shares = dict(initialized["installed_mapping"].block_shares)
        assert dict(original["mapping_installation"]["block_shares"]) == shares
        rows = store._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE type_name='d04.sourced_numeric_drive.v1'").fetchall()
        assert len(rows) == 3 and all(revision == 1 and valid == 1 for revision, _, valid in rows)
        drives = [decode_sourced_numeric_drive(json.loads(encoded)) for _, encoded, _ in rows]
        assert {drive.checkpoint_ref for drive in drives} == set(shares)
        expected = (0.0625, 0.03125, 0.015625) * 8
        for drive in drives:
            assert drive.mapping_compiler_ref == result["mapping_ref"]
            assert drive.source_ref == case["source_ref"]
            from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
            key = sourced_numeric_drive_write(drive).key
            edges = set(store._db.execute("SELECT dependency_token,dependency_revision FROM graph_dependency_edges "
                "WHERE dependent_token=? AND edge_kind='historical_provenance' AND operation_id=?",
                (key.token, result["operation_id"])).fetchall())
            assert {(drive.checkpoint_ref, drive.checkpoint_revision), (drive.source_ref, drive.source_revision),
                (drive.access_ref, drive.access_revision), (adopted["appraisal_ref"], 1)} <= edges
            assert store._db.execute("SELECT COUNT(*) FROM graph_dependencies WHERE dependent_token=?", (key.token,)).fetchone() == (0,)
            assert drive.role_start == 0 and drive.role_end > 0
            assert tuple(value * (drive.role_end - drive.role_start) for value in drive.drive) == pytest.approx(
                tuple(dose * shares[drive.checkpoint_ref] for dose in expected), rel=1e-12, abs=1e-15)
        repeated = await asyncio.to_thread(graph.commit_post_c02_semantic_drive_v3, case["bootstrap"], bundle, **args)
        assert repeated == result
        changed_bundle = replace(bundle, d04_semantic_drive=replace(bundle.d04_semantic_drive,
            mechanism_max_abs_doses={name: (0.0, 0.0, 0.0) for name in MECHANISMS}))
        graph._GraphCoordinator__d04_installed_joint_assembly = replace(assembly, admin_bundle=changed_bundle)
        try:
            with pytest.raises(ValueError, match="original identity conflict"):
                await asyncio.to_thread(graph.commit_post_c02_semantic_drive_v3,
                    case["bootstrap"], changed_bundle, **args)
        finally:
            graph._GraphCoordinator__d04_installed_joint_assembly = assembly
        assert store._db.execute("SELECT COUNT(*) FROM graph_d04_originals_v3 WHERE kind='semantic_mapping'").fetchone() == (1,)
        assert store._db.execute("SELECT COUNT(*) FROM graph_d04_originals_v3 WHERE kind='appraisal_call'").fetchone() == (1,)
        await initialized["assert_http_initialization_current"]()
        if after_drive is not None:
            await after_drive({**initialized, **case, "installed_bundle": bundle,
                "assembly": assembly, "runtime": runtime, "drive_result": result,
                "mapping_original": original, "drives": tuple(drives)})
        await initialized["assert_http_session_revoked"]()

    try:
        await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
            after_role_initialization=after_role, continue_to_ingress=True, after_c02=after_c02,
            enable_d09_workbench=True, enable_d04_root_cpu=True, enable_d04_semantic_drive=True,
            enable_d04_joint_numeric=after_drive is not None,
            extra_owner_purposes=("consolidation", "context") if after_drive is not None else (),
            enable_c04_body_work=after_drive is not None,
            natural_workflow_builder=appraisal_workflows)
    finally:
        if initialized.get("http_worker") is not None:
            await initialized["http_worker"].close()
