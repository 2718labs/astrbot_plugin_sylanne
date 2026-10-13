"""Permanent installed Owner task fixture, with no C02 management cause.

Root freezes and installs before executing this family. The Source-only capture
uses the actual reported input/C0/D03 projection, then stops before paid C1.
Owner Submit creates the Goal/Plan; only the installed Self task dispatcher may
create, select, prepare, execute and adopt the resulting persistent work.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
import json
from uuid import uuid4

import pytest

from test_m1_installed_artifact_draft_v1 import installed_m1_phase_fixture_v2
from m1_artifact_draft_acceptance_support_v1 import (
    cold_originals_v1, compose_actual_m1_services_v1, install_m1_owner_body_and_catalogue_v1)
from test_current_domain_production_v1 import command, domain_owner
from test_d04_owner_semantic_initialization_v3 import (
    real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock)
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d10 import LifeProject, ActivityRecipe
from sylanne3.graph_types import AtomKey, Owner, GraphVersion
from sylanne3.memory_types import SourceRecord
from sylanne3.runtime.d03_life_project_context_v1 import (
    PrepareLifeProjectContextRequestV1, life_project_context_keys_v1)
from sylanne3.runtime.domain_production_inputs_v1 import CreateCurrentLifeProjectInputRequestV1
from sylanne3.runtime.d11_life_contract_v1 import RECIPE_ID, WORK_KIND
from sylanne3.runtime.d07_life_project_focus_v1 import FocusLifeProjectRequestV1
from sylanne3.runtime.owner_source_note_task_contract_v1 import (
    SubmitOwnerSourceNoteTaskRequestV1, owner_source_note_task_ids_v1)
from sylanne3.runtime.owner_source_note_task_v1 import OPERATION, read_owner_source_note_task_authorization_v2
from sylanne3.runtime_contracts import canonical_digest


OWNER_NOTE_SOURCE_TEXT_V1 = "这是一条实际保留的原文材料：本地来源笔记记录输入、来源身份和已核验的保存结果。"


def _owner_note_unexecuted_inputs_v1(case, *, owner_material=False):
    """Actual Owner input operations; no task Goal, Plan, Action or job is supplied."""
    ns, source = case["namespace"], case["source_ref"]
    audience = "owner" if owner_material else case["ingress"].conversation_ref
    with cold_originals_v1(case) as db:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (source,)).fetchone()
        assert row is not None and row[2] == 1
        record = SourceRecord.from_dict(json.loads(row[1]))
        assert record.text == OWNER_NOTE_SOURCE_TEXT_V1
        if owner_material:
            assert record.source_kind == "authored" and record.assertion_status == "unknown"
            assert record.speaker_id == case["owner_note_session"].actor_id and record.audiences == ("owner",)
            assert set(record.purposes) == {"context","consolidation"} and not record.parent_source_ids
        else:
            assert record.source_kind == "reported" and record.speaker_id == case["ingress"].sender_ref
        assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('memory.episode.v1','memory.subjective_trace.v2')", case["namespace"].as_tuple).fetchone() == (0,)
    project = LifeProject("project:owner-source-note:" + uuid4().hex, ns,
        "Preserve the actual reported input as an installed SourceNote", "real_execution", "source_note")
    recipe = ActivityRecipe(RECIPE_ID, 1, "real_execution", ("source_note",), True)
    created = command(case, "create_life_project", CreateCurrentLifeProjectInputRequestV1(source, project, recipe),
        audience=audience, producer=True)
    persona = Owner("persona", *ns.as_tuple)
    project_ref = AtomKey(persona, "d10.life_project.v1", project.project_id).token
    recipe_ref = AtomKey(persona, "d10.activity_recipe.v1", recipe.recipe_id).token
    context = command(case, "prepare_life_project_context", PrepareLifeProjectContextRequestV1(
        project_ref, source, case["m1_owner_social_role"], case["m1_owner_norm_refs"]), audience=audience)
    assert context["coverage"] == "complete" and len(context["receipt"]["write_versions"]) == 2
    note_profile_id = case["source_note_initial_body_policy"].profile.profile_id
    artifact_profile_id = "body:m1-draft"
    assert note_profile_id != artifact_profile_id
    body_keys = tuple(AtomKey(persona, kind, profile_id).token
        for profile_id in (artifact_profile_id, note_profile_id)
        for kind in ("d02.body_profile.v1", "d02.body_state.v1"))
    with cold_originals_v1(case) as db:
        body_before = tuple(db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE token=?", (key,)).fetchone()
            for key in body_keys)
        assert all(row is not None and row[3] == 1 for row in body_before)
        assert tuple(json.loads(row[2])["profile_id"] for row in body_before) == (
            artifact_profile_id, artifact_profile_id, note_profile_id, note_profile_id)
    # This formal producer alone decides required-attention and real Body/CPU eligibility.
    # A held focus is the preserved first refusal, never a fixture permission to proceed.
    if owner_material:
        # The actual public Submit performs its validated Focus W01.
        # The fixture observes these same profiles before and after that pipeline.
        case["owner_note_body_before_public_submit"]=(body_keys,body_before)
        focus=None
    else:
        focus = command(case, "focus_life_project", FocusLifeProjectRequestV1(project_ref, source,
            case["source_note_initial_cpu_ceiling_ms"], 600), audience=audience)
        assert focus["coverage"] == "complete" and len(focus["receipt"]["write_versions"]) == 2, focus
        with cold_originals_v1(case) as db:
            assert tuple(db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE token=?", (key,)).fetchone()
                for key in body_keys) == body_before
    target, role = life_project_context_keys_v1(ns, project_ref)
    policy, effect = case["source_note_initial_body_policy"], case["source_note_initial_effect_policy"]
    with cold_originals_v1(case) as db:
        policy_row = db.execute("SELECT revision,payload_json FROM graph_d02_production_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
            (*ns.as_tuple, effect.policy_ref)).fetchone()
        assert policy_row is not None and policy_row[0] == effect.revision
        assert json.loads(policy_row[1]) == plain_v1(effect)
        grant = case["d11_issuer"].current_budget_grant(db, case["policy"].root_grant.lease_id)
        assert WORK_KIND in grant.allowed_work_kinds
    request = SubmitOwnerSourceNoteTaskRequestV1(source, project_ref, recipe_ref, target.token, role.token,
        policy.policy_id, policy.version, effect.policy_ref, min(policy.valid_until, grant.valid_until_utc))
    case.update(owner_note_input_request=request, owner_note_project_creation=created,
        owner_note_context_creation=context, owner_note_focus_creation=focus, owner_note_input_record=record)
    return request


async def create_and_acquire_installed_owner_note_task_v1(case):
    """The actual authenticated Owner Submit is the only cause of this Self job."""
    from sylanne3.runtime.owner_source_note_task_execution_v1 import (
        read_owner_source_note_task_responsibility_v2, decode_owner_source_note_task_job_v1)
    from sylanne3.runtime.jobs import get_job, _job_dict, _utc
    from sylanne3.runtime.d11_types import job_graph_write
    from sylanne3.runtime.owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2, owner_source_note_task_from_wire_v1
    auth, ids, worker = case["owner_note_authorization"], case["owner_note_ids"], case["phase_worker"]
    calls_before = tuple(case["phase_provider_calls"])
    created = await worker.call(lambda graph: graph.create_owner_source_note_task_v1(case["bootstrap"],
        case["installed_bundle"], authorization_original_ref=auth.original_ref))
    assert created["coverage"] == "complete" and created["operation_id"] == ids["create_operation_id"], created
    with cold_originals_v1(case) as db:
        initial = get_job(db, ids["job_id"])
        assert initial is not None and initial.phase == "queued" and initial.effect_id is None
        responsibility, saved_auth, original = read_owner_source_note_task_responsibility_v2(db,
            namespace=case["namespace"], original_ref=ids["responsibility_ref"], issuer=case["d11_issuer"])
        assert saved_auth == auth and original["operation_kind"] == "create_owner_source_note_task_v1"
        assert initial.activity_id == ids["activity_id"] and initial.budget_ref == auth.cause.parent_budget_lease_ref
        assert responsibility.self_entity_ref != auth.cause.owner_actor_ref
        assert decode_owner_source_note_task_job_v1(_job_dict(initial), namespace=case["namespace"]) == initial
        cont = owner_source_note_task_from_wire_v1(dict(initial.continuation), OwnerSourceNoteTaskContinuationV2)
        assert cont.step == "qualify" and cont.completed_original_refs == cont.pending_effect_refs == ()
        assert cont.responsibility_digest == responsibility.digest and cont.source_refs == auth.source_refs
        job_key = job_graph_write(initial).key
        assert original["receipt"].write_versions == (GraphVersion(job_key,1),)
    acquired = await worker.call(lambda graph: graph.acquire_owner_source_note_task_v1(case["bootstrap"],
        case["installed_bundle"], authorization_original_ref=auth.original_ref))
    assert acquired["coverage"] == "complete", acquired
    with cold_originals_v1(case) as db:
        running = get_job(db, ids["job_id"])
        assert running.phase == "running" and running.lease_holder == responsibility.self_entity_ref and running.fence == 1
        assert running.continuation == initial.continuation and running.deadline_utc == initial.deadline_utc
        assert _utc(running.lease_expires_utc,"lease").timestamp() <= auth.cause.original_deadline_utc
        head = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (job_key.token,)).fetchone()
        assert head[0] == 2 and head[2] == 1 and json.loads(head[1]) == job_graph_write(running).value
        assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('memory.episode.v1','memory.subjective_trace.v2')", case["namespace"].as_tuple).fetchone() == (0,)
    assert tuple(case["phase_provider_calls"]) == calls_before
    case.update(owner_note_task_creation=created, owner_note_task_acquisition=acquired,
        owner_note_task_responsibility=responsibility, owner_note_running_job=running)
    return running


async def run_installed_owner_source_note_task_case_v1(installation, *, after_submit):
    """One protected fresh NOTE installation; management Submit is independent."""
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    assert type(installation) is M1PhaseFixtureInstallationV2
    initialized = {}
    async def after_role(case):
        def install():
            initialize_owner_root_v3(case)
            mapping, clock = adopt_mapping_and_clock(case)
            for domain in ("d01", "d03", "d06", "d07", "d08", "d10"):
                registration = case["domain_registry"].registrations[domain]
                case["graph"].register_provider(case["bootstrap"], domain, registration.provider,
                    registration.proposal_schema, registration.proposal_schema_hash)
            install_m1_owner_body_and_catalogue_v1(case)
            assert "source_note_initial_body_policy" in case
            initialized.update(case, installed_mapping=mapping, installed_clock=clock)
        await asyncio.to_thread(install)
    async def captured(current):
        case = {**initialized, **current}
        assert "c02" not in current and not case["phase_provider_calls"]
        worker = case["phase_worker"]
        assert worker is case["phase_fixture_qualification"].worker
        assert case["installed_bundle"] is case["phase_fixture_qualification"].bundle
        await worker.call(lambda graph: compose_actual_m1_services_v1(case))
        request = await worker.call(lambda graph: _owner_note_unexecuted_inputs_v1(case))
        with cold_originals_v1(case) as db:
            assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name IN ('d08.goal.v1','d08.personal_plan.v1')", case["namespace"].as_tuple).fetchone() == (0,)
            before_jobs = tuple(db.execute("SELECT job_id,phase FROM runtime_jobs ORDER BY job_id"))
        # The other registered Body effect is real, but authorizes another work kind.
        wrong_effect = case["installed_bundle"].artifact_draft.body_policy.effect_component_policy_ref
        calls_before = tuple(case["phase_provider_calls"])
        def wrong_body_policy(graph):
            with domain_owner(case) as (authority, lease):
                held = graph.run_current_domain_operation_v1(authority, lease, operation_kind=OPERATION,
                    request=replace(request, effect_policy_ref=wrong_effect), operation_id=str(uuid4()),
                    activity_id="activity:owner-note-wrong-body", audience_ref=case["ingress"].conversation_ref,
                    parent_budget_lease_ref=case["policy"].root_grant.lease_id)
            error = graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
            assert type(error) is ValueError and "effect policy differs from its actual Body component" in str(error), repr(error)
            assert held["schema"] == "sylanne.domain-production-refusal.v1" and held["status"] == "held", held
            assert not held["job_states"] and not held["outbox"]
            return held
        wrong_body_held = await worker.call(wrong_body_policy)
        with cold_originals_v1(case) as db:
            assert tuple(db.execute("SELECT job_id,phase FROM runtime_jobs ORDER BY job_id")) == before_jobs
            assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name IN ('d08.goal.v1','d08.personal_plan.v1')", case["namespace"].as_tuple).fetchone() == (0,)
        assert tuple(case["phase_provider_calls"]) == calls_before
        submit_id = str(uuid4())
        result = await worker.call(lambda graph: command(case, OPERATION, request,
            audience=case["ingress"].conversation_ref, operation_id=submit_id))
        assert result["coverage"] == "complete", result
        ids = owner_source_note_task_ids_v1(case["namespace"], submit_id)
        with cold_originals_v1(case) as db:
            from sylanne3.runtime.d11_life_preparation_v1 import TABLE
            rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
                "AND kind='owner_source_note_task_authorization_v2' AND producing_operation_id=?",
                (*case["namespace"].as_tuple, submit_id)).fetchall()
            assert len(rows) == 1
            auth, original = read_owner_source_note_task_authorization_v2(db, namespace=case["namespace"],
                original_ref=rows[0][0], issuer=case["d11_issuer"])
            assert auth.cause.owner_operation_id == submit_id and auth.cause.owner_actor_ref == "owner-actor-reply"
            assert auth.request == request and auth.cause.request_digest == canonical_digest(request)
            assert set(original["receipt"].write_versions) == {GraphVersion(ids["goal_key"],1), GraphVersion(ids["plan_key"],1)}
            assert tuple(db.execute("SELECT job_id,phase FROM runtime_jobs ORDER BY job_id")) == before_jobs
            assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('memory.episode.v1','memory.subjective_trace.v2')", case["namespace"].as_tuple).fetchone() == (0,)
            assert 0 < auth.body_policy.cpu_ceiling_ms <= case["policy"].root_grant.max_ceiling["thread_cpu_ms"]
        assert not case["phase_provider_calls"]
        case.update(owner_note_submit=result, owner_note_authorization=auth,
            owner_note_authorization_original=original, owner_note_ids=ids, owner_note_wrong_body_held=wrong_body_held)
        await after_submit(case)
        assert not case["phase_provider_calls"]
    await real_owner_case(installation.data_dir, "owned", installed_package_root=installation.package_root,
        initial_phase_fixture_installation=installation, after_role_initialization=after_role,
        continue_to_ingress=True, after_initial_source_projection=captured,
        enable_d09_workbench=True, enable_c04_body_work=True, register_c04_domains=True,
        enable_d04_root_cpu=True, enable_d10_offline_ticks=True,
        enable_d12_package_maintenance=True, enable_c09_maintenance=True,
        extra_owner_capabilities=("workbench.control", "workbench.correct"),
        extra_owner_purposes=("context", "consolidation", "audit"), ingress_text=OWNER_NOTE_SOURCE_TEXT_V1)


def _install_owner_note_workbench_v1(case):
    from sylanne3.workbench_api.issuer import GraphWorkbenchIssuer
    from sylanne3.workbench_api.domain_registry import CurrentDomainViewRegistry
    from sylanne3.workbench_api.owner_grant import DurableOwnerGrantResolver, GraphCurrentOwnerGrantPort
    from sylanne3.workbench_api.service import AuthenticatedSession, WorkbenchService
    from sylanne3.graph_types import owner_grant_key
    graph, ns = case["graph"],case["namespace"]
    with cold_originals_v1(case) as db:
        row=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(owner_grant_key(*ns.as_tuple).token,)).fetchone()
        assert row is not None and row[1]==1
        current=json.loads(row[0])
    scope="/".join(ns.as_tuple)
    activation=graph._v2_graph_stamp(ns)[0].requirements.activation_generation
    port=GraphCurrentOwnerGrantPort(graph,case["bootstrap"],namespace=ns,activation_generation=activation,
        domains=tuple(sorted(graph._GraphCoordinator__providers)))
    resolver=DurableOwnerGrantResolver(port)
    session=AuthenticatedSession("owner-actor-reply","installed-owner-source-note:"+uuid4().hex,
        {scope:frozenset(current["capabilities"])},{scope:frozenset(current["audiences"])},
        {scope:frozenset(current["purposes"])},owner_session_token=case["owner_session_token"],
        owner_session_request=case["owner_session_request"])
    assert session.allows(scope,"workbench.create","workbench_user_action","owner")
    assert session.allows(scope,"workbench.read","workbench_view","owner")
    service=WorkbenchService(GraphWorkbenchIssuer(graph,resolver,CurrentDomainViewRegistry(lambda:case["domain_registry"])))
    refusals=[]
    original_submit=graph.submit_owner_source_note_task_v1
    def observed_submit(authority,lease,*,request,operation_id):
        try:return original_submit(authority,lease,request=request,operation_id=operation_id)
        except (RuntimeError,PermissionError) as error:
            refusals.append(error)
            raise
    graph.submit_owner_source_note_task_v1=observed_submit
    case.update(owner_note_scope=scope,owner_note_session=session,owner_note_grants=resolver,owner_note_service=service,
        owner_note_actual_submit_refusals=refusals)


def owner_note_workbench_request_v1(case,action,input_data,*,operation_id=None,session=None):
    from sylanne3.workbench_api.service import RequestContext
    purpose="workbench_view" if action.startswith("read_") else "workbench_user_action"
    with case["owner_note_grants"].request_scope():
        return case["owner_note_service"].handle({"schema_version":"d12.contract.v1","action":action,
            "scope":case["owner_note_scope"],"purpose":purpose,"audience":"owner",
            "operation_id":operation_id or str(uuid4()),"input":input_data},
            session=case["owner_note_session"] if session is None else session,context=RequestContext(True,True,True))


def _owner_note_no_execution_v1(case):
    with cold_originals_v1(case) as db:
        jobs=tuple(db.execute("SELECT job_id,phase,continuation_json,cancel_epoch FROM runtime_jobs ORDER BY job_id"))
        goals=tuple(db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name IN ('d08.goal.v1','d08.personal_plan.v1') ORDER BY token",case["namespace"].as_tuple))
        costs=tuple(db.execute("SELECT lease_id,used_json,reserved_json,unconfirmed_json FROM runtime_budget_leases ORDER BY lease_id"))
    return jobs,goals,costs,tuple(case["phase_provider_calls"])


def _admit_owner_material_v1(case,text):
    from sylanne3.runtime.owner_material_source_v1 import owner_material_source_id_v1
    from sylanne3.memory_types import source_key,access_key
    operation_id=str(uuid4());data={"request":{"text":text}}
    before=_owner_note_no_execution_v1(case)
    result=owner_note_workbench_request_v1(case,"domain_admit_owner_material_source_v1",data,operation_id=operation_id)
    assert result.status=="ready" and result.receipt["schema"]=="d12.domain-operation-receipt.v1",result.as_dict()
    original=result.receipt["original"]
    assert original["operation_id"]==operation_id and original["coverage"]=="complete"
    assert result.receipt["input_digest"]==canonical_digest(data) and result.receipt["original_digest"]==canonical_digest(original)
    assert not original["job_states"] and not original["outbox"] and len(original["receipt"]["write_versions"])==2
    source_id=owner_material_source_id_v1(case["namespace"],operation_id)
    source,access=source_key(*case["namespace"].as_tuple,source_id),access_key(*case["namespace"].as_tuple,source_id)
    with cold_originals_v1(case) as db:
        record=SourceRecord.from_dict(json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1",(source.token,)).fetchone()[0]))
        rights=json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1",(access.token,)).fetchone()[0])
    assert record.text==text and record.speaker_id==case["owner_note_session"].actor_id
    assert record.source_kind=="authored" and record.assertion_status=="unknown" and record.audiences==("owner",)
    assert set(record.purposes)==set(rights["purposes"])=={"context","consolidation"} and rights["status"]=="active"
    assert _owner_note_no_execution_v1(case)==before
    status=owner_note_workbench_request_v1(case,"read_owner_material_source_status_v1",
        {"owner_operation_id":operation_id,"input_digest":canonical_digest(data)})
    assert status.status=="ready" and status.projection["state"]=="accepted",status.as_dict()
    assert status.projection["source_ref"]==source.token and status.projection["source_revision"]==1
    return {"operation_id":operation_id,"input":data,"receipt":result.receipt,"source_ref":source.token,
        "source_id":source_id,"record":record,"status":status.projection}


def _owner_note_public_input_negatives_v1(case,request,options):
    """Different real causes; the valid task Root/lease remains unexpired throughout."""
    from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
    graph=case["graph"];ns=case["namespace"];audience="owner"
    source=request.body_source_ref;persona=Owner("persona",*ns.as_tuple)
    alternate=LifeProject("project:owner-note-other:"+uuid4().hex,ns,"Separate actual Role target","real_execution","source_note")
    recipe=ActivityRecipe(RECIPE_ID,1,"real_execution",("source_note",),True)
    command(case,"create_life_project",CreateCurrentLifeProjectInputRequestV1(source,alternate,recipe),audience=audience,producer=True)
    alternate_ref=AtomKey(persona,"d10.life_project.v1",alternate.project_id).token
    command(case,"prepare_life_project_context",PrepareLifeProjectContextRequestV1(alternate_ref,source,
        case["m1_owner_social_role"],case["m1_owner_norm_refs"]),audience=audience)
    _,alternate_role=life_project_context_keys_v1(ns,alternate_ref)
    now=options["observed_utc"]
    cases={"different_actual_role_target":replace(request,role_binding_ref=alternate_role.token),
        "different_actual_body_effect":replace(request,effect_policy_ref=case["installed_bundle"].artifact_draft.body_policy.effect_component_policy_ref),
        "expired_requested_task_deadline":replace(request,requested_deadline_utc=now)}
    negatives={}
    for name,bad in cases.items():
        before=_owner_note_no_execution_v1(case)
        refusal_count=len(case["owner_note_actual_submit_refusals"])
        refused=owner_note_workbench_request_v1(case,"domain_submit_owner_source_note_task_v1",{"request":asdict(bad)})
        assert refused.status in {"unavailable","unauthorized"},(name,refused.as_dict())
        assert len(case["owner_note_actual_submit_refusals"])==refusal_count+1,(name,refused.as_dict())
        error=case["owner_note_actual_submit_refusals"][-1]
        if name=="different_actual_body_effect":assert "effect policy differs from its actual Body component" in str(error)
        if name=="expired_requested_task_deadline":assert "actual_Owner_SourceNote_original_deadline" in str(error)
        if name=="different_actual_role_target":assert "actual_current_Owner_SourceNote_scope" in str(error)
        assert _owner_note_no_execution_v1(case)==before
        negatives[name]={"response":refused.as_dict(),"actual_refusal_type":type(error).__name__,"actual_refusal":str(error)}
    with cold_originals_v1(case) as db:
        from sylanne3.domains.d03.self_perspective import self_mapping_key
        self_actor=json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?",(self_mapping_key(ns).token,)).fetchone()[0])["self_entity_ref"]
    before=_owner_note_no_execution_v1(case)
    wrong_owner=owner_note_workbench_request_v1(case,"domain_submit_owner_source_note_task_v1",{"request":asdict(request)},
        session=replace(case["owner_note_session"],actor_id=self_actor))
    assert wrong_owner.status in {"unavailable","unauthorized"} and _owner_note_no_execution_v1(case)==before,wrong_owner.as_dict()
    negatives["actual_Self_actor_cannot_borrow_signed_Owner_session"]=wrong_owner.as_dict()
    with domain_owner(case) as (authority,lease):pass
    before=_owner_note_no_execution_v1(case)
    try:
        graph.run_current_domain_operation_v1(authority,lease,operation_kind=OPERATION,request=request,operation_id=str(uuid4()),
            activity_id="activity:owner-note-released-lease",audience_ref="owner",parent_budget_lease_ref=case["policy"].root_grant.lease_id)
    except PermissionError as error:
        negatives["released_actual_Owner_lease"]={"actual_refusal_type":type(error).__name__,"actual_refusal":str(error)}
    else:raise AssertionError("released actual Owner lease authorized task creation")
    assert _owner_note_no_execution_v1(case)==before
    wrong_source=_admit_owner_material_v1(case,"另一条真实Owner材料，仅用于验证撤回后的来源资格。")
    before=_owner_note_no_execution_v1(case)
    with domain_owner(case) as (authority,lease):
        graph.revoke_source_access_v1(authority,lease,SourceAccessRevocationRequest(wrong_source["source_id"],
            authority.actor,str(uuid4()),wrong_source["status"]["observed_utc"]))
    assert _owner_note_no_execution_v1(case)==before
    before=_owner_note_no_execution_v1(case)
    revoked=owner_note_workbench_request_v1(case,"domain_submit_owner_source_note_task_v1",
        {"request":asdict(replace(request,body_source_ref=wrong_source["source_ref"]))})
    assert revoked.status in {"unavailable","unauthorized"} and _owner_note_no_execution_v1(case)==before,revoked.as_dict()
    negatives["actual_revoked_material_Source"]=revoked.as_dict()
    eligible=owner_note_workbench_request_v1(case,"read_owner_source_note_task_options_v1",{"project_ref":request.project_ref})
    assert eligible.status=="ready" and any(item["body_source_ref"]==source for item in eligible.projection["items"]),eligible.as_dict()
    assert all(item["body_source_ref"]!=wrong_source["source_ref"] for item in eligible.projection["items"])
    case["owner_note_public_negatives"]=negatives


async def run_installed_owner_scope_source_note_case_v1(installation,*,after_acquire,include_input_negatives=True):
    """Actual Owner-scope intake/API and independently certified Self task start."""
    initialized={}
    async def after_role(case):
        def install():
            initialize_owner_root_v3(case)
            mapping,clock=adopt_mapping_and_clock(case)
            for domain in ("d01","d03","d06","d07","d08","d10"):
                registration=case["domain_registry"].registrations[domain]
                case["graph"].register_provider(case["bootstrap"],domain,registration.provider,
                    registration.proposal_schema,registration.proposal_schema_hash)
            install_m1_owner_body_and_catalogue_v1(case)
            assert "source_note_initial_body_policy" in case
            initialized.update(case,installed_mapping=mapping,installed_clock=clock)
        await asyncio.to_thread(install)
    async def after_self(current):
        case={**initialized,**current};worker=case["phase_worker"]
        assert worker is case["phase_fixture_qualification"].worker
        assert case["installed_bundle"] is case["phase_fixture_qualification"].bundle and not case["phase_provider_calls"]
        await worker.call(lambda graph:compose_actual_m1_services_v1(case))
        await worker.call(lambda graph:_install_owner_note_workbench_v1(case))
        material=await worker.call(lambda graph:_admit_owner_material_v1(case,OWNER_NOTE_SOURCE_TEXT_V1))
        case.update(source_ref=material["source_ref"],owner_note_material=material)
        request=await worker.call(lambda graph:_owner_note_unexecuted_inputs_v1(case,owner_material=True))
        options=await worker.call(lambda graph:owner_note_workbench_request_v1(case,"read_owner_source_note_task_options_v1",
            {"project_ref":request.project_ref}))
        assert options.status=="ready" and options.projection["schema"]=="d12.owner-source-note-task-options.v1",options.as_dict()
        wanted={key:value for key,value in asdict(request).items() if key not in {"project_ref","requested_deadline_utc"}}
        assert sum(item==wanted for item in options.projection["items"])==1,options.as_dict()
        request=replace(request,requested_deadline_utc=options.projection["deadline_upper_bound_utc"])
        if include_input_negatives:
            await worker.call(lambda graph:_owner_note_public_input_negatives_v1(case,request,options.projection))
        submit_id=str(uuid4());data={"request":asdict(request)}
        before=await worker.call(lambda graph:_owner_note_no_execution_v1(case))
        submit=await worker.call(lambda graph:owner_note_workbench_request_v1(case,"domain_submit_owner_source_note_task_v1",data,
            operation_id=submit_id))
        assert submit.status=="ready" and submit.receipt["input_digest"]==canonical_digest(data),submit.as_dict()
        assert submit.receipt["original"]["coverage"]=="complete" and not submit.receipt["original"]["job_states"]
        assert submit.receipt["original_digest"]==canonical_digest(submit.receipt["original"])
        ids=owner_source_note_task_ids_v1(case["namespace"],submit_id)
        with cold_originals_v1(case) as db:
            from sylanne3.runtime.d11_life_preparation_v1 import TABLE
            rows=db.execute("SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? "
                "AND kind='owner_source_note_task_authorization_v2' AND producing_operation_id=?",
                (*case["namespace"].as_tuple,submit_id)).fetchall()
            assert len(rows)==1
            auth,original=read_owner_source_note_task_authorization_v2(db,namespace=case["namespace"],original_ref=rows[0][0],issuer=case["d11_issuer"])
        after=await worker.call(lambda graph:_owner_note_no_execution_v1(case))
        assert after[0]==before[0] and after[2:]==before[2:] and len(after[1])==len(before[1])+2
        assert auth.request==request and auth.cause.audiences==("owner",) and auth.cause.owner_actor_ref==case["owner_note_session"].actor_id
        assert original["receipt"].write_versions==(GraphVersion(ids["goal_key"],1),GraphVersion(ids["plan_key"],1))
        from sylanne3.runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        focus_id="owner-note-focus:"+canonical_digest((case["namespace"],submit_id,canonical_digest({"request":plain_v1(request)})))[:40]
        with cold_originals_v1(case) as db:
            focused=read_adopted_domain_operation_v1(db,case["namespace"],focus_id)
            assert focused is not None and focused["operation_kind"]=="focus_life_project"
            assert focused["payload"]["authority"]["actor"]==auth.cause.owner_actor_ref
            assert focused["payload"]["request"]["project_ref"]==request.project_ref
            assert focused["payload"]["request"]["source_ref"]==request.body_source_ref
            assert focused["receipt"].commit_seq<original["receipt"].commit_seq
            body_keys,body_before=case["owner_note_body_before_public_submit"]
            assert tuple(db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE token=?",(key,)).fetchone()
                for key in body_keys)==body_before
        case.update(owner_note_submit=submit.receipt["original"],owner_note_authorization=auth,
            owner_note_authorization_original=original,owner_note_ids=ids,owner_note_public_input=data,owner_note_public_receipt=submit.receipt)
        async def status(expected):
            result=await worker.call(lambda graph:owner_note_workbench_request_v1(case,"read_owner_source_note_task_status_v1",
                {"owner_operation_id":submit_id,"input_digest":canonical_digest(data)}))
            assert result.status=="ready" and result.projection["state"]==expected,result.as_dict()
            return result.projection
        case["owner_note_status_before_start"]=await status("pending_start")
        conflict=await worker.call(lambda graph:owner_note_workbench_request_v1(case,"read_owner_source_note_task_status_v1",
            {"owner_operation_id":submit_id,"input_digest":canonical_digest({"request":asdict(replace(request,requested_deadline_utc=request.requested_deadline_utc-.001))})}))
        assert conflict.status=="ready" and conflict.projection["state"]=="conflict",conflict.as_dict()
        await create_and_acquire_installed_owner_note_task_v1(case)
        case["owner_note_status_running"]=await status("active")
        await after_acquire(case)
        assert not case["phase_provider_calls"]
    await real_owner_case(installation.data_dir,"owned",installed_package_root=installation.package_root,
        initial_phase_fixture_installation=installation,after_role_initialization=after_role,
        after_initial_self_registration=after_self,enable_d09_workbench=True,enable_c04_body_work=True,
        register_c04_domains=True,enable_d04_root_cpu=True,enable_d10_offline_ticks=True,
        enable_d12_package_maintenance=True,enable_c09_maintenance=True,
        extra_owner_capabilities=("workbench.control","workbench.correct"),extra_owner_purposes=("context","consolidation","audit"))


@pytest.mark.asyncio
async def test_installed_owner_source_note_public_material_full_self_task_v1(installed_m1_phase_fixture_v2):
    """Owner UI backend -> real Self -> native bytes/cost -> Goal/Plan settlement."""
    async def complete(case):
        from sylanne3.runtime.owner_source_note_task_driver_v1 import drive_owner_source_note_task_v1
        from sylanne3.authority_service.current_owner_source_note_task_v1 import read_completed_owner_source_note_task_v1
        from sylanne3.runtime.jobs import get_job
        from sylanne3.runtime.d11_types import job_graph_write
        from sylanne3.runtime.owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2,owner_source_note_task_from_wire_v1
        from sylanne3.runtime.d11_life_terminal_v1 import read_adopted_life_original_v1
        from sylanne3.runtime.d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1
        from sylanne3.runtime.d11_life_preparation_v1 import read_prepared_life_v1
        from sylanne3.runtime.d11_life_source_note_v1 import verify_durable_life_artifact_v1
        auth,worker=case["owner_note_authorization"],case["phase_worker"]
        result=await worker.call(lambda graph:drive_owner_source_note_task_v1(graph,case["bootstrap"],
            case["installed_bundle"],authorization_original_ref=auth.original_ref))
        assert result["status"]=="completed",result
        with cold_originals_v1(case) as db:
            proof=read_completed_owner_source_note_task_v1(db,namespace=case["namespace"],authorization=auth,issuer=case["d11_issuer"])
            assert proof is not None and proof.authorization_original_digest==auth.digest
            job=get_job(db,case["owner_note_ids"]["job_id"])
            cont=owner_source_note_task_from_wire_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
            assert job.phase==cont.step=="completed" and job.result_ref==proof.settlement_operation_id==result["result_ref"]
            assert job.lease_holder is None and job.lease_expires_utc is None and not cont.pending_effect_refs and cont.wait_reason is None
            assert {proof.settlement_operation_id,proof.progress_operation_id,proof.native_adoption_operation_id}<=set(cont.completed_original_refs)
            assert proof.goal_head.revision==proof.plan_head.revision==2 and proof.actual_cpu_ms>=0
            adopted=read_adopted_life_original_v1(db,namespace=case["namespace"],result_ref=proof.artifact_ref,issuer=case["d11_issuer"])
            terminal=life_from_wire_v1(adopted["terminal"],D11LifeTerminalV1)
            prepared=read_prepared_life_v1(db,binding=terminal.binding,issuer=case["d11_issuer"])
            assert prepared is not None and terminal.status=="completed" and terminal.original_ref==proof.terminal_original_ref
            data,digest,length=verify_durable_life_artifact_v1(db,prepared,digest=terminal.payload.artifact_digest,length=terminal.payload.artifact_length)
            stored=json.loads(data)
            assert stored["source_ref"]==auth.request.body_source_ref and stored["source_record"]==case["owner_note_material"]["record"].to_dict()
            assert stored["source_record"]["text"]==OWNER_NOTE_SOURCE_TEXT_V1 and length==len(data) and digest==terminal.payload.artifact_digest
            final_job_value=job_graph_write(job).value
        status=await worker.call(lambda graph:owner_note_workbench_request_v1(case,"read_owner_source_note_task_status_v1",
            {"owner_operation_id":auth.cause.owner_operation_id,"input_digest":canonical_digest(case["owner_note_public_input"])}))
        assert status.status=="ready" and status.projection["state"]==status.projection["job_phase"]=="completed",status.as_dict()
        assert status.projection["step"]=="completed" and not status.projection["pending_effect_refs"]
        # Terminal replay reads the same original task without reacquiring or executing.
        facts_before=await worker.call(lambda graph:_owner_note_no_execution_v1(case))
        replay=await worker.call(lambda graph:drive_owner_source_note_task_v1(graph,case["bootstrap"],
            case["installed_bundle"],authorization_original_ref=auth.original_ref))
        assert replay["status"]=="completed" and replay["job_id"]==job.job_id
        assert await worker.call(lambda graph:_owner_note_no_execution_v1(case))==facts_before
        with cold_originals_v1(case) as db:
            assert job_graph_write(get_job(db,job.job_id)).value==final_job_value
            assert read_completed_owner_source_note_task_v1(db,namespace=case["namespace"],authorization=auth,issuer=case["d11_issuer"])==proof
        assert not case["phase_provider_calls"]
    await run_installed_owner_scope_source_note_case_v1(installed_m1_phase_fixture_v2,after_acquire=complete)


@pytest.mark.asyncio
async def test_installed_owner_source_note_cancel_preserves_original_and_rejects_old_worker_v1(installed_m1_phase_fixture_v2):
    """Actual Owner cancel CAS drains its leased task; no Native effect is invented."""
    async def cancel(case):
        from sylanne3.runtime.cancel_owner_source_note_task_v1 import (CancelOwnerSourceNoteTaskRequestV1,
            owner_source_note_task_cancel_operation_id_v1)
        from sylanne3.runtime.owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2,owner_source_note_task_from_wire_v1
        from sylanne3.runtime.owner_source_note_task_driver_v1 import drive_owner_source_note_task_v1
        from sylanne3.runtime.jobs import get_job,_job_dict
        from sylanne3.runtime.d11_types import job_graph_write
        worker,auth=case["phase_worker"],case["owner_note_authorization"]
        before=case["owner_note_running_job"]
        facts=await worker.call(lambda graph:_owner_note_no_execution_v1(case))
        def owner_cancel(graph):
            with domain_owner(case) as (authority,lease):
                return graph.cancel_owner_source_note_task_v1(authority,lease,owner_operation_id=auth.cause.owner_operation_id)
        cancelled=await worker.call(owner_cancel)
        operation_id=owner_source_note_task_cancel_operation_id_v1(case["namespace"],auth.cause.owner_operation_id)
        assert cancelled["operation_id"]==operation_id and cancelled["coverage"]=="complete",cancelled
        with cold_originals_v1(case) as db:
            after=get_job(db,before.job_id)
            old=owner_source_note_task_from_wire_v1(dict(before.continuation),OwnerSourceNoteTaskContinuationV2)
            current=owner_source_note_task_from_wire_v1(dict(after.continuation),OwnerSourceNoteTaskContinuationV2)
            assert after.phase=="draining" and after.cancel_epoch==before.cancel_epoch+1 and after.fence==before.fence+1
            assert after.lease_holder==before.lease_holder and after.lease_expires_utc==before.lease_expires_utc
            assert after.deadline_utc==before.deadline_utc and after.budget_ref==before.budget_ref
            assert current==replace(old,cancel_generation=after.cancel_epoch)
            head=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(job_graph_write(after).key.token,)).fetchone()
            assert head[0]==3 and head[2]==1 and json.loads(head[1])==job_graph_write(after).value
            receipt=db.execute("SELECT digest,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
                "AND operation_id=? AND phase='cancel'",(*case["namespace"].as_tuple,operation_id)).fetchall()
            assert len(receipt)==1 and receipt[0][0]==canonical_digest(CancelOwnerSourceNoteTaskRequestV1(auth.cause.owner_operation_id))
            assert json.loads(receipt[0][1])==_job_dict(after)
            assert db.execute("SELECT count(*) FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? "
                "AND kind='prepared' AND json_extract(payload_json,'$.plan.activity_id')=?",
                (*case["namespace"].as_tuple,before.activity_id)).fetchone()==(0,)
        changed=await worker.call(lambda graph:_owner_note_no_execution_v1(case))
        assert changed[1:]==facts[1:]
        replay=await worker.call(owner_cancel)
        assert replay["operation_id"]==operation_id and await worker.call(lambda graph:_owner_note_no_execution_v1(case))==changed
        blocked=await worker.call(lambda graph:drive_owner_source_note_task_v1(graph,case["bootstrap"],case["installed_bundle"],
            authorization_original_ref=auth.original_ref))
        assert blocked["status"]=="draining" and await worker.call(lambda graph:_owner_note_no_execution_v1(case))==changed
        from sylanne3.runtime.owner_source_note_task_contract_v1 import CheckpointOwnerSourceNoteTaskRequestV1
        from sylanne3.runtime.owner_source_note_task_driver_v1 import run_owner_source_note_task_command_v1
        old_worker_request=CheckpointOwnerSourceNoteTaskRequestV1(job_graph_write(before).key.token,before.lease_holder,
            before.fence,replace(old,wait_reason="old_worker_after_actual_Owner_cancel"))
        def rejected_worker(graph):
            try:
                run_owner_source_note_task_command_v1(graph,case["bootstrap"],case["installed_bundle"],
                    authorization_original_ref=auth.original_ref,operation_kind="checkpoint_owner_source_note_task_v1",
                    request=old_worker_request,operation_id="owner-note-old-worker:"+uuid4().hex)
            except RuntimeError as error:
                return {"actual_refusal_type":type(error).__name__,"actual_refusal":str(error)}
            raise AssertionError("cancelled task accepted its old worker fence/generation")
        old_worker_denial=await worker.call(rejected_worker)
        assert old_worker_denial["actual_refusal"] and await worker.call(lambda graph:_owner_note_no_execution_v1(case))==changed
        status=await worker.call(lambda graph:owner_note_workbench_request_v1(case,"read_owner_source_note_task_status_v1",
            {"owner_operation_id":auth.cause.owner_operation_id,"input_digest":canonical_digest(case["owner_note_public_input"])}))
        assert status.status=="ready" and status.projection["job_phase"]=="draining" and status.projection["state"]=="draining",status.as_dict()
        assert not case["phase_provider_calls"]
    await run_installed_owner_scope_source_note_case_v1(installed_m1_phase_fixture_v2,after_acquire=cancel,include_input_negatives=False)


@pytest.mark.asyncio
async def test_installed_owner_source_note_native_lost_ack_recovers_same_original_once_v1(installed_m1_phase_fixture_v2):
    """Actual mTLS response loss leaves the frozen Parent and once Native facts intact."""
    async def unknown(case):
        from sylanne3.host.mtls_channel import AuthorityChannelUnavailable
        from sylanne3.host.mtls_transport import MtlsAuthorityTransport
        from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
        from sylanne3.runtime.owner_source_note_task_driver_v1 import drive_owner_source_note_task_v1
        from sylanne3.runtime.owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2,owner_source_note_task_from_wire_v1
        from sylanne3.runtime.d11_life_contract_v1 import D11LifeClaimV1,D11LifeTerminalV1,life_from_wire_v1
        from sylanne3.runtime.jobs import get_job
        from sylanne3.runtime.d11_types import job_graph_write
        from sylanne3.runtime.d11_life_preparation_v1 import read_prepared_life_v1
        from sylanne3.authority_service.current_owner_source_note_task_v1 import read_completed_owner_source_note_task_v1
        graph,worker,auth=case["graph"],case["phase_worker"],case["owner_note_authorization"]
        port=graph._GraphCoordinator__content_fence_v2
        transport=port._transport
        assert type(transport) is MtlsAuthorityTransport
        original_rpc=transport._rpc
        fault={"enabled":True,"execute_calls":0,"execute_response":None,"read_response":None,"first_exception":None}
        async def actual_lost_response(session,profile,method,request,handshake_binding=None,command=None,_on_dispatch=None):
            if method=="d11_life_execute_v1":fault["execute_calls"]+=1
            response=await original_rpc(session,profile,method,request,handshake_binding=handshake_binding,
                command=command,_on_dispatch=_on_dispatch)
            lose_execute=fault["enabled"] and method=="d11_life_execute_v1" and fault["execute_response"] is None
            lose_read=fault["enabled"] and method=="d11_life_original_v1" and fault["execute_response"] is not None and fault["read_response"] is None
            if lose_execute or lose_read:
                # The original RPC has completed on the genuine paired channel:
                # Core has persisted its actual claim/terminal before this finite loss.
                assert response["claim"] is not None and response["terminal"] is not None
                fault["execute_response" if lose_execute else "read_response"]=response
                session.writer.close()
                await asyncio.wait_for(session.writer.wait_closed(),profile.timeout_seconds)
                raise AuthorityChannelUnavailable("native_execute_response_lost" if lose_execute else "native_original_response_lost")
            return response
        transport._rpc=actual_lost_response
        try:
            try:
                await worker.call(lambda current:drive_owner_source_note_task_v1(current,case["bootstrap"],case["installed_bundle"],
                    authorization_original_ref=auth.original_ref))
            except (RuntimeError,TimeoutError) as error:
                fault["first_exception"]={"type":type(error).__name__,"message":str(error)}
            else:raise AssertionError("both actual Native response losses unexpectedly reported completion")
            assert fault["execute_calls"]==1 and fault["first_exception"] is not None
            first,read=fault["execute_response"],fault["read_response"]
            assert first is not None and read is not None and first["claim"]==read["claim"] and first["terminal"]==read["terminal"]
            claim=life_from_wire_v1(first["claim"],D11LifeClaimV1)
            terminal=life_from_wire_v1(first["terminal"],D11LifeTerminalV1)
            assert terminal.claim==claim and terminal.status=="completed"
            with cold_originals_v1(case) as db:
                parent=get_job(db,case["owner_note_ids"]["job_id"])
                cont=owner_source_note_task_from_wire_v1(dict(parent.continuation),OwnerSourceNoteTaskContinuationV2)
                assert parent.phase=="running" and cont.step=="prepare_life" and not cont.pending_effect_refs and cont.wait_reason is None
                head=db.execute("SELECT revision,value FROM graph_atoms WHERE token=?",(job_graph_write(parent).key.token,)).fetchone()
                prepared=read_prepared_life_v1(db,binding=terminal.binding,issuer=case["d11_issuer"])
                assert prepared is not None and prepared.binding==terminal.binding
                frozen=tuple((row.ref,row.revision) for row in prepared.read_rows)
                assert (job_graph_write(parent).key.token,head[0]) in frozen
                assert json.loads(head[1])==job_graph_write(parent).value
                assert db.execute("SELECT count(*) FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? "
                    "AND kind='adopted_life' AND json_extract(payload_json,'$.terminal.binding.effect_id')=?",
                    (*case["namespace"].as_tuple,terminal.binding.effect_id)).fetchone()==(0,)
                reservation=db.execute("SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (terminal.binding.parent_budget_lease_ref,terminal.binding.reservation_operation_id)).fetchone()
                assert reservation==("reserved",)
            pending_facts=await worker.call(lambda current:_owner_note_no_execution_v1(case))
            fault["enabled"]=False
            recovered_claim,recovered_terminal=await worker.call(lambda current:InstalledD11LifePortV1(port).read_d11_life_original_v1(binding=terminal.binding))
            assert recovered_claim==claim and recovered_terminal==terminal and fault["execute_calls"]==1
            assert await worker.call(lambda current:_owner_note_no_execution_v1(case))==pending_facts
            completed=await worker.call(lambda current:drive_owner_source_note_task_v1(current,case["bootstrap"],case["installed_bundle"],
                authorization_original_ref=auth.original_ref))
            assert completed["status"]=="completed" and fault["execute_calls"]==1,completed
            with cold_originals_v1(case) as db:
                proof=read_completed_owner_source_note_task_v1(db,namespace=case["namespace"],authorization=auth,issuer=case["d11_issuer"])
                assert proof is not None and proof.terminal_original_ref==terminal.original_ref and proof.actual_cpu_ms==terminal.actual_cpu_ms
                assert get_job(db,parent.job_id).phase=="completed"
                assert db.execute("SELECT count(*) FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? "
                    "AND kind='adopted_life' AND json_extract(payload_json,'$.terminal.binding.effect_id')=?",
                    (*case["namespace"].as_tuple,terminal.binding.effect_id)).fetchone()==(1,)
            assert not case["phase_provider_calls"]
        finally:
            transport._rpc=original_rpc
    await run_installed_owner_scope_source_note_case_v1(installed_m1_phase_fixture_v2,after_acquire=unknown,include_input_negatives=False)


@pytest.mark.asyncio
async def test_installed_owner_source_note_artifact_io_failure_keeps_actual_cpu_once_v1(installed_m1_phase_fixture_v2):
    """Real generation/timing precedes one ENOSPC; production signs and settles failure."""
    async def known_failed(case):
        import errno
        from unittest.mock import patch
        from sylanne3.runtime import d11_life_source_note_v1 as artifact_store
        from sylanne3.runtime.owner_source_note_task_driver_v1 import drive_owner_source_note_task_v1
        from sylanne3.runtime.owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2,owner_source_note_task_from_wire_v1
        from sylanne3.runtime.d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1,life_adoption_operation_id_v1
        from sylanne3.runtime.d11_life_terminal_v1 import read_adopted_life_original_v1
        from sylanne3.runtime.d11_types import job_graph_write
        from sylanne3.runtime.jobs import get_job
        worker,auth=case["phase_worker"],case["owner_note_authorization"]
        calls=[]
        def actual_writer_io_fault(db,prepared,data):
            assert db.in_transaction and type(data) is bytes
            assert prepared.binding.activity_id==case["owner_note_ids"]["activity_id"]
            assert json.loads(data)["source_record"]==case["owner_note_material"]["record"].to_dict()
            assert not calls
            calls.append({"prepared":prepared,"generated_bytes":data})
            raise OSError(errno.ENOSPC,"finite actual SourceNote artifact storage fault")
        with patch.object(artifact_store,"write_life_artifact_stage_v1",actual_writer_io_fault):
            result=await worker.call(lambda graph:drive_owner_source_note_task_v1(graph,case["bootstrap"],case["installed_bundle"],
                authorization_original_ref=auth.original_ref))
        assert result["status"]=="failed" and len(calls)==1,result
        prepared=calls[0]["prepared"]
        with cold_originals_v1(case) as db:
            adopted=read_adopted_life_original_v1(db,namespace=case["namespace"],result_ref=prepared.binding.artifact_ref,issuer=case["d11_issuer"])
            assert adopted is not None
            terminal=life_from_wire_v1(adopted["terminal"],D11LifeTerminalV1)
            assert terminal.status=="failed" and terminal.binding==prepared.binding and terminal.actual_cpu_ms>=0
            assert terminal.payload.reason_code=="artifact_stage_failed" and terminal.payload.artifact_ref is None
            assert terminal.payload.artifact_digest is None and terminal.payload.artifact_length is None
            parent=get_job(db,case["owner_note_ids"]["job_id"])
            cont=owner_source_note_task_from_wire_v1(dict(parent.continuation),OwnerSourceNoteTaskContinuationV2)
            adoption_id=life_adoption_operation_id_v1(terminal.binding)
            assert parent.phase=="failed" and parent.result_ref==adoption_id and cont.step=="prepare_life"
            assert parent.lease_holder is None and parent.lease_expires_utc is None and not cont.pending_effect_refs and cont.wait_reason is None
            assert adoption_id in cont.completed_original_refs and parent.cancel_epoch==cont.cancel_generation==0
            for key in (case["owner_note_ids"]["goal_key"],case["owner_note_ids"]["plan_key"]):
                row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(key.token,)).fetchone()
                assert row is not None and row[0]==1 and row[2]==1
                expected={write["key"]:write["value"] for write in case["owner_note_authorization_original"]["payload"]["writes"]}
                assert json.loads(row[1])==expected[key.token]
            assert db.execute("SELECT count(*) FROM graph_atoms WHERE token=?",(prepared.binding.artifact_ref,)).fetchone()==(0,)
            assert db.execute("SELECT count(*) FROM "+artifact_store.STAGE_TABLE+" WHERE bot=? AND persona=? AND execution_id=?",
                (*case["namespace"].as_tuple,prepared.binding.execution_id)).fetchone()==(0,)
            reservation=db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (prepared.binding.parent_budget_lease_ref,prepared.binding.reservation_operation_id)).fetchone()
            assert reservation is not None and reservation[0]=="settled"
            assert json.loads(reservation[1])==({"thread_cpu_ms":terminal.actual_cpu_ms} if terminal.actual_cpu_ms else {})
            actual_parent=job_graph_write(parent).value
        status=await worker.call(lambda graph:owner_note_workbench_request_v1(case,"read_owner_source_note_task_status_v1",
            {"owner_operation_id":auth.cause.owner_operation_id,"input_digest":canonical_digest(case["owner_note_public_input"])}))
        assert status.status=="ready" and status.projection["state"]==status.projection["job_phase"]=="failed",status.as_dict()
        facts=await worker.call(lambda graph:_owner_note_no_execution_v1(case))
        replay=await worker.call(lambda graph:drive_owner_source_note_task_v1(graph,case["bootstrap"],case["installed_bundle"],
            authorization_original_ref=auth.original_ref))
        assert replay["status"]=="failed" and len(calls)==1 and await worker.call(lambda graph:_owner_note_no_execution_v1(case))==facts
        with cold_originals_v1(case) as db:
            assert job_graph_write(get_job(db,parent.job_id)).value==actual_parent
            assert read_adopted_life_original_v1(db,namespace=case["namespace"],result_ref=prepared.binding.artifact_ref,issuer=case["d11_issuer"])==adopted
        assert not case["phase_provider_calls"]
    await run_installed_owner_scope_source_note_case_v1(installed_m1_phase_fixture_v2,after_acquire=known_failed,include_input_negatives=False)
