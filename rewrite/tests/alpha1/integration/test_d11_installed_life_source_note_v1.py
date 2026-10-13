"""Permanent installed Owner source-note work and exact final-ACK recovery.

Run with SYLANNE_D04_INSTALLED_ROOT pointing at an immutable installed package.
Root Action, Body quote, plan, CPU reserve, actual executor and both adoption
bundles use their real product producers. Only a returned finish ACK is lost.
"""
from __future__ import annotations

import asyncio
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import sys
import time
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_d04_owner_semantic_initialization_v3 import (
    installed_d04_root, real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock, current_owner,
)
from test_current_domain_production_v1 import command, domain_owner
from d11_offline_authority_acceptance_support_v1 import install_actual_offline_authority_case_v1
from sylanne3.authority_service.d11_life_service_v1 import AuthorityD11LifeServiceV1
from sylanne3.authority_service.d11_life_journal_v1 import ENTRY_PREFIX, decode_life_row_v1
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d02 import BodyProfile, BodyState, WorkComponent
from sylanne3.domains.d02.body_quote_original import FixedBodyPolicyV1
from sylanne3.domains.d08.execution import Goal, GoalPredicate, _decode_intent
from sylanne3.domains.d08.production_operations_v1 import observed_action_outcome_key_v1
from sylanne3.domains.d10 import LifeProject, ActivityRecipe
from sylanne3.domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
from sylanne3.host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
from sylanne3.host.v2_fence_port import V2FenceOutcomeUnknown
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.d02_production_operations_v1 import SettledBodyEffectPolicyV1
from sylanne3.runtime.d02_life_body_preparation_v1 import (
    PrepareSourceNoteBodyRequestV1, life_body_preparation_original_from_wire_v1,
)
from sylanne3.runtime.d03_life_project_context_v1 import (
    PrepareLifeProjectContextRequestV1, life_project_context_keys_v1,
)
from sylanne3.runtime.d07_life_project_focus_v1 import FocusLifeProjectRequestV1
from sylanne3.runtime.d08_source_note_action_v1 import (
    PrepareSourceNoteActionRequestV1, source_note_effect_id_v1, require_source_note_action_original_v1,
)
from sylanne3.runtime.d11_life_contract_v1 import (
    WORK_KIND, RECIPE_ID, POSTCONDITION_ID, LifeInputRefV1, LifeBodyComponentContractV1,
    RegisteredLifePlanV2, RegisteredLifeOutcomeV2, life_artifact_ref_v1,
)
from sylanne3.runtime.d11_life_preparation_v1 import (
    PrepareCurrentLifeRequestV1, _read, read_prepared_life_by_ref_v1, life_ids_v1,
)
from sylanne3.runtime.d11_life_adoption_v1 import adopt_current_life_v1
from sylanne3.runtime.d11_life_graph_types_v1 import life_role_segment_key_v1
from sylanne3.runtime.d11_life_source_note_v1 import verify_durable_life_artifact_v1
from sylanne3.runtime.d11_types import runtime_cost_settlement_key
from sylanne3.runtime.d10_life_outcome_v2 import life_experience_source_id_v1
from sylanne3.runtime.domain_production_inputs_v1 import (
    InstallCurrentBodyInputRequestV1, InstallCurrentBodyEffectInputRequestV1,
    CreateCurrentLifeProjectInputRequestV1, CreateCurrentGoalInputRequestV1,
    RegisterCurrentLifePlanInputRequestV2, RegisterCurrentLifeOutcomeInputRequestV2,
)
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


def _installed_life_service(case, *, register_host_process=True):
    _, owner_service, _ = install_actual_offline_authority_case_v1(case, register_host_process=register_host_process)
    graph, server = case["graph"], case["server"]
    bridge = server._v2_execution[case["authority_namespace"]]
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    if case.get('c09_daemon') is not None:
        service=server._d11_life_services_v1[case['authority_namespace']]
        assert type(service) is AuthorityD11LifeServiceV1 and service.bridge is bridge
        assert case['c09_daemon'].server is server and case['c09_daemon'].core is case['core']
        return service
    service = AuthorityD11LifeServiceV1(bridge=bridge, owner_tickets=server._v2_owner_tickets,
        namespace=case["namespace"], installation_id=case["policy"].installation_id,
        manifest_digest=case["manifest_digest"], graph_db_path=owner_service.graph_path,
        issuer=case["d11_issuer"], resource_issuer=case["d02_issuer"], credential=case["peer"],
        signing_key=hmac.new(bundle.d11_signing_key, b"sylanne.authority.d11-life-signing.v1", hashlib.sha256).digest(),
        trusted_now_utc=time.time, owner_service=owner_service, package_root=case["package_root"],
        body_quote_authority=graph._GraphCoordinator__body_quote_authority)
    assert case["authority_namespace"] not in server._d11_life_services_v1
    server._d11_life_services_v1[case["authority_namespace"]] = service
    case["core"].install_execution_redaction_d11_life_service_v1(case["authority_namespace"], service)
    # Keep the actual RPC and its sanitized response; retain the chained
    # internal exception in this permanent installed-product acceptance log.
    import functools
    import traceback
    original_command = server._v2_command
    @functools.wraps(original_command)
    def diagnosed_command(method, *args, **kwargs):
        try:
            return original_command(method, *args, **kwargs)
        except Exception:
            if method.startswith("d11_life_"):
                traceback.print_exc()
            raise
    server._v2_command = diagnosed_command
    return service


def _head(case, ref):
    with case["store"]._lock:
        revision, value, valid = case["store"]._db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
    assert valid == 1
    return revision, json.loads(value)


def _input(case, ref):
    revision, value = _head(case, ref)
    return LifeInputRefV1(ref, revision, canonical_digest(value))


def _cold_artifact(case, prepared, terminal):
    with case["store"]._lock:
        path = Path(case["store"]._db.execute("PRAGMA database_list").fetchone()[2])
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        return verify_durable_life_artifact_v1(db, prepared,
            digest=terminal.payload.artifact_digest, length=terminal.payload.artifact_length)
    finally:
        db.rollback()
        db.close()


def _life_rows(service, binding):
    journal = service.bridge.journal
    with journal.freeze_writes():
        _, rows = journal._scan_locked()
        return tuple(row for row in rows if row[4].startswith(ENTRY_PREFIX) and decode_life_row_v1(journal, row)[0] == binding)


def _prepare_owner_context_and_focus(case, *, project_ref, source_ref, audience):
    graph, store, ns = case["graph"], case["store"], case["namespace"]
    with store._lock:
        rows = store._db.execute("SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.role_binding' ORDER BY token LIMIT 129", ns.as_tuple).fetchall()
    assert len(rows) <= 128, "Context adoption requires the complete current RoleBinding inventory"
    bindings = tuple(json.loads(value) for value, valid in rows if valid and json.loads(value)["status"] == "active")
    roles = tuple(sorted({"project_worker", *(binding["social_role"] for binding in bindings)}))
    norms = tuple(sorted({norm for binding in bindings for norm in binding["norm_refs"]}))
    if "initial_context_catalogue" in case:
        catalogue = case["initial_context_catalogue"]
        # Initial root compilation preserved this exact formally accepted field.
        # The following production Context preparation independently qualifies
        # its current adopted candidate, Owner, Source and role inventory.
        from sylanne3.domains.d03.context import ContextProvider
        from sylanne3.domains.d12.types import character_draft_key
        from sylanne3.runtime.d12_domain_scheme_compile_v1 import CONTEXT_SCHEME_FIELD
        expected = ContextProvider().compile_scheme(
            {"schema": "d03.context.scheme.v1", "roles": roles, "norms": norms}, None)
        assert _head(case, character_draft_key(ns).token)[1]["fields"][CONTEXT_SCHEME_FIELD] == json.loads(canonical_serialize(expected))
    else:
        with domain_owner(case) as (authority, lease):
            catalogue = graph.adopt_current_context_catalogue_v1(authority, lease, operation_id=str(uuid4()),
                roles=roles, norms=norms, budget_ref=case["policy"].root_grant.lease_id)
    assert catalogue["graph_receipt"]["status"] == "committed"
    assert catalogue["compatibility"]["status"] == "compatible_static_catalogue"
    assert tuple(catalogue["compatibility"]["roles"]) == roles
    assert tuple(catalogue["compatibility"]["norms"]) == norms
    context = command(case, "prepare_life_project_context", PrepareLifeProjectContextRequestV1(
        project_ref, source_ref, "project_worker", ()), audience=audience)
    assert context["coverage"] == "complete" and len(context["receipt"]["write_versions"]) == 2
    focus = command(case, "focus_life_project", FocusLifeProjectRequestV1(project_ref, source_ref, 100, 600), audience=audience)
    assert focus["coverage"] == "complete" and len(focus["receipt"]["write_versions"]) == 2


async def run_installed_owner_life_case(tmp_path, installed_d04_root, *,
        natural_workflow_builder=None, after_episode_async=None, enable_c09_maintenance=False, life_before_root_operation_id=None,
        enable_d04_semantic_drive=False, enable_d04_joint_numeric=False,
        host_process_runner=None,c09_protected_root=None,initial_phase_fixture_installation=None,
        complete_c09_current_v3=False,c09_phase_setup_file=None):
    initialized = {}

    async def after_role(case):
        initialized.update(case)
        def install():
            initial_context = None
            if enable_d04_joint_numeric:
                registration = case["domain_registry"].registrations["d03"]
                case["graph"].register_provider(case["bootstrap"], "d03", registration.provider,
                    registration.proposal_schema, registration.proposal_schema_hash)
                def initial_context():
                    with domain_owner(case) as (authority, lease):
                        accepted = case["graph"].adopt_current_context_catalogue_v1(authority, lease,
                            operation_id=str(uuid4()), roles=("project_worker", "scene_participant"),
                            norms=(), budget_ref=case["policy"].root_grant.lease_id)
                    assert accepted["graph_receipt"]["status"] == "committed"
                    catalogue = accepted["compatibility"]
                    case["graph"]._GraphCoordinator__providers["d03"][0].compile_scheme(
                        {"schema": "d03.context.scheme.v1", "roles": tuple(catalogue["roles"]), "norms": tuple(catalogue["norms"])}, None)
                    case["initial_context_catalogue"] = accepted
            initialize_owner_root_v3(case, root_operation_id=life_before_root_operation_id,
                before_root_compile=initial_context)
            if life_before_root_operation_id is not None:
                graph = case["graph"]
                graph.install_life_before_capture_policy_v1(case["bootstrap"],
                    graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle)
            if enable_d04_joint_numeric:
                with current_owner(case) as (authority, lease):
                    topology = case["graph"].adopt_current_d04_root_coupling_v3(
                        authority, lease, operation_id=str(uuid4()),
                        root_operation_id=case["root_operation_id"], effective_until=86400.0)
                assert topology["edge_count"] == 48
                case["topology"] = topology
            mapping, clock = adopt_mapping_and_clock(case)
            case.update(installed_mapping=mapping, installed_clock=clock)
            for domain in ("d10",):
                registration = case["domain_registry"].registrations[domain]
                case["graph"].register_provider(case["bootstrap"], domain, registration.provider,
                    registration.proposal_schema, registration.proposal_schema_hash)
            if complete_c09_current_v3:
                from m1_artifact_draft_acceptance_support_v1 import install_m1_owner_body_and_catalogue_v1
                from d11_offline_authority_acceptance_support_v1 import install_phase_fixture_recall_owner_policies_v1
                for domain in ('d01','d03','d06','d07','d08'):
                    registration=case['domain_registry'].registrations[domain]
                    case['graph'].register_provider(case['bootstrap'],domain,registration.provider,
                        registration.proposal_schema,registration.proposal_schema_hash)
                install_m1_owner_body_and_catalogue_v1(case)
                install_phase_fixture_recall_owner_policies_v1(case)
            initialized["life_service"] = _installed_life_service(case)
            if complete_c09_current_v3:
                from c09_life_authority_phase_support_v1 import persist_life_cold_fixture_v1
                daemon=case['c09_daemon'];factory=daemon.config.c09_maintenance_factory;control=daemon.c09_control
                case['c09_cold_fixture']=persist_life_cold_fixture_v1(control.key_path.parent/'life-cold-installation.json',
                    core=daemon.core,control=control,namespace=case['namespace'],peer=case['peer'],
                    subject=case['client_grant'].subject,holder=case['policy'].administrator_holder,
                    package_root=case['package_root'],manifest_digest=case['manifest_digest'],inventory=factory.inventory,
                    target_directory=factory.target_directory,runtime_issuer_signing_key=case['installed_bundle'].d11_signing_key,
                    admin_d02_signing_key=case['installed_bundle'].d02_signing_key,provider_cache=case['c09_provider_cache'],
                    deployment_config=daemon.config,phase_setup_file=case['c09_phase_setup_file'])

            initialized.update(case)
        await asyncio.to_thread(install)

    async def after_c02(current):
        case = {**initialized, **current}
        def accept():
            graph, store, ns = case["graph"], case["store"], case["namespace"]
            audience = case["ingress"].conversation_ref
            source_ref = case["source_ref"]
            _, input_source = _head(case, source_ref)
            assert {"context", "consolidation"} <= set(input_source["purposes"])
            cpu_ceiling_ms = 100
            profile = BodyProfile("body:source-note", ns, 1, ("energy", "fatigue", "load"), (WORK_KIND,))
            state = BodyState(profile.profile_id, 1, .8, {WORK_KIND: .1}, .1, 0.0)
            component = WorkComponent("source-note-body", "body-energy", .02, 0.0)
            policy = FixedBodyPolicyV1("body-policy:source-note", 1, profile, state, WORK_KIND, component, time.time() + 3600)
            command(case, "initialize_body", InstallCurrentBodyInputRequestV1(policy), producer=True)
            effect_policy = SettledBodyEffectPolicyV1("body-effect:source-note", 1, ns, profile.profile_id,
                WORK_KIND, component.component_id, .01, .005)
            command(case, "install_body_effect_policy", InstallCurrentBodyEffectInputRequestV1(effect_policy), producer=True)
            project = LifeProject("project:source-note", ns, "Preserve this reported Source as a digital note", "real_execution", "source_note")
            recipe = ActivityRecipe(RECIPE_ID, 1, "real_execution", ("source_note",), True)
            command(case, "create_life_project", CreateCurrentLifeProjectInputRequestV1(source_ref, project, recipe), audience=audience, producer=True)
            persona = Owner("persona", *ns.as_tuple)
            project_ref = AtomKey(persona, "d10.life_project.v1", project.project_id).token
            recipe_ref = AtomKey(persona, "d10.activity_recipe.v1", recipe.recipe_id).token
            # The actual context catalogue and project focus are adopted by the
            # installed Owner entry points before the root Action can exist.
            _prepare_owner_context_and_focus(case, project_ref=project_ref, source_ref=source_ref, audience=audience)
            entity_key, role_key = life_project_context_keys_v1(ns, project_ref)
            build = read_installed_d11_life_build_v1(case["package_root"], case["manifest_digest"])
            root_operation = str(uuid4())
            activity = "activity:source-note-product"
            effect = source_note_effect_id_v1(ns, project_ref, root_operation)
            artifact_ref = life_artifact_ref_v1(ns, effect)
            predicate = GoalPredicate("artifact_verified", POSTCONDITION_ID,
                (("artifact_ref", artifact_ref), ("input_digest", canonical_digest(input_source)),
                    ("build_digest", build["postcondition_build_digest"])), 0.0, None)
            goal = Goal("goal:source-note", 1, "active", predicate, (source_ref,), (), None, (), ())
            command(case, "create_goal", CreateCurrentGoalInputRequestV1(source_ref, goal), audience=audience, producer=True)
            goal_ref = AtomKey(Owner("activity", *ns.as_tuple, "activity:domain-acceptance"), "d08.goal.v1", goal.goal_id).token
            root_receipt = command(case, "prepare_source_note_action", PrepareSourceNoteActionRequestV1(
                project_ref, recipe_ref, source_ref, goal_ref, entity_key.token, role_key.token),
                audience=audience, activity_id=activity, operation_id=root_operation)
            assert len(root_receipt["receipt"]["write_versions"]) == 3
            with store._lock:
                db = store._db
                action_ref = db.execute("SELECT json_extract(payload_json,'$.action_intent_ref') FROM graph_d11_life_originals_v1 "
                    "WHERE bot=? AND persona=? AND kind='source_note_action' AND producing_operation_id=?", (*ns.as_tuple, root_operation)).fetchone()[0]
                root = require_source_note_action_original_v1(db, namespace=ns, action_intent_ref=action_ref, issuer=case["d11_issuer"])
            assert root.schema == "d08.source-note-action-original.v2" and root.target_entity_ref == entity_key.token
            action = _decode_intent(_head(case, action_ref)[1])
            assert action.identity.operation_id == root_operation and action.identity.effect_id == effect
            body_operation = "d02-life-body:" + root_operation
            body_receipt = command(case, "prepare_source_note_body", PrepareSourceNoteBodyRequestV1(action_ref,
                policy.policy_id, policy.version, effect_policy.policy_ref, cpu_ceiling_ms), audience=audience,
                activity_id=activity, operation_id=body_operation)
            assert len(body_receipt["receipt"]["write_versions"]) == 1
            with store._lock:
                body_raw, producing_operation = _read(store._db, issuer=case["d11_issuer"], namespace=ns,
                    kind="life_body_preparation", ref="life-body:" + body_operation)
            body = life_body_preparation_original_from_wire_v1(body_raw)
            assert producing_operation == body_operation and body.action_operation_id == root_operation
            contract = LifeBodyComponentContractV1(**{f.name: getattr(body, f.name) for f in fields(LifeBodyComponentContractV1) if f.name != "schema"})
            plan = RegisteredLifePlanV2(_input(case, project_ref), _input(case, recipe_ref), _input(case, action_ref),
                _input(case, source_ref), _input(case, access_key(*ns.as_tuple, AtomKey.from_token(source_ref).owner.subject).token),
                action.identity.activity_id, action.identity.effect_id, action.identity.attempt_id, root_operation, (audience,),
                case["policy"].root_grant.lease_id, cpu_ceiling_ms,
                (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                build["algorithm_build_digest"], build["postcondition_build_digest"], canonical_serialize(plain_v1(contract)))
            plan_ref = "life-plan:source-note-product"
            command(case, "register_life_plan_v2", RegisterCurrentLifePlanInputRequestV2(plan_ref, plan),
                producer=True, audience=audience, activity_id=activity)
            prepare_operation = "d11-life-prepare:" + root_operation
            prepared_receipt = command(case, "prepare_life", PrepareCurrentLifeRequestV1(plan_ref, prepare_operation),
                audience=audience, operation_id=prepare_operation, activity_id=activity)
            assert prepared_receipt["operation_id"] == prepare_operation
            ids = life_ids_v1(plan)
            with store._lock:
                prepared = read_prepared_life_by_ref_v1(store._db, namespace=ns, prepared_original_ref=ids["prepared"], issuer=case["d11_issuer"])
                assert get_job(store._db, prepared.binding.job_id).phase == "running"
                assert store._db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (prepared.binding.parent_budget_lease_ref, prepared.binding.reservation_operation_id)).fetchone() == ("reserved", None)
            assert prepared.binding.operation_id == root_operation and prepared.binding.prepare_operation_id == prepare_operation
            assert prepared.admission_ref and prepared.admission_digest
            life_port = InstalledD11LifePortV1(graph._GraphCoordinator__content_fence_v2)
            claim, terminal = life_port.execute_d11_life_v1(binding=prepared.binding)
            assert terminal.status == "completed" and terminal.claim == claim and 0 <= terminal.actual_cpu_ms <= cpu_ceiling_ms
            assert life_port.read_d11_life_original_v1(binding=prepared.binding) == (claim, terminal)
            data, digest, length = _cold_artifact(case, prepared, terminal)
            assert hashlib.sha256(data).hexdigest() == digest and len(data) == length
            assert json.loads(data)["source_record"] == input_source
            before_rows = _life_rows(case["life_service"], prepared.binding)
            assert len(before_rows) == 2
            actual_finish = InstalledD11LifePortV1.life_adoption_bridge_v1
            lost = []
            def finish_then_lose_ack(port, **kwargs):
                result = actual_finish(port, **kwargs)
                if kwargs["action"] == "finish" and kwargs.get("outcome") == "committed" and not lost:
                    lost.append(True)
                    raise V2FenceOutcomeUnknown("actual finish committed, returned ACK lost")
                return result
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(InstalledD11LifePortV1, "life_adoption_bridge_v1", finish_then_lose_ack)
                with pytest.raises(V2FenceOutcomeUnknown, match="actual finish committed"):
                    adopt_current_life_v1(graph, case["bootstrap"], namespace=ns, prepared_original_ref=ids["prepared"])
            adopted = adopt_current_life_v1(graph, case["bootstrap"], namespace=ns, prepared_original_ref=ids["prepared"])
            assert lost == [True] and adopted["status"] == "completed" and adopted["actual_cpu_ms"] == terminal.actual_cpu_ms
            assert adopt_current_life_v1(graph, case["bootstrap"], namespace=ns, prepared_original_ref=ids["prepared"]) == adopted
            assert _life_rows(case["life_service"], prepared.binding) == before_rows
            outcome_key = observed_action_outcome_key_v1(AtomKey.from_token(action_ref), action)
            cost_ref = runtime_cost_settlement_key(*ns.as_tuple, activity, prepared.binding.reservation_operation_id).token
            members = (artifact_ref, outcome_key.token, cost_ref,
                life_role_segment_key_v1(prepared.binding, "start").token, life_role_segment_key_v1(prepared.binding, "end").token,
                AtomKey(Owner("activity", *ns.as_tuple, activity), "runtime.job", prepared.binding.job_id).token)
            with store._lock:
                db = store._db
                assert {db.execute("SELECT event_id FROM graph_history WHERE token=? ORDER BY revision DESC LIMIT 1", (ref,)).fetchone()[0]
                    for ref in members} == {adopted["operation_id"]}
                job = get_job(db, prepared.binding.job_id)
                from sylanne3.runtime.d11_life_terminal_v1 import read_adopted_life_original_v1
                signed_result = read_adopted_life_original_v1(db, namespace=ns, result_ref=artifact_ref,
                    issuer=graph._GraphCoordinator__d11_issuer)
                assert signed_result["schema"] == "d11.adopted-life-original.v4"
                assert signed_result["result_ref"] == artifact_ref
                assert job.phase == "completed" and job.result_ref == signed_result["job_result_binding"]["result_ref"]
                assert len(job.result_ref) == 80 and job.usage == {"thread_cpu_ms": terminal.actual_cpu_ms}
                settlement_state, actual_json = db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (prepared.binding.parent_budget_lease_ref, prepared.binding.reservation_operation_id)).fetchone()
                assert settlement_state == "settled" and json.loads(actual_json) == {"thread_cpu_ms": terminal.actual_cpu_ms}
                assert db.execute("SELECT count(*) FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
                    (*ns.as_tuple, prepared.binding.reservation_operation_id)).fetchone() == (1,)
            outcome_value = _head(case, outcome_key.token)[1]
            assert outcome_value["result_level"] == "completed_verified" and outcome_value["completed_effects"] == [effect]
            outcome = RegisteredLifeOutcomeV2(plan_ref, outcome_key.token, claim.original_ref, terminal.original_ref, artifact_ref, digest, (cost_ref,))
            outcome_ref = "life-outcome:source-note-product"
            command(case, "register_life_outcome_v2", RegisterCurrentLifeOutcomeInputRequestV2(outcome_ref, outcome),
                producer=True, audience=audience, activity_id=activity)
            progress_receipt = command(case, "advance_life", AdvanceCurrentLifeRequestV1(project_ref, outcome_ref),
                audience=audience, activity_id=activity)
            assert progress_receipt["coverage"] == "complete"
            experience_id = life_experience_source_id_v1(prepared.binding)
            experience_ref = source_key(*ns.as_tuple, experience_id).token
            experience = _head(case, experience_ref)[1]
            assert experience["source_kind"] == "internal" and experience["assertion_status"] == "confirmed"
            assert experience["purposes"] == ["context", "consolidation"] and "expression" not in experience["purposes"]
            facts = json.loads(experience["text"])
            assert facts["artifact_digest"] == digest and facts["actual_cpu_ms"] == terminal.actual_cpu_ms
            assert facts["start_original_ref"] == claim.original_ref and facts["terminal_original_ref"] == terminal.original_ref
            after_state = _head(case, AtomKey(persona, "d02.body_state.v1", profile.profile_id).token)[1]
            assert after_state["energy"] == pytest.approx(state.energy - component.fixed_cost)
            assert after_state["fatigue"][WORK_KIND] == pytest.approx(state.fatigue[WORK_KIND] + effect_policy.fatigue_increase)
            assert _head(case, source_ref)[1] == input_source
            progress_ref = AtomKey(Owner("activity", *ns.as_tuple, activity), "d10.life_progress.v1", effect).token
            with store._lock:
                db = store._db
                assert {db.execute("SELECT event_id FROM graph_history WHERE token=? ORDER BY revision DESC LIMIT 1", (ref,)).fetchone()[0]
                    for ref in (progress_ref, body.settlement_ref, experience_ref, access_key(*ns.as_tuple, experience_id).token)} == {progress_receipt["operation_id"]}
            from sylanne3.domains.d06.structured_experience_v1 import (
                EncodeCurrentStructuredExperienceRequestV1, structured_experience_output_keys_v1,
            )
            structured = command(case, "encode_structured_experience",
                EncodeCurrentStructuredExperienceRequestV1(progress_receipt["operation_id"], experience_ref),
                audience=audience, activity_id=activity)
            assert structured["coverage"] == "partial"
            from sylanne3.runtime.d06_internal_life_episode_v2 import (
                internal_life_episode_keys_v2, decode_internal_life_value_v2,
                PROVENANCE, validate_internal_life_episode_history_v2,
            )
            event_key, episode_key, proof_key, eligibility_key = internal_life_episode_keys_v2(ns, experience_ref)
            event = _head(case, event_key.token)[1]
            assert event['reality'] == 'internal_life' and event['assertion_scope'] == 'activity_occurred_only'
            assert event['activity']['source_ref'] == experience_ref
            assert event['activity']['artifact_ref'] == prepared.binding.artifact_ref
            assert event['activity']['terminal_original_ref'] == terminal.original_ref
            assert event['activity']['body_settlement_ref'] == body.settlement_ref
            assert event['activity']['actual_cpu_ms'] == terminal.actual_cpu_ms
            assert event['causal_operation_id'] == progress_receipt['operation_id']
            assert _head(case, episode_key.token)[1]["source_refs"] == [experience_ref]
            assert _head(case, eligibility_key.token)[1]['episode_ref'] == episode_key.token
            with store._lock:
                db = store._db
                db.execute('BEGIN')
                try:
                    proof = decode_internal_life_value_v2(PROVENANCE, _head(case, proof_key.token)[1])
                    original = validate_internal_life_episode_history_v2(db, proof)
                    assert original['receipt'].operation_id == structured['operation_id']
                    assert {v.key for v in original['receipt'].write_versions} == {event_key,episode_key,proof_key,eligibility_key}
                    assert db.execute('SELECT 1 FROM graph_atoms WHERE token=?',
                        (structured_experience_output_keys_v1(ns,experience_ref)[0].token,)).fetchone() is None
                    from sylanne3.runtime.c09_graph_rebase_candidate_v1 import (
                        _validate_internal_life_episode_history_inventory_v2,GraphRebaseHold,
                    )
                    _validate_internal_life_episode_history_inventory_v2(db)
                    # Actual historical originals must be present and exact;
                    # a closed DTO with a self-consistent digest is insufficient.
                    frozen=next(row for row in proof.historical_reads if row.ref==experience_ref)
                    db.execute('UPDATE graph_history SET value=? WHERE token=? AND revision=?',
                        ('{}',frozen.ref,frozen.revision))
                    with pytest.raises(GraphRebaseHold,match='historical production original'):
                        _validate_internal_life_episode_history_inventory_v2(db)
                finally:
                    db.execute('ROLLBACK')
            return {**case,'episode_ref':episode_key.token,'life_activity_id':activity,
                'life_causal_operation_id':progress_receipt['operation_id'],'life_audience':audience,
                'life_source_execution_id':prepared.binding.execution_id}
        completed=await asyncio.to_thread(accept)
        # No await or second worker entry occurs while the synchronous Life
        # acceptance holds the actual graph lock/SQL transaction.
        if after_episode_async is not None:
            await after_episode_async(completed)

    # This service shares the actual scoped C09 installation with the offline
    # service. Run its authorized migrations before the first Owner/business
    # write, so recovery and the selected four stores use the same mode.
    await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
        natural_workflow_builder=natural_workflow_builder,initial_phase_fixture_installation=initial_phase_fixture_installation,
        complete_c09_current_v3=complete_c09_current_v3,c09_phase_setup_file=c09_phase_setup_file,
        after_role_initialization=after_role, continue_to_ingress=True, after_c02=after_c02,
        enable_d09_workbench=True, enable_d04_root_cpu=True, enable_c04_body_work=True,
        enable_d10_offline_ticks=True, enable_d11_life_source_note=True,
        enable_c09_maintenance=enable_c09_maintenance,
        host_process_runner=host_process_runner, c09_protected_root=c09_protected_root,
        life_before_root_operation_id=life_before_root_operation_id,
        enable_d04_semantic_drive=enable_d04_semantic_drive,
        enable_d04_joint_numeric=enable_d04_joint_numeric,
        extra_owner_purposes=("context", "consolidation"))


@pytest.mark.asyncio
async def test_installed_owner_source_note_once_execution_body_progress_and_final_ack(tmp_path,installed_d04_root):
    await run_installed_owner_life_case(tmp_path,installed_d04_root)
