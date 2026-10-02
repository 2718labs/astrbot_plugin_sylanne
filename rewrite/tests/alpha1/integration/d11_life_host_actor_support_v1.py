"""Pure fresh-Host installed Life actor; original Authority stays in parent.

The process wrapper owns admission and actual exit. This driver constructs no
Authority service and returns only four completed-content locators after its
fresh Host graph, TLS clients, model fixture and reverse listener have closed.
"""
from __future__ import annotations
import asyncio
from contextlib import closing, contextmanager
from dataclasses import asdict, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import httpx
import json
import sqlite3
import time
import traceback
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4
import pytest
from astrbot.api.star import Context
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from astrbot.core.provider.entities import ProviderType
from openai import AsyncOpenAI
from c09_life_host_bootstrap_v1 import open_life_host_bootstrap_v1
from c09_life_host_process_support_v1 import HostInstallationCaseV1
from sylanne3.domains.d01 import PersonaBlock, PersonaPlan
from sylanne3.domains.d03 import ContextProvider, RoleBindingRequest, RoleBindingResolution
from sylanne3.domains.d04.authored_lineage_v3 import AuthoredRootBlockInputV3, RootAuthoredFacetV3
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.host.installed_d04_root_resources import load_installed_d04_root_preset_v3
from sylanne3.runtime.d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
from sylanne3.runtime_contracts import FenceScope, QueryEpoch
from sylanne3.graph_coordinator import IngressHostFacts, IngressLineage, first_ingress_encoding_acquire_operation_id
from sylanne3.host.authority_profile import (AdminIngressClockPolicy, AdminIngressEncodingPolicy,
    AdminD06PrivateReplySourcePolicy, AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
    AdminD04EncodingBaselinePolicy, AdminD06FirstIngressC02Policy)
from sylanne3.host.installed_model_capability import InstalledModelCapabilityPort
from sylanne3.host.self_identity_current_port import InstalledCurrentSelfIdentityPort
from sylanne3.host.worker_result_read_fact_port import InstalledWorkerResultReadFactPort
from sylanne3.host.worker_result_identity import first_ingress_worker_result_request_v1
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.installed_scene_identity import InstalledSceneIdentityPort
from sylanne3.host.scene_candidates import SceneCandidateCatalog
from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
from sylanne3.model_broker.first_ingress_encoding import issue_first_ingress_encoding_request_v2
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.workbench_api.d01_onboarding import VerifiedCreationResources, VerifiedModelCapability, VerifiedBudgetLease
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
from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
from sylanne3.runtime.internal_life_model_call_v2 import internal_life_model_draft_v2,seal_internal_life_model_call_v2
from sylanne3.runtime.internal_life_content_worker_v2 import TABLE,read_life_worker_original_v2
from sylanne3.runtime.internal_life_content_preparation_v1 import read_committed_internal_life_prepared_v1
from sylanne3.model_broker.internal_life_content_v1 import OUTPUT_SCHEMA,WORK_KIND as CONTENT_WORK_KIND,thaw_internal_life_content_request_v1
from sylanne3.runtime_contracts import AuthorityContext,canonical_digest
from sylanne3.host.authority_client import AuthorityClient,AuthoritySelection
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.model_broker.broker import ModelProviderDescriptor
from sylanne3.runtime.model_cost_settlement import read_original_model_cost,OriginalModelCostCommitV1
from sylanne3.authority_service.v2_model_egress_contract import ModelTerminalReceiptV2

@contextmanager
def domain_owner(case):
    graph = case["graph"]
    authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply",
        namespace=case["namespace"], domains=tuple(domain for domain in
            ("d01", "d02", "d03", "d05", "d06", "d07", "d08", "d10", "d11", "d12") if domain in graph._GraphCoordinator__providers),
        purpose="workbench_user_action", audience="owner", activation_generation=1,
        owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
    try:
        yield authority, lease
    finally:
        graph.release_current_owner_lease(case["bootstrap"], lease)

def command(case, kind, request, *, audience="owner", operation_id=None, activity_id="activity:domain-acceptance", producer=False):
    graph = case["graph"]
    with domain_owner(case) as (authority, lease):
        method = graph.register_current_domain_input_v1 if producer else graph.run_current_domain_operation_v1
        receipt = method(authority, lease, **{"producer_kind" if producer else "operation_kind": kind},
            request=request, operation_id=operation_id or str(uuid4()), activity_id=activity_id,
            audience_ref=audience, parent_budget_lease_ref=case["policy"].root_grant.lease_id)
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    assert receipt["schema"] == "sylanne.domain-production-receipt.v1", repr(
        getattr(runtime, "_last_refusal_exception_v1", receipt))
    assert receipt["receipt"]["status"] == "committed"
    assert receipt["receipt"]["operation_id"] == receipt["operation_id"]
    with case["store"]._lock:
        db = case["store"]._db
        row = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*case["namespace"].as_tuple, receipt["operation_id"])).fetchone()
        assert row == (receipt["receipt"]["operation_digest"], receipt["receipt"]["commit_seq"])
        assert db.execute("SELECT original_digest FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",
            (*case["namespace"].as_tuple, receipt["operation_id"])).fetchone() == (receipt["original_digest"],)
    return receipt

@contextmanager
def current_owner(case):
    graph = case["graph"]
    authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply",
        namespace=case["namespace"], domains=("d02", "d04", "d11", "d12"),
        purpose="workbench_user_action", audience="owner", activation_generation=1,
        owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
    try:
        yield authority, lease
    finally:
        graph.release_current_owner_lease(case["bootstrap"], lease)

@contextmanager
def current_mapping_read(case):
    """Actual installed Authority fence and the production reader transaction."""
    graph, store, port, ns = case["graph"], case["store"], case["port"], case["namespace"]
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(ns)
    anchor = port.current_anchor(namespace=ns, authority_namespace=case["authority_namespace"])
    operation = "d04-owner-acceptance-read:" + str(uuid4())
    permit = port.begin_fence(namespace=ns, authority_namespace=case["authority_namespace"],
        holder=case["policy"].administrator_holder, generation=1, operation="read", operation_id=operation,
        expected_anchor=anchor)
    scope = FenceScope(ns, case["authority_namespace"], 1, "read", operation, permit, anchor, epoch, metadata.graph_revision)
    try:
        with case["mapping_reader"].current_fence(scope):
            with store._lock:
                store._db.execute("BEGIN")
                try:
                    yield store._db
                finally:
                    store._db.rollback()
    finally:
        port.finish_fence(scope, request_id="finish:" + operation,
            request_digest="sha256:" + canonical_digest((operation, permit.token)))

def initialize_owner_root_v3(case, *, root_operation_id=None):
    """Use only real Owner draft, signed D11 budget, compile and root adoption."""
    graph, ns = case["graph"], case["namespace"]
    reader = case["mapping_reader"]
    preset = load_installed_d04_root_preset_v3(case["package_root"], case["manifest_digest"])
    blocks = tuple(AuthoredRootBlockInputV3(
        RootAuthoredFacetV3("owner-block:" + str(index), template.template_id, template.kind,
                           "owner-facet:" + str(index)), preset.axes, (0.5,) * 24,
        ((0.5, 0.5),) * 24, "owner-initial-box:" + str(index))
        for index, template in enumerate(preset.block_templates))
    field = {"candidate_id": "owner-authored-initial", "cursor": 0.0,
             "preset_digest": preset.digest, "asset_digest": preset.assets.digest,
             "blocks": json.loads(json.dumps([asdict(block) for block in blocks]))}
    with current_owner(case) as (authority, lease):
        graph.initialize_current_d04_root_draft_v3(authority, lease,
            operation_id=str(uuid4()), root_field=field)
        budget = graph.allocate_current_d04_root_budget_v3(authority, lease,
            operation_id=str(uuid4()), parent_budget_lease_ref=case["policy"].root_grant.lease_id,
            ceiling={"thread_cpu_ms": 60000})
        compiled = graph.compile_current_scheme_for_operation_v1(authority, lease,
            operation_id=str(uuid4()), draft_ref=character_draft_key(ns).token,
            budget_ref=case["policy"].root_grant.lease_id)
        root_operation = str(uuid4()) if root_operation_id is None else root_operation_id
        graph.commit_current_d04_authored_root_v3(authority, lease, operation_id=root_operation,
            compiled_digest=compiled.compiled.compiled_digest, parent_budget_lease_ref=budget["lease_id"], preset=preset)
        original = graph.read_current_d04_authored_root_v3(authority, lease, operation_id=root_operation)
        assert original.operation_id == root_operation
    case["root_operation_id"] = root_operation
    case["root_original"] = original
    return reader

def adopt_mapping_and_clock(case, *, role_clock_rate="1"):
    reader, graph, namespace = case["mapping_reader"], case["graph"], case["namespace"]
    profile = reader.profile()
    with current_mapping_read(case) as db:
        with pytest.raises(ValueError, match="explicit current Owner acceptance"):
            reader(db, namespace)
    with current_owner(case) as (authority, lease):
        operation = str(uuid4())
        accepted = reader.adopt_current(authority, lease, operation_id=operation,
            profile_digest=profile.profile_digest, expected_revision=0)
        assert accepted["acceptance_revision"] == 1
        assert reader.adopt_current(authority, lease, operation_id=operation,
            profile_digest=profile.profile_digest, expected_revision=0) == accepted
        with pytest.raises(ValueError, match="different immutable request"):
            reader.adopt_current(authority, lease, operation_id=operation,
                profile_digest=profile.profile_digest, expected_revision=1)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        request = {"operation_id": str(uuid4()), "expected_version": 0,
            "character_origin": "0", "rate": role_clock_rate, "wall_origin_utc": now.isoformat().replace("+00:00", "Z"),
            "valid_from_utc": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "valid_until_utc": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z")}
        clock = reader.register_current_role_clock(authority, lease, **request)
        assert reader.register_current_role_clock(authority, lease, **request) == clock
        assert clock["mapping_version"] == 1
        with pytest.raises(ValueError, match="different immutable request"):
            reader.register_current_role_clock(authority, lease, **{**request, "rate": "2" if role_clock_rate != "2" else "3"})
    with current_mapping_read(case) as db:
        mapping = reader(db, namespace)
        assert mapping.acceptance_digest == accepted["acceptance_digest"]
        assert sorted(share for _, share in mapping.block_shares) == [0.25, 0.25, 0.5]
        assert len(mapping.block_shares) == 3
        assert reader.current_role_condition(db, namespace).role_ref == mapping.asset.role_ref
        from sylanne3.domains.d01 import _activation_key
        activation = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?",
            (_activation_key(namespace).token,)).fetchone()[0])
        assert mapping.asset.role_ref == activation["head_id"]
        installed_clock = read_current_role_clock_installation_v1(reader, db, namespace)
        assert reader.current_role_clock_identity(db, namespace) == (installed_clock.mapping_id, 1)
    case.update(mapping_acceptance=accepted, clock_acceptance=clock)
    return mapping, installed_clock

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

def _prepare_owner_context_and_focus(case, *, project_ref, source_ref, audience):
    graph, store, ns = case["graph"], case["store"], case["namespace"]
    with store._lock:
        rows = store._db.execute("SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.role_binding' ORDER BY token LIMIT 129", ns.as_tuple).fetchall()
    assert len(rows) <= 128, "Context adoption requires the complete current RoleBinding inventory"
    bindings = tuple(json.loads(value) for value, valid in rows if valid and json.loads(value)["status"] == "active")
    roles = tuple(sorted({"project_worker", *(binding["social_role"] for binding in bindings)}))
    norms = tuple(sorted({norm for binding in bindings for norm in binding["norm_refs"]}))
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

def _run_source_note_and_episode(case):
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
        finally:
            db.execute('ROLLBACK')
    return {**case,'episode_ref':episode_key.token,'life_activity_id':activity,
        'life_causal_operation_id':progress_receipt['operation_id'],'life_audience':audience}

def _prepare_and_acquire_content(case):
    from sylanne3.model_broker.internal_life_content_v1 import internal_life_content_ids_for_occurrence_v1
    from sylanne3.runtime.internal_life_content_preparation_v1 import PrepareInternalLifeContentRequestV1
    from sylanne3.runtime.d06_internal_life_episode_v2 import PROVENANCE,decode_internal_life_value_v2
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
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as cold:
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
    from sylanne3.runtime.internal_life_content_worker_v2 import (
        AcquireInternalLifeContentRequestV2,read_committed_internal_life_request_v2)
    acquire_kind='acquire_internal_life_content_v2'
    locator=AcquireInternalLifeContentRequestV2(case['episode_ref'],case['life_causal_operation_id'])
    try:
        acquired=command(case,acquire_kind,locator,operation_id=ids['acquire'],
            activity_id=case['life_activity_id'],audience=case['life_audience'])
    except Exception:
        error=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
        if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
        raise
    assert acquired['coverage']=='deferred' and acquired['job_states']==[[ids['job'],'running']]
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as cold:
        cold.execute('PRAGMA query_only=ON');cold.execute('BEGIN')
        durable=read_committed_internal_life_request_v2(cold,namespace=ns,
            issuer=case['d11_issuer'],job_id=ids['job'])
        actual,binding,model=durable
        job=get_job(cold,ids['job'])
        assert actual==prepared and job.phase=='running' and job.fence==1
        assert model.identity.phase=='internal_life_content_v2' and model.call_id==ids['call']
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
    table='graph_internal_life_worker_originals_v2'
    assert store._db.execute('SELECT count(*) FROM '+table+' WHERE kind=?',
        ('request',)).fetchone()==(1,)
    assert store._db.execute('SELECT count(*) FROM '+table+' WHERE kind=?',
        ('acquire_commit',)).fetchone()==(1,)

def _register_installed_domains(case, domains):
    graph=case['graph']
    for domain in domains:
        registration=case['domain_registry'].registrations[domain]
        expected=(registration.provider,registration.proposal_schema,registration.proposal_schema_hash)
        existing=graph._GraphCoordinator__providers.get(domain)
        if existing is not None:
            assert existing==expected
            continue
        graph.register_provider(case['bootstrap'],domain,*expected)


async def _bind_scene_and_ingress(case):
    graph,graph_store,bootstrap,namespace,port,policy=(case[k] for k in
        ('graph','store','bootstrap','namespace','port','policy'))
    principal=case['owner_session_request'].principal
    owner_guard_token=case['owner_session_token'];owner_guard_request=case['owner_session_request']
    source_id=case['ingress_clock'].source_id
    ingress_text='hello'
    adapter = AiocqhttpAdapter(
        {"id": "platform-1", "ws_reverse_host": "127.0.0.1",
         "ws_reverse_port": 6199}, {}, asyncio.Queue())
    adapter.bot.call_action = AsyncMock(return_value={"user_id": "10001"})
    host_context = Context(
        asyncio.Queue(), {}, None, None,
        SimpleNamespace(platform_insts=[adapter]), None, None, None,
        SimpleNamespace(get_conf=lambda umo: {}), None, None)
    host_context.conversation_manager = _Conversations()
    host_context.persona_manager = _Personas()
    host_context.persona_manager.selected = "persona-reply"
    observed = SceneCandidateCatalog()
    ingress_utc = time.time()
    ingress = HostIngressEnvelope(
        namespace, '["platform-1","aiocqhttp","10001"]',
        '["platform-1:FriendMessage:123456","conversation-1"]',
        '["platform-1","user-1"]', "message:reply", ingress_text,
        ingress_utc, ingress_utc + 0.001, "private",
        SourceLineage("a" * 64, "reported", "onebot",
                      "external_report", "reported_claim"))
    candidate_scene = observed.observe(ingress)
    assert candidate_scene is not None
    scene_port = InstalledSceneIdentityPort(
        context=host_context, host_loop=asyncio.get_running_loop(),
        candidates=observed)
    verified_scene = await asyncio.to_thread(
        scene_port.verify, namespace, candidate_scene.scene_ref, "private")
    assert verified_scene is not None
    graph._GraphCoordinator__scene_identity_port = scene_port
    graph._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
        source_id, 0.5, 2.0)
    d03 = ContextProvider()
    d03.compile_scheme({
        "schema": "d03.context.scheme.v1",
        "roles": ("scene_participant",), "norms": (),
    }, None)
    graph.register_provider(
        bootstrap, "d03", d03, "d03.proposal.v1",
        d03.descriptor.request_schema_hash)
    with graph_store._lock:
        _, scene_epoch = graph._v2_graph_stamp(namespace)
    binding_request = RoleBindingRequest(
        f"persona:{namespace.persona_id}", None, None,
        verified_scene.scene_ref, "bind_scene",
        "workbench_user_action", 2.0, True)
    prior = RoleBindingResolution(
        "no_applicable_binding", (), (), (), (),
        QueryEpoch(namespace, "d03.role_binding", scene_epoch.revision),
        None, binding_request)
    scene_receipt = await asyncio.to_thread(
        graph.commit_scene_binding_v2,
        namespace=namespace, operation_id="scene-bind-reply",
        scene=verified_scene, prior=prior, principal=principal,
        actor_id="owner-actor-reply",
        request_digest="sha256:" + canonical_digest({
            "scene": verified_scene.scene_ref}),
        owner_session_token=owner_guard_token,
        owner_session_request=owner_guard_request)
    assert scene_receipt.operation_id == "scene-bind-reply"
    _register_installed_domains(case,("d04","d05","d06","d07","d08","d09","d11","d12","d02"))
    host=IngressHostFacts(namespace,ingress.platform_ref,ingress.conversation_ref,
        ingress.sender_ref,ingress.message_id,ingress.text,ingress.occurred_at,
        ingress.learned_at,ingress.visibility,IngressLineage('a'*64,'reported','onebot',
        'external_report','reported_claim','not_applicable'))
    case.update(ingress=ingress, host=host)
    return host,ingress

async def _run_first_ingress(case):
    graph,graph_store,bootstrap,namespace,port,policy,authority_client,client_grant=(case[k] for k in
        ('graph','store','bootstrap','namespace','port','policy','authority_client','client_grant'))
    installed_bundle=case['installed_bundle'];ingress_clock=case['ingress_clock']
    encoding=installed_bundle.ingress_encoding
    encoding_workflow=installed_bundle.model_workflows.encode
    model_context=case['model_context'];conversation_ref=case['ingress'].conversation_ref
    host=case['host'];current_anchor=await asyncio.to_thread(port.current_anchor,
        namespace=namespace,authority_namespace=case['authority_namespace'])
    first_ingress = await asyncio.to_thread(
        graph.commit_first_ingress_v2, bootstrap, host, policy,
        ingress_clock, encoding,
        AdminD06PrivateReplySourcePolicy(
            1, "private_conversation", True))
    assert first_ingress.status == "committed"
    arrival = await asyncio.to_thread(
        graph.commit_d03_message_arrival_v2, bootstrap, namespace,
        host.lineage.source_ref, policy,
        AdminD03ArrivalPolicy(
            30.0, {"cpu_ms": 3}, "snapshot:reply-arrival",
            "resource:reply-arrival"), ingress_clock)
    assert arrival.status == "committed"
    with graph_store._lock:
        job_id, ingress_operation_id = graph_store._db.execute(
            "SELECT job_id,operation_id FROM runtime_jobs WHERE operation_id=?",
            (first_ingress.operation_id,),
        ).fetchone()
    projection = await asyncio.to_thread(
        graph.commit_d03_self_identity_projection_v1,
        bootstrap, namespace, job_id, ingress_operation_id,
        policy, AdminD03SelfIdentityProjectionPolicy(
            30.0, {"cpu_ms": 4}, "snapshot:reply-projection",
            "resource:reply-projection"), ingress_clock)
    assert projection.status == "committed"
    baseline = await asyncio.to_thread(
        graph.commit_d04_encoding_baseline_v1,
        bootstrap, namespace, job_id, ingress_operation_id,
        policy, AdminD04EncodingBaselinePolicy(
            30.0, {"cpu_ms": 2}, "snapshot:reply-baseline",
            "resource:reply-baseline"), ingress_clock)
    assert baseline.status == "committed"
    acquire_operation_id = first_ingress_encoding_acquire_operation_id(
        namespace, job_id, ingress_operation_id, client_grant.subject,
        current_anchor.activation_generation, "a" * 32)
    worker_lease, worker_capability = graph.grant(
        bootstrap, actor=client_grant.subject, issuer_domain="d11",
        namespace=namespace, domains=("d11",),
        activation_generation=current_anchor.activation_generation,
        operation_id=acquire_operation_id)
    worker_authority = AuthorityContext(
        client_grant.subject, "d11", worker_capability, namespace,
        ("activity",), encoding_workflow.purpose, (conversation_ref,),
        encoding_workflow.provider_config_ref,
        current_anchor.activation_generation)
    try:
        acquired = await asyncio.to_thread(
            graph.acquire_first_ingress_encoding_job_v3,
            worker_authority, worker_lease, job_id,
            acquire_operation_id, lease_seconds=30)
        assert acquired.job_id == job_id
        worker_authority = replace(worker_authority, worker_fence=acquired.fence)
        model_preparation = await asyncio.to_thread(
            graph.read_first_ingress_model_egress_preparation_v2,
            worker_authority, worker_lease, job_id,
            acquire_operation_id)
        assert model_preparation[1].job_id == job_id
        binding, draft, model_anchor = model_preparation
        installed_adapter = AstrBotModelProvider(
            context=model_context, host_loop=asyncio.get_running_loop(),
            trusted_umo="platform-1:FriendMessage:123456",
            descriptor=ModelProviderDescriptor(
                encoding_workflow.provider_id, "astrbot-openai-official-v1", encoding_workflow.model_id,
                frozenset({"text"}), frozenset({"consolidation"}),
                frozenset({"private"}), encoding_workflow.provider_config_ref,
                "unknown", False, False),
            admin_model=encoding_workflow,
            installation_bundle=installed_bundle)
        model_executor = HostModelEgressExecutor(
            authority=authority_client, bundle=installed_bundle,
            grant=client_grant, adapter=installed_adapter)
        frozen_request = model_executor._frozen_encoding_request(
            binding, draft, model_anchor)
        assert frozen_request.call_id == binding.call_id
        model_prepared, _ = await authority_client.model_prepare_fenced_v1(
            installed_bundle, client_grant, draft=draft,
            expected_anchor=model_anchor)
        assert model_prepared.state == "prepared"
        terminal = await model_executor.execute_once(
            intent=model_prepared.intent, expected_anchor=model_anchor,
            request=frozen_request)
        assert terminal is not None
        graph._GraphCoordinator__model_terminal_cost_port = (
            InstalledModelTerminalCostPort(
                client=authority_client, bundle=installed_bundle,
                grant=client_grant, owner_loop=asyncio.get_running_loop()))
        graph._GraphCoordinator__accounting_maintenance_port = (
            InstalledAccountingMaintenancePort(
                client=authority_client, bundle=installed_bundle,
                grant=client_grant, owner_loop=asyncio.get_running_loop()))
        with graph_store._lock:
            original_job = get_job(graph_store._db, job_id)
        quote_id, quote_version = original_job.operator_versions[
            "resource_quote"].rsplit(":", 1)
        cost = await asyncio.to_thread(
            graph.commit_first_ingress_model_cost_v1,
            bootstrap, namespace, model_prepared.intent,
            quote_id=quote_id, quote_version=int(quote_version))
        assert cost.status == "committed"
        with graph_store._lock:
            settled_state = graph_store._db.execute(
                "SELECT state FROM runtime_budget_reservations WHERE lease_id=? "
                "AND operation_id=?",
                (original_job.budget_ref, original_job.operation_id)).fetchone()
            settle_operation = graph_store._db.execute(
                "SELECT phase FROM runtime_budget_operations WHERE bot_id=? "
                "AND persona_id=? AND operation_id=? AND phase='settle'",
                namespace.as_tuple + (original_job.operation_id,)).fetchone()
        assert (settled_state, settle_operation) == (("settled",), ("settle",))
        original_context = await asyncio.to_thread(
            graph.read_first_ingress_original_model_result_context_v1,
            worker_authority, worker_lease, job_id, acquire_operation_id)
        worker_read = await model_executor.read_original_for_worker(
            read_request=first_ingress_worker_result_request_v1(original_context),
            intent=model_prepared.intent, terminal=terminal)
        assert worker_read is not None
        graph._GraphCoordinator__worker_result_fact_port = (
            InstalledWorkerResultReadFactPort(
                client=authority_client, bundle=installed_bundle,
                grant=client_grant, owner_loop=asyncio.get_running_loop()))
        c02 = await asyncio.to_thread(
            graph.commit_first_ingress_c02_v2,
            bootstrap, model_prepared.intent, worker_read, policy,
            AdminD06FirstIngressC02Policy(
                30.0, {"cpu_ms": 2}, "snapshot:reply-c02",
                "resource:reply-c02"), ingress_clock)
        assert c02.status == "committed"
    finally:
        graph.release_authority_lease(bootstrap, worker_lease)
    return first_ingress, c02


async def _complete_content(case):
    from sylanne3.runtime.internal_life_content_worker_v2 import read_committed_internal_life_request_v2
    graph,store,ns,policy,port,issuer=(case[k] for k in
        ('graph','store','namespace','policy','port','d11_issuer'))
    bundle=case['installed_bundle'];installed_d04_root=case['package_root'];tmp_path=case['data_dir']
    with store._lock:
        path=Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve()
    readers=InstalledD06StructuredExperienceReadersV1(issuer=issuer,resource_issuer=issuer.resource_issuer,
        body_quote_authority=graph._GraphCoordinator__body_quote_authority)
    def draft_read():
        with store._lock:
            store._db.execute('BEGIN')
            try:
                rows=store._db.execute(f"SELECT job_id FROM {TABLE} WHERE bot=? AND persona=? AND kind='binding'",ns.as_tuple).fetchall()
                assert len(rows)==1
                job=rows[0][0]
                prepared=read_committed_internal_life_prepared_v1(store._db,namespace=ns,issuer=issuer,job_id=job)
                metadata,_=graph._v2_graph_stamp(ns)
            finally:store._db.rollback()
        authority=AuthorityContext(port.installation_grant.subject,'d11','life-content-read:'+prepared.digest,
            ns,('activity','event','persona','scene'),'consolidation',(case['life_audience'],),
            prepared.provider_config_ref,metadata.requirements.activation_generation)
        def observe(scope):
            actual,permit=port.get_current_owner_guard_for_fence(namespace=ns,
                authority_namespace=policy.authority_namespace,permit=scope.permit)
            assert permit==scope.permit
            return actual,permit
        def read():
            store._db.execute('BEGIN')
            try:
                metadata,epoch=graph._v2_graph_stamp(ns)
                return internal_life_model_draft_v2(store._db,namespace=ns,issuer=issuer,job_id=job,
                    metadata=metadata,epoch=epoch)
            finally:store._db.rollback()
        value,anchor,_,_=graph._read_v2(authority,read,fence_observer=observe,return_recovery_context=True)
        return (*value,anchor)
    prepared,binding,request,draft,anchor=await asyncio.to_thread(draft_read)
    frozen=thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json))
    case['model_reply_mode']['content']=json.dumps({'schema':OUTPUT_SCHEMA,
        'occurrence_digest':frozen.input.occurrence_digest,'summary':'The internal activity completed.',
        'keywords':['internal activity']})
    transport=MtlsAuthorityTransport({bundle.tls_profile.profile_id:bundle.tls_profile})
    mock=None;actual_handler=None
    try:
        client=AuthorityClient(AuthoritySelection(bundle.tls_profile.profile_id),package_root=installed_d04_root,
            data_dir=tmp_path,transport=transport)
        workflow=bundle.model_workflows.life_content
        descriptor=ModelProviderDescriptor(workflow.provider_id,'astrbot-openai-official-v1',workflow.model_id,
            frozenset({'text'}),frozenset({workflow.purpose}),frozenset({workflow.privacy_tier}),
            workflow.provider_config_ref,'unknown',False,False)
        adapter=AstrBotModelProvider(context=case['model_context'],host_loop=asyncio.get_running_loop(),
            trusted_umo=json.loads(case['life_audience'])[0],descriptor=descriptor,admin_model=workflow,installation_bundle=bundle)
        mock=case['model_http_client']._transport;actual_handler=mock.handler;calls=[]
        def counted(req):calls.append(req.url.host);return actual_handler(req)
        mock.handler=counted
        assert (await client.status_v2()).state=='paired'
        actual_grant=await client.installation_grant_v2()
        from sylanne3.host.installation_grant_identity import same_installed_grant_identity_v2
        assert same_installed_grant_identity_v2(case['client_grant'],actual_grant)
        executor=HostModelEgressExecutor(authority=client,bundle=bundle,grant=actual_grant,adapter=adapter)
        record,permit=await client.model_prepare_fenced_v1(bundle,actual_grant,draft=draft,expected_anchor=anchor)
        intent=record.intent
        assert record.state=='prepared'
        def seal():
            actual,state=port.get_fence_operation(namespace=ns,authority_namespace=policy.authority_namespace,
                operation_id=intent.operation_id)
            assert actual==permit and state=='active'
            with store._lock:
                db=store._db;db.execute('BEGIN IMMEDIATE')
                try:
                    metadata,epoch=graph._v2_graph_stamp(ns)
                    seal_internal_life_model_call_v2(db,namespace=ns,issuer=issuer,job_id=prepared.job_id,
                        intent=intent,permit=permit,metadata=metadata,epoch=epoch)
                    db.commit()
                except BaseException:db.rollback();raise
        await asyncio.to_thread(seal)
        terminal=await executor.execute_once(intent=intent,expected_anchor=anchor,request=request)
        assert type(terminal) is ModelTerminalReceiptV2 and len(calls)==1
        assert (terminal.call_id,terminal.request_digest,terminal.installation_id)==(
            prepared.call_id,request.digest,prepared.installation_id)
        # The donor's original channel may have retired while actual Life
        # execution ran. Re-authenticate that client through the installed
        # APIs and bind its cost port to the newly issued channel grant.
        from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
        from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
        donor=case['authority_client']
        assert (await donor.status_v2()).state=='paired'
        donor_grant=await donor.installation_grant_v2()
        assert same_installed_grant_identity_v2(case['client_grant'],donor_grant)
        graph._GraphCoordinator__model_terminal_cost_port=InstalledModelTerminalCostPort(
            client=donor,bundle=case['installed_bundle'],grant=donor_grant,
            owner_loop=asyncio.get_running_loop())
        graph._GraphCoordinator__accounting_maintenance_port=InstalledAccountingMaintenancePort(
            client=donor,bundle=case['installed_bundle'],grant=donor_grant,
            owner_loop=asyncio.get_running_loop())
        def settle():
            fact=read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port,intent)
            result=graph._commit_original_model_cost_v1(case['bootstrap'],ns,intent,
                quote_id=prepared.quote_id,quote_version=prepared.quote_version,work_kind=CONTENT_WORK_KIND)
            assert type(result) is OriginalModelCostCommitV1
            return result
        cost=await asyncio.to_thread(settle)
        assert cost.call_id==prepared.call_id
        def ledger():
            return tuple(store._db.execute('SELECT phase,digest,receipt_json FROM runtime_budget_operations '
                'WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase',(*ns.as_tuple,prepared.prepare_operation_id)))
        before=await asyncio.to_thread(ledger)
        assert [r[0] for r in before]==['reserve','settle']
        assert await executor.recover_original_terminal(intent)==terminal and len(calls)==1
        again=await asyncio.to_thread(settle)
        assert again.commit_seq==cost.commit_seq and await asyncio.to_thread(ledger)==before
        assert len(calls)==1
        from sylanne3.runtime.internal_life_paid_result_v2 import (prepare_life_result_selector_v2,
            record_life_paid_original_v2,read_life_paid_original_v2,read_life_cost_commit_v2)
        from sylanne3.authority_service.internal_life_model_result_contract_v2 import internal_life_result_to_wire_v2
        from sylanne3.runtime.internal_life_content_adoption_v1 import (AdoptInternalLifeContentRequestV1,
            OPERATION,PROVENANCE,content_keys_v1,decode_content_v1,InstalledInternalLifeContentReaderV1)
        def fenced_sql(action):
            def observe(scope):
                guard,actual=port.get_current_owner_guard_for_fence(namespace=ns,
                    authority_namespace=policy.authority_namespace,permit=scope.permit)
                assert actual==scope.permit
                return guard,actual
            authority=AuthorityContext(actual_grant.subject,'d11','life-content-read:'+prepared.digest,
                ns,('activity','event','persona','scene'),'consolidation',(case['life_audience'],),
                prepared.provider_config_ref,prepared.activation_generation)
            def transaction():
                db=store._db;db.execute('BEGIN IMMEDIATE')
                try:
                    value=action(db);db.commit();return value
                except BaseException:db.rollback();raise
            return graph._read_v2(authority,transaction,fence_observer=observe)
        selector=await asyncio.to_thread(fenced_sql,lambda db:prepare_life_result_selector_v2(db,
            namespace=ns,issuer=issuer,job_id=prepared.job_id,authority_id=actual_grant.authority_id,
            authority_namespace=policy.authority_namespace))
        delivered=await client.internal_life_model_result_read_v2(bundle,actual_grant,read_request=selector)
        delivered.require_original(intent,prepared,frozen,binding)
        _,read_state=await asyncio.to_thread(port.get_fence_operation,namespace=ns,
            authority_namespace=policy.authority_namespace,operation_id=selector.read_attempt_id)
        assert read_state=='finished'
        fact=await asyncio.to_thread(read_original_model_cost,graph._GraphCoordinator__model_terminal_cost_port,intent)
        def save_result(db):
            actual,actual_binding,_=read_committed_internal_life_request_v2(db,namespace=ns,issuer=issuer,job_id=prepared.job_id)
            assert (actual,actual_binding)==(prepared,binding)
            assert thaw_internal_life_content_request_v1(json.loads(actual.frozen_json))==frozen
            assert read_life_paid_original_v2(db,ns,issuer,'read_attempt',selector.read_attempt_id)==internal_life_result_to_wire_v2(selector)
            assert delivered.terminal_receipt==fact.receipt and delivered.observation.digest==fact.recovery.observation_digest
            read_life_cost_commit_v2(db,namespace=ns,issuer=issuer,prepared=prepared,intent=intent,terminal=terminal,fact=fact)
            return record_life_paid_original_v2(db,ns,issuer,'result',prepared.job_id,delivered)
        await asyncio.to_thread(fenced_sql,save_result)
        operation='life-content-adopt:'+prepared.job_id.removeprefix('life-content-job:')
        locator=AdoptInternalLifeContentRequestV1(prepared.episode_ref,
            frozen.input.cause.occurrence.event.causal_operation_id)
        def adopt():
            with domain_owner(case) as (authority,lease):
                result=graph.run_current_domain_operation_v1(authority,lease,operation_kind=OPERATION,
                    request=locator,operation_id=operation,activity_id=prepared.activity_id,
                    audience_ref=case['life_audience'],parent_budget_lease_ref=policy.root_grant.lease_id)
            runtime=graph._GraphCoordinator__domain_production_runtime_v1
            if result.get('schema')!='sylanne.internal-life-content-production-receipt.v1':
                error=runtime._last_refusal_exception_v1
                if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
            assert result['schema']=='sylanne.internal-life-content-production-receipt.v1'
            assert (result['completion'],result['capability'],result['before_state'],result['comparison'],result['affect'])==(
                'content_completed','content_only','evidence_unavailable','undetermined','unavailable')
            assert len(result['receipt']['write_versions'])==4 and not store._db.in_transaction
            return result
        adopted=await asyncio.to_thread(adopt)
        keys=content_keys_v1(prepared.episode_ref)
        def cold():
            from sylanne3.runtime.internal_life_completed_original_v1 import read_completed_internal_life_original_v1
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
                db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                proof=decode_content_v1(PROVENANCE,json.loads(db.execute('SELECT value FROM graph_atoms WHERE token=?',(keys[1].token,)).fetchone()[0]))
                completed=read_completed_internal_life_original_v1(db,namespace=ns,issuer=issuer,job_id=prepared.job_id)
                assert completed.validated_proof==proof and completed.prepared==prepared
                assert completed.intent==intent and completed.delivered==delivered and completed.cost==cost
                assert completed.receipt.operation_id==operation and len(completed.receipt.write_versions)==4
                assert canonical_digest(completed.receipt)==adopted['receipt_digest']
                assert get_job(db,prepared.job_id).phase=='completed'
                assert all(db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()==(1,1) for key in keys)
                assert proof.trace.before_state=='evidence_unavailable' and proof.trace.affect=='unavailable'
                assert db.total_changes==0
                return proof.trace
        trace=await asyncio.to_thread(cold)
        current_reader=InstalledInternalLifeContentReaderV1(graph=graph,installed_readers=readers)
        def current():
            authority,lease,_=graph.grant_current_owner(case['bootstrap'],actor='owner-actor-reply',namespace=ns,
                domains=('d06',),purpose='consolidation',audience=case['life_audience'],activation_generation=1,
                owner_session_token=case['owner_session_token'],owner_session_request=case['owner_session_request'])
            try:return current_reader.read(authority=authority,lease=lease,trace_ref=keys[0].token)
            finally:graph.release_current_owner_lease(case['bootstrap'],lease)
        assert await asyncio.to_thread(current)==trace
        def counts():
            return (tuple(store._db.execute('SELECT phase,digest,receipt_json FROM runtime_budget_operations '
                'WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase',(*ns.as_tuple,prepared.prepare_operation_id))),
                tuple(store._db.execute('SELECT operation_id,commit_seq,receipt_json FROM graph_bundle_operations '
                'WHERE bot=? AND persona=? AND operation_id IN (?,?) ORDER BY operation_id',(*ns.as_tuple,operation,cost.operation_id))),
                store._db.execute('SELECT count(*) FROM graph_internal_life_paid_originals_v2').fetchone())
        once=await asyncio.to_thread(counts)
        assert await asyncio.to_thread(adopt)==adopted
        assert await asyncio.to_thread(current)==trace and await asyncio.to_thread(cold)==trace
        assert await asyncio.to_thread(counts)==once and len(calls)==1
        assert trace.candidate.assertion_scope=='model_description_only'
        # Obtain genuine separately scoped Owner leases. Their grant is
        # valid, but it cannot broaden the Life Source-family permissions.
        from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
        from sylanne3.graph_coordinator import UnavailableGuard
        def refuse_scope(purpose,audience):
            authority,lease,_=graph.grant_current_owner(case['bootstrap'],actor='owner-actor-reply',namespace=ns,
                domains=('d06',),purpose=purpose,audience=audience,activation_generation=1,
                owner_session_token=case['owner_session_token'],owner_session_request=case['owner_session_request'])
            try:
                with pytest.raises(UnavailableGuard,match='v2 content authority is unavailable') as denied:
                    current_reader.read(authority=authority,lease=lease,trace_ref=keys[0].token)
                assert type(denied.value.__cause__) is MissingProductionOriginalV1
                assert 'current_source_family_permission' in str(denied.value.__cause__)
            finally:graph.release_current_owner_lease(case['bootstrap'],lease)
        await asyncio.to_thread(refuse_scope,'expression',case['life_audience'])
        await asyncio.to_thread(refuse_scope,'consolidation','owner')
        return dict(job_id=prepared.job_id,prepared_digest=prepared.digest,
            adoption_operation_id=operation,receipt_digest=adopted['receipt_digest'])
    finally:
        if mock is not None:
            mock.handler=actual_handler
        await transport.close()


class _ProviderManager:
    """Finite AstrBot test context with one actual installed provider instance."""
    def __init__(self, provider):
        self.provider_insts = [provider]
        self.inst_map = {provider.provider_config['id']: provider}
        self.selected = provider

    def get_using_provider(self, *, provider_type, umo):
        assert provider_type is ProviderType.CHAT_COMPLETION
        assert umo == 'platform-1:FriendMessage:123456'
        return self.selected

    async def get_using_provider_async(self, *, provider_type, umo):
        return self.get_using_provider(provider_type=provider_type, umo=umo)


class _Conversations:
    async def get_curr_conversation_id(self, umo):
        assert umo == 'platform-1:FriendMessage:123456'
        return 'conversation-1'

    async def get_conversation(self, umo, conversation_id, create_if_not_exists=False):
        assert umo == 'platform-1:FriendMessage:123456' and create_if_not_exists is False
        return SimpleNamespace(persona_id='persona-1') if conversation_id == 'conversation-1' else None


class _Personas:
    selected = 'persona-reply'

    async def resolve_selected_persona(self, **kwargs):
        assert kwargs['umo'] == 'platform-1:FriendMessage:123456'
        return self.selected, {}, None, False


def _creation_resources(case, plan):
    # Identical finite fixture resources to the original permanent Owner case.
    # Its budget is the signed lease produced by actual namespace provisioning.
    with case['store']._lock:
        lease = get_budget_lease(case['store']._db, 'lease-' + case['namespace'].persona_id)
    return VerifiedCreationResources(case['namespace'], 'blueprint:one', 'model:one', 'budget:one',
        plan.version, 'sha256:' + 'a' * 64, plan.blocks[1:], plan.values,
        VerifiedModelCapability(case['namespace'], 'model:one', 'provider/model', 1, 'sha256:' + 'b' * 64),
        VerifiedBudgetLease(case['namespace'], 'budget:one', lease.lease_id, lease.version,
            'sha256:' + canonical_digest(asdict(lease))))


async def _claim_and_initialize_owner(case, claim_material):
    if type(claim_material) is not dict or set(claim_material) != {'ticket', 'operation', 'grant_value'}:
        raise ValueError('closed initial Owner claim material required')
    port, graph, ns = case['port'], case['graph'], case['namespace']
    request, token = case['owner_session_request'], case['owner_session_token']
    ticket, operation, grant_value = (claim_material[k] for k in ('ticket', 'operation', 'grant_value'))
    assert ticket == operation.ticket
    assert operation.namespace == ns and operation.principal == request.principal
    assert await asyncio.to_thread(port.register_owner_ticket, namespace=ns,
        authority_namespace=case['authority_namespace'], ticket=ticket) == ticket
    pending = await asyncio.to_thread(port.reserve_owner_issue, namespace=ns,
        authority_namespace=case['authority_namespace'], operation=operation,
        owner_session_token=token, owner_session_request=request)
    assert pending.phase == 'pending'
    proof = await asyncio.to_thread(graph.commit_first_owner_grant_v2, case['bootstrap'],
        namespace=ns, operation_id=operation.operation_id, grant_value=grant_value)
    committed = await asyncio.to_thread(port.finalize_owner_issue, namespace=ns,
        authority_namespace=case['authority_namespace'], operation=operation, proof=proof,
        owner_session_token=token, owner_session_request=request)
    assert committed.phase == 'committed'
    guard_request = replace(request, audience='owner')
    challenge = await asyncio.to_thread(port.begin_owner_session, namespace=ns,
        authority_namespace=case['authority_namespace'], request=guard_request)
    guard_token = await asyncio.to_thread(port.accept_owner_session, namespace=ns,
        authority_namespace=case['authority_namespace'], challenge=challenge,
        signature=case['owner_key'].sign(challenge.signed_bytes()))
    case.update(owner_session_request=guard_request, owner_session_token=guard_token)
    plan = PersonaPlan('plan:reply', ns, 1,
        (PersonaBlock('identity', 'semantic_identity', 'reliable companion', 'read_only'),), (), True)
    role = await asyncio.to_thread(graph.commit_role_initialization_v2, namespace=ns,
        operation_id='role-init-reply', plan=plan, principal=guard_request.principal,
        request_digest='sha256:' + canonical_digest({'role': 'reply', 'plan_id': plan.plan_id}),
        resources=_creation_resources(case, plan), actor_id='owner-actor-reply',
        owner_session_token=guard_token, owner_session_request=guard_request)
    assert role.operation_id == 'role-init-reply'
    _register_installed_domains(case,("d02","d04","d11","d12"))
    await asyncio.to_thread(initialize_owner_root_v3, case)
    mapping, clock = await asyncio.to_thread(adopt_mapping_and_clock, case)
    case.update(installed_mapping=mapping, installed_clock=clock)
    _register_installed_domains(case,("d10",))


def _install_model_context(case, installation):
    workflow = case['installed_bundle'].model_workflows.encode
    mode = {'content': json.dumps({'event_summary': 'A person said hello.',
        'quoted_details': [{'quote': 'hello', 'salience': 0.5}],
        'possible_meanings': [], 'possible_feelings': []})}
    def handler(request):
        assert request.url.host == 'mock.invalid'
        return httpx.Response(200, json={'id': 'original-encoding-reply', 'object': 'chat.completion',
            'created': 1, 'model': workflow.model_id, 'choices': [{'index': 0,
                'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': mode['content']}}],
            'usage': {'prompt_tokens': 3, 'completion_tokens': 5, 'total_tokens': 8}})
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(case['c09_provider_cache'].wrap(handler)))
    try:
        provider = object.__new__(ProviderOpenAIOfficial)
        provider.provider_config = dict(installation.provider_config)
        provider.model_name = workflow.model_id
        provider.client = AsyncOpenAI(api_key='test-only', base_url='https://mock.invalid/v1', http_client=http_client)
        context = Context(asyncio.Queue(), {}, None, _ProviderManager(provider),
            None, None, None, None, None, None, None)
        selection = InstalledModelCapabilityPort(context=context, host_loop=asyncio.get_running_loop(),
            installed_namespace=case['namespace'], installation_bundle=case['installed_bundle'])
        def encoding_request_issuer(current):
            if (current.authority.namespace != case['namespace']
                    or current.authority.purpose != workflow.purpose
                    or not set(current.authority.audience).issubset(workflow.audiences)
                    or not selection.verify_admin_config(case['namespace'], workflow)
                    or not selection.verify_admin_selection(case['namespace'], workflow)):
                raise ValueError('current installed encoding selection unavailable')
            return issue_first_ingress_encoding_request_v2(current, provider_id=workflow.provider_id,
                model_id=workflow.model_id, provider_config_ref=workflow.provider_config_ref,
                provider_config_digest=workflow.provider_config_digest,
                required_capabilities=frozenset(workflow.required_capabilities), privacy_tier=workflow.privacy_tier,
                timeout_seconds=workflow.timeout_seconds, max_output_tokens=workflow.max_output_tokens)
        case['graph']._GraphCoordinator__encoding_request_issuer = encoding_request_issuer
        case['graph']._GraphCoordinator__self_identity_port = InstalledCurrentSelfIdentityPort(
            client=case['authority_client'], bundle=case['installed_bundle'], grant=case['client_grant'],
            owner_loop=asyncio.get_running_loop())
        case.update(model_context=context, model_reply_mode=mode, model_http_client=http_client,
            model_provider=provider, model_selection=selection)
        return http_client
    except BaseException:
        # Async closure is handled by the caller even if setup fails after this point.
        case['model_http_client'] = http_client
        raise


async def run_installed_life_host_actor_v1(installation: HostInstallationCaseV1):
    """Run genuine Owner→SourceNote→completed Life content on a fresh Host."""
    if type(installation) is not HostInstallationCaseV1:
        raise TypeError('exact HostInstallationCaseV1 required')
    config = installation.host_driver_configuration
    if type(config) is not dict or set(config) != {'schema', 'bootstrap', 'owner_claim'}:
        raise ValueError('closed Life Host actor configuration required')
    if config['schema'] != 'sylanne.c09.life-host-actor.v1':
        raise ValueError('Life Host actor schema differs')
    locators = None
    async with open_life_host_bootstrap_v1(installation) as case:
        case['data_dir'] = installation.data_dir
        http_client = None
        try:
            # The parent may provision the namespace and authorize claim material,
            # but this fresh Host performs every Owner and subsequent business write.
            await _claim_and_initialize_owner(case, config['owner_claim'])
            assert (await case['authority_client'].status_v2()).state == 'paired'
            case['client_grant'] = await case['authority_client'].installation_grant_v2()
            case['graph']._GraphCoordinator__accounting_maintenance_port = InstalledAccountingMaintenancePort(
                client=case['authority_client'], bundle=case['installed_bundle'], grant=case['client_grant'],
                owner_loop=asyncio.get_running_loop())
            http_client = _install_model_context(case, installation)
            await _bind_scene_and_ingress(case)
            first_ingress, c02 = await _run_first_ingress(case)
            case.update(c02=c02, source_ref=source_key(*case['namespace'].as_tuple, case['host'].lineage.source_ref).token)
            episode_case = await asyncio.to_thread(_run_source_note_and_episode, case)
            await asyncio.to_thread(_prepare_and_acquire_content, episode_case)
            locators = await _complete_content(episode_case)
        finally:
            model_client = getattr(case.get('model_provider'), 'client', None)
            try:
                if model_client is not None:
                    await model_client.close()
            finally:
                current_http = http_client or case.get('model_http_client')
                if current_http is not None:
                    await current_http.aclose()
    assert type(locators) is dict and set(locators) == {
        'job_id', 'prepared_digest', 'adoption_operation_id', 'receipt_digest'}
    return locators
