"""Permanent installed W01 domain acceptance with real paired Owner originals.

The fixture performs actual Authority/mTLS/Owner/root/C02 operations. Every
new input is registered through its public producing operation; no current
guard, completed effect, model finding, resource grant or consent is seeded.
"""
from contextlib import contextmanager
import asyncio
from dataclasses import replace
import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from test_m1_installed_artifact_draft_v1 import installed_m1_phase_fixture_v2

from test_d04_owner_semantic_initialization_v3 import (
    installed_d04_root, real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock,
)
from sylanne3.domains.d01.production_operations_v1 import EvaluateCurrentValuesRequestV1
from sylanne3.domains.d02 import BodyProfile, BodyState, BodyPassiveRates, WorkComponent
from sylanne3.domains.d02.body_quote_original import FixedBodyPolicyV1
from sylanne3.domains.d02.production_operations_v1 import AdvanceCurrentBodyRequestV1
from sylanne3.domains.d05.production_operations_v1 import AdoptCurrentRelationshipContributionRequestV1
from sylanne3.domains.d08.execution import Goal, GoalPredicate
from sylanne3.domains.d10 import ContactPolicy, ProactiveOpportunity, contact_policy_key, opportunity_key
from sylanne3.domains.d10.production_operations_v1 import PrepareCurrentContactRequestV1
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.d02_production_operations_v1 import PassiveBodyPolicyV1
from sylanne3.runtime.d05_production_operations_v1 import InstalledRelationshipPolicyV1
from sylanne3.runtime.domain_production_inputs_v1 import (
    InstallCurrentBodyInputRequestV1, InstallCurrentPassiveBodyInputRequestV1,
    FreezeCurrentValuesInputRequestV1, InstallCurrentRelationshipInputRequestV1,
    CreateCurrentGoalInputRequestV1, SetCurrentContactPolicyInputRequestV1,
    CreateCurrentContactOpportunityInputRequestV1,
)


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


def relations_api(case, *, scope=None):
    """Call the real D12 API and its durable current Owner grant resolver."""
    from sylanne3.workbench_api.domain_registry import CurrentDomainViewRegistry
    from sylanne3.workbench_api.issuer import GraphWorkbenchIssuer
    from sylanne3.workbench_api.owner_grant import DurableOwnerGrantResolver, GraphCurrentOwnerGrantPort
    from sylanne3.workbench_api.service import AuthenticatedSession, RequestContext, WorkbenchService
    graph, ns = case["graph"], case["namespace"]
    own_scope = "/".join(ns.as_tuple)
    port = GraphCurrentOwnerGrantPort(graph, case["bootstrap"], namespace=ns,
        activation_generation=1, domains=tuple(sorted(graph._GraphCoordinator__providers)))
    grants = DurableOwnerGrantResolver(port)
    issuer = GraphWorkbenchIssuer(graph, grants, CurrentDomainViewRegistry(lambda: case["domain_registry"]))
    session = AuthenticatedSession("owner-actor-reply", "domain-relations-api",
        {own_scope: frozenset({"workbench.read"})}, {own_scope: frozenset({"owner"})},
        {own_scope: frozenset({"workbench_view"})}, owner_session_token=case["owner_session_token"],
        owner_session_request=case["owner_session_request"])
    with grants.request_scope():
        return WorkbenchService(issuer).handle({"schema_version": "d12.contract.v1",
            "action": "read_character_view", "scope": scope or own_scope, "purpose": "workbench_view",
            "audience": "owner", "operation_id": str(uuid4()), "input": {"view_type": "relations"}},
            session=session, context=RequestContext(True, True, True))


@pytest.mark.asyncio
async def test_real_c04_activities_have_two_pending_relationship_contributions_and_one_external_family(tmp_path, installed_d04_root):
    """Actual local Authority/C02/appraisal/numeric/C04 commits feed D05/API.

    Model text is served by the existing local controlled HTTP fixture. No
    live model or sender is used, and no receipt or contribution is seeded.
    """
    from d04_http_initialization_acceptance_v3 import initialize_via_actual_workbench_v3
    from d04_numeric_authority_acceptance_support_v3 import install_actual_numeric_authority_case_v3
    from test_d04_installed_semantic_drive_v3 import appraisal_workflows, compose_installed_appraisal, explicit_subjective_reply
    from sylanne3.domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
    from sylanne3.domains.d06 import source_correction_head_key
    from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
    from sylanne3.domains.d05.production_operations_v1 import ReevaluateCurrentRelationshipRequestV1
    from sylanne3.host.authority_profile import AdminD06SourceCorrectionPolicy
    from sylanne3.host.installed_d04_appraisal_driver_v3 import run_installed_post_c02_appraisal_v3
    from sylanne3.host.installed_d06_build import verify_d06_algorithm_build, ALGORITHM_ID_V3
    from sylanne3.runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyV1
    from sylanne3.runtime.c04_current_trigger_v3 import CurrentC04TriggerV3
    from sylanne3.runtime.c04_v3_contracts import AssociationBudgetV3
    from sylanne3.runtime.d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3
    from sylanne3.runtime.d04_numeric_math_ticket_v3 import InstalledD04MathQueueV3, issue_current_numeric_math_ticket_v3
    from sylanne3.runtime.d04_numeric_policy_v3 import AdminD04JointNumericPolicyV3
    from sylanne3.runtime.d06_association_formation_v1 import FormCurrentAssociationRequestV1
    from sylanne3.runtime.issuers import D06_SOURCE_CORRECTION_WORK_KIND
    from sylanne3.runtime.domain_production_erasure_v1 import validate_domain_production_schema_v1
    from sylanne3.workbench_api.source_correction import SourceCorrectionRequestV1
    from sylanne3.workbench_api.service import request_digest

    initialized, queues, resources = {}, [], []

    async def after_role(case):
        await initialize_via_actual_workbench_v3(case)
        def register():
            graph = case["graph"]
            if "d05" not in graph._GraphCoordinator__providers:
                reg = case["domain_registry"].registrations["d05"]
                graph.register_provider(case["bootstrap"], "d05", reg.provider, reg.proposal_schema, reg.proposal_schema_hash)
        await asyncio.to_thread(register)
        initialized.update(case)

    async def after_c02(case):
        case = {**initialized, **case}
        graph, store, ns = case["graph"], case["store"], case["namespace"]
        bundle, assembly, runtime = compose_installed_appraisal(case, initialized)
        runtime.local_module_admission = graph.local_module_admission
        root = case["policy"].root_grant

        async def appraise(c02, source):
            args = {"c02_operation_id": c02.operation_id, "source_ref": source}
            prepared = await asyncio.to_thread(graph.prepare_post_c02_appraisal_v3, case["bootstrap"], bundle, **args)
            with store._lock:
                original = read_current_d04_appraisal_original_v3(store._db, ns, prepared["job_id"])
            case["model_reply_mode"]["content"] = explicit_subjective_reply(json.loads(original.frozen_json), 0.5)
            accepted = await run_installed_post_c02_appraisal_v3(runtime, assembly, context=case["model_context"],
                trusted_umo="platform-1:FriendMessage:123456", **args)
            assert accepted["status"] == "adopted", accepted
            return accepted["appraisal_ref"]

        first_appraisal = await appraise(case["c02"], case["source_ref"])
        first_args = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        drive = await asyncio.to_thread(graph.commit_post_c02_semantic_drive_v3, case["bootstrap"], bundle, **first_args)
        assert drive["status"] == "drive_adopted", drive
        numeric = AdminD04JointNumericPolicyV3(ns, case["policy"].installation_id, root.grant_id, root.version,
            root.lease_id, 100000, 256, 1e-8, 600)
        bundle = replace(bundle, d04_joint_numeric=numeric)
        assembly = replace(assembly, admin_bundle=bundle)
        graph._GraphCoordinator__d04_installed_joint_assembly = assembly
        support = await asyncio.to_thread(install_actual_numeric_authority_case_v3,
            {**case, "installed_bundle": bundle, "assembly": assembly}, owner_loop=asyncio.get_running_loop())
        resources.append(support)
        build = verify_d06_algorithm_build(case["package_root"], case["manifest_digest"],
            require_backend_runtime=True, algorithm_id=ALGORITHM_ID_V3)
        graph._GraphCoordinator__c04_algorithm_build_digest = build["build_digest"].removeprefix("sha256:")
        def issue_math():
            queue = InstalledD04MathQueueV3(graph, case["bootstrap"])
            graph._GraphCoordinator__d04_math_queue_v3 = queue
            return queue, issue_current_numeric_math_ticket_v3(graph, case["bootstrap"], bundle, queue, **first_args)
        queue, ticket = await asyncio.to_thread(issue_math)
        queues.append(queue)
        measurement = await asyncio.wrap_future(queue.submit(ticket))
        execution = await asyncio.to_thread(queue.accept, graph, measurement)
        joint = await asyncio.to_thread(graph.adopt_post_c02_joint_numeric_v3, case["bootstrap"], bundle,
            operation_id=execution.prepared.binding.operation_id)
        assert joint["status"] == "joint_advance_committed", joint
        encoding = await asyncio.to_thread(graph.commit_post_joint_c04_encoding_v3, case["bootstrap"], bundle,
            **first_args, joint_operation_id=execution.prepared.binding.operation_id)
        assert encoding["status"] == "encoding_baseline_committed", encoding

        with store._lock:
            db = store._db
            route = json.loads(db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name='d03.account_binding' AND valid=1 ORDER BY token", ns.as_tuple).fetchone()[0])
            events = db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name='d03.world_event' AND valid=1", ns.as_tuple).fetchall()
            event_ref = next(token for token, raw in events if case["source_ref"] in json.loads(raw)["source_refs"])
        policy = InstalledRelationshipPolicyV1("relationship-policy:p0", 1, ns,
            ("familiarity",), ("external_observation", "recollection", "simulation"), ("self_internal",))
        await asyncio.to_thread(command, case, "install_relationship_policy", InstallCurrentRelationshipInputRequestV1(policy), producer=True)
        external_request = AdoptCurrentRelationshipContributionRequestV1(event_ref, route["entity_id"],
            "familiarity", "external_observation", policy.policy_ref)
        await asyncio.to_thread(command, case, "adopt_relationship_contribution", external_request,
            audience='["platform-1:FriendMessage:123456","conversation-1"]')
        view = await asyncio.to_thread(relations_api, case)
        assert view.status == "ready", view.as_dict()
        first_dimension = view.projection["data"]["relations"][0]["dimensions"][0]
        assert first_dimension["availability"] == "available" and first_dimension["source_qualification"] == "qualified"
        assert first_dimension["estimate"] == "unknown"
        assert (await asyncio.to_thread(relations_api, case, scope=ns.bot_id + "/another-persona")).projection is None
        with store._lock:
            assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE type_name='d06.recollection.v1'").fetchone() == (0,)

        # The real existing focus expires; no served/send state is manufactured.
        with store._lock:
            focus = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE type_name='d07.focus.v1' AND valid=1").fetchone()[0])
            attention = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?", (focus["primary_ticket_ref"],)).fetchone()[0])
        await asyncio.sleep(max(0.0, attention["valid_until"] - time.time() + 0.05))
        ingress, second_c02 = await case["commit_second_c02"]("p0-recollection-cue", "hello again", commit_attention=True)
        second_source = next(v.key.token for v in ingress.write_versions if v.key.type_name == "memory.source")
        second_appraisal = await appraise(second_c02, second_source)
        association = FormCurrentAssociationRequestV1(second_source, second_c02.operation_id,
            case["source_ref"], case["c02"].operation_id, second_appraisal, "facet:inbound",
            first_appraisal, "facet:inbound", "relation_meaning")
        formed = await asyncio.to_thread(command, case, "form_association", association,
            audience='["platform-1:FriendMessage:123456","conversation-1"]')
        assert formed["coverage"] == "complete", formed

        def install_c04_policies():
            with domain_owner(case) as (authority, lease):
                profile = BodyProfile("p0-c04-body", ns, 1, ("energy",), (C04_INTERNAL_CPU_WORK_KIND,))
                body = FixedBodyPolicyV1("p0-c04-body-policy", 1, profile,
                    BodyState(profile.profile_id, 1, 0.8, {"cognition": 0.0}, 0.0, 0.0), C04_INTERNAL_CPU_WORK_KIND,
                    WorkComponent("p0-c04-component", "cognition", 0.1), time.time() + 3600)
                graph.adopt_current_fixed_body_work_policy_v1(authority, lease, operation_id=str(uuid4()), policy=body)
                cpu = C04InternalCpuQuotePolicyV1("p0-c04-cpu-policy", 1, ns, case["policy"].installation_id,
                    ALGORITHM_ID_V3, 1000, time.time() + 3600)
                graph.adopt_current_c04_cpu_policy_v3(authority, lease, operation_id=str(uuid4()), policy=cpu)
                return body, cpu
        body, cpu = await asyncio.to_thread(install_c04_policies)
        recollections = []
        for member in range(2):
            def realize():
                with domain_owner(case) as (authority, lease):
                    operation = str(uuid4())
                    trigger = CurrentC04TriggerV3(second_source, body.policy_id, body.version,
                        cpu.policy_id, cpu.version, root.lease_id, AssociationBudgetV3(2,32,16,16,8))
                    prepared = graph.prepare_owner_c04_trigger_v3(authority, lease, operation_id=operation, request=trigger)
                    assert prepared["status"] == "prepared", prepared
                    adopted = graph.advance_owner_c04_work_v3(authority, lease, original_operation_id=operation)
                    assert adopted["status"] == "adopted", adopted
                    assert graph.advance_owner_c04_work_v3(authority, lease, original_operation_id=operation) == adopted
                with store._lock:
                    rows = store._db.execute("SELECT token,value FROM graph_atoms WHERE type_name='d06.recollection.v1'").fetchall()
                    assert len(rows) == member + 1
                    token, value = next((token, json.loads(raw)) for token, raw in rows if token not in recollections)
                    assert value["content_refs"] == [AtomKey.from_token(case["source_ref"]).owner.subject]
                return token
            recollection_ref = await asyncio.to_thread(realize)
            recollections.append(recollection_ref)
            request = AdoptCurrentRelationshipContributionRequestV1(recollection_ref, route["entity_id"],
                "familiarity", "recollection", policy.policy_ref)
            first = await asyncio.to_thread(command, case, "adopt_relationship_contribution", request)
            assert first["coverage"] == "complete" and first["receipt"]["write_versions"]
            for _ in range(10):
                duplicate = await asyncio.to_thread(command, case, "adopt_relationship_contribution", request)
                assert not duplicate["receipt"]["write_versions"] and not duplicate["outbox"]
            # Observed content inside a recollection cannot qualify an external event.
            invalid = replace(request, semantics="external_observation")
            def reject_external_recollection():
                with domain_owner(case) as (authority, lease):
                    refused = graph.run_current_domain_operation_v1(authority, lease,
                        operation_kind="adopt_relationship_contribution", request=invalid,
                        operation_id=str(uuid4()), activity_id="p0-invalid-external-recollection",
                        audience_ref="owner", parent_budget_lease_ref=root.lease_id)
                runtime = graph._GraphCoordinator__domain_production_runtime_v1
                assert refused["schema"] != "sylanne.domain-production-receipt.v1", refused
                failure = getattr(runtime, "_last_refusal_exception_v1", None)
                assert isinstance(failure, ValueError) and "external relationship observation" in str(failure), repr(failure)
            await asyncio.to_thread(reject_external_recollection)

        with store._lock:
            rows = store._db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name='d05.contribution' AND valid=1", ns.as_tuple).fetchall()
            contributions = [json.loads(raw) for (raw,) in rows]
            assert len(contributions) == 3
            assert sum(c["semantics"] == "external_observation" for c in contributions) == 1
            internal = [c for c in contributions if c["semantics"] == "recollection"]
            assert len({c["canonical_event_or_family_ref"] for c in internal}) == 2
            assert all(c["source_refs"] == [case["source_ref"]] for c in internal)
            current_projection = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE type_name='d05.relationship_projection'").fetchone()[0])
            assert current_projection["influence_status"] == "unapplied_pending" and current_projection["estimate"] == "unknown"
            assert all(c["schema_version"] == 2 and c["kind"] == "internal_recollection"
                       and c["recollection_activity_ref"] in recollections for c in internal)
            before = store._db.execute("SELECT count(*) FROM graph_atoms WHERE type_name='d06.recollection.v1'").fetchone()[0]
            assert validate_domain_production_schema_v1(store._db)
        current_dimension = (await asyncio.to_thread(relations_api, case)).projection["data"]["relations"][0]["dimensions"][0]
        assert current_dimension["availability"] == "available" and current_dimension["estimate"] == "unknown"
        assert current_dimension["influence_status"] == "unapplied_pending"
        with store._lock:
            assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE type_name='d06.recollection.v1'").fetchone()[0] == before

        def correct_and_revoke():
            with store._lock:
                db = store._db
                epochs = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
            target = next(v.key.token for v in case["c02"].write_versions if v.key.type_name == "memory.interpretation")
            operation = str(uuid4())
            data = {"schema": "d12.source_correction.v1", "correction_kind": "source_claim", "statement": "The earlier account was mistaken.",
                "source_refs": [case["source_ref"]], "target_refs": [target], "access_epoch": epochs[0], "deletion_epoch": epochs[1]}
            digest = "sha256:" + request_digest({"action": "correct_or_edit", "scope": "/".join(ns.as_tuple),
                "purpose": "workbench_user_action", "audience": "owner", "operation_id": operation, "input": data})
            correction = graph.commit_source_correction_v1(request=SourceCorrectionRequestV1(ns, operation, digest,
                data["statement"], (case["source_ref"],), (target,), *epochs), actor_id="owner-actor-reply",
                principal=case["principal"], purpose="workbench_user_action", audience="owner", installation_policy=case["policy"],
                admin_policy=AdminD06SourceCorrectionPolicy(30.0, {"cpu_ms": 5}, "p0-correction-snapshot", "p0-correction-resource"),
                owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
            assert correction.operation_id == operation
            source_id = AtomKey.from_token(case["source_ref"]).owner.subject
            reevaluated = command(case, "reevaluate_relationship", ReevaluateCurrentRelationshipRequestV1(
                source_correction_head_key(ns, source_id).token))
            assert reevaluated["receipt"]["write_versions"]
            corrected_view = relations_api(case)
            assert corrected_view.status == "ready" and corrected_view.projection["data"]["relations"][0]["dimensions"][0]["status"] == "blocked_rebuild"
            # A distinct eligible family does not clear the held dimension.
            second_event = next(token for token, raw in store._db.execute("SELECT token,value FROM graph_atoms "
                "WHERE type_name='d03.world_event' AND valid=1") if second_source in json.loads(raw)["source_refs"])
            command(case, "adopt_relationship_contribution", replace(external_request, trigger_original_ref=second_event),
                audience='["platform-1:FriendMessage:123456","conversation-1"]')
            assert relations_api(case).projection["data"]["relations"][0]["dimensions"][0]["status"] == "blocked_rebuild"
            authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply", namespace=ns,
                domains=("d06", "d12"), purpose="audit", audience="owner", activation_generation=1,
                owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
            try:
                graph.revoke_source_access_v1(authority, lease,
                    SourceAccessRevocationRequest(AtomKey.from_token(second_source).owner.subject,
                        "owner-actor-reply", str(uuid4()), time.time()))
            finally:
                graph.release_current_owner_lease(case["bootstrap"], lease)
            assert relations_api(case, scope=ns.bot_id + "/another-persona").projection is None
            withdrawn = relations_api(case)
            assert withdrawn.status == "ready" and withdrawn.projection["data"]["relations"] == [], withdrawn.as_dict()
            with store._lock:
                assert store._db.execute("SELECT count(*) FROM graph_history WHERE token IN "
                    "(SELECT token FROM graph_atoms WHERE type_name='d05.contribution')").fetchone()[0] >= 3
                assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE type_name='d05.contribution' AND valid=1").fetchone() == (0,)
                assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE type_name='d06.recollection.v1'").fetchone() == (2,)
        await asyncio.to_thread(correct_and_revoke)

    try:
        await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
            after_role_initialization=after_role, continue_to_ingress=True, after_c02=after_c02,
            natural_workflow_builder=appraisal_workflows, enable_d04_semantic_drive=True, enable_d04_joint_numeric=True,
            enable_d09_workbench=True, enable_d04_root_cpu=True, enable_c04_body_work=True,
            extra_owner_capabilities=("workbench.correct",), extra_owner_purposes=("context", "consolidation", "audit"),
            extra_root_work_kinds=(D06_SOURCE_CORRECTION_WORK_KIND,))
    finally:
        for queue in queues:
            await asyncio.to_thread(queue.close)
        for support in resources:
            support.close()
        if initialized.get("http_worker") is not None:
            await initialized["http_worker"].close()


@pytest.mark.asyncio
async def test_true_owner_domain_inputs_passive_values_relationship_and_contact(tmp_path, installed_d04_root):
    initial = {}

    async def after_role(case):
        initial.update(case)
        def accept():
            initialize_owner_root_v3(case)
            _, clock = adopt_mapping_and_clock(case)
            for domain in ("d01", "d02", "d05", "d10", "d11"):
                if domain in case["graph"]._GraphCoordinator__providers:
                    continue
                registration = case["domain_registry"].registrations[domain]
                case["graph"].register_provider(case["bootstrap"], domain, registration.provider,
                    registration.proposal_schema, registration.proposal_schema_hash)
            ns = case["namespace"]
            policy = FixedBodyPolicyV1("body-policy:domain-acceptance", 1,
                BodyProfile("body:domain-acceptance", ns, 1, ("energy", "fatigue", "load"), ("message",)),
                BodyState("body:domain-acceptance", 1, 0.5, {"message": 0.4}, 0.4, 0.0),
                "message", WorkComponent("message", "body-energy", 0.1, 0.0), time.time() + 3600)
            command(case, "initialize_body", InstallCurrentBodyInputRequestV1(policy), producer=True)
            passive = PassiveBodyPolicyV1("passive-policy:domain-acceptance", 1, ns, policy.profile.profile_id,
                0.0, 3600.0, BodyPassiveRates(0.001, {"message": 0.001}, 0.001))
            command(case, "install_passive_body_policy", InstallCurrentPassiveBodyInputRequestV1(passive), producer=True)
            # The registered clock starts at the actual current wall second;
            # both policy commands consume real elapsed time. The target is a
            # conservative already-observed cursor, never an invented tick.
            target = min(0.01, max(0.0, time.time() - datetime.fromisoformat(clock.wall_origin_utc.replace("Z", "+00:00")).timestamp() - 2.0))
            assert target > 0, "real paired-clock work did not yet establish a positive elapsed interval"
            operation = str(uuid4())
            advanced = command(case, "advance_body", AdvanceCurrentBodyRequestV1(clock.mapping_id,
                target, "d11-tick:" + operation), operation_id=operation)
            assert advanced["coverage"] == "complete"
            state_key = AtomKey(Owner("persona", *ns.as_tuple), "d02.body_state.v1", policy.profile.profile_id)
            with case["store"]._lock:
                row = case["store"]._db.execute("SELECT revision,value FROM graph_atoms WHERE token=?", (state_key.token,)).fetchone()
            state = json.loads(row[1])
            assert row[0] == 2 and state["cursor"] == target and state["energy"] > 0.5
            waiting = command(case, "evaluate_values", EvaluateCurrentValuesRequestV1("missing:values", "missing:context"))
            assert waiting["coverage"] == "waiting_for_original" and waiting["missing_inputs"]
            assert all(phase == "waiting" for _, phase in waiting["job_states"])
            assert not waiting["receipt"]["write_versions"]
        await asyncio.to_thread(accept)

    async def after_c02(current):
        case = {**initial, **current}
        def accept():
            graph, store, ns = case["graph"], case["store"], case["namespace"]
            with store._lock:
                source = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?", (case["source_ref"],)).fetchone()[0])
                route_ref, route_json = store._db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND type_name='d03.account_binding' AND valid=1 ORDER BY token", ns.as_tuple).fetchone()
                event_ref = store._db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.world_event' "
                    "AND valid=1 ORDER BY token", ns.as_tuple).fetchone()[0]
            route = json.loads(route_json)
            audience = case["ingress"].conversation_ref
            frozen = command(case, "freeze_values", FreezeCurrentValuesInputRequestV1("values:current", "context:current"),
                audience=audience, producer=True)
            assert len(frozen["produced_originals"]) == 2
            evaluated = command(case, "evaluate_values", EvaluateCurrentValuesRequestV1("values:current", "context:current"), audience=audience)
            assert evaluated["coverage"] == "complete" and evaluated["outbox"]
            relationship_policy = InstalledRelationshipPolicyV1("relationship-policy:current", 1, ns,
                ("familiarity",), ("external_observation", "recollection", "simulation"), ("runtime_policy", "self_internal"))
            command(case, "install_relationship_policy", InstallCurrentRelationshipInputRequestV1(relationship_policy), producer=True)
            contribution = command(case, "adopt_relationship_contribution", AdoptCurrentRelationshipContributionRequestV1(
                event_ref, route["entity_id"], "familiarity", "external_observation", relationship_policy.policy_ref), audience=audience)
            assert contribution["coverage"] == "complete" and contribution["receipt"]["write_versions"] and contribution["outbox"]
            relation_view = relations_api(case)
            assert relation_view.status == "ready", relation_view.as_dict()
            dimension = relation_view.projection["data"]["relations"][0]["dimensions"][0]
            assert dimension["dimension"] == "familiarity" and dimension["availability"] == "available"
            assert dimension["source_qualification"] == "qualified" and dimension["estimate"] == "unknown"
            assert relations_api(case, scope=ns.bot_id + "/other-persona").projection is None
            # Owner goal creation is a real D08 adopted unexecuted intent.
            goal = Goal("goal:understand-current-message", 1, "active",
                GoalPredicate("domain_state", "d07", (("target", case["source_ref"]),), 0.0, None),
                (case["source_ref"],), (), None, (), ())
            adopted_goal = command(case, "create_goal", CreateCurrentGoalInputRequestV1(case["source_ref"], goal), audience=audience, producer=True)
            assert adopted_goal["receipt"]["write_versions"]
            now = time.time()
            policy = ContactPolicy("contact-policy:current", ns, 1, route["entity_id"], "private", "conversation",
                True, False, 1, now - 60, now + 3600)
            opportunity = ProactiveOpportunity("contact-opportunity:current", ns, case["source_ref"], route["entity_id"],
                "private", "conversation", now - 60, now + 3600)
            command(case, "set_contact_policy", SetCurrentContactPolicyInputRequestV1(policy), producer=True)
            command(case, "create_contact_opportunity", CreateCurrentContactOpportunityInputRequestV1(opportunity), audience=audience, producer=True)
            contact = command(case, "prepare_contact", PrepareCurrentContactRequestV1(opportunity_key(ns, opportunity.opportunity_id).token,
                contact_policy_key(ns, policy.policy_id).token, route_ref), audience=audience)
            assert contact["coverage"] == "complete" and contact["outbox"] and not contact["receipt"]["write_versions"]
            # Reported message content remains reported after relationship and
            # contact processing; neither candidate emits a delivery claim.
            with store._lock:
                assert json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?", (case["source_ref"],)).fetchone()[0]) == source
                assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d10.contact_claim.v1'", ns.as_tuple).fetchone()[0] == 0
                from sylanne3.runtime.domain_production_erasure_v1 import (
                    TABLE_COLUMNS, validate_domain_production_schema_v1, validate_domain_production_row_v1,
                )
                from sylanne3.runtime.domain_production_original_codec_v1 import decode_domain_production_original_row_v1
                validate_domain_production_schema_v1(store._db)
                for table, columns in TABLE_COLUMNS.items():
                    for row in store._db.execute("SELECT * FROM " + table):
                        validate_domain_production_row_v1(table, columns, row)
                for row in store._db.execute("SELECT * FROM graph_domain_production_originals_v1"):
                    decode_domain_production_original_row_v1(row, ns, registry=case["domain_registry"].type_registry)
            bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
            disposition = graph.consume_current_domain_followup_v1(case["bootstrap"], bundle, dedupe_key=evaluated["outbox"][0])
            assert disposition["schema"] == "sylanne.domain-followup-disposition.v1"
            assert disposition["state"] == "waiting" and disposition["missing_originals"] and not disposition["completed_commands"]
            assert graph.consume_current_domain_followup_v1(case["bootstrap"], bundle,
                dedupe_key=evaluated["outbox"][0]) == disposition
            with store._lock:
                saved = store._db.execute("SELECT state,consumer_operation_id,receipt_json FROM graph_domain_production_outbox_v1 "
                    "WHERE bot=? AND persona=? AND dedupe_key=?", (*ns.as_tuple, evaluated["outbox"][0])).fetchone()
                assert saved[:2] == ("waiting", disposition["consumer_operation_id"])
                assert json.loads(saved[2]) == disposition
                assert store._db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                    (*ns.as_tuple, disposition["consumer_operation_id"])).fetchone() == (1,)
        await asyncio.to_thread(accept)

    await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
        after_role_initialization=after_role, continue_to_ingress=True, after_c02=after_c02,
        enable_d09_workbench=True, enable_d04_root_cpu=True, enable_c04_body_work=True,
        extra_owner_purposes=("context", "consolidation"))


@pytest.mark.asyncio
async def test_true_owner_offline_schedule_acquired_preparation_and_original_read(tmp_path, installed_d04_root):
    """Real prepare→independent once execution→atomic adoption or historical fee."""
    from sylanne3.runtime.d10_offline_inputs_v1 import RegisterCurrentOfflineScheduleInputRequestV1
    from sylanne3.runtime.d11_offline_originals_v1 import read_current_d11_offline_value_v1
    from sylanne3.runtime.d10_offline_tick_execution_v1 import (
        PrepareCurrentOfflineTickRequestV1, offline_tick_ids_v1, read_prepared_offline_tick_v1,
        read_current_prepared_offline_tick_v1,
    )
    from sylanne3.runtime.domain_production_erasure_v1 import (
        TABLE_COLUMNS, validate_domain_production_row_v1, validate_domain_production_schema_v1,
    )
    from sylanne3.runtime.jobs import get_job

    async def after_role(case):
        def accept():
            initialize_owner_root_v3(case)
            adopt_mapping_and_clock(case)
            from d11_offline_authority_acceptance_support_v1 import install_actual_offline_authority_case_v1
            install_actual_offline_authority_case_v1(case)
            graph, store, ns = case["graph"], case["store"], case["namespace"]
            for domain in ("d01", "d06", "d10", "d11"):
                if domain not in graph._GraphCoordinator__providers:
                    registration = case["domain_registry"].registrations[domain]
                    graph.register_provider(case["bootstrap"], domain, registration.provider,
                        registration.proposal_schema, registration.proposal_schema_hash)
            request = RegisterCurrentOfflineScheduleInputRequestV1("offline-schedule:acceptance", 0,
                60, 4, 100, (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat().replace("+00:00", "Z"),
                ("consolidation", "context"))
            registered = command(case, "register_offline_schedule", request, producer=True)
            assert registered["coverage"] == "complete"
            with store._lock:
                db = store._db
                db.execute("BEGIN")
                try:
                    row = db.execute("SELECT original_ref FROM graph_d11_offline_originals_v1 WHERE bot=? AND persona=? AND kind='registered_schedule'", ns.as_tuple).fetchone()
                    schedule = read_current_d11_offline_value_v1(db, namespace=ns, original_ref=row[0], issuer=case["d11_issuer"])
                    assert schedule.cpu_ceiling_ms == 100 and schedule.starts_at_utc
                    assert db.execute("SELECT producing_operation_id FROM graph_d11_offline_originals_v1 WHERE original_ref=?", (row[0],)).fetchone() == (registered["operation_id"],)
                finally:
                    db.rollback()
            ids = offline_tick_ids_v1(ns, schedule.schedule_ref, schedule.starts_at_utc)
            with domain_owner(case) as (authority, lease):
                receipt = graph.run_current_domain_operation_v1(authority, lease, operation_kind="prepare_offline_tick",
                    request=PrepareCurrentOfflineTickRequestV1(schedule.schedule_ref, schedule.starts_at_utc),
                    operation_id=ids["operation"], activity_id=ids["activity"], audience_ref="owner",
                    parent_budget_lease_ref=case["policy"].root_grant.lease_id)
            runtime = graph._GraphCoordinator__domain_production_runtime_v1
            assert receipt["schema"] == "sylanne.domain-production-receipt.v1", repr(getattr(runtime, "_last_refusal_exception_v1", receipt))
            assert receipt["coverage"] == "deferred" and receipt["receipt"]["status"] == "committed"
            assert receipt["receipt"]["operation_id"] == "d11-offline-tick-prepare:" + ids["operation"]
            with store._lock:
                db = store._db
                db.execute("BEGIN")
                try:
                    prepared = read_prepared_offline_tick_v1(db, namespace=ns, prepared_original_ref=ids["prepared"], issuer=case["d11_issuer"])
                    assert prepared is not None
                    assert read_current_prepared_offline_tick_v1(db, binding=prepared.binding,
                        issuer=case["d11_issuer"], resource_issuer=case["d02_issuer"], now_utc=time.time()) == prepared
                    job = get_job(db, prepared.binding.job_id)
                    assert job.phase == "running" and job.fence == 1 and not job.usage and job.result_ref is None
                    reserve = db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                        (prepared.binding.parent_budget_lease_ref, prepared.binding.reservation_operation_id)).fetchone()
                    assert reserve == ("reserved", None)
                    assert db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (job.continuation["source_ref"],)).fetchone() is None
                    for row in db.execute("SELECT * FROM graph_d11_offline_originals_v1"):
                        validate_domain_production_row_v1("graph_d11_offline_originals_v1", TABLE_COLUMNS["graph_d11_offline_originals_v1"], row)
                finally:
                    db.rollback()
            port = graph._GraphCoordinator__content_fence_v2
            claim, terminal = port.execute_d11_offline_tick_v1(binding=prepared.binding)
            assert terminal.status == "completed" and terminal.actual_cpu_ms >= 0
            assert terminal.result.scheduled_at_utc == prepared.binding.scheduled_at_utc
            assert port.read_d11_offline_tick_original_v1(binding=prepared.binding) == (terminal.claim, terminal)
            adopted = graph.adopt_current_offline_tick_v1(case["bootstrap"], namespace=ns,
                prepared_original_ref=prepared.binding.prepared_original_ref)
            assert adopted["status"] == "completed" and len(adopted["source_refs"]) == 1
            assert adopted["actual_cpu_ms"] == terminal.actual_cpu_ms
            with store._lock:
                db = store._db
                validate_domain_production_schema_v1(db)
                job = get_job(db, prepared.binding.job_id)
                assert job.phase == "completed" and job.result_ref == ids["result"]
                assert job.usage == {"thread_cpu_ms": terminal.actual_cpu_ms}
                budget = db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (prepared.binding.parent_budget_lease_ref, prepared.binding.reservation_operation_id)).fetchone()
                assert budget[0] in {"settled", "overrun"}
                assert json.loads(budget[1]) == {"thread_cpu_ms": terminal.actual_cpu_ms}
                result_source = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?",
                    (adopted["source_refs"][0],)).fetchone()[0])
                assert result_source["source_kind"] == "simulated" and result_source["assertion_status"] == "unknown"
                assert json.loads(result_source["text"])["computed_at_utc"] == terminal.result.computed_at_utc
            # A legitimate later Graph commit must not invalidate immutable
            # completion history or cause the once-claimed CPU work to rerun.
            command(case, "evaluate_values", EvaluateCurrentValuesRequestV1("missing:offline-values", "missing:offline-context"))
            assert graph.adopt_current_offline_tick_v1(case["bootstrap"], namespace=ns,
                prepared_original_ref=prepared.binding.prepared_original_ref) == adopted
            assert port.execute_d11_offline_tick_v1(binding=prepared.binding) == (claim, terminal)

            historical_request = RegisterCurrentOfflineScheduleInputRequestV1("offline-schedule:historical-acceptance", 0,
                60, 4, 100, (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat().replace("+00:00", "Z"),
                ("consolidation", "context"))
            command(case, "register_offline_schedule", historical_request, producer=True)
            with store._lock:
                row = store._db.execute("SELECT original_ref FROM graph_d11_offline_originals_v1 WHERE bot=? AND persona=? "
                    "AND kind='registered_schedule' AND json_extract(payload_json,'$.schedule_id')=?",
                    (*ns.as_tuple, historical_request.schedule_id)).fetchone()
                historical_schedule = read_current_d11_offline_value_v1(store._db, namespace=ns,
                    original_ref=row[0], issuer=case["d11_issuer"])
            historical_ids = offline_tick_ids_v1(ns, historical_schedule.schedule_ref, historical_schedule.starts_at_utc)
            with domain_owner(case) as (authority, lease):
                graph.run_current_domain_operation_v1(authority, lease, operation_kind="prepare_offline_tick",
                    request=PrepareCurrentOfflineTickRequestV1(historical_schedule.schedule_ref, historical_schedule.starts_at_utc),
                    operation_id=historical_ids["operation"], activity_id=historical_ids["activity"], audience_ref="owner",
                    parent_budget_lease_ref=case["policy"].root_grant.lease_id)
            with store._lock:
                historical_prepared = read_prepared_offline_tick_v1(store._db, namespace=ns,
                    prepared_original_ref=historical_ids["prepared"], issuer=case["d11_issuer"])
            _, historical_terminal = port.execute_d11_offline_tick_v1(binding=historical_prepared.binding)
            assert historical_terminal.status == "completed"
            # Close a real completed execution through the explicit historical
            # cost-only operation. The unimported execution head intentionally
            # bars ordinary current Owner writes until this closure completes.
            # No Graph guard or Authority anchor is edited to bypass that gate.
            historical = graph.reconcile_historical_offline_tick_cost_v1(case["bootstrap"], binding=historical_prepared.binding)
            assert historical["adoption_status"] == "not_adopted"
            assert historical["actual_cpu_ms"] == historical_terminal.actual_cpu_ms
            assert historical["job_disposition"] == "failed" and "source_refs" not in historical
            with store._lock:
                validate_domain_production_schema_v1(store._db)
                assert get_job(store._db, historical_prepared.binding.job_id).phase == "failed"
                from sylanne3.memory_types import source_key
                assert store._db.execute("SELECT 1 FROM graph_atoms WHERE token=?",
                    (source_key(*ns.as_tuple, historical_ids["source"]).token,)).fetchone() is None
            assert graph.reconcile_historical_offline_tick_cost_v1(case["bootstrap"], binding=historical_prepared.binding) == historical
            # Prepare a third genuine tick, then cancel it before any claim.
            cancel_request = RegisterCurrentOfflineScheduleInputRequestV1("offline-schedule:cancel-acceptance", 0,
                60, 4, 100, (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat().replace("+00:00", "Z"),
                ("consolidation", "context"))
            command(case, "register_offline_schedule", cancel_request, producer=True)
            with store._lock:
                row = store._db.execute("SELECT original_ref FROM graph_d11_offline_originals_v1 WHERE bot=? AND persona=? "
                    "AND kind='registered_schedule' AND json_extract(payload_json,'$.schedule_id')=?",
                    (*ns.as_tuple, cancel_request.schedule_id)).fetchone()
                cancel_schedule = read_current_d11_offline_value_v1(store._db, namespace=ns,
                    original_ref=row[0], issuer=case["d11_issuer"])
            cancel_ids = offline_tick_ids_v1(ns, cancel_schedule.schedule_ref, cancel_schedule.starts_at_utc)
            with domain_owner(case) as (authority, lease):
                graph.run_current_domain_operation_v1(authority, lease, operation_kind="prepare_offline_tick",
                    request=PrepareCurrentOfflineTickRequestV1(cancel_schedule.schedule_ref, cancel_schedule.starts_at_utc),
                    operation_id=cancel_ids["operation"], activity_id=cancel_ids["activity"], audience_ref="owner",
                    parent_budget_lease_ref=case["policy"].root_grant.lease_id)
            with store._lock:
                cancel_prepared = read_prepared_offline_tick_v1(store._db, namespace=ns,
                    prepared_original_ref=cancel_ids["prepared"], issuer=case["d11_issuer"])
            assert port.read_historical_d11_offline_tick_original_v1(binding=cancel_prepared.binding) == (None, None)
            cancelled = graph.cancel_unstarted_offline_tick_v1(case["bootstrap"], binding=cancel_prepared.binding)
            assert cancelled["status"] == "cancelled_unstarted" and "actual_cpu_ms" not in cancelled
            assert cancelled["released_ceiling"] == {"thread_cpu_ms": 100}
            with store._lock:
                validate_domain_production_schema_v1(store._db)
                assert get_job(store._db, cancel_prepared.binding.job_id).phase == "cancelled"
                assert store._db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (cancel_prepared.binding.parent_budget_lease_ref, cancel_prepared.binding.reservation_operation_id)).fetchone() == ("cancelled_unstarted", None)
                from sylanne3.runtime.c09_budget_rows_v1 import validate_c09_budget_schema_v1
                validate_c09_budget_schema_v1(store._db)
            assert graph.cancel_unstarted_offline_tick_v1(case["bootstrap"], binding=cancel_prepared.binding) == cancelled
            with pytest.raises((ValueError, RuntimeError)):
                port.execute_d11_offline_tick_v1(binding=cancel_prepared.binding)
            assert port.read_historical_d11_offline_tick_original_v1(binding=cancel_prepared.binding) == (None, None)
        await asyncio.to_thread(accept)

    await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
        after_role_initialization=after_role, enable_d09_workbench=True, enable_d04_root_cpu=True,
        enable_c04_body_work=True, enable_d10_offline_ticks=True,
        extra_owner_purposes=("context", "consolidation"))


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy_state", ("ST0", "ST2"))
async def test_actual_d01_method_projection_uses_adopted_d07_scope_and_rejects_new_counterjudgment(
        tmp_path, installed_d04_root, monkeypatch, strategy_state):
    """Real Owner/C02/D07/D01 originals; no check, quote or completed effect is seeded.

    Controlled model findings test the production source/current projection,
    not method execution or benefit. Actual hard-qualified D08 dispatch remains
    a separate acceptance until its check/quote producer is registered.
    """
    import hmac
    from sylanne3.domains.d01 import PersonaPlan, PersonaBlock, FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.domains.d07 import METHOD_CONDITION_IDS_V1, method_condition_question_v1
    from sylanne3.domains.d08.personal_plan_v1 import PLAN_TYPE, PersonalPlanV1, PlanNodeV2
    from sylanne3.domains.d02.body_quote_original import D02BodyQuoteAuthority
    from sylanne3.host.v2_installation import V2InstallationAssembly
    from sylanne3.authority_service.d07_cognition_result_service_v1 import AuthorityD07CognitionResultServiceV1
    from sylanne3.model_broker.d07_cognition_v1 import OUTPUT_SCHEMA
    from sylanne3.runtime.d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    from sylanne3.runtime.d07_execution_v1 import D07SemanticQuestionV1, read_prepared_d07_execution_v1
    from sylanne3.runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    from sylanne3.runtime.d08_personal_plan_v1 import CreateCurrentPersonalPlanRequestV1
    from sylanne3.runtime.domain_production_inputs_v1 import RegisterCurrentSemanticQuestionInputRequestV1
    from sylanne3.runtime.domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from sylanne3.runtime.budget import get_budget_lease
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime_contracts import VersionedRef, canonical_serialize
    from test_d07_installed_execution_product_v1 import d07_workflows
    import test_post_c02_reply_assembly_v2 as donor

    # Authored fixture input enters the real role initialization transaction.
    # This does not seed a current head or invent a learning history.
    def authored_method_plan(plan_id, namespace, version, blocks, values, authored):
        claim = canonical_serialize({"schema": "d01.method-policy.v1", "policy_id": "CP-tone-order",
            "strategy_state": strategy_state})
        return PersonaPlan(plan_id, namespace, version,
            (*blocks, PersonaBlock("method:tone-order", "strategy", claim, "growth")), values, authored)
    monkeypatch.setattr(donor, "PersonaPlan", authored_method_plan)
    initialized = {}

    async def after_role(case):
        def initialize():
            initialize_owner_root_v3(case)
            adopt_mapping_and_clock(case)
            for domain in ("d01", "d07", "d08"):
                if domain not in case["graph"]._GraphCoordinator__providers:
                    registration = case["domain_registry"].registrations[domain]
                    case["graph"].register_provider(case["bootstrap"], domain, registration.provider,
                        registration.proposal_schema, registration.proposal_schema_hash)
            initialized.update(case)
        await asyncio.to_thread(initialize)

    async def after_c02(current):
        case = {**initialized, **current}
        graph, store, ns = case["graph"], case["store"], case["namespace"]
        bundle = replace(case["installed_bundle"], d02_signing_key=b"reply-issuer-key-" * 2,
            d11_signing_key=b"reply-issuer-key-" * 2, ingress_clock=case["ingress_clock"])
        assembly = V2InstallationAssembly(bundle.installation_policy, case["client_grant"], bundle.d11_signing_key,
            bundle.d02_signing_key, lambda: case["port"], installed_d04_root, tmp_path,
            ingress_clock=bundle.ingress_clock, admin_bundle=bundle)
        class Worker:
            async def call(self, call):
                return await asyncio.to_thread(call, graph)
        graph._GraphCoordinator__body_quote_authority = D02BodyQuoteAuthority(hmac.digest(
            bundle.d02_signing_key, b"sylanne3.d02.body_quote_original.v1\0" + bundle.installation_policy.installation_id.encode(), "sha256"))
        service = InstalledD07ExecutionServiceV1(graph=graph, bootstrap=case["bootstrap"], bundle=bundle,
            installation=assembly, worker=Worker(), authority_client=case["authority_client"],
            client_grant=case["client_grant"], context=case["model_context"], owner_loop=asyncio.get_running_loop())
        graph._GraphCoordinator__d07_execution_service_v1 = service
        graph._GraphCoordinator__body_quote_authority = service.body_authority
        graph._GraphCoordinator__domain_production_runtime_v1 = InstalledDomainOperationRuntimeV1(graph, case["bootstrap"])
        reader = AuthorityD07CognitionResultServiceV1(store=case["model_store"], fences=case["protected"],
            graph_db_path=store._db.execute("PRAGMA database_list").fetchone()[2], d11_issuer=case["d11_issuer"],
            installation_id=bundle.installation_policy.installation_id, read_subject=case["client_grant"].subject,
            holder=bundle.installation_policy.administrator_holder, trusted_now_utc=time.time)
        case["server"].install_d07_cognition_result_reader_v1(case["authority_namespace"], reader)
        # Use the actual installed executor explicitly, without racing its auto-wake.
        service.wake_committed_job_v1 = lambda ref: True
        audience = case["ingress"].conversation_ref
        source_ref = case["source_ref"]
        source_revision = store._db.execute("SELECT revision FROM graph_atoms WHERE token=?", (source_ref,)).fetchone()[0]
        body = FixedBodyPolicyV1("body-policy:method-scope", 1,
            BodyProfile("body:method-scope", ns, 1, ("cognitive",), ("d07.cognition",)),
            BodyState("body:method-scope", 1, 1.0, {"cognitive": 0.0}, 0.0, 0.0),
            "d07.cognition", WorkComponent("bounded-method-judgment", "cognitive", 0.0625, 0.0), time.time() + 3600)
        def install_body():
            with domain_owner(case) as (authority, lease):
                graph.register_current_fixed_body_work_policy_v1(case["bootstrap"], authority, lease,
                    operation_id=str(uuid4()), policy=body)
        await asyncio.to_thread(install_body)
        activity = "activity:method-plan"
        owner = Owner("activity", *ns.as_tuple, activity)
        goal_ref = AtomKey(owner, "d08.goal.v1", "goal:method-choice").token
        plan_ref = AtomKey(owner, PLAN_TYPE, "plan:method-choice").token
        predicate = GoalPredicate("domain_state", "d07", (("target", source_ref),), 0.0, None)
        goal = Goal("goal:method-choice", 1, "active", predicate, (source_ref,), (), None, ("user_stop",), ())
        full = PlanNodeV2("task:full", "persona:" + ns.persona_id, (), "artifact_draft_v1", predicate,
            True, None, "resource:method-choice", observable_postconditions=(predicate,), cost_ceiling=(("thread_cpu_ms", 10),))
        sample = replace(full, node_id="task:sample")
        plan = PersonalPlanV1("plan:method-choice", 1, goal_ref, 1, "active", "persona:" + ns.persona_id,
            (full, sample), ("candidate:full", "candidate:sample"), (), (), ("user_stop",), (source_ref,),
            (VersionedRef(source_ref, source_revision),), None,
            method_candidates=(("candidate:full", FULL_DRAFT_METHOD_V1), ("candidate:sample", TONE_SAMPLE_METHOD_V1)))
        created = await asyncio.to_thread(command, case, "create_personal_plan",
            CreateCurrentPersonalPlanRequestV1(source_ref, goal, plan), audience=audience, activity_id=activity)
        assert created["coverage"] == "complete"
        provider_calls = [0]
        transport = case["model_http_client"]._transport
        actual_handler = transport.handler
        def counted_response(request):
            provider_calls[0] += 1
            return actual_handler(request)
        transport.handler = counted_response

        async def adopt_condition(condition_id, truth):
            scope = method_condition_question_v1(goal_ref, 1, condition_id)
            question_ref = "semantic:method:" + str(uuid4())
            question = D07SemanticQuestionV1(scope,
                "For the exact registered goal, assess the explicitly supplied condition " + condition_id + ". Return a Boolean judgment.",
                VersionedRef(goal_ref, 1), (source_ref,))
            registered = await asyncio.to_thread(command, case, "register_semantic_question",
                RegisterCurrentSemanticQuestionInputRequestV1(question_ref, question), audience=audience, producer=True)
            assert registered["coverage"] == "complete"
            concern_operation = str(uuid4())
            concern_activity = "activity:method-condition:" + str(uuid4())
            def serve_concern():
                with domain_owner(case) as (authority, lease):
                    return graph.run_current_domain_operation_v1(authority, lease,
                        operation_kind="serve_concern", request=ServeCurrentConcernRequestV1("interaction", question_ref),
                        operation_id=concern_operation, activity_id=concern_activity, audience_ref=audience,
                        parent_budget_lease_ref=case["policy"].root_grant.lease_id)
            # D07 preparation has its own committed operation and signed
            # execution original; it is not a generic adopted-domain stage.
            deferred = await asyncio.to_thread(serve_concern)
            assert deferred["coverage"] == "deferred"
            job_id = deferred["job_states"][0][0]
            prepared = read_prepared_d07_execution_v1(store._db, case["d11_issuer"], ns, job_id)
            assert prepared.operation_id == concern_operation
            assert deferred["operation_id"] == concern_operation
            assert deferred["prepare_operation_id"] == prepared.prepare_operation_id
            assert prepared.prepare_operation_id == "d07-prepare:" + concern_operation
            assert deferred["receipt"]["status"] == "committed"
            assert deferred["receipt"]["operation_id"] == prepared.prepare_operation_id
            assert prepared.job_id == job_id and prepared.activity_id == concern_activity
            assert get_job(store._db, job_id).phase == "queued"
            frozen = json.loads(prepared.frozen_json)
            roots = [row["source_ref"]["ref"] for row in frozen["input"]["sources"]]
            case["model_reply_mode"]["content"] = json.dumps({"schema": OUTPUT_SCHEMA,
                "input_digest": frozen["input_digest"], "question_key": scope, "work_kind": "concern",
                "resolved_slots": [], "discriminating_refs": [], "predictions": [],
                "findings": [{"proposition": "true" if truth else "false", "source_refs": roots,
                    "qualification": "subjective", "stance": "support", "subjective_conviction": 0.75,
                    "evidence_status": "supported"}], "unknowns": [], "stop_reason": "bounded_segment_complete"})
            adopted = await service.execute_current_d07_job_v1(get_job(store._db, job_id))
            assert adopted["status"] == "adopted" and len(adopted["interpretation_refs"]) == 1
            return adopted["interpretation_refs"][0]

        try:
            condition_refs = []
            for index, condition in enumerate(METHOD_CONDITION_IDS_V1):
                condition_refs.append(await adopt_condition(condition, index < 6))
            frozen = await asyncio.to_thread(command, case, "freeze_values",
                FreezeCurrentValuesInputRequestV1("values:method", "context:method"), audience=audience, producer=True)
            assert frozen["coverage"] == "complete"
            evaluated = await asyncio.to_thread(command, case, "evaluate_values",
                EvaluateCurrentValuesRequestV1("values:method", "context:method"), audience=audience)
            assert evaluated["coverage"] == "complete"
            def provenance(receipt):
                row = store._db.execute("SELECT original_payload_json FROM graph_domain_production_originals_v1 "
                    "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, receipt["operation_id"])).fetchone()
                return json.loads(row[0])["provenance"]
            current = provenance(evaluated)
            projection = current["method_strategy"]
            expected_edge = ["candidate:sample", "candidate:full"] if strategy_state == "ST2" else ["candidate:full", "candidate:sample"]
            assert projection["preference_edges"] == [expected_edge]
            assert projection["applicability"] == "applicable" and projection["strategy_state"] == strategy_state
            assert projection["plan_head"]["key"] == plan_ref and projection["goal_head"]["key"] == goal_ref
            assert {head["key"] for head in projection["condition_heads"]} == set(condition_refs)
            assert len(projection["condition_originals"]) == len(METHOD_CONDITION_IDS_V1)
            assert projection["condition_query_epoch"]["namespace"] == plain_v1(ns)
            assert current["evaluation"]["rejected"] == [] and current["evaluation"]["action_authorized"] is False
            candidate_wire = json.loads(store._db.execute("SELECT payload_json FROM graph_d01_production_inputs_v1 "
                "WHERE bot=? AND persona=? AND original_ref='values:method'", ns.as_tuple).fetchone()[0])
            assert {head["key"] for head in candidate_wire["candidate_heads"]} == {plan_ref}
            assert {ref for ref, _ in candidate_wire["candidates"]} == set(plan.candidate_refs)
            assert "method_candidates" not in candidate_wire
            # Insert a genuine newly adopted opposite interpretation while all
            # positive old heads remain present. The old complete negative scope
            # must no longer authorize the previous method preference.
            await adopt_condition("tone_multiple_legal_readings", False)
            used_before = dict(get_budget_lease(store._db, case["policy"].root_grant.lease_id).used)
            reserved_before = dict(get_budget_lease(store._db, case["policy"].root_grant.lease_id).reserved)
            calls_before = provider_calls[0]
            held = await asyncio.to_thread(command, case, "evaluate_values",
                EvaluateCurrentValuesRequestV1("values:method", "context:method"), audience=audience)
            assert held["coverage"] == "waiting_for_original"
            assert "current_complete_method_condition_scope" in held["missing_inputs"]
            assert not held["receipt"]["write_versions"]
            assert provider_calls[0] == calls_before
            assert dict(get_budget_lease(store._db, case["policy"].root_grant.lease_id).used) == used_before
            assert dict(get_budget_lease(store._db, case["policy"].root_grant.lease_id).reserved) == reserved_before
            assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? "
                "AND type_name='d08.action_intent.v1'", ns.as_tuple).fetchone() == (0,)
            await asyncio.to_thread(command, case, "freeze_values",
                FreezeCurrentValuesInputRequestV1("values:counterjudgment", "context:counterjudgment"), audience=audience, producer=True)
            rechecked = await asyncio.to_thread(command, case, "evaluate_values",
                EvaluateCurrentValuesRequestV1("values:counterjudgment", "context:counterjudgment"), audience=audience)
            assert rechecked["coverage"] == "complete"
            assert provenance(rechecked)["method_strategy"]["preference_edges"] == []
            assert provenance(rechecked)["method_strategy"]["applicability"] == "unknown"
            assert provenance(evaluated) == current
        finally:
            transport.handler = actual_handler
            await service.close_v1()

    await real_owner_case(tmp_path, "owned", natural_workflow_builder=d07_workflows,
        installed_package_root=installed_d04_root, after_role_initialization=after_role,
        continue_to_ingress=True, after_c02=after_c02, enable_d09_workbench=True, enable_d04_root_cpu=True,
        ingress_text="Structure and materials are complete. The target is 600 to 900 words with two legal tone readings. "
            "One 120 to 180 word tone sample is permitted. Budget and deadline allow either method. "
            "This is neither a short draft nor an urgent request for the full draft; no factual or permission gap remains.",
        extra_owner_capabilities=("d02.body_policy.install",), extra_owner_purposes=("context", "consolidation"))


@pytest.mark.asyncio
async def test_installed_relationship_authored_prior_and_actual_shared_c3_revision_v2(installed_m1_phase_fixture_v2):
    """Fresh V5: real routing, independent Owner prior, then one actual C3 finding.

    The local endpoint authors the subjective finding explicitly. It supplies
    its ordinary installed simulated-provider original; no receipt, Source,
    contact permission, second event, confidence or paid balance is seeded.
    SourceNote selection and C04 remain separate qualified business nodes.
    """
    from m1_artifact_draft_acceptance_support_v1 import run_installed_m1_phase_case_v2, prepare_actual_m1_phase_recall_v2
    from sylanne3.host.model_workflows_v5 import AdminModelWorkflowsV5
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.domains.d05.relationship_revision_v2 import (
        RelationshipScopeV2, RelationshipDimensionRuleV2, InstalledRelationshipPolicyV2,
        RelationshipEvaluationCandidateV2, CHECKPOINT_TYPE, ESTIMATE_TYPE, CONTRIBUTION_TYPE,
    )
    from sylanne3.graph_types import GraphVersion
    from sylanne3.runtime_contracts import VersionedRef, canonical_digest
    from sylanne3.runtime.d05_relationship_revision_v2 import (
        InitializeCurrentRelationshipPriorRequestV2, AdoptCurrentRelationshipRevisionRequestV2,
        relationship_evaluation_question_scope_v2,
    )
    from sylanne3.runtime.d07_execution_v1 import D07RelationshipSemanticQuestionV2
    from sylanne3.runtime.d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    from sylanne3.runtime.domain_production_inputs_v1 import RegisterCurrentSemanticQuestionInputRequestV1
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1, read_observed_foreground_call_plan_v1
    from sylanne3.runtime.foreground_call_plan_v1 import SLOTS
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.d07_execution_v1 import read_prepared_d07_execution_v1, D07RelationshipPreparedV2
    from sylanne3.runtime.domain_production_erasure_v1 import validate_domain_production_schema_v1

    assert type(installed_m1_phase_fixture_v2.workflows) is AdminModelWorkflowsV5
    assert installed_m1_phase_fixture_v2.workflows.d07_relationship_cognition is not None

    async def after_c02(case):
        worker, graph, ns = case["phase_worker"], case["graph"], case["namespace"]
        await prepare_actual_m1_phase_recall_v2(case)
        service = case["phase_c3_runtime"]
        def actual_scope(current_graph):
            store = case["store"]
            with store._lock:
                db = store._db
                account = json.loads(db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND type_name='d03.account_binding' AND valid=1 ORDER BY token LIMIT 1", ns.as_tuple).fetchone()[0])
                subject = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.entity_anchor' "
                    "AND valid=1 AND json_extract(value,'$.entity_id')=? LIMIT 2", (*ns.as_tuple, account["entity_id"])).fetchall()
                assert len(subject) == 1
                authored = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='memory.source' "
                    "AND valid=1 AND json_extract(value,'$.source_kind')='authored' ORDER BY token LIMIT 1", ns.as_tuple).fetchone()
                assert authored is not None, "actual independent authored Source is required; never synthesize a prior source"
                event = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.world_event' AND valid=1 "
                    "AND EXISTS(SELECT 1 FROM json_each(graph_atoms.value,'$.source_refs') WHERE value=?) LIMIT 2", (*ns.as_tuple, case["source_ref"])).fetchall()
                assert len(event) == 1
                return RelationshipScopeV2(ns, GraphVersion(AtomKey.from_token(subject[0][0]), subject[0][1]),
                    None, "fixture_subjective_familiarity", "owner-declared-fixture-context", "familiarity", "fixture-v1"), authored[0], event[0][0]
        scope, authored_ref, event_ref = await worker.call(actual_scope)
        # These fixture numbers are explicit authored test policy, never production defaults.
        rule = RelationshipDimensionRuleV2("familiarity", "Fixture-only subjective familiarity with the actual canonical participant",
            scope.relationship_domain, scope.context_ref, scope.dimension_schema_version, "installed",
            (("external_interaction", 0.10), ("internal_recollection", 0.10), ("simulated_trial", 0.10)),
            0.25, 0.50, ("source_note",), ("source_note",), (), False, authored_ref, 0.0, False, 0.0)
        policy = InstalledRelationshipPolicyV2("relationship-policy:actual-v5-fixture", 1, ns, ("familiarity",),
            ("external_observation", "recollection", "simulation"), ("self_internal",), (rule,), (authored_ref,), "authored", 8, 16, 2)
        await worker.call(lambda current_graph: command(case, "install_relationship_policy", InstallCurrentRelationshipInputRequestV1(policy), producer=True))
        before_calls = tuple(case["phase_provider_calls"])
        initialization_id = str(uuid4())
        initialized = await worker.call(lambda current_graph: command(case, "initialize_relationship_prior_v2",
            InitializeCurrentRelationshipPriorRequestV2(scope, policy.policy_ref), operation_id=initialization_id))
        assert initialized["coverage"] == "complete"
        assert tuple(case["phase_provider_calls"]) == before_calls
        def initial_original(current_graph):
            with case["store"]._lock:
                db = case["store"]._db
                estimate = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?", (scope.key(ESTIMATE_TYPE).token,)).fetchone()[0])
                checkpoint = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?", (estimate["checkpoint_ref"],)).fetchone()[0])
                assert checkpoint["initialization_kind"] == "authored_prior"
                assert checkpoint["initialization_original_ref"] == initialization_id
                assert estimate["estimate"] == 0.0 and estimate["checkpoint_total_variation"] == 0.0
                assert not estimate["contribution_refs"] and not estimate["external_event_identities"]
                return estimate
        await worker.call(initial_original)
        # Only actual current cycle metadata supplies the shared CallPlan binding.
        def cycle_head(current_graph):
            with case["store"]._lock:
                db = case["store"]._db
                rows = db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
                    "AND work_kind='d11.foreground_cycle.v1' AND json_extract(continuation_json,'$.c02_operation_id')=? LIMIT 2",
                    (*ns.as_tuple, case["c02"].operation_id)).fetchall()
                assert len(rows) == 1
                job = get_job(db, rows[0][0])
                from sylanne3.runtime.d11_types import job_graph_write
                ref = job_graph_write(job).key
                revision, raw = db.execute("SELECT revision,value FROM graph_atoms WHERE token=?", (ref.token,)).fetchone()
                return GraphVersion(ref, revision), canonical_digest(json.loads(raw)), job
        cycle_version, cycle_digest, cycle_job = await worker.call(cycle_head)
        policy_digest = canonical_digest(plain_v1(policy))
        question_ref = "d07-relationship-question:" + str(uuid4())
        semantic = D07RelationshipSemanticQuestionV2(
            question_key=relationship_evaluation_question_scope_v2(scope, event_ref, policy.policy_ref, policy_digest),
            question="Return the closed D05 subjective relationship candidate for this actual source, with its explicit installed policy bound.",
            target_ref=VersionedRef(scope.subject_head.key.token, scope.subject_head.revision), source_refs=(case["source_ref"],),
            cycle_ref=cycle_version, cycle_digest=cycle_digest, scope=scope, trigger_original_ref=event_ref,
            policy_ref=policy.policy_ref, policy_revision=policy.revision, policy_digest=policy_digest)
        await worker.call(lambda current_graph: command(case, "register_semantic_question",
            RegisterCurrentSemanticQuestionInputRequestV1(question_ref, semantic), producer=True))
        now = time.time()
        candidate = RelationshipEvaluationCandidateV2(scope, event_ref, "external_interaction", 0.05, None, None,
            None, (), 0.25, "partial", (case["source_ref"],), (), (), (), (case["source_ref"],), ("source_note",),
            now - 1, now + 30, None, None, None)
        case["model_reply_mode"]["relationship_candidate"] = plain_v1(candidate)
        prepared_receipt = await worker.call(lambda current_graph: command(case, "serve_concern",
            ServeCurrentConcernRequestV1("interaction", question_ref)))
        assert prepared_receipt["coverage"] == "deferred"
        await asyncio.sleep(0)
        assert service._runner_task is not None
        await service._runner_task
        job_id = prepared_receipt["job_states"][0][0]
        def adopted(current_graph):
            with case["store"]._lock:
                prepared = read_prepared_d07_execution_v1(case["store"]._db, case["d11_issuer"], ns, job_id)
                assert type(prepared) is D07RelationshipPreparedV2
                return service._last_progress[job_id]
        actual = await worker.call(adopted)
        assert actual["status"] == "adopted", actual
        revision_request = AdoptCurrentRelationshipRevisionRequestV2(actual["interpretation_refs"][0], policy.policy_ref)
        revised = await worker.call(lambda current_graph: command(case, "adopt_relationship_revision_v2", revision_request))
        assert revised["coverage"] == "complete"
        def rich_originals(current_graph):
            with case["store"]._lock:
                db = case["store"]._db
                estimate = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?", (scope.key(ESTIMATE_TYPE).token,)).fetchone()[0])
                assert estimate["estimate"] == 0.05 and estimate["checkpoint_total_variation"] == 0.05
                assert len(estimate["external_event_identities"]) == len(estimate["independent_families"]) == 1
                assert len(estimate["contribution_refs"]) == 1
                cycle = foreground_cycle_from_wire_v1(get_job(db, cycle_job.job_id).continuation)
                observed = read_observed_foreground_call_plan_v1(db, namespace=ns, continuation=cycle,
                    issuer=case["d11_issuer"], installed_bundle=case["installed_bundle"])
                assert sum(SLOTS[row.slot][3] for row in observed.attempts) == 2
                assert len([row for row in observed.attempts if row.slot == "C3"]) == 2
                assert validate_domain_production_schema_v1(db)
                return estimate
        estimate = await worker.call(rich_originals)
        calls_after = tuple(case["phase_provider_calls"])
        duplicate = await worker.call(lambda current_graph: command(case, "adopt_relationship_revision_v2", revision_request))
        assert not duplicate["receipt"]["write_versions"] and not duplicate["outbox"]
        assert tuple(case["phase_provider_calls"]) == calls_after
        current = await worker.call(lambda current_graph: relations_api(case))
        dimension = next(row for relation in current.projection["data"]["relations"] for row in relation["dimensions"] if "domain" in row)
        assert dimension["estimate"] == 0.05 and dimension["time_status"] == "current"
        # Observe real expiry once; no caller time or altered stored estimate is supplied.
        await asyncio.sleep(max(0.0, candidate.valid_until - time.time() + 0.05))
        expired = await worker.call(lambda current_graph: relations_api(case))
        dimension = next(row for relation in expired.projection["data"]["relations"] for row in relation["dimensions"] if "domain" in row)
        assert dimension["estimate"] == "unknown" and dimension["time_status"] == "stale"
        assert tuple(case["phase_provider_calls"]) == calls_after
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02, owner_controls=True)
