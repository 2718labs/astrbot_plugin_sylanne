"""Permanent installed W01 domain acceptance with real paired Owner originals.

The fixture performs actual Authority/mTLS/Owner/root/C02 operations. Every
new input is registered through its public producing operation; no current
guard, completed effect, model finding, resource grant or consent is seeded.
"""
from contextlib import contextmanager
import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

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
