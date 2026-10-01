"""Installed D07 current readers around its existing single pure issuer.

The execution service owns real quote/preparation/model/Authority/result/cost
work. This adapter independently reads current D12 policy and original DB
tickets, sources, rounds and jobs. It never constructs a successful terminal.
"""
from __future__ import annotations

from dataclasses import replace
import json

from ..domains.d01.production_operations_v1 import stage_result_v1
from ..domains.d07 import D07DomainProvider
from ..domains.d07.concern_round import concern_round_key
from ..domains.d12.types import active_scheme_head_key
from ..graph_types import AtomKey, Owner, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1, raw_head_value_v1, table_exists_v1, waiting_stage_v1
from .d07_current_behavior_v1 import (
    AdvanceCurrentReflectionRequestV1, RunCurrentSimulationRequestV1, ServeCurrentConcernRequestV1,
    advance_current_concerns_v1, advance_current_reflection_v1, run_current_simulation_v1,
)
from .d12_current_d07_policy_v1 import read_current_d07_attention_policy_v1
from .domain_production_contracts_v1 import StagedDomainOperationV1
from .issuers import D11BudgetJobIssuer


class InstalledD07ProductionReadersV1:
    def __init__(self, *, issuer, execution_reader=None):
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("D07 needs the installed D11 cognition preparation issuer")
        if execution_reader is not None:
            from .d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
            if type(execution_reader) is not InstalledD07ExecutionServiceV1:
                raise TypeError("D07 needs the actual installed execution service")
        self.issuer, self.execution_reader = issuer, execution_reader

    def port(self, db, frame):
        if self.execution_reader is None:
            raise MissingProductionOriginalV1("installed_actual_d07_execution_service")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        policy = read_current_d07_attention_policy_v1(db, frame.envelope.authority.namespace)
        if policy.active_head_ref not in frame.snapshot.versions:
            raise ValueError("D07 adopted policy head or absence is not in its exact current read set")
        from ..host.installed_d07_behavior_port_v1 import InstalledD07BehaviorPortV1
        executor_ref = getattr(self.execution_reader, "installed_executor_ref", "d07.installed-cognition-executor.v1")
        return InstalledD07BehaviorPortV1(frame, policy=policy.policy,
            execution_reader=self.execution_reader, installed_executor_ref=executor_ref)


def _stage_current(db, frame, request, readers, kind, compiler, reader_name):
    if type(readers) is not InstalledD07ProductionReadersV1:
        raise TypeError("exact installed D07 current readers required")
    try:
        port = readers.port(db, frame)
        inputs = getattr(port, reader_name)(db, frame.envelope, request)
        stage = compiler(frame.envelope, request, inputs)
        if stage.status != "queued":
            from .d07_reflection_execution_v1 import stage_actual_d07_reflection_stop_v1
            stage = stage_actual_d07_reflection_stop_v1(db, readers.issuer, stage)
        if stage.status == "queued":
            preparation = readers.execution_reader.prepare_current_stage_in_transaction_v1(db, frame, stage)
            from .d07_execution_v1 import D07PreparationStageV1
            if type(preparation) is not D07PreparationStageV1:
                raise ValueError("D07 queue requires its actual dedicated preparation stage")
            frame, stage = preparation.frame, preparation.stage
            # A queued stage needs the exact signed quote and the original
            # reservation. Presence of a string resource ref alone is useless.
            quote, grant, lease = readers.issuer._admission_state(frame.envelope, db, now_utc=frame.now_utc)
            if quote.work_kind != "d07.cognition":
                raise ValueError("D07 queued work has another registered resource quote")
            reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (lease.lease_id, frame.envelope.identity.operation_id)).fetchone()
            if reservation is None or reservation[2] != "reserved" or json.loads(reservation[1]) != dict(quote.ceiling):
                raise MissingProductionOriginalV1("actual_d07_signed_quote_and_parent_reservation")
            if reservation[0] != preparation.prepared.reservation_digest:
                raise ValueError("D07 reservation differs from the actual immutable preparation")
            return preparation
        original_ref = "d07-current:" + canonical_digest((frame.envelope.authority.namespace,
            frame.envelope.identity.operation_id))[:48]
        result = port.as_staged_domain_operation(stage, original_ref)
        return verify_d07_production_stage_v1(result)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d07", kind, request, missing)


def stage_serve_current_concern_in_transaction_v1(db, *, frame, request, installed_readers):
    return _stage_current(db, frame, request, installed_readers, "serve_concern",
                          advance_current_concerns_v1, "read_concern")


def stage_advance_current_reflection_in_transaction_v1(db, *, frame, request, installed_readers):
    return _stage_current(db, frame, request, installed_readers, "advance_reflection",
                          advance_current_reflection_v1, "read_reflection")


def stage_run_current_simulation_in_transaction_v1(db, *, frame, request, installed_readers):
    return _stage_current(db, frame, request, installed_readers, "run_simulation",
                          run_current_simulation_v1, "read_simulation")


def verify_d07_production_stage_v1(stage):
    if type(stage) is not StagedDomainOperationV1 or stage.domain != "d07" or stage.operation_kind not in {
            "concern", "reflection", "simulation", "serve_concern", "advance_reflection", "run_simulation"}:
        raise ValueError("unregistered D07 current stage")
    specs = {spec.name: spec for spec in D07DomainProvider.type_specs()}
    allowed = {"d07.concern_round.v1", "d07.cognitive_activity.v1", "d07.working_set.v1",
               "d07.reflection_checkpoint.v1", "d07.simulation_branch.v1"}
    for proposal in stage.proposals:
        if proposal.proposal_schema != "d07.proposal.v1" or proposal.proposal_schema_hash != D07DomainProvider().descriptor.request_schema_hash:
            raise ValueError("D07 current proposal schema differs")
        for write in proposal.typed_writes:
            if write.key.type_name not in allowed or write.key.type_name not in specs:
                raise ValueError("D07 behavioral stage may not issue another graph type or C04 interpretation")
            spec = specs[write.key.type_name]
            if write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D07 behavioral write owner differs")
            spec.validator(write.value)
    return stage


def read_plan_current_d07_operation_v1(db, *, namespace, activity_id, operation_kind, request):
    types = ["d07.attention_ticket.v1", "d07.focus.v1", "d07.concern_round.v1",
             "d07.reflection_checkpoint.v1", "d07.working_set.v1", "d02.body_profile.v1",
             "d02.body_state.v1", "d02.reservation.v1"]
    keys = [owner_grant_key(*namespace.as_tuple), active_scheme_head_key(namespace)]
    roots, originals = [], []
    if operation_kind == "serve_concern" and type(request) is ServeCurrentConcernRequestV1:
        keys.append(concern_round_key(namespace, request.category))
        originals.append(request.trigger_original_ref)
        if table_exists_v1(db, "graph_d07_execution_originals_v1"):
            row = db.execute("SELECT payload_json FROM graph_d07_execution_originals_v1 WHERE bot=? AND persona=? "
                "AND kind='semantic_question' AND original_ref=?", (*namespace.as_tuple, request.trigger_original_ref)).fetchone()
            if row:
                question = json.loads(row[0])
                roots.extend(question["source_refs"])
                try:
                    keys.append(AtomKey.from_token(question["target_ref"]["ref"]))
                except (ValueError, TypeError):
                    target_ref = question["target_ref"]["ref"]
                    originals.append(target_ref)
                    from .d01_production_operations_v1 import raw_registered_input_v1
                    target = raw_registered_input_v1(db, "graph_d08_joint_plan_intents_v1", namespace, target_ref)
                    if target:
                        roots.extend(target["source_refs"])
                        keys.extend(AtomKey.from_token(ref) for ref in target["current_goal_refs"])
            else:
                row = db.execute("SELECT payload_json FROM graph_d07_execution_originals_v1 WHERE bot=? AND persona=? "
                    "AND kind='reflection_request' AND original_ref=?", (*namespace.as_tuple, request.trigger_original_ref)).fetchone()
                if row:
                    reflected = json.loads(row[0])
                    roots.extend(reflected["source_refs"])
                    keys.append(AtomKey.from_token(reflected["reflection_ref"]))
                    originals.extend(reflected[name] for name in ("cognition_adoption_receipt_ref",
                        "causal_root_ref", "causal_depth_original_ref"))
        rows = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d07.attention_ticket.v1' "
                          "AND valid=1 ORDER BY token LIMIT 129", namespace.as_tuple).fetchall()
        if len(rows) <= 128:
            for (encoded,) in rows:
                roots.extend(json.loads(encoded)["source_refs"])
    elif operation_kind == "advance_reflection" and type(request) is AdvanceCurrentReflectionRequestV1:
        keys.append(AtomKey.from_token(request.reflection_ref))
        originals.append(request.cognitive_terminal_ref)
    elif operation_kind == "run_simulation" and type(request) is RunCurrentSimulationRequestV1:
        originals.extend((request.simulation_request_ref, request.trigger_original_ref))
        if table_exists_v1(db, "graph_d07_execution_originals_v1"):
            row = db.execute("SELECT payload_json FROM graph_d07_execution_originals_v1 WHERE bot=? AND persona=? "
                "AND kind='simulation_request' AND original_ref=?",
                             (*namespace.as_tuple, request.simulation_request_ref)).fetchone()
            if row:
                original = json.loads(row[0])
                registered = original["request"]
                roots.extend(registered["snapshot_refs"])
                originals.append(original["dedicated_budget_ref"])
                from ..domains.d07 import SimulationRequest
                frozen = SimulationRequest(**{**registered,
                    "snapshot_refs": tuple(registered["snapshot_refs"]),
                    "alternatives": tuple(registered["alternatives"]),
                    "predictions": tuple(tuple(p) for p in registered["predictions"]),
                    "unknowns": tuple(registered["unknowns"])})
                # Branch keys depend only on the immutable assumptions and
                # source snapshot. Empty predictions never stand in for a
                # completed execution; they are used solely to plan rev0 reads.
                keys.extend(AtomKey(Owner("activity", *namespace.as_tuple, activity_id),
                    "d07.simulation_branch.v1", branch.branch_id)
                    for branch in D07DomainProvider.simulate(frozen).branches)
    else:
        raise ValueError("unregistered exact D07 production request")
    keys.append(AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "d07.cognitive_activity.v1", activity_id))
    if table_exists_v1(db, "runtime_jobs"):
        jobs = db.execute("SELECT continuation_json,result_ref,budget_ref FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
            "AND activity_id=? AND work_kind LIKE 'd07.%' ORDER BY job_id LIMIT 17", (*namespace.as_tuple, activity_id)).fetchall()
        if len(jobs) > 16:
            raise MissingProductionOriginalV1("bounded_current_d07_job_inventory")
        for continuation_json, result_ref, budget_ref in jobs:
            continuation = json.loads(continuation_json)
            if result_ref:
                originals.append(result_ref)
            for name in ("cognition_adoption_receipt_ref", "causal_root_ref", "causal_depth_original_ref", "dedicated_budget_original_ref"):
                if continuation.get(name):
                    originals.append(continuation[name])
            for ref in continuation.get("source_refs", ()):
                roots.append(ref)
            registered = continuation.get("registered_request")
            if registered:
                roots.extend(registered["snapshot_refs"])
                originals.append(budget_ref)
    return production_read_plan_v1(types, keys, roots, originals)
