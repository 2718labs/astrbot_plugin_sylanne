"""D10 installed original readers and exact effect/experience bundle staging.

Plans, quotes and scheduled ticks are not outcomes. Registered offline ticks
need a completed original D11 job and an adopted D06 source. Missing ticks
stop the cursor. All reads/writes use W01's one business connection.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d02.production_operations_v1 import AdvanceCurrentBodyRequestV1, ApplyCurrentBodyEffectRequestV1
from ..domains.d05.relationship import BoundaryRule, _tuple_payload
from ..domains.d06 import D06DomainAdapter, D06DomainProvider, SourceAdmission
from ..domains.d08.execution import _decode, _decode_intent
from ..domains.d10 import (
    ActivityOutcome, ActivityRecipe, ContactClaim, ContactPolicyReadSet, LifeDomain, LifeProject,
    decode_contact_policy, decode_proactive_opportunity,
)
from ..domains.d10.current_contact import project_current_contact_v1
from ..domains.d10.offline_interval import (
    OfflineIntervalReadSet, OfflineObservedTickV1, OfflineTickReadSetV1, OfflineTickRecipeV1,
    decode_offline_tick_recipe_v1, offline_tick_recipe_to_wire_v1,
    OfflineTickComputationV1, scheduled_offline_ticks_v1,
)
from ..domains.d10.production_operations_v1 import (
    AdvanceCurrentLifeRequestV1, AdvanceCurrentOfflineRequestV1, CurrentContactInputsV1,
    CurrentLifeEffectExperienceBundleV1, CurrentLifeInputsV1, CurrentOfflineInputsV1,
    LifeProgressHeadV1, OfflineCheckpointV1, PrepareCurrentContactRequestV1,
    compile_advance_current_life_v1, compile_advance_current_offline_v1,
    compile_prepare_current_contact_v1, verify_d10_production_stage_v1,
)
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, owner_grant_key
from ..memory_types import SourceRecord, access_key, source_key
from ..runtime_contracts import DependencySet, DomainProposal, NamespaceId, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize
from .budget import get_budget_lease
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, table_exists_v1, waiting_stage_v1
from .d02_production_operations_v1 import (
    InstalledD02ProductionReadersV1, stage_advance_current_body_in_transaction_v1,
    stage_apply_current_body_effect_in_transaction_v1,
)
from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionOutboxStageV1
from .issuers import D11BudgetJobIssuer
from .jobs import get_job
from .restore_anchor import RestoreAnchor


@dataclass(frozen=True, slots=True)
class RegisteredLifePlanV1:
    project_ref: str
    recipe_ref: str
    action_intent_ref: str
    start_source_ref: str
    body_effect_request: ApplyCurrentBodyEffectRequestV1


@dataclass(frozen=True, slots=True)
class RegisteredLifeOutcomeV1:
    plan_original_ref: str
    action_outcome_ref: str
    terminal_source_ref: str
    actual_terminal_ref: str
    artifact_ref: str | None
    paid_cost_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RegisteredOfflineIntervalV1:
    interval_ref: str
    start_source_ref: str
    end_source_ref: str
    clock_mapping_ref: str
    clock_mapping_version: int
    recipe_original_ref: str
    checkpoint_start_utc: str
    requested_until_utc: str
    decision_boundary_utc: str | None


def install_d10_production_schema_v1(db):
    if db.in_transaction:
        raise ValueError("install D10 production schemas before runtime transactions")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d10_production_inputs_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,kind TEXT NOT NULL,"
        "producing_operation_id TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,"
        "signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,PRIMARY KEY(bot,persona,original_ref))")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d10_observed_ticks_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,interval_ref TEXT NOT NULL,scheduled_at_utc TEXT NOT NULL,"
        "job_id TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,"
        "source_refs_json TEXT NOT NULL,PRIMARY KEY(bot,persona,interval_ref,scheduled_at_utc),UNIQUE(bot,persona,job_id))")


class InstalledD10ProductionReadersV1:
    def __init__(self, *, issuer, role_clock_reader, current_restore_anchor, body_readers):
        from ..host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
        if (type(issuer) is not D11BudgetJobIssuer or type(role_clock_reader) is not InstalledD04SemanticMappingReaderV3
                or type(current_restore_anchor) is not RestoreAnchor
                or type(body_readers) is not InstalledD02ProductionReadersV1):
            raise TypeError("D10 needs installed D11, actual role-clock/restore fence and D02 readers")
        self.issuer, self.role_clock_reader = issuer, role_clock_reader
        self.current_restore_anchor, self.body_readers = current_restore_anchor, body_readers

    def _record(self, db, read, ref, kind, value, operation, roots):
        read.committed_operation(db, operation)
        if roots:
            read.source_family(db, tuple(dict.fromkeys(roots)))
        raw = offline_tick_recipe_to_wire_v1(value) if type(value) is OfflineTickRecipeV1 else plain_v1(value)
        encoded, digest = canonical_serialize(raw), canonical_digest(raw)
        expected = (kind, operation, encoded, digest,
            self.issuer._signer.sign("d11.d10-production-input.v1", encoded), canonical_serialize(roots))
        row = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json "
            "FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*read.frame.envelope.authority.namespace.as_tuple, ref)).fetchone()
        if row is not None and row != expected:
            raise ValueError("D10 registered original replay conflicts")
        if row is None:
            db.execute("INSERT INTO graph_d10_production_inputs_v1 VALUES(?,?,?,?,?,?,?,?,?)",
                (*read.frame.envelope.authority.namespace.as_tuple, ref, *expected))
        return ProductionOriginalRefV1("d10." + kind, ref, digest)

    def _input(self, db, read, ref, kind):
        if not table_exists_v1(db, "graph_d10_production_inputs_v1"):
            raise MissingProductionOriginalV1("registered_d10_" + kind)
        row = db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM "
            "graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*read.frame.envelope.authority.namespace.as_tuple, ref)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1("registered_d10_" + kind + ":" + ref)
        self.issuer._signer.verify("d11.d10-production-input.v1", row[2], row[4])
        raw = json.loads(row[2])
        if row[0] != kind or canonical_digest(raw) != row[3] or canonical_serialize(raw) != row[2]:
            raise ValueError("D10 registered original bytes/kind changed")
        read.committed_operation(db, row[1])
        return raw, read.original(ref, kind="d10." + kind, digest=row[3])

    def _clock(self, db, read, ref):
        mapping = read_current_role_clock_installation_v1(self.role_clock_reader, db, read.frame.envelope.authority.namespace)
        if mapping.mapping_id != ref:
            raise ValueError("D10 operation names another current clock")
        read.original(ref, kind="d11.role_clock")
        return mapping

    def record_current_life_plan_v1(self, db, *, frame, original_ref, producing_operation_id, plan):
        """Freeze a real adopted D08 activity plan, never invent an outcome."""
        if type(plan) is not RegisteredLifePlanV1:
            raise TypeError("exact registered life plan required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        project = read.head(db, plan.project_ref, required=True)
        recipe = read.head(db, plan.recipe_ref, required=True)
        action = _decode_intent(read.head(db, plan.action_intent_ref, required=True).value)
        if (project.key.type_name != "d10.life_project.v1" or recipe.key.type_name != "d10.activity_recipe.v1"
                or project.value["next_step"] not in recipe.value["allowed_steps"]
                or action.identity.activity_id != frame.envelope.identity.activity_id
                or action.identity.effect_id != frame.envelope.identity.effect_id
                or plan.start_source_ref not in action.source_refs):
            raise ValueError("D10 life plan differs from adopted activity/source")
        start = SourceRecord.from_dict(read.head(db, plan.start_source_ref, required=True).value)
        if start.occurred_at is None:
            raise MissingProductionOriginalV1("actual_life_segment_start_time")
        read.original(plan.start_source_ref, kind="d11.role_segment_start")
        return self._record(db, read, original_ref, "life_plan", plan, producing_operation_id, (plan.start_source_ref,))

    def record_current_life_outcome_v1(self, db, *, frame, original_ref, producing_operation_id, outcome):
        """Join the actual D08 settled outcome and independent D11 terminal."""
        if type(outcome) is not RegisteredLifeOutcomeV1:
            raise TypeError("exact registered life outcome required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        plan, _ = self._input(db, read, outcome.plan_original_ref, "life_plan")
        original = read.head(db, outcome.action_outcome_ref, required=True)
        actual = _decode("d08.action_outcome.v1", original.value)
        action = _decode_intent(read.head(db, plan["action_intent_ref"], required=True).value)
        if (original.key.type_name != "d08.action_outcome.v1" or actual.action_id != action.action_id
                or actual.effect_id != action.identity.effect_id or actual.attempt_id != action.identity.attempt_id
                or actual.result_level != "completed_verified"
                or actual.unknown_effects or actual.effect_id not in actual.completed_effects
                or not actual.observation_refs):
            raise MissingProductionOriginalV1("actual_complete_life_effect_observation")
        terminal = read.original(outcome.actual_terminal_ref, kind="d11.role_segment_end")
        end = SourceRecord.from_dict(read.head(db, outcome.terminal_source_ref, required=True).value)
        if end.occurred_at is None or end.occurred_at != actual.observed_at:
            raise ValueError("life terminal time differs from actual outcome")
        for ref in actual.observation_refs:
            read.original(ref)
        if not outcome.paid_cost_refs:
            raise MissingProductionOriginalV1("actual_life_cost_settlement")
        body_inputs = self.body_readers.read_effect(db, frame, ApplyCurrentBodyEffectRequestV1(**plan["body_effect_request"]))
        if tuple(outcome.paid_cost_refs) != tuple(original.original_ref for original in body_inputs.paid_cost_originals):
            raise ValueError("life cost originals differ from the actual quoted/settled body component")
        if outcome.artifact_ref is not None:
            read.original(outcome.artifact_ref, kind="d11.actual_artifact")
        return self._record(db, read, original_ref, "life_outcome", outcome, producing_operation_id,
                            (plan["start_source_ref"], outcome.terminal_source_ref))

    def read_life(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        raw, outcome_original = self._input(db, read, request.activity_outcome_ref, "life_outcome")
        plan, plan_original = self._input(db, read, raw["plan_original_ref"], "life_plan")
        if plan["project_ref"] != request.project_ref:
            raise ValueError("life outcome belongs to another project")
        project_atom = read.head(db, request.project_ref, required=True)
        project = LifeProject(namespace=frame.envelope.authority.namespace, **project_atom.value)
        recipe_atom = read.head(db, plan["recipe_ref"], required=True)
        recipe = ActivityRecipe(**{**recipe_atom.value, "allowed_steps": tuple(recipe_atom.value["allowed_steps"])})
        action = _decode_intent(read.head(db, plan["action_intent_ref"], required=True).value)
        outcome_atom = read.head(db, raw["action_outcome_ref"], required=True)
        actual = _decode("d08.action_outcome.v1", outcome_atom.value)
        if (actual.effect_id != action.identity.effect_id or actual.action_id != action.action_id
                or actual.result_level != "completed_verified"
                or actual.unknown_effects or actual.effect_id not in actual.completed_effects):
            raise ValueError("life effect is not actually completed")
        if (frame.envelope.identity.activity_id != action.identity.activity_id
                or frame.envelope.identity.effect_id != actual.effect_id):
            raise ValueError("life adoption cannot change stable activity/effect identity")
        start_ref, end_ref = plan["start_source_ref"], raw["terminal_source_ref"]
        records = read.source_family(db, (start_ref, end_ref))
        start, end = records[start_ref], records[end_ref]
        if start.occurred_at is None or end.occurred_at is None or start.occurred_at >= end.occurred_at:
            raise MissingProductionOriginalV1("actual_life_role_execution_interval")
        mapping = read_current_role_clock_installation_v1(self.role_clock_reader, db, frame.envelope.authority.namespace)
        def stamp(value):
            return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
        role_start, role_end = float(mapping.character_at(stamp(start.occurred_at))), float(mapping.character_at(stamp(end.occurred_at)))
        terminal = read.original(raw["actual_terminal_ref"], kind="d11.role_segment_end")
        read.original(start_ref, kind="d11.role_segment_start")
        costs = tuple(read.original(ref) for ref in raw["paid_cost_refs"])
        outcome = ActivityOutcome(action.identity.activity_id, actual.effect_id, "completed", raw["artifact_ref"],
            tuple(dict.fromkeys((*actual.observation_refs, raw["actual_terminal_ref"]))))
        progress = LifeProgressHeadV1(request.project_ref, plan["recipe_ref"], outcome.activity_id, outcome.effect_id,
            recipe.reality, project.next_step, role_start, role_end, outcome.artifact_ref, raw["actual_terminal_ref"],
            outcome.receipt_refs, (start_ref, end_ref))
        key = AtomKey(Owner("activity", *frame.envelope.authority.namespace.as_tuple, progress.activity_id), "d10.life_progress.v1", progress.effect_id)
        prior = read.head(db, key)
        if prior.revision and (not prior.valid or prior.value != plain_v1(progress)):
            raise ValueError("life effect already recorded with different original progress")
        return CurrentLifeInputsV1(project, recipe, plan["recipe_ref"], outcome, progress, terminal, plan_original, costs, bool(prior.revision)), plan

    def record_offline_recipe_v1(self, db, *, frame, original_ref, producing_operation_id, recipe):
        if type(recipe) is not OfflineTickRecipeV1:
            raise TypeError("exact bounded tick-only offline recipe required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        read.original(recipe.schedule_ref.ref, kind="d11.registered_schedule")
        pin = tuple(item for item in frame.installed_policy_refs if item.policy_ref == original_ref)
        if len(pin) != 1 or pin[0].policy_digest != canonical_digest(offline_tick_recipe_to_wire_v1(recipe)):
            raise ValueError("offline recipe lacks explicit installed policy selection")
        return self._record(db, read, original_ref, "offline_recipe", recipe, producing_operation_id, ())

    def record_offline_interval_v1(self, db, *, frame, producing_operation_id, interval):
        if type(interval) is not RegisteredOfflineIntervalV1:
            raise TypeError("exact registered offline interval required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        mapping = self._clock(db, read, interval.clock_mapping_ref)
        if mapping.version != interval.clock_mapping_version:
            raise ValueError("offline registration mapping version differs")
        start = SourceRecord.from_dict(read.head(db, interval.start_source_ref, required=True).value)
        end = SourceRecord.from_dict(read.head(db, interval.end_source_ref, required=True).value)
        read.original(interval.start_source_ref, kind="d11.host_disconnect")
        read.original(interval.end_source_ref, kind="d11.host_reconnect")
        def stamp(value):
            return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
        if (start.occurred_at is None or end.occurred_at is None or start.occurred_at >= end.occurred_at
                or interval.checkpoint_start_utc != stamp(start.occurred_at)
                or interval.requested_until_utc != stamp(end.occurred_at)
                or end.occurred_at > frame.now_utc):
            raise ValueError("offline interval differs from actual registered disconnect/reconnect observations")
        from .d10_offline_inputs_v1 import require_adjacent_host_lifecycle_pair_v1
        from .d11_offline_originals_v1 import TABLE, read_current_d11_offline_value_v1
        boundaries = []
        for ref, kind in ((interval.start_source_ref, "host_disconnect"), (interval.end_source_ref, "host_reconnect")):
            row = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind=? "
                "AND json_extract(payload_json,'$.source_ref')=?",
                (*frame.envelope.authority.namespace.as_tuple, kind, ref)).fetchone()
            if row is None:
                raise MissingProductionOriginalV1("actual_signed_host_lifecycle_interval_boundary")
            boundaries.append(read_current_d11_offline_value_v1(db, namespace=frame.envelope.authority.namespace,
                original_ref=row[0], issuer=self.issuer))
        require_adjacent_host_lifecycle_pair_v1(db, namespace=frame.envelope.authority.namespace,
            disconnected=boundaries[0], reconnected=boundaries[1])
        self._input(db, read, interval.recipe_original_ref, "offline_recipe")
        return self._record(db, read, interval.interval_ref, "offline_interval", interval, producing_operation_id,
                            (interval.start_source_ref, interval.end_source_ref))

    def record_observed_offline_tick_v1(self, db, *, frame, interval_ref, job_id, source_ref):
        """Import one actually completed scheduled D11 simulation job.

        scheduled_at and occurrence identity come from the durable original
        job. The method cannot add an unobserved cadence or user response.
        """
        read = CurrentDomainReadV1(frame)
        read.check(db)
        interval, _ = self._input(db, read, interval_ref, "offline_interval")
        recipe_raw, _ = self._input(db, read, interval["recipe_original_ref"], "offline_recipe")
        from .d11_offline_originals_v1 import TABLE
        from .d10_offline_tick_terminal_v1 import read_adopted_offline_tick_original_v1
        from .d11_offline_adoption_v1 import _read_signed, verify_offline_adoption_commit_v1
        from ..authority_service.d11_offline_tick_bridge_v1 import offline_bridge_from_wire_v1
        ns = frame.envelope.authority.namespace
        row = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='adopted_tick' "
            "AND json_extract(payload_json,'$.terminal.binding.job_id')=?", (*ns.as_tuple, job_id)).fetchall()
        if len(row) != 1:
            raise MissingProductionOriginalV1("actual_completed_registered_offline_tick_job")
        adopted = read_adopted_offline_tick_original_v1(db, namespace=ns, result_ref=row[0][0], issuer=self.issuer)
        binding, result = adopted.terminal.binding, adopted.terminal.result
        recipe = decode_offline_tick_recipe_v1(recipe_raw)
        from ..domains.d10.offline_interval import _utc
        if (adopted.terminal.status != "completed" or result is None or adopted.source_refs != (source_ref,)
                or (binding.schedule_ref, binding.schedule_revision) != (recipe.schedule_ref.ref, recipe.schedule_ref.version)
                or not _utc(interval["checkpoint_start_utc"]) <= _utc(binding.scheduled_at_utc) < _utc(interval["requested_until_utc"])
                or binding.scheduled_at_utc not in scheduled_offline_ticks_v1(recipe,
                    start_utc=binding.scheduled_at_utc, until_utc=interval["requested_until_utc"])
                or (result.clock_mapping_ref, result.clock_mapping_version) != (interval["clock_mapping_ref"], interval["clock_mapping_version"])):
            raise ValueError("offline observed result differs from its actual interval/schedule/grid/clock/source")
        bridge = _read_signed(db, ns, "adoption_bridge", binding.execution_id, self.issuer)
        if bridge is None:
            raise MissingProductionOriginalV1("actual_atomic_offline_tick_adoption")
        verify_offline_adoption_commit_v1(db, gate=offline_bridge_from_wire_v1(bridge[1]), issuer=self.issuer,
            resource_issuer=self.issuer.resource_issuer, require_current_metadata=False)
        read.original(adopted.result_ref, kind="d11.completed_offline_tick")
        read.original(adopted.cost_ref, kind="d11.cost_settlement")
        read.source_family(db, (source_ref,))
        source = read.head(db, source_ref, required=True)
        access = read.head(db, access_key(*frame.envelope.authority.namespace.as_tuple, source.key.owner.subject), required=True)
        record = SourceRecord.from_dict(source.value)
        if (record.source_kind != "simulated" or record.assertion_status != "simulated"
                or record.text != canonical_serialize(plain_v1(result))
                or record.occurred_at != _utc(binding.scheduled_at_utc).timestamp()):
            raise ValueError("offline tick source content/time differs from its independently completed simulation")
        tick = OfflineObservedTickV1(binding.scheduled_at_utc, VersionedRef(adopted.result_ref, 1),
            VersionedRef(source_ref, source.revision), VersionedRef(access.key.token, access.revision), "role_simulation", "observed")
        raw, ns = plain_v1(tick), frame.envelope.authority.namespace
        encoded, digest = canonical_serialize(raw), canonical_digest(raw)
        expected = (job_id, encoded, digest, self.issuer._signer.sign("d11.d10-observed-offline-tick.v1", encoded), canonical_serialize((source_ref,)))
        row = db.execute("SELECT job_id,payload_json,payload_digest,signature,source_refs_json FROM graph_d10_observed_ticks_v1 "
            "WHERE bot=? AND persona=? AND interval_ref=? AND scheduled_at_utc=?", (*ns.as_tuple, interval_ref, tick.scheduled_at_utc)).fetchone()
        if row is not None and row != expected:
            raise ValueError("offline observed tick original replay conflicts")
        if row is None:
            db.execute("INSERT INTO graph_d10_observed_ticks_v1 VALUES(?,?,?,?,?,?,?,?,?)",
                (*ns.as_tuple, interval_ref, tick.scheduled_at_utc, *expected))
        return tick

    def read_offline(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        raw, interval_original = self._input(db, read, request.offline_interval_ref, "offline_interval")
        mapping = self._clock(db, read, request.clock_mapping_ref)
        if raw["clock_mapping_ref"] != mapping.mapping_id or raw["clock_mapping_version"] != mapping.version:
            raise MissingProductionOriginalV1("original_offline_clock_mapping_continuity")
        recipe_raw, _ = self._input(db, read, raw["recipe_original_ref"], "offline_recipe")
        recipe = decode_offline_tick_recipe_v1(recipe_raw)
        checkpoint_key = AtomKey(Owner("persona", *frame.envelope.authority.namespace.as_tuple), "d10.offline_checkpoint.v1",
                                "interval:" + canonical_digest(request.offline_interval_ref)[:48])
        atom = read.head(db, checkpoint_key)
        checkpoint = OfflineCheckpointV1(**{**atom.value, "occurrence_refs": tuple(atom.value["occurrence_refs"])}) if atom.valid else None
        start = checkpoint.processed_until_utc if checkpoint else raw["checkpoint_start_utc"]
        expected_continuation = "d10-offline:" + canonical_digest((request.offline_interval_ref, start))[:48] if checkpoint else None
        if request.continuation_ref != expected_continuation:
            raise ValueError("offline continuation must address the current committed prefix")
        self._clock(db, read, request.clock_mapping_ref)
        roots = (raw["start_source_ref"], raw["end_source_ref"])
        read.source_family(db, roots)
        if not table_exists_v1(db, "graph_d10_observed_ticks_v1"):
            raise MissingProductionOriginalV1("registered_observed_offline_ticks")
        from .d10_offline_tick_execution_v1 import offline_tick_ids_v1
        from .d10_offline_tick_terminal_v1 import read_adopted_offline_tick_original_v1
        ticks, computations = [], []
        versions = [VersionedRef(recipe.recipe_id, recipe.version), recipe.schedule_ref,
                    VersionedRef(checkpoint_key.token, atom.revision)]
        until = raw["decision_boundary_utc"] or raw["requested_until_utc"]
        for due in scheduled_offline_ticks_v1(recipe, start_utc=start, until_utc=until):
            ids = offline_tick_ids_v1(frame.envelope.authority.namespace, recipe.schedule_ref.ref, due)
            adopted = read_adopted_offline_tick_original_v1(db, namespace=frame.envelope.authority.namespace,
                result_ref=ids["result"], issuer=self.issuer)
            if adopted is None or adopted.terminal.status != "completed":
                break
            imported = self.record_observed_offline_tick_v1(db, frame=frame, interval_ref=request.offline_interval_ref,
                job_id=ids["job"], source_ref=adopted.source_refs[0])
            row = db.execute("SELECT job_id,payload_json,payload_digest,signature FROM graph_d10_observed_ticks_v1 "
                "WHERE bot=? AND persona=? AND interval_ref=? AND scheduled_at_utc=?",
                (*frame.envelope.authority.namespace.as_tuple, request.offline_interval_ref, due)).fetchone()
            job_id, encoded, digest, signature = row
            self.issuer._signer.verify("d11.d10-observed-offline-tick.v1", encoded, signature)
            value = json.loads(encoded)
            if canonical_digest(value) != digest:
                raise ValueError("offline observed tick bytes changed")
            for name in ("occurrence_ref", "source_ref", "access_ref"):
                value[name] = VersionedRef(**value[name])
            tick = OfflineObservedTickV1(**value)
            if tick != imported or job_id != adopted.terminal.binding.job_id or tick.occurrence_ref.ref != adopted.result_ref:
                raise ValueError("offline observed tick differs from its immutable adopted job/result")
            read.original(tick.occurrence_ref.ref, kind="d11.completed_offline_tick")
            read.source_family(db, (tick.source_ref.ref,))
            source, access = read.head(db, tick.source_ref.ref, required=True), read.head(db, tick.access_ref.ref, required=True)
            if (source.revision, access.revision) != (tick.source_ref.version, tick.access_ref.version):
                raise ValueError("offline observed source/access changed")
            ticks.append(tick)
            computations.append(OfflineTickComputationV1(tick.occurrence_ref,
                Decimal(adopted.terminal.result.character_at), adopted.terminal.result.computed_at_utc))
            versions.extend((tick.occurrence_ref, tick.source_ref, tick.access_ref))
        anchor = self.current_restore_anchor
        from ..graph_coordinator import namespace_ref
        if anchor.namespace != namespace_ref(frame.envelope.authority.namespace) or anchor.activation_generation != frame.activation_generation:
            raise ValueError("offline current independent restore anchor differs")
        read.original("restore-anchor:" + canonical_digest(anchor), kind="d11.restore_anchor", digest=canonical_digest(anchor))
        # A bounded table page is complete for the chosen <=24-hour slice only
        # when it covers every actual tick in that exact interval. Later ticks
        # remain durable and are read with the next committed continuation.
        from ..domains.d10.offline_interval import plan_offline_simulation_slice
        interval = OfflineIntervalReadSet(frame.envelope.authority.namespace, mapping, checkpoint_key.token,
            start, tuple(dict.fromkeys(versions)), anchor, "full")
        now = datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z")
        from ..domains.d10.production_operations_v1 import _ExactCurrentReadV1
        sliced = plan_offline_simulation_slice(interval, requested_until_utc=raw["requested_until_utc"],
            trusted_now_utc=now, boundary_utc=raw["decision_boundary_utc"], read_verifier=_ExactCurrentReadV1(interval))
        selected_ticks = tuple(tick for tick in ticks if sliced.start_utc <= tick.scheduled_at_utc < sliced.end_utc) if sliced.status == "candidate" else ()
        selected_refs = {tick.occurrence_ref for tick in selected_ticks}
        tick_read = OfflineTickReadSetV1(sliced, recipe, selected_ticks, "full",
            computations=tuple(item for item in computations if item.occurrence_ref in selected_refs))
        return CurrentOfflineInputsV1(interval, tick_read, raw["requested_until_utc"], raw["decision_boundary_utc"], interval_original, checkpoint)

    def read_contact(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        ns = frame.envelope.authority.namespace
        policy_atom = read.head(db, request.contact_policy_ref, required=True)
        opportunity_atom = read.head(db, request.opportunity_ref, required=True)
        policy, opportunity = decode_contact_policy(policy_atom.value, ns), decode_proactive_opportunity(opportunity_atom.value, ns)
        from .d10_contact_policy_authority_v1 import require_current_contact_policy_v1
        qualified = getattr(self, "current_contact_policy", None)
        if qualified is None:
            raise MissingProductionOriginalV1("actual_current_owner_contact_policy")
        original = require_current_contact_policy_v1(qualified, self.contact_policy_scope,
                                                    policy_atom.value, now=frame.now_utc)
        policy_original = read.original(original.original_ref, kind="d10.owner_contact_policy", digest=original.digest)
        if len(frame.envelope.authority.audience) != 1:
            raise ValueError("contact must bind one actual current conversation audience")
        audience = frame.envelope.authority.audience[0]
        from .contact_route_binding_v1 import read_current_contact_route_binding_v1
        route = read_current_contact_route_binding_v1(db, read,
            account_ref=request.target_route_ref, target_entity_ref=opportunity.subject_ref,
            audience=audience)
        read.source_family(db, (opportunity.source_ref,), purpose="expression", audience=audience)
        for type_name in ("d10.contact_policy.v1", "d10.proactive_opportunity.v1", "d10.contact_claim.v1", "d10.contact_claim.v2", "d05.boundary_rule"):
            read.complete_inventory(db, type_name)
        query = QueryEpoch(ns, "all", frame.snapshot.epochs[0].revision)
        candidate = project_current_contact_v1(frame.snapshot, query, namespace=ns,
            policy_id=policy.policy_id, opportunity_id=opportunity.opportunity_id, now=frame.now_utc, audience=audience)
        from .dispatch_source_correction_barrier import read_source_correction_barrier
        correction = read_source_correction_barrier(db, ns, query, (opportunity.source_ref,),
                                                    dependent_ref=opportunity_atom.key.token)
        if not correction.clear:
            candidate = replace(candidate, status="hold", reasons=correction.missing_sources)
        boundaries = []
        for atom in frame.snapshot.atoms:
            if atom.key.type_name != "d05.boundary_rule" or not atom.valid:
                continue
            rule = BoundaryRule(**_tuple_payload(atom.value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"))
            if rule.target_entity_ref != opportunity.subject_ref:
                continue
            read.source_family(db, rule.source_refs, purpose="expression", audience=audience)
            boundaries.append(ProductionOriginalRefV1("d05.current_boundary", atom.key.token,
                canonical_digest(atom.value), (GraphVersion(atom.key, atom.revision),)))
            if (rule.effect == "deny" and rule.applies_to(subject_persona_ref="persona:" + ns.persona_id,
                    target_entity_ref=opportunity.subject_ref, action_kind="message", audience_scope=audience,
                    scene_ref=rule.scene_ref, at_time=frame.now_utc)) or rule.status in {"superseded", "revoked"}:
                candidate = replace(candidate, status="hold", reasons=("current_d05_contact_boundary",))
        route_original = ProductionOriginalRefV1("d03.current_contact_route", request.target_route_ref,
            route.digest, (route.account_version, route.entity_version, route.evidence_version))
        source_original = read.original(opportunity.source_ref)
        return CurrentContactInputsV1(candidate, route_original, tuple(boundaries), None, source_original, policy_original)


def stage_advance_current_life_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("installed D10 readers required")
    try:
        inputs, _ = installed_readers.read_life(db, frame, request)
        stage = compile_advance_current_life_v1(frame, request, inputs)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "advance_life", request, missing)
    return verify_d10_production_stage_v1(stage)


def stage_advance_current_offline_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("installed D10 readers required")
    try:
        stage = compile_advance_current_offline_v1(frame, request, installed_readers.read_offline(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "advance_offline", request, missing)
    return verify_d10_production_stage_v1(stage)


def stage_prepare_current_contact_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("installed D10 readers required")
    try:
        stage = compile_prepare_current_contact_v1(frame, request, installed_readers.read_contact(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "prepare_contact", request, missing)
    return verify_d10_production_stage_v1(stage)


def _life_experience_admission_v1(frame, inputs):
    progress = inputs.progress
    source_id = "d10-life-experience:" + canonical_digest((progress.activity_id, progress.effect_id))[:48]
    simulation = progress.reality == "role_simulation"
    text = canonical_serialize({"kind": "life_step_completed", "project_ref": progress.project_ref,
        "recipe_ref": progress.recipe_ref, "step": progress.step, "role_start": progress.role_start,
        "role_end": progress.role_end, "artifact_ref": progress.artifact_ref,
        "terminal_ref": progress.terminal_ref, "reality": progress.reality})
    records = {atom.key.token: SourceRecord.from_dict(atom.value) for atom in frame.snapshot.atoms
               if atom.key.type_name == "memory.source" and atom.valid and atom.key.token in progress.source_refs}
    family = records[progress.source_refs[-1]].provenance_root
    return SourceAdmission(source_id, text, "persona:" + frame.envelope.authority.namespace.persona_id,
        "simulated" if simulation else "internal", "simulated" if simulation else "observed",
        "none" if simulation else "subjective_only", "committed", records[progress.source_refs[-1]].occurred_at, frame.now_utc,
        family, frame.envelope.authority.audience,
        experience_allowed_purposes_v1(frame.snapshot, frame.envelope.authority.namespace, progress.source_refs),
        tuple(AtomKey.from_token(ref).owner.subject for ref in progress.source_refs))


def experience_allowed_purposes_v1(snapshot, namespace, root_refs):
    """A derived experience keeps only permissions every actual parent has."""
    owner = snapshot.get(owner_grant_key(*namespace.as_tuple))
    if owner is None or not owner.valid or owner.revision < 1:
        raise MissingProductionOriginalV1("actual_owner_experience_source_policy")
    allowed = set(owner.value["purposes"]) & {"context", "consolidation", "expression", "audit"}
    visited, active = set(), set()
    def visit(ref):
        nonlocal allowed
        if ref in visited:
            return
        if ref in active or len(visited) + len(active) >= 128:
            raise MissingProductionOriginalV1("bounded_experience_permission_parent_closure")
        key = AtomKey.from_token(ref)
        source = snapshot.get(key)
        access = snapshot.get(access_key(*namespace.as_tuple, key.owner.subject))
        if (source is None or access is None or not source.valid or not access.valid
                or source.revision < 1 or access.revision < 1 or access.value["status"] != "active"):
            raise MissingProductionOriginalV1("actual_experience_parent_source_and_access")
        value = SourceRecord.from_dict(source.value)
        allowed &= set(value.purposes) & set(access.value["purposes"])
        active.add(ref)
        for parent in value.parent_source_ids:
            visit(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref)
        visited.add(ref)
    for ref in root_refs:
        visit(ref)
    if not root_refs or not allowed:
        raise MissingProductionOriginalV1("explicit_experience_source_purpose_permission")
    return tuple(sorted(allowed))


def life_bundle_required_experience_keys_v1(frame, inputs):
    admission = _life_experience_admission_v1(frame, inputs)
    ns = frame.envelope.authority.namespace
    return (source_key(*ns.as_tuple, admission.source_id), access_key(*ns.as_tuple, admission.source_id))


def _memory_experience_proposal_v1(frame, admissions):
    """Specific internal-experience issuer, never a generic cross-domain map."""
    adapter = D06DomainAdapter(frame.envelope.authority.namespace)
    guarded = {version.key: version.revision for version in frame.snapshot.versions}
    writes, refs, qualifications = [], [], []
    for admission in admissions:
        admitted = adapter.admit_source(admission)
        source = source_key(*frame.envelope.authority.namespace.as_tuple, admission.source_id)
        access = access_key(*frame.envelope.authority.namespace.as_tuple, admission.source_id)
        if guarded.get(source) != 0 or guarded.get(access) != 0:
            raise ValueError("D10 concrete experience source/access needs explicit absence reads")
        writes.extend((GraphWrite(source, admitted.source.to_dict()), GraphWrite(access,
            {"source_id": admission.source_id, "audiences": list(admission.audiences),
             "purposes": list(admission.purposes), "status": "active", "recorded_at": admission.learned_at}, (source,))))
        refs.append(source.token)
        qualifications.append(admitted.qualification)
    # W01's registered concrete bundle capability covers exactly D02/D06/D10.
    # The common envelope retains that actual actor/issuer; this fixed D06
    # issuer only rederives admitted internal source/access values. It never
    # substitutes a domain string for the coordinator's capability check.
    provider = D06DomainProvider()
    proposal = DomainProposal("d06", "d06.contract.v1", provider.descriptor.request_schema_hash,
        frame.envelope, tuple(writes), DependencySet(current_invalidation=tuple(version for version in frame.snapshot.versions
            if version.key in {key for write in writes for key in write.dependencies}),
            historical_provenance=tuple(version for version in frame.snapshot.versions
            if version.key.type_name == "memory.source" and version.revision > 0)),
        tuple("d10-internal-experience:" + ref for ref in refs), ("experience", "outbox"))
    provider.validate(proposal, frame.snapshot)
    return proposal, tuple(refs), tuple(qualifications)


def stage_current_life_effect_experience_bundle_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d11_life_product_adapter_v1 import raw_life_original_v1
    if raw_life_original_v1(db, frame.envelope.authority.namespace, "outcome", request.activity_outcome_ref) is not None:
        from .d10_life_outcome_v2 import stage_current_life_v2_in_transaction_v1
        return stage_current_life_v2_in_transaction_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    """Reissue exactly D10 progress, D02 effects and D06 actual experience.

    Ordinary life stages are never independently adopted. A missing body
    terminal, cost or explicit source absence returns a held single-domain
    stage; it cannot be converted into a successful partial life operation.
    """
    if type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("installed D10 concrete bundle reader required")
    try:
        inputs, plan = installed_readers.read_life(db, frame, request)
        life = compile_advance_current_life_v1(frame, request, inputs)
        if inputs.duplicate_progress:
            return verify_d10_production_stage_v1(life)
        body_request = ApplyCurrentBodyEffectRequestV1(**plan["body_effect_request"])
        body = stage_apply_current_body_effect_in_transaction_v1(db, frame=frame,
            request=body_request, installed_readers=installed_readers.body_readers)
        if body.coverage != "complete" or not body.proposals:
            raise MissingProductionOriginalV1(*(body.missing_inputs or ("actual_unconsumed_life_body_component",)))
        if body.paid_cost_originals != inputs.paid_cost_originals:
            raise ValueError("life claimed paid originals differ from the independently reissued real body component costs")
        body_payload = json.loads(body.original_payload_json)["provenance"]
        if body_payload["body_quote"]["activity_id"] != inputs.progress.activity_id:
            raise ValueError("life and body terminal belong to different activities")
        experience = _life_experience_admission_v1(frame, inputs)
        memory, refs, qualifications = _memory_experience_proposal_v1(frame, (experience,))
        life = replace(life, outbox=life.outbox + (
            # Encoding is future qualified work. This event requests its real
            # D11 budget/preparation; it does not manufacture a completed C02.
            ProductionOutboxStageV1(
                frame.envelope.authority.namespace, frame.envelope.identity.operation_id, "d06",
                "actual_internal_experience_requires_encoding", ProductionOriginalRefV1("d10.actual_life_experience",
                    refs[0], canonical_digest(plain_v1(experience)), frame.snapshot.versions)),))
        settlements = tuple(write.key.token for proposal in body.proposals for write in proposal.typed_writes
                            if write.key.type_name == "d02.settlement.v1")
        return CurrentLifeEffectExperienceBundleV1(frame.envelope, life, body, memory, refs,
            settlements, tuple(original.original_ref for original in inputs.paid_cost_originals))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "advance_life", request, missing)


def stage_current_offline_body_experience_bundle_in_transaction_v1(db, *, frame, request, installed_readers):
    """Only registered observed role-simulation ticks advance this bundle."""
    if type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("installed D10 concrete offline reader required")
    try:
        inputs = installed_readers.read_offline(db, frame, request)
        life = compile_advance_current_offline_v1(frame, request, inputs)
        if not life.proposals:
            return life
        provenance = json.loads(life.original_payload_json)["provenance"]
        prefix = provenance["observed_prefix"]
        processed = prefix["processed_until_utc"]
        target = float(inputs.interval.mapping.character_at(processed))
        body_request = AdvanceCurrentBodyRequestV1(request.clock_mapping_ref, target, request.offline_interval_ref)
        body = stage_advance_current_body_in_transaction_v1(db, frame=frame, request=body_request,
            installed_readers=installed_readers.body_readers)
        if body.coverage != "complete":
            raise MissingProductionOriginalV1(*(body.missing_inputs or ("current_offline_passive_body_interval",)))
        admissions = []
        for occurrence in prefix["outputs"]:
            source_id = "d10-offline-experience:" + canonical_digest(occurrence["occurrence_id"])[:48]
            root_ref = occurrence["source_ref"]["ref"]
            root = SourceRecord.from_dict(frame.snapshot.get(AtomKey.from_token(root_ref)).value)
            admissions.append(SourceAdmission(source_id, canonical_serialize(occurrence),
                "persona:" + frame.envelope.authority.namespace.persona_id, "simulated", "simulated", "none",
                "committed", datetime.fromisoformat(occurrence["scheduled_at_utc"].replace("Z", "+00:00")).timestamp(), frame.now_utc, root.provenance_root,
                frame.envelope.authority.audience,
                experience_allowed_purposes_v1(frame.snapshot, frame.envelope.authority.namespace, (root_ref,)), (root.source_id,)))
        memory, refs, _ = _memory_experience_proposal_v1(frame, tuple(admissions))
        if sum(len(proposal.typed_writes) for proposal in (*life.proposals, *body.proposals, memory)) > frame.limits.max_writes:
            raise ValueError("offline concrete bundle exceeds installed aggregate write limit")
        from .domain_production_contracts_v1 import ProductionOutboxStageV1
        life = replace(life, outbox=(ProductionOutboxStageV1(frame.envelope.authority.namespace,
            frame.envelope.identity.operation_id, "d06", "actual_offline_simulation_experiences_require_encoding",
            inputs.interval_original),))
        return CurrentLifeEffectExperienceBundleV1(frame.envelope, life, body, memory, refs, (), (),
            "d10.offline_tick_body_experience.v1")
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "advance_offline", request, missing)


D10_PRODUCTION_STORAGE_INVENTORY_V1 = {
    "graph_d10_production_inputs_v1": {"namespace_columns": ("bot", "persona"), "content_columns": ("payload_json",),
        "source_closure_column": "source_refs_json", "operation_column": "producing_operation_id",
        "recovery": "revalidate_registered_plan_and_actual_observations"},
    "graph_d10_observed_ticks_v1": {"namespace_columns": ("bot", "persona"), "content_columns": ("payload_json",),
        "source_closure_column": "source_refs_json", "recovery": "same_original_completed_job_only"}}


def read_plan_current_d10_operation_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d01_production_operations_v1 import production_read_plan_v1, raw_registered_input_v1, raw_head_value_v1
    from ..graph_types import owner_grant_key
    types = ["d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1"]
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    if operation_kind == "prepare_contact" and type(request) is PrepareCurrentContactRequestV1:
        types.extend(("d03.entity_anchor", "d03.account_binding", "d10.contact_policy.v1",
            "d10.proactive_opportunity.v1", "d10.contact_claim.v1", "d10.contact_claim.v2", "d05.boundary_rule"))
        keys.extend(AtomKey.from_token(ref) for ref in (request.opportunity_ref, request.contact_policy_ref, request.target_route_ref))
        from .contact_route_binding_v1 import contact_route_read_inputs_v1
        route_keys, route_sources = contact_route_read_inputs_v1(db, namespace, request.target_route_ref)
        keys.extend(route_keys)
        roots.extend(route_sources)
        opportunity = raw_head_value_v1(db, namespace, AtomKey.from_token(request.opportunity_ref))
        if opportunity:
            roots.append(opportunity["source_ref"])
            originals.append(opportunity["source_ref"])
    elif operation_kind == "advance_life" and type(request) is AdvanceCurrentLifeRequestV1:
        from .d11_life_product_adapter_v1 import read_plan_current_life_progress_v2
        actual = read_plan_current_life_progress_v2(db, namespace=namespace, activity_id=activity_id, request=request)
        if actual is not None:
            return actual
        keys.append(AtomKey.from_token(request.project_ref))
        originals.append(request.activity_outcome_ref)
        outcome = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, request.activity_outcome_ref)
        if outcome:
            originals.extend((outcome["plan_original_ref"], outcome["actual_terminal_ref"], *outcome["paid_cost_refs"]))
            keys.append(AtomKey.from_token(outcome["action_outcome_ref"]))
            roots.append(outcome["terminal_source_ref"])
            if outcome["artifact_ref"]:
                originals.append(outcome["artifact_ref"])
            plan = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, outcome["plan_original_ref"])
            if plan:
                keys.extend(AtomKey.from_token(plan[name]) for name in ("recipe_ref", "action_intent_ref"))
                roots.append(plan["start_source_ref"])
                originals.append(plan["start_source_ref"])
                action = raw_head_value_v1(db, namespace, AtomKey.from_token(plan["action_intent_ref"]))
                if action:
                    effect = action["identity"]["effect_id"]
                    keys.append(AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "d10.life_progress.v1", effect))
                    source_id = "d10-life-experience:" + canonical_digest((activity_id, effect))[:48]
                    keys.extend((source_key(*namespace.as_tuple, source_id), access_key(*namespace.as_tuple, source_id)))
                from .d02_production_operations_v1 import read_plan_current_d02_operation_v1
                body = read_plan_current_d02_operation_v1(db, namespace=namespace, activity_id=activity_id,
                    operation_kind="apply_body_effect", request=ApplyCurrentBodyEffectRequestV1(**plan["body_effect_request"]))
                types.extend(body.fixed_type_ids)
                keys.extend(body.exact_keys)
                roots.extend(body.source_roots)
                originals.extend(body.required_original_refs)
    elif operation_kind == "advance_offline" and type(request) is AdvanceCurrentOfflineRequestV1:
        originals.extend((request.offline_interval_ref, request.clock_mapping_ref))
        checkpoint_key = AtomKey(Owner("persona", *namespace.as_tuple), "d10.offline_checkpoint.v1",
                                "interval:" + canonical_digest(request.offline_interval_ref)[:48])
        keys.append(checkpoint_key)
        interval = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, request.offline_interval_ref)
        if interval:
            originals.append(interval["recipe_original_ref"])
            roots.extend((interval["start_source_ref"], interval["end_source_ref"]))
            recipe = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, interval["recipe_original_ref"])
            checkpoint = raw_head_value_v1(db, namespace, checkpoint_key)
            start = checkpoint["processed_until_utc"] if checkpoint else interval["checkpoint_start_utc"]
            if recipe:
                originals.append(recipe["schedule_ref"]["ref"])
            if recipe:
                from .d10_offline_tick_execution_v1 import offline_tick_ids_v1
                from .d11_types import runtime_cost_settlement_key, runtime_job_key
                until = interval["decision_boundary_utc"] or interval["requested_until_utc"]
                for due in scheduled_offline_ticks_v1(decode_offline_tick_recipe_v1(recipe), start_utc=start, until_utc=until):
                    ids = offline_tick_ids_v1(namespace, recipe["schedule_ref"]["ref"], due)
                    roots.append(source_key(*namespace.as_tuple, ids["source"]).token)
                    cost_key = runtime_cost_settlement_key(*namespace.as_tuple, ids["activity"], ids["reservation"])
                    originals.extend((ids["result"], cost_key.token))
                    keys.extend((cost_key, runtime_job_key(*namespace.as_tuple, ids["activity"], ids["job"])))
                    identity = canonical_digest({"recipe": recipe["recipe_id"], "recipe_version": recipe["version"],
                            "schedule": VersionedRef(**recipe["schedule_ref"]), "occurrence": VersionedRef(ids["result"], 1)})
                    occurrence_id = "offline-sim:" + identity
                    keys.append(AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "d10.offline_simulated_occurrence.v1", occurrence_id))
                    source_id = "d10-offline-experience:" + canonical_digest(occurrence_id)[:48]
                    keys.extend((source_key(*namespace.as_tuple, source_id), access_key(*namespace.as_tuple, source_id)))
    else:
        raise ValueError("unregistered exact D10 production request")
    return production_read_plan_v1(types, keys, roots, originals)
