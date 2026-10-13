"""Actual Life progress, Body and internal activity experience after W01 terminal adoption."""
from dataclasses import replace
import json

from ..runtime_contracts import canonical_digest, canonical_serialize, DomainProposal, DependencySet, SourceQualification
from ..graph_types import AtomKey, Owner, GraphWrite
from ..memory_types import SourceRecord, source_key, access_key
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d10 import LifeProject, ActivityRecipe, ActivityOutcome
from ..domains.d10.production_operations_v1 import (LifeProgressHeadV1, CurrentLifeInputsV1,
    CurrentLifeEffectExperienceBundleV1, compile_advance_current_life_v1)
from ..domains.d02.production_operations_v1 import ApplyCurrentBodyEffectRequestV1
from ..domains.d06 import D06DomainProvider
from ..domains.d08.execution import _decode, _decode_intent
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, waiting_stage_v1
from .d11_life_contract_v1 import (RegisteredLifeOutcomeV2, D11LifeTerminalV1, life_from_wire_v1, life_to_wire_v1)
from .d11_life_contract_v1 import D11DraftTerminalV1
from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
from .d11_life_preparation_v1 import _read, _record, read_registered_life_plan_v2, read_prepared_life_v1
from .d11_life_terminal_v1 import read_adopted_life_original_v1
from .d11_life_source_note_v1 import verify_durable_life_artifact_v1
from .d11_life_graph_types_v1 import life_role_segment_key_v1
from .d11_offline_originals_v1 import _utc
from .d02_life_effect_v1 import require_life_body_quote_v1
from .d02_production_operations_v1 import stage_apply_current_body_effect_in_transaction_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionOutboxStageV1


def life_experience_source_id_v1(binding):
    return "d10-life-experience:" + canonical_digest((binding.namespace, binding.activity_id, binding.effect_id))[:48]


def life_experience_provenance_ref_v1(binding):
    return "d11-life-experience-original:" + canonical_digest((binding.namespace, binding.execution_id, binding.digest))[:48]


def life_experience_dependencies_v1(snapshot,writes):
    """Classify the exact materialized invalidation edges, including absence."""
    keys={key for write in writes for key in write.dependencies}
    guarded={version.key:version for version in snapshot.versions}
    if not keys<=guarded.keys():
        raise ValueError('Life experience dependency lacks its actual current read guard')
    return DependencySet(current_invalidation=tuple(guarded[key] for key in sorted(keys,key=lambda key:key.token)),
        historical_provenance=tuple(v for v in snapshot.versions if v.key.type_name=='memory.source' and v.revision>0))


def _actual_outcome(db, read, issuer, outcome):
    ns = read.frame.envelope.authority.namespace
    plan = read_registered_life_plan_v2(db, namespace=ns, issuer=issuer, original_ref=outcome.plan_original_ref)
    adopted = read_adopted_life_original_v1(db, namespace=ns, result_ref=outcome.artifact_ref, issuer=issuer)
    if plan is None or adopted is None:
        raise MissingProductionOriginalV1("actual_life_plan_and_atomic_terminal_adoption")
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    b = terminal.binding
    if (terminal.status != "completed" or b.plan_original_ref != outcome.plan_original_ref
            or outcome.start_original_ref != terminal.claim.original_ref or outcome.terminal_original_ref != terminal.original_ref
            or outcome.artifact_digest != terminal.payload.artifact_digest):
        raise ValueError("Life outcome differs from actual start/end/artifact")
    prepared = read_prepared_life_v1(db, binding=b, issuer=issuer)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_life_frozen_source_and_body_preparation")
    from .d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1
    require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted)
    if type(terminal) is D11DraftTerminalV1:
        from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
        require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
    else:
        verify_durable_life_artifact_v1(db, prepared, digest=outcome.artifact_digest, length=terminal.payload.artifact_length)
    action = _decode_intent(read.head(db, plan.action_intent.ref, required=True).value)
    actual = _decode("d08.action_outcome.v1", read.head(db, outcome.action_outcome_ref, required=True).value)
    if (actual.action_id != action.action_id or actual.effect_id != b.effect_id or actual.attempt_id != b.attempt_id
            or actual.result_level != "completed_verified" or actual.completed_effects != (b.effect_id,)
            or actual.unknown_effects or actual.observation_refs != (terminal.original_ref,)):
        raise ValueError("Life outcome lacks actual D08 installed postcondition completion")
    for phase, original in (("start", terminal.claim), ("end", terminal)):
        atom = read.head(db, life_role_segment_key_v1(b, phase), required=True)
        if atom.value["binding"] != life_to_wire_v1(b) or atom.value["payload"] != life_to_wire_v1(original.payload):
            raise ValueError("Life current role segment fact differs from actual signed journal")
    read.committed_operation(db, adopted["producing_operation_id"])
    terminal_original = read.original(terminal.original_ref, kind="d11.life_terminal", digest=canonical_digest(terminal))
    costs = tuple(read.settled_cost_original(db, ref, activity_id=b.activity_id, effect_id=b.effect_id,
        operation_id=b.reservation_operation_id) for ref in outcome.paid_cost_refs)
    if len(costs) != 1:
        raise ValueError("Life outcome must consume the one actual thread CPU settlement")
    roots = tuple(dict.fromkeys((plan.input_source.ref, *plan.content.source_refs))) if type(plan) is RegisteredDraftFilePlanV3 else (plan.input_source.ref,)
    for purpose in ("context", "consolidation"):
        for audience in plan.audiences:
            read.source_family(db, roots, purpose=purpose, audience=audience)
    return plan, prepared, terminal, terminal_original, costs


def record_current_life_outcome_v2(db, *, frame, issuer, original_ref, producing_operation_id, outcome):
    if type(outcome) is not RegisteredLifeOutcomeV2:
        raise TypeError("actual RegisteredLifeOutcomeV2 required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    _actual_outcome(db, read, issuer, outcome)
    read.committed_operation(db, producing_operation_id)
    return _record(db, issuer=issuer, namespace=frame.envelope.authority.namespace, kind="outcome", ref=original_ref,
        operation_id=producing_operation_id, value=outcome)


def stage_current_life_v2_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d10_production_operations_v1 import InstalledD10ProductionReadersV1
    if type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("Life requires actual installed D10/D02 readers")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        original = _read(db, issuer=installed_readers.issuer, namespace=frame.envelope.authority.namespace,
            kind="outcome", ref=request.activity_outcome_ref)
        if original is None:
            raise MissingProductionOriginalV1("actual_registered_life_outcome_v2")
        outcome = life_from_wire_v1(original[0], RegisteredLifeOutcomeV2)
        plan, prepared, terminal, terminal_original, costs = _actual_outcome(db, read, installed_readers.issuer, outcome)
        b = terminal.binding
        if request.project_ref != plan.project.ref:
            raise ValueError("Life progress belongs to another registered project")
        project_atom, recipe_atom = read.head(db, plan.project.ref, required=True), read.head(db, plan.recipe.ref, required=True)
        if project_atom.revision != plan.project.revision or canonical_digest(project_atom.value) != plan.project.digest:
            raise ValueError("Life current project changed before progress adoption")
        project = LifeProject(namespace=b.namespace, **project_atom.value)
        recipe = ActivityRecipe(**{**recipe_atom.value, "allowed_steps": tuple(recipe_atom.value["allowed_steps"])})
        from .d11_life_preparation_v1 import _plan_current
        _plan_current(db, read, plan)
        contract, _, _ = require_life_body_quote_v1(db, prepared=prepared, issuer=installed_readers.issuer, resource_issuer=installed_readers.issuer.resource_issuer,
            body_quote_authority=installed_readers.body_readers.body_quote_authority)
        body_request = ApplyCurrentBodyEffectRequestV1(terminal.original_ref, contract.body_quote_ref,
            "d11-life-adopt:" + canonical_digest((b.namespace, b.execution_id, b.digest))[:48], contract.effect_policy_ref)
        body = stage_apply_current_body_effect_in_transaction_v1(db, frame=frame, request=body_request,
            installed_readers=installed_readers.body_readers)
        if body.coverage != "complete" or body.paid_cost_originals != costs:
            raise MissingProductionOriginalV1(*(body.missing_inputs or ("actual_life_body_component_settlement",)))
        activity = ActivityOutcome(b.activity_id, b.effect_id, "completed", b.artifact_ref,
            (terminal.claim.original_ref, terminal.original_ref, outcome.action_outcome_ref))
        roots = tuple(dict.fromkeys((plan.input_source.ref, *plan.content.source_refs))) if type(plan) is RegisteredDraftFilePlanV3 else (plan.input_source.ref,)
        progress = LifeProgressHeadV1(plan.project.ref, plan.recipe.ref, b.activity_id, b.effect_id, "real_execution", plan.step,
            float(terminal.claim.payload.character_at), float(terminal.payload.character_at), b.artifact_ref, terminal.original_ref,
            activity.receipt_refs, roots)
        progress_key = AtomKey(Owner("activity", *b.namespace.as_tuple, b.activity_id), "d10.life_progress.v1", b.effect_id)
        prior = read.head(db, progress_key)
        if prior.revision and (not prior.valid or prior.value != plain_v1(progress)):
            raise ValueError("Life stable effect already has different adopted progress")
        from .d10_life_progress_provenance_v1 import (
            require_current_life_progress_v1,life_progress_qualified_writes_v1,life_experience_access_dependencies_v1,
        )
        if prior.revision:
            require_current_life_progress_v1(db,namespace=b.namespace,progress=progress,issuer=installed_readers.issuer,read=read)
        inputs = CurrentLifeInputsV1(project, recipe, plan.recipe.ref, activity, progress, terminal_original,
            read.original(b.plan_original_ref, kind="d11.life_plan", digest=b.plan_digest), costs, bool(prior.revision))
        life = compile_advance_current_life_v1(frame, request, inputs)
        if prior.revision:
            return life
        from ..domains.d01.production_operations_v1 import stage_result_v1
        qualified_progress=life_progress_qualified_writes_v1(prepared,terminal,progress,frame.envelope.identity.operation_id)
        prior_proposal=life.proposals[0]
        life=stage_result_v1(frame,'d10','advance_life',request,writes=qualified_progress,
            provenance=json.loads(life.original_payload_json)['provenance'],
            contribution_keys=prior_proposal.contribution_keys,
            receiver_events=tuple((event.receiver_domain,event.event_kind) for event in life.outbox),
            costs=life.paid_cost_originals,proposal_schema=prior_proposal.proposal_schema,
            proposal_hash=prior_proposal.proposal_schema_hash)
        source_id = life_experience_source_id_v1(b)
        source, access = source_key(*b.namespace.as_tuple, source_id), access_key(*b.namespace.as_tuple, source_id)
        if read.head(db, source).revision or read.head(db, access).revision:
            raise ValueError("Life actual activity experience requires explicit source/access absence")
        adopted_operation_id = read_adopted_life_original_v1(db, namespace=b.namespace, result_ref=b.artifact_ref, issuer=installed_readers.issuer)["producing_operation_id"]
        provenance_ref = life_experience_provenance_ref_v1(b)
        payload = {"schema": "d10.actual-life-activity-experience.v1", "actual_provenance_ref": provenance_ref,
            "activity_id": b.activity_id, "effect_id": b.effect_id, "artifact_ref": b.artifact_ref,
            "artifact_digest": terminal.payload.artifact_digest, "artifact_length": terminal.payload.artifact_length,
            "start_original_ref": terminal.claim.original_ref, "terminal_original_ref": terminal.original_ref,
            "action_outcome_ref": outcome.action_outcome_ref, "cost_refs": list(outcome.paid_cost_refs),
            "actual_cpu_ms": terminal.actual_cpu_ms, "started_at_utc": terminal.claim.payload.claimed_at_utc,
            "completed_at_utc": terminal.payload.completed_at_utc, "reality": "real_execution", "step": plan.step}
        record = SourceRecord(source_id, canonical_serialize(payload), "persona:" + b.namespace.persona_id, "internal", "confirmed",
            _utc(terminal.payload.completed_at_utc).timestamp(), frame.now_utc, "life-terminal:" + terminal.terminal_digest,
            plan.audiences, ("context", "consolidation"), (AtomKey.from_token(plan.input_source.ref).owner.subject,), "same_root")
        writes = (GraphWrite(source, record.to_dict()),
            GraphWrite(access, {"source_id": source_id, "audiences": list(plan.audiences), "purposes": ["context", "consolidation"],
                "status": "active", "recorded_at": frame.now_utc}, life_experience_access_dependencies_v1(prepared,source)))
        provider = D06DomainProvider()
        memory = DomainProposal("d06", "d06.contract.v1", provider.descriptor.request_schema_hash, frame.envelope, writes,
            life_experience_dependencies_v1(frame.snapshot,writes),
            ("d10-life-internal-experience:" + source.token,), ("experience",))
        provider.validate(memory, frame.snapshot)
        _record(db, issuer=installed_readers.issuer, namespace=b.namespace, kind="experience", ref=provenance_ref,
            operation_id=frame.envelope.identity.operation_id, value={"schema": "d11.actual-life-experience-provenance.v1",
                "source_ref": source.token, "source_digest": canonical_digest(record.to_dict()), "binding": life_to_wire_v1(b),
                "terminal": life_to_wire_v1(terminal), "adopted_operation_id": adopted_operation_id, "experience": payload})
        life = replace(life, outbox=life.outbox + (ProductionOutboxStageV1(b.namespace, frame.envelope.identity.operation_id,
            "d06", "actual_internal_experience_requires_encoding", ProductionOriginalRefV1("d10.actual_life_experience",
                source.token, canonical_digest(record.to_dict()), frame.snapshot.versions)),))
        settlements = tuple(w.key.token for p in body.proposals for w in p.typed_writes if w.key.type_name == "d02.settlement.v1")
        return CurrentLifeEffectExperienceBundleV1(frame.envelope, life, body, memory, (source.token,), settlements,
            tuple(cost.original_ref for cost in costs))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "advance_life", request, missing)
