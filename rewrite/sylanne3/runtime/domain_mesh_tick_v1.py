"""Named producer companions for durable semantic progress in the producer's own CAS."""
from dataclasses import dataclass, replace
import json

from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeSpec
from ..runtime_contracts import DependencySet, DomainProposal, NamespaceId, canonical_digest, schema_hash
from ..runtime_storage_v3 import runtime_storage_v3
from ..domains.d01.production_operations_v1 import plain_v1
from ..memory_types import access_key
from ..domains.d06 import source_correction_head_key
from .d01_production_operations_v1 import CurrentDomainReadV1
from .domain_production_contracts_v1 import actual_frame_read_versions_v1
from .domain_production_contracts_v1 import StagedDomainOperationV1, actual_frame_read_versions_v1
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA
from .domain_mesh_contract_v1 import (
    MeshTickInputsV1, MeshPendingIdentityV1, MeshWaitV1, SemanticTickV1, TICK_TYPE,
    PersonalMeshStageReadsetCompositionV1,
)


@dataclass(frozen=True, slots=True)
class MeshCompanionTraceV1:
    operation_kind: str
    expected_head: GraphVersion
    after_tick: SemanticTickV1
    write_digest: str
    authority_composition: PersonalMeshStageReadsetCompositionV1 | None = None
    schema: str = "d11.semantic-tick-companion.v1"

    @property
    def tick_write(self):
        tick, key = self.after_tick, self.expected_head.key
        return GraphWrite(key, plain_v1(tick), dependencies=tuple(
            v.key for v in tick.read_versions if v.key != key and v.revision > 0))


@dataclass(frozen=True, slots=True)
class MeshTickCompanionV1:
    frame: object
    trace: MeshCompanionTraceV1
    proposal: DomainProposal | None


def semantic_tick_key_v1(namespace, activity_id, causal_original_ref, recipe_version):
    from .domain_mesh_contract_v1 import RECIPES, _text
    if type(namespace) is not NamespaceId or recipe_version not in RECIPES:
        raise ValueError("fixed installed semantic tick recipe/namespace required")
    _text(activity_id, "actual activity")
    _text(causal_original_ref, "actual causal original")
    name = "semantic-tick:" + canonical_digest((namespace, causal_original_ref, recipe_version))[:48]
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id), TICK_TYPE, name)


def decode_semantic_tick_v1(value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(value, SemanticTickV1)


def semantic_tick_type_spec_v1():
    return TypeSpec(TICK_TYPE, ("activity",), "state", decode_semantic_tick_v1,
        writer_domain="d11", schema_version=1,
        schema_hash=schema_hash({"type": TICK_TYPE, "version": 1}))


def validate_semantic_tick_write_v1(write, namespace, *, operation_id, activity_id):
    tick = decode_semantic_tick_v1(write.value)
    if (tick.namespace != namespace or tick.activity_id != activity_id
            or tick.producer_operation_id != operation_id
            or write.key != semantic_tick_key_v1(namespace, activity_id,
                tick.causal_original.original_ref, tick.recipe_version)):
        raise ValueError("semantic tick write differs from its actual producer command")
    return tick


def _current_sources(db, read, roots):
    ns = read.frame.envelope.authority.namespace
    if not set(roots) <= set(read.frame.envelope.source_qualification.source_refs):
        raise ValueError("tick cannot add Source roots outside its actual qualified producer")
    if not roots:
        return ()
    source_type = "memory.source"
    access_type = access_key(*ns.as_tuple, AtomKey.from_token(roots[0]).owner.subject).type_name
    correction_type = source_correction_head_key(ns, AtomKey.from_token(roots[0]).owner.subject).type_name
    # The actual producer Work has already qualified every Source and ancestor.
    # Record its exact closure without rereading a corrected historical body.
    closure = tuple(v for v in actual_frame_read_versions_v1(read.frame)
        if v.key.type_name in (source_type, access_type, correction_type))
    if not set(roots) <= {v.key.token for v in closure if v.key.type_name == source_type}:
        raise ValueError("tick roots lack their actual qualified Source versions")
    return closure


def _observed_inputs(db, read, inputs):
    if type(inputs) is not MeshTickInputsV1:
        raise TypeError("named producer must supply its actual immutable tick inputs")
    for original in (inputs.causal_original, *inputs.predecessors, *inputs.semantic_originals):
        if read.original(original.original_ref, kind=original.kind, digest=original.original_digest) != original:
            raise ValueError("semantic progress requires this actual authenticated original")
    for version in inputs.semantic_versions:
        if read.head(db, version.key, required=True).revision != version.revision:
            raise ValueError("semantic progress requires its actual current adopted version")
    if any(not p.complete for p in read.frame.query_coverage):
        raise ValueError("partial negative-query coverage cannot advance a semantic tick")


def _pending(previous, current):
    before = {(p.kind, p.original_ref, p.original_digest): p for p in previous}
    after = {(p.kind, p.original_ref, p.original_digest): p for p in current}
    if len(after) != len(current) or not set(before) <= set(after):
        raise ValueError("semantic checkpoint cannot forget an original in-flight or unknown identity")
    for key, prior in before.items():
        if prior.state in ("unknown", "unconfirmed") and after[key].state not in (prior.state, "observed"):
            raise ValueError("unknown effect/finance stays occupied until an actual observation")
    return current


def _wait(frame, recipe, reason, refs):
    from .domain_mesh_catalog_v1 import semantic_wait_event_v1
    domain, event = semantic_wait_event_v1(recipe)
    return MeshWaitV1(reason, domain, event, refs,
        actual_frame_read_versions_v1(frame), frame.query_coverage)


def _build(db, *, frame, operation_kind, actual_inputs, recipe):
    from .domain_mesh_catalog_v1 import require_semantic_recipe_operation_v1
    profile = require_semantic_recipe_operation_v1(recipe, operation_kind)
    read = CurrentDomainReadV1(frame)
    read.check(db)
    if frame.envelope.authority.purpose != profile.purpose:
        raise ValueError("semantic recipe changed its actual fixed producer purpose")
    _observed_inputs(db, read, actual_inputs)
    composition = None
    if recipe == "foreground-projection.v1":
        from .foreground_mesh_issuance_v1 import personal_mesh_composition_for_frame_v1, current_personal_mesh_facts_v1
        composition = personal_mesh_composition_for_frame_v1(frame)
        facts = current_personal_mesh_facts_v1(frame)
        if (composition is None or facts.causal_original != actual_inputs.causal_original
                or facts.predecessors != actual_inputs.predecessors):
            raise ValueError("Personal mesh companion lacks its exact independently issued Core recipe")
    ns, envelope = frame.envelope.authority.namespace, frame.envelope
    key = semantic_tick_key_v1(ns, envelope.identity.activity_id,
        actual_inputs.causal_original.original_ref, recipe)
    before = read.head(db, key)
    old = decode_semantic_tick_v1(before.value) if before.valid else None
    if before.revision and not before.valid:
        raise ValueError("an invalidated semantic tick cannot be silently reborn")
    expired = frame.now_utc >= actual_inputs.original_deadline_utc
    bookkeeping = (operation_kind in ("record_habit_miss_v1", "register_habit_occurrence_v1")
        and actual_inputs.wait is not None and actual_inputs.wait.reason == "original_deadline_expired")
    if frame.now_utc >= envelope.deadline_utc or expired and not bookkeeping:
        raise ValueError("semantic tick retains its original expired causal bound")
    source_closure = _current_sources(db, read, actual_inputs.source_roots)
    semantic = actual_inputs.semantic_digest
    wait = actual_inputs.wait
    pending = actual_inputs.pending
    deadline = min(actual_inputs.original_deadline_utc, envelope.deadline_utc)
    mode, wave, cursor, history = "observe" if expired else "birth", 0, 0, (semantic,)
    if old is not None:
        if ((old.namespace, old.activity_id, old.recipe_version, old.causal_original,
                old.parent_budget_lease_ref, old.activation_generation) !=
                (ns, envelope.identity.activity_id, recipe, actual_inputs.causal_original,
                    envelope.parent_budget_lease_ref, frame.activation_generation)):
            raise ValueError("tick cannot replace its causal root, original activity, budget or generation")
        if actual_inputs.cancellation_generation < old.cancellation_generation:
            raise ValueError("tick cannot regress the actual cancellation generation")
        if actual_inputs.cancellation_generation != old.cancellation_generation:
            if not profile.control:
                raise ValueError("old tick generation cannot advance after cancellation")
            wait = wait or _wait(frame, recipe, "current_rights", (actual_inputs.causal_original.original_ref,))
        if not set(old.predecessors) <= set(actual_inputs.predecessors):
            raise ValueError("tick cannot lose an actually committed predecessor")
        pending = _pending(old.pending, pending)
        deadline = min(old.original_deadline_utc, deadline)
        mode, wave, cursor, history = "checkpoint", old.wave, old.stage_cursor, old.semantic_history
        if semantic in old.semantic_history:
            reason = "same_semantic_state" if semantic != old.semantic_digest else "no_semantic_progress"
            wait = wait or _wait(frame, recipe, reason,
                tuple(v.original_ref for v in actual_inputs.semantic_originals))
        else:
            # A feedback wave is keyed to actual newly adopted versions/originals.
            if not actual_inputs.predecessors:
                raise ValueError("new feedback wave requires its actual adopted predecessor")
            wave, cursor, history = old.wave + 1, old.stage_cursor + 1, (*old.semantic_history, semantic)
        if profile.wake:
            if not actual_inputs.predecessors:
                raise ValueError("wake requires its real fixed outbox/cue predecessor")
            mode = "wake"
    if wait is not None and wait.next_due_utc is not None and wait.next_due_utc > deadline:
        raise ValueError("wait timer cannot refresh the original tick deadline")
    if expired:
        mode = "observe"
    state = "waiting" if wait is not None else "completed" if profile.final else "ready"
    if wait is not None and wait.reason in ("same_semantic_state", "no_semantic_progress"):
        state = "stopped"
    if state == "completed" and any(p.state != "observed" for p in pending):
        wait = _wait(frame, recipe, "external_result", tuple(p.original_ref for p in pending if p.state != "observed"))
        state = "waiting"
    guard = envelope.version_guard
    tick = SemanticTickV1(namespace=ns, activity_id=envelope.identity.activity_id, recipe_version=recipe,
        causal_original=actual_inputs.causal_original, owner_guard=frame.owner_guard,
        parent_budget_lease_ref=envelope.parent_budget_lease_ref, original_deadline_utc=deadline,
        source_roots=actual_inputs.source_roots, source_closure=source_closure,
        purpose=envelope.authority.purpose, audience=envelope.authority.audience,
        provider_policies=frame.installed_policy_refs,
        storage_generation=runtime_storage_v3(db).context.storage_generation,
        activation_generation=frame.activation_generation, access_epoch=guard.access_epoch,
        delete_epoch=guard.delete_epoch, cancellation_generation=actual_inputs.cancellation_generation,
        wave=wave, stage_cursor=cursor, mode=mode, state=state,
        producer_operation_id=envelope.identity.operation_id,
        producer_input_digest=envelope.identity.canonical_input_digest,
        predecessors=actual_inputs.predecessors, semantic_originals=actual_inputs.semantic_originals,
        semantic_versions=actual_inputs.semantic_versions, semantic_digest=semantic, semantic_history=history,
        pending=pending, wait=wait, read_versions=actual_frame_read_versions_v1(frame),
        query_coverage=frame.query_coverage)
    dependencies = tuple(v.key for v in actual_frame_read_versions_v1(frame)
        if v.key != key and v.revision > 0)
    write = GraphWrite(key, plain_v1(tick), dependencies=dependencies)
    trace = MeshCompanionTraceV1(operation_kind, GraphVersion(key, before.revision), tick, canonical_digest(write), composition)
    proposal = DomainProposal("d11", D11_PROPOSAL_SCHEMA, D11RuntimeProvider().descriptor.request_schema_hash,
        envelope, (write,), DependencySet(current_invalidation=tuple(
            v for v in actual_frame_read_versions_v1(frame) if v.key in set(dependencies)),
            historical_provenance=tuple(v for v in source_closure if v.key.type_name == "memory.source")),
        (), ())
    return MeshTickCompanionV1(frame, trace, proposal)


def stage_world_mesh_companion_v1(db, *, frame, operation_kind, request, actual_inputs):
    from .domain_mesh_catalog_v1 import require_mesh_request_v1
    require_mesh_request_v1("world-history.v1", operation_kind, request)
    return _build(db, frame=frame, operation_kind=operation_kind,
        actual_inputs=actual_inputs, recipe="world-history.v1")


def stage_prediction_mesh_companion_v1(db, *, frame, operation_kind, request, actual_inputs):
    from .domain_mesh_catalog_v1 import require_mesh_request_v1
    require_mesh_request_v1("prediction-conditioned.v1", operation_kind, request)
    return _build(db, frame=frame, operation_kind=operation_kind,
        actual_inputs=actual_inputs, recipe="prediction-conditioned.v1")


def stage_joint_habit_mesh_companion_v1(db, *, frame, operation_kind, request, actual_inputs):
    from .domain_mesh_catalog_v1 import require_mesh_request_v1
    require_mesh_request_v1("joint-habit.v1", operation_kind, request)
    return _build(db, frame=frame, operation_kind=operation_kind,
        actual_inputs=actual_inputs, recipe="joint-habit.v1")


def _habit_maintenance_context_v1(frame,operation_kind,request):
    from .habit_maintenance_frame_v1 import require_habit_maintenance_frame_v1,CurrentHabitMaintenanceReadV1
    from .domain_mesh_catalog_v1 import require_mesh_request_v1
    observed=require_habit_maintenance_frame_v1(frame)
    profile=require_mesh_request_v1('joint-habit.v1',operation_kind,request)
    if(operation_kind not in {'record_habit_miss_v1','adopt_habit_outcome_v1'}
            or operation_kind!=observed.request.operation_kind or request!=observed.request.command
            or request!=frame.issuance.command or frame.issuance.operation.operation_kind!=operation_kind
            or profile.domain!='d10' or frame.envelope.authority.purpose!=profile.purpose):
        raise ValueError('Habit maintenance Mesh requires its exact privately issued original-only command')
    return observed,CurrentHabitMaintenanceReadV1(frame)


def stage_habit_original_maintenance_mesh_companion_v1(db,*,frame,operation_kind,request,actual_inputs):
    observed,read=_habit_maintenance_context_v1(frame,operation_kind,request)
    read.check(db)
    _observed_inputs(db,read,actual_inputs)
    if(actual_inputs.original_deadline_utc>observed.original_deadline_utc
            or actual_inputs.cancellation_generation!=observed.standing_original.definition.cancellation_generation
            or actual_inputs.wait is not None and actual_inputs.wait.next_due_utc is not None):
        raise ValueError('Habit maintenance cannot extend the old lifetime, change its standing generation or schedule a timer')
    envelope,ns=frame.envelope,frame.envelope.authority.namespace
    key=semantic_tick_key_v1(ns,envelope.identity.activity_id,actual_inputs.causal_original.original_ref,'joint-habit.v1')
    before=read.head(db,key);old=decode_semantic_tick_v1(before.value)if before.valid else None
    if before.revision and not before.valid:raise ValueError('an invalidated original tick cannot be reborn by maintenance')
    deadline=min(actual_inputs.original_deadline_utc,envelope.deadline_utc,observed.original_deadline_utc)
    semantic=actual_inputs.semantic_digest;history=(semantic,);wave=cursor=0;pending=();wait=actual_inputs.wait
    if old is not None:
        if((old.namespace,old.activity_id,old.recipe_version,old.causal_original,old.parent_budget_lease_ref,old.activation_generation)
                !=(ns,envelope.identity.activity_id,'joint-habit.v1',actual_inputs.causal_original,envelope.parent_budget_lease_ref,frame.activation_generation)
                or old.cancellation_generation!=actual_inputs.cancellation_generation
                or not set(old.predecessors)<=set(actual_inputs.predecessors)
                or not set(old.source_roots)<=set(actual_inputs.source_roots)):
            raise ValueError('maintenance cannot replace the actual tick cause, budget, generation or retained dependency')
        deadline=min(old.original_deadline_utc,deadline);wave,cursor=old.wave,old.stage_cursor
        pending=old.pending;history=old.semantic_history
        if semantic not in history:history=(*history,semantic)
        else:wait=wait or _wait(frame,'joint-habit.v1','no_semantic_progress',tuple(v.original_ref for v in actual_inputs.semantic_originals))
    if actual_inputs.pending not in ((),pending):raise ValueError('maintenance cannot add, drop or silently settle an original pending identity')
    if operation_kind=='record_habit_miss_v1':
        if(frame.now_utc<observed.original_deadline_utc or wait is None or wait.reason!='original_deadline_expired'
                or not set(wait.dependency_refs)<={observed.request.policy_ref,observed.request.occurrence_ref,observed.request.cue_original_ref}):
            raise ValueError('miss maintenance retains only its original expired-window wait')
    if wait is None and any(p.state!='observed'for p in pending):
        wait=_wait(frame,'joint-habit.v1','external_result',tuple(p.original_ref for p in pending if p.state!='observed'))
    if wait is not None and(wait.next_due_utc is not None or not set(wait.observed_versions)<=set(actual_frame_read_versions_v1(frame))or wait.query_coverage!=frame.query_coverage):
        raise ValueError('maintenance wait cannot create a timer or leave its actual current readset')
    state='completed'if wait is None else 'stopped'if wait.reason in {'same_semantic_state','no_semantic_progress'}else 'waiting'
    source_closure=_current_sources(db,read,actual_inputs.source_roots);versions=actual_frame_read_versions_v1(frame);guard=envelope.version_guard
    tick=SemanticTickV1(namespace=ns,activity_id=envelope.identity.activity_id,recipe_version='joint-habit.v1',
        causal_original=actual_inputs.causal_original,owner_guard=frame.owner_guard,parent_budget_lease_ref=envelope.parent_budget_lease_ref,
        original_deadline_utc=deadline,source_roots=actual_inputs.source_roots,source_closure=source_closure,
        purpose=envelope.authority.purpose,audience=envelope.authority.audience,provider_policies=frame.installed_policy_refs,
        storage_generation=runtime_storage_v3(db).context.storage_generation,activation_generation=frame.activation_generation,
        access_epoch=guard.access_epoch,delete_epoch=guard.delete_epoch,cancellation_generation=actual_inputs.cancellation_generation,
        wave=wave,stage_cursor=cursor,mode='observe',state=state,producer_operation_id=envelope.identity.operation_id,
        producer_input_digest=envelope.identity.canonical_input_digest,predecessors=actual_inputs.predecessors,
        semantic_originals=actual_inputs.semantic_originals,semantic_versions=actual_inputs.semantic_versions,
        semantic_digest=semantic,semantic_history=history,pending=pending,wait=wait,read_versions=versions,query_coverage=frame.query_coverage)
    dependencies=tuple(v.key for v in versions if v.key!=key and v.revision>0)
    write=GraphWrite(key,plain_v1(tick),dependencies=dependencies)
    trace=MeshCompanionTraceV1(operation_kind,GraphVersion(key,before.revision),tick,canonical_digest(write))
    proposal=DomainProposal('d11',D11_PROPOSAL_SCHEMA,D11RuntimeProvider().descriptor.request_schema_hash,envelope,(write,),
        DependencySet(current_invalidation=tuple(v for v in versions if v.key in set(dependencies)),
            historical_provenance=tuple(v for v in source_closure if v.key.type_name=='memory.source')),(),())
    return MeshTickCompanionV1(frame,trace,proposal)


def _require_habit_maintenance_mesh_members_v1(base,companion,payload):
    from .d10_habit_v1 import habit_request_from_wire_v1
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    from ..domains.d10.habit_policy_v1 import HABIT_DISPOSITION_TYPE,HABIT_OCCURRENCE_TYPE,HABIT_OUTCOME_TYPE
    request=habit_request_from_wire_v1(base.operation_kind,payload['request'])
    observed,_=_habit_maintenance_context_v1(companion.frame,base.operation_kind,request)
    tick=companion.trace.after_tick
    if(tick.recipe_version!='joint-habit.v1'or tick.mode!='observe'or companion.trace.authority_composition is not None
            or tick.original_deadline_utc>observed.original_deadline_utc
            or tick.wait is not None and tick.wait.next_due_utc is not None
            or base.domain!='d10'or base.jobs or base.paid_cost_originals or base.coverage!='complete'
            or base.missing_inputs or base.continuation_ref is not None
            or any(p.domain!='d10'or p.contribution_keys or p.required_bundle_parts for p in base.proposals)):
        raise ValueError('maintenance records only its original result projection and cannot acquire work or cost')
    writes=tuple(w for p in base.proposals for w in p.typed_writes)
    original=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,companion.frame.snapshot.get(observed.occurrence_head.key).value)
    if base.operation_kind=='record_habit_miss_v1':
        if len(writes)!=1 or writes[0].key.type_name!=HABIT_DISPOSITION_TYPE or base.outbox:raise ValueError('miss maintenance has exactly one disposition and no runnable notification')
        value=habit_value_from_wire_v1(HABIT_DISPOSITION_TYPE,writes[0].value);definition=observed.standing_original.definition
        identity='habit-disposition:'+canonical_digest((observed.request.namespace,definition.policy_id,definition.revision,original.window_id,original.cue_original_ref,definition.miss_policy))[:48]
        expected=AtomKey(Owner('persona',*observed.request.namespace.as_tuple,observed.request.namespace.persona_id),HABIT_DISPOSITION_TYPE,identity)
        if writes[0].key!=expected or(value.policy_ref,value.policy_revision,value.window_id,value.cue_original_ref,value.disposition,value.reason_ref,value.original_deadline_utc)!=(original.policy_ref,original.policy_revision,original.window_id,original.cue_original_ref,definition.miss_policy,request.reason_ref,observed.original_deadline_utc):raise ValueError('miss companion changed the exact old standing window or rule')
    else:
        outcomes=tuple(w for w in writes if w.key.type_name==HABIT_OUTCOME_TYPE);updates=tuple(w for w in writes if w.key.token==observed.request.occurrence_ref)
        if len(writes)!=2 or len(outcomes)!=1 or len(updates)!=1:raise ValueError('outcome maintenance updates only its exact occurrence and one actual Habit outcome')
        result=habit_value_from_wire_v1(HABIT_OUTCOME_TYPE,outcomes[0].value);updated=habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,updates[0].value)
        if(result.occurrence_ref!=observed.request.occurrence_ref or result.occurrence_revision!=observed.request.expected_revision
                or(result.life_progress_ref,result.life_progress_revision,result.life_outcome_original_ref,result.actual_terminal_original_ref,result.accounting_original_refs,result.encoding_trigger_ref,result.growth_trigger_ref)
                !=(request.life_progress_ref,request.life_progress_revision,request.life_outcome_original_ref,request.actual_terminal_original_ref,request.accounting_original_refs,request.encoding_trigger_ref,request.growth_trigger_ref)
                or updated.state!='completed_verified'or updated.outcome_original_ref!=outcomes[0].key.token
                or any(getattr(updated,name)!=getattr(original,name)for name in('occurrence_id','activity_id','effect_id','attempt_id','parent_root_grant_ref','original_deadline_utc'))):
            raise ValueError('outcome maintenance cannot switch the actual terminal/accounting identity')
        if base.outbox:raise ValueError('maintenance cannot create new runnable encoding or growth notifications')


def stage_personal_mesh_companion_v1(db, *, frame, operation_kind, request, actual_inputs):
    from .domain_mesh_catalog_v1 import require_mesh_request_v1
    require_mesh_request_v1("foreground-projection.v1", operation_kind, request)
    return _build(db, frame=frame, operation_kind=operation_kind,
        actual_inputs=actual_inputs, recipe="foreground-projection.v1")


def combine_semantic_mesh_stage_v1(base, companion):
    if type(base) is not StagedDomainOperationV1 or type(companion) is not MeshTickCompanionV1:
        raise TypeError("mesh combines only the exact named producer's ordinary typed stage")
    frame, trace = companion.frame, companion.trace
    payload = json.loads(base.original_payload_json)
    if (base.operation_kind != trace.operation_kind
            or base.namespace != frame.envelope.authority.namespace
            or base.operation_id != frame.envelope.identity.operation_id
            or base.activity_id != frame.envelope.identity.activity_id
            or base.read_versions != actual_frame_read_versions_v1(frame)
            or payload["provenance"].get("semantic_mesh") != plain_v1(trace)):
        raise ValueError("producer original must describe the complete exact mesh companion before signing")
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1
    if type(frame)is CurrentHabitMaintenanceFrameV1:
        _require_habit_maintenance_mesh_members_v1(base,companion,payload)
    elif trace.after_tick.mode == "observe" and trace.after_tick.wait is not None and trace.after_tick.wait.reason == "original_deadline_expired":
        writes = tuple(w for p in base.proposals for w in p.typed_writes)
        if (base.operation_kind not in ("record_habit_miss_v1", "register_habit_occurrence_v1")
                or not writes or any(w.key.type_name != "d10.habit_disposition.v1" for w in writes)
                or base.jobs or base.paid_cost_originals):
            raise ValueError("expired tick bookkeeping cannot create execution, jobs or costs")
    proposals = (*base.proposals, companion.proposal) if companion.proposal is not None else base.proposals
    keys = [w.key for proposal in proposals for w in proposal.typed_writes]
    if len(keys) != len(set(keys)):
        raise ValueError("mesh companion cannot overlap another producer's Graph write")
    return replace(base, proposals=proposals)


def validate_semantic_mesh_trace_v1(value):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    trace = value if type(value) is MeshCompanionTraceV1 else decode_typed_production_value_v1(value, MeshCompanionTraceV1)
    if trace.schema != "d11.semantic-tick-companion.v1":
        raise ValueError("unknown semantic companion trace schema")
    tick, version = trace.after_tick, trace.expected_head
    if version.key != semantic_tick_key_v1(tick.namespace, tick.activity_id,
            tick.causal_original.original_ref, tick.recipe_version):
        raise ValueError("semantic trace changed its exact control key")
    if version not in tick.read_versions:
        raise ValueError("semantic trace lacks its exact expected control head")
    dependencies = tuple(v.key for v in tick.read_versions if v.key != version.key and v.revision > 0)
    write = GraphWrite(version.key, plain_v1(tick), dependencies=dependencies)
    if canonical_digest(write) != trace.write_digest:
        raise ValueError("semantic trace omits or changes its complete same-CAS write")
    composition = trace.authority_composition
    if composition is not None:
        versions = {v.key:v.revision for v in tick.read_versions}
        coverage = {row.type_id:row for row in tick.query_coverage}
        if (tick.recipe_version != "foreground-projection.v1"
                or composition.tick_keys != (version.key,) or composition.expected_tick != version
                or composition.core_qualification_readset_digest != canonical_digest((
                    composition.core_read_versions,composition.core_query_coverage,composition.core_source_closure))
                or composition.host_stage_readset_digest != canonical_digest((tick.read_versions,tick.query_coverage))
                or any(versions.get(v.key) != v.revision for v in composition.core_read_versions)
                or any(coverage.get(row.type_id) != row for row in composition.core_query_coverage)):
            raise ValueError("Personal mesh combined readsets differ from their independent Core and Host commitments")
    elif tick.recipe_version == "foreground-projection.v1":
        raise ValueError("Personal mesh trace lacks its independently issued Core composition")
    return trace


def verify_semantic_mesh_composition_v1(db, *, frame, stage):
    if type(stage) is not StagedDomainOperationV1:
        raise TypeError("semantic composition preserves its exact ordinary producer stage")
    payload = json.loads(stage.original_payload_json)
    raw = payload["provenance"].get("semantic_mesh")
    tick_writes = tuple(w for p in stage.proposals for w in p.typed_writes if w.key.type_name == TICK_TYPE)
    if raw is None:
        if tick_writes:
            raise ValueError("a semantic tick write has no fully signed producer trace")
        return
    trace = validate_semantic_mesh_trace_v1(raw)
    if trace.after_tick.recipe_version == "foreground-projection.v1":
        from .foreground_mesh_issuance_v1 import personal_mesh_composition_for_frame_v1
        if trace.authority_composition != personal_mesh_composition_for_frame_v1(frame):
            raise ValueError("Personal mesh pre-CAS lost its exact active paired Core proof")
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1,CurrentHabitMaintenanceReadV1
    if type(frame)is CurrentHabitMaintenanceFrameV1:
        from .d10_habit_v1 import habit_request_from_wire_v1
        request=habit_request_from_wire_v1(stage.operation_kind,payload['request'])
        tick=trace.after_tick
        inputs=MeshTickInputsV1(causal_original=tick.causal_original,source_roots=tick.source_roots,predecessors=tick.predecessors,
            semantic_originals=tick.semantic_originals,semantic_versions=tick.semantic_versions,
            original_deadline_utc=tick.original_deadline_utc,semantic_digest=tick.semantic_digest,
            cancellation_generation=tick.cancellation_generation,pending=tick.pending,wait=tick.wait)
        rebuilt=stage_habit_original_maintenance_mesh_companion_v1(db,frame=frame,operation_kind=stage.operation_kind,request=request,actual_inputs=inputs)
        if rebuilt.trace!=trace or rebuilt.proposal is None or rebuilt.proposal not in stage.proposals:raise ValueError('maintenance predicate must reconstruct its exact original-only Mesh companion')
        primary=replace(stage,proposals=tuple(p for p in stage.proposals if p is not next(p for p in stage.proposals if tick_writes[0]in p.typed_writes)))
        _require_habit_maintenance_mesh_members_v1(primary,rebuilt,payload)
        read=CurrentHabitMaintenanceReadV1(frame)
    else:read=CurrentDomainReadV1(frame)
    read.check(db)
    if (trace.operation_kind != stage.operation_kind or trace.after_tick.read_versions != actual_frame_read_versions_v1(frame)
            or trace.expected_head.revision != read.head(db, trace.expected_head.key).revision
            or trace.after_tick.owner_guard != frame.owner_guard
            or trace.after_tick.producer_operation_id != stage.operation_id
            or trace.after_tick.parent_budget_lease_ref != frame.envelope.parent_budget_lease_ref
            or trace.after_tick.original_deadline_utc > frame.envelope.deadline_utc
            or trace.after_tick.activation_generation != frame.activation_generation
            or trace.after_tick.access_epoch != frame.envelope.version_guard.access_epoch
            or trace.after_tick.delete_epoch != frame.envelope.version_guard.delete_epoch
            or trace.after_tick.storage_generation != runtime_storage_v3(db).context.storage_generation
            or len(tick_writes) != 1 or canonical_digest(tick_writes[0]) != trace.write_digest):
        raise ValueError("semantic companion changed its producer's actual frame, read set or proposal")
    if any(p.domain != "d11" for p in stage.proposals if tick_writes[0] in p.typed_writes):
        raise ValueError("only D11's closed companion validator may write a tick")
    for original in (trace.after_tick.causal_original, *trace.after_tick.predecessors,
            *trace.after_tick.semantic_originals):
        read.original(original.original_ref, kind=original.kind, digest=original.original_digest)


def require_semantic_mesh_stage_v1(stage):
    if type(stage) is not StagedDomainOperationV1:
        raise TypeError("mesh trace belongs to its exact actual ordinary producer stage")
    payload = json.loads(stage.original_payload_json)
    trace = validate_semantic_mesh_trace_v1(payload["provenance"]["semantic_mesh"])
    from .domain_mesh_catalog_v1 import require_semantic_recipe_operation_v1
    profile = require_semantic_recipe_operation_v1(trace.after_tick.recipe_version, stage.operation_kind)
    matches = tuple(p for p in stage.proposals if trace.tick_write in p.typed_writes)
    if (stage.domain != profile.domain or stage.namespace != trace.after_tick.namespace
            or stage.operation_id != trace.after_tick.producer_operation_id
            or stage.activity_id != trace.after_tick.activity_id
            or trace.after_tick.read_versions != stage.read_versions
            or len(matches) != 1 or matches[0].domain != "d11"
            or matches[0].typed_writes != (trace.tick_write,)
            or matches[0].proposal_schema != D11_PROPOSAL_SCHEMA
            or matches[0].proposal_schema_hash != D11RuntimeProvider().descriptor.request_schema_hash
            or matches[0].envelope.identity.operation_id != stage.operation_id
            or matches[0].envelope.identity.activity_id != stage.activity_id
            or matches[0].envelope.parent_budget_lease_ref != trace.after_tick.parent_budget_lease_ref
            or matches[0].envelope.authority.purpose != profile.purpose):
        raise ValueError("semantic companion is not the producer's exact single D11 control proposal")
    return trace
