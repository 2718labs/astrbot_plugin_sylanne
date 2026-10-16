"""Original-only Habit maintenance frames; expired work never regains execution authority."""
from dataclasses import dataclass, field, replace
import math

from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import canonical_digest
from .domain_production_contracts_v1 import CurrentOperationFrameV1, _validate_current_frame_fields_v1
from .d01_production_operations_v1 import CurrentDomainReadV1

MAINTENANCE_KINDS_V1 = frozenset(('record_habit_miss_v1', 'adopt_habit_outcome_v1'))


@dataclass(frozen=True, slots=True)
class CurrentHabitMaintenanceFrameV1(CurrentOperationFrameV1):
    issuance: object = field(kw_only=True, repr=False, compare=False)
    schema: str = 'd10.habit-original-maintenance-frame.v1'

    def __post_init__(self):
        if self.schema != 'd10.habit-original-maintenance-frame.v1':
            raise ValueError('exact Habit original-maintenance frame schema required')
        _validate_current_frame_fields_v1(self)
        if type(self.now_utc) not in (int, float) or not math.isfinite(self.now_utc):
            raise ValueError('Habit original-maintenance observation time must be finite')
        require_habit_maintenance_frame_v1(self)


def require_habit_maintenance_frame_v1(frame):
    from .habit_maintenance_issuance_v1 import require_habit_maintenance_issuance_v1
    if type(frame) is not CurrentHabitMaintenanceFrameV1:
        raise TypeError('actual private Habit original-maintenance frame required')
    issued = frame.issuance
    evidence = require_habit_maintenance_issuance_v1(issued, issued.graph, issued.scope)
    selector, scope = evidence.request, issued.scope
    envelope, ns = frame.envelope, frame.envelope.authority.namespace
    occurrence_key = AtomKey.from_token(selector.occurrence_ref)
    occurrence = frame.snapshot.get(occurrence_key)
    if (selector.operation_kind not in MAINTENANCE_KINDS_V1
            or scope.operation != 'write' or evidence.permit != scope.permit
            or envelope.identity.operation_id != selector.operation_id
            or envelope.identity.phase != selector.operation_kind
            or envelope.identity.effect_id is not None or envelope.identity.attempt_id != selector.operation_id
            or ns != selector.namespace or ns != evidence.current_self.namespace
            or envelope.authority.actor != evidence.current_self.self_entity_ref
            or envelope.authority.issuer_domain != 'd10'
            or evidence.current_self.permit != scope.permit
            or frame.activation_generation != scope.generation
            or frame.owner_guard != evidence.owner_guard
            or frame.snapshot.epochs != (scope.graph_epoch,)
            or scope.graph_epoch.revision != evidence.query_epoch.revision
            or (envelope.version_guard.access_epoch, envelope.version_guard.delete_epoch)
                != (evidence.access_epoch, evidence.delete_epoch)
            or envelope.parent_budget_lease_ref != evidence.original_root_ref
            or envelope.deadline_utc != evidence.original_deadline_utc
            or occurrence is None or not occurrence.valid
            or GraphVersion(occurrence_key, occurrence.revision) != evidence.occurrence_head
            or occurrence.revision != selector.expected_revision
            or canonical_digest(occurrence.value) != evidence.occurrence_digest
            or not set(frame.snapshot.versions) <= set(envelope.version_guard.read_versions)):
        raise ValueError('Habit maintenance changed its actual current Owner/Self/occurrence or original Root/deadline')
    from ..domains.d10.habit_occurrence_v1 import HABIT_OCCURRENCE_TYPE, habit_value_from_wire_v1
    value = habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE, occurrence.value)
    if (envelope.identity.activity_id != value.activity_id or value.parent_root_grant_ref != evidence.original_root_ref
            or value.original_deadline_utc != evidence.original_deadline_utc):
        raise ValueError('Habit maintenance changed the original activity/Root/execution lifetime')
    return evidence


class CurrentHabitMaintenanceReadV1(CurrentDomainReadV1):
    def __init__(self, frame):
        require_habit_maintenance_frame_v1(frame)
        self.frame = frame


def stage_habit_maintenance_result_v1(frame, domain, kind, request, *, writes,
        provenance, receiver_events=(), proposal_schema, proposal_hash):
    from ..domains.d01.production_operations_v1 import _assemble_current_stage_result_v1
    from ..domains.d10.habit_occurrence_v1 import (HABIT_DISPOSITION_TYPE, HABIT_OUTCOME_TYPE,
        HABIT_OCCURRENCE_TYPE, habit_value_from_wire_v1)
    observed = require_habit_maintenance_frame_v1(frame)
    issued, selector = frame.issuance, observed.request
    if (domain != 'd10' or kind != selector.operation_kind or request != issued.command
            or issued.operation.operation_kind != kind):
        raise ValueError('Habit maintenance cannot stage another registered command/domain')
    occurrence = habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE,
        frame.snapshot.get(AtomKey.from_token(selector.occurrence_ref)).value)
    if kind == 'record_habit_miss_v1':
        if len(writes) != 1 or receiver_events or writes[0].key.type_name != HABIT_DISPOSITION_TYPE:
            raise ValueError('Habit miss maintenance only records one original disposition')
        value = habit_value_from_wire_v1(HABIT_DISPOSITION_TYPE, writes[0].value)
        definition = observed.standing_original.definition
        identity = 'habit-disposition:' + canonical_digest((selector.namespace, definition.policy_id,
            definition.revision, occurrence.window_id, occurrence.cue_original_ref, definition.miss_policy))[:48]
        expected_key = AtomKey(Owner('persona', *selector.namespace.as_tuple, selector.namespace.persona_id),
            HABIT_DISPOSITION_TYPE, identity)
        if (writes[0].key != expected_key or value.namespace != selector.namespace
                or value.disposition_id != identity or value.policy_ref != selector.policy_ref
                or value.policy_revision != occurrence.policy_revision or value.window_id != occurrence.window_id
                or value.cue_original_ref != occurrence.cue_original_ref or value.reason_ref != request.reason_ref
                or value.original_deadline_utc != observed.original_deadline_utc
                or value.recorded_at_utc != frame.now_utc or frame.now_utc < observed.original_deadline_utc
                or value.disposition != definition.miss_policy):
            raise ValueError('Habit miss differs from its exact expired original occurrence/disposition')
    else:
        outcomes = tuple(write for write in writes if write.key.type_name == HABIT_OUTCOME_TYPE)
        updates = tuple(write for write in writes if write.key.token == selector.occurrence_ref)
        if len(writes) != 2 or len(outcomes) != 1 or len(updates) != 1:
            raise ValueError('Habit outcome maintenance only records its result and same occurrence projection')
        result = habit_value_from_wire_v1(HABIT_OUTCOME_TYPE, outcomes[0].value)
        update = habit_value_from_wire_v1(HABIT_OCCURRENCE_TYPE, updates[0].value)
        terminal=provenance['actual_terminal']
        progress=provenance['actual_life_progress']
        advances=tuple(original for original in frame.observed_originals
            if original.original_ref==request.growth_trigger_ref
            and original.kind=='d10.current-advance_life')
        if len(advances)!=1:
            raise ValueError('Habit outcome needs its exact actual advance_life COMMIT original')
        advance=advances[0]
        identity='habit-outcome:'+canonical_digest((occurrence.occurrence_id,
            terminal.original_ref,advance.original_digest))[:48]
        expected_key=AtomKey(Owner('persona',*selector.namespace.as_tuple,selector.namespace.persona_id),
            HABIT_OUTCOME_TYPE,identity)
        roots=tuple(dict.fromkeys((*occurrence.source_refs,*progress.source_refs,request.encoding_trigger_ref)))
        expected_update=replace(occurrence,state='completed_verified',
            life_plan_original_ref=terminal.binding.plan_original_ref,
            outcome_original_ref=expected_key.token,source_refs=roots)
        if (receiver_events or result.namespace!=selector.namespace or result.outcome_id!=identity
                or outcomes[0].key!=expected_key or result.source_refs!=roots or update!=expected_update
                or result.occurrence_ref!=selector.occurrence_ref or result.occurrence_revision!=selector.expected_revision
                or result.life_progress_ref!=request.life_progress_ref
                or result.life_progress_revision!=request.life_progress_revision
                or result.life_outcome_original_ref!=request.life_outcome_original_ref
                or result.actual_terminal_original_ref!=request.actual_terminal_original_ref
                or result.accounting_original_refs!=request.accounting_original_refs
                or result.encoding_trigger_ref!=request.encoding_trigger_ref
                or result.growth_trigger_ref!=advance.original_ref
                or terminal.original_ref!=request.actual_terminal_original_ref
                or (terminal.binding.activity_id,terminal.binding.effect_id,terminal.binding.attempt_id)
                    !=(occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id)):
            raise ValueError('Habit outcome differs from its exact terminal, advance original or same-occurrence projection')
    for write in writes:
        if not set(write.value['source_refs']) <= set(frame.envelope.source_qualification.source_refs):
            raise ValueError('Habit maintenance introduced Source content outside its actual ALL-qualified frame')
    return _assemble_current_stage_result_v1(frame, domain, kind, request, writes=writes,
        provenance=provenance, receiver_events=receiver_events,
        proposal_schema=proposal_schema, proposal_hash=proposal_hash)
