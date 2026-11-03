"""D02 chronological settlement from the actual sealed labor adoption Work.

All input originals are retained by that Work. This module neither opens a
Source nor invents a checkpoint, interval, passive rate, or execution grant.
"""
from dataclasses import dataclass, replace
from decimal import Decimal
import math

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d02 import BodyDomain, BodyState, BodyReservation, SettlementResult, _reservation
from ..domains.d02.character_labor_v1 import (
    CharacterLaborRebuildHeadV1, CharacterLaborCorrectionRevisionV1,
    advance_character_axes_v1, character_labor_rebuild_key_v1,
    character_labor_correction_key_v1,
)
from ..graph_types import AtomKey, GraphWrite, GraphVersion, NamespaceEpoch
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d11_character_work_segment_v1 import (
    CharacterWorkSegmentOriginalV1, character_labor_census_duration_root_v1,
)
from .d11_character_labor_accounting_v1 import CharacterLaborAccountingBasisV1
from .d02_production_operations_v1 import PassiveBodyPolicyV1


@dataclass(frozen=True, slots=True)
class CharacterLaborTerminalBodyRequestV1:
    execution_id: str
    segment_id: str
    segment_digest: str
    census_root: str


@dataclass(frozen=True, slots=True)
class CharacterLaborTerminalBodyV1:
    stage: object
    state: BodyState
    reservations: tuple
    head: CharacterLaborRebuildHeadV1
    correction: CharacterLaborCorrectionRevisionV1 | None
    checkpoint: tuple
    segment_originals: tuple


def _role(value):
    decimal = Decimal(value)
    if not decimal.is_finite() or decimal < 0:
        raise ValueError("labor endpoint is not its finite signed character clock")
    result = float(decimal)
    if not math.isfinite(result):
        raise ValueError("labor endpoint exceeds the installed finite resource arithmetic")
    return result


def _component_key(component, segment):
    return "character-labor:" + canonical_digest((component, segment.segment_id)) + "|" + canonical_digest(plain_v1(segment))


def _segment_members(census, originals, bases):
    entries = {e.execution_id:e for e in census.entries
        if e.classification in {"character_labor_v1", "retained_duration_v1"}}
    by_execution = {}
    for segment in originals:
        if type(segment) is not CharacterWorkSegmentOriginalV1:
            raise TypeError("actual authenticated character-work segment required")
        old = by_execution.get(segment.execution_id)
        if old is not None and old != segment:
            raise ValueError("same actual execution has conflicting character-work originals")
        by_execution[segment.execution_id] = segment
    if set(by_execution) != set(entries):
        raise MissingProductionOriginalV1("complete_core_census_to_signed_character_segment_bijection")
    indexed = {}
    for basis in bases:
        if type(basis) is not CharacterLaborAccountingBasisV1 or basis.execution_id in indexed:
            raise ValueError("distinct exact signed labor accounting bases required")
        indexed[basis.execution_id] = basis
    if set(indexed) != set(entries):
        raise MissingProductionOriginalV1("each_actual_character_segment_accounting_basis")
    result = []
    for execution in sorted(entries):
        entry, segment, basis = entries[execution], by_execution[execution], indexed[execution]
        if ((segment.namespace,segment.effect_id,segment.binding_digest,segment.prepared_digest)
                != (census.namespace,entry.binding.effect_id,entry.binding_digest,entry.prepared_digest)
                or (segment.claim_sequence,segment.claim_digest) != (entry.claim_sequence,entry.claim_digest)
                or (segment.terminal_sequence,segment.terminal_digest)
                    != (entry.terminal_sequence,entry.terminal_digest)
                or (segment.status if entry.status != "claimed" else "claimed") != entry.status
                or (basis.namespace,basis.execution_id,basis.effect_id,basis.binding_digest,basis.prepared_digest)
                    != (segment.namespace,execution,segment.effect_id,segment.binding_digest,segment.prepared_digest)
                or (basis.policy_digest,basis.body_preparation_digest,basis.admission_digest)
                    != (segment.policy_digest,segment.body_preparation_digest,segment.admission_original_digest)
                or basis.clock_original_digest != segment.clock_original_digest
                or (basis.policy.recipe_ref,basis.policy.recipe_revision,basis.policy.recipe_digest)
                    != (segment.recipe_ref,segment.recipe_revision,segment.recipe_digest)
                or tuple(c.component_id for c in (*basis.policy.fixed_components,*basis.policy.duration_components)) != segment.component_ids):
            raise ValueError("labor census/segment/basis changed their exact original execution or components")
        if entry.classification == "retained_duration_v1" and (
                entry.accounting_basis_digest != canonical_digest(plain_v1(basis))):
            raise ValueError("retained census does not identify its authenticated duration basis")
        start = _role(segment.from_character)
        end = None if segment.to_character is None else _role(segment.to_character)
        if (end is not None and Decimal(segment.to_character) > Decimal(segment.from_character)
                and end <= start):
            raise ValueError("actual labor interval is below the existing finite Body cursor resolution")
        result.append((segment,basis,start,end))
    return tuple(result)


def _checkpoint(metadata, records, current, body_ref):
    # A checkpoint precedes every labor interval reconstructed here. Earlier
    # already-settled work is not guessed from the absence of a Graph segment.
    earliest = min((start for _,_,start,_ in records), default=current.cursor)
    choices = []
    for locator, original in metadata.checkpoints:
        ref, revision = locator
        state, receipt, digest, history = original
        if (ref != body_ref or type(state) is not BodyState or state.version != revision
                or state.profile_id != current.profile_id or canonical_digest(plain_v1(state)) != digest
                or GraphVersion(AtomKey.from_token(ref),revision) not in _body_checkpoint_versions_v1(receipt)):
            raise ValueError("labor checkpoint is not the actual committed Body history member")
        if state.cursor <= earliest:
            choices.append((locator,original))
    if not choices:
        raise MissingProductionOriginalV1("actual_body_checkpoint_before_all_unsettled_character_work")
    return max(choices,key=lambda value:(value[1][0].cursor,value[0][1]))


def _known_fixed_before_checkpoint(metadata, checkpoint):
    # The current component projection proves identity and producing receipt,
    # but carries no independent impulse amount/time. It can prove that such
    # an impulse is already in a checkpoint; it cannot price a later impulse.
    _, (state, receipt, digest, history) = checkpoint
    for component, operation, original_digest, produced in metadata.components:
        from ..graph_types import GraphReceipt
        if type(receipt) is GraphReceipt:
            raise MissingProductionOriginalV1("actual_W01_checkpoint_after_historical_fixed_components")
        if produced.commit_seq > receipt.commit_seq:
            raise MissingProductionOriginalV1("post_checkpoint_fixed_impulse_cost_clock_and_settlement_original")
        if operation != produced.operation_id:
            raise ValueError("fixed Body component lost its actual producing receipt")
        settlement = tuple(a for a in metadata.body_atoms if a.valid and a.key.token == component.settlement_ref)
        if len(settlement) != 1:
            raise MissingProductionOriginalV1("actual_fixed_component_settlement_in_body_checkpoint")
        saved = settlement[0].value
        if (saved["state"]["cursor"] > state.cursor or saved["state"]["version"] > state.version
                or not any(item.split("|",1)[0] == component.component_id
                    for item in saved["reservation"]["settled_components"])):
            raise MissingProductionOriginalV1("fixed_component_already_accounted_before_checkpoint")


def _timeline(checkpoint_state, records, passive, target, limit):
    if len(records) > limit:
        raise MissingProductionOriginalV1("actual_character_labor_continuation_job_before_complete_resource_cursor")
    for policy in passive:
        if type(policy) is not PassiveBodyPolicyV1 or policy.profile_id != checkpoint_state.profile_id:
            raise ValueError("labor needs its actual same-profile signed passive intervals")
    unknown = tuple(start for _,_,start,end in records if end is None)
    stop = min((target,*unknown)) if unknown else target
    if stop < checkpoint_state.cursor:
        raise MissingProductionOriginalV1("earlier_actual_body_checkpoint_for_unknown_labor_start")
    for i, (segment,basis,start,end) in enumerate(records):
        if end is not None and end < start:
            raise ValueError("labor terminal clock precedes its real start")
        for other,other_basis,left,right in records[:i]:
            actual_right = math.inf if end is None else end
            other_right = math.inf if right is None else right
            if max(start,left) < min(actual_right,other_right) and segment.effect_id != other.effect_id:
                raise ValueError("exclusive main-focus labor intervals belong to different actual effects")
    boundaries = {checkpoint_state.cursor,stop}
    for segment,basis,start,end in records:
        if checkpoint_state.cursor < start < stop: boundaries.add(start)
        if end is not None and checkpoint_state.cursor < end < stop: boundaries.add(end)
    for policy in passive:
        if checkpoint_state.cursor < policy.from_role_cursor < stop: boundaries.add(policy.from_role_cursor)
        if checkpoint_state.cursor < policy.to_role_cursor < stop: boundaries.add(policy.to_role_cursor)
    boundaries = sorted(boundaries)
    if len(boundaries)-1 > limit:
        raise MissingProductionOriginalV1("actual_piecewise_resource_continuation_with_unchanged_segment_limit")
    costs = {segment.execution_id:{c.component_id:0.0 for c in basis.policy.duration_components
        if end is not None and end <= stop} for segment,basis,_,end in records}
    unpaid = {segment.execution_id:0.0 for segment,_,_,_ in records}
    state = checkpoint_state
    impulses = {}
    for segment,basis,start,end in records:
        if segment.status == "completed" and end is not None and end <= stop:
            impulses.setdefault(end,[]).append((segment,basis))
    def fixed(at, current):
        for segment,basis in sorted(impulses.get(at,()),key=lambda pair:pair[0].segment_id):
            for component in basis.policy.fixed_components:
                costs[segment.execution_id][component.component_id] = component.energy_cost
                shortage = max(0.0,component.energy_cost-current.energy)
                unpaid[segment.execution_id] = math.fsum((unpaid[segment.execution_id],shortage))
                current = replace(current,energy=max(0.0,current.energy-component.energy_cost))
        return current
    state = fixed(state.cursor,state)
    for left,right in zip(boundaries,boundaries[1:]):
        matches = tuple(p for p in passive if p.from_role_cursor <= left and right <= p.to_role_cursor)
        if len(matches) != 1:
            raise MissingProductionOriginalV1("unique_complete_signed_passive_policy_interval")
        active = []
        for segment,basis,start,end in records:
            if start <= left and end is not None and right <= end and right > start:
                active.append((segment,basis))
        if len({s.effect_id for s,_ in active}) > 1:
            raise ValueError("exclusive character labor cannot be allocated across concurrent effects")
        components = []
        owners = []
        for segment,basis in active:
            for component in basis.policy.duration_components:
                # Repeated views of one effect/component interval are a union.
                identity = (segment.effect_id,component.component_id)
                if identity in owners:
                    raise ValueError("overlapping distinct claim segments have ambiguous component ownership")
                owners.append(identity); components.append(component)
        compatible = all(basis.policy.recovery_compatible for _,basis in active)
        state, deltas = advance_character_axes_v1(state,matches[0].rates,tuple(components),
            from_cursor=left,to_cursor=right,recovery_compatible=compatible)
        position = 0
        for segment,basis in active:
            for component in basis.policy.duration_components:
                prior = costs[segment.execution_id].get(component.component_id,0.0)
                costs[segment.execution_id][component.component_id] = math.fsum((prior,deltas[position]))
                position += 1
        state = fixed(right,state)
    return state,costs,unpaid,stop,bool(unknown)


def _reservations(metadata, records, costs, unpaid, stop):
    indexed = {a.key.token:a for a in metadata.body_atoms if a.valid and a.key.type_name == "d02.reservation.v1"}
    results = []
    for segment,basis,start,end in records:
        atom = indexed.get(basis.reservation_ref)
        if atom is None:
            raise MissingProductionOriginalV1("actual_character_labor_unique_body_reservation")
        prior = _reservation(atom.value)
        if ((prior.effect_id,prior.quote_id,prior.reserved_cost)
                != (segment.effect_id,basis.quote.quote_ref,basis.quote.max_energy_cost)
                or atom.key.name != prior.reservation_id
                or NamespaceId.from_key(atom.key) != basis.namespace):
            raise ValueError("labor reservation differs from its original quote, effect or namespace")
        if any(not value.startswith("character-labor:") for value in prior.settled_components):
            raise ValueError("duration reservation cannot include an unrelated Fixed component charge")
        settled = tuple(_component_key(component,segment) for component in sorted(costs[segment.execution_id]))
        expected_keys = {_component_key(component,segment)
            for component in (*[c.component_id for c in basis.policy.duration_components],
                *[c.component_id for c in basis.policy.fixed_components])}
        if not set(prior.settled_components) <= expected_keys:
            raise ValueError("labor reservation contains another execution's settlement identity")
        spent = math.fsum(costs[segment.execution_id].values())
        overrun = max(0.0,spent-prior.reserved_cost,unpaid[segment.execution_id])
        ended = end is not None and end <= stop and segment.status in {"completed","failed"}
        status = "overrun" if overrun else ("settled" if ended else "pending_confirmation")
        remaining = 0.0 if ended and not overrun else max(0.0,prior.reserved_cost-spent)
        current = replace(prior,remaining_cost=remaining,settled_components=settled,status=status)
        results.append((segment,basis,prior,current,overrun))
    return tuple(results)


def prepare_character_labor_terminal_body_v1(db, *, frame, prepared, segment, census,
        body_readers, adoption_inputs):
    from .current_character_labor_adoption_v1 import (
        PreparedCharacterLaborAdoptionV1, require_character_labor_adoption_inputs_v1,
        require_character_labor_adoption_settlement_metadata_v1,
        require_character_labor_adoption_body_readers_v1,
        require_character_labor_adoption_accounting_bases_v1,
    )
    from .d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1
    from .d11_life_contract_v1 import life_adoption_operation_id_v1
    if type(adoption_inputs) is not PreparedCharacterLaborAdoptionV1 or type(prepared) is not D11CharacterLaborLifePreparedV1:
        raise TypeError("terminal Body requires the actual sealed new character-labor adoption")
    r = adoption_inputs.owner
    require_character_labor_adoption_inputs_v1(adoption_inputs,graph=r.graph,db=db,scope=r.scope,owner=r.owner_binding)
    adoption_inputs.require_frame_v1(frame)
    actual_readers = require_character_labor_adoption_body_readers_v1(adoption_inputs,db=db,frame=frame)
    if (actual_readers is not body_readers or prepared is not adoption_inputs.prepared
            or segment is not adoption_inputs.segment or census is not adoption_inputs.census
            or frame.envelope.identity.operation_id != life_adoption_operation_id_v1(prepared.binding)):
        raise ValueError("labor Body settlement crossed its actual inputs, frame, scope or producer")
    read = CurrentDomainReadV1(frame)
    profile, current, all_reservations = body_readers._current_body(db,read,adoption_inputs.body_preparation.policy.profile_id)
    if body_readers.require_labor_census_v1(db,read,current) is not census:
        raise ValueError("labor terminal requires its current same-frame complete census")
    metadata = require_character_labor_adoption_settlement_metadata_v1(adoption_inputs,db=db,frame=frame)
    bases = require_character_labor_adoption_accounting_bases_v1(adoption_inputs,db=db,frame=frame)
    originals = list(metadata.segments)
    originals.append(segment)
    all_records = _segment_members(census,tuple(originals),bases)
    records = tuple(item for item in all_records if item[1].policy.profile_id == current.profile_id)
    if len(records) > frame.limits.max_role_segments:
        raise MissingProductionOriginalV1("actual_character_labor_continuation_job_before_complete_resource_cursor")
    body = adoption_inputs.body_preparation
    own = tuple(b for s,b,_,_ in records if s.execution_id == prepared.binding.execution_id)
    if len(own) != 1 or (own[0].policy,own[0].quote,own[0].reservation_ref,own[0].settlement_ref) != (
            body.policy,body.quote,body.reservation_ref,body.settlement_ref):
        raise ValueError("current terminal basis differs from its exact signed B")
    target = max((current.cursor,*[end if end is not None else start for _,_,start,end in records]))
    request = CharacterLaborTerminalBodyRequestV1(prepared.binding.execution_id,segment.segment_id,
        canonical_digest(plain_v1(segment)),character_labor_census_duration_root_v1(census))
    return _stage_character_labor_history_v1(db,frame=frame,metadata=metadata,census=census,
        current=current,records=records,target=target,request=request,trigger_original_ref=segment.segment_id)


def _stage_character_labor_history_v1(db, *, frame, metadata, census, current, records,
        target, request, trigger_original_ref, expected_checkpoint=None):
    read = CurrentDomainReadV1(frame)
    checkpoint = _checkpoint(metadata,records,current,census.body_state.ref)
    if expected_checkpoint is not None:
        candidates = tuple(item for item in metadata.checkpoints if item[0] == expected_checkpoint)
        if len(candidates) != 1:
            raise MissingProductionOriginalV1("the_explicit_actual_body_checkpoint_original")
        checkpoint = candidates[0]
        if any(start < checkpoint[1][0].cursor for _,_,start,_ in records):
            raise MissingProductionOriginalV1("earlier_actual_checkpoint_before_crossing_character_labor")
    _known_fixed_before_checkpoint(metadata,checkpoint)
    state,costs,unpaid,processed,unknown = _timeline(checkpoint[1][0],records,
        metadata.passive_policies,target,frame.limits.max_role_segments)
    changed = replace(state,version=current.version) != current
    state = replace(state,version=current.version+1) if changed else current
    reservations = _reservations(metadata,records,costs,unpaid,processed)
    ns = frame.envelope.authority.namespace
    head_key = character_labor_rebuild_key_v1(ns,current.profile_id)
    prior_head = read.head(db,head_key)
    revision = prior_head.revision+1
    correction_key = character_labor_correction_key_v1(ns,current.profile_id,revision)
    if read.head(db,correction_key).revision:
        raise ValueError("labor correction identity already exists before this actual CAS")
    if prior_head.revision and not prior_head.valid:
        raise MissingProductionOriginalV1("current_valid_character_labor_rebuild_head")
    root = character_labor_census_duration_root_v1(census)
    head = CharacterLaborRebuildHeadV1(current.profile_id,revision,state.version,canonical_digest(state),
        checkpoint[0][0],checkpoint[0][1],checkpoint[1][2],checkpoint[1][0].cursor,
        processed,target,frame.envelope.version_guard.access_epoch,frame.envelope.version_guard.delete_epoch,
        root,"pending_confirmation" if unknown or any(item[4] for item in reservations) or any(unpaid.values())
            or any(end is None or end > processed for _,_,_,end in records) else "current",None)
    correction = CharacterLaborCorrectionRevisionV1(current.profile_id,revision,
        checkpoint[0][0],checkpoint[0][1],checkpoint[1][2],current.version,state.version,
        checkpoint[1][0].cursor,processed,root,head.source_epoch,head.deletion_epoch,trigger_original_ref) if changed else None
    writes = [GraphWrite(head_key,plain_v1(head))]
    if changed:
        writes.extend((BodyDomain.state_write(ns,state),GraphWrite(correction_key,plain_v1(correction))))
    for original,basis,prior,reservation,overrun in reservations:
        writes.append(BodyDomain.reservation_write(ns,basis.quote.activity_id,reservation))
        key = AtomKey.from_token(basis.settlement_ref)
        read.head(db,key)
        result = SettlementResult(state,reservation,False,overrun,unpaid[original.execution_id])
        writes.append(BodyDomain.settlement_write(ns,basis.quote.activity_id,key.name,result))
    if len({w.key for w in writes}) != len(writes):
        raise ValueError("labor terminal attempted repeated reservation or settlement writes")
    domain = BodyDomain()
    kind = "character_labor_terminal_body" if type(request) is CharacterLaborTerminalBodyRequestV1 else "rebuild_character_labor_body"
    stage = stage_result_v1(frame,"d02",kind,request,writes=tuple(writes),
        provenance={"checkpoint":checkpoint[0],"checkpoint_digest":checkpoint[1][2],
            "character_originals":tuple((s.segment_id,canonical_digest(plain_v1(s))) for s,_,_,_ in records),
            "costs":tuple((execution,tuple(sorted(values.items()))) for execution,values in sorted(costs.items())),
            "unknown_interval":unknown,"resource_head":head,"trigger_original_ref":trigger_original_ref,
            "checkpoint_receipt_digest":canonical_digest(checkpoint[1][1]),
            "census_digest":canonical_digest(census),
            "passive_policies":tuple((p.policy_ref,p.revision,canonical_digest(plain_v1(p))) for p in metadata.passive_policies),
            "settled_components":tuple((item[1].reservation_ref,item[3].settled_components) for item in reservations)},
        proposal_schema="d02.proposal.v1",proposal_hash=domain.descriptor.request_schema_hash)
    domain.validate(stage.proposals[0],frame.snapshot)
    return CharacterLaborTerminalBodyV1(stage,state,tuple(item[3] for item in reservations),
        head,correction,checkpoint,tuple(s for s,_,_,_ in records))

@dataclass(frozen=True, slots=True)
class RebuildCharacterLaborBodyRequestV1:
    action_intent: VersionedRef
    action_intent_digest: str
    action_original: ProductionOriginalRefV1
    policy_ref: str
    policy_revision: int
    policy_digest: str
    checkpoint: VersionedRef
    checkpoint_digest: str
    checkpoint_producer_operation_id: str
    checkpoint_producer_activity_id: str
    checkpoint_receipt_digest: str
    trigger_original: ProductionOriginalRefV1
    checkpoint_original: ProductionOriginalRefV1 | None = None

    def __post_init__(self):
        from ..runtime_contracts import VersionedRef
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        if (type(self.action_intent) is not VersionedRef or self.action_intent.version < 1
                or AtomKey.from_token(self.action_intent.ref).type_name != "d08.action_intent.v1"
                or type(self.checkpoint) is not VersionedRef or self.checkpoint.version < 1
                or AtomKey.from_token(self.checkpoint.ref).type_name != "d02.body_state.v1"
                or type(self.action_original) is not ProductionOriginalRefV1
                or type(self.trigger_original) is not ProductionOriginalRefV1
                or self.checkpoint_original is not None and (type(self.checkpoint_original) is not ProductionOriginalRefV1
                    or self.checkpoint_original.kind != "d02.body_policy_checkpoint_v1")
                or type(self.policy_revision) is not int or self.policy_revision < 1
                or any(type(v) is not str or not v for v in (self.policy_ref,
                    self.checkpoint_producer_operation_id,self.checkpoint_producer_activity_id))):
            raise ValueError("labor rebuild needs its real A/policy/Body checkpoint and producing originals")
        for digest in (self.action_intent_digest,self.policy_digest,self.checkpoint_digest,self.checkpoint_receipt_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("labor rebuild needs exact original commitments")

    @property
    def action_intent_ref(self):
        return self.action_intent.ref


def read_plan_rebuild_character_labor_body_v1(db, *, namespace, activity_id, operation_kind,
        request, operation_id=None):
    if operation_kind != "rebuild_character_labor_body" or type(request) is not RebuildCharacterLaborBodyRequestV1:
        raise TypeError("exact registered character-labor rebuild request required")
    from .d02_character_labor_read_v1 import read_plan_character_labor_source_v1
    return read_plan_character_labor_source_v1(db,namespace=namespace,activity_id=activity_id,
        operation_kind=operation_kind,request=request,operation_id=operation_id)

def stage_rebuild_character_labor_body_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not RebuildCharacterLaborBodyRequestV1:
        raise TypeError("exact current character-labor rebuild request required")
    from .d02_character_labor_read_v1 import require_character_labor_rebuild_inputs_v1
    read = CurrentDomainReadV1(frame)
    metadata,bases,policy = require_character_labor_rebuild_inputs_v1(
        db,frame=frame,request=request,body_readers=installed_readers)
    profile,current,reservations = installed_readers._current_body(db,read,policy.profile_id)
    census = installed_readers.require_labor_census_v1(db,read,current)
    pages = installed_readers.require_labor_pages_v1(db,read,current)
    originals = (*metadata.segments,*(item.segment for page in pages for item in page.items))
    all_records = _segment_members(census,originals,bases)
    records = tuple(item for item in all_records if item[1].policy.profile_id == current.profile_id)
    return _stage_character_labor_history_v1(db,frame=frame,metadata=metadata,census=census,
        current=current,records=records,target=current.cursor,request=request,
        trigger_original_ref=request.trigger_original.original_ref,
        expected_checkpoint=(request.checkpoint.ref,request.checkpoint.version))

LABOR_TERMINAL_BODY_TYPES_V1 = frozenset({
    "d02.body_state.v1","d02.reservation.v1","d02.settlement.v1",
    "d02.character_labor_rebuild_head.v1","d02.character_labor_correction_revision.v1",
})


def character_labor_terminal_body_keys_v1(namespace, *, basis, head_revision):
    from ..graph_types import Owner
    if type(basis) is not CharacterLaborAccountingBasisV1 or basis.namespace != namespace:
        raise TypeError("actual same-namespace labor accounting basis required")
    body = AtomKey(Owner("persona",*namespace.as_tuple),"d02.body_state.v1",basis.policy.profile_id)
    return (body,AtomKey.from_token(basis.reservation_ref),AtomKey.from_token(basis.settlement_ref),
        character_labor_rebuild_key_v1(namespace,basis.policy.profile_id),
        character_labor_correction_key_v1(namespace,basis.policy.profile_id,head_revision))


def validate_character_labor_terminal_body_history_v1(*, binding, segment, basis, receipt, before_body, atoms):
    """Pure membership/debt checks over independently authenticated history EOF.

    This is no signature verifier and issues no current Source, Body or claim
    permission. The caller must authenticate the frozen event and all columns.
    """
    from ..graph_types import GraphAtom
    from ..runtime_contracts import CommitReceipt
    from .d11_life_contract_v1 import D11LifeExecutionBindingV1,life_adoption_operation_id_v1
    from ..domains.d02 import _validate_settlement
    from ..authority_service.c09_character_labor_terminal_membership_v1 import (
        TerminalD02MembershipV1, require_terminal_d02_membership_v1,
    )
    if type(receipt) is TerminalD02MembershipV1:
        require_terminal_d02_membership_v1(receipt,binding=binding,segment=segment,basis=basis)
    elif type(receipt) is not CommitReceipt:
        raise TypeError("actual CommitReceipt or private terminal D02 membership required")
    if (type(binding) is not D11LifeExecutionBindingV1
            or type(segment) is not CharacterWorkSegmentOriginalV1
            or type(basis) is not CharacterLaborAccountingBasisV1
            or receipt.status != "committed"
            or receipt.operation_id != life_adoption_operation_id_v1(binding)
            or receipt.activity_id != binding.activity_id or receipt.effect_id != binding.effect_id
            or (segment.namespace,segment.execution_id,segment.effect_id,segment.binding_digest,segment.prepared_digest)
                != (binding.namespace,binding.execution_id,binding.effect_id,binding.digest,basis.prepared_digest)
            or basis.binding_digest != binding.digest or basis.namespace != binding.namespace
            or type(atoms) is not tuple or any(type(atom) is not GraphAtom for atom in atoms)
            or type(before_body) is not GraphAtom or not before_body.valid):
        raise ValueError("actual same-execution labor lifecycle and authenticated D02 history required")
    selected = {atom.key:atom for atom in atoms}
    expected = {v.key:v.revision for v in receipt.write_versions if v.key.type_name in LABOR_TERMINAL_BODY_TYPES_V1}
    if (len(selected) != len(atoms) or set(selected) != set(expected)
            or any(not atom.valid or atom.revision != expected[atom.key]
                or NamespaceId.from_key(atom.key) != binding.namespace for atom in atoms)):
        raise ValueError("labor terminal D02 history is not its complete exact W01 write membership")
    head_key = character_labor_rebuild_key_v1(binding.namespace,basis.policy.profile_id)
    head_atom = selected.get(head_key)
    if head_atom is None:
        raise ValueError("labor adoption lacks its actual resource rebuild head member")
    head = CharacterLaborRebuildHeadV1(**head_atom.value)
    keys = character_labor_terminal_body_keys_v1(binding.namespace,basis=basis,head_revision=head.revision)
    body_key,reservation_key,settlement_key,_,correction_key = keys
    if (head.revision != head_atom.revision or before_body.key != body_key
            or GraphVersion(body_key,before_body.revision) not in receipt.read_versions
            or head.profile_id != basis.policy.profile_id):
        raise ValueError("labor terminal checkpoint/current Body membership changed")
    prior = BodyState(**before_body.value)
    if prior.version != before_body.revision:
        raise ValueError("labor terminal before-Body has no exact actual GraphVersion")
    if reservation_key not in selected or settlement_key not in selected:
        raise ValueError("labor terminal has no same-effect reservation and settlement members")
    reservation = _reservation(selected[reservation_key].value)
    settlement = selected[settlement_key].value
    _validate_settlement(settlement)
    state = BodyState(**settlement["state"])
    if (_reservation(settlement["reservation"]) != reservation or settlement["duplicate"]
            or reservation.effect_id != binding.effect_id or reservation.quote_id != basis.quote.quote_ref
            or reservation.reserved_cost != basis.quote.max_energy_cost
            or state.profile_id != basis.policy.profile_id
            or head.body_state_version != state.version or head.body_state_digest != canonical_digest(state)
            or head.processed_cursor != state.cursor):
        raise ValueError("labor terminal Head/settlement/reservation changed their original numeric state")
    changed = body_key in selected
    if changed:
        if (BodyState(**selected[body_key].value) != state or state.version != prior.version+1
                or selected[body_key].revision != state.version or correction_key not in selected):
            raise ValueError("labor numeric correction lacks its actual one-CAS Body and immutable correction")
        correction = CharacterLaborCorrectionRevisionV1(**selected[correction_key].value)
        if (correction.profile_id != head.profile_id or correction.revision != head.revision
                or correction.prior_body_version != prior.version or correction.new_body_version != state.version
                or (correction.checkpoint_ref,correction.checkpoint_revision,correction.checkpoint_digest)
                    != (head.checkpoint_ref,head.checkpoint_revision,head.checkpoint_digest)
                or correction.originals_root != head.originals_root
                or correction.trigger_original_ref != segment.segment_id
                or (correction.source_epoch,correction.deletion_epoch) != (head.source_epoch,head.deletion_epoch)):
            raise ValueError("labor correction is not the same actual Head/terminal/checkpoint original")
    elif state != prior or correction_key in selected:
        raise ValueError("unchanged labor Body cannot invent a new Body version or correction")
    known_end = None if segment.to_character is None else _role(segment.to_character)
    complete = known_end is not None and known_end <= head.processed_cursor and segment.status in {"completed","failed"}
    if complete:
        components = (*basis.policy.duration_components,
            *(basis.policy.fixed_components if segment.status == "completed" else ()))
        if not {_component_key(component.component_id,segment) for component in components} <= set(reservation.settled_components):
            raise ValueError("closed labor history omitted an actual completed segment/component accounting identity")
        if reservation.status not in {"settled","overrun"}:
            raise ValueError("known completely processed labor retained an inconsistent reservation state")
    elif reservation.status not in {"pending_confirmation","overrun"} or head.status == "current":
        raise ValueError("unknown or unprocessed labor history discarded its actual resource debt")
    return tuple(GraphVersion(key,revision) for key,revision in sorted(expected.items(),key=lambda item:item[0].token))

# This original exists only for new installations. It cannot be reconstructed
# from graph_events, whose historical schema omits Event kind and time.
BODY_POLICY_CHECKPOINT_KIND_V1 = "body_policy_checkpoint_v1"
BODY_POLICY_CHECKPOINT_SIGN_KIND_V1 = "d02.body-policy-checkpoint.v1"


@dataclass(frozen=True, slots=True)
class BodyPolicyCheckpointOriginalV1:
    namespace: NamespaceId
    original_ref: str
    producing_operation_id: str
    attempt_id: str
    permit_digest: str
    authority_namespace: str
    activation_generation: int
    policy_json: str
    policy_signature: str
    event_json: str
    receipt_json: str
    before_epoch: int
    write_digests: tuple[tuple[VersionedRef,str], ...]
    schema: str = "d02.body-policy-checkpoint.v1"

    def __post_init__(self):
        from dataclasses import asdict
        from ..contracts import Event,Scope
        from ..graph_types import GraphReceipt,NamespaceEpoch
        from ..domains.d02.body_quote_original import FixedBodyPolicyV1
        from .d10_offline_tick_execution_v1 import _decode_json
        from ..runtime_contracts import canonical_serialize
        import json
        if (self.schema != BODY_POLICY_CHECKPOINT_SIGN_KIND_V1
                or type(self.namespace) is not NamespaceId
                or self.original_ref != "body-policy-checkpoint:"+self.attempt_id
                or type(self.activation_generation) is not int or self.activation_generation < 0
                or type(self.before_epoch) is not int or self.before_epoch < 0
                or type(self.write_digests) is not tuple or len(self.write_digests) != 2):
            raise ValueError("exact initial Body checkpoint identity required")
        policy = _decode_json(self.policy_json,FixedBodyPolicyV1)
        event_raw,receipt_raw = json.loads(self.event_json),json.loads(self.receipt_json)
        if (set(event_raw) != {"scope","event_id","occurred_at","kind","payload"}
                or set(event_raw["scope"]) != {"bot","persona","session"}
                or set(receipt_raw) != {"status","revisions","invalidated","epoch"}
                or set(receipt_raw["epoch"]) != {"bot","persona","revision"}):
            raise ValueError("closed actual Body installation Event and GraphReceipt required")
        event = Event(Scope(**event_raw["scope"]),event_raw["event_id"],
            event_raw["occurred_at"],event_raw["kind"],event_raw["payload"])
        def version(raw):
            if type(raw) is not dict or set(raw) != {"key","revision"}:
                raise ValueError("closed installation GraphVersion required")
            return GraphVersion(AtomKey.from_token(raw["key"]),raw["revision"])
        receipt = GraphReceipt(receipt_raw["status"],tuple(map(version,receipt_raw["revisions"])),
            tuple(map(version,receipt_raw["invalidated"])),NamespaceEpoch(**receipt_raw["epoch"]))
        expected = (BodyDomain.profile_write(policy.profile),BodyDomain.state_write(self.namespace,policy.initial_state))
        expected_versions = tuple(GraphVersion(write.key,1) for write in expected)
        if (policy.profile.namespace != self.namespace
                or self.attempt_id != "c04-body-install-"+canonical_digest((self.namespace,self.producing_operation_id,policy))[:48]
                or (event.scope.bot,event.scope.persona,event.scope.session,event.event_id,event.kind)
                    != (*self.namespace.as_tuple,"c04.fixed_body_install.v1",self.producing_operation_id,"body_policy_install")
                or dict(event.payload) != {"policy_digest":canonical_digest(policy)}
                or policy.valid_until <= event.occurred_at
                or receipt.status != "committed" or receipt.revisions != expected_versions
                or receipt.epoch != NamespaceEpoch(*self.namespace.as_tuple,self.before_epoch+1)
                or self.write_digests != tuple((VersionedRef(w.key.token,1),canonical_digest(w.value)) for w in expected)
                or canonical_serialize(asdict(policy)) != self.policy_json
                or canonical_serialize(plain_v1(event)) != self.event_json
                or canonical_serialize(plain_v1(receipt)) != self.receipt_json):
            raise ValueError("initial Body checkpoint is not its exact signed policy/event/two-write installation")
        for digest in (self.permit_digest,*(digest for _,digest in self.write_digests)):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("initial Body checkpoint requires exact original commitments")
        if not self.authority_namespace or not self.policy_signature:
            raise ValueError("initial Body checkpoint missing actual authority/signature")

    @property
    def graph_receipt(self):
        from ..graph_types import GraphReceipt,NamespaceEpoch
        import json
        value = json.loads(self.receipt_json)
        return GraphReceipt(value["status"],
            tuple(GraphVersion(AtomKey.from_token(v["key"]),v["revision"]) for v in value["revisions"]),
            tuple(GraphVersion(AtomKey.from_token(v["key"]),v["revision"]) for v in value["invalidated"]),
            NamespaceEpoch(**value["epoch"]))


def body_policy_checkpoint_from_wire_v1(raw):
    from dataclasses import fields
    from ..runtime_contracts import canonical_serialize
    if type(raw) is not dict or set(raw) != {f.name for f in fields(BodyPolicyCheckpointOriginalV1)}:
        raise ValueError("closed Body installation checkpoint fields required")
    value = dict(raw)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["write_digests"] = tuple((VersionedRef(**v),digest) for v,digest in value["write_digests"])
    result = BodyPolicyCheckpointOriginalV1(**value)
    if canonical_serialize(plain_v1(result)) != canonical_serialize(raw):
        raise ValueError("Body installation checkpoint canonical roundtrip changed")
    return result


from contextvars import ContextVar
_BODY_POLICY_INSTALLATION_V1 = ContextVar("body_policy_checkpoint_installation_v1",default=None)


def bind_body_policy_checkpoint_installation_v1(graph,*,bootstrap,authority,lease,policy,scope):
    from contextlib import contextmanager
    from threading import get_ident
    from types import SimpleNamespace
    from ..graph_coordinator import GraphCoordinator
    from ..runtime_contracts import AuthorityContext
    from ..domains.d02.body_quote_original import FixedBodyPolicyV1,D02BodyQuoteAuthority
    from .issuers import D11BudgetJobIssuer
    from ..runtime_contracts import FenceScope
    from .d11_life_preparation_v1 import DDL
    @contextmanager
    def bind():
        if (type(graph) is not GraphCoordinator or type(authority) is not AuthorityContext
                or type(policy) is not FixedBodyPolicyV1 or type(scope) is not FenceScope
                or _BODY_POLICY_INSTALLATION_V1.get() is not None):
            raise TypeError("actual single C04 Body installation invocation required")
        graph._admin(bootstrap)
        graph._authorize(lease,authority,frozenset(("d02",)),owner_read=True)
        owner = graph._GraphCoordinator__owner_leases.get(lease)
        proof = graph._GraphCoordinator__owner_session_proofs.get(lease)
        store = graph._GraphCoordinator__store
        issuer = graph._GraphCoordinator__d11_issuer
        quote = graph._GraphCoordinator__body_quote_authority
        port = graph._GraphCoordinator__content_fence_v2
        if (type(issuer) is not D11BudgetJobIssuer or type(quote) is not D02BodyQuoteAuthority
                or owner is None or proof is None or "d02.body_policy.install" not in owner.capabilities
                or owner.namespace != authority.namespace or owner.actor != authority.actor
                or owner.purpose != authority.purpose or authority.audience != (owner.audience,)
                or authority.issuer_domain != "d12" or policy.profile.namespace != authority.namespace
                or scope.namespace != authority.namespace or scope.operation != "write"
                or scope.operation_id != scope.permit.operation_id
                or scope.generation != authority.activation_generation
                or scope.permit.pinned_anchor != scope.pinned_anchor
                or port.validate_fence(scope) != scope.permit):
            raise ValueError("Body checkpoint requires the real installed policy/Owner/current WRITE fence")
        graph._owner_binding_in_fence(authority,scope,owner.principal,owner,owner_session_proof=proof)
        with store._lock:
            if store._db.in_transaction:
                raise ValueError("Body checkpoint installation context must precede Graph SQL")
            store._db.execute(DDL.replace("CREATE TABLE ","CREATE TABLE IF NOT EXISTS ",1))
        state = SimpleNamespace(graph=graph,db=store._db,scope=scope,policy=policy,
            issuer=issuer,quote=quote,thread=get_ident(),recorded=False)
        token = _BODY_POLICY_INSTALLATION_V1.set(state)
        try:
            yield state
        finally:
            _BODY_POLICY_INSTALLATION_V1.reset(token)
    return bind()


def record_body_policy_checkpoint_after_graph_v1(db,*,graph,policy,candidate,receipt):
    from dataclasses import asdict
    from threading import get_ident
    from ..graph_types import GraphCandidate,GraphReceipt
    from ..runtime_contracts import canonical_serialize
    from ..contracts import canonical_json
    from .d11_life_preparation_v1 import TABLE
    state = _BODY_POLICY_INSTALLATION_V1.get()
    if (state is None or state.graph is not graph or state.db is not db
            or state.thread != get_ident() or state.policy is not policy
            or state.recorded or not db.in_transaction
            or type(candidate) is not GraphCandidate or type(receipt) is not GraphReceipt):
        raise ValueError("actual same-transaction Body install callback required")
    scope,ns = state.scope,state.scope.namespace
    writes = (BodyDomain.profile_write(policy.profile),BodyDomain.state_write(ns,policy.initial_state))
    reads = tuple(GraphVersion(w.key,0) for w in writes)
    event = candidate.event
    if (candidate.writes != writes or candidate.reads != reads or candidate.epochs != (scope.graph_epoch,)
            or event.event_id == "" or scope.operation_id != "c04-body-install-"+canonical_digest((ns,event.event_id,policy))[:48]
            or receipt.revisions != tuple(GraphVersion(w.key,1) for w in writes)
            or receipt.status != "committed"):
        raise ValueError("Body checkpoint callback differs from its exact actual initialization")
    saved = db.execute("SELECT policy_json,signature,status FROM d02_fixed_body_policies_v1 WHERE bot=? AND persona=? AND policy_id=? AND version=?",
        (*ns.as_tuple,policy.policy_id,policy.version)).fetchone()
    expected_policy = canonical_serialize(asdict(policy))
    if saved is None or saved[0] != expected_policy or saved[2] != "active":
        raise ValueError("actual same-transaction signed FixedBodyPolicy required")
    state.quote._verify("d02-fixed-body-policy.v1",saved[0],saved[1])
    row = db.execute("SELECT digest,reads,epoch_reads,revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*ns.as_tuple,event.scope.session,event.event_id)).fetchone()
    expected = (event.digest,canonical_json([[v.key.token,v.revision] for v in reads]),
        canonical_json([[e.bot,e.persona,e.revision] for e in candidate.epochs]),
        canonical_json([[v.key.token,v.revision] for v in receipt.revisions]),
        canonical_json([[v.key.token,v.revision] for v in receipt.invalidated]),receipt.epoch.revision)
    if row != expected:
        raise ValueError("Body checkpoint is not the actual committed Graph event")
    for version in (*receipt.revisions,*receipt.invalidated):
        history = db.execute("SELECT valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
            (version.key.token,version.revision)).fetchone()
        if history != (int(version in receipt.revisions),*ns.as_tuple,event.scope.session,event.event_id):
            raise ValueError("Body checkpoint history is not its same true installation event")
    original = BodyPolicyCheckpointOriginalV1(ns,"body-policy-checkpoint:"+scope.operation_id,
        event.event_id,scope.operation_id,canonical_digest(scope.permit),scope.authority_namespace,
        scope.generation,saved[0],saved[1],canonical_serialize(plain_v1(event)),
        canonical_serialize(plain_v1(receipt)),scope.graph_epoch.revision,
        tuple((VersionedRef(w.key.token,1),canonical_digest(w.value)) for w in writes))
    wire,digest = canonical_serialize(plain_v1(original)),canonical_digest(plain_v1(original))
    signature = state.issuer._signer.sign(BODY_POLICY_CHECKPOINT_SIGN_KIND_V1,
        canonical_serialize((ns,BODY_POLICY_CHECKPOINT_KIND_V1,original.original_ref,digest)))
    db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?)",
        (*ns.as_tuple,BODY_POLICY_CHECKPOINT_KIND_V1,original.original_ref,event.event_id,wire,digest,signature))
    state.recorded = True
    return original


def _body_checkpoint_versions_v1(receipt):
    from ..graph_types import GraphReceipt
    from ..runtime_contracts import CommitReceipt
    if type(receipt) is GraphReceipt:
        return receipt.revisions
    if type(receipt) is CommitReceipt:
        return receipt.write_versions
    raise TypeError("actual W01 or initial Graph checkpoint receipt required")

@dataclass(frozen=True,slots=True)
class CharacterLaborRebuildSelectorV1:
    action_intent_ref: str
    policy_ref: str
    policy_revision: int

    def __post_init__(self):
        if (AtomKey.from_token(self.action_intent_ref).type_name != "d08.action_intent.v1"
                or type(self.policy_ref) is not str or not self.policy_ref
                or type(self.policy_revision) is not int or self.policy_revision < 1):
            raise ValueError("labor rebuild selection requires its explicit actual A and policy version")


@dataclass(frozen=True,eq=False)
class CharacterLaborRebuildSelectionInputsV1:
    request: RebuildCharacterLaborBodyRequestV1
    activity_id: str
    audience_ref: str
    parent_budget_lease_ref: str
    deadline_utc: float
    selection_digest: str
    graph_stamp: tuple


from weakref import WeakKeyDictionary
_REBUILD_SELECTION_KEY_V1 = object()
_REBUILD_SELECTIONS_V1 = WeakKeyDictionary()


class PreparedCharacterLaborRebuildSelectionV1:
    def __init__(self,key,reader,request):
        if key is not _REBUILD_SELECTION_KEY_V1:
            raise TypeError("actual complete metadata selector Work required")
        from .d02_character_labor_read_v1 import require_character_labor_rebuild_selector_ready_v1
        if require_character_labor_rebuild_selector_ready_v1(reader) is not request:
            raise ValueError("labor rebuild selection lacks its actual fixed metadata EOF")
        self.reader,self.request = reader,request
        self.selection_digest = canonical_digest((reader.request,plain_v1(request),
            reader.namespace,reader.operation_id,reader.selection_digest,reader.graph_stamp,
            reader.parent_budget_lease_ref,reader.deadline_utc))
        _REBUILD_SELECTIONS_V1[self] = (reader,reader.work,reader.operation,reader.fence,
            reader.owner_binding,reader.selection_digest,reader.graph_stamp,reader.deadline_utc,
            request,self.selection_digest,False)

    def release_payload_v3(self):
        reader = self.reader
        if reader is None:
            return
        record = _REBUILD_SELECTIONS_V1.get(self)
        if record is None or record[0] is not reader:
            raise ValueError("labor selector payload is not its actual registered reader")
        from .current_method_learning_read_v3 import release_current_method_metadata_selector_payload_v1
        release_current_method_metadata_selector_payload_v1(reader)


def require_character_labor_rebuild_selection_terminal_v1(value,work):
    if type(value) is not PreparedCharacterLaborRebuildSelectionV1:
        raise TypeError("actual private labor rebuild selection terminal required")
    record = _REBUILD_SELECTIONS_V1.get(value)
    r = value.reader
    if (record is None or r is None or record[:-1] != (r,work,r.operation,r.fence,r.owner_binding,
            r.selection_digest,r.graph_stamp,r.deadline_utc,value.request,value.selection_digest)
            or work.state is not r or work.operation is not r.operation
            or not r.inventory_sealed or not r.complete or not r.read_finished
            or r.inputs_sealed or r.business_started or r.operation.closed):
        raise ValueError("labor selection terminal is not this completed metadata-only READ Work")
    return value


def consume_character_labor_rebuild_selection_v1(proof,*,graph,work):
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3
    from .d02_character_labor_read_v1 import require_character_labor_rebuild_selector_ready_v1
    record = _REBUILD_SELECTIONS_V1.get(proof)
    if type(proof) is not PreparedCharacterLaborRebuildSelectionV1 or record is None:
        raise TypeError("actual private complete labor rebuild selector required")
    r = proof.reader
    if (record != (r,work,r.operation,r.fence,r.owner_binding,r.selection_digest,
            r.graph_stamp,r.deadline_utc,proof.request,proof.selection_digest,False)
            or r.graph is not graph or work.state is not r or r.db.in_transaction or not r.read_finished):
        raise ValueError("labor rebuild selector must be consumed once by its original terminal invocation")
    work._require_invocation(graph)
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock,runtime_storage_quantum_v3(r.db) as meter:
        if require_character_labor_rebuild_selector_ready_v1(r,meter=meter) is not proof.request:
            raise ValueError("labor rebuild selected originals changed before same-call handoff")
    _REBUILD_SELECTIONS_V1[proof] = (*record[:-1],True)
    inputs = CharacterLaborRebuildSelectionInputsV1(proof.request,r.activity_id,r.audience_ref,
        r.parent_budget_lease_ref,r.deadline_utc,r.selection_digest,r.graph_stamp)
    _DETACHED_REBUILD_INPUTS_V1[inputs] = (graph,canonical_digest(plain_v1(inputs)))
    return inputs


def release_character_labor_rebuild_selections_v1(reader):
    for value,record in tuple(_REBUILD_OPTIONS_V1.items()):
        if record[0] is reader:
            _REBUILD_OPTIONS_V1.pop(value,None)
            value.reader = None
    for proof,record in tuple(_REBUILD_SELECTIONS_V1.items()):
        if record[0] is reader:
            _REBUILD_SELECTIONS_V1.pop(proof,None)
            proof.reader = None


def character_labor_rebuild_selection_view_v1(inputs):
    """Data-only UI projection; it supplies no Source, Body or WRITE authority."""
    if type(inputs) is not CharacterLaborRebuildSelectionInputsV1:
        raise TypeError("exact detached labor selection inputs required")
    q = inputs.request
    return {"schema":"d02.character-labor-rebuild-selection.v1",
        "selector":{"action_intent_ref":q.action_intent.ref,"policy_ref":q.policy_ref,
            "policy_revision":q.policy_revision},
        "choice_digest":canonical_digest((plain_v1(q),inputs.selection_digest,inputs.graph_stamp)),
        "profile_id":AtomKey.from_token(q.checkpoint.ref).name,
        "checkpoint":{"ref":q.checkpoint.ref,"revision":q.checkpoint.version,
            "origin_kind":"body_policy_install_v1" if q.checkpoint_original is not None else "w01",
            "producer_operation_id":q.checkpoint_producer_operation_id},
        "activity_id":inputs.activity_id,"audience_ref":inputs.audience_ref,
        "parent_budget_lease_ref":inputs.parent_budget_lease_ref}

REBUILD_SELECTION_BINDING_KIND_V1 = "character_labor_rebuild_selection_binding_v1"
REBUILD_SELECTION_BINDING_SIGN_KIND_V1 = "d02.character-labor-rebuild-selection-binding.v1"


def _labor_digest_v1(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True,slots=True)
class CharacterLaborRebuildCommandContextV1:
    mutation_operation_id: str
    action: str
    scope: str
    purpose: str
    audience: str
    command_input_digest: str
    selector: CharacterLaborRebuildSelectorV1
    expected_choice_digest: str

    def __post_init__(self):
        from uuid import UUID
        if (str(UUID(self.mutation_operation_id)) != self.mutation_operation_id
                or self.action != "domain_rebuild_character_labor_body"
                or type(self.selector) is not CharacterLaborRebuildSelectorV1
                or any(type(v) is not str or not v for v in (self.scope,self.purpose,self.audience))
                or not all(_labor_digest_v1(v) for v in (self.command_input_digest,self.expected_choice_digest))):
            raise ValueError("actual canonical D12 labor command identity required")


@dataclass(frozen=True,slots=True)
class CharacterLaborRebuildAttemptV1:
    permit: object
    request_digest: str
    attempt_id: str
    finish_request_id: str
    finish_digest: str

    def __post_init__(self):
        from ..authority_service.v2_contract import FencePermitV2
        if (type(self.permit) is not FencePermitV2 or self.permit.operation != "write"
                or self.permit.operation_id != self.attempt_id
                or not _labor_digest_v1(self.request_digest)
                or self.finish_request_id != "finish:"+self.attempt_id
                or type(self.finish_digest) is not str or not self.finish_digest.startswith("sha256:")
                or not _labor_digest_v1(self.finish_digest[7:])):
            raise ValueError("actual original owner WRITE attempt and exact finish tuple required")


@dataclass(frozen=True,slots=True)
class CharacterLaborRebuildSelectionBindingV1:
    namespace: NamespaceId
    authority_id: str
    authority_namespace: str
    installation_id: str
    manifest_digest: str
    actor: str
    command: CharacterLaborRebuildCommandContextV1
    request: RebuildCharacterLaborBodyRequestV1
    activity_id: str
    audience_ref: str
    parent_budget_lease_ref: str
    deadline_utc: float
    selection_digest: str
    graph_stamp: tuple
    domain_original: ProductionOriginalRefV1
    domain_request_digest: str
    operation_digest: str
    receipt_digest: str
    commit_seq: int
    attempt: CharacterLaborRebuildAttemptV1
    native_result: dict
    event_digest: str
    before_graph_revision: int
    before_graph_epoch: int
    post_graph_revision: int
    post_graph_epoch: int
    invalidated_vector_sha256: str
    invalidated_vector_bytes: int
    invalidated_vector_count: int
    schema: str = "d02.character-labor-rebuild-selection-binding.v1"

    @property
    def original_ref(self):
        return "character-labor-rebuild-selection:"+self.command.mutation_operation_id

    def __post_init__(self):
        if (self.schema != "d02.character-labor-rebuild-selection-binding.v1"
                or type(self.namespace) is not NamespaceId
                or type(self.command) is not CharacterLaborRebuildCommandContextV1
                or type(self.request) is not RebuildCharacterLaborBodyRequestV1
                or type(self.attempt) is not CharacterLaborRebuildAttemptV1
                or type(self.domain_original) is not ProductionOriginalRefV1
                or self.domain_original.kind != "d02.current-rebuild_character_labor_body"
                or self.domain_original.read_versions
                or self.domain_original.original_ref != "d02-current:"+self.domain_original.original_digest[:48]
                or self.command.selector != CharacterLaborRebuildSelectorV1(self.request.action_intent.ref,
                    self.request.policy_ref,self.request.policy_revision)
                or self.command.audience != self.audience_ref
                or type(self.deadline_utc) not in (float,int) or not math.isfinite(self.deadline_utc)
                or self.deadline_utc <= 0 or type(self.commit_seq) is not int or self.commit_seq < 1
                or type(self.graph_stamp) is not tuple
                or any(type(v) is not str or not v for v in (self.authority_id,self.authority_namespace,
                    self.installation_id,self.actor,self.activity_id,self.audience_ref,self.parent_budget_lease_ref))
                or not all(_labor_digest_v1(v) for v in (self.manifest_digest,self.selection_digest,
                    self.domain_request_digest,self.operation_digest,self.receipt_digest,
                    self.domain_original.original_digest,self.event_digest,self.invalidated_vector_sha256))
                or any(type(v) is not int or v < 0 for v in (self.before_graph_revision,
                    self.before_graph_epoch,self.post_graph_revision,self.post_graph_epoch,
                    self.invalidated_vector_bytes,self.invalidated_vector_count))
                or self.post_graph_revision != self.before_graph_revision+1
                or self.post_graph_epoch != self.before_graph_epoch+1
                or self.invalidated_vector_count > 1024):
            raise ValueError("closed actual labor rebuild selection/command/W01 lineage required")
        from .domain_production_originals_v1 import _receipt
        expected_fields = {"schema","domain","operation_kind","operation_id","activity_id","original_ref",
            "original_digest","receipt","receipt_digest","job_states","coverage","missing_inputs",
            "continuation_ref","outbox","produced_originals"}
        n = self.native_result
        if (type(n) is not dict or set(n) != expected_fields
                or (n["schema"],n["domain"],n["operation_kind"],n["operation_id"],n["activity_id"],
                    n["original_ref"],n["original_digest"],n["receipt_digest"]) != (
                    "sylanne.domain-production-receipt.v1","d02","rebuild_character_labor_body",
                    self.command.mutation_operation_id,self.activity_id,self.domain_original.original_ref,
                    self.domain_original.original_digest,self.receipt_digest)
                or n["job_states"] != [] or n["outbox"] != [] or n["produced_originals"] != []):
            raise ValueError("labor binding requires its exact actual native committed reply")
        receipt = _receipt(n["receipt"])
        if (receipt.status != "committed" or receipt.operation_id != self.command.mutation_operation_id
                or receipt.commit_seq != self.commit_seq or receipt.operation_digest != self.operation_digest
                or canonical_digest(receipt) != self.receipt_digest):
            raise ValueError("labor binding native reply changed its actual W01 receipt")
        p = self.attempt.permit
        if (p.namespace != self.authority_namespace or p.authority_id != self.authority_id
                or self.command.expected_choice_digest != canonical_digest((plain_v1(self.request),
                    self.selection_digest,self.graph_stamp))
                or self.attempt.finish_digest != "sha256:"+canonical_digest({
                    "schema":"w01.owner-domain-write.v3","operation_id":self.command.mutation_operation_id,
                    "request_digest":self.attempt.request_digest,"permit_token":p.token})):
            raise ValueError("labor selection binding changed its original attempt or selected inputs")


def character_labor_rebuild_request_from_wire_v1(raw):
    from dataclasses import fields
    from ..runtime_contracts import canonical_serialize
    if type(raw) is not dict or set(raw) != {f.name for f in fields(RebuildCharacterLaborBodyRequestV1)}:
        raise ValueError("closed labor rebuild request fields required")
    v = dict(raw)
    for name in ("action_intent","checkpoint"):
        v[name] = VersionedRef(**v[name])
    for name in ("action_original","trigger_original","checkpoint_original"):
        if v[name] is not None:
            item = dict(v[name])
            item["read_versions"] = tuple(GraphVersion(AtomKey.from_token(x["key"]),x["revision"])
                for x in item["read_versions"])
            v[name] = ProductionOriginalRefV1(**item)
    result = RebuildCharacterLaborBodyRequestV1(**v)
    if canonical_serialize(plain_v1(result)) != canonical_serialize(raw):
        raise ValueError("labor rebuild request canonical roundtrip changed")
    return result


def character_labor_rebuild_selection_binding_from_wire_v1(raw):
    from dataclasses import fields
    from ..runtime_contracts import canonical_serialize
    from ..authority_service.v2_contract import from_wire
    if type(raw) is not dict or set(raw) != {f.name for f in fields(CharacterLaborRebuildSelectionBindingV1)}:
        raise ValueError("closed labor rebuild binding fields required")
    v = dict(raw)
    v["namespace"] = NamespaceId(**v["namespace"])
    command = dict(v["command"])
    command["selector"] = CharacterLaborRebuildSelectorV1(**command["selector"])
    v["command"] = CharacterLaborRebuildCommandContextV1(**command)
    v["request"] = character_labor_rebuild_request_from_wire_v1(v["request"])
    original = dict(v["domain_original"]); original["read_versions"] = tuple(original["read_versions"])
    v["domain_original"] = ProductionOriginalRefV1(**original)
    attempt = dict(v["attempt"]); attempt["permit"] = from_wire(attempt["permit"])
    v["attempt"] = CharacterLaborRebuildAttemptV1(**attempt)
    from ..graph_store import GraphRecoveryMetadataV2
    from ..graph_types import NamespaceEpoch
    from ..runtime_contracts import SnapshotRequirementsV2
    if type(v["graph_stamp"]) is not list or len(v["graph_stamp"]) != 2:
        raise ValueError("actual two typed Graph comparison stamps required")
    metadata,epoch = map(dict,v["graph_stamp"])
    requirements = dict(metadata["requirements"])
    requirements["namespace"] = NamespaceId(**requirements["namespace"])
    metadata["requirements"] = SnapshotRequirementsV2(**requirements)
    v["graph_stamp"] = (GraphRecoveryMetadataV2(**metadata),NamespaceEpoch(**epoch))
    result = CharacterLaborRebuildSelectionBindingV1(**v)
    if canonical_serialize(character_labor_rebuild_selection_binding_wire_v1(result)) != canonical_serialize(raw):
        raise ValueError("labor rebuild binding canonical roundtrip changed")
    return result


def character_labor_rebuild_selection_binding_wire_v1(value):
    if type(value) is not CharacterLaborRebuildSelectionBindingV1:
        raise TypeError("exact labor rebuild selection binding required")
    from ..authority_service.v2_contract import to_wire
    result = plain_v1(value)
    result["attempt"]["permit"] = to_wire(value.attempt.permit)
    return result


_DETACHED_REBUILD_INPUTS_V1 = WeakKeyDictionary()


def require_detached_character_labor_rebuild_inputs_v1(inputs,*,graph):
    record = _DETACHED_REBUILD_INPUTS_V1.get(inputs)
    if (type(inputs) is not CharacterLaborRebuildSelectionInputsV1 or record is None
            or record[0] is not graph or record[1] != canonical_digest(plain_v1(inputs))):
        raise ValueError("actual once-detached labor selection inputs required")
    return inputs


def record_character_labor_rebuild_selection_binding_after_cas_v1(witness,*,db,receipt,domain_original):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from .character_labor_rebuild_selector_v1 import require_current_character_labor_rebuild_binding_context_v1
    from .d11_life_preparation_v1 import TABLE
    from ..runtime_contracts import CommitReceipt,canonical_serialize
    from ..authority_service.v2_contract import from_wire
    import json
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or not db.in_transaction or type(receipt) is not CommitReceipt
            or witness.graph._GraphCoordinator__store._db is not db
            or type(witness.stage) is not CharacterLaborTerminalBodyV1
            or witness.operation.operation_kind != "rebuild_character_labor_body"):
        raise ValueError("actual same-transaction rebuild W01 private witness required")
    inputs,command = require_current_character_labor_rebuild_binding_context_v1(witness,db=db,receipt=receipt)
    require_detached_character_labor_rebuild_inputs_v1(inputs,graph=witness.graph)
    stage,authority = witness.stage.stage,witness.frame.envelope.authority
    if (type(command) is not CharacterLaborRebuildCommandContextV1 or witness.request is not inputs.request
            or receipt.status != "committed" or receipt.operation_id != command.mutation_operation_id
            or stage.operation_id != receipt.operation_id or type(domain_original) is not ProductionOriginalRefV1
            or domain_original != ProductionOriginalRefV1("d02.current-rebuild_character_labor_body",
                "d02-current:"+stage.original_digest[:48],stage.original_digest,stage.read_versions)
            or (receipt.activity_id,stage.activity_id,stage.namespace)!=(inputs.activity_id,inputs.activity_id,authority.namespace)
            or command.purpose != authority.purpose or authority.audience != (command.audience,)):
        raise ValueError("rebuild binding does not match its actual selected request/Domain original/W01")
    ns = authority.namespace
    ledger = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple,receipt.operation_id)).fetchone()
    if ledger != (receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise ValueError("rebuild binding is not its actual committed bundle")
    row = db.execute("SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple,receipt.operation_id)).fetchone()
    if row is None or row[1] != witness.scope.operation_id:
        raise ValueError("rebuild binding lost its actual owner attempt")
    permit = from_wire(json.loads(row[2]))
    if permit != witness.scope.permit:
        raise ValueError("rebuild binding cannot replace the original owner WRITE permit")
    attempt = CharacterLaborRebuildAttemptV1(permit,row[0],row[1],"finish:"+row[1],
        "sha256:"+canonical_digest({"schema":"w01.owner-domain-write.v3","operation_id":receipt.operation_id,
            "request_digest":row[0],"permit_token":permit.token}))
    from ..host.authority_profile import current_owner_metadata_installation_v3
    installation = current_owner_metadata_installation_v3(witness.graph)[0].installation_policy
    from .domain_production_commit_v1 import _members,build_domain_production_result_v1
    primary,proposals,jobs,events,extra = _members(witness.stage)
    if (primary is not stage or proposals != stage.proposals or jobs or events or extra
            or witness.external_originals or stage.outbox):
        raise ValueError("labor rebuild native reply requires its exact registered empty-job/outbox shape")
    native_result = build_domain_production_result_v1(primary=stage,receipt=receipt,
        original=domain_original,produced=(),job_states=())
    captured = _REBUILD_GRAPH_RECEIPTS_V1.get(id(witness))
    if captured is None or captured[0] is not witness:
        raise ValueError("rebuild binding lacks its actual FULL writer receipt capture")
    event = db.execute("SELECT digest,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*ns.as_tuple,receipt.activity_id,receipt.operation_id)).fetchone()
    fence = db.execute("SELECT digest,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple,receipt.operation_id)).fetchone()
    after_stamp = witness.graph._v2_graph_stamp(ns)
    expected_transition = (captured[2],captured[3],captured[2]+1,captured[4])
    if (event != (captured[1],captured[4]) or fence != (receipt.operation_digest,*expected_transition,
            attempt.finish_request_id,attempt.finish_digest)
            or (after_stamp[0].graph_revision,after_stamp[1].revision) != expected_transition[2:]):
        raise ValueError("rebuild binding changed its actual event/fenced Graph commit")
    value = CharacterLaborRebuildSelectionBindingV1(ns,installation.expected_authority_id,
        installation.authority_namespace,installation.installation_id,installation.manifest_digest,
        authority.actor,command,inputs.request,inputs.activity_id,inputs.audience_ref,inputs.parent_budget_lease_ref,
        inputs.deadline_utc,inputs.selection_digest,inputs.graph_stamp,
        ProductionOriginalRefV1(domain_original.kind,domain_original.original_ref,domain_original.original_digest),
        stage.request_digest,receipt.operation_digest,canonical_digest(receipt),receipt.commit_seq,attempt,native_result,
        captured[1],*expected_transition,*captured[5:])
    wire = canonical_serialize(character_labor_rebuild_selection_binding_wire_v1(value))
    digest = canonical_digest(character_labor_rebuild_selection_binding_wire_v1(value))
    issuer = witness.graph._GraphCoordinator__d11_issuer
    signature = issuer._signer.sign(REBUILD_SELECTION_BINDING_SIGN_KIND_V1,
        canonical_serialize((ns,REBUILD_SELECTION_BINDING_KIND_V1,value.original_ref,digest)))
    db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?)",
        (*ns.as_tuple,REBUILD_SELECTION_BINDING_KIND_V1,value.original_ref,receipt.operation_id,wire,digest,signature))
    release_character_labor_rebuild_graph_receipt_v1(witness)
    return ProductionOriginalRefV1("d02."+REBUILD_SELECTION_BINDING_KIND_V1,value.original_ref,digest)

@dataclass(frozen=True,slots=True)
class CharacterLaborRebuildOptionsRequestV1:
    action_intent_ref: str

    def __post_init__(self):
        if AtomKey.from_token(self.action_intent_ref).type_name != "d08.action_intent.v1":
            raise ValueError("explicit actual A locator required for labor policy options")


_REBUILD_OPTIONS_V1 = WeakKeyDictionary()


class PreparedCharacterLaborRebuildOptionsV1:
    def __init__(self,key,reader,view):
        if key is not _REBUILD_SELECTION_KEY_V1:
            raise TypeError("actual complete labor policy metadata catalogue required")
        self.reader,self.view = reader,view
        _REBUILD_OPTIONS_V1[self] = (reader,reader.work,reader.operation,reader.fence,
            reader.selection_digest,reader.graph_stamp,canonical_digest(view),False)

    def release_payload_v3(self):
        if self.reader is None:
            return
        from .current_method_learning_read_v3 import release_current_method_metadata_selector_payload_v1
        release_current_method_metadata_selector_payload_v1(self.reader)


def require_character_labor_rebuild_options_terminal_v1(value,work):
    if type(value) is not PreparedCharacterLaborRebuildOptionsV1:
        raise TypeError("actual private labor options terminal required")
    record = _REBUILD_OPTIONS_V1.get(value)
    r = value.reader
    if (r is None or record is None or record[:-1] != (r,work,r.operation,r.fence,
            r.selection_digest,r.graph_stamp,canonical_digest(value.view))
            or not r.complete or not r.read_finished or not r.inventory_sealed
            or r.inputs_sealed or r.business_started or r.operation.closed or work.state is not r):
        raise ValueError("labor options lack this complete metadata-only Method READ")
    return value


def consume_character_labor_rebuild_options_v1(value,*,graph,work):
    from .d02_character_labor_read_v1 import require_character_labor_rebuild_options_ready_v1
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3
    require_character_labor_rebuild_options_terminal_v1(value,work)
    r,record = value.reader,_REBUILD_OPTIONS_V1[value]
    if r.graph is not graph or record[-1] or r.db.in_transaction:
        raise ValueError("labor options may be consumed once by their actual terminal invocation")
    work._require_invocation(graph)
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock,runtime_storage_quantum_v3(r.db) as meter:
        require_character_labor_rebuild_options_ready_v1(r,meter=meter)
    _REBUILD_OPTIONS_V1[value] = (*record[:-1],True)
    return dict(value.view)

_REBUILD_BINDING_TASKS_V1 = WeakKeyDictionary()
_REBUILD_BINDING_READS_V1 = WeakKeyDictionary()
_REBUILD_BINDING_READ_KEY_V1 = object()


class PreparedCharacterLaborRebuildBindingV1:
    def __init__(self,key,task):
        if key is not _REBUILD_BINDING_READ_KEY_V1 or not task.complete or task.binding is None:
            raise TypeError("actual complete signed labor rebuild binding metadata required")
        self.binding,self.receipt,self.domain_original = task.binding,task.receipt,task.binding.domain_original
        self.attempt,self.native_result = task.binding.attempt,task.binding.native_result
        _REBUILD_BINDING_READS_V1[self] = task

    def require_current_v1(self,owner,*,meter=None):
        return _require_labor_binding_read_v1(self,owner,meter)


class NoCharacterLaborRebuildBindingV1:
    def __init__(self,key,task):
        if key is not _REBUILD_BINDING_READ_KEY_V1 or not task.complete or task.binding is not None:
            raise TypeError("actual complete labor UUID metadata absence required")
        _REBUILD_BINDING_READS_V1[self] = task

    def require_current_v1(self,owner,*,meter=None):
        return _require_labor_binding_read_v1(self,owner,meter)


def _require_labor_binding_read_v1(value,owner,meter):
    task = _REBUILD_BINDING_READS_V1.get(value)
    if (type(value) not in (PreparedCharacterLaborRebuildBindingV1,NoCharacterLaborRebuildBindingV1)
            or task is None or task.owner is not owner or task.result is not value or not task.complete):
        raise ValueError("labor UUID metadata proof is not its actual Root cold Work")
    task.require_v1(meter)
    if type(value) is PreparedCharacterLaborRebuildBindingV1:
        if (value.binding is not task.binding or value.receipt is not task.receipt
                or value.domain_original is not task.binding.domain_original
                or value.attempt is not task.binding.attempt
                or value.native_result is not task.binding.native_result
                or canonical_digest(character_labor_rebuild_selection_binding_wire_v1(task.binding)) != task.binding_digest):
            raise ValueError("labor binding proof no longer exposes its actual signed metadata originals")
    elif task.binding is not None or task.receipt is not None:
        raise ValueError("labor absence proof cannot disclose a committed binding")
    if meter is not None:
        task.require_headers_v1(meter)
    return value


class _CharacterLaborRebuildBindingReadV1:
    def __init__(self,owner):
        self.owner,self.db,self.namespace,self.operation = owner,owner.db,owner.namespace,owner.operation
        self.issuer,self.selection_digest = owner.issuer,owner.selection_digest
        self.headers,self.columns = [],{}
        self.pending,self.column = None,None
        self.binding=self.receipt=self.result=None
        self.binding_digest=None
        self.uuid_history_task=self.uuid_history_proof=None
        self.complete=False
        self.generator=self._run_v1()
        _REBUILD_BINDING_TASKS_V1[self] = (owner,self.db,self.operation,self.selection_digest)
        self.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        from .current_character_labor_adoption_v1 import _payload_heap_v1
        local=() if self.generator is None or self.generator.gi_frame is None else tuple(
            v for k,v in self.generator.gi_frame.f_locals.items() if k != "self")
        return _payload_heap_v1((self.headers,tuple((c.body,c.fragment,c.value) for c in self.columns.values()),
            self.binding,self.receipt,self.pending,local,
            () if self.uuid_history_task is None else self.uuid_history_task.retained_payload_v1()))+65536

    def require_v1(self,meter=None):
        from .character_labor_rebuild_selector_v1 import require_actual_character_labor_rebuild_cold_owner_v1
        if _REBUILD_BINDING_TASKS_V1.get(self) != (self.owner,self.db,self.operation,self.selection_digest):
            raise ValueError("actual registered labor binding cold metadata task required")
        require_actual_character_labor_rebuild_cold_owner_v1(self.owner,meter=meter)
        if self.owner.db is not self.db or self.owner.operation is not self.operation:
            raise ValueError("labor binding metadata changed its actual selected Root Work")
        return self

    def require_headers_v1(self,meter):
        if self.uuid_history_proof is not None:
            self.uuid_history_proof.require_current_v1(self.owner,
                mutation_operation_id=self.owner.mutation_operation_id,meter=meter)
        for table,columns,where,key,expected in self.headers:
            if meter.read_fixed_row(self.db,table,columns,where,key) != expected:
                raise ValueError("labor UUID original/Domain/attempt metadata changed during cold read")

    def _row_v1(self,table,columns,where,key):
        return ("row",table,columns,where,key)

    def _column_v1(self,table,column,keys,key):
        return ("column",table,column,keys,key)

    def advance_v1(self,meter):
        self.require_v1(meter)
        if self.complete:
            self.require_headers_v1(meter);return True
        try:
            if self.pending is None:
                self.pending=next(self.generator)
            request=self.pending
            if request[0] == "uuid_history":
                from .c09_character_labor_rebuild_identity_v1 import (
                    create_character_labor_rebuild_uuid_history_task_v1,
                    require_character_labor_rebuild_uuid_history_v1)
                if self.uuid_history_task is None:
                    self.uuid_history_task=create_character_labor_rebuild_uuid_history_task_v1(
                        self.owner,mutation_operation_id=self.owner.mutation_operation_id)
                if not self.uuid_history_task.advance_v1(meter):
                    self.operation.refresh_retained_state_v3(self);return False
                self.uuid_history_proof=require_character_labor_rebuild_uuid_history_v1(
                    self.uuid_history_task,self.owner,mutation_operation_id=self.owner.mutation_operation_id,meter=meter)
                value=self.uuid_history_proof.outcome
            elif request[0] in ("row","history_row"):
                _,table,columns,where,key=request
                value=meter.read_fixed_row(self.db,table,columns,where,key)
                if request[0] == "row":
                    self.headers.append((table,columns,where,key,value))
            else:
                from .current_character_labor_adoption_v1 import _LocatorMetadataColumnV1
                _,table,column,keys,key=request
                identity=(table,column,keys,key)
                c=self.columns.get(identity)
                if c is None:
                    c=_LocatorMetadataColumnV1(self,table,column,keys,key)
                    self.columns[identity]=c
                if not c.advance(meter):
                    self.operation.refresh_retained_state_v3(self);return False
                value=c.value
            self.pending=self.generator.send(value)
            self.operation.refresh_retained_state_v3(self)
            return False
        except StopIteration:
            self.generator=None;self.pending=None
            self.require_headers_v1(meter)
            self.complete=True
            self.result=(PreparedCharacterLaborRebuildBindingV1 if self.binding is not None
                else NoCharacterLaborRebuildBindingV1)(_REBUILD_BINDING_READ_KEY_V1,self)
            self.operation.refresh_retained_state_v3(self)
            return True

    def _run_v1(self):
        from .d11_life_preparation_v1 import TABLE
        from .domain_production_originals_v1 import _receipt
        from ..runtime_contracts import canonical_serialize
        from ..authority_service.v2_contract import from_wire
        from ..host.authority_profile import current_owner_metadata_installation_v3
        ns=self.namespace
        op=self.owner.mutation_operation_id
        ref="character-labor-rebuild-selection:"+op
        key=(*ns.as_tuple,REBUILD_SELECTION_BINDING_KIND_V1,ref)
        header=yield self._row_v1(TABLE,("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",key)
        attempt=yield self._row_v1("graph_owner_domain_attempts_v3",("request_digest","attempt_id","graph_revision","graph_epoch"),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        bundle=yield self._row_v1("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        existing_fence = yield self._row_v1("graph_bundle_fences_v2",("digest",),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        existing_event = yield self._row_v1("graph_events",("session",),
            "bot=? AND persona=? AND event_id=? ORDER BY session",(*ns.as_tuple,op))
        existing_intent = yield self._row_v1("graph_bundle_intents_v2",("fence_attempt_id",),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        domains=[]
        for table in ("graph_domain_production_originals_v1","graph_domain_production_originals_v3"):
            exists=yield self._row_v1("sqlite_schema",("name",),"type='table' AND name=?",(table,))
            if exists is None:
                continue
            row=yield self._row_v1(table,("domain","operation_kind","request_digest","original_digest","bundle_digest","receipt_digest"),
                "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
            if row is not None:
                domains.append((table,row))
        if header is None:
            if (attempt is not None or bundle is not None or domains or existing_fence is not None
                    or existing_event is not None or existing_intent is not None):
                raise MissingProductionOriginalV1("labor_UUID_half_binding_attempt_or_committed_receipt")
            outcome = yield ("uuid_history",)
            if outcome != "never_committed":
                raise MissingProductionOriginalV1("actual_rebuild_UUID_retired_not_a_new_submission")
            return
        if header[0] != op or attempt is None or bundle is None or len(domains) != 1:
            raise MissingProductionOriginalV1("complete_original_labor_UUID_binding_Domain_bundle_attempt")
        raw=yield self._column_v1(TABLE,"payload_json",("bot","persona","kind","original_ref"),key)
        binding=character_labor_rebuild_selection_binding_from_wire_v1(raw)
        digest=canonical_digest(character_labor_rebuild_selection_binding_wire_v1(binding))
        if (header[1] != digest or binding.original_ref != ref or binding.namespace != ns
                or binding.command.mutation_operation_id != op
                or binding.command.command_input_digest != self.owner.command_input_digest
                or binding.command != self.owner.command_context
                or (binding.activity_id,binding.audience_ref,binding.parent_budget_lease_ref) != (
                    self.owner.activity_id,self.owner.audience_ref,self.owner.parent_budget_lease_ref)):
            raise ValueError("same labor UUID was previously bound to different actual command content")
        self.issuer._signer.verify(REBUILD_SELECTION_BINDING_SIGN_KIND_V1,
            canonical_serialize((ns,REBUILD_SELECTION_BINDING_KIND_V1,ref,digest)),header[2])
        installed=current_owner_metadata_installation_v3(self.owner.graph)[0].installation_policy
        authority=self.owner.authority
        if ((binding.authority_id,binding.authority_namespace,binding.installation_id,binding.manifest_digest)!=(
                installed.expected_authority_id,installed.authority_namespace,installed.installation_id,installed.manifest_digest)
                or binding.actor != authority.actor or binding.command.purpose != authority.purpose
                or authority.audience != (binding.command.audience,)):
            raise ValueError("labor UUID binding belongs to another actual installed Owner invocation")
        table,domain=domains[0]
        if domain != ("d02","rebuild_character_labor_body",binding.domain_request_digest,
                binding.domain_original.original_digest,binding.operation_digest,binding.receipt_digest):
            raise ValueError("labor UUID binding changed its actual Domain original")
        receipt_raw=yield self._column_v1(table,"receipt_json",("bot","persona","operation_id"),(*ns.as_tuple,op))
        receipt=_receipt(receipt_raw)
        if (canonical_digest(receipt)!=binding.receipt_digest
                or receipt.operation_id!=op or receipt.operation_digest!=binding.operation_digest
                or receipt.commit_seq!=binding.commit_seq
                or bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
                or binding.native_result["receipt"]!=receipt_raw):
            raise ValueError("labor UUID binding lost its actual complete W01 receipt")
        a=binding.attempt
        if attempt!=(a.request_digest,a.attempt_id,binding.before_graph_revision,binding.before_graph_epoch):
            raise ValueError("labor UUID binding changed its original attempt identity")
        permit_raw=yield self._column_v1("graph_owner_domain_attempts_v3","permit_json",
            ("bot","persona","operation_id"),(*ns.as_tuple,op))
        if from_wire(permit_raw)!=a.permit:
            raise ValueError("labor UUID cold lookup cannot replace its actual saved permit")
        anchor_raw = yield self._column_v1("graph_owner_domain_attempts_v3","anchor_json",
            ("bot","persona","operation_id"),(*ns.as_tuple,op))
        from ..authority_service.v2_contract import _anchor_from_wire
        if _anchor_from_wire(anchor_raw) != a.permit.pinned_anchor:
            raise ValueError("labor UUID cold lookup changed its actual saved comparison anchor")
        reply=yield self._column_v1("graph_owner_domain_attempts_v3","receipt_json",
            ("bot","persona","operation_id"),(*ns.as_tuple,op))
        if reply!=binding.native_result:
            raise ValueError("labor UUID binding does not equal its actual saved native Domain result")
        event_key = (*ns.as_tuple,binding.activity_id,op)
        event = yield self._row_v1("graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",event_key)
        fence = yield self._row_v1("graph_bundle_fences_v2",("digest","pre_graph_revision","pre_graph_epoch",
            "post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest"),
            "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
        if (event != (binding.event_digest,binding.post_graph_epoch)
                or fence != (binding.operation_digest,binding.before_graph_revision,binding.before_graph_epoch,
                    binding.post_graph_revision,binding.post_graph_epoch,a.finish_request_id,a.finish_digest)):
            raise ValueError("labor UUID cold metadata changed its actual W01 event/fence")
        fence_permit = yield self._column_v1("graph_bundle_fences_v2","permit_json",
            ("bot","persona","operation_id"),(*ns.as_tuple,op))
        if from_wire(fence_permit) != a.permit:
            raise ValueError("labor UUID true fenced bundle changed its complete original permit")
        vectors = {}
        for column in ("reads","revisions","epoch_reads","invalidated"):
            vectors[column] = yield self._column_v1("graph_events",column,
                ("bot","persona","session","event_id"),event_key)
        if (vectors["reads"] != [[v.key.token,v.revision] for v in receipt.read_versions]
                or vectors["revisions"] != [[v.key.token,v.revision] for v in receipt.write_versions]
                or vectors["epoch_reads"] != [[*ns.as_tuple,binding.before_graph_epoch]]
                or receipt.invalidated_epochs != (NamespaceEpoch(*ns.as_tuple,binding.post_graph_epoch),)):
            raise ValueError("labor UUID full event reads/writes/epochs differ from its signed actual receipt")
        from hashlib import sha256
        vector_wire = canonical_serialize(vectors["invalidated"]).encode("utf-8")
        if (sha256(vector_wire).hexdigest(),len(vector_wire),len(vectors["invalidated"])) != (
                binding.invalidated_vector_sha256,binding.invalidated_vector_bytes,binding.invalidated_vector_count):
            raise ValueError("labor UUID complete invalidation vector differs from its actual writer capture")
        expected_history = {}
        for valid,column in ((1,"revisions"),(0,"invalidated")):
            for token,revision in vectors[column]:
                version = GraphVersion(AtomKey.from_token(token),revision)
                if (NamespaceId.from_key(version.key) != ns or version.revision < 1
                        or (token,revision) in expected_history):
                    raise ValueError("labor UUID event has duplicate or foreign history members")
                expected_history[(token,revision)] = valid
        cursor = ("",0);seen = set()
        while True:
            row = yield ("history_row","graph_history",("token","revision","valid"),
                "event_bot=? AND event_persona=? AND event_session=? AND event_id=? AND (token>? OR (token=? AND revision>?)) ORDER BY token,revision",
                (*event_key,cursor[0],cursor[0],cursor[1]))
            if row is None:
                break
            locator = row[:2]
            if len(seen) >= 1024 or locator in seen or expected_history.get(locator) != row[2]:
                raise ValueError("labor UUID full same-event history is outside its actual signed write/invalidation members")
            seen.add(locator);cursor=locator
        if seen != set(expected_history):
            raise ValueError("labor UUID event is missing actual committed history members")
        self.binding,self.receipt,self.binding_digest=binding,receipt,digest

    def release_v1(self):
        if _REBUILD_BINDING_TASKS_V1.pop(self,None) is None:
            return
        if self.result is not None:
            _REBUILD_BINDING_READS_V1.pop(self.result,None)
        if self.uuid_history_task is not None:
            self.uuid_history_task.release_v1()
        self.uuid_history_task=self.uuid_history_proof=None
        self.headers.clear();self.columns.clear()
        self.generator=self.pending=self.column=self.binding=self.receipt=self.result=None
        self.owner=None
        self.operation.unregister_retained_state_v3(self)


def create_character_labor_rebuild_binding_read_v1(owner):
    from .character_labor_rebuild_selector_v1 import require_actual_character_labor_rebuild_cold_owner_v1
    require_actual_character_labor_rebuild_cold_owner_v1(owner)
    return _CharacterLaborRebuildBindingReadV1(owner)


def require_character_labor_rebuild_binding_read_v1(task,owner,*,meter=None):
    if type(task) is not _CharacterLaborRebuildBindingReadV1 or task.owner is not owner:
        raise TypeError("actual same Root cold metadata binding task required")
    if not task.complete or task.result is None:
        raise MissingProductionOriginalV1("complete_labor_UUID_binding_metadata_EOF")
    return task.result.require_current_v1(owner,meter=meter)

_REBUILD_GRAPH_RECEIPTS_V1 = {}



def capture_character_labor_rebuild_graph_receipt_v1(witness,*,db,graph_receipt,hook_cap):
    from ..runtime_contracts import canonical_serialize
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    from hashlib import sha256
    if type(hook_cap) is not _CharacterLaborRebuildStoreReceiptV1:
        raise TypeError("actual temporary rebuild Store receipt metadata capability required")
    cap = hook_cap.require_v1(witness,db=db,receipt=graph_receipt)
    if id(witness) in _REBUILD_GRAPH_RECEIPTS_V1:
        raise ValueError("labor rebuild receipt was already captured in this actual W01")
    estimate = 4096+sum(len(v.key.token.encode("utf-8"))*8+512 for v in graph_receipt.invalidated)
    cap.operation.retain(estimate)
    with runtime_storage_quantum_v3(db) as meter:
        actual_header = meter.read_fixed_row(db,"graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",
            (*witness.scope.namespace.as_tuple,cap.candidate.event.scope.session,cap.candidate.event.event_id))
        if actual_header != cap.header:
            raise ValueError("labor Store event changed inside its actual callback")
        vector = [[v.key.token,v.revision] for v in graph_receipt.invalidated]
        wire = canonical_serialize(vector).encode("utf-8")
    _REBUILD_GRAPH_RECEIPTS_V1[id(witness)] = (witness,cap.header[0],
        cap.before_stamp[0].graph_revision,cap.before_stamp[1].revision,
        graph_receipt.epoch.revision,sha256(wire).hexdigest(),len(wire),len(vector))
    cap.used = True



def release_character_labor_rebuild_graph_receipt_v1(witness):
    value = _REBUILD_GRAPH_RECEIPTS_V1.get(id(witness))
    if value is not None and value[0] is witness:
        _REBUILD_GRAPH_RECEIPTS_V1.pop(id(witness))

_REBUILD_STORE_RECEIPT_KEY_V1 = object()
_REBUILD_STORE_RECEIPT_CAPS_V1 = WeakKeyDictionary()
_REBUILD_STORE_RECEIPT_CURRENT_V1 = ContextVar("character_labor_rebuild_store_receipt_v1",default=None)


class _CharacterLaborRebuildStoreReceiptV1:
    def __init__(self,key,*,witness,db,bundle,candidate,receipt,before_stamp,graph_capability,operation,header):
        if key is not _REBUILD_STORE_RECEIPT_KEY_V1:
            raise TypeError("actual same-transaction Store receipt callback required")
        from threading import get_ident
        self.witness,self.db,self.bundle,self.candidate = witness,db,bundle,candidate
        self.receipt,self.before_stamp,self.graph_capability = receipt,before_stamp,graph_capability
        self.operation,self.header,self.thread,self.used = operation,header,get_ident(),False
        _REBUILD_STORE_RECEIPT_CAPS_V1[self] = (witness,db,bundle,candidate,receipt,before_stamp,
            graph_capability,operation,header,self.thread)

    def require_v1(self,witness,*,db,receipt):
        from threading import get_ident
        from .domain_production_commit_v1 import _ACTIVE
        from .character_labor_rebuild_selector_v1 import require_character_labor_rebuild_store_receipt_operation_v1
        record = _REBUILD_STORE_RECEIPT_CAPS_V1.get(self)
        if (record is None or _REBUILD_STORE_RECEIPT_CURRENT_V1.get() is not self
                or self.used or record[0] is not witness or self.witness is not witness
                or record[1] is not db or self.db is not db or record[2] is not self.bundle
                or record[3] is not self.candidate or record[4] is not receipt or self.receipt is not receipt
                or record[5] != self.before_stamp or record[6] is not self.graph_capability
                or record[7] is not self.operation or record[8] != self.header
                or record[9] != self.thread or self.thread != get_ident()
                or _ACTIVE.get(id(witness)) is not witness or witness.bundle is not self.bundle
                or witness.graph._GraphCoordinator__store._db is not db or not db.in_transaction
                or not witness.graph._GraphCoordinator__store._lock._is_owned()
                or require_character_labor_rebuild_store_receipt_operation_v1(witness) is not self.operation):
            raise ValueError("labor Store receipt metadata capability ended or changed its actual writer")
        witness.graph._GraphCoordinator__store._require_recovery_capability(self.graph_capability)
        return self


def bind_character_labor_rebuild_store_receipt_v1(witness,*,db,graph_receipt,bundle,candidate,
        before_stamp,graph_capability):
    from contextlib import contextmanager
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from .character_labor_rebuild_selector_v1 import require_character_labor_rebuild_store_receipt_operation_v1
    from ..graph_store import GraphRecoveryMetadataV2
    from ..graph_types import GraphCandidate,GraphReceipt
    from ..runtime_storage_v3 import runtime_storage_quantum_v3

    @contextmanager
    def bind():
        if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
                or witness.operation.operation_kind != "rebuild_character_labor_body"
                or type(witness.stage) is not CharacterLaborTerminalBodyV1 or witness.bundle is not bundle
                or witness.frame.envelope is not bundle.envelope
                or type(candidate) is not GraphCandidate or type(graph_receipt) is not GraphReceipt
                or graph_receipt.status != "committed" or _REBUILD_STORE_RECEIPT_CURRENT_V1.get() is not None
                or type(before_stamp) is not tuple or len(before_stamp) != 2
                or type(before_stamp[0]) is not GraphRecoveryMetadataV2 or type(before_stamp[1]) is not NamespaceEpoch):
            raise ValueError("actual single rebuild Store callback/bundle/before stamp required")
        graph,scope = witness.graph,witness.scope
        store = graph._GraphCoordinator__store
        store._require_recovery_capability(graph_capability)
        if (graph_capability is not graph._GraphCoordinator__graph_capability or db is not store._db
                or not db.in_transaction or not store._lock._is_owned()
                or witness.runtime is not graph._GraphCoordinator__domain_production_runtime_v1
                or before_stamp[0].graph_revision != scope.graph_revision or before_stamp[1] != scope.graph_epoch
                or before_stamp[0].requirements.namespace != scope.namespace
                or candidate.event.scope.bot != scope.namespace.bot_id
                or candidate.event.scope.persona != scope.namespace.persona_id
                or candidate.event.scope.session != bundle.envelope.identity.activity_id
                or candidate.event.event_id != bundle.envelope.identity.operation_id
                or bundle.envelope.authority.namespace != scope.namespace
                or graph_receipt.epoch != NamespaceEpoch(*scope.namespace.as_tuple,scope.graph_epoch.revision+1)
                or tuple(v.key for v in graph_receipt.revisions) != tuple(w.key for w in candidate.writes)):
            raise ValueError("labor Store callback left its actual graph/permit/candidate/event identity")
        operation = require_character_labor_rebuild_store_receipt_operation_v1(witness)
        with runtime_storage_quantum_v3(db) as meter:
            header = meter.read_fixed_row(db,"graph_events",("digest","epoch_revision"),
                "bot=? AND persona=? AND session=? AND event_id=?",
                (*scope.namespace.as_tuple,candidate.event.scope.session,candidate.event.event_id))
        if header is None or header[1] != graph_receipt.epoch.revision:
            raise ValueError("labor Store callback has no actual persisted event header")
        cap = _CharacterLaborRebuildStoreReceiptV1(_REBUILD_STORE_RECEIPT_KEY_V1,witness=witness,db=db,
            bundle=bundle,candidate=candidate,receipt=graph_receipt,before_stamp=before_stamp,
            graph_capability=graph_capability,operation=operation,header=header)
        token = _REBUILD_STORE_RECEIPT_CURRENT_V1.set(cap)
        try:
            yield cap
        finally:
            _REBUILD_STORE_RECEIPT_CURRENT_V1.reset(token)
            _REBUILD_STORE_RECEIPT_CAPS_V1.pop(cap,None)
    return bind()
