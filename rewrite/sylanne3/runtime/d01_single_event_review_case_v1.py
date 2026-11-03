"""Real finite review material from Source-qualified D08/D10 outcomes.

Pre-Source planning retains fixed metadata only. Case creation and target use
independently recheck the exact current policy, Source closure and originals.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from ..domains.d01 import PersonaDomain
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d01.single_event_review_case_v1 import (CASE_KIND, CASE_SCHEMA,
    RegisteredSingleEventReviewCaseV1, SingleEventReviewCounterBindingV1,
    SingleEventPostAdoptionScopeBindingV1)
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import access_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import ProductionOriginalRefV1, actual_frame_read_versions_v1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1


def _metadata_candidates(db, namespace, terms):
    from .d01_single_event_growth_v1 import _single_type_metadata_v1
    wanted={'d08.action_outcome.v1','d10.life_progress.v1','d08.action_intent.v1',
        'd08.goal.v1','d08.personal_plan.v1'}
    rows={}
    for kind in sorted(wanted):
        values,complete=_single_type_metadata_v1(db,namespace,kind)
        if not complete or len(values)>128:
            raise MissingProductionOriginalV1('complete_single_event_post_adoption_'+kind)
        rows[kind]=tuple(value for value in values if value.valid)
    excluded={v.key for v in terms.exclusion_versions}
    candidates=[]
    for outcome in rows['d08.action_outcome.v1']:
        raw=outcome.value
        matches=tuple(a for a in rows['d08.action_intent.v1'] if
            (a.value['action_id'],a.value['identity']['effect_id'],a.value['identity']['attempt_id'])==
            (raw['action_id'],raw['effect_id'],raw['attempt_id']))
        if len(matches)!=1:continue
        action=matches[0]
        goals=tuple(g for g in rows['d08.goal.v1'] if g.key.name==action.value['goal_ref'])
        if len(goals)!=1:continue
        plans=tuple(p for p in rows['d08.personal_plan.v1'] if p.value['goal_ref']==goals[0].key.token)
        lineage=(action,goals[0],*plans)
        if excluded.intersection(a.key for a in lineage):continue
        scoped=tuple(v for v in terms.scope_versions if any(
            a.key==v.key and a.revision==v.revision for a in lineage))
        if not scoped:continue
        if raw['result_level']!='completed_verified':continue
        candidates.append((outcome,action,scoped[0],lineage))
    for outcome in rows['d10.life_progress.v1']:
        raw=outcome.value
        project=AtomKey.from_token(raw['project_ref'])
        if project in excluded or raw['reality']!='real_execution':continue
        scoped=tuple(v for v in terms.scope_versions if v.key==project)
        if scoped:candidates.append((outcome,None,scoped[0],()))
    return tuple(candidates)


def append_single_event_review_case_plan_v1(db,namespace,terms,keys,roots,originals):
    """Fixed metadata locates candidates; no result or claim Body is opened."""
    for outcome,action,scope,lineage in _metadata_candidates(db,namespace,terms):
        keys.append(outcome.key);originals.append(outcome.key.token)
        raw=outcome.value
        if action is not None:
            keys.extend(row.key for row in lineage)
            roots.extend(action.value['source_refs'])
            originals.extend(raw['observation_refs'])
            for row in lineage:
                if row.key.type_name=='d08.personal_plan.v1':roots.extend(row.value['source_refs'])
        else:
            from .d10_life_progress_provenance_v1 import life_progress_current_read_inputs_v1
            extra,source_roots,original_refs=life_progress_current_read_inputs_v1(db,namespace,outcome.key.token)
            keys.extend(extra);roots.extend(source_roots);originals.extend(original_refs)
            roots.extend(raw['source_refs']);originals.extend(raw['receipt_refs'])
            if raw['artifact_ref'] is not None:originals.append(raw['artifact_ref'])
            originals.append(raw['terminal_ref'])


def _producer(db,read,atom):
    from ..runtime_storage_v3 import read_graph_row_v3
    from .domain_background_read_v3 import background_json_loads_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    history=read_graph_row_v3(db,('event_id','value','valid'),where='token=? AND revision=?',
        parameters=(atom.key.token,atom.revision),history=True)
    if history is None or history[2]!=1 or background_json_loads_v3(history[1])!=atom.value:
        raise MissingProductionOriginalV1('actual_post_adoption_review_outcome_history')
    produced=read_adopted_domain_operation_v1(db,read.frame.envelope.authority.namespace,history[0])
    expected=('d08','settle_observed_action') if atom.key.type_name=='d08.action_outcome.v1' else ('d10','advance_life')
    if (produced is None or (produced['domain'],produced['operation_kind'])!=expected
            or GraphVersion(atom.key,atom.revision) not in produced['receipt'].write_versions):
        raise MissingProductionOriginalV1('actual_post_adoption_review_outcome_producer')
    read.committed_operation(db,history[0])
    original=ProductionOriginalRefV1(produced['domain']+'.current-'+produced['operation_kind'],
        produced['domain']+'-current:'+produced['original_digest'][:48],produced['original_digest'],
        ())
    return produced,original


def _counter_binding(db,read,policy):
    from .d01_single_event_growth_v1 import _single_type_metadata_v1
    rows,complete=_single_type_metadata_v1(db,policy.terms.namespace,'d07.current_interpretation.v1')
    pages=tuple(p for p in read.frame.query_coverage if p.type_id=='d07.current_interpretation.v1')
    versions=tuple(GraphVersion(a.key,a.revision)for a in rows)
    if (not complete or len(rows)>128 or len(pages)!=1 or not pages[0].complete
            or pages[0].row_versions!=versions):
        raise MissingProductionOriginalV1('complete_current_single_event_review_counter_domain')
    question='d01.growth:'+policy.terms.target_block+':core'
    members=[];qualification='qualified';roots=[]
    from ..domains.d07 import D07DomainProvider
    validator=next(v.validator for v in D07DomainProvider.type_specs() if v.name=='d07.current_interpretation.v1')
    for metadata in rows:
        if not metadata.valid or metadata.value['question_key']!=question or metadata.value['current']is not True:continue
        atom=read.head(db,metadata.key,required=True);validator(atom.value)
        if any(atom.value[k]!=v for k,v in metadata.value.items()):
            raise ValueError('review counter Body changed from actual metadata EOF')
        refs=tuple(atom.value['source_refs'])
        if refs:read.source_family(db,refs,purpose='consolidation')
        from ..runtime_storage_v3 import read_graph_row_v3
        from .domain_background_read_v3 import background_json_loads_v3
        history=read_graph_row_v3(db,('event_id','value','valid'),where='token=? AND revision=?',
            parameters=(atom.key.token,atom.revision),history=True)
        if history is None or history[2]!=1 or background_json_loads_v3(history[1])!=atom.value:
            raise MissingProductionOriginalV1('actual_review_counter_adoption_history')
        read.committed_operation(db,history[0]);read.original(atom.key.token)
        if atom.value['stance']=='oppose' and atom.value['evidence_status']=='supported':qualification='opposition'
        elif qualification!='opposition' and (not refs or atom.value['stance']!='support'
                or atom.value['evidence_status']!='supported' or atom.value['meaningful_unknowns']):qualification='unknown'
        members.append((GraphVersion(atom.key,atom.revision),canonical_digest(atom.value)));roots.extend(refs)
    if not members and policy.terms.target_kind!='semantic_identity':qualification='unknown'
    return SingleEventReviewCounterBindingV1(question,pages[0].epoch,versions,tuple(members),qualification),tuple(dict.fromkeys(roots))


def _clock_original(db,readers,read,now):
    from .d01_general_growth_v1 import _current_general_clock_v1
    from .d11_role_clock_installation_v1 import TABLE,SIGN_KIND,_mapping_original
    from .d04_semantic_installation_original_v3 import _read_signed
    mapping,digest,_=_current_general_clock_v1(db,readers,read)
    saved=_read_signed(db,readers.issuer,TABLE,SIGN_KIND,read.frame.envelope.authority.namespace,
        reader=readers.role_clock_reader)
    if saved is None:raise MissingProductionOriginalV1('actual_single_event_review_clock_original')
    body,actual_digest=saved
    verified=_mapping_original(db,read.frame.envelope.authority.namespace,saved)
    if (actual_digest!=digest or verified!=mapping or body['revision']!=mapping.version
            or body['mapping']['mapping_id']!=mapping.mapping_id):
        raise ValueError('review clock original differs from its actual signed runtime operation')
    mapping.character_at(datetime.fromtimestamp(now,timezone.utc).isoformat().replace('+00:00','Z'))
    return ProductionOriginalRefV1('d11.owner_role_clock_installation.v1',body['operation_id'],digest),mapping


def prepare_registered_single_event_review_case_v1(db,*,read,readers,adoption,adoption_original,policy,value,
        review_atom,review,persona_writer_qualification=None):
    from .d01_single_event_growth_v1 import (actual_current_single_event_upper_utc_v1,
        _issue_single_event_fact_read_v1,_requalify_trials,single_event_trial_costs_v1)
    if (review_atom.revision!=1 or review.disposition!='pending'
            or review_atom.key.type_name!='d01.single_event_growth_review.v2'):
        raise MissingProductionOriginalV1('actual_first_pending_single_event_review_v2')
    now=actual_current_single_event_upper_utc_v1(db,read.frame)
    if not adoption.review_not_before_utc<=now<min(adoption.review_due_utc,adoption.readout_valid_until_utc):
        raise MissingProductionOriginalV1('single_event_original_review_window')
    _requalify_trials(db,read,readers,policy,value,adoption.adopted_at_utc)
    proof=_issue_single_event_fact_read_v1(db,read,readers,policy,value)
    counter,counter_roots=_counter_binding(db,read,policy)
    if counter.qualification=='opposition':raise MissingProductionOriginalV1('single_event_actual_opposition_requires_direct_review')
    recorded=adoption_original['payload']['now_utc'];lower=max(recorded,adoption.adopted_at_utc)
    evidence=[];versions=[];bodies=[];bindings=[];causes=[];context=list(counter_roots)
    from ..domains.d08.execution import _decode
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    for metadata,planned_metadata,scope,lineage in _metadata_candidates(db,adoption.namespace,policy.terms):
        atom=read.head(db,metadata.key,required=True)
        if atom.revision!=metadata.revision:raise MissingProductionOriginalV1('current_post_adoption_review_outcome_changed')
        for row in lineage:
            actual=read.head(db,row.key,required=True)
            if actual.revision!=row.revision:raise MissingProductionOriginalV1('current_post_adoption_review_scope_link')
        if planned_metadata is not None:
            outcome=_decode('d08.action_outcome.v1',atom.value)
            if not lower<outcome.observed_at<=now:continue
            if (outcome.result_level!='completed_verified' or outcome.unknown_effects
                    or outcome.effect_id not in outcome.completed_effects or not outcome.observation_refs):continue
            planned=read.head(db,planned_metadata.key,required=True)
            action=_decode('d08.action_intent.v1',planned.value)
            if (action.action_id,action.identity.effect_id,action.identity.attempt_id)!=(outcome.action_id,outcome.effect_id,outcome.attempt_id):
                raise ValueError('review result changed its actual Action/effect/attempt')
            observers=tuple(read.original(ref)for ref in outcome.observation_refs)
            if any(o.kind not in {'d11.outbound_observation','d11.role_segment_end','d11.actual_artifact'}for o in observers):
                raise MissingProductionOriginalV1('actual_post_adoption_review_independent_observer')
            costs=single_event_trial_costs_v1(db,read,action,outcome,proof)
            if not costs:raise MissingProductionOriginalV1('actual_post_adoption_review_known_cost')
            for cost in costs:read.settled_cost_original(db,cost.key.token,activity_id=action.identity.activity_id,effect_id=outcome.effect_id)
            roots=tuple(action.source_refs);occurred=outcome.observed_at
            planned_version=GraphVersion(planned.key,planned.revision)
        else:
            progress=decode_typed_production_value_v1(atom.value,LifeProgressHeadV1)
            from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
            prepared,terminal,production=require_current_life_progress_v1(db,namespace=adoption.namespace,
                progress=progress,issuer=readers.issuer,read=read)
            occurred=datetime.fromisoformat(terminal.payload.completed_at_utc.replace('Z','+00:00')).timestamp()
            if not lower<occurred<=now:continue
            if progress.reality!='real_execution' or progress.actuality!='completed' or terminal.status!='completed':continue
            project=prepared.plan.project
            planned_version=GraphVersion(AtomKey.from_token(project.ref),project.revision)
            if planned_version!=scope or canonical_digest(read.head(db,scope.key,required=True).value)!=project.digest:
                raise MissingProductionOriginalV1('actual_post_adoption_review_scope_link')
            observers=(read.original(terminal.original_ref),read.original(terminal.binding.artifact_ref))
            roots=tuple(progress.source_refs)
        read.source_family(db,roots,purpose='consolidation')
        produced,producer_original=_producer(db,read,atom)
        version=GraphVersion(atom.key,atom.revision)
        actual_evidence=read.original(atom.key.token)
        evidence.append(ProductionOriginalRefV1(actual_evidence.kind,actual_evidence.original_ref,actual_evidence.original_digest));versions.append(version)
        causes.append((producer_original,produced['receipt'].operation_id,canonical_digest(produced['receipt'])))
        bodies.append((version,canonical_serialize(atom.value)))
        bindings.append(SingleEventPostAdoptionScopeBindingV1('typed_outcome',None,version,
            planned_version,scope,producer_original,tuple(ProductionOriginalRefV1(o.kind,o.original_ref,o.original_digest)for o in observers),occurred))
        context.extend(roots)
    if not evidence:raise MissingProductionOriginalV1('actual_post_adoption_review_evidence')
    context=tuple(dict.fromkeys((*policy.source_refs,*value.source_refs,*adoption.source_refs,*context)))
    if len(context)>16:raise MissingProductionOriginalV1('single_event_review_generic_source_bound')
    records=read.source_family(db,context,purpose='consolidation')
    from ..domains.d06 import source_correction_head_key
    source_versions=[]
    for ref in sorted(records):
        key=AtomKey.from_token(ref)
        for selected in (key,access_key(*adoption.namespace.as_tuple,key.owner.subject),source_correction_head_key(adoption.namespace,key.owner.subject)):
            actual=read.head(db,selected)
            source_versions.append(GraphVersion(selected,actual.revision))
    owner=_actual_case_owner_v1(db,adoption.namespace)
    from ..domains.d01 import _activation_key
    from ..graph_types import GraphSnapshot,owner_grant_key
    from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
    controls=tuple(read.head(db,k,required=True)for k in(_activation_key(adoption.namespace),owner_grant_key(*adoption.namespace.as_tuple)))
    epoch=next(e for e in read.frame.snapshot.epochs if(e.bot,e.persona)==adoption.namespace.as_tuple)
    control=PersonaDomain.resolve_active_role_control_v3(GraphSnapshot(controls,(epoch,)),
        namespace=adoption.namespace,current_guard=readers.owner_guard)
    plan_version,valid=growth_metadata_head_v1(db,adoption.namespace,control.plan_key)
    if not valid:raise MissingProductionOriginalV1('actual_current_full_persona_writer_plan_header')
    from .domain_background_read_v3 import BackgroundReadWorkV3
    if type(owner) is BackgroundReadWorkV3:
        from .single_event_review_target_v1 import prepare_current_single_event_review_target_v1
        selected=prepare_current_single_event_review_target_v1(owner)
        selected.require_current_v1(owner)
        if (selected.adoption_version!=GraphVersion(AtomKey.from_token(review.adoption_ref),read.head(db,review.adoption_ref,required=True).revision)
                or selected.control.head_id!=control.head_id or selected.head.plan_ref!=plan_version
                or not set(selected.read_versions)<=set(actual_frame_read_versions_v1(read.frame))):
            raise MissingProductionOriginalV1('single_event_review_selected_target_complete_current_CAS')
        target=selected.block
    else:
        from .current_full_persona_writer_v1 import require_current_full_persona_writer_v1,current_full_persona_writer_v1
        if persona_writer_qualification is None:persona_writer_qualification=current_full_persona_writer_v1(owner)
        plan=require_current_full_persona_writer_v1(persona_writer_qualification,owner,read.frame,plan_version,
            'review_single_event_growth_v1',owner.request)
        target=next(b for b in plan.blocks if b.block_id==adoption.target_block)
    if canonical_digest(target.claim)!=adoption.adopted_claim_digest:raise MissingProductionOriginalV1('single_event_actual_review_claim_changed')
    from .budget import get_budget_lease,require_budget_family_admissible
    parent=adoption_original['payload']['parent_budget']
    if read.frame.envelope.parent_budget_lease_ref!=parent:
        raise ValueError('review case cannot borrow another actual causal parent budget')
    lease=get_budget_lease(db,parent);require_budget_family_admissible(db,parent)
    grant=readers.issuer.current_budget_grant(db,parent)
    if lease.state!='active' or (lease.bot_id,lease.persona_id)!=adoption.namespace.as_tuple:
        raise MissingProductionOriginalV1('single_event_actual_review_original_budget')
    from .d01_general_growth_v1 import _general_current_budget_ancestors_v1
    family=_general_current_budget_ancestors_v1(db,readers.issuer,adoption.namespace,parent)
    deadline=min(adoption.review_due_utc,grant.valid_until_utc,read.frame.envelope.deadline_utc,
        *(bound for _,_,_,bound in family))
    clock,mapping=_clock_original(db,readers,read,now)
    policy_original=ProductionOriginalRefV1('d01.single_event_growth_policy_v1',adoption.policy_ref,adoption.policy_digest)
    input_original=ProductionOriginalRefV1('d01.single_event_growth_input_v1',adoption.input_ref,adoption.input_digest)
    cause=ProductionOriginalRefV1('d01.current-adopt_single_event_growth_v1',
        'd01-current:'+adoption_original['original_digest'][:48],adoption_original['original_digest'])
    actual_adoption=read.head(db,review.adoption_ref,required=True)
    actual_trials=tuple(readers._read(db,read,ref,'growth_trial' if policy.terms.target_kind=='semantic_identity' else 'general_growth_trial_v1')[1]
        for ref in value.trial_original_refs)
    trials=tuple(ProductionOriginalRefV1(o.kind,o.original_ref,o.original_digest)for o in actual_trials)
    result=RegisteredSingleEventReviewCaseV1(adoption.namespace,1,policy_original,input_original,
        GraphVersion(actual_adoption.key,actual_adoption.revision),canonical_digest(actual_adoption.value),cause,
        canonical_digest(adoption_original['receipt']),recorded,GraphVersion(review_atom.key,review_atom.revision),
        canonical_digest(review_atom.value),plan_version,control.head_id,
        adoption.target_block,target.claim,adoption.adopted_claim_digest,policy.terms.scope_versions,
        policy.terms.exclusion_versions,adoption.review_not_before_utc,adoption.review_due_utc,
        adoption.readout_valid_until_utc,tuple(evidence),tuple(versions),tuple(bodies),tuple(bindings),(),context,
        tuple(source_versions),counter,trials,clock,mapping.mapping_id,mapping.version,now,
        read.frame.envelope.identity.operation_id,causes[0][0],
        causes[0][1],causes[0][2],parent,
        canonical_digest(grant),deadline)
    return result


from weakref import WeakKeyDictionary

_CASE_REGISTRATION_PLANS_V1=WeakKeyDictionary()


def prepare_current_single_event_case_registration_v1(owner,frame,*,adoption,adoption_original,policy,value,review_atom,review,readers):
    """Freeze a new or already registered Case on the actual Source READ."""
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .persona_growth_review_frame_v1 import _FRAMES_V1
    _require_case_reader_v1(owner,owner.db,owner.namespace)
    bound=_FRAMES_V1.get(id(frame))
    if (type(frame)is not CurrentOperationFrameV1 or bound is None or bound[0]is not frame or bound[1]is not owner
            or frame.envelope.authority.namespace!=owner.namespace
            or frame.envelope.identity.phase!='review_single_event_growth_v1'):
        raise ValueError('Case registration preparation needs its official same-Work Source READ frame')
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    from .domain_background_read_v3 import BackgroundReadWorkV3
    if (type(owner)is _MethodLearningReadV3 and (owner.read_finished or owner.inputs_sealed)
            or type(owner)is BackgroundReadWorkV3 and owner.sealed):
        raise ValueError('Case registration cannot first prepare its original in WRITE')
    if type(owner)is _MethodLearningReadV3:
        if frame.envelope.identity.operation_id!=owner.operation_id or frame.owner_guard!=owner.material_owner_guard:
            raise ValueError('Case READ frame changed its actual Method command/Owner')
        request_identity=owner.request
    else:
        from .domain_background_read_v3 import require_background_followup_handoff_v3
        handoff=require_background_followup_handoff_v3(owner.handoff,owner.graph,owner.bundle)
        request_identity=handoff
        if (frame.envelope.identity.operation_id not in owner.selected_envelopes
                or frame.envelope.identity.request_digest!=canonical_digest(handoff.command.request)):
            raise ValueError('Case READ frame was not selected by its actual Background review child')
    read=CurrentDomainReadV1(frame);read.check(owner.db)
    try:
        candidate=prepare_registered_single_event_review_case_v1(owner.db,read=read,readers=readers,
            adoption=adoption,adoption_original=adoption_original,policy=policy,value=value,review_atom=review_atom,review=review)
    except MissingProductionOriginalV1 as missing:
        _CASE_REGISTRATION_PLANS_V1[owner]=(None,missing,_fresh_case_binding_v1(owner),request_identity,
            tuple(frame.envelope.version_guard.read_versions),None)
        return None,None
    from .d01_production_operations_v1 import TABLE
    if type(owner)is _MethodLearningReadV3:
        from .current_method_learning_read_v3 import read_bound_current_general_owner_signed_metadata_v1
        existing=read_bound_current_general_owner_signed_metadata_v1(owner.db,namespace=owner.namespace,
            issuer=readers.issuer,table=TABLE,original_ref=candidate.case_ref,kind=CASE_KIND)
    else:
        from .domain_background_read_v3 import read_bound_background_general_growth_input_metadata_v1
        handled,existing=read_bound_background_general_growth_input_metadata_v1(owner.db,namespace=owner.namespace,
            table=TABLE,original_ref=candidate.case_ref,kind=CASE_KIND)
        if not handled:raise ValueError('Case occupancy metadata has no actual Background owner')
    reused=None;case=candidate
    if existing is not None:
        _,reused=existing
        read_registered_single_event_review_case_metadata_v1(owner.db,namespace=owner.namespace,case_original=reused,issuer=readers.issuer)
        case=prepare_current_single_event_review_case_body_v1(owner,reused)
        if case.case_ref!=candidate.case_ref:
            raise ValueError('occupied Case original changed its actual semantic basis')
        _case_registered_receipt_v1(owner.db,owner,case)
        if _case_upper_v1(owner)>=min(case.original_deadline_utc,case.review_due_utc):
            raise MissingProductionOriginalV1('single_event_existing_case_original_deadline')
    selected=None
    if reused is None:
        from .d07_single_event_review_v1 import prepare_current_single_event_review_cause_history_v1
        history=prepare_current_single_event_review_cause_history_v1(owner)
        novel=history.novel_bindings_v1(owner,adoption_version=candidate.adoption_version,
            review_key=candidate.review_version.key,scope_bindings=candidate.post_adoption_scope_bindings,
            evidence_versions=candidate.post_adoption_evidence_versions,
            evidence_originals=candidate.post_adoption_evidence_originals)
        if not novel:
            missing=MissingProductionOriginalV1('single_event_review_no_new_independent_experience')
            _CASE_REGISTRATION_PLANS_V1[owner]=(None,missing,_fresh_case_binding_v1(owner),request_identity,
                tuple(frame.envelope.version_guard.read_versions),None)
            return None,None
        selected=novel[0]
        outcome=read.head(owner.db,selected.outcome_version.key,required=True)
        if GraphVersion(outcome.key,outcome.revision)!=selected.outcome_version:
            raise ValueError('new review experience changed its exact actual outcome version')
        produced,producer=_producer(owner.db,read,outcome)
        if producer!=selected.producer_original:
            raise ValueError('new review experience changed its actual independent outcome producer')
        case=replace(candidate,causal_original=producer,causal_operation_id=produced['receipt'].operation_id,
            causal_receipt_digest=canonical_digest(produced['receipt']))
    _CASE_REGISTRATION_PLANS_V1[owner]=(case,reused,_fresh_case_binding_v1(owner),request_identity,
        tuple(frame.envelope.version_guard.read_versions),candidate.case_ref,selected)
    return case,reused


def require_current_single_event_case_registration_v1(owner,frame):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    _require_case_reader_v1(owner,owner.db,owner.namespace)
    saved=_CASE_REGISTRATION_PLANS_V1.get(owner)
    request=owner.request if type(owner)is _MethodLearningReadV3 else owner.handoff
    if (saved is None or saved[2]!=_fresh_case_binding_v1(owner) or saved[3]is not request
            or saved[4]!=tuple(frame.envelope.version_guard.read_versions)
            or saved[0]is not None and saved[0].case_ref!=saved[5]):
        raise ValueError('Case registration WRITE has no exact prepared same-Work READ plan')
    case,original=saved[:2]
    if case is None:raise MissingProductionOriginalV1(*original.missing_inputs,continuation=original.continuation_ref)
    if not case.review_not_before_utc<=_case_upper_v1(owner)<min(case.review_due_utc,case.original_deadline_utc):
        raise MissingProductionOriginalV1('single_event_case_prepared_original_window')
    if original is not None:require_prepared_single_event_review_case_body_v1(owner,original)
    else:
        from .d07_single_event_review_v1 import prepare_current_single_event_review_cause_history_v1
        history=prepare_current_single_event_review_cause_history_v1(owner)
        selected=saved[6]
        if (selected not in history.novel_bindings_v1(owner,adoption_version=case.adoption_version,
                review_key=case.review_version.key,scope_bindings=case.post_adoption_scope_bindings,
                evidence_versions=case.post_adoption_evidence_versions,
                evidence_originals=case.post_adoption_evidence_originals)
                or case.causal_original!=selected.producer_original):
            raise MissingProductionOriginalV1('single_event_review_prepared_new_experience_changed')
    return case,original


def require_reused_single_event_case_after_cas_v1(db,case,*,frame,receipt):
    from .domain_production_commit_v1 import _ACTIVE,_members
    from .persona_growth_review_frame_v1 import _FRAMES_V1
    from ..runtime_storage_v3 import runtime_storage_v3
    registered=_FRAMES_V1.get(id(frame))
    if registered is None or registered[0]is not frame:raise ValueError('Case reuse has no actual W01 Source frame')
    owner=registered[1];saved=_CASE_REGISTRATION_PLANS_V1.get(owner)
    actual=tuple(w for w in _ACTIVE.values()if w.graph is owner.graph and w.frame is frame
        and _members(w.stage)[0].operation_id==receipt.operation_id and w.scope.operation=='write')
    if (owner.db is not db or saved is None or saved[0]!=case or saved[1]is None or len(actual)!=1
            or saved[2]!=_fresh_case_binding_v1(owner) or saved[4]!=receipt.read_versions
            or saved[1].original_digest!=canonical_digest(plain_v1(case))
            or receipt.write_versions or case.registration_operation_id==receipt.operation_id
            or owner.operation.closed or owner.work.state is not owner or owner.work.operation is not owner.operation
            or not db.in_transaction or not owner.store._lock._is_owned()
            or runtime_storage_v3(db)is not owner.operation.handle):
        raise ValueError('Case reuse needs its actual retained READ plan and one active no-write W01 receipt')
    after=owner.graph._v2_graph_stamp(owner.namespace);before=saved[2][6]
    if (after[0].graph_revision!=before[0].graph_revision+1 or after[1].revision!=before[1].revision+1
            or receipt.invalidated_epochs!=(after[1],)):
        raise ValueError('Case reuse has no exact same-CAS metadata successor')
    return saved[1]


_CASE_METADATA=WeakKeyDictionary()
_CASE_BODIES=WeakKeyDictionary()


def _require_case_reader_v1(owner,db,namespace):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,require_actual_method_learning_attachment_owner_v3
    from .domain_background_read_v3 import BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    from .d01_single_event_growth_v1 import OPERATIONS,single_event_metadata_work_v1
    if type(owner) is _MethodLearningReadV3:
        require_actual_method_learning_attachment_owner_v3(owner,db=db)
    elif type(owner) is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(owner,db=db)
        if not single_event_metadata_work_v1(owner):
            from .d07_single_event_review_v1 import require_actual_single_event_review_attention_case_metadata_owner_v1
            require_actual_single_event_review_attention_case_metadata_owner_v1(owner,db=db)
    else:raise TypeError('case metadata requires its exact registered Method or R03 Background owner')
    if owner.namespace!=namespace:raise ValueError('case metadata crossed the actual selected namespace')
    if type(owner) is _MethodLearningReadV3 and owner.operation_kind not in OPERATIONS:
        from .d07_single_event_review_v1 import require_actual_single_event_review_case_metadata_work_v1
        require_actual_single_event_review_case_metadata_work_v1(owner)
    return owner


def _actual_case_owner_v1(db,namespace):
    from .current_method_learning_read_v3 import _method_active
    from .domain_background_read_v3 import _active_v3
    method,background=_method_active(db),_active_v3(db)
    if method is not None and background is not None:raise ValueError('case cannot borrow another active metadata owner')
    return _require_case_reader_v1(method if method is not None else background,db,namespace)


def _case_scope_v1(owner):
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    from .domain_background_read_v3 import BackgroundReadWorkV3
    if type(owner) is _MethodLearningReadV3:return owner.fence.scope
    if type(owner) is BackgroundReadWorkV3:return owner.read_scope
    raise TypeError('case scope requires its actual registered owner')


def read_registered_single_event_review_case_metadata_v1(db,*,namespace,case_original,issuer):
    from .d01_single_event_growth_v1 import _single_signed_metadata_v1
    from .d01_production_operations_v1 import TABLE
    from .dispatch_current_inventory_v3 import _freeze_value_v3,_detach_value_v3
    owner=_actual_case_owner_v1(db,namespace)
    if (type(case_original) is not ProductionOriginalRefV1 or case_original.kind!='d01.'+CASE_KIND
            or issuer is not owner.graph._GraphCoordinator__d11_issuer):
        raise ValueError('case selector requires its actual signed D01 kind and installed issuer')
    metadata=_single_signed_metadata_v1(db,namespace,issuer,case_original.original_ref,CASE_KIND,[])
    identity=('signed',TABLE,CASE_KIND,case_original.original_ref)
    from .current_method_learning_read_v3 import _MethodLearningReadV3
    from .domain_background_read_v3 import BackgroundReadWorkV3
    if type(owner) is _MethodLearningReadV3:task=owner.attachments.get(('general_owner_metadata',identity))
    elif type(owner) is BackgroundReadWorkV3:task=owner.general_trial_metadata.get(identity)
    else:raise TypeError('case metadata has another actual registered task owner')
    if (task is None or not task.complete or task.reader is not owner or task.metadata[0]!=CASE_KIND
            or task.metadata[2]!=case_original.original_digest or task.column.signature_verified is not True
            or metadata['schema']!=CASE_SCHEMA or metadata['namespace']!=plain_v1(namespace)
            or metadata['registration_operation_id']!=task.metadata[1]):
        raise ValueError('case metadata is not its complete current signed original EOF')
    record=(tuple(task.metadata),_freeze_value_v3(metadata),owner.operation,owner.work,owner.graph_stamp)
    prior=_CASE_METADATA.setdefault(owner,{}).get(case_original.original_ref)
    if prior is not None:
        if prior[0]!=record[0] or prior[2:]!=record[2:]:
            raise ValueError('case metadata changed its actual selected original or Work')
        record=prior
    else:_CASE_METADATA[owner][case_original.original_ref]=record
    original=ProductionOriginalRefV1('d01.'+CASE_KIND,case_original.original_ref,record[0][2])
    return _detach_value_v3(record[1]),original


def read_plan_registered_single_event_review_case_v1(db,*,namespace,case_original,issuer):
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d01_single_event_growth_v1 import ReadSingleEventGrowthRequestV1,read_plan_single_event_growth_v1
    metadata,original=read_registered_single_event_review_case_metadata_v1(db,namespace=namespace,
        case_original=case_original,issuer=issuer)
    adoption=decode_typed_production_value_v1(metadata['adoption_version'],GraphVersion)
    base=read_plan_single_event_growth_v1(db,namespace=namespace,operation_kind='read_single_event_growth_v1',
        request=ReadSingleEventGrowthRequestV1(adoption.key.token),issuer=issuer)
    keys=list(base.exact_keys);roots=list(base.source_roots);refs=list(base.required_original_refs)
    keys.extend(decode_typed_production_value_v1(v,GraphVersion).key for name in
        ('scope_versions','exclusion_versions','post_adoption_evidence_versions','source_versions')for v in metadata[name])
    keys.extend(decode_typed_production_value_v1(metadata[name],GraphVersion).key for name in
        ('adoption_version','review_version','current_persona_head'))
    roots.extend((*metadata['support_source_refs'],*metadata['context_source_refs']))
    refs.append(original.original_ref)
    for name in ('policy_original','input_original','adoption_original','causal_original'):
        refs.append(metadata[name]['original_ref'])
    for name in ('post_adoption_evidence_originals','trial_originals'):
        refs.extend(item['original_ref']for item in metadata[name])
    for row in metadata['post_adoption_scope_bindings']:
        refs.extend(item['original_ref']for item in row['observer_originals'])
    # Persona identity is a current metadata guard, never a C3 claim grant.
    from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
    metadata_only_types=frozenset({'d01.persona_plan.v1','d01.persona_revision.v1','d01.growth_contribution.v1'})
    body_keys=[]
    for key in keys:
        if key.type_name in metadata_only_types:
            growth_metadata_head_v1(db,namespace,key)
        else:body_keys.append(key)
    return production_read_plan_v1(tuple(t for t in base.fixed_type_ids if t not in metadata_only_types),body_keys,roots,refs)


def _require_case_sources_v1(owner,metadata):
    from .current_beta1_source_read_v3 import beta1_source_reader_operation_v3,require_beta1_source_member_v3
    from .domain_background_read_v3 import BackgroundReadWorkV3
    from .current_method_learning_read_v3 import is_single_event_review_method_v1
    _require_case_reader_v1(owner,owner.db,owner.namespace)
    roots=tuple(dict.fromkeys((*metadata['support_source_refs'],*metadata['context_source_refs'])))
    if type(owner) is BackgroundReadWorkV3:
        from .d01_single_event_growth_v1 import require_single_event_background_source_permission_v1
        proof=require_single_event_background_source_permission_v1(owner)
        if not set(roots)<=set(proof.refs):raise MissingProductionOriginalV1('actual_case_complete_source_family')
    elif is_single_event_review_method_v1(owner):
        from .d07_single_event_review_v1 import require_current_single_event_review_case_sources_v1
        proof=require_current_single_event_review_case_sources_v1(owner,roots)
        proof.require_for_v1(owner,roots)
    elif beta1_source_reader_operation_v3(owner):
        for purpose in ('context','consolidation'):
            for ref in roots:require_beta1_source_member_v3(owner,ref,purpose,tuple(owner.authority.audience))
    else:
        from .current_method_learning_read_v3 import require_current_method_recipe_sources_v1
        proof=require_current_method_recipe_sources_v1(owner,owner.selected_plan.source_roots)
        if not set(roots)<=set(proof.source_refs):
            raise MissingProductionOriginalV1('actual_case_complete_source_family')
    return owner


class _SingleEventCaseBodyTaskV1:
    def __init__(self,owner,identity):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        if type(identity) is not tuple or len(identity)!=2:raise ValueError('case Body needs its exact signed ref/digest')
        record=_CASE_METADATA.get(owner,{}).get(identity[0])
        if record is None or record[0][2]!=identity[1]:raise ValueError('case Body has no actual signed metadata selection')
        self.owner,self.identity,self.record=owner,identity,record
        self.operation=owner.operation
        self.operation.retain(8192)
        self.binding=(owner.work,owner.operation,owner.graph_stamp,_case_scope_v1(owner),owner.authority,owner.selection_digest)
        self.offset=0;self.total=None;self.fragment=b'';self.fragment_offset=0
        self.parser=C09CanonicalJSONStreamV2()
        self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=owner.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.complete=False;self.result=None
        _CASE_BODIES.setdefault(owner,{})[identity[0]]=self

    def require_current_v1(self,owner,meter=None):
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3,runtime_storage_quantum_v3
        if (owner is not self.owner or _CASE_BODIES.get(owner,{}).get(self.identity[0]) is not self
                or self.binding!=(owner.work,owner.operation,owner.graph_stamp,_case_scope_v1(owner),owner.authority,owner.selection_digest)
                or _CASE_METADATA.get(owner,{}).get(self.identity[0])!=self.record):
            raise ValueError('case Body left its actual private Work/ref/Source selection')
        _require_case_reader_v1(owner,owner.db,owner.namespace)
        _require_case_sources_v1(owner,_detach_value_v3(self.record[1]))
        with runtime_storage_quantum_v3(owner.db) as actual_meter:
            if meter is not None and actual_meter is not meter:raise ValueError('case Body changed its actual quantum')
            header=_runtime_bounded_fixed_row_v3(owner.db,actual_meter,'graph_d01_production_inputs_v1',
                ('kind','producing_operation_id','payload_digest','signature'),
                'bot=? AND persona=? AND original_ref=?',(*owner.namespace.as_tuple,self.identity[0]))
        if header!=self.record[0]:raise ValueError('case signed header changed during independent Body EOF')
        return self

    def advance(self,meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from .d01_production_operations_v1 import SIGN_KIND
        self.require_current_v1(self.owner,meter)
        if self.complete:return True
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            raw=self.fragment[self.fragment_offset:end]
            self.parser.feed(raw,self.builder._emit);self.fragment_offset=end;return False
        if self.total is None:
            row=self.owner.db.execute('SELECT typeof(payload_json),length(CAST(payload_json AS BLOB)) '
                'FROM graph_d01_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?',
                (*self.owner.namespace.as_tuple,self.identity[0])).fetchone()
            meter.charge_read(24)
            if row is None or row[0]!='text' or type(row[1]) is not int or row[1]>8192:
                raise MissingProductionOriginalV1('single_event_review_generic_target_bound')
            self.total=row[1];return False
        if self.offset<self.total:
            from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2
            with legacy_cell_read_transaction_v2(self.owner.db):
                raw,total,kind=read_legacy_sql_cell_fragment_v2(self.owner.db,table='graph_d01_production_inputs_v1',
                    column='payload_json',where='bot=? AND persona=? AND original_ref=?',
                    parameters=(*self.owner.namespace.as_tuple,self.identity[0]),start=self.offset,
                    length=min(8192,self.total-self.offset),meter=meter)
            if (kind,total)!=('text',self.total):raise ValueError('case Body total changed')
            self.offset+=len(raw);self.fragment=raw;self.fragment_offset=0
            return False
        parsed=self.parser.finish()
        if (parsed.sha256,parsed.byte_count)!=(self.identity[1],self.total) or self.builder.nodes:
            raise ValueError('case Body failed exact complete canonical EOF')
        raw=_detach_value_v3(self.builder.value);encoded=canonical_serialize(raw)
        meter.charge_encode(len(encoded))
        self.owner.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,encoded,self.record[0][3])
        value=decode_typed_production_value_v1(raw,RegisteredSingleEventReviewCaseV1)
        if value.case_ref!=self.identity[0] or canonical_digest(raw)!=self.identity[1]:
            raise ValueError('case Body does not match its stable actual signed identity')
        self.result=value;self.complete=True;self.fragment=b'';self.parser=self.builder=None
        return True


def create_current_single_event_case_body_task_v1(reader,identity):
    existing=_CASE_BODIES.get(reader,{}).get(identity[0])
    return existing if existing is not None else _SingleEventCaseBodyTaskV1(reader,identity)



def prepare_current_single_event_review_case_body_v1(owner,case_original):
    """Prepare only this Work's selected signed Case after its real Source ALL."""
    from .current_method_learning_read_v3 import _need_method_input
    from .domain_background_read_v3 import BackgroundReadWorkV3,BackgroundReadNeededV3
    _require_case_reader_v1(owner,owner.db,owner.namespace)
    metadata,original=read_registered_single_event_review_case_metadata_v1(owner.db,namespace=owner.namespace,
        case_original=case_original,issuer=owner.graph._GraphCoordinator__d11_issuer)
    _require_case_sources_v1(owner,metadata)
    task=_CASE_BODIES.get(owner,{}).get(original.original_ref)
    if task is None or not task.complete:
        identity=('single_event_case_body',(original.original_ref,original.original_digest))
        if type(owner)is BackgroundReadWorkV3:
            if owner.sealed:raise ValueError('case Body was not prepared by its actual R03 READ Work')
            raise BackgroundReadNeededV3(identity)
        _need_method_input(owner,identity)
    task.require_current_v1(owner)
    return task.result


def require_prepared_single_event_review_case_body_v1(owner,case_original):
    """A complete Body original is distinct from current Case qualification."""
    _require_case_reader_v1(owner,owner.db,owner.namespace)
    if type(case_original)is not ProductionOriginalRefV1 or case_original.kind!='d01.'+CASE_KIND:
        raise TypeError('prepared Case Body requires its exact registered original locator')
    task=_CASE_BODIES.get(owner,{}).get(case_original.original_ref)
    if (task is None or not task.complete or task.identity!=(case_original.original_ref,case_original.original_digest)
            or task.result is None):
        raise ValueError('case dependencies require this actual Work complete signed Body original')
    task.require_current_v1(owner)
    return task.result

def _read_case_body(db,read,case_original,issuer):
    owner=_actual_case_owner_v1(db,read.frame.envelope.authority.namespace)
    if issuer is not owner.graph._GraphCoordinator__d11_issuer:raise ValueError('Case Body has another installed issuer')
    case=prepare_current_single_event_review_case_body_v1(owner,case_original)
    _,original=read_registered_single_event_review_case_metadata_v1(db,namespace=owner.namespace,
        case_original=case_original,issuer=issuer)
    return case,original


def release_current_single_event_review_case_v1(owner):
    _CASE_REGISTRATION_PLANS_V1.pop(owner,None)
    for fact,binding in tuple(_CASE_FRESH_FACTS_V1.items()):
        if binding[-1][0] is owner:_CASE_FRESH_FACTS_V1.pop(fact,None)
    _CASE_METADATA.pop(owner,None)
    _CASE_RECEIPTS.pop(owner,None)
    for task in _CASE_BODIES.pop(owner,{}).values():
        task.parser=task.builder=task.result=None;task.fragment=b''


_CASE_RECEIPTS=WeakKeyDictionary()


def case_original_control_allowed_v1(owner,operation_id):
    from .dispatch_current_inventory_v3 import _detach_value_v3
    for record in _CASE_METADATA.get(owner,{}).values():
        if (record[0][1]==operation_id and record[2:]==(owner.operation,owner.work,owner.graph_stamp)
                and _detach_value_v3(record[1])['registration_operation_id']==operation_id):
            _require_case_reader_v1(owner,owner.db,owner.namespace)
            return True
    return False


def case_original_metadata_request_allowed_v1(owner,request):
    table,columns,key_columns,key=request
    columns,key_columns,key=tuple(columns),tuple(key_columns),tuple(key)
    if table=='graph_bundle_operations' and columns==('digest','activity_id','effect_id','commit_seq','receipt_json'):
        return(key_columns==('bot','persona','operation_id') and key[:2]==owner.namespace.as_tuple
            and case_original_control_allowed_v1(owner,key[2]))
    if table=='graph_events' and columns==('reads','revisions','epoch_revision'):
        if key_columns!=('bot','persona','session','event_id') or key[:2]!=owner.namespace.as_tuple:return False
        receipt=_CASE_RECEIPTS.get(owner,{}).get(key[3])
        return(receipt is not None and receipt.activity_id==key[2]
            and case_original_control_allowed_v1(owner,key[3]))
    return False


def case_original_metadata_column_allowed_v1(owner,table,key,column):
    key=tuple(key)
    if table=='graph_domain_production_originals_v1' and column in {'receipt_json','read_versions_json'}:
        return len(key)==3 and key[:2]==owner.namespace.as_tuple and case_original_control_allowed_v1(owner,key[2])
    if table=='graph_bundle_operations' and column=='receipt_json':
        return len(key)==3 and key[:2]==owner.namespace.as_tuple and case_original_control_allowed_v1(owner,key[2])
    if table=='graph_events' and column in {'reads','revisions'}:
        return case_original_metadata_request_allowed_v1(owner,(table,('reads','revisions','epoch_revision'),
            ('bot','persona','session','event_id'),key))
    return False


def _case_registered_receipt_v1(db,owner,case):
    from .persona_growth_review_metadata_v1 import growth_original_control_v1
    from .d01_general_growth_v1 import _general_operation_receipt_v1
    control=growth_original_control_v1(db,case.registration_operation_id)
    if (control['domain'],control['operation_kind'])!=('d01','review_single_event_growth_v1'):
        raise ValueError('signed review case has another actual registered producer')
    _CASE_RECEIPTS.setdefault(owner,{})[case.registration_operation_id]=control['receipt']
    receipt=_general_operation_receipt_v1(db,case.namespace,case.registration_operation_id)
    if canonical_digest(receipt)!=canonical_digest(control['receipt']) or receipt.write_versions:
        raise ValueError('review case lost its actual same-W01 receipt/event or changed its pending obligation')
    required=(*case.source_versions,*case.scope_versions,*case.exclusion_versions,
        case.adoption_version,case.review_version,case.current_persona_head,*case.counter_scope_binding.inventory_versions)
    if not set(required)<=set(receipt.read_versions) or not set(required)<=set(control['read_versions']):
        raise ValueError('review case was not produced under its complete actual Source/control/counter readset')
    return receipt


def _case_current_reader_v1(db,read,issuer):
    owner=_actual_case_owner_v1(db,read.frame.envelope.authority.namespace)
    if issuer is not owner.graph._GraphCoordinator__d11_issuer:raise ValueError('case target has another installed issuer')
    return owner


def _case_upper_v1(owner):
    from ..host.v2_fence_port import VerifiedIngressClockV2
    from .first_ingress_v2 import trusted_upper
    _require_case_reader_v1(owner,owner.db,owner.namespace)
    if type(owner.initial_clock) is not VerifiedIngressClockV2:
        raise MissingProductionOriginalV1('actual_paired_single_event_case_clock')
    now=trusted_upper(owner.initial_clock)
    if owner.operation.deadline_utc is None or now>=owner.operation.deadline_utc:
        raise MissingProductionOriginalV1('single_event_case_original_work_deadline')
    return now


_CASE_FRESH_FACTS_V1=WeakKeyDictionary()


def _fresh_case_binding_v1(owner):
    from .domain_background_read_v3 import BackgroundReadWorkV3
    binding=owner.owner if type(owner) is BackgroundReadWorkV3 else owner.owner_binding
    return(owner,owner.work,owner.operation,_case_scope_v1(owner),owner.authority,
        owner.selection_digest,owner.graph_stamp,binding)


@dataclass(frozen=True,eq=False)
class SingleEventReviewCaseFactV1:
    case:RegisteredSingleEventReviewCaseV1
    original:ProductionOriginalRefV1
    read_versions:tuple
    valid_until_utc:float
    def require_current_v1(self,owner):
        bound=_CASE_FRESH_FACTS_V1.get(self)
        actual=(self.case,self.original,self.read_versions,self.valid_until_utc,_fresh_case_binding_v1(owner))
        if bound!=actual:
            raise ValueError('review Case fact is not the actual private current Method/Source result')
        _require_case_reader_v1(owner,owner.db,owner.namespace)
        task=_CASE_BODIES.get(owner,{}).get(self.original.original_ref)
        if task is None or not task.complete or task.result!=self.case:
            raise ValueError('review Case fact lost its actual complete signed Body original')
        task.require_current_v1(owner)
        if not self.case.review_not_before_utc<=_case_upper_v1(owner)<self.valid_until_utc:
            raise MissingProductionOriginalV1('single_event_review_case_original_window')
        return self


def require_single_event_review_case_fact_owner_v1(fact,db):
    if type(fact) is not SingleEventReviewCaseFactV1:
        raise TypeError('actual privately issued review Case fact required')
    record=_CASE_FRESH_FACTS_V1.get(fact)
    if record is None:raise ValueError('review Case fact has no live actual issuing Work')
    owner=record[-1][0]
    if owner.db is not db:raise ValueError('review Case fact crossed its actual Graph connection')
    fact.require_current_v1(owner)
    return owner


def require_registered_single_event_review_case_fact_v1(db,*,frame,case_original,issuer):
    if type(case_original) is not ProductionOriginalRefV1 or case_original.kind!='d01.'+CASE_KIND:
        raise TypeError('review Case fact requires its exact registered original selector')
    case,original,versions=require_registered_single_event_review_case_target_v1(db,
        frame=frame,case_ref=case_original.original_ref,issuer=issuer)
    if original!=case_original:
        raise ValueError('review Case fact changed its actual signed original digest')
    owner=_case_current_reader_v1(db,CurrentDomainReadV1(frame),issuer)
    until=min(case.review_due_utc,case.readout_valid_until_utc,case.original_deadline_utc,owner.operation.deadline_utc)
    value=SingleEventReviewCaseFactV1(case,original,tuple(versions),until)
    _CASE_FRESH_FACTS_V1[value]=(case,original,tuple(versions),until,_fresh_case_binding_v1(owner))
    return value.require_current_v1(owner)


def require_registered_single_event_review_case_target_v1(db,*,frame,case_ref,issuer):
    """Source ALL precedes this Body; current control never decodes a full plan."""
    read=CurrentDomainReadV1(frame);read.check(db)
    owner=_case_current_reader_v1(db,read,issuer)
    metadata_records=_CASE_METADATA.get(owner,{})
    record=metadata_records.get(case_ref)
    if record is None:raise ValueError('case Body target has no independent signed metadata selection')
    original=ProductionOriginalRefV1('d01.'+CASE_KIND,case_ref,record[0][2])
    case,original=_read_case_body(db,read,original,issuer)
    now=_case_upper_v1(owner)
    if not case.review_not_before_utc<=now<min(case.review_due_utc,case.readout_valid_until_utc,case.original_deadline_utc):
        raise MissingProductionOriginalV1('single_event_review_case_original_window')
    _case_registered_receipt_v1(db,owner,case)
    for version in (*case.source_versions,*case.scope_versions,*case.exclusion_versions,
            case.adoption_version,case.review_version,case.current_persona_head):
        from .persona_growth_review_metadata_v1 import growth_metadata_head_v1
        current,valid=growth_metadata_head_v1(db,case.namespace,version.key)
        if current!=version or version.revision>0 and not valid or version.revision==0 and valid:
            raise MissingProductionOriginalV1('single_event_review_case_current_version_changed')
    from .d01_single_event_growth_v1 import _single_signed_metadata_v1,POLICY_KIND,INPUT_KIND
    policy_raw=_single_signed_metadata_v1(db,case.namespace,issuer,case.policy_original.original_ref,POLICY_KIND,[])
    input_raw=_single_signed_metadata_v1(db,case.namespace,issuer,case.input_original.original_ref,INPUT_KIND,[])
    from ..domains.d01.single_event_growth_v1 import SingleEventGrowthPolicyV1,SingleEventGrowthInputV1
    policy=decode_typed_production_value_v1(policy_raw,SingleEventGrowthPolicyV1)
    value=decode_typed_production_value_v1(input_raw,SingleEventGrowthInputV1)
    if (canonical_digest(policy_raw)!=case.policy_original.original_digest
            or canonical_digest(input_raw)!=case.input_original.original_digest
            or value.policy_digest!=case.policy_original.original_digest
            or (policy.terms.scope_versions,policy.terms.exclusion_versions,policy.terms.target_block)!=(
                case.scope_versions,case.exclusion_versions,case.target_block)):
        raise ValueError('review case changed its actual signed policy/input/scope')
    from ..domains.d01.identity_v3 import RuntimeIdentityRef
    if policy.runtime_identity!=RuntimeIdentityRef.from_owner_guard(case.namespace,owner.owner_guard):
        raise MissingProductionOriginalV1('single_event_review_case_current_owner_incarnation')
    from ..domains.d01 import _activation_key
    from ..graph_types import GraphSnapshot,NamespaceEpoch,owner_grant_key
    atoms=tuple(read.head(db,key,required=True)for key in(_activation_key(case.namespace),owner_grant_key(*case.namespace.as_tuple)))
    epoch=next(e for e in frame.snapshot.epochs if(e.bot,e.persona)==case.namespace.as_tuple)
    control=PersonaDomain.resolve_active_role_control_v3(GraphSnapshot(atoms,(epoch,)),
        namespace=case.namespace,current_guard=owner.owner_guard)
    if control.plan_key!=case.current_persona_head.key or control.head_id!=case.current_persona_head_id:
        raise MissingProductionOriginalV1('single_event_review_case_actual_current_persona')
    adoption=read.head(db,case.adoption_version.key,required=True)
    review=read.head(db,case.review_version.key,required=True)
    if (canonical_digest(adoption.value)!=case.adoption_value_digest or canonical_digest(review.value)!=case.review_value_digest
            or adoption.value['adopted_claim_digest']!=case.adopted_claim_digest
            or adoption.value['input_digest']!=case.input_original.original_digest
            or case.adoption_recorded_at_utc>case.registered_at_utc):
        raise ValueError('review case no longer binds its exact actual adoption and pending review')
    counter,_=_counter_binding(db,read,policy)
    old=case.counter_scope_binding
    if (counter.question_key,counter.selected_members,counter.qualification)!=(old.question_key,old.selected_members,old.qualification):
        raise MissingProductionOriginalV1('single_event_review_case_current_counter_changed')
    from .d01_production_operations_v1 import InstalledD01ProductionReadersV1
    readers=InstalledD01ProductionReadersV1(issuer=issuer,owner_guard=owner.owner_guard,
        role_clock_reader=owner.graph._GraphCoordinator__d04_semantic_mapping_reader)
    clock,mapping=_clock_original(db,readers,read,now)
    if (clock,mapping.mapping_id,mapping.version)!=(case.clock_original,case.clock_mapping_id,case.clock_mapping_version):
        raise MissingProductionOriginalV1('single_event_review_case_clock_original_changed')
    from .budget import get_budget_lease,require_budget_family_admissible
    lease=get_budget_lease(db,case.original_parent_budget_lease_ref)
    require_budget_family_admissible(db,case.original_parent_budget_lease_ref)
    grant=issuer.current_budget_grant(db,case.original_parent_budget_lease_ref)
    if (lease.state!='active' or canonical_digest(grant)!=case.original_parent_grant_digest
            or now>=min(case.original_deadline_utc,grant.valid_until_utc)):
        raise MissingProductionOriginalV1('single_event_review_case_original_budget')
    for version,encoded in case.post_adoption_evidence_values:
        atom=read.head(db,version.key,required=True)
        if atom.revision!=version.revision or canonical_serialize(atom.value)!=encoded:
            raise MissingProductionOriginalV1('single_event_actual_post_adoption_result_changed')
    guards=actual_frame_read_versions_v1(frame)
    return case,original,guards
