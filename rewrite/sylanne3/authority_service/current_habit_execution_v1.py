"""Actual fresh-permit eligibility of the fixed SourceNote occurrence recipe phases."""
from .contract import AuthorityUnavailable
from .d10_habit_execution_contract_v1 import (HabitOccurrenceExecutionSelectorV1,habit_execution_typed_request_v1)
from .d10_habit_ledger_v1 import OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,habit_ledger_decode_v1,habit_identity_commitment_v1
from .d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1
from .habit_authority_source_read_v3 import (_read_habit_committed_original_v3,_fixed_row_v3,_run_column_v3,_source_refs_v3)
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1,habit_occurrence_id_v1,habit_occurrence_key_v1
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest,canonical_serialize


def require_current_habit_source_note_input_v1(inputs,definition):
    from ..domains.d10.habit_policy_v1 import HabitSourceNoteInputV1
    if definition.executor_kind!='source_note':return
    value=definition.source_note_input
    if type(value)is not HabitSourceNoteInputV1:raise AuthorityUnavailable('Habit SourceNote lacks actual signed typed standing input')
    witness=inputs.work.sources.get(value.source_ref)
    if(witness is None or witness.require_current_v3().valid is not True
            or(witness.revision,witness.canonical_semantic_digest)!=(value.source_revision,value.source_digest)):
        raise AuthorityUnavailable('Habit standing Source version/digest changed')
    role=inputs.bodies[AtomKey.from_token(value.role_binding_ref)]
    if(role.revision,canonical_digest(role.value))!=(value.role_binding_revision,value.role_binding_digest):
        raise AuthorityUnavailable('Habit standing role binding version/digest changed')


def _old_qualification_v1(service,permit,subject,request,policy):
    p=service.policy_service;selection=request.qualification_selector
    with p.fences._frozen()as(db,deletion,execution,_):
        anchor=p.fences._current_locked(db,deletion,execution)
        p.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        row=db.execute('SELECT * FROM '+OCCURRENCE_TABLE+' WHERE authority_namespace=? AND installation_id=? AND operation_commitment=?',
            (p.fences.namespace,p.installation_id,habit_identity_commitment_v1(service._key,'operation',selection.operation_id))).fetchone()
        if row is None:raise AuthorityUnavailable('Habit original occurrence qualification ledger row is absent')
        original=habit_ledger_decode_v1(OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,row,key=service._key,
            authority_namespace=p.fences.namespace,authority_id=p.core._id(db),installation_id=p.installation_id)
        if(type(original)is not HabitOccurrenceQualificationOriginalV1 or original.selector!=selection
                or(original.original_ref,original.digest)!=(request.qualification_original_ref,request.qualification_original_digest)
                or p._head_v1(db,policy.definition.policy_id)!=policy):
            raise AuthorityUnavailable('Habit execution changed the actual old immutable qualification or current standing policy')
    return original


def _producer_v1(inputs,operation,kind):
    return _read_habit_committed_original_v3(inputs,operation_id=operation,expected_kind=kind)


def _context_v1(inputs,occurrence,policy,qualification):
    from ..runtime.d10_habit_v1 import habit_source_note_context_operation_id_v1,habit_source_note_context_from_wire_v1
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    operation=habit_source_note_context_operation_id_v1(occurrence.namespace,occurrence.occurrence_id)
    digest,raw=_producer_v1(inputs,operation,'instantiate_current_habit_source_note_context_v1')
    context=habit_source_note_context_from_wire_v1(raw['provenance']['habit_source_note_context'])
    if(context.namespace,context.occurrence_ref,context.policy_ref,context.policy_revision,
            context.standing_original_ref,context.standing_original_digest,context.qualification_original_ref,
            context.qualification_original_digest,context.execution_operation_id,context.effect_id,
            context.parent_root_grant_ref,context.parent_root_grant_digest,context.original_deadline_utc)!=(
            occurrence.namespace,habit_occurrence_key_v1(occurrence.namespace,occurrence.occurrence_id).token,
            occurrence.policy_ref,occurrence.policy_revision,policy.original_ref,policy.digest,qualification.original_ref,
            qualification.digest,occurrence.occurrence_operation_id,occurrence.effect_id,occurrence.parent_root_grant_ref,
            occurrence.parent_root_grant_digest,occurrence.original_deadline_utc):
        raise AuthorityUnavailable('Habit execution context is not this occurrence and actual standing qualification')
    if(occurrence.goal_ref,occurrence.plan_ref)!=(context.goal_head.key.token,context.plan_head.key.token):
        raise AuthorityUnavailable('Habit current occurrence changed its committed context heads')
    for version in(context.goal_head,context.plan_head,context.input_source_head,context.role_binding_head,context.target_entity_head):
        current=inputs.work.heads.get(version.key.token)
        if current is None or current[:2]!=(version.revision,1):raise AuthorityUnavailable('Habit committed context head changed before its actual phase')
    checkpoint=inputs.bodies[project_checkpoint_key_v1(occurrence.namespace,policy.definition.project_ref)].value
    if(checkpoint['plan_ref'],checkpoint['plan_revision'],checkpoint['next_step'],checkpoint['state'])!=(
            context.plan_head.key.token,context.plan_head.revision,context.node_id,'active'):
        raise AuthorityUnavailable('Habit execution lost the actual current project checkpoint to this occurrence')
    return 'd08-current:'+digest[:48],digest


def _signed_life_plan_v1(service,inputs,ref,operation):
    from ..runtime.d11_life_preparation_v1 import TABLE,SIGN_KIND
    from ..runtime.d11_life_contract_v1 import RegisteredLifePlanV2,life_from_wire_v1
    from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    w=inputs.work;namespace=inputs.definition.namespace
    row=_fixed_row_v3(w,TABLE,('producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND kind=? AND original_ref=?',(*namespace.as_tuple,'plan',ref))
    if row is None or row[0]!=operation:raise AuthorityUnavailable('Habit prepare Life lacks its actual signed registered plan predecessor')
    column=DispatchOriginalJSONReadV3(w,table=TABLE,column='payload_json',
        key_columns=('bot','persona','kind','original_ref'),key=(*namespace.as_tuple,'plan',ref))
    raw=_run_column_v3(w,column)
    if canonical_digest(raw)!=row[1]or not _source_refs_v3(raw)<=set(inputs.roots):
        raise AuthorityUnavailable('Habit registered Life plan introduced unqualified Source or changed actual digest')
    service.issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,'plan',ref,row[1])),row[2])
    return life_from_wire_v1(raw,RegisteredLifePlanV2)


def current_habit_execution_v1(service,*,credential,subject,permit,request):
    from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1
    from ..runtime.habit_activity_issuance_v1 import habit_typed_command_digest_v1
    from ..runtime.d10_habit_v1 import (habit_source_note_context_operation_id_v1,habit_source_note_context_keys_v1,
        habit_source_note_life_ids_v1)
    from .habit_body_preparation_v3 import (HabitBodyPreparationSelectorV3,HabitBodyCPUPreparationV3,
        preparation_signature_material_v3,require_body_preparation_v3)
    preparing=type(request)is HabitBodyPreparationSelectorV3
    if type(service)is not InstalledCurrentHabitOccurrenceV1 or type(request)not in {HabitOccurrenceExecutionSelectorV1,HabitBodyPreparationSelectorV3}:
        raise TypeError('actual installed Habit service and exact closed execution selector required')
    policy,inputs=service._prepare_v1(credential=credential,subject=subject,permit=permit,request=request,require_write=not preparing)
    try:
        selection=request.qualification_selector;definition=policy.definition
        atom=inputs.bodies[AtomKey.from_token(request.occurrence_ref)]
        occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',atom.value)
        identity=habit_occurrence_id_v1(definition.namespace,definition.policy_id,definition.revision,selection.window_id,selection.cue_stable_key)
        if(atom.revision!=request.expected_occurrence_revision or atom.key!=habit_occurrence_key_v1(definition.namespace,identity)
                or occurrence.state!='qualified' or occurrence.actual_started_at_utc is not None
                or(occurrence.policy_ref,occurrence.policy_revision,occurrence.policy_digest,occurrence.cancellation_generation,
                    occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,
                    occurrence.recipe_ref,occurrence.recipe_revision,occurrence.parent_root_grant_ref,occurrence.parent_root_grant_digest,
                    occurrence.original_deadline_utc)!=(selection.policy_ref,selection.policy_revision,selection.policy_digest,selection.cancellation_generation,
                    selection.execution_operation_id,selection.activity_id,selection.effect_id,selection.attempt_id,
                    selection.recipe_ref,selection.recipe_revision,selection.parent_root_grant_ref,selection.parent_root_grant_digest,
                    selection.original_deadline_utc)):
            raise AuthorityUnavailable('Habit execution changed its original qualified occurrence, effect, recipe, Root or deadline')
        from .habit_authority_source_read_v3 import require_habit_no_other_obligation_v1
        require_habit_no_other_obligation_v1(inputs,occurrence_key=atom.key,
            context=request.operation_kind=="instantiate_current_habit_source_note_context_v1")
        qualification=_old_qualification_v1(service,permit,subject,request,policy)
        if(qualification.target_commitment,qualification.project_commitment)!=(policy.target_commitment,policy.project_commitment):
            raise AuthorityUnavailable("Habit old qualification changed original opaque target/project standing identity")
        if occurrence.qualification_original_ref!=qualification.original_ref:
            raise AuthorityUnavailable('Habit current occurrence does not name this actual immutable original qualification')
        _,qualified=_producer_v1(inputs,selection.operation_id,'qualify_habit_occurrence_v1')
        if qualified['provenance']['core_qualification']!=plain_v1(qualification):
            raise AuthorityUnavailable('Habit eligibility has no actual qualification COMMIT with that independent Core original')
        if preparing:command=request
        else:
            operation,command=habit_execution_typed_request_v1(request)
            if request.request_digest!=habit_typed_command_digest_v1(operation,command):
                raise AuthorityUnavailable('Habit fresh phase changed the actual installed typed command')
        require_current_habit_source_note_input_v1(inputs,definition)
        reading=service.clock();now=reading.utc_seconds+reading.utc_error_seconds
        if now>=occurrence.original_deadline_utc or reading.utc_seconds-reading.utc_error_seconds<qualification.issued_at_utc:
            raise AuthorityUnavailable('Habit original same-window execution time or absolute deadline changed')
        census=tuple((key,revision,value)for key,(revision,digest,value)in inputs.census.items()if value['policy_ref']==selection.policy_ref)
        counted=tuple(key for key,_,value in census if value['window_id']==occurrence.window_id)
        if len(counted)>definition.maximum_occurrences_per_window or atom.key not in counted:
            raise AuthorityUnavailable('Habit fresh execution lost complete cross-revision original window census')
        times=tuple(value['actual_started_at_utc']if value['actual_started_at_utc']is not None else value['admitted_at_utc']
            for key,_,value in census if key!=atom.key and(value['actual_started_at_utc']is not None or value['admitted_at_utc']is not None))
        if times and now-max(times)<definition.minimum_interval_seconds:raise AuthorityUnavailable('Habit actual minimum interval is not ready')
        service._require_cue_v1(inputs,policy,selection,now)
        kind=request.operation_kind
        if kind=='instantiate_current_habit_source_note_context_v1':
            expected=habit_source_note_context_operation_id_v1(definition.namespace,identity)
            keys=habit_source_note_context_keys_v1(definition.namespace,identity,occurrence.activity_id)
            from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
            from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1
            checkpoint_atom=inputs.bodies[project_checkpoint_key_v1(definition.namespace,definition.project_ref)]
            checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,checkpoint_atom.value)
            parent_atom=inputs.bodies[AtomKey.from_token(checkpoint.plan_ref)]
            parent=decode_personal_plan_type_v1(parent_atom.key.type_name,parent_atom.value)
            goal=inputs.bodies[AtomKey.from_token(parent.goal_ref)]
            if(checkpoint.plan_revision!=parent_atom.revision or parent.goal_revision!=goal.revision
                    or checkpoint.state in{'paused','cancelled'}or parent.state in{'paused','abandoned','superseded'}
                    or any(node.pending_original_effects for node in parent.nodes)):
                raise AuthorityUnavailable('Habit new occurrence context would overwrite an unresolved or paused current project plan')
            if(any(value is not None for value in(occurrence.goal_ref,occurrence.plan_ref,occurrence.action_intent_ref,occurrence.life_plan_original_ref,
                    occurrence.context_original_ref,occurrence.context_original_digest))or any(key.token in inputs.work.heads for key in keys.values())):
                raise AuthorityUnavailable('Habit occurrence context already exists; do not create a second context')
        else:
            context_ref,context_digest=_context_v1(inputs,occurrence,policy,qualification)
            if kind=='prepare_current_habit_source_note_action_v1':
                expected=occurrence.occurrence_operation_id
                if occurrence.action_intent_ref is not None or occurrence.life_plan_original_ref is not None:
                    raise AuthorityUnavailable('Habit Action already exists; observe its original identity')
            else:
                if(occurrence.action_intent_ref is None or(occurrence.context_original_ref,occurrence.context_original_digest)!=(context_ref,context_digest)):
                    raise AuthorityUnavailable('Habit phase has no actual committed Action and context predecessor')
                action_atom=inputs.bodies[AtomKey.from_token(occurrence.action_intent_ref)]
                _,action=_read_habit_committed_original_v3(inputs,operation_id=occurrence.occurrence_operation_id,
                    expected_kind='prepare_current_habit_source_note_action_v1',member=action_atom)
                from ..domains.d08.execution import _decode_intent,ActionCancellationState
                intent=_decode_intent(action_atom.value)
                cancellation_key=AtomKey(action_atom.key.owner,'d08.action_cancellation.v1',action_atom.key.name)
                cancel_raw=inputs.bodies[cancellation_key].value
                cancellation=ActionCancellationState(**{**cancel_raw,'source_refs':tuple(cancel_raw['source_refs'])})
                if(cancellation.state,cancellation.cancel_epoch,cancellation.action_revision,cancellation.action_digest,
                        cancellation.activity_id,cancellation.effect_id,cancellation.attempt_id)!=(
                        'active',0,action_atom.revision,canonical_digest(intent),occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id):
                    raise AuthorityUnavailable('Habit Action current cancellation or immutable effect binding changed')
                if action['provenance']['occurrence']['action_intent_ref']!=occurrence.action_intent_ref:
                    raise AuthorityUnavailable('Habit phase borrowed another Action producer')
                if kind=='prepare_source_note_body':
                    expected='d02-life-body:'+occurrence.occurrence_operation_id
                    if command.action_intent_ref!=occurrence.action_intent_ref or occurrence.life_plan_original_ref is not None:
                        raise AuthorityUnavailable('Habit Body command changed its exact original Action or replayed a later phase')
                    from ..runtime.habit_body_cpu_source_v3 import core_body_basis_v3
                    selected=request if preparing else request.command.preparation.selector
                    if(selected.namespace,selected.installation_id,selected.qualification_selector,selected.qualification_original_ref,
                            selected.qualification_original_digest,selected.occurrence_ref,selected.expected_occurrence_revision,
                            selected.action_intent_ref,selected.body_policy_id,selected.body_policy_version,selected.effect_policy_ref)!=(
                            request.namespace,service.policy_service.installation_id,request.qualification_selector,request.qualification_original_ref,
                            request.qualification_original_digest,request.occurrence_ref,request.expected_occurrence_revision,
                            command.action_intent_ref,command.body_policy_id,command.body_policy_version,command.effect_policy_ref):
                        raise AuthorityUnavailable('Habit Body fresh phase changed its complete preparation selector')
                    basis=core_body_basis_v3(service,inputs,selected,policy)
                    if now>=basis['valid_until_utc']:raise AuthorityUnavailable('Habit Body original preparation window expired')
                    if preparing:
                        import hashlib,hmac
                        signature=hmac.new(service._key,preparation_signature_material_v3(selected,basis,permit),hashlib.sha256).hexdigest()
                        return HabitBodyCPUPreparationV3(selected,basis,permit,signature),permit
                    require_body_preparation_v3(service,request.command.preparation,selected,basis,permit,inputs)
                    if command.cpu_ceiling_ms!=basis['cpu_ceiling_ms']:
                        raise AuthorityUnavailable('Habit Body fresh WRITE changed actual available CPU intersection')
                else:
                    _,body=_producer_v1(inputs,'d02-life-body:'+occurrence.occurrence_operation_id,'prepare_source_note_body')
                    if body['provenance']['life_body_root_action_ref']!=occurrence.action_intent_ref:
                        raise AuthorityUnavailable('Habit Life phase borrowed another actual Body predecessor')
                    from ..runtime.habit_body_cpu_source_v3 import require_core_committed_habit_body_v3
                    require_core_committed_habit_body_v3(service,inputs,occurrence,body)
                    ids=habit_source_note_life_ids_v1(definition.namespace,identity,definition.project_ref)
                    if kind=='register_current_habit_source_note_life_plan_v1':
                        expected=ids['plan_operation_id']
                        if occurrence.life_plan_original_ref is not None:raise AuthorityUnavailable('Habit Life plan already exists')
                    else:
                        expected=ids['prepare_operation_id']
                        if(occurrence.life_plan_original_ref,command.plan_original_ref,command.prepare_operation_id)!=(ids['plan_ref'],ids['plan_ref'],expected):
                            raise AuthorityUnavailable('Habit Life prepare changed original plan or fixed phase operation')
                        _,registered=_producer_v1(inputs,ids['plan_operation_id'],'register_current_habit_source_note_life_plan_v1')
                        plan=_signed_life_plan_v1(service,inputs,ids['plan_ref'],ids['plan_operation_id'])
                        from ..runtime.d11_offline_originals_v1 import _utc
                        pinned=definition.source_note_input
                        if(registered['provenance']['life_plan']!=plain_v1(plan)or(plan.activity_id,plan.effect_id,plan.attempt_id,plan.operation_id,
                                plan.parent_budget_lease_ref,plan.action_intent.ref,plan.project.ref,plan.recipe.ref,plan.recipe.revision,
                                plan.input_source.ref,plan.input_source.revision,plan.input_source.digest,plan.audiences)!=(
                                occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.occurrence_operation_id,
                                occurrence.parent_root_grant_ref,occurrence.action_intent_ref,definition.project_ref,definition.recipe_ref,
                                definition.recipe_revision,pinned.source_ref,pinned.source_revision,pinned.source_digest,definition.audience)
                                or not now<_utc(plan.deadline_utc).timestamp()<=occurrence.original_deadline_utc):
                            raise AuthorityUnavailable('Habit actual signed registered plan changed original Action/effect/Root/Source/audience/deadline lineage')
        if request.operation_id!=expected:raise AuthorityUnavailable('Habit fresh WRITE operation is outside its frozen recipe phase mapping')
        inputs.require_for_v3(service=service,permit=permit)
        evidence=service._evidence_v1(request,policy,inputs,qualification=qualification,now=now)
        if kind=='prepare_source_note_body':
            from dataclasses import replace
            evidence=replace(evidence,valid_until_utc=min(evidence.valid_until_utc,basis['valid_until_utc']))
        return evidence,permit
    finally:inputs.release_v3()
