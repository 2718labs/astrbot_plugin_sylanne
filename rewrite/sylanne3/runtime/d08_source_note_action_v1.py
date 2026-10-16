"""The actual W01 root of one installed internal source-note action."""
from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03.context import EntityAnchor, RoleBinding, RoleBindingRequest, _tuple_payload
from ..domains.d05.relationship import BoundaryRule, RelationshipProvider, _tuple_payload as boundary_payload
from ..domains.d07.qualified_attention_read import read_qualified_focus_attention_ticket
from ..domains.d08.execution import (ActionIntent, ActionSchema, ActionSchemaRecord,
    ActionCancellationState, GoalExecutionProvider, RequiredCheckSpec, _decode)
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import DomainProposal, DependencySet, VersionedRef, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d08_life_admission_v1 import PAIRS, LIFE_ADMISSION_TYPES_V1, life_criterion_ref_v1, _adopted, _context_provider
from .d11_life_contract_v1 import RECIPE_ID, WORK_KIND, POSTCONDITION_ID, life_artifact_ref_v1
from .d11_life_scope_v1 import LifeSemanticScopeV1, life_semantic_source_refs_v1
from .d01_life_activation_original_v1 import require_current_life_activation_original_v1


@dataclass(frozen=True, slots=True)
class PrepareSourceNoteActionRequestV1:
    project_ref: str
    recipe_ref: str
    source_ref: str
    goal_ref: str
    target_entity_ref: str
    role_binding_ref: str

    def __post_init__(self):
        for name, kind in (("project_ref", "d10.life_project.v1"), ("recipe_ref", "d10.activity_recipe.v1"),
                ("source_ref", "memory.source"), ("goal_ref", "d08.goal.v1"),
                ("target_entity_ref", "d03.entity_anchor"), ("role_binding_ref", "d03.role_binding")):
            if AtomKey.from_token(getattr(self, name)).type_name != kind:
                raise ValueError("source-note root requires actual project/recipe/Source/goal locators")


@dataclass(frozen=True, slots=True)
class SourceNoteActionStageV1:
    stage: object


@dataclass(frozen=True, slots=True)
class SourceNoteActionOriginalV1:
    action_intent_ref: str
    action_intent_digest: str
    action_operation_id: str
    activity_id: str
    effect_id: str
    project_ref: str
    recipe_ref: str
    input_source_ref: str
    goal_ref: str
    audiences: tuple[str, ...]
    target_entity_ref: str
    role_binding_ref: str
    context_commitments: tuple[tuple[str, int, str, str, str], ...]
    write_commitments: tuple[tuple[str, int, str], ...]
    receipt_digest: str
    schema: str = "d08.source-note-action-original.v2"

    def __post_init__(self):
        if (self.schema != "d08.source-note-action-original.v2" or not self.audiences
                or len(self.write_commitments) != 3 or len({v[0] for v in self.write_commitments}) != 3
                or {v[0] for v in self.context_commitments} != {self.target_entity_ref, self.role_binding_ref, self.project_ref}):
            raise ValueError("source-note root requires its three-member event and genuine adopted project context")


def source_note_action_original_from_wire_v1(raw):
    if type(raw) is dict and raw.get("schema")=="d08.habit-source-note-action-original.v1":
        from .d10_habit_v1 import habit_source_note_original_from_wire_v1
        return habit_source_note_original_from_wire_v1(raw)
    if type(raw) is dict and raw.get("schema") == "d08.selected-source-note-action-original.v2":
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        return decode_typed_production_value_v1(raw, SelectedSourceNoteActionOriginalV2)
    value = dict(raw)
    value["audiences"] = tuple(value["audiences"])
    value["write_commitments"] = tuple(tuple(v) for v in value["write_commitments"])
    value["context_commitments"] = tuple(tuple(v) for v in value["context_commitments"])
    return SourceNoteActionOriginalV1(**value)


def source_note_effect_id_v1(namespace, project_ref, operation_id):
    return "effect:source-note:" + canonical_digest((namespace, project_ref, operation_id))[:48]


def source_note_attempt_id_v1(namespace, project_ref, operation_id):
    """One typed D08 attempt, derived by the installed root before freezing."""
    from ..runtime_contracts import NamespaceId
    key = AtomKey.from_token(project_ref)
    if (type(namespace) is not NamespaceId or NamespaceId.from_key(key) != namespace
            or key.type_name != 'd10.life_project.v1'
            or type(operation_id) is not str or not operation_id):
        raise ValueError('source-note attempt requires its actual namespace/project/operation')
    return 'attempt:source-note:' + canonical_digest((
        'd08.source-note-attempt.v1', namespace, project_ref, operation_id))[:48]


def _keys(namespace, activity_id, operation_id, request):
    tag = canonical_digest((namespace, request.project_ref, operation_id))[:48]
    entity = AtomKey.from_token(request.target_entity_ref)
    action = AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "d08.action_intent.v1", "action:source-note:" + tag)
    cancel = AtomKey(action.owner, "d08.action_cancellation.v1", action.name)
    return entity, action, cancel


def read_plan_source_note_action_v1(db, *, namespace, activity_id, operation_id, request, now_utc, audiences):
    from .d11_life_product_adapter_v1 import life_inventory_read_inputs_v1
    entity, action, cancel = _keys(namespace, activity_id, operation_id, request)
    entity_row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (entity.token, *namespace.as_tuple)).fetchone()
    if entity_row is None or entity_row[1] != 1:
        raise MissingProductionOriginalV1("current_source_note_project_entity")
    entity_value = EntityAnchor(**_tuple_payload(json.loads(entity_row[0]), "creation_evidence_refs"))
    goal_row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (request.goal_ref, *namespace.as_tuple)).fetchone()
    if goal_row is None or goal_row[1] != 1:
        raise MissingProductionOriginalV1("current_source_note_goal")
    goal = _decode("d08.goal.v1", json.loads(goal_row[0]))
    scope = LifeSemanticScopeV1(namespace, request.project_ref, request.source_ref, entity.token,
        entity_value.entity_id, action.name, goal.goal_id, (), tuple(audiences), now_utc)
    keys, roots, originals = life_inventory_read_inputs_v1(db, namespace=namespace, scope=scope)
    keys += [entity, action, cancel, *(AtomKey.from_token(v) for v in
        (request.project_ref, request.recipe_ref, request.source_ref, request.goal_ref, request.role_binding_ref))]
    # Schema ref depends on the complete actual command. The complete schema
    # inventory supplies its negative-query guard before that command freezes.
    return production_read_plan_v1((*LIFE_ADMISSION_TYPES_V1, "d08.action_schema.v1"), keys,
        (*roots, request.source_ref), (*originals, request.project_ref, request.recipe_ref, request.goal_ref,
            request.target_entity_ref, request.role_binding_ref))


def _intent(db, frame, request, installed_readers):
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    read = CurrentDomainReadV1(frame)
    ns, identity = frame.envelope.authority.namespace, frame.envelope.identity
    if identity.attempt_id != source_note_attempt_id_v1(ns, request.project_ref, identity.operation_id):
        raise ValueError('source-note root lost its exact typed attempt identity')
    project, recipe, source, goal_atom = (read.head(db, ref, required=True) for ref in
        (request.project_ref, request.recipe_ref, request.source_ref, request.goal_ref))
    goal = _decode("d08.goal.v1", goal_atom.value)
    build = read_installed_d11_life_build_v1(installed_readers.package_root, installed_readers.manifest_digest)
    artifact_ref = life_artifact_ref_v1(ns, identity.effect_id)
    values=(project.value,recipe.value,source.value,artifact_ref,build)
    if identity.phase=='prepare_current_habit_source_note_action_v1':
        from .current_habit_source_read_v3 import current_habit_source_note_action_parameter_digest_v3
        parameter_digest=current_habit_source_note_action_parameter_digest_v3(db,ns,identity.operation_id,values)
    else:
        from .current_method_learning_read_v3 import current_action_parameter_digest_v3
        parameter_digest=current_action_parameter_digest_v3(db,ns,identity.operation_id,values)
    return source_note_action_parts_v1(namespace=ns, identity=identity, request=request,
        goal=goal, parameter_digest=parameter_digest)[0]


def source_note_schema_key_v1(db, *, frame, request, installed_readers):
    action = _intent(db, frame, request, installed_readers)
    key = source_note_schema_key_from_action_v1(frame.envelope.authority.namespace, action)
    if frame.envelope.identity.phase=='prepare_current_habit_source_note_action_v1':
        from .current_habit_source_read_v3 import verify_prepared_habit_source_note_schema_key_v3
        return verify_prepared_habit_source_note_schema_key_v3(db,frame.envelope.authority.namespace,frame.envelope.identity.operation_id,key)
    from .current_method_learning_read_v3 import verify_prepared_action_schema_key_v3
    return verify_prepared_action_schema_key_v3(db, frame.envelope.authority.namespace, frame.envelope.identity.operation_id, key)


def _build_source_note_action_in_transaction_v1(db, *, frame, request, installed_readers):
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    from ..domains.d03.context import ContextProvider
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns, identity = frame.envelope.authority.namespace, frame.envelope.identity
    if identity.effect_id != source_note_effect_id_v1(ns, request.project_ref, identity.operation_id):
        raise ValueError("source-note root lost its actual derived effect identity")
    project, recipe, source, goal_atom = tuple(read.head(db, ref, required=True) for ref in
        (request.project_ref, request.recipe_ref, request.source_ref, request.goal_ref))
    for atom in (project, recipe, source, goal_atom):
        _adopted(db, read, atom)
    require_current_life_activation_original_v1(db, read=read)
    if (project.value["reality"] != "real_execution" or project.value["next_step"] != "source_note"
            or recipe.value != {"recipe_id": RECIPE_ID, "version": 1, "reality": "real_execution",
                "allowed_steps": ["source_note"], "preemptible": True}):
        raise MissingProductionOriginalV1("current_fixed_source_note_project_recipe")
    audiences = frame.envelope.authority.audience
    from .d08_life_admission_v1 import _source_rights
    _source_rights(db, read, life_semantic_source_refs_v1(goal_atom.value), audiences)
    for audience in audiences:
        for purpose in ("context", "consolidation"):
            read.source_family(db, (request.source_ref,), purpose=purpose, audience=audience)
            focus = read_qualified_focus_attention_ticket(frame.snapshot, ns, now=frame.now_utc,
                audience=audience, purpose=purpose)
            if (focus is None or focus.attention.ticket.concern_ref != request.project_ref
                    or request.source_ref not in focus.attention.ticket.source_refs):
                raise MissingProductionOriginalV1("actual_source_note_focus_attention")
            for version in (focus.attention.focus_version, focus.attention.ticket_version):
                _adopted(db, read, read.head(db, version.key, required=True))
    build = read_installed_d11_life_build_v1(installed_readers.package_root, installed_readers.manifest_digest)
    goal = _decode("d08.goal.v1", goal_atom.value)
    artifact_ref = life_artifact_ref_v1(ns, identity.effect_id)
    predicate = goal.satisfaction_predicate
    if (goal.state != "active" or predicate.kind != "artifact_verified"
            or predicate.observation_provider != POSTCONDITION_ID
            or dict(predicate.parameters) != {"artifact_ref": artifact_ref, "input_digest": canonical_digest(source.value),
                "build_digest": build["postcondition_build_digest"]}
            or predicate.valid_from > frame.now_utc
            or predicate.valid_until is not None and predicate.valid_until <= frame.now_utc):
        raise MissingProductionOriginalV1("actual_source_note_goal_postcondition")
    entity_key, action_key, cancel_key = _keys(ns, identity.activity_id, identity.operation_id, request)
    for key in (action_key, cancel_key):
        if read.head(db, key).revision:
            raise ValueError("source-note root identity already exists")
    entity_atom = read.head(db, entity_key, required=True)
    _adopted(db, read, entity_atom)
    _source_rights(db, read, life_semantic_source_refs_v1(entity_atom.value), audiences)
    entity = EntityAnchor(**_tuple_payload(entity_atom.value, "creation_evidence_refs"))
    if (entity.kind not in {"activity", "object"} or entity.status != "active"
            or entity.owner_scope != "persona:" + ns.persona_id or request.project_ref not in entity.creation_evidence_refs):
        raise MissingProductionOriginalV1("actual_source_note_project_entity")
    roles = []
    scope = LifeSemanticScopeV1(ns, request.project_ref, request.source_ref, entity_key.token,
        entity.entity_id, action_key.name, goal.goal_id, (), audiences, frame.now_utc)
    role_request = scope.role_request()
    for atom in read.complete_inventory(db, "d03.role_binding"):
        if atom.valid:
            role = RoleBinding(**_tuple_payload(atom.value, "norm_refs", "source_refs"))
            if scope.role_applies(role):
                _adopted(db, read, atom)
                if role.source_refs:
                    for audience in audiences:
                        for purpose in ("context", "consolidation"):
                            read.source_family(db, role.source_refs, purpose=purpose, audience=audience)
            roles.append(role)
    selected_atom = read.head(db, request.role_binding_ref, required=True)
    selected = RoleBinding(**_tuple_payload(selected_atom.value, "norm_refs", "source_refs"))
    if (selected.target_entity_ref != entity.entity_id or selected.subject_persona_ref != "persona:" + ns.persona_id
            or selected.group_ref is not None or selected.scene_ref is not None
            or not selected.applies_to(RoleBindingRequest("persona:" + ns.persona_id, entity.entity_id, None, None,
                "source_note", "consolidation", frame.now_utc, True))):
        raise MissingProductionOriginalV1("actual_exact_target_source_note_role")
    resolution = _context_provider(db, read).resolve_role_binding(role_request, tuple(roles))
    if resolution.status != "complete":
        raise MissingProductionOriginalV1("actual_source_note_role_catalogue_binding")
    rules = []
    for atom in read.complete_inventory(db, "d05.boundary_rule"):
        if atom.valid:
            rule = BoundaryRule(**boundary_payload(atom.value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"))
            if scope.boundary_applies(rule):
                _adopted(db, read, atom)
                if rule.source_refs:
                    for audience in audiences:
                        for purpose in ("context", "consolidation"):
                            read.source_family(db, rule.source_refs, purpose=purpose, audience=audience)
            rules.append(rule)
    for audience in audiences:
        boundary = RelationshipProvider().provide_required_check(subject_persona_ref="persona:" + ns.persona_id,
            target_entity_ref=entity.entity_id, action_kind="source_note", audience_scope=audience,
            scene_ref=None, at_time=frame.now_utc, rules=tuple(rules), coverage_complete=True)
        if boundary.result != "pass":
            raise MissingProductionOriginalV1("actual_source_note_boundary")
    profile, state, reservations = installed_readers.body_readers._current_body(db, read)
    policies = db.execute("SELECT policy_id,version FROM d02_fixed_body_policies_v1 WHERE bot=? AND persona=? AND status='active'",
        ns.as_tuple).fetchall()
    eligible = [installed_readers.body_readers.body_quote_authority.policy(db, ns, ref, version) for ref, version in policies]
    eligible = [p for p in eligible if p.work_kind == WORK_KIND and p.profile == profile]
    if len(eligible) != 1:
        raise MissingProductionOriginalV1("actual_fixed_source_note_body_policy")
    from ..domains.d02 import BodyDomain
    if BodyDomain().check_work_start(state, reservations, additional_cost=eligible[0].component.fixed_cost).status != "clear":
        raise MissingProductionOriginalV1("actual_source_note_body_availability")
    action = _intent(db, frame, request, installed_readers)
    schema = ActionSchemaRecord.bind(action, ActionSchema(action.schema_id, action.action_kind, False, action.required_checks))
    schema_key = AtomKey(action_key.owner, "d08.action_schema.v1", schema.schema_ref)
    if read.head(db, schema_key).revision:
        raise ValueError("source-note schema identity already exists")
    # Read-plan materialization records absent output keys, including this
    # command-bound schema key, before the command can produce any write.
    if schema_key not in {v.key for v in frame.snapshot.versions}:
        raise MissingProductionOriginalV1("actual_source_note_schema_absence")
    cancel = ActionCancellationState.for_action(action, state="active", actor=frame.envelope.authority.actor,
        source_refs=action.source_refs, operation_id=identity.operation_id)
    writes = (GraphWrite(action_key, plain_v1(action)), GraphWrite(schema_key, plain_v1(schema)), GraphWrite(cancel_key, plain_v1(cancel)))
    provider = GoalExecutionProvider()
    stage = stage_result_v1(frame, "d08", "prepare_source_note_action", request, writes=writes,
        provenance={"source_note_target_entity_ref": request.target_entity_ref, "source_note_role_binding_ref": request.role_binding_ref,
            "source_note_project_ref": request.project_ref, "source_note_recipe_ref": request.recipe_ref, "source_note_goal_ref": request.goal_ref},
        proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0], frame.snapshot)
    return SourceNoteActionStageV1(stage)


def record_source_note_action_after_cas_v1(db, *, frame, staged, receipt, issuer):
    from .d11_life_preparation_v1 import _record
    primary = staged.stage
    if primary.operation_kind=="prepare_current_habit_source_note_action_v1":
        from .d10_habit_v1 import record_habit_source_note_action_after_cas_v1
        return record_habit_source_note_action_after_cas_v1(db,frame=frame,staged=staged,receipt=receipt,issuer=issuer)
    payload = json.loads(primary.original_payload_json)
    selected = primary.operation_kind == "prepare_selected_source_note_action_v2"
    request = PrepareSourceNoteActionRequestV1(**(payload["provenance"]["derived_request"] if selected else payload["request"]))
    writes = primary.proposals[0].typed_writes
    versions = {v.key: v.revision for v in receipt.write_versions}
    if set(versions) != {w.key for w in writes}:
        raise ValueError("source-note root receipt does not contain exactly its three actual writes")
    action_write = next(w for w in writes if w.key.type_name == "d08.action_intent.v1")
    identity = frame.envelope.identity
    read = CurrentDomainReadV1(frame)
    context_commitments = []
    from .d04_root_original_store_v1 import _receipt
    for ref in (request.target_entity_ref, request.role_binding_ref, request.project_ref):
        atom = read.head(db, ref, required=True)
        operation = _adopted(db, read, atom)
        context_commitments.append((ref, atom.revision, canonical_digest(atom.value), operation,
            canonical_digest(_receipt(db, primary.namespace, operation))))
    original = SourceNoteActionOriginalV1(action_write.key.token, canonical_digest(action_write.value), identity.operation_id,
        identity.activity_id, identity.effect_id, request.project_ref, request.recipe_ref, request.source_ref,
        request.goal_ref, frame.envelope.authority.audience, request.target_entity_ref, request.role_binding_ref,
        tuple(context_commitments),
        tuple((w.key.token, versions[w.key], canonical_digest(w.value)) for w in writes), canonical_digest(receipt))
    if selected:
        proof = payload["provenance"]
        from dataclasses import asdict
        original = SelectedSourceNoteActionOriginalV2(**{**asdict(original),
            "audiences": original.audiences, "context_commitments": original.context_commitments,
            "write_commitments": original.write_commitments, "schema": "d08.selected-source-note-action-original.v2",
            "decision_ref": proof["selected_decision_ref"], "decision_digest": proof["selected_decision_digest"],
            "preparation_original_ref": proof["preparation_original_ref"],
            "preparation_original_digest": proof["preparation_original_digest"]})
    return _record(db, issuer=issuer, namespace=primary.namespace, kind="source_note_action",
        ref="life-root:" + identity.operation_id, operation_id=identity.operation_id, value=original)


def require_source_note_action_original_v1(db, *, namespace, action_intent_ref, issuer,
        frame=None, installed_bundle=None, body_quote_authority=None):
    from .d11_life_preparation_v1 import TABLE, _read
    from .current_life_numeric_native_read_v3 import read_bound_native_life_action_refs_v3
    handled,rows=read_bound_native_life_action_refs_v3(db,namespace,action_intent_ref)
    if not handled:
        from .ordinary_source_note_habit_classification_v3 import read_bound_ordinary_source_note_action_refs_v3
        handled,rows=read_bound_ordinary_source_note_action_refs_v3(db,namespace,action_intent_ref)
    if not handled:
        from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_action_refs_v3
        handled,rows=read_bound_life_model_action_refs_v3(db,namespace,action_intent_ref)
    if not handled:
        rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='source_note_action' "
            "AND json_extract(payload_json,'$.action_intent_ref')=?", (*namespace.as_tuple,action_intent_ref)).fetchall()
    if len(rows) != 1:
        raise MissingProductionOriginalV1("actual_source_note_root_original")
    raw, operation = _read(db, issuer=issuer, namespace=namespace, kind="source_note_action", ref=rows[0][0])
    if raw.get("schema")=="d08.habit-source-note-action-original.v1":
        from .d10_habit_v1 import require_habit_source_note_original_v1
        return require_habit_source_note_original_v1(db,namespace=namespace,raw=raw,operation=operation,issuer=issuer,frame=frame)
    original = source_note_action_original_from_wire_v1(raw)
    from .d04_root_original_store_v1 import _receipt
    receipt = _receipt(db, namespace, operation)
    if (operation != original.action_operation_id or canonical_digest(receipt) != original.receipt_digest
            or {(v.key.token, v.revision) for v in receipt.write_versions} != {(r, v) for r, v, _ in original.write_commitments}):
        raise ValueError("source-note root signature loses its real atomic Graph receipt")
    for ref, revision, digest in original.write_commitments:
        from .current_life_numeric_native_read_v3 import read_bound_native_numeric_history_v3
        handled,history=read_bound_native_numeric_history_v3(db,ref,revision,('value', 'valid', 'event_bot', 'event_persona', 'event_session', 'event_id'))
        if not handled:
            from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_history_v3
            handled,history=read_bound_life_model_history_v3(db,ref,revision,('value', 'valid', 'event_bot', 'event_persona', 'event_session', 'event_id'))
        if not handled:
            from .natural_producer_qualification_v1 import _producer_original_point_v3
            history = _producer_original_point_v3(db,table="graph_history",
                columns=("value","valid","event_bot","event_persona","event_session","event_id"),
                key_columns=("token","revision"),key=(ref,revision),legacy_reader=lambda:db.execute(
                    "SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
                    (ref,revision)).fetchone())
        if (history is None or history[1:] != (1, *namespace.as_tuple, original.activity_id, operation)
                or canonical_digest(json.loads(history[0])) != digest):
            raise ValueError("source-note root loses one actual producing-event member")
    for ref, revision, digest, producing_operation, receipt_digest in original.context_commitments:
        producing_receipt = _receipt(db, namespace, producing_operation)
        from .current_life_numeric_native_read_v3 import read_bound_native_numeric_history_v3
        handled,row=read_bound_native_numeric_history_v3(db,ref,revision,('value', 'valid', 'event_bot', 'event_persona', 'event_session', 'event_id'))
        if not handled:
            from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_history_v3
            handled,row=read_bound_life_model_history_v3(db,ref,revision,('value', 'valid', 'event_bot', 'event_persona', 'event_session', 'event_id'))
        if not handled:
            from .natural_producer_qualification_v1 import _producer_original_point_v3
            row = _producer_original_point_v3(db,table="graph_history",
                columns=("value","valid","event_bot","event_persona","event_session","event_id"),
                key_columns=("token","revision"),key=(ref,revision),legacy_reader=lambda:db.execute(
                    "SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
                    (ref,revision)).fetchone())
        if (canonical_digest(producing_receipt) != receipt_digest
                or (ref, revision) not in {(v.key.token, v.revision) for v in producing_receipt.write_versions}
                or row is None or row[1:] != (1, *namespace.as_tuple, producing_receipt.activity_id, producing_operation)
                or canonical_digest(json.loads(row[0])) != digest):
            raise ValueError("source-note context loses its genuine prior producing receipt/history")
    if type(original) is SelectedSourceNoteActionOriginalV2 and frame is not None:
        if frame.envelope.authority.namespace != namespace:
            raise ValueError("selected SourceNote Body frame has another namespace")
        return require_current_selected_source_note_action_v2(db, frame=frame,
            action_original_ref=rows[0][0], issuer=issuer, installed_bundle=installed_bundle,
            body_quote_authority=body_quote_authority)[0]
    return original


SELECTED_OPERATION_V2 = "prepare_selected_source_note_action_v2"


@dataclass(frozen=True, slots=True, kw_only=True)
class SelectedSourceNoteActionOriginalV2(SourceNoteActionOriginalV1):
    decision_ref: str
    decision_digest: str
    preparation_original_ref: str
    preparation_original_digest: str
    schema: str = "d08.selected-source-note-action-original.v2"

    def __post_init__(self):
        from dataclasses import fields
        values = {field.name: getattr(self, field.name) for field in fields(SourceNoteActionOriginalV1)}
        values["schema"] = "d08.source-note-action-original.v2"
        SourceNoteActionOriginalV1(**values)
        if (self.schema != "d08.selected-source-note-action-original.v2"
                or AtomKey.from_token(self.decision_ref).type_name != "d08.decision_record.v2"
                or not self.preparation_original_ref.startswith("d08-current:")
                or any(len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
                    for value in (self.decision_digest, self.preparation_original_digest))):
            raise ValueError("selected SourceNote original requires its actual Decision/preparation commitments")


@dataclass(frozen=True, slots=True)
class InstalledSelectedSourceNoteActionReadersV2:
    legacy_readers: object
    personal_readers: object

    def __post_init__(self):
        from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
        from .d08_personal_candidate_v1 import InstalledPersonalCandidateReadersV1
        if type(self.legacy_readers) is not InstalledD08ProductionReadersV1 or type(self.personal_readers) is not InstalledPersonalCandidateReadersV1:
            raise TypeError("selected SourceNote requires the actual installed Body and personal original readers")

    @property
    def issuer(self):
        return self.legacy_readers.issuer

    @property
    def installed_bundle(self):
        return self.personal_readers.bundle


def stage_prepare_source_note_action_in_transaction_v1(db, *, frame, request, installed_readers):
    # The registered factory rejects private Self issuance for this bare Owner
    # operation. Selected Self uses the separately registered closed selector.
    return _build_source_note_action_in_transaction_v1(db, frame=frame, request=request, installed_readers=installed_readers)


def stage_prepare_selected_source_note_action_v2(db, *, frame, request, installed_readers):
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1, read_selected_personal_adapter_v1
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    if type(request) is not ConsumePersonalDecisionRequestV1 or type(installed_readers) is not InstalledSelectedSourceNoteActionReadersV2:
        raise TypeError("selected SourceNote consumes only actual Decision/preparation locators")
    from .joint_window_management_v1 import require_managed_joint_preparation_v1,attach_managed_joint_preparation_v1
    managed=require_managed_joint_preparation_v1(db,frame=frame,operation_kind='prepare_selected_source_note_action_v2',request=request)
    prepared, chosen, original = read_selected_personal_adapter_v1(db, frame=frame, request=request,
        installed_readers=installed_readers.personal_readers)
    if type(chosen.binding) is not SourceNoteCandidateBindingV1:
        raise ValueError("selected SourceNote cannot consume an Artifact candidate")
    future, identity = chosen.future_identity, frame.envelope.identity
    if (identity.activity_id, identity.operation_id, identity.attempt_id, identity.effect_id,
            frame.envelope.parent_budget_lease_ref, frame.envelope.deadline_utc) != (
            future.activity_id, future.action_operation_id, future.attempt_id, future.effect_id,
            future.parent_budget_lease_ref, future.deadline_utc):
        raise ValueError("selected SourceNote changed its actual chosen future effect/attempt/deadline/root identity")
    binding = chosen.binding
    derived = PrepareSourceNoteActionRequestV1(binding.project_ref, binding.recipe_ref, binding.source_ref,
        binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref)
    legacy = _build_source_note_action_in_transaction_v1(db, frame=frame, request=derived,
        installed_readers=installed_readers.legacy_readers)
    read = CurrentDomainReadV1(frame)
    decision = read.head(db, request.decision_ref, required=True)
    proof = dict(json.loads(legacy.stage.original_payload_json)["provenance"])
    proof.update(derived_request=derived, selected_decision_ref=decision.key.token,
        selected_decision_digest=canonical_digest(decision.value), preparation_original_ref="d08-current:" + original["original_digest"][:48],
        preparation_original_digest=original["original_digest"], selected_candidate=chosen)
    provider = GoalExecutionProvider()
    stage = stage_result_v1(frame, "d08", SELECTED_OPERATION_V2, request,
        writes=legacy.stage.proposals[0].typed_writes, provenance=proof,
        proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0], frame.snapshot)
    return attach_managed_joint_preparation_v1(SourceNoteActionStageV1(stage),managed)


def selected_source_note_binding_from_originals_v2(db, *, namespace, request):
    """Readonly exact locator path for the fixed dispatcher; full current gates run in W01."""
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1, SourceNoteCandidateBindingV1
    from ..domains.d08.personal_plan_v1 import DECISION_TYPE, decode_personal_plan_type_v1
    if type(request) is not ConsumePersonalDecisionRequestV1:
        raise TypeError("SourceNote dispatcher requires its exact selected locator")
    actual = read_adopted_domain_operation_v1(db, namespace, request.prepared_candidates_operation_id)
    if actual is None or actual["operation_kind"] != "prepare_personal_candidates_v1":
        raise MissingProductionOriginalV1("actual_selected_SourceNote_preparation_original")
    prepared = decode_typed_production_value_v1(actual["payload"]["provenance"]["prepared_candidates"], PreparedPersonalCandidateSetV1)
    if request.decision_ref != prepared.future_decision_ref:
        raise ValueError("selected SourceNote decision differs from its actual preparation")
    from .domain_background_read_v3 import background_graph_head_v3,background_history_v3
    row = background_graph_head_v3(db,namespace,request.decision_ref)
    if row is None or row[2] != 1:
        raise MissingProductionOriginalV1("actual_selected_SourceNote_Decision")
    history = background_history_v3(db,request.decision_ref,row[0],columns=("event_id","value","valid"))
    if history != (prepared.selection_operation_id, row[1], 1):
        raise ValueError("selected SourceNote Decision has another actual adoption occurrence")
    decision = decode_personal_plan_type_v1(DECISION_TYPE, json.loads(row[1]))
    chosen = tuple(candidate for candidate in prepared.candidates if candidate.future_identity.action_ref == decision.chosen_action_ref)
    if len(chosen) != 1 or type(chosen[0].binding) is not SourceNoteCandidateBindingV1 or chosen[0].eligibility.hard_status != "eligible":
        raise MissingProductionOriginalV1("actual_unique_eligible_selected_SourceNote_binding")
    return prepared, chosen[0], actual


def read_plan_selected_source_note_action_v2(db, *, namespace, activity_id, operation_id, request,
        now_utc, audiences, installed_readers):
    from .d08_personal_candidate_v1 import read_plan_personal_candidates_v1
    personal = read_plan_personal_candidates_v1(db, namespace=namespace, activity_id=activity_id,
        request=request, operation_id=operation_id, installed_readers=installed_readers.personal_readers)
    prepared, chosen, original = selected_source_note_binding_from_originals_v2(db, namespace=namespace, request=request)
    binding = chosen.binding
    if (activity_id, operation_id) != (chosen.future_identity.activity_id, chosen.future_identity.action_operation_id):
        raise ValueError("selected SourceNote read plan changed its actual chosen future activity/operation")
    derived = PrepareSourceNoteActionRequestV1(binding.project_ref, binding.recipe_ref, binding.source_ref,
        binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref)
    action = read_plan_source_note_action_v1(db, namespace=namespace, activity_id=activity_id,
        operation_id=operation_id, request=derived, now_utc=now_utc, audiences=audiences)
    from .d01_production_operations_v1 import production_read_plan_v1
    return production_read_plan_v1(tuple(dict.fromkeys((*personal.fixed_type_ids, *action.fixed_type_ids))),
        tuple(dict.fromkeys((*personal.exact_keys, *action.exact_keys))),
        tuple(dict.fromkeys((*personal.source_roots, *action.source_roots))),
        tuple(dict.fromkeys((*personal.required_original_refs, *action.required_original_refs, request.decision_ref))))


def selected_source_note_action_schema_key_v2(db, *, frame, request, installed_readers):
    from .d08_personal_candidate_v1 import read_selected_personal_adapter_v1
    prepared, chosen, original = read_selected_personal_adapter_v1(db, frame=frame, request=request,
        installed_readers=installed_readers.personal_readers)
    binding = chosen.binding
    from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
    if type(binding) is not SourceNoteCandidateBindingV1:
        raise ValueError("selected SourceNote schema cannot borrow an Artifact candidate")
    derived = PrepareSourceNoteActionRequestV1(binding.project_ref, binding.recipe_ref, binding.source_ref,
        binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref)
    return source_note_schema_key_v1(db, frame=frame, request=derived, installed_readers=installed_readers.legacy_readers)

from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1


def read_current_selected_source_note_evidence_v2(db, *, namespace, actor_ref, parent_budget_lease_ref, now_utc, max_query_rows, action_original_ref, issuer):
    """Accept only this action's actual own three-head adoption, never a generic stale-read exception."""
    from .d11_life_preparation_v1 import _read
    from ..runtime_contracts import NamespaceId
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1, PreparedPersonalCandidateV1, SourceNoteCandidateBindingV1
    from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
    saved = _read(db, issuer=issuer, namespace=namespace, kind="source_note_action", ref=action_original_ref)
    if saved is None:
        raise MissingProductionOriginalV1("actual_signed_selected_SourceNote_action_original")
    root = source_note_action_original_from_wire_v1(saved[0])
    if type(root) is not SelectedSourceNoteActionOriginalV2:
        raise ValueError("Self SourceNote Body/Life cannot borrow a legacy bare Owner action original")
    ns = namespace
    actual = read_adopted_domain_operation_v1(db, ns, saved[1])
    if actual is None or actual["operation_kind"] != SELECTED_OPERATION_V2 or saved[1] != root.action_operation_id:
        raise ValueError("selected SourceNote original lost its actual named W01 producer")
    request = decode_typed_production_value_v1(actual["payload"]["request"], ConsumePersonalDecisionRequestV1)
    prepared, chosen, preparation = selected_source_note_binding_from_originals_v2(db, namespace=ns, request=request)
    proof = actual["payload"]["provenance"]
    if (root.decision_ref, root.decision_digest, root.preparation_original_ref, root.preparation_original_digest) != (
            proof["selected_decision_ref"], proof["selected_decision_digest"],
            "d08-current:" + preparation["original_digest"][:48], preparation["original_digest"]):
        raise ValueError("selected SourceNote own adoption changed its actual Decision/preparation proof")
    if decode_typed_production_value_v1(proof["selected_candidate"], PreparedPersonalCandidateV1) != chosen:
        raise ValueError("selected SourceNote action changed its actual chosen candidate")
    binding, future = chosen.binding, chosen.future_identity
    if type(binding) is not SourceNoteCandidateBindingV1 or (root.project_ref, root.recipe_ref, root.input_source_ref,
            root.goal_ref, root.target_entity_ref, root.role_binding_ref) != (
            binding.project_ref, binding.recipe_ref, binding.source_ref, binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref):
        raise ValueError("selected SourceNote action parameters differ from its actual chosen binding")
    if ((root.activity_id, root.action_operation_id, root.effect_id, parent_budget_lease_ref) != (
            future.activity_id, future.action_operation_id, future.effect_id, future.parent_budget_lease_ref)
            or actor_ref != prepared.actor_ref or now_utc >= future.deadline_utc):
        raise ValueError("selected SourceNote own adoption lost its actual Self/effect/root/deadline")
    from .owner_source_note_need_v1 import read_owner_source_note_need_original_v2, require_owner_note_legal_task_job_progress_v1
    from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1
    prepare_request = decode_typed_production_value_v1(preparation["payload"]["request"],PrepareCurrentPersonalCandidatesRequestV1)
    owner_need = read_owner_source_note_need_original_v2(db,namespace=ns,original_ref=prepare_request.need_qualification_original_ref)
    owner_task_auth, owner_task_head = None, None
    if owner_need is not None:
        from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
        from .owner_source_note_task_execution_v1 import read_owner_source_note_task_responsibility_v2
        from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2
        from .jobs import get_job
        from .d11_types import job_graph_write
        value = owner_need[0]
        task = get_job(db,value.task_job_head.key.name)
        continuation = decode_typed_production_value_v1(dict(task.continuation),OwnerSourceNoteTaskContinuationV2)
        saved_responsibility = read_owner_source_note_task_responsibility_v2(db,namespace=ns,
            original_ref=continuation.responsibility_ref,issuer=issuer)
        if (saved_responsibility is None or continuation.authorization_original_ref != value.authorization_original_ref
                or continuation.authorization_original_digest != value.authorization_original_digest
                or continuation.responsibility_digest != value.responsibility_digest):
            raise ValueError("selected SourceNote action has another actual independent Owner task lineage")
        responsibility, owner_task_auth, _ = saved_responsibility
        if (responsibility.digest != value.responsibility_digest or responsibility.self_entity_ref != actor_ref
                or task.activity_id != future.activity_id or task.budget_ref != future.parent_budget_lease_ref
                or task.cancel_epoch or continuation.cancel_generation):
            raise ValueError("selected SourceNote current Owner task changed its actual Self/activity/root/cancellation")
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(value.task_job_head.key.token,)).fetchone()
        if row is None or row[2] != 1 or json.loads(row[1]) != job_graph_write(task).value:
            raise MissingProductionOriginalV1("actual_selected_Owner_task_current_job_projection")
        owner_task_head = GraphVersion(value.task_job_head.key,row[0])
    original_reads = {version.key: version.revision for version in actual["read_versions"]}
    if owner_task_head is not None:
        previous_revision = original_reads.get(owner_task_head.key)
        previous = None if previous_revision is None else db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (owner_task_head.key.token,previous_revision)).fetchone()
        if previous is None or previous[1] != 1:
            raise ValueError("selected Owner task action lacks its actual original task read")
        require_owner_note_legal_task_job_progress_v1(db,namespace=ns,
            previous_head=GraphVersion(owner_task_head.key,previous_revision),previous_digest=canonical_digest(json.loads(previous[0])),
            current_head=owner_task_head,current_digest=canonical_digest(json.loads(row[1])),
            authorization_original_ref=owner_task_auth.original_ref,responsibility_digest=responsibility.digest,max_rows=max_query_rows)
    writes = {version.key: version.revision for version in actual["receipt"].write_versions}
    expected = {AtomKey.from_token(ref): (revision, digest) for ref, revision, digest in root.write_commitments}
    if (set(writes) != set(expected) or len(writes) != 3
            or {key.type_name for key in writes} != {"d08.action_intent.v1", "d08.action_schema.v1", "d08.action_cancellation.v1"}
            or any(original_reads.get(key) != 0 or revision != 1 for key, revision in writes.items())):
        raise ValueError("selected SourceNote owns only its exact three absent-to-revision-one W01 heads")
    for key, revision in writes.items():
        archived = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (key.token, revision)).fetchone()
        head = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if (archived is None or archived[0] != root.action_operation_id or archived[2] != 1
                or expected[key] != (revision, canonical_digest(json.loads(archived[1])))
                or head != (revision, archived[1], 1)):
            raise ValueError("selected SourceNote own adoption differs from its actual receipt/history/current head")
    body_own_keys = set()
    body_saved = _read(db, issuer=issuer, namespace=ns, kind="life_body_preparation",
        ref="life-body:d02-life-body:" + root.action_operation_id)
    if body_saved is not None:
        from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
        body = life_body_preparation_original_from_wire_v1(body_saved[0])
        body_actual = read_adopted_domain_operation_v1(db, ns, body_saved[1])
        body_key = AtomKey.from_token(body.reservation_ref)
        if (body_actual is None or body_actual["operation_kind"] != "prepare_source_note_body"
                or body_saved[1] != body.body_prepare_operation_id
                or (body.action_intent_ref, body.action_intent_digest, body.action_operation_id, body.activity_id, body.effect_id) != (
                    root.action_intent_ref, root.action_intent_digest, root.action_operation_id, root.activity_id, root.effect_id)
                or body_key.type_name != "d02.reservation.v1" or NamespaceId.from_key(body_key) != ns
                or body.reservation_revision != 1 or original_reads.get(body_key, 0) != 0
                or body_actual["receipt"].write_versions != (GraphVersion(body_key, 1),)
                or canonical_digest(body_actual["receipt"]) != body.receipt_digest
                or not any(version.key == body_key and version.revision == 0 for version in body_actual["read_versions"])):
            raise ValueError("selected SourceNote accepts only its actual one-reservation Body adoption")
        archived = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1", (body_key.token,)).fetchone()
        head = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (body_key.token,)).fetchone()
        if (archived is None or archived[0] != body.body_prepare_operation_id or archived[2] != 1
                or canonical_digest(json.loads(archived[1])) != body.reservation_digest
                or head != (1, archived[1], 1)):
            raise ValueError("selected SourceNote Body reservation lost its exact receipt/history/current head")
        for page in actual["payload"]["query_coverage"]:
            if any(decode_typed_production_value_v1(row, GraphVersion).key == body_key for row in page["row_versions"]):
                raise ValueError("selected SourceNote Body reservation was already present before action adoption")
        body_own_keys.add(body_key)
    for key, revision in original_reads.items():
        if key in writes or key in body_own_keys or owner_task_head is not None and key == owner_task_head.key:
            continue
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        before = None if revision == 0 else db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (key.token, revision)).fetchone()
        if (revision == 0 and row is not None or revision > 0 and (before is None or row != (revision, *before))):
            raise MissingProductionOriginalV1("selected_SourceNote_other_current_read_changed:" + key.type_name)
    for page in actual["payload"]["query_coverage"]:
        if not page["complete"] or page["continuation_ref"] is not None:
            raise ValueError("selected SourceNote cannot recover from incomplete original query coverage")
        expected_rows = {decode_typed_production_value_v1(row, GraphVersion).key.token:
            decode_typed_production_value_v1(row, GraphVersion).revision for row in page["row_versions"]}
        current_page = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT ?",
            (*ns.as_tuple, page["type_id"], max_query_rows + 1)).fetchall()
        if len(current_page) > max_query_rows:
            raise MissingProductionOriginalV1("selected_SourceNote_current_query_exceeds_bound:" + page["type_id"])
        current_rows = dict(current_page)
        if owner_task_head is not None and owner_task_head.key.token in expected_rows:
            expected_rows[owner_task_head.key.token] = owner_task_head.revision
        for key in set(writes) | body_own_keys:
            current_rows.pop(key.token, None)
        if current_rows != expected_rows:
            raise MissingProductionOriginalV1("selected_SourceNote_other_negative_query_changed:" + page["type_id"])
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    # The preparation Need is authenticated in its original, with the live
    # authorization closure rechecked without recreating already adopted action absence.
    if owner_task_auth is not None:
        from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
        ids = owner_source_note_task_ids_v1(ns,owner_task_auth.cause.owner_operation_id)
        if (binding.project_ref,binding.recipe_ref,binding.source_ref,binding.goal_ref,binding.target_entity_ref,binding.role_binding_ref) != (
                owner_task_auth.request.project_ref,owner_task_auth.request.recipe_ref,owner_task_auth.request.body_source_ref,
                ids['goal_key'].token,owner_task_auth.request.target_entity_ref,owner_task_auth.request.role_binding_ref):
            raise ValueError("selected SourceNote action cannot switch its independent signed Owner task")
        return root,chosen,prepared,actual,owner_task_auth
    need_source = read_adopted_domain_operation_v1(db, ns, request.prepared_candidates_operation_id)
    from .d08_personal_candidate_v1 import _personal_ingress_need_locator_v1
    from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1
    prepare_request = decode_typed_production_value_v1(need_source["payload"]["request"], PrepareCurrentPersonalCandidatesRequestV1)
    found_need = _personal_ingress_need_locator_v1(db, ns, prepare_request)
    if found_need is None:
        raise MissingProductionOriginalV1("actual_selected_SourceNote_Need_lineage")
    cycle = get_job(db, AtomKey.from_token(found_need[0].cycle_job_ref).name)
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1
    if type(continuation) is not ForegroundSourceNoteContinuationV1:
        raise ValueError("selected SourceNote own adoption has another actual task responsibility")
    auth = read_source_note_task_authorization_v1(db, namespace=ns,
        original_ref=continuation.authorization_original_ref, issuer=issuer)
    if auth is None:
        raise MissingProductionOriginalV1("actual_selected_SourceNote_current_Owner_authorization")
    if (binding.project_ref, binding.recipe_ref, binding.source_ref, binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref) != (
            auth[0].request.project_ref, auth[0].request.recipe_ref, auth[0].request.body_source_ref,
            auth[0].request.goal_ref, auth[0].request.target_entity_ref, auth[0].request.role_binding_ref):
        raise ValueError("selected SourceNote own adoption cannot switch its signed task authorization")
    return root, chosen, prepared, actual,None


def require_current_selected_source_note_action_v2(db, *, frame, action_original_ref, issuer, installed_bundle, body_quote_authority=None):
    """Actual Frame authorization around the shared current evidence validator."""
    root, chosen, prepared, actual, owner_auth = read_current_selected_source_note_evidence_v2(db,
        namespace=frame.envelope.authority.namespace,actor_ref=frame.envelope.authority.actor,
        parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref,now_utc=frame.now_utc,max_query_rows=frame.limits.max_query_rows,
        action_original_ref=action_original_ref,issuer=issuer)
    if owner_auth is not None:
        if body_quote_authority is None: raise MissingProductionOriginalV1('actual_selected_Owner_task_current_Body_quote_authority')
        from .owner_source_note_task_v1 import require_current_owner_source_note_task_authorization_v2
        require_current_owner_source_note_task_authorization_v2(db,frame=frame,authorization=owner_auth,
            issuer=issuer,installed_bundle=installed_bundle,body_quote_authority=body_quote_authority)
    else:
        from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
        from .source_note_foreground_v1 import require_current_source_note_authorization_v1
        from .d08_personal_candidate_v1 import _personal_ingress_need_locator_v1
        from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from .jobs import get_job
        from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
        preparation = read_adopted_domain_operation_v1(db,root_namespace:=frame.envelope.authority.namespace,
            actual['payload']['request']['prepared_candidates_operation_id'])
        request = decode_typed_production_value_v1(preparation['payload']['request'],PrepareCurrentPersonalCandidatesRequestV1)
        need = _personal_ingress_need_locator_v1(db,root_namespace,request)
        continuation = foreground_cycle_from_wire_v1(get_job(db,AtomKey.from_token(need[0].cycle_job_ref).name).continuation)
        saved = read_source_note_task_authorization_v1(db,namespace=root_namespace,original_ref=continuation.authorization_original_ref,issuer=issuer)
        require_current_source_note_authorization_v1(db,frame=frame,authorization=saved[0],issuer=issuer,installed_bundle=installed_bundle)
    return root,chosen,prepared,actual


def source_note_action_parts_v1(*, namespace, identity, request, goal, parameter_digest):
    """Pure Action/schema tail; current Source/Role/Owner qualification stays in compiler."""
    entity_key, action_key, cancel_key = _keys(namespace, identity.activity_id, identity.operation_id, request)
    artifact_ref = life_artifact_ref_v1(namespace, identity.effect_id)
    checks = tuple(RequiredCheckSpec(kind, provider, "persona:" + namespace.persona_id, action_key.name,
        "consolidation", life_criterion_ref_v1(kind), (VersionedRef(life_criterion_ref_v1(kind), 1),)) for kind, provider in PAIRS)
    action = ActionIntent(action_key.name, 1, goal.goal_id, (), entity_key.name, "source_note", "consolidation", "internal",
        parameter_digest, identity, "d10.source-note.action.v1", checks, goal.satisfaction_predicate,
        (artifact_ref,), None, (request.source_ref,))
    schema = ActionSchemaRecord.bind(action, ActionSchema(action.schema_id, action.action_kind, False, checks))
    return action, schema, (action_key, AtomKey(action_key.owner, "d08.action_schema.v1", schema.schema_ref), cancel_key)


def source_note_schema_key_from_action_v1(namespace, action):
    schema = ActionSchemaRecord.bind(action, ActionSchema(action.schema_id, action.action_kind, False, action.required_checks))
    return AtomKey(Owner("activity", *namespace.as_tuple, action.identity.activity_id), "d08.action_schema.v1", schema.schema_ref)
