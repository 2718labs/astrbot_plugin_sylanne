"""The actual W01 root of one installed internal source-note action."""
from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03.context import EntityAnchor, RoleBinding, RoleBindingRequest, _tuple_payload
from ..domains.d05.relationship import BoundaryRule, RelationshipProvider, _tuple_payload as boundary_payload
from ..domains.d07.qualified_attention_read import read_qualified_focus_attention_ticket
from ..domains.d08.execution import (ActionIntent, ActionSchema, ActionSchemaRecord,
    ActionCancellationState, GoalExecutionProvider, RequiredCheckSpec, _decode)
from ..graph_types import AtomKey, GraphWrite, Owner
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
    entity_key, action_key, _ = _keys(ns, identity.activity_id, identity.operation_id, request)
    goal = _decode("d08.goal.v1", goal_atom.value)
    build = read_installed_d11_life_build_v1(installed_readers.package_root, installed_readers.manifest_digest)
    artifact_ref = life_artifact_ref_v1(ns, identity.effect_id)
    checks = tuple(RequiredCheckSpec(kind, provider, "persona:" + ns.persona_id, action_key.name,
        "consolidation", life_criterion_ref_v1(kind), (VersionedRef(life_criterion_ref_v1(kind), 1),)) for kind, provider in PAIRS)
    return ActionIntent(action_key.name, 1, goal.goal_id, (), entity_key.name, "source_note", "consolidation", "internal",
        canonical_digest((project.value, recipe.value, source.value, artifact_ref, build)), identity,
        "d10.source-note.action.v1", checks, goal.satisfaction_predicate, (artifact_ref,), None, (request.source_ref,))


def source_note_schema_key_v1(db, *, frame, request, installed_readers):
    action = _intent(db, frame, request, installed_readers)
    schema = ActionSchemaRecord.bind(action, ActionSchema(action.schema_id, action.action_kind, False, action.required_checks))
    return AtomKey(Owner("activity", *frame.envelope.authority.namespace.as_tuple, action.identity.activity_id),
        "d08.action_schema.v1", schema.schema_ref)


def stage_prepare_source_note_action_in_transaction_v1(db, *, frame, request, installed_readers):
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
    payload = json.loads(primary.original_payload_json)
    request = PrepareSourceNoteActionRequestV1(**payload["request"])
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
    return _record(db, issuer=issuer, namespace=primary.namespace, kind="source_note_action",
        ref="life-root:" + identity.operation_id, operation_id=identity.operation_id, value=original)


def require_source_note_action_original_v1(db, *, namespace, action_intent_ref, issuer):
    from .d11_life_preparation_v1 import TABLE, _read
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='source_note_action' "
        "AND json_extract(payload_json,'$.action_intent_ref')=?", (*namespace.as_tuple, action_intent_ref)).fetchall()
    if len(rows) != 1:
        raise MissingProductionOriginalV1("actual_source_note_root_original")
    raw, operation = _read(db, issuer=issuer, namespace=namespace, kind="source_note_action", ref=rows[0][0])
    original = source_note_action_original_from_wire_v1(raw)
    from .d04_root_original_store_v1 import _receipt
    receipt = _receipt(db, namespace, operation)
    if (operation != original.action_operation_id or canonical_digest(receipt) != original.receipt_digest
            or {(v.key.token, v.revision) for v in receipt.write_versions} != {(r, v) for r, v, _ in original.write_commitments}):
        raise ValueError("source-note root signature loses its real atomic Graph receipt")
    for ref, revision, digest in original.write_commitments:
        history = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
            (ref, revision)).fetchone()
        if (history is None or history[1:] != (1, *namespace.as_tuple, original.activity_id, operation)
                or canonical_digest(json.loads(history[0])) != digest):
            raise ValueError("source-note root loses one actual producing-event member")
    for ref, revision, digest, producing_operation, receipt_digest in original.context_commitments:
        producing_receipt = _receipt(db, namespace, producing_operation)
        row = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
            (ref, revision)).fetchone()
        if (canonical_digest(producing_receipt) != receipt_digest
                or (ref, revision) not in {(v.key.token, v.revision) for v in producing_receipt.write_versions}
                or row is None or row[1:] != (1, *namespace.as_tuple, producing_receipt.activity_id, producing_operation)
                or canonical_digest(json.loads(row[0])) != digest):
            raise ValueError("source-note context loses its genuine prior producing receipt/history")
    return original
