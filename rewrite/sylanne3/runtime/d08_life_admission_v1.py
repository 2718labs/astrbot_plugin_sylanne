"""Installed source-note admission from current originals and one mixed journal head.

Five fixed providers produce candidates. Only the signed post-CAS original
admits the once execution, after another actual current-original read.
"""
from dataclasses import dataclass, replace, fields
import hashlib
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner, GraphVersion
from ..runtime_contracts import (NamespaceId, FenceScope, VersionedRef, QueryEpoch, CheckReceipt,
    canonical_digest, canonical_serialize)
from .domain_production_contracts_v1 import (CurrentOperationFrameV1, ProductionQueryCoverageV1,
    ProductionPolicyRefV1, ProductionOriginalRefV1)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .issuers import D11BudgetJobIssuer, D02ResourceIssuer
from .d11_life_scope_v1 import LifeSemanticScopeV1, life_semantic_source_refs_v1
from .d01_life_activation_original_v1 import require_current_life_activation_original_v1
from ..authority_service.d11_life_execution_inventory_v1 import (LifeExecutionInventoryV1,
    verify_life_execution_inventory_v1, life_execution_inventory_to_wire_v1)

PAIRS = (("role_binding","d03.role_binding"),("boundary","d05.boundary"),
    ("source_grant","d06.source_grant"),("commitment_conflict","d08.commitment_conflict"),
    ("dispatch_budget","d11.dispatch_budget"))
LIFE_ADMISSION_TYPES_V1 = ("d01.persona_activation.v1","d03.entity_anchor","d03.role_binding",
    "d05.boundary_rule","d07.focus.v1","d07.attention_ticket.v1","d08.goal.v1","d08.commitment.v1",
    "d08.action_intent.v1","d08.action_schema.v1","d08.action_outcome.v1","d08.action_cancellation.v1",
    "d02.body_state.v1","d02.body_profile.v1","d02.reservation.v1","d12.active_scheme_head.v1")

def life_criterion_ref_v1(kind, *, recipe_id="d10.source-note.v1"):
    if kind not in dict(PAIRS): raise ValueError("closed source-note check kind required")
    if recipe_id not in {"d10.source-note.v1", "artifact_draft_v1"}:
        raise ValueError("closed registered Life recipe criteria required")
    return recipe_id + ":" + kind


@dataclass(frozen=True, slots=True)
class DraftActionRootV1:
    action_intent_ref: str
    action_intent_digest: str
    action_operation_id: str
    activity_id: str
    effect_id: str
    project_ref: str
    recipe_ref: str
    input_source_ref: str
    audiences: tuple[str, ...]
    target_entity_ref: str
    role_binding_ref: str
    context_commitments: tuple[tuple[str, int, str, str, str], ...]
    write_commitments: tuple[tuple[str, int, str], ...]
    receipt_digest: str
    schema: str = "d08.artifact-draft-action-original.v1"

    def __post_init__(self):
        if (self.schema != "d08.artifact-draft-action-original.v1" or not self.audiences
                or not 1 <= len(self.write_commitments) <= 32
                or len({row[0] for row in self.write_commitments}) != len(self.write_commitments)
                or {row[0] for row in self.context_commitments} !=
                   {self.target_entity_ref, self.role_binding_ref, self.project_ref}):
            raise ValueError("draft action requires actual adopted Action/context receipt membership")


def draft_action_root_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(DraftActionRootV1)}:
        raise ValueError("draft action original closed fields differ")
    value = dict(raw)
    value["audiences"] = tuple(value["audiences"])
    for name in ("context_commitments", "write_commitments"):
        value[name] = tuple(tuple(row) for row in value[name])
    result = DraftActionRootV1(**value)
    if plain_v1(result) != raw:
        raise ValueError("draft action original is not canonical")
    return result


@dataclass(frozen=True,slots=True)
class DraftActionRootSkeletonV1:
    project: object
    recipe: object
    action_intent: object
    input_source: object
    input_access: object
    activity_id: str
    effect_id: str
    attempt_id: str
    operation_id: str
    audiences: tuple[str,...]
    target: object
    content: object
    postcondition_build_digest: str

    def __post_init__(self):
        from .d11_life_contract_v1 import LifeInputRefV1
        from .d11_artifact_draft_contract_v1 import DraftFileTargetV1,FrozenDraftContentV1
        if (any(type(getattr(self,name)) is not LifeInputRefV1 for name in
                ("project","recipe","action_intent","input_source","input_access"))
                or type(self.target) is not DraftFileTargetV1 or type(self.content) is not FrozenDraftContentV1
                or type(self.audiences) is not tuple or not self.audiences):
            raise TypeError("actual Action root skeleton requires exact adopted typed commitments")
        from .d11_offline_originals_v1 import _digest
        _digest(self.postcondition_build_digest)


def record_draft_action_root_v1(db, *, frame, plan, issuer):
    from .foreground_command_writer_outputs_v3 import record_foreground_writer_life_v3
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from .d11_life_preparation_v1 import _record, _draft_plan_current_v1
    from .d04_root_original_store_v1 import _receipt
    from .d08_personal_plan_v1 import DraftActionRootSkeletonV2
    if type(plan) not in {RegisteredDraftFilePlanV3, DraftActionRootSkeletonV1, DraftActionRootSkeletonV2}:
        raise TypeError('actual final draft plan or adopted Action-only skeleton required')
    read = CurrentDomainReadV1(frame)
    action, _ = _draft_plan_current_v1(db, read, plan)
    entities = tuple((atom for atom in read.complete_inventory(db, 'd03.entity_anchor') if atom.valid and atom.value['entity_id'] == action.target_ref))
    if len(entities) != 1:
        raise MissingProductionOriginalV1('actual_draft_project_entity')
    entity = entities[0]
    roles = tuple((atom for atom in read.complete_inventory(db, 'd03.role_binding') if atom.valid and atom.value['target_entity_ref'] == action.target_ref and (atom.value['subject_persona_ref'] == 'persona:' + frame.envelope.authority.namespace.persona_id) and (atom.value['group_ref'] is None) and (atom.value['scene_ref'] is None)))
    if len(roles) != 1:
        raise MissingProductionOriginalV1('actual_unambiguous_draft_project_role')
    context = []
    for atom in (entity, roles[0], read.head(db, plan.project.ref, required=True)):
        operation = _adopted(db, read, atom)
        receipt = _receipt(db, frame.envelope.authority.namespace, operation)
        context.append((atom.key.token, atom.revision, canonical_digest(atom.value), operation, canonical_digest(receipt)))
    receipt = _receipt(db, frame.envelope.authority.namespace, plan.operation_id)
    from ..runtime_storage_v3 import read_graph_history_v3
    from .current_method_learning_read_v3 import method_post_commit_atom_digest_v3
    writes = []
    for version in receipt.write_versions:
        row = read_graph_history_v3(db, version.key.token, version.revision, columns=('event_id', 'value', 'valid'), namespace=frame.envelope.authority.namespace.as_tuple)
        if row is None or row[0] != plan.operation_id or row[2] != 1:
            raise ValueError('draft action actual producing member history differs')
        atom = read.head(db, version.key, required=True)
        if atom.revision != version.revision or _adopted(db, read, atom) != plan.operation_id:
            raise ValueError('draft action producing member revision or value differs')
        writes.append((version.key.token, version.revision, method_post_commit_atom_digest_v3(db, atom)))
    root = DraftActionRootV1(plan.action_intent.ref, plan.action_intent.digest, plan.operation_id, plan.activity_id, plan.effect_id, plan.project.ref, plan.recipe.ref, plan.input_source.ref, plan.audiences, entity.key.token, roles[0].key.token, tuple(context), tuple(writes), canonical_digest(receipt))
    return record_foreground_writer_life_v3(db, issuer=issuer, namespace=frame.envelope.authority.namespace, kind='draft_action', ref='life-draft-root:' + plan.operation_id, operation_id=plan.operation_id, value=root, recorder=record_draft_action_root_v1, frame=frame, actual_receipt=None)


def require_draft_action_root_v1(db, *, namespace, action_intent_ref, issuer):
    from .d11_life_preparation_v1 import TABLE, _read
    from .d04_root_original_store_v1 import _receipt
    rows = db.execute("SELECT original_ref FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='draft_action' AND json_extract(payload_json,'$.action_intent_ref')=?",
        (*namespace.as_tuple, action_intent_ref)).fetchall()
    if len(rows) != 1:
        raise MissingProductionOriginalV1("actual_signed_artifact_draft_action_root")
    raw, operation = _read(db, issuer=issuer, namespace=namespace, kind="draft_action", ref=rows[0][0])
    root = draft_action_root_from_wire_v1(raw)
    receipt = _receipt(db, namespace, operation)
    if (operation != root.action_operation_id or canonical_digest(receipt) != root.receipt_digest
            or {(v.key.token, v.revision) for v in receipt.write_versions} !=
               {(ref, revision) for ref, revision, digest in root.write_commitments}):
        raise ValueError("draft signed root lost its actual adopted Action receipt")
    for ref, revision, digest in root.write_commitments:
        row = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (ref, revision)).fetchone()
        if row is None or row[0] != operation or row[2] != 1 or canonical_digest(json.loads(row[1])) != digest:
            raise ValueError("draft root lost its actual immutable history member")
    return root

class InstalledLifeAdmissionReaderV1:
    def __init__(self, *, issuer, resource_issuer, body_quote_authority, execution_inventory, scope):
        from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
        if (type(issuer) is not D11BudgetJobIssuer or type(resource_issuer) is not D02ResourceIssuer
                or type(body_quote_authority) is not D02BodyQuoteAuthority
                or type(execution_inventory) is not LifeExecutionInventoryV1 or type(scope) is not FenceScope):
            raise TypeError("Life requires its real installed issuers, signed inventory and actual fence")
        verify_life_execution_inventory_v1(execution_inventory,issuer)
        if (execution_inventory.anchor != scope.pinned_anchor
                or execution_inventory.permit_digest != canonical_digest(scope.permit)):
            raise ValueError("Life mixed inventory differs from actual frozen fence")
        self.issuer,self.resource_issuer,self.body_quote_authority=issuer,resource_issuer,body_quote_authority
        self.execution_inventory,self.scope=execution_inventory,scope

@dataclass(frozen=True, slots=True)
class LifeActionAdmissionOriginalV1:
    binding_digest: str
    plan_digest: str
    action_operation_id: str
    prepare_operation_id: str
    prepare_receipt_digest: str
    graph_revision: int
    graph_epoch: int
    read_refs: tuple[str, ...]
    frame_template_json: str
    evidence_json: str
    schema: str = "d08.life-action-admission.v1"

    def __post_init__(self):
        if self.schema != "d08.life-action-admission.v1" or self.action_operation_id == self.prepare_operation_id:
            raise ValueError("closed root/prepare Life admission required")
        if type(self.read_refs) is not tuple or not self.read_refs or len(self.read_refs)>1024 or len(set(self.read_refs))!=len(self.read_refs):
            raise ValueError("Life admission requires exact explicit current read closure")
        for ref in self.read_refs: AtomKey.from_token(ref)
        from .d11_offline_originals_v1 import _digest
        for value in (self.binding_digest,self.plan_digest,self.prepare_receipt_digest): _digest(value)
        for text in (self.frame_template_json,self.evidence_json):
            if canonical_serialize(json.loads(text)) != text: raise ValueError("Life admission bytes changed")


def _adopted(db,read,atom):
    from .current_method_learning_read_v3 import read_bound_method_adoption_v3
    handled, event_id = read_bound_method_adoption_v3(db, atom)
    if handled:
        read.committed_operation(db, event_id)
        return event_id
    from ..runtime_storage_v3 import read_graph_history_v3
    history = read_graph_history_v3(
        db, atom.key.token, atom.revision, columns=("event_id", "value", "valid"))
    if history is None or history[1:] != (canonical_serialize(atom.value), 1):
        raise MissingProductionOriginalV1("actual_life_input_adoption:" + atom.key.type_name)
    read.committed_operation(db, history[0])
    return history[0]


def _context_provider(db,read):
    from ..domains.d03.context import ContextProvider
    from .d12_current_domain_selection_v1 import read_current_domain_selection_v1
    from .d12_domain_scheme_compile_v1 import CONTEXT_SCHEME_FIELD,D12ContextSchemeCandidateV1
    from .d12_compiled_candidate_store_v1 import verify_d12_domain_candidate_v1
    ns=read.frame.envelope.authority.namespace
    version,compiled,receipt=read_current_domain_selection_v1(db,ns,domain="d03",field_name=CONTEXT_SCHEME_FIELD)
    read.head(db,version.key,required=True)
    if receipt is None: raise MissingProductionOriginalV1("adopted_life_context_role_catalogue")
    from .domain_background_read_v3 import background_point_v3
    row=background_point_v3(db,table='graph_d12_domain_candidates_v1',columns=('candidate_json','candidate_sha256'),key_columns=('bot','persona','candidate_ref'),key=(*ns.as_tuple,receipt.candidate_ref),
        legacy_reader=lambda:db.execute('SELECT candidate_json,candidate_sha256 FROM graph_d12_domain_candidates_v1 WHERE bot=? AND persona=? AND candidate_ref=?',(*ns.as_tuple,receipt.candidate_ref)).fetchone())
    if row is None or hashlib.sha256(row[0].encode()).hexdigest()!=row[1]: raise ValueError("actual Context candidate changed")
    raw=json.loads(row[0])
    if raw.pop("$type",None)!="sylanne3.runtime.d12_domain_scheme_compile_v1.D12ContextSchemeCandidateV1": raise ValueError("wrong Context candidate type")
    namespace=raw.pop("namespace")
    if namespace.pop("$type",None)!="sylanne3.runtime_contracts.NamespaceId": raise ValueError("wrong Context namespace")
    for key in ("field_names","roles","norms"): raw[key]=tuple(raw[key])
    candidate=D12ContextSchemeCandidateV1(namespace=NamespaceId(**namespace),**raw)
    if canonical_serialize(candidate)!=row[0] or not verify_d12_domain_candidate_v1(db,ns,candidate,receipt):
        raise ValueError("actual Context catalogue adoption proof changed")
    provider=ContextProvider()
    provider.compile_scheme({"schema":candidate.schema,"roles":candidate.roles,"norms":candidate.norms},read.frame.snapshot)
    return provider


def _source_rights(db,read,refs,audiences):
    if refs:
        for purpose in ("context","consolidation"):
            for audience in audiences: read.source_family(db,tuple(refs),purpose=purpose,audience=audience)


def evaluate_life_admission_v1(db,*,frame,prepared,reader,new_work):
    from .d11_life_preparation_v1 import _plan_current,_verify_life_current_budget_v1
    from ..domains.d03.context import EntityAnchor,RoleBinding,RoleBindingRequest,_tuple_payload
    from ..domains.d05.relationship import BoundaryRule,RelationshipProvider,_tuple_payload as d05_payload
    from ..domains.d08.execution import _decode,ActionSchemaRecord,ActionSchema
    from ..domains.d07.qualified_attention_read import read_qualified_focus_attention_ticket
    from .d02_life_effect_v1 import require_life_body_quote_v1
    from ..domains.d02 import BodyState,BodyProfile,_reservation
    from .d02_production_operations_v1 import SettledBodyEffectPolicyV1
    from .d11_life_contract_v1 import life_work_kind_v1
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    if type(reader) is not InstalledLifeAdmissionReaderV1 or not db.in_transaction: raise TypeError("actual installed Life admission reader required")
    read=CurrentDomainReadV1(frame);read.check(db)
    b,p=prepared.binding,prepared.plan;ns=b.namespace
    if type(new_work) is not bool:
        raise TypeError("Life admission requires its explicit new-work or historical purpose")
    if new_work and type(p) is RegisteredDraftFilePlanV3:
        from .d08_project_control_v1 import project_control_basis_v1, require_current_project_plan_for_new_work_v1
        _, _, plan_head, _, _ = project_control_basis_v1(db, namespace=ns, project_ref=p.project.ref)
        read.head(db, plan_head.key, required=True)
        require_current_project_plan_for_new_work_v1(db, namespace=ns, plan_ref=plan_head.key.token)
    work_kind = life_work_kind_v1(b)
    if (reader.execution_inventory.namespace!=ns or reader.execution_inventory.authority_id!=b.authority_id
            or reader.execution_inventory.installation_id!=b.installation_id or reader.execution_inventory.manifest_digest!=b.manifest_digest):
        raise ValueError("Life mixed inventory installation differs")
    action,source=_plan_current(db,read,p)
    from .d08_source_note_action_v1 import require_source_note_action_original_v1
    root=(require_draft_action_root_v1(db,namespace=ns,action_intent_ref=p.action_intent.ref,issuer=reader.issuer)
        if type(p) is RegisteredDraftFilePlanV3 else
        require_source_note_action_original_v1(db,namespace=ns,action_intent_ref=p.action_intent.ref,issuer=reader.issuer))
    if type(p) is RegisteredDraftFilePlanV3:
        from .d11_life_preparation_v1 import require_draft_authority_inputs_v1
        require_draft_authority_inputs_v1(db, frame=frame, plan=p, issuer=reader.issuer)
    if (root.action_operation_id,root.action_intent_digest,root.activity_id,root.effect_id,root.project_ref,root.recipe_ref,root.input_source_ref,root.audiences) != (b.operation_id,p.action_intent.digest,b.activity_id,b.effect_id,p.project.ref,p.recipe.ref,p.input_source.ref,p.audiences):
        raise ValueError("Life signed root original differs from exact frozen registered plan")
    if _adopted(db,read,read.head(db,p.action_intent.ref,required=True)) != b.operation_id:
        raise ValueError("Life action is not its actual committed root operation")
    read.committed_operation(db,b.operation_id)
    if action.purpose!="consolidation" or action.effect_scope!=(b.artifact_ref,) or {(s.check_kind,s.provider_id) for s in action.required_checks}!=set(PAIRS):
        raise ValueError("fixed internal source-note action/check/effect scope differs")
    if any(s.criteria_version!=life_criterion_ref_v1(s.check_kind, recipe_id=p.recipe_id) or s.subject_ref!="persona:"+ns.persona_id
            or s.action_ref!=action.action_id or s.purpose!=action.purpose for s in action.required_checks):
        raise ValueError("Life Action does not name installed fixed source-note criteria")
    inventories={kind:read.complete_inventory(db,kind) for kind in LIFE_ADMISSION_TYPES_V1}
    from .d11_life_scope_v1 import DraftLifeSemanticScopeV1
    scope_kind=DraftLifeSemanticScopeV1 if type(p) is RegisteredDraftFilePlanV3 else LifeSemanticScopeV1
    scope=scope_kind(ns,p.project.ref,p.input_source.ref,root.target_entity_ref,
        action.target_ref,action.action_id,action.goal_ref,action.commitment_refs,p.audiences,frame.now_utc)
    def typed(kind, *, action_ids=None):
        result=[]
        for atom in inventories[kind]:
            if atom.valid:
                value=_decode(kind,atom.value)
                relevant=(value.action_id in action_ids if action_ids is not None
                    else scope.includes(kind,atom.key,atom.value))
                if relevant:
                    _adopted(db,read,atom)
                    _source_rights(db,read,life_semantic_source_refs_v1(atom.value),p.audiences)
                    result.append((atom,value))
        return result
    schemas=tuple(record for _,record in typed("d08.action_schema.v1") if record.action_ref==action.action_id)
    if len(schemas)!=1 or schemas[0]!=ActionSchemaRecord.bind(action,ActionSchema(action.schema_id,action.action_kind,False,action.required_checks)):
        raise MissingProductionOriginalV1("exact_adopted_life_action_schema")
    for ref,revision,digest,operation,receipt_digest in root.context_commitments:
        atom=read.head(db,ref,required=True)
        if (atom.revision,canonical_digest(atom.value),_adopted(db,read,atom)) != (revision,digest,operation):
            raise ValueError("Life current project context differs from its actual frozen root original")
    entities=[]
    for atom in inventories["d03.entity_anchor"]:
        if atom.valid:
            entity=EntityAnchor(**_tuple_payload(atom.value,"creation_evidence_refs"))
            if atom.key.token==root.target_entity_ref and entity.entity_id==action.target_ref:
                _adopted(db,read,atom)
                _source_rights(db,read,life_semantic_source_refs_v1(atom.value),p.audiences)
                entities.append(entity)
    if (len(entities)!=1 or entities[0].kind not in {"activity","object"} or entities[0].status!="active"
            or p.project.ref not in entities[0].creation_evidence_refs or entities[0].owner_scope!="persona:"+ns.persona_id):
        raise MissingProductionOriginalV1("adopted_internal_life_activity_entity")
    activation=require_current_life_activation_original_v1(db,read=read)
    owner=read.head(db,b.owner_grant_ref,required=True)
    if (activation.namespace!=ns or activation.activation_generation!=b.activation_generation
            or activation.owner_grant_revision!=b.owner_grant_revision or activation.owner_grant_id!=owner.value["grant_id"]):
        raise ValueError("Life actual D01 activation/current Owner differs")
    roles=[]
    selected_role=None
    for atom in inventories["d03.role_binding"]:
        if atom.valid:
            role=RoleBinding(**_tuple_payload(atom.value,"norm_refs","source_refs"))
            if atom.key.name!=role.role_binding_id or atom.revision!=role.binding_version: raise ValueError("Life role original version differs")
            if scope.role_applies(role):
                _adopted(db,read,atom);_source_rights(db,read,role.source_refs,p.audiences)
            roles.append(role)
            if atom.key.token==root.role_binding_ref: selected_role=role
    if (selected_role is None or selected_role.target_entity_ref!=action.target_ref
            or selected_role.group_ref is not None or selected_role.scene_ref is not None or not scope.role_applies(selected_role)):
        raise MissingProductionOriginalV1("actual_root_selected_internal_role_binding")
    resolution=_context_provider(db,read).resolve_role_binding(scope.role_request(),tuple(roles))
    if resolution.status!="complete": raise MissingProductionOriginalV1("current_life_internal_role_binding")
    rules=[]
    for atom in inventories["d05.boundary_rule"]:
        if atom.valid:
            rule=BoundaryRule(**d05_payload(atom.value,"source_refs","communicated_refs","acknowledged_refs","exception_refs"))
            if atom.key.name!=rule.rule_id or atom.revision!=rule.scope_version: raise ValueError("Life boundary version differs")
            if scope.boundary_applies(rule):
                _adopted(db,read,atom);_source_rights(db,read,rule.source_refs,p.audiences)
            rules.append(rule)
    for audience in p.audiences:
        boundary=RelationshipProvider().provide_required_check(subject_persona_ref="persona:"+ns.persona_id,target_entity_ref=action.target_ref,
            action_kind=action.action_kind,audience_scope=audience,scene_ref=None,at_time=frame.now_utc,rules=tuple(rules),coverage_complete=True)
        if boundary.result!="pass": raise MissingProductionOriginalV1("current_life_internal_boundary")
    _source_rights(db,read,(p.input_source.ref,),p.audiences)
    attention=None
    for purpose in ("context","consolidation"):
        for audience in p.audiences:
            focus=read_qualified_focus_attention_ticket(frame.snapshot,ns,now=frame.now_utc,audience=audience,purpose=purpose)
            if (focus is None or focus.attention.ticket.concern_ref!=p.project.ref or p.input_source.ref not in focus.attention.ticket.source_refs
                    or not focus.attention.ticket.eligible or not focus.attention.ticket.resources_available or focus.attention.ticket.cancel_refs):
                raise MissingProductionOriginalV1("current_adopted_life_focus_attention")
            attention=focus.attention
    for version in (attention.focus_version,attention.ticket_version): _adopted(db,read,read.head(db,version.key,required=True))
    goals=tuple(goal for _,goal in typed("d08.goal.v1") if goal.goal_id==action.goal_ref)
    if len(goals)!=1 or goals[0].state!="active" or goals[0].satisfaction_predicate!=action.success_predicate:
        raise MissingProductionOriginalV1("current_active_life_goal")
    commitments=typed("d08.commitment.v1")
    if not set(action.commitment_refs)<= {c.commitment_id for _,c in commitments}: raise MissingProductionOriginalV1("current_life_commitments")
    for atom,c in commitments:
        if c.fulfillment_state not in {"fulfilled","withdrawn"} and c.commitment_id not in action.commitment_refs:
            raise MissingProductionOriginalV1("unresolved_other_commitment_requires_life_conflict_resolution")
    cancellations=typed("d08.action_cancellation.v1")
    own_cancels=tuple(c for _,c in cancellations if c.action_id==action.action_id)
    if len(own_cancels)!=1 or own_cancels[0].state!="active" or own_cancels[0].action_digest!=canonical_digest(action):
        raise MissingProductionOriginalV1("current_active_life_action_cancellation_head")
    actions=typed("d08.action_intent.v1")
    outcomes=typed("d08.action_outcome.v1",action_ids={other.action_id for _,other in actions})
    if any(o.action_id==action.action_id for _,o in outcomes): raise MissingProductionOriginalV1("life_action_already_has_actual_outcome")
    for atom,other in actions:
        if other.action_id!=action.action_id and other.target_ref==action.target_ref and not any(o.action_id==other.action_id for _,o in outcomes):
            raise MissingProductionOriginalV1("conflicting_current_life_action")
    own=tuple(e for e in reader.execution_inventory.entries if e.family=="life" and e.execution_id==b.execution_id)
    for e in reader.execution_inventory.entries:
        if e in own:
            if (e.binding_digest!=b.digest or e.operation_id!=b.operation_id or e.effect_id!=b.effect_id
                    or e.claim_sequence!=json.loads(prepared.requirements_json)["execution_seq"]+1
                    or e.terminal_sequence is not None and e.terminal_sequence!=e.claim_sequence+1):
                raise ValueError("Life mixed own progress is not its exact actual once chain")
        elif e.status in {"claimed","unknown","dispatch_unresolved"}:
            raise MissingProductionOriginalV1("actual_unresolved_mixed_execution:"+e.execution_id)
    _verify_life_current_budget_v1(db,prepared,reader.issuer,reader.resource_issuer,frame.now_utc,for_execution=not own)
    contract,quote,body=require_life_body_quote_v1(db,prepared=prepared,issuer=reader.issuer,resource_issuer=reader.resource_issuer,body_quote_authority=reader.body_quote_authority)
    reservation=_reservation(read.head(db,contract.reservation_ref,required=True).value)
    part=next(c for c in body.components if c.component_id==contract.component_id)
    if (reservation.quote_id!=body.quote_id or reservation.effect_id!=b.effect_id or reservation.status!="reserved"
            or any(item.startswith(part.component_id+"|") for item in reservation.settled_components) or reservation.remaining_cost<part.fixed_cost
            or read.head(db,contract.settlement_ref).revision!=0): raise MissingProductionOriginalV1("current_unsettled_life_body_reservation")
    states=tuple(a for a in inventories["d02.body_state.v1"] if a.valid and a.value["profile_id"]==body.profile_id)
    profiles=tuple(a for a in inventories["d02.body_profile.v1"] if a.valid and a.value["profile_id"]==body.profile_id)
    if len(states)!=1 or len(profiles)!=1: raise MissingProductionOriginalV1("current_life_body_profile_state")
    state=BodyState(**states[0].value);raw=dict(profiles[0].value);raw["namespace"]=NamespaceId(**raw["namespace"])
    raw["applicable_axes"],raw["work_kinds"]=tuple(raw["applicable_axes"]),tuple(raw["work_kinds"]);profile=BodyProfile(**raw)
    if state.version!=states[0].revision or profile.version!=profiles[0].revision or profile.namespace!=ns or work_kind not in profile.work_kinds:
        raise ValueError("current Life Body qualification changed")
    policy=db.execute("SELECT revision,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
        (*ns.as_tuple,contract.effect_policy_ref)).fetchone()
    if policy is None: raise MissingProductionOriginalV1("current_installed_life_body_effect_policy")
    reader.issuer._signer.verify("d11.d02-production-policy.v1",policy[1],policy[3]);raw=json.loads(policy[1])
    if canonical_digest(raw)!=policy[2] or canonical_serialize(raw)!=policy[1]: raise ValueError("Life Body policy original changed")
    raw["namespace"]=NamespaceId(**raw["namespace"]);policy_value=SettledBodyEffectPolicyV1(**raw)
    if ((policy_value.profile_id,policy_value.work_kind,policy_value.component_id)!=(body.profile_id,work_kind,part.component_id)
            or not any(pin.policy_ref==contract.effect_policy_ref and pin.revision==policy[0] and pin.policy_digest==policy[2] for pin in frame.installed_policy_refs)):
        raise MissingProductionOriginalV1("pinned_current_life_body_effect_policy")
    deadline=min(frame.envelope.deadline_utc,attention.ticket.valid_until,quote.valid_until_utc,
        resolution.valid_until if resolution.valid_until is not None else frame.envelope.deadline_utc)
    if deadline<=frame.now_utc: raise MissingProductionOriginalV1("current_life_admission_validity")
    versions=tuple(VersionedRef(a.key.token,a.revision) for a in frame.snapshot.atoms)
    query_versions=tuple(VersionedRef("life-query:"+page.type_id,page.epoch.revision) for page in frame.query_coverage)
    current=(*versions,*query_versions,VersionedRef("life-execution:"+reader.execution_inventory.anchor.execution_journal_id,reader.execution_inventory.anchor.execution_seq),
        VersionedRef(b.quote_id,b.quote_version))
    specs=tuple(replace(s,required_input_versions=(*current,VersionedRef(life_criterion_ref_v1(s.check_kind, recipe_id=p.recipe_id),1))) for s in action.required_checks)
    checks=tuple(CheckReceipt(s.check_kind,s.subject_ref,s.action_ref,s.purpose,s.required_input_versions,"full","pass",deadline,s.provider_id) for s in specs)
    return {"schema":"d08.life-admission-evidence.v1","checks":plain_v1(checks),"effective_specs":plain_v1(specs),
        "focus_ref":attention.focus_version.key.token,"ticket_ref":attention.ticket_version.key.token,
        "execution_inventory":life_execution_inventory_to_wire_v1(reader.execution_inventory),
        "criteria_build_digest":b.algorithm_build_digest,"valid_until_utc":deadline}


def _frame_template(frame):
    return canonical_serialize({"envelope_json":canonical_serialize(frame.envelope),"owner_guard":plain_v1(frame.owner_guard),
        "types":[p.type_id for p in frame.query_coverage],"policies":plain_v1(frame.installed_policy_refs),
        "originals":plain_v1(frame.observed_originals)})


def rebuild_life_admission_frame_v1(db,*,prepared,template_json,now_utc):
    from .c02_bundle_codec import _decode
    from ..runtime_contracts import CommandEnvelope
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    from .d11_types import job_graph_write
    from .jobs import get_job
    template=json.loads(template_json);envelope=_decode(json.loads(template["envelope_json"]),CommandEnvelope)
    b=prepared.binding;epoch=NamespaceEpoch(*b.namespace.as_tuple,db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",b.namespace.as_tuple).fetchone()[0])
    keys={AtomKey.from_token(r.ref) for r in prepared.read_rows};keys.add(job_graph_write(get_job(db,b.job_id)).key)
    pages=[]
    for kind in template["types"]:
        rows=db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",(*b.namespace.as_tuple,kind)).fetchall()
        if len(rows)>128: raise MissingProductionOriginalV1("complete_current_life_inventory:"+kind)
        versions=tuple(GraphVersion(AtomKey.from_token(token),rev) for token,rev in rows);keys.update(v.key for v in versions)
        pages.append(ProductionQueryCoverageV1(QueryEpoch(b.namespace,kind,epoch.revision),kind,versions,True,None))
    atoms=[]
    for key in sorted(keys,key=lambda k:k.token):
        row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(key.token,)).fetchone()
        atoms.append(GraphAtom(key,row[0],json.loads(row[1]),bool(row[2])) if row else GraphAtom(key,0,{},False))
    snapshot=GraphSnapshot(tuple(atoms),(epoch,))
    envelope=replace(envelope,version_guard=replace(envelope.version_guard,read_versions=snapshot.versions,query_epochs=tuple(p.epoch for p in pages)))
    return CurrentOperationFrameV1(envelope,snapshot,now_utc,ProductionOwnerGuardV1(**template["owner_guard"]),b.activation_generation,
        tuple(pages),tuple(ProductionPolicyRefV1(**x) for x in template["policies"]),tuple(ProductionOriginalRefV1(x["kind"],x["original_ref"],x["original_digest"]) for x in template["originals"]))


def record_life_action_admission_after_cas_v1(db,*,preparation,prepared,receipt):
    from .d11_life_preparation_v1 import _record
    from .d04_root_original_store_v1 import _receipt
    if _receipt(db,prepared.binding.namespace,prepared.prepare_operation_id)!=receipt:
        raise ValueError("Life admission receipt is not the actual same-transaction CAS")
    template=_frame_template(preparation.frame)
    frame=rebuild_life_admission_frame_v1(db,prepared=prepared,template_json=template,now_utc=preparation.frame.now_utc)
    evidence=evaluate_life_admission_v1(db,frame=frame,prepared=prepared,reader=preparation.admission_reader,new_work=True)
    value=LifeActionAdmissionOriginalV1(prepared.binding.digest,prepared.binding.plan_digest,prepared.binding.operation_id,
        prepared.prepare_operation_id,canonical_digest(receipt),prepared.graph_revision,prepared.graph_epoch,
        tuple(a.key.token for a in frame.snapshot.atoms),template,canonical_serialize(evidence))
    return _record(db,issuer=preparation.admission_reader.issuer,namespace=prepared.binding.namespace,kind="action_admission",
        ref="d08-life-admission:"+prepared.binding.execution_id,operation_id=prepared.prepare_operation_id,value=value)


def require_current_life_action_admission_v1(db,*,prepared,reader,now_utc,frame=None):
    from .d11_life_preparation_v1 import _read
    original=_read(db,issuer=reader.issuer,namespace=prepared.binding.namespace,kind="action_admission",ref=prepared.admission_ref)
    if original is None or canonical_digest(original[0])!=prepared.admission_digest: raise MissingProductionOriginalV1("signed_life_action_admission")
    raw=dict(original[0]);raw["read_refs"]=tuple(raw["read_refs"])
    value=LifeActionAdmissionOriginalV1(**raw)
    if (value.binding_digest!=prepared.binding.digest or value.plan_digest!=prepared.binding.plan_digest
            or value.prepare_operation_id!=prepared.prepare_operation_id or value.graph_revision!=prepared.graph_revision or value.graph_epoch!=prepared.graph_epoch):
        raise ValueError("Life signed admission binding/CAS changed")
    from .d04_root_original_store_v1 import _receipt
    receipt=_receipt(db,prepared.binding.namespace,prepared.prepare_operation_id)
    if (canonical_digest(receipt)!=value.prepare_receipt_digest or receipt.invalidated_epochs!=(NamespaceEpoch(*prepared.binding.namespace.as_tuple,prepared.graph_epoch),)):
        raise ValueError("Life admission lost its actual E+1 commit receipt")
    from ..authority_service.d11_life_execution_inventory_v1 import life_execution_inventory_from_wire_v1
    evidence=json.loads(value.evidence_json)
    if set(evidence)!={"schema","checks","effective_specs","focus_ref","ticket_ref","execution_inventory","criteria_build_digest","valid_until_utc"} or evidence["schema"]!="d08.life-admission-evidence.v1":
        raise ValueError("Life signed admission evidence fields differ")
    verify_life_execution_inventory_v1(life_execution_inventory_from_wire_v1(evidence["execution_inventory"]),reader.issuer)
    if evidence["criteria_build_digest"]!=prepared.binding.algorithm_build_digest or {(c["check_kind"],c["issuer"]) for c in evidence["checks"]}!=set(PAIRS) or any(c["coverage"]!="full" or c["result"]!="pass" for c in evidence["checks"]):
        raise ValueError("Life signed admission is not the installed five-provider pass")
    if frame is None: frame=rebuild_life_admission_frame_v1(db,prepared=prepared,template_json=value.frame_template_json,now_utc=now_utc)
    evaluate_life_admission_v1(db,frame=frame,prepared=prepared,reader=reader,new_work=False)
    return value


def enrich_life_adoption_frame_v1(db,*,frame,prepared,issuer):
    from .d11_life_preparation_v1 import _read
    original=_read(db,issuer=issuer,namespace=prepared.binding.namespace,
        kind="action_admission",ref=prepared.admission_ref)
    raw=dict(original[0]);raw["read_refs"]=tuple(raw["read_refs"])
    value=LifeActionAdmissionOriginalV1(**raw)
    current=rebuild_life_admission_frame_v1(db,prepared=prepared,template_json=value.frame_template_json,now_utc=frame.now_utc)
    atoms={a.key:a for a in current.snapshot.atoms};atoms.update({a.key:a for a in frame.snapshot.atoms})
    snapshot=GraphSnapshot(tuple(atoms[k] for k in sorted(atoms,key=lambda x:x.token)),frame.snapshot.epochs)
    return replace(frame,snapshot=snapshot,query_coverage=current.query_coverage,installed_policy_refs=current.installed_policy_refs,
        envelope=replace(frame.envelope,version_guard=replace(frame.envelope.version_guard,read_versions=snapshot.versions,
            query_epochs=tuple(p.epoch for p in current.query_coverage))))
