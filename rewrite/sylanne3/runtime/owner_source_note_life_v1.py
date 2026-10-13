"""Selector-only Life plan/outcome producers for an actual Owner SourceNote task."""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1, ConsumePersonalDecisionRequestV1
from ..domains.d10 import LifeDomain
from ..graph_types import AtomKey, GraphVersion, Owner
from ..memory_types import access_key, SourceRecord
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskAuthorizationV2, owner_source_note_task_ids_v1
from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2, require_current_owner_source_note_task_authorization_v2
from .d08_source_note_action_v1 import (source_note_effect_id_v1, source_note_attempt_id_v1,
    require_source_note_action_original_v1, SelectedSourceNoteActionOriginalV2, selected_source_note_binding_from_originals_v2)
from .d02_life_body_preparation_v1 import (PrepareSourceNoteBodyRequestV1, LifeBodyPreparationOriginalV1,
    life_body_preparation_original_from_wire_v1)
from .d11_life_contract_v1 import (LifeInputRefV1, LifeBodyComponentContractV1, RegisteredLifePlanV2,
    RegisteredLifeOutcomeV2, D11LifeTerminalV1, life_artifact_ref_v1, life_from_wire_v1, WORK_KIND)
from .d11_life_preparation_v1 import (_read, record_registered_life_plan_v2,
    read_prepared_life_v1, PrepareCurrentLifeRequestV1)
from .d11_life_terminal_v1 import read_adopted_life_original_v1
from .d10_life_outcome_v2 import record_current_life_outcome_v2
from .d11_types import runtime_cost_settlement_key

PLAN_OPERATION = 'register_owner_source_note_life_plan_v1'
OUTCOME_OPERATION = 'register_owner_source_note_life_outcome_v1'
_READERS_KEY = object()


@dataclass(frozen=True, slots=True)
class RegisterOwnerSourceNoteLifePlanRequestV1:
    authorization_original_ref: str
    def __post_init__(self):
        if not self.authorization_original_ref.startswith('owner-source-note-authorization:'):
            raise ValueError('Owner Life plan selects its actual signed authorization')


@dataclass(frozen=True, slots=True)
class RegisterOwnerSourceNoteLifeOutcomeRequestV1:
    authorization_original_ref: str
    def __post_init__(self):
        if not self.authorization_original_ref.startswith('owner-source-note-authorization:'):
            raise ValueError('Owner Life outcome selects its actual signed authorization')


def owner_source_note_life_ids_v1(auth):
    if type(auth) is not OwnerSourceNoteTaskAuthorizationV2:
        raise TypeError('Owner Life IDs require its actual authorization')
    ns=auth.cause.namespace;ids=owner_source_note_task_ids_v1(ns,auth.cause.owner_operation_id)
    marker=ids['activity_id'].removeprefix('owner-note-task:')
    r=auth.request
    binding=SourceNoteCandidateBindingV1(ids['candidate_ref'],ids['node_id'],r.project_ref,r.recipe_ref,r.body_source_ref,
        ids['goal_key'].token,r.target_entity_ref,r.role_binding_ref)
    action_op='personal-source-note-action:'+canonical_digest((ns,ids['selection_operation_id'],binding))[:48]
    effect=source_note_effect_id_v1(ns,r.project_ref,action_op)
    action_key=AtomKey(Owner('activity',*ns.as_tuple,ids['activity_id']),'d08.action_intent.v1',
        'action:source-note:'+canonical_digest((ns,r.project_ref,action_op))[:48])
    plan_ref='owner-note-life-plan:'+marker;outcome_ref='owner-note-life-outcome:'+marker
    return {**ids,'binding':binding,'action_ref':action_key.token,'action_operation_id':action_op,
        'effect_id':effect,'attempt_id':source_note_attempt_id_v1(ns,r.project_ref,action_op),
        'body_operation_id':'d02-life-body:'+action_op,'action_original_ref':'life-root:'+action_op,
        'body_original_ref':'life-body:d02-life-body:'+action_op,'plan_ref':plan_ref,'plan_operation_id':plan_ref+':register',
        'outcome_ref':outcome_ref,'outcome_operation_id':outcome_ref+':register','prepare_operation_id':'d11-life-prepare:'+action_op,
        'advance_operation_id':'owner-note-life-advance:'+marker,'settle_operation_id':'owner-note-goal-settle:'+marker,
        'artifact_ref':life_artifact_ref_v1(ns,effect),
        'progress_ref':AtomKey(action_key.owner,'d10.life_progress.v1',effect).token}


def _head(db,ns,ref,versions):
    key=AtomKey.from_token(ref) if type(ref) is str else ref
    if NamespaceId.from_key(key)!=ns:raise ValueError('Owner Life head crossed namespace')
    row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
    if row is None or row[2]!=1:raise MissingProductionOriginalV1('actual_current_Owner_Life_head:'+key.type_name)
    versions[key]=row[0]
    return LifeInputRefV1(key.token,row[0],canonical_digest(json.loads(row[1]))),json.loads(row[1])


def _selected_action(db,*,auth,issuer,versions):
    ns=auth.cause.namespace;ids=owner_source_note_life_ids_v1(auth)
    root=require_source_note_action_original_v1(db,namespace=ns,action_intent_ref=ids['action_ref'],issuer=issuer)
    if (type(root) is not SelectedSourceNoteActionOriginalV2
            or (root.action_operation_id,root.activity_id,root.effect_id,root.project_ref,root.recipe_ref,root.input_source_ref,
                root.goal_ref,root.target_entity_ref,root.role_binding_ref,root.audiences)!=(ids['action_operation_id'],ids['activity_id'],
                ids['effect_id'],auth.request.project_ref,auth.request.recipe_ref,auth.request.body_source_ref,ids['goal_key'].token,
                auth.request.target_entity_ref,auth.request.role_binding_ref,auth.cause.audiences)):
        raise ValueError('Owner Life cannot borrow another actual selected action')
    original=read_adopted_domain_operation_v1(db,ns,root.action_operation_id)
    if original is None or (original['domain'],original['operation_kind'])!=('d08','prepare_selected_source_note_action_v2'):
        raise MissingProductionOriginalV1('actual_selected_Owner_Life_action_producer')
    request=decode_typed_production_value_v1(original['payload']['request'],ConsumePersonalDecisionRequestV1)
    prepared,chosen,preparation=selected_source_note_binding_from_originals_v2(db,namespace=ns,request=request)
    if (chosen.binding!=ids['binding'] or (chosen.future_identity.action_operation_id,chosen.future_identity.activity_id,
            chosen.future_identity.effect_id,chosen.future_identity.attempt_id,chosen.future_identity.parent_budget_lease_ref)!=
            (ids['action_operation_id'],ids['activity_id'],ids['effect_id'],ids['attempt_id'],auth.cause.parent_budget_lease_ref)
            or prepared.selection_operation_id!=ids['selection_operation_id'] or root.preparation_original_digest!=preparation['original_digest']
            or root.decision_ref!=request.decision_ref):
        raise ValueError('Owner Life selected binding changed its actual task future identity')
    decision,_=_head(db,ns,root.decision_ref,versions)
    if decision.digest!=root.decision_digest:raise ValueError('Owner Life current Decision changed')
    for ref,revision,digest in root.write_commitments:
        head,_=_head(db,ns,ref,versions)
        if (head.revision,head.digest)!=(revision,digest):raise ValueError('Owner Life action/schema/cancellation changed')
    return ids,root,chosen


@dataclass(frozen=True, slots=True)
class OwnerSourceNoteLifePlanMaterialV1:
    plan: RegisteredLifePlanV2
    action_original: SelectedSourceNoteActionOriginalV2
    body_original: LifeBodyPreparationOriginalV1
    read_versions: tuple[GraphVersion, ...]


def derive_owner_source_note_life_plan_v1(db,*,authorization,issuer,now_utc,installed_build):
    auth=authorization;ns=auth.cause.namespace;versions={}
    ids,root,chosen=_selected_action(db,auth=auth,issuer=issuer,versions=versions)
    inputs={}
    for name,ref in (('project',auth.request.project_ref),('recipe',auth.request.recipe_ref),('action_intent',ids['action_ref']),
            ('input_source',auth.request.body_source_ref)):
        inputs[name],value=_head(db,ns,ref,versions)
        if name=='input_source':source=SourceRecord.from_dict(value)
    inputs['input_access'],_=_head(db,ns,access_key(*ns.as_tuple,source.source_id),versions)
    saved=_read(db,issuer=issuer,namespace=ns,kind='life_body_preparation',ref=ids['body_original_ref'])
    if saved is None:raise MissingProductionOriginalV1('actual_Owner_Life_Body_B')
    body=life_body_preparation_original_from_wire_v1(saved[0])
    original=read_adopted_domain_operation_v1(db,ns,saved[1])
    expected_request=PrepareSourceNoteBodyRequestV1(ids['action_ref'],auth.body_policy.body_policy_id,
        auth.body_policy.body_policy_version,auth.body_policy.effect_policy_ref,auth.body_policy.cpu_ceiling_ms)
    if (original is None or original['operation_kind']!='prepare_source_note_body' or saved[1]!=ids['body_operation_id']
            or original['payload']['request']!=plain_v1(expected_request)
            or (body.action_intent_ref,body.action_intent_digest,body.action_operation_id,body.activity_id,body.effect_id)!=
                (ids['action_ref'],inputs['action_intent'].digest,ids['action_operation_id'],ids['activity_id'],ids['effect_id'])
            or body.receipt_digest!=canonical_digest(original['receipt'])
            or original['receipt'].write_versions!=(GraphVersion(AtomKey.from_token(body.reservation_ref),body.reservation_revision),)
            or (body.effect_policy_ref,body.effect_policy_revision,body.effect_policy_digest,body.component_id)!=
                (auth.body_policy.effect_policy_ref,auth.body_policy.effect_policy_revision,auth.body_policy.effect_policy_digest,auth.body_policy.component_id)):
        raise ValueError('Owner Life Body B differs from its actual authorized quote/producer')
    reservation,_=_head(db,ns,body.reservation_ref,versions)
    if (reservation.revision,reservation.digest)!=(body.reservation_revision,body.reservation_digest):
        raise ValueError('Owner Life original Body reservation changed')
    quote=issuer.resource_issuer.original_signed_quote(db,body.resource_quote_ref,body.resource_quote_version)
    if (canonical_digest(quote)!=body.resource_quote_digest or quote.work_kind!=WORK_KIND
            or (quote.operation_id,quote.activity_id,quote.effect_id,quote.parent_budget_lease_ref)!=
                (ids['body_operation_id'],ids['activity_id'],ids['effect_id'],auth.cause.parent_budget_lease_ref)
            or quote.ceiling.get('cpu_ms')!=auth.body_policy.cpu_ceiling_ms):
        raise ValueError('Owner Life actual signed resource quote changed')
    row=db.execute('SELECT body_quote_json FROM d02_body_quotes_v1 WHERE bot=? AND persona=? AND quote_id=? AND quote_version=?',
        (*ns.as_tuple,body.body_quote_ref,body.body_quote_version)).fetchone()
    if row is None:raise MissingProductionOriginalV1('actual_Owner_Life_Body_quote')
    from ..domains.d02 import BodyQuote
    body_quote=decode_typed_production_value_v1(json.loads(row[0]),BodyQuote)
    if canonical_digest(body_quote)!=body.body_quote_digest or body_quote.work_kind!=WORK_KIND:
        raise ValueError('Owner Life Body quote bytes differ from its authenticated B original')
    deadline=min(auth.cause.original_deadline_utc,chosen.future_identity.deadline_utc,quote.valid_until_utc,body_quote.valid_until)
    if now_utc>=deadline:raise MissingProductionOriginalV1('actual_unexpired_Owner_Life_original_deadline')
    contract=LifeBodyComponentContractV1(*(getattr(body,name) for name in ('body_quote_ref','body_quote_version','body_quote_digest',
        'resource_quote_ref','resource_quote_version','resource_quote_digest','reservation_ref','settlement_ref','component_id',
        'effect_policy_ref','body_prepare_operation_id')))
    plan=RegisteredLifePlanV2(inputs['project'],inputs['recipe'],inputs['action_intent'],inputs['input_source'],inputs['input_access'],
        ids['activity_id'],ids['effect_id'],ids['attempt_id'],ids['action_operation_id'],auth.cause.audiences,
        auth.cause.parent_budget_lease_ref,auth.body_policy.cpu_ceiling_ms,datetime.fromtimestamp(deadline,timezone.utc).isoformat().replace('+00:00','Z'),
        installed_build['algorithm_build_digest'],installed_build['postcondition_build_digest'],canonical_serialize(plain_v1(contract)))
    return OwnerSourceNoteLifePlanMaterialV1(plan,root,body,
        tuple(GraphVersion(key,revision) for key,revision in sorted(versions.items(),key=lambda row:row[0].token)))


def read_owner_source_note_registered_plan_v1(db,*,authorization,issuer):
    ids=owner_source_note_life_ids_v1(authorization);ns=authorization.cause.namespace
    saved=_read(db,issuer=issuer,namespace=ns,kind='plan',ref=ids['plan_ref'])
    if saved is None:raise MissingProductionOriginalV1('actual_named_Owner_Life_plan')
    original=read_adopted_domain_operation_v1(db,ns,saved[1])
    if (original is None or (original['domain'],original['operation_kind'])!=('d10',PLAN_OPERATION)
            or saved[1]!=ids['plan_operation_id'] or original['payload']['request']!={'authorization_original_ref':authorization.original_ref}
            or original['payload']['provenance']['owner_task_authorization_digest']!=authorization.digest
            or original['payload']['provenance']['life_plan']!=saved[0]):
        raise ValueError('Owner Life plan lost its exact named task producer')
    return life_from_wire_v1(saved[0],RegisteredLifePlanV2)


def derive_owner_source_note_life_outcome_v1(db,*,authorization,issuer):
    auth=authorization;ids=owner_source_note_life_ids_v1(auth);ns=auth.cause.namespace
    plan=read_owner_source_note_registered_plan_v1(db,authorization=auth,issuer=issuer)
    adopted=read_adopted_life_original_v1(db,namespace=ns,result_ref=ids['artifact_ref'],issuer=issuer)
    if adopted is None:raise MissingProductionOriginalV1('actual_Owner_Life_atomic_native_adoption')
    terminal=life_from_wire_v1(adopted['terminal'],D11LifeTerminalV1)
    b=terminal.binding;prepared=read_prepared_life_v1(db,binding=b,issuer=issuer)
    if (type(terminal) is not D11LifeTerminalV1 or terminal.status!='completed' or prepared is None or prepared.plan!=plan
            or (b.plan_original_ref,b.activity_id,b.effect_id,b.operation_id,b.artifact_ref,b.parent_budget_lease_ref)!=
                (ids['plan_ref'],ids['activity_id'],ids['effect_id'],ids['action_operation_id'],ids['artifact_ref'],auth.cause.parent_budget_lease_ref)):
        raise ValueError('Owner Life outcome is not its exact completed native once execution')
    from .d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1
    from .d11_life_source_note_v1 import verify_durable_life_artifact_v1
    from .d11_life_outcome_provenance_v1 import life_outcome_key_v1
    from .budget import _settlement_binding
    require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted)
    verify_durable_life_artifact_v1(db,prepared,digest=terminal.payload.artifact_digest,length=terminal.payload.artifact_length)
    actual={'thread_cpu_ms':terminal.actual_cpu_ms}
    rows=db.execute("SELECT digest,lease_id,resolution_binding_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*ns.as_tuple,b.reservation_operation_id)).fetchall()
    if rows!=[(b.reservation_digest,b.parent_budget_lease_ref,_settlement_binding(actual,True))]:
        raise ValueError('Owner Life outcome lacks its actual once CPU settlement')
    return RegisteredLifeOutcomeV2(ids['plan_ref'],life_outcome_key_v1(b,plan.action_intent.ref).token,terminal.claim.original_ref,
        terminal.original_ref,b.artifact_ref,terminal.payload.artifact_digest,
        (runtime_cost_settlement_key(*ns.as_tuple,b.activity_id,b.reservation_operation_id).token,))


class InstalledOwnerSourceNoteLifeReadersV1:
    def __init__(self,key,*,graph,scope,issued):
        if key is not _READERS_KEY:raise TypeError('Owner Life uses its actual private task factory')
        self.graph,self.scope,self.issued=graph,scope,issued
        self.issuer=graph._GraphCoordinator__d11_issuer
        assembly=graph._GraphCoordinator__d04_installed_joint_assembly
        self.bundle,self.package_root=assembly.admin_bundle,assembly.package_root
        self.body_quote_authority=graph._GraphCoordinator__body_quote_authority
    def current(self):
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        return require_owner_source_note_task_issuance_v1(self.issued,self.graph,self.scope)


def install_owner_source_note_life_readers_v1(graph,*,scope,owner_guard,owner_task_issuance):
    from ..graph_coordinator import GraphCoordinator
    from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
    if type(graph) is not GraphCoordinator:raise TypeError('actual Owner Life Graph required')
    value=require_owner_source_note_task_issuance_v1(owner_task_issuance,graph,scope)
    if value.request.operation_kind not in {PLAN_OPERATION,OUTCOME_OPERATION}:raise ValueError('Owner Life reader used for another command')
    return InstalledOwnerSourceNoteLifeReadersV1(_READERS_KEY,graph=graph,scope=scope,issued=owner_task_issuance)


def _scope(db,*,frame,request,readers,kind):
    expected=RegisterOwnerSourceNoteLifePlanRequestV1 if kind==PLAN_OPERATION else RegisterOwnerSourceNoteLifeOutcomeRequestV1
    if type(request) is not expected or type(readers) is not InstalledOwnerSourceNoteLifeReadersV1:
        raise TypeError('exact Owner Life selector and private reader required')
    from ..authority_service.current_owner_source_note_task_v1 import owner_task_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    evidence=readers.current();read=CurrentDomainReadV1(frame);read.check(db)
    if (evidence.request.operation_kind!=kind or evidence.request.request_digest!=owner_task_typed_command_digest_v1(installed_operation_v1(kind),request)
            or request.authorization_original_ref!=evidence.authorization.original_ref or evidence.owner_guard!=frame.owner_guard
            or evidence.current_self.self_entity_ref!=frame.envelope.authority.actor):
        raise ValueError('Owner Life selector differs from its actual task-issued command')
    auth=evidence.authorization
    require_current_owner_source_note_task_authorization_v2(db,frame=frame,authorization=auth,issuer=readers.issuer,
        installed_bundle=readers.bundle,body_quote_authority=readers.body_quote_authority)
    ids=owner_source_note_life_ids_v1(auth)
    if frame.envelope.identity.operation_id!=ids['plan_operation_id' if kind==PLAN_OPERATION else 'outcome_operation_id']:
        raise ValueError('Owner Life command changed its stable task operation')
    return auth,ids


def stage_register_owner_source_note_life_plan_v1(db,*,frame,request,installed_readers):
    readers=installed_readers;auth,ids=_scope(db,frame=frame,request=request,readers=readers,kind=PLAN_OPERATION)
    from .d08_source_note_action_v1 import require_current_selected_source_note_action_v2
    require_current_selected_source_note_action_v2(db,frame=frame,action_original_ref=ids['action_original_ref'],
        issuer=readers.issuer,installed_bundle=readers.bundle,body_quote_authority=readers.body_quote_authority)
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    build=read_installed_d11_life_build_v1(readers.package_root,auth.cause.manifest_digest)
    material=derive_owner_source_note_life_plan_v1(db,authorization=auth,issuer=readers.issuer,now_utc=frame.now_utc,installed_build=build)
    body=material.body_original
    quote=readers.issuer.resource_issuer.original_signed_quote(db,body.resource_quote_ref,body.resource_quote_version)
    original_body=readers.body_quote_authority.original_body_quote(db,body.body_quote_ref,body.body_quote_version,quote,body.body_prepare_operation_id)
    if canonical_digest(original_body)!=body.body_quote_digest:raise ValueError('Owner Life current Body signature differs')
    return stage_result_v1(frame,'d10',PLAN_OPERATION,request,provenance={'owner_task_authorization_ref':auth.original_ref,
        'owner_task_authorization_digest':auth.digest,'life_plan':material.plan,'action_original_ref':ids['action_original_ref'],
        'action_original_digest':canonical_digest(plain_v1(material.action_original)),'body_original_ref':ids['body_original_ref'],
        'body_original_digest':canonical_digest(plain_v1(body))},proposal_schema='d10.proposal.v1',proposal_hash=LifeDomain().descriptor.request_schema_hash)


def stage_register_owner_source_note_life_outcome_v1(db,*,frame,request,installed_readers):
    auth,ids=_scope(db,frame=frame,request=request,readers=installed_readers,kind=OUTCOME_OPERATION)
    outcome=derive_owner_source_note_life_outcome_v1(db,authorization=auth,issuer=installed_readers.issuer)
    return stage_result_v1(frame,'d10',OUTCOME_OPERATION,request,provenance={'owner_task_authorization_ref':auth.original_ref,
        'owner_task_authorization_digest':auth.digest,'life_outcome':outcome},proposal_schema='d10.proposal.v1',proposal_hash=LifeDomain().descriptor.request_schema_hash)


def record_owner_source_note_life_after_cas_v1(db,*,frame,stage,receipt,installed_readers):
    readers=installed_readers;proof=json.loads(stage.original_payload_json)['provenance'];auth=readers.current().authorization
    ids=owner_source_note_life_ids_v1(auth)
    if receipt.status!='committed' or receipt.write_versions or proof['owner_task_authorization_digest']!=auth.digest:
        raise ValueError('Owner Life original requires its actual metadata-only task W01 receipt')
    if stage.operation_kind==PLAN_OPERATION:
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        if receipt.operation_id!=ids['plan_operation_id']:raise ValueError('Owner Life plan receipt identity changed')
        plan=life_from_wire_v1(proof['life_plan'],RegisteredLifePlanV2)
        build=read_installed_d11_life_build_v1(readers.package_root,auth.cause.manifest_digest)
        return record_registered_life_plan_v2(db,frame=frame,issuer=readers.issuer,original_ref=ids['plan_ref'],
            producing_operation_id=receipt.operation_id,plan=plan,installed_build=build,body_quote_authority=readers.body_quote_authority)
    if stage.operation_kind!=OUTCOME_OPERATION or receipt.operation_id!=ids['outcome_operation_id']:
        raise ValueError('unregistered Owner Life receipt')
    return record_current_life_outcome_v2(db,frame=frame,issuer=readers.issuer,original_ref=ids['outcome_ref'],
        producing_operation_id=receipt.operation_id,outcome=life_from_wire_v1(proof['life_outcome'],RegisteredLifeOutcomeV2))


def read_plan_owner_source_note_life_v1(db,*,namespace,request,operation_kind,installed_readers):
    saved=read_owner_source_note_task_authorization_v2(db,namespace=namespace,original_ref=request.authorization_original_ref,issuer=installed_readers.issuer)
    if saved is None:raise MissingProductionOriginalV1('actual_Owner_Life_authorization_readplan')
    auth=saved[0];ids=owner_source_note_life_ids_v1(auth)
    from .d11_life_product_adapter_v1 import life_plan_read_inputs_v1,life_outcome_read_plan_v2
    if operation_kind==PLAN_OPERATION:
        from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
        build=read_installed_d11_life_build_v1(installed_readers.package_root,auth.cause.manifest_digest)
        # Source of the deadline is frozen A/B/auth, never this locator read's wall clock.
        material=derive_owner_source_note_life_plan_v1(db,authorization=auth,issuer=installed_readers.issuer,now_utc=auth.cause.submitted_at_utc,installed_build=build)
        plan=life_plan_read_inputs_v1(db,namespace=namespace,plan=material.plan,
            originals=(auth.original_ref,auth.cause.original_ref,ids['action_original_ref'],ids['body_original_ref']))
        extra=material.read_versions
    elif operation_kind==OUTCOME_OPERATION:
        outcome=derive_owner_source_note_life_outcome_v1(db,authorization=auth,issuer=installed_readers.issuer)
        plan=life_outcome_read_plan_v2(db,namespace=namespace,activity_id=ids['activity_id'],outcome=outcome,original_ref=ids['outcome_ref'])
        extra=()
    else:raise ValueError('unregistered Owner Life read plan')
    return production_read_plan_v1(plan.fixed_type_ids,(*plan.exact_keys,*(head.key for _,head,_ in auth.heads),*(v.key for v in extra)),
        tuple(dict.fromkeys((*plan.source_roots,*auth.source_refs))),tuple(dict.fromkeys((*plan.required_original_refs,auth.original_ref,auth.cause.original_ref))))


def qualify_owner_source_note_life_command_v1(db,*,authorization,request,issuer,now_utc,actor_ref):
    """Core-only independent reconstruction of the exact bounded task command."""
    from ..authority_service.current_owner_source_note_task_v1 import owner_task_typed_command_digest_v1
    from .domain_production_registry_v1 import installed_operation_v1
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    from ..domains.d10.production_operations_v1 import AdvanceCurrentLifeRequestV1
    from .d08_personal_plan_v1 import SettleCurrentPersonalGoalRequestV1
    auth=authorization;ids=owner_source_note_life_ids_v1(auth);kind=request.operation_kind
    versions=();expected_op=None
    if kind in {'prepare_source_note_body',PLAN_OPERATION,'prepare_life'}:
        from .d08_source_note_action_v1 import read_current_selected_source_note_evidence_v2
        from .domain_production_contracts_v1 import ProductionOperationLimitsV1
        selected=read_current_selected_source_note_evidence_v2(db,namespace=auth.cause.namespace,actor_ref=actor_ref,
            parent_budget_lease_ref=auth.cause.parent_budget_lease_ref,now_utc=now_utc,
            max_query_rows=ProductionOperationLimitsV1().max_query_rows,action_original_ref=ids['action_original_ref'],issuer=issuer)
        if selected[4]!=auth:
            raise ValueError('Owner Life selected evidence differs from its independently qualified actual task')
    if kind=='prepare_source_note_body':
        captured={};_selected_action(db,auth=auth,issuer=issuer,versions=captured)
        command=PrepareSourceNoteBodyRequestV1(ids['action_ref'],auth.body_policy.body_policy_id,auth.body_policy.body_policy_version,
            auth.body_policy.effect_policy_ref,auth.body_policy.cpu_ceiling_ms)
        expected_op=ids['body_operation_id'];versions=tuple(GraphVersion(k,v) for k,v in captured.items())
    elif kind in {PLAN_OPERATION,'prepare_life'}:
        build=read_installed_d11_life_build_v1(Path(__file__).resolve().parents[3],auth.cause.manifest_digest)
        material=derive_owner_source_note_life_plan_v1(db,authorization=auth,issuer=issuer,now_utc=now_utc,installed_build=build)
        versions=material.read_versions
        if kind==PLAN_OPERATION:
            command=RegisterOwnerSourceNoteLifePlanRequestV1(auth.original_ref);expected_op=ids['plan_operation_id']
        else:
            if read_owner_source_note_registered_plan_v1(db,authorization=auth,issuer=issuer)!=material.plan:
                raise ValueError('Owner Life preparation changed its independently derived actual plan')
            command=PrepareCurrentLifeRequestV1(ids['plan_ref'],ids['prepare_operation_id']);expected_op=ids['prepare_operation_id']
    elif kind in {OUTCOME_OPERATION,'advance_life','settle_personal_goal'}:
        outcome=derive_owner_source_note_life_outcome_v1(db,authorization=auth,issuer=issuer)
        if kind==OUTCOME_OPERATION:
            command=RegisterOwnerSourceNoteLifeOutcomeRequestV1(auth.original_ref);expected_op=ids['outcome_operation_id']
        else:
            saved=_read(db,issuer=issuer,namespace=auth.cause.namespace,kind='outcome',ref=ids['outcome_ref'])
            original=None if saved is None else read_adopted_domain_operation_v1(db,auth.cause.namespace,saved[1])
            if (original is None or saved[1]!=ids['outcome_operation_id'] or original['operation_kind']!=OUTCOME_OPERATION
                    or saved[0]!=plain_v1(outcome) or original['payload']['provenance']['owner_task_authorization_digest']!=auth.digest):
                raise ValueError('Owner Life consumption lacks its exact named outcome original')
            if kind=='advance_life':
                command=AdvanceCurrentLifeRequestV1(auth.request.project_ref,ids['outcome_ref']);expected_op=ids['advance_operation_id']
            else:
                command=SettleCurrentPersonalGoalRequestV1(ids['goal_key'].token,ids['plan_key'].token,ids['progress_ref'],1,1)
                expected_op=ids['settle_operation_id']
    else:raise ValueError('unregistered Owner Life command')
    if request.operation_id!=expected_op or request.request_digest!=owner_task_typed_command_digest_v1(installed_operation_v1(kind),command):
        raise ValueError('Owner Life command differs from its independently reconstructed task original')
    return versions
