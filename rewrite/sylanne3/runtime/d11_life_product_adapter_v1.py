"""Installed Life input and preparation adapters for the shared W01 runtime."""
from dataclasses import replace
import json

from ..graph_types import AtomKey, Owner, owner_grant_key
from ..memory_types import source_key, access_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d01_production_operations_v1 import production_read_plan_v1, table_exists_v1, MissingProductionOriginalV1, waiting_stage_v1
from .d11_life_contract_v1 import RegisteredLifePlanV2, RegisteredLifeOutcomeV2, life_from_wire_v1
from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
from .d11_life_preparation_v1 import TABLE, _read, life_ids_v1, PrepareCurrentLifeRequestV1

LIFE_CURRENT_TYPES = (
    "d03.entity_anchor", "d03.role_binding", "d03.self_identity_mapping.v1", "d01.persona_activation.v1",
    "d01.persona_plan.v1", "d05.boundary_rule", "d08.goal.v1", "d08.commitment.v1",
    "d08.action_intent.v1", "d08.action_schema.v1", "d08.action_outcome.v1",
    "d08.action_cancellation.v1", "d07.attention_ticket.v1", "d07.focus.v1",
    "d12.active_scheme_head.v1",
    "d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1", "d02.settlement.v1",
)


def raw_life_original_v1(db, namespace, kind, ref):
    """Locate frozen read inputs; the installed stage separately authenticates them."""
    if not table_exists_v1(db, TABLE):
        return None
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    row = _producer_original_point_v3(db,table=TABLE,columns=('payload_json','payload_digest','producing_operation_id'),
        key_columns=('bot','persona','kind','original_ref'),key=(*namespace.as_tuple,kind,ref),
        legacy_reader=lambda:db.execute("SELECT payload_json,payload_digest,producing_operation_id FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple,kind,ref)).fetchone())
    return None if row is None else json.loads(row[0])


def life_inventory_read_inputs_v1(db, *, namespace, scope):
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    from .d01_life_activation_original_v1 import life_activation_read_keys_v1
    keys.extend(life_activation_read_keys_v1(db, namespace))
    inventory = {}
    for type_name in LIFE_CURRENT_TYPES:
        from .borrowed_habit_classification_v3 import read_bound_borrowed_habit_inventory_v3
        handled,atoms=read_bound_borrowed_habit_inventory_v3(db,namespace,type_name)
        rows=tuple((atom.key.token,canonical_serialize(atom.value),int(atom.valid))for atom in atoms)if handled else db.execute(
            "SELECT token,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*namespace.as_tuple,type_name)).fetchall()
        if len(rows) > 128:
            raise MissingProductionOriginalV1("complete_life_input_inventory:" + type_name)
        inventory[type_name] = tuple((AtomKey.from_token(token), json.loads(encoded))
            for token, encoded, valid in rows if valid)
    action_ids = {value["action_id"] for key, value in inventory["d08.action_intent.v1"]
        if scope.includes("d08.action_intent.v1", key, value)}
    for type_name, rows in inventory.items():
        for key, value in rows:
            if (value.get("action_id") not in action_ids if type_name == "d08.action_outcome.v1"
                    else not scope.includes(type_name, key, value)):
                continue
            refs = (*value.get("source_refs", ()), *value.get("creation_evidence_refs", ()), *value.get("reason_refs", ()))
            for ref in refs:
                try:
                    key = AtomKey.from_token(ref)
                except ValueError:
                    # Owner configuration is an original locator, not a D06
                    # Source. Its concrete original reader decides its status.
                    originals.append(ref)
                    continue
                if key.type_name == "memory.source":
                    roots.append(ref)
                else:
                    keys.append(key)
                    originals.append(ref)
    return keys, roots, originals


def life_plan_read_inputs_v1(db, *, namespace, plan, originals=(), now_utc=None):
    keys = [owner_grant_key(*namespace.as_tuple)]
    keys.extend(AtomKey.from_token(getattr(plan, name).ref) for name in
        ("project", "recipe", "action_intent", "input_source", "input_access"))
    keys.append(AtomKey(Owner("activity", *namespace.as_tuple, plan.activity_id), "runtime.job", life_ids_v1(plan)["job"]))
    roots = [plan.input_source.ref]
    originals = list(originals)
    if type(plan) is RegisteredDraftFilePlanV3:
        from .d08_project_control_v1 import project_control_basis_v1
        _, _, actual_plan, _, actual_goal = project_control_basis_v1(db, namespace=namespace, project_ref=plan.project.ref)
        keys.extend((actual_plan.key, actual_goal.key))
        keys.append(AtomKey.from_token(plan.content.content.ref))
        roots.extend(plan.content.source_refs)
        originals.extend((plan.activity_scope_ref, plan.target.root_registration_ref))
        from .d11_life_preparation_v1 import draft_predecessor_original_refs_v1
        originals.extend(draft_predecessor_original_refs_v1(db, namespace=namespace, target=plan.target))
        scope = raw_life_original_v1(db, namespace, "activity_scope", plan.activity_scope_ref)
        if scope is not None:
            originals.extend((scope["ingress_original_ref"], scope["c02_original_ref"]))
    from .d11_role_clock_installation_v1 import role_clock_mapping_id_v1
    originals.append(role_clock_mapping_id_v1(namespace))
    if plan.body_effect_request_json is not None:
        contract = json.loads(plan.body_effect_request_json)
        keys.extend(AtomKey.from_token(contract[name]) for name in ("reservation_ref", "settlement_ref"))
        originals.extend(contract[name] for name in ("body_quote_ref", "resource_quote_ref", "effect_policy_ref"))
    from .d11_life_scope_v1 import life_scope_from_action_v1
    scope = life_scope_from_action_v1(db, namespace=namespace, action_ref=plan.action_intent.ref,
        project_ref=plan.project.ref, input_source_ref=plan.input_source.ref, audiences=plan.audiences, now_utc=now_utc)
    inventory_keys, inventory_roots, inventory_originals = life_inventory_read_inputs_v1(db, namespace=namespace, scope=scope)
    keys.extend(inventory_keys)
    roots.extend(inventory_roots)
    originals.extend(inventory_originals)
    return production_read_plan_v1(LIFE_CURRENT_TYPES, keys, roots, originals)


def artifact_phase_draft_plan_ref_v2(selector):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or not selector.generation:
        raise TypeError("phase file plan requires its exact generation selector")
    return "artifact-phase-file-plan:" + selector.identity_digest[:48]


def artifact_phase_draft_plan_registration_operation_id_v2(selector):
    return artifact_phase_draft_plan_ref_v2(selector) + ":register-file-plan"


def read_plan_current_phase_draft_file_registration_v2(db, *, namespace, activity_id, request, installed_readers):
    from .domain_production_inputs_v1 import RegisterCurrentPhaseDraftFilePlanInputRequestV2
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2, artifact_draft_file_ids_v2
    from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV2, artifact_draft_content_from_wire_v2
    from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
    from ..domains.d03.self_perspective import self_mapping_key
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    if type(request) is not RegisterCurrentPhaseDraftFilePlanInputRequestV2 or request.selector.task.namespace != namespace:
        raise TypeError("exact namespace phase file registration selector required")
    selector = request.selector
    from .d08_personal_plan_v1 import ProposeCurrentArtifactPhaseActionRequestV2, read_plan_current_artifact_phase_action_v2
    _, _, _, action_readers = _installed_phase_file_context_v2(installed_readers)
    action_plan = read_plan_current_artifact_phase_action_v2(db, namespace=namespace,
        request=ProposeCurrentArtifactPhaseActionRequestV2(selector), installed_readers=action_readers)
    ids, model_ids = artifact_draft_file_ids_v2(selector), artifact_draft_model_ids_v2(selector)
    if activity_id != ids["activity_id"]:
        raise ValueError("phase file registration crossed actual task activity")
    owner = Owner("activity", *namespace.as_tuple, activity_id)
    project = AtomKey(Owner("persona", *namespace.as_tuple), "d10.life_project.v1", ids["project"])
    action = AtomKey(owner, "d08.action_intent.v1", ids["action"])
    body_ref = "life-body:d02-life-body:" + ids["action_operation"]
    keys = [owner_grant_key(*namespace.as_tuple), self_mapping_key(namespace), AtomKey.from_token(selector.task.cycle_job_ref),
        AtomKey.from_token(selector.plan_ref), AtomKey.from_token(selector.decision_ref), project,
        AtomKey.from_token(ids["recipe_ref"]), action, AtomKey(owner, "d08.action_cancellation.v1", ids["action"])]
    keys.extend(life_project_context_keys_v1(namespace, project.token))
    roots = []
    originals = [selector.task.root_registration_ref, model_ids["job"], model_ids["frozen"], model_ids["adopt"],
        model_ids["paid"], model_ids["result"], "life-draft-root:" + ids["action_operation"], body_ref]
    if selector.prev_phase_original_ref is not None:
        originals.append(selector.prev_phase_original_ref)
    raw = raw_life_original_v1(db, namespace, "c4_phase_adopted", model_ids["adopt"])
    if raw is not None:
        adoption = artifact_draft_content_from_wire_v2(raw, ArtifactDraftContentAdoptionV2)
        if adoption.selector != selector:
            raise ValueError("phase file read plan changed actual paid content selector")
        roots.extend(adoption.content.source_refs)
        keys.extend((AtomKey.from_token(adoption.content.content.ref), AtomKey.from_token(adoption.task_source.ref)))
        keys.extend(access_key(*namespace.as_tuple, AtomKey.from_token(ref).owner.subject) for ref in adoption.content.source_refs)
        originals.extend((adoption.activity_scope_ref, adoption.extent_original_ref))
        from .d11_life_preparation_v1 import draft_predecessor_original_refs_v1
        originals.extend(draft_predecessor_original_refs_v1(db, namespace=namespace, target=adoption.target))
        scope = raw_life_original_v1(db, namespace, "activity_scope", adoption.activity_scope_ref)
        if scope is not None:
            originals.extend((scope["ingress_original_ref"], scope["c02_original_ref"]))
    body_raw = raw_life_original_v1(db, namespace, "life_body_preparation", body_ref)
    if body_raw is not None:
        body = life_body_preparation_original_from_wire_v1(body_raw)
        keys.extend((AtomKey.from_token(body.reservation_ref), AtomKey.from_token(body.settlement_ref)))
        originals.extend((body.body_quote_ref, body.resource_quote_ref, body.effect_policy_ref))
    return production_read_plan_v1((*LIFE_CURRENT_TYPES, *action_plan.fixed_type_ids),
        (*keys, *action_plan.exact_keys), (*roots, *action_plan.source_roots),
        (*originals, *action_plan.required_original_refs))


def _installed_phase_file_context_v2(installed_readers):
    from .d10_production_operations_v1 import InstalledD10ProductionReadersV1
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from .d08_personal_plan_v1 import install_artifact_phase_action_readers_v2
    if type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("phase file registration requires its actual installed D10 reader")
    graph = installed_readers.role_clock_reader.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise MissingProductionOriginalV1("actual_installed_phase_file_build_and_tool_scope")
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    model = InstalledArtifactDraftModelReadersV1(installed_readers.issuer, assembly.admin_bundle,
        graph._GraphCoordinator__artifact_draft_model_runtime_v1)
    action = install_artifact_phase_action_readers_v2(graph=graph, bootstrap=runtime._bootstrap,
        bundle=assembly.admin_bundle, model_readers=model)
    return graph, assembly, model, action


def derive_current_phase_draft_file_plan_v2(db, *, frame, request, installed_readers):
    from .domain_production_inputs_v1 import RegisterCurrentPhaseDraftFilePlanInputRequestV2
    from .d08_personal_plan_v1 import (ProposeCurrentArtifactPhaseActionRequestV2,
        read_current_artifact_phase_action_root_skeleton_v2)
    from .d11_artifact_draft_content_v1 import read_current_adopted_artifact_draft_content_v2
    from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1, DraftRootCapabilityV1, draft_from_wire_v1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from ..domains.d01.production_operations_v1 import plain_v1
    from .d02_life_body_preparation_v1 import read_current_draft_body_component_contract_v1, PrepareArtifactDraftBodyRequestV1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..host.authority_profile import AdminArtifactDraftPolicyV3, require_installed_artifact_target_v2
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
    from .d11_offline_originals_v1 import _utc
    if type(request) is not RegisterCurrentPhaseDraftFilePlanInputRequestV2:
        raise TypeError("selector-only phase file registration required")
    selector = request.selector
    ns = frame.envelope.authority.namespace
    if (selector.task.namespace != ns or frame.envelope.identity.operation_id !=
            artifact_phase_draft_plan_registration_operation_id_v2(selector)):
        raise ValueError("phase file registration changed actual namespace/once registration")
    graph, assembly, model_readers, action_readers = _installed_phase_file_context_v2(installed_readers)
    artifact = assembly.admin_bundle.artifact_draft
    if type(artifact) is not AdminArtifactDraftPolicyV3:
        raise MissingProductionOriginalV1("actual_installed_V3_phase_file_policy")
    skeleton = read_current_artifact_phase_action_root_skeleton_v2(db, frame=frame,
        request=ProposeCurrentArtifactPhaseActionRequestV2(selector), installed_readers=action_readers)
    adoption = read_current_adopted_artifact_draft_content_v2(db, frame=frame,
        selector=selector, installed_readers=model_readers)
    ids = artifact_draft_file_ids_v2(selector)
    if ((skeleton.activity_id, skeleton.effect_id, skeleton.attempt_id, skeleton.operation_id) != (
            ids["activity_id"], ids["effect"], ids["attempt"], ids["action_operation"])
            or (skeleton.target, skeleton.content, skeleton.activity_scope_ref, skeleton.activity_scope_digest) != (
                adoption.target, adoption.content, adoption.activity_scope_ref, adoption.activity_scope_digest)):
        raise ValueError("phase file plan changed actual adopted Action/content/scope identity")
    read = CurrentDomainReadV1(frame); read.check(db)
    scope_raw = _read(db, issuer=installed_readers.issuer, namespace=ns, kind="activity_scope", ref=adoption.activity_scope_ref)
    root_raw = _read(db, issuer=installed_readers.issuer, namespace=ns, kind="draft_root_capability", ref=selector.task.root_registration_ref)
    if scope_raw is None or root_raw is None:
        raise MissingProductionOriginalV1("actual_phase_file_scope_and_root")
    scope = draft_from_wire_v1(scope_raw[0], DraftActivityScopeV1)
    root = draft_from_wire_v1(root_raw[0], DraftRootCapabilityV1)
    require_installed_artifact_target_v2(artifact, root, adoption.target)
    from .artifact_task_text_extent_v1 import require_artifact_task_text_extent_history_v1
    extent_raw = _read(db, issuer=installed_readers.issuer, namespace=ns, kind="artifact_task_text_extent",
        ref=adoption.extent_original_ref)
    if extent_raw is None or canonical_digest(extent_raw[0]) != adoption.extent_original_digest:
        raise MissingProductionOriginalV1("actual_registered_full_method_phase_file_extent")
    extent = require_artifact_task_text_extent_history_v1(db, namespace=ns, original_ref=adoption.extent_original_ref,
        producing_operation_id=extent_raw[1], raw=extent_raw[0])
    if (skeleton.extent, skeleton.full_extent, skeleton.extent_original_ref, skeleton.extent_original_digest,
            extent.full_extent, extent.task_c02_operation_id, extent.task_source_head.key.token,
            extent.task_source_head.revision, extent.task_source_digest) != (
            adoption.extent, adoption.full_extent, adoption.extent_original_ref, adoption.extent_original_digest,
            adoption.full_extent, selector.task.c02_operation_id, adoption.task_source.ref,
            adoption.task_source.revision, adoption.task_source.digest):
        raise ValueError("phase file plan changed its actual registered task/full extent")
    if selector.phase_kind == "tone_sample" and adoption.target.mode != "create":
        raise ValueError("tone sample file requires its actual initial create target")
    if selector.phase_index and selector.phase_kind == "full":
        from .d11_artifact_draft_content_v1 import (ArtifactDraftPhaseVerifiedOriginalV2,
            artifact_draft_phase_verification_from_wire_v2, read_current_artifact_phase_verified_v2)
        previous = _read(db, issuer=installed_readers.issuer, namespace=ns, kind="c4_phase_verified",
            ref=selector.prev_phase_original_ref)
        if previous is None or canonical_digest(previous[0]) != selector.prev_phase_original_digest:
            raise MissingProductionOriginalV1("actual_independently_verified_sample_check_before_full_file")
        previous_value = artifact_draft_phase_verification_from_wire_v2(previous[0], ArtifactDraftPhaseVerifiedOriginalV2)
        verified = read_current_artifact_phase_verified_v2(db, namespace=ns, selector=previous_value.selector,
            issuer=installed_readers.issuer)
        target, readback = adoption.target, verified.readback
        if (verified.selector.phase_kind != "sample_check" or not verified.method_qualified
                or verified.selector.task != selector.task or verified.selector.method_ref != selector.method_ref
                or verified.selector.phase_index != selector.phase_index - 1 or target.mode != "replace"
                or (target.expected_prior_version, target.expected_prior_digest, target.expected_prior_identity,
                    target.expected_prior_effect_marker) != (readback.version, readback.content_digest,
                        readback.file_identity, readback.effect_marker)):
            raise ValueError("full phase file changed its actual verified sample predecessor")
    read.source_family(db, adoption.content.source_refs, purpose="consolidation")
    body = read_current_draft_body_component_contract_v1(db, frame=frame,
        action_intent_ref=skeleton.action_intent.ref, issuer=installed_readers.issuer,
        resource_issuer=graph._GraphCoordinator__d02_issuer, body_quote_authority=graph._GraphCoordinator__body_quote_authority)
    body_original = read_adopted_domain_operation_v1(db, ns, body.body_prepare_operation_id)
    if body_original is None or (body_original["domain"], body_original["operation_kind"]) != ("d02", "prepare_artifact_draft_body"):
        raise MissingProductionOriginalV1("actual_phase_file_Body_B_producer")
    body_request = decode_typed_production_value_v1(body_original["payload"]["request"], PrepareArtifactDraftBodyRequestV1)
    policy = artifact.body_policy
    if ((body_request.action_intent_ref, body_request.body_policy_id, body_request.body_policy_version,
            body_request.effect_policy_ref) != (skeleton.action_intent.ref, policy.policy_ref,
                policy.policy_version, policy.effect_component_policy_ref)
            or body_request.cpu_ceiling_ms > policy.cpu_ceiling_ms or policy.resource_id != adoption.target.root_resource_id):
        raise ValueError("phase file Body B differs from actual protected file policy")
    from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
    body_raw = _read(db, issuer=installed_readers.issuer, namespace=ns, kind="life_body_preparation",
        ref="life-body:" + body.body_prepare_operation_id)
    body_member = life_body_preparation_original_from_wire_v1(body_raw[0])
    if (body_member.effect_policy_ref, body_member.effect_policy_revision) != (
            policy.effect_component_policy_ref, policy.effect_component_policy_version):
        raise ValueError("phase file Body B changed its protected effect policy revision")
    quote = graph._GraphCoordinator__d02_issuer.original_signed_quote(db, body.resource_quote_ref, body.resource_quote_version)
    deadline = adoption.original_deadline_utc
    from .d10_habit_v1 import current_habit_draft_plan_deadline_v1
    deadline=current_habit_draft_plan_deadline_v1(db,frame=frame,selector=selector,deadline_utc=deadline,issuer=installed_readers.issuer)
    if (not frame.now_utc < _utc(deadline).timestamp() <= min(frame.envelope.deadline_utc,
            quote.valid_until_utc, _utc(scope.valid_until_utc).timestamp(), _utc(root.valid_until_utc).timestamp())
            or body_request.cpu_ceiling_ms > quote.ceiling.get("cpu_ms", 0)):
        raise MissingProductionOriginalV1("original_unexpired_phase_file_deadline_and_actual_Body_quote")
    build = read_installed_d11_life_build_v1(assembly.package_root, assembly.installation_policy.manifest_digest,
        recipe_id="artifact_draft_v1")
    if ((adoption.algorithm_build_digest, adoption.postcondition_build_digest, skeleton.postcondition_build_digest) != (
            build["algorithm_build_digest"], build["postcondition_build_digest"], build["postcondition_build_digest"])):
        raise ValueError("phase file plan build differs from its actual paid content and installed file closure")
    plan = RegisteredDraftFilePlanV3(skeleton.project, skeleton.recipe, skeleton.action_intent,
        skeleton.input_source, skeleton.input_access, skeleton.activity_id, skeleton.effect_id, skeleton.attempt_id,
        skeleton.operation_id, ids["execution_call"], adoption.activity_scope_ref, adoption.activity_scope_digest,
        skeleton.audiences, scope.parent_budget_lease_ref, body_request.cpu_ceiling_ms, deadline,
        build["algorithm_build_digest"], build["postcondition_build_digest"], canonical_serialize(plain_v1(body)), adoption.target, adoption.content)
    from .d11_life_preparation_v1 import require_draft_authority_inputs_v1
    require_draft_authority_inputs_v1(db, frame=frame, plan=plan, issuer=installed_readers.issuer)
    return plan



def registered_phase_draft_prepare_operation_id_v2(db,*,frame,request,plan,issuer):
    """Recover the original phase operation from its real signed registered-plan producer."""
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from .d11_life_preparation_v1 import _read
    from .domain_production_inputs_v1 import RegisterCurrentPhaseDraftFilePlanInputRequestV2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2,artifact_draft_phase_original_ref_v2
    from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1
    if type(plan)is not RegisteredDraftFilePlanV3:raise TypeError('only the actual registered phase Draft plan has this prepare operation')
    raw=_read(db,issuer=issuer,namespace=frame.envelope.authority.namespace,kind='plan',ref=request.plan_original_ref)
    if raw is None or canonical_digest(raw[0])!=canonical_digest(plain_v1(plan)):raise MissingProductionOriginalV1('actual_signed_registered_phase_Draft_plan')
    original=read_adopted_domain_operation_v1(db,frame.envelope.authority.namespace,raw[1])
    if original is None or(original['domain'],original['operation_kind'])!=('d10','input:register_artifact_phase_draft_plan_v2')or original['receipt'].status!='committed':raise MissingProductionOriginalV1('actual_phase_Draft_plan_registration_COMMIT')
    read=CurrentDomainReadV1(frame);read.check(db);read.committed_operation(db,raw[1])
    command=decode_typed_production_value_v1(original['payload']['request'],RegisterCurrentPhaseDraftFilePlanInputRequestV2);selector=command.selector
    ids=artifact_draft_file_ids_v2(selector)
    if request.plan_original_ref!=artifact_phase_draft_plan_ref_v2(selector)or raw[1]!=artifact_phase_draft_plan_registration_operation_id_v2(selector)or(plan.activity_id,plan.operation_id,plan.effect_id,plan.attempt_id,plan.execution_call_id)!=(ids['activity_id'],ids['action_operation'],ids['effect'],ids['attempt'],ids['execution_call']):raise ValueError('phase Draft preparation changed its actual registered selector, plan or original execution identity')
    return artifact_draft_phase_original_ref_v2(selector)+':file-prepare'

def read_plan_current_life_preparation_v1(db, *, namespace, activity_id, operation_kind, request, now_utc, before_capture_policy=None):
    if operation_kind != "prepare_life" or type(request) is not PrepareCurrentLifeRequestV1:
        raise TypeError("exact installed Life preparation read request required")
    raw = raw_life_original_v1(db, namespace, "plan", request.plan_original_ref)
    if raw is None:
        return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple),), (), (request.plan_original_ref,))
    plan = life_from_wire_v1(raw, RegisteredLifePlanV2)
    if plan.activity_id != activity_id:
        raise ValueError("Life preparation belongs to another actual adopted activity")
    reads = life_plan_read_inputs_v1(db, namespace=namespace, plan=plan, originals=(request.plan_original_ref,), now_utc=now_utc)
    if before_capture_policy is not None:
        from .d04_life_before_original_v1 import life_d04_before_read_inputs_v1
        keys, roots, originals = life_d04_before_read_inputs_v1(
            db, namespace=namespace, policy=before_capture_policy)
        reads = production_read_plan_v1(reads.fixed_type_ids,
            (*reads.exact_keys, *keys), (*reads.source_roots, *roots),
            (*reads.required_original_refs, *originals))
    return reads


def stage_prepare_current_life_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d11_life_preparation_v1 import prepare_current_life_in_transaction_v1
    from .d08_life_admission_v1 import InstalledLifeAdmissionReaderV1
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    graph = installed_readers.role_clock_reader.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    try:
        if assembly is None or assembly.installation_policy.namespace != frame.envelope.authority.namespace:
            raise MissingProductionOriginalV1("actual_installed_life_build")
        inventory = installed_readers.life_execution_inventory
        if inventory is None:
            raise MissingProductionOriginalV1("actual_same_head_life_execution_inventory")
        policy = assembly.installation_policy
        reader = InstalledLifeAdmissionReaderV1(issuer=installed_readers.issuer,
            resource_issuer=graph._GraphCoordinator__d02_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority,
            execution_inventory=inventory, scope=installed_readers.life_scope)
        raw_plan = raw_life_original_v1(db, frame.envelope.authority.namespace, "plan", request.plan_original_ref)
        recipe_id = "d10.source-note.v1" if raw_plan is None else raw_plan["recipe_id"]
        build = read_installed_d11_life_build_v1(assembly.package_root, policy.manifest_digest, recipe_id=recipe_id)
        return prepare_current_life_in_transaction_v1(db, frame=frame, request=request,
            issuer=installed_readers.issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,
            installation_id=policy.installation_id, authority_id=policy.expected_authority_id,
            authority_namespace=policy.authority_namespace, manifest_digest=policy.manifest_digest,
            job_holder=graph._GraphCoordinator__holder, installed_build=build,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority, admission_reader=reader,
            before_capture_policy=graph._GraphCoordinator__life_d04_before_capture_policy)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d10", "prepare_life", request, missing)


def read_plan_current_life_progress_v2(db, *, namespace, activity_id, request):
    raw = raw_life_original_v1(db, namespace, "outcome", request.activity_outcome_ref)
    if raw is None:
        return None
    outcome = life_from_wire_v1(raw, RegisteredLifeOutcomeV2)
    return life_outcome_read_plan_v2(db, namespace=namespace, activity_id=activity_id,
        outcome=outcome, original_ref=request.activity_outcome_ref, project_ref=request.project_ref)


def life_outcome_read_plan_v2(db, *, namespace, activity_id, outcome, original_ref, project_ref=None):
    plan_raw = raw_life_original_v1(db, namespace, "plan", outcome.plan_original_ref)
    if plan_raw is None:
        raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
    plan = life_from_wire_v1(plan_raw, RegisteredLifePlanV2)
    if plan.activity_id != activity_id or project_ref is not None and plan.project.ref != project_ref:
        raise ValueError("Life V2 outcome belongs to another project/activity")
    base = life_plan_read_inputs_v1(db, namespace=namespace, plan=plan,
        originals=(original_ref, outcome.plan_original_ref, outcome.start_original_ref,
            outcome.terminal_original_ref, outcome.artifact_ref, *outcome.paid_cost_refs))
    owner = Owner("activity", *namespace.as_tuple, activity_id)
    from .d11_life_contract_v1 import D11LifeTerminalV1
    from .d11_life_graph_types_v1 import life_role_segment_key_v1
    from .d10_life_outcome_v2 import life_experience_source_id_v1
    adopted = raw_life_original_v1(db, namespace, "adopted_life", outcome.artifact_ref)
    extra = [AtomKey.from_token(outcome.action_outcome_ref), AtomKey.from_token(outcome.artifact_ref),
        AtomKey(owner, "d10.life_progress.v1", plan.effect_id)]
    if adopted:
        terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
        from .d10_life_progress_provenance_v1 import life_progress_read_keys_v1
        extra.extend(life_progress_read_keys_v1(terminal.binding))
        from .d11_life_fact_provenance_v1 import life_fact_auxiliary_key_v1, PROVENANCE_TYPE, ELIGIBILITY_TYPE
        facts=(AtomKey.from_token(terminal.binding.artifact_ref),life_role_segment_key_v1(terminal.binding,'start'),life_role_segment_key_v1(terminal.binding,'end'))
        extra.extend(life_fact_auxiliary_key_v1(fact,kind) for fact in facts for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE))
        from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
        extra.extend(life_outcome_read_keys_v1(terminal.binding,plan.action_intent.ref))
        source_id = life_experience_source_id_v1(terminal.binding)
        extra.extend((life_role_segment_key_v1(terminal.binding, "start"), life_role_segment_key_v1(terminal.binding, "end"),
            source_key(*namespace.as_tuple, source_id), access_key(*namespace.as_tuple, source_id)))
    extra.extend(AtomKey.from_token(ref) for ref in outcome.paid_cost_refs)
    return production_read_plan_v1(base.fixed_type_ids, (*base.exact_keys, *extra), base.source_roots, base.required_original_refs)


def read_current_life_original_ref_v1(db, *, namespace, original_ref, issuer):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    if not table_exists_v1(db, TABLE):
        return None
    rows = db.execute("SELECT kind FROM " + TABLE + " WHERE bot=? AND persona=? AND original_ref=?",
        (*namespace.as_tuple, original_ref)).fetchall()
    if len(rows) > 1:
        raise ValueError("Life original reference is ambiguous across kinds")
    if rows:
        kind = rows[0][0]
        from .d11_artifact_draft_model_v1 import (C4_ORIGINAL_KINDS, C4_PHASE_ORIGINAL_KINDS_V2,
            decode_artifact_draft_original_v1, decode_artifact_draft_original_v2)
        from .c09_life_originals_v1 import FOREGROUND_CAUSE_KIND,read_foreground_post_c02_cause_original_v1
        if kind==FOREGROUND_CAUSE_KIND:
            from ..domains.d01.production_operations_v1 import plain_v1
            cause=read_foreground_post_c02_cause_original_v1(db,namespace=namespace,issuer=issuer,original_ref=original_ref)
            return ProductionOriginalRefV1("d11.life_"+FOREGROUND_CAUSE_KIND,original_ref,canonical_digest(plain_v1(cause)))
        if kind == "artifact_task_amendment":
            from .artifact_task_amendment_v1 import decode_amendment_v1,read_current_amendment_v1
            value=_read(db,issuer=issuer,namespace=namespace,kind=kind,ref=original_ref)
            amendment=decode_amendment_v1(value[0])
            actual=read_current_amendment_v1(db,namespace=namespace,
                root_registration_ref=amendment.root_registration_ref,issuer=issuer)
            if actual is None or (actual[0],actual[1])!=(amendment,original_ref):
                raise MissingProductionOriginalV1("actual_current_signed_task_amendment_original")
            return ProductionOriginalRefV1("d11.life_"+kind,original_ref,canonical_digest(value[0]))
        if kind == "artifact_task_continuation_authorization_v2":
            from .artifact_task_continuation_authorization_v2 import require_continuation_authorization_history_v2
            value=_read(db,issuer=issuer,namespace=namespace,kind=kind,ref=original_ref)
            require_continuation_authorization_history_v2(db,namespace=namespace,original_ref=original_ref,
                producing_operation_id=value[1],raw=value[0])
            return ProductionOriginalRefV1("d11.life_"+kind,original_ref,canonical_digest(value[0]))
        if kind in {"artifact_task_objective", "artifact_task_scope", "c1_task_intent"}:
            from .ingress_artifact_task_scope_v1 import (
                ArtifactTaskObjectiveV1, IngressArtifactTaskScopeOriginalV1, _decode as decode_task,
                task_scope_ref_v1, task_objective_ref_v1, require_task_scope_archive_v1,
            )
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
            value = _read(db, issuer=issuer, namespace=namespace, kind=kind, ref=original_ref)
            if kind == "c1_task_intent":
                from .c1_artifact_task_intent_v1 import (
                    validate_c1_task_original_row_v1, require_c1_task_original_history_v1,
                )
                typed = validate_c1_task_original_row_v1(namespace=namespace, original_ref=original_ref,
                    producing_operation_id=value[1], raw=value[0])
                require_c1_task_original_history_v1(db, typed)
            else:
                cls = ArtifactTaskObjectiveV1 if kind == "artifact_task_objective" else IngressArtifactTaskScopeOriginalV1
                typed = decode_task(value[0], cls)
                registration = typed.initial_root_registration_ref if kind == "artifact_task_objective" else typed.root.registration_ref
                root_row = _read(db, issuer=issuer, namespace=namespace, kind="draft_root_capability", ref=registration)
                if root_row is None or root_row[1] != value[1]:
                    raise MissingProductionOriginalV1("actual_initial_task_root_producer_for_original")
                root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
                producer = read_adopted_domain_operation_v1(db, namespace, value[1])
                if producer is None:
                    raise MissingProductionOriginalV1("actual_initial_task_W01_producer_for_original")
                scope = require_task_scope_archive_v1(db, namespace=namespace, root=root, producer=producer)
                if kind == "artifact_task_scope":
                    if typed != scope or original_ref != task_scope_ref_v1(registration):
                        raise ValueError("task scope resolver changed its actual exact signed variant")
                elif (typed.namespace != namespace or original_ref != task_objective_ref_v1(typed)
                        or scope.objective_ref != original_ref or scope.objective_digest != canonical_digest(value[0])
                        or producer["payload"]["provenance"]["artifact_task_objective"] != value[0]):
                    raise ValueError("task objective resolver changed its actual exact signed variant")
            return ProductionOriginalRefV1("d11.life_" + kind, original_ref, canonical_digest(value[0]))
        if kind not in {"plan", "prepared", "outcome", "adopted_life", "experience", "action_admission", "source_note_action", "draft_action", "activity_scope", "draft_root_capability", "draft_observation_admission", "life_body_preparation", "artifact_task_text_extent", *C4_ORIGINAL_KINDS, *C4_PHASE_ORIGINAL_KINDS_V2}:
            return None
        value = _read(db, issuer=issuer, namespace=namespace, kind=kind, ref=original_ref)
        if kind in C4_ORIGINAL_KINDS:decode_artifact_draft_original_v1(kind,value[0])
        if kind in C4_PHASE_ORIGINAL_KINDS_V2:
            original = decode_artifact_draft_original_v2(kind, value[0])
            if kind == "c4_phase_verified":
                from .d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
                actual = read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=original.selector, issuer=issuer)
                if actual != original:
                    raise ValueError("phase original locator changed its actual independently verified current body")
        if kind == "artifact_task_text_extent":
            from .artifact_task_text_extent_v1 import require_artifact_task_text_extent_history_v1
            require_artifact_task_text_extent_history_v1(db, namespace=namespace, original_ref=original_ref,
                producing_operation_id=value[1], raw=value[0])
        return ProductionOriginalRefV1("d11.life_" + kind, original_ref, canonical_digest(value[0]))
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1
    candidates = db.execute("SELECT original_ref FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='adopted_life' AND (json_extract(payload_json,'$.terminal.original_ref')=?"
        " OR json_extract(payload_json,'$.terminal.claim.original_ref')=?) ORDER BY original_ref LIMIT 33",
        (*namespace.as_tuple, original_ref, original_ref)).fetchall()
    if len(candidates) > 32:
        raise MissingProductionOriginalV1("bounded_life_effect_original_query")
    for (artifact_ref,) in candidates:
        adopted = read_adopted_life_original_v1(db, namespace=namespace, result_ref=artifact_ref, issuer=issuer)
        terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
        for kind, value in (("start", terminal.claim), ("terminal", terminal)):
            if value.original_ref == original_ref:
                return ProductionOriginalRefV1("d11.life_" + kind, original_ref, canonical_digest(value))
    return None
