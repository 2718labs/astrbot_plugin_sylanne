"""Joint node execution over exact existing D10 executor originals.

PlanNode.resource_ref commits the immutable binding bytes inside existing party
consent terms. No JointPlan V1 wire or existing signature is changed.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import GoalPredicate, ActionSchema, ActionSchemaRecord, _decode, _decode_intent, _decode_joint_plan
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .natural_producer_qualification_v1 import _producer_original_point_v3
from .domain_background_read_v3 import (background_json_loads_v3, background_json_matches_v3, background_json_digest_v3,
    background_verify_signature_v3, background_inventory_v3, background_history_v3)

BINDING_KIND = "joint_node_execution_binding_v1"
QUALIFICATION_KIND = "joint_plan_qualification_v1"
BINDING_PREFIX = "joint-node-binding:"
JOINT_EVENTS = frozenset(("joint_plan_adopted_requires_next_node_action", "joint_plan_adopted_requires_activity_qualification", "joint_node_observation_requires_node_recheck"))


@dataclass(frozen=True, slots=True)
class SourceNoteJointExecutorV1:
    authorization_original_ref: str
    schema: str = "d10.joint-source-note-executor.v1"

    def __post_init__(self):
        if self.schema != "d10.joint-source-note-executor.v1" or not self.authorization_original_ref.startswith("owner-source-note-authorization:"):
            raise ValueError("source-note Joint executor needs its actual registered Owner task")


@dataclass(frozen=True, slots=True)
class ArtifactJointExecutorV1:
    c02_operation_id: str
    source_ref: str
    root_registration_ref: str
    phase_selector: ArtifactDraftPhaseSelectorV2 | None = None
    schema: str = "d10.joint-artifact-executor.v1"

    def __post_init__(self):
        if self.schema != "d10.joint-artifact-executor.v1" or not self.c02_operation_id or not self.root_registration_ref:
            raise ValueError("artifact Joint executor needs the exact admitted cycle and root")
        if AtomKey.from_token(self.source_ref).type_name != "memory.source":
            raise ValueError("artifact Joint executor needs its actual causal Source")


@dataclass(frozen=True, slots=True)
class ContactJointExecutorV1:
    qualified_outbox_dedupe_key: str
    prepare_contact_operation_id: str
    schema: str = "d10.joint-contact-executor.v1"

    def __post_init__(self):
        if self.schema != "d10.joint-contact-executor.v1" or not self.qualified_outbox_dedupe_key or not self.prepare_contact_operation_id:
            raise ValueError("Contact Joint executor needs the existing qualified D10 outbox")


@dataclass(frozen=True, slots=True)
class JointNodeExecutionBindingV1:
    namespace: NamespaceId
    node_id: str
    plan_ref: str
    plan_revision: int
    owner_ref: str
    action_kind: str
    action_ref: str
    action_revision: int
    action_digest: str
    action_schema_ref: str
    action_schema_revision: int
    action_schema_digest: str
    project_ref: str | None
    recipe_ref: str | None
    goal_ref: str | None
    goal_id: str
    target_ref: str
    target_entity_ref: str
    role_ref: str | None
    source_refs: tuple[str, ...]
    progress_ref: str | None
    success_predicate: GoalPredicate
    executor: SourceNoteJointExecutorV1 | ArtifactJointExecutorV1 | ContactJointExecutorV1
    parent_budget_lease_ref: str
    parent_grant_id: str
    parent_grant_version: int
    parent_grant_digest: str
    original_deadline_utc: float
    purpose: str
    audience: tuple[str, ...]
    schema: str = "d10.joint-node-execution-binding.v1"

    def __post_init__(self):
        if (self.schema != "d10.joint-node-execution-binding.v1" or type(self.namespace) is not NamespaceId
                or not self.node_id.startswith("task:") or self.plan_revision < 1 or not self.owner_ref
                or type(self.executor) not in (SourceNoteJointExecutorV1, ArtifactJointExecutorV1, ContactJointExecutorV1)
                or type(self.success_predicate) is not GoalPredicate
                or type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 32
                or len(set(self.source_refs)) != len(self.source_refs)
                or type(self.audience) is not tuple or not 1 <= len(self.audience) <= 32
                or not self.parent_budget_lease_ref or self.parent_grant_version < 1
                or self.action_revision < 1 or self.action_schema_revision < 1
                or type(self.original_deadline_utc) not in (int, float)):
            raise ValueError("Joint binding requires bounded immutable execution scope")
        for digest in (self.action_digest, self.action_schema_digest, self.parent_grant_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Joint binding requires actual SHA256 commitments")
        for name, kind in (("plan_ref", "d08.joint_plan.v1"), ("action_ref", "d08.action_intent.v1"), ("action_schema_ref", "d08.action_schema.v1"),
                ("project_ref", "d10.life_project.v1"), ("recipe_ref", "d10.activity_recipe.v1"),
                ("goal_ref", "d08.goal.v1"), ("target_entity_ref", "d03.entity_anchor"), ("role_ref", "d03.role_binding"), ("progress_ref", "d10.life_progress.v1")):
            ref = getattr(self, name)
            if ref is not None:
                key = AtomKey.from_token(ref)
                if key.type_name != kind or NamespaceId.from_key(key) != self.namespace:
                    raise ValueError("Joint binding selectors cross type or namespace")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("Joint binding Sources cross namespace")
        if type(self.executor) is not ContactJointExecutorV1 and any(ref is None for ref in (
                self.project_ref, self.recipe_ref, self.goal_ref, self.role_ref, self.progress_ref)):
            raise ValueError("Life Joint binding preserves actual project, recipe, goal, role and progress")
        if self.success_predicate.valid_until is None or self.success_predicate.valid_until != self.original_deadline_utc:
            raise ValueError("Joint node predicate cannot outlive its original authorization")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def original_ref(self):
        return BINDING_PREFIX + self.digest


@dataclass(frozen=True, slots=True, kw_only=True)
class JointContactProspectiveBindingV1(JointNodeExecutionBindingV1):
    contact_id: str
    prospective_original_ref: str
    prospective_original_digest: str
    refresh_rule: str
    schema: str = "d10.joint-contact-prospective-binding.v1"

    def __post_init__(self):
        from dataclasses import fields
        if (self.schema!="d10.joint-contact-prospective-binding.v1"
                or type(self.executor) is not ContactJointExecutorV1
                or not self.contact_id.startswith("contact:")
                or not self.prospective_original_ref.startswith("contact-prospective-original:")
                or len(self.prospective_original_digest)!=64
                or any(c not in "0123456789abcdef" for c in self.prospective_original_digest)
                or self.refresh_rule!="d10.contact-prospective-successor.v1"):
            raise ValueError("Contact Joint prospective binding requires its exact real signed birth")
        values={field.name:getattr(self,field.name) for field in fields(JointNodeExecutionBindingV1)}
        values["schema"]="d10.joint-node-execution-binding.v1"
        JointNodeExecutionBindingV1(**values)


@dataclass(frozen=True, slots=True)
class RegisterJointNodeExecutionBindingRequestV1:
    binding: JointNodeExecutionBindingV1 | JointArtifactProspectiveBindingV1 | JointContactProspectiveBindingV1

    def __post_init__(self):
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
        if type(self.binding) not in (JointNodeExecutionBindingV1, JointArtifactProspectiveBindingV1, JointContactProspectiveBindingV1):
            raise TypeError("exact immutable Joint node binding required")


@dataclass(frozen=True, slots=True)
class QualifyJointPlanNodesRequestV1:
    plan_ref: str
    expected_plan_revision: int
    result_versions_digest: str

    def __post_init__(self):
        if AtomKey.from_token(self.plan_ref).type_name != "d08.joint_plan.v1" or self.expected_plan_revision < 1:
            raise ValueError("Joint continuation needs the exact adopted plan head")


@dataclass(frozen=True, slots=True)
class JointNodeQualificationV1:
    node_id: str
    binding_ref: str
    binding_digest: str
    state: str
    proof_ref: str | None
    missing_originals: tuple[str, ...]

    def __post_init__(self):
        if self.state not in ("ready", "completed_verified", "externally_confirmed", "waiting_dependency", "waiting_party", "cancelled", "waiting_original", "compensation_ready", "compensated_verified", "failed_verified", "cancelled_settled", "cancelled_unstarted"):
            raise ValueError("Joint node qualification state is not registered")
        if self.state == "completed_verified" and (self.proof_ref is None or self.missing_originals):
            raise ValueError("completed Joint node requires its actual verified original")


@dataclass(frozen=True, slots=True)
class JointPlanQualificationV1:
    namespace: NamespaceId
    plan_ref: str
    plan_revision: int
    plan_digest: str
    terms_digest: str
    result_versions_digest: str
    nodes: tuple[JointNodeQualificationV1, ...]
    read_versions: tuple[GraphVersion, ...]
    source_refs: tuple[str, ...]
    producing_operation_id: str
    schema: str = "d10.joint-plan-qualification.v1"

    def __post_init__(self):
        if (self.schema != "d10.joint-plan-qualification.v1" or type(self.namespace) is not NamespaceId
                or type(self.nodes) is not tuple or not 1 <= len(self.nodes) <= 8
                or len({node.node_id for node in self.nodes}) != len(self.nodes)
                or any(type(node) is not JointNodeQualificationV1 for node in self.nodes)
                or type(self.read_versions) is not tuple or len(self.read_versions) > 1024
                or any(type(version) is not GraphVersion for version in self.read_versions)
                or AtomKey.from_token(self.plan_ref).type_name != "d08.joint_plan.v1"
                or self.plan_revision < 1 or not self.producing_operation_id):
            raise ValueError("Joint qualification requires a bounded exact adopted plan")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def original_ref(self):
        return joint_qualification_ref_v1(self.namespace, self.producing_operation_id)



@dataclass(frozen=True, slots=True)
class JointExecutorIndexV1:
    namespace: NamespaceId
    selector_kind: str
    selector_key: tuple[str, ...]
    binding_ref: str
    binding_digest: str
    registration_request_digest: str
    source_refs: tuple[str, ...]
    schema: str = "d10.joint-executor-index.v1"

    def __post_init__(self):
        if (self.schema != "d10.joint-executor-index.v1" or self.selector_kind not in {"source_note", "artifact", "artifact_task", "contact", "action"}
                or not self.selector_key or self.binding_ref != BINDING_PREFIX + self.binding_digest):
            raise ValueError("executor index must point at its exact immutable Joint binding")

    @property
    def original_ref(self):
        return joint_executor_index_ref_v1(self.namespace, self.selector_kind, self.selector_key)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def joint_executor_index_ref_v1(namespace, selector_kind, selector_key):
    return "joint-executor-index:" + canonical_digest((namespace, selector_kind, tuple(selector_key)))


def joint_executor_index_values_v1(binding):
    executor = binding.executor
    if type(executor) is SourceNoteJointExecutorV1:
        kind, key = "source_note", (executor.authorization_original_ref,)
    elif type(executor) is ArtifactJointExecutorV1:
        kind, key = "artifact", (executor.c02_operation_id, executor.root_registration_ref,
            "legacy" if executor.phase_selector is None else executor.phase_selector.identity_digest)
    else:
        kind, key = "contact", (executor.prepare_contact_operation_id, executor.qualified_outbox_dedupe_key)
    aliases = ((kind, key),)
    if binding.action_ref is not None: aliases += (("action", (binding.action_ref,)),)
    if type(executor) is ArtifactJointExecutorV1:
        aliases += (("artifact_task", (executor.c02_operation_id, executor.root_registration_ref)),)
    return tuple(JointExecutorIndexV1(binding.namespace, selector_kind, selector_key,
        binding.original_ref, binding.digest, canonical_digest({"binding": plain_v1(binding)}), binding.source_refs) for selector_kind, selector_key in aliases)


def read_joint_executor_index_v1(db, *, namespace, selector_kind, selector_key, issuer):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3, background_verify_signature_v3, background_json_matches_v3
    ref = joint_executor_index_ref_v1(namespace, selector_kind, selector_key)
    row = _producer_original_point_v3(db, table="graph_d10_production_inputs_v1",
        columns=("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"),
        key_columns=("bot", "persona", "original_ref"), key=(*namespace.as_tuple, ref),
        legacy_reader=lambda: db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM graph_d10_production_inputs_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, ref)).fetchone())
    if row is None:
        return None
    background_verify_signature_v3(issuer._signer, "d11.d10-production-input.v1", row[2], row[4])
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    raw = background_json_loads_v3(row[2]); index = decode_typed_production_value_v1(raw, JointExecutorIndexV1)
    if (row[0] != "joint_executor_index_v1" or index.namespace != namespace or index.original_ref != ref
            or index.digest != row[3] or not background_json_matches_v3(row[2], raw)):
        raise ValueError("Joint executor index changed its exact immutable selector")
    from ..authority_service.artifact_model_original_family_v3 import register_artifact_model_joint_index_v3
    register_artifact_model_joint_index_v3(db,index)
    binding = read_joint_binding_v1(db, namespace=namespace, ref=index.binding_ref, issuer=issuer)
    if index not in joint_executor_index_values_v1(binding):
        raise ValueError("Joint executor index names another concrete action")
    return binding


def joint_qualification_operation_id_v1(namespace, request):
    return "joint-qualify:" + canonical_digest((namespace, request))[:48]


def joint_qualification_ref_v1(namespace, operation_id):
    return "joint-plan-qualification:" + canonical_digest((namespace, operation_id))


def decode_joint_binding_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    kinds={"d10.joint-artifact-prospective-binding.v1":JointArtifactProspectiveBindingV1,
        "d10.joint-contact-prospective-binding.v1":JointContactProspectiveBindingV1,
        "d10.joint-node-execution-binding.v1":JointNodeExecutionBindingV1}
    kind=kinds[raw["schema"]]
    return decode_typed_production_value_v1(raw, kind)


def read_joint_binding_v1(db, *, namespace, ref, issuer):
    if not ref.startswith(BINDING_PREFIX):
        raise MissingProductionOriginalV1("missing_registered_executor_binding:" + ref)
    row = _producer_original_point_v3(db, table="graph_d10_production_inputs_v1",
        columns=("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"),
        key_columns=("bot", "persona", "original_ref"), key=(*namespace.as_tuple, ref),
        legacy_reader=lambda: db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM graph_d10_production_inputs_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, ref)).fetchone())
    if row is None:
        raise MissingProductionOriginalV1("missing_registered_executor_binding:" + ref)
    background_verify_signature_v3(issuer._signer, "d11.d10-production-input.v1", row[2], row[4])
    raw = background_json_loads_v3(row[2]); value = decode_joint_binding_v1(raw)
    from ..authority_service.artifact_model_original_family_v3 import register_artifact_model_joint_binding_v3
    register_artifact_model_joint_binding_v3(db,value,row)
    original = read_adopted_domain_operation_v1(db, namespace, row[1])
    if (row[0] not in (BINDING_KIND, "joint_artifact_prospective_binding_v1","joint_contact_prospective_binding_v1") or not background_json_matches_v3(row[2], raw) or value.digest != row[3]
            or value.original_ref != ref or value.namespace != namespace or original is None
            or (original["domain"], original["operation_kind"]) != ("d10", "input:register_joint_node_execution_binding_v1")
            or original["payload"]["request"] != {"binding": raw}):
        raise ValueError("Joint binding lost its exact committed D10 producer")
    from .domain_background_read_v3 import register_joint_budget_locator_v3
    register_joint_budget_locator_v3(db, original=row[2], namespace=namespace,
        lease_id=value.parent_budget_lease_ref, version=value.parent_grant_version)
    return value


def qualify_joint_binding_v1(db, *, frame, binding, issuer):
    from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1, qualify_artifact_prospective_binding_v1
    if type(binding) is JointArtifactProspectiveBindingV1:
        return qualify_artifact_prospective_binding_v1(db, frame=frame, binding=binding, issuer=issuer)
    if type(binding) is JointContactProspectiveBindingV1:
        from .joint_contact_prospective_binding_v1 import qualify_contact_prospective_binding_v1
        return qualify_contact_prospective_binding_v1(db,frame=frame,binding=binding,issuer=issuer)
    read = CurrentDomainReadV1(frame); read.check(db)
    if binding.namespace != frame.envelope.authority.namespace:
        raise ValueError("Joint binding belongs to another installed namespace")
    action_atom = read.head(db, binding.action_ref, required=True)
    schema_atom = read.head(db, binding.action_schema_ref, required=True)
    action = _decode_intent(action_atom.value)
    record = _decode("d08.action_schema.v1", schema_atom.value)
    from .d08_life_admission_v1 import _adopted
    for atom in (action_atom, schema_atom):
        _adopted(db, read, atom)
    if ((action_atom.revision, canonical_digest(action_atom.value)) != (binding.action_revision, binding.action_digest)
            or (schema_atom.revision, canonical_digest(schema_atom.value)) != (binding.action_schema_revision, binding.action_schema_digest)
            or record != ActionSchemaRecord.bind(action, ActionSchema(record.schema_id, record.action_kind, record.proactive, record.required_checks))
            or (action.action_kind, action.target_ref, action.goal_ref, action.purpose, action.success_predicate) !=
                (binding.action_kind, binding.target_ref, binding.goal_id,
                 binding.purpose, binding.success_predicate)
            or not set(action.source_refs) <= set(binding.source_refs)):
        raise ValueError("Joint binding changed its exact adopted action/schema/success terms")
    grant = issuer.current_budget_grant(db, binding.parent_budget_lease_ref)
    if (grant.grant_id, grant.version, canonical_digest(grant)) != (
            binding.parent_grant_id, binding.parent_grant_version, binding.parent_grant_digest):
        raise MissingProductionOriginalV1("actual_joint_parent_budget_grant")
    for audience in binding.audience:
        read.source_family(db, binding.source_refs, purpose=binding.purpose, audience=audience)
    cancellation = AtomKey(action_atom.key.owner, "d08.action_cancellation.v1", action.action_id)
    cancel = read.head(db, cancellation)
    if cancel.valid and cancel.revision and cancel.value["state"] == "cancelled":
        return action, "cancelled"
    if frame.now_utc >= binding.original_deadline_utc:
        return action, "cancelled"
    if type(binding.executor) is SourceNoteJointExecutorV1:
        from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
        saved = read_owner_source_note_task_authorization_v2(db, namespace=binding.namespace,
            original_ref=binding.executor.authorization_original_ref, issuer=issuer)
        if saved is None:
            raise MissingProductionOriginalV1("actual_joint_source_note_owner_authorization")
        auth = saved[0]
        from .owner_source_note_life_v1 import owner_source_note_life_ids_v1
        ids = owner_source_note_life_ids_v1(auth)
        if ((auth.request.project_ref, auth.request.recipe_ref, auth.request.body_source_ref, auth.request.target_entity_ref,
             auth.request.role_binding_ref, ids["goal_key"].token, ids["progress_ref"], auth.cause.parent_budget_lease_ref,
             auth.cause.original_deadline_utc) !=
            (binding.project_ref, binding.recipe_ref, binding.source_refs[0], binding.target_entity_ref, binding.role_ref,
             binding.goal_ref, binding.progress_ref, binding.parent_budget_lease_ref, binding.original_deadline_utc)
                or action.identity.effect_id != ids["effect_id"]):
            raise ValueError("Joint source-note binding differs from its original Owner task")
        read.original(auth.original_ref, digest=auth.digest)
    elif type(binding.executor) is ArtifactJointExecutorV1:
        from .d08_personal_plan_v1 import artifact_draft_action_keys_v1
        from .d11_life_preparation_v1 import _read
        saved = _read(db, issuer=issuer, namespace=binding.namespace, kind="draft_root_capability",
            ref=binding.executor.root_registration_ref)
        if saved is None:
            raise MissingProductionOriginalV1("actual_joint_artifact_root_authorization")
        root = saved[0]
        if binding.executor.phase_selector is None:
            expected = artifact_draft_action_keys_v1(binding.namespace,
                c02_operation_id=binding.executor.c02_operation_id, root_registration_ref=binding.executor.root_registration_ref)[0]
        else:
            from .d08_personal_plan_v1 import artifact_phase_action_keys_v2
            phase = binding.executor.phase_selector
            if (phase.task.namespace, phase.task.c02_operation_id, phase.task.root_registration_ref) != (
                    binding.namespace, binding.executor.c02_operation_id, binding.executor.root_registration_ref):
                raise ValueError("Joint Artifact phase changed its exact original task")
            expected = artifact_phase_action_keys_v2(phase)[0]
        if (expected.token != binding.action_ref or binding.executor.source_ref not in binding.source_refs
                or root["source_ref"] != binding.executor.source_ref):
            raise ValueError("Joint artifact binding differs from the fixed cycle action")
        read.original(binding.executor.c02_operation_id)
        read.original(binding.executor.root_registration_ref, digest=canonical_digest(root))
    else:
        row = db.execute("SELECT causal_operation_id,event_kind FROM graph_domain_production_outbox_v1 "
            "WHERE bot=? AND persona=? AND dedupe_key=?", (*binding.namespace.as_tuple, binding.executor.qualified_outbox_dedupe_key)).fetchone()
        causal = read_adopted_domain_operation_v1(db, binding.namespace, binding.executor.prepare_contact_operation_id)
        if (row != (binding.executor.prepare_contact_operation_id, "qualified_contact_opportunity_requires_action")
                or causal is None or (causal["domain"], causal["operation_kind"]) != ("d10", "prepare_contact")
                or causal["payload"]["parent_budget"] != binding.parent_budget_lease_ref):
            raise ValueError("Joint Contact binding differs from the existing qualified original")
    return action, "current"


def _plan_original_v1(db, *, frame, request, readers):
    from .d08_life_admission_v1 import _adopted
    from ..domains.d08.production_operations_v1 import AdoptCurrentJointPlanRequestV1
    read = CurrentDomainReadV1(frame); read.check(db)
    atom = read.head(db, request.plan_ref, required=True); _adopted(db, read, atom)
    if atom.revision != request.expected_plan_revision:
        raise ValueError("Joint plan changed its original execution revision")
    row = background_history_v3(db, atom.key.token, atom.revision, columns=("event_id",))
    original = read_adopted_domain_operation_v1(db, frame.envelope.authority.namespace, row[0])
    if original is None or (original["domain"], original["operation_kind"]) != ("d08", "adopt_joint_plan"):
        raise ValueError("Joint plan lost its actual adopted W01 original")
    raw = original["payload"]["request"]
    current = readers.read_joint_plan(db, frame, AdoptCurrentJointPlanRequestV1(
        raw["joint_plan_proposal_ref"], tuple(raw["party_consent_original_refs"])), for_execution=True)
    plan = _decode_joint_plan(atom.value)
    if plain_v1(current.plan) != atom.value:
        raise MissingProductionOriginalV1("actual_current_joint_plan_terms_and_party_consents")
    return plan, current


def qualify_joint_plan_nodes_v1(db, *, frame, request, readers):
    plan, current = _plan_original_v1(db, frame=frame, request=request, readers=readers)
    if request.result_versions_digest != joint_result_versions_digest_v1(db, namespace=frame.envelope.authority.namespace, plan=plan):
        raise ValueError("Joint qualification actual result versions changed")
    read = CurrentDomainReadV1(frame); ns = frame.envelope.authority.namespace
    qualified, completed = {}, set()
    roots = list(plan.source_refs)
    from .d10_project_checkpoint_v1 import InstalledD10ProjectReadersV1
    for node in plan.nodes:
        try:
            if node.owner_ref != "persona:" + ns.persona_id:
                from .joint_external_observation_v1 import read_joint_d08_original_v1, current_external_node_observation_v1
                contract = read_joint_d08_original_v1(db, namespace=ns, original_ref=node.resource_ref, issuer=readers.issuer)
                roots.extend(contract.source_refs)
                observation = current_external_node_observation_v1(db, frame=frame, plan_ref=request.plan_ref,
                    plan=plan, inputs=current, node=node, issuer=readers.issuer)
                if observation is not None:
                    roots.extend(observation.source_refs)
                    completed.add(node.node_id)
                qualified[node.node_id] = JointNodeQualificationV1(node.node_id, contract.original_ref, contract.digest,
                    "waiting_party" if observation is None else "externally_confirmed",
                    None if observation is None else observation.original_ref,
                    ("actual_external_node_confirmation",) if observation is None else ())
                continue
            binding = read_joint_binding_v1(db, namespace=ns, ref=node.resource_ref, issuer=readers.issuer)
            if (binding.plan_ref, binding.plan_revision, binding.node_id, binding.owner_ref, binding.action_kind, binding.success_predicate) != (
                    request.plan_ref, plan.revision, node.node_id, node.owner_ref, node.action_kind, node.success_predicate):
                raise ValueError("Joint node binding is outside the exact party consent terms")
            roots.extend(binding.source_refs)
            from .owner_goal_projection_v1 import require_joint_artifact_goal_projection_gate_v1
            require_joint_artifact_goal_projection_gate_v1(db,namespace=ns,binding=binding,issuer=readers.issuer)
            action, state = qualify_joint_binding_v1(db, frame=frame, binding=binding, issuer=readers.issuer)
            proof_ref = None; missing = ()
            from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1, completed_artifact_joint_objective_v1
            if type(binding) is JointArtifactProspectiveBindingV1:
                proof_ref = completed_artifact_joint_objective_v1(db, frame=frame, binding=binding, issuer=readers.issuer)
                if proof_ref is not None:
                    completed.add(node.node_id); state = "completed_verified"
                elif state == "current": state = "ready"
                else:
                    raise MissingProductionOriginalV1("actual_prospective_artifact_cancellation_settlement")
                qualified[node.node_id] = JointNodeQualificationV1(node.node_id, binding.original_ref, binding.digest, state, proof_ref, ())
                continue
            outcomes = tuple(atom for atom in read.complete_inventory(db, "d08.action_outcome.v1")
                if atom.valid and atom.value["action_id"] == action.action_id
                and atom.value["effect_id"] == action.identity.effect_id and atom.value["attempt_id"] == action.identity.attempt_id)
            if outcomes and any(atom.value["unknown_effects"] or atom.value["result_level"] == "unknown" for atom in outcomes):
                qualified[node.node_id] = JointNodeQualificationV1(node.node_id, binding.original_ref, binding.digest,
                    "waiting_original", None, ("actual_original_joint_unknown_effect_settlement",))
                continue
            if outcomes and outcomes[-1].value["result_level"] == "failed_verified":
                from .joint_compensation_v1 import qualify_joint_compensation_v1, settled_joint_trigger_v1
                if node.compensation_ref is not None:
                    qualified[node.node_id] = qualify_joint_compensation_v1(db, frame=frame, plan=plan, node=node, binding=binding, issuer=readers.issuer)
                else:
                    settled = settled_joint_trigger_v1(db, frame=frame, binding=binding, issuer=readers.issuer, trigger_kind="failed_verified_settled")
                    qualified[node.node_id] = JointNodeQualificationV1(node.node_id, binding.original_ref, binding.digest, "failed_verified", settled, ())
                continue
            if state == "cancelled" and node.compensation_ref is not None:
                from .joint_compensation_v1 import qualify_joint_compensation_v1
                qualification = qualify_joint_compensation_v1(db, frame=frame, plan=plan, node=node, binding=binding, issuer=readers.issuer)
                repair = read_joint_binding_v1(db, namespace=ns, ref=qualification.binding_ref, issuer=readers.issuer)
                roots.extend(repair.source_refs)
                qualified[node.node_id] = qualification
                continue
            if state == "cancelled":
                from .joint_compensation_v1 import settled_joint_trigger_v1, actual_unstarted_joint_cancellation_v1
                unstarted = actual_unstarted_joint_cancellation_v1(db, frame=frame, binding=binding, issuer=readers.issuer)
                if unstarted is not None:
                    qualified[node.node_id] = JointNodeQualificationV1(node.node_id, binding.original_ref, binding.digest, "cancelled_unstarted", unstarted, ())
                    continue
                proof_ref = settled_joint_trigger_v1(db, frame=frame, binding=binding, issuer=readers.issuer, trigger_kind="cancelled_settled")
                state = "cancelled_settled"
            elif binding.progress_ref is not None:
                progress = read.head(db, binding.progress_ref)
                if progress.valid and progress.revision:
                    from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
                    from .d10_project_checkpoint_v1 import LifeProgressHeadV1
                    value = LifeProgressHeadV1(**{**progress.value, "receipt_refs": tuple(progress.value["receipt_refs"]),
                        "source_refs": tuple(progress.value["source_refs"])})
                    require_current_life_progress_v1(db, namespace=ns, progress=value, issuer=readers.issuer, read=read)
                    proof = InstalledD10ProjectReadersV1(issuer=readers.issuer).read_effect(db, frame, binding.progress_ref)
                    if (value.reality != "real_execution" or not proof.completed_verified
                            or proof.action_intent_ref != binding.action_ref or proof.effect_id != action.identity.effect_id
                            or proof.success_predicate != node.success_predicate
                            or (proof.project_ref, proof.recipe_ref) != (binding.project_ref, binding.recipe_ref)):
                        raise ValueError("Joint node progress does not prove this exact actual effect")
                    state, proof_ref = "completed_verified", binding.progress_ref
                    completed.add(node.node_id)
                else:
                    state = "ready" if node.owner_ref == "persona:" + ns.persona_id else "waiting_party"
            else:
                proof_ref = completed_contact_joint_effect_v1(db, read=read, action=action, binding=binding)
                if proof_ref is not None:
                    state = "completed_verified"; completed.add(node.node_id)
                else:
                    state = "ready" if node.owner_ref == "persona:" + ns.persona_id else "waiting_party"
            qualified[node.node_id] = JointNodeQualificationV1(node.node_id, binding.original_ref, binding.digest, state, proof_ref, missing)
        except MissingProductionOriginalV1 as error:
            qualified[node.node_id] = JointNodeQualificationV1(node.node_id, node.resource_ref, "", "waiting_original", None, error.missing_inputs)
    values = []
    for node in plan.nodes:
        value = qualified[node.node_id]
        if value.state == "ready" and not set(node.depends_on) <= completed:
            value = JointNodeQualificationV1(value.node_id, value.binding_ref, value.binding_digest,
                "waiting_dependency", None, tuple("verified_joint_dependency:" + dep for dep in node.depends_on if dep not in completed))
        values.append(value)
    return JointPlanQualificationV1(ns, request.plan_ref, plan.revision, canonical_digest(plain_v1(plan)),
        current.terms_digest, request.result_versions_digest, tuple(values), frame.snapshot.versions, tuple(dict.fromkeys(roots)), frame.envelope.identity.operation_id)



def joint_input_read_plan_v1(db, *, namespace, request):
    from .d01_production_operations_v1 import raw_registered_input_v1
    if type(request) is RegisterJointNodeExecutionBindingRequestV1:
        binding = request.binding
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1, artifact_prospective_read_inputs_v1
        if type(binding) is JointArtifactProspectiveBindingV1:
            keys, roots, originals = artifact_prospective_read_inputs_v1(db, binding=binding)
            return production_read_plan_v1(("d08.action_cancellation.v1", "d08.action_outcome.v1", "d03.role_binding", "runtime.cost_settlement"), keys, roots, originals)
        if type(binding) is JointContactProspectiveBindingV1:
            from .contact_owner_command_source_v3 import read_plan_joint_contact_owner_source_v3
            from .contact_host_source_v3 import contact_host_work_for_db_v3
            work=contact_host_work_for_db_v3(db)
            if work is None:raise ValueError('Contact prospective binding input requires actual private Owner Source READ and fresh WRITE')
            exact=read_plan_joint_contact_owner_source_v3(db,namespace=namespace,request=request,activity_id=work.result['activity_id'])
            from .joint_contact_prospective_binding_v1 import contact_prospective_joint_read_inputs_v1
            keys,roots,originals=contact_prospective_joint_read_inputs_v1(binding)
            preparation=work.result['binding_preparation']
            return production_read_plan_v1((*exact.fixed_type_ids,"d08.action_cancellation.v1","d08.action_outcome.v1","runtime.cost_settlement"),
                (*exact.exact_keys,*keys),exact.source_roots,(*exact.required_original_refs,*originals,preparation.original_ref))
        refs = (binding.action_ref, binding.action_schema_ref, binding.project_ref, binding.recipe_ref,
            binding.goal_ref, binding.target_entity_ref, binding.role_ref, binding.progress_ref)
        return production_read_plan_v1(("d08.action_cancellation.v1", "d08.action_outcome.v1", "runtime.cost_settlement"),
            tuple(AtomKey.from_token(ref) for ref in refs if ref is not None), binding.source_refs, joint_executor_originals_v1(binding))
    key = AtomKey.from_token(request.plan_ref)
    current_head = _joint_head_v1(db, namespace, key)
    row = None if current_head is None or not current_head[2] else (current_head[1],)
    keys, roots, originals = [key], [], []
    from ..graph_types import owner_grant_key
    keys.append(owner_grant_key(*namespace.as_tuple))
    if row is not None:
        plan = _decode_joint_plan(background_json_loads_v3(row[0])); roots.extend(plan.source_refs)
        history = background_history_v3(db, key.token, request.expected_plan_revision, columns=("event_id",))
        adopted = None if history is None else read_adopted_domain_operation_v1(db, namespace, history[0])
        if adopted is not None:
            prior_request = adopted["payload"]["request"]
            originals.extend((prior_request["joint_plan_proposal_ref"], *prior_request["party_consent_original_refs"]))
            intent = raw_registered_input_v1(db, "graph_d08_joint_plan_intents_v1", namespace, prior_request["joint_plan_proposal_ref"])
            if intent:
                keys.extend(AtomKey.from_token(ref) for ref in intent["current_goal_refs"])
                roots.extend(intent["source_refs"])
            for consent_ref in prior_request["party_consent_original_refs"]:
                consent = raw_registered_input_v1(db, "graph_d08_party_consents_v1", namespace, consent_ref)
                if consent:
                    keys.append(AtomKey.from_token(consent["acceptance_interpretation_ref"]))
                    roots.append(consent["inbound_source_ref"])
                    originals.extend((consent["acceptance_interpretation_ref"], *consent["outbound_receipt_refs"]))
        for node in plan.nodes:
            if node.owner_ref != "persona:" + namespace.persona_id:
                from .joint_external_observation_v1 import joint_external_plan_read_inputs_v1
                extra_keys, extra_roots, extra_originals = joint_external_plan_read_inputs_v1(db, namespace=namespace, node=node)
                keys.extend(extra_keys); roots.extend(extra_roots); originals.extend(extra_originals)
                continue
            raw = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, node.resource_ref)
            if node.resource_ref.startswith(BINDING_PREFIX): originals.append(node.resource_ref)
            if raw and raw.get("schema") in ("d10.joint-node-execution-binding.v1", "d10.joint-artifact-prospective-binding.v1","d10.joint-contact-prospective-binding.v1"):
                binding = decode_joint_binding_v1(raw); roots.extend(binding.source_refs)
                originals.extend(joint_executor_originals_v1(binding))
                from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1, artifact_prospective_read_inputs_v1
                if type(binding) is JointArtifactProspectiveBindingV1:
                    extra_keys, extra_roots, extra_originals = artifact_prospective_read_inputs_v1(db, binding=binding)
                    keys.extend(extra_keys); roots.extend(extra_roots); originals.extend(extra_originals)
                if type(binding) is JointContactProspectiveBindingV1:
                    from .joint_contact_prospective_binding_v1 import contact_prospective_joint_read_inputs_v1
                    extra_keys,extra_roots,extra_originals=contact_prospective_joint_read_inputs_v1(binding)
                    keys.extend(extra_keys);roots.extend(extra_roots);originals.extend(extra_originals)
                if node.compensation_ref is not None:
                    from .joint_external_observation_v1 import TABLE as JOINT_D08_TABLE
                    compensation_raw = raw_registered_input_v1(db, JOINT_D08_TABLE, namespace, node.compensation_ref)
                    originals.append(node.compensation_ref)
                    if compensation_raw is not None:
                        repair_raw = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, compensation_raw["repair_binding_ref"])
                        if repair_raw is not None:
                            repair = decode_joint_binding_v1(repair_raw)
                            roots.extend(repair.source_refs)
                            roots.extend(compensation_raw["source_refs"])
                            originals.extend((repair.original_ref, *joint_executor_originals_v1(repair)))
                            for ref in (repair.action_ref, repair.action_schema_ref, repair.project_ref, repair.recipe_ref,
                                    repair.goal_ref, repair.target_entity_ref, repair.role_ref, repair.progress_ref):
                                if ref is not None: keys.append(AtomKey.from_token(ref))
                            if repair.progress_ref is not None:
                                from .d10_life_progress_provenance_v1 import life_progress_current_read_inputs_v1
                                more_keys, more_roots, more_originals = life_progress_current_read_inputs_v1(db, namespace, repair.progress_ref)
                                keys.extend(more_keys); roots.extend(more_roots); originals.extend(more_originals)
                for ref in (binding.action_ref, binding.action_schema_ref, binding.project_ref, binding.recipe_ref,
                        binding.goal_ref, binding.target_entity_ref, binding.role_ref, binding.progress_ref):
                    if ref is not None: keys.append(AtomKey.from_token(ref))
                if binding.progress_ref:
                    from .d10_life_progress_provenance_v1 import life_progress_current_read_inputs_v1
                    more_keys, more_roots, more_originals = life_progress_current_read_inputs_v1(db, namespace, binding.progress_ref)
                    keys.extend(more_keys); roots.extend(more_roots); originals.extend(more_originals)
    from ..domains.d12.types import active_scheme_head_key
    keys.append(active_scheme_head_key(namespace))
    for ticket in background_inventory_v3(db, namespace, "d07.attention_ticket.v1", valid_only=True):
        roots.extend(ticket.value["source_refs"])
    return production_read_plan_v1(("d03.entity_anchor", "d03.account_binding", "d05.boundary_rule", "d07.current_interpretation.v1",
        "d07.attention_ticket.v1", "d07.focus.v1", "d07.concern_round.v1",
        "d08.goal.v1", "d08.action_intent.v1", "d08.action_schema.v1", "d08.action_cancellation.v1",
        "d08.action_outcome.v1", "d10.life_progress.v1", "runtime.cost_settlement"), keys, roots, originals)


def _joint_head_v1(db, namespace, ref):
    key = AtomKey.from_token(ref) if type(ref) is str else ref
    return _producer_original_point_v3(db, table="graph_atoms", columns=("revision", "value", "valid"),
        key_columns=("token", "bot", "persona"), key=(key.token, *namespace.as_tuple),
        legacy_reader=lambda: db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (key.token, *namespace.as_tuple)).fetchone())


def joint_result_versions_digest_v1(db, *, namespace, plan):
    """Actual finite heads vary qualification rounds; executor identities stay fixed."""
    from ..graph_types import owner_grant_key
    from ..memory_types import access_key
    from .d01_production_operations_v1 import raw_registered_input_v1
    versions = []
    grant_key = owner_grant_key(*namespace.as_tuple); grant = _joint_head_v1(db, namespace, grant_key)
    versions.append((grant_key.token, None if grant is None else (grant[0], grant[2])))
    for kind in ("d05.boundary_rule", "d03.role_binding", "d07.current_interpretation.v1", "d08.action_outcome.v1"):
        rows = background_inventory_v3(db, namespace, kind, valid_only=False)
        if len(rows) > 128:
            raise MissingProductionOriginalV1("bounded_joint_current_gate_inventory:" + kind)
        versions.extend((atom.key.token, atom.revision, atom.valid) for atom in rows)
    for node in plan.nodes:
        if node.owner_ref != "persona:" + namespace.persona_id:
            from .joint_external_observation_v1 import joint_external_result_versions_v1
            versions.extend(joint_external_result_versions_v1(db, namespace=namespace, node=node)); continue
        raw = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, node.resource_ref)
        if raw is None:
            versions.append((node.resource_ref, 0)); continue
        binding = decode_joint_binding_v1(raw)
        if binding.action_ref is None:
            refs = (binding.goal_ref, binding.project_ref, binding.recipe_ref, binding.role_ref, *binding.source_refs,
                *(access_key(*namespace.as_tuple, AtomKey.from_token(ref).owner.subject).token for ref in binding.source_refs))
            for ref in refs:
                head = _joint_head_v1(db, namespace, ref)
                versions.append((ref, None if head is None else (head[0], head[2])))
            continue
        action_key = AtomKey.from_token(binding.action_ref)
        refs = (binding.action_ref, binding.action_schema_ref, binding.progress_ref,
            AtomKey(action_key.owner, "d08.action_cancellation.v1", action_key.name).token, *binding.source_refs,
            *(access_key(*namespace.as_tuple, AtomKey.from_token(ref).owner.subject).token for ref in binding.source_refs))
        for ref in refs:
            if ref is not None:
                head = _joint_head_v1(db, namespace, ref)
                versions.append((ref, None if head is None else (head[0], head[2])))
    return canonical_digest(tuple(versions))


def completed_contact_joint_effect_v1(db, *, read, action, binding):
    """Only an actual verified ActionOutcome and original cost can close a node."""
    ns = binding.namespace
    outcomes = tuple(atom for atom in read.complete_inventory(db, "d08.action_outcome.v1")
        if atom.valid and atom.value.get("action_id") == action.action_id
        and atom.value.get("effect_id") == action.identity.effect_id
        and atom.value.get("attempt_id") == action.identity.attempt_id)
    if not outcomes:
        return None
    if len(outcomes) != 1:
        raise ValueError("Joint Contact has ambiguous actual outcomes for the same effect")
    atom = outcomes[0]; outcome = _decode("d08.action_outcome.v1", atom.value)
    if (outcome.result_level != "completed_verified" or outcome.unknown_effects
            or outcome.completed_effects != (action.identity.effect_id,)):
        return None
    history = background_history_v3(db, atom.key.token, atom.revision, columns=("event_id",))
    production = None if history is None else read_adopted_domain_operation_v1(db, ns, history[0])
    if production is None or (production["domain"], production["operation_kind"]) != ("d08", "settle_observed_action"):
        raise MissingProductionOriginalV1("actual_registered_joint_contact_verified_outcome_producer")
    provenance = production["payload"]["provenance"]
    if provenance["action_outcome"] != atom.value:
        raise ValueError("Joint Contact outcome changed its adopted observation original")
    request = production["payload"]["request"]
    if request["action_intent_ref"] != binding.action_ref:
        raise ValueError("Joint Contact outcome belongs to another exact Action")
    read.original(request["cost_settlement_ref"], digest=provenance["cost_original"]["original_digest"])
    read.original(request["outbound_receipt_ref"], digest=provenance["observation_original"]["original_digest"])
    if (not binding.success_predicate.valid_from <= outcome.observed_at <= binding.original_deadline_utc
            or binding.success_predicate != action.success_predicate):
        raise ValueError("Joint Contact verified outcome changed its original deadline or predicate")
    return atom.key.token


def validate_joint_input_v1(db, *, frame, request, issuer, installed_readers=None):
    from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
    if type(request) is RegisterJointNodeExecutionBindingRequestV1:
        binding = request.binding
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1, require_installed_artifact_joint_contract_v1
        if type(binding) is JointArtifactProspectiveBindingV1:
            if installed_readers is None: raise MissingProductionOriginalV1("actual_installed_joint_artifact_build_reader")
            require_installed_artifact_joint_contract_v1(binding, readers=installed_readers)
        if binding.owner_ref != "persona:" + binding.namespace.persona_id:
            raise MissingProductionOriginalV1("actual_independent_party_executor_original")
        action, state = qualify_joint_binding_v1(db, frame=frame, binding=binding, issuer=issuer)
        if state != "current" or frame.envelope.parent_budget_lease_ref != binding.parent_budget_lease_ref:
            raise ValueError("Joint binding registration changed original authorization or deadline")
        return binding
    return qualify_joint_plan_nodes_v1(db, frame=frame, request=request, readers=InstalledD08ProductionReadersV1(issuer=issuer))




def joint_followup_resolution_v1(db, *, frame, original, issuer):
    from .domain_production_followups_v1 import DomainFollowupCommandV1, DomainFollowupResolutionV1
    ns = frame.envelope.authority.namespace
    refs = tuple(version.key.token for version in original["receipt"].write_versions
        if version.key.type_name == "d08.joint_plan.v1")
    if not refs and original["operation_kind"] == "input:observe_joint_external_node_v1":
        refs = (original["payload"]["request"]["plan_ref"],)
    commands = []
    complete = True
    for ref in refs:
        atom = CurrentDomainReadV1(frame).head(db, ref, required=True)
        plan = _decode_joint_plan(atom.value)
        request = QualifyJointPlanNodesRequestV1(ref, atom.revision,
            joint_result_versions_digest_v1(db, namespace=ns, plan=plan))
        from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
        qualification = qualify_joint_plan_nodes_v1(db, frame=frame, request=request, readers=InstalledD08ProductionReadersV1(issuer=issuer))
        complete = complete and all(node.state in {"completed_verified", "externally_confirmed", "failed_verified", "cancelled_settled", "cancelled_unstarted", "compensated_verified"} for node in qualification.nodes)
        from .joint_external_observation_v1 import current_external_observation_requests_v1
        pending_observations = current_external_observation_requests_v1(db, frame=frame, plan_ref=ref, issuer=issuer)
        from .joint_external_observation_v1 import current_joint_semantic_question_requests_v1
        questions = current_joint_semantic_question_requests_v1(db, frame=frame, plan_ref=ref, issuer=issuer)
        commands.extend(DomainFollowupCommandV1("d07", "input:prepare_joint_external_semantic_question_v1", question,
            "joint-question:" + canonical_digest((ns, ref, question.node_id, question.inbound_source))[:48],
            frame.envelope.authority.audience[0], frame.envelope.authority.audience) for question in questions)
        commands.extend(DomainFollowupCommandV1("d08", "input:observe_joint_external_node_v1", observed,
            "joint-plan:" + canonical_digest((ns, ref, atom.revision))[:48], frame.envelope.authority.audience[0],
            frame.envelope.authority.audience) for observed in pending_observations)
        commands.append(DomainFollowupCommandV1("d10", "input:qualify_joint_plan_nodes_v1", request,
            "joint-plan:" + canonical_digest((ns, ref, atom.revision))[:48], frame.envelope.authority.audience[0],
            frame.envelope.authority.audience))
    if complete and commands:
        return DomainFollowupResolutionV1("ready", tuple(commands), refs, ())
    return DomainFollowupResolutionV1("partial" if commands else "waiting_for_original", tuple(commands), refs,
        ("actual_joint_node_executor_completion_and_successor_progress",),
        "joint-node-results:" + canonical_digest((ns, refs))[:48])


def read_joint_execution_wakes_v1(db, *, namespace, qualification_ref, issuer, frame):
    """Signed qualification is a locator; original executor still obtains each fence."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    row = _producer_original_point_v3(db, table="graph_d10_production_inputs_v1",
        columns=("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"),
        key_columns=("bot", "persona", "original_ref"), key=(*namespace.as_tuple, qualification_ref),
        legacy_reader=lambda: db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM graph_d10_production_inputs_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, qualification_ref)).fetchone())
    if row is None or row[0] != QUALIFICATION_KIND:
        raise MissingProductionOriginalV1("actual_joint_qualification_original")
    background_verify_signature_v3(issuer._signer, "d11.d10-production-input.v1", row[2], row[4])
    value = decode_typed_production_value_v1(background_json_loads_v3(row[2]), JointPlanQualificationV1)
    if value.original_ref != qualification_ref or value.digest != row[3] or value.namespace != namespace:
        raise ValueError("Joint qualification changed its immutable bytes")
    original = read_adopted_domain_operation_v1(db, namespace, row[1])
    if original is None or (original["domain"], original["operation_kind"]) != ("d10", "input:qualify_joint_plan_nodes_v1"):
        raise ValueError("Joint qualification lost its exact same-W01 producer")
    wakes = []
    for node in value.nodes:
        if node.state != "ready":
            continue
        binding = read_joint_binding_v1(db, namespace=namespace, ref=node.binding_ref, issuer=issuer)
        if binding.digest != node.binding_digest or binding.owner_ref != "persona:" + namespace.persona_id:
            raise ValueError("Joint executor wake crosses party authority")
        current = require_current_joint_binding_gate_v1(db, frame=frame, binding=binding, issuer=issuer)
        current_node = next(node for node in current.nodes if node.binding_ref == binding.original_ref)
        if current_node.state in {"ready", "compensation_ready"}:
            wakes.append(binding)
    return tuple(wakes)


def require_joint_executor_gate_v1(db, *, namespace, binding, issuer):
    """Read the exact durable qualifier for current heads; issue no execution grant."""
    from .joint_window_management_v1 import require_managed_joint_execution_v1
    require_managed_joint_execution_v1(db,namespace=namespace,issuer=issuer,binding=binding)
    plan_row = _joint_head_v1(db, namespace, binding.plan_ref)
    if plan_row is None or not plan_row[2] or plan_row[0] != binding.plan_revision:
        raise MissingProductionOriginalV1("actual_current_joint_plan_revision")
    plan = _decode_joint_plan(background_json_loads_v3(plan_row[1]))
    from .artifact_host_dispatch_source_v3 import register_artifact_host_joint_current_plan_v3
    register_artifact_host_joint_current_plan_v3(db,namespace=namespace,binding=binding,plan=plan)
    request = QualifyJointPlanNodesRequestV1(binding.plan_ref, binding.plan_revision,
        joint_result_versions_digest_v1(db, namespace=namespace, plan=plan))
    operation_id = joint_qualification_operation_id_v1(namespace, request)
    ref = joint_qualification_ref_v1(namespace, operation_id)
    from .artifact_host_dispatch_source_v3 import register_artifact_host_joint_qualification_v3
    register_artifact_host_joint_qualification_v3(db,namespace=namespace,binding=binding,plan=plan,request=request,operation_id=operation_id,ref=ref)
    row = _producer_original_point_v3(db, table="graph_d10_production_inputs_v1",
        columns=("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"),
        key_columns=("bot", "persona", "original_ref"), key=(*namespace.as_tuple, ref),
        legacy_reader=lambda: db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM graph_d10_production_inputs_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, ref)).fetchone())
    if row is None:
        raise MissingProductionOriginalV1("current_joint_party_consent_and_verified_dependencies:" + binding.node_id)
    background_verify_signature_v3(issuer._signer, "d11.d10-production-input.v1", row[2], row[4])
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(background_json_loads_v3(row[2]), JointPlanQualificationV1)
    node = next((node for node in value.nodes if node.binding_ref == binding.original_ref), None)
    if (row[0] != QUALIFICATION_KIND or row[1] != operation_id or value.digest != row[3] or value.original_ref != ref
            or value.plan_digest != canonical_digest(plain_v1(plan)) or node is None or node.binding_digest != binding.digest
            or node.state not in {"ready", "completed_verified", "compensation_ready", "compensated_verified"}):
        raise MissingProductionOriginalV1("actual_joint_ready_node_original:" + binding.node_id)
    original = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if original is None or (original["domain"], original["operation_kind"]) != ("d10", "input:qualify_joint_plan_nodes_v1"):
        raise ValueError("Joint qualifier lost its exact same-W01 producer")
    return value


def require_joint_bound_action_gate_v1(db, *, namespace, action_ref, issuer, frame=None):
    from .joint_window_management_v1 import require_managed_joint_execution_v1
    require_managed_joint_execution_v1(db,namespace=namespace,issuer=issuer,action_ref=action_ref,frame=frame)
    binding = read_joint_executor_index_v1(db, namespace=namespace, selector_kind="action", selector_key=(action_ref,), issuer=issuer)
    if binding is None:
        from .joint_artifact_execution_v1 import joint_artifact_binding_for_adopted_action_v1
        binding = joint_artifact_binding_for_adopted_action_v1(db, namespace=namespace, action_ref=action_ref, issuer=issuer)
        if binding is None: return
    from .owner_goal_projection_v1 import require_joint_artifact_goal_projection_gate_v1
    require_joint_artifact_goal_projection_gate_v1(db,namespace=namespace,binding=binding,issuer=issuer)
    if frame is None:
        return require_joint_executor_gate_v1(db, namespace=namespace, binding=binding, issuer=issuer)
    return require_current_joint_binding_gate_v1(db, frame=frame, binding=binding, issuer=issuer)


def validate_joint_original_joins_v1(db):
    """C09 checks exact scalar producer joins; no current execution is authorized."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1, DomainProductionErasureHold
    from .joint_external_observation_v1 import validate_joint_d08_joins_v1
    rows = db.execute("SELECT bot,persona,original_ref,kind,producing_operation_id,payload_json,payload_digest "
        "FROM graph_d10_production_inputs_v1 WHERE kind IN (?,?,?,?)", (BINDING_KIND, "joint_artifact_prospective_binding_v1", QUALIFICATION_KIND, "joint_executor_index_v1"))
    types = {BINDING_KIND: JointNodeExecutionBindingV1, "joint_artifact_prospective_binding_v1": JointArtifactProspectiveBindingV1, QUALIFICATION_KIND: JointPlanQualificationV1,
        "joint_executor_index_v1": JointExecutorIndexV1}
    for bot, persona, ref, kind, operation, encoded, digest in rows:
        namespace = NamespaceId(bot, persona)
        value = decode_typed_production_value_v1(json.loads(encoded), types[kind])
        if value.namespace != namespace or value.digest != digest or value.original_ref != ref:
            raise DomainProductionErasureHold("Joint original changed its exact stored identity")
        if kind in (BINDING_KIND, "joint_artifact_prospective_binding_v1"):
            operation_kind = "input:register_joint_node_execution_binding_v1"
            request_digest = canonical_digest({"binding": plain_v1(value)})
        elif kind == "joint_executor_index_v1":
            operation_kind = "input:register_joint_node_execution_binding_v1"
            request_digest = value.registration_request_digest
        else:
            operation_kind = "input:qualify_joint_plan_nodes_v1"
            request_digest = canonical_digest(plain_v1(QualifyJointPlanNodesRequestV1(value.plan_ref, value.plan_revision, value.result_versions_digest)))
            if value.producing_operation_id != operation:
                raise DomainProductionErasureHold("Joint qualification lost its exact producing operation")
        validate_joint_retained_producer_v1(db, namespace=namespace, operation_id=operation,
            domain="d10", operation_kind=operation_kind, request_digest=request_digest)
    validate_joint_d08_joins_v1(db)


def validate_joint_retained_producer_v1(db, *, namespace, operation_id, domain, operation_kind, request_digest):
    from .domain_production_erasure_v1 import DomainProductionErasureHold
    row = db.execute("SELECT o.domain,o.operation_kind,o.request_digest,o.bundle_digest,b.digest,b.commit_seq "
        "FROM graph_domain_production_originals_v1 o JOIN graph_bundle_operations b "
        "ON b.bot=o.bot AND b.persona=o.persona AND b.operation_id=o.operation_id "
        "WHERE o.bot=? AND o.persona=? AND o.operation_id=?", (*namespace.as_tuple, operation_id)).fetchone()
    if row is None or row[:3] != (domain, operation_kind, request_digest) or row[3] != row[4] or row[5] < 1:
        raise DomainProductionErasureHold("Joint original lost its actual same-W01 exact producer")


def joint_executor_originals_v1(binding):
    executor = binding.executor
    if type(executor) is SourceNoteJointExecutorV1:
        return (executor.authorization_original_ref,)
    if type(executor) is ArtifactJointExecutorV1:
        return (executor.c02_operation_id, executor.root_registration_ref)
    return (executor.prepare_contact_operation_id,)



def require_current_joint_binding_gate_v1(db, *, frame, binding, issuer):
    from .joint_window_management_v1 import require_managed_joint_execution_v1
    require_managed_joint_execution_v1(db,namespace=binding.namespace,issuer=issuer,binding=binding,frame=frame)
    from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
    plan_atom = CurrentDomainReadV1(frame).head(db, binding.plan_ref, required=True)
    plan = _decode_joint_plan(plan_atom.value)
    request = QualifyJointPlanNodesRequestV1(binding.plan_ref, binding.plan_revision,
        joint_result_versions_digest_v1(db, namespace=binding.namespace, plan=plan))
    qualification = qualify_joint_plan_nodes_v1(db, frame=frame, request=request,
        readers=InstalledD08ProductionReadersV1(issuer=issuer))
    node = next((node for node in qualification.nodes if node.binding_ref == binding.original_ref), None)
    if node is None or node.state not in {"ready", "completed_verified", "compensation_ready", "compensated_verified"}:
        raise MissingProductionOriginalV1("current_joint_verified_dependencies_and_party_scope:" + binding.node_id)
    return qualification


def current_joint_executor_wakes_v1(db, *, frame, resolution, issuer, require_adopted_qualification):
    wakes = []
    from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
    for command in resolution.commands:
        if command.operation_kind != "input:qualify_joint_plan_nodes_v1":
            continue
        operation_id = joint_qualification_operation_id_v1(frame.envelope.authority.namespace, command.request)
        if require_adopted_qualification:
            wakes.extend(read_joint_execution_wakes_v1(db, namespace=frame.envelope.authority.namespace,
                qualification_ref=joint_qualification_ref_v1(frame.envelope.authority.namespace, operation_id), issuer=issuer, frame=frame))
            continue
        qualification = qualify_joint_plan_nodes_v1(db, frame=frame, request=command.request,
            readers=InstalledD08ProductionReadersV1(issuer=issuer))
        for node in qualification.nodes:
            if node.state in {"ready", "compensation_ready"}:
                wakes.append(read_joint_binding_v1(db, namespace=qualification.namespace, ref=node.binding_ref, issuer=issuer))
    return tuple(wakes)


def augment_joint_binding_read_plan_v1(db, *, namespace, plan, binding):
    if binding is None:
        return plan
    extra = joint_input_read_plan_v1(db, namespace=namespace,
        request=QualifyJointPlanNodesRequestV1(binding.plan_ref, binding.plan_revision, ""))
    return production_read_plan_v1((*plan.fixed_type_ids, *extra.fixed_type_ids), (*plan.exact_keys, *extra.exact_keys),
        (*plan.source_roots, *extra.source_roots), (*plan.required_original_refs, *extra.required_original_refs, binding.original_ref))


def joint_source_note_binding_for_authorization_v1(db, *, namespace, authorization_ref, issuer):
    return read_joint_executor_index_v1(db, namespace=namespace, selector_kind="source_note",
        selector_key=(authorization_ref,), issuer=issuer)


def joint_artifact_binding_for_selector_v1(db, *, selector, issuer):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1, ArtifactDraftPhaseSelectorV2
    task = selector.task if type(selector) is ArtifactDraftPhaseSelectorV2 else selector
    if type(task) is not ArtifactDraftTaskSelectorV1:
        raise TypeError("Joint artifact gate requires the fixed actual Artifact selector")
    task_binding = read_joint_executor_index_v1(db, namespace=task.namespace, selector_kind="artifact_task",
        selector_key=(task.c02_operation_id, task.root_registration_ref), issuer=issuer)
    binding = read_joint_executor_index_v1(db, namespace=task.namespace, selector_kind="artifact",
        selector_key=(task.c02_operation_id, task.root_registration_ref,
            selector.identity_digest if type(selector) is ArtifactDraftPhaseSelectorV2 else "legacy"), issuer=issuer)
    if task_binding is not None and binding is None:
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1, require_artifact_joint_phase_successor_v1
        if type(task_binding) is JointArtifactProspectiveBindingV1 and type(selector) is ArtifactDraftPhaseSelectorV2:
            require_artifact_joint_phase_successor_v1(db, binding=task_binding, selector=selector, issuer=issuer)
            return task_binding
        raise MissingProductionOriginalV1("actual_separately_consented_joint_artifact_phase")
    return binding


def augment_joint_artifact_read_plan_v1(db, *, plan, selector, issuer):
    binding = joint_artifact_binding_for_selector_v1(db, selector=selector, issuer=issuer)
    if binding is None:
        return plan
    return augment_joint_binding_read_plan_v1(db, namespace=binding.namespace, plan=plan, binding=binding)


def require_joint_artifact_frame_gate_v1(db, *, frame, selector, issuer):
    from .d10_habit_v1 import require_current_habit_artifact_generation_v1
    require_current_habit_artifact_generation_v1(db,frame=frame,selector=selector,issuer=issuer)
    binding = joint_artifact_binding_for_selector_v1(db, selector=selector, issuer=issuer)
    if binding is not None:
        from .owner_goal_projection_v1 import require_joint_artifact_goal_projection_gate_v1
        require_joint_artifact_goal_projection_gate_v1(db,namespace=binding.namespace,binding=binding,issuer=issuer)
        require_current_joint_binding_gate_v1(db, frame=frame, binding=binding, issuer=issuer)


def require_joint_prepared_artifact_gate_v1(db, *, prepared, issuer):
    from .d10_habit_v1 import require_current_habit_prepared_artifact_v1
    require_current_habit_prepared_artifact_v1(db,prepared=prepared,issuer=issuer)
    binding = joint_artifact_binding_for_selector_v1(db, selector=prepared.selector, issuer=issuer)
    if binding is not None:
        from .owner_goal_projection_v1 import require_joint_artifact_goal_projection_gate_v1
        require_joint_artifact_goal_projection_gate_v1(db,namespace=binding.namespace,binding=binding,issuer=issuer)
        require_joint_executor_gate_v1(db, namespace=binding.namespace, binding=binding, issuer=issuer)


from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1


def augment_joint_operation_read_plan_v1(db, *, namespace, operation_kind, request, plan, issuer):
    selector = None; action_ref = None
    if operation_kind in {"prepare_artifact_draft_model", "prepare_artifact_draft_model_v2",
            "acquire_artifact_draft_model", "acquire_artifact_draft_model_v2",
            "propose_artifact_draft_phase_action_v2", "input:register_artifact_phase_draft_plan_v2"}:
        selector = request.selector
    elif operation_kind == "propose_artifact_draft_action":
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        selector = artifact_draft_task_selector_v1(namespace, c02_operation_id=request.c02_operation_id, root_registration_ref=request.root_registration_ref)
    elif operation_kind in {"prepare_source_note_body", "prepare_artifact_draft_body"}:
        action_ref = request.action_intent_ref
    elif operation_kind in {"input:register_life_plan_v2", "input:register_artifact_draft_plan_v3"}:
        action_ref = request.plan.action_intent.ref
    elif operation_kind == "prepare_life":
        from .d11_life_preparation_v1 import read_registered_life_plan_v2
        registered = read_registered_life_plan_v2(db, namespace=namespace, issuer=issuer, original_ref=request.plan_original_ref)
        if registered is not None: action_ref = registered.action_intent.ref
    if selector is not None:
        return augment_joint_artifact_read_plan_v1(db, plan=plan, selector=selector, issuer=issuer)
    if action_ref is not None:
        binding = read_joint_executor_index_v1(db, namespace=namespace, selector_kind="action", selector_key=(action_ref,), issuer=issuer)
        if binding is None:
            from .joint_artifact_execution_v1 import joint_artifact_binding_for_adopted_action_v1
            binding = joint_artifact_binding_for_adopted_action_v1(db, namespace=namespace, action_ref=action_ref, issuer=issuer)
        return augment_joint_binding_read_plan_v1(db, namespace=namespace, plan=plan, binding=binding)
    return plan
