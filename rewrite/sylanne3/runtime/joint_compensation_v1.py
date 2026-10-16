"""D08 compensation terms over independent, fixed existing executor originals."""
from dataclasses import dataclass

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import _decode, _decode_intent
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1


@dataclass(frozen=True, slots=True)
class JointCompensationAuthorizationV1:
    namespace: NamespaceId
    plan_ref: str
    plan_revision: int
    node_id: str
    trigger_binding_ref: str
    trigger_binding_digest: str
    repair_binding_ref: str
    repair_binding_digest: str
    trigger_kind: str
    source_refs: tuple[str, ...]
    schema: str = "d08.joint-compensation-authorization.v1"

    def __post_init__(self):
        if (self.schema != "d08.joint-compensation-authorization.v1" or type(self.namespace) is not NamespaceId
                or AtomKey.from_token(self.plan_ref).type_name != "d08.joint_plan.v1"
                or self.plan_revision < 1 or not self.node_id.startswith("task:")
                or self.trigger_kind not in {"cancelled_settled", "failed_verified_settled"}
                or self.trigger_binding_ref == self.repair_binding_ref
                or not self.source_refs):
            raise ValueError("compensation requires independent immutable fixed-executor terms")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def original_ref(self):
        return "joint-node-compensation:" + self.digest


@dataclass(frozen=True, slots=True)
class RegisterJointCompensationRequestV1:
    authorization: JointCompensationAuthorizationV1


def validate_joint_compensation_input_v1(db, *, frame, request, issuer):
    from .joint_node_execution_v1 import read_joint_binding_v1, qualify_joint_binding_v1
    auth = request.authorization
    if type(auth) is not JointCompensationAuthorizationV1 or auth.namespace != frame.envelope.authority.namespace:
        raise TypeError("exact actual Owner compensation authorization required")
    trigger = read_joint_binding_v1(db, namespace=auth.namespace, ref=auth.trigger_binding_ref, issuer=issuer)
    repair = read_joint_binding_v1(db, namespace=auth.namespace, ref=auth.repair_binding_ref, issuer=issuer)
    if (trigger.digest, repair.digest) != (auth.trigger_binding_digest, auth.repair_binding_digest):
        raise ValueError("compensation changed its original trigger or repair terms")
    trigger_action, _ = qualify_joint_binding_v1(db, frame=frame, binding=trigger, issuer=issuer)
    repair_action, state = qualify_joint_binding_v1(db, frame=frame, binding=repair, issuer=issuer)
    if (trigger.plan_ref, trigger.plan_revision, trigger.node_id) != (auth.plan_ref, auth.plan_revision, auth.node_id):
        raise ValueError("compensation trigger belongs to another exact Joint node")
    if (repair.plan_ref, repair.plan_revision, repair.node_id) != (auth.plan_ref, auth.plan_revision, auth.node_id):
        raise ValueError("repair terms do not belong to the authorized compensation responsibility")
    if (state != "current" or trigger.owner_ref != "persona:" + auth.namespace.persona_id
            or repair.owner_ref != trigger.owner_ref or repair_action.identity.effect_id == trigger_action.identity.effect_id
            or repair_action.identity.operation_id == trigger_action.identity.operation_id):
        raise ValueError("repair requires its own registered action, effect and original authorization")
    # Its normal executor owns all current checks and its original dedicated
    # parent grant/deadline; a cancellation flag never supplies those permissions.
    read = CurrentDomainReadV1(frame)
    for audience in repair.audience:
        read.source_family(db, auth.source_refs, purpose=repair.purpose, audience=audience)
    return auth


def read_joint_compensation_terms_v1(db, *, frame, plan, node, binding, issuer):
    from .joint_external_observation_v1 import read_joint_d08_original_v1
    auth = read_joint_d08_original_v1(db, namespace=binding.namespace, original_ref=node.compensation_ref, issuer=issuer)
    if (type(auth) is not JointCompensationAuthorizationV1 or auth.trigger_binding_ref != binding.original_ref
            or auth.trigger_binding_digest != binding.digest
            or (auth.plan_ref, auth.plan_revision, auth.node_id) != (binding.plan_ref, plan.revision, node.node_id)):
        raise ValueError("compensation is outside the exact accepted Joint terms")
    if not node.cancellation_point:
        raise MissingProductionOriginalV1("actual_safe_joint_cancellation_point")
    return auth


def settled_joint_trigger_v1(db, *, frame, binding, issuer, trigger_kind):
    read = CurrentDomainReadV1(frame); action = _decode_intent(read.head(db, binding.action_ref, required=True).value)
    outcomes = tuple(atom for atom in read.complete_inventory(db, "d08.action_outcome.v1")
        if atom.valid and atom.value["action_id"] == action.action_id and atom.value["effect_id"] == action.identity.effect_id
        and atom.value["attempt_id"] == action.identity.attempt_id)
    if not outcomes and trigger_kind == "cancelled_settled":
        unstarted = actual_unstarted_joint_cancellation_v1(db, frame=frame, binding=binding, issuer=issuer)
        if unstarted is not None: return unstarted
    if len(outcomes) != 1:
        raise MissingProductionOriginalV1("actual_original_joint_effect_terminal_before_compensation")
    outcome = _decode("d08.action_outcome.v1", outcomes[0].value)
    if outcome.unknown_effects or outcome.result_level == "unknown":
        raise MissingProductionOriginalV1("original_joint_unknown_effect_settlement_before_compensation")
    if trigger_kind == "failed_verified_settled" and outcome.result_level != "failed_verified":
        raise MissingProductionOriginalV1("actual_joint_failed_verified_trigger")
    if trigger_kind == "cancelled_settled":
        key = AtomKey.from_token(binding.action_ref)
        cancellation = read.head(db, AtomKey(key.owner, "d08.action_cancellation.v1", key.name), required=True)
        if cancellation.value["state"] != "cancelled":
            raise MissingProductionOriginalV1("actual_joint_cancelled_trigger_original")
    if binding.progress_ref is None:
        from .domain_background_read_v3 import background_history_v3
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        history = background_history_v3(db, outcomes[0].key.token, outcomes[0].revision, columns=("event_id",))
        actual = None if history is None else read_adopted_domain_operation_v1(db, binding.namespace, history[0])
        if actual is None or (actual["domain"], actual["operation_kind"]) != ("d08", "settle_observed_action"):
            raise MissingProductionOriginalV1("actual_contact_trigger_outcome_and_original_cost")
        request = actual["payload"]["request"]; provenance = actual["payload"]["provenance"]
        if request["action_intent_ref"] != binding.action_ref or provenance["action_outcome"] != outcomes[0].value:
            raise ValueError("Contact compensation trigger names another actual Action")
        read.original(request["cost_settlement_ref"], digest=provenance["cost_original"]["original_digest"])
        read.original(request["outbound_receipt_ref"], digest=provenance["observation_original"]["original_digest"])
        return outcomes[0].key.token
    artifact_ref = dict(binding.success_predicate.parameters).get("artifact_ref")
    if artifact_ref is None:
        raise MissingProductionOriginalV1("registered_life_postcondition_ref_for_actual_trigger")
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_preparation_v1 import read_prepared_life_v1
    from .d11_life_contract_v1 import life_from_wire_v1, D11LifeTerminalV1
    from .d11_life_adoption_v1 import validate_life_recovery_heads_v1
    adopted = read_adopted_life_original_v1(db, namespace=binding.namespace, result_ref=artifact_ref, issuer=issuer)
    if adopted is None:
        raise MissingProductionOriginalV1("actual_signed_original_trigger_terminal_and_cost")
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if prepared is None or terminal.status == "unknown" or terminal.binding.effect_id != action.identity.effect_id:
        raise MissingProductionOriginalV1("actual_original_trigger_execution_settlement")
    validate_life_recovery_heads_v1(db, binding=terminal.binding, prepared_digest=prepared.digest,
        prepared=prepared, adopted=adopted)
    return outcomes[0].key.token


def qualify_joint_compensation_v1(db, *, frame, plan, node, binding, issuer):
    from .joint_node_execution_v1 import read_joint_binding_v1, qualify_joint_binding_v1, JointNodeQualificationV1
    auth = read_joint_compensation_terms_v1(db, frame=frame, plan=plan, node=node, binding=binding, issuer=issuer)
    trigger_ref = settled_joint_trigger_v1(db, frame=frame, binding=binding, issuer=issuer, trigger_kind=auth.trigger_kind)
    repair = read_joint_binding_v1(db, namespace=binding.namespace, ref=auth.repair_binding_ref, issuer=issuer)
    action, state = qualify_joint_binding_v1(db, frame=frame, binding=repair, issuer=issuer)
    if state != "current":
        raise MissingProductionOriginalV1("actual_live_independent_compensation_authorization")
    progress = CurrentDomainReadV1(frame).head(db, repair.progress_ref) if repair.progress_ref is not None else None
    if progress is None or not progress.valid:
        return JointNodeQualificationV1(node.node_id, repair.original_ref, repair.digest, "compensation_ready", trigger_ref, ())
    from .d10_project_checkpoint_v1 import InstalledD10ProjectReadersV1, LifeProgressHeadV1
    from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
    read = CurrentDomainReadV1(frame)
    value = LifeProgressHeadV1(**{**progress.value, "source_refs": tuple(progress.value["source_refs"]), "receipt_refs": tuple(progress.value["receipt_refs"])})
    require_current_life_progress_v1(db, namespace=repair.namespace, progress=value, issuer=issuer, read=read)
    proof = InstalledD10ProjectReadersV1(issuer=issuer).read_effect(db, frame, repair.progress_ref)
    if (not proof.completed_verified or value.reality != "real_execution" or proof.action_intent_ref != repair.action_ref
            or proof.effect_id != action.identity.effect_id or proof.success_predicate != repair.success_predicate):
        raise ValueError("compensation did not prove its own independent actual postcondition")
    return JointNodeQualificationV1(node.node_id, repair.original_ref, repair.digest, "compensated_verified", repair.progress_ref, ())


def joint_compensation_read_plan_v1(db, *, namespace, request):
    from .joint_node_execution_v1 import joint_input_read_plan_v1, RegisterJointNodeExecutionBindingRequestV1
    auth = request.authorization
    from .d01_production_operations_v1 import raw_registered_input_v1
    from .joint_node_execution_v1 import decode_joint_binding_v1
    plans = []
    for ref in (auth.trigger_binding_ref, auth.repair_binding_ref):
        raw = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, ref)
        if raw is None:
            raise MissingProductionOriginalV1("actual_compensation_binding_input:" + ref)
        binding = decode_joint_binding_v1(raw)
        plans.append(joint_input_read_plan_v1(db, namespace=namespace, request=RegisterJointNodeExecutionBindingRequestV1(binding)))
    return production_read_plan_v1(tuple(kind for plan in plans for kind in plan.fixed_type_ids),
        tuple(key for plan in plans for key in plan.exact_keys), (*auth.source_refs, *(ref for plan in plans for ref in plan.source_roots)),
        (auth.trigger_binding_ref, auth.repair_binding_ref, *(ref for plan in plans for ref in plan.required_original_refs)))


def actual_unstarted_joint_cancellation_v1(db, *, frame, binding, issuer):
    from .joint_node_execution_v1 import SourceNoteJointExecutorV1
    if type(binding.executor) is not SourceNoteJointExecutorV1:
        return None
    from .owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
    from .owner_source_note_life_v1 import owner_source_note_life_ids_v1
    from .d11_life_preparation_v1 import read_registered_life_plan_v2
    saved = read_owner_source_note_task_authorization_v2(db, namespace=binding.namespace,
        original_ref=binding.executor.authorization_original_ref, issuer=issuer)
    if saved is None:
        raise MissingProductionOriginalV1("actual_original_unstarted_owner_task_authorization")
    ids = owner_source_note_life_ids_v1(saved[0])
    if read_registered_life_plan_v2(db, namespace=binding.namespace, issuer=issuer, original_ref=ids["plan_ref"]) is not None:
        return None
    # The fixed Native writer requires a signed registered plan/preparation.
    # Its exact absence proves this cancellation precedes the execution path;
    # earlier planning/model costs remain their separate existing originals.
    read = CurrentDomainReadV1(frame); key = AtomKey.from_token(binding.action_ref)
    cancellation = read.head(db, AtomKey(key.owner, "d08.action_cancellation.v1", key.name), required=True)
    if cancellation.value["state"] != "cancelled":
        return None
    from .domain_background_read_v3 import background_history_v3
    history = background_history_v3(db, cancellation.key.token, cancellation.revision, columns=("event_id",))
    if history is None or history[0] != cancellation.value["operation_id"]:
        raise MissingProductionOriginalV1("actual_adopted_unstarted_cancellation_operation")
    read.committed_operation(db, history[0])
    return cancellation.key.token
