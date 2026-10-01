"""Closed installed operation dispatch; no request controls code or SQL."""
from dataclasses import dataclass
from importlib import import_module


@dataclass(frozen=True, slots=True)
class InstalledDomainOperationV1:
    domain: str
    operation_kind: str
    request_type: type
    stage_name: str
    verifier_name: str
    capability: str


# Each row is part of the installed package. Public JSON selects an exact
# operation and supplies only that operation's strictly typed intent/locators.
_OPERATIONS = {
    "adopt_contact_expression_plan": ("d08", "AdoptCurrentContactExpressionPlanRequestV1", "stage_adopt_current_contact_expression_plan_in_transaction_v1", "workbench.create"),
    "prepare_contact_model": ("d11", "PrepareCurrentContactModelRequestV1", "stage_prepare_current_contact_model_in_transaction_v1", "workbench.create"),
    "focus_life_project": ("d07", "FocusLifeProjectRequestV1", "stage_focus_life_project_in_transaction_v1", "workbench.create"),
    "prepare_life_project_context": ("d03", "PrepareLifeProjectContextRequestV1", "stage_prepare_life_project_context_in_transaction_v1", "workbench.create"),
    "prepare_source_note_action": ("d08", "PrepareSourceNoteActionRequestV1", "stage_prepare_source_note_action_in_transaction_v1", "workbench.create"),
    "prepare_source_note_body": ("d02", "PrepareSourceNoteBodyRequestV1", "stage_prepare_source_note_body_in_transaction_v1", "workbench.create"),
    "record_host_lifecycle": ("d11", "HostLifecycleRequestV1", "stage_current_host_lifecycle_in_transaction_v1", "workbench.create"),
    "prepare_offline_tick": ("d10", "PrepareCurrentOfflineTickRequestV1", "stage_prepare_current_offline_tick_in_transaction_v1", "workbench.create"),
    "prepare_life": ("d10", "PrepareCurrentLifeRequestV1", "stage_prepare_current_life_in_transaction_v1", "workbench.create"),
    "encode_structured_experience": ("d06", "EncodeCurrentStructuredExperienceRequestV1", "stage_encode_current_structured_experience_in_transaction_v1", "workbench.create"),
    "form_association": ("d06", "FormCurrentAssociationRequestV1", "stage_form_current_association_in_transaction_v1", "workbench.create"),
    "evaluate_values": ("d01", "EvaluateCurrentValuesRequestV1", "stage_evaluate_current_values_in_transaction_v1", "workbench.read"),
    "adopt_growth": ("d01", "AdoptCurrentGrowthRequestV1", "stage_adopt_current_growth_in_transaction_v1", "workbench.activate"),
    "advance_body": ("d02", "AdvanceCurrentBodyRequestV1", "stage_advance_current_body_in_transaction_v1", "workbench.activate"),
    "apply_body_effect": ("d02", "ApplyCurrentBodyEffectRequestV1", "stage_apply_current_body_effect_in_transaction_v1", "workbench.activate"),
    "adopt_relationship_contribution": ("d05", "AdoptCurrentRelationshipContributionRequestV1", "stage_adopt_current_relationship_contribution_in_transaction_v1", "workbench.create"),
    "revise_boundary": ("d05", "ReviseCurrentBoundaryRequestV1", "stage_revise_current_boundary_in_transaction_v1", "workbench.activate"),
    "reevaluate_relationship": ("d05", "ReevaluateCurrentRelationshipRequestV1", "stage_reevaluate_current_relationship_in_transaction_v1", "workbench.activate"),
    "serve_concern": ("d07", "ServeCurrentConcernRequestV1", "stage_serve_current_concern_in_transaction_v1", "workbench.create"),
    "advance_reflection": ("d07", "AdvanceCurrentReflectionRequestV1", "stage_advance_current_reflection_in_transaction_v1", "workbench.activate"),
    "run_simulation": ("d07", "RunCurrentSimulationRequestV1", "stage_run_current_simulation_in_transaction_v1", "workbench.create"),
    "recheck_action": ("d08", "RecheckCurrentActionRequestV1", "stage_recheck_current_action_in_transaction_v1", "workbench.read"),
    "settle_observed_action": ("d08", "SettleCurrentObservedActionRequestV1", "stage_settle_current_observed_action_in_transaction_v1", "workbench.activate"),
    "acknowledge_bilateral": ("d08", "AcknowledgeCurrentBilateralRequestV1", "stage_acknowledge_current_bilateral_in_transaction_v1", "workbench.activate"),
    "adopt_joint_plan": ("d08", "AdoptCurrentJointPlanRequestV1", "stage_adopt_current_joint_plan_in_transaction_v1", "workbench.activate"),
    "advance_life": ("d10", "AdvanceCurrentLifeRequestV1", "stage_current_life_effect_experience_bundle_in_transaction_v1", "workbench.activate"),
    "advance_offline": ("d10", "AdvanceCurrentOfflineRequestV1", "stage_current_offline_body_experience_bundle_in_transaction_v1", "workbench.activate"),
    "prepare_contact": ("d10", "PrepareCurrentContactRequestV1", "stage_prepare_current_contact_in_transaction_v1", "workbench.create"),
}


def installed_operation_v1(operation_kind):
    if type(operation_kind) is str and operation_kind.startswith("input:"):
        from .domain_production_inputs_v1 import input_operation_for_request_v1
        registered = input_operation_for_request_v1(operation_kind[len("input:"):])
        return InstalledDomainOperationV1(registered.domain, operation_kind, registered.request_type,
            "stage_current_domain_input_v1", "rebuild_current_domain_input_v1", registered.capability)
    if type(operation_kind) is not str or operation_kind not in _OPERATIONS:
        raise ValueError("unregistered installed domain operation")
    domain, request_name, stage_name, capability = _OPERATIONS[operation_kind]
    module = import_module(".contact_plan_adoption_v1" if operation_kind == "adopt_contact_expression_plan" else
        ".contact_product_adapter_v1" if operation_kind == "prepare_contact_model" else
        ".d07_life_project_focus_v1" if operation_kind == "focus_life_project" else
        ".d03_life_project_context_v1" if operation_kind == "prepare_life_project_context" else
        ".d08_source_note_action_v1" if operation_kind == "prepare_source_note_action" else
        ".d02_life_body_preparation_v1" if operation_kind == "prepare_source_note_body" else
        ".d11_host_lifecycle_v1" if operation_kind == "record_host_lifecycle" else
        ".d11_life_preparation_v1" if operation_kind == "prepare_life" else
        ".d10_offline_tick_execution_v1" if operation_kind == "prepare_offline_tick" else
        ".d06_association_formation_v1" if operation_kind == "form_association" else
        "..domains.d06.structured_experience_v1" if domain == "d06" else ".d07_current_behavior_v1" if domain == "d07"
        else "..domains." + domain + ".production_operations_v1", package=__package__)
    request_type = getattr(module, request_name)
    return InstalledDomainOperationV1(domain, operation_kind, request_type, stage_name,
        "verify_" + domain + "_production_stage_v1", capability)


def installed_readers_for_operation_v1(graph, operation, *, scope, owner_guard, execution_reader=None):
    from ..graph_coordinator import GraphCoordinator
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..runtime_contracts import FenceScope
    if (type(graph) is not GraphCoordinator or type(operation) is not InstalledDomainOperationV1
            or type(scope) is not FenceScope or type(owner_guard) is not OwnerAuthorizationGuardV1
            or installed_operation_v1(operation.operation_kind) != operation
            or owner_guard.namespace != scope.namespace):
        raise ValueError("domain operation needs its actual installed current Owner fence")
    issuer = graph._GraphCoordinator__d11_issuer
    if operation.operation_kind == "focus_life_project":
        from .d07_life_project_focus_v1 import InstalledD07LifeFocusReadersV1
        from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
        return InstalledD07LifeFocusReadersV1(issuer=issuer, body_readers=InstalledD02ProductionReadersV1(
            issuer=issuer, body_quote_authority=graph._GraphCoordinator__body_quote_authority,
            role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader))
    if operation.operation_kind == "prepare_life_project_context":
        from .d03_life_project_context_v1 import InstalledD03LifeProjectContextReaderV1
        return InstalledD03LifeProjectContextReaderV1(issuer=issuer)
    if operation.domain == "d06":
        if operation.operation_kind == "form_association":
            from .d06_association_formation_v1 import InstalledD06AssociationReadersV1
            return InstalledD06AssociationReadersV1(issuer=issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
        from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
        return InstalledD06StructuredExperienceReadersV1(issuer=issuer,
            resource_issuer=graph._GraphCoordinator__d02_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
    contact = operation.operation_kind in {"adopt_contact_expression_plan", "prepare_contact_model"}
    reader_domain = "d10" if contact else operation.domain
    module = import_module("." + reader_domain + "_production_operations_v1", package=__package__)
    cls = getattr(module, "Installed" + reader_domain.upper() + "ProductionReadersV1")
    if operation.domain == "d01":
        return cls(issuer=issuer, owner_guard=owner_guard)
    if operation.domain in {"d05", "d08"} and not contact:
        readers = cls(issuer=issuer)
        if operation.operation_kind == "prepare_source_note_action":
            from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
            readers.body_readers = InstalledD02ProductionReadersV1(issuer=issuer,
                body_quote_authority=graph._GraphCoordinator__body_quote_authority,
                role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader)
            assembly = graph._GraphCoordinator__d04_installed_joint_assembly
            if assembly is None:
                raise ValueError("actual installed source-note package is absent")
            readers.package_root = assembly.package_root
            readers.manifest_digest = assembly.installation_policy.manifest_digest
        return readers
    if operation.domain in {"d02", "d10"} or contact:
        from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
        clock = graph._GraphCoordinator__d04_semantic_mapping_reader
        body = InstalledD02ProductionReadersV1(issuer=issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority, role_clock_reader=clock)
        if operation.domain == "d02":
            return body
        readers = cls(issuer=issuer, role_clock_reader=clock, current_restore_anchor=scope.pinned_anchor, body_readers=body)
        readers.life_scope = scope
        readers.life_execution_inventory = graph._GraphCoordinator__domain_production_runtime_v1._active_life_execution_inventory_v1
        return readers
    return cls(issuer=issuer, execution_reader=execution_reader)


def stage_installed_domain_operation_v1(db, *, operation, frame, request, installed_readers):
    if (type(operation) is not InstalledDomainOperationV1
            or installed_operation_v1(operation.operation_kind) != operation
            or type(request) is not operation.request_type or not db.in_transaction):
        raise ValueError("exact registered domain request and current transaction required")
    if operation.operation_kind.startswith("input:"):
        from .domain_production_inputs_v1 import stage_current_domain_input_v1
        return stage_current_domain_input_v1(db, frame=frame,
            producer_kind=operation.operation_kind[len("input:"):], request=request, installed_readers=installed_readers)
    module = import_module(".contact_product_adapter_v1" if operation.operation_kind in {
        "adopt_contact_expression_plan", "prepare_contact_model"} else
        ".d07_life_project_focus_v1" if operation.operation_kind == "focus_life_project" else
        ".d03_life_project_context_v1" if operation.operation_kind == "prepare_life_project_context" else
        ".d08_source_note_action_v1" if operation.operation_kind == "prepare_source_note_action" else
        ".d02_life_body_preparation_v1" if operation.operation_kind == "prepare_source_note_body" else
        ".d10_offline_tick_execution_v1" if operation.operation_kind == "prepare_offline_tick" else
        ".d11_life_product_adapter_v1" if operation.operation_kind == "prepare_life" else
        ".d06_association_formation_v1" if operation.operation_kind == "form_association" else
        ".d06_structured_experience_v1" if operation.domain == "d06" else
        "." + operation.domain + "_production_operations_v1", package=__package__)
    return getattr(module, operation.stage_name)(db, frame=frame, request=request, installed_readers=installed_readers)
