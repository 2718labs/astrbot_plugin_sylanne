"""Dedicated Habit frame terminal; it consumes only its actual Source Work and issuance."""
from ..runtime_contracts import CommandEnvelope,FenceScope
from .domain_production_contracts_v1 import ProductionOperationLimitsV1,ProductionReadPlanV1
from .habit_activity_issuance_v1 import (require_habit_activity_issuance_v1,habit_typed_command_digest_v1,habit_activity_domains_v1)

def freeze_habit_activity_frame_v1(graph,db,*,envelope,issued,scope,plan,now_utc,operation,request,
        process_lease,observed_originals=(),installed_policy_refs=(),limits=ProductionOperationLimitsV1()):
    from ..graph_coordinator import GraphCoordinator
    from .domain_production_frame_v1 import _materialize_current_domain_frame_v1
    from .current_habit_source_read_v3 import read_bound_current_habit_frame_inputs_v3
    if(type(graph)is not GraphCoordinator or db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()or type(envelope)is not CommandEnvelope
            or type(scope)is not FenceScope or type(plan)is not ProductionReadPlanV1):
        raise ValueError("Habit frame requires actual installed W01 transaction and typed plan")
    evidence=require_habit_activity_issuance_v1(issued,graph,scope);selector=evidence.request;policy=evidence.policy_original.definition
    graph._authorize(process_lease,envelope.authority,frozenset(habit_activity_domains_v1(operation.operation_kind)))
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1,habit_execution_purpose_v1
    purpose=habit_execution_purpose_v1(selector)if type(selector)is HabitOccurrenceExecutionSelectorV1 else "context"
    if type(selector)is HabitOccurrenceExecutionSelectorV1:
        from ..authority_service.d10_habit_execution_contract_v1 import habit_execution_phase_identity_v1
        if(envelope.identity.activity_id,envelope.identity.effect_id,envelope.identity.attempt_id)!=habit_execution_phase_identity_v1(selector):
            raise ValueError("Habit execution command changed the fixed recipe phase activity/effect/attempt")
    metadata,epoch=graph._v2_graph_stamp(selector.namespace)
    if(operation!=issued.operation or request!=issued.command or selector.request_digest!=habit_typed_command_digest_v1(operation,request)
            or envelope.identity.operation_id!=selector.operation_id or envelope.identity.phase!=operation.operation_kind
            or envelope.authority.actor!=evidence.current_self.self_entity_ref or envelope.authority.issuer_domain!=operation.domain
            or envelope.authority.namespace!=selector.namespace or envelope.authority.purpose!=purpose
            or envelope.authority.audience!=policy.audience or envelope.parent_budget_lease_ref!=policy.parent_root_grant_ref
            or scope.graph_epoch!=epoch or scope.graph_revision!=metadata.graph_revision
            or evidence.current_self.graph_revision!=metadata.graph_revision or evidence.query_epoch.revision!=epoch.revision
            or envelope.authority.activation_generation!=evidence.current_self.activation_generation
            or not graph._anchor_matches(metadata.requirements,scope.pinned_anchor)
            or envelope.deadline_utc>evidence.valid_until_utc or now_utc>=envelope.deadline_utc):
        raise ValueError("Habit frame changed same actual current command/Source/Owner/Root/deadline")
    qualified={v.key.token for v in evidence.read_versions if v.key.type_name=="memory.source"}
    if not set(plan.source_roots)<=qualified:raise ValueError("Habit frame introduced unqualified Source roots")
    prepared=read_bound_current_habit_frame_inputs_v3(db,graph=graph,scope=scope,plan=plan,issued=issued)
    return _materialize_current_domain_frame_v1(graph,db,envelope=envelope,scope=scope,plan=plan,
        prepared_inputs=prepared,now_utc=now_utc,expected_owner_guard=evidence.owner_guard,
        expected_rights=(evidence.access_epoch,evidence.delete_epoch),observed_originals=observed_originals,
        installed_policy_refs=installed_policy_refs,limits=limits)
