"""Installed W01 compilation for the closed set of domain production operations."""
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import replace
import json
import time

from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, canonical_digest,
)
from .budget import get_budget_lease, require_budget_family_admissible
from .domain_production_frame_v1 import freeze_domain_production_frame_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .domain_production_registry_v1 import installed_operation_v1, installed_readers_for_operation_v1, stage_installed_domain_operation_v1


class InstalledDomainOperationRuntimeV1:
    def __init__(self, graph, bootstrap):
        from ..graph_coordinator import GraphCoordinator
        if type(graph) is not GraphCoordinator:
            raise TypeError("installed domain runtime requires the concrete W01 coordinator")
        graph._admin(bootstrap)
        self.graph, self._bootstrap = graph, bootstrap
        self._active_life_execution_inventory_v1 = None
        self._active_foreground_issuance_v1 = None
        self._active_foreground_process_lease_v1 = None
        self._active_draft_root_registration_v1 = None
        self._active_owner_stop_projection_v1 = None
        self._last_refusal_exception_v1 = None

    def _current(self):
        if getattr(self.graph, "_GraphCoordinator__domain_production_runtime_v1", None) is not self:
            raise ValueError("domain production runtime is not installed on its coordinator")

    def read_current_operation_plan_v3(self, db, *, operation, request, operation_id,
            activity_id, audience_ref, scope, owner_guard, now_utc):
        """Pure plan and original locators under the caller's actual held snapshot."""
        self._current()
        graph = self.graph
        if (db is not graph._GraphCoordinator__store._db or not db.in_transaction
                or not graph._GraphCoordinator__store._lock._is_owned()):
            raise ValueError("operation plan needs its actual held Graph snapshot")
        from .domain_production_registry_v1 import _POSTCONDITION_OPERATIONS
        from .d01_method_learning_v1 import OPERATIONS as METHOD_OPERATIONS
        from .current_method_learning_read_v3 import METHOD_INPUT_OPERATIONS_V3
        from .domain_production_read_plans_v1 import (
            read_plan_current_domain_operation_v1, read_independent_current_original_requests_v1)
        reader_operations = {*_POSTCONDITION_OPERATIONS, *METHOD_OPERATIONS,
            "create_artifact_task_plan_v1", "adopt_current_c1_method_conditions_v1",
            "adopt_current_task_no_search_v1", "quote_current_method_choices_v1",
            "observe_method_comparison_v1", "evaluate_values", "prepare_personal_candidates_v1",
            "select_personal_step_v2", "prepare_selected_source_note_action_v2",
            "input:register_artifact_task_text_extent"} | METHOD_INPUT_OPERATIONS_V3
        phase_readers = (installed_readers_for_operation_v1(graph, operation,
            scope=scope, owner_guard=owner_guard)
            if operation.operation_kind in reader_operations else None)
        plan = read_plan_current_domain_operation_v1(db, namespace=scope.namespace,
            activity_id=activity_id, domain=operation.domain, operation_kind=operation.operation_kind,
            request=request, operation_id=operation_id, now_utc=now_utc, audiences=(audience_ref,),
            life_d04_before_capture_policy=graph._GraphCoordinator__life_d04_before_capture_policy,
            personal_candidate_readers=phase_readers
                if operation.operation_kind in {"prepare_personal_candidates_v1", "select_personal_step_v2",
                    "input:register_artifact_task_text_extent"} else None,
            artifact_phase_readers=phase_readers, installed_readers=phase_readers)
        return plan, read_independent_current_original_requests_v1(db, namespace=scope.namespace, plan=plan)

    def read_current_borrowed_operation_plan_v3(self, db, *, operation, request, issued, scope, now_utc):
        """Read the original typed Self recipe; this issues no capability or frame."""
        self._current()
        graph = self.graph
        if (db is not graph._GraphCoordinator__store._db or not db.in_transaction
                or not graph._GraphCoordinator__store._lock._is_owned()):
            raise ValueError("borrowed operation plan needs its actual held Graph snapshot")
        from .owner_source_note_task_issuance_v1 import (
            _IssuedOwnerSourceNoteTaskV1, require_owner_source_note_task_issuance_v1)
        from .foreground_activity_issuance_v1 import (
            _IssuedForegroundActivityV1, require_foreground_activity_issuance_v1)
        from .domain_production_read_plans_v1 import (
            read_plan_current_domain_operation_v1, read_independent_current_original_requests_v1)
        if type(issued) is _IssuedOwnerSourceNoteTaskV1:
            evidence = require_owner_source_note_task_issuance_v1(issued, graph, scope)
            from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
            auth = evidence.authorization
            ids = owner_source_note_task_ids_v1(auth.cause.namespace, auth.cause.owner_operation_id)
            readers = installed_readers_for_operation_v1(graph, operation, scope=scope,
                owner_guard=evidence.owner_guard, owner_task_issuance=issued)
            plan = read_plan_current_domain_operation_v1(db, namespace=auth.cause.namespace,
                activity_id=ids["activity_id"], domain=operation.domain, operation_kind=operation.operation_kind,
                request=request, operation_id=evidence.request.operation_id, now_utc=now_utc,
                audiences=auth.cause.audiences, installed_readers=readers, artifact_phase_readers=readers,
                personal_candidate_readers=readers if operation.operation_kind in {
                    "prepare_personal_candidates_v1", "select_personal_step_v2"} else None)
        elif type(issued) is _IssuedForegroundActivityV1:
            evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
            readers = installed_readers_for_operation_v1(graph, operation, scope=scope,
                owner_guard=evidence.owner_guard, foreground_issuance=issued)
            plan = read_plan_current_domain_operation_v1(db, namespace=evidence.request.namespace,
                activity_id=evidence.request.activity_id, domain=operation.domain, operation_kind=operation.operation_kind,
                request=request, operation_id=evidence.request.operation_id, now_utc=now_utc,
                audiences=evidence.request.audiences,
                d06_recall_policy=readers.installed_bundle.d06_recall if operation.operation_kind == "prepare_ingress_recall_need_v1" else None,
                d07_execution_service=readers.execution_reader if operation.operation_kind in {
                    "prepare_ingress_recall_model_v1", "acquire_ingress_recall_model_v1", "prepare_ingress_recall_result_read_v1",
                    "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1"} else None,
                ingress_c03_readers=readers if operation.operation_kind == "select_ingress_recall_seed_v1" else None,
                self_c04_readers=readers if operation.operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"} else None,
                ingress_task_scope_readers=readers if operation.operation_kind == "derive_ingress_artifact_task_scope_v1" else None,
                personal_candidate_readers=readers if operation.operation_kind in {
                    "prepare_personal_candidates_v1", "select_personal_step_v2"} else None,
                artifact_phase_readers=readers, installed_readers=readers)
        else:
            raise TypeError("borrowed recipe requires an actual active typed Self issuance")
        from .current_method_learning_read_v3 import read_bound_method_borrowed_plan_v3
        handled, prepared_plan = read_bound_method_borrowed_plan_v3(db, graph=graph, issued=issued, plan=plan)
        if handled:
            plan = prepared_plan
        return plan, read_independent_current_original_requests_v1(db, namespace=scope.namespace, plan=plan), readers

    def _method_measurement_policy_refs_v1(self, policies, *, operation, scope, owner_guard, owner_binding=None):
        from .d01_method_learning_v1 import OPERATIONS
        required = {"evaluate_values", "prepare_personal_candidates_v1", "select_personal_step", "select_personal_step_v2",
            "register_artifact_phase_postcondition_contract_v1", "propose_artifact_draft_phase_action_v2",
            "activate_artifact_task_project_checkpoint_v1", "activate_artifact_task_project_checkpoint_v2",
            "prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2", "observe_method_comparison_v1"}
        if operation.operation_kind not in {*OPERATIONS, *required}:
            return policies
        assembly = self.graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None or assembly.admin_bundle.method_measurement_policy is None:
            return policies
        from .d11_method_observation_v1 import install_method_observation_readers_v1
        from .domain_production_contracts_v1 import ProductionPolicyRefV1
        actual = install_method_observation_readers_v1(self.graph, scope=scope,
            owner_guard=owner_guard, owner_binding=owner_binding).current()
        return (*policies, ProductionPolicyRefV1(actual.policy_ref, actual.policy_version, actual.digest))

    def compile_in_transaction(self, db, *, operation, request, envelope, scope, owner, guard,
            now_utc, external_originals=(), source_storage_prepare=None):
        self._current()
        if operation.operation_kind == "owner_stop_reply_v1":
            return self.compile_owner_stop_projection_in_transaction_v1(db, operation=operation,
                request=request, envelope=envelope, scope=scope, now_utc=now_utc)
        issued = getattr(self, "_active_foreground_issuance_v1", None)
        if issued is not None:
            return self.compile_foreground_in_transaction(db, operation=operation, request=request,
                envelope=envelope, scope=scope, issued=issued, now_utc=now_utc, external_originals=external_originals)
        if operation.operation_kind == "record_host_lifecycle":
            from types import SimpleNamespace
            from .d11_host_lifecycle_driver_v1 import require_background_host_lifecycle_v1
            from .d11_host_lifecycle_v1 import (read_current_host_lifecycle_scope_v1,
                read_plan_current_host_lifecycle_v1, stage_current_host_lifecycle_in_transaction_v1)
            issued = self._active_host_lifecycle_v1
            require_background_host_lifecycle_v1(issued, self.graph, issued.authority, envelope.identity.operation_id)
            if request != operation.request_type(issued.observation.kind,
                    issued.observation.host_incarnation, issued.observation.observation_id):
                raise ValueError("Host lifecycle request differs from the actual capture")
            issuer = self.graph._GraphCoordinator__d11_issuer
            ns = envelope.authority.namespace
            audiences, purposes, schedules = read_current_host_lifecycle_scope_v1(db,
                namespace=ns, issuer=issuer, now_utc=now_utc)
            envelope = replace(envelope, authority=replace(envelope.authority,
                audience=audiences, purpose=purposes[0]))
            plan = read_plan_current_host_lifecycle_v1(db, namespace=ns,
                observation=issued.observation, issuer=issuer, now_utc=now_utc)
            frame = freeze_domain_production_frame_v1(self.graph, db, envelope=envelope,
                current_owner=owner, scope=scope, plan=plan, now_utc=now_utc,
                observed_originals=tuple(external_originals) + schedules)
            stage = stage_current_host_lifecycle_in_transaction_v1(db, frame=frame,
                observer=issued.observer, observation=issued.observation, issuer=issuer)
            return frame, stage, SimpleNamespace(issuer=issuer)
        from .domain_production_read_plans_v1 import (
            read_plan_current_domain_operation_v1, read_current_domain_original_refs_v1,
            read_current_domain_policy_refs_v1, read_current_domain_command_identity_v1)
        if operation.operation_kind == "adopt_owner_artifact_project_context_v1":
            from ..graph_coordinator import OwnerLeaseBindingV1
            if (type(owner) is not OwnerLeaseBindingV1 or not {"context", "consolidation"} <= set(owner.purposes)
                    or not set(envelope.authority.audience) <= set(owner.audiences)):
                raise ValueError("Owner project role adoption exceeds its actual Source purpose/audience scope")
        readers = installed_readers_for_operation_v1(self.graph, operation, scope=scope, owner_guard=guard, owner_binding=owner,
            execution_reader=getattr(self.graph, "_GraphCoordinator__d07_execution_service_v1", None))
        if operation.operation_kind == "acquire_internal_life_content_v2":
            from .internal_life_worker_binding_v2 import require_installed_life_worker_v2
            readers.life_worker_issuance_v2 = require_installed_life_worker_v2(
                self._active_internal_life_worker_v2,self)
        contact_policy = getattr(self, "_active_contact_policy_original_v1", None)
        if operation.operation_kind == "input:set_contact_policy":
            readers.contact_policy_original = contact_policy
        current_contact = getattr(self, "_active_current_contact_policy_v1", None)
        if operation.operation_kind in {"prepare_contact", "adopt_contact_expression_plan", "adopt_contact_expression_plan_v2", "prepare_contact_model", "prepare_contact_model_v2", "prepare_contact_dispatch", "prepare_contact_dispatch_v3"}:
            readers.contact_policy_scope = scope
            readers.current_contact_policy = current_contact
        identity = read_current_domain_command_identity_v1(db, namespace=envelope.authority.namespace,
            operation_kind=operation.operation_kind, request=request,
            requested_activity_id=envelope.identity.activity_id, requested_audience_ref=envelope.authority.audience[0],
            installed_readers=readers, operation_id=envelope.identity.operation_id)
        life_audiences = None
        if operation.operation_kind in {"prepare_life", "input:register_life_plan_v2", "input:register_life_outcome_v2", "advance_life"}:
            from .d11_life_product_adapter_v1 import raw_life_original_v1
            from .d11_life_preparation_v1 import read_registered_life_plan_v2
            if operation.operation_kind == "input:register_life_plan_v2":
                life_audiences = request.plan.audiences
            else:
                plan_ref = request.plan_original_ref if operation.operation_kind == "prepare_life" else (
                    request.outcome.plan_original_ref if operation.operation_kind == "input:register_life_outcome_v2" else None)
                if operation.operation_kind == "advance_life":
                    outcome = raw_life_original_v1(db, envelope.authority.namespace, "outcome", request.activity_outcome_ref)
                    if outcome is not None:
                        plan_ref = outcome["plan_original_ref"]
                if plan_ref is not None:
                    actual = read_registered_life_plan_v2(db, namespace=envelope.authority.namespace,
                        issuer=readers.issuer, original_ref=plan_ref)
                    if actual is None:
                        from .d01_production_operations_v1 import MissingProductionOriginalV1
                        raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
                    life_audiences = actual.audiences
        offline = getattr(self, "_active_background_offline_v1", None)
        followup = getattr(self, "_active_background_followup_v1", None)
        envelope = replace(envelope, identity=replace(envelope.identity, effect_id=identity.effect_id),
            authority=replace(envelope.authority, purpose=identity.purpose,
                audience=life_audiences if life_audiences is not None else offline.authority.audience if offline is not None else
                    followup.authority.audience if followup is not None else (identity.audience_ref,)))
        if operation.operation_kind == 'prepare_source_note_action':
            from .d08_source_note_action_v1 import PrepareSourceNoteActionRequestV1, source_note_attempt_id_v1
            if type(request) is not PrepareSourceNoteActionRequestV1:
                raise TypeError('source-note root requires its exact installed request')
            envelope = replace(envelope, identity=replace(envelope.identity,
                attempt_id=source_note_attempt_id_v1(envelope.authority.namespace,
                    request.project_ref, envelope.identity.operation_id)))
        plan = read_plan_current_domain_operation_v1(db, namespace=envelope.authority.namespace,
            activity_id=envelope.identity.activity_id, domain=operation.domain,
            operation_kind=operation.operation_kind, request=request, operation_id=envelope.identity.operation_id,
            now_utc=now_utc, audiences=envelope.authority.audience,
            life_d04_before_capture_policy=self.graph._GraphCoordinator__life_d04_before_capture_policy,
            personal_candidate_readers=readers if operation.operation_kind in {
                "prepare_personal_candidates_v1", "select_personal_step_v2", "input:register_artifact_task_text_extent"} else None,
            artifact_phase_readers=readers, installed_readers=readers)
        followup = getattr(self, "_active_background_followup_v1", None)
        if followup is not None:
            from .domain_production_followups_v1 import read_plan_current_domain_followup_v1
            from .domain_production_contracts_v1 import ProductionReadPlanV1
            extra = read_plan_current_domain_followup_v1(db, namespace=envelope.authority.namespace, event=followup.event)
            plan = ProductionReadPlanV1(tuple(sorted(set(plan.fixed_type_ids + extra.fixed_type_ids))),
                tuple(sorted(set(plan.exact_keys + extra.exact_keys), key=lambda key:key.token)),
                tuple(sorted(set(plan.source_roots + extra.source_roots))), plan.required_original_refs)
        if operation.operation_kind == "register_artifact_draft_root":
            issued = self._active_draft_root_registration_v1
            keys = tuple(version.key for version in issued.evidence.read_versions)
            plan = replace(plan, exact_keys=tuple(sorted(set((*plan.exact_keys, *keys)), key=lambda key: key.token)))
        policies = read_current_domain_policy_refs_v1(db, namespace=envelope.authority.namespace,
            plan=plan, installed_readers=readers)
        policies = self._method_measurement_policy_refs_v1(policies, operation=operation, scope=scope,
            owner_guard=guard, owner_binding=owner)
        originals = read_current_domain_original_refs_v1(db, namespace=envelope.authority.namespace,
            plan=plan, installed_readers=readers, authenticated_external_originals=external_originals)
        if operation.operation_kind == "input:set_contact_policy" and contact_policy is not None:
            originals += (ProductionOriginalRefV1("d10.owner_contact_policy",
                contact_policy.original_ref, contact_policy.digest),)
        if operation.operation_kind in {"prepare_contact", "adopt_contact_expression_plan", "adopt_contact_expression_plan_v2", "prepare_contact_model", "prepare_contact_model_v2", "prepare_contact_dispatch", "prepare_contact_dispatch_v3"} and current_contact is not None:
            originals += (ProductionOriginalRefV1("d10.owner_contact_policy",
                current_contact.original.original_ref, current_contact.original.digest),)
        frame = freeze_domain_production_frame_v1(self.graph, db, envelope=envelope,
            current_owner=owner, scope=scope, plan=plan, now_utc=now_utc, observed_originals=originals, installed_policy_refs=policies)
        if operation.operation_kind == "prepare_source_note_action":
            from .d08_source_note_action_v1 import source_note_schema_key_v1
            key = source_note_schema_key_v1(db, frame=frame, request=request, installed_readers=readers)
            plan = replace(plan, exact_keys=tuple(sorted(set((*plan.exact_keys, key)), key=lambda item: item.token)))
            frame = freeze_domain_production_frame_v1(self.graph, db, envelope=envelope,
                current_owner=owner, scope=scope, plan=plan, now_utc=now_utc,
                observed_originals=originals, installed_policy_refs=policies)
        if source_storage_prepare is not None:
            from .owner_material_source_v1 import OPERATION
            from .owner_material_source_storage_v3 import prepare_owner_material_source_storage_v3
            if operation.operation_kind != OPERATION:
                raise ValueError("physical Source preparation cannot replace another installed stage")
            metadata, epoch = source_storage_prepare
            stage = prepare_owner_material_source_storage_v3(self, db, frame=frame, request=request,
                installed_readers=readers, scope=scope, owner=owner, guard=guard, metadata=metadata, epoch=epoch)
        else:
            stage = stage_installed_domain_operation_v1(db, operation=operation, frame=frame, request=request,
                installed_readers=readers)
        return frame, stage, readers

    def compile_owner_stop_projection_in_transaction_v1(self, db, *, operation, request,
            envelope, scope, now_utc):
        from types import SimpleNamespace
        from .foreground_activity_issuance_v1 import require_owner_stop_projection_issuance_v1
        from .domain_production_frame_v1 import freeze_owner_stop_projection_frame_v1
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        from .owner_stop_reply_v1 import stage_owner_stop_reply_projection_v1
        issued = self._active_owner_stop_projection_v1
        observed = require_owner_stop_projection_issuance_v1(issued, self.graph, scope)
        if operation != installed_operation_v1("owner_stop_reply_v1") or request != observed.request:
            raise ValueError("Stop projection changed its actual privately observed Owner request")
        plan = ProductionReadPlanV1((), tuple(v.key for v in observed.read_versions), (),
            (observed.initial_original.original_ref,))
        frame = freeze_owner_stop_projection_frame_v1(self.graph, db, envelope=envelope,
            issued=issued, scope=scope, plan=plan, now_utc=now_utc)
        readers = SimpleNamespace(issuer=self.graph._GraphCoordinator__d11_issuer)
        stage = stage_owner_stop_reply_projection_v1(db, frame=frame, request=request,
            original=observed.initial_original, installed_readers=readers)
        return frame, stage, readers

    def run_owner_source_note_task_current_v1(self, *, selector, operation_kind, request):
        self._current()
        from ..authority_service.current_owner_source_note_task_v1 import (
            OwnerTaskActivityRequestV1, OwnerTaskActivityValuesChildRequestV1, owner_task_typed_command_digest_v1)
        operation=installed_operation_v1(operation_kind)
        if (type(selector) not in {OwnerTaskActivityRequestV1,OwnerTaskActivityValuesChildRequestV1} or selector.operation_kind!=operation_kind
                or selector.request_digest!=owner_task_typed_command_digest_v1(operation,request)):
            raise ValueError('Owner task selector differs from its actual registered typed command')
        return self.graph._owner_task_domain_write_v1(self,selector=selector,operation=operation,request=request)

    def compile_owner_task_in_transaction_v1(self, db, *, operation, request, envelope, scope, issued,
            now_utc, external_originals=()):
        self._current()
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        from .domain_production_frame_v1 import freeze_owner_source_note_task_frame_v1
        from .domain_production_read_plans_v1 import (read_plan_current_domain_operation_v1,
            read_current_domain_original_refs_v1,read_current_domain_policy_refs_v1)
        from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
        evidence=require_owner_source_note_task_issuance_v1(issued,self.graph,scope)
        auth=evidence.authorization
        plan, _, readers = self.read_current_borrowed_operation_plan_v3(db, operation=operation,
            request=request, issued=issued, scope=scope, now_utc=now_utc)
        policies=read_current_domain_policy_refs_v1(db,namespace=auth.cause.namespace,plan=plan,installed_readers=readers)
        originals=read_current_domain_original_refs_v1(db,namespace=auth.cause.namespace,plan=plan,
            installed_readers=readers,authenticated_external_originals=external_originals)
        frame=freeze_owner_source_note_task_frame_v1(self.graph,db,envelope=envelope,issued=issued,scope=scope,
            plan=plan,now_utc=now_utc,operation=operation,request=request,
            process_lease=self._active_owner_task_process_lease_v1,observed_originals=originals,
            installed_policy_refs=policies)
        if operation.operation_kind=='prepare_selected_source_note_action_v2':
            from .d08_source_note_action_v1 import selected_source_note_action_schema_key_v2
            key=selected_source_note_action_schema_key_v2(db,frame=frame,request=request,installed_readers=readers)
            plan=replace(plan,exact_keys=tuple(sorted(set((*plan.exact_keys,key)),key=lambda item:item.token)))
            frame=freeze_owner_source_note_task_frame_v1(self.graph,db,envelope=envelope,issued=issued,scope=scope,
                plan=plan,now_utc=now_utc,operation=operation,request=request,
                process_lease=self._active_owner_task_process_lease_v1,observed_originals=originals,
                installed_policy_refs=policies)
        stage=stage_installed_domain_operation_v1(db,operation=operation,frame=frame,request=request,installed_readers=readers)
        from .domain_production_commit_v1 import _members
        primary,proposals,_,_,_=_members(stage)
        if (primary.operation_kind!=evidence.request.operation_kind
                or not {proposal.domain for proposal in proposals}<=set(evidence.allowed_write_domains)):
            raise ValueError('Owner task compiler exceeded its independently qualified closed domains')
        return frame,stage,readers

    def _compile_and_commit_owner_task_in_transaction_v1(self, db, *, selector, issued, operation, request,
            scope, metadata, epoch, now_utc, external_originals=()):
        self._current()
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
        from .local_module_admission_v1 import required_operation_modules_v1
        from .domain_production_commit_v1 import commit_installed_domain_operation_v1
        from .domain_production_originals_v1 import _receipt
        from datetime import datetime
        evidence=require_owner_source_note_task_issuance_v1(issued,self.graph,scope)
        if evidence.request!=selector or getattr(self,'_active_owner_task_issuance_v1',None) is not None:
            raise ValueError('Owner task W01 changed its actual issued command')
        self.graph.local_module_admission.require_v1(required_operation_modules_v1(operation.operation_kind),operation.operation_kind)
        from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskActivityValuesChildRequestV1
        if type(selector) is OwnerTaskActivityValuesChildRequestV1:
            self.graph.local_module_admission.require_v1(
                required_operation_modules_v1('input:freeze_owner_source_note_values_parent_v1'),operation.operation_kind)
        auth=evidence.authorization
        grant=self.graph._GraphCoordinator__d11_issuer.current_budget_grant(db,auth.cause.parent_budget_lease_ref)
        lease=get_budget_lease(db,grant.lease_id)
        require_budget_family_admissible(db,lease.lease_id)
        if lease.state!='active' or grant.valid_until_utc<=now_utc:
            raise ValueError('Owner task lost its actual active original budget')
        token,capability=self.graph.grant(self._bootstrap,actor=evidence.current_self.self_entity_ref,
            issuer_domain=operation.domain,namespace=selector.namespace,domains=evidence.allowed_write_domains,
            activation_generation=evidence.current_self.activation_generation,operation_id=selector.operation_id)
        self._active_owner_task_issuance_v1=issued
        self._active_owner_task_process_lease_v1=token
        try:
            versions=dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' AND kind IN ('scheme','operator','policy')",selector.namespace.as_tuple).fetchall())
            if set(versions)!={'scheme','operator','policy'}:
                raise ValueError('Owner task lacks its actual installed guard versions')
            deadline=min(auth.cause.original_deadline_utc,grant.valid_until_utc,
                datetime.fromisoformat(evidence.valid_until_utc.replace('Z','+00:00')).timestamp())
            ids=owner_source_note_task_ids_v1(selector.namespace,auth.cause.owner_operation_id)
            from .jobs import get_job
            job=get_job(db,ids['job_id'])
            authority=AuthorityContext(evidence.current_self.self_entity_ref,operation.domain,capability,
                selector.namespace,tuple(sorted(self.graph._GraphCoordinator__leases[token][5])),
                'consolidation',auth.cause.audiences,grant.policy_ref,evidence.current_self.activation_generation,
                worker_fence=0 if job is None else job.fence)
            envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(ids['activity_id'],None,selector.operation_id,
                operation.operation_kind,selector.operation_id,canonical_digest({'input_refs':[]})),authority,
                VersionGuard((),(QueryEpoch(selector.namespace,'namespace',epoch.revision),),evidence.access_epoch,
                    evidence.delete_epoch,self.graph._GraphCoordinator__store._registry.catalogue_hash,
                    versions['scheme'],versions['operator'],versions['policy'],(),(),()),
                SourceQualification((),'derived',None,now_utc,'inference','ineligible',None,'not_applicable'),
                (),auth.cause.parent_budget_lease_ref,deadline,time.monotonic()+deadline-now_utc,
                'owner-task-current:'+selector.operation_id,())
            if operation.operation_kind=='prepare_selected_source_note_action_v2':
                from .d08_source_note_action_v1 import selected_source_note_binding_from_originals_v2
                future=selected_source_note_binding_from_originals_v2(db,namespace=selector.namespace,request=request)[1].future_identity
                if (ids['activity_id'],selector.operation_id,auth.cause.parent_budget_lease_ref,deadline)!=(future.activity_id,
                        future.action_operation_id,future.parent_budget_lease_ref,future.deadline_utc):
                    raise ValueError('Owner task Action differs from its actually selected future identity')
                envelope=replace(envelope,identity=replace(envelope.identity,effect_id=future.effect_id,attempt_id=future.attempt_id))
            if operation.operation_kind=='prepare_source_note_body':
                from .d08_source_note_action_v1 import require_source_note_action_original_v1
                root=require_source_note_action_original_v1(db,namespace=selector.namespace,
                    action_intent_ref=request.action_intent_ref,issuer=self.graph._GraphCoordinator__d11_issuer)
                if (ids['activity_id'],selector.operation_id)!=(root.activity_id,'d02-life-body:'+root.action_operation_id):
                    raise ValueError('Owner task Body changed its actual signed selected Action identity')
                envelope=replace(envelope,identity=replace(envelope.identity,effect_id=root.effect_id))
            if operation.operation_kind=='prepare_life':
                from .d11_life_preparation_v1 import read_registered_life_plan_v2
                from .d11_life_contract_v1 import RegisteredLifePlanV2
                plan=read_registered_life_plan_v2(db,namespace=selector.namespace,issuer=self.graph._GraphCoordinator__d11_issuer,
                    original_ref=request.plan_original_ref)
                if (type(plan) is not RegisteredLifePlanV2 or plan.activity_id!=ids['activity_id']
                        or plan.project.ref!=auth.request.project_ref or plan.input_source.ref!=auth.request.body_source_ref
                        or selector.operation_id!=request.prepare_operation_id):
                    raise ValueError('Owner task Life changed its actual signed fixed recipe/input/identity')
                envelope=replace(envelope,identity=replace(envelope.identity,effect_id=plan.effect_id))
            frame,stage,readers=self.compile_owner_task_in_transaction_v1(db,operation=operation,request=request,
                envelope=envelope,scope=scope,issued=issued,now_utc=now_utc,external_originals=external_originals)
            result=commit_installed_domain_operation_v1(self,db,operation=operation,request=request,frame=frame,
                stage=stage,readers=readers,scope=scope,owner=None,guard=evidence.owner_guard,metadata=metadata,
                epoch=epoch,process_lease=token,external_originals=external_originals)
            return result
        finally:
            self._active_owner_task_issuance_v1=None
            self._active_owner_task_process_lease_v1=None
            self.graph.release_authority_lease(self._bootstrap,token)

    def run_foreground_current(self, *, selector, operation_kind, request):
        """Closed self entry; the actual W01 coordinator owns begin/recovery/finish."""
        self._current()
        from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV1,
            ForegroundActivityRequestV2, ForegroundActivityPreparationParentRequestV2, foreground_typed_command_digest_v1)
        operation = installed_operation_v1(operation_kind)
        if (type(selector) not in {ForegroundActivityRequestV1, ForegroundActivityRequestV2, ForegroundActivityPreparationParentRequestV2} or selector.operation_kind != operation_kind
                or selector.request_digest != foreground_typed_command_digest_v1(operation, request)):
            raise ValueError("foreground selector differs from its actual registered typed compiler request")
        return self.graph._foreground_domain_write_v1(self, selector=selector, operation=operation, request=request)

    def compile_foreground_in_transaction(self, db, *, operation, request, envelope, scope, issued,
            now_utc, external_originals=()):
        self._current()
        from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
        from .domain_production_frame_v1 import freeze_foreground_production_frame_v1
        from .domain_production_read_plans_v1 import (read_plan_current_domain_operation_v1,
            read_current_domain_original_refs_v1, read_current_domain_policy_refs_v1)
        from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
        evidence = require_foreground_activity_issuance_v1(issued, self.graph, scope)
        if (evidence.request.operation_kind != operation.operation_kind
                or evidence.request.request_digest != foreground_typed_command_digest_v1(operation, request)):
            raise ValueError("foreground compiler cannot change its independently issued kind/body digest")
        from .foreground_cycle_v1 import (CreateForegroundCycleRequestV1, CreateForegroundCycleRequestV2,
            CheckpointForegroundCycleRequestV1, CheckpointForegroundCycleRequestV2)
        from .source_note_foreground_v1 import CheckpointSourceNoteForegroundCycleRequestV1
        if type(request) in {CreateForegroundCycleRequestV1, CreateForegroundCycleRequestV2}:
            if (request.c02_operation_id, request.source_ref) != (
                    evidence.request.c02_operation_id, evidence.request.cue_source_ref):
                raise ValueError("foreground creation compiler changed its actual qualified C02/source origin")
        elif operation.operation_kind == "create_source_note_foreground_cycle_v1":
            from .source_note_task_authorization_v1 import read_source_note_task_authorization_v1
            saved = read_source_note_task_authorization_v1(db, namespace=evidence.request.namespace,
                original_ref=request.authorization_original_ref, issuer=self.graph._GraphCoordinator__d11_issuer)
            if saved is None or (saved[0].request.c02_operation_id, saved[0].request.source_ref) != (
                    evidence.request.c02_operation_id, evidence.request.cue_source_ref):
                raise ValueError("SourceNote initial compiler changed its actual Owner authorization/C02/cue")
        elif operation.operation_kind in {"acquire_foreground_cycle", "checkpoint_foreground_cycle", "checkpoint_foreground_cycle_v2", "checkpoint_source_note_foreground_cycle_v1", "wake_foreground_cycle", "wake_artifact_draft_cycle_v1", "wake_artifact_draft_cycle_v2"}:
            if request.job_ref != evidence.request.cycle_job_ref:
                raise ValueError("foreground compiler cannot borrow another cycle target")
            if type(request) in {CheckpointForegroundCycleRequestV1, CheckpointForegroundCycleRequestV2, CheckpointSourceNoteForegroundCycleRequestV1} and (request.holder, request.fence) != (
                    evidence.request.worker_holder, evidence.request.worker_fence):
                raise ValueError("foreground checkpoint changed its actual admitted worker holder/fence")
        elif operation.operation_kind in {"prepare_ingress_recall_need_v1", "prepare_ingress_recall_model_v1", "acquire_ingress_recall_model_v1", "prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1", "adopt_ingress_recall_model_v1", "select_ingress_recall_seed_v1", "prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
            if (request.c02_operation_id, request.source_ref, request.job_ref) != (
                    evidence.request.c02_operation_id, evidence.request.cue_source_ref, evidence.request.cycle_job_ref):
                raise ValueError("recall need changed its actual privately issued C02/Source/cycle")
        if operation.operation_kind == "prepare_selected_source_note_action_v2":
            from .d08_source_note_action_v1 import selected_source_note_binding_from_originals_v2
            frozen, selected_note, source_original = selected_source_note_binding_from_originals_v2(db,
                namespace=evidence.request.namespace, request=request)
            if (envelope.identity.activity_id, envelope.identity.operation_id, envelope.identity.attempt_id, envelope.identity.effect_id,
                    envelope.deadline_utc, envelope.parent_budget_lease_ref) != (
                    selected_note.future_identity.activity_id, selected_note.future_identity.action_operation_id,
                    selected_note.future_identity.attempt_id, selected_note.future_identity.effect_id,
                    selected_note.future_identity.deadline_utc, selected_note.future_identity.parent_budget_lease_ref):
                raise ValueError("selected SourceNote compiler requires the exact actual chosen future identity")
        if operation.operation_kind in {"adopt_current_task_no_search_v1","adopt_current_c1_method_conditions_v1"}:
            if (request.c02_operation_id != evidence.request.c02_operation_id
                    or operation.operation_kind == "adopt_current_task_no_search_v1" and request.source_ref != evidence.request.cue_source_ref):
                raise ValueError("method semantic adoption changed its actual privately issued task")
        elif operation.operation_kind == "quote_current_method_choices_v1":
            if (request.task.c02_operation_id,request.task.cycle_job_ref,request.task.root_registration_ref) != (
                    evidence.request.c02_operation_id,evidence.request.cycle_job_ref,evidence.request.draft_root_registration_ref):
                raise ValueError("method readiness changed its independently issued task selector")
        plan, _, readers = self.read_current_borrowed_operation_plan_v3(db, operation=operation,
            request=request, issued=issued, scope=scope, now_utc=now_utc)
        policies = read_current_domain_policy_refs_v1(db, namespace=evidence.request.namespace, plan=plan, installed_readers=readers)
        policies = self._method_measurement_policy_refs_v1(policies, operation=operation, scope=scope,
            owner_guard=evidence.owner_guard)
        originals = read_current_domain_original_refs_v1(db, namespace=evidence.request.namespace,
            plan=plan, installed_readers=readers, authenticated_external_originals=external_originals)
        from .domain_production_contracts_v1 import ProductionOperationLimitsV1
        limits = ProductionOperationLimitsV1()
        if operation.operation_kind == "prepare_ingress_recall_need_v1":
            policy = readers.installed_bundle.d06_recall
            pages = len(plan.fixed_type_ids)
            limits = replace(limits, max_query_rows=min(64, policy.max_ledger_nodes // pages))
        frame = freeze_foreground_production_frame_v1(self.graph, db, envelope=envelope, issued=issued,
            scope=scope, plan=plan, now_utc=now_utc, operation=operation, request=request,
            process_lease=self._active_foreground_process_lease_v1,
            observed_originals=originals, installed_policy_refs=policies, limits=limits)
        if operation.operation_kind == "propose_artifact_draft_action":
            from .d08_personal_plan_v1 import artifact_draft_action_schema_key_v1
            key = artifact_draft_action_schema_key_v1(db, frame=frame, request=request, installed_readers=readers)
            plan = replace(plan, exact_keys=tuple(sorted(set((*plan.exact_keys, key)), key=lambda item: item.token)))
            frame = freeze_foreground_production_frame_v1(self.graph, db, envelope=envelope, issued=issued,
                scope=scope, plan=plan, now_utc=now_utc, operation=operation, request=request,
                process_lease=self._active_foreground_process_lease_v1,
                observed_originals=originals, installed_policy_refs=policies)
        if operation.operation_kind == "propose_artifact_draft_phase_action_v2":
            from .d08_personal_plan_v1 import artifact_phase_action_schema_key_v2
            key = artifact_phase_action_schema_key_v2(db, frame=frame, request=request, installed_readers=readers)
            plan = replace(plan, exact_keys=tuple(sorted(set((*plan.exact_keys, key)), key=lambda item: item.token)))
            frame = freeze_foreground_production_frame_v1(self.graph, db, envelope=envelope, issued=issued,
                scope=scope, plan=plan, now_utc=now_utc, operation=operation, request=request,
                process_lease=self._active_foreground_process_lease_v1,
                observed_originals=originals, installed_policy_refs=policies)
        if operation.operation_kind == "prepare_selected_source_note_action_v2":
            from .d08_source_note_action_v1 import selected_source_note_action_schema_key_v2
            key = selected_source_note_action_schema_key_v2(db, frame=frame, request=request, installed_readers=readers)
            plan = replace(plan, exact_keys=tuple(sorted(set((*plan.exact_keys, key)), key=lambda item: item.token)))
            frame = freeze_foreground_production_frame_v1(self.graph, db, envelope=envelope, issued=issued,
                scope=scope, plan=plan, now_utc=now_utc, operation=operation, request=request,
                process_lease=self._active_foreground_process_lease_v1, observed_originals=originals,
                installed_policy_refs=policies, limits=limits)
        stage = stage_installed_domain_operation_v1(db, operation=operation, frame=frame, request=request, installed_readers=readers)
        from .domain_production_commit_v1 import _members
        primary, proposals, _, _, _ = _members(stage)
        if (primary.operation_kind != evidence.request.operation_kind
                or not {proposal.domain for proposal in proposals} <= set(evidence.allowed_write_domains)):
            raise ValueError("foreground actual typed stage exceeded its closed independently issued domains")
        return frame, stage, readers

    def _compile_and_commit_foreground_in_transaction_v1(self, db, *, selector, issued, operation, request,
            scope, metadata, epoch, now_utc, external_originals=()):
        """Fixed private W01 callback; no supplied callback/Owner lease can select its code."""
        self._current()
        from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1, record_foreground_life_scope_after_commit_v1
        from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
        from datetime import datetime
        evidence = require_foreground_activity_issuance_v1(issued, self.graph, scope)
        if (evidence.request != selector or selector.request_digest != foreground_typed_command_digest_v1(operation, request)
                or getattr(self, "_active_foreground_issuance_v1", None) is not None):
            raise ValueError("foreground W01 callback changed its actual issued registered command")
        from .local_module_admission_v1 import required_operation_modules_v1
        self.graph.local_module_admission.require_v1(required_operation_modules_v1(operation.operation_kind), operation.operation_kind)
        issuer = self.graph._GraphCoordinator__d11_issuer
        grant = issuer.current_budget_grant(db, selector.parent_budget_lease_ref)
        lease = get_budget_lease(db, grant.lease_id)
        require_budget_family_admissible(db, grant.lease_id)
        if lease.state != "active" or grant.valid_until_utc <= now_utc or (grant.bot_id, grant.persona_id) != selector.namespace.as_tuple:
            raise ValueError("foreground operation lost its actual original active budget")
        count_material = None
        if operation.operation_kind == "acquire_artifact_draft_model_v2":
            from .d02_artifact_phase_price_v1 import require_artifact_phase_count_material_for_foreground_v2
            count_material = require_artifact_phase_count_material_for_foreground_v2(self, db,
                issued=issued, operation=operation, request=request, scope=scope, now_utc=now_utc)
            token = count_material.process_lease
        else:
            token, capability = self.graph.grant(self._bootstrap, actor=evidence.current_self.self_entity_ref,
                issuer_domain=operation.domain, namespace=selector.namespace, domains=evidence.allowed_write_domains,
                activation_generation=evidence.current_self.activation_generation, operation_id=selector.operation_id)
        self._active_foreground_issuance_v1 = issued
        self._active_foreground_process_lease_v1 = token
        try:
            if count_material is None:
                versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' "
                    "AND kind IN ('scheme','operator','policy')", selector.namespace.as_tuple).fetchall())
                if set(versions) != {"scheme", "operator", "policy"}:
                    raise ValueError("foreground requires actual installed current scheme/operator/policy heads")
                deadline = min(selector.requested_deadline_utc, grant.valid_until_utc,
                    datetime.fromisoformat(evidence.valid_until_utc.replace("Z", "+00:00")).timestamp())
                if operation.operation_kind == "quote_current_method_choices_v1":
                    from .d02_method_readiness_v1 import current_method_readiness_count_deadline_v1
                    deadline=min(deadline,current_method_readiness_count_deadline_v1(self,issued=issued,
                        operation_id=selector.operation_id,request=request,scope=scope))
                authority = AuthorityContext(evidence.current_self.self_entity_ref, operation.domain, capability,
                    selector.namespace, tuple(sorted(self.graph._GraphCoordinator__leases[token][5])), selector.purpose, selector.audiences,
                    grant.policy_ref, evidence.current_self.activation_generation)
                envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(selector.activity_id, None, selector.operation_id,
                    operation.operation_kind, selector.operation_id, canonical_digest({"input_refs": []})), authority,
                    VersionGuard((), (QueryEpoch(selector.namespace, "namespace", epoch.revision),), evidence.access_epoch,
                        evidence.delete_epoch, self.graph._GraphCoordinator__store._registry.catalogue_hash,
                        versions["scheme"], versions["operator"], versions["policy"], (), (), ()),
                    SourceQualification((), "derived", None, now_utc, "inference", "ineligible", None, "not_applicable"),
                    (), selector.parent_budget_lease_ref, deadline, time.monotonic() + deadline - now_utc,
                    "foreground-current:" + selector.operation_id, ())
                if operation.operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
                    from .c04_ingress_preparation_v4 import configure_self_c04_envelope_v4
                    envelope = configure_self_c04_envelope_v4(db, graph=self.graph, envelope=envelope,
                        request=request, operation_kind=operation.operation_kind)
                if operation.operation_kind == "prepare_ingress_recall_model_v1":
                    from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
                    ids = ingress_recall_model_ids_v1(selector.namespace, request.c02_operation_id)
                    if selector.operation_id != ids["prepare"]:
                        raise ValueError("Self C3 must retain its actual fixed preparation identity")
                    envelope = replace(envelope, identity=replace(envelope.identity,
                        effect_id=ids["effect"], attempt_id=ids["attempt"]))
                if operation.operation_kind == "prepare_selected_source_note_action_v2":
                    from .d08_source_note_action_v1 import selected_source_note_binding_from_originals_v2
                    future = selected_source_note_binding_from_originals_v2(db,
                        namespace=selector.namespace, request=request)[1].future_identity
                    if (selector.activity_id, selector.operation_id, selector.parent_budget_lease_ref, deadline) != (
                            future.activity_id, future.action_operation_id, future.parent_budget_lease_ref, future.deadline_utc):
                        raise ValueError("SourceNote selected future changed its actual privately issued identity or deadline")
                    envelope = replace(envelope, identity=replace(envelope.identity,
                        effect_id=future.effect_id, attempt_id=future.attempt_id))
                if operation.operation_kind == "propose_artifact_draft_action":
                    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
                    ids = artifact_draft_file_ids_v1(selector.namespace, c02_operation_id=request.c02_operation_id,
                        root_registration_ref=request.root_registration_ref)
                    if selector.operation_id != ids["action_operation"]:
                        raise ValueError("artifact Action must use its actual task's fixed operation identity")
                    envelope = replace(envelope, identity=replace(envelope.identity, effect_id=ids["effect"], attempt_id=ids["attempt"]))
                if operation.operation_kind == "propose_artifact_draft_phase_action_v2":
                    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
                    ids = artifact_draft_file_ids_v2(request.selector)
                    if (selector.operation_id, selector.activity_id) != (ids["action_operation"], ids["activity_id"]):
                        raise ValueError("phase Action must use its actual original file operation/activity")
                    envelope = replace(envelope, identity=replace(envelope.identity,
                        effect_id=ids["effect"], attempt_id=ids["attempt"]))
                if operation.operation_kind == "prepare_artifact_draft_body":
                    from .d08_life_admission_v1 import require_draft_action_root_v1
                    root = require_draft_action_root_v1(db, namespace=selector.namespace,
                        action_intent_ref=request.action_intent_ref, issuer=issuer)
                    if (selector.operation_id, selector.activity_id) != (
                            "d02-life-body:" + root.action_operation_id, root.activity_id):
                        raise ValueError("Body command differs from its actual signed Action root")
                    envelope = replace(envelope, identity=replace(envelope.identity, effect_id=root.effect_id))
                if operation.operation_kind == "prepare_life":
                    from .d11_life_preparation_v1 import read_registered_life_plan_v2
                    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
                    plan = read_registered_life_plan_v2(db, namespace=selector.namespace, issuer=issuer,
                        original_ref=request.plan_original_ref)
                    if (type(plan) is not RegisteredDraftFilePlanV3 or selector.activity_id != plan.activity_id
                            or selector.operation_id != request.prepare_operation_id
                            or selector.draft_root_registration_ref != plan.target.root_registration_ref):
                        raise ValueError("foreground Life preparation must retain the actual signed draft plan identity")
                    envelope = replace(envelope, identity=replace(envelope.identity, effect_id=plan.effect_id))
                frame, stage, readers = self.compile_foreground_in_transaction(db, operation=operation, request=request,
                    envelope=envelope, scope=scope, issued=issued, now_utc=now_utc, external_originals=external_originals)
            else:
                frame, stage, readers = count_material.frame, count_material.stage, count_material.readers
                self.graph._GraphCoordinator__artifact_draft_model_runtime_v1._active_artifact_phase_count_stage_v2 = (
                    count_material.stage, count_material.count_pair, now_utc)
            from .domain_production_commit_v1 import commit_installed_domain_operation_v1
            result = commit_installed_domain_operation_v1(self, db, operation=operation, request=request,
                frame=frame, stage=stage, readers=readers, scope=scope, owner=None, guard=evidence.owner_guard,
                metadata=metadata, epoch=epoch, process_lease=token, external_originals=external_originals)
            from .domain_production_originals_v1 import _receipt
            from contextlib import ExitStack
            with ExitStack() as post_commit_stack:
                successor = None
                if (operation.operation_kind in {
                        "propose_artifact_draft_action", "propose_artifact_draft_phase_action_v2"}
                        and result["coverage"] == "complete"):
                    from .current_method_learning_read_v3 import bind_method_post_commit_v3
                    successor = post_commit_stack.enter_context(bind_method_post_commit_v3(
                        db, graph=self.graph, prior_frame=frame, stage=stage,
                        actual_receipt=_receipt(result["receipt"]), scope=scope,
                        issued=issued, process_lease=token))
                if operation.operation_kind in {
                        "prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2"}:
                    from .current_method_learning_read_v3 import bind_method_foreground_scope_post_commit_v3
                    with bind_method_foreground_scope_post_commit_v3(
                            db, graph=self.graph, prior_frame=frame, stage=stage,
                            actual_receipt=_receipt(result["receipt"]), scope=scope,
                            issued=issued, process_lease=token):
                        originals = record_foreground_life_scope_after_commit_v1(
                            db, graph=self.graph, issued=issued, frame=frame,
                            receipt=_receipt(result["receipt"]), issuer=issuer)
                else:
                    originals = record_foreground_life_scope_after_commit_v1(
                        db, graph=self.graph, issued=issued, frame=frame,
                        receipt=_receipt(result["receipt"]), issuer=issuer)
                result["produced_originals"].extend({"kind": item.kind, "original_ref": item.original_ref,
                    "original_digest": item.original_digest} for item in originals)
                from .d07_ingress_recall_result_v1 import D07IngressRecallResultStageV1, record_ingress_recall_result_after_cas_v1
                if type(stage) is D07IngressRecallResultStageV1:
                    produced = record_ingress_recall_result_after_cas_v1(db, stage=stage,
                        receipt=_receipt(result["receipt"]), issuer=issuer)
                    if produced is not None:
                        result["produced_originals"].append(produced)
                from .d11_artifact_draft_content_v1 import ArtifactDraftContentStageV1, ArtifactDraftContentStageV2, record_artifact_draft_content_after_cas_v1
                if type(stage) in {ArtifactDraftContentStageV1, ArtifactDraftContentStageV2}:
                    produced = record_artifact_draft_content_after_cas_v1(db, stage=stage,
                        receipt=_receipt(result["receipt"]), installed_readers=readers)
                    result["produced_originals"].append({"kind": produced.kind, "original_ref": produced.original_ref,
                        "original_digest": produced.original_digest})
                from .d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerificationStageV2, record_artifact_draft_phase_verified_after_cas_v2
                if type(stage) is ArtifactDraftPhaseVerificationStageV2:
                    produced = record_artifact_draft_phase_verified_after_cas_v2(db, stage=stage,
                        receipt=_receipt(result["receipt"]), installed_readers=readers)
                    result["produced_originals"].append({"kind": produced.kind, "original_ref": produced.original_ref,
                        "original_digest": produced.original_digest})
                if operation.operation_kind == "propose_artifact_draft_action" and result["coverage"] == "complete":
                    from .domain_production_inputs_v1 import _post_commit_frame
                    from .d08_personal_plan_v1 import read_current_artifact_action_root_skeleton_v1
                    from .d08_life_admission_v1 import record_draft_action_root_v1
                    post = _post_commit_frame(db, frame, request, _successor_v3=successor)
                    skeleton = read_current_artifact_action_root_skeleton_v1(db, frame=post, request=request, installed_readers=readers)
                    produced = record_draft_action_root_v1(db, frame=post, plan=skeleton, issuer=issuer)
                    result["produced_originals"].append({"kind": produced.kind, "original_ref": produced.original_ref,
                        "original_digest": produced.original_digest})
                if operation.operation_kind == "propose_artifact_draft_phase_action_v2" and result["coverage"] == "complete":
                    from .domain_production_inputs_v1 import _post_commit_frame
                    from .d08_personal_plan_v1 import read_current_artifact_phase_action_root_skeleton_v2
                    from .d08_life_admission_v1 import record_draft_action_root_v1
                    post = _post_commit_frame(db, frame, request, _successor_v3=successor)
                    skeleton = read_current_artifact_phase_action_root_skeleton_v2(db,
                        frame=post, request=request, installed_readers=readers)
                    produced = record_draft_action_root_v1(db, frame=post, plan=skeleton, issuer=issuer)
                    result["produced_originals"].append({"kind": produced.kind, "original_ref": produced.original_ref,
                        "original_digest": produced.original_digest})
            return result
        finally:
            self._active_foreground_issuance_v1 = None
            self._active_foreground_process_lease_v1 = None
            if count_material is None:
                self.graph.release_authority_lease(self._bootstrap, token)

    def run_current(self, authority, lease, *, operation_kind, request, operation_id,
            activity_id, audience_ref, parent_budget_lease_ref, _background_followup=None,
            _background_host_lifecycle=None, _background_offline=None,
            _owner_material_command_v3=None, _owner_material_work_v3=None, _method_inputs_v3=None):
        self._current()
        self._last_refusal_exception_v1 = None
        graph = self.graph
        operation = installed_operation_v1(operation_kind)
        if type(request) is not operation.request_type:
            raise TypeError("production operation requires its exact typed request")
        for value in (operation_id, activity_id, audience_ref, parent_budget_lease_ref):
            if type(value) is not str or not value or len(value) > 4096:
                raise ValueError("production operation original identity is invalid")
        namespace = authority.namespace
        if _background_offline is not None:
            from .d10_offline_recovery_driver_v1 import require_background_offline_command_v1
            require_background_offline_command_v1(_background_offline, graph, authority, operation_id)
            if (_background_followup is not None or _background_host_lifecycle is not None
                    or (_background_offline.operation_kind, _background_offline.request) != (operation_kind, request)):
                raise ValueError("offline recovery issuance differs from its exact installed command")
        if _background_followup is not None:
            from .domain_followup_consumer_v1 import require_background_followup_v1
            require_background_followup_v1(_background_followup, graph, authority, operation_id)
        if _background_host_lifecycle is not None:
            from .d11_host_lifecycle_driver_v1 import require_background_host_lifecycle_v1
            require_background_host_lifecycle_v1(_background_host_lifecycle, graph, authority, operation_id)
            if _background_followup is not None or operation_kind != "record_host_lifecycle":
                raise ValueError("Host lifecycle issuance cannot select another operation")
        elif operation_kind == "record_host_lifecycle":
            raise ValueError("actual Host lifecycle capture is required")
        from ..runtime_storage_v3 import runtime_storage_v3
        if operation_kind == 'admit_owner_material_source_v1' and runtime_storage_v3(graph._GraphCoordinator__store._db) is not None:
            from .owner_material_source_storage_v3 import (
                prepare_owner_material_command_digest_v3, require_owner_material_command_digest_v3)
            if _background_followup or _background_host_lifecycle or _background_offline:
                raise ValueError("material Source digest requires the actual explicit Owner action")
            if _owner_material_command_v3 is None:
                command = prepare_owner_material_command_digest_v3(self, authority, lease, request=request,
                    operation_id=operation_id, activity_id=activity_id, audience_ref=audience_ref,
                    parent_budget_lease_ref=parent_budget_lease_ref)
                return graph._prepare_owner_material_command_work_v3(command)
            from ..graph_worker import GraphStorageWorkV3
            if (type(_owner_material_work_v3) is not GraphStorageWorkV3
                    or _owner_material_work_v3.coordinator is not graph
                    or _owner_material_work_v3.operation is not _owner_material_command_v3.operation):
                raise ValueError("selected material Source requires the same actual initial Work/retention lease")
            _owner_material_work_v3._require_invocation(graph)
            request_digest = require_owner_material_command_digest_v3(_owner_material_command_v3,
                self, authority, lease, request=request, operation_id=operation_id, activity_id=activity_id,
                audience_ref=audience_ref, parent_budget_lease_ref=parent_budget_lease_ref,
                storage_work=_owner_material_work_v3)
        else:
            if _owner_material_command_v3 is not None or _owner_material_work_v3 is not None:
                raise ValueError("material Source command witness cannot alter another operation")
            request_digest = canonical_digest(("sylanne.domain-production-command.v1", namespace,
                authority.actor, operation_kind, request, operation_id, activity_id, audience_ref, parent_budget_lease_ref))
        from .current_method_learning_read_v3 import (METHOD_INPUT_OPERATIONS_V3, PreparedMethodDomainInputsV3)
        if _method_inputs_v3 is not None:
            if (type(_method_inputs_v3) is not PreparedMethodDomainInputsV3
                    or _method_inputs_v3.owner.runtime is not self
                    or _method_inputs_v3.owner.authority != authority
                    or _method_inputs_v3.owner.lease is not lease
                    or _method_inputs_v3.owner.operation_kind != operation_kind
                    or _method_inputs_v3.owner.request != request
                    or _method_inputs_v3.owner.request_digest != request_digest
                    or _method_inputs_v3.owner.operation_id != operation_id
                    or _method_inputs_v3.owner.activity_id != activity_id
                    or _method_inputs_v3.owner.audience_ref != audience_ref
                    or _method_inputs_v3.owner.parent_budget_lease_ref != parent_budget_lease_ref):
                raise ValueError("method prepared inputs changed their actual installed command")
            _method_inputs_v3._actual_v3()
        elif (operation_kind in METHOD_INPUT_OPERATIONS_V3
                and runtime_storage_v3(graph._GraphCoordinator__store._db) is not None):
            with graph._GraphCoordinator__store._lock:
                saved_method = graph._GraphCoordinator__store._db.execute(
                    "SELECT request_digest,receipt_json IS NOT NULL FROM graph_owner_domain_attempts_v3 "
                    "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone()
            if saved_method is None or not saved_method[1]:
                return graph._prepare_current_method_operation_v3(self, authority, lease,
                    operation_kind=operation_kind, request=request, operation_id=operation_id,
                    activity_id=activity_id, audience_ref=audience_ref,
                    parent_budget_lease_ref=parent_budget_lease_ref, request_digest=request_digest,
                    background_followup=_background_followup,
                    background_host_lifecycle=_background_host_lifecycle, background_offline=_background_offline)
        if operation_kind == "register_artifact_draft_root":
            from ..authority_service.current_foreground_activity_v1 import draft_root_registration_operation_digest_v1
            if (_background_followup is not None or _background_host_lifecycle is not None or _background_offline is not None
                    or lease is None or request.operation_id != operation_id or request.namespace != namespace):
                raise ValueError("draft root setup requires its exact explicit Owner command/session")
            request_digest = draft_root_registration_operation_digest_v1(request, authority.actor)
        def new_work_admission(db):
            from .local_module_admission_v1 import required_operation_modules_v1, completed_original_input_v1
            required = required_operation_modules_v1(operation_kind)
            if required and not (_background_followup or _background_host_lifecycle or _background_offline):
                required = (*required, "d12")
            if (set(required) & set(graph.local_module_admission.disabled_modules)
                    and operation_kind in {"input:register_life_outcome", "input:register_life_outcome_v2",
                                           "input:record_body_component"}):
                # Called before the Owner business transaction. Existing Life
                # artifact/provenance readers require one pinned SQL snapshot.
                db.execute("BEGIN")
                try:
                    completed = completed_original_input_v1(db, namespace, operation_kind, request,
                                                            graph._GraphCoordinator__d11_issuer)
                finally:
                    db.rollback()
                if completed:
                    required = ()
            graph.local_module_admission.require_v1(required, operation_kind)
        context = {"external_originals": ()}
        process_lease = []
        @contextmanager
        def fence_context(scope, guard, owner):
            context.update(scope=scope, guard=guard, owner=owner)
            reader = getattr(graph, "_GraphCoordinator__d04_semantic_mapping_reader", None)
            if (operation.domain in {"d02", "d07", "d10"} or operation.operation_kind in {
                    "adopt_contact_expression_plan", "adopt_contact_expression_plan_v2", "prepare_contact_model", "prepare_contact_model_v2", "prepare_contact_dispatch", "prepare_contact_dispatch_v3"}) and reader is None:
                raise ValueError("actual installed role-clock reader is unavailable")
            from .domain_production_read_plans_v1 import (read_plan_current_domain_operation_v1,
                read_independent_current_original_requests_v1)
            store = graph._GraphCoordinator__store
            contact_plan, contact_policy_ref = None, None
            clock = graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
                graph._GraphCoordinator__scene_clock_policy)
            from .first_ingress_v2 import trusted_upper
            read_now_utc = trusted_upper(clock)
            with store._lock:
                store._db.execute("BEGIN")
                try:
                    if _background_host_lifecycle is not None:
                        requests = ()
                    else:
                        plan, requests = self.read_current_operation_plan_v3(store._db,
                            operation=operation, request=request, operation_id=operation_id,
                            activity_id=activity_id, audience_ref=audience_ref, scope=scope,
                            owner_guard=guard, now_utc=read_now_utc)
                        if operation.operation_kind in {"prepare_contact_model", "prepare_contact_model_v2", "prepare_contact_dispatch", "prepare_contact_dispatch_v3"}:
                            from .contact_plan_adoption_v1 import read_adopted_contact_plan_v1
                            if operation.operation_kind in {"prepare_contact_model_v2", "prepare_contact_dispatch_v3"}:
                                from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2 as read_adopted_contact_plan_v1
                            contact_plan, _, contact_original, _ = read_adopted_contact_plan_v1(store._db,
                                namespace=namespace, contact_id=request.contact_id, issuer=graph._GraphCoordinator__d11_issuer)
                            contact_policy_ref = contact_original["policy_ref"]
                finally:
                    store._db.rollback()
            originals = [ProductionOriginalRefV1("d11.restore_anchor",
                "restore-anchor:" + canonical_digest(scope.pinned_anchor), canonical_digest(scope.pinned_anchor))]
            originals.append(ProductionOriginalRefV1("d11.trusted_tick", "d11-tick:" + operation_id,
                canonical_digest(clock.sample)))
            if operation.operation_kind in {"encode_structured_experience", "adopt_owner_artifact_project_context_v1"}:
                from .domain_structured_self_observation_v1 import observe_structured_self_identity_v1
                originals.append(observe_structured_self_identity_v1(graph, namespace=namespace,
                    operation_id=operation_id, scope=scope, owner_guard=guard))
            port = getattr(graph, "_GraphCoordinator__c04_authority_port_v3", None)
            if operation.operation_kind == "prepare_life":
                from ..host.d11_life_port_v1 import InstalledD11LifePortV1
                assembly = graph._GraphCoordinator__d04_installed_joint_assembly
                if assembly is None or assembly.installation_policy.namespace != namespace:
                    raise ValueError("actual installed Life namespace/build is unavailable")
                self._active_life_execution_inventory_v1 = InstalledD11LifePortV1(
                    graph._GraphCoordinator__content_fence_v2).read_d11_life_execution_inventory_v1(
                        namespace=assembly.installation_policy.authority_namespace, permit=scope.permit)
            if operation.operation_kind == "input:set_contact_policy":
                if _background_followup is not None or _background_offline is not None or lease is None:
                    raise ValueError("background work cannot issue contact consent")
                session_token, session_request = graph._GraphCoordinator__owner_session_proofs[lease]
                if port is None:
                    raise ValueError("actual installed contact-policy Authority port is unavailable")
                actual_policy = port.contact_policy(scope.permit, "issue",
                    owner_actor_id=authority.actor, owner_session_token=session_token,
                    owner_session_request=session_request,
                    operation_id="contact-policy-issue:" + operation_id, policy=request.policy)
                self._active_contact_policy_original_v1 = actual_policy
                originals.append(ProductionOriginalRefV1("d10.owner_contact_policy",
                    actual_policy.original_ref, actual_policy.digest))
            if requests and port is None:
                raise ValueError("actual paired C04 original reader unavailable")
            from .c04_product_lifecycle_v3 import c04_terminal_proof_from_inspection_v3
            for requested in requests:
                proof = c04_terminal_proof_from_inspection_v3(port.inspect(requested.binding))
                if proof is None:
                    continue
                verified = port.verify_terminal(proof)
                if (verified.proof_digest != canonical_digest(proof)
                        or requested.component_proof_digest != verified.proof_digest
                        or requested.terminal_receipt_ref != verified.terminal_receipt_ref
                        or requested.terminal_receipt_digest != verified.terminal_receipt_digest):
                    raise ValueError("independent C04 terminal differs from its actual paid original")
                originals.extend((ProductionOriginalRefV1("d11.internal_component", requested.component_ref, verified.proof_digest),
                    ProductionOriginalRefV1("d11.internal_cost", verified.terminal_receipt_ref, verified.terminal_receipt_digest)))
            with ExitStack() as qualifications:
                # These observations belong to this exact independently held
                # scope, including failures while subsequent observers enter.
                qualifications.callback(setattr, self, '_active_draft_root_registration_v1', None)
                if operation.operation_kind == "register_artifact_draft_root":
                    from .foreground_activity_issuance_v1 import draft_root_registration_for_fence_v1
                    session_token, session_request = graph._GraphCoordinator__owner_session_proofs[lease]
                    self._active_draft_root_registration_v1 = qualifications.enter_context(draft_root_registration_for_fence_v1(
                        graph, scope=scope, request=request, owner_actor_ref=authority.actor,
                        owner_session_token=session_token, owner_session_request=session_request))
                qualifications.callback(setattr, self, '_active_life_numeric_environment_v1', None)
                qualifications.callback(setattr, self, '_active_life_numeric_topology_v1', None)
                if operation.operation_kind in {"prepare_contact", "adopt_contact_expression_plan", "adopt_contact_expression_plan_v2", "prepare_contact_model", "prepare_contact_model_v2", "prepare_contact_dispatch", "prepare_contact_dispatch_v3"}:
                    from ..graph_types import AtomKey
                    from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
                    policy_key = AtomKey.from_token(contact_policy_ref if contact_policy_ref is not None else request.contact_policy_ref)
                    if policy_key.type_name != "d10.contact_policy.v1" or port is None:
                        raise ValueError("contact opportunity needs its actual installed policy Authority")
                    current_policy = qualifications.enter_context(read_installed_current_contact_policy_v1(
                        port, scope, policy_key.name))
                    if contact_plan is not None and (current_policy is None
                            or current_policy.original.original_ref != contact_plan.policy_original_ref
                            or current_policy.original.digest != contact_plan.policy_original_digest):
                        raise ValueError("contact model preparation no longer has its actual current Owner policy")
                    self._active_current_contact_policy_v1 = current_policy
                    if current_policy is not None:
                        originals.append(ProductionOriginalRefV1("d10.owner_contact_policy",
                            current_policy.original.original_ref, current_policy.original.digest))
                if operation.operation_kind in {'prepare_internal_life_interval_baseline', 'adopt_internal_life_numeric_trace'}:
                    from .installed_c04_encoding_context_v3 import observe_installed_c04_encoding_environment_v3
                    self._active_life_numeric_environment_v1 = observe_installed_c04_encoding_environment_v3(
                        graph, self._bootstrap, namespace)
                if operation.operation_kind == 'prepare_internal_life_numeric_joint':
                    topology = graph._installed_d04_authored_topology_verifier_v3()
                    topology.observe_current_location_for_fence_v3(graph._GraphCoordinator__content_fence_v2, scope)
                    self._active_life_numeric_topology_v1 = topology
                context["external_originals"] = tuple(originals)
                qualifications.enter_context(reader.current_fence(scope) if operation.domain in {"d02", "d07", "d10"}
                                              or operation.operation_kind in {"prepare_internal_life_numeric_drive", "prepare_internal_life_numeric_joint", "prepare_source_note_action", "adopt_contact_expression_plan", "adopt_contact_expression_plan_v2", "prepare_contact_model", "prepare_contact_model_v2", "prepare_contact_dispatch", "prepare_contact_dispatch_v3"}
                                             else nullcontext())
                if operation.operation_kind in {"prepare_contact_dispatch", "prepare_contact_dispatch_v3"}:
                    from .contact_final_stage_v2 import command_identity_contact_final_v2
                    if operation.operation_kind == "prepare_contact_dispatch_v3":
                        from .contact_final_stage_v3 import command_identity_contact_final_v3 as command_identity_contact_final_v2
                    with store._lock:
                        store._db.execute('BEGIN')
                        try:
                            _, effect_id, _ = command_identity_contact_final_v2(store._db, namespace=namespace,
                                request=request, operation_id=operation_id, issuer=graph._GraphCoordinator__d11_issuer)
                        finally:
                            store._db.rollback()
                    actual_port = graph._GraphCoordinator__content_fence_v2
                    self._active_contact_final_command_v1 = (request, operation_id)
                    self._active_contact_final_scope_v1 = scope
                    self._active_contact_final_owner_v1 = owner
                    self._active_contact_final_guard_v1 = guard
                    self._active_contact_final_clock_v1 = clock
                    self._active_contact_final_effect_v1 = actual_port.read_current_effect(namespace=namespace,
                        authority_namespace=scope.authority_namespace, effect_id=effect_id)
                    self._active_contact_final_effect_snapshot_v1 = actual_port.read_current_effect_snapshot_for_write_fence(
                        namespace=namespace, authority_namespace=scope.authority_namespace, permit=scope.permit)
                    self._active_contact_final_stage_call_v1 = object()
                if operation.operation_kind=='adopt_internal_life_content_v1':
                    from .internal_life_content_adoption_v1 import content_keys_v1
                    from .internal_life_paid_result_v2 import read_life_paid_original_v2
                    from .internal_life_content_worker_v2 import read_life_worker_original_v2
                    from .d06_internal_life_episode_v2 import PROVENANCE,decode_internal_life_value_v2
                    from ..model_broker.internal_life_content_v1 import internal_life_content_ids_for_occurrence_v1
                    from ..graph_types import AtomKey
                    from ..authority_service.v2_model_egress_wire import from_wire
                    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
                    from .model_cost_settlement import read_original_model_cost
                    with store._lock:
                        store._db.execute('BEGIN')
                        try:
                            key=AtomKey.from_token(request.episode_ref)
                            ep=decode_internal_life_value_v2(PROVENANCE,json.loads(store._db.execute('SELECT value FROM graph_atoms WHERE token=?',
                                (AtomKey(key.owner,PROVENANCE,'record').token,)).fetchone()[0]))
                            ids=internal_life_content_ids_for_occurrence_v1(ep)
                            original=read_life_worker_original_v2(store._db,namespace=namespace,issuer=graph._GraphCoordinator__d11_issuer,
                                kind='call',job_id=ids['job'])
                            if original is None:raise ValueError('Life content adoption actual sealed call missing')
                            actual_intent=from_wire(original['intent'],ModelEgressIntentV1)
                        finally:store._db.rollback()
                    self._active_life_content_fact_v2=read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port,actual_intent)
                numeric_worker = None
                if operation.operation_kind == 'acquire_internal_life_numeric':
                    from .d06_life_numeric_worker_v1 import issue_installed_life_numeric_worker_v1
                    numeric_worker = issue_installed_life_numeric_worker_v1(self, scope, guard, owner)
                    self._active_life_numeric_issuance_v1 = numeric_worker
                life_worker = None
                if operation.operation_kind == 'acquire_internal_life_content_v2':
                    from .internal_life_worker_binding_v2 import issue_installed_life_worker_v2
                    life_worker = issue_installed_life_worker_v2(self,scope,guard,owner)
                    self._active_internal_life_worker_v2 = life_worker
                if operation.operation_kind == "prepare_personal_candidates_v1":
                    from .d02_artifact_phase_price_v1 import personal_phase_counts_for_owner_fence_v1
                    qualifications.enter_context(personal_phase_counts_for_owner_fence_v1(self,
                        authority=authority, operation=operation, request=request, operation_id=operation_id,
                        activity_id=activity_id, audience_ref=audience_ref,
                        parent_budget_lease_ref=parent_budget_lease_ref, scope=scope, owner=owner,
                        guard=guard, external_originals=context["external_originals"], now_utc=read_now_utc))
                try:
                    yield
                finally:
                    if numeric_worker is not None:
                        from .d06_life_numeric_worker_v1 import release_installed_life_numeric_worker_v1
                        release_installed_life_numeric_worker_v1(numeric_worker)
                        self._active_life_numeric_issuance_v1 = None
                    if life_worker is not None:
                        from .internal_life_worker_binding_v2 import release_installed_life_worker_v2
                        release_installed_life_worker_v2(life_worker)
                        self._active_internal_life_worker_v2 = None
                    self._active_contact_policy_original_v1 = None
                    self._active_current_contact_policy_v1 = None
                    self._active_life_execution_inventory_v1 = None
                    self._active_life_content_fact_v2 = None
                    if operation.operation_kind in {'prepare_contact_dispatch', 'prepare_contact_dispatch_v3'}:
                        from .contact_final_stage_v1 import revoke_contact_final_material_v1
                        if operation.operation_kind == "prepare_contact_dispatch_v3":
                            from .contact_final_stage_v3 import revoke_contact_final_material_v3 as revoke_contact_final_material_v1
                        revoke_contact_final_material_v1(self)
                        self._active_contact_final_command_v1 = None
                        self._active_contact_final_scope_v1 = None
                        self._active_contact_final_stage_call_v1 = None
                        self._active_contact_final_stage_v1 = None
        def staged_commit(db, metadata, epoch, now, owner, scope, *, prepare_source_storage=False):
            from .domain_production_commit_v1 import commit_installed_domain_operation_v1
            resolution = None
            if _background_followup is not None:
                from .domain_followup_consumer_v1 import validate_followup_command_in_transaction_v1
                _followup_frame, resolution = validate_followup_command_in_transaction_v1(
                    _background_followup, graph, db, scope, owner, now)
            budget = get_budget_lease(db, parent_budget_lease_ref)
            management_cancel=operation.operation_kind=='cancel_owner_source_note_task_v1'
            if management_cancel:
                from .cancel_owner_source_note_task_v1 import _authorization
                readers=installed_readers_for_operation_v1(graph,operation,scope=scope,
                    owner_guard=context['guard'],owner_binding=owner)
                _,auth=_authorization(db,namespace=namespace,request=request,issuer=readers.issuer)
                grant,_=graph._GraphCoordinator__d11_issuer.signed_budget_grant_at_version(db,
                    auth.cause.parent_budget_lease_ref,auth.cause.parent_grant_version)
                if (auth.cause.owner_actor_ref!=authority.actor or auth.cause.parent_budget_lease_ref!=parent_budget_lease_ref
                        or grant.grant_id!=auth.cause.parent_grant_id or canonical_digest(grant)!=auth.cause.parent_grant_digest
                        or (grant.bot_id,grant.persona_id,grant.lease_id)!=(*namespace.as_tuple,budget.lease_id)):
                    raise ValueError('Owner cancellation changed its actual historical task/Root identity')
            else:
                grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, parent_budget_lease_ref)
                if ((budget.bot_id, budget.persona_id) != namespace.as_tuple or budget.state != "active"
                        or (grant.bot_id, grant.persona_id, grant.lease_id) != (*namespace.as_tuple, budget.lease_id)
                        or grant.valid_until_utc <= now):
                    raise ValueError("domain operation parent budget is not currently installed")
                require_budget_family_admissible(db, budget.lease_id)
            if _owner_material_command_v3 is not None:
                _owner_material_command_v3.require_original_root_v3(db, grant, budget)
            domains = (("d08", "d09", "d10", "d11") if operation.operation_kind in {"prepare_contact_dispatch", "prepare_contact_dispatch_v3"} else
                ("d06", "d11") if operation.operation_kind == "record_host_lifecycle" else
                ("d08", "d11") if operation.operation_kind == "prepare_source_note_action" else
                ("d03", "d06", "d07", "d11") if operation.operation_kind == "prepare_internal_life_numeric_context" else
                ("d03", "d06", "d11") if operation.domain == "d06" else
                ("d02", "d06", "d10", "d11") if operation.domain == "d10" else
                ("d02", "d07", "d11") if operation.domain == "d07" else (operation.domain, "d11"))
            token, capability = graph.grant(self._bootstrap, actor=authority.actor,
                issuer_domain=operation.domain, namespace=namespace, domains=domains,
                activation_generation=authority.activation_generation, operation_id=operation_id)
            process_lease.append(token)
            actual_authority = AuthorityContext(authority.actor, operation.domain, capability, namespace,
                tuple(sorted(graph._GraphCoordinator__leases[token][5])),
                'workbench_user_action' if management_cancel else
                "consolidation" if operation.operation_kind == "adopt_owner_artifact_project_context_v1" else
                    authority.purpose if _background_offline is not None else "context",
                authority.audience if _background_offline is not None or _background_followup is not None
                    else (audience_ref,),
                grant.policy_ref, authority.activation_generation)
            deadline_seconds = 60.0
            if operation.operation_kind in {"adopt_contact_expression_plan", "adopt_contact_expression_plan_v2"}:
                assembly = graph._GraphCoordinator__d04_installed_joint_assembly
                if assembly is None:
                    raise ValueError("actual installed contact model workflows are unavailable")
                generation = assembly.admin_bundle.model_workflows.contact_generation
                review = assembly.admin_bundle.model_workflows.contact_review
                if generation is None or review is None:
                    raise ValueError("both actual installed contact workflows are required")
                deadline_seconds = generation.timeout_seconds + review.timeout_seconds + 30.0
            if operation.domain == "d07":
                execution = getattr(graph, "_GraphCoordinator__d07_execution_service_v1", None)
                if execution is not None:
                    workflow = execution.bundle.model_workflows.d07_cognition
                    if workflow is not None:
                        deadline_seconds = 2.0 * workflow.timeout_seconds + 30.0
            deadline = now+deadline_seconds if management_cancel else min(now + deadline_seconds, grant.valid_until_utc)
            if _owner_material_command_v3 is not None:
                deadline = min(deadline, _owner_material_command_v3.deadline_utc)
            if _method_inputs_v3 is not None:
                deadline = min(deadline, _method_inputs_v3.envelope.deadline_utc)
                if now >= deadline:
                    raise ValueError("method original preparation deadline expired before WRITE")
            if operation.operation_kind=='submit_owner_source_note_task_v1':
                from ..domains.d01.production_operations_v1 import plain_v1
                from .d07_life_project_focus_v1 import _keys
                from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                focus_id='owner-note-focus:'+canonical_digest((namespace,operation_id,
                    canonical_digest({'request':plain_v1(request)})))[:40]
                focus_original=read_adopted_domain_operation_v1(db,namespace,focus_id)
                if focus_original is not None:
                    ticket_key,focus_key=_keys(namespace,focus_id)
                    ticket=db.execute('SELECT value,valid FROM graph_atoms WHERE token=?',(ticket_key.token,)).fetchone()
                    focus=db.execute('SELECT value,valid FROM graph_atoms WHERE token=?',(focus_key.token,)).fetchone()
                    if (focus_original['operation_kind']!='focus_life_project'
                            or focus_original['payload']['authority']['actor']!=authority.actor
                            or ticket is None or ticket[1]!=1 or focus is None or focus[1]!=1):
                        raise ValueError('Owner submit original Focus qualification changed')
                    selected=json.loads(ticket[0])
                    if (selected['concern_ref']!=request.project_ref or selected['causal_root']!=request.body_source_ref
                            or json.loads(focus[0])['primary_ticket_ref']!=ticket_key.token or selected['valid_until']<=now):
                        raise ValueError('Owner submit original Focus expired or was replaced')
                    deadline=min(deadline,selected['valid_until'])
            if operation.operation_kind == "prepare_personal_candidates_v1":
                from .d02_artifact_phase_price_v1 import original_personal_phase_count_deadline_v1
                counted_deadline = original_personal_phase_count_deadline_v1(self, operation_id=operation_id)
                if counted_deadline is not None:
                    deadline = min(deadline, counted_deadline)
            inputs = ()
            versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
                "AND ref='current' AND kind IN ('scheme','operator','policy')", namespace.as_tuple).fetchall())
            if set(versions) != {"scheme", "operator", "policy"}:
                raise ValueError("domain operation requires the current registered scheme/operator/policy heads")
            envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(activity_id, None, operation_id,
                operation_kind, operation_id, canonical_digest({"input_refs": list(inputs)})), actual_authority,
                VersionGuard((), (QueryEpoch(namespace, "namespace", epoch.revision),), owner.access_epoch,
                    owner.delete_epoch, graph._GraphCoordinator__store._registry.catalogue_hash,
                    versions["scheme"], versions["operator"], versions["policy"], (), (), ()),
                SourceQualification((), "derived", None, now, "inference", "ineligible", None, "not_applicable"),
                inputs, parent_budget_lease_ref, deadline, time.monotonic() + (deadline - now),
                "domain-current:" + operation_id, ())
            if operation_kind=='admit_owner_material_source_v1':
                envelope=replace(envelope,source_qualification=SourceQualification((),'authored',None,now,
                    'authored_content','ineligible',None,'not_applicable'),
                    monotonic_deadline=min(envelope.monotonic_deadline,_owner_material_command_v3.monotonic_deadline)
                        if _owner_material_command_v3 is not None else envelope.monotonic_deadline)
            frame, stage, readers = self.compile_in_transaction(db, operation=operation, request=request,
                envelope=envelope, scope=scope, owner=owner, guard=context["guard"], now_utc=now,
                external_originals=context["external_originals"],
                source_storage_prepare=(metadata, epoch) if prepare_source_storage else None)
            if prepare_source_storage:
                stage.process_lease = token
                actual_session = graph._GraphCoordinator__owner_session_proofs.get(lease)
                if actual_session is None:
                    raise ValueError("physical Owner Source requires its actual registered Owner session proof")
                session_digest = canonical_digest(actual_session)
                stage.metadata_value["owner_session_proof_ref"] = "owner-session-proof:" + session_digest
                stage.metadata_value["owner_session_proof_digest"] = session_digest
                stage.external_originals = context["external_originals"]
                stage.command = _owner_material_command_v3
                stage.metadata_value["command_seed_digest"] = _owner_material_command_v3.require_command_seed_v3(
                    db,scope.operation_id,request_digest)
                stage.metadata_value["initial_parent_budget_digest"] = _owner_material_command_v3.root_grant_digest
                # The same actual granted process lease moves to the Work state.
                # Removing it here prevents this synchronous frame's finally from releasing it.
                process_lease.remove(token)
                return stage
            result = commit_installed_domain_operation_v1(self, db, operation=operation, request=request,
                frame=frame, stage=stage, readers=readers, scope=scope, owner=owner,
                guard=context["guard"], metadata=metadata, epoch=epoch, process_lease=token,
                external_originals=context["external_originals"])
            if _background_followup is not None:
                from .domain_followup_consumer_v1 import finish_followup_command_in_transaction_v1
                result["followup_disposition"] = finish_followup_command_in_transaction_v1(
                    _background_followup, graph, db, resolution, result)
            return result
        def prepare_source_storage(db, metadata, epoch, now, owner, scope):
            from .owner_material_source_v1 import OPERATION
            if operation.operation_kind != OPERATION:
                raise ValueError("only actual Owner material Source has a physical Work preparation")
            return staged_commit(db, metadata, epoch, now, owner, scope, prepare_source_storage=True)

        def commit(db, metadata, epoch, now, owner, scope):
            from ..contracts import StaleRead
            from ..graph_coordinator import AuthorityDenied, UnavailableGuard
            # Every installed stage is SQL-only. A deterministic refusal can
            # roll back its quote/job/projection changes before closing the
            # actual Owner fence; no external work was started by this seam.
            db.execute("SAVEPOINT domain_production_stage_v1")
            try:
                value = staged_commit(db, metadata, epoch, now, owner, scope)
                db.execute("RELEASE domain_production_stage_v1")
                return value
            except (ValueError, TypeError, StaleRead, AuthorityDenied, UnavailableGuard) as exc:
                if not db.in_transaction:
                    raise
                db.execute("ROLLBACK TO domain_production_stage_v1")
                db.execute("RELEASE domain_production_stage_v1")
                if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise
                self._last_refusal_exception_v1 = exc
                return {"schema": "sylanne.domain-production-refusal.v1", "status": "held",
                    "domain": operation.domain, "operation_kind": operation.operation_kind,
                    "operation_id": operation_id, "activity_id": activity_id,
                    "request_digest": request_digest, "reason_code": type(exc).__name__,
                    "coverage": "waiting_for_original", "missing_inputs": ["current_domain_prerequisite"],
                    "job_states": [], "outbox": [], "continuation_ref": None}
        if (getattr(self, "_active_background_followup_v1", None) is not None
                or getattr(self, "_active_host_lifecycle_v1", None) is not None
                or getattr(self, "_active_background_offline_v1", None) is not None):
            raise ValueError("another installed followup compilation is already active")
        self._active_background_followup_v1 = _background_followup
        self._active_host_lifecycle_v1 = _background_host_lifecycle
        self._active_background_offline_v1 = _background_offline
        try:
            if operation.operation_kind in {'prepare_contact_dispatch', 'prepare_contact_dispatch_v3'}:
                from .contact_final_ack_v1 import issue_contact_owner_call_v1
                issue_contact_owner_call_v1(self,authority=authority,lease=lease,request=request,
                    operation_id=operation_id,request_digest=request_digest)
            result = graph._owner_domain_write_v3(authority, lease, operation_id=operation_id,
                request_digest=request_digest, domains=(operation.domain,), capability=operation.capability,
                commit=commit, fence_context=fence_context,
                background_original=_background_followup or _background_host_lifecycle or _background_offline,
                new_work_admission=new_work_admission,
                storage_prepare=prepare_source_storage if _owner_material_work_v3 is not None else None,
                storage_work=_owner_material_work_v3)
            from ..graph_worker import GraphStorageWorkV3
            if type(result) is GraphStorageWorkV3:
                return result
            if operation.operation_kind == 'acquire_internal_life_content' and result.get('job_states'):
                from contextlib import closing
                from pathlib import Path
                import sqlite3
                from .internal_life_content_worker_v1 import read_committed_internal_life_request_v1
                store = graph._GraphCoordinator__store
                path = Path(store._db.execute('PRAGMA database_list').fetchone()[2])
                with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as durable:
                    durable.execute('PRAGMA query_only=ON'); durable.execute('BEGIN')
                    read_committed_internal_life_request_v1(durable,namespace=namespace,
                        issuer=graph._GraphCoordinator__d11_issuer,job_id=result['job_states'][0][0])
                    durable.rollback()
            if operation.operation_kind == 'prepare_internal_life_content' and result.get('job_states'):
                # The Owner helper has performed the actual COMMIT. This
                # independent read certifies historical durability only;
                # workers must acquire fresh current Owner/Source permission.
                from .internal_life_content_preparation_v1 import read_committed_internal_life_prepared_v1
                store = graph._GraphCoordinator__store
                with store._lock:
                    store._db.execute('BEGIN')
                    try:
                        prepared = read_committed_internal_life_prepared_v1(store._db,
                            namespace=namespace, issuer=graph._GraphCoordinator__d11_issuer,
                            job_id=result['job_states'][0][0])
                        if prepared.prepare_operation_id != operation_id:
                            raise ValueError('Life content returned another durable preparation')
                    finally:
                        store._db.rollback()
            if operation.operation_kind=='adopt_contact_expression_plan_v2' and result.get('coverage')=='complete':
                from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
                store = graph._GraphCoordinator__store
                with store._lock:
                    store._db.execute('BEGIN')
                    try:
                        original=store._db.execute('SELECT original_payload_json FROM graph_domain_production_originals_v1 '
                            'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
                        if original is None:raise ValueError('Contact Plan v2 actual durable production original absent')
                        contact_id=json.loads(original[0])['provenance']['contact_plan']['contact_id']
                        read_adopted_contact_plan_v2(store._db,namespace=namespace,contact_id=contact_id,
                            issuer=graph._GraphCoordinator__d11_issuer)
                    finally:store._db.rollback()
            return result
        finally:
            if operation.operation_kind in {'prepare_contact_dispatch', 'prepare_contact_dispatch_v3'}:
                from .contact_final_ack_v1 import revoke_contact_owner_call_v1
                revoke_contact_owner_call_v1(self)
                from .contact_final_stage_v1 import revoke_contact_final_material_v1
                if operation.operation_kind == "prepare_contact_dispatch_v3":
                    from .contact_final_stage_v3 import revoke_contact_final_material_v3 as revoke_contact_final_material_v1
                revoke_contact_final_material_v1(self)
                for name in ('command','scope','stage_call','stage','owner','guard','clock','effect','effect_snapshot'):
                    setattr(self, '_active_contact_final_' + name + '_v1', None)
            self._active_background_followup_v1 = None
            self._active_host_lifecycle_v1 = None
            self._active_background_offline_v1 = None
            self._active_contact_policy_original_v1 = None
            self._active_current_contact_policy_v1 = None
            for token in process_lease:
                graph.release_authority_lease(self._bootstrap, token)
