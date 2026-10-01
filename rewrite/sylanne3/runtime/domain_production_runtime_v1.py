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

    def _current(self):
        if getattr(self.graph, "_GraphCoordinator__domain_production_runtime_v1", None) is not self:
            raise ValueError("domain production runtime is not installed on its coordinator")

    def compile_in_transaction(self, db, *, operation, request, envelope, scope, owner, guard,
            now_utc, external_originals=()):
        self._current()
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
        readers = installed_readers_for_operation_v1(self.graph, operation, scope=scope, owner_guard=guard,
            execution_reader=getattr(self.graph, "_GraphCoordinator__d07_execution_service_v1", None))
        contact_policy = getattr(self, "_active_contact_policy_original_v1", None)
        if operation.operation_kind == "input:set_contact_policy":
            readers.contact_policy_original = contact_policy
        current_contact = getattr(self, "_active_current_contact_policy_v1", None)
        if operation.operation_kind in {"prepare_contact", "adopt_contact_expression_plan", "prepare_contact_model"}:
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
        plan = read_plan_current_domain_operation_v1(db, namespace=envelope.authority.namespace,
            activity_id=envelope.identity.activity_id, domain=operation.domain,
            operation_kind=operation.operation_kind, request=request, operation_id=envelope.identity.operation_id,
            now_utc=now_utc, audiences=envelope.authority.audience)
        followup = getattr(self, "_active_background_followup_v1", None)
        if followup is not None:
            from .domain_production_followups_v1 import read_plan_current_domain_followup_v1
            from .domain_production_contracts_v1 import ProductionReadPlanV1
            extra = read_plan_current_domain_followup_v1(db, namespace=envelope.authority.namespace, event=followup.event)
            plan = ProductionReadPlanV1(tuple(sorted(set(plan.fixed_type_ids + extra.fixed_type_ids))),
                tuple(sorted(set(plan.exact_keys + extra.exact_keys), key=lambda key:key.token)),
                tuple(sorted(set(plan.source_roots + extra.source_roots))), plan.required_original_refs)
        policies = read_current_domain_policy_refs_v1(db, namespace=envelope.authority.namespace,
            plan=plan, installed_readers=readers)
        originals = read_current_domain_original_refs_v1(db, namespace=envelope.authority.namespace,
            plan=plan, installed_readers=readers, authenticated_external_originals=external_originals)
        if operation.operation_kind == "input:set_contact_policy" and contact_policy is not None:
            originals += (ProductionOriginalRefV1("d10.owner_contact_policy",
                contact_policy.original_ref, contact_policy.digest),)
        if operation.operation_kind in {"prepare_contact", "adopt_contact_expression_plan", "prepare_contact_model"} and current_contact is not None:
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
        stage = stage_installed_domain_operation_v1(db, operation=operation, frame=frame, request=request,
            installed_readers=readers)
        return frame, stage, readers

    def run_current(self, authority, lease, *, operation_kind, request, operation_id,
            activity_id, audience_ref, parent_budget_lease_ref, _background_followup=None,
            _background_host_lifecycle=None, _background_offline=None):
        self._current()
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
        request_digest = canonical_digest(("sylanne.domain-production-command.v1", namespace,
            authority.actor, operation_kind, request, operation_id, activity_id, audience_ref, parent_budget_lease_ref))
        context = {"external_originals": ()}
        process_lease = []
        @contextmanager
        def fence_context(scope, guard, owner):
            context.update(scope=scope, guard=guard, owner=owner)
            reader = getattr(graph, "_GraphCoordinator__d04_semantic_mapping_reader", None)
            if (operation.domain in {"d02", "d07", "d10"} or operation.operation_kind in {
                    "adopt_contact_expression_plan", "prepare_contact_model"}) and reader is None:
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
                        plan = read_plan_current_domain_operation_v1(store._db, namespace=namespace,
                            activity_id=activity_id, domain=operation.domain, operation_kind=operation_kind,
                            request=request, operation_id=operation_id, now_utc=read_now_utc,
                            audiences=(audience_ref,))
                        requests = read_independent_current_original_requests_v1(store._db, namespace=namespace, plan=plan)
                        if operation.operation_kind == "prepare_contact_model":
                            from .contact_plan_adoption_v1 import read_adopted_contact_plan_v1
                            contact_plan, _, contact_original, _ = read_adopted_contact_plan_v1(store._db,
                                namespace=namespace, contact_id=request.contact_id, issuer=graph._GraphCoordinator__d11_issuer)
                            contact_policy_ref = contact_original["policy_ref"]
                finally:
                    store._db.rollback()
            originals = [ProductionOriginalRefV1("d11.restore_anchor",
                "restore-anchor:" + canonical_digest(scope.pinned_anchor), canonical_digest(scope.pinned_anchor))]
            originals.append(ProductionOriginalRefV1("d11.trusted_tick", "d11-tick:" + operation_id,
                canonical_digest(clock.sample)))
            if operation.operation_kind == "encode_structured_experience":
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
                if operation.operation_kind in {"prepare_contact", "adopt_contact_expression_plan", "prepare_contact_model"}:
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
                context["external_originals"] = tuple(originals)
                qualifications.enter_context(reader.current_fence(scope) if operation.domain in {"d02", "d07", "d10"}
                                              or operation.operation_kind in {"prepare_source_note_action", "adopt_contact_expression_plan", "prepare_contact_model"}
                                             else nullcontext())
                try:
                    yield
                finally:
                    self._active_contact_policy_original_v1 = None
                    self._active_current_contact_policy_v1 = None
                    self._active_life_execution_inventory_v1 = None
        def staged_commit(db, metadata, epoch, now, owner, scope):
            from .domain_production_commit_v1 import commit_installed_domain_operation_v1
            resolution = None
            if _background_followup is not None:
                from .domain_followup_consumer_v1 import validate_followup_command_in_transaction_v1
                _followup_frame, resolution = validate_followup_command_in_transaction_v1(
                    _background_followup, graph, db, scope, owner, now)
            budget = get_budget_lease(db, parent_budget_lease_ref)
            grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, parent_budget_lease_ref)
            if ((budget.bot_id, budget.persona_id) != namespace.as_tuple or budget.state != "active"
                    or (grant.bot_id, grant.persona_id, grant.lease_id) != (*namespace.as_tuple, budget.lease_id)
                    or grant.valid_until_utc <= now):
                raise ValueError("domain operation parent budget is not currently installed")
            require_budget_family_admissible(db, budget.lease_id)
            domains = (("d06", "d11") if operation.operation_kind == "record_host_lifecycle" else
                ("d08", "d11") if operation.operation_kind == "prepare_source_note_action" else
                ("d03", "d06", "d11") if operation.domain == "d06" else
                ("d02", "d06", "d10", "d11") if operation.domain == "d10" else
                ("d02", "d07", "d11") if operation.domain == "d07" else (operation.domain, "d11"))
            token, capability = graph.grant(self._bootstrap, actor=authority.actor,
                issuer_domain=operation.domain, namespace=namespace, domains=domains,
                activation_generation=authority.activation_generation, operation_id=operation_id)
            process_lease.append(token)
            actual_authority = AuthorityContext(authority.actor, operation.domain, capability, namespace,
                tuple(sorted(graph._GraphCoordinator__leases[token][5])), authority.purpose if _background_offline is not None else "context",
                authority.audience if _background_offline is not None or _background_followup is not None
                    else (audience_ref,),
                grant.policy_ref, authority.activation_generation)
            deadline_seconds = 60.0
            if operation.operation_kind == "adopt_contact_expression_plan":
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
            deadline = min(now + deadline_seconds, grant.valid_until_utc)
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
            frame, stage, readers = self.compile_in_transaction(db, operation=operation, request=request,
                envelope=envelope, scope=scope, owner=owner, guard=context["guard"], now_utc=now,
                external_originals=context["external_originals"])
            result = commit_installed_domain_operation_v1(self, db, operation=operation, request=request,
                frame=frame, stage=stage, readers=readers, scope=scope, owner=owner,
                guard=context["guard"], metadata=metadata, epoch=epoch, process_lease=token,
                external_originals=context["external_originals"])
            if _background_followup is not None:
                from .domain_followup_consumer_v1 import finish_followup_command_in_transaction_v1
                result["followup_disposition"] = finish_followup_command_in_transaction_v1(
                    _background_followup, graph, db, resolution, result)
            return result
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
            return graph._owner_domain_write_v3(authority, lease, operation_id=operation_id,
                request_digest=request_digest, domains=(operation.domain,), capability=operation.capability,
                commit=commit, fence_context=fence_context,
                background_original=_background_followup or _background_host_lifecycle or _background_offline)
        finally:
            self._active_background_followup_v1 = None
            self._active_host_lifecycle_v1 = None
            self._active_background_offline_v1 = None
            self._active_contact_policy_original_v1 = None
            self._active_current_contact_policy_v1 = None
            for token in process_lease:
                graph.release_authority_lease(self._bootstrap, token)
