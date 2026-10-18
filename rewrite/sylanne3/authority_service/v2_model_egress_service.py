"""Authority-local typed preparation; provider handoff remains HOLD."""

from __future__ import annotations

from dataclasses import asdict
from contextlib import ExitStack, nullcontext
import secrets

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest
from ..runtime_contracts import NamespaceId
from ..host.model_workflows_v3 import AdminModelWorkflowsV3
from ..host.model_workflows_v4 import AdminModelWorkflowsV4
from ..host.model_workflows_v5 import AdminModelWorkflowsV5
from ..host.model_workflows_v6 import AdminModelWorkflowsV6
from ..host.model_workflows_v7 import AdminModelWorkflowsV7
from ..host.model_workflows_v8 import AdminModelWorkflowsV8
from ..host.model_workflows_v9 import AdminModelWorkflowsV9
from ..host.authority_profile import AdminIngressModelPolicy, AdminModelWorkflowsV2
from ..model_broker.broker import ModelCallRequest
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from ..model_broker.reply_language import (
    REPLY_TEMPLATE_DIGEST, REPLY_TEMPLATE_VERSION,
)
from .contract import AuthorityUnavailable, identifier
from .current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
from .v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressObservationV1,
    ModelAdmissionV2, HostObservedModelCompletionV2, ModelTerminalReceiptV2,
)
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_terminal_c02_recovery_contract import OriginalC02ResultKeyV1
from .v2_fence_service import AuthorityV2FenceService


class AuthorityV2ModelEgressService:
    def __init__(self, store: AuthorityV2ModelEgressStore,
                 fences: AuthorityV2FenceService | None = None, *,
                 graph_verifier: PinnedCurrentModelEgressGraphVerifier | None = None,
                 admin_model_policy: (AdminIngressModelPolicy | AdminModelWorkflowsV2 |
                                      AdminModelWorkflowsV3 | AdminModelWorkflowsV4 | AdminModelWorkflowsV5 | AdminModelWorkflowsV6 | AdminModelWorkflowsV7 | AdminModelWorkflowsV8 | AdminModelWorkflowsV9 | None) = None,
                 source_location=None):
        if type(store) is not AuthorityV2ModelEgressStore:
            raise TypeError("Authority-owned model egress store required")
        if fences is not None and (type(fences) is not AuthorityV2FenceService
                                   or store._db is not fences.core._db
                                   or store._lock is not fences.core._lock):
            raise AuthorityUnavailable("model egress and fence must share Authority DB and lock")
        if (graph_verifier is not None
                and type(graph_verifier) is not PinnedCurrentModelEgressGraphVerifier):
            raise TypeError("administrator-pinned model egress graph verifier required")
        if (admin_model_policy is not None
                and type(admin_model_policy) not in (AdminIngressModelPolicy, AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9)):
            raise TypeError("administrator-installed model policy required")
        self._store = store
        self._fences = fences
        self._graph_verifier = graph_verifier
        self._owner_goal_cancellation_service_v1 = None
        self._admin_model_policy = admin_model_policy
        # Installed composition, never a caller-supplied location proof. The
        # concrete qualifier is checked when configured; old initial-generation
        # callers remain compatible, but cannot dispatch after a storage rebase
        # without the installed current-location qualification below.
        self._source_location = None
        self._d13_provider_http_counter_v1 = None
        if source_location is not None:
            self.install_current_source_location_v1(source_location)
        from .model_capacity_v1 import install_model_capacity_functions_v1
        install_model_capacity_functions_v1(self._store._db)
        from .d07_model_timing_v1 import install_d07_model_timing_schema_v1
        with self._store._tx() as db:
            install_d07_model_timing_schema_v1(db)

    def install_owner_goal_cancellation_service_v1(self, service):
        from .owner_goal_cancellation_v1 import InstalledOwnerGoalCancellationServiceV1
        if (type(service) is not InstalledOwnerGoalCancellationServiceV1
                or self._fences is None or service.core is not self._fences.core
                or service.fences is not self._fences
                or service.bundle is not self._graph_verifier._artifact_draft_bundle
                or self._owner_goal_cancellation_service_v1 is not None):
            raise AuthorityUnavailable("Goal barrier needs its actual installed same Core/model service")
        self._owner_goal_cancellation_service_v1 = service

    def install_d13_provider_http_counter_v1(self, counter):
        from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
        from ..host.model_workflows_v7 import AdminModelWorkflowsV7
        if (type(counter) is not InstalledD13CoreCounterServiceV1
                or type(self._admin_model_policy) not in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                or counter.core._db is not self._store._db or counter.fences is not self._fences
                or self._d13_provider_http_counter_v1 is not None):
            raise AuthorityUnavailable('provider HTTP counter must be the exact installed model/Core instance')
        self._d13_provider_http_counter_v1=counter

    def bind_observed_d13_provider_http_v1(self, *, credential, subject, holder, intent, admission, content):
        counter=self._d13_provider_http_counter_v1
        if counter is None or intent.namespace!=self._fences.namespace:
            raise AuthorityUnavailable('actual installed V7 provider HTTP counter unavailable')
        self._fences.core._require(credential,'model_egress',self._fences.namespace,holder)
        with self._fences._frozen() as (db,deletion_head,execution_head,deletion_history):
            record=self._store.read_locked(db,intent)
            actual_admission,report,terminal=self._store.read_admission_locked(db,intent)
            row=self._fences.fences._row(db,intent.operation_id)
            anchor=self._fences._current_locked(db,deletion_head,execution_head,holder=holder,
                generation=intent.authority_activation_generation)
            if (subject!=intent.subject or actual_admission!=admission or report is not None or terminal is not None
                    or record.state!='dispatch_started' or row is None or row[6]!='active'
                    or canonical_digest(asdict(anchor))!=intent.anchor_digest):
                raise AuthorityUnavailable('provider HTTP capture crossed original live model admission')
            permit=self._fences.fences._permit(row)
            self._fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        location=self._source_location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
        if self._graph_verifier.complete_graph_current(intent,source_location=self._source_location,
                location_observation=location,model_service=self,credential=credential,subject=subject,permit=permit) is not True:
            raise AuthorityUnavailable('provider HTTP capture lacks actual current Source/job/reservation')
        with self._fences._frozen() as (db,deletion_head,execution_head,deletion_history):
            actual_anchor=self._fences._current_locked(db,deletion_head,execution_head,holder=holder,
                generation=intent.authority_activation_generation)
            if actual_anchor!=anchor:raise AuthorityUnavailable('provider HTTP original anchor changed')
            self._fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=actual_anchor)
            self._source_location.require_current_in_tx_v1(db,location)
            from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
            require_lifecycle_admission_in_tx_v1(db,intent.namespace,action='first_model_dispatch')
            from .d13_provider_http_admission_v1 import record_observed_provider_http_v1
            return record_observed_provider_http_v1(db,counter=counter,intent=intent,admission=admission,
                actual_content=content,now_utc=self._graph_verifier._clock())

    def install_current_source_location_v1(self, qualifier):
        """Bind once during installed assembly, never through a wire request."""
        from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        if (type(qualifier) is not InstalledCurrentSourceLocationQualifierV1
                or self._fences is None or qualifier._fences is not self._fences
                or qualifier.core is not self._fences.core
                or self._graph_verifier is None
                or qualifier._graph_db_path != self._graph_verifier._path
                or self._source_location is not None
                   and self._source_location is not qualifier):
            raise AuthorityUnavailable("same installed model fence and Graph location qualifier required")
        self._source_location = qualifier
        from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
        install_authority_graph_read_controller_v3(self._graph_verifier,service=self,source_location=qualifier)

    def _require_reply_scope_in_tx_v1(self, db, scope, anchor, *, action):
        if scope is None:
            return
        from .owner_stop_reply_v1 import require_reply_scope_not_stopped_in_tx_v1
        if scope.service.core is not self._fences.core:
            raise AuthorityUnavailable("model reply scope crossed its actual Core")
        require_reply_scope_not_stopped_in_tx_v1(db,
            authority_namespace=self._fences.namespace,
            installation_id=scope.service.installation_id,
            activation_generation=anchor.activation_generation,
            actual_cycle_identity=scope, action=action)

    def _artifact_draft_admin_matches_v1(self, intent, request):
        from ..host.authority_profile import AdminInstallationBundle
        from ..runtime.d11_artifact_draft_model_v1 import installed_artifact_draft_workflow_v1
        from ..model_broker.artifact_draft_v1 import (ArtifactDraftInputV1,
            TEMPLATE_DIGEST, TEMPLATE_VERSION, WORK_KIND, artifact_draft_from_wire_v1,
            artifact_draft_model_ids_v1, artifact_draft_provider_messages_v1)
        verifier = self._graph_verifier
        if verifier is None or type(self._admin_model_policy) not in {AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
            return False
        bundle = verifier._artifact_draft_bundle
        if (type(bundle) is not AdminInstallationBundle
                or bundle.model_workflows is not self._admin_model_policy):
            return False
        workflow = installed_artifact_draft_workflow_v1(bundle)
        artifact_draft_provider_messages_v1(request)
        frozen = artifact_draft_from_wire_v1(dict(request.payload)["input"], ArtifactDraftInputV1)
        ids = artifact_draft_model_ids_v1(frozen.selector)
        installation = bundle.installation_policy
        authority = request.envelope.authority
        ceiling = dict(intent.budget_ceiling)
        return (
            workflow is bundle.model_workflows.artifact_draft
            and (workflow.work_kind, workflow.purpose, workflow.template_version)
                == (WORK_KIND, "consolidation", TEMPLATE_VERSION)
            and frozen.selector.namespace == authority.namespace == installation.namespace
            and intent.namespace == installation.authority_namespace == self._fences.namespace
            and intent.authority_id == installation.expected_authority_id
            and request.digest == intent.request_digest
            and (request.call_id, intent.call_id, intent.job_id, request.identity.operation_id,
                 intent.operation_id, intent.acquire_operation_id, intent.budget_reservation_operation_id)
                == (ids["call"], ids["call"], ids["job"], ids["acquire"],
                    ids["acquire"], ids["acquire"], ids["prepare"])
            and authority.actor == intent.subject
            and authority.issuer_domain == "d11"
            and authority.activation_generation == intent.authority_activation_generation
            and authority.worker_fence == intent.worker_fence
            and authority.purpose == "consolidation"
            and request.identity.phase == WORK_KIND
            and request.prompt_template_digest == TEMPLATE_DIGEST
            and bool(authority.audience) and set(authority.audience) <= set(workflow.audiences)
            and request.privacy_tier == workflow.privacy_tier
            and request.required_capabilities == frozenset(workflow.required_capabilities)
            and (request.provider_id, intent.provider_id) == (workflow.provider_id, workflow.provider_id)
            and (request.model_id, intent.model_id) == (workflow.model_id, workflow.model_id)
            and intent.provider_config_digest == workflow.provider_config_digest
            and request.max_output_tokens == intent.max_output_tokens == workflow.max_output_tokens
            and request.timeout_seconds == workflow.timeout_seconds
            and set(ceiling) == {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
            and request.max_output_tokens <= ceiling["output_tokens"]
            and all(amount <= workflow.quote_ceiling[dimension] for dimension, amount in ceiling.items()))

    def _artifact_draft_admin_matches_v2(self, intent, request):
        from ..host.authority_profile import (
            AdminInstallationBundle, AdminArtifactDraftPolicyV3, AdminArtifactDraftToolScopeV2,
            is_installed_artifact_draft_phase_slot_v2,
        )
        from ..model_broker.artifact_draft_v1 import (
            TEMPLATE_DIGEST_V2, TEMPLATE_VERSION_V2, WORK_KIND,
            artifact_draft_input_from_wire_v2, artifact_draft_model_ids_v2,
            artifact_draft_provider_messages_v2, artifact_draft_phase_token_limits_v2,
        )
        from ..domains.d01 import TONE_SAMPLE_METHOD_V1
        from ..host.model_workflows_v6 import AdminModelWorkflowsV6
        from ..host.model_workflows_v7 import AdminModelWorkflowsV7
        from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4, require_paired_phase_frozen_target_v4
        verifier = self._graph_verifier
        if verifier is None or type(self._admin_model_policy) not in {AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
            return False
        bundle = verifier._artifact_draft_bundle
        if (type(bundle) is not AdminInstallationBundle or bundle.model_workflows is not self._admin_model_policy
                or type(bundle.artifact_draft) not in {AdminArtifactDraftPolicyV3, AdminArtifactDraftPairedPolicyV4}):
            return False
        workflow = bundle.artifact_draft.phase_model_workflow
        if not is_installed_artifact_draft_phase_slot_v2(bundle, workflow):
            return False
        artifact_draft_provider_messages_v2(request)
        frozen = artifact_draft_input_from_wire_v2(dict(request.payload)["input"])
        ids = artifact_draft_model_ids_v2(frozen.selector)
        limits = artifact_draft_phase_token_limits_v2(frozen.selector)
        tool_scope = bundle.artifact_draft.tool_scope
        if type(bundle.artifact_draft) is AdminArtifactDraftPairedPolicyV4:
            tool_scope = require_paired_phase_frozen_target_v4(bundle.artifact_draft,frozen)
        if (frozen.selector.method_ref == TONE_SAMPLE_METHOD_V1
                and (type(tool_scope) is not AdminArtifactDraftToolScopeV2
                    or tool_scope.maximum_artifact_version < 2)):
            return False
        installation = bundle.installation_policy
        authority = request.envelope.authority
        ceiling = dict(intent.budget_ceiling)
        return (
            (workflow.work_kind, workflow.purpose, workflow.template_version) == (WORK_KIND, "consolidation", TEMPLATE_VERSION_V2)
            and frozen.selector.task.namespace == authority.namespace == installation.namespace
            and intent.namespace == installation.authority_namespace == self._fences.namespace
            and intent.authority_id == installation.expected_authority_id
            and request.digest == intent.request_digest
            and (request.call_id, intent.call_id, intent.job_id, request.identity.operation_id,
                 intent.operation_id, intent.acquire_operation_id, intent.budget_reservation_operation_id)
                == (ids["call"], ids["call"], ids["job"], ids["acquire"], ids["acquire"], ids["acquire"], ids["prepare"])
            and authority.actor == intent.subject and authority.issuer_domain == "d11"
            and authority.activation_generation == intent.authority_activation_generation
            and authority.worker_fence == intent.worker_fence and authority.purpose == "consolidation"
            and request.identity.phase == WORK_KIND and request.prompt_template_digest == TEMPLATE_DIGEST_V2
            and bool(authority.audience) and set(authority.audience) <= set(workflow.audiences)
            and request.privacy_tier == workflow.privacy_tier
            and request.required_capabilities == frozenset(workflow.required_capabilities)
            and (request.provider_id, intent.provider_id) == (workflow.provider_id, workflow.provider_id)
            and (request.model_id, intent.model_id) == (workflow.model_id, workflow.model_id)
            and intent.provider_config_digest == workflow.provider_config_digest
            and request.max_output_tokens == intent.max_output_tokens == min(workflow.max_output_tokens, limits["output_tokens"])
            and 0 < request.timeout_seconds <= workflow.timeout_seconds
            and set(ceiling) == {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
            and ceiling["input_tokens"] <= limits["input_tokens"] and ceiling["output_tokens"] <= limits["output_tokens"]
            and request.max_output_tokens <= ceiling["output_tokens"]
            and all(amount <= workflow.quote_ceiling[dimension] for dimension, amount in ceiling.items()))

    def _admin_model_matches(self, intent: ModelEgressIntentV1,
                             request: ModelCallRequest | None, *, d07_source_material=None) -> bool:
        """Match a graph-bound request to this Authority installation's policy."""
        policy = self._admin_model_policy
        if type(request) is not ModelCallRequest:
            return False
        if request.identity.phase == "artifact_draft_v1":
            from ..model_broker.artifact_draft_v1 import TEMPLATE_DIGEST_V2
            if request.prompt_template_digest == TEMPLATE_DIGEST_V2:
                return self._artifact_draft_admin_matches_v2(intent, request)
            return self._artifact_draft_admin_matches_v1(intent, request)
        authority = request.envelope.authority
        if type(policy) in (AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9):
            if request.identity.phase == "d13.precompress":
                from ..model_broker.d13_precompression import (
                    TEMPLATE_DIGEST as D13_TEMPLATE_DIGEST,
                )
                workflow = policy.reply
                ceiling = dict(intent.budget_ceiling)
                return (
                    request.digest == intent.request_digest
                    and request.call_id == intent.call_id
                    and request.identity.operation_id == intent.operation_id
                    and authority.actor == intent.subject
                    and authority.issuer_domain == "d13"
                    and authority.activation_generation
                        == intent.authority_activation_generation
                    and authority.worker_fence == intent.worker_fence
                    and authority.purpose == "context"
                    and bool(authority.audience)
                    and set(authority.audience) <= set(workflow.audiences)
                    and request.privacy_tier == workflow.privacy_tier
                    and request.required_capabilities
                        == frozenset(workflow.required_capabilities)
                    and request.prompt_template_digest == D13_TEMPLATE_DIGEST
                    and (request.provider_id, request.model_id,
                         intent.provider_id, intent.model_id) == (
                            workflow.provider_id, workflow.model_id,
                            workflow.provider_id, workflow.model_id)
                    and intent.provider_config_digest
                        == workflow.provider_config_digest
                    and request.max_output_tokens == intent.max_output_tokens
                    and request.max_output_tokens <= workflow.max_output_tokens
                    and request.max_output_tokens <= ceiling.get("output_tokens", 0)
                    and request.timeout_seconds == workflow.timeout_seconds
                )
            if authority.purpose=="consolidation" and request.identity.phase=="d07.cognition":
                from ..model_broker.general_growth_cognition_v1 import TEMPLATE_VERSION as GENERAL_VERSION,TEMPLATE_DIGEST as GENERAL_DIGEST
                if type(policy) not in (AdminModelWorkflowsV8, AdminModelWorkflowsV9) or request.prompt_template_digest!=GENERAL_DIGEST:
                    return False
                verifier=self._graph_verifier
                if verifier is None:return False
                workflow=verifier.read_current_named_d07_model_workflow_v3(intent,request,source_material=d07_source_material)
                if workflow is not policy.general_growth_cognition:return False
                expected=("d07.cognition","consolidation",GENERAL_VERSION,GENERAL_DIGEST)
            elif authority.purpose == "proposal":
                if request.identity.phase == "context_reply":
                    from ..model_broker.context_reply import (
                        CONTEXT_REPLY_TEMPLATE_DIGEST,
                        CONTEXT_REPLY_TEMPLATE_VERSION,
                    )
                    workflow = policy.context_reply
                    expected = ("context_reply", "proposal",
                                CONTEXT_REPLY_TEMPLATE_VERSION,
                                CONTEXT_REPLY_TEMPLATE_DIGEST)
                elif request.identity.phase == "natural_generation":
                    from ..model_broker.natural_reply import (
                        TEMPLATE_DIGEST, TEMPLATE_VERSION,
                    )
                    workflow = policy.natural_generation
                    from ..model_broker.natural_reply_history_v3 import (
                        TEMPLATE_DIGEST as V3_TEMPLATE_DIGEST,
                        TEMPLATE_VERSION as V3_TEMPLATE_VERSION,
                    )
                    if request.prompt_template_digest == V3_TEMPLATE_DIGEST:
                        TEMPLATE_VERSION, TEMPLATE_DIGEST = V3_TEMPLATE_VERSION, V3_TEMPLATE_DIGEST
                    from ..model_broker.natural_reply_history_v4 import TEMPLATE_DIGEST as V4_TEMPLATE_DIGEST, TEMPLATE_VERSION as V4_TEMPLATE_VERSION
                    if request.prompt_template_digest == V4_TEMPLATE_DIGEST:
                        TEMPLATE_VERSION, TEMPLATE_DIGEST = V4_TEMPLATE_VERSION, V4_TEMPLATE_DIGEST
                    from ..model_broker.natural_reply_history_v4 import TEMPLATE_DIGEST_V5, TEMPLATE_VERSION_V5
                    if request.prompt_template_digest == TEMPLATE_DIGEST_V5:
                        TEMPLATE_VERSION, TEMPLATE_DIGEST = TEMPLATE_VERSION_V5, TEMPLATE_DIGEST_V5
                    from ..model_broker.natural_reply_history_v6 import TEMPLATE_DIGEST as V6_TEMPLATE_DIGEST, TEMPLATE_VERSION as V6_TEMPLATE_VERSION
                    if request.prompt_template_digest == V6_TEMPLATE_DIGEST:
                        if type(policy) is not AdminModelWorkflowsV6 or workflow is None or workflow.template_version != V6_TEMPLATE_VERSION:
                            raise AuthorityUnavailable("V6 natural wire requires its actual named installed V6 workflow")
                        TEMPLATE_VERSION, TEMPLATE_DIGEST = V6_TEMPLATE_VERSION, V6_TEMPLATE_DIGEST
                    from ..model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST as V7_TEMPLATE_DIGEST,TEMPLATE_VERSION as V7_TEMPLATE_VERSION
                    if request.prompt_template_digest==V7_TEMPLATE_DIGEST:
                        if type(policy) not in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} or workflow is None or workflow.template_version!=V7_TEMPLATE_VERSION:
                            raise AuthorityUnavailable('V7 natural wire requires its actual named installed V7 workflow')
                        TEMPLATE_VERSION,TEMPLATE_DIGEST=V7_TEMPLATE_VERSION,V7_TEMPLATE_DIGEST
                    expected = ("natural_generation", "proposal",
                                TEMPLATE_VERSION, TEMPLATE_DIGEST)
                elif request.identity.phase == "natural_review":
                    from ..model_broker.natural_review import (
                        REVIEW_TEMPLATE_DIGEST, REVIEW_TEMPLATE_VERSION,
                        REVIEW_TEMPLATE_DIGEST_V2, REVIEW_TEMPLATE_VERSION_V2,
                    )
                    workflow = policy.natural_review
                    if request.prompt_template_digest == REVIEW_TEMPLATE_DIGEST_V2:
                        REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_DIGEST = REVIEW_TEMPLATE_VERSION_V2, REVIEW_TEMPLATE_DIGEST_V2
                    expected = ("natural_review", "proposal",
                                REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_DIGEST)
                elif request.identity.phase in {"contact_generation", "contact_review"}:
                    from ..model_broker.contact_expression_v1 import (GENERATION_TEMPLATE_VERSION,
                        GENERATION_TEMPLATE_DIGEST, REVIEW_TEMPLATE_VERSION as CONTACT_REVIEW_VERSION,
                        REVIEW_TEMPLATE_DIGEST as CONTACT_REVIEW_DIGEST)
                    if type(policy) in (AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9):
                        from ..model_broker.contact_expression_v2 import (
                            GENERATION_TEMPLATE_VERSION, GENERATION_TEMPLATE_DIGEST,
                            REVIEW_TEMPLATE_VERSION as CONTACT_REVIEW_VERSION,
                            REVIEW_TEMPLATE_DIGEST as CONTACT_REVIEW_DIGEST,
                        )
                    if request.identity.phase == "contact_generation":
                        workflow = policy.contact_generation
                        expected = ("contact_generation", "proposal", GENERATION_TEMPLATE_VERSION, GENERATION_TEMPLATE_DIGEST)
                    else:
                        workflow = policy.contact_review
                        expected = ("contact_review", "proposal", CONTACT_REVIEW_VERSION, CONTACT_REVIEW_DIGEST)
                elif request.identity.phase == "d04.appraisal":
                    from ..model_broker.d04_appraisal import TEMPLATE_VERSION as APPRAISAL_TEMPLATE, TEMPLATE_DIGEST as APPRAISAL_DIGEST
                    workflow = policy.appraisal
                    expected = ("d04.appraisal", "proposal", APPRAISAL_TEMPLATE, APPRAISAL_DIGEST)
                elif request.identity.phase == "d07.cognition":
                    from ..model_broker.d07_cognition_v1 import D07_COGNITION_TEMPLATE_DIGESTS_V1
                    workflow = policy.d07_cognition
                    from ..model_broker.d07_cognition_v1 import TEMPLATE_DIGEST
                    if type(policy) in {AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} and request.prompt_template_digest == TEMPLATE_DIGEST:
                        verifier = self._graph_verifier
                        if verifier is None:
                            return False
                        workflow = verifier.read_current_named_d07_model_workflow_v3(intent, request,source_material=d07_source_material)
                        installed_named = (policy.d07_cognition,policy.d07_relationship_cognition,)
                        if type(policy)in {AdminModelWorkflowsV6,AdminModelWorkflowsV7,AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
                            installed_named += (policy.growth_cognition,)
                        if workflow is None or not any(workflow is named for named in installed_named):
                            return False
                    if workflow is None or workflow.template_version not in D07_COGNITION_TEMPLATE_DIGESTS_V1:
                        return False
                    expected = ("d07.cognition", "proposal", workflow.template_version,
                        D07_COGNITION_TEMPLATE_DIGESTS_V1[workflow.template_version])
                elif request.identity.phase == "post_c02_reply_model":
                    workflow = policy.reply
                    expected = ("reply", "proposal", REPLY_TEMPLATE_VERSION,
                                REPLY_TEMPLATE_DIGEST)
                else:
                    return False
            else:
                if request.identity.phase == "internal_life_content_v2":
                    from ..model_broker.internal_life_content_v1 import WORK_KIND, TEMPLATE_VERSION, TEMPLATE_DIGEST
                    if type(policy) not in (AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9):
                        return False
                    workflow = policy.life_content
                    expected = (WORK_KIND, "consolidation", TEMPLATE_VERSION, TEMPLATE_DIGEST)
                elif request.identity.phase == "internal_life_numeric_v1":
                    from ..model_broker.internal_life_numeric_v1 import WORK_KIND, TEMPLATE_VERSION, TEMPLATE_DIGEST
                    if type(policy) not in (AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9):
                        return False
                    workflow = policy.life_numeric
                    expected = (WORK_KIND, "consolidation", TEMPLATE_VERSION, TEMPLATE_DIGEST)
                elif request.identity.phase == "internal_life_content":
                    return False  # No Life command/result verifier is installed yet.
                else:
                    # Keep the existing encoding scope and checks unchanged.
                    from ..model_broker.first_ingress_encoding import encoding_template_digest_v1
                    workflow = policy.encode
                    expected = ("d06.encode_source", "consolidation", workflow.template_version,
                                encoding_template_digest_v1(workflow.template_version))
            if (workflow is None
                    or (workflow.work_kind, workflow.purpose,
                    workflow.template_version,
                    request.prompt_template_digest) != expected):
                return False
            ceiling = dict(intent.budget_ceiling)
            return (
                request.digest == intent.request_digest
                and request.call_id == intent.call_id
                and request.identity.operation_id == intent.operation_id
                and authority.actor == intent.subject
                and authority.issuer_domain == "d11"
                and authority.activation_generation
                    == intent.authority_activation_generation
                and authority.worker_fence == intent.worker_fence
                and authority.purpose == workflow.purpose
                and bool(authority.audience)
                and set(authority.audience) <= set(workflow.audiences)
                and request.privacy_tier == workflow.privacy_tier
                and request.required_capabilities
                    == frozenset(workflow.required_capabilities)
                and (request.provider_id, request.model_id,
                     intent.provider_id, intent.model_id) == (
                        workflow.provider_id, workflow.model_id,
                        workflow.provider_id, workflow.model_id)
                and intent.provider_config_digest
                    == workflow.provider_config_digest
                and request.prompt_template_digest
                    == expected[3]
                and request.max_output_tokens == intent.max_output_tokens
                and request.max_output_tokens <= workflow.max_output_tokens
                and request.max_output_tokens
                    <= ceiling.get("output_tokens", 0)
                and request.timeout_seconds == workflow.timeout_seconds
                and all(amount <= workflow.quote_ceiling.get(dimension, 0)
                        for dimension, amount in intent.budget_ceiling)
            )
        if type(policy) is not AdminIngressModelPolicy:
            return False
        return (
            bool(policy.allowed_purposes and policy.allowed_audiences
                 and policy.allowed_privacy_tiers)
            and request.digest == intent.request_digest
            and request.call_id == intent.call_id
            and request.identity.operation_id == intent.operation_id
            and authority.actor == intent.subject
            and authority.issuer_domain == "d11"
            and authority.activation_generation == intent.authority_activation_generation
            and authority.worker_fence == intent.worker_fence
            and authority.purpose in policy.allowed_purposes
            and bool(authority.audience)
            and set(authority.audience) <= set(policy.allowed_audiences)
            and request.privacy_tier == policy.privacy_tier
            and request.privacy_tier in policy.allowed_privacy_tiers
            and request.required_capabilities == frozenset(policy.required_capabilities)
            and (request.provider_id, request.model_id,
                 intent.provider_id, intent.model_id) == (
                    policy.provider_id, policy.model_id,
                    policy.provider_id, policy.model_id)
            and intent.provider_config_digest == policy.provider_config_digest
            and request.max_output_tokens == intent.max_output_tokens
            and request.max_output_tokens <= policy.max_output_tokens
            and request.max_output_tokens <= dict(intent.budget_ceiling).get("output_tokens", 0)
            and request.timeout_seconds == policy.timeout_seconds
        )

    def model_capacity_reconcile_v1(self, *, credential, subject: str, holder: str,
            expected_anchor: RestoreAnchor, installation_id: str,
            draft: ModelEgressDraftV1 | None = None, close_prepared: bool = False):
        """Fresh content-free facts and optional unsent closure; never issue a permit."""
        from .model_capacity_v1 import (model_capacity_census_locked_v1,
            retained_model_capacity_match_locked_v1)
        from .v2_contract import FenceNeverBegunReceiptV2,canonical_bytes,decode_bytes
        if self._fences is None or type(expected_anchor) is not RestoreAnchor:
            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
        identifier(subject,"subject")
        identifier(holder,"holder")
        identifier(installation_id,"installation_id")
        if (type(close_prepared) is not bool
                or draft is not None and type(draft) is not ModelEgressDraftV1
                or close_prepared and draft is None
                or expected_anchor.namespace != self._fences.namespace):
            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
        if draft is not None and (draft.namespace,draft.subject,draft.authority_id) != (
                self._fences.namespace,subject,expected_anchor.authority_id):
            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
        self._fences.core._require(credential,"model_egress",self._fences.namespace,holder)
        with self._fences._frozen() as (db,deletion_head,execution_head,_):
            anchor = self._fences._current_locked(db,deletion_head,execution_head,holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor:
                raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
            status = "census"
            exclude = None
            draft_digest = None if draft is None else canonical_digest(asdict(draft))
            if draft is not None:
                retained = retained_model_capacity_match_locked_v1(db,draft,installation_id)
                original = self._store.capacity_original_locked_v1(db,draft)
                if retained:
                    status = "retained"
                elif original is None:
                    status = "absent"
                    row = db.execute("SELECT request_id,request_digest,"
                        "CASE WHEN length(receipt)<=16384 THEN receipt END "
                        "FROM authority_v2_never_begun WHERE operation_id=?",
                        (draft.operation_id,)).fetchone()
                    request_id = "model-capacity-close:" + draft_digest
                    rejection_digest = "sha256:" + draft_digest
                    if row is not None:
                        try:
                            saved = decode_bytes(row[2])
                        except (TypeError,ValueError,UnicodeError) as exc:
                            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED") from exc
                        if (type(saved) is not FenceNeverBegunReceiptV2
                                or row != (request_id,rejection_digest,canonical_bytes(saved))
                                or (saved.authority_id,saved.namespace,saved.subject,
                                    saved.installation_id,saved.holder,saved.operation_id,
                                    saved.request_id,saved.request_digest) !=
                                    (anchor.authority_id,self._fences.namespace,subject,
                                    installation_id,holder,draft.operation_id,request_id,rejection_digest)):
                            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
                        status = "never_begun"
                    elif close_prepared:
                        self._fences.fences.reject_unbegun_content_fence_locked(db,
                            subject=subject,installation_id=installation_id,holder=holder,
                            generation=anchor.activation_generation,operation_id=draft.operation_id,
                            current_anchor=anchor,request_id=request_id,request_digest=rejection_digest)
                        status = "never_begun"
                    elif self._fences.fences._row(db,draft.operation_id) is not None:
                        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
                else:
                    intent,state = original
                    row = self._fences.fences._row(db,intent.operation_id)
                    if row is None:
                        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
                    permit = self._fences.fences._permit(row)
                    if (permit.operation != "model_egress" or (permit.authority_id,permit.namespace,
                            permit.subject,permit.holder) !=
                            (anchor.authority_id,self._fences.namespace,subject,holder)
                            or (intent.fence_token,intent.fence_epoch,intent.fence_revision,
                                intent.anchor_digest) != (permit.token,permit.fence_epoch,
                                permit.revision,canonical_digest(asdict(permit.pinned_anchor)))
                            or not self._store.is_fence_bound_locked(db,intent)
                            or row[10] is not None):
                        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
                    installed = db.execute("SELECT installation_id FROM authority_model_original_identity_v2 "
                        "WHERE call_id=?",(intent.call_id,)).fetchone()
                    admission = db.execute("SELECT json_extract(admission_json,'$.installation_id') "
                        "FROM authority_model_admissions_v2 WHERE call_id=?",(intent.call_id,)).fetchone()
                    if (installed is not None and installed != (installation_id,)
                            or admission is not None and admission != (installation_id,)):
                        raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
                    status = "unresolved"
                    if state == "prepared" and admission is None:
                        if close_prepared:
                            self._fences.fences.finish_current_prepared_model_not_dispatched_locked(
                                db,permit,intent=intent,current_anchor=anchor,subject=subject,holder=holder)
                            row = self._fences.fences._row(db,intent.operation_id)
                        expected_finish = self._fences.fences.model_terminal_finish_digest(
                            intent,permit,"not_dispatched")
                        if row[6] == "finished" and (row[8],row[9]) == (intent.call_id,expected_finish):
                            status = "not_dispatched"
                        elif row[6] == "active":
                            status = "prepared"
                            exclude = (intent.namespace,intent.call_id,intent.operation_id,intent.request_digest)
                    elif state == "observed":
                        # SQL census release requires the exact paired terminal and finished fence.
                        selected = model_capacity_census_locked_v1(db,self._fences.namespace,
                            selected=(intent.namespace,intent.call_id,intent.operation_id,intent.request_digest))
                        if selected.pop("selected_released"):
                            status = "terminal"
            fact = model_capacity_census_locked_v1(db,self._fences.namespace)
            if exclude is not None:
                available = model_capacity_census_locked_v1(db,self._fences.namespace,exclude=exclude)
                fact["capacity_available"] = available["capacity_available"]
            selected_admission_count = None
            selected_observation_count = None
            if draft is not None:
                selected_admission_count = 0
                selected_observation_count = 0
                identity = (draft.authority_id, draft.namespace, draft.subject,
                    draft.operation_id, draft.call_id, draft.request_digest)
                for table, column, admission_row in (
                        ("authority_model_admissions_v2", "admission_json", True),
                        ("authority_model_egress_observations_v1", "observation_json", False)):
                    fields = ("authority_id", "namespace", "subject", "operation_id",
                        "call_id", "request_digest")
                    projection = ",".join("json_extract(" + column + ",'$." + field + "')"
                        for field in fields)
                    if admission_row:
                        projection += ",json_extract(admission_json,'$.installation_id')"
                    row = db.execute("SELECT " + projection + " FROM " + table +
                        " WHERE call_id=?", (draft.call_id,)).fetchone()
                    if row is not None:
                        expected = identity + ((installation_id,) if admission_row else ())
                        if original is None or row != expected:
                            raise AuthorityUnavailable("MODEL_CAPACITY_UNRESOLVED")
                        if admission_row:
                            selected_admission_count = 1
                        else:
                            selected_observation_count = 1
            return {"status":status,**fact,
                "selected_admission_count":selected_admission_count,
                "selected_observation_count":selected_observation_count,
                "call_id":None if draft is None else draft.call_id,
                "request_digest":None if draft is None else draft.request_digest,
                "authority_id":anchor.authority_id,"namespace":self._fences.namespace,
                "subject":subject,"installation_id":installation_id,
                "current_anchor_digest":canonical_digest(asdict(anchor)),"draft_digest":draft_digest}

    def prepare_fenced(self, *, credential, subject: str, holder: str,
                       draft: ModelEgressDraftV1,
                       expected_anchor: RestoreAnchor,
                       installation_id: str | None = None):
        """Create a typed record and a fresh model fence in one SQLite commit.

        This is a recovery identity only. It does not attest the complete graph
        request and cannot be used to start a provider dispatch.
        """
        if self._fences is None:
            raise AuthorityUnavailable("protected model fence service unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (type(draft) is not ModelEgressDraftV1
                or type(expected_anchor) is not RestoreAnchor
                or (draft.namespace, draft.subject, draft.authority_id,
                    draft.authority_activation_generation,
                    draft.authority_revocation_epoch,
                    draft.authority_deletion_seq,
                    draft.authority_execution_seq) !=
                   (self._fences.namespace, subject, expected_anchor.authority_id,
                    expected_anchor.activation_generation,
                    expected_anchor.revocation_epoch,
                    expected_anchor.deletion_seq, expected_anchor.execution_seq)
                or expected_anchor.namespace != self._fences.namespace):
            raise AuthorityUnavailable("model intent differs from authenticated Authority anchor")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        from .model_reply_scope_observation_v3 import retain_authority_model_reply_scope_observation_v3
        from ..runtime_storage_v3 import runtime_storage_v3
        scope_observation_required = (self._source_location is not None
                                      or runtime_storage_v3(self._fences.core._db) is not None)
        scope_observation = (
            retain_authority_model_reply_scope_observation_v3(
                self._graph_verifier, model_service=self, credential=credential,
                subject=subject, holder=holder, intent=draft,
                expected_anchor=expected_anchor)
            if scope_observation_required else nullcontext())
        with scope_observation:
            reply_scope = ((self._graph_verifier.observe_current_reply_scope_for_model_v1(
                               draft, model_service=self, credential=credential, subject=subject,
                               holder=holder, expected_anchor=expected_anchor)
                           if scope_observation_required else
                           self._graph_verifier.observe_current_reply_scope_for_model_v1(draft))
                           if self._graph_verifier is not None else None)
            from .artifact_goal_barrier_v1 import observe_current_artifact_goal_target_v1
            goal_target = (observe_current_artifact_goal_target_v1(self._graph_verifier,
                model_service=self, credential=credential, subject=subject, holder=holder,
                intent=draft, expected_anchor=expected_anchor)
                if scope_observation_required else None)
            if reply_scope is not None and installation_id != reply_scope.service.installation_id:
                raise AuthorityUnavailable("model preparation crossed its installed reply scope")
            with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
                anchor = self._fences._current_locked(
                    db, deletion_head, execution_head, holder=holder,
                    generation=expected_anchor.activation_generation)
                if anchor != expected_anchor:
                    raise AuthorityUnavailable("model egress anchor changed")
                self._require_reply_scope_in_tx_v1(db, reply_scope, anchor, action="model_prepare")
                from .artifact_goal_barrier_v1 import require_model_artifact_goal_not_cancelled_in_tx_v1
                require_model_artifact_goal_not_cancelled_in_tx_v1(db, model_service=self,
                    target=goal_target, action="model_prepare")
                old = self._store._read(db, draft.call_id)
                job_row = db.execute(
                    "SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? "
                    "AND json_extract(identity_json,'$.job_id')=?",
                    (draft.namespace, draft.job_id),
                ).fetchone()
                if job_row is not None and job_row[0] != draft.call_id:
                    raise AuthorityUnavailable("model job already has a call identity")
                fence_row = self._fences.fences._row(db, draft.operation_id)
                if old is not None and fence_row is None:
                    raise AuthorityUnavailable("passive model record has no atomic fence")
                if old is not None and not self._store.is_fence_bound_locked(db, old.intent):
                    raise AuthorityUnavailable("passive model record has no atomic binding")
                if old is None and fence_row is not None:
                    raise AuthorityUnavailable("model fence operation already exists without typed record")
                if old is not None and ModelEgressDraftV1.from_intent(old.intent) != draft:
                    raise AuthorityUnavailable("model egress identity changed")
                from .model_capacity_v1 import require_model_capacity_locked_v1
                require_model_capacity_locked_v1(db,self._fences.namespace,
                    exclude=None if old is None else (old.intent.namespace,old.intent.call_id,
                        old.intent.operation_id,old.intent.request_digest))
                permit = self._fences.fences.begin_fence_locked(
                    db, subject=subject, holder=holder, operation="model_egress",
                    current_anchor=anchor, operation_id=draft.operation_id)
                intent = ModelEgressIntentV1(
                    **asdict(draft), fence_token=permit.token,
                    fence_epoch=permit.fence_epoch, fence_revision=permit.revision,
                    anchor_digest=canonical_digest(asdict(permit.pinned_anchor)))
                if old is not None and old.intent != intent:
                    raise AuthorityUnavailable("persisted model fence differs from typed record")
                record = self._store.prepare_locked(db, intent)
                if old is None:
                    self._store.bind_fence_locked(db, intent)
                if intent.binding_digest is not None:
                    if installation_id is None:
                        raise AuthorityUnavailable("original model installation is absent")
                    self._store.bind_original_identity_locked(
                        db, intent, installation_id)
                return record, permit

    def lookup_original_intent_v1(
        self, *, credential, subject: str, holder: str, authority_id: str,
        installation_id: str,
        namespace: str, job_id: str, acquire_operation_id: str,
        original_model_operation_id: str, call_id: str,
        request_digest: str, binding_digest: str,
        historical_accounting: bool = False,
    ):
        """Read the Authority's V2 original key; never issue a send or content."""
        if self._fences is None or namespace != self._fences.namespace:
            raise AuthorityUnavailable("original model namespace unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        for name, value in (("authority_id", authority_id), ("namespace", namespace),
                            ("installation_id", installation_id),
                            ("job_id", job_id),
                            ("acquire_operation_id", acquire_operation_id),
                            ("original_model_operation_id", original_model_operation_id),
                            ("call_id", call_id)):
            identifier(value, name)
        if (type(request_digest) is not str or len(request_digest) != 64
                or any(c not in "0123456789abcdef" for c in request_digest)
                or type(binding_digest) is not str or len(binding_digest) != 64
                or any(c not in "0123456789abcdef" for c in binding_digest)
                or acquire_operation_id != original_model_operation_id):
            raise AuthorityUnavailable("invalid original model lookup key")
        self._fences.core._require(credential, "current", namespace)
        with self._fences._frozen() as (db, deletion_head, execution_head,
                                       deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder)
            if anchor.authority_id != authority_id:
                raise AuthorityUnavailable("original model Authority changed")
            # _current_locked(require_clear=True) already qualifies RELEASED
            # current storage when deletion history exists. Historical lookup
            # remains an explicit separate mode below; normal lookup keeps
            # activation/revocation and consumed-identity exclusions intact.
            record = self._store.lookup_original_locked(
                db, authority_id=authority_id, namespace=namespace,
                installation_id=installation_id,
                job_id=job_id, acquire_operation_id=acquire_operation_id,
                operation_id=original_model_operation_id, call_id=call_id,
                request_digest=request_digest, binding_digest=binding_digest)
            if record is None:
                return None
            intent = record.intent
            if (intent.subject != subject or (not historical_accounting and (
                    intent.authority_activation_generation != anchor.activation_generation
                    or intent.authority_revocation_epoch != anchor.revocation_epoch))):
                raise AuthorityUnavailable("original model activation or subject changed")
            if not self._store.is_fence_bound_locked(db, intent):
                raise AuthorityUnavailable("original model fence binding absent")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None:
                raise AuthorityUnavailable("original model fence absent")
            permit = self._fences.fences._permit(row)
            if (permit.operation != "model_egress" or permit.subject != subject
                    or permit.namespace != namespace
                    or row[6] not in {"active", "finished"}
                    or (intent.fence_token, intent.fence_epoch,
                        intent.fence_revision, intent.anchor_digest) !=
                       (permit.token, permit.fence_epoch, permit.revision,
                        canonical_digest(asdict(permit.pinned_anchor)))):
                raise AuthorityUnavailable("original model fence identity changed")
            if row[6] == "finished":
                status = {"prepared": "not_dispatched", "observed": "completed",
                          "unknown": "unknown"}.get(record.state)
                if (status is None or row[10] is not None or
                        (row[8], row[9]) != (
                            intent.call_id,
                            self._fences.fences.model_terminal_finish_digest(
                                intent, permit, status, record.observation_digest))):
                    raise AuthorityUnavailable("original model terminal state changed")
            admission = terminal = None
            if db.execute("SELECT 1 FROM authority_model_admissions_v2 WHERE call_id=?",
                          (call_id,)).fetchone():
                admission, _, terminal = self._store.read_admission_locked(db, intent)
            return record, permit, admission, terminal

    def terminal_recovery_identity_v1(
        self, *, credential, subject: str, holder: str,
        authority_id: str, namespace: str, namespace_id: NamespaceId,
        installation_id: str, job_id: str, original_operation_id: str,
        acquire_operation_id: str, original_model_operation_id: str,
        call_id: str, request_digest: str, binding_digest: str,
    ) -> OriginalC02ResultKeyV1:
        """Authority-only terminal preflight; this does not release content.

        The graph and read-attempt qualifications are deliberately separate.
        No caller may use this key alone as a completed content handoff.
        """
        if type(namespace_id) is not NamespaceId:
            raise AuthorityUnavailable("typed C02 namespace required")
        identifier(original_operation_id, "original_operation_id")
        found = self.lookup_original_intent_v1(
            credential=credential, subject=subject, holder=holder,
            authority_id=authority_id, namespace=namespace,
            installation_id=installation_id, job_id=job_id,
            acquire_operation_id=acquire_operation_id,
            original_model_operation_id=original_model_operation_id,
            call_id=call_id, request_digest=request_digest,
            binding_digest=binding_digest)
        if found is None:
            raise AuthorityUnavailable("original terminal C02 result absent")
        record, _permit, admission, terminal = found
        intent = record.intent
        if (record.state != "observed" or record.content_erased
                or record.observation_digest is None
                or admission is None or terminal is None
                or intent.budget_reservation_operation_id != original_operation_id
                or (terminal.call_id, terminal.request_digest,
                    terminal.observation_digest, terminal.installation_id,
                    terminal.admission_id) !=
                   (intent.call_id, intent.request_digest,
                    record.observation_digest, installation_id,
                    admission.admission_id)):
            raise AuthorityUnavailable("original C02 terminal evidence unavailable")
        return OriginalC02ResultKeyV1(
            authority_id, namespace, namespace_id, installation_id,
            job_id, original_operation_id, acquire_operation_id,
            original_model_operation_id, call_id, binding_digest,
            request_digest, canonical_digest(asdict(intent)),
            record.observation_digest, canonical_digest(asdict(terminal)))

    def recover_fenced(self, *, credential, subject: str,
                       intent: ModelEgressIntentV1):
        """Read the typed identity and fence; prepared plus finished means unsent.

        The recovery DTO alone is passive. Production dispatch remains HOLD.
        """
        if self._fences is None or type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "current", self._fences.namespace)
        with self._fences.core._tx() as db:
            self._fences._require_mode(db)
            record = self._store.read_locked(db, intent)
            if not self._store.is_fence_bound_locked(db, intent):
                raise AuthorityUnavailable("model fence was not atomically bound")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None:
                raise AuthorityUnavailable("typed model fence absent")
            permit = self._fences.fences._permit(row)
            if (permit.operation != "model_egress" or permit.subject != subject
                    or permit.namespace != intent.namespace or row[6] not in {"active", "finished"}
                    or (intent.fence_token, intent.fence_epoch,
                        intent.fence_revision, intent.anchor_digest) !=
                       (permit.token, permit.fence_epoch, permit.revision,
                        canonical_digest(asdict(permit.pinned_anchor)))):
                raise AuthorityUnavailable("typed model fence identity changed")
            if row[6] == "finished":
                status = {"prepared": "not_dispatched", "observed": "completed",
                          "unknown": "unknown"}.get(record.state)
                if (status is None or row[10] is not None or
                        (row[8], row[9]) != (
                            intent.call_id,
                            self._fences.fences.model_terminal_finish_digest(
                                intent, permit, status, record.observation_digest))):
                    raise AuthorityUnavailable("finished model fence lacks original terminal state")
            return record, permit

    def read_observation_fenced(self, *, credential, subject: str,
                                intent: ModelEgressIntentV1) -> ModelEgressObservationV1:
        """HOLD: a terminal receipt is recovery evidence, never read authority.

        The missing versioned read request must bind this call and admission to
        an authenticated consumer Owner principal, actor, live signed session,
        fixed read purpose/audience, and a fresh Authority-issued read permit.
        Existing OwnerSessionStore.require_current_in_tx and
        OwnerTicketStore.get_current_guard can recheck the Authority half, but
        the GraphCoordinator Owner lease is a private process capability, not
        a transferable proof. A pinned result-read verifier must check current
        source/access/delete/activation and Owner graph grant in one read-only
        graph snapshot while the read fence is active. The admission verifier
        cannot serve this role: it requires a still-running job, pending outbox,
        and reserved budget. After graph verification outside Authority locks,
        `_frozen` must recheck the same permit, Owner session/guard, original
        v2 admission and terminal receipt before copying completed content;
        close the read fence before return. This signature has none of those
        consumer inputs. A caller boolean or finished model fence is not proof.
        """
        raise AuthorityUnavailable(
            "HOLD: current Owner-qualified model result read proof is unavailable"
        )

    def _record_provider_observation(self, *, intent: ModelEgressIntentV1,
                                     response):
        """Unbound responses cannot become Authority facts in a separate commit."""
        raise AuthorityUnavailable(
            "HOLD: unbound provider response cannot be an Authority observation"
        )

    def _finish_observed_fenced(self, *, credential, subject: str, holder: str,
                                intent: ModelEgressIntentV1,
                                expected_anchor: RestoreAnchor):
        """Close a previously durable observation, including crash recovery."""
        if self._fences is None or type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor:
                raise AuthorityUnavailable("model finish anchor changed")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None:
                raise AuthorityUnavailable("typed model fence absent")
            permit = self._fences.fences._permit(row)
            self._fences.fences.finish_observed_model_egress_locked(
                db, permit, intent=intent, current_anchor=anchor)
            return self._store.read_locked(db, intent), permit

    def _finish_prepared_not_dispatched_fenced(
            self, *, credential, subject: str, holder: str,
            intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor):
        """Close a prepared unsent call and release its exclusive model fence."""
        if self._fences is None or type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor:
                raise AuthorityUnavailable("model finish anchor changed")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None:
                raise AuthorityUnavailable("typed model fence absent")
            permit = self._fences.fences._permit(row)
            record = self._store._finish_not_dispatched_fenced_locked(
                db, intent, permit, self._fences.fences, anchor)
            return record, permit

    def _admit_dispatch(self, *, credential, subject: str, holder: str,
                            intent: ModelEgressIntentV1,
                            expected_anchor: RestoreAnchor,
                            request: ModelCallRequest | None = None,
                            admission: ModelAdmissionV2 | None = None):
        """Grant one internal dispatch admission after graph and policy checks.

        A model fence is held across the independent graph read. Any failure
        closes an untouched prepared call as not_dispatched. The admission
        marker is not a provider result or a host executor-result binding.
        """
        if (self._fences is None or type(intent) is not ModelEgressIntentV1
                or type(expected_anchor) is not RestoreAnchor):
            raise AuthorityUnavailable("protected typed model egress unavailable")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model egress subject or namespace mismatch")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, holder)
        with self._fences._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor:
                raise AuthorityUnavailable("model dispatch anchor changed")
            record = self._store.read_locked(db, intent)
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None or row[6] != "active":
                raise AuthorityUnavailable("model dispatch fence is no longer active")
            permit = self._fences.fences._permit(row)
            self._fences.fences.validate_fence_locked(
                db, permit, subject=subject, current_anchor=anchor)
            if not self._store.is_fence_bound_locked(db, intent):
                raise AuthorityUnavailable("model dispatch lacks original fence binding")
            if record.state != "prepared":
                raise AuthorityUnavailable("model dispatch admission cannot repeat")
        from .model_reply_scope_observation_v3 import retain_authority_model_reply_scope_observation_v3
        from ..runtime_storage_v3 import runtime_storage_v3
        scope_observation_required = (self._source_location is not None
                                      or runtime_storage_v3(self._fences.core._db) is not None)
        with ExitStack() as scope_observation:
            # No journal or Authority lock is held during this independent read.
            location_observation = None
            reply_scope = None
            goal_target = None
            d07_source_material = None
            try:
                if scope_observation_required:
                    scope_observation.enter_context(
                        retain_authority_model_reply_scope_observation_v3(
                            self._graph_verifier, model_service=self, credential=credential,
                            subject=subject, holder=holder, intent=intent,
                            expected_anchor=expected_anchor, permit=permit))
                if self._graph_verifier is not None:
                    reply_scope = (
                        self._graph_verifier.observe_current_reply_scope_for_model_v1(
                            intent, model_service=self, credential=credential, subject=subject,
                            holder=holder, expected_anchor=expected_anchor, permit=permit)
                        if scope_observation_required else
                        self._graph_verifier.observe_current_reply_scope_for_model_v1(intent))
                    if (reply_scope is not None and admission is not None
                            and admission.installation_id != reply_scope.service.installation_id):
                        raise AuthorityUnavailable("model admission crossed its installed reply scope")
                if scope_observation_required:
                    from .artifact_goal_barrier_v1 import observe_current_artifact_goal_target_v1
                    goal_target = observe_current_artifact_goal_target_v1(self._graph_verifier,
                        model_service=self, credential=credential, subject=subject, holder=holder,
                        intent=intent, expected_anchor=expected_anchor, permit=permit)
                if self._source_location is not None:
                    location_observation = self._source_location.observe_business_for_fence_v1(
                        credential=credential, subject=subject, permit=permit)
                elif deletion_history:
                    raise AuthorityUnavailable("installed post-erasure model location unavailable")
                if type(request) is ModelCallRequest and request.identity.phase == "d07.cognition":
                    from .owner_location_read_v3 import current_d07_model_policy_source_v3
                    d07_source_material=scope_observation.enter_context(current_d07_model_policy_source_v3(
                        self,credential=credential,subject=subject,intent=intent,permit=permit,
                        location_observation=location_observation))
                graph_current = self._graph_verifier is not None
                if graph_current:
                    if location_observation is None:
                        graph_current = self._graph_verifier.complete_graph_current(
                            intent, model_service=self, credential=credential, subject=subject, permit=permit,
                            d07_source_material=d07_source_material) is True
                    else:
                        graph_current = self._graph_verifier.complete_graph_current(
                            intent, source_location=self._source_location,
                            location_observation=location_observation, model_service=self,
                            credential=credential, subject=subject, permit=permit,
                            d07_source_material=d07_source_material) is True
            except Exception:
                graph_current = False
            try:
                policy_current = self._admin_model_matches(intent, request,d07_source_material=d07_source_material)
            except Exception:
                policy_current = False
            if not graph_current or not policy_current:
                self._finish_prepared_not_dispatched_fenced(
                    credential=credential, subject=subject, holder=holder,
                    intent=intent, expected_anchor=expected_anchor)
                if not graph_current:
                    raise AuthorityUnavailable("HOLD: complete current model graph is unavailable")
                raise AuthorityUnavailable("HOLD: independent administrator model policy is unavailable")
            try:
                if d07_source_material is not None:
                    d07_source_material.require_for_observer_v3(d07_source_material.work)
                with self._fences._frozen() as (db, deletion_head, execution_head,
                                               deletion_history):
                    anchor = self._fences._current_locked(
                        db, deletion_head, execution_head, holder=holder,
                        generation=expected_anchor.activation_generation)
                    if anchor != expected_anchor:
                        raise AuthorityUnavailable("model dispatch anchor changed")
                    row = self._fences.fences._row(db, intent.operation_id)
                    if row is None or self._fences.fences._permit(row) != permit:
                        raise AuthorityUnavailable("original model dispatch permit changed")
                    if location_observation is not None:
                        self._source_location.require_current_in_tx_v1(db, location_observation)
                    self._require_reply_scope_in_tx_v1(db, reply_scope, anchor, action="model_admit")
                    from .artifact_goal_barrier_v1 import require_model_artifact_goal_not_cancelled_in_tx_v1
                    require_model_artifact_goal_not_cancelled_in_tx_v1(db, model_service=self,
                        target=goal_target, action="model_admit")
                    from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
                    require_lifecycle_admission_in_tx_v1(db, intent.namespace, action="first_model_dispatch")
                    from .model_capacity_v1 import require_model_capacity_locked_v1
                    require_model_capacity_locked_v1(db,self._fences.namespace,
                        exclude=(intent.namespace,intent.call_id,intent.operation_id,intent.request_digest))
                    record = self._store._record_dispatch_started_fenced_locked(
                        db, intent, permit, self._fences.fences, anchor)
                    if admission is not None:
                        self._store.record_admission_locked(db, intent, admission)
                        from ..model_broker.natural_reply_history_v7 import TEMPLATE_DIGEST as V7_TEMPLATE_DIGEST
                        if request is not None and request.prompt_template_digest==V7_TEMPLATE_DIGEST:
                            if self._d13_provider_http_counter_v1 is None:
                                raise AuthorityUnavailable('V7 actual provider HTTP admission counter is missing')
                            from .d13_provider_http_admission_v1 import stage_expected_provider_http_v1
                            stage_expected_provider_http_v1(db,counter=self._d13_provider_http_counter_v1,
                                intent=intent,request=request,admission=admission,now_utc=self._graph_verifier._clock())
                    if request is not None and request.identity.phase == "d07.cognition":
                        from .d07_model_timing_v1 import record_d07_model_start_locked_v1
                        record_d07_model_start_locked_v1(db, intent, admission)
                    return record, permit
            except AuthorityUnavailable:
                # A competing successful CAS must never be reclassified as unsent.
                try:
                    self._finish_prepared_not_dispatched_fenced(
                        credential=credential, subject=subject, holder=holder,
                        intent=intent, expected_anchor=expected_anchor)
                except AuthorityUnavailable:
                    pass
                raise

    def admit_dispatch_once(self, *, credential, subject: str, holder: str,
                            intent: ModelEgressIntentV1,
                            expected_anchor: RestoreAnchor,
                            request: ModelCallRequest | None = None):
        """Legacy admission; no v2 observer binding, so terminal report stays HOLD."""
        return self._admit_dispatch(
            credential=credential, subject=subject, holder=holder,
            intent=intent, expected_anchor=expected_anchor, request=request)

    def admit_dispatch_once_v2(self, *, credential, subject: str, holder: str,
                               intent: ModelEgressIntentV1,
                               expected_anchor: RestoreAnchor,
                               request: ModelCallRequest,
                               installation_id: str, observer_peer_sha256: str,
                               observer_profile_id: str, manifest_digest: str,
                               host_incarnation: str):
        """Atomically grant one dispatch and bind its designated host observer."""
        if type(intent) is not ModelEgressIntentV1:
            raise AuthorityUnavailable("typed original model intent required")
        admission = ModelAdmissionV2(
            secrets.token_hex(32), intent.authority_id, intent.namespace,
            intent.subject, intent.operation_id, intent.call_id,
            intent.request_digest, intent.provider_config_digest,
            installation_id, observer_peer_sha256, observer_profile_id,
            manifest_digest, host_incarnation)
        record, permit = self._admit_dispatch(
            credential=credential, subject=subject, holder=holder,
            intent=intent, expected_anchor=expected_anchor, request=request,
            admission=admission)
        return record, permit, admission

    def complete_observed_v2(self, *, credential, subject: str, holder: str,
                             intent: ModelEgressIntentV1,
                             expected_anchor: RestoreAnchor,
                             admission: ModelAdmissionV2,
                             report: HostObservedModelCompletionV2,
                             installation_id: str, observer_peer_sha256: str,
                             observer_profile_id: str, manifest_digest: str):
        """Commit the designated mTLS host's complete report, finish, and receipt once.

        The host adapter is in the trust boundary. This does not independently
        attest its provider HTTP exchange; incomplete evidence leaves the fence.
        """
        if (self._fences is None or type(intent) is not ModelEgressIntentV1
                or type(expected_anchor) is not RestoreAnchor
                or type(admission) is not ModelAdmissionV2
                or type(report) is not HostObservedModelCompletionV2):
            raise AuthorityUnavailable("typed v2 model completion required")
        identifier(subject, "subject")
        identifier(holder, "holder")
        if (subject, intent.namespace) != (intent.subject, self._fences.namespace):
            raise AuthorityUnavailable("model completion subject or namespace mismatch")
        if (admission.installation_id, admission.observer_peer_sha256,
                admission.observer_profile_id, admission.manifest_digest) != (
                installation_id, observer_peer_sha256, observer_profile_id,
                manifest_digest):
            raise AuthorityUnavailable("designated model observer differs")
        if (report.admission_id, report.host_incarnation, report.call_id,
                report.request_digest, report.provider_config_digest) != (
                admission.admission_id, admission.host_incarnation,
                intent.call_id, intent.request_digest,
                admission.provider_config_digest):
            raise AuthorityUnavailable("model report differs from admission")
        observation = report.observation_for(intent)
        self._fences.core._require(
            credential, "model_egress", self._fences.namespace, holder)

        def checked_replay(db):
            saved, report_digest, receipt = self._store.read_admission_locked(db, intent)
            if saved != admission:
                raise AuthorityUnavailable("original model admission differs")
            if type(self._admin_model_policy) in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} and intent.job_id.startswith('natural-generation-job:'):
                if self._d13_provider_http_counter_v1 is None:
                    raise AuthorityUnavailable('V7 completion requires actual installed HTTP original verifier')
                from .d13_provider_http_admission_v1 import require_recorded_provider_http_binding_v1
                require_recorded_provider_http_binding_v1(db,counter=self._d13_provider_http_counter_v1,
                    intent=intent,admission=admission)
            if receipt is None:
                return None
            record = self._store.read_locked(db, intent)
            row = self._fences.fences._row(db, intent.operation_id)
            if (report_digest != report.digest or record.state != "observed"
                    or record.observation_digest != observation.digest
                    or receipt.observation_digest != observation.digest
                    or row is None or row[6] != "finished"
                    or (row[8], row[9]) != (intent.call_id, receipt.finish_digest)):
                raise AuthorityUnavailable("model terminal replay conflicts")
            return record, self._fences.fences._permit(row), receipt

        with self._fences.core._tx() as db:
            replay = checked_replay(db)
            if replay is not None:
                return replay
        with self._fences._frozen() as (db, deletion_head, execution_head,
                                       deletion_history):
            replay = checked_replay(db)
            if replay is not None:
                return replay
            anchor = self._fences._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor:
                raise AuthorityUnavailable("model completion anchor changed")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None or row[6] != "active":
                raise AuthorityUnavailable("original model fence is not active")
            permit = self._fences.fences._permit(row)
            self._fences.fences.validate_fence_locked(
                db, permit, subject=subject, current_anchor=anchor)
            record = self._store._finish_terminal_observation_fenced_locked(
                db, intent, observation, permit, self._fences.fences, anchor)
            receipt = ModelTerminalReceiptV2(
                admission.admission_id, intent.call_id, intent.request_digest,
                report.digest, observation.digest,
                self._fences.fences.model_terminal_finish_digest(
                    intent, permit, "completed", observation.digest),
                admission.installation_id, admission.host_incarnation)
            self._store.record_terminal_receipt_locked(db, admission, receipt)
            from .d07_model_timing_v1 import record_d07_model_end_locked_v1
            record_d07_model_end_locked_v1(db, intent, receipt)
            return record, permit, receipt

    async def begin_handoff(self, request, request_digest):
        raise AuthorityUnavailable(
            "HOLD: independent current graph verifier and fenced executor are not integrated"
        )

    async def finish_handoff(self, start, outcome_digest):
        raise AuthorityUnavailable(
            "HOLD: independent provider observation and fenced finish are not integrated"
        )


    def close_prepared_no_dispatch_witness_v1(self, *, credential, subject, request):
        """Core closure observes no Source content and asserts no D08 cancellation."""
        from dataclasses import asdict
        from hashlib import sha256
        from .v2_model_egress_contract import (
            ModelNoDispatchClosureRequestV1, ModelNoDispatchWitnessV1, MODEL_NO_DISPATCH_SIGN_KIND_V1)
        from .v2_model_egress_store import (
            read_model_no_dispatch_witness_locked_v1, record_model_no_dispatch_witness_locked_v1)
        from .v2_model_egress_wire import from_wire, to_wire
        from .v2_contract import to_wire as permit_to_wire
        from ..runtime_contracts import canonical_serialize
        if (self._fences is None or type(request) is not ModelNoDispatchClosureRequestV1
                or (subject, request.intent.namespace) != (request.intent.subject, self._fences.namespace)
                or self._graph_verifier is None):
            raise AuthorityUnavailable("exact installed original model closure required")
        self._fences.core._require(credential, "model_egress", self._fences.namespace, request.holder)
        signer = self._graph_verifier._issuer._signer
        with self._fences._frozen() as (db, deletion_head, execution_head, _history):
            anchor = self._fences._current_locked(db, deletion_head, execution_head,
                holder=request.holder, generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor:
                raise AuthorityUnavailable("original model closure current anchor changed")
            intent = request.intent
            original = self._store.lookup_original_locked(db, authority_id=intent.authority_id,
                namespace=intent.namespace, installation_id=request.installation_id, job_id=intent.job_id,
                acquire_operation_id=intent.acquire_operation_id, operation_id=intent.operation_id,
                call_id=intent.call_id, request_digest=intent.request_digest, binding_digest=intent.binding_digest)
            if original is None or original.intent != intent or original.state != "prepared" or original.observation_digest is not None:
                raise AuthorityUnavailable("admitted, dispatched or unknown original cannot become no-dispatch")
            row = self._fences.fences._row(db, intent.operation_id)
            if row is None or row[10] is not None or not self._store.is_fence_bound_locked(db, intent):
                raise AuthorityUnavailable("original model closure lacks its exact nonpending fence")
            permit = self._fences.fences._permit(row)
            if (permit.holder != request.holder or db.execute("SELECT 1 FROM authority_model_admissions_v2 WHERE call_id=?",
                    (intent.call_id,)).fetchone() is not None
                    or db.execute("SELECT 1 FROM authority_model_egress_observation_status_v1 WHERE call_id=?",
                        (intent.call_id,)).fetchone() is not None
                    or db.execute("SELECT 1 FROM authority_model_egress_observations_v1 WHERE call_id=?",
                        (intent.call_id,)).fetchone() is not None):
                raise AuthorityUnavailable("actual original admission/observation exists; no zero witness")
            saved = read_model_no_dispatch_witness_locked_v1(self._store, db, request=request, signer=signer)
            expected_finish = self._fences.fences.model_terminal_finish_digest(intent, permit, "not_dispatched")
            if saved is not None:
                if (row[6], row[8], row[9], row[10]) != ("finished", intent.call_id, expected_finish, None):
                    raise AuthorityUnavailable("saved no-dispatch witness lost its actual Core finish")
                if saved.original_permit != permit:
                    raise AuthorityUnavailable("saved no-dispatch witness original permit changed")
                return saved
            before_row = self._store._read_ledger(db, intent.call_id)
            self._fences.fences.finish_current_prepared_model_not_dispatched_locked(db, permit,
                intent=intent, current_anchor=anchor, subject=subject, holder=request.holder)
            after_row = self._fences.fences._row(db, intent.operation_id)
            if (after_row[6], after_row[8], after_row[9], after_row[10]) != ("finished", intent.call_id, expected_finish, None):
                raise AuthorityUnavailable("actual no-dispatch Core CAS did not finish")
            epoch = db.execute("SELECT last_epoch FROM authority_v2_epochs WHERE namespace=?", (intent.namespace,)).fetchone()
            if epoch is None: raise AuthorityUnavailable("actual original model namespace epoch absent")
            unsigned = dict(request=to_wire(request), original_permit=permit_to_wire(permit),
                namespace_epoch=epoch[0], prepared_row_commitment=canonical_digest(before_row),
                finished_row_commitment=canonical_digest((after_row[:7], sha256(bytes(after_row[7])).hexdigest(), after_row[8:11])),
                absence_scope_commitment=canonical_digest(("core.model-no-dispatch-absence.v1",
                    intent.authority_id, intent.namespace, request.installation_id, intent.call_id,
                    canonical_digest(asdict(intent)), "prepared", "no_admission", "no_observation", "no_pending",
                    permit.token, permit.revision, epoch[0])),
                before_anchor=asdict(anchor), after_anchor=asdict(anchor), finish_request_id=intent.call_id,
                finish_digest=expected_finish, witness_operation_id="model-no-dispatch:" + request.identity_digest,
                schema="sylanne3.authority.model-no-dispatch-witness.v1")
            signature = signer.sign(MODEL_NO_DISPATCH_SIGN_KIND_V1, canonical_serialize(unsigned))
            witness = from_wire({**unsigned, "signature": signature}, ModelNoDispatchWitnessV1)
            return record_model_no_dispatch_witness_locked_v1(self._store, db, witness=witness)



__all__ = ["AuthorityV2ModelEgressService"]
