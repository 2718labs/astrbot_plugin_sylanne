"""Private eight-type method census and original EOF retained by its actual Work."""
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from weakref import WeakKeyDictionary, WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d01.method_learning_v1 import VALUE_TYPES
from ..graph_types import AtomKey, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_storage_v3 import (RuntimeStorageOperationV3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, runtime_storage_v3)
from ..graph_worker import GraphStorageWorkV3, GraphStorageStepV3
from .dispatch_current_inventory_v3 import (_CurrentNamespaceInventoryKernelV3,
    _FrozenDispatchAtomV3, _freeze_value_v3, _detach_value_v3, _heap)

METHOD_LEARNING_FAMILY_V3 = "method_learning_v3"
METHOD_LEARNING_WORK_KIND_V3 = "current_method_learning_read_v3"
METHOD_LEARNING_TYPES_V3 = frozenset(VALUE_TYPES) | {"d07.current_interpretation.v1"}
_HISTORY_COLUMNS = ("event_id", "value", "valid")
_DOMAIN_COLUMNS = ("domain", "operation_kind", "request_digest", "original_digest",
    "original_payload_json", "read_versions_json", "bundle_digest", "receipt_json", "receipt_digest")
_BUNDLE_COLUMNS = ("digest", "activity_id", "effect_id", "commit_seq")
_NUMERIC_OWNER_OPERATIONS_V1=frozenset({
    "prepare_internal_life_numeric_context","prepare_internal_life_numeric",
    "acquire_internal_life_numeric","adopt_internal_life_numeric",
    "prepare_internal_life_numeric_drive","prepare_internal_life_numeric_joint",
    "prepare_internal_life_interval_baseline","adopt_internal_life_numeric_trace"})
_NUMERIC_NATIVE_READ_OPERATIONS_V3=frozenset({"read_current_life_numeric_joint_prepared_v3","read_current_life_numeric_trace_v3"})
_NUMERIC_READ_ONLY_OPERATIONS_V3=frozenset({
    "read_current_life_numeric_identity_v3","read_current_life_numeric_model_draft_v3",
    "qualify_current_life_numeric_candidate_v3","read_current_life_numeric_joint_prepared_v3","read_current_life_numeric_trace_v3"})
_NUMERIC_METADATA_OPERATIONS_V3=_NUMERIC_OWNER_OPERATIONS_V1 | _NUMERIC_READ_ONLY_OPERATIONS_V3
_OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3=frozenset({"cancel_current_owner_job_v3"})
_NUMERIC_PAID_WRITE_OPERATIONS_V3=frozenset({"prepare_current_life_numeric_result_read_v3","record_current_life_numeric_paid_result_v3"})
METHOD_INPUT_OPERATIONS_V3 = _NUMERIC_OWNER_OPERATIONS_V1 | frozenset({
    "input:freeze_artifact_candidate_preparation_v1", "input:freeze_values",
    "freeze_general_growth_intent_v1","register_general_growth_trial_start_v1",
    "derive_general_growth_trial_v1","adopt_general_growth_v1",
    'prepare_personal_candidate_eligibility_v1', 'adopt_personal_candidate_eligibility_v1',
    "register_method_evaluation_protocol_v1", "register_scoped_method_trial_v1", "register_method_experiment_v1",
    "register_method_trial_proposal_v2", "register_scoped_method_trial_v2", "register_method_experiment_v2",
    "register_method_blind_review_request_v2", "evaluate_current_method_outcome_v1",
    "review_current_method_growth_v1", "adopt_current_method_strategy_v1", "evaluate_values",
    "create_artifact_task_plan_v1", "create_personal_plan", "revise_personal_plan", "select_personal_step",
    "settle_personal_goal", "compose_artifact_goal_plan", "propose_artifact_draft_action",
    "prepare_personal_candidates_v1", "select_personal_step_v2", "prepare_selected_source_note_action_v2",
    "propose_artifact_draft_phase_action_v2", "revise_artifact_task_plan_v2",
    "activate_artifact_task_project_checkpoint_v2", "prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2",
    "register_artifact_phase_postcondition_contract_v1", "quote_current_method_choices_v1",
    "observe_method_comparison_v1", "adopt_current_c1_method_conditions_v1",
})
from .borrowed_habit_classification_v3 import BORROWED_HABIT_METADATA_OPERATIONS_V3
METHOD_INPUT_OPERATIONS_V3 = METHOD_INPUT_OPERATIONS_V3 | BORROWED_HABIT_METADATA_OPERATIONS_V3
_METHOD_LEARNING_OPERATIONS_V3 = frozenset({
    "register_method_evaluation_protocol_v1", "register_scoped_method_trial_v1", "register_method_experiment_v1",
    "register_method_trial_proposal_v2", "register_scoped_method_trial_v2", "register_method_experiment_v2",
    "register_method_blind_review_request_v2", "evaluate_current_method_outcome_v1",
    "review_current_method_growth_v1", "adopt_current_method_strategy_v1",
})
_PERSONAL_PLAN_OPERATIONS_V3 = frozenset({"create_artifact_task_plan_v1", "create_personal_plan",
    "revise_personal_plan", "select_personal_step", "settle_personal_goal",
    "compose_artifact_goal_plan", "propose_artifact_draft_action"})
_CANDIDATE_CONSUMERS_V3 = METHOD_INPUT_OPERATIONS_V3 - _METHOD_LEARNING_OPERATIONS_V3 - _PERSONAL_PLAN_OPERATIONS_V3 - {
    "evaluate_values", "quote_current_method_choices_v1", "observe_method_comparison_v1", "adopt_current_c1_method_conditions_v1"}


def _method_preplan_families_v3(kind):
    """Only the actual registered recipe's fixed families may precede its plan."""
    if kind in (_NUMERIC_READ_ONLY_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3):return frozenset()
    from .current_beta1_source_read_v3 import beta1_source_operation_v3
    if beta1_source_operation_v3(kind):return frozenset()
    from .borrowed_habit_classification_v3 import BORROWED_HABIT_METADATA_OPERATIONS_V3
    if kind in BORROWED_HABIT_METADATA_OPERATIONS_V3:
        from .d11_life_product_adapter_v1 import LIFE_CURRENT_TYPES
        return frozenset(LIFE_CURRENT_TYPES)
    if kind not in METHOD_INPUT_OPERATIONS_V3: raise AuthorityUnavailable("unregistered method input operation")
    if kind in _GENERAL_OWNER_OPERATIONS_V1 or kind in _NUMERIC_OWNER_OPERATIONS_V1:return frozenset()
    families = set(METHOD_LEARNING_TYPES_V3)
    if kind in _METHOD_LEARNING_OPERATIONS_V3:
        families.update(("d01.persona_activation.v1", "d01.persona_plan.v1", "d03.account_binding", "d03.entity_anchor"))
    elif kind == "evaluate_values":
        families.update(("d01.persona_activation.v1", "d01.persona_plan.v1", "d01.persona_revision.v1", "d01.growth_contribution.v1"))
    elif kind in _PERSONAL_PLAN_OPERATIONS_V3:
        from .d08_personal_plan_v1 import OBLIGATION_TYPES
        families.update(OBLIGATION_TYPES)
    elif kind in _CANDIDATE_CONSUMERS_V3:
        families.update(("d01.persona_activation.v1", "d01.persona_plan.v1"))
    elif kind == "quote_current_method_choices_v1":
        from .d06_ingress_recall_v1 import LEDGER_TYPES
        families.update(LEDGER_TYPES)
    return frozenset(families)

_ISSUER = object()
_READERS = WeakSet()
_ISSUED = WeakKeyDictionary()
_BOUND = ContextVar("sylanne_current_method_learning_read_v3", default=None)


class _MethodLearningReadV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self, issuer, graph, operation, fence, *, runtime, authority, lease, operation_kind,
            request, operation_id, activity_id, audience_ref, parent_budget_lease_ref, request_digest,
            owner_binding, owner_guard, session_proof, initial_now_utc, source_pending_owner=None):
        if issuer is not _ISSUER or type(operation) is not RuntimeStorageOperationV3:
            raise AuthorityUnavailable("actual method Work retention issuer required")
        if operation.closed or runtime_storage_v3(graph._GraphCoordinator__store._db) is not operation.handle:
            raise AuthorityUnavailable("method census crossed its actual selected storage")
        self.runtime, self.authority, self.lease = runtime, authority, lease
        self.operation_kind, self.request = operation_kind, request
        self.operation_id, self.activity_id, self.audience_ref = operation_id, activity_id, audience_ref
        self.parent_budget_lease_ref, self.request_digest = parent_budget_lease_ref, request_digest
        self.owner_binding, self.owner_guard, self.session_proof = owner_binding, owner_guard, session_proof
        self.source_pending_owner=source_pending_owner
        if source_pending_owner is not None:
            from .current_beta1_source_read_v3 import require_pending_beta1_owner_factory_v3
            require_pending_beta1_owner_factory_v3(source_pending_owner,graph,operation,fence,authority,operation_kind,request)
            if owner_binding is not None or owner_guard is not None or session_proof is not None:
                raise AuthorityUnavailable('pending Source Owner factory cannot carry a placeholder/current Owner proof')
            self.material_owner_guard=None
        else:
            from .domain_production_contracts_v1 import ProductionOwnerGuardV1
            self.material_owner_guard = ProductionOwnerGuardV1(owner_grant_key(*authority.namespace.as_tuple).token,
                owner_binding.grant_revision, owner_binding.grant_digest.removeprefix("sha256:"),
                owner_binding.authorization_head.removeprefix("sha256:"))
        self.initial_now_utc, self.deadline_utc = initial_now_utc, operation.deadline_utc
        if (runtime.graph is not graph or authority.namespace != fence.scope.namespace
                or owner_binding is not None and owner_binding.namespace != authority.namespace or operation.operation_id != operation_id):
            raise AuthorityUnavailable("method command crossed its actual runtime/Owner/business operation")
        self.work, self.owner_head = None, None
        self.inventory_sealed = self.inputs_sealed = False
        self.read_finished = self.business_started = self.business_completed = False
        self.inventory = self.selected_plan = self.selected_envelope = self.frame_fields = None
        self.prepared_encoding_inputs_v3=None
        self.prepared_numeric_drive_inputs_v3=None
        self.points, self.inventories, self.input_heads = {}, {}, {}
        self.census_columns, self.census_versions = {}, {}
        self.atom_column = self.pending_input = None
        self.action_schema_locator = None
        self.observed_originals, self.installed_policy_refs = (), ()
        self.installed_readers = None
        self.budget_task, self.policy_tasks = None, {}
        self.preplan_families = frozenset()if source_pending_owner is not None else _method_preplan_families_v3(operation_kind)
        self.preference_type = None
        self.preference_origin = self.preference_inventory = None
        self.preferences_from_census = False
        from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1, SourceNoteCandidateBindingV1
        if (operation_kind == "prepare_personal_candidates_v1" and type(request) is PrepareCurrentPersonalCandidatesRequestV1
                and any(type(binding) is SourceNoteCandidateBindingV1 for binding in request.bindings)):
            from ..domains.d05.relationship_revision_v2 import ESTIMATE_TYPE
            self.preference_type = ESTIMATE_TYPE
            self.preferences_from_census = True
            self.preference_origin = ("actual_prepare_request", operation_id, request_digest, request.bindings)
        from .current_beta1_source_read_v3 import beta1_source_operation_v3
        own_source=source_pending_owner is not None or beta1_source_operation_v3(operation_kind)
        self.numeric_source_permission=None
        self.general_metadata_issuing_task=None
        self.general_metadata_reserved=0;self.general_source_reserved=0
        self.general_owner_entry=self.general_source_permission=None
        self.attachments, self.pending_attachments = {}, []
        self.wires = {}
        self.attachment = None
        self.prefinal = self
        super().__init__(graph, operation, fence, projection_types=(frozenset() if own_source or operation_kind in (_GENERAL_OWNER_OPERATIONS_V1 | _NUMERIC_METADATA_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3) else METHOD_LEARNING_TYPES_V3 | (frozenset({self.preference_type}) if self.preference_type else frozenset())),
            selected_tokens=frozenset(), census_schema="sylanne.method-learning-census.v3",
            leaf_schema="sylanne.method-learning-census-leaf.v3")
        if type(self)is _MethodLearningReadV3 and operation_kind in (_GENERAL_OWNER_OPERATIONS_V1 | _NUMERIC_METADATA_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3):
            self.census_schema="numeric-owner-header-census.v1" if operation_kind in _NUMERIC_METADATA_OPERATIONS_V3 else "general-owner-header-census.v1"
            self.leaf_schema="numeric-owner-header-census-leaf.v1" if operation_kind in _NUMERIC_METADATA_OPERATIONS_V3 else "general-owner-header-census-leaf.v1"
            self.root=canonical_digest((self.census_schema,self.namespace,self.query,self.selection_digest))
        if own_source:
            self.census_schema="world-owner-header-census.v3"
            self.leaf_schema="world-owner-header-census-leaf.v3"
            self.root=canonical_digest((self.census_schema,self.namespace,self.query,self.selection_digest))
        _READERS.add(self)

    def require_current(self, *, meter=None):
        if self not in _READERS or self.operation.closed or self.work is None:
            raise AuthorityUnavailable("actual originating method Work reader required")
        if self.operation_kind in _NUMERIC_READ_ONLY_OPERATIONS_V3:
            from .current_life_numeric_read_v3 import require_numeric_read_work_v3
            require_numeric_read_work_v3(self)
        if self.operation_kind in _NUMERIC_PAID_WRITE_OPERATIONS_V3:
            from .current_life_numeric_paid_write_v3 import require_numeric_paid_write_work_v3
            require_numeric_paid_write_work_v3(self)
        from .current_beta1_source_read_v3 import beta1_source_operation_v3,beta1_source_work_kind_v3,beta1_source_reader_work_kind_v3,require_current_beta1_source_work_v3
        own_source=self.work.kind=='current_habit_source_read_v3' or(type(self)is not BorrowedMethodLearningReadV3 and beta1_source_operation_v3(self.operation_kind))
        if own_source:require_current_beta1_source_work_v3(self)
        if self.source_pending_owner is not None and self.owner_binding is None:
            from .current_beta1_source_read_v3 import require_pending_beta1_owner_reader_current_v3
            return require_pending_beta1_owner_reader_current_v3(self,meter=meter)
        store = self.store
        if (not store._lock._is_owned() or self.work.state is not self
                or self.work.operation is not self.operation or self.work.coordinator is not self.graph
                or self.work.kind != (beta1_source_reader_work_kind_v3(self)if own_source else "current_life_numeric_paid_write_v3" if self.operation_kind in _NUMERIC_PAID_WRITE_OPERATIONS_V3 else "current_owner_job_cancel_v3" if self.operation_kind in _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 else "current_life_numeric_read_v3" if self.operation_kind in _NUMERIC_READ_ONLY_OPERATIONS_V3 else METHOD_LEARNING_WORK_KIND_V3)
                or self.work.operation_id != self.operation.operation_id
                or self.work.deadline_utc != self.operation.deadline_utc
                or self.work.selection_digest != self.selection_digest
                or runtime_storage_v3(self.db) is not self.operation.handle
                or self.operation.selection_digest != self.selection_digest
                or self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp
                or store._registry.catalogue_hash != self.catalogue_hash):
            raise AuthorityUnavailable("method census selection/stamp/catalogue changed")
        with runtime_storage_quantum_v3(self.db) as current:
            if meter is not None and current is not meter:
                raise AuthorityUnavailable("method attachment changed its actual quantum")
            epochs = self._epochs(current)
            owner = current.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*self.namespace.as_tuple, owner_grant_key(*self.namespace.as_tuple).token))
        if epochs != self.authority_epochs or owner != self.owner_head:
            raise AuthorityUnavailable("method census access/deletion/Owner head changed")
        return self

    def _next(self, meter):
        if self.work.kind=='current_conditioned_self_source_read_v3':
            from .current_conditioned_self_read_v3 import require_conditioned_owner_ready_v3
            require_conditioned_owner_ready_v3(self)
        from .current_beta1_source_read_v3 import beta1_source_operation_v3
        if type(self)is _MethodLearningReadV3 and (self.work.kind=='current_habit_source_read_v3' or beta1_source_operation_v3(self.operation_kind)):
            return _advance_general_method_header_census_v1(self,meter)
        if type(self)is _MethodLearningReadV3 and self.operation_kind in (_GENERAL_OWNER_OPERATIONS_V1 | _NUMERIC_METADATA_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3):
            return _advance_general_method_header_census_v1(self,meter)
        super()._next(meter)
        from .artifact_borrowed_source_v3 import record_artifact_borrowed_header_v3
        record_artifact_borrowed_header_v3(self)
        if self.cell is not None and self.body is not None:
            key, revision, valid, _, _ = self.pending
            self.atom_column = MethodJSONColumnV3(_ISSUER, self, table="graph_atoms", column="value",
                key_columns=("token", "bot", "persona"), key=(key.token, *self.namespace.as_tuple), cell=self.cell)
            self.body = None

    def _cell(self, meter):
        if self.atom_column is None:
            return super()._cell(meter)
        column = self.atom_column
        if not column.advance(meter): return
        from ..graph_types import GraphAtom
        from ..runtime_contracts import canonical_digest
        key, revision, valid, type_name, cell_id = self.pending
        self.census_columns[key.token] = column
        self.census_versions[key.token] = (revision, bool(valid))
        atom = GraphAtom(key, revision, column.json_v3(), bool(valid), _canonical_original=column)
        self.atoms.append(atom); self.wires[key.token] = column.wire
        self.heads[key.token] = (revision, valid, cell_id)
        self.root = canonical_digest((self.leaf_schema, self.root, key.token,
            revision, valid, type_name, column.sha256, cell_id, tuple(column.cell.header)))
        self.count += 1
        self.cell = self.parser = self.pending = self.body = self.atom_column = None
        self.fragment, self.offset = b"", 0
        self._reserve()

    def seal_plan_v3(self, plan, *, envelope, installed_readers=None, observed_originals=(), installed_policy_refs=()):
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        if not self.inventory_sealed or self.inputs_sealed or type(plan) is not ProductionReadPlanV1:
            raise AuthorityUnavailable("actual unfinished inventory-sealed method plan required")
        if self.selected_plan is not None and plan != self.selected_plan:
            raise AuthorityUnavailable("pure method read plan changed during same-Work preparation")
        if envelope.identity.operation_id != self.operation_id or envelope.deadline_utc > self.deadline_utc:
            raise AuthorityUnavailable("method plan envelope changed its business identity/deadline")
        self.selected_plan, self.selected_envelope, self.installed_readers = plan, envelope, installed_readers
        self.observed_originals, self.installed_policy_refs = tuple(observed_originals), tuple(installed_policy_refs)
        self.work.phase = "selected_inputs"

    def _graph_eof_v3(self):
        for type_id in self.projection_types:
            if sum(atom.key.type_name == type_id for atom in self.atoms) > 128:
                raise AuthorityUnavailable("method/preference census exceeds its original fixed-family 128-row bound")
        for atom in self.atoms:
            if atom.key.type_name not in METHOD_LEARNING_TYPES_V3: continue
            self._queue(("graph_history", _HISTORY_COLUMNS, ("token", "revision"),
                (atom.key.token, atom.revision)))
        self.work.phase = "method_originals"

    def _queue(self, request):
        from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
        table, columns, key_columns, key = request
        if (table, columns, key_columns) not in _HOST_ATTACHMENT_SHAPES_V3:
            raise AuthorityUnavailable("unregistered fixed method original attachment")
        if len(key) != len(key_columns):
            raise ValueError("method original full key differs")
        if table in {"graph_atoms", "graph_history", "graph_dependencies"}:
            if NamespaceId.from_key(AtomKey.from_token(key[0])) != self.namespace:
                raise AuthorityUnavailable("method history crossed namespace")
        elif tuple(key[:2]) != self.namespace.as_tuple:
            raise AuthorityUnavailable("method original crossed namespace")
        if request not in self.attachments and request not in self.pending_attachments:
            self.operation.retain(1024 + _heap(request))
            self.pending_attachments.append(request)

    def advance(self):
        from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
        with bind_runtime_storage_operation_v3(self.operation, self.db), runtime_storage_quantum_v3(self.db) as meter:
            if self.authority_epochs is None:
                self.authority_epochs = self._epochs(meter)
                self.owner_head = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                    "bot=? AND persona=? AND token=?", (*self.namespace.as_tuple, owner_grant_key(*self.namespace.as_tuple).token))
            elif not self.graph_eof:
                if self.cell is None: self._next(meter)
                else: self._cell(meter)
            elif self.attachment is not None:
                self.attachment.advance(meter)
                if self.attachment.complete:
                    task = self.attachment
                    self.attachments[task.request] = task
                    if task.table == "graph_history" and task.row is not None:
                        event_id = dict(zip(task.columns, task.row))["event_id"]
                        self._queue(("graph_domain_production_originals_v1", _DOMAIN_COLUMNS,
                            ("bot", "persona", "operation_id"), (*self.namespace.as_tuple, event_id)))
                        self._queue(("graph_bundle_operations", _BUNDLE_COLUMNS,
                            ("bot", "persona", "operation_id"), (*self.namespace.as_tuple, event_id)))
                    self.attachment = None
            elif self.pending_attachments:
                request = self.pending_attachments.pop(0)
                self.attachment = _HostProducerAttachmentV3(self, request)
            else:
                self.require_current(meter=meter)
                self._reserve(65536)
                self.inventory_sealed = True
                self.inventory = _method_inventory_result_v3(self)
                if self.preferences_from_census:
                    self.preference_inventory = PreparedMethodRelationshipPreferencesV3(_ISSUER, self,
                        tuple(atom for atom in self.atoms if atom.key.type_name == self.preference_type))
                self.work.phase = "plan_resolution"
        return self


def begin_current_method_learning_read_v3(graph, operation, fence, *, runtime, authority, lease,
        operation_kind, request, operation_id, activity_id, audience_ref, parent_budget_lease_ref,
        request_digest, owner_binding, owner_guard, session_proof, initial_now_utc, source_pending_owner=None):
    """Root supplies its actual existing command, fence and original retention."""
    return _MethodLearningReadV3(_ISSUER, graph, operation, fence, runtime=runtime, authority=authority,
        lease=lease, operation_kind=operation_kind, request=request, operation_id=operation_id,
        activity_id=activity_id, audience_ref=audience_ref, parent_budget_lease_ref=parent_budget_lease_ref,
        request_digest=request_digest, owner_binding=owner_binding, owner_guard=owner_guard,
        session_proof=session_proof, initial_now_utc=initial_now_utc, source_pending_owner=source_pending_owner)


def attach_current_method_learning_work_v3(reader, work):
    from .current_beta1_source_read_v3 import beta1_source_operation_v3,beta1_source_work_kind_v3,beta1_source_reader_work_kind_v3,register_current_beta1_source_work_v3
    own_source=type(reader)is _MethodLearningReadV3 and beta1_source_operation_v3(reader.operation_kind)
    if (type(reader) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3, PreparedPersonalEligibilityRecoveryReadV1) or reader not in _READERS or reader.work is not None
            or type(work) is not GraphStorageWorkV3 or work.kind != (beta1_source_reader_work_kind_v3(reader)if own_source else METHOD_LEARNING_WORK_KIND_V3)
            or work.state is not reader or work.operation is not reader.operation
            or work.coordinator is not reader.graph or work.operation_id != reader.operation.operation_id
            or work.deadline_utc != reader.operation.deadline_utc or work.selection_digest != reader.selection_digest):
        raise AuthorityUnavailable("actual originating method Work must attach once")
    work._require_invocation(reader.graph, initial=True)
    reader.work = work
    work.phase = "method_census"
    if own_source:register_current_beta1_source_work_v3(reader,work)
    return work


def queue_current_method_learning_attachment_v3(reader, *, read_plan, table, columns, key_columns, key):
    """Add only an actual selected Source history from this Work's read recipe."""
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    if (type(reader) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3, PreparedPersonalEligibilityRecoveryReadV1) or reader not in _READERS or reader.complete
            or not reader.graph_eof or type(read_plan) is not ProductionReadPlanV1):
        raise AuthorityUnavailable("unfinished actual method Work/read recipe required")
    reader.work._require_invocation(reader.graph)
    request = (table, tuple(columns), tuple(key_columns), tuple(key))
    if request[:3] != ("graph_history", _HISTORY_COLUMNS, ("token", "revision")) or len(key) != 2:
        raise AuthorityUnavailable("selected method dependency requires its exact Source history shape")
    atom_key = AtomKey.from_token(key[0])
    source = reader.sources.get(key[0])
    if (atom_key.type_name != "memory.source" or atom_key not in read_plan.exact_keys
            or source is None or source.revision != key[1]):
        raise AuthorityUnavailable("Source history is not an actual selected read-plan current head")
    reader._queue(request)


def advance_current_method_learning_read_v3(graph, work):
    reader = work.state
    if type(reader) is PreparedPersonalEligibilityRecoveryReadV1:
        return _advance_personal_eligibility_recovery_v1(graph,work)
    if type(reader) is BorrowedMethodLearningReadV3:
        return _advance_borrowed_method_learning_read_v3(graph, work)
    if (type(reader) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3, PreparedPersonalEligibilityRecoveryReadV1) or reader not in _READERS or reader.work is not work
            or graph is not reader.graph or work.operation is not reader.operation):
        raise AuthorityUnavailable("actual same-operation method Work required")
    with bind_runtime_storage_operation_v3(work.operation, reader.db):
        if not reader.read_finished:
            _prepare_current_general_method_owner_entry_v1(reader)
            graph._validate_read_fence_v3(reader.fence)
        if reader.inputs_sealed:
            if not reader.read_finished:
                graph._finish_read_fence_v3(reader.fence)
                reader.read_finished = True
                work.phase = "business_write"
            elif not reader.business_started:
                reader.business_started = True
                proof = reader.result
                with bind_prepared_method_learning_read_v3(proof, graph, reader.db):
                    result = graph._complete_current_method_operation_v3(reader, proof)
                if type(result) is GraphStorageWorkV3:
                    raise AuthorityUnavailable("prepared method WRITE cannot prepare another Work")
                proof.business_result = result
                _BUSINESS_RESULTS[proof] = (work, result)
                reader.business_completed = True
                work.phase = "business_completed"
            else:
                raise AuthorityUnavailable("method business WRITE must complete exactly once")
        elif not reader.inventory_sealed:
            with reader.store._lock:
                if reader.db.in_transaction: raise AuthorityUnavailable("method continuation retained a transaction")
                if reader.authority_epochs is not None: reader.require_current()
                reader.advance()
        elif reader.pending_input is not None:
            with reader.store._lock, runtime_storage_quantum_v3(reader.db) as meter:
                if reader.db.in_transaction: raise AuthorityUnavailable("method selected point retained a transaction")
                reader.require_current(meter=meter)
                reader.pending_input.advance(meter)
                if reader.pending_input.complete: reader.pending_input = None
        else:
            token = _READING.set(reader)
            try:
                with bind_prepared_method_learning_read_v3(reader.inventory, graph, reader.db):
                    if reader.selected_plan is None:
                        graph._advance_current_method_learning_plan_v3(reader)
                    else:
                        from .domain_production_frame_v1 import _materialize_current_domain_frame_fields_v1
                        from .domain_production_contracts_v1 import ProductionOperationLimitsV1
                        with reader.store._lock:
                            if reader.db.in_transaction: raise AuthorityUnavailable("method selected-input step inherited a transaction")
                            reader.db.execute("BEGIN")
                            try:
                                from .d07_source_preparation_members_v3 import prepare_current_d07_source_read_dependencies_v3
                                prepare_current_d07_source_read_dependencies_v3(reader)
                                reader.frame_fields = _materialize_current_domain_frame_fields_v1(graph, reader.db,
                                    envelope=reader.selected_envelope, scope=reader.fence.scope, plan=reader.selected_plan,
                                    now_utc=reader.initial_now_utc, expected_owner_guard=reader.material_owner_guard,
                                    expected_rights=(reader.owner_binding.access_epoch, reader.owner_binding.delete_epoch),
                                    observed_originals=reader.observed_originals, installed_policy_refs=reader.installed_policy_refs,
                                    limits=ProductionOperationLimitsV1(), prepared_inputs=PreparedMethodDomainInputsV3(
                                        _ISSUER, reader, reader.selected_plan, reader.selected_envelope))
                                if reader.work.kind=='current_conditioned_self_source_read_v3':
                                    from .current_conditioned_self_read_v3 import augment_current_conditioned_output_plan_v3,finalize_current_conditioned_source_inputs_v3
                                    if augment_current_conditioned_output_plan_v3(reader):return GraphStorageStepV3('progress')
                                    finalize_current_conditioned_source_inputs_v3(reader)
                                if reader.operation_kind=="prepare_internal_life_numeric_drive":
                                    from .d06_life_numeric_drive_v1 import capture_prepared_numeric_drive_inputs_v3
                                    capture_prepared_numeric_drive_inputs_v3(reader)
                                if reader.operation_kind=="prepare_internal_life_interval_baseline":
                                    from .c04_encoding_context_original_v3 import capture_prepared_w01_life_encoding_inputs_v3
                                    capture_prepared_w01_life_encoding_inputs_v3(reader)
                            finally: reader.db.rollback()
                        reader.inputs_sealed = reader.complete = True
                        work.phase = "inputs_sealed"
                        reader.result = PreparedMethodDomainInputsV3(_ISSUER, reader, reader.selected_plan, reader.selected_envelope)
            except MethodInputNeededV3 as needed:
                kind, actual = needed.request
                if kind == "point":
                    _require_input_request(reader, actual)
                    task = reader.points.get(actual)
                    if task is None: task = _MethodPointReadV3(reader, actual); reader.points[actual] = task
                elif kind == "inventory":
                    allowed = set(reader.preplan_families)
                    if reader.selected_plan is not None: allowed.update(reader.selected_plan.fixed_type_ids)
                    if reader.preference_origin is not None: allowed.add(reader.preference_type)
                    if actual not in allowed:
                        raise AuthorityUnavailable("method inventory has no actual fixed recipe or adopted selected dependency")
                    task = reader.inventories.get(actual)
                    if task is None: task = _MethodInventoryReadV3(reader, actual); reader.inventories[actual] = task
                elif kind=='frozen_joint_d12':
                    from .frozen_joint_command_source_v3 import create_frozen_joint_d12_task_v3
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        task=create_frozen_joint_d12_task_v3(reader,actual)
                elif kind=='frozen_joint_metadata':
                    from .frozen_joint_command_source_v3 import create_frozen_joint_metadata_task_v3
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        task=create_frozen_joint_metadata_task_v3(reader,actual)
                elif kind=='conditioned_owner_metadata':
                    from .current_conditioned_self_read_v3 import create_current_conditioned_metadata_task_v3
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        task=create_current_conditioned_metadata_task_v3(reader,actual)
                elif kind=="world_metadata":
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        if reader.operation_kind=="run_simulation":
                            from .current_d07_simulation_source_read_v3 import create_current_d07_simulation_metadata_task_v3
                            task=create_current_d07_simulation_metadata_task_v3(reader,actual)
                        else:
                            from .world_owner_read_v3 import create_world_metadata_task_v3
                            task=create_world_metadata_task_v3(reader,actual)
                elif kind=="beta1_source_metadata":
                    from .current_beta1_source_read_v3 import create_current_beta1_source_metadata_task_v3
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        task=create_current_beta1_source_metadata_task_v3(reader,actual)
                elif kind == "general_method_source_metadata":
                    with reader.store._lock:
                        require_actual_source_owner_metadata_work_v1(reader)
                        tasks=_GENERAL_METHOD_SOURCE_TASKS_V1.setdefault(reader,{})
                        task=tasks.get(actual)
                        if task is None:
                            task=_GeneralMethodSourceMetadataEOFV1(_GENERAL_METHOD_SOURCE_ISSUER_V1,reader,actual)
                            tasks[actual]=task
                elif kind=="drive_dose_grant":
                    from .d06_life_numeric_drive_v1 import DriveDoseGrantTaskV3
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        identity=(kind,actual);task=reader.attachments.get(identity)
                        if task is None:task=DriveDoseGrantTaskV3(reader,actual);reader.attachments[identity]=task
                elif kind=="math_nonseries_metadata":
                    from .c04_encoding_context_original_v3 import MathNonSeriesMetadataTaskV3
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        identity=(kind,actual);task=reader.attachments.get(identity)
                        if task is None:task=MathNonSeriesMetadataTaskV3(reader,actual);reader.attachments[identity]=task
                elif kind=="numeric_c04_selection":
                    from .current_life_numeric_metadata_v1 import NumericC04SelectorTaskV1
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        identity=("numeric_c04_selection",actual)
                        task=reader.attachments.get(identity)
                        if task is None:
                            task=NumericC04SelectorTaskV1(reader,actual)
                            reader.attachments[identity]=task
                elif kind=="numeric_owner_metadata":
                    from .current_life_numeric_metadata_v1 import NumericMetadataTaskV1
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        identity=("numeric_owner_metadata",actual)
                        task=reader.attachments.get(identity)
                        if task is None:
                            task=NumericMetadataTaskV1(reader,actual)
                            reader.attachments[identity]=task
                elif kind=="general_owner_metadata":
                    from .d01_general_growth_v1 import create_current_general_owner_metadata_task_v1
                    with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                        require_actual_general_owner_metadata_work_v1(reader,operation_kind=reader.operation_kind,namespace=reader.namespace)
                        identity=("general_owner_metadata",actual)
                        task=reader.attachments.get(identity)
                        if task is None:
                            task=create_current_general_owner_metadata_task_v1(reader,actual)
                            reader.attachments[identity]=task
                elif kind == "joint_original_keys":
                    table, namespace, original_kind = actual
                    if table != "graph_d08_joint_node_originals_v1" or namespace != reader.namespace:
                        raise AuthorityUnavailable("Joint original key recipe crossed namespace or family")
                    tasks = _JOINT_KEY_SCANS_V3.setdefault(reader, {})
                    task = tasks.get(actual)
                    if task is None:
                        task = _JointOriginalKeysReadV3(reader, actual); tasks[actual] = task
                elif kind == "budget_grant":
                    if actual != reader.parent_budget_lease_ref: raise AuthorityUnavailable("method budget locator differs from its actual parent")
                    if reader.budget_task is None: reader.budget_task = _MethodBudgetGrantReadV3(reader, actual)
                    task = reader.budget_task
                elif kind == "relationship_policy":
                    if reader.preference_type is None: raise AuthorityUnavailable("relationship policy has no actual SourceNote candidate")
                    task = reader.policy_tasks.get(actual)
                    if task is None: task = _MethodRelationshipPolicyReadV3(reader, actual); reader.policy_tasks[actual] = task
                else: raise AuthorityUnavailable("unregistered method selected-input request")
                reader.pending_input = task
            finally: _READING.reset(token)
        if not reader.read_finished:
            _prepare_current_general_method_owner_entry_v1(reader)
            graph._validate_read_fence_v3(reader.fence)
    return GraphStorageStepV3("complete", reader.result) if reader.business_completed else GraphStorageStepV3("progress")


def finish_current_method_learning_read_v3(graph, work, error):
    reader = work.state
    payload = reader.result
    try:
        if type(reader) is PreparedPersonalEligibilityRecoveryReadV1:
            if reader.owner_read_entry is not None:
                reader.owner_read_entry.release_v3(); reader.owner_read_entry=None
            if reader.read_issuance_lifetime is not None:
                reader.read_issuance_lifetime.close(); reader.read_issuance_lifetime=None
        if type(reader) in (_MethodLearningReadV3,PreparedPersonalEligibilityRecoveryReadV1) and not reader.read_finished:
            graph._finish_read_fence_v3(reader.fence)
            reader.read_finished = True
        if error is None: work.result_lease = work.operation
    except BaseException as finish_error:
        error = finish_error
        finish_runtime_storage_operation_v3(work.operation)
        raise
    finally:
        reader.cell = reader.parser = reader.pending = reader.body = reader.fragment = reader.result = None
        if error is not None:
            # Drop both ends of privately registered owner/column/proof references.
            _release_method_registered_payloads_v3(reader)
            if type(payload) in (PreparedMethodDomainInputsV3, PreparedBorrowedMethodDomainInputsV3):
                payload.release_payload_v3()
            elif reader.inventory is not None:
                reader.inventory.release_payload_v3()
            reader.attachments.clear(); reader.pending_attachments.clear(); reader.wires.clear()
            reader.points.clear(); reader.inventories.clear(); reader.input_heads.clear()
            reader.census_columns.clear(); reader.census_versions.clear(); reader.policy_tasks.clear()
            if reader.preference_inventory is not None: reader.preference_inventory.release_payload_v3()
            if reader.action_schema_locator is not None: _ACTION_LOCATORS.pop(reader.action_schema_locator, None)
            reader.atom_column = reader.attachment = reader.pending_input = reader.budget_task = None
            reader.preference_origin = reader.preference_inventory = reader.action_schema_locator = None
            reader.selected_plan = reader.selected_envelope = reader.frame_fields = reader.inventory = None
            reader.atoms = reader.sources = reader.heads = None
            _READERS.discard(reader)
    if error is not None: finish_runtime_storage_operation_v3(work.operation)


class PreparedCurrentMethodLearningReadV3:
    """An independently issued method EOF proof; carries no write or Source grant."""
    def __init__(self, issuer, reader):
        if (issuer is not _ISSUER or reader not in _READERS or not reader.graph_eof
                or not reader.inventory_sealed or reader.work is None or reader.attachment is not None
                or reader.pending_attachments):
            raise AuthorityUnavailable("actual complete method census/original EOF required")
        self.reader, self.graph, self.db, self.namespace = reader, reader.graph, reader.db, reader.namespace
        self.work, self.ticket, self.operation = reader.work, reader.work.ticket, reader.operation
        self.scope, self.graph_stamp, self.query = reader.fence.scope, reader.graph_stamp, reader.query
        self.selection_digest, self.catalogue_hash = reader.selection_digest, reader.catalogue_hash
        self.authority_epochs, self.owner_head = reader.authority_epochs, reader.owner_head
        self.full_eof, self.leaf_count, self.ordered_root = True, reader.count, reader.root
        self.atoms = tuple(_FrozenDispatchAtomV3(atom.key, atom.revision, _freeze_value_v3(atom.value),
            atom.valid, _heap(atom.value)) for atom in reader.atoms if atom.key.type_name in METHOD_LEARNING_TYPES_V3)
        self.wires, self.attachments = MappingProxyType(dict(reader.wires)), MappingProxyType(dict(reader.attachments))
        _ISSUED[self] = self._identity()

    def _identity(self):
        return (self.reader, self.graph, self.db, self.namespace, self.work, self.ticket, self.operation,
            self.scope, self.graph_stamp, self.query, self.selection_digest, self.catalogue_hash,
            self.authority_epochs, self.owner_head, self.full_eof, self.leaf_count, self.ordered_root,
            self.atoms, self.wires, self.attachments)

    def _actual(self):
        if (_ISSUED.get(self) != self._identity() or self.operation.closed
                or self.reader not in _READERS or self.work.state is not self.reader
                or self.reader.work is not self.work or self.work.operation is not self.operation
                or self.work.coordinator is not self.graph or self.work.ticket != self.ticket
                or not self.full_eof or not self.reader.graph_eof or not self.reader.inventory_sealed):
            raise AuthorityUnavailable("actual private method originating Work/EOF differs")
        return self

    def require_current(self, graph, db, namespace):
        self._actual()
        if (_BOUND.get() != (self, graph, db) or graph is not self.graph or db is not self.db
                or namespace != self.namespace or not db.in_transaction):
            raise AuthorityUnavailable("actual bound transactional method proof required")
        self.reader.require_current()
        return self

    def release_payload_v3(self):
        if _ISSUED.pop(self, None) is None: return
        self.atoms = self.wires = self.attachments = None
        reader = self.reader
        reader.attachments.clear(); reader.pending_attachments.clear(); reader.wires.clear()
        reader.attachment = None
        reader.atoms = reader.sources = reader.heads = None
        _READERS.discard(reader)


@contextmanager
def bind_prepared_method_learning_read_v3(proof, graph, db):
    if type(proof) in (PreparedMethodDomainInputsV3, PreparedBorrowedMethodDomainInputsV3):
        proof._actual_v3()
        proof = proof.owner.inventory
    if type(proof) not in (PreparedCurrentMethodLearningReadV3,PreparedPersonalEligibilityRecoveryInventoryV1):
        raise AuthorityUnavailable("actual private method Binder required")
    proof._actual()
    if proof.graph is not graph or proof.db is not db:
        raise AuthorityUnavailable("method Binder crossed coordinator/storage")
    token = _BOUND.set((proof, graph, db))
    try:
        with bind_runtime_storage_operation_v3(proof.operation, db): yield proof
    finally: _BOUND.reset(token)


def require_actual_method_learning_attachment_owner_v3(owner, *, db=None):
    if (type(owner) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3, PreparedPersonalEligibilityRecoveryReadV1) or owner not in _READERS
            or owner.work is None or owner.work.state is not owner or owner.work.operation is not owner.operation
            or owner.work.coordinator is not owner.graph or not owner.graph_eof or owner.operation.closed
            or db is not None and db is not owner.db):
        raise AuthorityUnavailable("actual same-Work method attachment reader required")
    owner.require_current()
    return owner


def _bound_proof(db, namespace):
    bound = _BOUND.get()
    if bound is None: raise AuthorityUnavailable("actual prepared method-learning family is unavailable")
    proof, graph, actual_db = bound
    return proof.require_current(graph, db, namespace)


def require_bound_method_learning_rows_v3(db, namespace, type_name, columns=("token", "revision", "value", "valid"), *, valid_only=True):
    if type_name not in METHOD_LEARNING_TYPES_V3 or not columns or any(name not in {"token", "revision", "value", "valid"} for name in columns):
        raise AuthorityUnavailable("fixed method projection columns/type required")
    from .foreground_command_source_v3 import is_foreground_command_source_reader_v3
    owner=_method_active(db)
    if owner is not None and is_foreground_command_source_reader_v3(owner):
        handled,rows=read_bound_method_type_rows_v3(db,namespace,type_name,columns,valid_only=valid_only)
        if not handled:raise AuthorityUnavailable('Foreground method rows lost their actual Body binder')
        return rows
    proof = _bound_proof(db, namespace)
    proof.operation.retain(256 + len(proof.atoms) * (64 + len(columns) * 16))
    rows = []
    for atom in proof.atoms:
        if atom.key.type_name != type_name or valid_only and not atom.valid: continue
        data = {"token": atom.key.token, "revision": atom.revision, "value": proof.wires[atom.key.token], "valid": int(atom.valid)}
        rows.append(tuple(data[name] for name in columns))
    return tuple(rows)


def require_bound_method_learning_head_v3(db, namespace, key):
    if NamespaceId.from_key(key) != namespace or key.type_name not in METHOD_LEARNING_TYPES_V3:
        raise AuthorityUnavailable("fixed method head namespace/type required")
    from .foreground_command_source_v3 import is_foreground_command_source_reader_v3
    owner=_method_active(db)
    if owner is not None and is_foreground_command_source_reader_v3(owner):
        handled,row=read_bound_method_graph_point_v3(db,columns=('revision','value','valid'),key_columns=('token',),key=(key.token,))
        return row
    proof = _bound_proof(db, namespace)
    atom = next((atom for atom in proof.atoms if atom.key == key), None)
    return None if atom is None else (atom.revision, proof.wires[key.token], int(atom.valid))


def require_bound_method_learning_atom_v3(db, namespace, key):
    from ..graph_types import GraphAtom
    from .foreground_command_source_v3 import is_foreground_command_source_reader_v3
    owner=_method_active(db)
    if owner is not None and is_foreground_command_source_reader_v3(owner):
        return method_graph_head_v3(db,namespace,key)
    proof = _bound_proof(db, namespace)
    if NamespaceId.from_key(key) != namespace or key.type_name not in METHOD_LEARNING_TYPES_V3:
        raise AuthorityUnavailable("fixed method atom namespace/type required")
    atom = next((atom for atom in proof.atoms if atom.key == key), None)
    if atom is None: return GraphAtom(key, 0, {}, False)
    proof.operation.retain(atom.retained_bytes * 4 + 512)
    return GraphAtom(key, atom.revision, _detach_value_v3(atom.value), atom.valid)


def require_bound_method_learning_history_v3(db, namespace, key, revision):
    _bound_proof(db, namespace)
    if NamespaceId.from_key(key) != namespace:
        raise AuthorityUnavailable("method history crossed namespace")
    _, row = read_bound_method_learning_attachment_v3(db, table="graph_history", columns=_HISTORY_COLUMNS,
        key_columns=("token", "revision"), key=(key.token, revision))
    return row


def read_bound_method_learning_attachment_v3(db, *, table, columns, key_columns, key):
    from .foreground_command_writer_outputs_v3 import read_bound_foreground_writer_point_v3
    handled,row=read_bound_foreground_writer_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return True,row
    from .world_owner_read_v3 import read_bound_world_attachment_v3
    handled,row=read_bound_world_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return True,row
    post = _method_post_commit_active_v3(db)
    if post is not None:
        return True, post.attachment_v3(table, tuple(columns), tuple(key_columns), tuple(key))
    if (table == "graph_bundle_operations" and tuple(columns) == ("digest", "receipt_json", "commit_seq")
            and tuple(key_columns) == ("bot", "persona", "operation_id")):
        handled, row = read_bound_method_learning_attachment_v3(db, table=table,
            columns=("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"), key_columns=key_columns, key=key)
        return handled, None if row is None else (row[0], row[4], row[3])
    owner = _method_active(db)
    if owner is None: return False, None
    request = (table, tuple(columns), tuple(key_columns), tuple(key))
    if table == "graph_history":
        allowed = {"event_id", "value", "valid", "event_bot", "event_persona", "event_session"}
        if not set(columns) <= allowed or not set(key_columns) <= {"token", "revision", "event_bot", "event_persona", "event_session", "event_id"}:
            raise AuthorityUnavailable("unregistered method history metadata projection")
        criteria = dict(zip(key_columns, key))
        if "token" not in criteria or "revision" not in criteria or len(key_columns) != len(key):
            raise AuthorityUnavailable("method history needs its exact original token/revision")
        fixed = (table, _HISTORY_COLUMNS, ("token", "revision"), (criteria["token"], criteria["revision"]))
        task = owner.attachments.get(fixed)
        point = owner.points.get(fixed)
        if task is None and (point is None or not point.complete):
            _require_input_request(owner, fixed); _need_method_input(owner, ("point", fixed))
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        with runtime_storage_quantum_v3(db) as meter:
            owner.require_current(meter=meter)
            row = task.require_row_v3(owner, meter) if task is not None else point.require_row_v3(meter)
            if row is None: return True, None
            values = dict(zip(_HISTORY_COLUMNS, row))
            values = {name: value.wire if type(value) is MethodJSONColumnV3 else value for name, value in values.items()}
            metadata = _runtime_bounded_fixed_row_v3(db, meter, "graph_history",
                ("event_id", "event_bot", "event_persona", "event_session"), "token=? AND revision=?", fixed[3])
        if (metadata is None or metadata[0] != values["event_id"] or tuple(metadata[1:3]) != owner.namespace.as_tuple):
            raise AuthorityUnavailable("method history current event identity/namespace changed")
        values.update(zip(("event_id", "event_bot", "event_persona", "event_session"), metadata))
        values.update(token=criteria["token"], revision=criteria["revision"])
        if any(values[name] != value for name, value in criteria.items()): return True, None
        return True, tuple(values[name] for name in columns)
    if table == "graph_atoms" and tuple(key_columns) in {("token",), ("token", "bot", "persona")}:
        return read_bound_method_graph_point_v3(db, columns=tuple(columns), key_columns=tuple(key_columns), key=tuple(key))
    task = owner.attachments.get(request)
    if task is not None:
        with runtime_storage_quantum_v3(db) as meter:
            owner.require_current(meter=meter); row = task.require_row_v3(owner, meter)
        return True, None if row is None else tuple(dict(zip(task.columns, row))[name] for name in columns)
    _require_input_request(owner, request)
    point = owner.points.get(request)
    if point is None or not point.complete: _need_method_input(owner, ("point", request))
    with runtime_storage_quantum_v3(db) as meter:
        owner.require_current(meter=meter); row = point.require_row_v3(meter)
    return True, None if row is None else tuple(value.wire if type(value) is MethodJSONColumnV3 else value for value in row)


# Selected domain inputs use a distinct issuer; only the JSON parser is mechanical.
_INPUTS = WeakKeyDictionary()
_BUSINESS_RESULTS = WeakKeyDictionary()
_JSON_COLUMNS = WeakKeyDictionary()
_READING = ContextVar("sylanne_method_domain_reading_v3", default=None)


class MethodInputNeededV3(Exception):
    def __init__(self, request): self.request = request


class _MethodJSONStreamV3:
    def __new__(cls,column,*,ensure_ascii,wire_metadata=None):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        class Stream(C09CanonicalJSONStreamV2):
            def _append_decoded_codepoint(self,codepoint):
                state=self._string
                if state is None or state["mode"]!="value":
                    return super()._append_decoded_codepoint(codepoint)
                column._actual()
                if wire_metadata is not None and wire_metadata.consume_codepoint_v3(state["path"],codepoint):return
                if not column.retain_path_v3(state["path"]):return
                high=column.text_high
                if high is not None:
                    column.text_high=None
                    if 0xdc00<=codepoint<=0xdfff:
                        column.text_chars.append(chr(0x10000+((high-0xd800)<<10)+codepoint-0xdc00));return
                    column.text_chars.append(chr(high))
                if 0xd800<=codepoint<=0xdbff:column.text_high=codepoint
                else:column.text_chars.append(chr(codepoint))
        return Stream(ensure_ascii=ensure_ascii)


class MethodJSONColumnV3:
    def __init__(self, issuer, owner, *, table, column, key_columns, key, cell=None,
            signer=None, signature_kind=None, signature=None,
            general_metadata_issuer=None,general_metadata_profile=None,beta1_metadata_task=None,beta1_metadata_issuer=None):
        if issuer is not _ISSUER or owner not in _READERS:
            raise AuthorityUnavailable("actual method JSON-column issuer required")
        self.beta1_metadata_task=beta1_metadata_task
        self.beta1_metadata_fields_seen=set()
        if beta1_metadata_task is not None:
            from .current_beta1_source_read_v3 import require_beta1_metadata_column_task_v3
            if general_metadata_profile is not None:raise AuthorityUnavailable("distinct metadata issuers cannot be combined")
            require_beta1_metadata_column_task_v3(beta1_metadata_task,owner,issuer=beta1_metadata_issuer,
                table=table,column=column,key_columns=key_columns,key=key)
        elif general_metadata_profile is None:_require_current_general_method_body_v1(owner,table,key)
        self.owner, self.db, self.operation = owner, owner.db, owner.operation
        self.general_metadata_profile=general_metadata_profile
        self.general_metadata_fields_seen=set()
        self.general_metadata_task=None
        self.semantic_decoder=self.semantic_hash=None
        if general_metadata_profile is not None:
            if general_metadata_issuer is not _GENERAL_METADATA_COLUMN_ISSUER_V1:
                raise AuthorityUnavailable("private actual General metadata column issuer required")
            require_actual_general_owner_metadata_work_v1(owner,operation_kind=owner.operation_kind,namespace=owner.namespace)
            self.general_metadata_task=owner.general_metadata_issuing_task
            if self.general_metadata_task is None or self.general_metadata_task.reader is not owner:
                raise AuthorityUnavailable("actual General issuing attachment task required")
            _GENERAL_METADATA_COLUMNS_V1[self]=(owner,general_metadata_profile,self.general_metadata_task)
            if cell is not None and cell.header[0]=="canonical-json.utf8.v1":
                import codecs,hashlib
                self.semantic_decoder=codecs.getincrementaldecoder("utf8")("strict");self.semantic_hash=hashlib.sha256()
        self.table, self.column, self.key_columns, self.key = table, column, tuple(key_columns), tuple(key)
        self.cell = cell
        self.signer, self.signature_kind, self.signature = signer, signature_kind, signature
        self.signature_state, self.signature_bytes, self.signature_verified = None, 0, False
        self.nodes, self.value, self.scalar = {}, None, bytearray()
        self.text_parts, self.text_chars, self.text_high = [], [], None
        self.fragment, self.fragment_offset, self.offset, self.total = b"", 0, 0, None
        self.complete, self.frozen, self.sha256, self.byte_count = False, None, None, None
        self.reserved = 0
        self.wire_parts, self.wire = [], None
        self.canonical_digest = None; self.canonical_stream = None
        wire_metadata=None
        if beta1_metadata_task is not None and owner.work.kind=='current_conditioned_self_source_read_v3':
            from .current_conditioned_self_read_v3 import conditioned_metadata_wire_capture_v3
            wire_metadata=conditioned_metadata_wire_capture_v3(beta1_metadata_task)
        self.parser = _MethodJSONStreamV3(self, ensure_ascii=cell is None or cell.header[0] != "canonical-json.utf8.v1",wire_metadata=wire_metadata)
        _JSON_COLUMNS[self] = (owner, self.db, table, column, self.key_columns, self.key, cell, signer, signature_kind, signature)
        if signer is not None: self.signature_state = signer.begin_original_stream_verification_v3(signature_kind, self)

    def _actual(self):
        if (_JSON_COLUMNS.get(self) != (self.owner, self.db, self.table, self.column, self.key_columns, self.key, self.cell,
                    self.signer, self.signature_kind, self.signature)
                or self.owner not in _READERS or self.operation.closed):
            raise AuthorityUnavailable("actual method JSON-column identity changed")
        return self

    def _reserve_v3(self, extra=0):
        if self.general_metadata_profile is not None:
            return reserve_current_general_owner_metadata_peak_v1(self.owner,extra=extra)
        size = _heap((self.nodes, self.value, self.scalar, self.text_parts, self.text_chars, self.fragment, self.wire_parts,
            self.general_metadata_fields_seen)) + extra + 65536
        if size > self.reserved:
            self.operation.retain(size - self.reserved); self.reserved = size
    def retain_path_v3(self,path):
        if self.beta1_metadata_task is not None:
            from .current_beta1_source_read_v3 import retain_beta1_metadata_path_v3
            return retain_beta1_metadata_path_v3(self,path)
        if self.general_metadata_profile is None:return True
        _require_general_owner_metadata_column_v1(self)
        from .d01_general_growth_v1 import retain_current_general_owner_metadata_path_v1
        return retain_current_general_owner_metadata_path_v1(self.general_metadata_profile,path)
    def _put_v3(self, path, value):
        if not path: self.value = value
        else:
            parent = self.nodes[path[:-1]]
            if type(parent) is list: parent.append(value)
            else: parent[path[-1]] = value
    def _flush_text_v3(self):
        if self.text_chars:
            self.text_parts.append("".join(self.text_chars)); self.text_chars = []
    def _emit_v3(self,event):
        if self.beta1_metadata_task is not None:
            if event.kind=="key"and len(event.path)==1:self.beta1_metadata_fields_seen.add(event.key)
            if not self.retain_path_v3(event.path):return
        if self.general_metadata_profile is not None:
            if event.kind=="key" and len(event.path)==1:self.general_metadata_fields_seen.add(event.key)
            if not self.retain_path_v3(event.path):return
        import json
        if event.kind in ("object_start", "array_start"):
            self._reserve_v3(1024)
            value = {} if event.kind == "object_start" else []
            self.nodes[event.path] = value; self._put_v3(event.path, value)
        elif event.kind == "scalar_start":
            self.scalar = bytearray(); self.text_parts = []; self.text_chars = []; self.text_high = None
        elif event.kind == "scalar_chunk" and event.scalar_kind != "string":
            self._reserve_v3(len(event.raw) * 4 + 1024); self.scalar.extend(event.raw)
        elif event.kind == "scalar_end":
            if event.scalar_kind == "string":
                if self.text_high is not None: self.text_chars.append(chr(self.text_high)); self.text_high = None
                self._flush_text_v3(); self._reserve_v3(sum(map(len, self.text_parts)) * 4 + 1024)
                value = "".join(self.text_parts); self.text_parts = []
            else: value = json.loads(self.scalar)
            self.scalar = bytearray(); self._put_v3(event.path, value)

    def advance(self, meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2, read_legacy_sql_cell_fragment_v2, _quote
        self._actual(); self.owner.require_current(meter=meter)
        if self.beta1_metadata_task is not None:
            from .current_beta1_source_read_v3 import advance_beta1_metadata_column_v3
            return advance_beta1_metadata_column_v3(self,meter)
        if self.general_metadata_profile is not None:return _advance_general_owner_metadata_column_v1(self,meter)
        if self.complete: return True
        if self.canonical_stream is not None:
            self.canonical_stream.read_fragment(meter)
            if self.canonical_stream.complete:
                self.canonical_digest = self.canonical_stream.hash.hexdigest()
                self.canonical_stream = None; self.complete = True
            return self.complete
        if self.fragment_offset < len(self.fragment):
            end = min(self.fragment_offset + 1024, len(self.fragment))
            self._reserve_v3(131072)
            self.parser.feed(self.fragment[self.fragment_offset:end], self._emit_v3)
            self.fragment_offset = end; self._flush_text_v3(); return False
        if self.cell is not None: chunk = self.cell.read_fragment(meter=meter)
        else:
            where = " AND ".join(_quote(n) + "=?" for n in self.key_columns)
            with legacy_cell_read_transaction_v2(self.db):
                if self.total is None:
                    row = self.db.execute("SELECT typeof(" + _quote(self.column) + "),length(CAST(" + _quote(self.column)
                        + " AS BLOB)) FROM " + _quote(self.table) + " WHERE " + where, self.key).fetchone()
                    meter.charge_read(16)
                    if row is None or row[0] != "text": raise AuthorityUnavailable("actual method JSON column kind changed")
                    self.total = row[1]
                if self.offset < self.total:
                    chunk, total, kind = read_legacy_sql_cell_fragment_v2(self.db, table=self.table, column=self.column,
                        where=where, parameters=self.key, start=self.offset, length=min(16384, self.total-self.offset), meter=meter)
                    if (total, kind) != (self.total, "text"): raise AuthorityUnavailable("method original column changed")
                    self.offset += len(chunk)
                else: chunk = None
        if chunk is not None:
            if self.signature_state is not None:
                self.signature_state.update(chunk); self.signature_bytes += len(chunk)
            self.operation.retain(len(chunk) + 1024); self.wire_parts.append(chunk)
            self.fragment, self.fragment_offset = chunk, 0; return False
        parsed = self.parser.finish()
        if self.cell is not None:
            digest = self.cell.finish(meter=meter)
            if (parsed.sha256, parsed.byte_count) != (digest, self.cell.header[3]):
                raise AuthorityUnavailable("method JSON canonical cell digest/fullEOF changed")
        elif parsed.byte_count != self.total: raise AuthorityUnavailable("method original column EOF changed")
        self.operation.retain(_heap(self.value) * 2 + parsed.byte_count * 2 + 1024)
        self.frozen = _freeze_value_v3(self.value)
        self.wire = b"".join(self.wire_parts).decode("utf-8")
        self.sha256, self.byte_count = parsed.sha256, parsed.byte_count
        if self.cell is not None and self.cell.header[0] == "canonical-json.utf8.v1":
            from .owner_material_source_storage_v3 import CanonicalValueStreamV3
            self.canonical_stream = CanonicalValueStreamV3(self.value)
        else:
            self.canonical_digest = self.sha256; self.complete = True
        self.value = None; self.nodes = {}; self.scalar = bytearray(); self.fragment = b""; self.parser = None
        self.wire_parts.clear()
        if self.signature_state is not None:
            self.signer.finish_original_stream_verification_v3(self.signature_kind, self.signature, self, self.signature_state)
            self.signature_verified = True
        return self.complete

    def json_v3(self):
        self._actual()
        if self.general_metadata_profile is not None or self.beta1_metadata_task is not None:
            raise AuthorityUnavailable("locator metadata is not a protected whole-body original")
        if not self.complete: raise AuthorityUnavailable("method JSON must reach actual EOF")
        self.operation.retain(_heap(self.frozen) + 1024)
        return _detach_value_v3(self.frozen)


class _MethodPointReadV3:
    def __init__(self, owner, request):
        self.owner, self.request = owner, request
        self.table, self.columns, self.key_columns, self.key = request
        self.phase, self.metadata, self.small = "metadata", None, None
        self.values, self.pending, self.column = {}, [], None
        self.complete, self.row = False, None
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3, begin_runtime_cell_read_v3
        from .c09_paged_sql_v2 import _quote
        o = self.owner; o.require_current(meter=meter)
        where = " AND ".join(_quote(n) + "=?" for n in self.key_columns)
        if self.phase == "metadata":
            json_names = tuple(n for n in self.columns if n.endswith("_json") or n in {"value", "reads", "revisions", "dependencies", "invalidated"})
            names = tuple(n for n in self.columns if n not in json_names)
            if self.table in {"graph_atoms", "graph_history"} and "value" in json_names: names += ("value_cell_id",)
            self.metadata_columns = tuple(dict.fromkeys((*self.key_columns, *names)))
            self.metadata = _runtime_bounded_fixed_row_v3(o.db, meter, self.table, self.metadata_columns, where, self.key)
            if self.metadata is None: self.complete = True; return
            self.small = dict(zip(self.metadata_columns, self.metadata)); self.pending = list(json_names)
            self.phase = "columns"; return
        if self.column is not None:
            if self.column.advance(meter): self.values[self.column.column] = self.column; self.column = None
            return
        if self.pending:
            name = self.pending.pop(0)
            cell_id = self.small.get("value_cell_id") if name == "value" else None
            cell = None if cell_id is None else begin_runtime_cell_read_v3(o.db, cell_id,
                erasure_owner_ref=self.key[0] if self.table == "graph_history" else None)
            if cell is None:
                kind = o.db.execute("SELECT typeof(" + _quote(name) + ") FROM " + _quote(self.table) + " WHERE " + where, self.key).fetchone()
                meter.charge_read(8)
                if kind is None: raise AuthorityUnavailable("method original column disappeared")
                if kind[0] == "null": self.values[name] = None; return
                if kind[0] != "text": raise AuthorityUnavailable("method original JSON kind changed")
            self.column = MethodJSONColumnV3(_ISSUER, o, table=self.table, column=name,
                key_columns=self.key_columns, key=self.key, cell=cell); return
        self.row = tuple(self.values[n] if n in self.values else self.small[n] for n in self.columns)
        self.complete = True
    def require_row_v3(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        where = " AND ".join(n + "=?" for n in self.key_columns)
        if not self.complete: raise AuthorityUnavailable("method point lacks actual EOF")
        if self.owner.operation_kind=="prepare_internal_life_numeric_drive":
            from .d06_life_numeric_drive_v1 import recheck_drive_numeric_point_header_v3
            actual=recheck_drive_numeric_point_header_v3(self,meter)
        else:
            actual = _runtime_bounded_fixed_row_v3(self.owner.db, meter, self.table, self.metadata_columns, where, self.key)
        if actual != self.metadata: raise AuthorityUnavailable("method point full key/current row changed after EOF")
        return self.row


def require_method_graph_atom_json_v3(original, *, key, revision, value, valid):
    if type(original) is not MethodJSONColumnV3:
        raise AuthorityUnavailable("actual private method Graph JSON required")
    original._actual(); o = original.owner
    o.require_current()
    if original.table != "graph_atoms" or original.column != "value" or original.key[0] != key.token:
        raise AuthorityUnavailable("method Graph JSON has another actual key/table")
    point = next((p for p in o.points.values() if p.complete and p.values.get("value") is original), None)
    census = o.census_columns.get(key.token)
    actual = (point.small["revision"], bool(point.small["valid"])) if point is not None else (
        None if census is not original else o.census_versions[key.token])
    if actual != (revision, valid) or not original.complete or _freeze_value_v3(value) != original.frozen:
        raise AuthorityUnavailable("method Graph atom revision/value/EOF differs")
    if NamespaceId.from_key(key) != o.namespace: raise AuthorityUnavailable("method Graph JSON crossed namespace")
    o.store._validate_key(key)
    if valid: o.store._registry.spec(key.type_name).validator(value)
    return original.json_v3()


class _MethodInventoryReadV3:
    def __init__(self, owner, type_id):
        owner.store._registry.spec(type_id)
        self.owner, self.type_id, self.after = owner, type_id, None
        self.rows, self.pending, self.complete = [], None, False
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        o = self.owner; o.require_current(meter=meter)
        if self.pending is not None:
            if not self.pending.complete: self.pending.advance(meter); return
            atom = _method_point_atom(self.pending, meter)
            self.rows.append(atom); o.input_heads[atom.key.token] = atom; self.pending = None
            if len(self.rows) > 128: raise AuthorityUnavailable("method fixed inventory exceeds original 128-row bound")
            return
        where = "bot=? AND persona=? AND type_name=?"; args = (*o.namespace.as_tuple, self.type_id)
        if self.after is not None: where += " AND token>?"; args += (self.after,)
        row = _runtime_bounded_fixed_row_v3(o.db, meter, "graph_atoms", ("token",), where + " ORDER BY token", args)
        if row is None: self.complete = True; return
        key = AtomKey.from_token(row[0])
        if NamespaceId.from_key(key) != o.namespace or key.type_name != self.type_id:
            raise AuthorityUnavailable("method inventory full key/type differs")
        self.after = row[0]
        request = ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona"), (key.token, *o.namespace.as_tuple))
        self.pending = o.points.get(request)
        if self.pending is None: self.pending = _MethodPointReadV3(o, request); o.points[request] = self.pending


def _method_point_atom(point, meter):
    from ..graph_types import GraphAtom
    row = point.require_row_v3(meter); key = AtomKey.from_token(point.key[0])
    if row is None: return GraphAtom(key, 0, {}, False)
    column = point.values["value"]; value = column.json_v3()
    return GraphAtom(key, row[0], value, bool(row[2]), _canonical_original=column)


def _method_active(db):
    owner = _READING.get()
    if owner is None:
        bound = _BOUND.get(); owner = None if bound is None else bound[0].reader
    if owner is not None and (owner not in _READERS or owner.db is not db):
        raise AuthorityUnavailable("actual method selected-input Binder differs")
    return owner


def _require_input_request(owner, request):
    from .foreground_command_source_v3 import require_foreground_command_point_v3
    if require_foreground_command_point_v3(owner,request):return
    from .artifact_borrowed_source_v3 import require_artifact_borrowed_point_v3
    if require_artifact_borrowed_point_v3(owner,request):return
    from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    table, columns, key_columns, key = request
    from .current_beta1_source_read_v3 import beta1_source_operation_v3
    if owner.work.kind=='current_habit_source_read_v3' or beta1_source_operation_v3(owner.operation_kind):
        from .current_beta1_source_read_v3 import require_beta1_source_point_v3
        return require_beta1_source_point_v3(owner,request)
    if owner.operation_kind in _NUMERIC_PAID_WRITE_OPERATIONS_V3:
        from .current_life_numeric_paid_write_v3 import require_numeric_paid_point_v3
        require_numeric_paid_point_v3(owner,request)
        return
    if owner.operation_kind in _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3:
        from .current_owner_job_cancel_v3 import require_cancel_job_point_v3
        require_cancel_job_point_v3(owner,request)
        return
    if owner.operation_kind in _NUMERIC_READ_ONLY_OPERATIONS_V3:
        from .current_life_numeric_read_v3 import require_numeric_read_point_v3
        require_numeric_read_point_v3(owner,request)
        return
    if owner.operation_kind=="prepare_internal_life_interval_baseline" and table in {"graph_c04_encoding_baselines_v3","graph_d11_life_originals_v1"}:
        from .c04_encoding_context_original_v3 import require_life_encoding_prior_selector_v3
        if require_life_encoding_prior_selector_v3(owner,request):return
    if owner.operation_kind=="prepare_internal_life_numeric_drive" and table in {"graph_d04_originals_v3","graph_d11_life_originals_v1","graph_dependency_edges"}:
        from .d06_life_numeric_drive_v1 import require_drive_input_selector_v3
        if require_drive_input_selector_v3(owner,request):return
    numeric_c04=False
    if (owner.operation_kind in _NUMERIC_OWNER_OPERATIONS_V1 and request[:3] in {
            ("graph_c04_internal_work_prepared_v1",("binding_digest","prepared_digest","prepared_json"),("bot","persona","operation_id")),
            ("d11_c04_cpu_cost_originals_v1",("original_json","original_digest"),("bot","persona","operation_id"))}):
        from .current_life_numeric_metadata_v1 import require_numeric_c04_original_selector_v1
        require_numeric_c04_original_selector_v1(owner,request);numeric_c04=True
    if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3 and request[:3] not in {
            ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona")),
            ("graph_d05_production_policies_v1", ("payload_json",), ("bot", "persona", "policy_ref", "revision"))} and not numeric_c04:
        raise AuthorityUnavailable("unregistered fixed method selected point")
    if table in {"graph_atoms", "graph_history", "graph_dependencies"}:
        if NamespaceId.from_key(AtomKey.from_token(key[0])) != owner.namespace:
            raise AuthorityUnavailable("method selected point crossed namespace")
    elif tuple(key[:2]) != owner.namespace.as_tuple:
        raise AuthorityUnavailable("method original point crossed namespace")
    if len(key) != len(key_columns): raise AuthorityUnavailable("method selected point full key differs")


def _need_method_input(owner, request):
    if owner.inputs_sealed: raise AuthorityUnavailable("exact dependency was not prepared by the actual method Work")
    raise MethodInputNeededV3(request)


def method_graph_head_v3(db, namespace, key):
    from .foreground_command_writer_outputs_v3 import read_foreground_writer_head_v3
    handled,atom=read_foreground_writer_head_v3(db,namespace,key)
    if handled:return atom
    post = _method_post_commit_active_v3(db)
    if post is not None:
        if namespace != post.namespace: raise AuthorityUnavailable("successor head crossed namespace")
        return post.head_v3(key)
    from ..graph_types import GraphAtom
    from .current_beta1_source_read_v3 import beta1_source_operation_v3
    from .foreground_command_source_v3 import is_foreground_command_source_reader_v3
    owner = _method_active(db)
    if owner is None: raise AuthorityUnavailable("actual method selected-input family is unavailable")
    if NamespaceId.from_key(key) != namespace or namespace != owner.namespace:
        raise AuthorityUnavailable("method selected head crossed namespace")
    if key.token in owner.census_columns:
        column = owner.census_columns[key.token]; revision, valid = owner.census_versions[key.token]
        return GraphAtom(key, revision, column.json_v3(), valid, _canonical_original=column)
    inventory = owner.inventories.get(key.type_name)
    if inventory is not None and inventory.complete and not any(atom.key == key for atom in inventory.rows):
        owner.require_current()
        return GraphAtom(key, 0, {}, False)
    if (key.type_name in METHOD_LEARNING_TYPES_V3 and owner.inventory_sealed
            and owner.operation_kind not in (_GENERAL_OWNER_OPERATIONS_V1 | _NUMERIC_METADATA_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3)
            and owner.work.kind!='current_habit_source_read_v3' and not beta1_source_operation_v3(owner.operation_kind)
            and not _artifact_borrowed_reader_v3(owner) and not is_foreground_command_source_reader_v3(owner)
            and key.token not in owner.census_columns):
        owner.require_current()
        return GraphAtom(key, 0, {}, False)
    request = ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona"), (key.token, *namespace.as_tuple))
    _require_input_request(owner, request)
    point = owner.points.get(request)
    if point is None or not point.complete: _need_method_input(owner, ("point", request))
    with runtime_storage_quantum_v3(db) as meter:
        owner.require_current(meter=meter)
        atom = _method_point_atom(point, meter)
    owner.input_heads[key.token] = atom
    if key.type_name == "memory.source" and atom.revision > 0 and owner.selected_plan is not None:
        history = ("graph_history", _HISTORY_COLUMNS, ("token", "revision"), (key.token, atom.revision))
        prior = owner.attachments.get(history)
        selected = owner.points.get(history)
        if prior is None and (selected is None or not selected.complete):
            _need_method_input(owner, ("point", history))
        # Current history event metadata is checked by the same exact getter as stage.
        read_bound_method_learning_attachment_v3(db, table="graph_history", columns=_HISTORY_COLUMNS,
            key_columns=("token", "revision"), key=(key.token, atom.revision))
    return atom


def method_domain_inventory_v3(db, namespace, type_id):
    post = _method_post_commit_active_v3(db)
    if post is not None:
        if type(post) is not PreparedMethodPostCommitV3:
            raise AuthorityUnavailable("model foreground scope successor grants no inventory/query read")
        if namespace != post.namespace: raise AuthorityUnavailable("Artifact successor inventory crossed namespace")
        pages = tuple(page for page in post.coverage if page.type_id == type_id)
        if len(pages) != 1 or not pages[0].complete:
            raise AuthorityUnavailable("Artifact successor inventory has no actual complete selected coverage")
        if post._query_versions_v3(type_id, post.prior_frame.limits.max_query_rows) != pages[0].row_versions:
            raise AuthorityUnavailable("Artifact successor inventory current metadata changed")
        return tuple(post.head_v3(version.key) for version in pages[0].row_versions)
    owner = _method_active(db)
    if owner is None or namespace != owner.namespace: raise AuthorityUnavailable("actual method inventory Binder required")
    from .current_beta1_source_read_v3 import beta1_source_operation_v3
    from .foreground_command_source_v3 import is_foreground_command_source_reader_v3,foreground_command_inventory_types_v3
    if type_id in METHOD_LEARNING_TYPES_V3 and owner.operation_kind not in _NUMERIC_METADATA_OPERATIONS_V3 and owner.work.kind!='current_habit_source_read_v3' and not beta1_source_operation_v3(owner.operation_kind) and not _artifact_borrowed_reader_v3(owner) and not is_foreground_command_source_reader_v3(owner):
        return tuple(method_graph_head_v3(db, namespace, atom.key) for atom in owner.inventory.atoms if atom.key.type_name == type_id)
    if type_id == owner.preference_type and owner.preferences_from_census:
        owner.preference_inventory.require_current_v3()
        return tuple(method_graph_head_v3(db, namespace, atom.key) for atom in owner.preference_inventory.atoms)
    from .artifact_borrowed_source_v3 import artifact_borrowed_inventory_types_v3
    allowed = set(owner.preplan_families)|set(artifact_borrowed_inventory_types_v3(owner))|set(foreground_command_inventory_types_v3(owner))
    if owner.selected_plan is not None: allowed.update(owner.selected_plan.fixed_type_ids)
    if owner.preference_origin is not None: allowed.add(owner.preference_type)
    if type_id not in allowed:
        raise AuthorityUnavailable("method selected family is outside its actual fixed recipe/plan")
    task = owner.inventories.get(type_id)
    if task is None or not task.complete: _need_method_input(owner, ("inventory", type_id))
    owner.require_current()
    if type_id == owner.preference_type:
        if owner.preference_inventory is None:
            owner.preference_inventory = PreparedMethodRelationshipPreferencesV3(_ISSUER, owner, tuple(task.rows))
        owner.preference_inventory.require_current_v3()
    return tuple(task.rows)


class PreparedMethodDomainInputsV3:
    def __init__(self, issuer, owner, plan, envelope):
        if issuer is not _ISSUER or owner not in _READERS or not owner.inventory_sealed:
            raise AuthorityUnavailable("actual method selected-input issuer required")
        self.owner, self.plan, self.envelope = owner, plan, envelope
        self.read_scope, self.graph_stamp = owner.fence.scope, owner.graph_stamp
        self.owner_rights = (owner.owner_binding.access_epoch, owner.owner_binding.delete_epoch)
        self.business_result = None
        _INPUTS[self] = (owner, plan, envelope, self.read_scope, self.graph_stamp, self.owner_rights)
    def _actual_v3(self):
        if (_INPUTS.get(self) != (self.owner, self.plan, self.envelope, self.read_scope, self.graph_stamp, self.owner_rights)
                or not self.owner.inputs_sealed or self.plan != self.owner.selected_plan):
            raise AuthorityUnavailable("actual sealed method domain inputs required")
        self.owner.inventory._actual()
        return self
    def require_business_result_v3(self, work):
        self._actual_v3()
        o = self.owner
        if (work is not o.work or work.state is not o or work.operation is not o.operation
                or work.coordinator is not o.graph or not o.read_finished or not o.inputs_sealed
                or not o.business_started or not o.business_completed
                or _BUSINESS_RESULTS.get(self) != (work, self.business_result)):
            raise AuthorityUnavailable("actual same-Work single completed business result required")
        return self.business_result
    def head_v3(self, key): return method_graph_head_v3(self.owner.db, self.owner.namespace, key)
    def inventory_v3(self, type_id):
        if type_id not in self.plan.fixed_type_ids: raise AuthorityUnavailable("method frame family differs from actual plan")
        return method_domain_inventory_v3(self.owner.db, self.owner.namespace, type_id)
    def require_current_v3(self, db, scope, current_owner):
        if _INPUTS.get(self) != (self.owner, self.plan, self.envelope, self.read_scope, self.graph_stamp, self.owner_rights):
            raise AuthorityUnavailable("actual method frame-input proof required")
        o = self.owner; o.require_current()
        if (db is not o.db or scope.namespace != o.namespace or current_owner is None
                or current_owner.namespace != o.namespace
                or tuple(getattr(current_owner, name) for name in ("actor", "grant_revision", "grant_digest", "authorization_head"))
                    != tuple(getattr(o.owner_binding, name) for name in ("actor", "grant_revision", "grant_digest", "authorization_head"))
                or (scope.graph_revision, scope.graph_epoch) != (o.graph_stamp[0].graph_revision, o.graph_stamp[1])
                or (current_owner.access_epoch, current_owner.delete_epoch) != self.owner_rights):
            raise AuthorityUnavailable("method data evidence changed before actual WRITE qualification")
        if not o.inputs_sealed and (scope is not o.fence.scope or current_owner is not o.owner_binding):
            raise AuthorityUnavailable("unfinished method READ inputs require their actual READ scope/Owner")
        _register_current_general_method_source_write_phase_v1(self,scope,current_owner)
        return self
    def release_payload_v3(self):
        _release_method_registered_payloads_v3(self.owner)
        _INPUTS.pop(self, None); _BUSINESS_RESULTS.pop(self, None)
        self.business_result = None
        self.owner.inventory.release_payload_v3()
        self.owner.points.clear(); self.owner.inventories.clear(); self.owner.input_heads.clear()
        self.owner.census_columns.clear(); self.owner.census_versions.clear()
        self.owner.policy_tasks.clear(); self.owner.budget_task = None
        if self.owner.preference_inventory is not None: self.owner.preference_inventory.release_payload_v3()
        self.owner.preference_origin = None
        self.owner.selected_plan = self.owner.selected_envelope = self.owner.frame_fields = None
        if self.owner.action_schema_locator is not None: _ACTION_LOCATORS.pop(self.owner.action_schema_locator, None)
        self.owner.action_schema_locator = None
        self.owner.pending_input = self.owner.result = None
        self.owner.personal_eligibility_wave_v1 = None


def read_bound_method_frame_inputs_v3(db, *, graph, scope, plan, envelope, current_owner):
    owner = _method_active(db)
    if owner is None: return False, None
    if type(owner) not in (_MethodLearningReadV3,PreparedPersonalEligibilityRecoveryReadV1):
        raise AuthorityUnavailable("Owner frame getter cannot consume borrowed issuance")
    if (owner.graph is not graph or envelope.authority.namespace != owner.namespace
            or envelope.identity.operation_id != owner.operation_id
            or envelope.deadline_utc > owner.operation.deadline_utc):
        raise AuthorityUnavailable("method frame command/root deadline differs")
    if owner.inputs_sealed:
        if plan != owner.selected_plan: raise AuthorityUnavailable("method WRITE changed its independently prepared plan")
    else:
        if scope is not owner.fence.scope or current_owner is not owner.owner_binding:
            raise AuthorityUnavailable("actual method plan-resolution READ scope required")
        if owner.selected_plan is None: owner.selected_plan = plan
        elif plan != owner.selected_plan: raise AuthorityUnavailable("pure method read plan changed during preparation")
        owner.selected_envelope = envelope
    if owner.inputs_sealed and owner.work.kind == 'current_habit_source_read_v3':
        proof = owner.result
        if type(proof) is not PreparedMethodDomainInputsV3 or proof.owner is not owner:
            raise AuthorityUnavailable('Habit WRITE lost its actual once-sealed same-Work inputs')
        proof._actual_v3()
    else:
        proof = PreparedMethodDomainInputsV3(_ISSUER, owner, plan, envelope)
    proof.require_current_v3(db, scope, current_owner)
    return True, proof


def require_bound_relationship_preferences_v3(db, namespace):
    from ..domains.d05.relationship_revision_v2 import ESTIMATE_TYPE
    owner = _method_active(db)
    if owner is None or namespace != owner.namespace or owner.preference_type != ESTIMATE_TYPE:
        raise AuthorityUnavailable("actual SourceNote candidate preference family is unavailable")
    return method_domain_inventory_v3(db, namespace, ESTIMATE_TYPE)


def read_bound_method_graph_point_v3(db, *, columns, key_columns, key, history=False):
    post = _method_post_commit_active_v3(db)
    if post is not None:
        return True, post.attachment_v3("graph_history" if history else "graph_atoms", tuple(columns), tuple(key_columns), tuple(key))
    owner = _method_active(db)
    if owner is None: return False, None
    if history:
        return read_bound_method_learning_attachment_v3(db, table="graph_history", columns=columns, key_columns=key_columns, key=key)
    if tuple(key_columns) not in {("token",), ("token", "bot", "persona")} or not set(columns) <= {"revision", "value", "valid", "token"}:
        raise AuthorityUnavailable("unregistered method Graph head projection")
    atom_key = AtomKey.from_token(key[0])
    if len(key) == 3 and tuple(key[1:]) != owner.namespace.as_tuple: raise AuthorityUnavailable("method head fullPK crossed namespace")
    atom = method_graph_head_v3(db, owner.namespace, atom_key)
    if atom.revision == 0: return True, None
    column = owner.census_columns.get(atom_key.token)
    if column is None:
        point = owner.points[("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona"), (atom_key.token, *owner.namespace.as_tuple))]
        column = point.values["value"]
    values = {"token": atom_key.token, "revision": atom.revision, "value": column.wire, "valid": int(atom.valid)}
    return True, tuple(values[name] for name in columns)


def read_bound_method_type_rows_v3(db, namespace, type_id, columns, *, valid_only=False):
    owner = _method_active(db)
    if owner is None: return False, None
    if not set(columns) <= {"token", "revision", "value", "valid"}: raise AuthorityUnavailable("fixed method family columns required")
    atoms = method_domain_inventory_v3(db, namespace, type_id)
    rows = []
    for atom in atoms:
        if valid_only and not atom.valid: continue
        _, row = read_bound_method_graph_point_v3(db, columns=columns, key_columns=("token",), key=(atom.key.token,))
        rows.append(row)
    return True, tuple(rows)


class _MethodBudgetGrantReadV3:
    def __init__(self, owner, lease_id):
        self.owner, self.lease_id = owner, lease_id
        self.metadata, self.column, self.complete = None, None, False
    def require_metadata_v3(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        row = _runtime_bounded_fixed_row_v3(self.owner.db, meter, "runtime_budget_grants",
            ("lease_id", "version", "signature", "status"), "lease_id=? ORDER BY version DESC", (self.lease_id,))
        if row != self.metadata or row is None or row[3] != "active":
            raise AuthorityUnavailable("actual latest signed method budget grant changed")
        return row
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        o = self.owner; o.require_current(meter=meter)
        if self.metadata is None:
            self.metadata = _runtime_bounded_fixed_row_v3(o.db, meter, "runtime_budget_grants",
                ("lease_id", "version", "signature", "status"), "lease_id=? ORDER BY version DESC", (self.lease_id,))
            if self.metadata is None or self.metadata[3] != "active":
                raise AuthorityUnavailable("actual active signed method budget grant is absent")
            return
        if self.column is None:
            self.column = MethodJSONColumnV3(_ISSUER, o, table="runtime_budget_grants", column="grant_json",
                key_columns=("lease_id", "version"), key=self.metadata[:2],
                signer=o.graph._GraphCoordinator__d11_issuer._signer, signature_kind="budget-grant.v1", signature=self.metadata[2])
            return
        if self.column.advance(meter):
            self.require_metadata_v3(meter); self.complete = True


def require_method_signature_column_v3(original, *, signer, kind, signature=None, verifier=None, complete=False):
    if type(original) is not MethodJSONColumnV3:
        raise AuthorityUnavailable("actual method signed-column original required")
    original._actual(); o = original.owner
    from .foreground_command_source_v3 import require_foreground_command_signature_column_v3
    handled,value=require_foreground_command_signature_column_v3(original,signer=signer,kind=kind,
        signature=signature,verifier=verifier,complete=complete)
    if handled:return value
    if original.beta1_metadata_task is not None:
        from .current_beta1_source_read_v3 import require_beta1_metadata_signature_v3
        return require_beta1_metadata_signature_v3(original,signer=signer,kind=kind,signature=signature,
            verifier=verifier,complete=complete)[1]
    if original.general_metadata_profile is not None:
        _require_general_owner_metadata_column_v1(original)
        original.general_metadata_task.require_signature_v1(original,signer,kind)
        if complete and (not original.complete or signature!=original.signature or verifier is not original.signature_state
                or original.signature_bytes!=original.byte_count):
            raise AuthorityUnavailable("General signed metadata lacks actual whole HMAC EOF")
        return original
    if o.operation_kind=="prepare_internal_life_numeric_drive" and original.table=="runtime_budget_grants" and original.key[0]!=o.parent_budget_lease_ref:
        from .d06_life_numeric_drive_v1 import require_drive_dose_signature_v3
        return require_drive_dose_signature_v3(original,signer=signer,kind=kind,signature=signature,verifier=verifier,complete=complete)
    task = o.budget_task
    if (task is None or original.table != "runtime_budget_grants" or original.column != "grant_json"
            or original.key_columns != ("lease_id", "version") or original.key != task.metadata[:2]
            or original.key[0] != o.parent_budget_lease_ref or kind != "budget-grant.v1"
            or signer is not o.graph._GraphCoordinator__d11_issuer._signer
            or original.signer is not signer or original.signature_kind != kind
            or original.signature != task.metadata[2]):
        raise AuthorityUnavailable("method signature crossed actual parent lease/version/installed signer")
    with runtime_storage_quantum_v3(o.db) as meter: task.require_metadata_v3(meter)
    if complete and (not original.complete or signature != original.signature
            or verifier is not original.signature_state or original.signature_bytes != original.byte_count):
        raise AuthorityUnavailable("method signed raw column lacks actual complete bytes/state/signature")
    return original


def read_bound_method_budget_grant_v3(db, lease_id):
    post = _method_post_commit_active_v3(db)
    if type(post) is PreparedMethodForegroundScopePostCommitV3:
        raise AuthorityUnavailable("model foreground scope successor grants no budget/price read")
    owner = _method_active(db)
    if owner is None: return False, None
    if lease_id!=owner.parent_budget_lease_ref and owner.operation_kind=="prepare_internal_life_numeric_drive":
        from .d06_life_numeric_drive_v1 import read_bound_drive_dose_grant_v3
        return read_bound_drive_dose_grant_v3(owner,lease_id)
    if lease_id != owner.parent_budget_lease_ref:
        raise AuthorityUnavailable("method budget grant is not its actual parent lease")
    task = owner.budget_task
    if task is None or not task.complete: _need_method_input(owner, ("budget_grant", lease_id))
    with runtime_storage_quantum_v3(db) as meter:
        post = _method_post_commit_active_v3(db)
        if post is None: owner.require_current(meter=meter)
        elif post.owner is not owner: raise AuthorityUnavailable("budget original belongs to another successor Work")
        task.require_metadata_v3(meter)
    if not task.column.signature_verified: raise AuthorityUnavailable("method budget raw-column signature is not verified")
    from .issuers import BudgetLeaseGrant
    value = task.column.json_v3(); value["allowed_work_kinds"] = tuple(value["allowed_work_kinds"])
    grant = BudgetLeaseGrant(**value)
    if (grant.lease_id, grant.version, grant.bot_id, grant.persona_id) != (*task.metadata[:2], *owner.namespace.as_tuple):
        raise AuthorityUnavailable("method signed grant payload differs from its actual lease/version/namespace")
    return True, grant


class _MethodRelationshipPolicyReadV3:
    def __init__(self, owner, policy_ref):
        self.owner, self.policy_ref, self.revision = owner, policy_ref, None
        self.point, self.complete = None, False
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        o = self.owner; o.require_current(meter=meter)
        if self.point is None:
            row = _runtime_bounded_fixed_row_v3(o.db, meter, "graph_d05_production_policies_v1", ("revision",),
                "bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC", (*o.namespace.as_tuple, self.policy_ref))
            if row is None: self.complete = True; return
            self.revision = row[0]
            request = ("graph_d05_production_policies_v1", ("payload_json",), ("bot", "persona", "policy_ref", "revision"),
                (*o.namespace.as_tuple, self.policy_ref, self.revision))
            self.point = _MethodPointReadV3(o, request); o.points[request] = self.point; return
        if self.point.advance(meter) or self.point.complete: self.complete = self.point.complete
    def row_v3(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        row = _runtime_bounded_fixed_row_v3(self.owner.db, meter, "graph_d05_production_policies_v1", ("revision",),
            "bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC", (*self.owner.namespace.as_tuple, self.policy_ref))
        if row != (None if self.revision is None else (self.revision,)):
            raise AuthorityUnavailable("relationship selected policy latest revision changed")
        return None if self.point is None else self.point.require_row_v3(meter)


def read_bound_method_relationship_policy_v3(db, namespace, policy_ref):
    owner = _method_active(db)
    if owner is None or owner.preference_type is None or namespace != owner.namespace:
        raise AuthorityUnavailable("actual SourceNote relationship-policy reader required")
    task = owner.policy_tasks.get(policy_ref)
    if task is None or not task.complete: _need_method_input(owner, ("relationship_policy", policy_ref))
    with runtime_storage_quantum_v3(db) as meter:
        owner.require_current(meter=meter); row = task.row_v3(meter)
    return None if row is None else row[0].json_v3()


_PREFS = WeakKeyDictionary()


class PreparedMethodRelationshipPreferencesV3:
    def __init__(self, issuer, owner, atoms):
        if issuer is not _ISSUER or owner.preference_origin is None or not owner.inventory_sealed:
            raise AuthorityUnavailable("actual independent preference EOF issuer required")
        self.owner, self.origin, self.atoms = owner, owner.preference_origin, tuple(atoms)
        _PREFS[self] = (owner, self.origin, self.atoms, owner.graph_stamp, owner.authority_epochs)
    def require_current_v3(self):
        o = self.owner
        if _PREFS.get(self) != (o, self.origin, self.atoms, o.graph_stamp, o.authority_epochs) or self.origin != o.preference_origin:
            raise AuthorityUnavailable("actual independent preference origin/EOF changed")
        o.require_current(); return self
    def release_payload_v3(self):
        _PREFS.pop(self, None); self.atoms = None


def register_adopted_personal_candidate_preferences_v3(db, *, namespace, operation_id, original, decoded_request, prepared_set):
    """Derive preference scope only from the actually adopted preparation producer."""
    owner = _method_active(db)
    if owner is None: return
    if owner.namespace != namespace: raise AuthorityUnavailable("adopted candidate origin crossed method namespace")
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.personal_candidate_v1 import (PrepareCurrentPersonalCandidatesRequestV1,
        PreparedPersonalCandidateSetV1, SourceNoteCandidateBindingV1)
    actual = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if (actual is None or actual != original or (actual["domain"], actual["operation_kind"])
            != ("d08", "prepare_personal_candidates_v1")):
        raise AuthorityUnavailable("actual adopted candidate producer/ref/digest required")
    request = decode_typed_production_value_v1(actual["payload"]["request"], PrepareCurrentPersonalCandidatesRequestV1)
    prepared = decode_typed_production_value_v1(actual["payload"]["provenance"]["prepared_candidates"], PreparedPersonalCandidateSetV1)
    if request != decoded_request or prepared != prepared_set or prepared.namespace != namespace or prepared.preparation_operation_id != operation_id:
        raise AuthorityUnavailable("adopted candidate typed payload/bindings differ from producer")
    if not any(type(binding) is SourceNoteCandidateBindingV1 for binding in request.bindings): return
    from ..domains.d05.relationship_revision_v2 import ESTIMATE_TYPE
    origin = ("actual_adopted_preparation", operation_id, actual["original_digest"],
        actual["receipt"], actual["read_versions"], prepared.query_coverage, request.bindings)
    if owner.preference_origin is not None and owner.preference_origin != origin:
        raise AuthorityUnavailable("adopted preparation changed its independent preference origin")
    owner.preference_origin, owner.preference_type = origin, ESTIMATE_TYPE


_BORROWED_INPUTS = WeakKeyDictionary()


class _BorrowedMaterialScopeV3:
    """Plain current-data locator for the census; never a READ fence or grant."""
    def __init__(self, issuer, scope, metadata, epoch):
        if issuer is not _ISSUER: raise AuthorityUnavailable("actual borrowed material-scope issuer required")
        self.scope, self.metadata, self.epoch = scope, metadata, epoch


def _require_borrowed_issuance_v3(issued, graph):
    from .foreground_activity_issuance_v1 import _IssuedForegroundActivityV1, require_foreground_activity_issuance_v1
    from .owner_source_note_task_issuance_v1 import _IssuedOwnerSourceNoteTaskV1, require_owner_source_note_task_issuance_v1
    if type(issued) is _IssuedForegroundActivityV1:
        return require_foreground_activity_issuance_v1(issued, graph, issued.scope)
    if type(issued) is _IssuedOwnerSourceNoteTaskV1:
        return require_owner_source_note_task_issuance_v1(issued, graph, issued.scope)
    raise AuthorityUnavailable("actual exact borrowed foreground/Owner-task issuance required")


class BorrowedMethodLearningReadV3(_MethodLearningReadV3):
    def __init__(self, issuer, graph, operation, *, runtime, issued, operation_kind, request, selector, initial_now_utc):
        from datetime import datetime
        from .domain_production_registry_v1 import installed_operation_v1
        from .foreground_activity_issuance_v1 import _IssuedForegroundActivityV1
        from .owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
        if issuer is not _ISSUER or type(operation) is not RuntimeStorageOperationV3 or operation.closed:
            raise AuthorityUnavailable("actual borrowed method retention issuer required")
        evidence = _require_borrowed_issuance_v3(issued, graph)
        if evidence.request != selector or selector.operation_kind != operation_kind or runtime.graph is not graph:
            raise AuthorityUnavailable("borrowed method changed its actual issued selector/runtime")
        installed = installed_operation_v1(operation_kind)
        if type(request) is not installed.request_type: raise AuthorityUnavailable("borrowed method needs its exact registered typed request")
        if type(issued) is _IssuedForegroundActivityV1:
            from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
            digest = foreground_typed_command_digest_v1(installed, request)
            activity = selector.activity_id; purpose = selector.purpose; audiences = selector.audiences
            parent = selector.parent_budget_lease_ref; authorized_deadline = selector.requested_deadline_utc
        else:
            from ..authority_service.current_owner_source_note_task_v1 import owner_task_typed_command_digest_v1
            digest = owner_task_typed_command_digest_v1(installed, request)
            cause = evidence.authorization.cause
            activity = owner_source_note_task_ids_v1(selector.namespace, cause.owner_operation_id)["activity_id"]
            purpose = "consolidation"; audiences = cause.audiences; parent = cause.parent_budget_lease_ref
            authorized_deadline = cause.original_deadline_utc
        deadline = min(authorized_deadline, datetime.fromisoformat(evidence.valid_until_utc.replace("Z", "+00:00")).timestamp())
        if (selector.request_digest != digest or operation.operation_id != selector.operation_id
                or operation.deadline_utc > deadline or issued.scope.operation != "write"):
            raise AuthorityUnavailable("borrowed method altered original command/deadline/WRITE scope")
        metadata, epoch = graph._v2_graph_stamp(selector.namespace)
        if (issued.scope.namespace != selector.namespace or issued.scope.graph_revision != metadata.graph_revision
                or issued.scope.graph_epoch != epoch or evidence.query_epoch.revision != epoch.revision
                or evidence.current_self.graph_revision != metadata.graph_revision):
            raise AuthorityUnavailable("borrowed method original Graph/Self/query stamp changed")
        self.runtime, self.issued, self.selector, self.evidence = runtime, issued, selector, evidence
        self.authority = self.lease = self.owner_binding = self.session_proof = None
        self.source_pending_owner = None
        self.operation_kind, self.request, self.operation_id = operation_kind, request, selector.operation_id
        self.request_digest, self.activity_id, self.audience_ref = digest, activity, audiences[0]
        self.purpose, self.audiences, self.parent_budget_lease_ref = purpose, tuple(audiences), parent
        self.owner_guard = self.material_owner_guard = evidence.owner_guard
        self.expected_rights, self.current_self = (evidence.access_epoch, evidence.delete_epoch), evidence.current_self
        self.initial_now_utc, self.deadline_utc = initial_now_utc, operation.deadline_utc
        self.work = self.owner_head = None
        self.inventory_sealed = self.inputs_sealed = self.read_finished = False
        self.business_started = self.business_completed = False
        self.inventory = self.selected_plan = self.selected_envelope = self.frame_fields = None
        self.points, self.inventories, self.input_heads = {}, {}, {}
        self.census_columns, self.census_versions, self.wires = {}, {}, {}
        self.attachments, self.pending_attachments, self.attachment = {}, [], None
        self.atom_column = self.pending_input = None
        self.action_schema_locator = None
        self.observed_originals, self.installed_policy_refs, self.installed_readers = (), (), None
        self.budget_task, self.policy_tasks = None, {}
        from .foreground_command_contract_v3 import foreground_command_source_spec_v3
        from .artifact_borrowed_source_v3 import ARTIFACT_BORROWED_OPERATIONS_V3
        source_spec=foreground_command_source_spec_v3(operation_kind,request,selector)
        artifact_source=(type(issued)is _IssuedForegroundActivityV1 and operation_kind in ARTIFACT_BORROWED_OPERATIONS_V3)
        self.preplan_families=(frozenset()if source_spec is not None or artifact_source else _method_preplan_families_v3(operation_kind))
        self.preference_type = self.preference_origin = self.preference_inventory = None
        self.preferences_from_census = False
        from ..domains.d08.personal_candidate_v1 import PrepareCurrentPersonalCandidatesRequestV1, SourceNoteCandidateBindingV1
        if (operation_kind == "prepare_personal_candidates_v1" and type(request) is PrepareCurrentPersonalCandidatesRequestV1
                and any(type(binding) is SourceNoteCandidateBindingV1 for binding in request.bindings)):
            from ..domains.d05.relationship_revision_v2 import ESTIMATE_TYPE
            self.preference_type, self.preferences_from_census = ESTIMATE_TYPE, True
            self.preference_origin = ("actual_prepare_request", self.operation_id, digest, request.bindings)
        self.prefinal = self
        context = _BorrowedMaterialScopeV3(_ISSUER, issued.scope, metadata, epoch)
        _CurrentNamespaceInventoryKernelV3.__init__(self, graph, operation, context,
            projection_types=(frozenset()if source_spec is not None else METHOD_LEARNING_TYPES_V3 | (frozenset({self.preference_type}) if self.preference_type else frozenset())),
            selected_tokens=frozenset(), census_schema="sylanne.method-learning-census.v3",
            leaf_schema="sylanne.method-learning-census-leaf.v3")
        _READERS.add(self)
        from .foreground_command_source_v3 import register_foreground_command_constructor_v3
        if not register_foreground_command_constructor_v3(self):
            from .artifact_borrowed_source_v3 import register_artifact_borrowed_constructor_v3
            register_artifact_borrowed_constructor_v3(self)

    def seal_plan_v3(self, plan, *, installed_readers=None, observed_originals=(), installed_policy_refs=()):
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        if not self.inventory_sealed or self.inputs_sealed or type(plan) is not ProductionReadPlanV1:
            raise AuthorityUnavailable("actual unfinished borrowed method plan required")
        roots = {v.key.token for v in self.evidence.read_versions if v.key.type_name == "memory.source"}
        if not set(plan.source_roots) <= roots:
            raise AuthorityUnavailable("borrowed plan added Source outside its actual qualified issuance")
        from .artifact_borrowed_source_v3 import require_artifact_borrowed_seal_plan_v3
        from .foreground_command_source_v3 import is_foreground_command_source_reader_v3,require_foreground_command_seal_plan_v3
        if is_foreground_command_source_reader_v3(self):
            combined=ProductionReadPlanV1(plan.fixed_type_ids,
                tuple(sorted(set((*plan.exact_keys,*(v.key for v in self.evidence.read_versions))),key=lambda k:k.token)),
                plan.source_roots,plan.required_original_refs)
            require_foreground_command_seal_plan_v3(self,combined)
        elif _artifact_borrowed_reader_v3(self):
            require_artifact_borrowed_seal_plan_v3(self,plan)
            combined=plan
        else:
            combined = ProductionReadPlanV1(plan.fixed_type_ids,
                tuple(sorted(set((*plan.exact_keys, *(v.key for v in self.evidence.read_versions))), key=lambda k:k.token)),
                plan.source_roots, plan.required_original_refs)
        if self.selected_plan is not None and combined != self.selected_plan:
            raise AuthorityUnavailable("pure borrowed method plan changed during preparation")
        self.selected_plan, self.installed_readers = combined, installed_readers
        self.observed_originals, self.installed_policy_refs = tuple(observed_originals), tuple(installed_policy_refs)
        self.work.phase = "selected_inputs"


def begin_current_method_learning_read_in_scope_v3(graph, operation, *, runtime, issued, operation_kind,
        request, selector, initial_now_utc):
    return BorrowedMethodLearningReadV3(_ISSUER, graph, operation, runtime=runtime, issued=issued,
        operation_kind=operation_kind, request=request, selector=selector, initial_now_utc=initial_now_utc)


class PreparedBorrowedMethodDomainInputsV3:
    def __init__(self, issuer, owner, plan):
        if issuer is not _ISSUER or type(owner) is not BorrowedMethodLearningReadV3 or not owner.inventory_sealed:
            raise AuthorityUnavailable("actual borrowed method domain-input issuer required")
        self.owner, self.plan, self.issued = owner, plan, owner.issued
        self.business_result = None
        _BORROWED_INPUTS[self] = (owner, plan, self.issued, owner.graph_stamp, owner.expected_rights)
    def _actual_v3(self):
        o = self.owner
        if (_BORROWED_INPUTS.get(self) != (o, self.plan, self.issued, o.graph_stamp, o.expected_rights)
                or not o.inputs_sealed or self.plan != o.selected_plan):
            raise AuthorityUnavailable("actual sealed borrowed method inputs required")
        o.inventory._actual()
        from .foreground_command_source_v3 import is_foreground_command_source_reader_v3,_body_state_v3
        if is_foreground_command_source_reader_v3(o):_body_state_v3(o)
        return self
    def head_v3(self, key): return method_graph_head_v3(self.owner.db, self.owner.namespace, key)
    def inventory_v3(self, type_id):
        if type_id not in self.plan.fixed_type_ids: raise AuthorityUnavailable("borrowed frame family is outside actual plan")
        return method_domain_inventory_v3(self.owner.db, self.owner.namespace, type_id)
    def require_issued_current_v3(self, db, scope, issued):
        o = self.owner
        if (_BORROWED_INPUTS.get(self) != (o, self.plan, self.issued, o.graph_stamp, o.expected_rights)
                or db is not o.db or issued is not self.issued or scope is not issued.scope):
            raise AuthorityUnavailable("borrowed frame lost its actual original issuance/scope")
        current = _require_borrowed_issuance_v3(issued, o.graph)
        if current != o.evidence: raise AuthorityUnavailable("borrowed frame original evidence changed")
        o.require_current()
        from .foreground_command_source_v3 import is_foreground_command_source_reader_v3,_body_state_v3
        if is_foreground_command_source_reader_v3(o):_body_state_v3(o)
        return self
    def require_business_result_v3(self, work):
        self._actual_v3(); o = self.owner
        if (work is not o.work or work.state is not o or work.operation is not o.operation
                or not o.inputs_sealed or not o.business_started or not o.business_completed
                or _BUSINESS_RESULTS.get(self) != (work, self.business_result)):
            raise AuthorityUnavailable("actual borrowed single completed business result required")
        return self.business_result
    def release_payload_v3(self):
        _release_method_registered_payloads_v3(self.owner)
        _BORROWED_INPUTS.pop(self, None); _BUSINESS_RESULTS.pop(self, None); self.business_result = None
        o = self.owner; o.inventory.release_payload_v3()
        o.points.clear(); o.inventories.clear(); o.input_heads.clear(); o.census_columns.clear(); o.census_versions.clear()
        o.policy_tasks.clear(); o.budget_task = None
        if o.preference_inventory is not None: o.preference_inventory.release_payload_v3()
        if o.action_schema_locator is not None: _ACTION_LOCATORS.pop(o.action_schema_locator, None)
        o.action_schema_locator = None
        o.preference_origin = o.selected_plan = o.frame_fields = o.pending_input = o.result = None
        o.personal_eligibility_wave_v1 = None


def read_bound_method_issued_frame_inputs_v3(db, *, graph, scope, plan, issued):
    o = _method_active(db)
    if o is None: return False, None
    if type(o) is not BorrowedMethodLearningReadV3 or o.graph is not graph or o.issued is not issued:
        raise AuthorityUnavailable("exact borrowed method frame Binder required")
    if plan != o.selected_plan: raise AuthorityUnavailable("borrowed final compiler changed its actual prepared plan")
    proof = PreparedBorrowedMethodDomainInputsV3(_ISSUER, o, plan)
    proof.require_issued_current_v3(db, scope, issued)
    return True, proof


def _start_borrowed_method_input_v3(reader, needed):
    kind, actual = needed.request
    if kind == "point":
        _require_input_request(reader, actual)
        task = reader.points.get(actual)
        if task is None: task = _MethodPointReadV3(reader, actual); reader.points[actual] = task
    elif kind == "inventory":
        from .artifact_borrowed_source_v3 import artifact_borrowed_inventory_types_v3
        from .foreground_command_source_v3 import foreground_command_inventory_types_v3
        allowed = set(reader.preplan_families)|set(artifact_borrowed_inventory_types_v3(reader))|set(foreground_command_inventory_types_v3(reader))
        if reader.selected_plan is not None: allowed.update(reader.selected_plan.fixed_type_ids)
        if reader.preference_origin is not None: allowed.add(reader.preference_type)
        if actual not in allowed: raise AuthorityUnavailable("borrowed inventory has no actual fixed recipe/dependency")
        task = reader.inventories.get(actual)
        if task is None: task = _MethodInventoryReadV3(reader, actual); reader.inventories[actual] = task
    elif kind == "artifact_body_dependencies":
        from .artifact_borrowed_source_v3 import start_artifact_borrowed_dependencies_v3
        task=start_artifact_borrowed_dependencies_v3(reader,actual)
    elif kind == "task_choice_catalogue":
        from .artifact_task_choice_lookup_v3 import start_task_choice_catalogue_v3
        task=start_task_choice_catalogue_v3(reader,actual)
    elif kind == "budget_grant":
        if actual != reader.parent_budget_lease_ref: raise AuthorityUnavailable("borrowed budget locator changed original parent")
        if reader.budget_task is None: reader.budget_task = _MethodBudgetGrantReadV3(reader, actual)
        task = reader.budget_task
    elif kind == "relationship_policy":
        if reader.preference_origin is None: raise AuthorityUnavailable("borrowed relation has no actual adopted SourceNote origin")
        task = reader.policy_tasks.get(actual)
        if task is None: task = _MethodRelationshipPolicyReadV3(reader, actual); reader.policy_tasks[actual] = task
    else: raise AuthorityUnavailable("unregistered borrowed method selected dependency")
    reader.pending_input = task


def _artifact_borrowed_reader_v3(reader):
    from .artifact_borrowed_source_v3 import is_artifact_borrowed_source_reader_v3
    return is_artifact_borrowed_source_reader_v3(reader)


def _advance_artifact_borrowed_classification_v3(reader):
    from .artifact_borrowed_source_v3 import advance_artifact_borrowed_classification_v3
    with runtime_storage_quantum_v3(reader.db)as meter:
        return advance_artifact_borrowed_classification_v3(reader,meter)


def _advance_borrowed_method_learning_read_v3(graph, work):
    r = work.state
    if (type(r) is not BorrowedMethodLearningReadV3 or r not in _READERS or r.work is not work
            or r.graph is not graph or work.operation is not r.operation):
        raise AuthorityUnavailable("actual originating borrowed method Work required")
    with bind_runtime_storage_operation_v3(work.operation, r.db):
        # Root performs the original exact issuance require/reobserve outside SQL.
        graph._validate_borrowed_method_scope_v3(r)
        if r.inputs_sealed:
            if r.business_started: raise AuthorityUnavailable("borrowed method WRITE must run exactly once")
            r.business_started = True
            proof = r.result
            with bind_prepared_method_learning_read_v3(proof, graph, r.db):
                result = graph._complete_borrowed_method_operation_v3(r, proof)
            if type(result) is GraphStorageWorkV3: raise AuthorityUnavailable("borrowed prepared WRITE cannot create another Work")
            proof.business_result = result; _BUSINESS_RESULTS[proof] = (work, result)
            r.business_completed = True; work.phase = "business_completed"
        elif not r.inventory_sealed:
            with r.store._lock:
                if r.db.in_transaction: raise AuthorityUnavailable("borrowed census inherited a transaction")
                from .borrowed_habit_classification_v3 import (BORROWED_HABIT_METADATA_OPERATIONS_V3,
                    advance_borrowed_habit_metadata_eof_v3)
                if r.authority_epochs is None:r.advance()
                elif _advance_artifact_borrowed_classification_v3(r):pass
                elif r.operation_kind in BORROWED_HABIT_METADATA_OPERATIONS_V3:
                    with runtime_storage_quantum_v3(r.db)as meter:
                        if advance_borrowed_habit_metadata_eof_v3(r,meter):r.advance()
                else:r.require_current();r.advance()
        elif r.pending_input is not None:
            with r.store._lock, runtime_storage_quantum_v3(r.db) as meter:
                if r.db.in_transaction: raise AuthorityUnavailable("borrowed selected step inherited a transaction")
                r.require_current(meter=meter); r.pending_input.advance(meter)
                if r.pending_input.complete: r.pending_input = None
        else:
            token = _READING.set(r)
            try:
                with bind_prepared_method_learning_read_v3(r.inventory, graph, r.db):
                    if r.action_schema_locator is not None and not r.action_schema_locator.complete:
                        with r.store._lock, runtime_storage_quantum_v3(r.db) as meter:
                            if r.db.in_transaction: raise AuthorityUnavailable("schema locator inherited a transaction")
                            r.db.execute("BEGIN")
                            try: r.action_schema_locator.advance(meter)
                            finally: r.db.rollback()
                        if r.action_schema_locator.complete:
                            from dataclasses import replace
                            r.selected_plan = replace(r.selected_plan, exact_keys=tuple(sorted(
                                set((*r.selected_plan.exact_keys, r.action_schema_locator.key)), key=lambda k:k.token)))
                            from .artifact_borrowed_source_v3 import artifact_borrowed_action_schema_complete_v3
                            artifact_borrowed_action_schema_complete_v3(r)
                            from .foreground_command_source_v3 import foreground_command_action_schema_complete_v3
                            foreground_command_action_schema_complete_v3(r)
                            work.phase = "selected_inputs_final"
                        return GraphStorageStepV3("progress")
                    if r.selected_plan is None:
                        graph._advance_borrowed_method_learning_plan_v3(r)
                    else:
                        from .domain_production_frame_v1 import _materialize_current_domain_read_set_v3
                        from .domain_production_contracts_v1 import ProductionOperationLimitsV1
                        with r.store._lock:
                            if r.db.in_transaction: raise AuthorityUnavailable("borrowed read-set inherited a transaction")
                            r.db.execute("BEGIN")
                            try:
                                r.frame_fields = _materialize_current_domain_read_set_v3(graph, r.db, namespace=r.namespace,
                                    plan=r.selected_plan, expected_owner_guard=r.material_owner_guard,
                                    expected_rights=r.expected_rights, observed_originals=r.observed_originals,
                                    limits=ProductionOperationLimitsV1(), prepared_inputs=PreparedBorrowedMethodDomainInputsV3(
                                        _ISSUER, r, r.selected_plan))
                                from .ordinary_source_note_habit_classification_v3 import prepare_current_ordinary_source_note_habit_classification_v3
                                prepare_current_ordinary_source_note_habit_classification_v3(r)
                                from .artifact_preparation_parent_work_v3 import prepare_borrowed_artifact_preparation_parent_v3
                                prepare_borrowed_artifact_preparation_parent_v3(r)
                                from .foreground_command_post_frame_v3 import prepare_foreground_input_successor_histories_v3
                                prepare_foreground_input_successor_histories_v3(r)
                            finally: r.db.rollback()
                        if r.operation_kind in ACTION_SCHEMA_LOCATOR_OPERATIONS_V3 and r.action_schema_locator is None:
                            r.action_schema_locator = begin_current_borrowed_action_schema_locator_v3(r, r.frame_fields, r.selected_plan)
                            work.phase = "action_schema_locator"
                        else:
                            r.inputs_sealed = r.complete = True; work.phase = "inputs_sealed"
                            r.result = PreparedBorrowedMethodDomainInputsV3(_ISSUER, r, r.selected_plan)
            except MethodInputNeededV3 as needed: _start_borrowed_method_input_v3(r, needed)
            finally: _READING.reset(token)
        if not r.business_completed: graph._validate_borrowed_method_scope_v3(r)
    return GraphStorageStepV3("complete", r.result) if r.business_completed else GraphStorageStepV3("progress")


_ACTION_LOCATORS = WeakKeyDictionary()
ACTION_SCHEMA_LOCATOR_OPERATIONS_V3 = frozenset({"propose_artifact_draft_action",
    "propose_artifact_draft_phase_action_v2", "prepare_selected_source_note_action_v2"})


def current_action_parameter_digest_v3(db, namespace, operation_id, values):
    from ..runtime_contracts import canonical_digest
    owner = _method_active(db)
    if owner is None:
        if runtime_storage_v3(db) is not None:
            raise AuthorityUnavailable("actual prepared parameter EOF is required for segmented Action parameters")
        return canonical_digest(values)
    locator = owner.action_schema_locator
    if (namespace != owner.namespace or operation_id != owner.operation_id or locator is None
            or not locator.complete or _ACTION_LOCATORS.get(locator) != locator._identity_v3()
            or _freeze_value_v3(values) != locator.parameter_frozen):
        raise AuthorityUnavailable("Action parameters differ from their actual same-Work canonical tuple EOF")
    _require_method_locator_current_v3(owner)
    return locator.parameter_digest


class _BorrowedActionSchemaLocatorV3:
    def __init__(self, issuer, reader, read_set, plan):
        if (issuer is not _ISSUER or type(reader) is not BorrowedMethodLearningReadV3
                or reader not in _READERS or not reader.inventory_sealed or reader.inputs_sealed
                or reader.operation_kind not in ACTION_SCHEMA_LOCATOR_OPERATIONS_V3 or plan != reader.selected_plan
                or read_set is not reader.frame_fields):
            raise AuthorityUnavailable("actual selected borrowed Action material required")
        self.reader, self.read_set, self.plan = reader, read_set, plan
        self.phase, self.complete, self.key = "materials", False, None
        self.values = self.parameter_frozen = self.parameter_digest = self.stream = None
        self.identity = self.material = None
        _ACTION_LOCATORS[self] = self._identity_v3()
    def _identity_v3(self):
        return (self.reader, self.read_set, self.plan, self.phase, self.complete, self.key,
            self.parameter_frozen, self.parameter_digest, self.identity, self.material)
    def _record_v3(self): _ACTION_LOCATORS[self] = self._identity_v3()
    def _head(self, key, *, required=True):
        atom = method_graph_head_v3(self.reader.db, self.reader.namespace, key)
        if required and (not atom.valid or atom.revision < 1):
            raise AuthorityUnavailable("actual schema locator material is absent:" + key.type_name)
        return atom
    def _materials_v3(self):
        from ..runtime_contracts import OperationIdentity, canonical_digest
        from ..domains.d08.execution import _decode_goal, _decode
        from ..domains.d08.personal_plan_v1 import PLAN_TYPE, decode_personal_plan_type_v1
        from .d11_life_preparation_v1 import _read
        from .d11_artifact_draft_content_v1 import (artifact_draft_content_from_wire_v1, artifact_draft_content_from_wire_v2,
            ArtifactDraftContentAdoptionV1, ArtifactDraftContentAdoptionV2)
        from .d03_life_project_context_v1 import life_project_context_keys_v1
        from ..model_broker.artifact_draft_v1 import (artifact_draft_task_selector_v1, artifact_draft_model_ids_v1,
            artifact_draft_model_ids_v2, artifact_draft_file_ids_v1, artifact_draft_file_ids_v2)
        from .d08_personal_plan_v1 import (artifact_draft_action_keys_v1, artifact_phase_action_keys_v2,
            artifact_goal_plan_keys_v1)
        r = self.reader; ns = r.namespace
        digest = canonical_digest({"input_refs": sorted(set(self.plan.source_roots + self.plan.required_original_refs))})
        if r.operation_kind == "prepare_selected_source_note_action_v2":
            from .d08_source_note_action_v1 import (selected_source_note_binding_from_originals_v2,
                PrepareSourceNoteActionRequestV1, source_note_attempt_id_v1)
            from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
            from .d11_life_contract_v1 import life_artifact_ref_v1
            prepared, chosen, original = selected_source_note_binding_from_originals_v2(r.db, namespace=ns, request=r.request)
            binding = chosen.binding
            derived = PrepareSourceNoteActionRequestV1(binding.project_ref, binding.recipe_ref, binding.source_ref,
                binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref)
            future = chosen.future_identity
            if (future.activity_id, future.action_operation_id, future.attempt_id) != (r.activity_id, r.operation_id,
                    source_note_attempt_id_v1(ns, binding.project_ref, r.operation_id)):
                raise AuthorityUnavailable("schema locator changed its actually chosen SourceNote future identity")
            self.identity = OperationIdentity(r.activity_id, future.effect_id, r.operation_id, r.operation_kind, future.attempt_id, digest)
            project, recipe, source, goal = (self._head(AtomKey.from_token(ref)) for ref in
                (derived.project_ref, derived.recipe_ref, derived.source_ref, derived.goal_ref))
            readers = r.installed_readers
            legacy = readers.legacy_readers
            build = read_installed_d11_life_build_v1(legacy.package_root, legacy.manifest_digest)
            artifact = life_artifact_ref_v1(ns, future.effect_id)
            self.values = (project.value, recipe.value, source.value, artifact, build)
            self.material = (derived, _decode_goal(goal.value))
        else:
            phase = r.operation_kind == "propose_artifact_draft_phase_action_v2"
            if phase:
                selector = r.request.selector; ids = artifact_draft_file_ids_v2(selector)
                model = artifact_draft_model_ids_v2(selector)
                readers = r.installed_readers
                row = _read(r.db, issuer=readers.issuer, namespace=ns, kind="c4_phase_adopted", ref=model["adopt"])
                if row is None: raise AuthorityUnavailable("actual phase content adoption is absent for schema locator")
                adoption = artifact_draft_content_from_wire_v2(row[0], ArtifactDraftContentAdoptionV2)
                if adoption.selector != selector or adoption.adoption_operation_id != row[1]:
                    raise AuthorityUnavailable("phase schema locator adopted selector/producer differs")
                plan_atom = self._head(AtomKey.from_token(selector.plan_ref))
                plan = decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value)
                goal = _decode_goal(self._head(AtomKey.from_token(plan.goal_ref)).value)
                from .d08_personal_plan_v1 import require_artifact_task_objective_original_v1
                _, objective = require_artifact_task_objective_original_v1(r.db, namespace=ns,
                    goal_ref=plan.goal_ref, goal=goal, issuer=readers.issuer)
                entity = self._head(life_project_context_keys_v1(ns, objective["project_ref"])[0])
                existing = self._head(artifact_phase_action_keys_v2(selector)[0], required=False)
                self.identity = _decode("d08.action_intent.v1", existing.value).identity if existing.revision else OperationIdentity(
                    ids["activity_id"], ids["effect"], ids["action_operation"], r.operation_kind, ids["attempt"], digest)
                self.material = (selector, goal, plan, entity.value["entity_id"], adoption,
                    tuple(dict.fromkeys((adoption.task_source.ref, *adoption.content.source_refs))))
            else:
                selector = artifact_draft_task_selector_v1(ns, c02_operation_id=r.request.c02_operation_id,
                    root_registration_ref=r.request.root_registration_ref)
                ids = artifact_draft_file_ids_v1(ns, c02_operation_id=r.request.c02_operation_id,
                    root_registration_ref=r.request.root_registration_ref)
                model = artifact_draft_model_ids_v1(selector)
                row = _read(r.db, issuer=r.installed_readers.issuer, namespace=ns, kind="c4_adopted", ref=model["adopt"])
                if row is None: raise AuthorityUnavailable("actual content adoption is absent for schema locator")
                adoption = artifact_draft_content_from_wire_v1(row[0], ArtifactDraftContentAdoptionV1)
                if adoption.selector != selector or adoption.adoption_operation_id != row[1]:
                    raise AuthorityUnavailable("schema locator content adoption producer/selector differs")
                from .artifact_continuation_originals_v1 import artifact_control_keys_for_task_v1
                control = artifact_control_keys_for_task_v1(r.db, namespace=ns, c02_operation_id=selector.c02_operation_id,
                    root_registration_ref=selector.root_registration_ref)
                goal = _decode_goal(self._head(control[0]).value)
                plan = decode_personal_plan_type_v1(PLAN_TYPE, self._head(control[1]).value)
                entity = self._head(life_project_context_keys_v1(ns, control[2].token)[0])
                nodes = tuple(node for node in plan.nodes if node.node_id == ids["node"])
                if len(nodes) != 1: raise AuthorityUnavailable("schema locator needs its actual unique artifact node")
                self.identity = OperationIdentity(ids["activity_id"], ids["effect"], ids["action_operation"], r.operation_kind, ids["attempt"], digest)
                self.material = (goal, plan, nodes[0], entity.value["entity_id"], adoption,
                    artifact_draft_action_keys_v1(ns, c02_operation_id=selector.c02_operation_id,
                        root_registration_ref=selector.root_registration_ref))
            self.values = (plain_parameter_v3(adoption.target), plain_parameter_v3(adoption.content))
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        r.operation.retain(_heap(self.values) * 2 + 65536)
        self.parameter_frozen = _freeze_value_v3(self.values)
        self.stream = CanonicalValueStreamV3(self.values)
        self.phase = "parameter_tuple"; self._record_v3()
    def advance(self, meter):
        r = self.reader; r.require_current(meter=meter)
        token = _READING.set(r)
        try:
            if self.phase == "materials":
                self._materials_v3()
            elif self.phase == "parameter_tuple":
                self.stream.read_fragment(meter)
                if self.stream.complete:
                    self.parameter_digest = self.stream.hash.hexdigest(); self.phase = "schema"; self._record_v3()
            elif self.phase == "schema":
                from .d08_personal_plan_v1 import artifact_action_schema_parts_v1, artifact_phase_action_schema_parts_v2
                from .d08_source_note_action_v1 import source_note_action_parts_v1
                if r.operation_kind == "prepare_selected_source_note_action_v2":
                    request, goal = self.material
                    parts = source_note_action_parts_v1(namespace=r.namespace, identity=self.identity,
                        request=request, goal=goal, parameter_digest=self.parameter_digest)
                elif r.operation_kind == "propose_artifact_draft_phase_action_v2":
                    selector, goal, plan, entity, adoption, roots = self.material
                    parts = artifact_phase_action_schema_parts_v2(namespace=r.namespace, selector=selector,
                        goal=goal, plan=plan, entity_ref=entity, identity=self.identity, parameter_digest=self.parameter_digest,
                        adoption=adoption, target=adoption.target, roots=roots)
                else:
                    goal, plan, node, entity, adoption, keys = self.material
                    parts = artifact_action_schema_parts_v1(namespace=r.namespace, goal=goal, plan=plan, node=node,
                        entity_ref=entity, identity=self.identity, parameter_digest=self.parameter_digest,
                        action_key=keys[0], cancel_key=keys[1], adoption=adoption)
                self.key = parts[2][1]
                self.phase = "schema_head"; self._record_v3()
            elif self.phase == "schema_head":
                self._head(self.key, required=False)
                self.complete = True; self.phase = "complete"; self._record_v3()
            return self.complete
        finally: _READING.reset(token)


def plain_parameter_v3(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    return plain_v1(value)


def begin_current_borrowed_action_schema_locator_v3(reader, read_set, plan):
    return _BorrowedActionSchemaLocatorV3(_ISSUER, reader, read_set, plan)


def verify_prepared_action_schema_key_v3(db, namespace, operation_id, key):
    owner = _method_active(db)
    if owner is None:
        if runtime_storage_v3(db) is None: return key
        raise AuthorityUnavailable("actual prepared schema key is unavailable")
    locator = owner.action_schema_locator
    if (owner.namespace != namespace or owner.operation_id != operation_id or locator is None
            or not locator.complete or _ACTION_LOCATORS.get(locator) != locator._identity_v3() or locator.key != key
            or owner.selected_plan is None or key not in owner.selected_plan.exact_keys):
        raise AuthorityUnavailable("final Action schema differs from the actual prepared schema head/absence")
    _require_method_locator_current_v3(owner); return key


def read_bound_method_borrowed_plan_v3(db, *, graph, issued, plan):
    """Return only the already prepared schema extension of the actual base plan."""
    from dataclasses import replace
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    owner = _method_active(db)
    if owner is None or type(owner) is not BorrowedMethodLearningReadV3:
        return False, None
    if owner.graph is not graph or owner.issued is not issued or owner.db is not db:
        raise AuthorityUnavailable("borrowed plan has another actual originating Work/issuer")
    if not owner.inputs_sealed:
        return False, None
    if type(plan) is not ProductionReadPlanV1:
        raise AuthorityUnavailable("exact actual borrowed base read plan required")
    owner.result._actual_v3()
    if _require_borrowed_issuance_v3(issued, graph) != owner.evidence:
        raise AuthorityUnavailable("borrowed base plan lost its original issued evidence")
    owner.require_current()
    if _artifact_borrowed_reader_v3(owner):combined=plan
    else:
        combined = ProductionReadPlanV1(plan.fixed_type_ids,
            tuple(sorted(set((*plan.exact_keys, *(v.key for v in owner.evidence.read_versions))), key=lambda key:key.token)),
            plan.source_roots, plan.required_original_refs)
    sealed = owner.selected_plan
    if ((combined.fixed_type_ids, combined.source_roots, combined.required_original_refs) !=
            (sealed.fixed_type_ids, sealed.source_roots, sealed.required_original_refs)):
        raise AuthorityUnavailable("borrowed base plan changed a fixed family, Source root or original input")
    if owner.operation_kind in ACTION_SCHEMA_LOCATOR_OPERATIONS_V3:
        locator = owner.action_schema_locator
        if (locator is None or not locator.complete or locator.reader is not owner
                or _ACTION_LOCATORS.get(locator) != locator._identity_v3()):
            raise AuthorityUnavailable("borrowed schema was not prepared by the actual completed locator")
        expected = tuple(sorted(set((*combined.exact_keys, locator.key)), key=lambda key:key.token))
        if sealed.exact_keys != expected:
            raise AuthorityUnavailable("borrowed sealed plan contains an unprepared or changed exact dependency")
        augmented = replace(plan, exact_keys=tuple(sorted(set((*plan.exact_keys, locator.key)), key=lambda key:key.token)))
    else:
        if combined != sealed:
            raise AuthorityUnavailable("borrowed operation changed its actual prepared base plan")
        augmented = plan
    return True, augmented


def _release_method_registered_payloads_v3(owner):
    """Invalidate this Work's actual partial/final registrations without scope reads."""
    from .artifact_task_choice_lookup_v3 import release_task_choice_catalogue_v3
    release_task_choice_catalogue_v3(owner)
    from .foreground_command_source_v3 import release_foreground_command_source_v3
    release_foreground_command_source_v3(owner)
    if type(owner)is BorrowedMethodLearningReadV3:
        from .personal_candidate_eligibility_v1 import release_borrowed_personal_eligibility_results_v3
        release_borrowed_personal_eligibility_results_v3(owner)
        from .artifact_preparation_parent_work_v3 import release_borrowed_artifact_preparation_parent_v3
        release_borrowed_artifact_preparation_parent_v3(owner)
        from .borrowed_habit_classification_v3 import release_borrowed_habit_metadata_v3
        from .ordinary_source_note_habit_classification_v3 import release_ordinary_source_note_habit_classification_v3
        from .artifact_frame_control_reads_v3 import release_artifact_model_source_frames_v3
        release_artifact_model_source_frames_v3(owner)
        release_ordinary_source_note_habit_classification_v3(owner)
        release_borrowed_habit_metadata_v3(owner)
        from .artifact_borrowed_source_v3 import release_artifact_borrowed_source_v3
        release_artifact_borrowed_source_v3(owner)
    from .current_beta1_source_read_v3 import beta1_source_operation_v3,release_current_beta1_source_work_v3
    if owner.work.kind=='current_habit_source_read_v3' or beta1_source_operation_v3(owner.operation_kind):release_current_beta1_source_work_v3(owner)
    if owner.operation_kind=="prepare_internal_life_interval_baseline":
        from .c04_encoding_context_original_v3 import release_prepared_life_encoding_inputs_v3
        release_prepared_life_encoding_inputs_v3(owner)
    if owner.operation_kind=="prepare_internal_life_numeric_drive":
        from .d06_life_numeric_drive_v1 import release_prepared_numeric_drive_inputs_v3
        release_prepared_numeric_drive_inputs_v3(owner)
    _GENERAL_METHOD_SOURCE_WRITE_PHASES_V1.pop(owner,None)
    source_tasks=_GENERAL_METHOD_SOURCE_TASKS_V1.pop(owner,{})
    for task in source_tasks.values():
        task.parser=task.cell=task.metadata=None;task.fragment=b""
    if type(owner)is _MethodLearningReadV3 and owner.operation_kind in (_NUMERIC_METADATA_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3):
        from .current_life_numeric_metadata_v1 import release_numeric_metadata_payloads_v1
        release_numeric_metadata_payloads_v1(owner)
    if type(owner)is _MethodLearningReadV3 and owner.operation_kind in (_GENERAL_OWNER_OPERATIONS_V1 | _NUMERIC_METADATA_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3):
        if owner.general_source_permission is not None:
            _GENERAL_METHOD_SOURCE_PROOFS_V1.pop(owner.general_source_permission,None)
            owner.general_source_permission=None
        if owner.general_owner_entry is not None:
            owner.general_owner_entry.release_v3();owner.general_owner_entry=None
    for column, record in tuple(_JSON_COLUMNS.items()):
        if record[0] is owner:
            _JSON_COLUMNS.pop(column, None)
            _GENERAL_METADATA_COLUMNS_V1.pop(column,None)
            column.nodes.clear(); column.scalar.clear(); column.text_parts.clear(); column.text_chars.clear()
            column.wire_parts.clear()
            column.value = column.frozen = column.wire = column.parser = column.cell = column.signature_state = column.canonical_stream = None
            column.fragment = b""
    for registry in (_INPUTS, _BORROWED_INPUTS, _PREFS, _ACTION_LOCATORS):
        for proof, record in tuple(registry.items()):
            if record[0] is owner:
                registry.pop(proof, None)
    for proof, record in tuple(_BUSINESS_RESULTS.items()):
        if record[0] is owner.work: _BUSINESS_RESULTS.pop(proof, None)


# A distinct post-CAS issuer: the prior read proof never acquires the new stamp.
_POST_COMMIT = ContextVar("sylanne_method_post_commit_v3", default=None)
_POST_COMMIT_PROOFS = WeakKeyDictionary()
_METHOD_ARTIFACT_POST_OPERATIONS_V3 = frozenset({"propose_artifact_draft_action", "propose_artifact_draft_phase_action_v2"})


def _method_post_commit_active_v3(db):
    proof = _POST_COMMIT.get()
    if proof is None: return None
    if type(proof) not in (PreparedMethodPostCommitV3, PreparedMethodForegroundScopePostCommitV3) or proof.db is not db:
        raise AuthorityUnavailable("actual Method successor Binder crossed its selected database")
    return proof.require_current_v3()


def _require_method_locator_current_v3(owner):
    post = _method_post_commit_active_v3(owner.db)
    if post is None: return owner.require_current()
    if type(post) is not PreparedMethodPostCommitV3 or post.owner is not owner:
        raise AuthorityUnavailable("Method locator requires its actual Action successor Work")
    return post


class PreparedMethodPostCommitV3:
    """Only the actual borrowed Artifact CAS may seal this current successor."""
    def __init__(self, issuer, db, graph, prior_frame, stage, actual_receipt, scope, issued, process_lease):
        from .domain_production_contracts_v1 import CurrentOperationFrameV1, StagedDomainOperationV1
        from .foreground_activity_issuance_v1 import _IssuedForegroundActivityV1
        from ..runtime_contracts import CommitReceipt
        from .foreground_command_post_frame_v3 import EMPTY_INPUT_DOMAINS_V3,require_foreground_input_post_witness_v3
        owner = _method_active(db)
        if (issuer is not _ISSUER or type(owner) is not BorrowedMethodLearningReadV3
                or owner.graph is not graph or not owner.inputs_sealed or not owner.business_started
                or owner.business_completed or owner.operation_kind not in (_METHOD_ARTIFACT_POST_OPERATIONS_V3 | frozenset(EMPTY_INPUT_DOMAINS_V3))
                or type(prior_frame) is not CurrentOperationFrameV1 or type(stage) is not StagedDomainOperationV1
                or type(actual_receipt) is not CommitReceipt or type(issued) is not _IssuedForegroundActivityV1
                or issued is not owner.issued or scope is not issued.scope or not db.in_transaction
                or not owner.store._lock._is_owned()):
            raise AuthorityUnavailable("actual same-transaction borrowed Artifact CAS successor required")
        writer = require_foreground_input_post_witness_v3(owner,db,graph,prior_frame,stage,actual_receipt,scope,issued,process_lease)
        empty_input = stage.operation_kind in EMPTY_INPUT_DOMAINS_V3
        if empty_input and writer is None:
            raise AuthorityUnavailable('Input successor requires its actual captured W01 writer')
        owner.inventory._actual()
        if writer is None:owner.result._actual_v3()
        owner.work._require_invocation(graph)
        identity = prior_frame.envelope.identity
        if (stage.coverage != "complete" or stage.domain != (EMPTY_INPUT_DOMAINS_V3[stage.operation_kind] if empty_input else "d08") or stage.operation_kind != owner.operation_kind
                or stage.operation_id != owner.operation_id or stage.namespace != owner.namespace
                or identity.operation_id != owner.operation_id or stage.activity_id != identity.activity_id
                or actual_receipt.status != "committed" or actual_receipt.operation_id != stage.operation_id
                or (actual_receipt.activity_id, actual_receipt.effect_id) != (identity.activity_id, identity.effect_id)
                or stage.read_versions != (prior_frame.envelope.version_guard.read_versions if writer is not None else prior_frame.snapshot.versions)
                or actual_receipt.read_versions != prior_frame.envelope.version_guard.read_versions
                or prior_frame.owner_guard != owner.material_owner_guard
                or (prior_frame.envelope.version_guard.access_epoch, prior_frame.envelope.version_guard.delete_epoch)
                    != owner.expected_rights
                or owner.runtime._active_foreground_issuance_v1 is not issued
                or owner.runtime._active_foreground_process_lease_v1 is not process_lease):
            raise AuthorityUnavailable("Artifact successor changed the actual stage/receipt/Owner/process lease")
        self.writer_capture = writer
        self.owner, self.db, self.graph, self.namespace = owner, db, graph, owner.namespace
        self.prior_frame, self.stage, self.receipt = prior_frame, stage, actual_receipt
        self.scope, self.issued, self.process_lease = scope, issued, process_lease
        self.atoms, self.digests, self.wires, self.head_metadata, self.histories = {}, {}, {}, {}, {}
        self.coverage, self.snapshot, self.after_stamp = None, None, None
        self.point_rows = {}
        self.complete = False
        self._seal_v3()
        self.frozen_values = MappingProxyType({key: _freeze_value_v3(atom.value) for key, atom in self.atoms.items()})
        owner.operation.retain(_heap(self.frozen_values) + 4096)
        for name in ("atoms", "digests", "wires", "head_metadata", "histories", "point_rows"):
            setattr(self, name, MappingProxyType(getattr(self, name)))
        self.complete = True
        _POST_COMMIT_PROOFS[self] = self._identity_v3()

    def _identity_v3(self):
        return (self.writer_capture,self.guard_versions,self.owner, self.db, self.graph, self.namespace, self.prior_frame, self.stage, self.receipt,
            self.scope, self.issued, self.process_lease, self.after_stamp, self.snapshot, self.coverage,
            self.atoms, self.digests, self.wires, self.head_metadata, self.histories, self.point_rows, self.frozen_values, self.complete)

    def _small_v3(self, table, columns, where, parameters):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        with runtime_storage_quantum_v3(self.db) as meter:
            return _runtime_bounded_fixed_row_v3(self.db, meter, table, columns, where, parameters)

    def _prior_column_v3(self, atom):
        owner = self.owner
        column = owner.census_columns.get(atom.key.token)
        if column is None:
            inventory = owner.inventories.get(atom.key.type_name)
            if atom.revision == 0 and (atom.key.type_name in METHOD_LEARNING_TYPES_V3 and owner.inventory_sealed
                    or inventory is not None and inventory.complete and not any(row.key == atom.key for row in inventory.rows)):
                return None
            request = ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona"),
                (atom.key.token, *self.namespace.as_tuple))
            point = owner.points.get(request)
            if point is None or not point.complete:
                raise AuthorityUnavailable("successor head lacks its actual selected head/absence EOF")
            column = point.values.get("value")
            metadata = point.small
            if atom.revision == 0:
                if point.metadata is not None: raise AuthorityUnavailable("selected head was not actually absent")
                return None
            if (metadata["revision"], bool(metadata["valid"])) != (atom.revision, atom.valid):
                raise AuthorityUnavailable("selected head revision/valid changed before successor")
        else:
            if owner.census_versions[atom.key.token] != (atom.revision, atom.valid):
                raise AuthorityUnavailable("successor census revision/valid differs")
        if (type(column) is not MethodJSONColumnV3 or not column.complete or column.canonical_digest is None
                or _JSON_COLUMNS.get(column) is None or column.owner is not owner
                or _freeze_value_v3(atom.value) != column.frozen):
            raise AuthorityUnavailable("successor needs the actual selected canonical head EOF")
        column._actual()
        return column

    def _seal_v3(self):
        import json
        from hashlib import sha256
        from ..contracts import Event, Scope
        from ..graph_types import GraphAtom, GraphSnapshot, GraphVersion
        from ..runtime_contracts import QueryEpoch, canonical_serialize
        from .domain_production_contracts_v1 import ProductionQueryCoverageV1
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3, read_runtime_cell_origin_v3
        from ..segmented_sql_cell_v1 import MAX_SEGMENT_BYTES
        from .foreground_command_post_frame_v3 import EMPTY_INPUT_DOMAINS_V3,source_bound_successor_guard_v3
        receipt, frame, owner = self.receipt, self.prior_frame, self.owner
        empty_input = self.stage.operation_kind in EMPTY_INPUT_DOMAINS_V3
        self.after_stamp = self.graph._v2_graph_stamp(self.namespace)
        if (self.after_stamp[0].graph_revision != owner.graph_stamp[0].graph_revision + 1
                or len(receipt.invalidated_epochs) != 1 or receipt.invalidated_epochs[0] != self.after_stamp[1]
                or self.after_stamp[1].revision != owner.graph_stamp[1].revision + 1):
            raise AuthorityUnavailable("Artifact successor lacks the actual one-commit after stamp/epoch")
        bundle = self._small_v3("graph_bundle_operations", ("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"),
            "bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, receipt.operation_id))
        if bundle is None or bundle[:4] != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
            raise AuthorityUnavailable("Artifact successor receipt is not the actual committed bundle")
        data = json.loads(bundle[4])
        if (data.get("commit_seq"), tuple(data.get("ledger_refs", ())), tuple(data.get("outbox_refs", ()))) != (
                receipt.commit_seq, receipt.ledger_refs, receipt.outbox_refs):
            raise AuthorityUnavailable("Artifact successor committed receipt JSON differs")
        from .domain_production_originals_v1 import TABLE
        original = self._small_v3(TABLE,
            ("domain", "operation_kind", "request_digest", "original_digest", "bundle_digest"),
            "bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, receipt.operation_id))
        if original != (self.stage.domain, self.stage.operation_kind, self.stage.request_digest,
                self.stage.original_digest, receipt.operation_digest):
            raise AuthorityUnavailable("Artifact successor stage is not its actual adopted producer")
        event_scope = (*self.namespace.as_tuple, receipt.activity_id, receipt.operation_id)
        event = self._small_v3("graph_events", ("digest", "reads", "epoch_reads", "revisions", "invalidated", "epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?", event_scope)
        expected_event = Event(Scope(*self.namespace.as_tuple, receipt.activity_id), receipt.operation_id,
            frame.envelope.source_qualification.learned_at, "domain_bundle", {"bundle_digest": receipt.operation_digest})
        if (event is None or event[0] != expected_event.digest
                or json.loads(event[1]) != [[v.key.token, v.revision] for v in receipt.read_versions]
                or json.loads(event[2]) != []
                or json.loads(event[3]) != [[v.key.token, v.revision] for v in receipt.write_versions]
                or event[5] != self.after_stamp[1].revision):
            raise AuthorityUnavailable("Artifact successor lost the exact committed Graph event")
        writes = {write.key: write for proposal in self.stage.proposals for write in proposal.typed_writes}
        if empty_input:
            if writes or receipt.write_versions or json.loads(event[3]) != [] or json.loads(event[4]) != []:
                raise AuthorityUnavailable('Input successor cannot own a Graph write or invalidate any prior input')
        elif (len(writes) != 3 or len(writes) != sum(len(proposal.typed_writes) for proposal in self.stage.proposals)
                or {key.type_name for key in writes} != {"d08.action_intent.v1", "d08.action_schema.v1", "d08.action_cancellation.v1"}
                or len(writes) != len(receipt.write_versions) or set(writes) != {v.key for v in receipt.write_versions}):
            raise AuthorityUnavailable("Artifact successor write versions differ from the actual stage")
        prior = {atom.key: atom for atom in frame.snapshot.atoms}
        if not set(writes) <= set(prior):
            raise AuthorityUnavailable("Artifact successor changed a key outside the actual original selected head/absence set")
        for key in set(prior) | set(writes):
            if NamespaceId.from_key(key) != self.namespace:
                raise AuthorityUnavailable("Artifact successor crossed namespace")
            current = self._small_v3("graph_atoms", ("revision", "valid", "value_cell_id"), "token=? AND bot=? AND persona=?",
                (key.token, *self.namespace.as_tuple))
            self.head_metadata[key] = current
            if key not in writes:
                atom = prior[key]; column = self._prior_column_v3(atom)
                if atom.revision == 0:
                    if current is not None: raise AuthorityUnavailable("successor selected absence became a head")
                    self.atoms[key] = atom; continue
                if current != (atom.revision, int(atom.valid), column.cell.cell_id):
                    raise AuthorityUnavailable("successor unchanged selected head/cell was changed or invalidated")
                self.atoms[key], self.digests[key], self.wires[key] = atom, column.canonical_digest, column.wire
            else:
                version = next(v for v in receipt.write_versions if v.key == key)
                if current is None or current[:2] != (version.revision, 1):
                    raise AuthorityUnavailable("successor changed head differs from actual committed revision")
                with runtime_storage_quantum_v3(self.db) as meter:
                    cell = begin_runtime_cell_read_v3(self.db, current[2], erasure_owner_ref=key.token)
                    # The two Artifact writes contain small Action/schema/cancel contracts, never Source bodies.
                    if cell.header[3] > MAX_SEGMENT_BYTES or cell.header[4] != 1:
                        raise AuthorityUnavailable("Artifact post-CAS write needs a registered continuation beyond one actual segment")
                    origin = read_runtime_cell_origin_v3(self.db, current[2], header=cell.header, meter=meter)
                    normalized = owner.store._registry.validate(key, writes[key].value)
                    wire = canonical_serialize(normalized)
                    digest = sha256(wire.encode("utf8")).hexdigest()
                    raw = cell.read_fragment(meter=meter)
                    if (origin is None or origin["operation_id"] != receipt.operation_id or origin["event_digest"] != event[0]
                            or origin["locator"] != {"table": "graph_atoms", "token": key.token, "revision": version.revision}
                            or raw != wire.encode("utf8") or cell.read_fragment(meter=meter) is not None or cell.finish(meter=meter) != digest):
                        raise AuthorityUnavailable("Artifact changed value lacks its actual committed canonical cell EOF")
                    atom = GraphAtom(key, version.revision, normalized, True)
                self.atoms[key], self.digests[key], self.wires[key] = atom, digest, wire
            self._seal_history_v3(self.atoms[key], current[2], event_scope if key in writes else None)
        self._seal_points_v3()
        # These two projections are the actual newly committed receipt, never a newly read business dependency.
        bundle_key = (*self.namespace.as_tuple, receipt.operation_id)
        self.point_rows[("graph_bundle_operations", ("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"),
            ("bot", "persona", "operation_id"), bundle_key)] = bundle
        self.point_rows[("graph_bundle_operations", ("digest", "receipt_json", "commit_seq"),
            ("bot", "persona", "operation_id"), bundle_key)] = (bundle[0], bundle[4], bundle[3])
        self.point_rows[("graph_events", ("reads", "revisions", "epoch_revision"),
            ("bot", "persona", "session", "event_id"), event_scope)] = (event[1], event[3], event[5])
        pages = []
        for page in frame.query_coverage:
            versions = self._query_versions_v3(page.type_id, frame.limits.max_query_rows)
            if len(versions) > frame.limits.max_query_rows or any(v.key not in self.atoms for v in versions):
                raise AuthorityUnavailable("Artifact successor query is outside the actual selected/changed closure")
            if any(self.atoms[v.key].revision != v.revision for v in versions):
                raise AuthorityUnavailable("Artifact successor query members differ from current heads")
            pages.append(ProductionQueryCoverageV1(QueryEpoch(self.namespace, page.epoch.scope_ref,
                self.after_stamp[1].revision), page.type_id, versions, True, None))
        self.coverage = tuple(pages)
        self.snapshot = GraphSnapshot(tuple(self.atoms[atom.key] for atom in frame.snapshot.atoms),
            (self.after_stamp[1],), frame.snapshot.ingress_receipts, frame.snapshot.scene_proofs)
        self.guard_versions = (source_bound_successor_guard_v3(self) if self.writer_capture is not None else self.snapshot.versions)
        owner.operation.retain(_heap((self.head_metadata, self.histories, self.point_rows, self.coverage,self.guard_versions)) + 4096)

    def _seal_history_v3(self, atom, cell_id, expected_event):
        row = self._small_v3("graph_history", ("valid", "value_cell_id", "event_bot", "event_persona", "event_session", "event_id"),
            "token=? AND revision=? AND event_bot=? AND event_persona=?", (atom.key.token, atom.revision, *self.namespace.as_tuple))
        if (row is None or row[0] != int(atom.valid) or tuple(row[2:4]) != self.namespace.as_tuple
                or expected_event is not None and (row[1] != cell_id or tuple(row[2:]) != expected_event)):
            raise AuthorityUnavailable("Artifact successor history/cell/full event key differs")
        if expected_event is None and row[1] != cell_id:
            digest, frozen, history_cell = _prepared_method_history_canonical_v3(self.owner, atom.key, atom.revision)
            if (history_cell != row[1] or digest != self.digests[atom.key] or frozen != _freeze_value_v3(atom.value)):
                raise AuthorityUnavailable("unchanged successor history independent canonical EOF differs")
        self.histories[(atom.key.token, atom.revision)] = (row, MappingProxyType(dict(token=atom.key.token, revision=atom.revision,
            valid=int(atom.valid), value=self.wires[atom.key], event_bot=row[2], event_persona=row[3], event_session=row[4], event_id=row[5])))

    def _seal_points_v3(self):
        from .foreground_command_writer_outputs_v3 import foreground_writer_owns_output_point_v3
        changed = {version.key.token for version in self.receipt.write_versions}
        for request, task in (*self.owner.points.items(), *self.owner.attachments.items()):
            if self.writer_capture is not None and foreground_writer_owns_output_point_v3(self.db,request):continue
            if not task.complete: raise AuthorityUnavailable("Artifact successor has unfinished selected originals")
            if task.table == "graph_atoms" and task.key[0] in changed: continue
            if task.table == "graph_history" and task.key[:2] in {(v.key.token, v.revision) for v in self.receipt.write_versions}: continue
            metadata = self._small_v3(task.table, task.metadata_columns, " AND ".join(name + "=?" for name in task.key_columns), task.key)
            if metadata != task.metadata: raise AuthorityUnavailable("Artifact successor selected original metadata changed")
            self.point_rows[request] = None if task.row is None else tuple(
                value.wire if type(value) is MethodJSONColumnV3 else value for value in task.row)
        budget = self.owner.budget_task
        if budget is not None:
            with runtime_storage_quantum_v3(self.db) as meter: budget.require_metadata_v3(meter)

    def _query_versions_v3(self, type_id, limit):
        from ..graph_types import GraphVersion
        after, versions = "", []
        for _ in range(limit + 1):
            row = self._small_v3("graph_atoms", ("token", "revision"),
                "bot=? AND persona=? AND type_name=? AND token>? ORDER BY token", (*self.namespace.as_tuple, type_id, after))
            if row is None: break
            versions.append(GraphVersion(AtomKey.from_token(row[0]), row[1])); after = row[0]
        return tuple(versions)

    def require_current_v3(self):
        owner = self.owner
        if (_POST_COMMIT_PROOFS.get(self) != self._identity_v3() or not self.complete or _POST_COMMIT.get() is not self
                or owner not in _READERS or owner.operation.closed or self.db is not owner.db or self.graph is not owner.graph
                or not self.db.in_transaction or not owner.store._lock._is_owned() or owner.work.state is not owner
                or owner.work.operation is not owner.operation or owner.work.coordinator is not self.graph
                or runtime_storage_v3(self.db) is not owner.operation.handle
                or owner.runtime._active_foreground_issuance_v1 is not self.issued
                or owner.runtime._active_foreground_process_lease_v1 is not self.process_lease
                or self.graph._v2_graph_stamp(self.namespace) != self.after_stamp
                or owner.store._registry.catalogue_hash != owner.catalogue_hash):
            raise AuthorityUnavailable("actual Artifact successor Work/storage/transaction/after stamp is not current")
        owner.work._require_invocation(self.graph)
        if _require_borrowed_issuance_v3(self.issued, self.graph) != owner.evidence:
            raise AuthorityUnavailable("Artifact successor lost its actual original issued evidence")
        with runtime_storage_quantum_v3(self.db) as meter:
            if owner._epochs(meter) != owner.authority_epochs: raise AuthorityUnavailable("Artifact successor access/deletion guards changed")
            grant = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*self.namespace.as_tuple, owner_grant_key(*self.namespace.as_tuple).token))
        if grant != owner.owner_head: raise AuthorityUnavailable("Artifact successor upstream Owner changed")
        return self

    def head_v3(self, key):
        self.require_current_v3()
        if NamespaceId.from_key(key) != self.namespace or key not in self.atoms:
            raise AuthorityUnavailable("Artifact successor cannot add an unprepared head or absence")
        current = self._small_v3("graph_atoms", ("revision", "valid", "value_cell_id"),
            "token=? AND bot=? AND persona=?", (key.token, *self.namespace.as_tuple))
        if (current != self.head_metadata[key] or _freeze_value_v3(self.atoms[key].value) != self.frozen_values[key]):
            raise AuthorityUnavailable("Artifact successor current head/cell/canonical value changed")
        return self.atoms[key]

    def atom_digest_v3(self, atom):
        actual = self.head_v3(atom.key)
        if actual != atom or atom.key not in self.digests:
            raise AuthorityUnavailable("Artifact successor digest needs its actual positive canonical atom EOF")
        return self.digests[atom.key]

    def snapshot_and_coverage_v3(self, frame):
        self.require_current_v3()
        if frame is not self.prior_frame: raise AuthorityUnavailable("Artifact successor post-frame is not its exact original frame")
        for atom in self.snapshot.atoms: self.head_v3(atom.key)
        for page in self.coverage:
            if self._query_versions_v3(page.type_id, frame.limits.max_query_rows) != page.row_versions:
                raise AuthorityUnavailable("Artifact successor complete query metadata changed")
        return self.snapshot, self.coverage

    def attachment_v3(self, table, columns, key_columns, key):
        self.require_current_v3()
        if (table == "graph_bundle_operations" and columns == ("digest", "receipt_json", "commit_seq")
                and key_columns == ("bot", "persona", "operation_id")
                and (table, columns, key_columns, key) not in self.point_rows):
            row = self.attachment_v3(table, ("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"), key_columns, key)
            return None if row is None else (row[0], row[4], row[3])
        if len(key_columns) != len(key) or len(set(key_columns)) != len(key_columns):
            raise AuthorityUnavailable("Artifact successor requires an exact registered full point key")
        criteria = dict(zip(key_columns, key))
        if table == "graph_atoms":
            if (tuple(key_columns) not in {("token",), ("token", "bot", "persona")}
                    or not set(columns) <= {"token", "revision", "value", "valid"}):
                raise AuthorityUnavailable("Artifact successor head projection is not registered")
            atom = self.head_v3(AtomKey.from_token(criteria["token"]))
            if len(key) == 3 and tuple(key[1:]) != self.namespace.as_tuple: raise AuthorityUnavailable("Artifact successor head full key crossed namespace")
            if atom.revision == 0: return None
            values = dict(token=atom.key.token, revision=atom.revision, value=self.wires[atom.key], valid=int(atom.valid))
            return tuple(values[name] for name in columns)
        if table == "graph_history":
            allowed = {"token", "revision", "value", "valid", "event_id", "event_bot", "event_persona", "event_session"}
            if (not set(columns) <= allowed or not set(key_columns) <= allowed - {"value", "valid"}
                    or not {"token", "revision"} <= set(criteria)):
                raise AuthorityUnavailable("Artifact successor history requires its original key/revision")
            identity = (criteria["token"], criteria["revision"])
            found = self.histories.get(identity)
            if found is None:
                request = (table, columns, key_columns, key)
                if request not in self.point_rows: raise AuthorityUnavailable("Artifact successor history is outside actual selected originals")
                return self.point_rows[request]
            metadata, values = found
            current = self._small_v3("graph_history", ("valid", "value_cell_id", "event_bot", "event_persona", "event_session", "event_id"),
                "token=? AND revision=? AND event_bot=? AND event_persona=?", (*identity, *self.namespace.as_tuple))
            if current != metadata: raise AuthorityUnavailable("Artifact successor history full event/cell identity changed")
            if any(values[name] != value for name, value in criteria.items()): return None
            return tuple(values[name] for name in columns)
        request = (table, columns, key_columns, key)
        if request not in self.point_rows: raise AuthorityUnavailable("Artifact successor original is outside the actual prepared point closure")
        task = self.owner.points.get(request) or self.owner.attachments.get(request)
        if task is not None:
            current = self._small_v3(table, task.metadata_columns, " AND ".join(name + "=?" for name in key_columns), key)
            if current != task.metadata: raise AuthorityUnavailable("Artifact successor original current metadata changed")
        elif table in {"graph_bundle_operations", "graph_events"}:
            current = self._small_v3(table, columns, " AND ".join(name + "=?" for name in key_columns), key)
            if current != self.point_rows[request]: raise AuthorityUnavailable("Artifact successor actual receipt/event metadata changed")
        return self.point_rows[request]

    def release_payload_v3(self):
        from .foreground_command_post_frame_v3 import release_foreground_command_post_frames_v3
        release_foreground_command_post_frames_v3(self)
        _POST_COMMIT_PROOFS.pop(self, None)
        self.writer_capture=self.guard_versions=None
        self.atoms = self.digests = self.wires = self.head_metadata = self.histories = self.point_rows = self.frozen_values = None
        self.snapshot = self.coverage = None; self.complete = False


@contextmanager
def bind_method_post_commit_v3(db, graph, prior_frame, stage, actual_receipt, scope, issued, process_lease):
    if _POST_COMMIT.get() is not None: raise AuthorityUnavailable("Artifact successor Binder cannot be nested")
    proof = PreparedMethodPostCommitV3(_ISSUER, db, graph, prior_frame, stage, actual_receipt, scope, issued, process_lease)
    token = _POST_COMMIT.set(proof)
    try:
        proof.require_current_v3()
        yield proof
    finally:
        _POST_COMMIT.reset(token); proof.release_payload_v3()


def read_bound_method_post_commit_head_v3(db, *, namespace, key):
    proof = _method_post_commit_active_v3(db)
    if proof is None: return False, None
    if namespace != proof.namespace: raise AuthorityUnavailable("Artifact successor head crossed namespace")
    return True, proof.head_v3(key)


def read_bound_method_graph_atom_v3(db, namespace, key):
    owner = _method_active(db)
    if owner is None: return False, None
    return True, method_graph_head_v3(db, namespace, key)


def read_bound_method_post_commit_adoption_v3(db, atom):
    proof = _method_post_commit_active_v3(db)
    if proof is None: return False, None
    if type(proof) is not PreparedMethodPostCommitV3:
        raise AuthorityUnavailable("model foreground scope successor grants no adopted history read")
    proof.atom_digest_v3(atom)
    if not atom.valid: raise AuthorityUnavailable("Artifact successor adoption requires a valid current atom")
    row = proof.attachment_v3("graph_history", ("event_id", "valid"), ("token", "revision"), (atom.key.token, atom.revision))
    if row is None or row[1] != 1: raise AuthorityUnavailable("Artifact successor atom has no actual adopted history EOF")
    return True, row[0]


def method_post_commit_atom_digest_v3(db, atom):
    from ..runtime_contracts import canonical_digest
    from .foreground_command_writer_outputs_v3 import foreground_writer_atom_digest_v3
    handled,digest=foreground_writer_atom_digest_v3(db,atom)
    if handled:return digest
    proof = _method_post_commit_active_v3(db)
    if proof is not None: return proof.atom_digest_v3(atom)
    owner = _method_active(db)
    if owner is None: return canonical_digest(atom.value)
    actual = method_graph_head_v3(db, owner.namespace, atom.key)
    if actual != atom or atom.revision < 1:
        raise AuthorityUnavailable("Method atom digest needs its actual current selected positive head")
    column = owner.census_columns.get(atom.key.token)
    if column is None:
        request = ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona"),
            (atom.key.token, *owner.namespace.as_tuple))
        column = owner.points[request].values["value"]
    if (type(column) is not MethodJSONColumnV3 or not column.complete or column.canonical_digest is None
            or column.owner is not owner or _freeze_value_v3(atom.value) != column.frozen):
        raise AuthorityUnavailable("Method atom digest lacks its actual canonical head EOF")
    column._actual(); owner.require_current()
    return column.canonical_digest


def method_current_or_post_parameter_digest_v3(db, namespace, operation_id, values):
    from ..runtime_contracts import canonical_digest
    proof = _method_post_commit_active_v3(db)
    owner = _method_active(db)
    if proof is not None or owner is not None:
        return current_action_parameter_digest_v3(db, namespace, operation_id, values)
    return canonical_digest(values)


def read_bound_method_adoption_v3(db, atom):
    handled, event_id = read_bound_method_post_commit_adoption_v3(db, atom)
    if handled: return handled, event_id
    owner = _method_active(db)
    if owner is None: return False, None
    actual = method_graph_head_v3(db, owner.namespace, atom.key)
    if actual != atom or not atom.valid or atom.revision < 1:
        raise AuthorityUnavailable("Method adoption needs the actual current positive selected head")
    column = owner.census_columns.get(atom.key.token)
    if column is None:
        request = ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona"),
            (atom.key.token, *owner.namespace.as_tuple))
        column = owner.points[request].values["value"]
    if (type(column) is not MethodJSONColumnV3 or not column.complete or column.canonical_digest is None
            or _freeze_value_v3(atom.value) != column.frozen):
        raise AuthorityUnavailable("Method adoption lacks its actual canonical head EOF")
    _, row = read_bound_method_learning_attachment_v3(db, table="graph_history", columns=_HISTORY_COLUMNS,
        key_columns=("token", "revision"), key=(atom.key.token, atom.revision))
    history_digest, history_frozen, history_cell = _prepared_method_history_canonical_v3(owner, atom.key, atom.revision)
    if history_digest != column.canonical_digest or history_frozen != column.frozen:
        raise AuthorityUnavailable("Method adopted history canonical EOF differs from the actual current head EOF")
    with runtime_storage_quantum_v3(db) as meter:
        owner.require_current(meter=meter)
        metadata = meter.read_fixed_row(db, "graph_history", ("valid", "value_cell_id", "event_bot", "event_persona", "event_id"),
            "token=? AND revision=? AND event_bot=? AND event_persona=?", (atom.key.token, atom.revision, *owner.namespace.as_tuple))
    if (row is None or metadata != (1, history_cell, *owner.namespace.as_tuple, row[0]) or row[2] != 1):
        raise AuthorityUnavailable("Method adoption history is not its actual canonical history cell")
    return True, row[0]


def _prepared_method_history_canonical_v3(owner, key, revision):
    request = ("graph_history", _HISTORY_COLUMNS, ("token", "revision"), (key.token, revision))
    point = owner.points.get(request)
    if point is not None and point.complete:
        original = point.values.get("value")
        if (type(original) is not MethodJSONColumnV3 or not original.complete or original.canonical_digest is None
                or original.owner is not owner or original.cell is None):
            raise AuthorityUnavailable("actual Method selected history canonical column EOF required")
        original._actual()
        return original.canonical_digest, original.frozen, original.cell.cell_id
    attachment = owner.attachments.get(request)
    if attachment is None or not attachment.complete:
        raise AuthorityUnavailable("actual Method prepared history canonical EOF required")
    from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    original = attachment.json_columns.get("value")
    if type(original) is not DispatchOriginalJSONReadV3 or original.cell is None:
        raise AuthorityUnavailable("actual Method mechanical history column required")
    value = original.require_v3(owner)
    return original.sha256, _freeze_value_v3(value), original.cell.cell_id


_METHOD_FOREGROUND_SCOPE_POST_OPERATIONS_V3 = frozenset({"prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2"})
_FOREGROUND_SCOPE_POST_PROOFS = WeakKeyDictionary()


class PreparedMethodForegroundScopePostCommitV3:
    """A model job CAS exposes only its unchanged Source and registered root."""
    def __init__(self, issuer, db, graph, prior_frame, stage, actual_receipt, scope, issued, process_lease):
        import json
        from .d11_artifact_draft_model_v1 import ArtifactDraftModelStageV2
        from .domain_production_contracts_v1 import CurrentOperationFrameV1, StagedDomainOperationV1
        from .domain_production_commit_v1 import _members, foreground_domain_finish_digest_v1
        from .foreground_activity_issuance_v1 import _IssuedForegroundActivityV1
        from .domain_production_originals_v1 import TABLE
        from ..authority_service.v2_contract import to_wire
        from ..contracts import Event, Scope, canonical_json
        from ..runtime_contracts import CommitReceipt
        owner = _method_active(db)
        if (issuer is not _ISSUER or type(owner) is not BorrowedMethodLearningReadV3
                or owner.graph is not graph or owner.db is not db or not owner.inputs_sealed
                or not owner.business_started or owner.business_completed
                or owner.operation_kind not in _METHOD_FOREGROUND_SCOPE_POST_OPERATIONS_V3
                or type(stage) is not ArtifactDraftModelStageV2 or stage.frame is not prior_frame
                or type(stage.stage) is not StagedDomainOperationV1 or type(prior_frame) is not CurrentOperationFrameV1
                or type(actual_receipt) is not CommitReceipt or type(issued) is not _IssuedForegroundActivityV1
                or issued is not owner.issued or scope is not issued.scope or not db.in_transaction
                or not owner.store._lock._is_owned()):
            raise AuthorityUnavailable("actual borrowed model-stage foreground scope CAS required")
        owner.inventory._actual(); owner.result._actual_v3(); owner.work._require_invocation(graph)
        primary, proposals, experiences, settlements, paid_costs = _members(stage)
        identity = prior_frame.envelope.identity
        evidence = _require_borrowed_issuance_v3(issued, graph)
        from .artifact_frame_control_reads_v3 import require_artifact_model_post_commit_readsets_v3
        require_artifact_model_post_commit_readsets_v3(owner,prior_frame,primary,actual_receipt)
        if (primary is not stage.stage or primary.domain != "d11" or primary.coverage != "complete"
                or primary.operation_kind != owner.operation_kind or primary.operation_id != owner.operation_id
                or primary.namespace != owner.namespace or primary.activity_id != identity.activity_id
                or identity.operation_id != owner.operation_id or actual_receipt.status != "committed"
                or (actual_receipt.operation_id, actual_receipt.activity_id, actual_receipt.effect_id)
                    != (identity.operation_id, identity.activity_id, identity.effect_id)
                or primary.read_versions != prior_frame.envelope.version_guard.read_versions
                or actual_receipt.read_versions != prior_frame.envelope.version_guard.read_versions
                or prior_frame.owner_guard != owner.material_owner_guard or evidence != owner.evidence
                or (prior_frame.envelope.version_guard.access_epoch, prior_frame.envelope.version_guard.delete_epoch) != owner.expected_rights
                or owner.runtime._active_foreground_issuance_v1 is not issued
                or owner.runtime._active_foreground_process_lease_v1 is not process_lease
                or primary.jobs or experiences or settlements or paid_costs):
            raise AuthorityUnavailable("model foreground scope changed its actual primary/receipt/Owner/process lease")
        self.owner, self.db, self.graph, self.namespace = owner, db, graph, owner.namespace
        self.prior_frame, self.stage, self.receipt, self.scope = prior_frame, stage, actual_receipt, scope
        self.issued, self.process_lease = issued, process_lease
        self.complete = False
        self.after_stamp = graph._v2_graph_stamp(self.namespace)
        fence = self._small_v3("graph_bundle_fences_v2", ("digest", "permit_json", "pre_graph_revision", "pre_graph_epoch",
            "post_graph_revision", "post_graph_epoch", "finish_request_id", "finish_request_digest"),
            "bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, actual_receipt.operation_id))
        expected_fence = (actual_receipt.operation_digest, canonical_json(to_wire(scope.permit)),
            owner.graph_stamp[0].graph_revision, owner.graph_stamp[1].revision,
            self.after_stamp[0].graph_revision, self.after_stamp[1].revision, "finish:" + scope.operation_id,
            foreground_domain_finish_digest_v1(evidence.request, scope.permit))
        if (fence != expected_fence or self.after_stamp[0].graph_revision != owner.graph_stamp[0].graph_revision + 1
                or self.after_stamp[1].revision != owner.graph_stamp[1].revision + 1
                or actual_receipt.invalidated_epochs != (self.after_stamp[1],)):
            raise AuthorityUnavailable("model scope successor lacks its actual original permit/pre-post Graph fence")
        bundle = self._small_v3("graph_bundle_operations", ("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"),
            "bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, actual_receipt.operation_id))
        if bundle is None or bundle[:4] != (actual_receipt.operation_digest, identity.activity_id, identity.effect_id, actual_receipt.commit_seq):
            raise AuthorityUnavailable("model scope successor receipt is not its actual adopted bundle")
        data = json.loads(bundle[4])
        if (data.get("commit_seq"), tuple(data.get("ledger_refs", ())), tuple(data.get("outbox_refs", ()))) != (
                actual_receipt.commit_seq, actual_receipt.ledger_refs, actual_receipt.outbox_refs):
            raise AuthorityUnavailable("model scope successor receipt JSON differs")
        original = self._small_v3(TABLE, ("domain", "operation_kind", "request_digest", "original_digest", "bundle_digest"),
            "bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, actual_receipt.operation_id))
        if original != ("d11", owner.operation_kind, primary.request_digest, primary.original_digest, actual_receipt.operation_digest):
            raise AuthorityUnavailable("model scope successor is not its actual adopted primary original")
        event_scope = (*self.namespace.as_tuple, identity.activity_id, identity.operation_id)
        event = self._small_v3("graph_events", ("digest", "reads", "epoch_reads", "revisions", "epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?", event_scope)
        expected_event = Event(Scope(*self.namespace.as_tuple, identity.activity_id), identity.operation_id,
            prior_frame.envelope.source_qualification.learned_at, "domain_bundle", {"bundle_digest": actual_receipt.operation_digest})
        if (event is None or event[0] != expected_event.digest or json.loads(event[1]) != [[v.key.token, v.revision] for v in actual_receipt.read_versions]
                or json.loads(event[2]) != [] or json.loads(event[3]) != [[v.key.token, v.revision] for v in actual_receipt.write_versions]
                or event[4] != self.after_stamp[1].revision):
            raise AuthorityUnavailable("model scope successor Graph event/read/write receipt differs")
        writes = tuple(write for proposal in proposals for write in proposal.typed_writes)
        if (len({write.key for write in writes}) != len(writes) or len(writes) != len(actual_receipt.write_versions)
                or {write.key for write in writes} != {v.key for v in actual_receipt.write_versions}
                or any(write.key.type_name != "runtime.job" for write in writes)):
            raise AuthorityUnavailable("model scope successor contains a write outside its actual model/cycle job members")
        changed = {v.key: v for v in actual_receipt.write_versions}
        for key, version in changed.items():
            before = prior_frame.snapshot.get(key)
            row = self._small_v3("graph_atoms", ("revision", "valid", "value_cell_id"),
                "token=? AND bot=? AND persona=?", (key.token, *self.namespace.as_tuple))
            if before is None or row is None or row[:2] != (version.revision, 1) or version.revision != before.revision + 1:
                raise AuthorityUnavailable("model job receipt lacks its actual selected before/current revision")
        source_key = AtomKey.from_token(evidence.request.plan_source_ref)
        root = evidence.root_capability
        if (root is None or source_key.type_name != "memory.source" or NamespaceId.from_key(source_key) != self.namespace
                or source_key in changed):
            raise AuthorityUnavailable("model foreground scope has no unchanged actual Source/registered root")
        self.source = prior_frame.snapshot.get(source_key)
        if self.source is None or not self.source.valid or self.source.revision < 1:
            raise AuthorityUnavailable("model scope Source was not in its actual qualified original frame")
        self.source_column = self._prior_column_v3(self.source)
        self.source_frozen, self.source_digest = self.source_column.frozen, self.source_column.canonical_digest
        guards = {}
        for atom in prior_frame.snapshot.atoms:
            if atom.key in changed: continue
            column = self._prior_column_v3(atom)
            expected = None if atom.revision == 0 else (atom.revision, int(atom.valid), column.cell.cell_id)
            row = self._small_v3("graph_atoms", ("revision", "valid", "value_cell_id"),
                "token=? AND bot=? AND persona=?", (atom.key.token, *self.namespace.as_tuple))
            if row != expected: raise AuthorityUnavailable("model scope Source/ancestry/access/correction/Owner selected guard changed")
            guards[atom.key] = expected
        self.guard_metadata = MappingProxyType(guards)
        root_request = ("graph_d11_life_originals_v1", ("producing_operation_id", "payload_json", "payload_digest", "signature"),
            ("bot", "persona", "kind", "original_ref"), (*self.namespace.as_tuple, "draft_root_capability", root.registration_ref))
        root_row, task = self._prepared_point_v3(root_request)
        if root_row is None: raise AuthorityUnavailable("model scope root has no actual prior signed original EOF")
        from ..domains.d01.production_operations_v1 import plain_v1
        column = task.values.get("payload_json") if type(task) is _MethodPointReadV3 else task.json_columns.get("payload_json")
        if type(column) is MethodJSONColumnV3:
            column._actual(); frozen, digest = column.frozen, column.canonical_digest
        else:
            from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
            if type(column) is not DispatchOriginalJSONReadV3: raise AuthorityUnavailable("model scope needs its actual signed root JSON EOF")
            frozen, digest = _freeze_value_v3(column.require_v3(owner)), column.sha256
        if frozen != _freeze_value_v3(plain_v1(root)) or digest != root_row[2]:
            raise AuthorityUnavailable("model scope signed root differs from its actual issued capability")
        committed_request = ("graph_bundle_operations", ("digest", "receipt_json", "commit_seq"),
            ("bot", "persona", "operation_id"), (*self.namespace.as_tuple, root_row[0]))
        canonical_committed_request = (committed_request[0],
            ("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"), committed_request[2], committed_request[3])
        producer, committed_task = self._prepared_point_v3(canonical_committed_request)
        committed = None if producer is None else (producer[0], producer[4], producer[3])
        if committed is None or committed[2] < 1 or json.loads(committed[1]).get("commit_seq") != committed[2]:
            raise AuthorityUnavailable("model scope registered root lost its actual committed producer")
        self.point_rows = MappingProxyType({root_request: root_row, committed_request: committed})
        self.point_tasks = MappingProxyType({root_request: task, committed_request: committed_task})
        owner.operation.retain(_heap((self.guard_metadata, self.point_rows)) + 4096)
        self.complete = True
        _FOREGROUND_SCOPE_POST_PROOFS[self] = self._identity_v3()

    _small_v3 = PreparedMethodPostCommitV3._small_v3
    _prior_column_v3 = PreparedMethodPostCommitV3._prior_column_v3

    def _identity_v3(self):
        return (self.owner, self.db, self.graph, self.namespace, self.prior_frame, self.stage, self.receipt, self.scope,
            self.issued, self.process_lease, self.after_stamp, self.source, self.source_column, self.source_frozen,
            self.source_digest, self.guard_metadata, self.point_rows, self.point_tasks, self.complete)

    def _prepared_point_v3(self, request):
        task = self.owner.points.get(request) or self.owner.attachments.get(request)
        if task is None or not task.complete:
            raise AuthorityUnavailable("model scope successor cannot open a new signed root/producer point")
        current = self._small_v3(task.table, task.metadata_columns, " AND ".join(name + "=?" for name in task.key_columns), task.key)
        if current != task.metadata: raise AuthorityUnavailable("model scope prior signed point metadata changed")
        return (None if task.row is None else tuple(value.wire if type(value) is MethodJSONColumnV3 else value for value in task.row)), task

    def require_current_v3(self):
        owner = self.owner
        if (_FOREGROUND_SCOPE_POST_PROOFS.get(self) != self._identity_v3() or not self.complete
                or _POST_COMMIT.get() is not self or owner not in _READERS or owner.operation.closed
                or not self.db.in_transaction or not owner.store._lock._is_owned()
                or owner.work.state is not owner or owner.work.operation is not owner.operation
                or owner.work.coordinator is not self.graph or runtime_storage_v3(self.db) is not owner.operation.handle
                or owner.runtime._active_foreground_issuance_v1 is not self.issued
                or owner.runtime._active_foreground_process_lease_v1 is not self.process_lease
                or self.graph._v2_graph_stamp(self.namespace) != self.after_stamp
                or owner.store._registry.catalogue_hash != owner.catalogue_hash):
            raise AuthorityUnavailable("actual model foreground scope successor is not current")
        owner.work._require_invocation(self.graph)
        if _require_borrowed_issuance_v3(self.issued, self.graph) != owner.evidence:
            raise AuthorityUnavailable("model foreground scope lost its actual original issuance")
        with runtime_storage_quantum_v3(self.db) as meter:
            if owner._epochs(meter) != owner.authority_epochs:
                raise AuthorityUnavailable("model scope Source access/deletion barrier changed")
            grant = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*self.namespace.as_tuple, owner_grant_key(*self.namespace.as_tuple).token))
        if grant != owner.owner_head: raise AuthorityUnavailable("model scope upstream Owner changed")
        for key, expected in self.guard_metadata.items():
            row = self._small_v3("graph_atoms", ("revision", "valid", "value_cell_id"),
                "token=? AND bot=? AND persona=?", (key.token, *self.namespace.as_tuple))
            if row != expected: raise AuthorityUnavailable("model scope unchanged Source/ancestry/access/correction guard changed")
        self.source_column._actual()
        if _freeze_value_v3(self.source.value) != self.source_frozen:
            raise AuthorityUnavailable("model scope Source differs from its actual canonical EOF")
        return self

    def head_v3(self, key):
        self.require_current_v3()
        if key != self.source.key or NamespaceId.from_key(key) != self.namespace:
            raise AuthorityUnavailable("model foreground scope exposes only its actual unchanged plan Source")
        return self.source

    def atom_digest_v3(self, atom):
        if self.head_v3(atom.key) != atom:
            raise AuthorityUnavailable("model foreground scope digest requires its actual unchanged Source EOF")
        return self.source_digest

    def attachment_v3(self, table, columns, key_columns, key):
        self.require_current_v3()
        request = (table, tuple(columns), tuple(key_columns), tuple(key))
        if table == "graph_atoms":
            if (tuple(key_columns) not in {("token",), ("token", "bot", "persona")}
                    or len(key) != len(key_columns) or not set(columns) <= {"token", "revision", "value", "valid"}
                    or key[0] != self.source.key.token or len(key) == 3 and tuple(key[1:]) != self.namespace.as_tuple):
                raise AuthorityUnavailable("model scope head projection is outside its actual Source slot")
            values = dict(token=self.source.key.token, revision=self.source.revision,
                value=self.source_column.wire, valid=int(self.source.valid))
            return tuple(values[name] for name in columns)
        if request not in self.point_rows:
            raise AuthorityUnavailable("model foreground scope exposes only its actual prior signed root/committed producer")
        task = self.point_tasks[request]
        current = self._small_v3(table, task.metadata_columns, " AND ".join(name + "=?" for name in key_columns), key)
        if current != task.metadata:
            raise AuthorityUnavailable("model foreground scope signed root/producer metadata changed")
        return self.point_rows[request]

    def release_payload_v3(self):
        _FOREGROUND_SCOPE_POST_PROOFS.pop(self, None)
        self.source = self.source_column = self.source_frozen = self.source_digest = None
        self.guard_metadata = self.point_rows = self.point_tasks = None; self.complete = False


@contextmanager
def bind_method_foreground_scope_post_commit_v3(db, graph, prior_frame, stage, actual_receipt, scope, issued, process_lease):
    if _POST_COMMIT.get() is not None:
        raise AuthorityUnavailable("model foreground scope successor cannot be nested with another successor")
    proof = PreparedMethodForegroundScopePostCommitV3(_ISSUER, db, graph, prior_frame, stage,
        actual_receipt, scope, issued, process_lease)
    token = _POST_COMMIT.set(proof)
    try:
        proof.require_current_v3()
        yield proof
    finally:
        _POST_COMMIT.reset(token); proof.release_payload_v3()


class PreparedPersonalEligibilityRecoveryReadV1(_MethodLearningReadV3):
    """Exact private READ continuation; this class never invokes a write compiler."""
    def __init__(self, issuer, graph, operation, fence, *, runtime, authority, owner_binding, owner_guard,
            issued, selector, request, initial_now_utc, saved_wave, saved_original, saved_receipt):
        if issuer is not _ISSUER or fence.scope.operation != "read" or selector.operation_kind != "prepare_personal_candidate_eligibility_v1":
            raise AuthorityUnavailable("actual exact saved-eligibility READ issuer required")
        self.issued, self.selector = issued, selector
        self.business_operation_id=selector.operation_id
        self.saved_wave, self.saved_original, self.saved_receipt = saved_wave, saved_original, saved_receipt
        self.personal_eligibility_wave_v1 = None
        self.selection_source_refs = frozenset(version.key.token for version in saved_original["read_versions"]
            if version.key.type_name == "memory.source")
        self.recovery_source_ref = issued.source_ref
        super().__init__(_ISSUER,graph,operation,fence,runtime=runtime,authority=authority,lease=None,
            operation_kind=selector.operation_kind,request=request,operation_id=operation.operation_id,
            activity_id=saved_original["payload"]["identity"]["activity_id"],audience_ref=issued.audiences[0],
            parent_budget_lease_ref=saved_wave.parent_budget_lease_ref,request_digest=canonical_digest(request),
            owner_binding=owner_binding,owner_guard=owner_guard,session_proof=None,initial_now_utc=initial_now_utc)
        self.selected_tokens = frozenset(version.key.token for version in saved_original["read_versions"])
        self.census_schema = "d08.personal-eligibility-recovery-metadata-census.v1"
        self.leaf_schema = "d08.personal-eligibility-recovery-selected-leaf.v1"
        self.root = canonical_digest((self.census_schema,self.namespace,self.query,self.selection_digest))
        self.recovery_versions = {version.key.token:version.revision for version in saved_wave.read_versions}
        self.recovery_families = frozenset(page.type_id for page in saved_wave.query_coverage)

    def _graph_eof_v3(self):
        self.work.phase = "eligibility_recovery_originals"

    def _next(self,meter):
        # Closed metadata census includes every negative-query member. Source
        # bytes are restricted to the actual saved preparation's Source closure.
        row=meter.read_fixed_row(self.db,"graph_atoms",("token","revision","type_name"),
            "bot=? AND persona=? AND token>? ORDER BY token",(*self.namespace.as_tuple,self.cursor))
        if row is not None and row[0] in self.recovery_versions and row[1] != self.recovery_versions[row[0]]:
            raise AuthorityUnavailable("saved eligibility semantic head changed before recovery material disclosure")
        if row is not None and row[2] in METHOD_LEARNING_TYPES_V3 and row[0] not in self.selected_tokens:
            if row[2] in self.recovery_families:
                raise AuthorityUnavailable("saved eligibility complete negative metadata scope changed")
            self.cursor=row[0]; return
        if row is not None and row[2] == "memory.source" and row[0] not in self.selection_source_refs:
            self.cursor=row[0]; return
        return super()._next(meter)

    def require_current(self, *, meter=None):
        super().require_current(meter=meter)
        if self.issued.graph is not self.graph or self.issued.scope is not self.fence.scope or self.issued.operation_id != self.business_operation_id:
            raise AuthorityUnavailable("eligibility recovery changed its actual fresh READ issuance")
        if not self.read_finished: self.graph._validate_read_fence_v3(self.fence)


class PreparedPersonalEligibilityRecoveryInventoryV1(PreparedCurrentMethodLearningReadV3):
    def __init__(self,issuer,reader):
        if type(reader) is not PreparedPersonalEligibilityRecoveryReadV1:
            raise AuthorityUnavailable("exact selected-Source recovery census required")
        self.recovery_selection = (reader.census_schema,reader.leaf_schema,reader.selection_source_refs)
        super().__init__(issuer,reader)

    def _identity(self):
        return (*super()._identity(), self.recovery_selection)


def _method_inventory_result_v3(reader):
    if type(reader) is PreparedPersonalEligibilityRecoveryReadV1:
        return PreparedPersonalEligibilityRecoveryInventoryV1(_ISSUER,reader)
    return PreparedCurrentMethodLearningReadV3(_ISSUER,reader)


def _advance_personal_eligibility_recovery_v1(graph,work):
    reader=work.state
    if type(reader) is not PreparedPersonalEligibilityRecoveryReadV1 or reader not in _READERS or reader.work is not work:
        raise AuthorityUnavailable("actual private same-Work eligibility READ required")
    with bind_runtime_storage_operation_v3(work.operation,reader.db):
        graph._validate_read_fence_v3(reader.fence)
        if reader.authority_epochs is not None:
            with reader.store._lock:
                reader.require_current()
        if reader.inputs_sealed:
            if reader.business_started: raise AuthorityUnavailable("saved eligibility READ completes exactly once")
            reader.business_started=True
            proof=reader.result
            with bind_prepared_method_learning_read_v3(proof,graph,reader.db):
                from .personal_candidate_eligibility_v1 import complete_personal_eligibility_recovery_read_v1
                result=complete_personal_eligibility_recovery_read_v1(reader)
            proof.business_result=result; _BUSINESS_RESULTS[proof]=(work,result)
            reader.business_completed=True
            reader.read_issuance_lifetime.close()
            graph._finish_read_fence_v3(reader.fence); reader.read_finished=True
            return GraphStorageStepV3("complete",proof)
        if not reader.inventory_sealed:
            with reader.store._lock:
                if reader.db.in_transaction: raise AuthorityUnavailable("eligibility recovery retained a transaction")
                reader.advance()
            return GraphStorageStepV3("progress")
        if reader.pending_input is not None:
            with reader.store._lock,runtime_storage_quantum_v3(reader.db) as meter:
                reader.require_current(meter=meter); reader.pending_input.advance(meter)
                if reader.pending_input.complete:reader.pending_input=None
            return GraphStorageStepV3("progress")
        token=_READING.set(reader)
        try:
            with bind_prepared_method_learning_read_v3(reader.inventory,graph,reader.db):
                from .personal_candidate_eligibility_v1 import prepare_personal_eligibility_recovery_inputs_v1
                prepare_personal_eligibility_recovery_inputs_v1(reader)
        except MethodInputNeededV3 as needed:
            kind,actual=needed.request
            if kind=="point":
                _require_input_request(reader,actual)
                task=reader.points.get(actual)
                if task is None:task=_MethodPointReadV3(reader,actual);reader.points[actual]=task
            elif kind=="inventory":
                allowed=set(reader.preplan_families)
                if reader.selected_plan is not None:allowed.update(reader.selected_plan.fixed_type_ids)
                if actual not in allowed:raise AuthorityUnavailable("recovery requested an unregistered fixed family")
                task=reader.inventories.get(actual)
                if task is None:task=_MethodInventoryReadV3(reader,actual);reader.inventories[actual]=task
            elif kind=="budget_grant":
                if actual!=reader.parent_budget_lease_ref:raise AuthorityUnavailable("recovery changed its original parent budget")
                if reader.budget_task is None:reader.budget_task=_MethodBudgetGrantReadV3(reader,actual)
                task=reader.budget_task
            else:raise AuthorityUnavailable("unregistered saved eligibility READ dependency")
            reader.pending_input=task
        finally:_READING.reset(token)
        with reader.store._lock:
            reader.require_current()
        return GraphStorageStepV3("progress")



# Private, less-than-body metadata mode uses the exact existing signer-recognized Method column.
_GENERAL_OWNER_OPERATIONS_V1=frozenset({
    "freeze_general_growth_intent_v1","register_general_growth_trial_start_v1",
    "derive_general_growth_trial_v1","adopt_general_growth_v1"})
_GENERAL_OWNER_METADATA_TYPES_V1=frozenset(('d07.current_interpretation.v1', 'd08.action_outcome.v1', 'd10.life_progress.v1', 'runtime.job', 'runtime.cost_settlement'))
_GENERAL_METADATA_COLUMN_ISSUER_V1=object()
_GENERAL_METADATA_COLUMNS_V1=WeakKeyDictionary()

def require_actual_general_owner_metadata_work_v1(owner,*,operation_kind,namespace):
    require_actual_method_learning_attachment_owner_v3(owner,db=owner.db)
    if (type(owner)is not _MethodLearningReadV3 or owner.operation_kind not in _GENERAL_OWNER_OPERATIONS_V1
            or owner.operation_kind!=operation_kind or owner.namespace!=namespace
            or owner.fence.scope.operation!="read"):
        raise AuthorityUnavailable("actual same Owner General READ input Work required")
    return owner

def prepare_current_general_owner_metadata_column_v1(owner,*,table,column,key_columns,key,profile,
        signer=None,signature_kind=None,signature=None,cell=None):
    require_actual_general_owner_metadata_work_v1(owner,operation_kind=owner.operation_kind,namespace=owner.namespace)
    from .d01_general_growth_v1 import validate_current_general_owner_metadata_profile_v1
    validate_current_general_owner_metadata_profile_v1(table,column,tuple(key_columns),tuple(key),profile,owner.namespace)
    return MethodJSONColumnV3(_ISSUER,owner,table=table,column=column,key_columns=key_columns,key=key,cell=cell,
        signer=signer,signature_kind=signature_kind,signature=signature,
        general_metadata_issuer=_GENERAL_METADATA_COLUMN_ISSUER_V1,general_metadata_profile=profile)

def _require_general_owner_metadata_column_v1(column):
    state=_GENERAL_METADATA_COLUMNS_V1.get(column)
    if state is None or state!=(column.owner,column.general_metadata_profile,column.general_metadata_task):
        raise AuthorityUnavailable("actual issued fixed General metadata column required")
    column._actual()
    return state

def _advance_general_owner_metadata_column_v1(column,meter):
    from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2,_quote
    c=column;_require_general_owner_metadata_column_v1(c);c.owner.require_current(meter=meter)
    if c.complete:return True
    if c.fragment_offset<len(c.fragment):
        end=min(c.fragment_offset+1024,len(c.fragment));chunk=c.fragment[c.fragment_offset:end]
        c._reserve_v3(131072);c.parser.feed(chunk,c._emit_v3)
        if c.semantic_decoder is not None:
            from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
            _D07AuthorityGraphMetadataColumnV3._semantic_v3(c,chunk,meter)
        c.fragment_offset=end;c._flush_text_v3();return False
    if c.cell is not None:chunk=c.cell.read_fragment(meter=meter)
    else:
        where=" AND ".join(_quote(name)+"=?"for name in c.key_columns)
        with legacy_cell_read_transaction_v2(c.db):
            if c.total is None:
                row=c.db.execute("SELECT typeof("+_quote(c.column)+"),length(CAST("+_quote(c.column)+" AS BLOB)) FROM "+
                    _quote(c.table)+" WHERE "+where,c.key).fetchone();meter.charge_read(16)
                if row is None or row[0]!="text":raise AuthorityUnavailable("actual General metadata column absent")
                c.total=row[1]
            if c.offset<c.total:
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(c.db,table=c.table,column=c.column,
                    where=where,parameters=c.key,start=c.offset,length=min(16384,c.total-c.offset),meter=meter)
                if (total,kind)!=(c.total,"text"):raise AuthorityUnavailable("General metadata original changed")
                c.offset+=len(chunk)
            else:chunk=None
    if chunk is not None:
        if c.signature_state is not None:c.signature_state.update(chunk);c.signature_bytes+=len(chunk)
        c.fragment,c.fragment_offset=chunk,0;return False
    parsed=c.parser.finish()
    if c.cell is not None:
        digest=c.cell.finish(meter=meter)
        if (parsed.sha256,parsed.byte_count)!=(digest,c.cell.header[3]):
            raise AuthorityUnavailable("General metadata canonical cell whole EOF differs")
    elif parsed.byte_count!=c.total:raise AuthorityUnavailable("General metadata whole raw EOF differs")
    if c.semantic_decoder is not None:
        from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
        _D07AuthorityGraphMetadataColumnV3._semantic_v3(c,b"",meter,final=True)
        c.canonical_digest=c.semantic_hash.hexdigest()
    else:c.canonical_digest=parsed.sha256
    c._reserve_v3(_heap(c.value)*2+1024);c.frozen=_freeze_value_v3(c.value)
    c.sha256,c.byte_count=parsed.sha256,parsed.byte_count
    c.value=None;c.nodes={};c.scalar=bytearray();c.fragment=b"";c.parser=None
    c.semantic_decoder=c.semantic_hash=None
    c.complete=True
    if c.signature_state is not None:
        c.signer.finish_original_stream_verification_v3(c.signature_kind,c.signature,c,c.signature_state)
        c.signature_verified=True
    return True

def current_general_owner_metadata_column_value_v1(column):
    _require_general_owner_metadata_column_v1(column)
    if not column.complete:raise AuthorityUnavailable("General metadata getter requires complete actual EOF")
    reserve_current_general_owner_metadata_peak_v1(column.owner,extra=_general_method_metadata_heap_v1(column.frozen)+1024)
    return _detach_value_v3(column.frozen)



def _require_current_general_owner_metadata_reader_v1(db,namespace,issuer=None):
    owner=_method_active(db)
    if owner is None:raise AuthorityUnavailable("actual General Owner Method input Binder required")
    require_actual_general_owner_metadata_work_v1(owner,operation_kind=owner.operation_kind,namespace=namespace)
    if issuer is not None and issuer is not owner.graph._GraphCoordinator__d11_issuer:
        raise AuthorityUnavailable("General metadata issuer differs from actual installed D11")
    return owner

def _read_current_general_owner_metadata_attachment_v1(owner,identity):
    key=("general_owner_metadata",identity)
    task=owner.attachments.get(key)
    if task is None or not task.complete:_need_method_input(owner,key)
    if task.reader is not owner or task.identity!=identity:
        raise AuthorityUnavailable("General metadata attachment changed actual originating Work")
    task.require_reader_v1()
    return task.result

def read_bound_current_general_owner_signed_metadata_v1(db,*,namespace,issuer,table,original_ref,kind):
    from .current_conditioned_self_read_v3 import read_bound_conditioned_general_signed_metadata_v3
    handled,result=read_bound_conditioned_general_signed_metadata_v3(db,namespace=namespace,issuer=issuer,table=table,original_ref=original_ref,kind=kind)
    if handled:return result
    owner=_require_current_general_owner_metadata_reader_v1(db,namespace,issuer)
    return _read_current_general_owner_metadata_attachment_v1(owner,("signed",table,kind,original_ref))

def read_bound_current_general_owner_graph_metadata_v1(db,*,namespace,key,kind):
    from .current_conditioned_self_read_v3 import read_bound_conditioned_general_graph_metadata_v3
    handled,result=read_bound_conditioned_general_graph_metadata_v3(db,namespace=namespace,key=key,kind=kind)
    if handled:return result
    owner=_require_current_general_owner_metadata_reader_v1(db,namespace)
    if type(key)is not AtomKey or NamespaceId.from_key(key)!=namespace:
        raise AuthorityUnavailable("General metadata head differs from actual namespace")
    return _read_current_general_owner_metadata_attachment_v1(owner,("graph",kind,key.token))

def read_bound_current_general_owner_type_metadata_v1(db,*,namespace,type_id,limit=129):
    from .current_conditioned_self_read_v3 import read_bound_conditioned_general_type_metadata_v3
    handled,result=read_bound_conditioned_general_type_metadata_v3(db,namespace=namespace,type_id=type_id,limit=limit)
    if handled:return result
    owner=_require_current_general_owner_metadata_reader_v1(db,namespace)
    if limit!=129:raise AuthorityUnavailable("General metadata preserves actual complete 128-row bound")
    rows,complete=_read_current_general_owner_metadata_attachment_v1(owner,("type",type_id,129))
    if not complete or len(rows)>128:raise AuthorityUnavailable("General metadata type inventory incomplete")
    return rows,complete

def read_bound_current_general_owner_prepared_for_adoption_v1(db,*,namespace,issuer,prepared_digest):
    owner=_require_current_general_owner_metadata_reader_v1(db,namespace,issuer)
    return _read_current_general_owner_metadata_attachment_v1(owner,("prepared_for_adoption",prepared_digest))

def read_bound_current_general_owner_start_metadata_inventory_v1(db,*,namespace,issuer,limit=129):
    owner=_require_current_general_owner_metadata_reader_v1(db,namespace,issuer)
    if limit!=129:raise AuthorityUnavailable("General start metadata preserves its actual complete bound")
    rows,complete=_read_current_general_owner_metadata_attachment_v1(owner,("starts",129))
    if not complete or len(rows)>128:raise AuthorityUnavailable("General immutable start inventory incomplete")
    return rows,complete

def require_current_general_owner_metadata_coverage_v1(inputs,type_id):
    if type(inputs)is not PreparedMethodDomainInputsV3 or type_id not in _GENERAL_OWNER_METADATA_TYPES_V1:
        raise AuthorityUnavailable("actual General selected Method frame counter metadata required")
    if _INPUTS.get(inputs)!=(inputs.owner,inputs.plan,inputs.envelope,inputs.read_scope,inputs.graph_stamp,inputs.owner_rights):
        raise AuthorityUnavailable("actual registered General Method frame inputs required")
    owner=inputs.owner
    owner.require_current()
    if inputs.plan!=owner.selected_plan:
        raise AuthorityUnavailable("General metadata coverage changed actual selected plan")
    if owner.operation_kind not in _GENERAL_OWNER_OPERATIONS_V1 or type_id not in inputs.plan.fixed_type_ids:
        raise AuthorityUnavailable("General counter coverage differs from actual selected recipe")
    rows,complete=read_bound_current_general_owner_type_metadata_v1(owner.db,namespace=owner.namespace,type_id=type_id,limit=129)
    for row in rows:row.require_for_v1(owner)
    return rows

def _general_method_metadata_heap_v1(value,seen=None):
    import sys
    if seen is None:seen=set()
    if id(value)in seen:return 0
    if type(value)is MappingProxyType:
        seen.add(id(value))
        return sys.getsizeof(value)+sum(_general_method_metadata_heap_v1(k,seen)+
            _general_method_metadata_heap_v1(v,seen)for k,v in value.items())
    if type(value)in(dict,list,tuple,set):
        seen.add(id(value))
        entries=value.items()if type(value)is dict else ((None,item)for item in value)
        return sys.getsizeof(value)+sum((0 if k is None else _general_method_metadata_heap_v1(k,seen))+
            _general_method_metadata_heap_v1(v,seen)for k,v in entries)
    return _heap(value,seen)

def reserve_current_general_owner_metadata_peak_v1(reader,extra=0):
    require_actual_general_owner_metadata_work_v1(reader,operation_kind=reader.operation_kind,namespace=reader.namespace)
    from .d01_general_growth_v1 import GeneralOwnerGraphMetadataV1
    seen=set();size=extra+65536
    for column,(owner,profile,task)in tuple(_GENERAL_METADATA_COLUMNS_V1.items()):
        if owner is not reader:continue
        size+=_general_method_metadata_heap_v1((column.nodes,column.value,column.frozen,column.scalar,
            column.text_parts,column.text_chars,column.fragment,column.general_metadata_fields_seen),seen)
        if column.parser is not None:
            parser=column.parser
            size+=_general_method_metadata_heap_v1((parser._stack,parser._string,parser._literal,parser._number,
                parser._active_scalar),seen)
    def result_heap(value):
        if type(value)is GeneralOwnerGraphMetadataV1:
            return _general_method_metadata_heap_v1((value.key,value._frozen_value,value.payload_digest),seen)
        if type(value)is tuple or type(value)is list:
            import sys
            if id(value)in seen:return 0
            seen.add(id(value))
            return sys.getsizeof(value)+sum(result_heap(item)for item in value)
        return _general_method_metadata_heap_v1(value,seen)
    visited=set()
    def task_heap(task):
        if task is None or id(task)in visited:return 0
        visited.add(id(task))
        total=_general_method_metadata_heap_v1((task.identity,task.cursor),seen)+result_heap(task.rows)
        total+=_general_method_metadata_heap_v1((task.metadata,task.value),seen)
        total+=result_heap(task.result)
        return total+task_heap(task.child)
    for identity,task in reader.attachments.items():
        if identity[0]=="general_owner_metadata":size+=task_heap(task)
    size+=task_heap(reader.general_metadata_issuing_task)
    if size>reader.general_metadata_reserved:
        reader.operation.retain(size-reader.general_metadata_reserved);reader.general_metadata_reserved=size
    return size


_GENERAL_METHOD_SOURCE_ISSUER_V1=object()
_GENERAL_METHOD_SOURCE_TASKS_V1=WeakKeyDictionary()
_GENERAL_METHOD_SOURCE_PROOFS_V1=WeakKeyDictionary()

def _general_method_source_heap_v1(reader,extra=0):
    size=extra
    for task in _GENERAL_METHOD_SOURCE_TASKS_V1.get(reader,{}).values():
        size+=_general_method_metadata_heap_v1((task.key,task.header,task.fragment,task.metadata))
        if task.parser is not None:
            parser=task.parser
            size+=parser._source_heap_bytes()+_heap((parser._stack,parser._string,parser._literal,parser._number,parser._active_scalar))
    if size>reader.general_source_reserved:
        reader.operation.retain(size-reader.general_source_reserved);reader.general_source_reserved=size
    return size

def _new_general_method_source_parser_v1(reader,*,ensure_ascii):
    from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
    from weakref import ref as weak_ref
    reader_ref=weak_ref(reader)
    class _ActualGeneralSourceParser(C09MemorySourceJSONStreamV3):
        def _source_require_arena(self,extra=0):
            _general_method_source_heap_v1(reader_ref(),extra)
            return super()._source_require_arena(extra)
    return _ActualGeneralSourceParser(ensure_ascii=ensure_ascii)

def require_actual_source_owner_metadata_work_v1(reader):
    if reader.operation_kind in _NUMERIC_PAID_WRITE_OPERATIONS_V3:
        from .current_life_numeric_paid_write_v3 import require_numeric_paid_write_work_v3
        return require_numeric_paid_write_work_v3(reader)
    if reader.operation_kind in _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3:
        from .current_owner_job_cancel_v3 import require_current_job_cancel_work_v3
        return require_current_job_cancel_work_v3(reader)
    if reader.operation_kind in _GENERAL_OWNER_OPERATIONS_V1:
        return require_actual_general_owner_metadata_work_v1(reader,operation_kind=reader.operation_kind,namespace=reader.namespace)
    from .current_life_numeric_metadata_v1 import require_numeric_owner_metadata_work_v1
    return require_numeric_owner_metadata_work_v1(reader)


class _GeneralMethodSourceMetadataEOFV1:
    def __init__(self,issuer,reader,ref):
        if issuer is not _GENERAL_METHOD_SOURCE_ISSUER_V1:raise TypeError("actual General Source metadata leaf issuer required")
        require_actual_source_owner_metadata_work_v1(reader)
        from weakref import ref as weak_ref
        self.reader=weak_ref(reader);self.key=AtomKey.from_token(ref)
        if self.key.type_name!="memory.source"or NamespaceId.from_key(self.key)!=reader.namespace:
            raise ValueError("General Source metadata leaf crossed actual Source namespace")
        self.header=None;self.cell=None;self.parser=None;self.fragment=b"";self.offset=0;self.total=None
        self.phase="header";self.metadata=None;self.sha256=None;self.complete=False

    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
        reader=self.reader();reader.require_current(meter=meter)
        if self.complete:self.require_v1(reader,meter);return True
        if self.header is not None:
            if reader.operation_kind in _NUMERIC_NATIVE_READ_OPERATIONS_V3:
                from .current_life_numeric_native_read_v3 import recheck_native_numeric_source_header_v3
                current=recheck_native_numeric_source_header_v3(reader,meter,self)
            elif reader.operation_kind=="prepare_internal_life_numeric_drive":
                from .d06_life_numeric_drive_v1 import recheck_drive_numeric_source_header_v3
                current=recheck_drive_numeric_source_header_v3(reader,meter,self)
            else:
                current=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                    "token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple))
            if current!=self.header:raise AuthorityUnavailable("General Method Source physical head changed")
        if self.phase=="header":
            self.header=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_atoms",
                ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",
                (self.key.token,*reader.namespace.as_tuple))
            if self.header is None or self.header[0]<1 or self.header[1]!=1:
                raise ValueError("General Source metadata lost its actual positive current head")
            self.cell=begin_runtime_cell_read_v3(reader.db,self.header[2],erasure_owner_ref=self.key.token)if self.header[2]is not None else None
            codec=None if self.cell is None else self.cell.header[0]
            if codec not in(None,"canonical-json.ascii.v1","canonical-json.utf8.v1"):
                raise ValueError("General Source metadata has another actual cell codec")
            self.parser=_new_general_method_source_parser_v1(reader,ensure_ascii=codec!="canonical-json.utf8.v1")
            self.phase="source";return False
        if self.fragment:
            part=self.fragment[:1024]
            _general_method_source_heap_v1(reader,len(part)*4+65536)
            self.parser.feed(part,lambda event:None)
            self.fragment=self.fragment[len(part):]
            return False
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        else:
            with legacy_cell_read_transaction_v2(reader.db):
                if self.total is None:
                    meter.require_available(1024)
                    row=reader.db.execute("SELECT typeof(value),length(CAST(value AS BLOB)) FROM graph_atoms "
                        "WHERE token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple)).fetchone()
                    meter.charge_read(16)
                    if row is None or row[0]!="text":raise ValueError("General Source original byte length/kind disappeared")
                    self.total=row[1]
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(reader.db,table="graph_atoms",column="value",
                        where="token=? AND bot=? AND persona=?",parameters=(self.key.token,*reader.namespace.as_tuple),
                        start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    if(total,kind)!=(self.total,"text"):raise ValueError("General Source original byte count/kind changed")
                    self.offset+=len(chunk)
                else:chunk=None
        if chunk is not None:
            _general_method_source_heap_v1(reader,len(chunk)+65536);self.fragment=chunk;return False
        result=self.parser.finish()
        if self.cell is not None:
            if(result.sha256,result.byte_count)!=(self.cell.finish(meter=meter),self.cell.header[3]):
                raise ValueError("General Source actual raw EOF/cell digest differs")
        elif result.byte_count!=self.total:raise ValueError("General Source legacy original EOF differs")
        _general_method_source_heap_v1(reader,_heap(self.parser._source_metadata))
        metadata=dict(self.parser._source_metadata)
        for name in("audiences","purposes","parent_source_ids"):metadata[name]=tuple(metadata[name])
        if metadata["source_id"]!=self.key.owner.subject:
            raise ValueError("General Source metadata identity differs from actual key")
        _general_method_source_heap_v1(reader,_heap(metadata))
        self.metadata=MappingProxyType(metadata);self.sha256=result.sha256;self.complete=True
        self.parser=None;self.cell=None;self.fragment=b""
        return True

    def require_v1(self,reader,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if self.reader()is not reader or _GENERAL_METHOD_SOURCE_TASKS_V1.get(reader,{}).get(self.key.token)is not self or not self.complete:
            raise ValueError("General Source metadata is not this actual Work's complete original leaf")
        reader.require_current(meter=meter)
        if reader.operation_kind in _NUMERIC_NATIVE_READ_OPERATIONS_V3:
            from .current_life_numeric_native_read_v3 import recheck_native_numeric_source_header_v3
            current=recheck_native_numeric_source_header_v3(reader,meter,self)
        elif reader.operation_kind=="prepare_internal_life_numeric_drive":
            from .d06_life_numeric_drive_v1 import recheck_drive_numeric_source_header_v3
            current=recheck_drive_numeric_source_header_v3(reader,meter,self)
        else:
            current=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_atoms",
                ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple))
        if current!=self.header:raise ValueError("General Source metadata changed its physical head after actual EOF")
        return self


    @property
    def revision(self):return self.header[0]
    @property
    def valid(self):return bool(self.header[1])

class _GeneralMethodSourcePermissionV1:
    def __init__(self,issuer,reader,roots,records,versions):
        if issuer is not _GENERAL_METHOD_SOURCE_ISSUER_V1:
            raise AuthorityUnavailable("actual Method Source completion issuer required")
        self.reader,self.roots=reader,roots
        self.source_refs=tuple(sorted(records))
        self.versions=tuple(versions)
        self.authority,self.scope,self.owner_entry=reader.authority,reader.fence.scope,reader.general_owner_entry
        _GENERAL_METHOD_SOURCE_PROOFS_V1[self]=(reader,reader.work,reader.operation,reader.selection_digest,
            self.scope,self.authority,roots,self.source_refs,self.versions,self.owner_entry)
    def require_for_v1(self,reader,roots):
        expected=(reader,reader.work,reader.operation,reader.selection_digest,self.scope,
            reader.authority,tuple(sorted(set(roots))),self.source_refs,self.versions,reader.general_owner_entry)
        if (_GENERAL_METHOD_SOURCE_PROOFS_V1.get(self)!=expected or self.reader is not reader
                or reader.general_source_permission is not self or reader.fence.scope is not self.scope
                or self.scope.operation!="read"):
            raise AuthorityUnavailable("General Method Source proof crossed actual Work/READ/selection")
        reader.require_current()
        if reader.read_finished:_require_current_general_method_source_write_phase_v1(reader)
        else:self.owner_entry.require_for_v3(reader)
        with runtime_storage_quantum_v3(reader.db)as meter:
            for ref in self.source_refs:
                _GENERAL_METHOD_SOURCE_TASKS_V1[reader][ref].require_v1(reader,meter)
            for version in self.versions:
                row=meter.read_fixed_row(reader.db,"graph_atoms",("revision",),
                    "token=? AND bot=? AND persona=?",(version.key.token,*reader.namespace.as_tuple))
                if (0 if row is None else row[0])!=version.revision:
                    raise AuthorityUnavailable("General Method Source closure current revision changed")
        return self

def qualify_method_source_metadata_kernel_v1(reader,roots,*,purposes):
    """Mechanical current Source/ancestor EOF traversal; grants no consumer permission."""
    from ..memory_types import source_key,access_key
    from ..domains.d06 import source_correction_head_key
    from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
    from ..graph_types import GraphVersion
    require_actual_source_owner_metadata_work_v1(reader)
    if reader.operation_kind in _NUMERIC_PAID_WRITE_OPERATIONS_V3:
        from .current_life_numeric_paid_write_v3 import require_numeric_paid_source_purposes_v3
        require_numeric_paid_source_purposes_v3(reader,purposes)
    elif reader.operation_kind in _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3:
        from .current_owner_job_cancel_v3 import require_cancel_source_purposes_v3
        require_cancel_source_purposes_v3(reader,purposes)
    elif tuple(purposes) not in ((reader.authority.purpose,),tuple(dict.fromkeys((reader.authority.purpose,"consolidation")))):
        raise AuthorityUnavailable("Source traversal differs from the caller's actual fixed purposes")
    records,versions,active={},{},set()
    def visit(ref):
        if ref in active:raise AuthorityUnavailable("General Method Source ancestry is cyclic")
        if ref in records:return
        if len(records)+len(active)>=256:raise AuthorityUnavailable("General Method Source family exceeds bounded original closure")
        key=AtomKey.from_token(ref)
        if key!=source_key(*reader.namespace.as_tuple,key.owner.subject or ""):
            raise AuthorityUnavailable("General Method Source root is not actual canonical Source")
        task=_GENERAL_METHOD_SOURCE_TASKS_V1.get(reader,{}).get(ref)
        if task is None or not task.complete:
            if reader.inputs_sealed:raise AuthorityUnavailable("General Method Source EOF was not actually prepared before WRITE")
            _need_method_input(reader,("general_method_source_metadata",ref))
        with runtime_storage_quantum_v3(reader.db)as meter:task.require_v1(reader,meter)
        access=method_graph_head_v3(reader.db,reader.namespace,access_key(*reader.namespace.as_tuple,key.owner.subject))
        correction=method_graph_head_v3(reader.db,reader.namespace,source_correction_head_key(reader.namespace,key.owner.subject))
        record=None
        for purpose in purposes:
            for audience in reader.authority.audience:
                record=_qualify_source_rights_values_v3(reader.namespace,ref,task,access,correction,
                    audience=audience,purpose=purpose,metadata_only=True)
                if record is None:
                    raise AuthorityUnavailable("Method Source current assertion/access/correction/purpose/audience denied")
        active.add(ref)
        for parent in record.parent_source_ids:visit(source_key(*reader.namespace.as_tuple,parent).token)
        active.remove(ref);records[ref]=record
        for atom in (task,access,correction):
            atom_key=task.key if atom is task else atom.key
            versions[atom_key]=GraphVersion(atom_key,atom.revision)
    for ref in roots:visit(ref)
    return records,versions

def require_current_general_method_sources_v1(reader,roots):
    roots=tuple(sorted(set(roots)))
    require_actual_general_owner_metadata_work_v1(reader,operation_kind=reader.operation_kind,namespace=reader.namespace)
    if reader.selected_plan is None or roots!=tuple(sorted(set(reader.selected_plan.source_roots))):
        raise AuthorityUnavailable("General Method Source roots differ from actual selected metadata plan")
    if reader.authority.purpose!="consolidation"or not reader.authority.audience:
        raise AuthorityUnavailable("General Method Source requires actual consolidation audience")
    if reader.general_owner_entry is None:
        raise AuthorityUnavailable("General Method Source requires completed independent MetaOwner entry")
    if reader.read_finished:_require_current_general_method_source_write_phase_v1(reader)
    else:reader.general_owner_entry.require_for_v3(reader)
    proof=reader.general_source_permission
    if proof is not None:return proof.require_for_v1(reader,roots)
    records,versions=qualify_method_source_metadata_kernel_v1(reader,roots,purposes=(reader.authority.purpose,))
    reader.operation.retain(_heap((tuple(records),tuple(versions.values())))+1024)
    proof=_GeneralMethodSourcePermissionV1(_GENERAL_METHOD_SOURCE_ISSUER_V1,reader,roots,records,
        tuple(sorted(versions.values(),key=lambda version:version.key.token)))
    reader.general_source_permission=proof
    return proof.require_for_v1(reader,roots)

def _require_current_general_method_body_v1(reader,table,key):
    from .foreground_command_source_v3 import require_foreground_command_body_column_v3
    if require_foreground_command_body_column_v3(reader,table,key):return
    from .artifact_borrowed_source_v3 import require_artifact_borrowed_body_column_v3
    if require_artifact_borrowed_body_column_v3(reader,table,key):return
    from .current_beta1_source_read_v3 import beta1_source_operation_v3
    if reader.work.kind=='current_habit_source_read_v3' or beta1_source_operation_v3(reader.operation_kind):
        from .current_beta1_source_read_v3 import require_beta1_source_body_v3
        return require_beta1_source_body_v3(reader,table,key)
    if reader.operation_kind in _NUMERIC_PAID_WRITE_OPERATIONS_V3:
        from .current_life_numeric_paid_write_v3 import require_numeric_paid_body_v3
        return require_numeric_paid_body_v3(reader,table,key)
    if reader.operation_kind in _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3:
        from .current_owner_job_cancel_v3 import require_cancel_job_body_v3
        return require_cancel_job_body_v3(reader,table,key)
    if reader.operation_kind in _NUMERIC_METADATA_OPERATIONS_V3:
        from .current_life_numeric_metadata_v1 import require_numeric_method_body_v1
        return require_numeric_method_body_v1(reader,table,key)
    if reader.operation_kind not in _GENERAL_OWNER_OPERATIONS_V1:return
    if reader.inputs_sealed:
        raise AuthorityUnavailable("General WRITE cannot open an unprepared body column")
    if table=="runtime_budget_grants":return
    if table=="graph_atoms":
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        atom_key=AtomKey.from_token(key[0])
        if atom_key==owner_grant_key(*reader.namespace.as_tuple):return
        subject=atom_key.owner.subject or ""
        if atom_key in {access_key(*reader.namespace.as_tuple,subject),
                source_correction_head_key(reader.namespace,subject)}:return
    if reader.general_source_permission is None:
        raise AuthorityUnavailable("General selected body requires all-parent Source metadata completion")
    proof=reader.general_source_permission.require_for_v1(reader,reader.selected_plan.source_roots)
    if table in {"graph_atoms","graph_history"}:
        atom_key=AtomKey.from_token(key[0])
        selected=atom_key in reader.selected_plan.exact_keys
        if atom_key.type_name=="memory.source":selected=atom_key.token in proof.source_refs
        elif atom_key.type_name not in _GENERAL_OWNER_METADATA_TYPES_V1:
            selected=selected or atom_key.type_name in reader.selected_plan.fixed_type_ids
        if not selected:
            raise AuthorityUnavailable("General body escaped same qualified exact keys/Source closure")

def _prepare_current_general_method_owner_entry_v1(reader):
    from .current_beta1_source_read_v3 import beta1_source_operation_v3,prepare_current_beta1_owner_entry_v3
    if reader.work.kind=='current_habit_source_read_v3' or beta1_source_operation_v3(reader.operation_kind):return prepare_current_beta1_owner_entry_v3(reader)
    if reader.operation_kind not in (_GENERAL_OWNER_OPERATIONS_V1 | _NUMERIC_METADATA_OPERATIONS_V3 | _OWNER_JOB_CANCEL_METADATA_OPERATIONS_V3 | _NUMERIC_PAID_WRITE_OPERATIONS_V3):return
    if reader.general_owner_entry is None:
        from ..authority_service.owner_location_read_v3 import prepare_current_host_method_owner_read_entry_v3
        reader.general_owner_entry=prepare_current_host_method_owner_read_entry_v3(reader)
    reader.general_owner_entry.require_permission_v3(reader)
    with reader.store._lock:reader.general_owner_entry.require_for_v3(reader)

_GENERAL_METHOD_SOURCE_WRITE_PHASES_V1=WeakKeyDictionary()

def _register_current_general_method_source_write_phase_v1(inputs,scope,current_owner):
    reader=inputs.owner
    from .current_beta1_source_read_v3 import beta1_source_operation_v3
    if reader.work.kind=='current_habit_source_read_v3' or beta1_source_operation_v3(reader.operation_kind):
        from .current_beta1_source_read_v3 import register_beta1_source_write_phase_v3
        return register_beta1_source_write_phase_v3(inputs,scope,current_owner)
    if reader.operation_kind not in (_GENERAL_OWNER_OPERATIONS_V1 | _NUMERIC_OWNER_OPERATIONS_V1):return
    if not reader.inputs_sealed:return
    if (not reader.read_finished or not reader.business_started or scope.operation!="write"
            or scope is reader.fence.scope or _method_active(reader.db)is not reader
            or inputs.plan!=reader.selected_plan or tuple(getattr(current_owner,name)for name in ("principal","actor","namespace","grant_id","scope","issuer_ref","capabilities","purposes","audiences","grant_digest","grant_revision","access_epoch","delete_epoch","graph_incarnation","authorization_head","authorization_revision","revocation_epoch"))!=tuple(getattr(reader.owner_binding,name)for name in ("principal","actor","namespace","grant_id","scope","issuer_ref","capabilities","purposes","audiences","grant_digest","grant_revision","access_epoch","delete_epoch","graph_incarnation","authorization_head","authorization_revision","revocation_epoch"))):
        raise AuthorityUnavailable("General cached READ input requires actual current business WRITE")
    reader.work._require_invocation(reader.graph)
    _GENERAL_METHOD_SOURCE_WRITE_PHASES_V1[reader]=(inputs,scope,current_owner,reader.work,reader.operation,
        reader.selection_digest,reader.graph_stamp,reader.selected_plan)

def _require_current_general_method_source_write_phase_v1(reader):
    record=_GENERAL_METHOD_SOURCE_WRITE_PHASES_V1.get(reader)
    if record is None:raise AuthorityUnavailable("General Source cached input has no actual business WRITE phase")
    inputs,scope,owner,work,operation,selection,stamp,plan=record
    if (_INPUTS.get(inputs)!=(reader,inputs.plan,inputs.envelope,inputs.read_scope,inputs.graph_stamp,inputs.owner_rights)
            or _method_active(reader.db)is not reader or inputs.owner is not reader
            or not reader.read_finished or not reader.inputs_sealed or not reader.business_started
            or scope.operation!="write" or scope is reader.fence.scope or tuple(getattr(owner,name)for name in ("principal","actor","namespace","grant_id","scope","issuer_ref","capabilities","purposes","audiences","grant_digest","grant_revision","access_epoch","delete_epoch","graph_incarnation","authorization_head","authorization_revision","revocation_epoch"))!=tuple(getattr(reader.owner_binding,name)for name in ("principal","actor","namespace","grant_id","scope","issuer_ref","capabilities","purposes","audiences","grant_digest","grant_revision","access_epoch","delete_epoch","graph_incarnation","authorization_head","authorization_revision","revocation_epoch"))
            or (work,operation,selection,stamp,plan)!=(reader.work,reader.operation,reader.selection_digest,
                reader.graph_stamp,reader.selected_plan)):
        raise AuthorityUnavailable("General Source WRITE phase changed actual sealed input/Owner/selection")
    reader.work._require_invocation(reader.graph)
    reader.require_current()
    return record

def _advance_general_method_header_census_v1(reader,meter):
    row=meter.read_fixed_row(reader.db,"graph_atoms",("token","revision","valid","type_name","value_cell_id"),
        "bot=? AND persona=? AND token>? ORDER BY token",(*reader.namespace.as_tuple,reader.cursor))
    if row is None:
        if reader._epochs(meter)!=reader.authority_epochs:
            raise AuthorityUnavailable("General Method metadata census Source epochs changed")
        reader.graph_eof=True;reader._graph_eof_v3();return
    token,revision,valid,type_id,cell_id=row
    key=AtomKey.from_token(token)
    if (NamespaceId.from_key(key)!=reader.namespace or key.type_name!=type_id
            or type(revision)is not int or revision<1 or valid not in(0,1)):
        raise AuthorityUnavailable("General Method metadata census graph header differs")
    reader.store._validate_key(key)
    reader.cursor=token
    reader.heads[token]=(revision,valid,cell_id)
    reader.root=canonical_digest((reader.leaf_schema,reader.root,token,revision,valid,type_id,cell_id))
    reader.count+=1;reader._reserve()


_JOINT_KEY_SCANS_V3 = WeakKeyDictionary()


class _JointOriginalKeysReadV3:
    """Bounded original-key EOF; signed bodies use ordinary exact point reads."""
    def __init__(self, owner, request):
        self.owner, self.request = owner, request
        self.table, self.namespace, self.kind = request
        self.rows, self.after, self.complete = [], None, False

    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        self.owner.require_current(meter=meter)
        where = "bot=? AND persona=? AND kind=?"
        params = (*self.namespace.as_tuple, self.kind)
        if self.after is not None:
            where += " AND original_ref>?"; params = (*params, self.after)
        row = _runtime_bounded_fixed_row_v3(self.owner.db, meter, self.table, ("original_ref",),
            where + " ORDER BY original_ref", params)
        if row is None:
            self.complete = True; return
        self.owner.operation.retain(len(row[0].encode("utf-8")) * 8 + 1024)
        self.rows.append(row); self.after = row[0]
        if len(self.rows) == 129:
            self.complete = True


def read_bound_method_joint_original_keys_v3(db, *, table, namespace, kind):
    owner = _method_active(db)
    if owner is None:
        return False, None
    from .artifact_borrowed_source_v3 import artifact_borrowed_joint_original_keys_v3
    artifact,keys=artifact_borrowed_joint_original_keys_v3(owner,table=table,namespace=namespace,kind=kind)
    if artifact:return True,keys
    if (table != "graph_d08_joint_node_originals_v1" or namespace != owner.namespace
            or kind not in {"external_node_contract_v1", "external_node_observation_v1", "compensation_authorization_v1"}):
        raise AuthorityUnavailable("unregistered Joint original key family")
    request = (table, namespace, kind)
    tasks = _JOINT_KEY_SCANS_V3.setdefault(owner, {})
    task = tasks.get(request)
    if task is None or not task.complete:
        _need_method_input(owner, ("joint_original_keys", request))
    owner.require_current()
    return True, tuple(task.rows)
