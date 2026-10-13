"""Private eight-type method census and original EOF retained by its actual Work."""
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from weakref import WeakKeyDictionary, WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d01.method_learning_v1 import VALUE_TYPES
from ..graph_types import AtomKey, owner_grant_key
from ..runtime_contracts import NamespaceId
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
METHOD_INPUT_OPERATIONS_V3 = frozenset({
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
    if kind not in METHOD_INPUT_OPERATIONS_V3: raise AuthorityUnavailable("unregistered method input operation")
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
            owner_binding, owner_guard, session_proof, initial_now_utc):
        if issuer is not _ISSUER or type(operation) is not RuntimeStorageOperationV3:
            raise AuthorityUnavailable("actual method Work retention issuer required")
        if operation.closed or runtime_storage_v3(graph._GraphCoordinator__store._db) is not operation.handle:
            raise AuthorityUnavailable("method census crossed its actual selected storage")
        self.runtime, self.authority, self.lease = runtime, authority, lease
        self.operation_kind, self.request = operation_kind, request
        self.operation_id, self.activity_id, self.audience_ref = operation_id, activity_id, audience_ref
        self.parent_budget_lease_ref, self.request_digest = parent_budget_lease_ref, request_digest
        self.owner_binding, self.owner_guard, self.session_proof = owner_binding, owner_guard, session_proof
        from .domain_production_contracts_v1 import ProductionOwnerGuardV1
        self.material_owner_guard = ProductionOwnerGuardV1(owner_grant_key(*authority.namespace.as_tuple).token,
            owner_binding.grant_revision, owner_binding.grant_digest.removeprefix("sha256:"),
            owner_binding.authorization_head.removeprefix("sha256:"))
        self.initial_now_utc, self.deadline_utc = initial_now_utc, operation.deadline_utc
        if (runtime.graph is not graph or authority.namespace != fence.scope.namespace
                or owner_binding.namespace != authority.namespace or operation.operation_id != operation_id):
            raise AuthorityUnavailable("method command crossed its actual runtime/Owner/business operation")
        self.work, self.owner_head = None, None
        self.inventory_sealed = self.inputs_sealed = False
        self.read_finished = self.business_started = self.business_completed = False
        self.inventory = self.selected_plan = self.selected_envelope = self.frame_fields = None
        self.points, self.inventories, self.input_heads = {}, {}, {}
        self.census_columns, self.census_versions = {}, {}
        self.atom_column = self.pending_input = None
        self.action_schema_locator = None
        self.observed_originals, self.installed_policy_refs = (), ()
        self.installed_readers = None
        self.budget_task, self.policy_tasks = None, {}
        self.preplan_families = _method_preplan_families_v3(operation_kind)
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
        self.attachments, self.pending_attachments = {}, []
        self.wires = {}
        self.attachment = None
        self.prefinal = self
        super().__init__(graph, operation, fence, projection_types=METHOD_LEARNING_TYPES_V3 | (frozenset({self.preference_type}) if self.preference_type else frozenset()),
            selected_tokens=frozenset(), census_schema="sylanne.method-learning-census.v3",
            leaf_schema="sylanne.method-learning-census-leaf.v3")
        _READERS.add(self)

    def require_current(self, *, meter=None):
        if self not in _READERS or self.operation.closed or self.work is None:
            raise AuthorityUnavailable("actual originating method Work reader required")
        store = self.store
        if (not store._lock._is_owned() or self.work.state is not self
                or self.work.operation is not self.operation or self.work.coordinator is not self.graph
                or self.work.kind != METHOD_LEARNING_WORK_KIND_V3
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
        super()._next(meter)
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
                self.inventory = PreparedCurrentMethodLearningReadV3(_ISSUER, self)
                if self.preferences_from_census:
                    self.preference_inventory = PreparedMethodRelationshipPreferencesV3(_ISSUER, self,
                        tuple(atom for atom in self.atoms if atom.key.type_name == self.preference_type))
                self.work.phase = "plan_resolution"
        return self


def begin_current_method_learning_read_v3(graph, operation, fence, *, runtime, authority, lease,
        operation_kind, request, operation_id, activity_id, audience_ref, parent_budget_lease_ref,
        request_digest, owner_binding, owner_guard, session_proof, initial_now_utc):
    """Root supplies its actual existing command, fence and original retention."""
    return _MethodLearningReadV3(_ISSUER, graph, operation, fence, runtime=runtime, authority=authority,
        lease=lease, operation_kind=operation_kind, request=request, operation_id=operation_id,
        activity_id=activity_id, audience_ref=audience_ref, parent_budget_lease_ref=parent_budget_lease_ref,
        request_digest=request_digest, owner_binding=owner_binding, owner_guard=owner_guard,
        session_proof=session_proof, initial_now_utc=initial_now_utc)


def attach_current_method_learning_work_v3(reader, work):
    if (type(reader) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3) or reader not in _READERS or reader.work is not None
            or type(work) is not GraphStorageWorkV3 or work.kind != METHOD_LEARNING_WORK_KIND_V3
            or work.state is not reader or work.operation is not reader.operation
            or work.coordinator is not reader.graph or work.operation_id != reader.operation.operation_id
            or work.deadline_utc != reader.operation.deadline_utc or work.selection_digest != reader.selection_digest):
        raise AuthorityUnavailable("actual originating method Work must attach once")
    work._require_invocation(reader.graph, initial=True)
    reader.work = work
    work.phase = "method_census"
    return work


def queue_current_method_learning_attachment_v3(reader, *, read_plan, table, columns, key_columns, key):
    """Add only an actual selected Source history from this Work's read recipe."""
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    if (type(reader) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3) or reader not in _READERS or reader.complete
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
    if type(reader) is BorrowedMethodLearningReadV3:
        return _advance_borrowed_method_learning_read_v3(graph, work)
    if (type(reader) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3) or reader not in _READERS or reader.work is not work
            or graph is not reader.graph or work.operation is not reader.operation):
        raise AuthorityUnavailable("actual same-operation method Work required")
    with bind_runtime_storage_operation_v3(work.operation, reader.db):
        if not reader.read_finished: graph._validate_read_fence_v3(reader.fence)
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
                                reader.frame_fields = _materialize_current_domain_frame_fields_v1(graph, reader.db,
                                    envelope=reader.selected_envelope, scope=reader.fence.scope, plan=reader.selected_plan,
                                    now_utc=reader.initial_now_utc, expected_owner_guard=reader.material_owner_guard,
                                    expected_rights=(reader.owner_binding.access_epoch, reader.owner_binding.delete_epoch),
                                    observed_originals=reader.observed_originals, installed_policy_refs=reader.installed_policy_refs,
                                    limits=ProductionOperationLimitsV1(), prepared_inputs=PreparedMethodDomainInputsV3(
                                        _ISSUER, reader, reader.selected_plan, reader.selected_envelope))
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
        if not reader.read_finished: graph._validate_read_fence_v3(reader.fence)
    return GraphStorageStepV3("complete", reader.result) if reader.business_completed else GraphStorageStepV3("progress")


def finish_current_method_learning_read_v3(graph, work, error):
    reader = work.state
    payload = reader.result
    try:
        if type(reader) is _MethodLearningReadV3 and not reader.read_finished:
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
    if type(proof) is not PreparedCurrentMethodLearningReadV3:
        raise AuthorityUnavailable("actual private method Binder required")
    proof._actual()
    if proof.graph is not graph or proof.db is not db:
        raise AuthorityUnavailable("method Binder crossed coordinator/storage")
    token = _BOUND.set((proof, graph, db))
    try:
        with bind_runtime_storage_operation_v3(proof.operation, db): yield proof
    finally: _BOUND.reset(token)


def require_actual_method_learning_attachment_owner_v3(owner, *, db=None):
    if (type(owner) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3) or owner not in _READERS
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
    proof = _bound_proof(db, namespace)
    atom = next((atom for atom in proof.atoms if atom.key == key), None)
    return None if atom is None else (atom.revision, proof.wires[key.token], int(atom.valid))


def require_bound_method_learning_atom_v3(db, namespace, key):
    from ..graph_types import GraphAtom
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


class MethodJSONColumnV3:
    def __init__(self, issuer, owner, *, table, column, key_columns, key, cell=None,
            signer=None, signature_kind=None, signature=None):
        if issuer is not _ISSUER or owner not in _READERS:
            raise AuthorityUnavailable("actual method JSON-column issuer required")
        from .domain_background_read_v3 import _BackgroundJSONStreamV3
        self.owner, self.db, self.operation = owner, owner.db, owner.operation
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
        self.parser = _BackgroundJSONStreamV3(self, ensure_ascii=cell is None or cell.header[0] != "canonical-json.utf8.v1")
        _JSON_COLUMNS[self] = (owner, self.db, table, column, self.key_columns, self.key, cell, signer, signature_kind, signature)
        if signer is not None: self.signature_state = signer.begin_original_stream_verification_v3(signature_kind, self)

    def _actual(self):
        if (_JSON_COLUMNS.get(self) != (self.owner, self.db, self.table, self.column, self.key_columns, self.key, self.cell,
                    self.signer, self.signature_kind, self.signature)
                or self.owner not in _READERS or self.operation.closed):
            raise AuthorityUnavailable("actual method JSON-column identity changed")
        return self

    def _reserve_v3(self, extra=0):
        size = _heap((self.nodes, self.value, self.scalar, self.text_parts, self.text_chars, self.fragment, self.wire_parts)) + extra + 65536
        if size > self.reserved:
            self.operation.retain(size - self.reserved); self.reserved = size
    def retain_path_v3(self, path): return True
    def _put_v3(self, path, value):
        if not path: self.value = value
        else:
            parent = self.nodes[path[:-1]]
            if type(parent) is list: parent.append(value)
            else: parent[path[-1]] = value
    def _flush_text_v3(self):
        if self.text_chars:
            self.text_parts.append("".join(self.text_chars)); self.text_chars = []
    def _emit_v3(self, event):
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
    from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    table, columns, key_columns, key = request
    if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3 and request[:3] not in {
            ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona")),
            ("graph_d05_production_policies_v1", ("payload_json",), ("bot", "persona", "policy_ref", "revision"))}:
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
    post = _method_post_commit_active_v3(db)
    if post is not None:
        if namespace != post.namespace: raise AuthorityUnavailable("successor head crossed namespace")
        return post.head_v3(key)
    from ..graph_types import GraphAtom
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
    if key.type_name in METHOD_LEARNING_TYPES_V3 and owner.inventory_sealed and key.token not in owner.census_columns:
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
    if type_id in METHOD_LEARNING_TYPES_V3:
        return tuple(method_graph_head_v3(db, namespace, atom.key) for atom in owner.inventory.atoms if atom.key.type_name == type_id)
    if type_id == owner.preference_type and owner.preferences_from_census:
        owner.preference_inventory.require_current_v3()
        return tuple(method_graph_head_v3(db, namespace, atom.key) for atom in owner.preference_inventory.atoms)
    allowed = set(owner.preplan_families)
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


def read_bound_method_frame_inputs_v3(db, *, graph, scope, plan, envelope, current_owner):
    owner = _method_active(db)
    if owner is None: return False, None
    if type(owner) is not _MethodLearningReadV3:
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
    original._actual(); o = original.owner; task = o.budget_task
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
        self.preplan_families = _method_preplan_families_v3(operation_kind)
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
            projection_types=METHOD_LEARNING_TYPES_V3 | (frozenset({self.preference_type}) if self.preference_type else frozenset()),
            selected_tokens=frozenset(), census_schema="sylanne.method-learning-census.v3",
            leaf_schema="sylanne.method-learning-census-leaf.v3")
        _READERS.add(self)

    def seal_plan_v3(self, plan, *, installed_readers=None, observed_originals=(), installed_policy_refs=()):
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        if not self.inventory_sealed or self.inputs_sealed or type(plan) is not ProductionReadPlanV1:
            raise AuthorityUnavailable("actual unfinished borrowed method plan required")
        roots = {v.key.token for v in self.evidence.read_versions if v.key.type_name == "memory.source"}
        if not set(plan.source_roots) <= roots:
            raise AuthorityUnavailable("borrowed plan added Source outside its actual qualified issuance")
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
        o.inventory._actual(); return self
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
        o.require_current(); return self
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
        allowed = set(reader.preplan_families)
        if reader.selected_plan is not None: allowed.update(reader.selected_plan.fixed_type_ids)
        if reader.preference_origin is not None: allowed.add(reader.preference_type)
        if actual not in allowed: raise AuthorityUnavailable("borrowed inventory has no actual fixed recipe/dependency")
        task = reader.inventories.get(actual)
        if task is None: task = _MethodInventoryReadV3(reader, actual); reader.inventories[actual] = task
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
                if r.authority_epochs is not None: r.require_current()
                r.advance()
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
    for column, record in tuple(_JSON_COLUMNS.items()):
        if record[0] is owner:
            _JSON_COLUMNS.pop(column, None)
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
        owner = _method_active(db)
        if (issuer is not _ISSUER or type(owner) is not BorrowedMethodLearningReadV3
                or owner.graph is not graph or not owner.inputs_sealed or not owner.business_started
                or owner.business_completed or owner.operation_kind not in _METHOD_ARTIFACT_POST_OPERATIONS_V3
                or type(prior_frame) is not CurrentOperationFrameV1 or type(stage) is not StagedDomainOperationV1
                or type(actual_receipt) is not CommitReceipt or type(issued) is not _IssuedForegroundActivityV1
                or issued is not owner.issued or scope is not issued.scope or not db.in_transaction
                or not owner.store._lock._is_owned()):
            raise AuthorityUnavailable("actual same-transaction borrowed Artifact CAS successor required")
        owner.inventory._actual(); owner.result._actual_v3(); owner.work._require_invocation(graph)
        identity = prior_frame.envelope.identity
        if (stage.coverage != "complete" or stage.domain != "d08" or stage.operation_kind != owner.operation_kind
                or stage.operation_id != owner.operation_id or stage.namespace != owner.namespace
                or identity.operation_id != owner.operation_id or stage.activity_id != identity.activity_id
                or actual_receipt.status != "committed" or actual_receipt.operation_id != stage.operation_id
                or (actual_receipt.activity_id, actual_receipt.effect_id) != (identity.activity_id, identity.effect_id)
                or stage.read_versions != prior_frame.snapshot.versions
                or actual_receipt.read_versions != prior_frame.envelope.version_guard.read_versions
                or prior_frame.owner_guard != owner.material_owner_guard
                or (prior_frame.envelope.version_guard.access_epoch, prior_frame.envelope.version_guard.delete_epoch)
                    != owner.expected_rights
                or owner.runtime._active_foreground_issuance_v1 is not issued
                or owner.runtime._active_foreground_process_lease_v1 is not process_lease):
            raise AuthorityUnavailable("Artifact successor changed the actual stage/receipt/Owner/process lease")
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
        return (self.owner, self.db, self.graph, self.namespace, self.prior_frame, self.stage, self.receipt,
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
        receipt, frame, owner = self.receipt, self.prior_frame, self.owner
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
        if (len(writes) != 3 or len(writes) != sum(len(proposal.typed_writes) for proposal in self.stage.proposals)
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
        owner.operation.retain(_heap((self.head_metadata, self.histories, self.point_rows, self.coverage)) + 4096)

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
        changed = {version.key.token for version in self.receipt.write_versions}
        for request, task in (*self.owner.points.items(), *self.owner.attachments.items()):
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
        _POST_COMMIT_PROOFS.pop(self, None)
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
        if (primary is not stage.stage or primary.domain != "d11" or primary.coverage != "complete"
                or primary.operation_kind != owner.operation_kind or primary.operation_id != owner.operation_id
                or primary.namespace != owner.namespace or primary.activity_id != identity.activity_id
                or identity.operation_id != owner.operation_id or actual_receipt.status != "committed"
                or (actual_receipt.operation_id, actual_receipt.activity_id, actual_receipt.effect_id)
                    != (identity.operation_id, identity.activity_id, identity.effect_id)
                or primary.read_versions != prior_frame.snapshot.versions
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
