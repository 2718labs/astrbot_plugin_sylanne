"""Additional Joint restrictions, authenticated negative census and fixed Source gates.

A metadata-only early restriction can decline work but cannot classify a recipe
as ordinary or grant managed execution. Positive classifications consume the
actual current Source-qualified operation frame, immutable recipe original and
complete authenticated guard-table EOF in the same selected storage lifetime.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3, _runtime_bounded_fixed_row_v3
from .b3_managed_metadata_v1 import JOINT_TABLE, metadata_columns_v1, validate_managed_metadata_row_v1
from .joint_window_management_v1 import (
    ManagedWindowArgumentV1, JointWindowClassificationV1, managed_window_selector_digest_v1)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1

_KEY = object()
_RESTRICTIONS = WeakKeyDictionary()
_FRAME_BINDINGS = {}


@dataclass(frozen=True, slots=True, weakref_slot=True)
class JointWindowRestrictionCheckedV3:
    namespace: NamespaceId
    action_ref: str | None
    binding_ref: str | None
    inventory_digest: str
    # This object contains no complete/ordinary/managed permission observation.
    schema: str = 'd08.joint-window-restriction-checked.v3'


def is_joint_window_restriction_checked_v3(value, namespace):
    return (type(value) is JointWindowRestrictionCheckedV3 and value.namespace == namespace
        and _RESTRICTIONS.get(value) == (value.namespace, value.action_ref, value.binding_ref, value.inventory_digest))


class JointWindowGuardInventoryV3:
    def __init__(self, key, db, namespace, issuer, operation):
        if key is not _KEY or type(namespace) is not NamespaceId or operation is None or operation.closed:
            raise AuthorityUnavailable('Joint guard EOF requires actual retained selected storage')
        self.db, self.namespace, self.issuer, self.operation = db, namespace, issuer, operation
        self.selection_digest = operation.selection_digest
        self.after, self.complete, self.count = '', False, 0
        self.rows = []
        self.digest = canonical_digest(('d08.joint-managed-guard-eof.v3', namespace, self.selection_digest))
        self.epoch = None

    def advance(self, meter):
        from .b3_managed_metadata_v1 import DDLS
        if self.operation.closed or self.operation.selection_digest != self.selection_digest:
            raise AuthorityUnavailable('Joint guard EOF changed selected storage retention')
        if self.epoch is None:
            schema = _runtime_bounded_fixed_row_v3(self.db, meter, 'sqlite_master', ('sql',),
                'type=? AND name=?', ('table', JOINT_TABLE))
            if schema != (DDLS[JOINT_TABLE],):
                raise AuthorityUnavailable('Joint guard EOF requires its actual canonical installed table')
            self.epoch = _runtime_bounded_fixed_row_v3(self.db, meter, 'graph_epochs', ('revision',),
                'bot=? AND persona=?', self.namespace.as_tuple)
            if self.epoch is None:
                raise AuthorityUnavailable('Joint guard EOF has no current namespace epoch')
            return False
        current = _runtime_bounded_fixed_row_v3(self.db, meter, 'graph_epochs', ('revision',),
            'bot=? AND persona=?', self.namespace.as_tuple)
        if current != self.epoch:
            raise AuthorityUnavailable('Joint guard EOF namespace changed')
        if self.complete:
            return True
        row = _runtime_bounded_fixed_row_v3(self.db, meter, JOINT_TABLE, metadata_columns_v1(JOINT_TABLE),
            'bot=? AND persona=? AND selector_digest>? ORDER BY selector_digest', (*self.namespace.as_tuple, self.after))
        if row is None:
            self.complete = True
            self.digest = canonical_digest((self.digest, 'actual_eof', self.count, self.epoch))
            return True
        ns, value = validate_managed_metadata_row_v1(JOINT_TABLE, metadata_columns_v1(JOINT_TABLE), tuple(row), issuer=self.issuer)
        if ns != self.namespace or value['selector_digest'] <= self.after:
            raise AuthorityUnavailable('Joint guard metadata crossed its actual namespace/cursor')
        from .dispatch_current_inventory_v3 import _heap
        self.operation.retain(_heap(row) * 2 + 1024)
        self.rows.append(value)
        self.after = value['selector_digest']
        self.count += 1
        self.digest = canonical_digest((self.digest, tuple(row)))
        return False

    def require(self):
        if not self.complete or self.operation.closed:
            raise AuthorityUnavailable('Joint guard classification requires full authenticated EOF')
        with runtime_storage_quantum_v3(self.db) as meter:
            if _runtime_bounded_fixed_row_v3(self.db, meter, 'graph_epochs', ('revision',),
                    'bot=? AND persona=?', self.namespace.as_tuple) != self.epoch:
                raise AuthorityUnavailable('Joint guard classification namespace changed after EOF')
        return self


def create_joint_guard_inventory_for_work_v3(work, issuer):
    from ..authority_service.named_joint_binding_source_read_v3 import require_named_joint_inputs_v3
    require_named_joint_inputs_v3(work)
    return JointWindowGuardInventoryV3(_KEY, work.db, work.namespace, issuer, work.operation)


@contextmanager
def _guard_inventory(db, namespace, issuer):
    from ..authority_service.named_joint_binding_body_v1 import _bound
    qualified=_bound(db)
    if qualified is not None:
        if qualified.work.namespace!=namespace or qualified.service.issuer is not issuer or qualified.guard_inventory.operation is not qualified.work.operation:
            raise AuthorityUnavailable('Joint guard EOF crossed its actual privately qualified Source Work')
        yield qualified.guard_inventory.require()
        return
    from .artifact_host_dispatch_source_v3 import current_artifact_host_joint_inventory_v3
    host_artifact=current_artifact_host_joint_inventory_v3(db)
    if host_artifact is not None:
        yield host_artifact.require()
        return
    from ..authority_service.artifact_model_source_read_v3 import current_artifact_model_joint_inventory_v3
    artifact=current_artifact_model_joint_inventory_v3(db)
    if artifact is not None:
        yield artifact.require()
        return
    from .current_method_learning_read_v3 import _method_active,BorrowedMethodLearningReadV3
    from .borrowed_habit_classification_v3 import BORROWED_HABIT_METADATA_OPERATIONS_V3,require_borrowed_habit_metadata_eof_v3
    borrowed=_method_active(db)
    if type(borrowed)is BorrowedMethodLearningReadV3 and borrowed.operation_kind in BORROWED_HABIT_METADATA_OPERATIONS_V3:
        proof=require_borrowed_habit_metadata_eof_v3(borrowed)
        if borrowed.namespace!=namespace or borrowed.graph._GraphCoordinator__d11_issuer is not issuer:
            raise AuthorityUnavailable('Joint classification crossed the original Borrowed metadata EOF scope')
        yield _BorrowedJointGuardInventoryV3(borrowed,proof,issuer).require()
        return
    from uuid import uuid4
    from ..runtime_storage_v3 import (_OPERATION, begin_runtime_storage_operation_v3,
        bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3)
    existing = _OPERATION.get()
    operation = existing if existing is not None else begin_runtime_storage_operation_v3(db, 'joint-guard-restriction:' + uuid4().hex, None)
    try:
        with bind_runtime_storage_operation_v3(operation, db):
            inventory = JointWindowGuardInventoryV3(_KEY, db, namespace, issuer, operation)
            while not inventory.complete:
                with runtime_storage_quantum_v3(db) as meter:
                    inventory.advance(meter)
            yield inventory.require()
    finally:
        if existing is None:
            finish_runtime_storage_operation_v3(operation)


def _positive_head_original(db, read, atom, expected_kinds=None, expected_operation=None, expected_digest=None):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_background_read_v3 import background_history_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..graph_types import GraphWrite
    ns = read.frame.envelope.authority.namespace
    history = background_history_v3(db, atom.key.token, atom.revision, columns=('event_id', 'valid'))
    if history is None or history[1] != 1:
        raise MissingProductionOriginalV1('actual_joint_current_producing_history')
    actual = read_adopted_domain_operation_v1(db, ns, history[0])
    if (actual is None or actual['receipt'].status != 'committed'
            or expected_kinds is not None and actual['operation_kind'] not in expected_kinds
            or expected_operation is not None and history[0] != expected_operation
            or expected_digest is not None and canonical_digest(actual['receipt']) != expected_digest
            or GraphVersion(atom.key, atom.revision) not in actual['receipt'].write_versions):
        raise MissingProductionOriginalV1('actual_joint_current_positive_commit')
    writes = tuple(decode_typed_production_value_v1(raw, GraphWrite) for raw in actual['payload']['writes'] if raw['key'] == atom.key.token)
    if len(writes) != 1 or canonical_digest(writes[0].value) != canonical_digest(atom.value):
        raise AuthorityUnavailable('Joint current Head differs from its actual producing COMMIT member')
    return actual


def _source_groups(db, read, groups):
    for roots, purpose, audiences in groups:
        if not roots:
            raise MissingProductionOriginalV1('actual_joint_recipe_source_roots')
        for audience in audiences:
            read.source_family(db, tuple(roots), purpose=purpose, audience=audience)


def _binding_input(db, read, binding, issuer):
    from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1, qualify_artifact_prospective_binding_v1
    from .joint_node_execution_v1 import JointContactProspectiveBindingV1
    from .joint_contact_prospective_binding_v1 import qualify_contact_prospective_binding_v1
    if type(binding) is JointArtifactProspectiveBindingV1:
        qualify_artifact_prospective_binding_v1(db, frame=read.frame, binding=binding, issuer=issuer)
        original = read.original(binding.task_scope_ref, digest=binding.task_scope_digest)
        return 'draft_file', binding.task_scope_ref, binding.task_scope_digest, original
    if type(binding) is JointContactProspectiveBindingV1:
        qualify_contact_prospective_binding_v1(db, frame=read.frame, binding=binding, issuer=issuer)
        original = read.original(binding.prospective_original_ref, digest=binding.prospective_original_digest)
        return 'contact', binding.prospective_original_ref, binding.prospective_original_digest, original
    raise AuthorityUnavailable('Managed binding input requires its original fixed prospective executor')


def _preparation_input(db, frame, operation_kind, request, issuer):
    from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1
    from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1
    read = CurrentDomainReadV1(frame)
    read.check(db)
    if operation_kind == 'prepare_selected_source_note_action_v2' and type(request) is ConsumePersonalDecisionRequestV1:
        decision = read.head(db, request.decision_ref, required=True)
        original = _positive_head_original(db, read, decision,
            {'select_personal_step', 'select_personal_step_v2', 'select_current_conditioned_personal_step_v1'})
        # This proves the actual immutable Decision, while the original selected
        # adapter remains responsible for its full candidate/current future proof.
        return 'source_note', decision.key.token, canonical_digest(decision.value), original
    if operation_kind == 'input:register_joint_node_execution_binding_v1' and type(request) is RegisterJointNodeExecutionBindingRequestV1:
        return _binding_input(db, read, request.binding, issuer)
    raise AuthorityUnavailable('Joint preparation operation has no closed original recipe')


def _current_window(db, read, row, *, preparing, issuer):
    from ..domains.d08.long_term_plan_v1 import LONG_PLAN_TYPE, JOINT_WINDOW_TYPE, long_term_value_from_wire_v1
    window_atom = read.head(db, row['window_ref'], required=True)
    plan_atom = read.head(db, row['plan_ref'], required=True)
    window = long_term_value_from_wire_v1(JOINT_WINDOW_TYPE, window_atom.value)
    plan = long_term_value_from_wire_v1(LONG_PLAN_TYPE, plan_atom.value)
    if window.long_term_plan_ref != plan_atom.key.token or plan.state in {'paused', 'stopped', 'closed'}:
        raise MissingProductionOriginalV1('actual_current_joint_window_long_plan')
    if window_atom.revision < row['window_birth_revision'] or read.frame.now_utc >= window.original_deadline_utc:
        raise MissingProductionOriginalV1('actual_unexpired_joint_window_current_revision')
    _source_groups(db, read, ((window.source_refs, read.frame.envelope.authority.purpose, read.frame.envelope.authority.audience),
        (plan.source_refs, plan.purpose, plan.audience)))
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    born = read_adopted_domain_operation_v1(db, plan.namespace, row['registration_operation_id'])
    if (born is None or born['operation_kind'] != 'prepare_joint_window_v1' or born['receipt'].status != 'committed'
            or canonical_digest(born['receipt']) != row['registration_receipt_digest']
            or GraphVersion(window_atom.key, row['window_birth_revision']) not in born['receipt'].write_versions):
        raise MissingProductionOriginalV1('actual_named_joint_window_birth_positive_commit')
    birth_writes = tuple(raw for raw in born['payload']['writes'] if raw['key'] == window_atom.key.token)
    if len(birth_writes) != 1 or canonical_digest(birth_writes[0]['value']) != row['window_birth_digest']:
        raise AuthorityUnavailable('Joint guard differs from actual immutable Window birth')
    _positive_head_original(db, read, window_atom)
    _positive_head_original(db, read, plan_atom)
    if preparing:
        if window.state != 'preparing':
            raise MissingProductionOriginalV1('actual_joint_window_preparing')
        if window.prior_window_ref is None:
            if window.window_index != 0 or plan.current_window_ref is not None:
                raise MissingProductionOriginalV1('actual_initial_preparing_window_and_empty_pointer')
        else:
            prior_atom = read.head(db, window.prior_window_ref, required=True)
            prior = long_term_value_from_wire_v1(JOINT_WINDOW_TYPE, prior_atom.value)
            if (plan.current_window_ref != prior_atom.key.token or prior.long_term_plan_ref != plan_atom.key.token
                    or window.window_index != prior.window_index + 1):
                raise MissingProductionOriginalV1('actual_exact_preparing_window_successor')
            _source_groups(db, read, ((prior.source_refs, read.frame.envelope.authority.purpose, read.frame.envelope.authority.audience),))
            _positive_head_original(db, read, prior_atom)
            from .d08_long_term_plan_v1 import _joint_current
            _joint_current(db, read.frame, prior, issuer=issuer, completed=True)
    elif window.state != 'ready' or plan.current_window_ref != window_atom.key.token:
        raise MissingProductionOriginalV1('actual_current_ready_joint_execution_window')
    node = next((item for item in window.node_drafts if item.node_id == row['node_id']), None)
    if node is None or (node.executor_kind, node.typed_request_ref, node.typed_input_original_digest, node.typed_request_digest) != (
            row['executor_kind'], row['input_ref'], row['input_digest'], row['request_digest']):
        raise AuthorityUnavailable('Joint guard changed actual immutable node/input/request commitment')
    _source_groups(db, read, ((node.source_refs, node.purpose, node.audience),))
    return window_atom, window, plan_atom, plan, node


def _classification(db, frame, inventory, *, executor_kind, input_ref, input_digest, ordinary_original_ref,
        ordinary_original_digest, argument, preparing, issuer, binding_ref=None, action_ref=None):
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    selector = managed_window_selector_digest_v1(ns, executor_kind, input_ref, input_digest)
    inventory.require()
    matches = tuple(row for row in inventory.rows if row['selector_digest'] == selector)
    aliases = tuple(row for row in inventory.rows if not row['retired'] and (
        action_ref is not None and row['action_ref'] == action_ref or binding_ref is not None and row['binding_ref'] == binding_ref))
    if len(matches) > 1 or any(row not in matches for row in aliases):
        raise AuthorityUnavailable('Joint immutable recipe aliases disagree with full authenticated guard census')
    if not matches:
        if argument is not None:
            raise MissingProductionOriginalV1('named_joint_guard_is_not_an_actual_registered_window')
        return JointWindowClassificationV1(ns, executor_kind, selector, 'ordinary', None, None, None, None, None, None,
            inventory.epoch[0], True, ordinary_original_ref, ordinary_original_digest)
    row = matches[0]
    if row['retired']:
        raise MissingProductionOriginalV1('actual_opaque_retired_joint_selector_deny')
    window_atom, window, plan_atom, plan, node = _current_window(db, read, row, preparing=preparing, issuer=issuer)
    actual = ManagedWindowArgumentV1(window_atom.key.token, window_atom.revision, node.node_id, node.executor_kind,
        node.typed_request_ref, node.typed_input_original_digest, node.typed_request_digest)
    if preparing and (argument is None or argument != actual):
        raise MissingProductionOriginalV1('actual_explicit_named_joint_preparation_argument')
    return JointWindowClassificationV1(ns, executor_kind, selector, 'managed', actual, plan_atom.key.token, plan_atom.revision,
        plan.state, plan.current_window_ref, window.state, inventory.epoch[0], True)


def require_current_joint_window_management_v3(db, *, frame, operation_kind, request):
    binding = _FRAME_BINDINGS.get(id(frame))
    argument = None if binding is None else binding[1]
    issuer = None if binding is None else binding[2]
    if issuer is None:
        from .current_method_learning_read_v3 import _method_active
        reader = _method_active(db)
        if reader is None:
            raise AuthorityUnavailable('Joint preparation requires its actual private Source frame binding')
        issuer = reader.graph._GraphCoordinator__d11_issuer
    with _guard_inventory(db, frame.envelope.authority.namespace, issuer) as inventory:
        kind, ref, digest, original = _preparation_input(db, frame, operation_kind, request, issuer)
        original_ref = original.original_ref if hasattr(original, 'original_ref') else original['domain'] + '-current:' + original['original_digest'][:48]
        original_digest = original.original_digest if hasattr(original, 'original_digest') else original['original_digest']
        value = _classification(db, frame, inventory, executor_kind=kind, input_ref=ref, input_digest=digest,
            ordinary_original_ref=original_ref, ordinary_original_digest=original_digest, argument=argument, preparing=True, issuer=issuer)
    return value, argument


def read_current_joint_window_execution_classification_v3(db, *, namespace, issuer, action_ref=None, binding=None, frame=None):
    from .joint_node_execution_v1 import JointArtifactProspectiveBindingV1, JointContactProspectiveBindingV1, JointNodeExecutionBindingV1, read_joint_binding_v1, qualify_joint_binding_v1
    if (action_ref is None) == (binding is None):
        raise ValueError('Joint execution restriction requires exactly one actual action or binding')
    if frame is None:
        # Early host task lookups have no Source scope. Complete HMAC metadata
        # can reject a known selector, but this object grants no positive right.
        with _guard_inventory(db, namespace, issuer) as inventory:
            binding_ref=None if binding is None else binding.original_ref
            selected=None
            if binding is not None:
                if type(binding)is JointArtifactProspectiveBindingV1:
                    selected=managed_window_selector_digest_v1(namespace,'draft_file',binding.task_scope_ref,binding.task_scope_digest)
                elif type(binding)is JointContactProspectiveBindingV1:
                    selected=managed_window_selector_digest_v1(namespace,'contact',binding.prospective_original_ref,binding.prospective_original_digest)
            for row in inventory.rows:
                if selected==row['selector_digest']:
                    if row['retired']:raise MissingProductionOriginalV1('actual_opaque_retired_joint_selector_deny')
                    if row['birth_operation_id'] is None:raise MissingProductionOriginalV1('actual_named_joint_preparation_has_not_committed')
                if not row['retired'] and(action_ref is not None and row['action_ref']==action_ref or binding_ref is not None and row['binding_ref']==binding_ref):
                    if row['birth_operation_id'] is None:raise MissingProductionOriginalV1('actual_named_joint_birth_is_not_committed')
            value = JointWindowRestrictionCheckedV3(namespace, action_ref, binding_ref, inventory.digest)
            _RESTRICTIONS[value] = (value.namespace, value.action_ref, value.binding_ref, value.inventory_digest)
            return value
    with _guard_inventory(db, namespace, issuer) as inventory:
        return _qualified_execution_classification(db, frame, inventory, namespace=namespace, issuer=issuer,
            action_ref=action_ref, binding=binding)


def _qualified_execution_classification(db, frame, inventory, *, namespace, issuer, action_ref, binding):
    from .joint_node_execution_v1 import JointArtifactProspectiveBindingV1, JointContactProspectiveBindingV1, JointNodeExecutionBindingV1, read_joint_binding_v1, qualify_joint_binding_v1
    read = CurrentDomainReadV1(frame)
    read.check(db)
    if frame.envelope.authority.namespace != namespace:
        raise ValueError('Joint execution frame changed the actual namespace')
    if binding is not None:
        actual = read_joint_binding_v1(db, namespace=namespace, ref=binding.original_ref, issuer=issuer)
        if actual != binding:
            raise AuthorityUnavailable('Joint execution binding differs from its actual signed positive producer')
        if type(binding) in {JointArtifactProspectiveBindingV1, JointContactProspectiveBindingV1}:
            kind, ref, digest, original = _binding_input(db, read, binding, issuer)
            ordinary_ref, ordinary_digest = original.original_ref, original.original_digest
        elif type(binding) is JointNodeExecutionBindingV1:
            qualify_joint_binding_v1(db, frame=frame, binding=binding, issuer=issuer)
            from .joint_node_execution_v1 import SourceNoteJointExecutorV1, ArtifactJointExecutorV1
            executor = binding.executor
            if type(executor) is ArtifactJointExecutorV1:
                from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
                from .d11_life_preparation_v1 import _read
                ref = task_scope_ref_v1(executor.root_registration_ref)
                scope = _read(db, issuer=issuer, namespace=namespace, kind='artifact_task_scope', ref=ref)
                if scope is None:
                    raise MissingProductionOriginalV1('actual_immutable_artifact_task_scope_for_complete_joint_classification')
                digest = canonical_digest(scope[0])
                original = read.original(ref, digest=digest)
                kind, ordinary_ref, ordinary_digest = 'draft_file', original.original_ref, original.original_digest
            elif type(executor) is SourceNoteJointExecutorV1:
                kind, ref, digest, ordinary_ref, ordinary_digest = _selected_or_original_source_note_action(
                    db, read, binding.action_ref)
            else:
                kind,ref,digest,ordinary_ref,ordinary_digest=_contact_action_recipe(db,read,binding.action_ref,issuer)
        else:
            raise AuthorityUnavailable('Joint execution binding has no actual registered immutable recipe')
    else:
        kind, ref, digest, ordinary_ref, ordinary_digest = _actual_action_recipe(db,read,action_ref,issuer)
    return _classification(db, frame, inventory, executor_kind=kind, input_ref=ref, input_digest=digest,
        ordinary_original_ref=ordinary_ref, ordinary_original_digest=ordinary_digest, argument=None, preparing=False,
        issuer=issuer, binding_ref=None if binding is None else binding.original_ref, action_ref=action_ref)


@contextmanager
def bind_current_joint_window_source_frame_v3(frame, *, graph, argument, selector=None):
    if type(argument) is not ManagedWindowArgumentV1 or id(frame) in _FRAME_BINDINGS:
        raise AuthorityUnavailable('Joint named frame requires one actual fixed managed argument')
    record = (frame, argument, graph._GraphCoordinator__d11_issuer, selector, graph)
    _FRAME_BINDINGS[id(frame)] = record
    try:
        yield record
    finally:
        _FRAME_BINDINGS.pop(id(frame), None)

def _selected_or_original_source_note_action(db, read, action_ref):
    action = read.head(db, action_ref, required=True)
    original = _positive_head_original(db, read, action,
        {'prepare_selected_source_note_action_v2', 'prepare_source_note_action'})
    proof = original['payload']['provenance']
    original_ref = original['domain'] + '-current:' + original['original_digest'][:48]
    if original['operation_kind'] == 'prepare_selected_source_note_action_v2':
        ref, digest = proof['selected_decision_ref'], proof['selected_decision_digest']
        decision = read.head(db, ref, required=True)
        if canonical_digest(decision.value) != digest:
            raise AuthorityUnavailable('Joint selected SourceNote action changed its immutable Decision')
        _positive_head_original(db, read, decision,
            {'select_personal_step', 'select_personal_step_v2', 'select_current_conditioned_personal_step_v1'})
    else:
        # This real legacy producer cannot consume ManagedWindowArgumentV1;
        # the exact immutable W01 Original is its ordinary recipe identity.
        if proof.get('managed_window_argument') is not None:
            raise AuthorityUnavailable('Legacy ordinary SourceNote cannot carry a named managed birth')
        ref, digest = original_ref, original['original_digest']
    roots = tuple(dict.fromkeys(v.key.token for v in original['read_versions'] if v.key.type_name == 'memory.source'))
    _source_groups(db, read, ((roots, read.frame.envelope.authority.purpose, read.frame.envelope.authority.audience),))
    return 'source_note', ref, digest, original_ref, original['original_digest']


def _artifact_scope_recipe(db,read,root_registration_ref,issuer):
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from .d11_life_preparation_v1 import _read
    ref=task_scope_ref_v1(root_registration_ref)
    saved=_read(db,issuer=issuer,namespace=read.frame.envelope.authority.namespace,kind='artifact_task_scope',ref=ref)
    if saved is None:raise MissingProductionOriginalV1('actual_immutable_artifact_task_scope_for_joint_classification')
    digest=canonical_digest(saved[0]);original=read.original(ref,digest=digest)
    return 'draft_file',ref,digest,original.original_ref,original.original_digest


def _contact_action_recipe(db,read,action_ref,issuer):
    from .contact_prospective_v1 import read_contact_prospective_original_v1,contact_prospective_original_ref_v1
    from .domain_background_read_v3 import background_json_loads_v3
    atom=read.head(db,action_ref,required=True)
    actual=_positive_head_original(db,read,atom,{'prepare_contact_dispatch','prepare_contact_dispatch_v3'})
    ref=actual['domain']+'-current:'+actual['original_digest'][:48]
    birth=read_contact_prospective_original_v1(db,issuer,read.frame.envelope.authority.namespace,actual['payload']['request']['contact_id'])
    if birth is not None:
        raw=background_json_loads_v3(birth.payload_json)
        # Only the immutable birth's exact future Action may consume its managed
        # selector. Another legacy Action keeps its actual original recipe.
        identity=atom.value['identity']
        if(identity['operation_id'],identity['effect_id'])==(raw['final_operation_id'],raw['effect_id']):
            birth_ref=contact_prospective_original_ref_v1(read.frame.envelope.authority.namespace,raw['contact_id'],raw['birth_operation_id'])
            original=read.original(birth_ref,digest=birth.digest)
            return 'contact',birth_ref,birth.digest,original.original_ref,original.original_digest
    if actual['payload']['provenance'].get('managed_window_argument') is not None:
        raise AuthorityUnavailable('Managed Contact cannot downgrade its immutable birth to an ordinary Action')
    roots=tuple(dict.fromkeys(v.key.token for v in actual['read_versions']if v.key.type_name=='memory.source'))
    _source_groups(db,read,((roots,read.frame.envelope.authority.purpose,read.frame.envelope.authority.audience),))
    return 'contact',ref,actual['original_digest'],ref,actual['original_digest']


def _actual_action_recipe(db,read,action_ref,issuer):
    atom=read.head(db,action_ref,required=True)
    actual=_positive_head_original(db,read,atom)
    kind=actual['operation_kind']
    if kind in {'prepare_selected_source_note_action_v2','prepare_source_note_action'}:
        return _selected_or_original_source_note_action(db,read,action_ref)
    if kind in {'propose_artifact_draft_action','propose_artifact_draft_phase_action_v2'}:
        request=actual['payload']['request']
        root=request['root_registration_ref']if kind=='propose_artifact_draft_action'else request['selector']['task']['root_registration_ref']
        return _artifact_scope_recipe(db,read,root,issuer)
    if kind in {'prepare_contact_dispatch','prepare_contact_dispatch_v3'}:
        return _contact_action_recipe(db,read,action_ref,issuer)
    raise MissingProductionOriginalV1('actual_closed_joint_executor_action_recipe')


def prepare_current_managed_joint_node_source_work_v3(graph,context,argument,request):
    from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1
    from .named_joint_source_work_v3 import prepare_named_joint_host_work_v3
    from .named_joint_source_note_command_v1 import ManagedSourceNotePreparationRequestV1
    if type(argument)is not ManagedWindowArgumentV1:raise TypeError('Exact adopted managed argument required')
    if type(request)is RegisterJointNodeExecutionBindingRequestV1:
        return prepare_named_joint_host_work_v3(graph,context,argument,request)
    if type(request)is ManagedSourceNotePreparationRequestV1:
        if argument.executor_kind!='source_note':raise ValueError('Original SourceNote request changed its adopted executor')
        return prepare_named_joint_host_work_v3(graph,context,argument,request.command,original_selector=request.original_selector)
    raise TypeError('Named preparation accepts only closed original prospective or SourceNote commands')


class _BorrowedJointGuardInventoryV3:
    """Projection of the actual same-Work two-table EOF, never another census."""
    def __init__(self,reader,proof,issuer):
        self.reader,self.proof=reader,proof
        self.operation=reader.operation;self.epoch=(reader.graph_stamp[1].revision,)
        self.digest=proof.commitment;self.complete=True
        self.rows=tuple(validate_managed_metadata_row_v1(JOINT_TABLE,metadata_columns_v1(JOINT_TABLE),row,issuer=issuer)[1]
            for row in proof.managed_rows_v3(JOINT_TABLE))
    def require(self):
        self.proof.require_current_v3(self.reader)
        if self.digest!=self.proof.commitment or self.operation.closed:
            raise AuthorityUnavailable('Joint classification lost its original complete Borrowed metadata EOF')
        return self

