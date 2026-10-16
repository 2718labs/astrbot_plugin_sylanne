"""Fixed Owner state READ on the existing independently qualified Beta1 Source Work.

The caller selects only current World/Habit/LongWindow references. Metadata is
streamed before Source ALL; bodies and W01 originals open only after current
Owner EOF and full-parent Source/Access/Correction qualification. This profile
never seals write inputs or enters a domain business operation.
"""
from dataclasses import dataclass, field
from weakref import WeakKeyDictionary
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3

READ_KIND = 'read_beta1_owner_state_v1'
_TYPES = {
    'world': frozenset({'d03.world_assertion_input.v1', 'd03.world_view.v1', 'd09.world_perspective_input.v1'}),
    'habit': frozenset({'d10.habit_policy.v1', 'd10.habit_occurrence.v1'}),
    'long_window': frozenset({'d08.long_term_plan.v1', 'd08.joint_window.v1'}),
}
def owner_state_required_domains_v3(request):
    if type(request) is not Beta1OwnerStateRequestV1:
        raise AuthorityUnavailable('Owner state domains require the exact typed finite request')
    domains = {'d06', 'd11', *(AtomKey.from_token(ref).type_name.split('.')[0] for ref in request.refs)}
    if request.domain == 'world':
        domains.add('d03')
    return frozenset(domains)
_PRODUCERS = {
    'd03.world_assertion_input.v1': frozenset({'adopt_world_assertion_v1', 'relearn_world_assertion_v1'}),
    'd03.world_view.v1': frozenset({'query_world_view_v1'}),
    'd09.world_perspective_input.v1': frozenset({'project_world_perspective_v1'}),
    'd10.habit_policy.v1': frozenset({'create_habit_policy_v1', 'revise_habit_policy_v1', 'pause_habit_policy_v1', 'resume_habit_policy_v1', 'stop_habit_policy_v1'}),
    'd10.habit_occurrence.v1': frozenset({'register_habit_occurrence_v1', 'qualify_habit_occurrence_v1', 'record_habit_miss_v1', 'adopt_habit_outcome_v1', 'instantiate_current_habit_source_note_context_v1', 'prepare_current_habit_source_note_action_v1', 'register_current_habit_source_note_life_plan_v1'}),
    'd08.long_term_plan.v1': frozenset({'adopt_long_term_plan_v1', 'prepare_joint_window_v1', 'enter_current_joint_window_v1', 'finalize_current_joint_window_v1', 'advance_long_term_window_v1', 'pause_long_term_plan_v1', 'resume_long_term_plan_v1', 'stop_long_term_plan_v1'}),
    'd08.joint_window.v1': frozenset({'prepare_joint_window_v1', 'enter_current_joint_window_v1', 'finalize_current_joint_window_v1', 'advance_long_term_window_v1', 'pause_long_term_plan_v1', 'resume_long_term_plan_v1', 'stop_long_term_plan_v1'}),
}
_FACTORIES = WeakKeyDictionary()
_STATES = WeakKeyDictionary()
_RESULTS = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class Beta1OwnerStateRequestV1:
    domain: str
    refs: tuple[str, ...]

    def __post_init__(self):
        if self.domain not in _TYPES or type(self.refs) is not tuple or not 1 <= len(self.refs) <= 16 or len(set(self.refs)) != len(self.refs):
            raise ValueError('Owner state requires one to sixteen unique fixed-domain references')
        for ref in self.refs:
            key = AtomKey.from_token(ref)
            if key.token != ref or key.type_name not in _TYPES[self.domain]:
                raise ValueError('Owner state reference is outside its exact registered domain types')


def decode_owner_state_request_v1(data):
    if type(data) is not dict or set(data) != {'domain', 'refs'} or type(data['refs']) is not list:
        raise ValueError('Owner state requires exactly domain and refs')
    return Beta1OwnerStateRequestV1(data['domain'], tuple(data['refs']))


def _identity(reader):
    return (reader.graph, reader.work, reader.operation, reader.fence, reader.authority, reader.lease,
        reader.session_proof, reader.request, reader.selection_digest, reader.graph_stamp,
        reader.catalogue_hash, reader.initial_monotonic_deadline)


@dataclass(slots=True)
class _StateReadV3:
    reader: object
    identity: tuple
    tasks: dict = field(default_factory=dict)
    histories: dict = field(default_factory=dict)
    world_views: dict = field(default_factory=dict)
    producers: set = field(default_factory=set)
    roots: set = field(default_factory=set)
    source_permission: object = None
    metadata_complete: bool = False
    first_utc: float = 0.0
    first_monotonic: float = 0.0


def register_owner_state_reader_v3(reader, work):
    from .current_method_learning_read_v3 import _MethodLearningReadV3, _READERS
    from .current_beta1_source_read_v3 import WORLD_SOURCE_WORK_KIND_V3
    issued = _FACTORIES.get(reader)
    if (type(reader) is not _MethodLearningReadV3 or reader not in _READERS or issued != _identity(reader)
            or reader.work is not work or work.state is not reader or work.operation is not reader.operation
            or work.coordinator is not reader.graph or work.kind != WORLD_SOURCE_WORK_KIND_V3
            or type(reader.request) is not Beta1OwnerStateRequestV1 or reader.operation_kind != READ_KIND
            or reader.session_proof is None or reader.fence.scope.operation != 'read'
            or reader.authority.purpose != 'context' or reader.authority.audience != ('owner',)
            or 'workbench.read' not in reader.owner_binding.capabilities or reader in _STATES
            or reader.projection_types or reader.preplan_families):
        raise AuthorityUnavailable('Owner state requires its privately issued exact signed Source READ factory')
    for ref in reader.request.refs:
        if NamespaceId.from_key(AtomKey.from_token(ref)) != reader.namespace:
            raise AuthorityUnavailable('Owner state reference crossed the actual current namespace')
    work._require_invocation(reader.graph, initial=True)
    reader.graph._authorize(reader.lease, reader.authority, owner_state_required_domains_v3(reader.request), owner_read=True)
    _STATES[reader] = _StateReadV3(reader, _identity(reader), first_utc=reader.initial_now_utc, first_monotonic=time.monotonic())
    return work


def require_owner_state_reader_v3(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(reader)
    state = _STATES.get(reader)
    if state is None or state.reader is not reader or state.identity != _identity(reader) or _FACTORIES.get(reader) != _identity(reader):
        raise AuthorityUnavailable('Owner state lost its exact private read profile/Owner/selection')
    return state


def pin_owner_state_owner_v3(reader):
    state = require_owner_state_reader_v3(reader)
    if reader.general_owner_entry is None:
        raise AuthorityUnavailable('Owner state requires its actual completed independent Owner EOF')
    return state


def owner_state_source_groups_v3(reader, roots):
    state = require_owner_state_reader_v3(reader)
    if not state.metadata_complete or set(roots) != state.roots:
        raise AuthorityUnavailable('Owner state Source union differs from its complete fixed metadata recipe')
    from .named_joint_node_descriptor_v3 import descriptor_groups_v3
    groups=descriptor_groups_v3(reader,roots)
    if groups is not None:return groups
    return (('context', ('owner',), tuple(sorted(roots))),) if roots else ()


def owner_state_metadata_spec_v3(reader, identity):
    state = require_owner_state_reader_v3(reader)
    from .named_joint_node_descriptor_v3 import descriptor_metadata_spec_v3
    descriptor=descriptor_metadata_spec_v3(reader,identity)
    if descriptor is not None:return descriptor
    kind, ref = identity
    if ref not in reader.request.refs and not (kind == 'view_head' and ref in state.world_views):
        raise AuthorityUnavailable('Owner state metadata reference was not explicitly selected')
    if kind in {'head', 'view_head'}:
        return ('graph_atoms', 'value', ('token', 'bot', 'persona'), (ref, *reader.namespace.as_tuple),
            ('revision', 'valid', 'value_cell_id'), (('source_refs',), ('definition', 'source_refs'), ('view_version',)), None)
    if kind == 'world_index' and AtomKey.from_token(ref).type_name == 'd03.world_assertion_input.v1':
        from .d03_world_history_v1 import TABLE, SIGN_KIND
        return (TABLE, 'payload_json', ('bot', 'persona', 'original_ref'), (*reader.namespace.as_tuple, ref),
            ('payload_digest', 'signature', 'producing_operation_id', 'assertion_commitment', 'known_sequence'),
            (('source_refs',), ('input_version',), ('adoption_operation_id',), ('assertion_commitment',), ('known_from_sequence',)), SIGN_KIND)
    raise AuthorityUnavailable('Owner state metadata shape is not part of its fixed read profile')


def finish_owner_state_metadata_v3(task, value):
    reader = task.reader
    state = require_owner_state_reader_v3(reader)
    if value is None:
        return None
    from .named_joint_node_descriptor_v3 import finish_descriptor_metadata_v3
    handled,descriptor=finish_descriptor_metadata_v3(task,value)
    if handled:return descriptor
    kind, ref = task.identity
    if kind in {'head', 'view_head'}:
        header = reader.heads.get(ref)
        if header != task.metadata or task.metadata[0] < 1 or task.metadata[1] != 1:
            raise AuthorityUnavailable('Owner state metadata changed its exact census Head')
        if kind == 'view_head' and header[0] != state.world_views[ref]:
            raise AuthorityUnavailable('Owner state expression view changed its exact adopted revision')
        if AtomKey.from_token(ref).type_name == 'd09.world_perspective_input.v1':
            view = value['view_version']
            key = AtomKey.from_token(view['key'])
            if (set(view) != {'key', 'revision'} or key.type_name != 'd03.world_view.v1'
                    or NamespaceId.from_key(key) != reader.namespace or type(view['revision']) is not int or view['revision'] < 1):
                raise AuthorityUnavailable('Owner state expression metadata has no exact same-namespace World view')
            if view['key'] in state.world_views and state.world_views[view['key']] != view['revision']:
                raise AuthorityUnavailable('Owner state expressions disagree on the same actual view revision')
            state.world_views[view['key']] = view['revision']
        values = value.get('definition', value)
        roots = tuple(values.get('source_refs', ()))
    else:
        version = value['input_version']
        if (version != {'key': ref, 'revision': reader.heads[ref][0]}
                or value['adoption_operation_id'] != task.metadata[2]
                or value['adoption_operation_id'] != state.histories.get(ref)
                or value['assertion_commitment'] != task.metadata[3]
                or value['known_from_sequence'] != task.metadata[4]):
            raise AuthorityUnavailable('Owner state World index differs from its signed current Head/producer')
        roots = tuple(value['source_refs'])
    if len(set(roots)) != len(roots):
        raise AuthorityUnavailable('Owner state metadata duplicated its exact Source roots')
    for ref in roots:
        key = AtomKey.from_token(ref)
        if key.type_name != 'memory.source' or NamespaceId.from_key(key) != reader.namespace:
            raise AuthorityUnavailable('Owner state Source metadata crossed namespace/type')
    return {'source_refs': roots}


def _metadata(reader, identity):
    from .current_method_learning_read_v3 import _need_method_input
    state = require_owner_state_reader_v3(reader)
    task = state.tasks.get(identity)
    if task is None or not task.complete:
        _need_method_input(reader, ('owner_state_metadata', identity))
    with runtime_storage_quantum_v3(reader.db) as meter:
        task.require_header_v3(meter)
    return task.result


def _metadata_plan(reader):
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    state = require_owner_state_reader_v3(reader)
    from .named_joint_node_descriptor_v3 import descriptor_plan_v3
    descriptor=descriptor_plan_v3(reader)
    if descriptor is not None:return descriptor
    roots = set()
    for ref in reader.request.refs:
        header = reader.heads.get(ref)
        if header is None or header[0] < 1 or header[1] != 1:
            continue
        with runtime_storage_quantum_v3(reader.db) as meter:
            history = _beta1_metadata_row_v3(reader, meter, 'graph_history',
                ('event_bot', 'event_persona', 'event_id', 'valid'), 'token=? AND revision=?', (ref, header[0]))
        if history is None or tuple(history[:2]) != reader.namespace.as_tuple or history[3] != 1:
            raise AuthorityUnavailable('Owner state has no exact valid current producing history')
        state.histories[ref] = history[2]
        state.producers.add(history[2])
        value = _metadata(reader, ('head', ref))
        if value is None:
            raise AuthorityUnavailable('Owner state current Head disappeared during metadata EOF')
        roots.update(value['source_refs'])
        if AtomKey.from_token(ref).type_name == 'd03.world_assertion_input.v1':
            index = _metadata(reader, ('world_index', ref))
            if index is None:
                raise AuthorityUnavailable('Owner state requires the actual signed World revision index')
            roots.update(index['source_refs'])
    for ref, revision in state.world_views.items():
        header = reader.heads.get(ref)
        if header is None or header[:2] != (revision, 1):
            raise AuthorityUnavailable('Owner state expression requires its actual current committed World view')
        with runtime_storage_quantum_v3(reader.db) as meter:
            history = _beta1_metadata_row_v3(reader, meter, 'graph_history',
                ('event_bot', 'event_persona', 'event_id', 'valid'), 'token=? AND revision=?', (ref, revision))
        if history is None or tuple(history[:2]) != reader.namespace.as_tuple or history[3] != 1:
            raise AuthorityUnavailable('Owner state expression view lost its real producing history')
        state.histories[ref] = history[2]
        state.producers.add(history[2])
        view = _metadata(reader, ('view_head', ref))
        if view is None:
            raise AuthorityUnavailable('Owner state expression current World view is absent')
        roots.update(view['source_refs'])
    if state.metadata_complete and roots != state.roots:
        raise AuthorityUnavailable('Owner state Source metadata changed during its original READ')
    state.roots = roots
    state.metadata_complete = True
    keys = tuple(AtomKey.from_token(ref) for ref in dict.fromkeys((*reader.request.refs, *state.world_views)))
    return ProductionReadPlanV1((), (*keys, owner_grant_key(*reader.namespace.as_tuple)), tuple(sorted(roots)), ())


def require_owner_state_point_v3(reader, request):
    state = require_owner_state_reader_v3(reader)
    from .named_joint_node_descriptor_v3 import descriptor_point_v3
    if descriptor_point_v3(reader,request):return
    table, columns, key_columns, key = request
    if table == 'graph_atoms' and tuple(columns) == ('revision', 'value', 'valid') and tuple(key_columns) == ('token', 'bot', 'persona'):
        if len(key) != 3 or tuple(key[1:]) != reader.namespace.as_tuple:
            raise AuthorityUnavailable('Owner state current point crossed namespace')
        from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
        if require_beta1_source_control_point_v3(reader, request):
            return
        if key[0] not in reader.request.refs and key[0] not in state.world_views:
            raise AuthorityUnavailable('Owner state body was not explicitly selected')
        return require_owner_state_body_v3(reader, table, key)
    if table == 'graph_domain_production_originals_v1' and tuple(columns) == ('domain', 'operation_kind', 'request_digest', 'original_digest', 'original_payload_json', 'read_versions_json', 'bundle_digest', 'receipt_json', 'receipt_digest') and tuple(key_columns) == ('bot', 'persona', 'operation_id'):
        return require_owner_state_body_v3(reader, table, key)
    if table == 'graph_bundle_operations' and tuple(columns) == ('digest', 'activity_id', 'effect_id', 'commit_seq') and tuple(key_columns) == ('bot', 'persona', 'operation_id'):
        return require_owner_state_body_v3(reader, table, key)
    raise AuthorityUnavailable('Owner state point has no registered selected read shape')


def require_owner_state_body_v3(reader, table, key):
    state = require_owner_state_reader_v3(reader)
    from .named_joint_node_descriptor_v3 import descriptor_body_v3
    if descriptor_body_v3(reader,table,key):return
    if table == 'graph_atoms':
        from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
        if require_beta1_source_control_point_v3(reader, (table, ('revision', 'value', 'valid'), ('token', 'bot', 'persona'), tuple(key))):
            return
        allowed = len(key) == 3 and (key[0] in reader.request.refs or key[0] in state.world_views) and tuple(key[1:]) == reader.namespace.as_tuple
    else:
        allowed = table in {'graph_domain_production_originals_v1', 'graph_bundle_operations'} and len(key) == 3 and tuple(key[:2]) == reader.namespace.as_tuple and key[2] in state.producers
    if not allowed or not state.metadata_complete or state.source_permission is None:
        raise AuthorityUnavailable('Owner state protected body requires its exact selected original and complete Source ALL')
    state.source_permission.require_for_v3(reader)


def _typed_state(key, value):
    if key.type_name == 'd10.habit_policy.v1':
        from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
        return graph_adopted_habit_policy_from_wire_v1(value).definition.state
    if key.type_name == 'd10.habit_occurrence.v1':
        from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
        return habit_value_from_wire_v1(key.type_name, value).state
    if key.type_name in _TYPES['long_window']:
        from ..domains.d08.long_term_plan_v1 import long_term_value_from_wire_v1
        return long_term_value_from_wire_v1(key.type_name, value).state
    from ..domains.d03.world_history_v1 import decode_world_value_v1, WorldAssertionInputV1, WorldViewResultV1, WorldPerspectiveExpressionInputV1
    cls = {'d03.world_assertion_input.v1': WorldAssertionInputV1, 'd03.world_view.v1': WorldViewResultV1,
        'd09.world_perspective_input.v1': WorldPerspectiveExpressionInputV1}[key.type_name]
    typed = decode_world_value_v1(value, cls)
    return typed.assertion_status if key.type_name == 'd03.world_assertion_input.v1' else typed.coverage if key.type_name == 'd03.world_view.v1' else 'adopted_projection'


def _world_not_erased(reader, atom):
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from .d03_world_history_v1 import ERASURE_TABLE, world_assertion_commitment_v1
    if atom.key.type_name == 'd03.world_assertion_input.v1':
        values = ((atom.value['assertion_id'], atom.key.token, reader.heads[atom.key.token][0]),)
    elif atom.key.type_name == 'd03.world_view.v1':
        values = tuple((item['assertion']['assertion_id'], item['input_version']['key'], item['input_version']['revision']) for item in atom.value['revisions'])
    elif atom.key.type_name == 'd09.world_perspective_input.v1':
        from .current_method_learning_read_v3 import method_graph_head_v3
        from ..domains.d03.world_history_v1 import decode_world_value_v1, WorldViewResultV1
        state = require_owner_state_reader_v3(reader)
        version = atom.value['view_version']
        if state.world_views.get(version['key']) != version['revision']:
            raise AuthorityUnavailable('Owner state expression changed its actual metadata-bound view')
        view = method_graph_head_v3(reader.db, reader.namespace, AtomKey.from_token(version['key']))
        _verify_current_original(reader, view)
        decode_world_value_v1(view.value, WorldViewResultV1)
        if not set(view.value['source_refs']) <= set(state.source_permission.source_refs):
            raise AuthorityUnavailable('Owner state expression view has an unqualified Source')
        return _world_not_erased(reader, view)
    else:
        return
    issuer = reader.graph._GraphCoordinator__d11_issuer
    for identity, ref, revision in values:
        commitment = world_assertion_commitment_v1(reader.namespace, identity, issuer)
        with runtime_storage_quantum_v3(reader.db) as meter:
            index = _beta1_metadata_row_v3(reader, meter, 'graph_world_revision_index_v1', ('known_sequence', 'producing_operation_id'),
                'bot=? AND persona=? AND original_ref=?', (*reader.namespace.as_tuple, ref))
            if index is None:
                raise AuthorityUnavailable('Owner state World revision metadata has been erased or retired')
            barrier = _beta1_metadata_row_v3(reader, meter, ERASURE_TABLE, ('deletion_generation',),
                'bot=? AND persona=? AND assertion_commitment=? AND known_sequence=?', (*reader.namespace.as_tuple, commitment, index[0]))
        if barrier is not None:
            raise AuthorityUnavailable('Owner state World revision is covered by its actual C09 erasure barrier')


def _verify_current_original(reader, atom):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..graph_types import GraphWrite
    state = require_owner_state_reader_v3(reader)
    key, ref = atom.key, atom.key.token
    if ref not in state.histories or not atom.valid or atom.revision != reader.heads[ref][0]:
        raise AuthorityUnavailable('Owner state actual body has no current metadata-selected history')
    original = read_adopted_domain_operation_v1(reader.db, reader.namespace, state.histories[ref])
    if (original is None or original['operation_kind'] not in _PRODUCERS[key.type_name]
            or original['receipt'].status != 'committed'
            or GraphVersion(key, atom.revision) not in original['receipt'].write_versions):
        raise AuthorityUnavailable('Owner state Head lacks its exact actual registered producing COMMIT')
    writes = tuple(decode_typed_production_value_v1(raw, GraphWrite) for raw in original['payload']['writes'] if raw['key'] == ref)
    if len(writes) != 1 or canonical_digest(writes[0].value) != canonical_digest(atom.value):
        raise AuthorityUnavailable('Owner state current body differs from its real adopted write')


def _projection(reader):
    from .named_joint_node_descriptor_v3 import descriptor_projection_v3
    descriptor=descriptor_projection_v3(reader)
    if descriptor is not None:return descriptor
    from .current_method_learning_read_v3 import method_graph_head_v3
    state = require_owner_state_reader_v3(reader)
    rows, missing = [], []
    for ref in reader.request.refs:
        header = reader.heads.get(ref)
        if header is None or header[0] < 1 or header[1] != 1:
            missing.append('current_head_absent_or_retired:' + ref)
            continue
        key = AtomKey.from_token(ref)
        atom = method_graph_head_v3(reader.db, reader.namespace, key)
        if atom.revision != header[0] or not atom.valid:
            raise AuthorityUnavailable('Owner state current Head changed after Source ALL')
        _verify_current_original(reader, atom)
        current = _typed_state(key, atom.value)
        value = atom.value.get('definition', atom.value)
        roots = tuple(value.get('source_refs', ()))
        declared = _metadata(reader, ('head', ref))['source_refs']
        if set(roots) != set(declared) or not set(roots) <= set(state.source_permission.source_refs):
            raise AuthorityUnavailable('Owner state actual typed roots differ from its qualified metadata')
        if reader.request.domain == 'world':
            _world_not_erased(reader, atom)
        related = []
        for name in ('policy_ref', 'project_ref', 'recipe_ref', 'goal_ref', 'current_window_ref', 'long_term_plan_ref',
                'prior_window_ref', 'final_joint_plan_ref', 'action_intent_ref', 'plan_ref', 'supersedes_ref', 'correction_ref'):
            if value.get(name) is not None:
                related.append(value[name])
        reasons = []
        if key.type_name == 'd03.world_view.v1':
            reasons.append('saved_temporal_view_not_independent_truth')
            if atom.value.get('unknowns') or not atom.value.get('eof'):
                reasons.append('world_view_partial_or_unknown')
        if current in {'paused', 'stopped', 'waiting', 'missed', 'unknown', 'deferred', 'described', 'preparing'}:
            reasons.append('current_state:' + current)
        item={'ref': ref, 'type_name': key.type_name, 'revision': atom.revision, 'state': current,
            'source_refs': list(roots), 'related_refs': list(dict.fromkeys(related)), 'reason_codes': reasons}
        if key.type_name=='d08.joint_window.v1':
            item['managed_nodes']=[{'node_id':node['node_id'],'executor_kind':node['executor_kind']}for node in value['node_drafts']if node['executor_kind']in {'source_note','draft_file','contact'}]
        rows.append(item)
    return {'domain': reader.request.domain, 'items': rows, 'coverage': 'partial' if missing else 'complete', 'missing_inputs': missing}


class _OwnerStateResultV3:
    def __init__(self, reader, value):
        self.reader, self.value = reader, value
        _RESULTS[self] = (reader, reader.work, reader.operation, reader.selection_digest, value)

    def require_result_v3(self, work):
        reader = self.reader
        if (_RESULTS.get(self) != (reader, work, reader.operation, reader.selection_digest, self.value)
                or work.state is not reader or reader.operation_kind != READ_KIND
                or not reader.complete or not reader.read_finished or reader.inputs_sealed or reader.business_started):
            raise AuthorityUnavailable('Owner state result lost its exact complete readonly Source Work')
        return self.value

    def release_payload_v3(self):
        if _RESULTS.pop(self, None) is None:
            return
        from .current_method_learning_read_v3 import _release_method_registered_payloads_v3
        reader = self.reader
        _release_method_registered_payloads_v3(reader)
        if reader.inventory is not None:
            reader.inventory.release_payload_v3()
        reader.points.clear(); reader.inventories.clear(); reader.input_heads.clear()
        self.value = None


def advance_owner_state_read_v3(graph, work):
    from ..graph_worker import GraphStorageStepV3
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from .current_method_learning_read_v3 import _READING, bind_prepared_method_learning_read_v3, MethodInputNeededV3, _MethodPointReadV3
    from .current_beta1_source_read_v3 import prepare_current_beta1_owner_entry_v3, qualify_current_beta1_source_groups_v3, create_current_beta1_source_metadata_task_v3, create_current_beta1_metadata_task_v3
    reader = work.state
    state = require_owner_state_reader_v3(reader)
    if reader.graph is not graph or reader.read_finished or reader.inputs_sealed or reader.business_started:
        raise AuthorityUnavailable('Owner state cannot enter a write or reuse a completed READ')
    with bind_runtime_storage_operation_v3(work.operation, reader.db):
        now = state.first_utc + max(0.0, time.monotonic() - state.first_monotonic)
        if time.monotonic() >= reader.initial_monotonic_deadline or now >= reader.operation.deadline_utc:
            raise AuthorityUnavailable('Owner state exceeded its original absolute READ deadline')
        prepare_current_beta1_owner_entry_v3(reader)
        graph._validate_read_fence_v3(reader.fence)
        if not reader.inventory_sealed:
            with reader.store._lock:
                reader.advance()
            return GraphStorageStepV3('progress')
        if reader.pending_input is not None:
            with reader.store._lock, runtime_storage_quantum_v3(reader.db) as meter:
                reader.pending_input.advance(meter)
                if reader.pending_input.complete:
                    reader.pending_input = None
            return GraphStorageStepV3('progress')
        token = _READING.set(reader)
        try:
            with bind_prepared_method_learning_read_v3(reader.inventory, graph, reader.db), reader.store._lock:
                reader.db.execute('BEGIN')
                try:
                    reader.selected_plan = _metadata_plan(reader)
                    state.source_permission = qualify_current_beta1_source_groups_v3(reader, reader.selected_plan.source_roots)
                    value = _projection(reader)
                    state.source_permission.require_for_v3(reader)
                    from .dispatch_current_inventory_v3 import _heap
                    from .named_joint_node_descriptor_v3 import named_descriptor_retained_heap_v3
                    descriptor_bytes=named_descriptor_retained_heap_v3(value)
                    reader.operation.retain((_heap(value)if descriptor_bytes is None else descriptor_bytes) * 2 + 65536)
                    reader.result = _OwnerStateResultV3(reader, value)
                    reader.complete = True
                finally:
                    reader.db.rollback()
            graph._validate_read_fence_v3(reader.fence)
            graph._finish_read_fence_v3(reader.fence)
            reader.read_finished = True
            return GraphStorageStepV3('complete', reader.result)
        except MethodInputNeededV3 as needed:
            kind, actual = needed.request
            with reader.store._lock, runtime_storage_quantum_v3(reader.db):
                if kind == 'owner_state_metadata':
                    task = state.tasks.get(actual)
                    if task is None:
                        task = create_current_beta1_metadata_task_v3(reader, actual)
                        state.tasks[actual] = task
                elif kind == 'beta1_source_metadata':
                    task = create_current_beta1_source_metadata_task_v3(reader, actual)
                elif kind == 'point':
                    require_owner_state_point_v3(reader, actual)
                    task = reader.points.get(actual)
                    if task is None:
                        task = _MethodPointReadV3(reader, actual)
                        reader.points[actual] = task
                else:
                    raise AuthorityUnavailable('Owner state dependency is outside its finite formal READ recipe')
                reader.pending_input = task
        finally:
            _READING.reset(token)
        graph._validate_read_fence_v3(reader.fence)
        return GraphStorageStepV3('progress')


def require_owner_state_terminal_v3(value, work):
    if type(value) is not _OwnerStateResultV3:
        raise AuthorityUnavailable('Owner state returned no privately issued actual readonly result')
    return value.require_result_v3(work)


def release_owner_state_reader_v3(reader):
    from .named_joint_node_descriptor_v3 import release_named_descriptor_v3
    release_named_descriptor_v3(reader)
    _STATES.pop(reader, None)
    _FACTORIES.pop(reader, None)


def require_owner_state_work_v3(work, graph, authority, lease, request):
    from ..graph_worker import GraphStorageWorkV3
    if type(work) is not GraphStorageWorkV3:
        raise AuthorityUnavailable('Owner state requires its actual serial GraphStorageWork')
    reader = work.state
    require_owner_state_reader_v3(reader)
    if reader.graph is not graph or reader.authority is not authority or reader.lease is not lease or reader.request != request or reader.work is not work:
        raise AuthorityUnavailable('Owner state Work differs from its exact signed command')
    return reader


def prepare_owner_state_read_v3(graph, authority, lease, *, request):
    from uuid import uuid4
    from .first_ingress_v2 import trusted_upper
    from ..graph_worker import require_graph_storage_work_admission_v3, create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3
    from .current_method_learning_read_v3 import begin_current_method_learning_read_v3
    from .current_beta1_source_read_v3 import register_current_beta1_source_work_v3, WORLD_SOURCE_WORK_KIND_V3
    require_graph_storage_work_admission_v3(graph)
    if type(request) is not Beta1OwnerStateRequestV1 or authority.purpose != 'context' or authority.audience != ('owner',):
        raise AuthorityUnavailable('Owner state requires its actual fixed typed Owner context READ')
    graph._authorize(lease, authority, owner_state_required_domains_v3(request), owner_read=True)
    owner = graph._GraphCoordinator__owner_leases.get(lease)
    session = graph._GraphCoordinator__owner_session_proofs.get(lease)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if owner is None or session is None or assembly is None or 'workbench.read' not in owner.capabilities or assembly.admin_bundle.installation_policy.namespace != authority.namespace:
        raise AuthorityUnavailable('Owner state requires its actual installed signed Owner READ lease')
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation_id = 'owner-state-read:' + uuid4().hex
    operation = begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db, operation_id, now + 60.0)
    fence = reader = None
    try:
        with bind_runtime_storage_operation_v3(operation, graph._GraphCoordinator__store._db):
            fence = graph._begin_read_fence_v3(authority, operation_id=operation_id, owner_session_proof=session)
            reader = begin_current_method_learning_read_v3(graph, operation, fence,
                runtime=graph._GraphCoordinator__domain_production_runtime_v1, authority=authority, lease=lease,
                operation_kind=READ_KIND, request=request, operation_id=operation_id, activity_id=operation_id,
                audience_ref='owner', parent_budget_lease_ref=assembly.admin_bundle.installation_policy.root_grant.lease_id,
                request_digest=canonical_digest((READ_KIND, request)), owner_binding=owner, owner_guard=None,
                session_proof=session, initial_now_utc=now)
            reader.initial_monotonic_deadline = time.monotonic() + 60.0
            reader.background_followup = reader.background_host_lifecycle = reader.background_offline = None
        work = create_graph_storage_work_v3(graph, kind=WORLD_SOURCE_WORK_KIND_V3, operation_id=operation_id,
            selection_digest=operation.selection_digest, deadline_utc=operation.deadline_utc, state=reader, operation=operation)
        reader.work = work
        _FACTORIES[reader] = _identity(reader)
        register_current_beta1_source_work_v3(reader, work)
        work.phase = 'owner_state_owner_eof'
        return work
    except BaseException:
        if reader is not None:
            release_owner_state_reader_v3(reader)
        try:
            if fence is not None:
                graph._finish_read_fence_v3(fence)
        finally:
            finish_runtime_storage_operation_v3(operation)
        raise
