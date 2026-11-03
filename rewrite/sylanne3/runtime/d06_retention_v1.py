"""D06 retention operations under the actual current Source Work and W01 fence."""
from __future__ import annotations

from dataclasses import dataclass, replace, fields, is_dataclass
import hashlib
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..contracts import canonical_json
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..memory_types import SourceRecord, validate_subjective_trace, validate_subjective_trace_v2
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1, current_frame_guard_v1
from ..domains.d06.retention_v1 import (
    POLICY_TYPE, DETAIL_TYPE, READ_TYPE, CONTRIBUTION_TYPE, MemoryRetentionPolicyDefinitionV1,
    MemoryRetentionPolicyV1, DetailRetentionV1, MemoryRetentionReadV1, MemoryRetentionContributionV1,
    RetentionClockObservationV1,
    RetentionProtectionMemberV1, RetentionProtectionSnapshotV1,
    retention_payload_v1, retention_payload_digest_v1, decode_retention_value_v1,
    detail_retention_key_v1, retention_read_key_v1, retention_contribution_key_v1,
    seed_retention_details_v1, retention_read_details_v1, detail_cues_from_retention_read_v1,
    contribute_retention_details_v1, retention_candidate_tier_v1)
from .domain_production_contracts_v1 import ProductionOriginalRefV1, StagedDomainOperationV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .issuers import D11BudgetJobIssuer

WORK_KIND = 'd06.memory_retention'
POLICY_SIGNATURE_KIND = 'd06.memory-retention-policy.v1'
C02_CAUSE_KIND = 'foreground_post_c02_cause'
C04_CAUSE_KIND = 'memory_retention_c04_cause_v1'
C04_EVENT = 'recollection_retention_contribution_required_v1'
_KEY = object()
_METADATA = WeakKeyDictionary()
_READS = WeakKeyDictionary()
_STAGES = WeakKeyDictionary()
_STAGE_VALUES = {}
_PROTECTION = WeakKeyDictionary()
_CLOCKS = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class RegisterMemoryRetentionPolicyRequestV1:
    policy_ref: str
    expected_revision: int
    definition: MemoryRetentionPolicyDefinitionV1

    def __post_init__(self):
        key = AtomKey.from_token(self.policy_ref)
        if (key.type_name != POLICY_TYPE or key.owner.kind != 'persona'
                or type(self.expected_revision) is not int or self.expected_revision < 0
                or type(self.definition) is not MemoryRetentionPolicyDefinitionV1):
            raise ValueError('explicit same-namespace retention policy request required')


@dataclass(frozen=True, slots=True)
class InitializeMemoryRetentionRequestV1:
    c02_original: ProductionOriginalRefV1
    source_version: GraphVersion
    trace_version: GraphVersion
    policy_ref: str
    policy_revision: int

    def __post_init__(self):
        if (type(self.c02_original) is not ProductionOriginalRefV1
                or self.c02_original.kind != 'd11.life_' + C02_CAUSE_KIND
                or type(self.source_version) is not GraphVersion or self.source_version.revision < 1
                or self.source_version.key.type_name != 'memory.source'
                or type(self.trace_version) is not GraphVersion or self.trace_version.revision < 1
                or self.trace_version.key.type_name not in {'memory.subjective_trace.v1', 'memory.subjective_trace.v2'}
                or AtomKey.from_token(self.policy_ref).type_name != POLICY_TYPE
                or type(self.policy_revision) is not int or self.policy_revision < 1):
            raise ValueError('retention seed requires the real C02 cause and Source/Trace versions')


@dataclass(frozen=True, slots=True)
class ApplyRecollectionRetentionRequestV1:
    c04_adoption_original: ProductionOriginalRefV1
    recollection_version: GraphVersion
    projection_version: GraphVersion
    retention_read_original: ProductionOriginalRefV1

    def __post_init__(self):
        if (type(self.c04_adoption_original) is not ProductionOriginalRefV1
                or self.c04_adoption_original.kind != 'd11.life_' + C04_CAUSE_KIND
                or type(self.retention_read_original) is not ProductionOriginalRefV1
                or self.retention_read_original.kind != READ_TYPE):
            raise ValueError('retention enhancement needs actual signed adoption and frozen read originals')
        for version, kind in ((self.recollection_version, 'd06.recollection.v1'),
                (self.projection_version, 'd06.recollection_projection.v1')):
            if type(version) is not GraphVersion or version.revision < 1 or version.key.type_name != kind:
                raise ValueError('retention enhancement has another actual C04 member')


@dataclass(frozen=True, slots=True)
class ReconcileMemoryRetentionTierRequestV1:
    source_ref: str
    expected_retention_version: GraphVersion
    maintenance_trigger_original: ProductionOriginalRefV1

    def __post_init__(self):
        if (AtomKey.from_token(self.source_ref).type_name != 'memory.source'
                or type(self.expected_retention_version) is not GraphVersion
                or self.expected_retention_version.revision < 1
                or self.expected_retention_version.key.type_name != DETAIL_TYPE
                or type(self.maintenance_trigger_original) is not ProductionOriginalRefV1):
            raise ValueError('retention tier request needs its actual Source/state/maintenance cause')


OPERATIONS = {
    'register_memory_retention_policy_v1': RegisterMemoryRetentionPolicyRequestV1,
    'initialize_memory_retention_v1': InitializeMemoryRetentionRequestV1,
    'apply_recollection_retention_v1': ApplyRecollectionRetentionRequestV1,
    'reconcile_memory_retention_tier_v1': ReconcileMemoryRetentionTierRequestV1,
}


def _request_kind(request):
    matches = tuple(k for k, cls in OPERATIONS.items() if type(request) is cls)
    if len(matches) != 1:
        raise TypeError('exact installed retention operation request required')
    return matches[0]


def _owner_v1(reader, meter=None):
    from .current_method_learning_read_v3 import (_MethodLearningReadV3,
        require_actual_method_learning_attachment_owner_v3)
    from .foreground_command_source_v3 import (
        is_foreground_command_source_reader_v3, require_foreground_command_owner_reader_v3)
    if type(reader) is _MethodLearningReadV3:
        require_actual_method_learning_attachment_owner_v3(reader, db=reader.db)
        if OPERATIONS.get(reader.operation_kind) is not type(reader.request):
            raise AuthorityUnavailable('retention reader has another registered actual operation')
        if reader.read_finished:
            from .current_beta1_source_read_v3 import require_beta1_source_write_phase_v3
            require_beta1_source_write_phase_v3(reader)
        else:
            reader.require_current(meter=meter)
    elif is_foreground_command_source_reader_v3(reader):
        from .c04_self_scope_v4 import PREPARE_OPERATION, PrepareIngressC04RequestV1
        state = require_foreground_command_owner_reader_v3(reader)
        if reader.operation_kind != PREPARE_OPERATION or type(reader.request) is not PrepareIngressC04RequestV1:
            raise AuthorityUnavailable('retention read cannot borrow another foreground command')
        reader.require_current(meter=meter)
        return state
    else:
        raise AuthorityUnavailable('retention needs the actual Method or C04 Source Work')
    return reader


def _binding_v1(reader):
    return (reader, reader.work, reader.operation, reader.selection_digest, reader.graph_stamp,
        reader.operation_kind, reader.request, reader.fence.scope if hasattr(reader, 'fence') else reader.issued.scope)


def _active_reader_v1(db):
    from .current_method_learning_read_v3 import _method_active
    reader = _method_active(db)
    _owner_v1(reader)
    return reader


def _missing_metadata(identity):
    from .current_method_learning_read_v3 import MethodInputNeededV3
    raise MethodInputNeededV3(('memory_retention_metadata', identity))


def _metadata_identity_v1(reader, kind, ref):
    _owner_v1(reader)
    request = reader.request
    if kind == C02_CAUSE_KIND:
        expected = request.c02_original if type(request) is InitializeMemoryRetentionRequestV1 else None
    elif kind == C04_CAUSE_KIND:
        expected = request.c04_adoption_original if type(request) is ApplyRecollectionRetentionRequestV1 else None
    else:
        raise AuthorityUnavailable('unregistered retention metadata original kind')
    if expected is None or expected.original_ref != ref:
        raise AuthorityUnavailable('retention metadata selector differs from the actual typed request')
    return ('life_original', kind, ref)


class _RetentionColumnV1:
    def __new__(cls, task, **arguments):
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3, _COLUMNS
        from .source_correction_read_v3 import _heap
        class Column(DispatchOriginalJSONReadV3):
            def __init__(self):
                self.registered = self.growing = False
                super().__init__(task.reader, **arguments)
            def _emit(self, event):
                keep = (_protection_retains_v1(event.path, AtomKey.from_token(task.row[0]).type_name)
                    if task.identity[0] == 'protection' else retention_metadata_retains_path_v1(task.identity, event.path))
                if keep:
                    super()._emit(event)
            def _reserve(self, extra=0):
                if not self.registered:
                    self.operation.register_retained_state_v3(self)
                    self.registered = True
                if self.growing:
                    self.operation.finish_retained_state_growth_v3(self)
                self.operation.reserve_retained_state_growth_v3(self, extra)
                self.growing = True
            def _runtime_retained_heap_bytes_v3(self):
                return 65536 + self._payload_bytes + _heap((self.scalar, self.fragment))
            def advance(self, meter):
                task.require_current_v1(meter)
                try:
                    return super().advance(meter)
                finally:
                    if self.growing:
                        self.operation.finish_retained_state_growth_v3(self)
                        self.growing = False
            def release_v1(self):
                if self.growing:
                    self.operation.finish_retained_state_growth_v3(self)
                    self.growing = False
                _COLUMNS.pop(self, None)
                self.value = self._frozen_value = self.parser = self.cell = None
                self.nodes = {}; self.scalar = bytearray(); self.fragment = b''
                if self.registered:
                    self.operation.unregister_retained_state_v3(self)
                    self.registered = False
        return Column()


class CurrentRetentionMetadataTaskV1:
    def __init__(self, key, reader, identity):
        if key is not _KEY or identity != _metadata_identity_v1(reader, identity[1], identity[2]):
            raise AuthorityUnavailable('actual fixed retention metadata issuer required')
        self.reader, self.identity = reader, identity
        self.binding = _binding_v1(reader)
        self.header = self.column = self.value = None
        self.phase = "original_header"
        self.bundle_header = self.receipt = None
        self.control_columns = {}; self.control_index = 0
        self.complete = False
        self.points = {}
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 65536 + _heap((self.identity, self.header, self.value, self.points, self.bundle_header, self.receipt, self.control_columns))
    def require_current_v1(self, meter=None):
        _owner_v1(self.reader, meter)
        if self.binding != _binding_v1(self.reader) or _METADATA.get(self.reader, {}).get(self.identity) is not self:
            raise AuthorityUnavailable('retention metadata left its actual Work/selection/request')
        if meter is not None:
            from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
            for (table, columns, where, key), expected in self.points.items():
                if _runtime_bounded_fixed_row_v3(self.reader.db, meter, table, columns, where, key) != expected:
                    raise AuthorityUnavailable('retention metadata current fixed header changed')
        return self
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d11_life_preparation_v1 import TABLE, SIGN_KIND
        self.require_current_v1(meter)
        if self.complete:
            return True
        r = self.reader
        _, kind, ref = self.identity
        if self.phase == 'original_header':
            spec = (TABLE, ('producing_operation_id', 'payload_digest', 'signature'),
                'bot=? AND persona=? AND kind=? AND original_ref=?', (*r.namespace.as_tuple, kind, ref))
            self.header = _runtime_bounded_fixed_row_v3(r.db, meter, *spec)
            if self.header is None:
                raise MissingProductionOriginalV1('actual_signed_retention_cause:' + kind)
            self.points[spec] = self.header
            self.column = _RetentionColumnV1(self, table=TABLE, column='payload_json',
                key_columns=('bot', 'persona', 'kind', 'original_ref'), key=(*r.namespace.as_tuple, kind, ref))
            self.phase = 'original_payload'
            return False
        if self.phase == 'original_payload':
            if not self.column.advance(meter):
                return False
            self.value = self.column.require_v3(r)
            if self.column.sha256 != self.header[1]:
                raise ValueError('retention cause changed its complete canonical payload')
            issuer = r.graph._GraphCoordinator__d11_issuer
            issuer._signer.verify(SIGN_KIND, canonical_serialize((r.namespace, kind, ref, self.header[1])), self.header[2])
            self.column.release_v1(); self.column = None
            self.phase = 'bundle_header'
            return False
        if self.phase == 'bundle_header':
            spec = ('graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq'),
                'bot=? AND persona=? AND operation_id=?', (*r.namespace.as_tuple, self.header[0]))
            self.bundle_header = _runtime_bounded_fixed_row_v3(r.db, meter, *spec)
            if self.bundle_header is None:
                raise MissingProductionOriginalV1('actual_retention_cause_bundle')
            self.points[spec] = self.bundle_header
            if kind == C04_CAUSE_KIND:
                cause=decode_retention_value_v1(self.value,RetentionAdoptionCauseV1)
                spec=('graph_domain_production_originals_v1',('original_digest','bundle_digest','receipt_digest'),
                    'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.header[0]))
                actual=_runtime_bounded_fixed_row_v3(r.db,meter,*spec)
                if actual!=(cause.adoption_original.original_digest,self.bundle_header[0],cause.adoption_receipt_digest):
                    raise ValueError('signed retention cause lacks its actual C04 Domain/Graph receipt header')
                self.points[spec]=actual
            spec = ('graph_events', ('epoch_revision',), 'bot=? AND persona=? AND session=? AND event_id=?',
                (*r.namespace.as_tuple, self.bundle_header[1], self.header[0]))
            epoch = _runtime_bounded_fixed_row_v3(r.db, meter, *spec)
            if epoch is None:
                raise MissingProductionOriginalV1('actual_retention_cause_event')
            self.points[spec] = epoch
            self.event_epoch = epoch[0]
            self.control_specs = (
                ('receipt', 'graph_bundle_operations', 'receipt_json', ('bot', 'persona', 'operation_id'),
                    (*r.namespace.as_tuple, self.header[0])),
                ('reads', 'graph_events', 'reads', ('bot', 'persona', 'session', 'event_id'),
                    (*r.namespace.as_tuple, self.bundle_header[1], self.header[0])),
                ('writes', 'graph_events', 'revisions', ('bot', 'persona', 'session', 'event_id'),
                    (*r.namespace.as_tuple, self.bundle_header[1], self.header[0])))
            self.phase = 'control_columns'
            return False
        if self.phase == 'control_columns':
            if self.control_index < len(self.control_specs):
                label, table, column, columns, key = self.control_specs[self.control_index]
                if self.column is None:
                    self.column = _RetentionColumnV1(self, table=table, column=column, key_columns=columns, key=key)
                    return False
                if not self.column.advance(meter):
                    return False
                self.control_columns[label] = self.column.require_v3(r)
                self.column.release_v1(); self.column = None; self.control_index += 1
                r.operation.refresh_retained_state_v3(self)
                return False
            from ..runtime_contracts import CommitReceipt
            from ..graph_types import NamespaceEpoch
            from ..graph_store import GraphStore
            detail = self.control_columns['receipt']
            self.receipt = CommitReceipt('committed', self.header[0], *self.bundle_header,
                GraphStore._version_rows(canonical_json(self.control_columns['reads'])),
                GraphStore._version_rows(canonical_json(self.control_columns['writes'])),
                (NamespaceEpoch(*r.namespace.as_tuple, self.event_epoch),),
                tuple(detail['ledger_refs']), tuple(detail['outbox_refs']))
            if detail.get('status') == 'committed':
                from .domain_production_originals_v1 import _receipt
                if _receipt(detail) != self.receipt:
                    raise ValueError('retention signed cause lost its actual event/receipt member sets')
            self.complete = True
            r.operation.refresh_retained_state_v3(self)
            return True
        raise AuthorityUnavailable('unregistered retention metadata phase')
    def release_v1(self):
        if self.column is not None:
            self.column.release_v1()
        self.column = self.value = self.header = self.bundle_header = self.receipt = None
        self.control_columns.clear(); self.points.clear()
        self.reader.operation.unregister_retained_state_v3(self)


def create_current_retention_metadata_task_v1(reader, identity):
    if type(identity) is not tuple:
        raise AuthorityUnavailable('unregistered retention metadata continuation')
    if len(identity) == 2 and identity[0] == 'protection':
        task = _PROTECTION.get(reader)
        if task is None or task.source_ref != identity[1]:
            raise AuthorityUnavailable('retention protection continuation was not privately selected')
        return task
    if len(identity) == 2 and identity[0] == 'cause_census':
        return create_current_retention_cause_watermark_task_v1(reader, identity[1])
    if len(identity) == 2 and identity[0] == 'graph_head':
        cls = CurrentRetentionGraphMetadataTaskV1
    elif len(identity) == 3 and identity[0] == 'life_original':
        _metadata_identity_v1(reader, identity[1], identity[2])
        cls = CurrentRetentionMetadataTaskV1
    else:
        raise AuthorityUnavailable('unregistered retention metadata continuation')
    tasks = _METADATA.setdefault(reader, {})
    task = tasks.get(identity)
    if task is None:
        task = cls(_KEY, reader, identity)
        tasks[identity] = task
    return task


def _signed_cause_v1(reader, original, kind):
    identity = _metadata_identity_v1(reader, kind, original.original_ref)
    task = _METADATA.get(reader, {}).get(identity)
    if task is None or not task.complete:
        _missing_metadata(identity)
    task.require_current_v1()
    if original.kind != 'd11.life_' + kind or task.header[1] != original.original_digest:
        raise ValueError('retention cause differs from its actual signed original locator')
    return task.value, task.header[0]


class InstalledD06RetentionReadersV1:
    def __init__(self, *, issuer, owner_guard, installed_bundle):
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError('retention requires the actual installed D11 issuer')
        self.issuer, self.owner_guard, self.installed_bundle = issuer, owner_guard, installed_bundle
    def read_current(self, db, frame, request):
        return _read_current_retention_inputs_v1(self, db, frame, request)


def _current_v1(readers, db, frame, request):
    current_frame_guard_v1(frame)
    reader = _active_reader_v1(db)
    if (reader.request != request or reader.operation_kind != _request_kind(request)
            or readers.issuer is not reader.graph._GraphCoordinator__d11_issuer
            or readers.installed_bundle is not reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
            or readers.owner_guard != reader.owner_guard or frame.owner_guard != reader.material_owner_guard
            or frame.envelope.identity.operation_id != reader.operation_id):
        raise AuthorityUnavailable('retention frame/request/Owner/installation left its actual Source Work')
    read = CurrentDomainReadV1(frame)
    read.check(db)
    return reader, read


def _head_v1(read, db, version):
    atom = read.head(db, version.key, required=True)
    if atom.revision != version.revision:
        raise MissingProductionOriginalV1('exact_current_retention_version:' + version.key.type_name)
    return atom


def _source_v1(read, db, version):
    family = read.source_family(db, (version.key.token,), purpose='consolidation')
    atom = _head_v1(read, db, version)
    source = family.get(version.key.token)
    if type(source) is not SourceRecord or plain_v1(source) != atom.value:
        raise ValueError('retention Source Body differs from its actual ALL-qualified record')
    return atom, source


def _policy_message_v1(value):
    raw = retention_payload_v1(value)
    del raw['signature']
    return canonical_serialize(raw)


def _verify_policy_v1(readers, atom):
    value = decode_retention_value_v1(atom.value, MemoryRetentionPolicyV1)
    policy = readers.installed_bundle.installation_policy
    if (value.namespace != policy.namespace or value.policy_ref != atom.key.token
            or value.policy_revision != atom.revision or value.installation_id != policy.installation_id
            or value.manifest_digest != policy.manifest_digest):
        raise ValueError('retention policy belongs to another actual installed original')
    readers.issuer._signer.verify(POLICY_SIGNATURE_KIND, _policy_message_v1(value), value.signature)
    return value


def _maintenance_grant_v1(readers, db, frame, definition):
    grant = readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    if ((grant.bot_id, grant.persona_id) != frame.envelope.authority.namespace.as_tuple
            or WORK_KIND not in grant.allowed_work_kinds or frame.now_utc >= grant.valid_until_utc
            or grant.policy_ref != definition.maintenance_resource_policy_ref
            or grant.version != definition.maintenance_resource_policy_version):
        raise MissingProductionOriginalV1('actual_current_explicit_retention_maintenance_resource_policy')
    return grant


def _history_member_v1(db, read, atom, operation_id, receipt):
    from ..runtime_storage_v3 import read_graph_row_v3
    if GraphVersion(atom.key, atom.revision) not in receipt.write_versions:
        raise ValueError('retention original is not a real producing receipt member')
    row = read_graph_row_v3(db, ('event_bot', 'event_persona', 'event_session', 'event_id', 'value', 'valid'),
        where='token=? AND revision=?', parameters=(atom.key.token, atom.revision), history=True)
    from .domain_background_read_v3 import background_json_loads_v3
    if (row is None or row[:4] != (*read.frame.envelope.authority.namespace.as_tuple, receipt.activity_id, operation_id)
            or row[5] != 1 or background_json_loads_v3(row[4]) != atom.value):
        raise MissingProductionOriginalV1('actual_retention_producer_history_member')



def _state_producer_v1(db, read, atom):
    from ..runtime_storage_v3 import read_graph_row_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    row = read_graph_row_v3(db, ('event_bot', 'event_persona', 'event_session', 'event_id', 'value', 'valid'),
        where='token=? AND revision=?', parameters=(atom.key.token, atom.revision), history=True)
    if row is None or row[5] != 1 or row[:2] != read.frame.envelope.authority.namespace.as_tuple:
        raise MissingProductionOriginalV1('actual_retention_state_producer_history')
    from .domain_background_read_v3 import background_json_loads_v3
    if background_json_loads_v3(row[4]) != atom.value:
        raise ValueError('retention state current EOF differs from its producing history')
    original = read_adopted_domain_operation_v1(db, read.frame.envelope.authority.namespace, row[3])
    if (original is None or original['domain'] != 'd06' or original['operation_kind'] not in OPERATIONS
            or original['receipt'].activity_id != row[2]
            or GraphVersion(atom.key, atom.revision) not in original['receipt'].write_versions):
        raise MissingProductionOriginalV1('actual_registered_retention_state_producer')
    writes = original['payload']['writes']
    matches = tuple(v for v in writes if decode_retention_value_v1(v['key'], AtomKey) == atom.key)
    if len(matches) != 1 or matches[0]['value'] != atom.value:
        raise ValueError('retention state is not the actual typed producer output')
    if atom.key.type_name == DETAIL_TYPE:
        _verify_seed_identity_v1(db,read,decode_retention_value_v1(atom.value,DetailRetentionV1))
    return original


def _c02_seed_v1(readers, reader, db, read, request):
    from .foreground_cycle_v1 import ForegroundPostC02CauseV1, foreground_post_c02_cause_ref_v1
    raw, operation_id = _signed_cause_v1(reader, request.c02_original, C02_CAUSE_KIND)
    cause = decode_retention_value_v1(raw, ForegroundPostC02CauseV1)
    task = _METADATA[reader][_metadata_identity_v1(reader, C02_CAUSE_KIND, request.c02_original.original_ref)]
    receipt = task.receipt
    ns = read.frame.envelope.authority.namespace
    policy = readers.installed_bundle.installation_policy
    if (cause.namespace != ns or cause.installation_id != policy.installation_id
            or cause.manifest_digest != policy.manifest_digest or cause.c02_operation_id != operation_id
            or request.c02_original.original_ref != foreground_post_c02_cause_ref_v1(ns, operation_id)
            or cause.source_ref != request.source_version.key.token
            or cause.source_revision != request.source_version.revision
            or request.source_version not in receipt.read_versions
            or cause.c02_receipt_digest != canonical_digest(receipt) or cause.commit_seq != receipt.commit_seq):
        raise ValueError('retention C02 seed is not its exact actual signed Source/receipt/clock cause')
    _, source = _source_v1(read, db, request.source_version)
    source_atom = _head_v1(read, db, request.source_version)
    if canonical_digest(source_atom.value) != cause.source_digest:
        raise ValueError('retention C02 source changed since the true encoding adoption')
    trace = _head_v1(read, db, request.trace_version)
    (validate_subjective_trace_v2 if trace.key.type_name.endswith('.v2') else validate_subjective_trace)(trace.value)
    unique = tuple(v for v in receipt.write_versions if v.key.type_name in {'memory.subjective_trace.v1', 'memory.subjective_trace.v2'})
    if unique != (request.trace_version,):
        raise ValueError('retention seed has no unique actual C02 Trace write')
    _history_member_v1(db, read, trace, operation_id, receipt)
    episode = read.head(db, trace.value['episode_ref'], required=True)
    if (episode.key.type_name != 'memory.episode.v1' or source_atom.key.token not in episode.value['source_refs']
            or GraphVersion(episode.key, episode.revision) not in receipt.write_versions):
        raise ValueError('retention C02 Trace does not belong to its actual Source episode')
    _history_member_v1(db, read, episode, operation_id, receipt)
    quotes = tuple((quote, weight) for quote, weight in trace.value['detail_weights'])
    return source, cause, receipt, quotes


@dataclass(frozen=True, slots=True)
class RetentionAdoptionCauseV1:
    namespace: NamespaceId
    activity_id: str
    adoption_operation_id: str
    adoption_original: ProductionOriginalRefV1
    adoption_receipt_digest: str
    adoption_commit_seq: int
    cause_time_utc: float
    source_version: GraphVersion
    trace_version: GraphVersion
    retention_read_version: GraphVersion
    retention_read_digest: str
    recollection_version: GraphVersion
    projection_version: GraphVersion
    actual_detail_states: tuple[tuple[str, str], ...]
    parent_budget_lease_ref: str
    original_deadline_utc: float
    schema: str = 'd06.memory-retention-c04-cause.v1'

    def __post_init__(self):
        if (self.schema != 'd06.memory-retention-c04-cause.v1' or type(self.namespace) is not NamespaceId
                or type(self.adoption_original) is not ProductionOriginalRefV1
                or type(self.adoption_commit_seq) is not int or self.adoption_commit_seq < 1
                or len(self.actual_detail_states) > 128 or len(dict(self.actual_detail_states)) != len(self.actual_detail_states)):
            raise ValueError('actual retention C04 cause has another closed identity')
        for v, kinds in ((self.source_version, {'memory.source'}),
                (self.trace_version, {'memory.subjective_trace.v1', 'memory.subjective_trace.v2'}),
                (self.retention_read_version, {READ_TYPE}), (self.recollection_version, {'d06.recollection.v1'}),
                (self.projection_version, {'d06.recollection_projection.v1'})):
            if type(v) is not GraphVersion or v.revision < 1 or NamespaceId.from_key(v.key) != self.namespace or v.key.type_name not in kinds:
                raise ValueError('actual retention C04 cause changed a real member version')
        for name in ('adoption_receipt_digest', 'retention_read_digest'):
            digest = getattr(self, name)
            if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('actual retention C04 cause lost a complete commitment')
        if not 0 <= self.cause_time_utc < self.original_deadline_utc:
            raise ValueError('retention C04 cause left its actual original time scope')
        if any(state not in {'retrieved', 'blurred', 'inferred', 'unavailable', 'uncertain'} for _, state in self.actual_detail_states):
            raise ValueError('retention C04 cause has an unregistered adopted detail state')


def _adopted_cause_v1(reader, db, read, request):
    raw, operation_id = _signed_cause_v1(reader, request.c04_adoption_original, C04_CAUSE_KIND)
    cause = decode_retention_value_v1(raw, RetentionAdoptionCauseV1)
    task = _METADATA[reader][_metadata_identity_v1(reader, C04_CAUSE_KIND, request.c04_adoption_original.original_ref)]
    receipt = task.receipt
    if (cause.adoption_operation_id != operation_id or cause.namespace != read.frame.envelope.authority.namespace
            or (cause.recollection_version, cause.projection_version) != (request.recollection_version, request.projection_version)
            or canonical_digest(receipt) != cause.adoption_receipt_digest or receipt.commit_seq != cause.adoption_commit_seq
            or request.retention_read_original.original_ref != cause.retention_read_version.key.token
            or request.retention_read_original.original_digest != cause.retention_read_digest
            or read.frame.envelope.parent_budget_lease_ref != cause.parent_budget_lease_ref
            or read.frame.envelope.deadline_utc > cause.original_deadline_utc
            or read.frame.now_utc >= cause.original_deadline_utc):
        raise ValueError('retention contribution differs from its actual signed C04 adoption')
    frozen_atom = _head_v1(read, db, cause.retention_read_version)
    frozen = decode_retention_value_v1(frozen_atom.value, MemoryRetentionReadV1)
    if (retention_payload_digest_v1(frozen) != cause.retention_read_digest
            or cause.retention_read_version not in receipt.read_versions
            or frozen.status != 'initialized' or frozen.source_version != cause.source_version
            or frozen.trace_version != cause.trace_version or frozen.activity_id != cause.activity_id):
        raise ValueError('actual C04 did not consume this exact initialized retention read')
    _source_v1(read, db, cause.source_version)
    recollection = _head_v1(read, db, cause.recollection_version)
    projection = _head_v1(read, db, cause.projection_version)
    _history_member_v1(db, read, recollection, operation_id, receipt)
    _history_member_v1(db, read, projection, operation_id, receipt)
    value = projection.value
    if (value['source_ref'] != cause.source_version.key.token or value['source_revision'] != cause.source_version.revision
            or value['recollection_ref'] != recollection.key.token or value['activity_id'] != cause.activity_id
            or tuple((d['detail_id'], d['state']) for d in value['details']) != cause.actual_detail_states):
        raise ValueError('retention cause is not the actual adopted subjective detail projection')
    return cause, frozen


@dataclass(frozen=True, slots=True)
class _RetentionInputsV1:
    reader: object
    read: object
    writes: tuple[GraphWrite, ...]
    provenance: object
    view: object


def _read_current_retention_inputs_v1(readers, db, frame, request):
    reader, read = _current_v1(readers, db, frame, request)
    ns = frame.envelope.authority.namespace
    if type(request) is RegisterMemoryRetentionPolicyRequestV1:
        key = AtomKey.from_token(request.policy_ref)
        if NamespaceId.from_key(key) != ns:
            raise ValueError('retention policy registration crossed the actual Owner namespace')
        before = read.head(db, key)
        if before.revision != request.expected_revision:
            raise MissingProductionOriginalV1('exact_retention_policy_CAS')
        if before.revision:
            prior = _verify_policy_v1(readers, before)
            if request.definition.version <= prior.definition.version:
                raise ValueError('retention policy replacement needs an explicit newer definition version')
        _maintenance_grant_v1(readers, db, frame, request.definition)
        installed = readers.installed_bundle.installation_policy
        unsigned = MemoryRetentionPolicyV1(ns, key.token, before.revision + 1, request.definition,
            frame.envelope.identity.operation_id, frame.now_utc, canonical_digest(frame.owner_guard),
            installed.installation_id, installed.manifest_digest, 'pending-signature')
        policy = replace(unsigned, signature=readers.issuer._signer.sign(POLICY_SIGNATURE_KIND, _policy_message_v1(unsigned)))
        return _RetentionInputsV1(reader, read, (GraphWrite(key, retention_payload_v1(policy)),),
            {'policy': policy, 'duplicate': False}, {'status': 'policy_registered', 'ref': key.token, 'revision': before.revision + 1})
    if type(request) is InitializeMemoryRetentionRequestV1:
        source, cause, receipt, quotes = _c02_seed_v1(readers, reader, db, read, request)
        policy_atom = _head_v1(read, db, GraphVersion(AtomKey.from_token(request.policy_ref), request.policy_revision))
        policy = _verify_policy_v1(readers, policy_atom)
        _maintenance_grant_v1(readers, db, frame, policy.definition)
        key = detail_retention_key_v1(ns, request.source_version, request.trace_version)
        before = read.head(db, key)
        if before.revision:
            current = decode_retention_value_v1(before.value, DetailRetentionV1)
            _state_producer_v1(db, read, before)
            if (current.source_version != request.source_version or current.trace_version != request.trace_version
                    or current.c02_original != request.c02_original):
                raise ValueError('retention seed cannot replace a different real encoding original')
            return _RetentionInputsV1(reader, read, (), {'state': current, 'duplicate': True},
                {'status': 'already_initialized', 'ref': key.token, 'revision': before.revision, 'tier': current.tier})
        details = seed_retention_details_v1(ns, request.source_version, request.trace_version, source.text, quotes,
            policy.definition, cause.cause_frozen_at_utc)
        current = DetailRetentionV1(ns, request.source_version, request.trace_version,
            GraphVersion(policy_atom.key, policy_atom.revision), retention_payload_digest_v1(policy),
            retention_payload_digest_v1(policy.definition), policy.definition, request.c02_original,
            canonical_digest(receipt), cause.cause_frozen_at_utc, details, 'hot', receipt.commit_seq, None)
        return _RetentionInputsV1(reader, read, (GraphWrite(key, retention_payload_v1(current), (request.source_version.key,)),),
            {'state': current, 'policy': policy, 'c02_cause': cause, 'duplicate': False},
            {'status': 'initialized', 'ref': key.token, 'revision': 1, 'tier': current.tier})
    if type(request) is ApplyRecollectionRetentionRequestV1:
        cause, frozen = _adopted_cause_v1(reader, db, read, request)
        contribution_key = retention_contribution_key_v1(ns, cause.activity_id, cause.source_version.key.token)
        prior = read.head(db, contribution_key)
        state_atom = read.head(db, frozen.state_version.key, required=True)
        state = decode_retention_value_v1(state_atom.value, DetailRetentionV1)
        _state_producer_v1(db, read, state_atom)
        if prior.revision:
            old = decode_retention_value_v1(prior.value, MemoryRetentionContributionV1)
            original = _state_producer_v1(db, read, prior)
            if (old.causal_activity_id, old.source_target) != (cause.activity_id, cause.source_version.key.token):
                raise ValueError('retention contribution dedupe belongs to another activity/Source')
            return _RetentionInputsV1(reader, read, (), {'contribution': old, 'duplicate': True,
                'original_receipt': original['receipt']}, {'status': 'already_applied', 'ref': contribution_key.token,
                'revision': prior.revision, 'state_ref': state_atom.key.token, 'state_revision': state_atom.revision})
        _maintenance_grant_v1(readers, db, frame, state.policy_definition)
        require_retention_cause_watermark_v1(reader, source_ref=cause.source_version.key.token,
            through_commit_seq=cause.adoption_commit_seq, applying_original=request.c04_adoption_original)
        if (state.source_version, state.trace_version) != (cause.source_version, cause.trace_version):
            raise ValueError('retention cause changed its actual Source/Trace target')
        if cause.adoption_commit_seq <= state.last_cause_commit_seq:
            raise MissingProductionOriginalV1('ordered_unapplied_retention_causes')
        details, changes = contribute_retention_details_v1(state, cause_time_utc=cause.cause_time_utc,
            actual_detail_states=cause.actual_detail_states)
        after = replace(state, details=details, last_cause_commit_seq=cause.adoption_commit_seq,
            last_contribution_ref=contribution_key.token)
        contribution = MemoryRetentionContributionV1(ns, cause.activity_id, cause.source_version.key.token,
            'internal_recollection', request.c04_adoption_original, cause.recollection_version, cause.projection_version,
            cause.retention_read_version, GraphVersion(state_atom.key, state_atom.revision),
            GraphVersion(state_atom.key, state_atom.revision + 1), cause.adoption_commit_seq, cause.cause_time_utc, changes)
        writes = (GraphWrite(state_atom.key, retention_payload_v1(after), (cause.source_version.key,)),
            GraphWrite(contribution_key, retention_payload_v1(contribution), (cause.source_version.key,)))
        return _RetentionInputsV1(reader, read, writes, {'state': after, 'contribution': contribution,
            'c04_cause': cause, 'frozen_read': frozen, 'duplicate': False},
            {'status': 'applied', 'ref': contribution_key.token, 'revision': 1,
                'state_ref': state_atom.key.token, 'state_revision': state_atom.revision + 1})
    if type(request) is ReconcileMemoryRetentionTierRequestV1:
        state_atom = _head_v1(read, db, request.expected_retention_version)
        state = decode_retention_value_v1(state_atom.value, DetailRetentionV1)
        _state_producer_v1(db, read, state_atom)
        if state.source_version.key.token != request.source_ref:
            raise ValueError('tier maintenance selected another actual Source state')
        _source_v1(read, db, state.source_version)
        read.original(request.maintenance_trigger_original.original_ref,
            kind=request.maintenance_trigger_original.kind, digest=request.maintenance_trigger_original.original_digest)
        _maintenance_grant_v1(readers, db, frame, state.policy_definition)
        protection = prepare_current_retention_protection_v1(reader, source_ref=request.source_ref)
        protection.require_current_v1(reader)
        require_retention_cause_watermark_v1(reader, source_ref=request.source_ref, through_commit_seq=None)
        tier = retention_candidate_tier_v1(state, evaluation_utc=frame.now_utc, protection_reasons=protection.reasons)
        after = replace(state, tier=tier)
        writes = () if tier == state.tier else (GraphWrite(state_atom.key, retention_payload_v1(after), (state.source_version.key,)),)
        return _RetentionInputsV1(reader, read, writes, {'state': after, 'protection': protection.value, 'duplicate': not writes},
            {'status': 'tier_reconciled', 'ref': state_atom.key.token,
                'revision': state_atom.revision + bool(writes), 'tier': tier})
    raise TypeError('unregistered actual retention operation')


class CurrentRetentionStageV1:
    def __init__(self, key, frame, request, inputs, stage):
        if key is not _KEY:
            raise AuthorityUnavailable('retention stage is issued only by actual current readers')
        self.frame, self.request, self.inputs, self.stage = frame, request, inputs, stage
        self.binding = _binding_v1(inputs.reader)
        self.write_digest = canonical_digest(tuple(w for p in stage.proposals for w in p.typed_writes))
        _STAGES[self] = (inputs.reader, frame, request, stage, self.binding, self.write_digest)
        _STAGE_VALUES[id(stage)] = self
        inputs.reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 65536 + _heap((self.request, self.inputs.provenance, self.inputs.view, self.stage))
    def release_payload_v1(self):
        if _STAGES.pop(self, None) is not None:
            _STAGE_VALUES.pop(id(self.stage),None)
            self.inputs.reader.operation.unregister_retained_state_v3(self)


def stage_memory_retention_v1(db, *, frame, request, installed_readers):
    inputs = installed_readers.read_current(db, frame, request)
    from ..domains.d06 import D06DomainProvider
    provider = D06DomainProvider()
    stage = stage_result_v1(frame, 'd06', _request_kind(request), request, writes=inputs.writes,
        provenance=inputs.provenance, proposal_schema='d06.contract.v1', proposal_hash=provider.descriptor.request_schema_hash)
    CurrentRetentionStageV1(_KEY, frame, request, inputs, stage)
    return stage


def require_actual_retention_stage_v1(stage, db, *, scope, owner_guard):
    value=_STAGE_VALUES.get(id(stage))
    if value is None or value.stage is not stage or type(value) is not CurrentRetentionStageV1:
        raise AuthorityUnavailable('actual retention stage qualification required')
    expected = _STAGES.get(value)
    if expected != (value.inputs.reader, value.frame, value.request, value.stage, value.binding, value.write_digest):
        raise AuthorityUnavailable('retention stage left its private issued identity')
    reader = value.inputs.reader
    _owner_v1(reader)
    value.inputs.read.check(db)
    if (value.binding != _binding_v1(reader) or db is not reader.db or scope.operation != 'write'
            or scope.namespace != value.stage.namespace or value.stage.request_digest != canonical_digest({"request": value.request, "envelope": value.frame.envelope})
            or value.write_digest != canonical_digest(tuple(w for p in value.stage.proposals for w in p.typed_writes))
            or owner_guard != value.frame.owner_guard
            or scope is not require_current_retention_write_v1(reader)[1]):
        raise AuthorityUnavailable('retention stage changed its actual W01 Source/Owner/write candidate')
    require_current_retention_source_v1(reader).permission.require_for_v3(reader)
    return stage


def verify_retention_stage_v1(stage):
    if type(stage) is not StagedDomainOperationV1:
        raise AuthorityUnavailable('retention needs its actual formal staged domain operation')
    value=_STAGE_VALUES.get(id(stage))
    if value is None or value.stage is not stage or value not in _STAGES:
        raise AuthorityUnavailable('unissued retention stage')
    stage = value.stage
    if stage.domain != 'd06' or OPERATIONS.get(stage.operation_kind) is not type(value.request):
        raise ValueError('retention stage operation has another typed contract')
    for proposal in stage.proposals:
        if proposal.domain != 'd06' or any(w.key.type_name not in {POLICY_TYPE, DETAIL_TYPE, CONTRIBUTION_TYPE} for w in proposal.typed_writes):
            raise ValueError('retention maintenance cannot write other domain contents')
    return stage


def committed_memory_retention_view_v1(stage, receipt):
    verify_retention_stage_v1(stage)
    value=_STAGE_VALUES[id(stage)]
    if receipt.status != 'committed' or receipt.operation_id != value.stage.operation_id:
        raise ValueError('retention committed view requires its actual same-operation receipt')
    return dict(value.inputs.view)


def _c02_cause_type_v1():
    from .foreground_cycle_v1 import ForegroundPostC02CauseV1
    return ForegroundPostC02CauseV1


class CurrentRetentionClockV1:
    def __init__(self, key, reader, value):
        if key is not _KEY or type(value) is not RetentionClockObservationV1:
            raise AuthorityUnavailable('actual paired retention clock observation required')
        self.reader, self.value, self.binding = reader, value, _binding_v1(reader)
        _CLOCKS[self] = (reader, self.binding, value)
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 4096 + _heap(self.value)
    def require_current_v1(self, reader):
        _owner_v1(reader)
        if (_CLOCKS.get(self) != (reader, self.binding, self.value)
                or self.binding != _binding_v1(reader)):
            raise AuthorityUnavailable('retention clock left its actual retained Source Work')
        return self
    def release_payload_v1(self):
        if _CLOCKS.pop(self, None) is not None:
            self.reader.operation.unregister_retained_state_v3(self)


def observe_current_retention_clock_v1(reader):
    import time
    from .first_ingress_v2 import trusted_upper_at_v4
    from ..host.v2_fence_port import VerifiedIngressClockV2
    from ..authority_service.v2_clock import CLOCK_SCHEMA
    _owner_v1(reader)
    if reader.db.in_transaction:
        raise AuthorityUnavailable('retention paired clock RPC must precede the Graph SQL quantum')
    graph = reader.graph
    reading = graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    if type(reading) is not VerifiedIngressClockV2:
        raise TypeError('actual paired ingress reading required')
    policy = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
    if reading.sample.installation_id != policy.installation_id:
        raise AuthorityUnavailable('retention clock crossed the actual installed Authority pairing')
    observed = time.monotonic()
    value = RetentionClockObservationV1(reading.sample, reading.monotonic_before_seconds,
        reading.monotonic_after_seconds, reading.utc_upper_bound_seconds, observed,
        trusted_upper_at_v4(reading, observed), CLOCK_SCHEMA)
    return CurrentRetentionClockV1(_KEY, reader, value)


def _foreground_frame_v1(reader):
    from .foreground_command_source_v3 import _FRAMES
    found = tuple(frame for frame, state, prepared in _FRAMES.values() if state.reader is reader)
    if len(found) != 1:
        raise AuthorityUnavailable('retention read requires the actual current C04 foreground frame')
    frame = found[0]
    if frame.envelope.identity.operation_id != reader.operation_id or frame.owner_guard != reader.material_owner_guard:
        raise AuthorityUnavailable('retention read changed its actual C04 frame/Owner')
    return frame


class CurrentRetentionReadV1:
    def __init__(self, key, reader, frame, value, write, clock):
        if key is not _KEY or type(value) is not MemoryRetentionReadV1:
            raise AuthorityUnavailable('retention read requires its actual same-Work producer')
        self.reader, self.frame, self.value, self.write, self.clock = reader, frame, value, write, clock
        self.binding = _binding_v1(reader)
        self.write_digest = canonical_digest(write)
        self.read_versions = frame.snapshot.versions
        self.candidate_version = GraphVersion(write.key, 1)
        _READS[self] = (reader, frame, value, write, clock, self.binding, self.write_digest)
        reader.operation.register_retained_state_v3(self)
    @property
    def detail_cues(self):
        return detail_cues_from_retention_read_v1(self.value)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 65536 + _heap((self.value, self.write, self.read_versions))
    def require_current_v1(self, reader):
        _owner_v1(reader)
        if (_READS.get(self) != (reader, self.frame, self.value, self.write, self.clock, self.binding, self.write_digest)
                or self.binding != _binding_v1(reader) or self.write_digest != canonical_digest(self.write)):
            raise AuthorityUnavailable('retention read changed its actual Source Work or frozen write')
        self.clock.require_current_v1(reader)
        CurrentDomainReadV1(self.frame).check(reader.db)
        return self
    def release_payload_v1(self):
        if _READS.pop(self, None) is not None:
            self.reader.operation.unregister_retained_state_v3(self)


def prepare_current_retention_read_v1(reader, *, source_ref, trace_ref, evaluation_clock):
    from .foreground_command_source_v3 import require_foreground_command_owner_reader_v3
    state = require_foreground_command_owner_reader_v3(reader)
    _owner_v1(reader)
    if not state.source_complete:
        raise AuthorityUnavailable('retention detail Body cannot precede C04 Source ALL')
    if type(evaluation_clock) is not CurrentRetentionClockV1:
        raise AuthorityUnavailable('retention read cannot accept a caller time or fabricated clock DTO')
    clock = evaluation_clock.require_current_v1(reader)
    frame = _foreground_frame_v1(reader)
    read = CurrentDomainReadV1(frame)
    read.check(reader.db)
    source_atom = read.head(reader.db, source_ref, required=True)
    trace_atom = read.head(reader.db, trace_ref, required=True)
    source_version, trace_version = GraphVersion(source_atom.key, source_atom.revision), GraphVersion(trace_atom.key, trace_atom.revision)
    _source_v1(read, reader.db, source_version)
    (validate_subjective_trace_v2 if trace_atom.key.type_name.endswith('.v2') else validate_subjective_trace)(trace_atom.value)
    key = detail_retention_key_v1(reader.namespace, source_version, trace_version)
    current = read.head(reader.db, key)
    require_retention_cause_watermark_v1(reader, source_ref=source_ref, through_commit_seq=None)
    if current.valid and current.revision:
        value = decode_retention_value_v1(current.value, DetailRetentionV1)
        _state_producer_v1(reader.db, read, current)
        if value.source_version != source_version or value.trace_version != trace_version:
            raise ValueError('current retention state changed its exact Source/Trace seed')
        details = retention_read_details_v1(value, clock.value.evaluation_utc)
        state_version, policy_version, status = GraphVersion(current.key, current.revision), value.policy_version, 'initialized'
    elif current.revision:
        raise MissingProductionOriginalV1('retention_state_invalidated_or_retired_requires_original_resolution')
    else:
        details, state_version, policy_version, status = (), None, None, 'uninitialized'
    read_key = retention_read_key_v1(reader.namespace, frame.envelope.identity.activity_id,
        frame.envelope.identity.operation_id, source_ref)
    if read.head(reader.db, read_key).revision:
        raise MissingProductionOriginalV1('actual_original_retention_read_replay')
    source_versions = tuple(v for v in frame.snapshot.versions if v.key.type_name in {
        'memory.source', 'memory.access', 'd06.source_correction_head.v1'})
    frozen = MemoryRetentionReadV1(reader.namespace, frame.envelope.identity.activity_id,
        frame.envelope.identity.operation_id, source_version, trace_version, state_version, policy_version,
        clock.value.evaluation_utc, clock.value, retention_payload_digest_v1(clock.value),
        source_versions, details, status)
    write = GraphWrite(read_key, retention_payload_v1(frozen), (source_atom.key,))
    return CurrentRetentionReadV1(_KEY, reader, frame, frozen, write, clock)


def require_actual_retention_read_write_v1(proof, *, reader, frame, write):
    if type(proof) is not CurrentRetentionReadV1:
        raise AuthorityUnavailable('actual C04 retention read producer required')
    proof.require_current_v1(reader)
    if proof.frame is not frame or proof.write != write or proof.write_digest != canonical_digest(write):
        raise AuthorityUnavailable('C04 retention read writer changed its qualified candidate')
    return proof


def record_retention_read_after_cas_v1(graph, db, *, witness, proof, receipt):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    from .c04_ingress_preparation_v4 import SelfC04PreparationStageV4
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.runtime.graph is not graph or witness.scope is None or witness.scope.operation != 'write'
            or type(witness.stage) is not SelfC04PreparationStageV4 or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or type(proof) is not CurrentRetentionReadV1 or proof not in _READS
            or witness.frame is not proof.frame or receipt.status != 'committed'
            or receipt.operation_id != proof.value.preparation_operation_id
            or proof.candidate_version not in receipt.write_versions):
        raise AuthorityUnavailable('retention read original requires its real active C04 prepare CAS')
    return ProductionOriginalRefV1(READ_TYPE, proof.write.key.token,
        retention_payload_digest_v1(proof.value), (proof.candidate_version,))


def record_recollection_retention_cause_after_cas_v1(graph, db, *, witness, staged, receipt, adoption_original):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    from .c04_ingress_adoption_v4 import SelfC04AdoptionStageV4
    from .d11_life_preparation_v1 import _record
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.runtime.graph is not graph or witness.stage is not staged
            or type(staged) is not SelfC04AdoptionStageV4 or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or receipt.status != 'committed'
            or receipt.operation_id != staged.frame.envelope.identity.operation_id
            or type(adoption_original) is not ProductionOriginalRefV1):
        raise AuthorityUnavailable('retention cause requires the actual active Self C04 adopting W01')
    if (adoption_original.kind != 'd06.current-' + staged.stage.operation_kind
            or adoption_original.original_ref != 'd06-current:' + staged.stage.original_digest[:48]
            or adoption_original.original_digest != staged.stage.original_digest
            or adoption_original.read_versions != staged.stage.read_versions):
        raise ValueError('retention cause requires the actual recorded C04 Domain original')
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    with runtime_storage_quantum_v3(db) as meter:
        actual=_runtime_bounded_fixed_row_v3(db,meter,'graph_domain_production_originals_v1',
            ('original_digest','bundle_digest','receipt_digest'),
            'bot=? AND persona=? AND operation_id=?',(*staged.stage.namespace.as_tuple,receipt.operation_id))
    if actual!=(adoption_original.original_digest,receipt.operation_digest,canonical_digest(receipt)):
        raise ValueError('retention cause has no same-CAS actual Domain/Graph receipt')
    frozen = tuple(row for row in staged.work.reads if AtomKey.from_token(row.ref).type_name == READ_TYPE)
    if not frozen:
        return None
    # The selected Source alone contributes; other evaluated candidates do not.
    from .c04_v3_contracts import canonical_v3_digest
    planned = {v.ref: v for v in staged.plan.writes}
    writes = tuple(w for p in staged.bundle.proposals for w in p.typed_writes if w.key.token in planned)
    if {w.key.token for w in writes} != set(planned) or any(
            canonical_v3_digest(w.value) != planned[w.key.token].value_digest for w in writes):
        raise ValueError("retention cause changed the actual planned C04 value commitments")
    recollections = tuple(w for w in writes if w.key.type_name == 'd06.recollection.v1')
    projections = tuple(w for w in writes if w.key.type_name == 'd06.recollection_projection.v1')
    if len(writes) != 5 or len(recollections) != 1 or len(projections) != 1:
        raise ValueError('retention cause cannot extend or replace the actual C04 five writes')
    recollection, projection = recollections[0], projections[0]
    selected = projection.value['source_ref']
    matching = tuple(row for row in frozen if row.valid and row.value is not None and row.value['source_version']['key'] ==
        retention_payload_v1(AtomKey.from_token(selected)))
    if len(matching) != 1:
        raise ValueError('actual selected C04 Source lacks its unique frozen retention read')
    row = matching[0]
    value = decode_retention_value_v1(row.value, MemoryRetentionReadV1)
    if value.status == 'uninitialized':
        return None
    read_version = GraphVersion(AtomKey.from_token(row.ref), row.revision)
    by_key = {v.key: v for v in receipt.write_versions}
    if (read_version not in receipt.read_versions or recollection.key not in by_key or projection.key not in by_key
            or value.activity_id != receipt.activity_id or value.source_version.key.token != selected
            or projection.value['source_revision'] != value.source_version.revision):
        raise ValueError('retention cause changed real C04 reads/writes/activity')
    states = tuple((v['detail_id'], v['state']) for v in projection.value['details'])
    if len(dict(states)) != len(states) or not set(dict(states)) <= {v.detail_id for v in value.details}:
        raise ValueError('retention contribution includes detail identities outside the actual frozen read')
    cause = RetentionAdoptionCauseV1(value.namespace, receipt.activity_id, receipt.operation_id, adoption_original,
        canonical_digest(receipt), receipt.commit_seq, staged.frame.now_utc, value.source_version, value.trace_version,
        read_version, retention_payload_digest_v1(value), by_key[recollection.key], by_key[projection.key], states,
        staged.frame.envelope.parent_budget_lease_ref, staged.frame.envelope.deadline_utc)
    ref = 'retention-c04:' + canonical_digest((value.namespace, receipt.activity_id, selected))[:48]
    original = _record(db, issuer=graph._GraphCoordinator__d11_issuer, namespace=value.namespace,
        kind=C04_CAUSE_KIND, ref=ref, operation_id=receipt.operation_id, value=cause)
    dedupe = canonical_digest((value.namespace, receipt.operation_id, 'd06', C04_EVENT))
    if db.execute('SELECT 1 FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?',
            (*value.namespace.as_tuple, dedupe)).fetchone() is not None:
        raise ValueError('a new C04 retention cause cannot replace its durable maintenance outbox')
    db.execute('INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (*value.namespace.as_tuple, dedupe, receipt.operation_id, 'd06', C04_EVENT,
            original.original_ref, original.original_digest, 'pending', None, None))
    return original


_RETENTION_GRAPH_METADATA_FIELDS_V1 = {
    POLICY_TYPE: frozenset({'schema', 'namespace', 'policy_ref', 'policy_revision', 'definition', 'issuing_operation_id',
        'issued_at_utc', 'owner_guard_digest', 'installation_id', 'manifest_digest', 'signature'}),
    DETAIL_TYPE: frozenset({'schema', 'namespace', 'source_version', 'trace_version', 'policy_version',
        'policy_original_digest', 'policy_definition_digest', 'c02_original', 'c02_receipt_digest',
        'encoding_time_utc', 'tier', 'last_cause_commit_seq', 'last_contribution_ref'}),
    READ_TYPE: frozenset({'schema', 'namespace', 'activity_id', 'preparation_operation_id', 'source_version',
        'trace_version', 'state_version', 'policy_version', 'evaluation_utc', 'status'}),
    CONTRIBUTION_TYPE: frozenset({'schema', 'namespace', 'causal_activity_id', 'source_target', 'cause_kind',
        'c04_adoption_original', 'recollection_version', 'projection_version', 'retention_read_version',
        'previous_state_version', 'resulting_state_version', 'cause_commit_seq', 'cause_time_utc'}),
    'memory.subjective_trace.v1': frozenset({'trace_id', 'episode_ref'}),
    'memory.subjective_trace.v2': frozenset({'trace_id', 'episode_ref', 'encoding_baseline_ref'}),
}


def retention_metadata_retains_path_v1(identity, path):
    if identity[0] == 'graph_head':
        key = AtomKey.from_token(identity[1])
        return not path or path[0] in _RETENTION_GRAPH_METADATA_FIELDS_V1[key.type_name]
    return True


class CurrentRetentionGraphMetadataTaskV1:
    def __init__(self, key, reader, identity):
        _owner_v1(reader)
        token = AtomKey.from_token(identity[1])
        if (key is not _KEY or identity[0] != 'graph_head' or len(identity) != 2
                or NamespaceId.from_key(token) != reader.namespace
                or token.type_name not in _RETENTION_GRAPH_METADATA_FIELDS_V1):
            raise AuthorityUnavailable('unregistered fixed retention Graph metadata selector')
        self.reader, self.identity, self.key, self.binding = reader, identity, token, _binding_v1(reader)
        self.header = self.column = self.value = self.producer_header = None
        self.complete = False
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 65536 + _heap((self.identity, self.header, self.value, self.producer_header))
    def require_current_v1(self, meter=None):
        _owner_v1(self.reader, meter)
        if self.binding != _binding_v1(self.reader) or _METADATA.get(self.reader, {}).get(self.identity) is not self:
            raise AuthorityUnavailable('retention Graph metadata left its actual same Source Work')
        if meter is not None and self.header is not None:
            from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
            current = _runtime_bounded_fixed_row_v3(self.reader.db, meter, 'graph_atoms',
                ('revision', 'valid', 'value_cell_id'), 'bot=? AND persona=? AND token=?',
                (*self.reader.namespace.as_tuple, self.key.token))
            if current != self.header:
                raise AuthorityUnavailable('retention Graph metadata current head changed')
        return self
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        self.require_current_v1(meter)
        if self.complete:
            return True
        r = self.reader
        if self.header is None:
            self.header = _runtime_bounded_fixed_row_v3(r.db, meter, 'graph_atoms',
                ('revision', 'valid', 'value_cell_id'), 'bot=? AND persona=? AND token=?',
                (*r.namespace.as_tuple, self.key.token))
            if self.header is None:
                self.value = {'ref': self.key.token, 'revision': 0, 'valid': False, 'metadata': None,
                    'value_digest': None, 'producer_operation_id': None}
                self.complete = True
                return True
            self.column = _RetentionColumnV1(self, table='graph_atoms', column='value',
                key_columns=('token',), key=(self.key.token,), cell_id=self.header[2])
            return False
        if self.column is not None:
            if not self.column.advance(meter):
                return False
            metadata = self.column.require_v3(r)
            self.value = {'ref': self.key.token, 'revision': self.header[0], 'valid': bool(self.header[1]),
                'metadata': metadata, 'value_digest': self.column.sha256, 'producer_operation_id': None}
            self.column.release_v1(); self.column = None
            return False
        self.producer_header = _runtime_bounded_fixed_row_v3(r.db, meter, 'graph_history',
            ('event_bot', 'event_persona', 'event_session', 'event_id', 'valid'),
            'token=? AND revision=?', (self.key.token, self.header[0]))
        if (self.producer_header is None or self.producer_header[:2] != r.namespace.as_tuple
                or self.producer_header[4] != self.header[1]):
            raise AuthorityUnavailable('retention selected Graph head lacks its exact producer history')
        self.value['producer_operation_id'] = self.producer_header[3]
        self.complete = True
        r.operation.refresh_retained_state_v3(self)
        return True
    def release_v1(self):
        if self.column is not None:
            self.column.release_v1()
        self.column = self.value = self.header = self.producer_header = None
        self.reader.operation.unregister_retained_state_v3(self)


def _graph_metadata_v1(reader, key):
    identity = ('graph_head', key.token)
    task = _METADATA.get(reader, {}).get(identity)
    if task is None or not task.complete:
        _missing_metadata(identity)
    return task.require_current_v1().value


def _metadata_originals_v1(reader, keys):
    result = []
    for key in keys:
        if key.type_name not in _RETENTION_GRAPH_METADATA_FIELDS_V1:
            continue
        value = _graph_metadata_v1(reader, key)
        if value['revision']:
            result.append(value['producer_operation_id'])
    return tuple(dict.fromkeys(result))


def read_plan_memory_retention_v1(db, *, namespace, activity_id, operation_kind, request,
        operation_id=None, issuer=None):
    reader = _active_reader_v1(db)
    if (reader.namespace != namespace or operation_kind != _request_kind(request)
            or reader.request != request or operation_id != reader.operation_id
            or issuer is not None and issuer is not reader.graph._GraphCoordinator__d11_issuer):
        raise AuthorityUnavailable('retention read plan changed its actual private operation metadata')
    keys, roots, originals = [], [], []
    if type(request) is RegisterMemoryRetentionPolicyRequestV1:
        keys.append(AtomKey.from_token(request.policy_ref))
    elif type(request) is InitializeMemoryRetentionRequestV1:
        keys.extend((request.source_version.key, request.trace_version.key, AtomKey.from_token(request.policy_ref),
            detail_retention_key_v1(namespace, request.source_version, request.trace_version)))
        trace = _graph_metadata_v1(reader, request.trace_version.key)
        if trace['revision'] != request.trace_version.revision or not trace['valid']:
            raise MissingProductionOriginalV1('actual_retention_trace_metadata')
        keys.append(AtomKey.from_token(trace['metadata']['episode_ref']))
        _signed_cause_v1(reader, request.c02_original, C02_CAUSE_KIND)
        roots.append(request.source_version.key.token)
        originals.append(request.c02_original.original_ref)
    elif type(request) is ApplyRecollectionRetentionRequestV1:
        raw, operation = _signed_cause_v1(reader, request.c04_adoption_original, C04_CAUSE_KIND)
        cause = decode_retention_value_v1(raw, RetentionAdoptionCauseV1)
        require_retention_cause_watermark_v1(reader,source_ref=cause.source_version.key.token,
            through_commit_seq=cause.adoption_commit_seq,applying_original=request.c04_adoption_original)
        frozen = _graph_metadata_v1(reader, cause.retention_read_version.key)
        if frozen['metadata'] is None or frozen['metadata']['state_version'] is None:
            raise MissingProductionOriginalV1('actual_initialized_retention_read_metadata')
        state_version = decode_retention_value_v1(frozen['metadata']['state_version'], GraphVersion)
        keys.extend((cause.source_version.key, cause.trace_version.key, cause.retention_read_version.key,
            state_version.key, cause.recollection_version.key, cause.projection_version.key,
            retention_contribution_key_v1(namespace, cause.activity_id, cause.source_version.key.token)))
        roots.append(cause.source_version.key.token)
        # The signed causal metadata authenticates the past C04 producer and frozen read.
        # Its Domain original is a header commitment, never a request for the old whole C04 Body.
        originals.append(request.c04_adoption_original.original_ref)
    else:
        keys.extend((AtomKey.from_token(request.source_ref), request.expected_retention_version.key))
        roots.append(request.source_ref)
        originals.append(request.maintenance_trigger_original.original_ref)
        protection = prepare_current_retention_protection_v1(reader, source_ref=request.source_ref)
        require_retention_cause_watermark_v1(reader,source_ref=request.source_ref,through_commit_seq=None)
        # Complete protection coverage contributes CAS only, never a request for other domains' Body.
        protection.require_current_v1(reader)
    producers=_metadata_originals_v1(reader, keys)
    originals.extend(producers)
    plan=production_read_plan_v1((), tuple(sorted(set(keys), key=lambda k:k.token)), tuple(roots), tuple(dict.fromkeys(originals)))
    state=require_current_retention_source_v1(reader)
    state.plan=plan;state.keys=set(keys);state.roots=set(roots);state.producers=set(producers)
    reader.operation.refresh_retained_state_v3(state)
    return plan


def release_current_retention_v1(reader):
    _SOURCE_WRITES.pop(reader,None)
    source_state=_SOURCE_STATES.pop(reader,None)
    if source_state is not None:
        source_state.plan=source_state.permission=None
        source_state.keys.clear();source_state.roots.clear();source_state.producers.clear()
        reader.operation.unregister_retained_state_v3(source_state)
    for task in _METADATA.pop(reader, {}).values():
        task.release_v1()
    for proof, record in tuple(_READS.items()):
        if record[0] is reader:
            proof.release_payload_v1()
    for proof, record in tuple(_CLOCKS.items()):
        if record[0] is reader:
            proof.release_payload_v1()
    for proof in tuple(_STAGES):
        if proof.inputs.reader is reader:
            proof.release_payload_v1()
    for task in _WATERMARKS.pop(reader, {}).values():
        task.release_v1()
    protection = _PROTECTION.pop(reader, None)
    if protection is not None:
        protection.release_v1()


_WATERMARKS = WeakKeyDictionary()


def _require_selected_source_v1(reader, source_ref):
    _owner_v1(reader)
    key = AtomKey.from_token(source_ref)
    if NamespaceId.from_key(key) != reader.namespace or key.type_name != 'memory.source':
        raise AuthorityUnavailable('retention metadata target has another namespace/type')
    request = reader.request
    if type(request) is InitializeMemoryRetentionRequestV1:
        allowed = (request.source_version.key.token,)
    elif type(request) is ReconcileMemoryRetentionTierRequestV1:
        allowed = (request.source_ref,)
    elif type(request) is ApplyRecollectionRetentionRequestV1:
        raw, _ = _signed_cause_v1(reader, request.c04_adoption_original, C04_CAUSE_KIND)
        allowed = (decode_retention_value_v1(raw, RetentionAdoptionCauseV1).source_version.key.token,)
    else:
        from .foreground_command_source_v3 import require_foreground_command_owner_reader_v3
        allowed = require_foreground_command_owner_reader_v3(reader).current_roots
    if source_ref not in allowed:
        raise AuthorityUnavailable('retention metadata escaped its actual Source selector')


class CurrentRetentionCauseWatermarkV1:
    def __init__(self, key, reader, source_ref):
        _require_selected_source_v1(reader, source_ref)
        if key is not _KEY:
            raise AuthorityUnavailable('actual retention watermark issuer required')
        self.reader, self.source_ref, self.binding = reader, source_ref, _binding_v1(reader)
        self.identity = ('cause_census', source_ref)
        self.after = ''; self.count = 0; self.header = self.column = None
        self.causes = []; self.versions = {}; self.complete = False
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 65536 + _heap((self.after, self.header, self.causes, self.versions))
    def require_current_v1(self, meter=None):
        _owner_v1(self.reader, meter)
        if self.binding != _binding_v1(self.reader) or _WATERMARKS.get(self.reader, {}).get(self.source_ref) is not self:
            raise AuthorityUnavailable('retention cause census left its actual Work/namespace epoch')
        return self
    def advance(self, meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d11_life_preparation_v1 import TABLE, SIGN_KIND
        self.require_current_v1(meter)
        if self.complete:
            return True
        r = self.reader
        if self.header is None:
            header = _runtime_bounded_fixed_row_v3(r.db, meter, TABLE,
                ('original_ref', 'producing_operation_id', 'payload_digest', 'signature'),
                'bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref LIMIT 1',
                (*r.namespace.as_tuple, C04_CAUSE_KIND, self.after))
            if header is None:
                self.causes.sort(key=lambda v:(v[0].adoption_commit_seq, v[1].original_ref))
                if len({v[0].adoption_commit_seq for v in self.causes}) != len(self.causes):
                    raise ValueError('one real retention Source has conflicting cause commit sequences')
                self.complete = True
                return True
            if self.count >= 128:
                raise MissingProductionOriginalV1('complete_bounded_retention_cause_metadata_census')
            self.count += 1; self.header = header
            self.column = _RetentionColumnV1(self, table=TABLE, column='payload_json',
                key_columns=('bot', 'persona', 'kind', 'original_ref'),
                key=(*r.namespace.as_tuple, C04_CAUSE_KIND, header[0]))
            return False
        if not self.column.advance(meter):
            return False
        raw = self.column.require_v3(r)
        ref, operation, digest, signature = self.header
        if self.column.sha256 != digest:
            raise ValueError('retention causal inventory lost complete canonical EOF')
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace, C04_CAUSE_KIND, ref, digest)), signature)
        cause = decode_retention_value_v1(raw, RetentionAdoptionCauseV1)
        if cause.namespace != r.namespace or cause.adoption_operation_id != operation:
            raise ValueError('retention causal census has another actual namespace/producer')
        if cause.source_version.key.token == self.source_ref:
            key = retention_contribution_key_v1(r.namespace, cause.activity_id, self.source_ref)
            head = _runtime_bounded_fixed_row_v3(r.db, meter, 'graph_atoms', ('revision', 'valid'),
                'bot=? AND persona=? AND token=?', (*r.namespace.as_tuple, key.token))
            if head is not None and (head[0] < 1 or head[1] != 1):
                raise MissingProductionOriginalV1('actual_retired_retention_contribution_resolution')
            self.versions[key] = 0 if head is None else head[0]
            self.causes.append((cause, ProductionOriginalRefV1('d11.life_' + C04_CAUSE_KIND, ref, digest), head is not None))
        self.column.release_v1(); self.column = None
        self.after = ref; self.header = None
        r.operation.refresh_retained_state_v3(self)
        return False
    def release_v1(self):
        if self.column is not None:
            self.column.release_v1()
        self.column = self.header = None
        self.causes.clear(); self.versions.clear()
        self.reader.operation.unregister_retained_state_v3(self)


def create_current_retention_cause_watermark_task_v1(reader, source_ref):
    values = _WATERMARKS.setdefault(reader, {})
    task = values.get(source_ref)
    if task is None:
        task = CurrentRetentionCauseWatermarkV1(_KEY, reader, source_ref)
        values[source_ref] = task
    return task


def require_retention_cause_watermark_v1(reader, *, source_ref, through_commit_seq, applying_original=None):
    _require_selected_source_v1(reader, source_ref)
    task = _WATERMARKS.get(reader, {}).get(source_ref)
    if task is None or not task.complete:
        _missing_metadata(('cause_census', source_ref))
    task.require_current_v1()
    for cause, original, applied in task.causes:
        if applied:
            continue
        if applying_original is not None and original == applying_original:
            if through_commit_seq != cause.adoption_commit_seq:
                raise ValueError('retention applying watermark changed its actual cause sequence')
            continue
        if through_commit_seq is None or cause.adoption_commit_seq < through_commit_seq:
            raise MissingProductionOriginalV1('earlier_actual_retention_contribution_pending',
                continuation='retention-cause:' + original.original_digest[:48])
    return task


def retention_metadata_versions_v1(reader):
    _owner_v1(reader)
    versions = {}
    for task in _METADATA.get(reader, {}).values():
        if type(task) is CurrentRetentionGraphMetadataTaskV1 and task.complete:
            task.require_current_v1()
            versions[task.key] = task.value['revision']
    for task in _WATERMARKS.get(reader, {}).values():
        if not task.complete:
            raise MissingProductionOriginalV1('complete_actual_retention_causal_watermark')
        task.require_current_v1()
        for key, revision in task.versions.items():
            if key in versions and versions[key] != revision:
                raise ValueError('retention metadata versions disagree within one actual Work')
            versions[key] = revision
    protection = _PROTECTION.get(reader)
    if protection is not None:
        protection.require_current_v1(reader)
        for version in protection.read_versions:
            if version.key in versions and versions[version.key] != version.revision:
                raise ValueError('retention protection and current Source versions disagree')
            versions[version.key] = version.revision
    if len(versions) > 1024:
        raise MissingProductionOriginalV1('bounded_retention_metadata_CAS_heads')
    return tuple(GraphVersion(k, v) for k, v in sorted(versions.items(), key=lambda item:item[0].token))


_PROTECTION_FIELDS_V1 = {
    'd01.persona_activation.v1': ('state','plan_id','plan_version','head_id'),
    'd05.boundary_rule': ('status','source_refs','communicated_refs','acknowledged_refs','exception_refs'),
    'd05.relationship_projection': ('status',),
    'd05.relationship_profile.v2': ('source_refs',),
    'd05.dimension_estimate.v2': ('status','source_refs'),
    'd05.relationship_expectation.v2': ('source_refs',),
    'd05.reciprocity_pattern.v2': ('source_refs','opportunity_source_refs','capability_source_refs','preference_source_refs'),
    'd05.repair_process.v2': ('status','source_refs'),
    'd08.aspiration.v1': ('source_refs',),
    'd08.goal.v1': ('state','reason_refs','dependency_refs','progress_refs'),
    'd08.commitment.v1': ('establishment_state','fulfillment_state','source_refs'),
    'd08.joint_plan.v1': ('source_refs',),
    'd08.long_term_plan.v1': ('state','source_refs'),
    'd08.joint_window.v1': ('state','source_refs'),
    'd10.life_project.v1': ('project_id',),
    'd10.life_progress.v1': ('source_refs',),
    'd10.habit_policy.v1': ('definition',),
    'd10.habit_occurrence.v1': ('state','source_refs'),
    'd06.source_correction_head.v1': ('state','source_ref','correction_source_ref','target_refs'),
}
_PROTECTION_STATES_V1 = {
    'd01.persona_activation.v1': ('state', frozenset({'active'}), frozenset()),
    'd05.boundary_rule': ('status', frozenset({'active'}), frozenset({'superseded','revoked'})),
    'd05.dimension_estimate.v2': ('status', frozenset({'current','held_reevaluation'}), frozenset()),
    'd05.repair_process.v2': ('status', frozenset({'proposed','waiting','practicing','partial','paused'}), frozenset({'ended'})),
    'd08.goal.v1': ('state', frozenset({'proposed','active','waiting','paused'}), frozenset({'satisfied','abandoned','superseded'})),
    'd08.commitment.v1': ('fulfillment_state', frozenset({'pending','partially_fulfilled','overdue','renegotiating'}), frozenset({'fulfilled','withdrawn'})),
    'd08.long_term_plan.v1': ('state', frozenset({'described','preparing','ready','waiting','paused'}), frozenset({'stopped','closed'})),
    'd08.joint_window.v1': ('state', frozenset({'described','preparing','ready','waiting','paused'}), frozenset({'stopped','closed'})),
    'd10.habit_occurrence.v1': ('state', frozenset({'registered','waiting','qualified','active','unknown'}), frozenset({'completed_verified','failed_verified','cancelled'})),
    'd06.source_correction_head.v1': ('state', frozenset({'pending_reevaluation'}), frozenset({'resolved_reevaluation'})),
}


def _protection_selected_v1(kind, value):
    if kind == 'd10.habit_policy.v1':
        status = value['definition']['state']
        if status not in {'enabled','paused','stopped','superseded'}:
            raise MissingProductionOriginalV1('known_current_retention_habit_state')
        return status in {'enabled','paused'}
    if kind == 'd05.relationship_projection':
        from ..domains.d05.relationship import RELATIONSHIP_STATUS_PUBLIC_V1
        if value['status'] not in RELATIONSHIP_STATUS_PUBLIC_V1:
            raise MissingProductionOriginalV1('known_current_retention_relationship_status')
        return True
    if kind in _PROTECTION_STATES_V1:
        field, active, terminal = _PROTECTION_STATES_V1[kind]
        status = value[field]
        if status not in active | terminal:
            raise MissingProductionOriginalV1('known_current_retention_protection_state:' + kind)
        if kind == 'd08.commitment.v1' and value['establishment_state'] not in {
                'private_intention','offered','communicated','acknowledged','disputed'}:
            raise MissingProductionOriginalV1('known_current_retention_establishment_state')
        return status in active
    return True


def _protection_retains_v1(path, kind):
    if not path:
        return True
    if kind == 'd10.habit_policy.v1':
        return path[0] == 'definition' and (len(path) == 1 or path[1] in {'state','source_refs'})
    return path[0] in _PROTECTION_FIELDS_V1[kind]


class CurrentRetentionProtectionTaskV1:
    def __init__(self, key, reader, source_ref):
        if key is not _KEY:
            raise AuthorityUnavailable('retention protection requires its actual private issuer')
        _require_selected_source_v1(reader, source_ref)
        for kind in _PROTECTION_FIELDS_V1:
            if reader.store._registry.spec(kind).writer_domain != kind.split('.')[0]:
                raise MissingProductionOriginalV1('registered_retention_protection_provider:' + kind)
        self.reader, self.source_ref, self.binding = reader, source_ref, _binding_v1(reader)
        self.identity = ('protection',source_ref)
        self.phase, self.after, self.count = 'census','',0
        self.census = hashlib.sha256(b'sylanne3.retention-protection.v1\0')
        self.row = self.column = self.inspection = self.current = None
        self.versions, self.members, self.roots, self.edges = {}, [], {}, {}
        self.queue, self.seen, self.source_nodes = [], set(), {}
        self.edge_after, self.complete, self.value = '', False, None
        self.type_counts={};self.edge_count=0
        self.control = self.control_task = None
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 65536 + _heap((self.row,self.versions,self.members,self.roots,self.edges,self.queue,self.seen,self.source_nodes,self.value,self.type_counts))
    def require_current_v1(self, reader=None, meter=None):
        r = self.reader
        _owner_v1(r,meter)
        if (reader is not None and reader is not r or _PROTECTION.get(r) is not self
                or self.binding != _binding_v1(r)):
            raise AuthorityUnavailable('retention protection left its actual Work/current metadata selection')
        if self.control is not None:self.control.require_current_v1(r)
        return self
    @property
    def reasons(self):
        if not self.complete:
            raise MissingProductionOriginalV1('complete_retention_protection_snapshot')
        return self.value.reasons
    @property
    def read_versions(self):
        return tuple(GraphVersion(key,rev) for key,rev in sorted(self.versions.items(),key=lambda v:v[0].token))
    def _version(self,key,revision):
        if key in self.versions and self.versions[key] != revision:
            raise AuthorityUnavailable('retention protection changed a current head within its census')
        self.versions[key] = revision
        if len(self.versions)>1024:
            raise MissingProductionOriginalV1('bounded_retention_protection_heads')
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.reader;self.require_current_v1(meter=meter)
        if self.complete:return True
        if self.phase=='census':
            types=tuple(sorted(_PROTECTION_FIELDS_V1))
            row=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_atoms',
                ('token','revision','valid','value_cell_id'),
                'bot=? AND persona=? AND type_name IN ('+','.join('?' for _ in types)+') AND token>? ORDER BY token',
                (*r.namespace.as_tuple,*types,self.after))
            if row is None:
                self.queue=list(self.roots);self.phase='dependencies';return False
            self.row=row;self.after=row[0];self.count+=1
            if self.count>1024:raise MissingProductionOriginalV1('bounded_complete_retention_protection_census')
            key=AtomKey.from_token(row[0]);self._version(key,row[1])
            self.type_counts[key.type_name]=self.type_counts.get(key.type_name,0)+1
            if self.type_counts[key.type_name]>128:
                raise MissingProductionOriginalV1('bounded_complete_retention_protection_type_query')
            self.census.update(canonical_serialize(row).encode('ascii'))
            if not row[2]:return False
            self.column=_RetentionColumnV1(self,table='graph_atoms',column='value',key_columns=('token',),key=(row[0],),cell_id=row[3])
            self.phase='metadata';return False
        if self.phase=='metadata':
            if not self.column.advance(meter):return False
            value=self.column.require_v3(r);digest=self.column.sha256
            key=AtomKey.from_token(self.row[0]);self.census.update(digest.encode('ascii'))
            if _protection_selected_v1(key.type_name,value):
                refs=[]
                values=value['definition'] if key.type_name=='d10.habit_policy.v1' else value
                for name in ('source_refs','opportunity_source_refs','capability_source_refs','preference_source_refs','source_ref','correction_source_ref'):
                    selected=values.get(name,())
                    if type(selected) is str:selected=(selected,)
                    for ref in selected:
                        token=AtomKey.from_token(ref)
                        if token.type_name!='memory.source' or NamespaceId.from_key(token)!=r.namespace:
                            raise AuthorityUnavailable('typed retention protection Source crossed namespace/type')
                        refs.append(ref)
                self.members.append((key,self.row[1],digest,tuple(dict.fromkeys(refs))))
                self.roots[key.token]=tuple(dict.fromkeys(refs))
                if key.type_name=='d01.persona_activation.v1':
                    plan=AtomKey(key.owner,'d01.persona_plan.v1',value['plan_id'])
                    self._version(plan,value['plan_version'])
                    self.edges.setdefault(key.token,set()).add(plan.token)
                    self.roots.setdefault(plan.token,())
                for ref in refs:self.roots.setdefault(ref,())
            self.column.release_v1();self.column=None;self.phase='census'
            r.operation.refresh_retained_state_v3(self);return False
        if self.phase=='dependencies':
            if self.current is None:
                if not self.queue:self.phase='control';return False
                token=self.queue.pop()
                if token in self.seen:return False
                self.seen.add(token);key=AtomKey.from_token(token)
                if NamespaceId.from_key(key)!=r.namespace:
                    raise AuthorityUnavailable('retention support dependency crossed namespace')
                if len(self.seen)>1024:raise MissingProductionOriginalV1('bounded_retention_typed_support_closure')
                head=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*r.namespace.as_tuple,token))
                if head is None or not head[1]:raise MissingProductionOriginalV1('current_retention_support_dependency')
                self._version(key,head[0]);self.current=token;self.edge_after='';self.edge_count=0
                if key.type_name=='memory.source':
                    from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
                    self.inspection=InspectionMetadataReadV3(r,key);self.phase='source_metadata'
                return False
            row=_runtime_bounded_fixed_row_v3(r.db,meter,'graph_dependencies',('dependency_token','dependency_revision'),
                'dependent_token=? AND dependency_token>? ORDER BY dependency_token',(self.current,self.edge_after))
            if row is None:self.current=None;return False
            token,revision=row;self.edge_after=token;self.edge_count+=1
            if self.edge_count>128:raise MissingProductionOriginalV1('bounded_retention_support_dependency_query')
            key=AtomKey.from_token(token)
            if NamespaceId.from_key(key)!=r.namespace or revision<1:
                raise AuthorityUnavailable('retention typed support dependency is not an actual same-namespace version')
            self._version(key,revision)
            self.edges.setdefault(self.current,set()).add(token);self.queue.append(token)
            r.operation.refresh_retained_state_v3(self);return False
        if self.phase=='source_metadata':
            if not self.inspection.advance(meter):return False
            original=self.inspection.result.require_v3(r,meter)
            if not original.valid:raise MissingProductionOriginalV1('current_retention_support_Source_metadata')
            from ..memory_types import source_key
            parents=tuple(source_key(*r.namespace.as_tuple,p).token for p in original.metadata['parent_source_ids'])
            self.source_nodes[self.current]=parents
            if len(self.source_nodes)>256:raise MissingProductionOriginalV1('bounded_retention_Source_ancestry_metadata')
            self.edges.setdefault(self.current,set()).update(parents);self.queue.extend(parents)
            self.inspection.release_v3();self.inspection=None;self.phase='dependencies';return False
        if self.phase=='control':
            if self.control_task is None:
                from .retention_control_protection_v1 import create_current_retention_control_protection_task_v1
                self.control_task=create_current_retention_control_protection_task_v1(r,(self.source_ref,))
                return False
            if not self.control_task.advance(meter):return False
            self.control=_current_control_protection_v1(r,self.source_ref)
            self.control.require_current_v1(r)
            for version in self.control.read_versions:self._version(version.key,version.revision)
            members=[];reasons=[]
            for key,revision,digest,refs in self.members:
                pending=[key.token,*refs];visited=set();supports=[]
                while pending:
                    token=pending.pop()
                    if token in visited:continue
                    visited.add(token)
                    if AtomKey.from_token(token).type_name=='memory.source':supports.append(token)
                    pending.extend(self.edges.get(token,()))
                if self.source_ref in visited:
                    reasons.append(key.type_name)
                    members.append(RetentionProtectionMemberV1(key.type_name,GraphVersion(key,revision),digest,tuple(sorted(set(supports)))))
            if self.control.protected:reasons.append('authority.current_correction_or_deletion')
            self.value=RetentionProtectionSnapshotV1(r.namespace,self.source_ref,self.census.hexdigest(),self.count,
                self.read_versions,r.graph_stamp[1].revision,tuple(self.control.query_epochs),tuple(members),tuple(self.control.originals),
                self.control.coverage_digest,tuple(sorted(set(reasons))))
            self.complete=True;r.operation.refresh_retained_state_v3(self);return True
        raise AuthorityUnavailable('unregistered retention protection continuation')
    def release_v1(self):
        if self.column is not None:self.column.release_v1()
        if self.inspection is not None:self.inspection.release_v3()
        if self.control_task is not None:self.control_task.release_v1()
        self.column=self.inspection=self.control=self.control_task=self.value=self.row=None
        self.versions.clear();self.members.clear();self.roots.clear();self.edges.clear();self.queue.clear();self.seen.clear();self.source_nodes.clear()
        self.reader.operation.unregister_retained_state_v3(self)


def _current_control_protection_v1(reader,source_ref):
    from .retention_control_protection_v1 import require_current_retention_control_protection_v1
    return require_current_retention_control_protection_v1(reader,source_ref=source_ref)


def prepare_current_retention_protection_v1(reader,*,source_ref):
    _require_selected_source_v1(reader,source_ref)
    task=_PROTECTION.get(reader)
    if task is None:
        task=CurrentRetentionProtectionTaskV1(_KEY,reader,source_ref);_PROTECTION[reader]=task
    if task.source_ref!=source_ref:raise AuthorityUnavailable('retention protection cannot switch actual target')
    task.require_current_v1(reader)
    if not task.complete:_missing_metadata(('protection',source_ref))
    return task


_SOURCE_STATES = WeakKeyDictionary()
_SOURCE_WRITES = WeakKeyDictionary()


class _RetentionSourceStateV1:
    def __init__(self,reader):
        self.reader=reader;self.identity=_binding_v1(reader);self.owner_binding=reader.owner_binding
        self.plan=self.permission=None
        self.keys,self.roots,self.producers=set(),set(),set()
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 4096+_heap((self.keys,self.roots,self.producers,self.plan))


def register_current_retention_source_v1(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    from .domain_production_registry_v1 import installed_operation_v1
    require_current_beta1_source_work_v3(reader)
    if (OPERATIONS.get(reader.operation_kind) is not type(reader.request)
            or installed_operation_v1(reader.operation_kind).request_type is not type(reader.request)
            or reader in _SOURCE_STATES):
        raise AuthorityUnavailable('retention Source profile requires its actual once-issued typed operation')
    state=_RetentionSourceStateV1(reader);_SOURCE_STATES[reader]=state
    reader.operation.register_retained_state_v3(state)


def require_current_retention_source_v1(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(reader)
    state=_SOURCE_STATES.get(reader)
    if (state is None or state.identity!=_binding_v1(reader)
            or state.permission is not None and state.owner_binding is not reader.owner_binding):
        raise AuthorityUnavailable('retention Source changed actual Work/Owner/selection/request')
    return state


def pin_current_retention_owner_v1(reader):
    state=require_current_retention_source_v1(reader)
    reader.general_owner_entry.require_for_v3(reader)
    state.owner_binding=reader.owner_binding


def retention_required_domains_v1():
    return frozenset({'d01','d05','d06','d08','d10','d11'})


def retention_source_groups_v1(reader,roots):
    state=require_current_retention_source_v1(reader)
    if state.plan is None or set(roots)!=state.roots:
        raise AuthorityUnavailable('retention Source groups differ from the complete actual metadata plan')
    return (('consolidation',(reader.audience_ref,),tuple(sorted(roots))),) if roots else ()


def require_current_retention_sources_v1(reader,roots):
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state=require_current_retention_source_v1(reader)
    state.permission=qualify_current_beta1_source_groups_v3(reader,roots)
    return state.permission


def require_current_retention_body_v1(reader,table,key):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    state=require_current_retention_source_v1(reader)
    if require_beta1_source_control_point_v3(reader,(table,('revision','value','valid'),('token','bot','persona'),tuple(key))):return
    if state.permission is None:
        raise AuthorityUnavailable('retention Body requires its actual complete Source ALL')
    state.permission.require_for_v3(reader)
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if atom not in state.keys and atom.token not in state.permission.source_refs:
            raise AuthorityUnavailable('retention Body is outside its exact current metadata plan')
        if table=='graph_history':
            expected=reader.heads.get(atom.token)
            if expected is None or key[1]!=expected[0]:
                raise AuthorityUnavailable('retention historical Body is outside its selected exact version')
    elif table=='graph_domain_production_originals_v1':
        if key[-1] not in state.producers:
            raise AuthorityUnavailable('retention producer original is not selected by actual Graph history')
    elif table=='runtime_budget_grants':
        if key[0]!=reader.parent_budget_lease_ref:
            raise AuthorityUnavailable('retention cannot borrow another actual resource grant')
    else:
        raise AuthorityUnavailable('retention has no Body authority for this table')


def require_current_retention_point_v1(reader,request):
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    if require_beta1_source_control_point_v3(reader,request):return
    table,columns,key_columns,key=request
    shapes={
        ('graph_atoms',('revision','value','valid'),('token','bot','persona')),
        ('graph_history',('event_bot','event_persona','event_session','event_id','value','valid'),('token','revision')),
        ('graph_domain_production_originals_v1',('domain','operation_kind','request_digest','original_digest','original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest'),('bot','persona','operation_id')),
    }
    if (table,columns,key_columns) not in shapes:
        raise AuthorityUnavailable('retention point is not a registered finite Body shape')
    if table in {'graph_atoms','graph_history'}:
        if NamespaceId.from_key(AtomKey.from_token(key[0]))!=reader.namespace:
            raise AuthorityUnavailable('retention point crossed namespace')
    elif tuple(key[:2])!=reader.namespace.as_tuple:
        raise AuthorityUnavailable('retention producer point crossed namespace')
    require_current_retention_body_v1(reader,table,key)


def register_current_retention_write_v1(inputs,scope,current_owner):
    reader=inputs.owner;state=require_current_retention_source_v1(reader)
    if not reader.inputs_sealed:return
    from .current_method_learning_read_v3 import _method_active
    if (not reader.read_finished or not reader.business_started or scope.operation!='write'
            or scope is reader.fence.scope or current_owner!=reader.owner_binding
            or inputs.plan!=state.plan or _method_active(reader.db) is not reader or state.permission is None):
        raise AuthorityUnavailable('retention WRITE requires the actual sealed same-Work Source/Owner inputs')
    _SOURCE_WRITES[reader]=(inputs,scope,current_owner,state.identity,state.permission)


def require_current_retention_write_v1(reader):
    state=require_current_retention_source_v1(reader);saved=_SOURCE_WRITES.get(reader)
    if (saved is None or saved[0].owner is not reader or saved[2]!=reader.owner_binding
            or saved[3:]!=(state.identity,state.permission) or not reader.business_started):
        raise AuthorityUnavailable('retention lost its actual same-Work WRITE qualification')
    return saved



def validate_memory_retention_provenance_v1(domain,operation_kind,provenance):
    if domain!='d06' or operation_kind not in OPERATIONS:
        raise ValueError('retention provenance has another exact installed producer')
    if type(provenance) is not dict or type(provenance.get('duplicate')) is not bool:
        raise ValueError('retention provenance requires its explicit closed disposition')
    duplicate=provenance['duplicate']
    from ..runtime_contracts import CommitReceipt
    mappings={
        'register_memory_retention_policy_v1': {'policy':MemoryRetentionPolicyV1,'duplicate':bool},
        'initialize_memory_retention_v1': ({'state':DetailRetentionV1,'duplicate':bool} if duplicate else
            {'state':DetailRetentionV1,'policy':MemoryRetentionPolicyV1,'c02_cause':_c02_cause_type_v1(),'duplicate':bool}),
        'apply_recollection_retention_v1': ({'contribution':MemoryRetentionContributionV1,'duplicate':bool,
            'original_receipt':CommitReceipt} if duplicate else
            {'state':DetailRetentionV1,'contribution':MemoryRetentionContributionV1,'c04_cause':RetentionAdoptionCauseV1,
             'frozen_read':MemoryRetentionReadV1,'duplicate':bool}),
        'reconcile_memory_retention_tier_v1': {'state':DetailRetentionV1,'protection':RetentionProtectionSnapshotV1,'duplicate':bool},
    }
    expected=mappings[operation_kind]
    if operation_kind=='apply_recollection_retention_v1' and duplicate:
        expected['original_receipt']=CommitReceipt
    if set(provenance)!=set(expected):
        raise ValueError('retention provenance closed fields changed')
    values={name:decode_retention_value_v1(provenance[name],cls) for name,cls in expected.items()}
    refs=set()
    def collect(value):
        if type(value) is AtomKey:refs.add(value.token)
        elif type(value) is GraphVersion:refs.add(value.key.token)
        elif type(value) is ProductionOriginalRefV1:
            for version in value.read_versions:collect(version)
        elif type(value) in (tuple,list):
            for item in value:collect(item)
        elif is_dataclass(value):
            for field in fields(value):collect(getattr(value,field.name))
    for value in values.values():collect(value)
    for name in ('policy','state','contribution','frozen_read','protection','c02_cause'):
        value=values.get(name)
        if type(value) is MemoryRetentionPolicyV1:refs.add(value.policy_ref)
        elif type(value) is DetailRetentionV1 and value.last_contribution_ref is not None:refs.add(value.last_contribution_ref)
        elif type(value) is MemoryRetentionContributionV1:refs.add(value.source_target)
        elif type(value) is RetentionProtectionSnapshotV1:
            refs.add(value.source_ref)
            for member in value.members:refs.update(member.support_source_refs)
        elif type(value) is _c02_cause_type_v1():refs.add(value.source_ref)
    return tuple(sorted(refs))


def decode_memory_retention_c04_cause_v1(value):
    return decode_retention_value_v1(value,RetentionAdoptionCauseV1)


def apply_request_from_retention_cause_v1(value,original):
    if (type(value) is not RetentionAdoptionCauseV1 or type(original) is not ProductionOriginalRefV1
            or original.kind!='d11.life_'+C04_CAUSE_KIND
            or original.original_digest!=retention_payload_digest_v1(value)):
        raise ValueError('retention Apply locator must retain its actual signed causal payload')
    return ApplyRecollectionRetentionRequestV1(original,value.recollection_version,value.projection_version,
        ProductionOriginalRefV1(READ_TYPE,value.retention_read_version.key.token,value.retention_read_digest,
            (value.retention_read_version,)))


def retention_c04_metadata_plan_v1(reader,*,source_version,trace_version):
    from .foreground_command_source_v3 import require_foreground_command_owner_reader_v3
    state=require_foreground_command_owner_reader_v3(reader);_owner_v1(reader)
    if (type(source_version) is not GraphVersion or type(trace_version) is not GraphVersion
            or source_version.key.token not in state.current_roots
            or NamespaceId.from_key(source_version.key)!=reader.namespace
            or NamespaceId.from_key(trace_version.key)!=reader.namespace
            or source_version.key.type_name!='memory.source'
            or trace_version.key.type_name not in {'memory.subjective_trace.v1','memory.subjective_trace.v2'}):
        raise AuthorityUnavailable('C04 retention metadata is outside its actual current Source/Trace selection')
    key=detail_retention_key_v1(reader.namespace,source_version,trace_version)
    metadata=_graph_metadata_v1(reader,key)
    require_retention_cause_watermark_v1(reader,source_ref=source_version.key.token,through_commit_seq=None)
    read_key=retention_read_key_v1(reader.namespace,reader.activity_id,reader.operation_id,source_version.key.token)
    originals=() if not metadata['revision'] else (metadata['producer_operation_id'],)
    return (key,read_key),originals



def _verify_seed_identity_v1(db,read,state):
    _,source=_source_v1(read,db,state.source_version)
    trace=_head_v1(read,db,state.trace_version)
    (validate_subjective_trace_v2 if trace.key.type_name.endswith('.v2') else validate_subjective_trace)(trace.value)
    expected=seed_retention_details_v1(state.namespace,state.source_version,state.trace_version,source.text,
        tuple((quote,weight) for quote,weight in trace.value['detail_weights']),state.policy_definition,state.encoding_time_utc)
    immutable=('detail_id','quote_sha256','quote_byte_count','source_span','span_status','encoding_weight','stability_seconds')
    if (len(expected)!=len(state.details) or any(tuple(getattr(a,f) for f in immutable)!=
            tuple(getattr(b,f) for f in immutable) for a,b in zip(expected,state.details,strict=True))):
        raise ValueError('retention state changed actual C02 detail identity/span/encoding stability')



def retention_apply_operation_id_v1(cause):
    if type(cause) is not RetentionAdoptionCauseV1:
        raise TypeError('typed actual-cause locator required for the deterministic maintenance identity')
    return 'retention-apply:' + canonical_digest((cause.namespace,cause.activity_id,
        cause.source_version.key.token,'internal_recollection'))[:48]
