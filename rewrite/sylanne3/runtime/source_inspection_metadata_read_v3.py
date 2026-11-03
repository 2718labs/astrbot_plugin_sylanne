"""Actual D06 inspection metadata EOF, without opening Source/claim segments."""
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary
from sys import getsizeof

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId
from ..runtime_storage_v3 import runtime_storage_v3, _runtime_bounded_fixed_row_v3, begin_runtime_cell_read_v3
from ..domains.d06.inspection_metadata_v1 import inspection_key_v1, validate_inspection_metadata_v1
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3, _COLUMNS
from .dispatch_current_inventory_v3 import _detach_value_v3
from .source_correction_read_v3 import _heap

_TASKS = WeakKeyDictionary()
_ORIGINALS = WeakKeyDictionary()
_INSPECTION_CORE_RESULTS = WeakKeyDictionary()


class LegacyInspectionMetadataUnavailableV3(AuthorityUnavailable):
    pass


def _owner_v3(owner, meter=None):
    from .c04_body_resource_inputs_v3 import (
        CurrentC04BodyResourceReadV3,require_actual_c04_body_resource_reader_v3)
    if type(owner)is CurrentC04BodyResourceReadV3:
        return require_actual_c04_body_resource_reader_v3(owner,meter=meter)
    from .current_character_labor_adoption_v1 import (
        CharacterLaborAdoptionReadV1,require_actual_character_labor_adoption_reader_v1)
    if type(owner)is CharacterLaborAdoptionReadV1:
        return require_actual_character_labor_adoption_reader_v1(owner,meter=meter)
    from .d13_natural_parent_closure_read_v3 import (
        D13NaturalParentClosureReadV3,require_actual_d13_natural_parent_closure_reader_v3)
    if type(owner)is D13NaturalParentClosureReadV3:
        return require_actual_d13_natural_parent_closure_reader_v3(owner,meter=meter)
    from .source_inspection_migration_v1 import SourceInspectionMigrationWorkV1
    if type(owner) is SourceInspectionMigrationWorkV1:
        owner.require_current_inspection_metadata_owner_v1()
        if (owner.work is not owner or runtime_storage_v3(owner.db) is not owner.handle
                or owner.operation.handle is not owner.handle
                or owner.operation.selection_digest != owner.handle.selection_digest):
            raise AuthorityUnavailable('inspection metadata lost its actual issued maintenance Work/selected operation')
        if meter is not None:
            owner.handle.require_current(meter)
        return owner
    from ..authority_service.current_authority_graph_read_v3 import (
        AuthorityGraphReadWorkV3, require_actual_authority_graph_attachment_owner_v3,
        _authority_attachment_owner_v3)
    if type(owner) is AuthorityGraphReadWorkV3:
        require_actual_authority_graph_attachment_owner_v3(owner, db=owner.db)
        if (_authority_attachment_owner_v3(owner.db) is not owner
                or runtime_storage_v3(owner.db) is not owner.handle
                or owner.operation.selection_digest != owner.handle.selection_digest
                or owner.scope.namespace != owner.namespace
                or owner.scope.permit is not owner.permit
                or owner.scope.operation_id != owner.permit.operation_id
                or type(owner.graph_stamp) is not tuple or len(owner.graph_stamp) != 3):
            raise AuthorityUnavailable('inspection metadata requires its exact current Authority attachment/selection/scope')
        return owner
    from ..graph_worker import GraphStorageWorkV3
    from .current_method_learning_read_v3 import (
        BorrowedMethodLearningReadV3, _READERS, _require_borrowed_issuance_v3)
    if type(owner) is BorrowedMethodLearningReadV3:
        work, scope = owner.work, owner.issued.scope
        if (owner not in _READERS or _require_borrowed_issuance_v3(owner.issued, owner.graph) != owner.evidence
                or type(work) is not GraphStorageWorkV3 or work.state is not owner
                or work.coordinator is not owner.graph or work.operation is not owner.operation
                or work.operation_id != owner.operation.operation_id or work.deadline_utc != owner.operation.deadline_utc
                or work.selection_digest != owner.operation.selection_digest or owner.operation.closed
                or owner.db is not owner.graph._GraphCoordinator__store._db
                or runtime_storage_v3(owner.db) is not owner.operation.handle
                or scope.operation != 'write' or scope.namespace != owner.namespace
                or scope.operation_id != owner.operation.operation_id or owner.fence.scope is not scope
                or (scope.graph_revision, scope.graph_epoch) !=
                    (owner.graph_stamp[0].graph_revision, owner.graph_stamp[1])):
            raise AuthorityUnavailable('inspection metadata requires its actual issued Borrowed WRITE Work/evidence')
        work._require_invocation(owner.graph)
        if meter is not None:
            owner.require_current(meter=meter)
        return owner
    from .domain_background_read_v3 import (BackgroundReadWorkV3, D07StageReadSelectorV3,
        require_actual_background_attachment_owner_v3)
    if type(owner) is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(owner, db=owner.db)
        work, scope = owner.work, owner.read_scope
        if (type(work) is not GraphStorageWorkV3 or work.coordinator is not owner.graph
                or work.operation_id != owner.operation.operation_id
                or work.selection_digest != owner.operation.selection_digest
                or scope is None or scope.namespace != owner.namespace):
            raise AuthorityUnavailable('inspection metadata requires its actual issued Background Work/scope')
        if (owner.kind == 'd07_stage' and type(owner.d07_selector) is D07StageReadSelectorV3
                and owner.d07_selector.stage == 'egress_seal'):
            from ..authority_service.owner_location_read_v3 import D07ActualModelSealReadBindingV3
            binding = owner.d07_model_seal_binding
            if (type(binding) is not D07ActualModelSealReadBindingV3 or scope is not binding.scope
                    or scope.permit is not binding.permit or owner.graph_stamp != binding.graph_stamp
                    or scope.operation != 'model_egress' or scope.permit.operation != 'model_egress'
                    or scope.operation_id != binding.permit.operation_id):
                raise AuthorityUnavailable('inspection metadata lost its exact D07 model-seal data binding')
        elif (scope.operation != 'read' or scope.operation_id != owner.operation.operation_id
                or scope.permit.operation != 'read' or scope.permit.operation_id != scope.operation_id
                or scope.permit.namespace != scope.authority_namespace):
            raise AuthorityUnavailable('inspection metadata requires its actual issued Background READ scope')
        work._require_invocation(owner.graph)
        if meter is not None:
            owner.require_data_current_v3(meter)
        return owner
    from .natural_outbound_receipt_adoption_read_v3 import NaturalOutboundReceiptAdoptionReadV3
    from .artifact_outbound_receipt_adoption_read_v3 import ArtifactOutboundReceiptAdoptionReadV3
    if type(owner) in (NaturalOutboundReceiptAdoptionReadV3, ArtifactOutboundReceiptAdoptionReadV3):
        owner.require_current_v3()
        work, scope = owner.work, owner.scope
        if (type(work) is not GraphStorageWorkV3 or work.state is not owner or work.coordinator is not owner.graph
                or work.operation is not owner.operation or work.operation_id != owner.operation.operation_id
                or work.selection_digest != owner.operation.selection_digest
                or owner.db is not owner.graph._GraphCoordinator__store._db
                or work.kind != ('artifact_outbound_receipt_adoption_read_v3' if type(owner) is ArtifactOutboundReceiptAdoptionReadV3
                    else 'natural_outbound_receipt_adoption_read_v3')
                or scope.operation != 'read' or scope.namespace != owner.namespace
                or scope.operation_id != owner.operation.operation_id or scope.permit.operation != 'read'
                or scope.permit.operation_id != scope.operation_id or scope.permit.namespace != scope.authority_namespace):
            raise AuthorityUnavailable('inspection metadata requires its actual named Natural recorded-fact READ scope')
        return owner
    work = owner.work
    if (type(work) is not GraphStorageWorkV3 or work.state is not owner
            or work.coordinator is not owner.graph or work.operation is not owner.operation
            or owner.operation.closed or owner.db is not owner.graph._GraphCoordinator__store._db
            or runtime_storage_v3(owner.db) is not owner.operation.handle
            or owner.fence.authority is not owner.authority
            or owner.fence.scope.operation != 'read' or owner.fence.scope.namespace != owner.namespace
            or owner.graph_stamp != (owner.fence.metadata, owner.fence.epoch)):
        raise AuthorityUnavailable('inspection metadata requires its actual originating selected READ Work')
    work._require_invocation(owner.graph)
    return owner


class _InspectionColumnV3(DispatchOriginalJSONReadV3):
    """Reuse the canonical EOF decoder with releasable per-row retention."""
    def __init__(self, owner, *, table, column, key_columns, key, cell_id=None):
        self._registered = False
        self._extra = 0
        super().__init__(owner, table=table, column=column, key_columns=key_columns, key=key, cell_id=cell_id)
        if self.cell is not None:
            from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
            if self.cell.header[0] not in {'canonical-json.ascii.v1', 'canonical-json.utf8.v1'}:
                raise AuthorityUnavailable('inspection metadata requires its registered canonical codec')
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == 'canonical-json.ascii.v1')

    def _runtime_retained_heap_bytes_v3(self):
        return self._payload_bytes + getsizeof(self.scalar) + getsizeof(self.fragment) + self._extra + 65536

    def _reserve(self, extra=0):
        self._extra = extra
        if not self._registered:
            self.operation.register_retained_state_v3(self)
            self._registered = True
        else:
            self.operation.refresh_retained_state_v3(self)

    def value_v3(self, owner):
        if (self.owner is not owner or self.operation.closed or not self.complete
                or _COLUMNS.get(self) != (owner, self.table, self.column, self.key,
                    self.sha256, self.byte_count, self._frozen_value)):
            raise AuthorityUnavailable('inspection column lost its actual complete same-Work EOF')
        self._reserve(self._detached_container_bytes * 2 + 4096)
        return _detach_value_v3(self._frozen_value)

    def release_v3(self):
        if self._registered:
            self.operation.unregister_retained_state_v3(self)
            self._registered = False
        _COLUMNS.pop(self, None)
        self.value = self._frozen_value = self.parser = self.cell = None
        self.nodes = {}; self.scalar = bytearray(); self.fragment = b''


@dataclass(frozen=True, eq=False)
class SourceInspectionOriginalV3:
    owner: object
    task: object
    key: AtomKey
    revision: int
    valid: bool
    cell_id: str
    header: tuple
    metadata: object
    semantic_digest: str

    @property
    def payload_sha256(self):
        return self.header[5]

    def require_v3(self, owner, meter):
        if owner is not self.owner or _ORIGINALS.get(self) != self._identity_v3():
            raise AuthorityUnavailable('inspection original lost its exact private metadata producer')
        self.task.require_current_v3(meter)
        return self

    def _identity_v3(self):
        return (self.owner, self.task, self.key, self.revision, self.valid, self.cell_id,
            self.header, self.metadata, self.semantic_digest)


class InspectionMetadataReadV3:
    def __init__(self, owner, target):
        _owner_v3(owner)
        if (type(target) is not AtomKey or NamespaceId.from_key(target) != owner.namespace
                or target.type_name not in {'memory.source', 'memory.interpretation'}):
            raise AuthorityUnavailable('inspection metadata requires an exact current namespace target')
        self.owner, self.target = owner, target
        self.phase = 'target'
        self.target_head = self.metadata_head = self.target_header = self.metadata_header = None
        self.metadata_key = self.value = self.column = self.event = self.receipt = None
        self.target_history = self.metadata_history = None
        self.complete = False
        self.result = None
        self.event_reads = self.event_writes = None
        self.provenance = None
        _TASKS[self] = (owner, owner.work, owner.operation, target)
        owner.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        return 8192 + _heap((self.target_head, self.metadata_head, self.target_header, self.metadata_header,
            self.value, self.event, self.receipt, self.target_history, self.metadata_history,
            self.event_reads, self.event_writes))

    def _actual_v3(self, meter=None):
        owner = _owner_v3(self.owner, meter)
        if _TASKS.get(self) != (owner, owner.work, owner.operation, self.target):
            raise AuthorityUnavailable('inspection metadata task changed its originating private Work')
        return owner

    def _fixed_v3(self, meter, table, columns, where, key):
        from .d13_natural_parent_closure_read_v3 import D13NaturalParentClosureReadV3
        if type(self.owner)is D13NaturalParentClosureReadV3:
            _owner_v3(self.owner,meter)
            return self.owner.fixed_v3(meter,table,columns,where,key)
        return _runtime_bounded_fixed_row_v3(self.owner.db, meter, table, columns, where, key)

    def _head_v3(self, meter, key):
        return self._fixed_v3(meter, 'graph_atoms', ('revision', 'valid', 'value_cell_id'),
            'bot=? AND persona=? AND token=?', (*self.owner.namespace.as_tuple, key.token))

    def require_current_v3(self, meter):
        self._actual_v3(meter)
        from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
        if type(self.owner) is AuthorityGraphReadWorkV3:
            self.owner.require_current(meter=meter)
        if (not self.complete or self._head_v3(meter, self.target) != self.target_head
                or self._head_v3(meter, self.metadata_key) != self.metadata_head):
            raise AuthorityUnavailable('inspection target/projection changed after metadata EOF')
        if self.provenance is not None:
            self.provenance.require_current_v1(meter)
        return self.result

    def _start_column_v3(self, table, column, key_columns, key, cell_id=None):
        self.column = _InspectionColumnV3(self.owner, table=table, column=column,
            key_columns=key_columns, key=key, cell_id=cell_id)

    def _finish_column_v3(self, meter):
        if not self.column.advance(meter):
            return False, None
        value = self.column.value_v3(self.owner)
        self.owner.operation.refresh_retained_state_v3(self)
        return True, value

    def _release_column_v3(self):
        self.column.release_v3()
        self.column = None

    def advance(self, meter):
        self._actual_v3(meter)
        ns = self.owner.namespace
        if self.complete:
            self.require_current_v3(meter)
            return True
        if self.phase == 'target':
            self.target_head = self._head_v3(meter, self.target)
            if self.target_head is None or self.target_head[0] < 1 or self.target_head[1] != 1 or self.target_head[2] is None:
                raise AuthorityUnavailable('current inspection target unavailable')
            self.metadata_key = inspection_key_v1(self.target, self.target_head[0])
            self.phase = 'projection'
        elif self.phase == 'projection':
            self.metadata_head = self._head_v3(meter, self.metadata_key)
            if self.metadata_head is None or self.metadata_head[:2] != (1, 1) or self.metadata_head[2] is None:
                raise LegacyInspectionMetadataUnavailableV3('legacy_metadata_unavailable')
            self.target_header = begin_runtime_cell_read_v3(self.owner.db, self.target_head[2]).header
            self.metadata_header = begin_runtime_cell_read_v3(self.owner.db, self.metadata_head[2]).header
            self._start_column_v3('graph_atoms', 'value', ('token', 'bot', 'persona'),
                (self.metadata_key.token, *ns.as_tuple), self.metadata_head[2])
            self.phase = 'metadata'
        elif self.phase == 'metadata':
            done, value = self._finish_column_v3(meter)
            if done:
                validate_inspection_metadata_v1(value, source=self.target.type_name == 'memory.source')
                if (value['target_ref'] != self.target.token or value['target_revision'] != self.target_head[0]
                        or (value['target_codec'], value['target_bytes'], value['target_sha256']) !=
                            (self.target_header[0], self.target_header[3], self.target_header[5])
                        or value['producer_operation_id'] != self.metadata_header[2]
                        or self.target_header[1] != self.target.token
                        or self.metadata_header[1] != self.metadata_key.token):
                    raise AuthorityUnavailable('inspection original differs from its actual target header commitment')
                self.value = value
                self.owner.operation.refresh_retained_state_v3(self)
                self._release_column_v3()
                if value['producer_operation_id'] != self.target_header[2]:
                    from .source_inspection_migration_v1 import begin_source_inspection_migration_provenance_v1
                    self.provenance = begin_source_inspection_migration_provenance_v1(self.owner, target=self.target,
                        metadata_key=self.metadata_key, target_head=self.target_head, target_header=self.target_header,
                        metadata_head=self.metadata_head, metadata_header=self.metadata_header, value=value, meter=meter)
                    if self.provenance is None:
                        raise AuthorityUnavailable('inspection target/metadata producer difference lacks its actual migration original')
                    self.phase = 'provenance'
                else:
                    self.phase = 'history'
        elif self.phase == 'history':
            columns = ('event_bot', 'event_persona', 'event_session', 'event_id', 'valid')
            self.target_history = self._fixed_v3(meter, 'graph_history', columns, 'token=? AND revision=?',
                (self.target.token, self.target_head[0]))
            self.metadata_history = self._fixed_v3(meter, 'graph_history', columns, 'token=? AND revision=1',
                (self.metadata_key.token,))
            if (self.target_history is None or self.target_history != self.metadata_history
                    or self.target_history[:2] != ns.as_tuple or self.target_history[3] != self.value['producer_operation_id']
                    or self.target_history[4] != 1):
                raise AuthorityUnavailable('inspection target and projection have no exact same-commit producing history')
            if self.target_history[2] == 'd13-outbound-observation':
                from .d13_outbound_observation_v1 import OutboundSourceInspectionProvenanceReadV1
                self.provenance = OutboundSourceInspectionProvenanceReadV1(self)
                self.phase = 'provenance'
            else:
                self.receipt = self._fixed_v3(meter, 'graph_bundle_operations', ('activity_id', 'effect_id', 'digest', 'commit_seq'),
                    'bot=? AND persona=? AND operation_id=?', (*ns.as_tuple, self.value['producer_operation_id']))
                if self.receipt is None or self.receipt[0] != self.target_history[2] or self.receipt[3] < 1:
                    raise AuthorityUnavailable('inspection producing W01 receipt metadata unavailable')
                self.event = (*ns.as_tuple, self.target_history[2], self.target_history[3])
                self._start_column_v3('graph_events', 'reads', ('bot', 'persona', 'session', 'event_id'), self.event)
                self.phase = 'reads'
        elif self.phase == 'provenance':
            if self.provenance.advance(meter):
                self.provenance.require_current_v1(meter)
                self._start_column_v3('graph_history', 'dependencies', ('token', 'revision'), (self.metadata_key.token, 1))
                self.phase = 'dependencies'
        elif self.phase in {'reads', 'writes', 'dependencies'}:
            done, value = self._finish_column_v3(meter)
            if done:
                if self.phase == 'reads':
                    self.event_reads = value
                    if ([self.target.token, self.target_head[0] - 1] not in value
                            or [self.metadata_key.token, 0] not in value):
                        raise AuthorityUnavailable('inspection producing original lacks target/projection complete CAS reads')
                    self.owner.operation.refresh_retained_state_v3(self)
                    self._release_column_v3()
                    self._start_column_v3('graph_events', 'revisions', ('bot', 'persona', 'session', 'event_id'), self.event)
                    self.phase = 'writes'
                elif self.phase == 'writes':
                    self.event_writes = value
                    if [self.target.token, self.target_head[0]] not in value or [self.metadata_key.token, 1] not in value:
                        raise AuthorityUnavailable('inspection producing receipt does not write both actual versions')
                    self.owner.operation.refresh_retained_state_v3(self)
                    self._release_column_v3()
                    self._start_column_v3('graph_history', 'dependencies', ('token', 'revision'), (self.metadata_key.token, 1))
                    self.phase = 'dependencies'
                else:
                    if value != [[self.target.token, self.target_head[0]]]:
                        raise AuthorityUnavailable('inspection metadata lacks its actual invalidation dependency')
                    del value
                    self._release_column_v3()
                    self.event_reads = self.event_writes = None
                    metadata = MappingProxyType({k: tuple(v) if type(v) is list else v for k, v in self.value['metadata'].items()})
                    self.result = SourceInspectionOriginalV3(self.owner, self, self.target, self.target_head[0], True,
                        self.target_head[2], self.target_header, metadata, self.value['target_semantic_digest'])
                    _ORIGINALS[self.result] = self.result._identity_v3()
                    self.complete = True
                    self.require_current_v3(meter)
        self.owner.operation.refresh_retained_state_v3(self)
        return self.complete

    def release_v3(self):
        if _TASKS.pop(self, None) is None:
            return
        if self.column is not None:
            self._release_column_v3()
        if self.provenance is not None:
            self.provenance.release_v1()
            self.provenance = None
        if self.result is not None:
            _ORIGINALS.pop(self.result, None)
        self.owner.operation.unregister_retained_state_v3(self)
        self.value = self.result = self.event_reads = self.event_writes = None


def release_inspection_metadata_owner_v3(owner):
    for task, identity in tuple(_TASKS.items()):
        if identity[0] is owner:
            task.release_v3()


def require_inspection_metadata_core_result_v3(parent, provenance, selector):
    if _TASKS.get(parent) != (parent.owner, parent.owner.work, parent.owner.operation, parent.target):
        raise AuthorityUnavailable('inspection Core result lost its actual originating metadata task')
    actual = _INSPECTION_CORE_RESULTS.get(provenance)
    if actual is None:
        return None
    if actual[:3] != (parent, parent.owner.work, selector):
        raise AuthorityUnavailable('inspection Core result changed its exact Work/receipt selector')
    return actual[3]


def release_inspection_metadata_core_result_v3(provenance):
    _INSPECTION_CORE_RESULTS.pop(provenance, None)


def resolve_pending_inspection_metadata_core_v3(work):
    """Resolve at most one private metadata request outside Graph/Core SQL."""
    from ..graph_worker import GraphStorageWorkV3
    from ..authority_service.current_authority_graph_read_v3 import (
        AuthorityGraphReadWorkV3, require_actual_authority_graph_attachment_owner_v3,
        require_authority_inspection_execution_v3)
    from ..authority_service.v2_contract import MutationReceiptV2
    from ..authority_service.observation_refinement_contract_v3 import (
        PlatformObservationRefinementReceiptV3, observation_receipt_digest_v3)
    from .d13_outbound_observation_v1 import OutboundSourceInspectionProvenanceReadV1
    from .source_inspection_migration_v1 import (
        SourceInspectionMigrationWorkV1, SourceInspectionMigrationProvenanceReadV1)
    if type(work) not in (GraphStorageWorkV3, AuthorityGraphReadWorkV3, SourceInspectionMigrationWorkV1):
        return False
    for parent, identity in tuple(_TASKS.items()):
        if identity[1] is not work:
            continue
        provenance, owner = parent.provenance, parent.owner
        if type(provenance) is SourceInspectionMigrationProvenanceReadV1:
            admission = provenance.pending_member_admission_v1(owner)
            if admission is None:
                continue
            if identity != (owner, work, owner.operation, parent.target) or owner.db.in_transaction:
                raise AuthorityUnavailable('inspection member admission lost its actual SQL-free metadata Work')
            from .source_inspection_member_admission_v1 import verify_source_inspection_member_admission_v1
            proof = verify_source_inspection_member_admission_v1(owner, provenance, admission)
            provenance.bind_authority_member_verification_v1(owner, proof)
            return True
        if type(provenance) is not OutboundSourceInspectionProvenanceReadV1:
            continue
        selector = provenance.pending_core_request_v1()
        if selector is None:
            continue
        if identity != (owner, work, owner.operation, parent.target) or owner.db.in_transaction:
            raise AuthorityUnavailable('inspection historical receipt must resolve in its actual SQL-free Work')
        if type(work) is AuthorityGraphReadWorkV3:
            require_actual_authority_graph_attachment_owner_v3(work, db=owner.db)
            execution = require_authority_inspection_execution_v3(work)
            if execution.core._db.in_transaction:
                raise AuthorityUnavailable('inspection historical receipt must precede Core SQL')
            actual = execution.read_historical_observation_receipt_v3(credential=work.credential, subject=work.subject,
                effect_id=selector[0], mutation_id=selector[1], expected_receipt_digest=selector[2])
        elif type(work) is SourceInspectionMigrationWorkV1:
            owner.require_external_inspection_metadata_owner_v1()
            from .source_inspection_member_admission_v1 import read_source_inspection_migration_historical_observation_v1
            actual = read_source_inspection_migration_historical_observation_v1(owner,
                effect_id=selector[0], mutation_id=selector[1], expected_receipt_digest=selector[2])
        else:
            _owner_v3(owner)
            work._require_invocation(work.coordinator)
            actual = owner.graph._GraphCoordinator__content_fence_v2.read_historical_observation_receipt_v3(
                namespace=owner.namespace, authority_namespace=owner.graph_stamp[0].requirements.authority_namespace,
                effect_id=selector[0], mutation_id=selector[1], expected_receipt_digest=selector[2])
        if (type(actual) not in (MutationReceiptV2, PlatformObservationRefinementReceiptV3)
                or observation_receipt_digest_v3(actual) != selector[2]
                or actual.pending.mutation_id != selector[1]):
            raise AuthorityUnavailable('inspection historical receipt RPC returned another original')
        _INSPECTION_CORE_RESULTS[provenance] = (parent, work, selector, actual)
        provenance.authenticated_observation = actual
        owner.operation.refresh_retained_state_v3(provenance)
        return True
    return False

def source_inspection_member_authority_route_v1(owner):
    """Return only this exact live inspection owner's SQL-free Authority route."""
    from ..authority_service.current_authority_graph_read_v3 import (
        AuthorityGraphReadWorkV3, require_actual_authority_graph_attachment_owner_v3,
        require_authority_inspection_member_service_v1)
    from .source_inspection_migration_v1 import SourceInspectionMigrationWorkV1
    if type(owner) is SourceInspectionMigrationWorkV1:
        owner.require_external_inspection_metadata_owner_v1()
        return owner.service
    if type(owner) is AuthorityGraphReadWorkV3:
        require_actual_authority_graph_attachment_owner_v3(owner, db=owner.db)
        owner.controller.require_installed_v3()
        if owner.db.in_transaction or owner.controller.fences.core._db.in_transaction:
            raise AuthorityUnavailable('inspection member verification requires its SQL-free Authority Work')
        return require_authority_inspection_member_service_v1(owner)
    _owner_v3(owner)
    if owner.db.in_transaction:
        raise AuthorityUnavailable('inspection member verification requires its SQL-free Host Work')
    return (owner.graph._GraphCoordinator__content_fence_v2, owner.namespace,
        owner.graph_stamp[0].requirements.authority_namespace)
