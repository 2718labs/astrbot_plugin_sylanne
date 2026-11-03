"""Narrow same-full-Work D13 metadata -> ALL Source rights -> page bodies.

The original Graph permit, operation, selection and stamp remain the authority.
This reader uses the existing finite D13 page algorithms; it does not expand the
ordinary FULL projection or create a replacement Authority/paid client.
"""
from dataclasses import dataclass, replace
from time import monotonic
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .d13_current_window import _D13PaidWindowMetadataV3, _D13PaidWindowBodyV3
from .d13_current_collection_v6 import (_CONTEXT_KEY, _CurrentCollectorContextV6,
    CurrentD13PageV6, _merge_current_d13_pages_v6)
from .first_ingress_v2 import trusted_upper_at_v4, scene_ref_for_conversation

_READERS = WeakKeyDictionary()
_ISSUER = object()


@dataclass(frozen=True, slots=True)
class _ContextAudienceSelectionV2:
    namespace: object
    audience: tuple


class _PageMetadataV2(_D13PaidWindowMetadataV3):
    def __init__(self, reader, scene_ref, maximum):
        super().__init__(reader, scene_ref, maximum)
        self.expires_at_utc = reader.deadline


class _PageBodyV2(_D13PaidWindowBodyV3):
    def advance_v3(self, meter):
        # The shared body driver accepts already selected input requests. Set its
        # page generator before its normal final-stage entry so empty later pages
        # retain the existing collector-context semantics.
        if (self.program is None and self.startup and not self.queue and self.request is None):
            from .d13_current_window import _current_d13_window_program_v6
            reader = self.reader
            self.program = _current_d13_window_program_v6(reader.db, reader.namespace,
                self.metadata.scene_ref, self.metadata.conversation_ref, self.metadata.max_slots,
                reader.initial_now, before_sequence=self.metadata.before_sequence,
                expected_activation_generation=reader.fence.scope.generation,
                expected_owner_authorization_head=reader.owner_guard_head,
                _collector_context=reader.collection_context, _page_observation=reader.page_observation)
        super().advance_v3(meter)


class GraphFullReadD13CollectionV2:
    def __init__(self, issuer, full, *, reading, guard, meter):
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3
        from .current_graph_source_material_v3 import require_prepared_current_source_material_v3
        from .d13_cache_use_admission_v2 import _bundle_use_enabled_v2
        if issuer is not _ISSUER or type(full) is not _OrdinaryFullReadV3 or full.work.state is not full:
            raise AuthorityUnavailable('D13 collection requires the actual originating full-read Work')
        material = full.source_material.proof
        require_prepared_current_source_material_v3(material, prefinal_inventory=full.prefinal,
            actual_entry=full.source_locator)
        bundle = full.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        if not _bundle_use_enabled_v2(bundle):
            raise AuthorityUnavailable('new D13 collection requires its actual explicitly enabled installed pair')
        self.full, self.work = full, full.work
        self.graph, self.db, self.namespace = full.graph, full.db, full.namespace
        self.operation, self.fence, self.graph_stamp = full.operation, full.fence, full.graph_stamp
        self.material, self.reading, self.owner_guard = material, reading, guard
        self.owner_guard_head = guard.authorization_head
        self.initial_now = self.now_utc = trusted_upper_at_v4(reading, monotonic())
        deadlines = [bundle.d13_cache_use_control_v2.valid_until, material.source_record.recorded_at + 72 * 3600]
        if full.operation.deadline_utc is not None:
            deadlines.append(full.operation.deadline_utc)
        self.deadline = min(deadlines)
        source_id = AtomKey.from_token(material.source_ref).owner.subject
        rows = self.db.execute('SELECT platform_ref,conversation_ref,visibility FROM graph_first_ingress_identity_v1 '
            'WHERE bot=? AND persona=? AND source_ref=? LIMIT 2', (*self.namespace.as_tuple, source_id)).fetchall()
        meter.charge_read(sum(sum(len(str(value).encode('utf-8')) for value in row) + 32 for row in rows))
        if len(rows) != 1 or rows[0][1] != material.inputs.conversation_ref or rows[0][2] != 'private':
            raise AuthorityUnavailable('D13 collector root differs from its actual private ingress conversation')
        self.scene_ref = scene_ref_for_conversation(self.namespace, rows[0][0], rows[0][1])
        self.conversation_ref = rows[0][1]
        # These fields select current context rights; they confer no capability.
        self.authority = _ContextAudienceSelectionV2(self.namespace, (self.conversation_ref,))
        self.max_slots = 256 if bundle.d13_wire_policy is None else bundle.d13_wire_policy.max_slots
        self.args, self.remaining = {'before_sequence': None}, self.max_slots
        self.metadata_pages, self.page_bodies, self.pages = [], [], []
        self.window_metadata = self.window_body = self.collection_context = None
        self.page_observation = None
        self.frozen_versions, self.sources, self.source_heads, self.access_atoms = {}, {}, {}, {}
        self.pending_sources, self.column = [], None
        self.source_inspection_tasks={}
        self.qualified, self.complete = False, False
        self.phase, self.page_index, self.reserved = 'window_metadata', 0, 0
        self.collection = self.candidate_selection = None
        self.candidates, self.pin_index = (), 0
        self._advance_head_memo_v2 = None
        _READERS[self] = (full, self.work, self.operation, self.fence.scope.permit,
            self.material, self.reading, self.owner_guard, self.graph_stamp)
        self.require_current_v3(meter=meter)

    def reserve_v3(self, extra=0):
        from .source_correction_read_v3 import _heap
        values = (self.metadata_pages, self.pages, self.frozen_versions, self.source_heads,
            self.pending_sources, tuple(source.metadata for source in self.sources.values()),
            tuple(atom.value for atom in self.access_atoms.values()))
        size = _heap(values) + extra + 65536
        if self.column is not None:
            size += _heap((self.column.fragment, self.column.body, self.column.value))
        for body in self.page_bodies:
            size += _heap(tuple(atom.value for atom in body.atoms.values()))
        if size > self.reserved:
            self.operation.retain(size - self.reserved)
            self.reserved = size

    def require_current_v3(self, *, meter=None):
        if (_READERS.get(self) != (self.full, self.work, self.operation, self.fence.scope.permit,
                self.material, self.reading, self.owner_guard, self.graph_stamp)
                or self.work.state is not self.full or self.full.work is not self.work
                or self.operation is not self.full.operation or self.operation.closed):
            raise AuthorityUnavailable('D13 collection lost its actual original full-read owner')
        self.work._require_invocation(self.graph)
        self.now_utc = trusted_upper_at_v4(self.reading, monotonic())
        if self.now_utc >= self.deadline:
            raise AuthorityUnavailable('D13 original context Source/use lifetime ended')
        self.full.prefinal.require_current(meter=meter)
        with runtime_storage_quantum_v3(self.db) as current:
            if meter is not None and current is not meter:
                raise AuthorityUnavailable('D13 collection changed its actual Graph quantum')
            self._require_all_current_source_heads_v2(current)
        return self

    def _require_all_current_source_heads_v2(self, meter):
        self._advance_head_memo_v2 = require_current_metadata_heads_v3(self.db, self.namespace,
            self.source_heads, meter, self._advance_head_memo_v2)

    def window_atom_v3(self, key):
        return self.window_body.atom_v3(key)

    def window_family_v3(self, kind):
        return self.window_body.family_v3(kind)

    def window_original_point_v3(self, table, columns, key_columns, key):
        return self.window_body.original_point_v3(table, columns, key_columns, key)

    def advance(self, *, meter):
        # Memo lifetime is exactly this invocation inside its original READ tx.
        # Public replay and the next quantum always perform fresh SQL checks.
        if not self.db.in_transaction or self._advance_head_memo_v2 is not None:
            raise AuthorityUnavailable('D13 advance requires its one actual Graph READ transaction')
        self._advance_head_memo_v2 = (self.db.total_changes, {})
        try:
            return self._advance_in_read_transaction_v2(meter=meter)
        finally:
            self._advance_head_memo_v2 = None

    def _advance_in_read_transaction_v2(self, *, meter):
        from .d13_paid_original_read_v3 import D13PaidOriginalReadWorkV3
        from .d13_cache_use_admission_v2 import (begin_graph_d13_cache_use_selection_v2,
            prepare_graph_d13_cache_use_v2)
        self.require_current_v3(meter=meter)
        if self.complete:
            return self
        if self.phase == 'window_metadata':
            if self.window_metadata is None:
                self.window_metadata = _PageMetadataV2(self, self.scene_ref, min(64, self.remaining))
            self.window_metadata.advance_v3(meter)
            if self.window_metadata.complete:
                page = self.window_metadata
                self.metadata_pages.append(page)
                self.deadline = min(self.deadline, page.expires_at_utc)
                for ref, revision in page.source_versions:
                    if ref in self.frozen_versions and self.frozen_versions[ref] != revision:
                        raise AuthorityUnavailable('D13 page metadata changed an actual Source version')
                    self.frozen_versions[ref] = revision
                self.pending_sources.extend(page.refroots)
                self.remaining -= page.end - page.start + 1
                self.args['before_sequence'] = page.start
                self.window_metadata = None
                if not self.remaining or page.start == 0:
                    self.pending_sources = sorted(set(self.pending_sources))
                    self.phase = 'sources'
            self.reserve_v3()
            return self
        if self.phase == 'sources':
            D13PaidOriginalReadWorkV3._sources(self, meter)
            if self.phase == 'originals':
                self.phase = 'window_body'
            self.reserve_v3()
            return self
        if self.phase == 'access':
            D13PaidOriginalReadWorkV3._access(self, meter)
            self.reserve_v3()
            return self
        if self.phase == 'window_body':
            if self.window_body is None:
                metadata = self.metadata_pages[self.page_index]
                self.page_observation = {'expired': [], 'unclosed': []}
                self.window_body = _PageBodyV2(self, metadata)
                self.page_bodies.append(self.window_body)
            self.window_body.advance_v3(meter)
            if not self.window_body.complete:
                return self
            body = self.window_body
            window, metadata = body.window, body.metadata
            if self.collection_context is None:
                self.collection_context = _CurrentCollectorContextV6(_CONTEXT_KEY, self.db, window)
            else:
                self.collection_context.require_current(self.db, self.namespace, self.scene_ref, self.conversation_ref)
            status = ('available' if window.turns else 'empty_expired'
                if len(self.page_observation['expired']) == metadata.end - metadata.start + 1 else 'empty_with_gaps')
            self.pages.append(CurrentD13PageV6(metadata.before_sequence, metadata.max_slots,
                metadata.start, metadata.end, window, status, tuple(self.page_observation['expired']),
                tuple(self.page_observation['unclosed'])))
            self.page_index += 1
            self.window_body = None
            if self.page_index == len(self.metadata_pages):
                self.collection = _merge_current_d13_pages_v6(self.pages[0].window, self.pages,
                    self.max_slots, canonical_digest(self.collection_context.snapshot))
                self.phase = 'candidate_metadata'
            self.reserve_v3()
            return self
        if self.phase == 'candidate_metadata':
            if self.candidate_selection is None:
                self.candidate_selection = begin_graph_d13_cache_use_selection_v2(self.work,
                    collection=self.collection, question_ref=self.material.source_ref, meter=meter)
            self.candidate_selection.advance(meter=meter)
            if self.candidate_selection.complete:
                self.candidates = self.candidate_selection.require_candidates_v2(self.work, meter=meter)
                self.phase = 'pins'
            return self
        if self.phase == 'pins':
            if self.pin_index == len(self.candidates):
                self.complete = True
                return self
            metadata, ref = self.candidates[self.pin_index]
            prepare_graph_d13_cache_use_v2(self.work, metadata=metadata, metadata_ref=ref, meter=meter)
            self.pin_index += 1
            return self
        raise AuthorityUnavailable('unregistered actual full-read D13 collection phase')

    def release_payload_v3(self):
        from .d13_paid_original_read_v3 import release_d13_paid_source_inspection_v3
        release_d13_paid_source_inspection_v3(self)
        _READERS.pop(self, None)
        for body in self.page_bodies:
            if body.program is not None:
                body.program.close()
        if self.candidate_selection is not None:
            self.candidate_selection.release_payload_v3()
        self.metadata_pages.clear()
        self.page_bodies.clear()
        self.pages.clear()
        self.sources.clear()
        self.source_heads.clear()
        self.access_atoms.clear()
        self.frozen_versions.clear()
        self.pending_sources.clear()
        self.column = self.window_metadata = self.window_body = self.collection = self.collection_context = None
        self.candidates = ()


def require_graph_d13_window_reader_v2(reader):
    if type(reader) is not GraphFullReadD13CollectionV2:
        return False
    reader.require_current_v3()
    if not reader.qualified or reader.phase != 'window_body' or reader.window_body is None:
        raise AuthorityUnavailable('D13 Graph window Body lacks its actual ALL Source metadata qualification')
    return True


def graph_full_read_needs_d13_collection_v2(full):
    from .d13_cache_use_admission_v2 import _graph_use_enabled_v2
    return (full.source_locator is not None and full.contract.name in
        {'natural_model_full_read_v3', 'natural_route_full_read_v3', 'natural_admin_prepare_full_v3'}
        and _graph_use_enabled_v2(full.graph))


def advance_graph_full_read_d13_collection_v2(full):
    from .d13_cache_use_admission_v2 import (D13CacheUseAdmissionRequiredV2,
        resolve_graph_d13_cache_use_v2)
    port = full.graph._GraphCoordinator__content_fence_v2
    if full.d13_observation is None:
        if full.db.in_transaction:
            raise AuthorityUnavailable('D13 actual clock/Owner observation cannot inherit Graph SQL')
        reading = port.read_ingress_clock(full.graph._GraphCoordinator__scene_clock_policy)
        result = port.get_current_owner_guard_for_fence(namespace=full.namespace,
            authority_namespace=full.fence.scope.authority_namespace, permit=full.fence.scope.permit)
        if (type(result) is not tuple or len(result) != 2 or type(result[0]) is not OwnerAuthorizationGuardV1
                or result[1] != full.fence.scope.permit or result[0].namespace != full.namespace
                or result[0].pending_revoke_operation_id is not None
                or result[0].authorization_revision != 1 or result[0].minimum_revocation_revision != 0
                or result[0].minimum_revocation_epoch != 0):
            raise AuthorityUnavailable('D13 actual originating permit Owner guard is unavailable')
        full.d13_observation = (reading, result[0])
        return False
    resolve_graph_d13_cache_use_v2(full.work)
    with full.store._lock, runtime_storage_quantum_v3(full.db) as meter:
        full.db.execute('BEGIN')
        try:
            if full.d13_collection is None:
                full.d13_collection = GraphFullReadD13CollectionV2(_ISSUER, full,
                    reading=full.d13_observation[0], guard=full.d13_observation[1], meter=meter)
            try:
                full.d13_collection.advance(meter=meter)
            except D13CacheUseAdmissionRequiredV2 as needed:
                if needed.work is not full.work:
                    raise AuthorityUnavailable('D13 pin continuation crossed its actual full-read Work')
        finally:
            full.db.rollback()
    resolve_graph_d13_cache_use_v2(full.work)
    return full.d13_collection.complete


def read_bound_graph_d13_collection_v2(db, namespace, scene_ref, conversation_ref, now_utc, *,
        expected_activation_generation, expected_owner_authorization_head, max_slots, before_sequence):
    from .current_graph_full_read_v3 import _BOUND, PreparedCurrentGraphFullReadV3
    bound = _BOUND.get()
    if bound is None or type(bound) is not tuple or type(bound[0]) is not PreparedCurrentGraphFullReadV3:
        return False, None
    proof, graph, actual_db, work, operation = bound
    if actual_db is not db:
        raise AuthorityUnavailable('D13 Graph collection crossed its actual bound database')
    if not graph_full_read_needs_d13_collection_v2(work.state):
        return False, None
    proof.require_current(graph, db, namespace, required_families=frozenset())
    collector = work.state.d13_collection
    if collector is None or not collector.complete:
        raise AuthorityUnavailable('D13 bound Graph collection has not completed its original ALL Source/pin EOF')
    collector.require_current_v3()
    if (collector.operation is not operation or namespace != collector.namespace
            or scene_ref != collector.scene_ref or conversation_ref != collector.conversation_ref
            or expected_activation_generation != collector.fence.scope.generation
            or expected_owner_authorization_head not in (None, collector.owner_guard_head)
            or max_slots != collector.max_slots or before_sequence is not None or now_utc >= collector.deadline):
        raise AuthorityUnavailable('D13 Graph collection changed its exact current frame selector/lifetime')
    collection = collector.collection
    window = replace(collection.window, trusted_utc=now_utc)
    return True, replace(collection, window=window,
        pages=tuple(replace(page, window=replace(page.window, trusted_utc=now_utc)) for page in collection.pages))


def read_bound_graph_d13_candidate_rows_v2(db, collection):
    from .current_graph_full_read_v3 import _BOUND, PreparedCurrentGraphFullReadV3
    from ..runtime_contracts import canonical_serialize
    bound = _BOUND.get()
    if bound is None or type(bound) is not tuple or type(bound[0]) is not PreparedCurrentGraphFullReadV3:
        return False, None
    proof, graph, actual_db, work, operation = bound
    if actual_db is not db or not graph_full_read_needs_d13_collection_v2(work.state):
        return False, None
    proof.require_current(graph, db, collection.window.namespace, required_families=frozenset())
    collector = work.state.d13_collection
    if collector is None or not collector.complete or collector.collection.snapshot_commitment != collection.snapshot_commitment:
        raise AuthorityUnavailable('D13 candidate rows differ from their actual prepared current collection')
    collector.require_current_v3()
    return True, tuple((ref.ref, ref.version, canonical_serialize(metadata)) for metadata, ref in collector.candidates)


def read_bound_graph_d13_metadata_v2(db, block_ref):
    from .current_graph_full_read_v3 import _BOUND, PreparedCurrentGraphFullReadV3
    from ..runtime_contracts import canonical_serialize
    bound = _BOUND.get()
    if bound is None or type(bound) is not tuple or type(bound[0]) is not PreparedCurrentGraphFullReadV3:
        return False, None
    proof, graph, actual_db, work, operation = bound
    if actual_db is not db or not graph_full_read_needs_d13_collection_v2(work.state):
        return False, None
    collector = work.state.d13_collection
    proof.require_current(graph, db, collector.namespace, required_families=frozenset())
    collector.require_current_v3()
    matches = [(metadata, ref) for metadata, ref in collector.candidates if metadata.block_ref == block_ref]
    if not matches:
        return True, None
    if len(matches) != 1:
        raise AuthorityUnavailable('D13 current candidate metadata identity is ambiguous')
    metadata, ref = matches[0]
    with runtime_storage_quantum_v3(db) as meter:
        head = meter.read_fixed_row(db, 'graph_atoms', ('revision', 'valid'),
            'token=? AND bot=? AND persona=?', (ref.ref, *collector.namespace.as_tuple))
        if head != (ref.version, 1):
            raise AuthorityUnavailable('D13 actual paid candidate metadata head changed after pin admission')
    return True, (canonical_serialize(metadata), 1)


def require_current_metadata_heads_v3(db, namespace, expected_heads, meter, memo=None):
    """Recheck every Source/access and absent correction in the same READ tx.

    Each batch is at most 64 already selected keys. SQLite observes the actual
    transfer lengths before any row is transferred; no Source Body is selected.
    The complete expected mapping, including absent heads, is compared exactly.
    """
    if not db.in_transaction:
        raise AuthorityUnavailable('D13 complete current-head check requires its actual Graph READ transaction')
    items = tuple(expected_heads.items())
    if memo is not None:
        if memo[0] != db.total_changes:
            memo = (db.total_changes, {})
        meter.require_available(len(items) * 128 + 256)
        unchecked = tuple((token, head) for token, head in items if token not in memo[1])
    else:
        unchecked = items
    position = 0
    while position < len(unchecked):
        batch, expected_bytes = [], 0
        while position < len(unchecked) and len(batch) < 64:
            token, head = unchecked[position]
            row_bound = len(token.encode('utf-8')) + 128
            if batch and expected_bytes + row_bound > 16384:
                break
            batch.append((token, head))
            expected_bytes += row_bound
            position += 1
        keys = tuple(token for token, _ in batch)
        where = 'bot=? AND persona=? AND token IN (' + ','.join('?' for _ in keys) + ')'
        parameters = (*namespace.as_tuple, *keys)
        count, actual_bytes = db.execute(
            'SELECT count(*),coalesce(sum(length(CAST(token AS BLOB))+'
            'length(CAST(revision AS BLOB))+length(CAST(valid AS BLOB))+'
            'length(CAST(value_cell_id AS BLOB))),0) FROM graph_atoms WHERE ' + where,
            parameters).fetchone()
        meter.charge_read(16)
        meter.require_available(actual_bytes * 8 + len(batch) * 64 + 256)
        rows = db.execute('SELECT token,revision,valid,value_cell_id FROM graph_atoms WHERE '
            + where + ' ORDER BY token LIMIT 64', parameters).fetchall()
        meter.charge_read(actual_bytes)
        actual = {row[0]: tuple(row[1:]) for row in rows}
        expected = {token: head for token, head in batch if head is not None}
        if len(rows) != count or count > len(batch) or actual != expected:
            raise AuthorityUnavailable('D13 current Source/access/correction changed before page Body')
        if memo is not None:
            memo[1].update(batch)
    if memo is not None and any(memo[1][token] != head for token, head in items):
        raise AuthorityUnavailable('D13 complete expected current heads changed within the actual READ transaction')
    return memo
