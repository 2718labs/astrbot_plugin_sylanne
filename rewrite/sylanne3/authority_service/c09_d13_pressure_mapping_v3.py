"""Historical Counter pressure mapping joins; no current selection or execution grant."""
from copy import copy, deepcopy
from dataclasses import fields
import base64
import sys

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId
from ..graph_types import AtomKey
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2, _CanonicalJSONValueBuilderV3
from ..runtime.c09_paged_sql_v2 import (current_c09_sql_meter_v2, legacy_cell_read_transaction_v2,
    read_legacy_sql_cell_fragment_v2, read_c09_table_shape_v2)


class _PressureJSONV3(C09CanonicalJSONStreamV2, _CanonicalJSONValueBuilderV3):
    def __init__(self, owner, *, ensure_ascii=True):
        super().__init__(ensure_ascii=ensure_ascii)
        self.owner = owner
        self._initialize_json_value_v3(incremental_retention=False,
            frozen_object_type=None, frozen_array_type=None)

    def _reserve(self, extra=0):
        self.owner._require_arena(extra + 16384)

    def emit_v3(self, event):
        _CanonicalJSONValueBuilderV3._emit(self, event)

    def copy_for_v3(self, owner):
        base = C09CanonicalJSONStreamV2(ensure_ascii=self.ensure_ascii,
            max_depth=self.max_depth, max_key_bytes=self.max_key_bytes)
        for name in C09CanonicalJSONStreamV2.__slots__:
            setattr(base, name, getattr(self, name))
        cloned = base.copy()
        result = copy(self)
        for name in C09CanonicalJSONStreamV2.__slots__:
            setattr(result, name, getattr(cloned, name))
        result.owner = owner
        result.nodes, result.value, result.scalar = deepcopy((self.nodes, self.value, self.scalar))
        result.source_members = []
        return result

    def heap_v3(self):
        from .c09_d13_accounting_disposition_v3 import _heap
        return _heap((self.nodes, self.value, self.scalar, self.fragment,
            self._stack, self._string, self._number, self._literal, self._active_scalar))


class _PressureColumnV3:
    """One genuine frozen metadata column, or an opaque-text Source record."""
    def __init__(self, owner, *, capture=None, table=None, column=None,
                 key=None, key_columns=None, reference=None, source=False):
        from .c09_authority_storage_rebase_v2 import _d13_frozen_graph_pair_v3
        from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3, C09MemoryAccessJSONStreamV3
        self.owner, self.capture = owner, capture
        self.table, self.column, self.key, self.key_columns = table, column, key, key_columns
        self.reference = reference
        self.offset = self.ordinal = 0
        self.complete = False
        self.scope = self.header = None
        self.root = None
        self.eof = None
        self.source = source
        self.pair = owner.builder.pair if capture is not None else _d13_frozen_graph_pair_v3(owner.builder)
        if capture is not None:
            capture.require_complete(owner.builder, capture.shape, capture.key)
            self.total = capture.size
            self.parser = _PressureJSONV3(owner)
            return
        if table == 'graph_history':
            if (reference is None or key != (reference.ref, reference.version)
                    or key_columns != ('token', 'revision') or column != 'value'
                    or NamespaceId.from_key(AtomKey.from_token(reference.ref)) != owner.namespace):
                raise AuthorityUnavailable('pressure historical cell crossed its registered member/version')
            meta = current_c09_sql_meter_v2().read_fixed_row(self.pair.source, table,
                ('valid', 'event_bot', 'event_persona', 'event_session', 'event_id'),
                'token=? AND revision=?', key)
            if meta is None or meta[0] != 1 or meta[1:3] != owner.namespace.as_tuple:
                raise AuthorityUnavailable('pressure member lost its actual valid historical producer')
        elif (table, column, key_columns) != (
                'runtime_budget_grants', 'grant_json', ('lease_id', 'version')):
            raise AuthorityUnavailable('unregistered pressure metadata column')
        self.where = ' AND '.join(name + '=?' for name in key_columns)
        meter = current_c09_sql_meter_v2()
        shape = read_c09_table_shape_v2(self.pair.source, table, meter=meter)
        if table == 'graph_history' and 'value_cell_id' in shape.columns:
            from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
            ddl = meter.read_fixed_row(self.pair.source, 'sqlite_master', ('sql',),
                'type=? AND name=?', ('table', table))
            if ddl != (GRAPH_REF_DDLS_V3[table],):
                raise AuthorityUnavailable('pressure history physical schema differs')
            row = meter.read_fixed_row(self.pair.source, table, ('value_cell_id',), self.where, key)
            self.scope = owner.builder.session.begin_source_physical_read_v3(self.pair, meter=meter)
            self.header = self.scope.read_cell_header_v3(row[0], meter=meter)
            if self.header[1] != 'canonical-json.ascii.v1' or self.header[2] != reference.ref:
                raise AuthorityUnavailable('pressure history Source codec/owner differs')
            self.total = self.header[4]
            self.root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', row[0]))
        else:
            with legacy_cell_read_transaction_v2(self.pair.source):
                _, self.total, kind = read_legacy_sql_cell_fragment_v2(self.pair.source,
                    table=table, column=column, where=self.where, parameters=key,
                    start=0, length=0, meter=meter)
            if kind != 'text':
                raise AuthorityUnavailable('pressure history/grant requires actual canonical text')
        if self.total < 1:
            raise AuthorityUnavailable('pressure history/grant original is empty')
        if source:
            self.parser = C09MemorySourceJSONStreamV3(ensure_ascii=True,
                source_arena=owner.builder.session._source_parser_arena_v3)
        elif reference is not None and AtomKey.from_token(reference.ref).type_name == 'memory.access':
            self.parser = C09MemoryAccessJSONStreamV3(ensure_ascii=True,
                source_arena=owner.builder.session._source_parser_arena_v3)
        else:
            self.parser = _PressureJSONV3(owner)

    def copy_for_v3(self, owner):
        result = copy(self)
        result.owner = owner
        if type(self.parser) is _PressureJSONV3:
            result.parser = self.parser.copy_for_v3(owner)
        else:
            result.parser = self.parser.copy()
        return result

    def advance(self, meter):
        self.pair.require_current()
        if self.offset < self.total:
            if self.header is not None:
                segment = self.scope.read_cell_segment_v3(self.header[0], self.ordinal, meter=meter)
                if segment is None or segment[0] != self.offset:
                    raise AuthorityUnavailable('pressure historical Source segment order differs')
                raw = segment[1]
                self.root = canonical_digest(('sylanne3.segmented-cell-link.v1', self.root,
                    self.header[0], self.ordinal, self.offset, len(raw), segment[2]))
                self.ordinal += 1
            else:
                amount = min(4096, self.total - self.offset)
                if self.capture is not None:
                    raw = self.capture.read_payload_fragment_v3(start=self.offset, length=amount, meter=meter)
                else:
                    with legacy_cell_read_transaction_v2(self.pair.source):
                        raw, total, kind = read_legacy_sql_cell_fragment_v2(self.pair.source,
                            table=self.table, column=self.column, where=self.where, parameters=self.key,
                            start=self.offset, length=amount, meter=meter)
                    if (total, kind, len(raw)) != (self.total, 'text', amount):
                        raise AuthorityUnavailable('pressure frozen metadata column changed')
            self.parser.feed(raw, self.parser.emit_v3 if type(self.parser) is _PressureJSONV3 else lambda event: None)
            self.parser._emit_callback = None
            self.offset += len(raw)
            return
        self.eof = self.parser.finish()
        if self.eof.byte_count != self.total:
            raise AuthorityUnavailable('pressure original did not reach complete canonical EOF')
        if self.capture is not None and self.eof.sha256 != self.capture.payload_digest:
            raise AuthorityUnavailable('pressure mapping raw metadata digest differs')
        if self.header is not None:
            self.scope.require_cell_eof_v3(self.header[0], self.ordinal, meter=meter)
            if (self.offset, self.ordinal, self.eof.sha256, self.root) != (
                    self.header[4], self.header[5], self.header[6], self.header[7]):
                raise AuthorityUnavailable('pressure original physical SHA/root/EOF differs')
        self.complete = True

    @property
    def value(self):
        if not self.complete:
            raise AuthorityUnavailable('pressure metadata needs complete Source EOF')
        if self.source:
            return self.parser._source_metadata
        return self.parser.value if type(self.parser) is _PressureJSONV3 else self.parser.metadata

    def heap_v3(self):
        return sys.getsizeof(self.__dict__) + (self.parser.heap_v3()
            if type(self.parser) is _PressureJSONV3 else 0)


class _D13PressureMappingReadV3:
    """Only the existing actual Counter family's fourth historical phase."""
    def __init__(self, parent):
        from .c09_authority_storage_rebase_v2 import _D13CoreDispositionReadV3
        if type(parent) is not _D13CoreDispositionReadV3 or parent.phase != 'pressure_mapping':
            raise AuthorityUnavailable('actual Counter-family pressure phase required')
        self.builder, self.capture, self.draft = parent.builder, parent.capture, parent.family_capture
        self.namespace = self.builder.session._control.maintenance.namespace_id
        self.counter_operation_id = parent.counter_operation_id
        self.parent_refs = frozenset(parent.references)
        self.phase, self.mapping_capture, self.column = 'locate', None, None
        self.envelope = self.origin = self.policy = self.grant_signature = None
        self.member_index = 0
        self.member_values = {}
        self.references = ()
        self.complete = self.absent = False
        self.proof = None
        self.scene_ref = None
        self.builder.session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        from .c09_d13_accounting_disposition_v3 import _heap
        return sys.getsizeof(self.__dict__) + _heap((self.envelope, self.origin, self.policy,
            self.member_values, self.references, self.parent_refs)) + (0 if self.column is None else self.column.heap_v3())

    def _require_arena(self, extra=0):
        meter = current_c09_sql_meter_v2()
        if sum(value._source_heap_bytes() for value in self.builder.session._source_parser_arena_v3) + extra > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable('pressure originals exceed the actual reserved Source arena')

    def copy_for_v3(self, parent):
        self._require_arena(self._source_heap_bytes())
        result = copy(self)
        result.member_values = dict(self.member_values)
        if self.column is not None:
            result.column = self.column.copy_for_v3(result)
        self.builder.session._source_parser_arena_v3.add(result)
        return result

    def confirm_quantum_v3(self):
        if self.mapping_capture is not None:
            self.mapping_capture.quantum_completed = True

    def _decode(self):
        from .d13_current_pressure_mapping_v1 import pressure_mapping_original_from_wire_v1
        self._require_arena(self.column.total * 12 + 32768)
        self.envelope, self.origin = pressure_mapping_original_from_wire_v1(self.column.value)
        self.column = None
        self.phase = 'identity'

    def _identity(self, parent, meter):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from .d13_current_pressure_mapping_v1 import _pressure_selection_policy_from_wire_v1, SIGNING_DOMAIN
        from .c09_authority_storage_rebase_v2 import _verify_d13_counter_history_v3
        service, frame, count, _, _, _ = _verify_d13_counter_history_v3(self.builder,
            (self.builder.scope.authority_namespace, self.counter_operation_id, 'evidence'), meter)
        payload = self.envelope.payload
        original = self.draft.parser.metadata
        if ((payload.namespace, payload.installation_id, payload.authority_namespace,
                payload.counter_operation_id, payload.frame_intent_digest, payload.counter_evidence_digest,
                payload.collection_digest, payload.collection_snapshot_commitment, payload.frozen_at_utc) !=
                (frame.namespace, frame.install_id, frame.authority_namespace, frame.counter_operation_id,
                 frame.frame_intent_digest, count.evidence_digest, frame.collection_digest,
                 frame.collection_snapshot_commitment, frame.frozen_at_utc)
                or (payload.collection_digest, payload.collection_snapshot_commitment,
                    payload.frame_intent_digest, payload.activation_epoch) !=
                   (original['collection_digest'], original['collection_snapshot_commitment'],
                    original['frame_intent_digest'], original['activation_generation'])
                or self.envelope.key_id != service.policy.counter_key_id
                or payload.expires_at_utc > frame.expires_at_utc):
            raise AuthorityUnavailable('pressure mapping differs from its qualified V7 family/full collection')
        # The official envelope decoder already proved its existing 65536-byte
        # canonical descriptor bound. Decode and verification occupy distinct
        # original quanta; retain/charge the signature input's actual copies.
        meter.require_available(3 * 65536 + 8192)
        self._require_arena(3 * 65536)
        encoded = canonical_serialize(payload).encode('ascii')
        meter.charge_encode(len(encoded))
        signed = SIGNING_DOMAIN + encoded
        meter.charge_encode(len(signed))
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(service.policy.counter_public_key_hex)).verify(
            base64.b64decode(self.envelope.signature, validate=True), signed)
        self.policy = _pressure_selection_policy_from_wire_v1(payload.selection_policy)
        selection = self.draft.parser.history_selections['raw']
        if ((payload.scene_ref, payload.audience_ref, payload.conversation_ref,
                payload.order_watermark, payload.access_epoch, payload.delete_epoch, payload.activation_epoch) !=
                (selection.scene_ref, selection.audience_ref, selection.conversation_ref,
                 selection.order_watermark, selection.access_epoch, selection.deletion_epoch, selection.activation_generation)
                or payload.owner_ref != 'persona:' + self.namespace.persona_id):
            raise AuthorityUnavailable('pressure scene/audience/epochs differ from original full Counter selection')
        selected = {member.sequence for member in payload.selected_members}
        expired, unclosed = set(payload.expired_sequences), set(payload.unclosed_sequences)
        if selected & (expired | unclosed) or expired & unclosed or selected | expired | unclosed != set(range(payload.first_sequence, payload.last_sequence + 1)):
            raise AuthorityUnavailable('pressure latest slot manifest is not a complete disjoint selection')
        from ..domains.d13.raw_slice import _merge_ranges
        missing = ([(0, payload.first_sequence - 1)] if payload.first_sequence else []) + [
            (sequence, sequence) for sequence in sorted(expired | unclosed)]
        if payload.missing_ranges != _merge_ranges(missing):
            raise AuthorityUnavailable('pressure missing ranges differ from actual signed slot classification')
        refs = {(payload.scene_ref.ref, payload.scene_ref.version), (payload.audience_ref.ref, payload.audience_ref.version)}
        for member in payload.selected_members:
            refs.update((ref.ref, ref.version) for ref in (member.raw_ref, member.source_ref, member.access_ref))
            if not (payload.frozen_at_utc <= payload.expires_at_utc <= member.trusted_utc + payload.ttl_seconds
                    and 0 <= payload.frozen_at_utc - member.trusted_utc < payload.ttl_seconds):
                raise AuthorityUnavailable('pressure member is outside its original trusted-time lifetime')
        if not refs <= self.parent_refs:
            raise AuthorityUnavailable('pressure members are absent from the actual qualified parent full read set')
        self.references = tuple(sorted(refs))
        self.proof = canonical_digest((self.mapping_capture.payload_digest, self.mapping_capture.size, self.draft.payload_digest,
            payload.selection_policy_origin_digest, payload.grant_original_digest,
            self.envelope.key_id, self.envelope.signature, frame.frame_intent_digest, count.evidence_digest))
        self.column = None
        self.phase = 'grant'

    def _grant(self, meter):
        from .c09_authority_storage_rebase_v2 import _d13_frozen_graph_pair_v3
        pair = _d13_frozen_graph_pair_v3(self.builder)
        policy = self.policy
        row = meter.read_fixed_row(pair.source, 'runtime_budget_grants', ('signature',),
            'lease_id=? AND version=?', (policy.lease_id, policy.grant_version))
        lease = meter.read_fixed_row(pair.source, 'runtime_budget_leases', ('bot_id', 'persona_id'),
            'lease_id=?', (policy.lease_id,))
        if row is None or lease != self.namespace.as_tuple:
            raise AuthorityUnavailable('pressure historical D11 grant/lease original is absent')
        self.grant_signature = row[0]
        self.column = _PressureColumnV3(self, table='runtime_budget_grants', column='grant_json',
            key_columns=('lease_id', 'version'), key=(policy.lease_id, policy.grant_version))
        self.phase = 'grant_bytes'

    def _grant_complete(self, meter):
        from ..runtime.issuers import BudgetLeaseGrant, D11BudgetJobIssuer
        raw = dict(self.column.value)
        if set(raw) != {field.name for field in fields(BudgetLeaseGrant)}:
            raise AuthorityUnavailable('pressure D11 grant original fields differ')
        raw['allowed_work_kinds'] = tuple(raw['allowed_work_kinds'])
        grant = BudgetLeaseGrant(**raw)
        service = self.builder.session.require_installed_d13_counter_service_v1()
        issuer = service.source.observer.issuer
        if type(issuer) is not D11BudgetJobIssuer:
            raise AuthorityUnavailable('actual installed D11 pressure signer required')
        self._require_arena(self.column.total * 8 + 16384)
        meter.require_available(self.column.total * 4 + 8192)
        encoded = canonical_serialize(self.column.value)
        meter.charge_encode(len(encoded))
        issuer._signer.verify('budget-grant.v1', encoded, self.grant_signature)
        p, policy = self.envelope.payload, self.policy
        if ((grant.grant_id, grant.version, grant.lease_id, grant.bot_id, grant.persona_id) !=
                (policy.grant_id, policy.grant_version, policy.lease_id, *self.namespace.as_tuple)
                or canonical_digest((grant, self.grant_signature)) != p.grant_original_digest
                or policy.work_kind not in grant.allowed_work_kinds
                or any(grant.max_ceiling.get(name, 0) < amount for name, amount in policy.quote_ceiling.items())
                or grant.valid_until_utc is not None and p.expires_at_utc > grant.valid_until_utc):
            raise AuthorityUnavailable('pressure original policy differs from its historical signed D11 grant')
        self.proof = canonical_digest((self.proof, self.column.eof.sha256, p.grant_original_digest))
        self.column = None
        self.phase = 'scene'

    def _scene_complete(self):
        from ..domains.d03 import RoleBinding
        raw = dict(self.column.value)
        if set(raw) != {field.name for field in fields(RoleBinding)}:
            raise AuthorityUnavailable('pressure historical scene binding fields differ')
        raw['norm_refs'] = tuple(raw['norm_refs'])
        raw['source_refs'] = tuple(raw['source_refs'])
        binding = RoleBinding(**raw)
        p = self.envelope.payload
        key = AtomKey.from_token(p.scene_ref.ref)
        if (key.name != binding.role_binding_id or p.scene_ref.version != binding.binding_version
                or binding.status != 'active' or binding.visibility_scope != 'private'
                or binding.subject_persona_ref != p.owner_ref
                or not binding.effective_from <= p.frozen_at_utc
                or binding.effective_until is not None and p.frozen_at_utc >= binding.effective_until):
            raise AuthorityUnavailable('pressure scene differs from actual original private Owner binding')
        self.scene_ref = binding.scene_ref
        self.proof = canonical_digest((self.proof, self.column.eof.sha256, binding))
        self.column = None
        self.phase = 'member'

    def _member_begin(self):
        p = self.envelope.payload
        if self.member_index == len(p.selected_members):
            self.complete = True
            self.phase = 'complete'
            return
        self.member_values = {}
        self.phase = 'completion'
        self._begin_member_column(p.selected_members[self.member_index].raw_ref)

    def _begin_member_column(self, reference, *, source=False):
        self.column = _PressureColumnV3(self, table='graph_history', column='value',
            key_columns=('token', 'revision'), key=(reference.ref, reference.version),
            reference=reference, source=source)

    def _member_complete(self):
        from ..domains.d09.turn_order import turn_completion_key, turn_slot_key, validate_turn_completion_v1
        from ..memory_types import source_key, access_key
        p = self.envelope.payload
        member = p.selected_members[self.member_index]
        completion, source, access = (self.member_values[name] for name in ('completion', 'source', 'access'))
        validate_turn_completion_v1(completion)
        skey = AtomKey.from_token(member.source_ref.ref)
        if (member.raw_ref.ref != turn_completion_key(self.namespace, self.scene_ref,
                    p.conversation_ref, member.sequence).token
                or completion['scene_ref'] != self.scene_ref
                or completion['slot_ref'] != turn_slot_key(self.namespace, self.scene_ref,
                    p.conversation_ref, member.sequence).token
                or (completion['conversation_ref'], completion['sequence'], completion['trusted_utc'],
                    completion['source_ref'], completion['access_ref']) !=
                   (p.conversation_ref, member.sequence, member.trusted_utc, member.source_ref.ref, member.access_ref.ref)
                or completion['version'] != member.raw_ref.version
                or member.source_ref.ref != source_key(*self.namespace.as_tuple, source['source_id']).token
                or member.access_ref.ref != access_key(*self.namespace.as_tuple, source['source_id']).token
                or skey.owner.subject != access['source_id']
                or completion['speaker_ref'] != source['speaker_id']
                or access['status'] != 'active'
                or 'context' not in source['purposes'] or 'context' not in access['purposes']
                or p.conversation_ref not in source['audiences'] or p.conversation_ref not in access['audiences']):
            raise AuthorityUnavailable('pressure member completion/Source/Access historical identity differs')
        self.proof = canonical_digest((self.proof, member, self.member_values))
        self.member_index += 1
        self.column = None
        self.phase = 'member'

    def advance(self, parent, budget, meter):
        from .c09_authority_storage_rebase_v2 import _D13CoreRowCaptureV3, _table_shape
        if (parent.builder is not self.builder or parent.capture is not self.capture
                or parent.family_capture is not self.draft or parent.counter_operation_id != self.counter_operation_id):
            raise AuthorityUnavailable('pressure continuation crossed its actual Counter-family Source')
        self.builder.require_current()
        result = self.copy_for_v3(parent)
        if result.column is not None and not result.column.complete:
            result.column.advance(meter)
        elif result.phase == 'locate':
            key = (self.builder.scope.authority_namespace, self.counter_operation_id, 'pressure_mapping_v1')
            row = meter.read_fixed_row(self.builder.pair.source, 'authority_d13_counter_originals_v1',
                ('payload_digest',), 'namespace=? AND counter_operation_id=? AND phase=?', key)
            if row is None:
                result.absent = result.complete = True
                result.proof = canonical_digest(('pressure_mapping_v1', key, 'absent'))
                result.phase = 'complete'
            else:
                result.mapping_capture = self.capture if self.capture.key == key else _D13CoreRowCaptureV3(
                    self.builder, _table_shape(self.builder.pair.source, 'authority_d13_counter_originals_v1'), key, budget, meter)
                result.phase = 'capture'
        elif result.phase == 'capture':
            if not (result.mapping_capture.complete and result.mapping_capture.quantum_completed):
                result.mapping_capture = result.mapping_capture.next_quantum(budget, meter)
            else:
                result.column = _PressureColumnV3(result, capture=result.mapping_capture)
                result.phase = 'mapping_bytes'
        elif result.phase == 'mapping_bytes':
            result._decode()
        elif result.phase == 'identity':
            result._identity(parent, meter)
        elif result.phase == 'grant':
            result._grant(meter)
        elif result.phase == 'grant_bytes':
            result._grant_complete(meter)
        elif result.phase == 'scene':
            result._begin_member_column(result.envelope.payload.scene_ref)
            result.phase = 'scene_bytes'
        elif result.phase == 'scene_bytes':
            result._scene_complete()
        elif result.phase == 'member':
            result._member_begin()
        elif result.phase in {'completion', 'source', 'access'}:
            name = result.phase
            result.member_values[name] = result.column.value
            p = result.envelope.payload
            member = p.selected_members[result.member_index]
            if name == 'completion':
                result.phase = 'source'
                result._begin_member_column(member.source_ref, source=True)
            elif name == 'source':
                result.phase = 'access'
                result._begin_member_column(member.access_ref)
            else:
                result._member_complete()
        result._require_arena()
        return result
