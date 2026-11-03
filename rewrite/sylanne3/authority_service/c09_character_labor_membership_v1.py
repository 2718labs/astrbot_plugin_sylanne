"""Incremental actual C membership bytes, bound to one final frozen source."""
from copy import copy
from hashlib import sha256
from weakref import WeakSet
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold, read_legacy_sql_cell_fragment_v2, read_c09_table_shape_v2
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
_MEMBERS = WeakSet()

class _CharacterLaborMembershipReadV1:

    def __init__(self, owner, basis):
        from .c09_character_labor_execution_v1 import _CharacterLaborCoreReverseReadV1, _LABOR_REVERSE
        from ..runtime.d11_character_labor_accounting_v1 import CharacterLaborAccountingBasisV1
        if type(owner) is not _CharacterLaborCoreReverseReadV1 or owner not in _LABOR_REVERSE or type(basis) is not CharacterLaborAccountingBasisV1:
            raise C09PagedCaptureHold('actual final labor membership owner/basis required')
        self.builder = owner.builder
        self.graph = owner.graph
        self.production = owner.production
        self.member_identity = owner.member_identity
        self.basis = basis
        self.index = 0
        self.offset = 0
        self.ordinal = 0
        self.hash = sha256()
        self.root = None
        self.header = None
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.complete = False
        _MEMBERS.add(self)
        self.builder.session._control.maintenance.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        parser = tuple((getattr(self.parser, name) for name in self.parser.__slots__ if name != '_emit_callback'))
        return 16384 + _retained_size((self.basis, self.header, parser), set())

    def require_current(self, owner=None):
        from .c09_character_labor_execution_v1 import _CharacterLaborCoreReverseReadV1, _LABOR_REVERSE
        if self not in _MEMBERS:
            raise C09PagedCaptureHold('actual registered C membership required')
        if owner is not None and (type(owner) is not _CharacterLaborCoreReverseReadV1 or owner not in _LABOR_REVERSE or owner.builder is not self.builder or (owner.graph is not self.graph) or (owner.production != self.production) or (owner.member_identity != self.member_identity)):
            raise C09PagedCaptureHold('labor C membership left its exact actual source member')
        self.builder.require_current()
        self.graph.require_current()

    def require_complete(self, owner, basis):
        self.require_current(owner)
        if not self.complete or self.basis != basis:
            raise C09PagedCaptureHold('actual complete C membership byte proof required')
        return canonical_digest(('d11.verified-character-labor-C-source-eof.v1', owner.builder.scope.scope_digest, owner.graph.pair.source_original.role_source_digest, self.basis.membership))

    def _headers(self, meter):
        require_character_labor_C_headers_v1(self.builder.session, self.graph.pair, self.basis, meter=meter)

    def advance(self, meter):
        self.require_current()
        self._headers(meter)
        result = copy(self)
        result.hash = self.hash.copy()
        result.parser = self.parser.copy()
        _MEMBERS.add(result)
        self.builder.session._control.maintenance.control.register_c09_retained_state_v3(result)
        b = self.basis
        m = b.membership
        db = self.graph.pair.source
        if self.index < 3:
            commitment = m.columns[self.index]
            if commitment.column != ('reads', 'revisions', 'invalidated')[self.index]:
                raise C09PagedCaptureHold('labor C attestation column order changed')
            total = commitment.byte_count
            length = min(4096, total - self.offset)
            raw, actual, kind = read_legacy_sql_cell_fragment_v2(db, table='graph_events', column=commitment.column, where='bot=? AND persona=? AND session=? AND event_id=?', parameters=(*b.namespace.as_tuple, m.activity_id, b.prepare_operation_id), start=self.offset, length=length, meter=meter)
            if actual != total or kind != 'text':
                raise C09PagedCaptureHold('labor C original event byte length/storage class changed')
            expected = commitment.sha256
        else:
            shape = read_c09_table_shape_v2(db, 'graph_history', meter=meter)
            column = 'value_cell_id' if 'value_cell_id' in shape.columns else 'value'
            columns = ('valid', 'event_bot', 'event_persona', 'event_session', 'event_id')
            row = meter.read_fixed_row(db, 'graph_history', (column, *columns) if column == 'value_cell_id' else columns, 'token=? AND revision=?', (m.job_ref, m.job_revision))
            if column == 'value' and row is not None:
                row = (None, *row)
            if row is None or row[1:] != (1, *b.namespace.as_tuple, m.activity_id, b.prepare_operation_id):
                raise C09PagedCaptureHold('labor original job is not its exact valid same-C member')
            expected = m.job_value_sha256
            if column == 'value':
                _, total, kind = read_legacy_sql_cell_fragment_v2(db, table='graph_history', column='value', where='token=? AND revision=?', parameters=(m.job_ref, m.job_revision), start=0, length=0, meter=meter)
                if kind != 'text':
                    raise C09PagedCaptureHold('labor native job original is not text')
                raw, actual, _ = read_legacy_sql_cell_fragment_v2(db, table='graph_history', column='value', where='token=? AND revision=?', parameters=(m.job_ref, m.job_revision), start=self.offset, length=min(4096, total - self.offset), meter=meter)
                if actual != total:
                    raise C09PagedCaptureHold('labor native job byte length changed')
            else:
                from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
                ddl = meter.read_fixed_row(db, 'sqlite_master', ('sql',), 'type=? AND name=?', ('table', 'graph_history'))
                if ddl != (GRAPH_REF_DDLS_V3['graph_history'],):
                    raise C09PagedCaptureHold('labor original job physical layout is not registered')
                scope = self.builder.session.begin_source_physical_read_v3(self.graph.pair, meter=meter)
                header = scope.read_cell_header_v3(row[0], meter=meter)
                if header[1:3] != ('canonical-json.ascii.v1', m.job_ref) or header[6] != expected:
                    raise C09PagedCaptureHold('labor job actual physical header differs from signed whole-value commitment')
                if self.header is not None and self.header != header:
                    raise C09PagedCaptureHold('labor job header changed between its real quantum fragments')
                result.header = header
                total = header[4]
                if self.ordinal < header[5]:
                    segment = scope.read_cell_segment_v3(row[0], self.ordinal, meter=meter)
                    if segment is None or segment[0] != self.offset:
                        raise C09PagedCaptureHold('labor job actual fragment order changed')
                    raw = segment[1]
                    result.ordinal += 1
                    prior = canonical_digest(('sylanne3.segmented-cell-genesis.v1', row[0])) if self.root is None else self.root
                    result.root = canonical_digest(('sylanne3.segmented-cell-link.v1', prior, row[0], self.ordinal, self.offset, len(raw), segment[2]))
                else:
                    raw = b''
                if self.offset + len(raw) == total:
                    scope.require_cell_eof_v3(row[0], result.ordinal, meter=meter)
                    if result.root != header[7]:
                        raise C09PagedCaptureHold('labor complete job Source cell root changed')
                scope.require_current(meter=meter)
        meter.require_available(len(raw) * 2 + 4096)
        self.builder.session._control.require_c09_retained_arena_v3(meter=meter, additional_bytes=len(raw) * 4 + 16384)
        result.hash.update(raw)
        result.parser.feed(raw, lambda event: None)
        result.parser._emit_callback = None
        result.offset += len(raw)
        meter.charge_encode(len(raw))
        if result.offset == total:
            result.parser.finish()
            if result.hash.hexdigest() != expected:
                raise C09PagedCaptureHold('labor C actual complete canonical EOF/SHA differs from signed member')
            result.index += 1
            result.offset = 0
            result.ordinal = 0
            result.header = None
            result.root = None
            result.hash = sha256()
            result.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
            if result.index == 4:
                result.complete = True
        result.require_current()
        return result

def require_character_labor_C_headers_v1(session, pair, basis, *, meter):
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    from ..runtime.d11_character_labor_accounting_v1 import CharacterLaborAccountingBasisV1
    if type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2 or pair._producer.session is not session or (pair.source_original.role != 'graph') or (pair.source_original.scope_digest != session.scope.scope_digest) or (type(basis) is not CharacterLaborAccountingBasisV1):
        raise C09PagedCaptureHold('actual same-scope Graph and signed C basis required')
    session.require_current()
    pair.require_current()
    b = basis
    m = b.membership
    source = pair.source
    bundle = meter.read_fixed_row(source, 'graph_bundle_operations', ('digest', 'activity_id', 'effect_id', 'commit_seq'), 'bot=? AND persona=? AND operation_id=?', (*b.namespace.as_tuple, b.prepare_operation_id))
    event = meter.read_fixed_row(source, 'graph_events', ('digest', 'epoch_revision'), 'bot=? AND persona=? AND session=? AND event_id=?', (*b.namespace.as_tuple, m.activity_id, b.prepare_operation_id))
    if bundle != (m.operation_digest, m.activity_id, m.effect_id, m.commit_seq) or event != (m.event_digest, m.graph_epoch):
        raise C09PagedCaptureHold('labor actual bundle/event fixed headers differ from C attestation')
    issuer = session.get_c09_domain_original_issuer_v2()
    from ..runtime.d11_life_preparation_v1 import SIGN_KIND
    for kind, ref, expected in (('character_labor_prepared_v1', b.prepared_ref, b.prepared_digest), ('character_labor_admission_v1', b.admission_ref, b.admission_digest), ('accounting_prepared', b.accounting_ref, b.accounting_digest), ('character_labor_prepared_metadata_v1', 'character-labor-prepared-metadata:' + b.execution_id, None)):
        row = meter.read_fixed_row(source, 'graph_d11_life_originals_v1', ('producing_operation_id', 'payload_digest', 'signature'), 'bot=? AND persona=? AND kind=? AND original_ref=?', (*b.namespace.as_tuple, kind, ref))
        if row is None or row[0] != b.prepare_operation_id or (expected is not None and row[1] != expected):
            raise C09PagedCaptureHold('labor initial C signed member/header commitment changed')
        issuer._signer.verify(SIGN_KIND, canonical_serialize((b.namespace, kind, ref, row[1])), row[2])
