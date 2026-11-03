"""Actual frozen numeric D02 history of one authenticated labor adoption."""
from hashlib import sha256
import json
from ..graph_types import AtomKey, GraphAtom, Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold, read_c09_table_shape_v2

def _read_numeric_history_v1(db, *, namespace, token, revision, meter, event_identity=None):
    from .c09_character_labor_execution_v1 import _LaborFrozenSourcesV1
    from ..runtime.d02_character_labor_rebuild_v1 import LABOR_TERMINAL_BODY_TYPES_V1
    source = db._character_labor_source_v1
    if type(source) is not _LaborFrozenSourcesV1:
        raise C09PagedCaptureHold('labor D02 history needs the actual private frozen source interval')
    source.require_current(db)
    key = AtomKey.from_token(token)
    if key.type_name not in LABOR_TERMINAL_BODY_TYPES_V1 or NamespaceId.from_key(key) != namespace:
        raise C09PagedCaptureHold('labor D02 history is outside registered numeric metadata types')
    shape = read_c09_table_shape_v2(db.db, 'graph_history', meter=meter)
    column = 'value_cell_id' if 'value_cell_id' in shape.columns else 'value'
    row = db.execute('SELECT ' + column + ',valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?', (token, revision)).fetchone()
    if row is None or row[1] != 1 or row[2:4] != namespace.as_tuple or (event_identity is not None and row[2:] != event_identity):
        raise C09PagedCaptureHold('labor numeric metadata is not its actual valid original event member')
    event = db.execute('SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?', row[2:]).fetchone()
    if event is None:
        raise C09PagedCaptureHold('labor numeric history original event is absent')
    writes = json.loads(event[0])
    if sum((item == [token, revision] for item in writes)) != 1:
        raise C09PagedCaptureHold('labor numeric historical revision is not a unique original event write')
    if column == 'value':
        encoded = row[0].encode('utf-8')
    else:
        from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
        schema = meter.read_fixed_row(db.db, 'sqlite_master', ('sql',), 'type=? AND name=?', ('table', 'graph_history'))
        if schema != (GRAPH_REF_DDLS_V3['graph_history'],):
            raise C09PagedCaptureHold('labor D02 metadata physical schema is not registered')
        pair = source.pairs[0]
        if pair.source is not db.db:
            raise C09PagedCaptureHold('labor numeric source is not actual Graph')
        scope = source.session.begin_source_physical_read_v3(pair, meter=meter)
        header = scope.read_cell_header_v3(row[0], meter=meter)
        if header[1:3] != ('canonical-json.ascii.v1', token):
            raise C09PagedCaptureHold('labor numeric cell changed original codec/owner')
        source.session._control.require_c09_retained_arena_v3(meter=meter, additional_bytes=header[4] * 12 + 32768)
        meter.require_available(header[4] * 2 + header[5] * 1024 + 8192)
        raw = bytearray()
        digest = sha256()
        root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', row[0]))
        for ordinal in range(header[5]):
            segment = scope.read_cell_segment_v3(row[0], ordinal, meter=meter)
            if segment is None or segment[0] != len(raw):
                raise C09PagedCaptureHold('labor numeric metadata source fragments changed')
            digest.update(segment[1])
            root = canonical_digest(('sylanne3.segmented-cell-link.v1', root, row[0], ordinal, len(raw), len(segment[1]), segment[2]))
            raw.extend(segment[1])
        scope.require_cell_eof_v3(row[0], header[5], meter=meter)
        if (len(raw), digest.hexdigest(), root) != (header[4], header[6], header[7]):
            raise C09PagedCaptureHold('labor numeric physical Source complete EOF/SHA/root differs')
        encoded = bytes(raw)
    from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
    parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
    for offset in range(0, len(encoded), 4096):
        parser.feed(encoded[offset:offset + 4096], lambda event: None)
    parser.finish()
    parser._emit_callback = None
    meter.charge_encode(len(encoded) * 2)
    value = json.loads(encoded)
    source.session._control.maintenance.graph._registry.validate(key, value)
    atom = GraphAtom(key, revision, value, True)
    source.values.append(atom)
    source.session._control.require_c09_retained_arena_v3(meter=meter)
    source.require_current(db)
    return atom

def require_character_labor_terminal_body_history_v1(db, *, binding, segment, basis, membership, meter):
    from ..runtime.d02_character_labor_rebuild_v1 import LABOR_TERMINAL_BODY_TYPES_V1, validate_character_labor_terminal_body_history_v1
    from .c09_character_labor_terminal_membership_v1 import require_terminal_d02_membership_v1
    receipt = require_terminal_d02_membership_v1(membership, binding=binding, segment=segment, basis=basis)
    source = db._character_labor_source_v1
    from .c09_character_labor_execution_v1 import _LaborFrozenSourcesV1
    if type(source) is not _LaborFrozenSourcesV1:
        raise C09PagedCaptureHold('labor terminal needs its exact frozen numeric history reader')
    source.require_current(db)
    ns = binding.namespace
    operation = receipt.operation_id
    body_key = AtomKey(Owner('persona', *ns.as_tuple), 'd02.body_state.v1', basis.policy.profile_id)
    before = [v for v in receipt.read_versions if v.key == body_key]
    if len(before) != 1 or before[0].revision < 1:
        raise C09PagedCaptureHold('labor adoption has no exact real before-Body read')
    before_body = _read_numeric_history_v1(db, namespace=ns, token=body_key.token, revision=before[0].revision, meter=meter)
    versions = tuple((v for v in receipt.write_versions if v.key.type_name in LABOR_TERMINAL_BODY_TYPES_V1))
    atoms = tuple((_read_numeric_history_v1(db, namespace=ns, token=v.key.token, revision=v.revision, meter=meter, event_identity=(*ns.as_tuple, binding.activity_id, operation)) for v in versions))
    actual = validate_character_labor_terminal_body_history_v1(binding=binding, segment=segment, basis=basis, receipt=receipt, before_body=before_body, atoms=atoms)
    source.require_current(db)
    return canonical_digest(('d11.verified-character-labor-terminal-body-membership.v1', binding.digest, basis.membership.receipt_digest, receipt.original_commitment, receipt.event_digest, tuple(((v.key.token, v.revision) for v in actual)), before_body, atoms))
