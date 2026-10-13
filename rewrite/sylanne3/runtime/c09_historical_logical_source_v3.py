"""Historical V3 logical originals, read through actual signed metadata only."""
from __future__ import annotations
import json
from .c09_paged_sql_v2 import (C09PagedCaptureHold,canonical_digest,canonical_serialize,
    require_c09_capture_member_v2,require_c09_logical_source_row_member_v3)
from .c09_paged_capture_contract_v2 import (C09StreamIdentityV2,C09CompleteStreamV2,
    c09_paged_value_from_wire_v2)


def require_historical_logical_graph_disposition_v3(session,pair,anchor,row,*,meter):
    """Decode only after the actual signed disposition member and Source member join."""
    from ..authority_service.c09_historical_capture_scope_v2 import VerifiedHistoricalCaptureScopeV2
    from .c09_historical_proof_row_codec_v2 import _nested_locator_for_family,_require_exact_structural_member,_require_signed_locator
    from .c09_graph_rebase_candidate_v2 import _graph_logical_preservation_original_v3
    from .c09_storage_rebase_contract_v1 import GraphRowDispositionV3
    if type(anchor) is not VerifiedHistoricalCaptureScopeV2:
        raise TypeError('actual installed historical anchor required')
    session.require_current();pair.require_current();anchor.require_current()
    if len(row)!=13 or row[0]!=anchor.scope.scope_digest or row[5]!='logical_preserved_v3':
        raise C09PagedCaptureHold('historical explicit V3 disposition grammar differs')
    table=row[1];key=tuple(json.loads(row[3]))
    if row[2]!=canonical_digest((table,key)):
        raise C09PagedCaptureHold('historical V3 full business primary key differs')
    family=_nested_locator_for_family(pair.source,anchor,anchor.certificate.candidate.disposition_directory,table,meter)
    _require_exact_structural_member(pair.source,family,key,row,meter)
    parent=meter.read_fixed_row(pair.source,'c09_capture_streams_v2',('identity_json','status','seal_json'),
        'stream_id=?',(row[7],))
    if parent is None or parent[1]!='sealed':raise C09PagedCaptureHold('historical Source stream original absent')
    identity=c09_paged_value_from_wire_v2(json.loads(parent[0]),C09StreamIdentityV2)
    complete=c09_paged_value_from_wire_v2(json.loads(parent[2]),C09CompleteStreamV2)
    source=_require_signed_locator(pair.source,anchor,identity,meter)
    if (source.complete!=complete or identity.stream_kind!='graph_facts' or identity.family!=table
            or identity.scope_digest!=anchor.scope.scope_digest
            or identity.role_source_digest!=anchor.source.role_source_digest
            or not 1<=row[8]<=complete.record_count):
        raise C09PagedCaptureHold('historical logical original crossed signed Source scope/family/ordinal')
    descriptor=require_c09_logical_source_row_member_v3(pair.source,identity,role='graph',
        table_name=table,key=key,record_ordinal=row[8],meter=meter)
    if (descriptor['source_role_digest']!=anchor.source.role_source_digest
            or descriptor['logical_shape_digest']!=identity.schema_digest
            or canonical_digest(descriptor)!=row[4]):
        raise C09PagedCaptureHold('historical logical Source descriptor differs from signed stream')
    raw=json.loads(row[12])
    if type(raw) is not dict or set(raw)!={'target_cell_seal','logical_equivalence_original'}:
        raise C09PagedCaptureHold('historical logical original field set differs')
    header=tuple(raw['target_cell_seal']['header'])
    source_header=tuple(raw['logical_equivalence_original']['source_cell_header'])
    bindings=descriptor['cell_bindings']
    if len(bindings)!=1 or 'source_header9' not in bindings[0] or tuple(bindings[0]['source_header9'])!=source_header:
        raise C09PagedCaptureHold('historical actual old Header9 original is missing or differs')
    if len(header)!=9 or header[3]!=anchor.scope.operation_id or header[8]!=anchor.scope.scope_digest:
        raise C09PagedCaptureHold('historical target seal belongs to another capture actor/scope')
    expected=_graph_logical_preservation_original_v3(anchor.scope.scope_digest,table,key,
        descriptor,source_header,header,row[6])
    if row[9:]!=expected:raise C09PagedCaptureHold('historical V3 three original locators differ')
    anchor.require_current();pair.require_current();session.require_current()
    return GraphRowDispositionV3(row[2],row[4],row[5],row[6],*row[9:12])


def require_historical_logical_source_descriptor_row_v3(session,pair,anchor,shape,key,row,*,meter):
    """A Source metadata row is authenticated by its actual signed business source member."""
    from .c09_historical_proof_row_codec_v2 import _require_signed_locator
    data=dict(zip(shape.columns,row,strict=True))
    if (shape.table!='c09_logical_source_rows_v3' or data['scope_digest']!=anchor.scope.scope_digest
            or data['role']!='graph' or data['key_digest']!=canonical_digest(tuple(json.loads(data['primary_key_json'])))):
        raise C09PagedCaptureHold('historical logical Source metadata full PK/role differs')
    parent=meter.read_fixed_row(pair.source,'c09_capture_streams_v2',('identity_json','status'),
        'stream_id=?',(data['origin_stream_id'],))
    if parent is None or parent[1]!='sealed':raise C09PagedCaptureHold('historical logical Source parent absent')
    identity=c09_paged_value_from_wire_v2(json.loads(parent[0]),C09StreamIdentityV2)
    locator=_require_signed_locator(pair.source,anchor,identity,meter)
    business_key=tuple(json.loads(data['primary_key_json']))
    descriptor=require_c09_logical_source_row_member_v3(pair.source,identity,role='graph',
        table_name=data['table_name'],key=business_key,record_ordinal=data['origin_record_ordinal'],meter=meter)
    if (locator.identity.family!=data['table_name'] or locator.identity.schema_digest!=data['logical_shape_digest']
            or data['descriptor_digest']!=canonical_digest(descriptor)
            or descriptor['source_role_digest']!=anchor.source.role_source_digest):
        raise C09PagedCaptureHold('historical logical Source metadata lost its actual signed descriptor')
    return locator
