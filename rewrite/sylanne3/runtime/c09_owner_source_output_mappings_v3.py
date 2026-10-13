"""Immutable bodyless C09 mappings for actual Owner prepared output facts."""
from __future__ import annotations
import json
from ..runtime_contracts import canonical_digest,canonical_serialize
from .c09_paged_sql_v2 import C09PagedCaptureHold

TABLE='c09_owner_source_output_mappings_v3'
NAMES=('bundle','http_request','input','original','source','stage_request')
COLUMNS=('capture_scope_digest','prepared_digest','cell_name','source_role_digest',
    'prepared_row_descriptor_digest','original_owner_cell_id','source_cell_descriptor_digest',
    'outcome','target_cell_id','target_cell_seal_digest','logical_equivalence_original_digest',
    'original_json','original_digest','origin_stream_id','origin_record_ordinal')
DDL="""CREATE TABLE c09_owner_source_output_mappings_v3(
    capture_scope_digest TEXT NOT NULL,prepared_digest TEXT NOT NULL,
    cell_name TEXT NOT NULL CHECK(cell_name IN ('bundle','http_request','input','original','source','stage_request')),
    source_role_digest TEXT NOT NULL,prepared_row_descriptor_digest TEXT NOT NULL,
    original_owner_cell_id TEXT NOT NULL,source_cell_descriptor_digest TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('complete','carry_prefix','retired')),
    target_cell_id TEXT,target_cell_seal_digest TEXT,logical_equivalence_original_digest TEXT,
    original_json TEXT NOT NULL,original_digest TEXT NOT NULL,origin_stream_id TEXT NOT NULL,
    origin_record_ordinal INTEGER NOT NULL CHECK(origin_record_ordinal>0),
    PRIMARY KEY(capture_scope_digest,prepared_digest,cell_name),
    CHECK((outcome='complete' AND target_cell_id IS NOT NULL AND target_cell_seal_digest IS NOT NULL AND logical_equivalence_original_digest IS NOT NULL)
       OR (outcome='carry_prefix' AND target_cell_seal_digest IS NULL AND logical_equivalence_original_digest IS NULL)
       OR (outcome='retired' AND target_cell_id IS NULL AND target_cell_seal_digest IS NULL AND logical_equivalence_original_digest IS NULL))) STRICT"""
DDL_MAP={TABLE:DDL,
    TABLE+'_immutable_update':"CREATE TRIGGER c09_owner_source_output_mappings_v3_immutable_update BEFORE UPDATE ON c09_owner_source_output_mappings_v3 BEGIN SELECT RAISE(ABORT,'immutable Owner output mapping'); END",
    TABLE+'_immutable_delete':"CREATE TRIGGER c09_owner_source_output_mappings_v3_immutable_delete BEFORE DELETE ON c09_owner_source_output_mappings_v3 BEGIN SELECT RAISE(ABORT,'immutable Owner output mapping'); END"}

from pathlib import Path
from weakref import WeakSet
_ISSUER=object()
_ROWS=WeakSet()
_FIELDS={'schema','capture_scope_digest','namespace','prepared_digest','cell_name',
    'operation_id','attempt_id','source_role_digest','prepared_metadata','prepared_row_descriptor',
    'original_owner_cell_id','source_cell_descriptor','source_origin','source_disposition',
    'outcome','target_cell_seal','prefix_equivalence','retirement_original','logical_equivalence_original',
    'clock_original','clock_original_digest'}

def _sha(value):
    if type(value) is not str or len(value)!=64 or any(char not in '0123456789abcdef' for char in value):
        raise C09PagedCaptureHold('Owner output mapping commitment differs')
    return value

def decode_owner_source_output_mapping_row_v3(row):
    """Closed metadata grammar; this decoder issues no read qualification."""
    if type(row) is not tuple or len(row)!=len(COLUMNS):
        raise C09PagedCaptureHold('Owner output mapping actual15-column row required')
    data=dict(zip(COLUMNS,row,strict=True))
    original=json.loads(data['original_json'])
    if (type(original) is not dict or set(original)!=_FIELDS
            or original['schema']!='sylanne3.c09.owner-source-output-mapping-original.v3'
            or canonical_serialize(original)!=data['original_json']
            or canonical_digest(original)!=data['original_digest']):
        raise C09PagedCaptureHold('Owner output mapping original canonical schema/digest differs')
    for name in ('capture_scope_digest','prepared_digest','cell_name','source_role_digest',
                 'original_owner_cell_id','outcome'):
        if original[name]!=data[name]:
            raise C09PagedCaptureHold('Owner output mapping original and physical identity differ')
    if data['cell_name'] not in NAMES or data['outcome'] not in ('complete','carry_prefix','retired'):
        raise C09PagedCaptureHold('Owner output mapping fixed name/outcome differs')
    metadata=original['prepared_metadata']
    if (type(metadata) is not dict or metadata['schema']!='d06.owner-source-prepared.v3'
            or canonical_digest(metadata)!=data['prepared_digest']
            or metadata['namespace']!=original['namespace']
            or metadata['operation_id']!=original['operation_id']
            or metadata['attempt_id']!=original['attempt_id']
            or set(metadata['expected_outputs'])!=set(NAMES)):
        raise C09PagedCaptureHold('Owner output mapping old prepared metadata changed')
    clock=original['clock_original']
    details=clock['details']
    if (clock['original_digest']!=original['clock_original_digest']
            or details['schema']!='sylanne3.c09.owner-output-disposition-clock.v3'
            or details['scope_digest']!=data['capture_scope_digest']
            or details['prepared_digest']!=data['prepared_digest']
            or details['original_deadline_utc']!=metadata['original_deadline_utc']
            or details['graph_role_source_digest']!=data['source_role_digest']):
        raise C09PagedCaptureHold('Owner output as-of clock original crossed Source/prepared/deadline')
    _sha(original['clock_original_digest'])
    expected=metadata['expected_outputs'][data['cell_name']]
    original_id=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',
        instance=metadata['storage_instance'],prepared_digest=data['prepared_digest'],
        name=data['cell_name'],sha256=expected['payload_sha256']))
    if data['original_owner_cell_id']!=original_id:
        raise C09PagedCaptureHold('Owner output mapping changed its original Owner cell identity')
    prepared=original['prepared_row_descriptor']
    if (type(prepared) is not dict or set(prepared)!={'schema','scope_digest','table_name','primary_key',
            'physical_schema_digest','row_commitment','origin_stream_id','origin_record_ordinal'}
            or prepared['schema']!='sylanne3.c09.owner-prepared-source-row.v3'
            or prepared['scope_digest']!=data['capture_scope_digest']
            or prepared['table_name']!='graph_owner_source_prepared_v3'
            or prepared['primary_key']!=[data['prepared_digest']]
            or canonical_digest(prepared)!=data['prepared_row_descriptor_digest']
            or (prepared['origin_stream_id'],prepared['origin_record_ordinal'])!=(data['origin_stream_id'],data['origin_record_ordinal'])
            or type(data['origin_record_ordinal']) is not int or data['origin_record_ordinal']<1):
        raise C09PagedCaptureHold('Owner output mapping actual prepared Source member differs')
    source=original['source_cell_descriptor']
    not_started=type(source) is dict and source.get('schema')=='sylanne3.c09.prepared-output-source-not-started.v3'
    if not_started:
        required={'schema','scope_digest','source_role_digest','source_identity','prepared_digest','prepared_metadata_digest','cell_name',
            'original_storage_instance','original_owner_cell_id','factual_source_state','expected_payload_sha256','expected_total_bytes',
            'schema_eof_digest','absence_eof_digest','no_w01_terminal_digest','original_deadline_utc'}
        if (set(source)!=required or source['scope_digest']!=data['capture_scope_digest']
                or source['source_role_digest']!=data['source_role_digest'] or source['prepared_digest']!=data['prepared_digest']
                or source['prepared_metadata_digest']!=data['prepared_digest'] or source['cell_name']!=data['cell_name']
                or source['original_storage_instance']!=metadata['storage_instance'] or source['original_owner_cell_id']!=original_id
                or source['factual_source_state']!='not_started'
                or (source['expected_payload_sha256'],source['expected_total_bytes'])!=(expected['payload_sha256'],expected['total_bytes'])
                or source['original_deadline_utc']!=metadata['original_deadline_utc']
                or canonical_digest(source)!=data['source_cell_descriptor_digest']):
            raise C09PagedCaptureHold('Owner output NotStarted actual absence original differs')
        for name in ('schema_eof_digest','absence_eof_digest','no_w01_terminal_digest'):_sha(source[name])
    else:
        source_fields={'schema','scope_digest','source_role_digest','prepared_digest','cell_name','kind',
            'original_owner_cell_id','current_cell_id','header9','cursor','observed_bytes','observed_segments',
            'observed_sha256','observed_root','expected_sha256','expected_total_bytes'}
        if (type(source) is not dict or set(source)!=source_fields
                or source['schema']!='sylanne3.c09.prepared-output-source.v3'
                or canonical_digest(source)!=data['source_cell_descriptor_digest']
                or source['source_role_digest']!=data['source_role_digest']
                or source['scope_digest']!=data['capture_scope_digest']
                or source['prepared_digest']!=data['prepared_digest'] or source['cell_name']!=data['cell_name']
                or source['original_owner_cell_id']!=original_id
                or (source['expected_sha256'],source['expected_total_bytes'])!=(expected['payload_sha256'],expected['total_bytes'])
                or source['kind'] not in ('Complete','Prefix','Retired')):
            raise C09PagedCaptureHold('Owner output mapping actual Source descriptor differs')
        for name in ('observed_bytes','observed_segments','expected_total_bytes'):
            if type(source[name]) is not int or source[name]<0:
                raise C09PagedCaptureHold('Owner output mapping Source counters differ')
        for name in ('capture_scope_digest','prepared_digest','source_role_digest','prepared_row_descriptor_digest',
                     'original_owner_cell_id','source_cell_descriptor_digest','original_digest','origin_stream_id'):
            _sha(data[name])
        _sha(source['expected_sha256']);_sha(source['observed_sha256'])
        if source['kind']=='Retired':
            prior_ref=original['source_origin']['details']['previous_mapping_original_ref']
            if source['header9'] is not None or source['cursor'] is not None:
                raise C09PagedCaptureHold('Retired Source cannot claim a complete header or readable prefix')
            if prior_ref is not None:
                if source['current_cell_id'] is not None or source['observed_root'] is not None:
                    raise C09PagedCaptureHold('mapped bodyless Retired Source cannot invent old cells/root')
            elif (source['current_cell_id']!=original_id or source['observed_root']!=
                    canonical_digest(('sylanne3.segmented-cell-genesis.v1',original_id))):
                raise C09PagedCaptureHold('initial Retired Source changed its real original locator/genesis fact')
        else:_sha(source['observed_root'])
    for name in ('capture_scope_digest','prepared_digest','source_role_digest','prepared_row_descriptor_digest',
                 'original_owner_cell_id','source_cell_descriptor_digest','original_digest','origin_stream_id'):_sha(data[name])
    origin=original['source_origin']
    details=origin['details']
    if (details['schema']!='sylanne3.c09.prepared-output-source-original.v3'
            or details['scope_digest']!=data['capture_scope_digest']
            or details['source_role_digest']!=data['source_role_digest']
            or details['prepared_digest']!=data['prepared_digest'] or details['cell_name']!=data['cell_name']
            or details['prepared_metadata_digest']!=data['prepared_digest'] or details['source_descriptor']!=source):
        raise C09PagedCaptureHold('Source descriptor is not its exact protected Q05 scope original')
    _sha(origin['original_digest'])
    previous_retirement=details['previous_retirement_original']
    previous_ref=details['previous_mapping_original_ref']
    if previous_retirement is not None:
        if (previous_ref is None or canonical_digest(previous_retirement)!=details['previous_retirement_original_digest']
                or previous_ref['prepared_digest']!=data['prepared_digest'] or previous_ref['cell_name']!=data['cell_name']):
            raise C09PagedCaptureHold('previous retirement differs from actual protected Source provenance')
    outcomes=('target_cell_seal','prefix_equivalence','retirement_original','logical_equivalence_original')
    selected={name:original[name] for name in outcomes}
    if data['outcome']=='complete':
        seal=selected['target_cell_seal'];equiv=selected['logical_equivalence_original']
        if (not_started or source['kind']!='Complete' or type(seal) is not dict or type(equiv) is not dict
                or selected['prefix_equivalence'] is not None or selected['retirement_original'] is not None
                or canonical_digest(seal)!=data['target_cell_seal_digest']
                or canonical_digest(equiv)!=data['logical_equivalence_original_digest']):
            raise C09PagedCaptureHold('Owner output mapping complete original differs')
        if set(seal)!={'schema','scope_digest','prepared_digest','cell_name','header9','locator','prefix_sha256'}:
            raise C09PagedCaptureHold('Owner output complete target seal exact fields differ')
        header=seal['header9']
        if (type(header) is not list or len(header)!=9 or header[0]!=data['target_cell_id']
                or header[1]!='canonical-json.ascii.v1' or header[2]!=metadata['source_ref']
                or header[4]!=expected['total_bytes'] or header[6]!=expected['payload_sha256']
                or seal['scope_digest']!=data['capture_scope_digest']
                or seal['prepared_digest']!=data['prepared_digest'] or seal['cell_name']!=data['cell_name']):
            raise C09PagedCaptureHold('Owner output complete target header/owner/bytes differ')
        if (set(equiv)!={'schema','scope_digest','prepared_digest','cell_name','source_cell_descriptor_digest',
                'target_cell_seal_digest','codec_id','total_bytes','payload_sha256','source_business_operation_id','source_role_digest'}
                or equiv['schema']!='sylanne3.c09.owner-output-logical-equivalence.v3'
                or equiv['scope_digest']!=data['capture_scope_digest'] or equiv['prepared_digest']!=data['prepared_digest']
                or equiv['cell_name']!=data['cell_name'] or equiv['source_cell_descriptor_digest']!=data['source_cell_descriptor_digest']
                or equiv['target_cell_seal_digest']!=data['target_cell_seal_digest']
                or (equiv['codec_id'],equiv['total_bytes'],equiv['payload_sha256'])!=('canonical-json.ascii.v1',expected['total_bytes'],expected['payload_sha256'])
                or equiv['source_business_operation_id']!=metadata['operation_id'] or equiv['source_role_digest']!=data['source_role_digest']
                or seal['schema']!='sylanne3.c09.owner-output-target-seal.v3' or seal['prefix_sha256']!=expected['payload_sha256']):
            raise C09PagedCaptureHold('Owner output complete logical equivalence exact binding differs')
    elif data['outcome']=='carry_prefix':
        prefix=selected['prefix_equivalence']
        if ((not not_started and source['kind']!='Prefix') or type(prefix) is not dict
                or any(selected[name] is not None for name in outcomes if name!='prefix_equivalence')
                or data['target_cell_seal_digest'] is not None or data['logical_equivalence_original_digest'] is not None):
            raise C09PagedCaptureHold('Owner output prefix cannot claim a complete seal/equivalence')
        if set(prefix)!={'schema','scope_digest','prepared_digest','cell_name','source_descriptor_digest','cursor','prefix_sha256','prefix_bytes','prefix_segments','prefix_root'}:
            raise C09PagedCaptureHold('Owner output prefix original exact fields differ')
        cursor=prefix['cursor']
        if (type(cursor) is not list or len(cursor)!=18 or cursor[0]!=data['target_cell_id']
                or cursor[1]!=data['capture_scope_digest'] or cursor[3]!='canonical-json.ascii.v1'
                or cursor[5]!=metadata['source_ref'] or cursor[12]!=expected['total_bytes']
                or (prefix['prefix_bytes'],prefix['prefix_segments'],prefix['prefix_sha256'])!=
                   ((0,0,__import__('hashlib').sha256().hexdigest()) if not_started else
                    (source['observed_bytes'],source['observed_segments'],source['observed_sha256']))
                or prefix['source_descriptor_digest']!=data['source_cell_descriptor_digest']
                or prefix['schema']!='sylanne3.c09.owner-output-prefix-equivalence.v3'
                or prefix['scope_digest']!=data['capture_scope_digest'] or prefix['prepared_digest']!=data['prepared_digest']
                or prefix['cell_name']!=data['cell_name'] or prefix['prefix_root']!=cursor[9]):
            raise C09PagedCaptureHold('Owner output actual target prefix cursor differs')
    else:
        if (type(selected['retirement_original']) is not dict
                or any(selected[name] is not None for name in outcomes if name!='retirement_original')
                or any(data[name] is not None for name in ('target_cell_id','target_cell_seal_digest','logical_equivalence_original_digest'))):
            raise C09PagedCaptureHold('Owner output retirement cannot carry body authority')
        retirement=selected['retirement_original']
        if (not_started or set(retirement)!={'schema','scope_digest','prepared_digest','cell_name','source_cell_descriptor_digest',
                'reason','source_disposition_digest','erasure_disposition_refs'}
                or retirement['schema']!='sylanne3.c09.owner-output-retirement.v3'
                or retirement['scope_digest']!=data['capture_scope_digest'] or retirement['prepared_digest']!=data['prepared_digest']
                or retirement['cell_name']!=data['cell_name']
                or retirement['source_cell_descriptor_digest']!=data['source_cell_descriptor_digest']
                or retirement['reason'] not in ('aborted_verified','erased')
                or type(retirement['erasure_disposition_refs']) is not list
                or (retirement['reason']=='aborted_verified' and (source['kind']!='Retired'
                    or (previous_retirement is None and retirement['source_disposition_digest']!=canonical_digest(original['source_disposition']))
                    or retirement['erasure_disposition_refs']))
                or (retirement['reason']=='erased' and not retirement['erasure_disposition_refs'])):
            raise C09PagedCaptureHold('Owner output retirement actual refusal/erasure original differs')
        if previous_retirement is not None:
            for field in ('reason','source_disposition_digest','erasure_disposition_refs'):
                if retirement[field]!=previous_retirement[field]:
                    raise C09PagedCaptureHold('retired mapping changed the actual prior retirement reason/facts')
    return original

class VerifiedSelectedOwnerOutputMappingRowV3:
    """One retained signed row; this proof makes no whole-cell EOF claim."""
    def __init__(self,token,basis,row,original,directory,family):
        if token is not _ISSUER:
            raise C09PagedCaptureHold('actual signed selected mapping row factory required')
        self.basis,self.row,self.original=basis,row,original
        self.metadata=original['prepared_metadata'];self.outcome=original['outcome']
        self.original_owner_cell_id=original['original_owner_cell_id']
        self.target_descriptor=original['target_cell_seal'] if self.outcome=='complete' else original['prefix_equivalence']
        self.directory,self.family=directory,family
        _ROWS.add(self)
    def require_current(self,*,db,meter):
        if self not in _ROWS:raise C09PagedCaptureHold('actual signed selected mapping row proof required')
        self.basis.require_current(meter=meter)
        _require_selected_owner_mapping_db_v3(db,self.basis,meter)
        from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
        actual=meter.read_fixed_row(db,TABLE,COLUMNS,
            'capture_scope_digest=? AND prepared_digest=? AND cell_name=?',self.row[:3])
        if actual!=self.row:raise C09PagedCaptureHold('actual retained mapping row changed')
        _require_exact_structural_member(db,self.family,self.row[:3],self.row,meter)
        return self

def _require_selected_owner_mapping_db_v3(db,basis,meter):
    from ..authority_service.c09_selected_history_v3 import _read_one
    paths=_read_one(db,'PRAGMA database_list',(),meter)
    if paths is None or paths[1]!='main' or Path(paths[2]).resolve(strict=True)!=Path(basis.member('graph')['resolved_path']).resolve(strict=True):
        raise C09PagedCaptureHold('selected Owner mapping crossed its actual Graph member')

def require_selected_owner_output_mapping_row_v3(db,basis,prepared_digest,cell_name,meter):
    """Issue only from actual selected basis and retained signed directory/member."""
    from ..authority_service.c09_selected_history_v3 import _InstalledSelectedStorageBasisV3,_read_one
    from ..authority_service.c09_prepared_storage_v3 import _read_original
    from ..authority_service.c09_graph_rebase_issue_v2 import AuthorityGraphRebaseIssuedV2
    from .c09_paged_capture_contract_v2 import (GraphErasureRebaseCertificateV2,C09FrozenRoleSourceV2,
        C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
    from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
    if type(basis) is not _InstalledSelectedStorageBasisV3 or cell_name not in NAMES:
        raise C09PagedCaptureHold('actual selected Owner output basis/name required')
    basis.require_current(meter=meter)
    _require_selected_owner_mapping_db_v3(db,basis,meter)
    from .owner_material_source_storage_v3 import read_selected_owner_source_prepared_v3,read_selected_owner_source_cell_v3,begin_selected_owner_source_stage_read_v3
    prepared=read_selected_owner_source_prepared_v3(db,basis=basis,prepared_digest=prepared_digest,meter=meter)
    if prepared is None:raise C09PagedCaptureHold('actual Owner prepared output metadata is absent')
    metadata=prepared['metadata']
    present=meter.read_fixed_row(db,'sqlite_master',('name',),'type=? AND name=?',('table',TABLE))
    mapping_exists=None if present is None else meter.read_fixed_row(db,TABLE,('capture_scope_digest',),
        'prepared_digest=? AND cell_name=? ORDER BY capture_scope_digest',(prepared_digest,cell_name))
    layout=meter.read_fixed_row(db,'segmented_storage_layout_v1',('storage_instance_id',),'singleton=?',(1,))
    if mapping_exists is None and layout==(metadata['storage_instance'],) and metadata['storage_instance']==basis.manifest['segmented_layouts']['graph']['storage_instance_id']:
        descriptor=metadata['expected_outputs'][cell_name]
        original_id=canonical_digest(dict(schema='sylanne3.owner-source-cell.v3',instance=metadata['storage_instance'],
            prepared_digest=prepared_digest,name=cell_name,sha256=descriptor['payload_sha256']))
        header=meter.read_fixed_row(db,'segmented_cells_v1',('cell_id','codec_id','erasure_owner_ref','producer_operation_id',
            'total_bytes','segment_count','payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(original_id,))
        if header is not None:
            actual=read_selected_owner_source_cell_v3(db,basis=basis,cell_id=original_id,header=tuple(header[1:]),meter=meter)
            if actual is None or actual['prepared_digest']!=prepared_digest or actual['cell_name']!=cell_name:
                raise C09PagedCaptureHold('fresh Owner output has no actual literal producer')
        else:
            cursor=meter.read_fixed_row(db,'segmented_cell_writes_v1',('cell_id',),'cell_id=?',(original_id,))
            if cursor is not None:
                begin_selected_owner_source_stage_read_v3(db,selected_basis=basis,cell_id=original_id,meter=meter)
            elif prepared['actual_committed']:
                raise C09PagedCaptureHold('adopted fresh Owner output lost its actual body/cursor')
            elif meter.read_fixed_row(db,'segmented_cell_segments_v1',('ordinal',),'cell_id=? ORDER BY ordinal',(original_id,)) is not None:
                raise C09PagedCaptureHold('fresh unstarted Owner output has orphaned material')
            # A fresh live NotStarted name remains the actual producer's absence
            # fact. This None grants no body or continuation; the live reader
            # must still qualify its own current material before consumption.
        basis.require_current(meter=meter)
        return None
    with basis.control._db() as control_db:
        issue_raw=_read_original(basis.control,control_db,basis.prepared['operation_id'],
            'graph_issued_v2',basis.prepared['graph_issue_original_digest'],meter)
        base=_read_original(basis.control,control_db,basis.prepared['operation_id'],
            'capture_role_complete_v2_graph',basis.prepared['four_role_complete_original_digests']['graph'],meter)
    certificate=c09_paged_value_from_wire_v2(issue_raw['certificate'],GraphErasureRebaseCertificateV2)
    AuthorityGraphRebaseIssuedV2(certificate,issue_raw['issue_digest'],issue_raw['signature'],issue_raw['schema'])
    candidate=certificate.candidate;scope=candidate.scope
    source=c09_paged_value_from_wire_v2(base['source_original'],C09FrozenRoleSourceV2)
    target_identity=tuple(base['target_identity'])
    if len(target_identity)!=4 or any(type(value) is not int or value<0 for value in target_identity):
        raise C09PagedCaptureHold('actual Graph BaseRoleComplete four-field target identity differs')
    if (scope.scope_digest!=basis.prepared['capture_scope_digest'] or scope.operation_id!=basis.prepared['operation_id']
            or scope.authority_id!=basis.control.authority_id or scope.installation_id!=basis.control.installation_id
            or scope.authority_namespace!=basis.prepared['namespace'] or source!=candidate.source
            or base['scope_digest']!=scope.scope_digest or base['role']!='graph'
            or base['target_path']!=basis.member('graph')['resolved_path']
            or issue_raw['issue_digest']!=basis.manifest['graph_issue_digest']
            or certificate.certificate_digest!=basis.manifest['certificate_digest']):
        raise C09PagedCaptureHold('selected mapping signed Graph scope/member/issue differs')
    present=meter.read_fixed_row(db,'sqlite_master',('name',),'type=? AND name=?',('table',TABLE))
    row=None if present is None else meter.read_fixed_row(db,TABLE,COLUMNS,
        'capture_scope_digest=? AND prepared_digest=? AND cell_name=?',(scope.scope_digest,prepared_digest,cell_name))
    if row is None:raise C09PagedCaptureHold('migrated Owner output mapping is missing; no old-ID fallback')
    for name,ddl in DDL_MAP.items():
        kind='table' if name==TABLE else 'trigger'
        actual=meter.read_fixed_row(db,'sqlite_master',('sql',),'type=? AND name=?',(kind,name))
        if actual!=(ddl,):raise C09PagedCaptureHold('selected Owner mapping immutable schema differs')
    original=decode_owner_source_output_mapping_row_v3(tuple(row))
    ns=original['namespace']
    if type(ns) is not dict or set(ns)!={'bot_id','persona_id'} or [ns['bot_id'],ns['persona_id']]!=json.loads(scope.graph_namespace):
        raise C09PagedCaptureHold('selected Owner mapping namespace differs')
    outer=candidate.target_directory
    cols=('scope_digest','family','identity_json','complete_json')
    directory_row=meter.read_fixed_row(db,outer.identity.family,cols,
        'scope_digest=? AND family=?',(scope.scope_digest,TABLE))
    if directory_row is None:raise C09PagedCaptureHold('mapping family is missing from actual signed target directory')
    _require_exact_structural_member(db,outer,(scope.scope_digest,TABLE),directory_row,meter)
    identity=c09_paged_value_from_wire_v2(json.loads(directory_row[2]),C09StreamIdentityV2)
    complete=c09_paged_value_from_wire_v2(json.loads(directory_row[3]),C09CompleteStreamV2)
    family=C09SealedStreamLocatorV2('graph',identity,complete)
    if (identity.scope_digest!=scope.scope_digest or identity.family!=TABLE
            or identity.primary_key_columns!=COLUMNS[:3] or identity.role_source_digest!=source.role_source_digest):
        raise C09PagedCaptureHold('mapping family signed identity differs')
    _require_exact_structural_member(db,family,tuple(row[:3]),tuple(row),meter)
    basis.require_current(meter=meter)
    return VerifiedSelectedOwnerOutputMappingRowV3(_ISSUER,basis,tuple(row),original,outer,family)
