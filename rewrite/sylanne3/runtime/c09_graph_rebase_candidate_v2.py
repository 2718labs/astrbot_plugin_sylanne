"""Installed Graph paged-build/cold interface; never a DTO authority entry."""
from __future__ import annotations
from .contact_effect_accounting_v1 import ORIGINAL_TABLE as CONTACT_EFFECT_ORIGINAL, ATTEMPT_TABLE as CONTACT_EFFECT_ATTEMPT

from dataclasses import asdict
from ..authority_service.v3_owner_paid_guard_observation import GRAPH_TABLE,GRAPH_DDL_MAP
import hashlib
import json
from pathlib import Path
import sqlite3
from time import monotonic_ns

from ..runtime_contracts import canonical_digest,canonical_serialize
from .c09_paged_capture_contract_v2 import (GraphRebaseCandidateV2,GraphErasureRebaseCertificateV2,
    C09SealedStreamLocatorV2,C09StreamIdentityV2,c09_paged_value_from_wire_v2,c09_paged_value_to_wire_v2)
from .c09_paged_sql_v2 import (c09_sql_meter_quantum_v2,C09PagedCaptureHold,require_c09_reserved_meter_v3,capture_transaction_v2,
    read_c09_next_schema_object_v2,apply_c09_schema_object_v2,
    begin_c09_stream_verification_v2,advance_verify_c09_census_v2,advance_verify_c09_stream_v2,
    read_c09_table_shape_v2,_bounded_capture_row,begin_capture_stream_v2,advance_c09_census_v2,advance_c09_rows_v2,
    seal_capture_stream_v2,read_capture_cursor_v2,current_c09_sql_meter_v2,C09RowTransformResultV2,c09_row_commitment_v2)
from .c09_closure_index_v2 import CLOSURE_TABLES_V2
from .c09_domain_original_index_v2 import DOMAIN_INDEX_TABLES_V2

GRAPH_BUILD_DDL_V2="CREATE TABLE c09_graph_build_progress_v2 (scope_digest TEXT PRIMARY KEY, phase TEXT NOT NULL, progress_json TEXT NOT NULL)"
GRAPH_DISPOSITION_DDL_V2="CREATE TABLE c09_graph_dispositions_v2 (scope_digest TEXT NOT NULL, table_name TEXT NOT NULL, key_digest TEXT NOT NULL, source_primary_key_json TEXT NOT NULL, old_commitment TEXT NOT NULL, disposition TEXT NOT NULL, new_commitment TEXT, origin_stream_id TEXT NOT NULL, origin_record_ordinal INTEGER NOT NULL, PRIMARY KEY(scope_digest,table_name,key_digest))"
GRAPH_DISPOSITION_COLUMNS_V2=('scope_digest','table_name','key_digest','source_primary_key_json','old_commitment','disposition','new_commitment','origin_stream_id','origin_record_ordinal')
GRAPH_DISPOSITION_COLUMNS_V3=GRAPH_DISPOSITION_COLUMNS_V2+('source_logical_row_descriptor_digest','target_cell_seal_digest','logical_equivalence_original_digest','original_json')
GRAPH_DISPOSITION_DDL_V3="CREATE TABLE c09_graph_dispositions_v3 (scope_digest TEXT NOT NULL, table_name TEXT NOT NULL, key_digest TEXT NOT NULL, source_primary_key_json TEXT NOT NULL, old_commitment TEXT NOT NULL, disposition TEXT NOT NULL CHECK(disposition='logical_preserved_v3'), new_commitment TEXT NOT NULL, origin_stream_id TEXT NOT NULL, origin_record_ordinal INTEGER NOT NULL, source_logical_row_descriptor_digest TEXT NOT NULL, target_cell_seal_digest TEXT NOT NULL, logical_equivalence_original_digest TEXT NOT NULL, original_json TEXT NOT NULL, PRIMARY KEY(scope_digest,table_name,key_digest))"
GRAPH_DISPOSITION_TRIGGERS_V3=tuple((f'c09_graph_dispositions_v3_no_{action.lower()}',f"CREATE TRIGGER c09_graph_dispositions_v3_no_{action.lower()} BEFORE {action} ON c09_graph_dispositions_v3 BEGIN SELECT RAISE(ABORT,'logical disposition original is immutable'); END") for action in ('UPDATE','DELETE'))
GRAPH_DIRECTORY_DDL_V2="CREATE TABLE c09_graph_stream_directory_v2 (scope_digest TEXT NOT NULL, directory_kind TEXT NOT NULL, family TEXT NOT NULL, identity_json TEXT NOT NULL, complete_json TEXT NOT NULL, PRIMARY KEY(scope_digest,directory_kind,family))"
GRAPH_PROOF_DDLS_V2={'c09_graph_dispositions_v3':GRAPH_DISPOSITION_DDL_V3,'c09_graph_build_progress_v2':GRAPH_BUILD_DDL_V2,'c09_graph_dispositions_v2':GRAPH_DISPOSITION_DDL_V2,'c09_graph_stream_directory_v2':GRAPH_DIRECTORY_DDL_V2}
GRAPH_PROOF_TABLES_V2=frozenset(GRAPH_PROOF_DDLS_V2)

GRAPH_GENERATED_DDL_V2="CREATE TABLE c09_graph_generated_rows_v2 (scope_digest TEXT NOT NULL,table_name TEXT NOT NULL,key_digest TEXT NOT NULL,key_json TEXT NOT NULL,row_commitment TEXT NOT NULL,producer TEXT NOT NULL,origin_ref TEXT NOT NULL,origin_digest TEXT NOT NULL,PRIMARY KEY(scope_digest,table_name,key_digest))"
GRAPH_GENERATED_TABLES_V2=frozenset({'c09_graph_generated_rows_v2'})
GRAPH_PROOF_DDLS_V2['c09_graph_generated_rows_v2']=GRAPH_GENERATED_DDL_V2
GRAPH_PROOF_TABLES_V2=frozenset(GRAPH_PROOF_DDLS_V2)
_GRAPH_DIRECTORY_FIELDS_V2=('schema_catalogue','disposition_directory','closure','tombstones','target_directory','generated_directory')

GRAPH_SCHEMA_DDL_V2="CREATE TABLE c09_graph_target_schema_v2 (scope_digest TEXT NOT NULL,object_type TEXT NOT NULL,object_name TEXT NOT NULL,table_name TEXT NOT NULL,target_sql TEXT NOT NULL,PRIMARY KEY(scope_digest,object_type,object_name))"
GRAPH_NESTED_DIRECTORY_DDLS_V2={
    name:"CREATE TABLE "+name+" (scope_digest TEXT NOT NULL,family TEXT NOT NULL,identity_json TEXT NOT NULL,complete_json TEXT NOT NULL,PRIMARY KEY(scope_digest,family))"
    for name in ('c09_graph_disposition_directory_v2','c09_graph_target_directory_v2','c09_graph_closure_directory_v2')}
GRAPH_PROOF_DDLS_V2.update(GRAPH_NESTED_DIRECTORY_DDLS_V2)
GRAPH_PROOF_DDLS_V2['c09_graph_target_schema_v2']=GRAPH_SCHEMA_DDL_V2
from .c09_contact_plan_prefix_history_v3 import DDL_MAP as CONTACT_PREFIX_DDLS_V3
GRAPH_PROOF_DDLS_V2.update(CONTACT_PREFIX_DDLS_V3)
GRAPH_PROOF_TABLES_V2=frozenset(GRAPH_PROOF_DDLS_V2)
_GRAPH_DIRECTORY_TABLES_V2=('c09_graph_target_schema_v2','c09_graph_disposition_directory_v2',
    'c09_graph_closure_directory_v2','graph_c09_erased_keys_v1','c09_graph_target_directory_v2','c09_graph_generated_rows_v2')
_GRAPH_DIRECTORY_KINDS_V2=('schema_catalogue','row_dispositions','dependency_closure','tombstones','target_rows','generated_rows')
GRAPH_TOMBSTONE_DDL_V2="CREATE TABLE graph_c09_erased_keys_v1 (bot TEXT NOT NULL, persona TEXT NOT NULL, key_digest TEXT NOT NULL, maintenance_generation INTEGER NOT NULL, operation_id TEXT NOT NULL, PRIMARY KEY(bot,persona,key_digest))"
GRAPH_CERTIFICATE_DDL_V2="CREATE TABLE graph_c09_rebase_certificates_v2 (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,certificate_json TEXT NOT NULL,issue_digest TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id))"



CLOSURE_VERIFICATION_CONTROL_DDLS_V2={
 'c09_graph_closure_verification_runs_v2':"CREATE TABLE c09_graph_closure_verification_runs_v2 (verification_run_id TEXT PRIMARY KEY,scope_digest TEXT NOT NULL,candidate_digest TEXT NOT NULL,source_digest TEXT NOT NULL,round INTEGER NOT NULL,member_generation INTEGER NOT NULL,round_generation INTEGER NOT NULL,phase TEXT NOT NULL CHECK(phase IN ('collect','expand','sealed')),cursor_json TEXT NOT NULL)",
 'c09_graph_closure_verification_members_v2':"CREATE TABLE c09_graph_closure_verification_members_v2 (verification_run_id TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('atom','source_id','operation','domain_link','row')),ref TEXT NOT NULL,added_round INTEGER NOT NULL,origin_stream_id TEXT NOT NULL,origin_record_ordinal INTEGER NOT NULL,origin_commitment TEXT NOT NULL,PRIMARY KEY(verification_run_id,kind,ref),FOREIGN KEY(verification_run_id) REFERENCES c09_graph_closure_verification_runs_v2(verification_run_id))",
 'c09_graph_closure_verification_edges_v2':"CREATE TABLE c09_graph_closure_verification_edges_v2 (verification_run_id TEXT NOT NULL,dependent_ref TEXT NOT NULL,dependency_ref TEXT NOT NULL,origin_stream_id TEXT NOT NULL,origin_record_ordinal INTEGER NOT NULL,origin_commitment TEXT NOT NULL,PRIMARY KEY(verification_run_id,dependent_ref,dependency_ref,origin_stream_id,origin_record_ordinal),FOREIGN KEY(verification_run_id) REFERENCES c09_graph_closure_verification_runs_v2(verification_run_id))"}
CLOSURE_VERIFICATION_CONTROL_INDEXES_V2=(
 "CREATE INDEX c09_graph_closure_verification_dependency_v2 ON c09_graph_closure_verification_edges_v2(verification_run_id,dependency_ref,dependent_ref)",
 "CREATE INDEX c09_graph_closure_verification_scope_v2 ON c09_graph_closure_verification_runs_v2(scope_digest,candidate_digest,source_digest,verification_run_id)")
CLOSURE_VERIFICATION_CONTROL_TRIGGERS_V2=()

_BUILD=object();_COLD=object();_SWEEP=object()


def _installed_pair(session):
    from ..authority_service.c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from ..authority_service.c09_role_capture_pair_v2 import InstalledC09RolePairV2,C09RolePairProgressV2
    if type(session) is not C09PagedCaptureSessionV2:raise TypeError('actual installed capture session required')
    session.require_current();pair=session.open_role_pair('graph')
    if type(pair) is C09RolePairProgressV2:return pair
    if type(pair) is not InstalledC09RolePairV2 or pair.source_original.role!='graph':
        raise C09PagedCaptureHold('actual registered Graph source/candidate pair required')
    pair.require_current()
    if pair.source_original.scope_digest!=session.scope.scope_digest:
        raise C09PagedCaptureHold('Graph role pair crossed its actual scope')
    return pair


def capture_prior_graph_certificate_v2(build):
    """Advance real source historical inspection; None means not yet complete."""
    if type(build) is not InstalledGraphRebaseBuildV2:raise TypeError('actual installed Graph build required')
    build.require_current();namespace=tuple(json.loads(build.scope.graph_namespace));source=build.pair.source
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            source.execute('BEGIN')
            try:
                present=False
                for table in ('graph_c09_rebase_certificates_v1','graph_c09_rebase_certificates_v2'):
                    if source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is None:continue
                    row=meter.read_fixed_row(source,table,('operation_id',),'bot=? AND persona=? ORDER BY operation_id COLLATE BINARY',namespace)
                    present=present or row is not None
            finally:source.rollback()
            if present and build.prior_view is None:
                from .c09_graph_originals_read_v5 import read_latest_verified_graph_certificate_view_v5
                if build.prior_reader is None:build.prior_reader=read_latest_verified_graph_certificate_view_v5(build.session,build.pair)
                if build.prior_reader is None:raise C09PagedCaptureHold('actual nonempty certificate history has no installed reader')
                build.prior_view=build.prior_reader.advance(budget=budget,meter=meter)
                if build.prior_view is None:return None
            details={'schema':'sylanne3.c09.prior-graph-certificate-inspection.v2','scope_digest':build.scope.scope_digest,
                'prior_schema':None if build.prior_view is None else build.prior_view.certificate_schema,
                'prior_digest':None if build.prior_view is None else build.prior_view.certificate_digest}
            build.require_current()
            return build.session._control.maintenance.control.record_build_original_v1(
                operation_id=build.scope.operation_id,kind='capture_prior_graph_certificate_v2',details=details)


def _install_graph_proof_schema(candidate):
    """Install only fixed registered objects, metering each actual read/write."""
    from .c09_paged_sql_v2 import CAPTURE_DDLS_V2,CAPTURE_TRIGGERS_V2
    from .c09_closure_index_v2 import CLOSURE_DDLS_V2
    from .c09_domain_original_index_v2 import DOMAIN_INDEX_DDL_V2
    from .c09_graph_originals_read_v5 import PRIOR_GRAPH_VIEW_DDLS_V2
    from .c09_owner_source_output_mappings_v3 import TABLE as OUTPUT_TABLE,DDL as OUTPUT_DDL,DDL_MAP as OUTPUT_DDLS
    meter=current_c09_sql_meter_v2()
    tables={**CAPTURE_DDLS_V2,**CLOSURE_DDLS_V2,
        'c09_domain_original_lookup_v2':DOMAIN_INDEX_DDL_V2,**PRIOR_GRAPH_VIEW_DDLS_V2,**GRAPH_PROOF_DDLS_V2,
        'graph_c09_erased_keys_v1':GRAPH_TOMBSTONE_DDL_V2,
        'graph_c09_rebase_certificates_v2':GRAPH_CERTIFICATE_DDL_V2,OUTPUT_TABLE:OUTPUT_DDL}
    for name,ddl in tables.items():
        saved=meter.read_fixed_row(candidate,'sqlite_master',('sql',),"type='table' AND name=?",(name,))
        if saved is None:meter.charge_write(len(ddl.encode('utf-8')));candidate.execute(ddl)
        elif saved!=(ddl,):raise C09PagedCaptureHold('registered fixed Graph bootstrap table differs: '+name)
    from .c09_contact_plan_prefix_history_v3 import INDEX as CONTACT_PREFIX_INDEX
    saved=meter.read_fixed_row(candidate,'sqlite_master',('sql',),"type='index' AND name=?",('c09_contact_prefix_operation_v3',))
    if saved is None:meter.charge_write(len(CONTACT_PREFIX_INDEX.encode()));candidate.execute(CONTACT_PREFIX_INDEX)
    elif saved!=(CONTACT_PREFIX_INDEX,):raise C09PagedCaptureHold('Contact prefix operation lookup index differs')
    for name,ddl in (*CAPTURE_TRIGGERS_V2,*GRAPH_DISPOSITION_TRIGGERS_V3):
        saved=meter.read_fixed_row(candidate,'sqlite_master',('sql',),"type='trigger' AND name=?",(name,))
        if saved is None:meter.charge_write(len(ddl.encode('utf-8')));candidate.execute(ddl)
        elif saved!=(ddl,):raise C09PagedCaptureHold('registered immutable Graph bootstrap trigger differs')



class InstalledGraphRebaseBuildV2:
    __slots__=('_issuer', 'session', 'pair', 'scope', 'prior_reader', 'prior_view', 'barrier_view', 'hash_file', 'hash_identity', 'hash_value', 'hash_offset', 'candidate_done', 'source_disposition_view', 'historical_verification', 'source_row_capture_v3', 'segmented_target_v3', 'segmented_writer_v3', 'segmented_seal_v3', 'target_prior_checked_v3', 'marker_cause_capture_v3', 'mapped_source_scope_v3', 'mapped_source_shapes_v3', 'source_container_reader_v3', 'source_container_proof_v3', 'pre_graph_core_source_v3', 'pre_graph_owner_links_v3', 'pre_graph_history_reader_v3', 'owner_output_publisher_v3', 'owner_family_mode_v3', 'owner_family_reader_v3', 'owner_family_proof_v3', 'contact_plan_birth_reader_v3', 'contact_plan_birth_after_v3', 'contact_plan_birth_complete_v3', 'contact_plan_birth_proofs_v3', 'contact_plan_target_v3', 'contact_plan_birth_capture_v3', 'contact_prefix_source_v3', 'contact_prefix_publisher_v3', 'contact_prospective_reader_v1', 'contact_prospective_after_v1', 'contact_prospective_table_v1', 'contact_prospective_complete_v1', 'contact_prospective_proofs_v1', 'world_producer_capture_v1', 'b3_managed_metadata_proof_v1')
    def __init__(self,token,session,pair):
        if token is not _BUILD:raise TypeError('installed Graph builder is not caller constructible')
        self._issuer=token;self.session=session;self.pair=pair;self.scope=session.scope
        self.prior_reader=None;self.prior_view=None;self.barrier_view=None
        self.source_row_capture_v3=None;self.owner_output_publisher_v3=None;self.world_producer_capture_v1=None
        self.contact_plan_birth_reader_v3=None;self.contact_plan_birth_capture_v3=None;self.contact_plan_birth_after_v3=('','','')
        self.contact_plan_birth_complete_v3=False;self.contact_plan_birth_proofs_v3={};self.contact_plan_target_v3=None
        self.contact_prospective_reader_v1=None;self.contact_prospective_after_v1=None;self.contact_prospective_table_v1=0
        self.contact_prospective_complete_v1=False;self.contact_prospective_proofs_v1={}
        self.b3_managed_metadata_proof_v1=None
        self.contact_prefix_source_v3=self.contact_prefix_publisher_v3=None
        self.owner_family_mode_v3=self.owner_family_reader_v3=self.owner_family_proof_v3=None
        self.mapped_source_scope_v3=None;self.mapped_source_shapes_v3={}
        self.source_container_reader_v3=self.source_container_proof_v3=None
        self.pre_graph_core_source_v3=self.pre_graph_owner_links_v3=self.pre_graph_history_reader_v3=None
        self.segmented_target_v3=None;self.segmented_writer_v3=None;self.segmented_seal_v3=None;self.target_prior_checked_v3=False;self.marker_cause_capture_v3=None
        self.hash_file=None;self.hash_identity=None;self.hash_value=None;self.hash_offset=0;self.candidate_done=None;self.source_disposition_view=None;self.historical_verification=None
    def require_current(self):
        self.session.require_current();self.pair.require_current()
        if self._issuer is not _BUILD:raise C09PagedCaptureHold('Graph builder identity changed')
        return self.scope
    def read_progress(self):
        self.require_current()
        row=_bounded_capture_row(self.pair.candidate,'c09_graph_build_progress_v2',('phase','progress_json'),
            'scope_digest=?',(self.scope.scope_digest,),(32,65536))
        if row is None:raise C09PagedCaptureHold('actual Graph build progress absent')
        return row[0],json.loads(row[1])


def begin_current_graph_rebase_candidate_v2(session):
    pair=_installed_pair(session)
    from ..authority_service.c09_role_capture_pair_v2 import C09RolePairProgressV2
    if type(pair) is C09RolePairProgressV2:return pair
    from ..segmented_sql_cell_v1 import open_c09_segmented_target_v1
    target=open_c09_segmented_target_v1(session,pair)
    with target.quantum() as quantum:target.install_empty_layout(quantum)
    with session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter),capture_transaction_v2(pair.candidate):
            _install_graph_proof_schema(pair.candidate)
            from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
            ddl=GRAPH_REF_DDLS_V3['graph_d09_turn_slot_origins_v3']
            actual=meter.read_fixed_row(pair.candidate,'sqlite_master',('sql',),'type=? AND name=?',('table','graph_d09_turn_slot_origins_v3'))
            if actual is None:pair.candidate.execute(ddl);meter.charge_write(len(ddl.encode()))
            elif actual!=(ddl,):raise C09PagedCaptureHold('registered GraphV3 turn-slot origin table differs')
            raw=canonical_serialize({'object_key':None,'table':None,'cursor_digest':None})
            prior=meter.read_fixed_row(pair.candidate,'c09_graph_build_progress_v2',('phase','progress_json'),
                'scope_digest=?',(session.scope.scope_digest,))
            if prior is None:
                meter.write_row(pair.candidate,'c09_graph_build_progress_v2',('scope_digest','phase','progress_json'),
                    (session.scope.scope_digest,'schema',raw))
            if monotonic_ns()-meter.started_ns>budget.max_local_ns:
                raise C09PagedCaptureHold('actual fixed Graph bootstrap exceeded its installed reserved quantum')
    build=InstalledGraphRebaseBuildV2(_BUILD,session,pair)
    build.segmented_target_v3=target
    return build


def advance_current_graph_rebase_candidate_v2(build):
    """Advance the real registered build, preserving strict unknown-codec HOLD."""
    if type(build) is not InstalledGraphRebaseBuildV2:raise TypeError('actual installed Graph build required')
    build.require_current();phase,progress=build.read_progress();started=monotonic_ns()
    if build.candidate_done is not None:
        build.require_current();return build.candidate_done
    if _advance_source_container_census_for_graph_v3(build):return {'status':'progress','phase':'source_container_census'}
    if _advance_graph_owner_family_qualification_v3(build):return {'status':'progress','phase':'owner_family_source_qualification'}
    if _advance_graph_pre_graph_owner_qualification_v3(build):return {'status':'progress','phase':'pre_graph_owner_qualification'}
    if phase=='index':return _advance_graph_original_index_v2(build,progress)
    if phase=='closure':
        from .c09_contact_plan_birth_v3 import advance_contact_plan_birth_v3
        if advance_contact_plan_birth_v3(build):
            return {'status':'progress','phase':'contact_plan_birth'}
        from .c09_contact_prospective_history_v1 import advance_contact_prospective_history_v1
        if advance_contact_prospective_history_v1(build):
            return {'status':'progress','phase':'contact_prospective_history'}
        if build.session._control.maintenance.control.read_build_original_v1(operation_id=build.scope.operation_id,kind='capture_prior_graph_certificate_v2') is None:
            result=capture_prior_graph_certificate_v2(build)
            if result is None:return {'status':'progress','phase':'prior_certificate'}
        return _advance_graph_closure_v2(build,progress)
    if phase=='target':return _advance_graph_target_v2(build,progress)
    if phase=='owner_outputs':return _advance_graph_owner_outputs_v3(build,progress)
    if phase=='contact_prefix_history':
        from .c09_contact_plan_prefix_history_v3 import advance_contact_prefix_history_stage_v3
        return advance_contact_prefix_history_stage_v3(build,progress)
    if phase=='generated':return _advance_graph_generated_v2(build,progress)
    if phase=='deferred_schema':return _advance_deferred_graph_schema_v2(build,progress)
    if phase=='nested_directories':return _advance_graph_nested_directories_v2(build,progress)
    if phase=='schema_catalogue':return _advance_graph_target_schema_v2(build,progress)
    if phase=='directories':return _advance_graph_six_directories_v2(build,progress)
    if phase=='candidate_hash':return _advance_graph_candidate_hash_v2(build,progress)
    if phase!='schema':
        raise C09PagedCaptureHold('Graph '+phase+' requires its complete registered row/closure producer')
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget);candidate=build.pair.candidate;source=build.pair.source
        after=None if progress['object_key'] is None else tuple(progress['object_key'])
        from .c09_graph_rebase_candidate_v1 import _KNOWN
        from .c09_paged_sql_v2 import CAPTURE_TABLES_V2
        from .c09_source_plan_barrier_v2 import SOURCE_PLAN_BARRIER_TABLES_V2
        from .c09_graph_originals_read_v5 import PRIOR_GRAPH_VIEW_TABLES_V2
        from .domain_production_originals_v1 import PHYSICAL_TABLE,PHYSICAL_DDL
        from .c09_owner_source_output_mappings_v3 import TABLE as OUTPUT_TABLE,DDL_MAP as OUTPUT_DDLS
        from ..authority_service.c09_source_physical_read_v3 import source_owner_storage_catalogue_v3
        owner_catalogue={(kind,name):ddl for kind,name,ddl in source_owner_storage_catalogue_v3()}
        owner_tables={name for kind,name,ddl in source_owner_storage_catalogue_v3() if kind=='table'}
        known={OUTPUT_TABLE}|{GRAPH_TABLE}|owner_tables|(_KNOWN|{PHYSICAL_TABLE})|CAPTURE_TABLES_V2|CLOSURE_TABLES_V2|DOMAIN_INDEX_TABLES_V2|GRAPH_PROOF_TABLES_V2|SOURCE_PLAN_BARRIER_TABLES_V2|PRIOR_GRAPH_VIEW_TABLES_V2
        count=0
        with c09_sql_meter_quantum_v2(meter):
            source.execute('BEGIN')
            try:
                with capture_transaction_v2(candidate):
                    # Tables are installed before their indexes/triggers. The
                    # catalogue stream later verifies every object and its order.
                    while count<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
                        obj=read_c09_next_schema_object_v2(source,after,max_bytes=meter.remaining_bytes)
                        if obj is None:
                            candidate.execute("UPDATE c09_graph_build_progress_v2 SET phase='index',progress_json=? WHERE scope_digest=?",
                                (canonical_serialize({'object_key':None,'table':None,'cursor_digest':None}),build.scope.scope_digest));phase='index';break
                        if obj.table_name==PHYSICAL_TABLE and (obj.object_type!='table' or obj.sql!=PHYSICAL_DDL.replace(' IF NOT EXISTS','')):
                            raise C09PagedCaptureHold('actual DomainSource registered physical DDL differs')
                        if obj.table_name in owner_tables and owner_catalogue.get((obj.object_type,obj.name))!=obj.sql:
                            raise C09PagedCaptureHold('formal Owner Source storage schema differs')
                        if obj.table_name==GRAPH_TABLE and GRAPH_DDL_MAP.get(obj.name)!=obj.sql:
                            raise C09PagedCaptureHold('formal paid Owner Graph schema differs')
                        from ..segmented_sql_cell_v1 import DDLS as PHYSICAL_CONTAINERS
                        if obj.table_name in PHYSICAL_CONTAINERS:
                            build.source_container_proof_v3.require_current(meter=meter)
                            build.source_container_proof_v3.require_source_identity_v3(build.mapped_source_scope_v3)
                            after=obj.primary_key;progress['object_key']=after;count+=1
                            continue
                        if obj.table_name==OUTPUT_TABLE and OUTPUT_DDLS.get(obj.name)!=obj.sql:
                            raise C09PagedCaptureHold('prior Owner output mapping registered DDL differs')
                        from .contact_background_scheduler_v3 import TABLE as scheduler_table,DDL as scheduler_ddl
                        if obj.table_name == scheduler_table and (obj.object_type != 'table' or obj.sql != scheduler_ddl):
                            raise C09PagedCaptureHold('Contact durable scheduler exact schema differs')
                        from .contact_plan_adoption_v3 import TABLE as PLAN3,DDL_MAP as PLAN3_DDLS
                        from .contact_plan_physical_write_v3 import STREAM_TABLE,STREAM_DDL
                        if obj.table_name==STREAM_TABLE and obj.object_type=='table' and obj.sql!=STREAM_DDL:
                            raise C09PagedCaptureHold('Contact Plan3 exact staged stream schema differs')
                        if obj.table_name == PLAN3 and obj.object_type in {'table','trigger'}:
                            if PLAN3_DDLS.get(obj.name) != obj.sql:
                                raise C09PagedCaptureHold('Contact Plan3 exact schema/immutable trigger differs')
                        if obj.table_name not in known:raise C09PagedCaptureHold('unregistered Graph table schema: '+obj.table_name)
                        meter.charge_read(len(obj.sql.encode('utf-8')))
                        if obj.object_type=='table':
                            from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
                            if obj.name in {'graph_atoms','graph_history'}:
                                ddl=GRAPH_REF_DDLS_V3[obj.name]
                                actual=meter.read_fixed_row(candidate,'sqlite_master',('sql',),'type=? AND name=?',('table',obj.name))
                                if actual is None:
                                    candidate.execute(ddl);meter.charge_write(len(ddl.encode()))
                                elif actual!=(ddl,):raise C09PagedCaptureHold('registered GraphV3 reference table differs')
                            else:
                                apply_c09_schema_object_v2(candidate,obj,verify_installed_object=lambda actual: _require_known_graph_object(actual,known))
                                meter.charge_write(len(obj.sql.encode('utf-8')))
                        after=obj.primary_key;progress['object_key']=after;count+=1
                    if phase=='schema':_save_graph_progress_v2(build,'schema',progress,meter)
            finally:source.rollback()
    build.require_current()
    return {'status':'progress','phase':phase,'scope_digest':build.scope.scope_digest,'completed_records':count,
        'actual_io_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
        'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def _begin_graph_source_capture_v3(build,shape,key,metadata,**profile):
    from .c09_graph_row_codec_v2 import C09MemorySourceRowCaptureV3,C09MappedGraphRowCaptureV3
    from .c09_domain_original_source_v3 import C09MappedDomainOriginalCaptureV3
    if shape.table=='graph_contact_expression_plan_originals_v3':
        from .c09_contact_plan_physical_v3 import C09MappedContactPlanCaptureV3
        return C09MappedContactPlanCaptureV3(build,shape,key,metadata,**profile)
    if shape.table=='graph_domain_production_originals_v3':
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        actual=current_c09_sql_meter_v2().read_fixed_row(build.pair.source,shape.table,('domain','operation_kind'),
            'bot=? AND persona=? AND operation_id=?',tuple(key))
        if actual==('d08','adopt_contact_expression_plan_v2'):
            from .c09_contact_plan_physical_v3 import C09MappedContactDomainCaptureV3
            return C09MappedContactDomainCaptureV3(build,shape,key,metadata,**profile)
        return C09MappedDomainOriginalCaptureV3(build,shape,key,metadata,**profile)
    kind=C09MappedGraphRowCaptureV3 if 'value_cell_id' in shape.columns else C09MemorySourceRowCaptureV3
    return kind(build,shape,key,metadata,**profile)


def _mapped_graph_source_shape_v3(build,shape,meter):
    if shape.table not in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3') and (shape.table not in ('graph_atoms','graph_history') or 'value_cell_id' not in shape.columns):
        return None
    from .c09_logical_source_v3 import read_c09_logical_source_shape_v3
    if build.mapped_source_scope_v3 is None:
        build.mapped_source_scope_v3=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
    logical=build.mapped_source_shapes_v3.get(shape.table)
    if logical is None:
        logical=read_c09_logical_source_shape_v3(build.mapped_source_scope_v3,shape.table,meter=meter)
        build.mapped_source_shapes_v3[shape.table]=logical
    if logical.physical_shape!=shape:raise C09PagedCaptureHold('actual mapped Graph Source physical DDL changed')
    return logical


def _source_stream_identity_v2(build,shape,kind):
    logical=_mapped_graph_source_shape_v3(build,shape,current_c09_sql_meter_v2())
    return C09StreamIdentityV2(build.scope.scope_digest,build.pair.source_original.role_source_digest,
        kind,shape.table,shape.schema_digest if logical is None else logical.logical_shape_digest,
        shape.primary_key_columns,shape.primary_key_types)



def _advance_source_container_census_for_graph_v3(build):
    """Actual Source physical EOF; it never implies six-output target preservation."""
    from ..authority_service.c09_source_physical_read_v3 import begin_source_physical_container_census_v3
    scope=build.mapped_source_scope_v3;reader=build.source_container_reader_v3;proof=build.source_container_proof_v3
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            layout=meter.read_fixed_row(build.pair.source,'sqlite_master',('name',),'type=? AND name=?',('table','segmented_storage_layout_v1'))
            if layout is None:return False
            if proof is not None:proof.require_current(meter=meter);return False
            if scope is None:scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
            if reader is None:reader=begin_source_physical_container_census_v3(scope,meter=meter)
            else:
                reader=reader.advance_prospective_v3(meter)
                if reader.complete:proof=reader.proof
    build.mapped_source_scope_v3=scope;build.source_container_reader_v3=reader;build.source_container_proof_v3=proof
    return True

def _require_owner_source_metadata_row_for_graph_v3(build,shape,key,row,meter):
    from ..authority_service.c09_source_physical_read_v3 import source_owner_storage_catalogue_v3
    tables={name for kind,name,ddl in source_owner_storage_catalogue_v3() if kind=='table'}
    if shape.table not in tables:return False
    if build.mapped_source_scope_v3 is None:
        build.mapped_source_scope_v3=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
    proof=build.mapped_source_scope_v3.qualify_owner_source_storage_row_v3(shape.table,tuple(key),meter=meter)
    proof.require_current(meter=meter)
    if tuple(proof.row)!=tuple(row):raise C09PagedCaptureHold('Owner Source metadata row differs from actual private producer')
    return True


def _advance_graph_pre_graph_owner_qualification_v3(build):
    """Actual pre-Graph Source and all-link EOF; adopt only after reserve exit."""
    from ..authority_service.c09_pre_graph_core_dependency_source_v3 import (
        VerifiedPreGraphCoreDependencySourceV3,VerifiedPreGraphPaidOwnerLinksV3,
        begin_pre_graph_core_dependency_source_v3,advance_pre_graph_core_dependency_source_v3,
        begin_pre_graph_paid_owner_link_qualification_v3,advance_pre_graph_paid_owner_link_qualification_v3,
        begin_historical_pre_graph_paid_owner_links_v3)
    source,links,history=build.pre_graph_core_source_v3,build.pre_graph_owner_links_v3,build.pre_graph_history_reader_v3
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            from ..authority_service.v3_owner_paid_guard_observation import GRAPH_TABLE
            present=meter.read_fixed_row(build.pair.source,'sqlite_master',('name',),'type=? AND name=?',('table',GRAPH_TABLE))
            if present is None:return False
            if type(links) is VerifiedPreGraphPaidOwnerLinksV3:
                links.require_historical_current_v3(build.session,build.pair,meter=meter);return False
            complete=build.session._control.maintenance.control.read_build_original_v1(
                operation_id=build.scope.operation_id,kind='capture_pre_graph_paid_owner_links_complete_v3')
            if complete is not None:
                if history is None:history=begin_historical_pre_graph_paid_owner_links_v3(build.session,build.pair,meter=meter)
                else:
                    result=history.advance(meter)
                    if type(result) is VerifiedPreGraphPaidOwnerLinksV3:links=result
                    else:history=result
            elif source is None:source=begin_pre_graph_core_dependency_source_v3(build.session,build.pair,meter=meter)
            elif type(source) is not VerifiedPreGraphCoreDependencySourceV3:
                source=advance_pre_graph_core_dependency_source_v3(source,meter=meter)
            elif links is None:links=begin_pre_graph_paid_owner_link_qualification_v3(source,build.pair,meter)
            else:links=advance_pre_graph_paid_owner_link_qualification_v3(links,meter=meter)
    build.pre_graph_core_source_v3,build.pre_graph_owner_links_v3,build.pre_graph_history_reader_v3=source,links,history
    return True

def _require_paid_owner_graph_source_row_v3(build,shape,row,meter):
    from ..authority_service.v3_owner_paid_guard_observation import GRAPH_TABLE,GRAPH_COLUMNS,validate_paid_owner_guard_link_row_v3
    from ..authority_service.c09_pre_graph_core_dependency_source_v3 import VerifiedPreGraphPaidOwnerLinksV3
    if shape.table!=GRAPH_TABLE:return False
    if shape.columns!=GRAPH_COLUMNS:raise C09PagedCaptureHold('actual paid Owner link physical columns differ')
    validate_paid_owner_guard_link_row_v3(tuple(row))
    proof=build.pre_graph_owner_links_v3
    if type(proof) is not VerifiedPreGraphPaidOwnerLinksV3:
        raise C09PagedCaptureHold('actual all-link Core dependency EOF qualification required')
    proof.require_historical_current_v3(build.session,build.pair,meter=meter)
    proof.require_row_v3(tuple(row[:4]),tuple(row),meter=meter)
    return True

def _advance_graph_original_index_v2(build,progress):
    build.require_current();source=build.pair.source;candidate=build.pair.candidate;started=monotonic_ns()
    streamed_source=False;pending_capture=None
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            if progress['table'] is None:
                table=_next_graph_logical_source_table_v3(build,None)
                if table is None:raise C09PagedCaptureHold('actual frozen Graph source has no tables')
                progress.update(table=table,scan_phase='census')
            shape=read_c09_table_shape_v2(source,progress['table']);stream=_source_stream_identity_v2(build,shape,'graph_facts')
            with capture_transaction_v2(candidate):begin_capture_stream_v2(candidate,stream)
            logical_shape=_mapped_graph_source_shape_v3(build,shape,meter)
            census_phase=progress.get('scan_phase','census')=='census'
            if logical_shape is not None:
                if census_phase:
                    result=advance_c09_census_v2(source,candidate,stream,logical_shape,budget,
                        check_frozen_source=build.pair.check_source,meter=meter)
                    if result['eof']:progress['scan_phase']='rows'
                else:
                    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2,capture_read_transaction_v2
                    from .c09_graph_row_codec_v2 import C09MappedGraphRowCaptureV3
                    capture=build.source_row_capture_v3
                    if capture is None:
                        cursor=read_capture_cursor_v2(candidate,stream)
                        with capture_read_transaction_v2(source):found=read_c09_next_row_metadata_v2(source,shape,cursor.last_key)
                        if found is not None:
                            key,metadata=found;capture=_begin_graph_source_capture_v3(build,shape,key,metadata)
                    if capture is not None:
                        if not (capture.row.complete and capture.value.complete):
                            capture=capture.next_quantum(budget)
                            result={'status':'progress','completed_records':0,'eof':False,'actual_io_bytes':meter.consumed_bytes}
                        else:
                            from .c09_paged_sql_v2 import append_completed_memory_source_capture_v3
                            result=append_completed_memory_source_capture_v3(build,stream,shape,budget,completed=capture,meter=meter)
                            capture=None
                        pending_capture=capture;streamed_source=True
                    else:
                        result=advance_c09_rows_v2(source,candidate,stream,logical_shape,budget,
                            check_frozen_source=build.pair.check_source,
                            stream_row_boundary=lambda actual_shape,key,metadata:True,meter=meter)
            else:
                if progress.get('scan_phase','census')=='census':
                    result=advance_c09_census_v2(source,candidate,stream,shape,budget,
                        check_frozen_source=build.pair.check_source,meter=meter)
                    if result['eof']:progress['scan_phase']='rows'
                else:
                    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2,capture_read_transaction_v2
                    capture=build.source_row_capture_v3
                    if capture is None and shape.table in {'graph_atoms','graph_history'}:
                        cursor=read_capture_cursor_v2(candidate,stream)
                        with capture_read_transaction_v2(source):
                            found=read_c09_next_row_metadata_v2(source,shape,cursor.last_key)
                            if found is not None:
                                key,metadata=found
                                from ..graph_types import AtomKey
                                if (sum(size or 0 for _,size in metadata)*9>budget.max_bytes
                                        and AtomKey.from_token(key[0]).type_name=='memory.source'):
                                    from .c09_graph_row_codec_v2 import C09MemorySourceRowCaptureV3
                                    capture=_begin_graph_source_capture_v3(build,shape,key,metadata)
                    if capture is not None:
                        if not (capture.row.complete and capture.value.complete):
                            capture=capture.next_quantum(budget)
                        else:
                            from .c09_paged_sql_v2 import append_completed_memory_source_capture_v3
                            result=append_completed_memory_source_capture_v3(build,stream,shape,budget,completed=capture,meter=meter)
                            capture=None
                        pending_capture=capture
                        # Retain prospective hash/parser state only after the actual
                        # reserved batch's exit succeeds below.
                        streamed_source=True
                    else:
                        streamed_source=False
                    def index_row(db,actual_shape,key,row,remaining):
                        active=current_c09_sql_meter_v2()
                        _index_actual_graph_original_row_v2(build,stream,actual_shape,key,row,budget,active)
                        from .c09_paged_sql_v2 import c09_row_commitment_v2
                        # Parent meter records actual SQL/encoding once; logical
                        # callback counters are not added to it a second time.
                        return C09RowTransformResultV2(c09_row_commitment_v2(row),0,0)
                    if not streamed_source:
                        def source_boundary(actual_shape,key,metadata):
                            if actual_shape.table not in {'graph_atoms','graph_history'}:return False
                            from ..graph_types import AtomKey
                            return (sum(size or 0 for _,size in metadata)*9>budget.max_bytes
                                and AtomKey.from_token(key[0]).type_name=='memory.source')
                        result=advance_c09_rows_v2(source,candidate,stream,shape,budget,
                            check_frozen_source=build.pair.check_source,transform_row=index_row,
                            stream_row_boundary=source_boundary,meter=meter)
                    elif pending_capture is not None:
                        result={'status':'progress','completed_records':0,'eof':False,'actual_io_bytes':meter.consumed_bytes}
            if not census_phase and result['eof']:
                with capture_transaction_v2(candidate):
                    complete=seal_capture_stream_v2(candidate,stream)
                    _directory_put_legacy_v2(build,'source_originals',stream,complete,meter)
                following=_next_graph_logical_source_table_v3(build,shape.table)
                progress.update(table=following,scan_phase='census')
                if following is None:
                    with capture_transaction_v2(candidate):
                        _save_graph_progress_v2(build,'closure',
                            {'round':0,'table':None,'row_key':None,'pattern_kind':'atom','pattern_after':None},meter)
                    return _graph_step_report_v2(build,'closure',meter,started)
            with capture_transaction_v2(candidate):_save_graph_progress_v2(build,'index',progress,meter)
            result.update(status='progress',phase='index',table=shape.table,actual_meter_bytes=meter.consumed_bytes,
                local_ns=monotonic_ns()-started,
                resource_quantum_within_limit=monotonic_ns()-started<=budget.max_local_ns and meter.consumed_bytes<=budget.max_bytes)
    if streamed_source:
        if pending_capture is not None:pending_capture.quantum_completed=True
        build.source_row_capture_v3=pending_capture
    build.require_current();return result


def _index_actual_graph_original_row_v2(build,stream,shape,key,row,budget,meter):
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    from .c09_graph_row_codec_v2 import read_c09_domain_row_v2
    from .c09_domain_original_index_v2 import C09DomainOriginalIndexV2
    from .c09_d04_originals_v3 import TABLE as D04
    from .c09_d07_execution_v1 import TABLE as D07
    from .c09_contact_originals_v1 import TABLE as CONTACT
    from .c09_contact_originals_v2 import TABLE as CONTACT2
    from .domain_production_erasure_v1 import TABLE_COLUMNS
    from .c09_paged_sql_v2 import current_c09_capture_row_position_v2
    actual_stream_id,actual_ordinal=current_c09_capture_row_position_v2()
    if actual_stream_id!=stream.stream_id:raise C09PagedCaptureHold('domain index origin belongs to another source stream')
    from .c09_b3_managed_metadata_v1 import index_b3_managed_original_v1
    index_b3_managed_original_v1(build,stream,shape,key,row,meter)
    # Index only declared domain families; Graph atoms/events are separately
    # validated and traversed by the closure and target codecs.
    from .domain_production_erasure_v1 import DERIVED_STORE_TABLES_V6
    from .contact_plan_adoption_v3 import TABLE as PLAN3
    if shape.table in (set(TABLE_COLUMNS)-set(DERIVED_STORE_TABLES_V6)) or shape.table in {D04,D07,CONTACT,CONTACT2,PLAN3,CONTACT_EFFECT_ORIGINAL}:
        decoded=read_c09_domain_row_v2(shape.table,shape.columns,row,
            authority_namespace=build.scope.authority_namespace,issuer=build.session.get_c09_domain_original_issuer_v2())
        index=C09DomainOriginalIndexV2(candidate=build.pair.candidate,source=build.pair.source,
            scope_digest=build.scope.scope_digest,family=shape.table,shape=shape,
            authority_namespace=build.scope.authority_namespace,issuer=build.session.get_c09_domain_original_issuer_v2(),budget=budget,
            verify_origin=lambda *args: (_ for _ in ()).throw(C09PagedCaptureHold('index production is not a verified membership read')))
        index.add_actual_row(key,row,decoded,row_commitment=_row_digest(row),origin_stream_id=stream.stream_id,
            origin_record_ordinal=actual_ordinal)
        meter.charge_write(len(canonical_serialize((build.scope.scope_digest,shape.table,key,decoded.kind,
            decoded.original_ref,decoded.original_commitment)).encode('utf-8')))


def _require_known_graph_object(original,known):
    from .c09_b3_managed_metadata_v1 import require_b3_managed_schema_object_v1
    if require_b3_managed_schema_object_v1(original):return
    from .c09_contact_effect_accounting_v1 import require_financial_schema_object_v1
    require_financial_schema_object_v1(original)
    if original.table_name not in known:raise C09PagedCaptureHold('unknown installed Graph schema object')


class VerifiedGraphRebaseColdV2:
    __slots__=('_issuer','session','pair','candidate','cold_read_digest','target_identity','target_file_sha256','_read_db','cold_phase','validated_mirror_digest','issued_digest','target_schema_digest','segmented_sweep_v3','source_disposition_view_v3','_closed')
    def __init__(self,token,session,pair,candidate,cold_digest,identity,file_sha,read_db,*,cold_phase,validated_mirror_digest,issued_digest,segmented_sweep,source_disposition_view):
        if token is not _COLD:raise TypeError('actual independently verified cold handle required')
        self._issuer=token;self.session=session;self.pair=pair;self.candidate=candidate
        self.cold_read_digest=cold_digest;self.target_identity=identity;self.target_file_sha256=file_sha;self._read_db=read_db
        self.cold_phase=cold_phase;self.validated_mirror_digest=validated_mirror_digest;self.issued_digest=issued_digest
        self.target_schema_digest=candidate.schema_catalogue.complete.digest
        from ..authority_service.c09_segmented_census_v3 import VerifiedSegmentedPhysicalSweepV3
        if type(segmented_sweep) is not VerifiedSegmentedPhysicalSweepV3 or segmented_sweep.bound.pair is not pair:
            raise C09PagedCaptureHold('actual Graph cold requires same-pair complete segmented physical sweep')
        if (type(source_disposition_view) is not VerifiedC09SourceDispositionV2
                or source_disposition_view.verified.pair is not pair
                or not source_disposition_view.verified.target_eof or not source_disposition_view.verified.source_eof
                or source_disposition_view.verified.phase!='file_hash'):
            raise C09PagedCaptureHold('final Graph handle lacks actual complete Source/target proof')
        self.source_disposition_view_v3=source_disposition_view
        self.segmented_sweep_v3=segmented_sweep;self._closed=False
    def require_current(self):
        if self._closed:raise C09PagedCaptureHold('actual Graph cold handle closed')
        self.session.require_current();self.pair.require_current()
        self.segmented_sweep_v3.require_current()
        stage,mirror,issued=_derive_actual_mirror_stage_v2(self.session,self.pair,self.candidate)
        if (stage,mirror,issued)!=(self.cold_phase,self.validated_mirror_digest,self.issued_digest):
            raise C09PagedCaptureHold('cold handle belongs to another actual mirror stage')
        stat=Path(self.pair.target_path).stat()
        if self._issuer is not _COLD or (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)!=self.target_identity:
            raise C09PagedCaptureHold('cold Graph candidate identity changed')
        return self.candidate
    def require_original_disposition_row_v3(self,table,primary_key,*,meter):
        self.require_current()
        result=self.source_disposition_view_v3.require_original_disposition_row_v3(table,primary_key,meter=meter)
        self.require_current();return result
    def close(self):
        if self._closed:return
        self._closed=True
        try:self._read_db.close()
        finally:self.segmented_sweep_v3.bound.close()


class GraphRebaseColdProgressV2:
    __slots__=('session', 'pair', 'candidate', 'read_db', 'locator_index', 'verification', 'table_verifications', 'file', 'file_hash', 'file_offset', 'done', 'phase', 'table_name', 'source_key', 'completed_rows', 'cold_phase', 'validated_mirror_digest', 'issued_digest', 'file_identity', 'target_table', 'target_key', 'directory_phase', 'directory_after', '_issuer', 'source_eof', 'target_eof', 'verified_directories', 'census_db', 'nested_field', 'nested_after', 'nested_locator', 'nested_verification', 'schema_key', 'schema_count', 'cold_build', 'pattern_progress', 'originals_after', 'originals_locator', 'originals_verification', 'source_semantic_eof', 'semantic_table', 'semantic_key', 'target_schema_eof', 'closure_semantic_eof', 'verification_run_id', 'closure_replay_phase', 'closure_replay_progress', 'prospective_source_capture_v3', 'cold_graph_cell_v3', 'prospective_marker_cause_capture_v3', 'segmented_census_v3', 'segmented_sweep_v3', 'logical_descriptor_after_v3', 'logical_descriptor_count_v3', 'domain_cold_cell_v3', 'prospective_domain_cell_v3', 'disposition_inventory_version_v3', 'disposition_inventory_after_v3', 'disposition_inventory_count_v3', 'owner_outputs_cold_reader_v3', 'prospective_owner_outputs_cold_v3', 'owner_outputs_cold_proof_v3', 'contact_plan_cold_cells_v3', 'prospective_contact_plan_cold_v3', 'contact_prefix_cold_v3', 'prospective_contact_prefix_cold_v3', 'contact_prefix_cold_proof_v3', 'prospective_world_producer_capture_v1')
    def __init__(self,token,session,pair,candidate):
        if token is not _SWEEP:raise TypeError('actual installed cold sweep required')
        self._issuer=token;self.source_eof=False;self.target_eof=False;self.verified_directories=0
        self.session=session;self.pair=pair;self.candidate=candidate
        self.read_db=sqlite3.connect(Path(pair.target_path).as_uri()+'?mode=ro',uri=True,isolation_level=None)
        self.read_db.execute('PRAGMA query_only=ON')
        self.census_db=sqlite3.connect(Path(pair.target_path).as_uri()+'?mode=ro',uri=True,isolation_level=None)
        self.census_db.execute('PRAGMA query_only=ON')
        self.nested_field=None;self.nested_after=None;self.nested_locator=None;self.nested_verification=None
        self.schema_key=None;self.schema_count=0
        self.cold_build=InstalledGraphRebaseBuildV2(_BUILD,session,pair)
        self.owner_outputs_cold_reader_v3=self.prospective_owner_outputs_cold_v3=self.owner_outputs_cold_proof_v3=None
        self.prospective_source_capture_v3=None;self.prospective_world_producer_capture_v1=None
        self.prospective_marker_cause_capture_v3=None
        self.segmented_census_v3=None;self.segmented_sweep_v3=None
        self.cold_graph_cell_v3=None;self.domain_cold_cell_v3=None;self.prospective_domain_cell_v3=None
        self.contact_plan_cold_cells_v3=self.prospective_contact_plan_cold_v3=None
        self.contact_prefix_cold_v3=self.prospective_contact_prefix_cold_v3=self.contact_prefix_cold_proof_v3=None
        self.pattern_progress={'pattern_kind':'atom','pattern_after':None,'nested_hit':False}
        self.originals_after=None;self.originals_locator=None;self.originals_verification=None
        self.logical_descriptor_after_v3="";self.logical_descriptor_count_v3=0
        self.disposition_inventory_version_v3=0;self.disposition_inventory_after_v3="";self.disposition_inventory_count_v3=0
        self.source_semantic_eof=False;self.semantic_table=None;self.semantic_key=None;self.target_schema_eof=False;self.closure_semantic_eof=False
        import secrets
        self.verification_run_id=secrets.token_hex(16);self.closure_replay_phase='edge_scan'
        self.closure_replay_progress={'seed_after':'','table':None,'row_key':None,'pattern_kind':'atom','pattern_after':None,'nested_hit':False}
        self.locator_index=0;self.verification=None;self.table_verifications=None
        self.file=None;self.file_hash=hashlib.sha256();self.file_offset=0;self.done=None
        self.phase='prior';self.table_name=None;self.source_key=None;self.completed_rows=0
        self.cold_phase,self.validated_mirror_digest,self.issued_digest=_derive_actual_mirror_stage_v2(session,pair,candidate)
        self.file_identity=None;self.target_table=None;self.target_key=None
        self.directory_phase='census';self.directory_after=None


def _derive_actual_mirror_stage_v2(session,pair,candidate):
    exists=pair.candidate.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_c09_rebase_certificates_v2'").fetchone()
    row=None
    if exists is not None:
        namespace=json.loads(session.scope.graph_namespace)
        row=_bounded_capture_row(pair.candidate,'graph_c09_rebase_certificates_v2',('certificate_json','issue_digest'),
            'bot=? AND persona=? AND operation_id=?',(*namespace,session.scope.operation_id),(65536,64))
    if row is None:return 'pre_mirror',None,None
    # A caller cannot choose post_mirror. The actual Graph row must join the
    # independently signed same-Core issue and the real Control original.
    from ..authority_service.c09_graph_rebase_issue_v2 import _read_issue,_verify_signature,_wire
    maintenance=session._control.maintenance
    installed=maintenance.core._c09_maintenance_authority_v1
    if installed is None:raise C09PagedCaptureHold('actual installed Graph issue signer absent')
    actual_close=maintenance._closed_connection_originals_v3.get(id(maintenance.core))
    if actual_close is not None and actual_close[0] is maintenance.core:
        from contextlib import closing
        current=maintenance.control.read_verified_current_storage_v1(verify_files=False)
        member=next(item for item in current.manifest['members'] if item['role']=='core')
        maintenance.control.verify_member_v1(member,prepared=False)
        source_path=Path(member['resolved_path']).resolve(strict=True)
        if Path(actual_close[2]['path']).resolve(strict=True)!=source_path or source_path!=maintenance.core.path.resolve(strict=True):
            raise C09PagedCaptureHold('actual closed Core proof differs from selected old Core member')
        if any(Path(str(source_path)+suffix).exists() for suffix in ('-wal','-shm','-journal')):
            raise C09PagedCaptureHold('selected old Core has not crossed its clean close boundary')
        before=source_path.stat()
        with closing(sqlite3.connect(source_path.as_uri()+'?mode=ro&immutable=1',uri=True,isolation_level=None)) as db:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            issue=_read_issue(db,session.scope.authority_namespace,session.scope.operation_id)
        after=source_path.stat()
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
            raise C09PagedCaptureHold('selected immutable old Core changed during mirror verification')
        maintenance.control.verify_member_v1(member,prepared=False)
    else:
        with maintenance.core._tx() as db:
            issue=_read_issue(db,session.scope.authority_namespace,session.scope.operation_id)
    if issue is None:raise C09PagedCaptureHold('Graph mirror has no actual same-Core issue')
    _verify_signature(issue,installed[0])
    original=maintenance.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='graph_issued_v2')
    if original is None or original['details']!=_wire(issue):raise C09PagedCaptureHold('actual Control issued mirror original differs')
    expected=canonical_serialize(c09_paged_value_to_wire_v2(issue.certificate))
    if issue.certificate.candidate!=candidate or row!=(expected,issue.issue_digest):
        raise C09PagedCaptureHold('Graph mirror differs from the actual signed candidate issue')
    digest=canonical_digest(('sylanne3.c09.actual-graph-mirror.v2',session.scope.scope_digest,issue.issue_digest,issue.certificate.certificate_digest))
    return 'post_mirror',digest,issue.issue_digest


def begin_current_graph_rebase_cold_v2(session,candidate):
    if type(candidate) is not GraphRebaseCandidateV2:raise TypeError('exact versioned Graph candidate required')
    pair=_installed_pair(session)
    from ..authority_service.c09_role_capture_pair_v2 import C09RolePairProgressV2
    if type(pair) is C09RolePairProgressV2:raise C09PagedCaptureHold('actual Graph frozen source seal is incomplete')
    if (candidate.scope!=session.scope or candidate.source!=pair.source_original or candidate.target_path!=pair.target_path
            or candidate.new_incarnation!=pair.build_plan['new_incarnation']):
        raise C09PagedCaptureHold('candidate did not come from this actual registered build')
    # Authority may not enter through a caller DTO. The actual Control producer
    # original must commit this exact header before independently checking it.
    saved=session._control.maintenance.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='graph_candidate_v2')
    if saved is None or saved['details']!=c09_paged_value_to_wire_v2(candidate):
        raise C09PagedCaptureHold('actual Graph candidate producer original absent or different')
    return GraphRebaseColdProgressV2(_SWEEP,session,pair,candidate)


def _next_source_table_v2(source,after):
    row=source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name COLLATE BINARY > ? ORDER BY name COLLATE BINARY LIMIT 1",('' if after is None else after,)).fetchone()
    return None if row is None else row[0]


def _source_row_codec_v2(progress,shape,row):
    _validate_graph_source_row_v2(progress.session,shape,row)


def _read_graph_disposition_original_row_v3(db,scope_digest,table,key,meter):
    """Read the one authoritative version; reject duplicate version ownership."""
    args=(scope_digest,table,canonical_digest((table,key)));rows=[]
    for name,columns in (('c09_graph_dispositions_v2',GRAPH_DISPOSITION_COLUMNS_V2),
                         ('c09_graph_dispositions_v3',GRAPH_DISPOSITION_COLUMNS_V3)):
        present=meter.read_fixed_row(db,'sqlite_master',('sql',),'type=? AND name=?',('table',name))
        if present is None:continue
        if present!=(GRAPH_PROOF_DDLS_V2[name],):raise C09PagedCaptureHold('Graph disposition version schema differs')
        row=meter.read_fixed_row(db,name,columns,'scope_digest=? AND table_name=? AND key_digest=?',args)
        if row is not None:rows.append(tuple(row))
    if len(rows)>1:raise C09PagedCaptureHold('Graph row has duplicate V2/V3 authoritative dispositions')
    if not rows:return None
    if rows[0][3]!=canonical_serialize(key):raise C09PagedCaptureHold('Graph disposition full primary key differs')
    return rows[0]


def _graph_logical_preservation_original_v3(scope_digest,table,key,descriptor,source_header,header,new_commitment):
    """Recipe called only after real producer or independent cold qualification."""
    from ..graph_types import AtomKey
    if table=='graph_contact_expression_plan_originals_v3':
        from .c09_contact_plan_physical_v3 import contact_plan_logical_preservation_original_v3
        return contact_plan_logical_preservation_original_v3(scope_digest,key,descriptor,source_header,header,new_commitment)
    bindings=descriptor['cell_bindings']
    domain=table=='graph_domain_production_originals_v3';logical_column='original_payload_json' if domain else 'value'
    if len(bindings)!=1 or bindings[0]['logical_column']!=logical_column:
        raise C09PagedCaptureHold('logical preservation requires its registered single cell binding')
    binding=bindings[0]
    if 'source_header9' not in binding or tuple(binding['source_header9'])!=tuple(source_header):
        raise C09PagedCaptureHold('actual old Source Header9 original missing or changed')
    if domain:
        from ..runtime_contracts import NamespaceId
        from ..memory_types import source_key
        from .owner_material_source_v1 import owner_material_source_id_v1,AdmitOwnerMaterialSourceRequestV1
        from .domain_production_registry_v1 import installed_operation_v1
        ns=NamespaceId(*key[:2])
        owner_key=AtomKey.from_token(source_header[2])
        if owner_key.type_name=='d08.contact_expression_plan.v2':
            from .contact_plan_adoption_v2 import AdoptCurrentContactExpressionPlanRequestV2
            operation=installed_operation_v1('adopt_contact_expression_plan_v2')
            if (NamespaceId.from_key(owner_key)!=ns or operation.domain!='d08'
                    or operation.request_type is not AdoptCurrentContactExpressionPlanRequestV2):
                raise C09PagedCaptureHold('Contact domain logical type/request registration differs')
            owner=owner_key.token;logical_type='d08.current-adopt_contact_expression_plan_v2.v1'
        else:
            owner=source_key(*ns.as_tuple,owner_material_source_id_v1(ns,key[2])).token
            operation=installed_operation_v1('admit_owner_material_source_v1')
            if operation.domain!='d06' or operation.request_type is not AdmitOwnerMaterialSourceRequestV1:
                raise C09PagedCaptureHold('Domain logical type registry differs')
            logical_type='d06.current-admit_owner_material_source_v1.v1'
    else:
        owner=key[0];logical_type=AtomKey.from_token(key[0]).type_name
    if (canonical_digest(tuple(source_header))!=binding['header_digest']
            or source_header[0]!=binding['cell_id'] or source_header[2]!=owner
            or header[2]!=source_header[2]):
        raise C09PagedCaptureHold('logical preservation lost the actual original cell identity/owner/header')
    if (header[1],header[4],header[6])!=(binding['codec_id'],binding['total_bytes'],binding['payload_sha256']):
        raise C09PagedCaptureHold('Graph target seal differs from actual Source logical bytes')
    seal={'schema':'sylanne3.c09.target-cell-seal-original.v3','scope_digest':scope_digest,
        'role':'graph','table_name':table,'primary_key':key,'logical_column':logical_column,
        'header':tuple(header),'physical_row_commitment':new_commitment}
    seal_digest=canonical_digest(seal)
    equivalence={'schema':'sylanne3.c09.logical-equivalence-original.v3','scope_digest':scope_digest,
        'role':'graph','table_name':table,'primary_key':key,'type_name':logical_type,
        'source_role_digest':descriptor['source_role_digest'],'logical_shape_digest':descriptor['logical_shape_digest'],
        'source_logical_row_descriptor_digest':canonical_digest(descriptor),'target_cell_seal_digest':seal_digest,
        'source_logical_row_commitment':descriptor['logical_row_commitment'],
        'target_logical_row_commitment':descriptor['logical_row_commitment'],
        'logical_column':logical_column,'codec_id':header[1],'total_bytes':header[4],'payload_sha256':header[6],
        'source_cell_header':tuple(source_header)}
    return (canonical_digest(descriptor),seal_digest,canonical_digest(equivalence),
        canonical_serialize({'target_cell_seal':seal,'logical_equivalence_original':equivalence}))


def _require_graph_logical_disposition_original_v3(build,db,shape,key,proof,meter,*,target_header=None):
    from .c09_storage_rebase_contract_v1 import GraphRowDispositionV3
    from .c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
    if len(proof)!=13 or proof[5]!='logical_preserved_v3':
        raise C09PagedCaptureHold('explicit V3 logical disposition original required')
    locator=_actual_source_locator_v2(build,shape,meter)
    if proof[7]!=locator.identity.stream_id:raise C09PagedCaptureHold('logical disposition crossed Source stream')
    descriptor=require_c09_logical_source_row_member_v3(db,locator.identity,role='graph',
        table_name=shape.table,key=key,record_ordinal=proof[8],meter=meter)
    raw=json.loads(proof[12])
    if type(raw) is not dict or set(raw)!={'target_cell_seal','logical_equivalence_original'}:
        raise C09PagedCaptureHold('logical disposition producer original grammar differs')
    if shape.table=='graph_contact_expression_plan_originals_v3':
        from .contact_plan_adoption_v3 import COLUMNS,contact_plan_logical_descriptor_v3,SIGN_KIND
        row=meter.read_fixed_row(db,shape.table,COLUMNS,'bot=? AND persona=? AND contact_id=?',key)
        if row is None:
            raise C09PagedCaptureHold('Contact Plan3 actual target physical row absent')
        build.session.get_c09_domain_original_issuer_v2()._signer.verify(SIGN_KIND,
            canonical_serialize(contact_plan_logical_descriptor_v3(row)),row[13])
        if target_header is None:
            target_header=tuple(meter.read_fixed_row(db,'segmented_cells_v1',
                ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                    'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell,))for cell in (row[4],row[9]))
        if any(header is None for header in target_header):
            raise C09PagedCaptureHold('Contact Plan3 actual target two-cell seals absent')
        expected=_graph_logical_preservation_original_v3(build.scope.scope_digest,shape.table,key,descriptor,
            raw['logical_equivalence_original']['source_cell_headers'],target_header,proof[6])
    else:
        if target_header is None:
            from .c09_paged_sql_v2 import _quote
            where=' AND '.join(_quote(name)+'=?' for name in shape.primary_key_columns)
            ref=meter.read_fixed_row(db,shape.table,('original_payload_cell_id' if shape.table=='graph_domain_production_originals_v3' else 'value_cell_id',),where,key)
            if ref is None:raise C09PagedCaptureHold('logical disposition target row absent')
            target_header=meter.read_fixed_row(db,'segmented_cells_v1',
                ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                 'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(ref[0],))
        if target_header is None:raise C09PagedCaptureHold('logical disposition actual target seal absent')
        expected=_graph_logical_preservation_original_v3(build.scope.scope_digest,shape.table,key,
            descriptor,raw['logical_equivalence_original']['source_cell_header'],target_header,proof[6])
    if proof[9:]!=expected or proof[4]!=expected[0]:
        raise C09PagedCaptureHold('logical disposition Source/target/equivalence original differs')
    return GraphRowDispositionV3(proof[2],proof[4],proof[5],proof[6],*proof[9:12])


def _advance_graph_disposition_inventory_v3(progress,stream,complete,shape,meter):
    """Full two-version PK census; every row must be a real sealed stream member."""
    from .c09_paged_sql_v2 import require_c09_capture_member_v2,c09_row_commitment_v2
    version=progress.disposition_inventory_version_v3
    table=('c09_graph_dispositions_v2','c09_graph_dispositions_v3')[version]
    columns=(GRAPH_DISPOSITION_COLUMNS_V2,GRAPH_DISPOSITION_COLUMNS_V3)[version]
    row=meter.read_fixed_row(progress.read_db,table,columns,
        'scope_digest=? AND table_name=? AND key_digest>? ORDER BY key_digest',
        (progress.session.scope.scope_digest,shape.table,progress.disposition_inventory_after_v3))
    if row is None:
        if version==0:
            progress.disposition_inventory_version_v3=1;progress.disposition_inventory_after_v3='';return False
        if progress.disposition_inventory_count_v3!=complete.record_count:
            raise C09PagedCaptureHold('Graph disposition versions/member EOF counts differ')
        return True
    key=tuple(json.loads(row[3]))
    actual=_read_graph_disposition_original_row_v3(progress.read_db,progress.session.scope.scope_digest,shape.table,key,meter)
    if actual!=tuple(row):raise C09PagedCaptureHold('Graph disposition inventory identity differs')
    member=meter.read_fixed_row(progress.read_db,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(key)))
    if member is None or member[1]!=c09_row_commitment_v2(tuple(row)):
        raise C09PagedCaptureHold('extra Graph disposition outside its real sealed member stream')
    require_c09_capture_member_v2(progress.read_db,stream,member[0],key,member[1],meter=meter)
    if version==1:_require_graph_logical_disposition_original_v3(progress.cold_build,progress.read_db,shape,key,tuple(row),meter)
    progress.disposition_inventory_after_v3=row[2];progress.disposition_inventory_count_v3+=1
    if progress.disposition_inventory_count_v3>complete.record_count:
        raise C09PagedCaptureHold('Graph disposition versions contain extra rows')
    return False


def _verify_cold_graph_ref_source_v3(progress,shape,key,metadata,meter,*,verify_semantics=True):
    from ..segmented_sql_cell_v1 import C09ColdGraphCellV3,graph_ref_columns_v3
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
    from .c09_paged_sql_v2 import c09_row_commitment_v2,_quote
    build=progress.cold_build;closure=C09ClosureIndexV2(progress.read_db,progress.session.scope)
    if closure._state()[3]!='sealed':raise C09PagedCaptureHold('cold reference Source requires its actual sealed closure')
    from ..graph_types import AtomKey
    historical=_actual_erased_graph_marker_v3(build,shape,key,meter)
    if historical and 'value_cell_id' not in shape.columns:
        _require_prior_erased_graph_row_v3(build,shape,key,meter)
        row=meter.read_row(progress.pair.source,shape,key)
        origin=_actual_source_row_origin_v2(build,shape,key,tuple(row),meter)
        if not verify_semantics and not progress.source_semantic_eof:
            raise C09PagedCaptureHold('historical erased marker cannot skip actual source semantic EOF')
        hit=False
    elif 'value_cell_id' in shape.columns or AtomKey.from_token(key[0]).type_name=='memory.source':
        if verify_semantics:
            hit,done,pending,actual=_advance_source_nested_match_v3(
                build,shape,key,metadata,closure,progress.pattern_progress,meter.budget,meter)
            progress.prospective_source_capture_v3=pending
            if not done:return None
            small,origin=actual
        else:
            if not progress.source_semantic_eof:raise C09PagedCaptureHold('cold reference Source cannot skip actual semantic EOF')
            capture=_advance_cold_source_row_capture_v3(progress,shape,key,metadata,meter.budget)
            if capture is None:return None
            small=_source_row_small_sql_v3(build,shape,key,meter)
            origin=_actual_streamed_source_origin_v3(build,shape,key,metadata,capture,meter)
            hit=False
    else:
        row=meter.read_row(progress.pair.source,shape,key)
        if row is None:raise C09PagedCaptureHold('actual non-Source Graph original disappeared')
        _validate_graph_source_row_v2(progress.session,shape,tuple(row))
        if verify_semantics:
            hit,done=_graph_nested_advance_v2(closure,_graph_row_nested_value_v2(shape,tuple(row)),
                progress.pattern_progress,meter.budget,meter)
            if not done:return None
        elif not progress.source_semantic_eof:
            raise C09PagedCaptureHold('cold reference row cannot skip actual semantic EOF')
        origin=_actual_source_row_origin_v2(build,shape,key,tuple(row),meter)
    erased=closure.contains_atom(key[0]) and AtomKey.from_token(key[0]).type_name!='memory.access'
    reader=progress.cold_graph_cell_v3
    if reader is None or reader.shape!=shape or reader.key!=key:
        if erased or historical:
            if not historical:
                ready,pending=_advance_marker_cause_capture_v3(build,key,meter.budget,meter)
                progress.prospective_marker_cause_capture_v3=pending
                if not ready:return None
            from ..segmented_sql_cell_v1 import _ColdGeneratedGraphMarkerV3
            reader=_ColdGeneratedGraphMarkerV3(progress,shape,key,basis_kind='prior_erased' if historical else 'current_closure')
        else:reader=C09ColdGraphCellV3(progress,shape,key)
    result=reader.advance();progress.cold_graph_cell_v3=reader
    if not result['complete']:return None
    columns=('source_primary_key_json','old_commitment','disposition','new_commitment','origin_stream_id','origin_record_ordinal')
    original_proof=_read_graph_disposition_original_row_v3(progress.read_db,progress.session.scope.scope_digest,shape.table,key,meter)
    proof=None if original_proof is None else original_proof[3:9]
    expected=(canonical_serialize(key),origin['origin_commitment'],
        'payload_erased_retained_facts' if erased and not historical else ('logical_preserved_v3' if 'value_cell_id' in shape.columns and not historical else 'rebuilt_from_surviving_sources'),
        result['logical_commitment'],origin['origin_stream_id'],origin['origin_record_ordinal'])
    if proof!=expected:raise C09PagedCaptureHold('actual cold reference Source lost exact old/new SQL commitments and origin')
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    small_columns=tuple(name for name in shape.columns if name not in ('value','value_cell_id'))
    raw=meter.read_fixed_row(progress.pair.source,shape.table,small_columns,where,key)
    if raw is None:raise C09PagedCaptureHold('cold reference original SQL metadata disappeared')
    values=dict(zip(small_columns,raw,strict=True));values['value_cell_id' if 'value_cell_id' in shape.columns else 'value']=reader.header[0]
    if erased or historical:
        values['valid']=0
        if shape.table=='graph_history':values['dependencies']='[]'
    expected_row=tuple(values[name] for name in shape.columns)
    if 'value_cell_id' in shape.columns:
        from ..authority_service.c09_authority_storage_rebase import _row_commitment
        target_commitment=_row_commitment(shape.table,shape.columns,expected_row)
    else:target_commitment=c09_row_commitment_v2(expected_row)
    if reader.logical!=expected_row or target_commitment!=proof[3]:
        raise C09PagedCaptureHold('actual cold GraphV3 reference metadata differs from its actual physical target row')
    if len(original_proof)==13:
        disposition=_require_graph_logical_disposition_original_v3(build,progress.read_db,shape,key,original_proof,meter,target_header=reader.header)
    else:disposition=GraphRowDispositionV1(canonical_digest((shape.table,key)),proof[1],proof[2],proof[3])
    progress.cold_graph_cell_v3=None
    progress.pattern_progress={'pattern_kind':'atom','pattern_after':None,'nested_hit':False}
    return disposition


def _verify_cold_source_row_v2(progress,shape,key,row,meter,*,verify_semantics=True):
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
    key_digest=canonical_digest((shape.table,key))
    columns=('source_primary_key_json','old_commitment','disposition','new_commitment','origin_stream_id','origin_record_ordinal')
    proof=meter.read_fixed_row(progress.read_db,'c09_graph_dispositions_v2',columns,
        'scope_digest=? AND table_name=? AND key_digest=?',(progress.candidate.scope.scope_digest,shape.table,key_digest))
    if proof is None or proof[0]!=canonical_serialize(key) or proof[1]!=_row_digest(row):
        raise C09PagedCaptureHold('actual source row lacks its exact disposition original')
    disposition=GraphRowDispositionV1(key_digest,proof[1],proof[2],proof[3])
    _source_row_codec_v2(progress,shape,row)
    if verify_semantics:
        from .c09_b3_managed_metadata_v1 import prepare_b3_managed_source_row_v1
        if not prepare_b3_managed_source_row_v1(progress.cold_build,shape,key,row,meter):return None
    if shape.table=='graph_world_revision_index_v1':
        from .d03_world_history_v1 import decode_world_revision_index_row_v1
        from .c09_world_producer_metadata_v1 import prepare_cold_world_producer_v1
        index=decode_world_revision_index_row_v1(shape.columns,row)
        if prepare_cold_world_producer_v1(progress,index,meter.budget) is None:return None
    from .c09_closure_index_v2 import C09ClosureIndexV2
    closure=C09ClosureIndexV2(progress.read_db,progress.session.scope)
    if closure._state()[3]!='sealed':raise C09PagedCaptureHold('cold Graph dependency closure has not reached its actual fixed point')
    if verify_semantics:
        hit,complete=_graph_nested_advance_v2(closure,_graph_row_nested_value_v2(shape,row),progress.pattern_progress,meter.budget,meter)
        if not complete:return None
        origin={'origin_stream_id':proof[4],'origin_record_ordinal':proof[5],'origin_commitment':proof[1]}
        expected,target_row=_classify_graph_target_row_v2(progress.cold_build,shape,key,row,closure,hit,origin,meter.budget,meter)
        expected_commitment=None if target_row is None else _row_digest(target_row)
        if (expected,expected_commitment)!=(disposition.disposition,disposition.new_commitment):
            raise C09PagedCaptureHold('actual cold source disposition differs from independently recomputed domain semantics')
        progress.pattern_progress={'pattern_kind':'atom','pattern_after':None,'nested_hit':False}
    elif not progress.source_semantic_eof:
        raise C09PagedCaptureHold('nested disposition cannot skip its independent completed semantic source sweep')
    target=meter.read_row(progress.read_db,shape,key)
    if disposition.disposition=='derived_removed':
        if target is not None:raise C09PagedCaptureHold('removed source body still exists in the actual target')
    elif target is None or _row_digest(target)!=disposition.new_commitment:
        raise C09PagedCaptureHold('actual target row differs from the sealed disposition')
    if disposition.disposition=='payload_erased_retained_facts' and shape.table in {'graph_atoms','graph_history'}:
        values=dict(zip(shape.columns,target,strict=True))
        if json.loads(values['value'])!={'schema':'sylanne3.graph.erased_value.v1','key_digest':canonical_digest(values['token'])} or values['valid']!=0:
            raise C09PagedCaptureHold('erased Graph row does not retain only its exact marker facts')
        if shape.table=='graph_history' and values['dependencies']!='[]':
            raise C09PagedCaptureHold('erased history still retains reconstructable dependency payload')
    # Original page membership is verified independently in the directory pass.
    return disposition


def advance_current_graph_rebase_cold_v2(progress):
    if type(progress) is not GraphRebaseColdProgressV2:raise TypeError('actual cold progress required')
    progress.prospective_source_capture_v3=None;progress.prospective_world_producer_capture_v1=None
    progress.prospective_marker_cause_capture_v3=None
    progress.prospective_domain_cell_v3=None
    result=_advance_current_graph_rebase_cold_quantum_v2(progress)
    if progress.prospective_world_producer_capture_v1 is not None:
        capture=progress.prospective_world_producer_capture_v1
        capture.quantum_completed=True
        progress.cold_build.world_producer_capture_v1=capture
        progress.prospective_world_producer_capture_v1=None
    if progress.prospective_contact_prefix_cold_v3 is not None:
        advanced=progress.prospective_contact_prefix_cold_v3
        advanced.quantum_completed=True
        progress.contact_prefix_cold_v3=advanced
        progress.prospective_contact_prefix_cold_v3=None
    if progress.prospective_owner_outputs_cold_v3 is not None:
        adopted=progress.prospective_owner_outputs_cold_v3
        adopted.quantum_completed=True
        if adopted.semantic is not None:adopted.semantic.quantum_completed=True
        progress.owner_outputs_cold_reader_v3=adopted
        progress.prospective_owner_outputs_cold_v3=None
    # The inner reserve_batch context has exited successfully. A failed quantum
    # cannot issue a complete private Source row or move its volatile hash state.
    if progress.prospective_source_capture_v3 is not None:
        capture=progress.prospective_source_capture_v3
        capture.quantum_completed=True
        progress.cold_build.source_row_capture_v3=capture
        progress.prospective_source_capture_v3=None
    if progress.prospective_marker_cause_capture_v3 is not None:
        capture=progress.prospective_marker_cause_capture_v3
        capture.quantum_completed=True
        progress.cold_build.marker_cause_capture_v3=capture
        progress.prospective_marker_cause_capture_v3=None
    if progress.prospective_contact_plan_cold_v3 is not None:
        progress.contact_plan_cold_cells_v3=progress.prospective_contact_plan_cold_v3
        progress.prospective_contact_plan_cold_v3=None
    if progress.prospective_domain_cell_v3 is not None:
        progress.domain_cold_cell_v3=progress.prospective_domain_cell_v3[0]
        progress.prospective_domain_cell_v3=None
    return result


def _advance_current_graph_rebase_cold_quantum_v2(progress):
    """Independently read real source rows and target dispositions per quantum."""
    if type(progress) is not GraphRebaseColdProgressV2:raise TypeError('actual cold progress required')
    progress.session.require_current();progress.pair.require_current()
    if progress.done is not None:return progress.done
    if _advance_graph_pre_graph_owner_qualification_v3(progress.cold_build):return {'status':'progress','phase':'pre_graph_owner_historical_qualification'}
    if _advance_source_container_census_for_graph_v3(progress.cold_build):return {'status':'progress','phase':'source_container_independent_census'}
    if _advance_graph_owner_family_qualification_v3(progress.cold_build):return {'status':'progress','phase':'owner_family_independent_qualification'}
    from .c09_contact_plan_birth_v3 import advance_contact_plan_birth_v3
    if advance_contact_plan_birth_v3(progress.cold_build):
        return {'status':'progress','phase':'contact_plan_birth_independent_qualification'}
    from .c09_contact_prospective_history_v1 import advance_contact_prospective_history_v1
    if advance_contact_prospective_history_v1(progress.cold_build):
        return {'status':'progress','phase':'contact_prospective_independent_history'}
    started=monotonic_ns();completed=0
    if progress.phase=='segmented_physical':
        from ..authority_service.c09_segmented_census_v3 import begin_segmented_census_v3,VerifiedSegmentedPhysicalSweepV3
        if progress.segmented_census_v3 is None:
            progress.segmented_census_v3=begin_segmented_census_v3(progress.session,'graph')
            if progress.segmented_census_v3.pair is not progress.pair:
                raise C09PagedCaptureHold('actual Graph cold segmented sweep crossed registered pair')
        result=progress.segmented_census_v3.advance()
        if type(result) is VerifiedSegmentedPhysicalSweepV3:
            progress.segmented_sweep_v3=result;progress.phase='target_rows'
            return {'status':'progress','phase':'target_rows','segmented_physical_sweep_digest':result.digest}
        return result
    with progress.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        if progress.phase=='prior':
            return _advance_actual_cold_prior_v2(progress,budget,meter,started)
        if progress.phase=='barrier':
            return _advance_actual_cold_barrier_v2(progress,budget,meter,started)
        if progress.phase=='source_originals':
            return _advance_actual_cold_source_originals_v2(progress,budget,meter,started)
        if progress.phase=='closure_replay':
            return _advance_independent_graph_closure_v2(progress,budget,meter,started)
        if progress.phase=='source_semantics':
            return _advance_source_semantic_stage_v2(progress,budget,meter,started)
        if progress.phase=='owner_outputs_cold':
            return _advance_graph_owner_outputs_cold_v3(progress,budget,meter,started)
        if progress.phase=='contact_prefix_cold':
            return _advance_graph_contact_prefix_cold_v3(progress,budget,meter,started)
        if progress.phase=='source_qualified':
            if progress.owner_outputs_cold_proof_v3 is None:
                progress.phase='owner_outputs_cold'
                return _advance_graph_owner_outputs_cold_v3(progress,budget,meter,started)
            progress.owner_outputs_cold_proof_v3.require_current(meter=meter)
            if progress.contact_prefix_cold_proof_v3 is None:
                progress.phase='contact_prefix_cold'
                return _advance_graph_contact_prefix_cold_v3(progress,budget,meter,started)
            progress.contact_prefix_cold_proof_v3.require_current(meter)
            progress.cold_build.source_disposition_view=VerifiedC09SourceDispositionV2(_SOURCE_DISPOSITION_V2,progress)
            progress.phase='source_rows'
            return {'status':'progress','phase':'source_rows','source_disposition_qualified':True}
        if progress.phase=='source_rows':
            from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
            source=progress.pair.source;source.execute('BEGIN');progress.read_db.execute('BEGIN')
            try:
                while completed<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
                    if progress.table_name is None:
                        progress.table_name=_next_graph_logical_source_table_v3(progress.cold_build,None)
                        if progress.table_name is None:raise C09PagedCaptureHold('frozen actual Graph source has no tables')
                    shape=read_c09_table_shape_v2(source,progress.table_name)
                    found=read_c09_next_row_metadata_v2(source,shape,progress.source_key)
                    if found is None:
                        next_table=_next_graph_logical_source_table_v3(progress.cold_build,progress.table_name)
                        if next_table is None:progress.source_eof=True;progress.phase='segmented_physical';break
                        progress.table_name=next_table;progress.source_key=None;continue
                    key,metadata=found
                    if shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
                        from .c09_domain_original_source_v3 import verify_cold_domain_original_v3
                        with c09_sql_meter_quantum_v2(meter):
                            if verify_cold_domain_original_v3(progress,shape,key,metadata,meter) is None:break
                        progress.source_key=key;completed+=1;progress.completed_rows+=1;continue
                    if shape.table in {'graph_atoms','graph_history'}:
                        from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
                        actual=meter.read_fixed_row(progress.read_db,'sqlite_master',('sql',),'type=? AND name=?',('table',shape.table))
                        if actual==(GRAPH_REF_DDLS_V3[shape.table],):
                            with c09_sql_meter_quantum_v2(meter):
                                if _verify_cold_graph_ref_source_v3(progress,shape,key,metadata,meter) is None:break
                            progress.source_key=key;completed+=1;progress.completed_rows+=1
                            continue
                    size=sum(0 if size is None else size for _,size in metadata)
                    if size*7>meter.remaining_bytes:
                        if completed==0:raise C09PagedCaptureHold('cold source row requires its registered streaming codec')
                        break
                    row=meter.read_row(source,shape,key)
                    if row is None:raise C09PagedCaptureHold('frozen actual source row disappeared')
                    with c09_sql_meter_quantum_v2(meter):
                        waiting=_prepare_historical_row_stream_v2(progress.cold_build,shape,tuple(row),meter)
                    if waiting:break
                    with c09_sql_meter_quantum_v2(meter):
                        checked=_verify_cold_source_row_v2(progress,shape,key,tuple(row),meter)
                    if checked is None:break
                    progress.source_key=key;completed+=1;progress.completed_rows+=1
            finally:progress.read_db.rollback();source.rollback()
            if progress.cold_build.historical_verification is not None and not progress.cold_build.historical_verification.complete:
                with c09_sql_meter_quantum_v2(meter):_advance_historical_row_stream_v2(progress.cold_build,budget,meter)
        elif progress.phase=='target_rows':
            return _advance_actual_graph_cold_targets_v2(progress,budget,meter,started)
        elif progress.phase=='target_schema':
            return _advance_actual_cold_schema_v2(progress,budget,meter,started)
        elif progress.phase=='nested':
            return _advance_actual_cold_nested_v2(progress,budget,meter,started)
        elif progress.phase=='directories':
            return _advance_actual_graph_cold_directories_v2(progress,budget,meter,started)
        elif progress.phase=='file_hash':
            return _advance_actual_graph_cold_file_hash_v2(progress,budget,meter,started)
        else:
            # Target EOF/generated-row coverage and the six authenticated stream
            # directories are additional mandatory sweeps. Unknown codecs never
            # become a complete private cold handle.
            raise C09PagedCaptureHold('cold '+progress.phase+' coverage requires its complete registered producer')
    progress.pair.require_current()
    return {'status':'progress','phase':progress.phase,'completed_records':completed,
        'actual_io_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
        'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def mirror_current_graph_rebase_v2(session,verified,issued):
    if type(verified) is not VerifiedGraphRebaseColdV2:raise TypeError('actual cold verified handle required')
    verified.require_current()
    from ..authority_service.c09_graph_rebase_issue_v2 import require_current_graph_rebase_issue_v2
    with session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            certificate=require_current_graph_rebase_issue_v2(session,verified,issued)
            if type(certificate) is not GraphErasureRebaseCertificateV2 or certificate.candidate!=verified.candidate:
                raise C09PagedCaptureHold('actual Core issue differs from independently verified candidate')
            pair=verified.pair;namespace=tuple(json.loads(session.scope.graph_namespace))
            with capture_transaction_v2(pair.candidate):
                raw=canonical_serialize(c09_paged_value_to_wire_v2(certificate));meter.charge_encode(len(raw.encode('utf-8')))
                saved=meter.read_fixed_row(pair.candidate,'graph_c09_rebase_certificates_v2',('certificate_json','issue_digest'),
                    'bot=? AND persona=? AND operation_id=?',(*namespace,session.scope.operation_id))
                values=(raw,issued.issue_digest)
                if saved is None:meter.write_row(pair.candidate,'graph_c09_rebase_certificates_v2',
                    ('bot','persona','operation_id','certificate_json','issue_digest'),(*namespace,session.scope.operation_id,*values))
                elif saved!=values:raise C09PagedCaptureHold('Graph mirror original was replaced')
            checkpoint=pair.candidate.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            if checkpoint is not None and checkpoint[0]!=0:raise C09PagedCaptureHold('postmirror checkpoint remains busy')
            verified.require_current() if verified.cold_phase=='post_mirror' else session.require_current()
            if monotonic_ns()-meter.started_ns>budget.max_local_ns:
                raise C09PagedCaptureHold('actual mirror exceeded installed local quantum')
    return begin_current_graph_rebase_cold_v2(session,verified.candidate)


def _advance_actual_graph_cold_file_hash_v2(progress,budget,meter,started):
    """Hash the same registered target handle after all independent sweeps.

    The complete identity is stable across quanta; reopening restarts at zero.
    No persisted hash cursor or producer-supplied hash is accepted as proof.
    """
    import os
    if progress._issuer is not _SWEEP or not progress.source_eof or not progress.target_eof or progress.verified_directories!=6:
        raise C09PagedCaptureHold('actual source/target/six-directory cold sweeps are incomplete')
    progress.session.require_current();progress.pair.require_current()
    if progress.file is None:
        progress.file=Path(progress.pair.target_path).open('rb')
        original=os.fstat(progress.file.fileno())
        progress.file_identity=(original.st_dev,original.st_ino,original.st_size,original.st_mtime_ns)
        if progress.file_identity[:2]!=progress.pair.target_identity:
            raise C09PagedCaptureHold('cold Graph hash handle is not the registered inode')
        progress.file_hash=hashlib.sha256();progress.file_offset=0
    original=os.fstat(progress.file.fileno())
    identity=(original.st_dev,original.st_ino,original.st_size,original.st_mtime_ns)
    if identity!=progress.file_identity:
        raise C09PagedCaptureHold('cold Graph changed between hash quanta')
    eof=False
    while meter.remaining_bytes and monotonic_ns()-started<budget.max_local_ns:
        size=min(16384,meter.remaining_bytes)
        block=progress.file.read(size)
        if not block:eof=True;break
        meter.charge_read(len(block));progress.file_hash.update(block);progress.file_offset+=len(block)
    final=os.fstat(progress.file.fileno())
    if (final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns)!=identity:
        raise C09PagedCaptureHold('cold Graph bytes changed during hash quantum')
    progress.pair.require_current()
    if not eof:
        return {'status':'progress','phase':'file_hash','bytes_processed':progress.file_offset,
            'actual_io_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
            'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}
    if progress.file_offset!=identity[2]:
        raise C09PagedCaptureHold('cold Graph file EOF does not cover its actual length')
    actual=progress.file_hash.hexdigest()
    if progress.cold_phase=='pre_mirror' and (
            progress.candidate.target_identity!=identity or progress.candidate.target_file_sha256!=actual):
        raise C09PagedCaptureHold('actual pre-mirror file differs from the producer header')
    stage,mirror,issued=_derive_actual_mirror_stage_v2(progress.session,progress.pair,progress.candidate)
    if (stage,mirror,issued)!=(progress.cold_phase,progress.validated_mirror_digest,progress.issued_digest):
        raise C09PagedCaptureHold('cold Graph mirror stage changed while hashing')
    # The six locators remain fixed and bounded; each has already completed its
    # independent census/page/member/actual-row sweep before phase=file_hash.
    fields=('schema_catalogue','disposition_directory','closure','tombstones','target_directory','generated_directory')
    commitments=tuple(getattr(progress.candidate,name).complete.digest for name in fields)
    cold_digest=canonical_digest(('sylanne3.graph.c09.actual-cold-complete.v2',
        progress.candidate.candidate_digest,stage,mirror,issued,commitments,
        progress.completed_rows,identity,actual))
    progress.file.close();progress.file=None
    progress.done=VerifiedGraphRebaseColdV2(_COLD,progress.session,progress.pair,
        progress.candidate,cold_digest,identity,actual,progress.read_db,
        cold_phase=stage,validated_mirror_digest=mirror,issued_digest=issued,segmented_sweep=progress.segmented_sweep_v3,source_disposition_view=progress.cold_build.source_disposition_view)
    progress.done.require_current()
    return progress.done


def _next_cold_target_table_v2(progress,after,meter):
    from .c09_paged_sql_v2 import CAPTURE_DDLS_V2,CAPTURE_TRIGGERS_V2
    from .c09_closure_index_v2 import CLOSURE_DDLS_V2
    from .c09_domain_original_index_v2 import DOMAIN_INDEX_DDL_V2
    from .c09_graph_originals_read_v5 import PRIOR_GRAPH_VIEW_DDLS_V2
    fixed={**CAPTURE_DDLS_V2,**CLOSURE_DDLS_V2,**GRAPH_PROOF_DDLS_V2,**PRIOR_GRAPH_VIEW_DDLS_V2,
        'c09_domain_original_lookup_v2':DOMAIN_INDEX_DDL_V2}
    last='' if after is None else after
    while True:
        row=meter.read_fixed_row(progress.read_db,'sqlite_master',('name','sql'),
            "type='table' AND name NOT GLOB 'sqlite_*' AND name COLLATE BINARY>? ORDER BY name COLLATE BINARY",(last,))
        if row is None:return None
        last=row[0]
        if last not in fixed:
            from ..segmented_sql_cell_v1 import DDLS
            if last in DDLS:
                if row[1]!=DDLS[last]:raise C09PagedCaptureHold('actual cold segmented physical schema differs')
                from ..authority_service.c09_segmented_census_v3 import VerifiedSegmentedPhysicalSweepV3
                if type(progress.segmented_sweep_v3) is not VerifiedSegmentedPhysicalSweepV3:
                    raise C09PagedCaptureHold('actual segmented physical table requires complete private four-stream sweep')
                progress.segmented_sweep_v3.require_current()
            return last
        if row[1]!=fixed[last]:raise C09PagedCaptureHold('actual cold proof table schema differs')
        # These are the current typed proof stores. Their contents must pass the
        # separate six-directory and membership sweep, not a business-row skip.
        if last in PRIOR_GRAPH_VIEW_DDLS_V2:
            if progress.cold_build.prior_view is None:
                if progress.read_db.execute('SELECT 1 FROM "'+last+'" LIMIT 1').fetchone() is not None:
                    raise C09PagedCaptureHold('populated prior metadata has no independently completed historical view')
            continue
        if last in DOMAIN_INDEX_TABLES_V2 or last in CLOSURE_TABLES_V2 or last in GRAPH_PROOF_TABLES_V2:
            continue
        if last in CAPTURE_DDLS_V2:continue


def _advance_cold_graph_ref_row_v3(progress,shape,key,metadata,meter):
    from ..segmented_sql_cell_v1 import C09ColdGraphCellV3
    source_shape=read_c09_table_shape_v2(progress.pair.source,shape.table)
    from ..graph_types import AtomKey
    from .c09_closure_index_v2 import C09ClosureIndexV2
    closure=C09ClosureIndexV2(progress.read_db,progress.session.scope)
    if closure._state()[3]!='sealed':raise C09PagedCaptureHold('actual cold GraphV3 row lacks sealed closure')
    erased=closure.contains_atom(key[0]) and AtomKey.from_token(key[0]).type_name!='memory.access'
    historical=_actual_erased_graph_marker_v3(progress.cold_build,source_shape,key,meter)
    reader=progress.cold_graph_cell_v3
    if reader is None or reader.shape!=source_shape or reader.key!=key:
        if erased or historical:
            if not historical:
                ready,pending=_advance_marker_cause_capture_v3(progress.cold_build,key,meter.budget,meter)
                progress.prospective_marker_cause_capture_v3=pending
                if not ready:return False
            from ..segmented_sql_cell_v1 import _ColdGeneratedGraphMarkerV3
            reader=_ColdGeneratedGraphMarkerV3(progress,source_shape,key,basis_kind='prior_erased' if historical else 'current_closure')
        else:reader=C09ColdGraphCellV3(progress,source_shape,key)
    result=reader.advance()
    progress.cold_graph_cell_v3=reader
    if not result['complete']:return False
    original_proof=_read_graph_disposition_original_row_v3(progress.read_db,progress.session.scope.scope_digest,shape.table,key,meter)
    proof=None if original_proof is None else original_proof[4:9]
    if original_proof is not None and len(original_proof)==13:
        _require_graph_logical_disposition_original_v3(progress.cold_build,progress.read_db,source_shape,key,original_proof,meter,target_header=reader.header)
    if proof is None or proof[1]!=('payload_erased_retained_facts' if erased and not historical else ('logical_preserved_v3' if 'value_cell_id' in source_shape.columns and not historical else 'rebuilt_from_surviving_sources')) or proof[2]!=result['logical_commitment']:
        raise C09PagedCaptureHold('actual cold GraphV3 logical row has no exact layout-transform disposition')
    from .c09_paged_sql_v2 import require_c09_capture_member_v2
    source_locator=_actual_source_locator_v2(progress.cold_build,source_shape,meter)
    if proof[3]!=source_locator.identity.stream_id:
        raise C09PagedCaptureHold('actual cold GraphV3 layout transform crossed original source family')
    require_c09_capture_member_v2(progress.read_db,source_locator.identity,proof[4],key,proof[0],meter=meter)
    from .c09_paged_sql_v2 import _quote
    small_columns=tuple(name for name in source_shape.columns if name not in ('value','value_cell_id'))
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in source_shape.primary_key_columns)
    original=meter.read_fixed_row(progress.pair.source,source_shape.table,small_columns,where,key)
    if original is None:raise C09PagedCaptureHold('actual cold GraphV3 source metadata disappeared')
    values=dict(zip(small_columns,original,strict=True));values['value_cell_id' if 'value_cell_id' in source_shape.columns else 'value']=reader.header[0]
    if erased or historical:
        values['valid']=0
        if shape.table=='graph_history':values['dependencies']='[]'
    if reader.logical!=tuple(values[name] for name in source_shape.columns):
        raise C09PagedCaptureHold('actual cold GraphV3 row changed its original revision/namespace/event facts')
    progress.cold_graph_cell_v3=None
    return True


def _verify_actual_target_row_v2(progress,shape,key,row,meter):
    from .c09_b3_managed_metadata_v1 import require_b3_managed_target_row_v1
    if require_b3_managed_target_row_v1(progress,shape,key,row,meter):return
    from .c09_contact_plan_prefix_history_v3 import TABLE as PREFIX_TABLE,COLUMNS as PREFIX_COLUMNS,decode_contact_prefix_history_row_v3,_contact_prefix_target_family_v3
    if shape.table==PREFIX_TABLE and row[0]==progress.session.scope.scope_digest:
        from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
        if shape.columns!=PREFIX_COLUMNS or tuple(key)!=tuple(row[:3]) or row[0]!=progress.session.scope.scope_digest:
            raise C09PagedCaptureHold('Contact prefix target row has another actual current schema/primary key')
        decode_contact_prefix_history_row_v3(tuple(row))
        _require_exact_structural_member(progress.read_db,_contact_prefix_target_family_v3(progress,meter),key,tuple(row),meter)
        return
    from .c09_owner_source_output_mappings_v3 import TABLE,COLUMNS,decode_owner_source_output_mapping_row_v3
    if shape.table==TABLE:
        from .c09_owner_source_outputs_cold_v3 import _family
        from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
        if shape.columns!=COLUMNS or tuple(key)!=tuple(row[:3]) or row[0]!=progress.session.scope.scope_digest:
            raise C09PagedCaptureHold('generated mapping actual current complete primary key differs')
        decode_owner_source_output_mapping_row_v3(tuple(row))
        _require_exact_structural_member(progress.read_db,_family(progress,progress.read_db,meter),key,tuple(row),meter)
        return
    from ..segmented_sql_cell_v1 import DDLS
    if shape.table in DDLS:
        from ..authority_service.c09_segmented_census_v3 import require_segmented_target_row_v3
        require_segmented_target_row_v3(progress.segmented_sweep_v3,shape.table,key,row,meter=meter)
        return
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    key_digest=canonical_digest((shape.table,key))
    proof=meter.read_fixed_row(progress.read_db,'c09_graph_dispositions_v2',
        ('new_commitment','disposition'),'scope_digest=? AND table_name=? AND key_digest=?',
        (progress.candidate.scope.scope_digest,shape.table,key_digest))
    actual=_row_digest(row)
    if proof is not None and proof[0]==actual and proof[1]!='derived_removed':return
    # Post-mirror certificate is the only row added after the sealed pre-mirror
    # directories; its actual same-Core issue is independently revalidated.
    if shape.table=='graph_c09_rebase_certificates_v2':
        values=dict(zip(shape.columns,row,strict=True));namespace=json.loads(progress.session.scope.graph_namespace)
        if (values['bot'],values['persona'],values['operation_id'])==(*namespace,progress.session.scope.operation_id):
            stage,mirror,issued=_derive_actual_mirror_stage_v2(progress.session,progress.pair,progress.candidate)
            if (stage,mirror,issued)!=('post_mirror',progress.validated_mirror_digest,progress.issued_digest):
                raise C09PagedCaptureHold('target certificate is not this actual mirror')
            return
    generated=meter.read_fixed_row(progress.read_db,'c09_graph_generated_rows_v2',
        ('key_json','row_commitment','producer','origin_ref','origin_digest'),
        'scope_digest=? AND table_name=? AND key_digest=?',
        (progress.candidate.scope.scope_digest,shape.table,key_digest))
    if generated is None or generated[:2]!=(canonical_serialize(key),actual):
        raise C09PagedCaptureHold('actual target row has no complete source/generated proof')
    return _verify_actual_generated_graph_row_v2(progress,shape,key,row,generated[2],generated[3],generated[4],meter)


def _verify_actual_generated_graph_row_v2(progress,shape,key,row,producer,origin_ref,origin_digest,meter):
    from .b3_managed_metadata_v1 import TABLES as B3_MANAGED_TABLES
    if shape.table in B3_MANAGED_TABLES:
        raise C09PagedCaptureHold('managed metadata target must have its actual source disposition, never a guessed generated birth')
    namespace=tuple(json.loads(progress.session.scope.graph_namespace))
    if producer=='c09_erased_key_v2':
        if shape.table!='graph_c09_erased_keys_v1' or tuple(row[:2])!=namespace or row[3:]!=(progress.session.scope.maintenance_generation,progress.session.scope.operation_id):
            raise C09PagedCaptureHold('generated erased key marker has another scope')
        # Each marker comes from a real erased Graph atom/history source key.
        member=meter.read_fixed_row(progress.read_db,'c09_closure_members_v2',
            ('ref','origin_commitment'),'scope_digest=? AND kind=? AND ref=?',
            (progress.session.scope.scope_digest,'atom',origin_ref))
        if member!=(origin_ref,origin_digest) or canonical_digest(origin_ref)!=row[2]:
            raise C09PagedCaptureHold('generated erased marker lacks its actual atom closure origin')
    elif producer=='world_erasure_barrier_v1':
        return _verify_generated_world_erasure_barrier_v1(progress,shape,key,row,origin_ref,origin_digest,meter)
    elif producer=='d09_turn_slot_origin_v3':
        if shape.table!='graph_d09_turn_slot_origins_v3' or key!=(origin_ref,) or tuple(row[1:3])!=namespace:
            raise C09PagedCaptureHold('generated turn-slot origin has another actual logical namespace/key')
        from ..graph_types import AtomKey
        from .c09_closure_index_v2 import C09ClosureIndexV2
        from .c09_paged_sql_v2 import (read_legacy_sql_cell_fragment_v2,
            legacy_cell_read_transaction_v2,require_c09_capture_member_v2)
        atom=AtomKey.from_token(origin_ref)
        if atom.type_name!='d09.turn_slot.v1':raise C09PagedCaptureHold('generated turn-slot origin has another typed producer')
        closure=C09ClosureIndexV2(progress.read_db,progress.session.scope)
        if closure._state()[3]!='sealed' or closure.contains_atom(origin_ref):
            raise C09PagedCaptureHold('generated turn-slot projection lacks actual surviving closed Source')
        source_shape=read_c09_table_shape_v2(progress.pair.source,'graph_atoms')
        locator=_actual_source_locator_v2(progress.cold_build,source_shape,meter)
        original=meter.read_fixed_row(progress.read_db,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize((origin_ref,))))
        if original is None or original[1]!=origin_digest:
            raise C09PagedCaptureHold('generated turn-slot origin has no exact frozen source member')
        require_c09_capture_member_v2(progress.read_db,locator.identity,original[0],(origin_ref,),origin_digest,meter=meter)
        with legacy_cell_read_transaction_v2(progress.pair.source):
            _,total,kind=read_legacy_sql_cell_fragment_v2(progress.pair.source,table='graph_atoms',column='value',
                where='token=?',parameters=(origin_ref,),start=0,length=0,meter=meter)
            if total>16384:raise C09PagedCaptureHold('generated turn-slot projection exceeds its registered complete typed bound')
            block,total,kind=read_legacy_sql_cell_fragment_v2(progress.pair.source,table='graph_atoms',column='value',
                where='token=?',parameters=(origin_ref,),start=0,length=total,meter=meter)
        if kind!='text' or total>16384 or len(block)!=total:
            raise C09PagedCaptureHold('generated turn-slot projection exceeds registered complete typed bound')
        value=json.loads(block)
        progress.session._control.maintenance.graph._registry.validate(atom,value)
        if row!=(origin_ref,*namespace,value['origin_ref']):
            raise C09PagedCaptureHold('generated turn-slot projection differs from actual original typed value')
    else:raise C09PagedCaptureHold('unknown actual generated Graph producer')


def _advance_actual_graph_cold_targets_v2(progress,budget,meter,started):
    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
    completed=0
    progress.read_db.execute('BEGIN')
    read_started=monotonic_ns()
    try:
        while completed<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
            if progress.target_table is None:
                progress.target_table=_next_cold_target_table_v2(progress,None,meter)
                if progress.target_table is None:raise C09PagedCaptureHold('actual Graph target has no business tables')
            shape=read_c09_table_shape_v2(progress.read_db,progress.target_table)
            found=read_c09_next_row_metadata_v2(progress.read_db,shape,progress.target_key)
            if found is None:
                following=_next_cold_target_table_v2(progress,progress.target_table,meter)
                if following is None:
                    progress.target_eof=True;progress.phase='file_hash' if progress.verified_directories==6 and progress.target_schema_eof else 'target_schema';break
                progress.target_table=following;progress.target_key=None;continue
            key,metadata=found;raw_size=sum(size or 0 for _,size in metadata)
            if shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
                from .c09_domain_original_source_v3 import verify_cold_domain_original_v3
                source_shape=read_c09_table_shape_v2(progress.pair.source,shape.table)
                source_metadata=_read_frozen_source_row_metadata_v3(progress.cold_build,source_shape,key,meter)
                with c09_sql_meter_quantum_v2(meter):
                    if verify_cold_domain_original_v3(progress,source_shape,key,source_metadata,meter) is None:break
                progress.target_key=key;completed+=1;continue
            if shape.table in {'graph_atoms','graph_history'} and 'value_cell_id' in shape.columns:
                with c09_sql_meter_quantum_v2(meter):
                    if not _advance_cold_graph_ref_row_v3(progress,shape,key,metadata,meter):break
                progress.target_key=key;completed+=1
                continue
            if raw_size*7>meter.remaining_bytes:
                if completed==0:raise C09PagedCaptureHold('actual cold target row needs bounded codec')
                break
            row=meter.read_row(progress.read_db,shape,key)
            if row is None:raise C09PagedCaptureHold('actual cold target row disappeared')
            if _verify_actual_target_row_v2(progress,shape,key,tuple(row),meter) is False:break
            progress.target_key=key;completed+=1
    finally:progress.read_db.rollback()
    read_ns=monotonic_ns()-read_started
    if read_ns>budget.max_read_ns:raise C09PagedCaptureHold('cold target read exceeded installed transaction limit')
    progress.pair.require_current()
    return {'status':'progress','phase':progress.phase,'completed_records':completed,
        'actual_io_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
        'read_transaction_ns':read_ns,'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def _directory_shape_v2(progress,locator):
    # The producer's logical family never chooses an arbitrary SQL expression.
    # Resolve the real physical table through its matching schema commitment.
    field=_GRAPH_DIRECTORY_FIELDS_V2[progress.locator_index]
    family=_GRAPH_DIRECTORY_TABLES_V2[progress.locator_index]
    if locator.identity.family!=family:
        raise C09PagedCaptureHold('candidate directory is not the registered fixed physical family')
    if progress.read_db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(family,)).fetchone() is None:
        raise C09PagedCaptureHold('registered directory has no actual physical table')
    shape=read_c09_table_shape_v2(progress.read_db,family)
    if (shape.schema_digest,shape.primary_key_columns,shape.primary_key_types)!=(
        locator.identity.schema_digest,locator.identity.primary_key_columns,locator.identity.primary_key_types):
        raise C09PagedCaptureHold('actual directory schema differs from sealed identity')
    return shape


def _verify_actual_graph_directory_record_v2(progress,field,shape,record,meter):
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    row=meter.read_row(progress.read_db,shape,record.primary_key)
    if row is None:raise C09PagedCaptureHold('actual cold directory record absent')
    if field=='tombstones':
        values=dict(zip(shape.columns,row,strict=True))
        if shape.table!='graph_c09_erased_keys_v1' or any(name not in values for name in ('bot','persona','key_digest','maintenance_generation','operation_id')):
            raise C09PagedCaptureHold('tombstone directory has another registered schema')
        if values['maintenance_generation']>progress.session.scope.maintenance_generation:
            raise C09PagedCaptureHold('tombstone belongs to a future generation')
    elif field=='generated_directory':
        values=dict(zip(shape.columns,row,strict=True))
        if shape.table!='c09_graph_generated_rows_v2':raise C09PagedCaptureHold('generated directory physical table differs')
        target_shape=read_c09_table_shape_v2(progress.read_db,values['table_name'])
        target_key=tuple(json.loads(values['key_json']))
        target=meter.read_row(progress.read_db,target_shape,target_key)
        if target is None or _row_digest(target)!=values['row_commitment']:
            raise C09PagedCaptureHold('generated directory target commitment differs')
        return _verify_actual_generated_graph_row_v2(progress,target_shape,target_key,target,values['producer'],values['origin_ref'],values['origin_digest'],meter)
    elif field in {'disposition_directory','target_directory','closure'}:
        values=dict(zip(shape.columns,row,strict=True))
        nested=c09_paged_value_from_wire_v2(json.loads(values['identity_json']),C09StreamIdentityV2)
        from .c09_paged_capture_contract_v2 import C09CompleteStreamV2
        seal=c09_paged_value_from_wire_v2(json.loads(values['complete_json']),C09CompleteStreamV2)
        saved=meter.read_fixed_row(progress.read_db,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(nested.stream_id,))
        if saved is None or saved[0]!='sealed' or c09_paged_value_from_wire_v2(json.loads(saved[1]),type(seal))!=seal:
            raise C09PagedCaptureHold('actual nested directory stream has no identical complete original')
    elif field=='schema_catalogue':
        values=dict(zip(shape.columns,row,strict=True))
        actual=meter.read_fixed_row(progress.read_db,'sqlite_master',('sql',),
            'type=? AND name=?',(values['object_type'],values['object_name']))
        if actual!=(values['target_sql'],):raise C09PagedCaptureHold('actual directory schema DDL differs')
    else:raise C09PagedCaptureHold('unknown fixed Graph directory')
    if record.commitment!=_row_digest(tuple(row)):
        raise C09PagedCaptureHold('actual directory row commitment differs')


def _advance_actual_graph_cold_directories_v2(progress,budget,meter,started):
    if progress.locator_index==6:
        progress.phase='file_hash' if progress.source_eof and progress.target_eof else 'source_qualified'
        return {'status':'progress','phase':progress.phase,'completed_records':0,
            'actual_io_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started}
    field=_GRAPH_DIRECTORY_FIELDS_V2[progress.locator_index]
    locator=getattr(progress.candidate,field)
    shape=_directory_shape_v2(progress,locator)
    if progress.verification is None:
        progress.verification=begin_c09_stream_verification_v2(progress.read_db,locator.identity)
        if progress.verification.seal_digest!=locator.complete.digest:
            raise C09PagedCaptureHold('actual candidate directory seal differs')
    if not progress.verification.census_complete:
        result=advance_verify_c09_census_v2(progress.census_db,progress.read_db,locator.identity,shape,budget,
            verification=progress.verification,check_frozen_source=progress.pair.require_current,meter=meter)
    else:
        result=advance_verify_c09_stream_v2(progress.read_db,locator.identity,budget,
            verification=progress.verification,
            verify_record=lambda record:_verify_actual_graph_directory_record_v2(progress,field,shape,record,meter),
            meter=meter)
        if result['complete']:
            if field in {'disposition_directory','target_directory','closure'}:
                progress.phase='nested';progress.nested_field=field;progress.nested_after=None
                progress.nested_locator=None;progress.nested_verification=None
            else:
                progress.verified_directories+=1;progress.locator_index+=1
            progress.verification=None
    progress.pair.require_current()
    result.update(status='progress',phase='directories',directory=field,
        actual_io_bytes=meter.consumed_bytes,local_ns=monotonic_ns()-started)
    return result


def _save_graph_progress_v2(build,phase,progress,meter):
    raw=canonical_serialize(progress);meter.charge_encode(len(raw.encode('utf-8')))
    meter.charge_write(len(raw.encode('utf-8'))+len(phase)+len(build.scope.scope_digest))
    build.pair.candidate.execute('UPDATE c09_graph_build_progress_v2 SET phase=?,progress_json=? WHERE scope_digest=?',
        (phase,raw,build.scope.scope_digest))


def _graph_step_report_v2(build,phase,meter,started,records=0):
    build.require_current()
    return {'status':'progress','phase':phase,'completed_records':records,
        'actual_meter_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
        'resource_quantum_within_limit':meter.consumed_bytes<=meter.budget.max_bytes and monotonic_ns()-started<=meter.budget.max_local_ns}


def _directory_put_v2(build,table,stream,complete,meter):
    values=(build.scope.scope_digest,stream.family,canonical_serialize(c09_paged_value_to_wire_v2(stream)),
        canonical_serialize(c09_paged_value_to_wire_v2(complete)))
    saved=meter.read_fixed_row(build.pair.candidate,table,
        ('scope_digest','family','identity_json','complete_json'),'scope_digest=? AND family=?',values[:2])
    if saved is None:meter.write_row(build.pair.candidate,table,('scope_digest','family','identity_json','complete_json'),values)
    elif saved!=values:raise C09PagedCaptureHold('actual completed Graph directory member was replaced')


def _advance_deferred_graph_schema_v2(build,progress):
    started=monotonic_ns();source=build.pair.source;candidate=build.pair.candidate
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            after=None if progress.get('object_key') is None else tuple(progress['object_key']);count=0
            source.execute('BEGIN')
            try:
                with capture_transaction_v2(candidate):
                    while count<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
                        obj=read_c09_next_schema_object_v2(source,after,max_bytes=meter.remaining_bytes)
                        if obj is None:
                            from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3,GRAPH_REF_INDEXES_V3
                            for name,ddl in {**{'graph_d09_turn_slot_origins_v3':GRAPH_REF_DDLS_V3['graph_d09_turn_slot_origins_v3']},**GRAPH_REF_INDEXES_V3}.items():
                                kind='table' if name in GRAPH_REF_DDLS_V3 else 'index'
                                actual=meter.read_fixed_row(candidate,'sqlite_master',('sql',),'type=? AND name=?',(kind,name))
                                if actual is None:candidate.execute(ddl);meter.charge_write(len(ddl.encode()))
                                elif actual!=(ddl,):raise C09PagedCaptureHold('registered GraphV3 turn-slot origin schema differs')
                            for pragma in ('user_version','application_id'):
                                value=source.execute('PRAGMA '+pragma).fetchone()[0]
                                candidate.execute('PRAGMA '+pragma+'='+str(value));meter.charge_read(8);meter.charge_write(8)
                            _save_graph_progress_v2(build,'nested_directories',{'directory':0,'table':None,'scan_phase':'census'},meter)
                            return _graph_step_report_v2(build,'nested_directories',meter,started,count)
                        if obj.object_type in {'index','trigger'}:
                            if obj.object_type=='index' and obj.name=='graph_d09_turn_slot_origin':
                                # V3 derives this exact index from verified turn-slot
                                # values into its own bounded typed table below.
                                _require_source_graph_schema_object_v2(source,obj)
                            else:
                                apply_c09_schema_object_v2(candidate,obj,verify_installed_object=lambda actual:_require_source_graph_schema_object_v2(source,actual))
                                meter.charge_write(len(obj.sql.encode('utf-8')))
                        after=obj.primary_key;count+=1
                    _save_graph_progress_v2(build,'deferred_schema',{'object_key':after},meter)
            finally:source.rollback()
    return _graph_step_report_v2(build,'deferred_schema',meter,started,count)


def _require_source_graph_schema_object_v2(source,obj):
    from .d03_world_history_v1 import TABLE,DDL,INDEX_DDL,ERASURE_TABLE,ERASURE_DDL,ERASURE_INDEX_DDL
    expected={('table',TABLE):DDL,('index','graph_world_revision_temporal_v1'):INDEX_DDL,
        ('table',ERASURE_TABLE):ERASURE_DDL,('index','graph_world_erased_knowledge_v1'):ERASURE_INDEX_DDL}
    if obj.table_name in {TABLE,ERASURE_TABLE} and not obj.name.startswith('sqlite_autoindex_'):
        wanted=expected.get((obj.object_type,obj.name))
        if wanted is None or obj.sql!=wanted.replace(' IF NOT EXISTS',''):
            raise C09PagedCaptureHold('World C09 schema object differs from its exact installed metadata schema')
    from .c09_contact_effect_accounting_v1 import require_financial_schema_object_v1
    require_financial_schema_object_v1(obj)
    actual=source.execute('SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type=? AND name=?',obj.primary_key).fetchone()
    if actual!=(obj.object_type,obj.name,obj.table_name,obj.sql):
        raise C09PagedCaptureHold('deferred Graph DDL differs from its actual frozen original')


def _open_graph_target_reader_v2(build):
    build.require_current();db=sqlite3.connect(Path(build.pair.target_path).as_uri()+'?mode=ro',uri=True,isolation_level=None)
    db.execute('PRAGMA query_only=ON');return db


def _advance_graph_nested_directories_v2(build,progress):
    """Independent actual table census and immutable row capture per family."""
    candidate=build.pair.candidate;started=monotonic_ns();directory=progress['directory']
    family_sets=(None,('c09_closure_members_v2','c09_closure_edges_v2'))
    if directory==0:
        table=progress.get('table') or _next_graph_target_directory_table_v3(build,None)
        directory_table='c09_graph_target_directory_v2';kind='target_rows'
    else:
        families=family_sets[1];table=progress.get('table') or families[0]
        directory_table='c09_graph_closure_directory_v2';kind='dependency_closure'
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            shape=read_c09_table_shape_v2(candidate,table);stream=_source_stream_identity_v2(build,shape,kind)
            with capture_transaction_v2(candidate):begin_capture_stream_v2(candidate,stream)
            reader=_open_graph_target_reader_v2(build)
            try:
                if progress.get('scan_phase','census')=='census':
                    result=advance_c09_census_v2(reader,candidate,stream,shape,budget,check_frozen_source=build.pair.require_current,meter=meter)
                    if result['eof']:progress['scan_phase']='rows'
                else:
                    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
                    result=advance_c09_rows_v2(reader,candidate,stream,shape,budget,check_frozen_source=build.pair.require_current,
                        transform_row=lambda db,sh,key,row,remaining:C09RowTransformResultV2(_row_digest(row),0,0),meter=meter)
                    if result['eof']:
                        with capture_transaction_v2(candidate):
                            seal=seal_capture_stream_v2(candidate,stream);_directory_put_v2(build,directory_table,stream,seal,meter)
                        following=_next_graph_target_directory_table_v3(build,table) if directory==0 else (families[1] if table==families[0] else None)
                        progress.update(table=following,scan_phase='census')
                        if following is None:
                            progress={'directory':1,'table':None,'scan_phase':'census'} if directory==0 else {'object_key':None}
                            phase='nested_directories' if directory==0 else 'schema_catalogue'
                            with capture_transaction_v2(candidate):_save_graph_progress_v2(build,phase,progress,meter)
                            return _graph_step_report_v2(build,phase,meter,started)
                progress['table']=table if progress.get('table') is None else progress['table']
                with capture_transaction_v2(candidate):_save_graph_progress_v2(build,'nested_directories',progress,meter)
            finally:reader.close()
    return _graph_step_report_v2(build,'nested_directories',meter,started)


def _advance_graph_target_schema_v2(build,progress):
    """Record the actual complete target SQLite catalogue, not source type inventory."""
    candidate=build.pair.candidate;started=monotonic_ns();after=progress.get('object_key')
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter),capture_transaction_v2(candidate):
            count=0
            while count<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
                obj=read_c09_next_schema_object_v2(candidate,None if after is None else tuple(after),max_bytes=meter.remaining_bytes)
                if obj is None:
                    _save_graph_progress_v2(build,'directories',{'index':0,'scan_phase':'census'},meter)
                    return _graph_step_report_v2(build,'directories',meter,started,count)
                values=(build.scope.scope_digest,obj.object_type,obj.name,obj.table_name,obj.sql)
                saved=meter.read_fixed_row(candidate,'c09_graph_target_schema_v2',
                    ('scope_digest','object_type','object_name','table_name','target_sql'),
                    'scope_digest=? AND object_type=? AND object_name=?',values[:3])
                if saved is None:meter.write_row(candidate,'c09_graph_target_schema_v2',
                    ('scope_digest','object_type','object_name','table_name','target_sql'),values)
                elif saved!=values:raise C09PagedCaptureHold('target schema changed while its independent catalogue was captured')
                after=obj.primary_key;count+=1
            _save_graph_progress_v2(build,'schema_catalogue',{'object_key':after},meter)
    return _graph_step_report_v2(build,'schema_catalogue',meter,started,count)


def _advance_graph_six_directories_v2(build,progress):
    candidate=build.pair.candidate;started=monotonic_ns();index=progress['index']
    if not 0<=index<6:raise C09PagedCaptureHold('actual Graph directory ordinal differs')
    table=_GRAPH_DIRECTORY_TABLES_V2[index]
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            shape=read_c09_table_shape_v2(candidate,table)
            stream=_source_stream_identity_v2(build,shape,_GRAPH_DIRECTORY_KINDS_V2[index])
            with capture_transaction_v2(candidate):begin_capture_stream_v2(candidate,stream)
            reader=_open_graph_target_reader_v2(build)
            try:
                if progress['scan_phase']=='census':
                    result=advance_c09_census_v2(reader,candidate,stream,shape,budget,check_frozen_source=build.pair.require_current,meter=meter)
                    if result['eof']:progress['scan_phase']='rows'
                else:
                    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
                    result=advance_c09_rows_v2(reader,candidate,stream,shape,budget,check_frozen_source=build.pair.require_current,
                        transform_row=lambda db,sh,key,row,remaining:C09RowTransformResultV2(_row_digest(row),0,0),meter=meter)
                    if result['eof']:
                        with capture_transaction_v2(candidate):
                            complete=seal_capture_stream_v2(candidate,stream)
                            _directory_put_legacy_v2(build,'final_directory',stream,complete,meter)
                        progress={'index':index+1,'scan_phase':'census'}
                phase='candidate_hash' if progress['index']==6 else 'directories'
                with capture_transaction_v2(candidate):_save_graph_progress_v2(build,phase,progress,meter)
            finally:reader.close()
    return _graph_step_report_v2(build,phase,meter,started)


def _directory_put_legacy_v2(build,kind,stream,complete,meter):
    values=(build.scope.scope_digest,kind,stream.family,canonical_serialize(c09_paged_value_to_wire_v2(stream)),canonical_serialize(c09_paged_value_to_wire_v2(complete)))
    cols=('scope_digest','directory_kind','family','identity_json','complete_json')
    saved=meter.read_fixed_row(build.pair.candidate,'c09_graph_stream_directory_v2',cols,
        'scope_digest=? AND directory_kind=? AND family=?',values[:3])
    if saved is None:meter.write_row(build.pair.candidate,'c09_graph_stream_directory_v2',cols,values)
    elif saved!=values:raise C09PagedCaptureHold('completed Graph stream directory was replaced')


def _advance_graph_candidate_hash_v2(build,progress):
    import os
    started=monotonic_ns();candidate=build.pair.candidate
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            if build.hash_file is None:
                checkpoint=candidate.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
                if checkpoint is not None and checkpoint[0]!=0:raise C09PagedCaptureHold('Graph candidate checkpoint remains busy')
                if any(Path(build.pair.target_path+suffix).exists() and Path(build.pair.target_path+suffix).stat().st_size for suffix in ('-wal','-journal')):
                    raise C09PagedCaptureHold('Graph target still has mutable journal bytes')
                build.hash_file=Path(build.pair.target_path).open('rb');stat=os.fstat(build.hash_file.fileno())
                build.hash_identity=(stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns)
                if build.hash_identity[:2]!=build.pair.target_identity:raise C09PagedCaptureHold('candidate hash opened another target inode')
                build.hash_value=hashlib.sha256();build.hash_offset=0
            before=os.fstat(build.hash_file.fileno())
            identity=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)
            if identity!=build.hash_identity:raise C09PagedCaptureHold('Graph candidate changed between actual hash quanta')
            eof=False
            while meter.remaining_bytes and monotonic_ns()-started<budget.max_local_ns:
                block=build.hash_file.read(min(16384,meter.remaining_bytes))
                if not block:eof=True;break
                meter.charge_read(len(block));build.hash_value.update(block);build.hash_offset+=len(block)
            after=os.fstat(build.hash_file.fileno())
            if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=identity:raise C09PagedCaptureHold('candidate hash bytes changed')
            if not eof:return _graph_step_report_v2(build,'candidate_hash',meter,started)
            if build.hash_offset!=identity[2]:raise C09PagedCaptureHold('candidate hash did not read real EOF')
            locators=[]
            from .c09_paged_capture_contract_v2 import C09CompleteStreamV2
            for table in _GRAPH_DIRECTORY_TABLES_V2:
                row=meter.read_fixed_row(candidate,'c09_graph_stream_directory_v2',('identity_json','complete_json'),
                    'scope_digest=? AND directory_kind=? AND family=?',(build.scope.scope_digest,'final_directory',table))
                if row is None:raise C09PagedCaptureHold('actual complete six-directory producer original absent')
                stream=c09_paged_value_from_wire_v2(json.loads(row[0]),C09StreamIdentityV2)
                complete=c09_paged_value_from_wire_v2(json.loads(row[1]),C09CompleteStreamV2)
                locators.append(C09SealedStreamLocatorV2('graph',stream,complete))
            ns=tuple(json.loads(build.scope.graph_namespace));source=build.pair.source
            source.execute('BEGIN')
            try:
                recovery=meter.read_fixed_row(source,'graph_recovery_metadata_v2',('requirements_json','graph_revision'),'bot=? AND persona=?',ns)
                epoch=meter.read_fixed_row(source,'graph_epochs',('revision',),'bot=? AND persona=?',ns)
                authority=meter.read_fixed_row(source,'graph_authority_epochs',('access_epoch','delete_epoch'),'bot=? AND persona=?',ns)
            finally:source.rollback()
            if recovery is None or epoch is None or authority is None:raise C09PagedCaptureHold('actual Graph generation heads absent')
            old=json.loads(recovery[0])['graph_incarnation']
            if old!=build.pair.build_plan['old_incarnation']:raise C09PagedCaptureHold('actual Graph frozen incarnation differs')
            result=GraphRebaseCandidateV2(build.scope,build.pair.source_original,build.pair.target_path,
                identity,build.hash_value.hexdigest(),old,recovery[1],epoch[0],authority[0],authority[1],
                build.pair.build_plan['new_incarnation'],epoch[0],authority[0],authority[1],*locators)
            build.require_current()
            build.session._control.maintenance.control.record_build_original_v1(operation_id=build.scope.operation_id,
                kind='graph_candidate_v2',details=c09_paged_value_to_wire_v2(result))
            build.hash_file.close();build.hash_file=None;build.candidate_done=result
            return result


def _actual_source_locator_v2(build,shape,meter):
    row=meter.read_fixed_row(build.pair.candidate,'c09_graph_stream_directory_v2',('identity_json','complete_json'),
        'scope_digest=? AND directory_kind=? AND family=?',(build.scope.scope_digest,'source_originals',shape.table))
    if row is None:raise C09PagedCaptureHold('actual frozen-source complete row directory absent')
    from .c09_paged_capture_contract_v2 import C09CompleteStreamV2
    identity=c09_paged_value_from_wire_v2(json.loads(row[0]),C09StreamIdentityV2)
    complete=c09_paged_value_from_wire_v2(json.loads(row[1]),C09CompleteStreamV2)
    if identity!=_source_stream_identity_v2(build,shape,'graph_facts'):
        raise C09PagedCaptureHold('actual frozen-source locator crossed role source/schema/primary key')
    sealed=meter.read_fixed_row(build.pair.candidate,'c09_capture_streams_v2',('status','seal_json'),
        'stream_id=?',(identity.stream_id,))
    if sealed is None or sealed[0]!='sealed' or c09_paged_value_from_wire_v2(json.loads(sealed[1]),C09CompleteStreamV2)!=complete:
        raise C09PagedCaptureHold('actual frozen-source locator differs from its complete stream original')
    return C09SealedStreamLocatorV2('graph',identity,complete)


def _actual_source_row_origin_v2(build,shape,key,row,meter):
    from .c09_paged_sql_v2 import require_c09_capture_member_v2
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    locator=_actual_source_locator_v2(build,shape,meter)
    item=meter.read_fixed_row(build.pair.candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
    if item is None or item[1]!=_row_digest(row):raise C09PagedCaptureHold('actual source row has no exact immutable member')
    require_c09_capture_member_v2(build.pair.candidate,locator.identity,item[0],key,item[1],meter=meter)
    return dict(origin_stream_id=locator.identity.stream_id,origin_record_ordinal=item[0],origin_commitment=item[1])


def _actual_domain_index_v2(build,shape,budget,meter):
    from .c09_domain_original_index_v2 import C09DomainOriginalIndexV2
    from .c09_paged_sql_v2 import require_c09_capture_member_v2
    locator=_actual_source_locator_v2(build,shape,meter)
    def verify(stream_id,ordinal,key,commitment):
        if stream_id!=locator.identity.stream_id:raise C09PagedCaptureHold('domain lookup crossed source original family')
        require_c09_capture_member_v2(build.pair.candidate,locator.identity,ordinal,key,commitment,meter=meter)
    return C09DomainOriginalIndexV2(candidate=build.pair.candidate,source=build.pair.source,
        scope_digest=build.scope.scope_digest,family=shape.table,shape=shape,
        authority_namespace=build.scope.authority_namespace,issuer=build.session.get_c09_domain_original_issuer_v2(),
        budget=budget,verify_origin=verify)


def _verify_graph_domain_joins_v2(build,shape,row,original,budget,meter):
    if shape.table=="graph_owner_goal_cancellation_projections_v1":
        from .owner_goal_projection_v1 import validate_goal_projection_row_v1
        observed,receipt=validate_goal_projection_row_v1(shape.columns,row,issuer=build.session.get_c09_domain_original_issuer_v2())
        # The original event is metadata-only. Requiring an independently read
        # exact event digest keeps this receipt tied to its actual W01 CAS.
        event=meter.read_fixed_row(build.pair.source,"graph_events",("digest",),
            "bot=? AND persona=? AND session=? AND event_id=?",
            (*receipt.namespace.as_tuple,receipt.event_session,receipt.operation_id))
        if event!=(receipt.event_digest,):raise C09PagedCaptureHold("Goal projection actual W01 event join changed")
        return
    from .c09_graph_row_codec_v2 import verify_c09_life_domain_join_v2,verify_c09_d07_accounting_join_v2,verify_c09_contact_accounting_join_v2
    from .c09_d07_execution_v1 import TABLE as D07
    from .c09_contact_originals_v1 import TABLE as CONTACT
    from .c09_contact_originals_v2 import TABLE as CONTACT2
    from ..runtime_contracts import NamespaceId
    values=dict(zip(shape.columns,row,strict=True));ns=NamespaceId(values['bot'],values['persona'])
    index=_actual_domain_index_v2(build,shape,budget,meter)
    def read(kind,ref):
        saved=index.get(ns,kind,ref);return None if saved is None else saved[1]
    if shape.table in ('graph_contact_prospective_originals_v1','graph_contact_prospective_successors_v1'):
        from .c09_contact_prospective_history_v1 import require_contact_prospective_c09_join_v1
        require_contact_prospective_c09_join_v1(build,shape,row,original,meter)
    elif shape.table == CONTACT_EFFECT_ORIGINAL:
        from .c09_contact_effect_accounting_v1 import verify_financial_original_join_v1
        verify_financial_original_join_v1(original, read_original=read)
    elif shape.table=='graph_d11_life_originals_v1':
        verify_c09_life_domain_join_v2(build.pair.source,original,shape.columns,row,index=index)
    elif shape.table==D07:verify_c09_d07_accounting_join_v2(original,read_original=read)
    elif shape.table in {CONTACT,CONTACT2}:
        def account_by_digest(digest):
            item=meter.read_fixed_row(build.pair.candidate,'c09_domain_original_lookup_v2',('original_ref',),
                'scope_digest=? AND family=? AND bot=? AND persona=? AND kind=? AND prepared_digest=? ORDER BY original_ref COLLATE BINARY',
                (build.scope.scope_digest,shape.table,*ns.as_tuple,'accounting_prepared',digest))
            return None if item is None else read('accounting_prepared',item[0])
        verify_c09_contact_accounting_join_v2(original,read_original=read,read_account_by_digest=account_by_digest)


def _validate_graph_source_row_v2(session,shape,row):
    from .c09_b3_managed_metadata_v1 import validate_b3_managed_source_row_v1
    if validate_b3_managed_source_row_v1(session,shape,row):return
    if shape.table=='graph_world_revision_index_v1':
        from .d03_world_history_v1 import decode_world_revision_index_row_v1,SIGN_KIND
        decode_world_revision_index_row_v1(shape.columns,row)
        session.get_c09_domain_original_issuer_v2()._signer.verify(SIGN_KIND,row[5],row[7])
        return
    if shape.table=='graph_world_revision_erasure_barriers_v1':
        from .d03_world_history_v1 import decode_world_erasure_barrier_row_v1,ERASURE_SIGN_KIND
        decode_world_erasure_barrier_row_v1(shape.columns,row)
        session.get_c09_domain_original_issuer_v2()._signer.verify(ERASURE_SIGN_KIND,row[8],row[10])
        return
    if shape.table in {CONTACT_EFFECT_ORIGINAL, CONTACT_EFFECT_ATTEMPT}:
        from .c09_contact_effect_accounting_v1 import validate_graph_financial_row_v1
        validate_graph_financial_row_v1(shape.table,shape.columns,row,issuer=session.get_c09_domain_original_issuer_v2())
        return
    from .contact_plan_adoption_v3 import TABLE as PLAN3
    from .contact_plan_physical_write_v3 import STREAM_TABLE,validate_contact_plan_stream_row_v3
    if shape.table==STREAM_TABLE:
        validate_contact_plan_stream_row_v3(shape.columns,row)
        return
    if shape.table == PLAN3:
        from .c09_graph_row_codec_v2 import read_c09_domain_row_v2
        read_c09_domain_row_v2(shape.table,shape.columns,row,authority_namespace=session.scope.authority_namespace,
            issuer=session.get_c09_domain_original_issuer_v2())
        return
    from .contact_background_scheduler_v3 import TABLE as scheduler_table,validate_contact_scheduler_row_v3
    if shape.table == scheduler_table:
        validate_contact_scheduler_row_v3(shape.columns,row)
        return
    from .c09_budget_rows_v1 import TABLES,validate_c09_budget_row_v1
    from .c09_d07_execution_v1 import STAGE_TABLE,ACCOUNTING_TABLE,validate_d07_stage_attempt_row_v1,validate_d07_accounting_attempt_row_v1
    if shape.table in TABLES:validate_c09_budget_row_v1(shape.table,shape.columns,row);return
    if shape.table==STAGE_TABLE:validate_d07_stage_attempt_row_v1(shape.columns,row);return
    if shape.table==ACCOUNTING_TABLE:validate_d07_accounting_attempt_row_v1(shape.columns,row);return
    if shape.table in {'graph_atoms','graph_history'}:
        from ..graph_types import AtomKey
        value=dict(zip(shape.columns,row,strict=True));key=AtomKey.from_token(value['token']);decoded=json.loads(value['value'])
        if type(decoded) is dict and decoded.get('schema')=='sylanne3.graph.erased_value.v1':
            if decoded!={'schema':'sylanne3.graph.erased_value.v1','key_digest':canonical_digest(key.token)}:raise C09PagedCaptureHold('historical erased marker commitment differs')
        else:session._control.maintenance.graph._registry.validate(key,decoded)
        if shape.table=='graph_history':
            deps=json.loads(value['dependencies'])
            if type(deps) is not list or any(type(x) is not list or len(x)!=2 or type(x[0]) is not str or type(x[1]) is not int for x in deps):
                raise C09PagedCaptureHold('actual historical dependency representation differs')
    # Every remaining string body follows the old registered JSON field codec.
    _graph_row_nested_value_v2(shape,row)


def _graph_row_nested_value_v2(shape,row):
    values=dict(zip(shape.columns,row,strict=True));decoded={}
    for name,value in values.items():
        if type(value) is str and (name.endswith('_json') or name in {'value','dependencies','reads','epoch_reads','revisions','invalidated','payload','body_json','original'}):
            try:decoded[name]=json.loads(value)
            except (TypeError,ValueError) as exc:raise C09PagedCaptureHold('unreadable registered Graph JSON cell '+shape.table+'.'+name) from exc
        else:decoded[name]=value
    return decoded


def _graph_nested_advance_v2(closure,value,progress,budget,meter):
    """A false answer is accepted only after both pattern families reach EOF."""
    kind=progress.get('pattern_kind','atom');after=progress.get('pattern_after')
    hit=progress.get('nested_hit',False)
    if hit:return True,True
    result=closure.scan_nested_value_page(value,kind=kind,after_ref=after,budget=budget)
    meter.charge_read(result['encoded_bytes']);meter.charge_encode(result['encoded_bytes'])
    progress['pattern_after']=result['last_ref']
    if result['hit']:progress['nested_hit']=True;return True,True
    if result['eof'] and kind=='atom':
        progress.update(pattern_kind='source_id',pattern_after=None);return False,False
    return False,result['eof']


def _large_memory_source_v3(shape,key,metadata,meter):
    if shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):return True
    if shape.table not in {'graph_atoms','graph_history'}:
        return False
    if 'value_cell_id' in shape.columns:
        return True
    if sum(size or 0 for _,size in metadata)*9<=meter.remaining_bytes:
        return False
    from ..graph_types import AtomKey
    return AtomKey.from_token(key[0]).type_name=='memory.source'


def _source_row_small_sql_v3(build,shape,key,meter,*,capture=None):
    """Actual nonbody SQL columns; oversized second cells keep their codec HOLD."""
    if shape.table=='graph_contact_expression_plan_originals_v3':
        from .c09_contact_plan_physical_v3 import C09MappedContactPlanCaptureV3
        current=build.source_row_capture_v3 if capture is None else capture
        if type(current) is not C09MappedContactPlanCaptureV3 or current.key!=tuple(key) or not current.row.complete or not current.value.complete:
            raise C09PagedCaptureHold('Contact Plan3 metadata requires its actual complete physical producer')
        return {'bot':key[0],'persona':key[1],'contact_id':key[2],'producing_operation_id':current.physical[3],'payload_digest':current.physical[8]}
    if shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
        from .c09_domain_original_source_v3 import C09MappedDomainOriginalCaptureV3
        from .c09_contact_plan_physical_v3 import C09MappedContactDomainCaptureV3
        current=build.source_row_capture_v3 if capture is None else capture
        if type(current) not in (C09MappedDomainOriginalCaptureV3,C09MappedContactDomainCaptureV3) or current.key!=tuple(key) or not current.row.complete or not current.value.complete:
            raise C09PagedCaptureHold('Domain small metadata needs its actual completed producer')
        return {'bot':key[0],'persona':key[1],'operation_id':key[2],'original_digest':current.identity[2]}
    from .c09_paged_sql_v2 import _quote
    columns=tuple(name for name in shape.columns if name not in ('value','value_cell_id'))
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    row=meter.read_fixed_row(build.pair.source,shape.table,columns,where,key)
    if row is None:raise C09PagedCaptureHold('actual Source SQL metadata disappeared')
    values=dict(zip(columns,row,strict=True))
    from ..graph_types import AtomKey
    atom=AtomKey.from_token(key[0])
    if shape.table=='graph_atoms':
        expected={'bot':atom.owner.bot,'persona':atom.owner.persona,'owner_kind':atom.owner.kind,
            'subject':atom.owner.subject,'type_name':atom.type_name,'name':atom.name}
        if any(values[name]!=value for name,value in expected.items()):
            raise C09PagedCaptureHold('actual Source SQL metadata differs from its canonical owner/key')
    else:
        if (values['revision']!=key[1] or (values['event_bot'],values['event_persona'])!=
                (atom.owner.bot,atom.owner.persona)):
            raise C09PagedCaptureHold('actual Source history SQL metadata differs from its original namespace/revision')
        event=meter.read_fixed_row(build.pair.source,'graph_events',('event_id',),
            'bot=? AND persona=? AND session=? AND event_id=?',
            (values['event_bot'],values['event_persona'],values['event_session'],values['event_id']))
        if event!=(values['event_id'],):raise C09PagedCaptureHold('actual Source history lacks its original event')
    for name in ('dependencies',):
        if name in values:
            values[name]=json.loads(values[name])
            if (type(values[name]) is not list or any(type(item) is not list or len(item)!=2
                    or type(item[0]) is not str or type(item[1]) is not int for item in values[name])):
                raise C09PagedCaptureHold('actual historical dependency representation differs')
    return values


def _actual_streamed_source_origin_v3(build,shape,key,metadata,capture,meter):
    from .c09_paged_sql_v2 import require_c09_capture_member_v2
    commitment=capture.require_complete(build,shape,key,metadata)
    locator=_actual_source_locator_v2(build,shape,meter)
    if 'value_cell_id' in shape.columns or shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
        from .c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
        original=meter.read_fixed_row(build.pair.candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
        if original is None or original[1]!=commitment:raise C09PagedCaptureHold('actual mapped Source row lost its composite member')
        descriptor=require_c09_logical_source_row_member_v3(build.pair.candidate,locator.identity,
            role='graph',table_name=shape.table,key=key,record_ordinal=original[0],meter=meter)
        if canonical_serialize(descriptor)!=canonical_serialize(capture.row.result.descriptor):
            raise C09PagedCaptureHold('independent mapped Source row differs from its immutable logical descriptor')
    item=meter.read_fixed_row(build.pair.candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
    if item is None or item[1]!=commitment:
        raise C09PagedCaptureHold('streamed Source row has no exact original SQL-row member')
    require_c09_capture_member_v2(build.pair.candidate,locator.identity,item[0],key,commitment,meter=meter)
    return dict(origin_stream_id=locator.identity.stream_id,origin_record_ordinal=item[0],origin_commitment=commitment)


def _advance_source_nested_match_v3(build,shape,key,metadata,closure,progress,budget,meter):
    """One actual closure pattern at a time, decoded text across byte boundaries."""
    from .c09_graph_row_codec_v2 import C09MemorySourceRowCaptureV3
    kind=progress.get('pattern_kind','atom');after=progress.get('pattern_after')
    pattern=next(closure.iter_members(kind,after,1),None)
    ref=None if pattern is None else pattern[0]
    if pattern is not None:
        encoded=canonical_serialize(pattern)
        from .c09_closure_index_v2 import C09ClosureIndexV2
        if type(closure) is C09ClosureIndexV2:meter.charge_read(len(encoded.encode()))
    capture=build.source_row_capture_v3
    if shape.table in {'graph_atoms','graph_history'} and 'value_cell_id' not in shape.columns and _actual_erased_graph_marker_v3(build,shape,key,meter):
        _require_prior_erased_graph_row_v3(build,shape,key,meter)
        row=tuple(meter.read_row(build.pair.source,shape,key))
        hit,done=_graph_nested_advance_v2(closure,_graph_row_nested_value_v2(shape,row),progress,budget,meter)
        if not done:return False,False,None,None
        small=_source_row_small_sql_v3(build,shape,key,meter,capture=capture)
        return hit,True,None,(small,_actual_source_row_origin_v2(build,shape,key,row,meter))
    capture=build.source_row_capture_v3
    if (capture is None or capture.shape!=shape or capture.key!=key or capture.metadata!=metadata
            or capture.pattern_kind!=kind or capture.pattern_ref!=ref):
        capture=_begin_graph_source_capture_v3(build,shape,key,metadata,pattern_kind=kind,pattern_ref=ref)
    if not (capture.row.complete and capture.value.complete and capture.quantum_completed):
        capture=capture.next_quantum(budget)
        return False,False,capture,None
    small=_source_row_small_sql_v3(build,shape,key,meter,capture=capture)
    origin=_actual_streamed_source_origin_v3(build,shape,key,metadata,capture,meter)
    if pattern is None:
        if kind=='atom':
            progress.update(pattern_kind='source_id',pattern_after=None)
            return False,False,None,None
        return False,True,capture,(small,origin)
    hit=capture.require_nested_hit(build,shape,key,metadata,small)
    progress['pattern_after']=ref
    if hit:
        progress['nested_hit']=True
        return True,True,capture,(small,origin)
    return False,False,None,None


def _expand_streamed_source_closure_v3(build,shape,key,small,origin,closure,hit,*,capture=None):
    # The existing typed-edge codec has no memory.source auxiliary branch.
    # Historical SQL dependencies and the actual nested hit retain V2 directions.
    capture=build.source_row_capture_v3 if capture is None else capture
    if shape.table=='graph_contact_expression_plan_originals_v3':
        from .c09_contact_plan_physical_v3 import C09MappedContactPlanCaptureV3
        from ..domains.d08.contact_plan_v3 import contact_plan_keys_v3
        from ..graph_types import AtomKey
        if type(capture) is not C09MappedContactPlanCaptureV3:
            raise C09PagedCaptureHold('Contact closure lost its actual mapped Plan3 producer')
        born=build.contact_plan_birth_proofs_v3.get(tuple(key))
        if born is None:
            raise C09PagedCaptureHold('Contact closure requires its actual complete historical birth joins')
        born.require_complete(build,current_c09_sql_meter_v2())
        refs=tuple(row.ref for row in capture.proof.historical_reads if AtomKey.from_token(row.ref).type_name=='memory.source')
        for member in contact_plan_keys_v3(capture.plan):
            for dependency in refs:
                closure.add_edge(member.token,dependency,**origin)
                if closure.contains_atom(dependency):
                    closure.add_atom(member.token,**origin)
        if hit or any(closure.contains_atom(ref)for ref in refs):
            closure.add_member('operation',capture.proof.producing_operation_id,**origin)
        return
    if shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
        from .c09_domain_original_source_v3 import C09MappedDomainOriginalCaptureV3,_domain_removed_v3
        from .c09_contact_plan_physical_v3 import C09MappedContactDomainCaptureV3
        if type(capture) not in (C09MappedDomainOriginalCaptureV3,C09MappedContactDomainCaptureV3):raise C09PagedCaptureHold('Domain closure actual producer missing')
        if _domain_removed_v3(capture,closure,hit):
            closure.add_member('operation',capture.operation_id,**origin)
        return
    from .c09_graph_row_codec_v2 import C09MappedGraphRowCaptureV3,iter_c09_typed_graph_edges_v2
    from ..graph_types import AtomKey
    if type(capture) is C09MappedGraphRowCaptureV3 and not capture.source_metadata:
        decoded=capture.value.parser.value;atom=AtomKey.from_token(key[0])
        if atom.type_name=='memory.access':return
        if type(decoded) is dict and decoded.get('schema')=='sylanne3.graph.erased_value.v1':return
        for dependent,dependency in iter_c09_typed_graph_edges_v2(build.pair.source,atom,decoded):
            closure.add_edge(dependent,dependency,**origin)
            if closure.contains_atom(dependency):closure.add_atom(dependent,**origin)
    for dependency,_ in small.get('dependencies',()):
        closure.add_edge(key[0],dependency,**origin)
        if closure.contains_atom(dependency):closure.add_atom(key[0],**origin)
    if hit:closure.add_atom(key[0],**origin)


def _advance_graph_closure_v2(build,progress):
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_source_plan_barrier_v2 import begin_verify_c09_source_barrier_v2,advance_verify_c09_source_barrier_v2,next_c09_barrier_source_member_v2
    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
    started=monotonic_ns();candidate=build.pair.candidate;source=build.pair.source
    source_nested_used=False;source_nested_pending=None
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            closure=C09ClosureIndexV2(candidate,build.scope)
            with capture_transaction_v2(candidate):closure.begin()
            if not progress.get('seed_complete'):
                source.execute('BEGIN')
                try:
                    if build.barrier_view is None:build.barrier_view=begin_verify_c09_source_barrier_v2(source,session=build.session)
                    if not build.barrier_view.complete:
                        advance_verify_c09_source_barrier_v2(build.barrier_view,budget=budget)
                        return _graph_step_report_v2(build,'closure_barrier',meter,started)
                    with capture_transaction_v2(candidate):
                        member=next_c09_barrier_source_member_v2(build.barrier_view,progress.get('seed_after',''),budget=budget)
                        if member is None:
                            progress={'seed_complete':True,'round':0,'table':None,'row_key':None,'pattern_kind':'atom','pattern_after':None}
                        else:
                            closure.add_atom(member['source_ref'],origin_stream_id=member['barrier_digest'],
                                origin_record_ordinal=member['record_ordinal'],origin_commitment=member['record_commitment'])
                            progress['seed_after']=member['source_ref']
                        _save_graph_progress_v2(build,'closure',progress,meter)
                finally:source.rollback()
                return _graph_step_report_v2(build,'closure_seed',meter,started)
            with capture_transaction_v2(candidate):
                state=closure._state()
                if state[3]=='collect':
                    closure.begin_round();progress.update(round=state[0]+1,table=None,row_key=None,pattern_kind='atom',pattern_after=None,nested_hit=False)
            table=progress.get('table') or _next_graph_logical_source_table_v3(build,None)
            if table is None:raise C09PagedCaptureHold('actual Graph source has no closure inventory')
            shape=read_c09_table_shape_v2(source,table);source.execute('BEGIN')
            try:
                found=read_c09_next_row_metadata_v2(source,shape,None if progress.get('row_key') is None else tuple(progress['row_key']))
                if found is None:
                    following=_next_graph_logical_source_table_v3(build,table)
                    with capture_transaction_v2(candidate):
                        if following is None:
                            roots=meter.read_fixed_row(candidate,'c09_closure_state_v2',('round','member_generation','round_generation'),'scope_digest=?',(build.scope.scope_digest,))
                            complete=closure.finish_round(actual_scan_eof_digest=canonical_digest(('c09.actual-closure-round-eof.v2',build.scope.scope_digest,roots)))
                            phase='target' if complete else 'closure'
                            progress={'table':None,'scan_phase':'census','pattern_kind':'atom','pattern_after':None} if complete else {'seed_complete':True,'table':None,'row_key':None,'pattern_kind':'atom','pattern_after':None}
                        else:phase='closure';progress.update(table=following,row_key=None,pattern_kind='atom',pattern_after=None,nested_hit=False)
                        _save_graph_progress_v2(build,phase,progress,meter)
                    return _graph_step_report_v2(build,phase,meter,started)
                key,metadata=found;size=sum(n or 0 for _,n in metadata)
                if _large_memory_source_v3(shape,key,metadata,meter):
                    hit,done,source_nested_pending,actual=_advance_source_nested_match_v3(
                        build,shape,key,metadata,closure,progress,budget,meter)
                    source_nested_used=True
                    with capture_transaction_v2(candidate):
                        if done:
                            small,origin=actual
                            previous_capture=build.source_row_capture_v3
                            build.source_row_capture_v3=source_nested_pending
                            try:_expand_streamed_source_closure_v3(build,shape,key,small,origin,closure,hit)
                            finally:build.source_row_capture_v3=previous_capture
                            progress.update(row_key=key,pattern_kind='atom',pattern_after=None,nested_hit=False)
                            source_nested_pending=None
                        progress['table']=table;_save_graph_progress_v2(build,'closure',progress,meter)
                else:
                    if size*9>meter.remaining_bytes:raise C09PagedCaptureHold('actual closure row needs its registered streaming semantic codec')
                    row=tuple(meter.read_row(source,shape,key));_validate_graph_source_row_v2(build.session,shape,row)
                    from .c09_b3_managed_metadata_v1 import prepare_b3_managed_source_row_v1
                    if not prepare_b3_managed_source_row_v1(build,shape,key,row,meter):
                        progress['table']=table
                        with capture_transaction_v2(candidate):_save_graph_progress_v2(build,'closure',progress,meter)
                        return _graph_step_report_v2(build,'closure',meter,started)
                    with capture_transaction_v2(candidate):
                        hit,done=_graph_nested_advance_v2(closure,_graph_row_nested_value_v2(shape,row),progress,budget,meter)
                        if done:
                            origin=_actual_source_row_origin_v2(build,shape,key,row,meter)
                            _expand_graph_closure_row_v2(build,shape,key,row,closure,hit,origin,budget,meter)
                            progress.update(row_key=key,pattern_kind='atom',pattern_after=None,nested_hit=False)
                        progress['table']=table;_save_graph_progress_v2(build,'closure',progress,meter)
            finally:source.rollback()
    if source_nested_used:
        if source_nested_pending is not None:source_nested_pending.quantum_completed=True
        build.source_row_capture_v3=source_nested_pending
    return _graph_step_report_v2(build,'closure',meter,started)


def _expand_graph_closure_row_v2(build,shape,key,row,closure,hit,origin,budget,meter):
    from ..graph_types import AtomKey
    from ..runtime_contracts import NamespaceId
    from .c09_graph_row_codec_v2 import iter_c09_typed_graph_edges_v2,read_c09_domain_row_v2,classify_c09_domain_row_v2
    from .domain_production_erasure_v1 import TABLE_COLUMNS,DERIVED_STORE_TABLES_V6
    from .c09_d04_originals_v3 import TABLE as D04
    from .c09_d07_execution_v1 import TABLE as D07
    from .c09_contact_originals_v1 import TABLE as CONTACT
    from .c09_contact_originals_v2 import TABLE as CONTACT2
    from .c09_b3_managed_metadata_v1 import expand_b3_managed_metadata_closure_v1
    if expand_b3_managed_metadata_closure_v1(build,shape,key,row,closure,hit,origin):return
    values=dict(zip(shape.columns,row,strict=True));namespace=tuple(json.loads(build.scope.graph_namespace))
    if _require_source_owner_mapping_metadata_v3(build,shape,key,row,meter):return
    if _require_owner_source_metadata_row_for_graph_v3(build,shape,key,row,meter):return
    if _require_paid_owner_graph_source_row_v3(build,shape,row,meter):
        if hit:closure.add_member('operation',row[2],**origin)
        return
    if shape.table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(values['token'])
        if NamespaceId.from_key(atom).as_tuple!=namespace:return
        if atom.type_name=='memory.access':return
        decoded=json.loads(values['value'])
        if type(decoded) is dict and decoded.get('schema')=='sylanne3.graph.erased_value.v1':return
        for dependent,dependency in iter_c09_typed_graph_edges_v2(build.pair.source,atom,decoded):
            closure.add_edge(dependent,dependency,**origin)
            if closure.contains_atom(dependency):closure.add_atom(dependent,**origin)
        if shape.table=='graph_history':
            for dependency,_ in json.loads(values['dependencies']):
                closure.add_edge(atom.token,dependency,**origin)
                if closure.contains_atom(dependency):closure.add_atom(atom.token,**origin)
        if hit:closure.add_atom(atom.token,**origin)
    elif shape.table in {'graph_dependencies','graph_dependency_edges'}:
        dependent=AtomKey.from_token(values['dependent_token']);dependency=AtomKey.from_token(values['dependency_token'])
        if NamespaceId.from_key(dependent).as_tuple!=namespace:return
        closure.add_edge(dependent.token,dependency.token,**origin)
        if dependent.type_name!='memory.access' and closure.contains_atom(dependency.token):closure.add_atom(dependent.token,**origin)
    elif shape.table=='graph_events' and hit:
        if (values.get('bot'),values.get('persona'))==namespace:closure.add_member('operation',values['event_id'],**origin)
    elif shape.table in (set(TABLE_COLUMNS)-set(DERIVED_STORE_TABLES_V6)) or shape.table in {D04,D07,CONTACT,CONTACT2,CONTACT_EFFECT_ORIGINAL}:
        original=read_c09_domain_row_v2(shape.table,shape.columns,row,authority_namespace=build.scope.authority_namespace,
            issuer=build.session.get_c09_domain_original_issuer_v2())
        classify_c09_domain_row_v2(original,shape.columns,row,closure=closure,nested_hit=hit,origin=origin,
            verify_original_joins=lambda actual:_verify_graph_domain_joins_v2(build,shape,row,actual,budget,meter))


def _classify_graph_target_row_v2(build,shape,key,row,closure,nested_hit,origin,budget,meter):
    from .c09_budget_rows_v1 import TABLES,validate_c09_budget_row_v1
    from .c09_graph_rebase_candidate_v1 import _COMMITMENT_TABLES,_REBASE_TABLES,_FACT_COLUMNS
    from .c09_graph_row_codec_v2 import read_c09_domain_row_v2,classify_c09_domain_row_v2,classify_c09_shared_original_row_v2,classify_c09_shared_outbox_row_v2,classify_c09_derived_store_row_v2
    from .domain_production_erasure_v1 import TABLE_COLUMNS,DERIVED_STORE_TABLES_V6
    from .c09_d04_originals_v3 import TABLE as D04
    from .c09_d07_execution_v1 import TABLE as D07
    from .c09_contact_originals_v1 import TABLE as CONTACT
    from .c09_contact_originals_v2 import TABLE as CONTACT2
    from ..graph_types import AtomKey
    if shape.table=='graph_world_revision_index_v1':
        _authenticated_world_revision_index_v1(build,shape,row,meter)
    if shape.table=='graph_world_revision_erasure_barriers_v1':
        _require_prior_world_erasure_barrier_v1(build,shape,key,row,meter)
        return 'preserved_exact',tuple(row)
    if _require_source_owner_mapping_metadata_v3(build,shape,key,row,meter):return 'derived_removed',None
    if _require_owner_source_metadata_row_for_graph_v3(build,shape,key,row,meter):return 'preserved_exact',row
    if _require_paid_owner_graph_source_row_v3(build,shape,row,meter):
        removed=closure.contains_operation(row[2]) or nested_hit
        return ('derived_removed',None) if removed else ('preserved_exact',row)
    from .b3_managed_metadata_v1 import TABLES as B3_MANAGED_TABLES
    if shape.table in B3_MANAGED_TABLES:
        from .c09_b3_managed_metadata_v1 import classify_b3_managed_metadata_row_v1
        return classify_b3_managed_metadata_row_v1(build,shape,key,row,closure,nested_hit)
    values=dict(zip(shape.columns,row,strict=True));updated=list(row);disposition='preserved_exact'
    from .c09_foreground_attempt_v1 import TABLE as FOREGROUND_TABLE
    from .c09_source_plan_barrier_v2 import SOURCE_PLAN_BARRIER_TABLES_V2,SOURCE_PLAN_BARRIER_DDLS_V2
    if shape.table in SOURCE_PLAN_BARRIER_TABLES_V2:
        actual_sql=build.pair.source.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(shape.table,)).fetchone()
        if actual_sql!=(SOURCE_PLAN_BARRIER_DDLS_V2[shape.table],):raise C09PagedCaptureHold('Source barrier metadata schema differs')
        namespace=tuple(json.loads(build.scope.graph_namespace))
        if (values['bot'],values['persona'],values['operation_id'])==(*namespace,build.scope.operation_id):
            if build.barrier_view is None or not build.barrier_view.complete:raise C09PagedCaptureHold('current Source barrier metadata has no independently completed original view')
            return 'preserved_exact',tuple(row)
        if build.prior_view is None:raise C09PagedCaptureHold('historical Source barrier metadata requires its actual prior certificate')
        proof=build.prior_view.require_target_row_disposition(shape.table,key,_metered_graph_row_commitment_v2(row),meter=meter)
        if proof.disposition!='preserved_exact' or proof.old_commitment!=proof.new_commitment:raise C09PagedCaptureHold('historical Source barrier metadata lost its exact preserved commitment')
        return 'preserved_exact',tuple(row)
    if shape.table in _managed_graph_metadata_tables_v2():
        from .c09_historical_proof_row_codec_v2 import classify_historical_graph_proof_row_v2
        disposition=classify_historical_graph_proof_row_v2(build.session,build.pair,shape,key,row,meter=meter,
            require_complete_stream=lambda locator:_require_historical_complete_stream_v2(build,locator))
        return disposition,None if disposition=='derived_removed' else tuple(row)
    if shape.table==FOREGROUND_TABLE:
        actual=build.session.read_finished_foreground_graph_original_v2(build.pair,row,meter=meter)
        if actual.row!=tuple(row):raise C09PagedCaptureHold('foreground actual Core finish returned another Graph original')
        from .domain_production_original_codec_v1 import ORIGINAL_COLUMNS
        parent=meter.read_fixed_row(build.pair.source,'graph_domain_production_originals_v1',ORIGINAL_COLUMNS,
            'bot=? AND persona=? AND operation_id=?',(*actual.namespace.as_tuple,actual.operation_id))
        if parent is None:raise C09PagedCaptureHold('finished foreground fence lacks its actual shared original')
        parent_shape=read_c09_table_shape_v2(build.pair.source,'graph_domain_production_originals_v1')
        parent_key=tuple(parent[parent_shape.columns.index(name)] for name in parent_shape.primary_key_columns)
        proof=meter.read_fixed_row(build.pair.candidate,'c09_graph_dispositions_v2',('old_commitment','disposition','new_commitment'),
            'scope_digest=? AND table_name=? AND key_digest=?',
            (build.scope.scope_digest,parent_shape.table,canonical_digest((parent_shape.table,parent_key))))
        if proof is None or proof[0]!=_metered_graph_row_commitment_v2(parent) or proof[1] not in {'preserved_exact','derived_removed'}:
            raise C09PagedCaptureHold('foreground parent has no completed actual shared original disposition')
        return proof[1],None if proof[1]=='derived_removed' else tuple(row)
    if shape.table in TABLES:validate_c09_budget_row_v1(shape.table,shape.columns,row)
    elif shape.table in DERIVED_STORE_TABLES_V6:
        disposition=classify_c09_derived_store_row_v2(build.pair.source,shape.table,shape.columns,row,closure=closure,
            authority_namespace=build.scope.authority_namespace,require_erased_fact=lambda *args,**kw:_require_previous_derived_fact_v2(build,*args,**kw),meter=meter)
    elif shape.table in TABLE_COLUMNS or shape.table in {D04,D07,CONTACT,CONTACT2,CONTACT_EFFECT_ORIGINAL}:
        original=read_c09_domain_row_v2(shape.table,shape.columns,row,authority_namespace=build.scope.authority_namespace,
            issuer=build.session.get_c09_domain_original_issuer_v2())
        disposition=classify_c09_domain_row_v2(original,shape.columns,row,closure=closure,nested_hit=nested_hit,origin=origin,
            verify_original_joins=lambda actual:_verify_graph_domain_joins_v2(build,shape,row,actual,budget,meter))
    elif shape.table=='graph_domain_production_originals_v1':
        disposition=classify_c09_shared_original_row_v2(build.pair.source,row,registry=build.session._control.maintenance.graph._registry,
            closure=closure,nested_hit=nested_hit)
    elif shape.table=='graph_domain_production_outbox_v1':
        def causal(ns,op):
            from .domain_production_original_codec_v1 import ORIGINAL_COLUMNS
            actual=meter.read_fixed_row(build.pair.source,'graph_domain_production_originals_v1',ORIGINAL_COLUMNS,
                'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,op))
            if actual is None:return None
            proof=meter.read_fixed_row(build.pair.candidate,'c09_graph_dispositions_v2',('disposition',),
                'scope_digest=? AND table_name=? AND key_digest=?',(build.scope.scope_digest,'graph_domain_production_originals_v1',canonical_digest(('graph_domain_production_originals_v1',tuple(actual[:3])))))
            if proof is None:raise C09PagedCaptureHold('shared outbox causal original not yet classified in actual target order')
            return proof[0]
        disposition=classify_c09_shared_outbox_row_v2(build.pair.source,row,closure=closure,read_causal_disposition=causal)
    elif shape.table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(values['token'])
        if closure.contains_atom(atom.token) and atom.type_name!='memory.access':
            updated[shape.columns.index('value')]=canonical_serialize({'schema':'sylanne3.graph.erased_value.v1','key_digest':canonical_digest(atom.token)})
            updated[shape.columns.index('valid')]=0
            if shape.table=='graph_history':updated[shape.columns.index('dependencies')]='[]'
            disposition='payload_erased_retained_facts'
    elif shape.table in {'graph_dependencies','graph_dependency_edges'}:
        if closure.contains_atom(values['dependent_token']) or closure.contains_atom(values['dependency_token']):disposition='derived_removed'
    elif shape.table=='graph_recovery_metadata_v2' and (values['bot'],values['persona'])==tuple(json.loads(build.scope.graph_namespace)):
        requirements=json.loads(values['requirements_json'])
        if requirements['graph_incarnation']!=build.pair.build_plan['old_incarnation']:raise C09PagedCaptureHold('actual source recovery incarnation differs')
        requirements['graph_incarnation']=build.pair.build_plan['new_incarnation']
        updated[shape.columns.index('requirements_json')]=canonical_serialize(requirements);disposition='rebuilt_from_surviving_sources'
    elif shape.table not in _COMMITMENT_TABLES|_REBASE_TABLES|{'graph_c09_rebase_certificates_v2'}:
        body_operation=any(name in values and type(values[name]) is str and closure.contains_operation(values[name]) for name in ('event_id','operation_id','producing_operation_id'))
        body_columns=any(name in {'value','content','payload','input','output'} or name.endswith('_body_json') for name in shape.columns)
        if nested_hit or body_operation and body_columns:disposition='derived_removed'
    return disposition,None if disposition=='derived_removed' else tuple(updated)


def _require_previous_derived_fact_v2(build,db,table,columns,row,*,namespace,key,revision,meter):
    from .c09_graph_originals_read_v5 import require_c09_erased_derived_fact_v2
    require_c09_erased_derived_fact_v2(db,table,columns,row,namespace=namespace,key=key,revision=revision,
        view=build.prior_view if build.prior_view is not None else build.source_disposition_view,meter=meter)





def _actual_erased_graph_marker_v3(build,shape,key,meter):
    """Recognize only the finite exact marker, never invalidity alone."""
    if shape.table not in {'graph_atoms','graph_history'}:return False
    from .c09_paged_sql_v2 import _quote,read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
    expected=canonical_serialize({'schema':'sylanne3.graph.erased_value.v1','key_digest':canonical_digest(key[0])}).encode()
    if 'value_cell_id' in shape.columns:
        _mapped_graph_source_shape_v3(build,shape,meter);scope=build.mapped_source_scope_v3
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
        cell=meter.read_fixed_row(build.pair.source,shape.table,('value_cell_id',),where,key)
        if cell is None:raise C09PagedCaptureHold('actual mapped marker source disappeared')
        header=scope.read_cell_header_v3(cell[0],meter=meter)
        if header[4]!=len(expected):return False
        if header[2]!=key[0]:raise C09PagedCaptureHold('mapped marker source owner differs from canonical key')
        block,total=scope.read_cell_fragment_v3(cell[0],start=0,length=header[4],meter=meter)
        if total!=header[4] or hashlib.sha256(block).hexdigest()!=header[6]:
            raise C09PagedCaptureHold('actual complete mapped marker payload SHA differs')
        # Even this small body must have the declared ordered segments and EOF.
        root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell[0]));offset=0
        for ordinal in range(header[5]):
            segment=scope.read_cell_segment_v3(cell[0],ordinal,meter=meter)
            if segment is None or segment[0]!=offset:raise C09PagedCaptureHold('actual mapped marker segment order differs')
            root=canonical_digest(('sylanne3.segmented-cell-link.v1',root,cell[0],ordinal,offset,len(segment[1]),segment[2]))
            offset+=len(segment[1])
        scope.require_cell_eof_v3(cell[0],header[5],meter=meter)
        if offset!=header[4] or root!=header[7]:raise C09PagedCaptureHold('actual mapped marker complete ordered root differs')
        return block==expected
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    with legacy_cell_read_transaction_v2(build.pair.source):
        _,total,kind=read_legacy_sql_cell_fragment_v2(build.pair.source,table=shape.table,column='value',
            where=where,parameters=key,start=0,length=0,meter=meter)
        if kind!='text' or total!=len(expected):return False
        block,actual_total,actual_kind=read_legacy_sql_cell_fragment_v2(build.pair.source,table=shape.table,column='value',
            where=where,parameters=key,start=0,length=total,meter=meter)
    return actual_kind=='text' and actual_total==total and block==expected


def _require_prior_erased_graph_row_v3(build,shape,key,meter):
    from .c09_paged_sql_v2 import c09_row_commitment_v2
    if build.prior_view is None or not _actual_erased_graph_marker_v3(build,shape,key,meter):
        raise C09PagedCaptureHold('historical erased Graph marker requires completed actual prior certificate')
    row=meter.read_row(build.pair.source,shape,key)
    if row is None:raise C09PagedCaptureHold('historical erased Graph row disappeared')
    values=dict(zip(shape.columns,row,strict=True))
    if values['valid']!=0 or shape.table=='graph_history' and values['dependencies']!='[]':
        raise C09PagedCaptureHold('historical erased Graph row retains payload facts')
    if 'value_cell_id' in shape.columns:
        from ..authority_service.c09_authority_storage_rebase import _row_commitment
        old=_row_commitment(shape.table,shape.columns,tuple(row))
    else:old=c09_row_commitment_v2(tuple(row))
    prior=build.prior_view.require_target_row_disposition(shape.table,key,old,meter=meter)
    if (prior.new_commitment!=old or prior.disposition not in {'payload_erased_retained_facts','preserved_exact'}
            or prior.disposition=='preserved_exact' and prior.old_commitment!=old):
        raise C09PagedCaptureHold('historical exact marker has no qualified erasure/preserved-facts disposition')
    ns=tuple(json.loads(build.scope.graph_namespace))
    tombstone=meter.read_fixed_row(build.pair.source,'graph_c09_erased_keys_v1',
        ('bot','persona','key_digest','maintenance_generation','operation_id'),
        'bot=? AND persona=? AND key_digest=?',(*ns,canonical_digest(key[0])))
    if tombstone is None:raise C09PagedCaptureHold('historical marker lacks actual old tombstone')
    from .c09_graph_originals_read_v5 import VerifiedPagedPriorGraphCertificateViewV2,VerifiedPriorGraphCertificateViewV2
    if type(build.prior_view) is VerifiedPagedPriorGraphCertificateViewV2:
        prior_scope=build.prior_view.reader.certificate.candidate.scope
        newly_generated=tombstone[3:]==(prior_scope.maintenance_generation,prior_scope.operation_id)
    elif type(build.prior_view) is VerifiedPriorGraphCertificateViewV2:
        reader=build.prior_view.reader
        newly_generated=tombstone[3:]==(reader.header['maintenance_generation'],reader.operation)
    else:raise C09PagedCaptureHold('actual historical marker requires registered completed prior view')
    if newly_generated:
        lineage=build.prior_view.require_generated_erased_key_v3(key[0],tombstone,meter=meter)
    else:
        tombstone_proof=build.prior_view.require_target_row_disposition('graph_c09_erased_keys_v1',
            tombstone[:3],c09_row_commitment_v2(tombstone),meter=meter)
        if tombstone_proof.new_commitment!=c09_row_commitment_v2(tombstone):
            raise C09PagedCaptureHold('historical erased marker tombstone lost its actual certificate lineage')
        lineage=asdict(tombstone_proof)
    return {'old_commitment':old,'prior_disposition':asdict(prior),'tombstone':tombstone,'tombstone_lineage':lineage}


_GRAPH_ERASURE_BASIS_V3=object()


class _GeneratedGraphErasureBasisV3:
    __slots__=('issuer','build','shape','key','old_commitment','basis_digest','locator','marker','basis_kind')
    def __init__(self,token,build,shape,key,old_commitment,basis_digest,basis_kind):
        if token is not _GRAPH_ERASURE_BASIS_V3:raise C09PagedCaptureHold('actual installed Graph marker basis required')
        self.issuer,self.build,self.shape,self.key=token,build,shape,key
        self.old_commitment,self.basis_digest,self.basis_kind=old_commitment,basis_digest,basis_kind
        self.locator={'role':'graph','family':shape.table,'primary_key':key,'column':'value',
            'source_schema_digest':shape.schema_digest,'producer_kind':basis_kind+'_erased_marker.v3',
            'basis_digest':basis_digest}
        self.marker=canonical_serialize({'schema':'sylanne3.graph.erased_value.v1',
            'key_digest':canonical_digest(key[0])}).encode('utf-8')
    def require_current(self,meter):
        fresh=_require_graph_erasure_basis_v3(self.build,self.shape,self.key,meter,basis_kind=self.basis_kind)
        if (self.issuer is not _GRAPH_ERASURE_BASIS_V3 or fresh.basis_digest!=self.basis_digest
                or fresh.old_commitment!=self.old_commitment or fresh.locator!=self.locator):
            raise C09PagedCaptureHold('actual generated Graph marker basis changed')
        return self






def _advance_marker_cause_capture_v3(build,key,budget,meter):
    """Separate actual cause capture cannot displace the converted Source parser."""
    from .c09_graph_row_codec_v2 import C09MemorySourceRowCaptureV3
    member=meter.read_fixed_row(build.pair.candidate,'c09_closure_members_v2',
        ('origin_stream_id','origin_record_ordinal','origin_commitment'),
        'scope_digest=? AND kind=? AND ref=?',(build.scope.scope_digest,'atom',key[0]))
    if member is None or member[0]==build.scope.barrier_digest:return True,None
    raw=meter.read_fixed_row(build.pair.candidate,'c09_capture_streams_v2',('identity_json',),
        'stream_id=?',(member[0],))
    if raw is None:raise C09PagedCaptureHold('marker cause lacks actual original stream')
    stream=c09_paged_value_from_wire_v2(json.loads(raw[0]),C09StreamIdentityV2)
    origin=meter.read_fixed_row(build.pair.candidate,'c09_capture_members_v2',('primary_key_json','commitment'),
        'stream_id=? AND record_ordinal=?',(member[0],member[1]))
    if origin is None or origin[1]!=member[2]:raise C09PagedCaptureHold('marker cause original member differs')
    cause_key=tuple(json.loads(origin[0]));shape=read_c09_table_shape_v2(build.pair.source,stream.family)
    if stream!=_source_stream_identity_v2(build,shape,'graph_facts'):
        raise C09PagedCaptureHold('marker cause crosses actual source role/schema/PK')
    metadata=_read_frozen_source_row_metadata_v3(build,shape,cause_key,meter)
    if not _large_memory_source_v3(shape,cause_key,metadata,meter):return True,None
    capture=build.marker_cause_capture_v3
    if capture is None or capture.shape!=shape or capture.key!=cause_key or capture.metadata!=metadata:
        capture=_begin_graph_source_capture_v3(build,shape,cause_key,metadata)
    if capture.row.complete and capture.value.complete and capture.quantum_completed:
        if capture.require_complete(build,shape,cause_key,metadata)!=member[2]:
            raise C09PagedCaptureHold('complete marker cause differs from actual original SQL commitment')
        return True,None
    return False,capture.next_quantum(budget)


def _advance_graph_marker_cause_v3(build,key):
    started=monotonic_ns()
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            ready,pending=_advance_marker_cause_capture_v3(build,key,budget,meter)
    if pending is not None:
        pending.quantum_completed=True;build.marker_cause_capture_v3=pending
    if ready:return None
    return _graph_step_report_v2(build,'target_marker_cause',meter,started)


def _require_generated_closure_origin_v3(build,key,member,meter):
    """Validate the actual cause original independently of the converted row."""
    from .c09_source_plan_barrier_v2 import C09SourceBarrierVerificationV2,next_c09_barrier_source_member_v2
    from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,require_c09_capture_member_v2,c09_row_commitment_v2
    from ..graph_types import AtomKey
    view=build.barrier_view
    if (type(view) is not C09SourceBarrierVerificationV2 or view.session is not build.session
            or view.db is not build.pair.source or not view.complete or view.receipt.digest!=build.scope.barrier_digest):
        raise C09PagedCaptureHold('generated marker origin lacks actual same-session completed barrier')
    with legacy_cell_read_transaction_v2(build.pair.source):
        view.require_current()
        if member[0]==build.scope.barrier_digest:
            ns=tuple(json.loads(build.scope.graph_namespace))
            previous=meter.read_fixed_row(build.pair.source,'graph_c09_source_members_v2',('source_ref',),
                'bot=? AND persona=? AND operation_id=? AND affected=1 AND source_ref<? ORDER BY source_ref DESC',
                (*ns,build.scope.operation_id,key[0]))
            actual=next_c09_barrier_source_member_v2(view,'' if previous is None else previous[0],budget=meter.budget)
            if actual is None or (actual['source_ref'],actual['record_ordinal'],actual['record_commitment'])!=(key[0],member[1],member[2]):
                raise C09PagedCaptureHold('generated marker closure seed lost actual barrier page membership')
            return
        raw=meter.read_fixed_row(build.pair.candidate,'c09_capture_streams_v2',('identity_json','status'),
            'stream_id=?',(member[0],))
        if raw is None or raw[1]!='sealed':raise C09PagedCaptureHold('generated marker cause has no actual sealed original stream')
        stream=c09_paged_value_from_wire_v2(json.loads(raw[0]),C09StreamIdentityV2)
        if stream.scope_digest!=build.scope.scope_digest or stream.stream_kind!='graph_facts':
            raise C09PagedCaptureHold('generated marker cause crossed actual scope/original family')
        original=meter.read_fixed_row(build.pair.candidate,'c09_capture_members_v2',('primary_key_json','commitment'),
            'stream_id=? AND record_ordinal=?',(member[0],member[1]))
        if original is None or original[1]!=member[2]:raise C09PagedCaptureHold('generated marker cause member commitment differs')
        cause_key=tuple(json.loads(original[0]))
        require_c09_capture_member_v2(build.pair.candidate,stream,member[1],cause_key,member[2],meter=meter)
        shape=read_c09_table_shape_v2(build.pair.source,stream.family)
        if stream!=_source_stream_identity_v2(build,shape,'graph_facts'):
            raise C09PagedCaptureHold('generated marker cause identity differs from actual role source/schema/PK')
        metadata=_read_frozen_source_row_metadata_v3(build,shape,cause_key,meter)
        if _large_memory_source_v3(shape,cause_key,metadata,meter):
            capture=build.marker_cause_capture_v3
            if capture is None or capture.require_complete(build,shape,cause_key,metadata)!=member[2]:
                raise C09PagedCaptureHold('generated marker cause needs independently completed streamed original')
        else:
            row=meter.read_row(build.pair.source,shape,cause_key)
            if row is None or c09_row_commitment_v2(tuple(row))!=member[2]:
                raise C09PagedCaptureHold('generated marker cause differs from actual frozen SQL row')
        # This member is produced only by the actual fixed-point algorithm.
        # Exact cause membership is independently replayed through all physical
        # typed/history edges before a cold generated reader can qualify it.


def _require_graph_erasure_basis_v3(build,shape,key,meter,*,basis_kind='current_closure'):
    """Actual source member and sealed accepted closure; no future disposition."""
    from ..graph_types import AtomKey
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_paged_sql_v2 import require_c09_capture_member_v2
    if type(build) is not InstalledGraphRebaseBuildV2 or shape.table not in {'graph_atoms','graph_history'}:
        raise C09PagedCaptureHold('actual installed Graph marker build required')
    build.require_current();atom=AtomKey.from_token(key[0])
    if atom.type_name=='memory.access':raise C09PagedCaptureHold('registered access facts retain their original payload')
    closure=C09ClosureIndexV2(build.pair.candidate,build.scope)
    if closure._state()[3]!='sealed' or build.barrier_view is None or not build.barrier_view.complete:
        raise C09PagedCaptureHold('generated Graph marker requires actual accepted barrier and sealed closure')
    member=meter.read_fixed_row(build.pair.candidate,'c09_closure_members_v2',
        ('origin_stream_id','origin_record_ordinal','origin_commitment'),
        'scope_digest=? AND kind=? AND ref=?',(build.scope.scope_digest,'atom',key[0]))
    if basis_kind=='current_closure':
        if member is None:raise C09PagedCaptureHold('generated Graph marker has no actual closure member')
        _require_generated_closure_origin_v3(build,key,member,meter)
    if basis_kind not in {'current_closure','prior_erased'}:
        raise C09PagedCaptureHold('unknown registered generated Graph marker basis')
    prior=_require_prior_erased_graph_row_v3(build,shape,key,meter) if basis_kind=='prior_erased' else None
    locator=_actual_source_locator_v2(build,shape,meter)
    original=meter.read_fixed_row(build.pair.candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
    if original is None:raise C09PagedCaptureHold('generated Graph marker lacks its complete original row')
    require_c09_capture_member_v2(build.pair.candidate,locator.identity,original[0],key,original[1],meter=meter)
    digest=canonical_digest({'schema':'sylanne3.graph-erasure-basis.v3','scope':build.scope.scope_digest,
        'source_stream':locator.identity.stream_id,'source_ordinal':original[0],'old_commitment':original[1],
        'closure_origin':member if basis_kind=='current_closure' else None,'prior_erased':prior,
        'basis_kind':basis_kind,'barrier_digest':build.scope.barrier_digest,'key':key,'family':shape.table})
    return _GeneratedGraphErasureBasisV3(_GRAPH_ERASURE_BASIS_V3,build,shape,key,original[1],digest,basis_kind)




def _advance_graph_marker_barrier_v3(build):
    """A restarted target rebuilds the actual private barrier view from byte zero."""
    from .c09_source_plan_barrier_v2 import begin_verify_c09_source_barrier_v2,advance_verify_c09_source_barrier_v2
    from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2
    started=monotonic_ns()
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter),legacy_cell_read_transaction_v2(build.pair.source):
            if build.barrier_view is None:
                build.barrier_view=begin_verify_c09_source_barrier_v2(build.pair.source,session=build.session)
            if not build.barrier_view.complete:
                advance_verify_c09_source_barrier_v2(build.barrier_view,budget=budget)
    build.require_current()
    return _graph_step_report_v2(build,'target_barrier_recovery',meter,started)


def _advance_graph_ref_cell_v3(build,progress,shape):
    """Real retained-row copy/seal; withdrawn bodies never enter new segments."""
    from ..segmented_sql_cell_v1 import (open_c09_segmented_target_v1,VerifiedSealedCellV1,
        _GeneratedGraphMarkerWriterV3,_GeneratedGraphMarkerSealV3)
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2,capture_read_transaction_v2
    if build.segmented_target_v3 is None:
        build.segmented_target_v3=open_c09_segmented_target_v1(build.session,build.pair)
    target=build.segmented_target_v3;sealed=None;started=monotonic_ns()
    if build.barrier_view is None or not build.barrier_view.complete:
        return _advance_graph_marker_barrier_v3(build)
    if not build.target_prior_checked_v3:
        inspection=capture_prior_graph_certificate_v2(build)
        if inspection is None:return {'status':'progress','phase':'target_prior_recovery'}
        build.target_prior_checked_v3=True
    cause_report=_advance_graph_marker_cause_v3(build,tuple(progress['row_complete']))
    if cause_report is not None:return cause_report
    with target.quantum() as quantum:
        meter=quantum.meter
        closure=C09ClosureIndexV2(build.pair.candidate,build.scope)
        if closure._state()[3]!='sealed':raise C09PagedCaptureHold('GraphV3 reference publication requires actual sealed closure')
        key=tuple(progress['row_complete'])
        stream=_source_stream_identity_v2(build,shape,'row_dispositions')
        cursor=read_capture_cursor_v2(build.pair.candidate,stream)
        with capture_read_transaction_v2(build.pair.source):
            found=read_c09_next_row_metadata_v2(build.pair.source,shape,cursor.last_key)
        if found is None or found[0]!=key:
            raise C09PagedCaptureHold('GraphV3 cell continuation is not the actual next source row')
        from ..graph_types import AtomKey
        erased=closure.contains_atom(key[0]) and AtomKey.from_token(key[0]).type_name!='memory.access'
        historical=_actual_erased_graph_marker_v3(build,shape,key,meter)
        if historical and build.prior_view is None:
            raise C09PagedCaptureHold('historical erased marker target requires its independently restored prior view')
        writer=build.segmented_writer_v3
        if writer is None:
            if erased or historical:
                basis=_require_graph_erasure_basis_v3(build,shape,key,meter,
                    basis_kind='prior_erased' if historical else 'current_closure')
                writer=_GeneratedGraphMarkerWriterV3(target,quantum,basis)
            elif 'value_cell_id' in shape.columns:
                capture=build.source_row_capture_v3
                from .c09_graph_row_codec_v2 import C09MappedGraphRowCaptureV3
                if type(capture) is not C09MappedGraphRowCaptureV3 or capture.key!=key:
                    raise C09PagedCaptureHold('mapped target copy requires its actual completed Source semantic row')
                capture.require_complete(build,shape,key,capture.metadata)
                writer=target.begin_mapped_cell_copy(quantum,source_row=capture.row.result,column='value')
            else:writer=target.begin_cell_copy(quantum,table=shape.table,primary_key=key,column='value')
        elif writer.shape!=shape or writer.key!=key or writer.column!='value':
            raise C09PagedCaptureHold('GraphV3 cell writer belongs to another actual logical row')
        if writer.phase=='write':writer.advance(quantum)
        elif writer.phase=='replay_prefix':writer.replay_prefix(quantum)
        elif writer.phase=='verify':
            value=writer.verify_and_seal(quantum)
            if type(value) in (VerifiedSealedCellV1,_GeneratedGraphMarkerSealV3):sealed=value
        else:raise C09PagedCaptureHold('GraphV3 sealed writer requires exact publication recovery')
        next_progress=dict(progress)
        if sealed is not None:next_progress['scan_phase']='ref_publish'
        with capture_transaction_v2(build.pair.candidate):_save_graph_progress_v2(build,'target',next_progress,meter)
    build.segmented_writer_v3=writer
    if sealed is not None:build.segmented_seal_v3=sealed
    build.require_current()
    return _graph_step_report_v2(build,'target',meter,started)


def _publish_graph_ref_row_v3(build,progress,shape):
    """Publish real reference/disposition/page/cursor atomically in the candidate."""
    from ..segmented_sql_cell_v1 import graph_ref_columns_v3,open_c09_segmented_target_v1
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_paged_sql_v2 import (_load_census,_capture_data_state,_quote,_wire,
        require_c09_capture_member_v2,c09_row_commitment_v2,capture_read_transaction_v2)
    from .c09_paged_capture_contract_v2 import C09CaptureRecordV2,append_c09_page_v2
    from ..graph_types import AtomKey
    if build.segmented_target_v3 is None:
        build.segmented_target_v3=open_c09_segmented_target_v1(build.session,build.pair)
    target=build.segmented_target_v3;key=tuple(progress['row_complete']);started=monotonic_ns()
    if build.segmented_seal_v3 is None:
        # A cold process rechecks real prefix/segments/source, not a stored seal flag.
        replay_progress=dict(progress);replay_progress['scan_phase']='ref_copy'
        return _advance_graph_ref_cell_v3(build,replay_progress,shape)
    with target.quantum() as quantum:
        meter=quantum.meter;candidate=build.pair.candidate;source=build.pair.source
        ref=build.segmented_seal_v3.require_current(target,quantum=quantum,
            table=shape.table,primary_key=key,column='value')
        closure=C09ClosureIndexV2(candidate,build.scope)
        from ..segmented_sql_cell_v1 import _GeneratedGraphMarkerSealV3
        erased=closure.contains_atom(key[0]) and AtomKey.from_token(key[0]).type_name!='memory.access'
        historical=_actual_erased_graph_marker_v3(build,shape,key,meter)
        generated=type(build.segmented_seal_v3) is _GeneratedGraphMarkerSealV3
        if closure._state()[3]!='sealed' or (erased or historical)!=generated:
            raise C09PagedCaptureHold('GraphV3 publication differs from its actual retained/generated Source basis')
        stream=_source_stream_identity_v2(build,shape,'row_dispositions')
        locator=_actual_source_locator_v2(build,shape,meter)
        original=meter.read_fixed_row(candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
        if original is None:raise C09PagedCaptureHold('GraphV3 reference lost its actual original SQL row member')
        require_c09_capture_member_v2(candidate,locator.identity,original[0],key,original[1],meter=meter)
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
        mapped_source='value_cell_id' in shape.columns
        value_column='value_cell_id' if mapped_source else 'value'
        small_columns=tuple(name for name in shape.columns if name!=value_column)
        with capture_read_transaction_v2(source):
            small=meter.read_fixed_row(source,shape.table,small_columns,where,key)
        if small is None:raise C09PagedCaptureHold('GraphV3 reference source metadata disappeared')
        facts=dict(zip(small_columns,small,strict=True));facts[value_column]=ref.cell_id
        if erased or historical:
            facts['valid']=0
            if shape.table=='graph_history':facts['dependencies']='[]'
        row=tuple(facts[name] for name in shape.columns)
        columns=graph_ref_columns_v3(shape.columns)
        if mapped_source:
            from ..authority_service.c09_authority_storage_rebase import _row_commitment
            new_commitment=_row_commitment(shape.table,columns,row)
        else:new_commitment=c09_row_commitment_v2(row)
        proof=(build.scope.scope_digest,shape.table,canonical_digest((shape.table,key)),canonical_serialize(key),
            original[1],'payload_erased_retained_facts' if erased and not historical else ('logical_preserved_v3' if mapped_source and not historical else 'rebuilt_from_surviving_sources'),
            new_commitment,locator.identity.stream_id,original[0])
        disposition_table='c09_graph_dispositions_v2';disposition_columns=GRAPH_DISPOSITION_COLUMNS_V2
        if mapped_source and not (erased or historical):
            from .c09_logical_source_v3 import CompleteLogicalSourceRowV3
            from .c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
            completed=build.segmented_writer_v3.mapped_source
            if type(completed) is not CompleteLogicalSourceRowV3 or completed.scope.source is not source:
                raise C09PagedCaptureHold('logical disposition lacks its actual qualified Source row')
            completed.scope.require_current(meter=meter)
            descriptor=require_c09_logical_source_row_member_v3(candidate,locator.identity,role='graph',
                table_name=shape.table,key=key,record_ordinal=original[0],meter=meter)
            if canonical_serialize(descriptor)!=canonical_serialize(completed.descriptor):
                raise C09PagedCaptureHold('logical disposition Source descriptor differs from its actual producer')
            header=quantum.read_header(candidate,ref.cell_id)
            source_header=completed.scope.read_cell_header_v3(descriptor['cell_bindings'][0]['cell_id'],meter=meter)
            proof+=_graph_logical_preservation_original_v3(build.scope.scope_digest,shape.table,key,descriptor,source_header,header,new_commitment)
            disposition_table='c09_graph_dispositions_v3';disposition_columns=GRAPH_DISPOSITION_COLUMNS_V3
        with capture_transaction_v2(candidate):
            _load_census(candidate,stream)
            cursor=read_capture_cursor_v2(candidate,stream);data=_capture_data_state(candidate,stream)
            existing=_read_graph_disposition_original_row_v3(candidate,build.scope.scope_digest,shape.table,key,meter)
            actual=meter.read_fixed_row(candidate,shape.table,columns,where,key)
            if existing is not None:
                if existing!=proof or actual!=row:
                    raise C09PagedCaptureHold('GraphV3 committed reference/disposition replay differs')
                member=meter.read_fixed_row(candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
                    'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(key)))
                if member is None or member[1]!=c09_row_commitment_v2(proof):
                    raise C09PagedCaptureHold('GraphV3 committed reference lost its actual capture page')
                require_c09_capture_member_v2(candidate,stream,member[0],key,member[1],meter=meter)
            else:
                if actual is not None:raise C09PagedCaptureHold('GraphV3 logical row exists without this atomic disposition')
                from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
                with capture_read_transaction_v2(source):found=read_c09_next_row_metadata_v2(source,shape,cursor.last_key)
                if found is None or found[0]!=key or data['eof'] is not None:
                    raise C09PagedCaptureHold('GraphV3 publication is not its actual current capture cursor')
                meter.write_row(candidate,shape.table,columns,row)
                meter.write_row(candidate,disposition_table,disposition_columns,proof)
                record=C09CaptureRecordV2(key,c09_row_commitment_v2(proof))
                page=append_c09_page_v2(stream,cursor,(record,))
                quantum.mutate(candidate,'INSERT INTO c09_capture_pages_v2 VALUES(?,?,?,?)',
                    (stream.stream_id,page.page_index,_wire(page),json.dumps([asdict(record)],sort_keys=True,separators=(',',':'))))
                quantum.mutate(candidate,'INSERT INTO c09_capture_members_v2 VALUES(?,?,?,?,?,?)',
                    (stream.stream_id,cursor.record_offset+1,canonical_digest(key),canonical_serialize(key),record.commitment,page.page_index))
                data['cursor']=asdict(page.next_cursor)
                quantum.mutate(candidate,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",
                    (canonical_serialize(data),stream.stream_id))
                if not (erased or historical) and shape.table=='graph_atoms' and AtomKey.from_token(key[0]).type_name=='d09.turn_slot.v1':
                    if mapped_source:
                        from .c09_graph_row_codec_v2 import C09MappedGraphRowCaptureV3
                        capture=build.source_row_capture_v3
                        if (type(capture) is not C09MappedGraphRowCaptureV3 or capture.key!=key
                                or capture.shape!=shape or not capture.value.complete or not capture.quantum_completed
                                or capture.row.result is not build.segmented_writer_v3.mapped_source):
                            raise C09PagedCaptureHold('turn-slot origin lacks its real completed typed Source producer')
                        value=capture.value.parser.value
                    else:
                        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
                        with capture_read_transaction_v2(source):
                            block,total,kind=read_legacy_sql_cell_fragment_v2(source,table=shape.table,column='value',
                                where=where,parameters=key,start=0,length=min(ref.total_bytes,16384),meter=meter)
                        if total!=ref.total_bytes or total>16384 or kind!='text':
                            raise C09PagedCaptureHold('turn-slot origin requires its registered bounded typed projection')
                        value=json.loads(block)
                        build.session._control.maintenance.graph._registry.validate(AtomKey.from_token(key[0]),value)
                    origin=value['origin_ref']
                    if type(origin) is not str:raise C09PagedCaptureHold('turn-slot actual origin differs')
                    projection=(key[0],facts['bot'],facts['persona'],origin)
                    meter.write_row(candidate,'graph_d09_turn_slot_origins_v3',('token','bot','persona','origin_ref'),projection)
                    generated=(build.scope.scope_digest,'graph_d09_turn_slot_origins_v3',
                        canonical_digest(('graph_d09_turn_slot_origins_v3',(key[0],))),canonical_serialize((key[0],)),
                        c09_row_commitment_v2(projection),'d09_turn_slot_origin_v3',key[0],original[1])
                    meter.write_row(candidate,'c09_graph_generated_rows_v2',
                        ('scope_digest','table_name','key_digest','key_json','row_commitment','producer','origin_ref','origin_digest'),generated)
            next_progress=dict(progress)
            next_progress.update(scan_phase='patterns',pattern_kind='atom',pattern_after=None,nested_hit=False,row_complete=None)
            _save_graph_progress_v2(build,'target',next_progress,meter)
    build.segmented_writer_v3=None;build.segmented_seal_v3=None;build.source_row_capture_v3=None
    build.require_current()
    return _graph_step_report_v2(build,'target',meter,started,1)


def _advance_graph_target_v2(build,progress):
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
    source=build.pair.source;candidate=build.pair.candidate;started=monotonic_ns()
    if progress.get('scan_phase')=='world_producer_metadata':
        from .c09_world_producer_metadata_v1 import advance_world_producer_target_phase_v1
        return advance_world_producer_target_phase_v1(build,progress)
    source_target_used=False;source_target_pending=None
    table=progress.get('table') or _next_graph_logical_source_table_v3(build,None)
    shape=read_c09_table_shape_v2(source,table);stream=_source_stream_identity_v2(build,shape,'row_dispositions')
    if shape.table=='graph_contact_expression_plan_originals_v3' and progress.get('scan_phase') in {'contact_plan_copy','contact_plan_publish','contact_plan_remove'}:
        from .c09_contact_plan_physical_v3 import advance_contact_plan_target_v3
        return advance_contact_plan_target_v3(build,progress,shape)
    if shape.table=='graph_domain_production_originals_v3' and progress.get('scan_phase') in {'domain_copy','domain_publish','domain_remove'}:
        from .c09_domain_original_source_v3 import advance_domain_original_target_v3
        return advance_domain_original_target_v3(build,progress,shape)
    if shape.table in {'graph_atoms','graph_history'} and progress.get('scan_phase')=='ref_copy':
        return _advance_graph_ref_cell_v3(build,progress,shape)
    if shape.table in {'graph_atoms','graph_history'} and progress.get('scan_phase')=='ref_publish':
        return _publish_graph_ref_row_v3(build,progress,shape)
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            closure=C09ClosureIndexV2(candidate,build.scope)
            if closure._state()[3]!='sealed':raise C09PagedCaptureHold('target requires actual complete dependency fixed point')
            with capture_transaction_v2(candidate):begin_capture_stream_v2(candidate,stream)
            if progress.get('scan_phase','census')=='census':
                result=advance_c09_census_v2(source,candidate,stream,_mapped_graph_source_shape_v3(build,shape,meter) or shape,budget,check_frozen_source=build.pair.check_source,meter=meter)
                if result['eof']:progress['scan_phase']='patterns'
            elif progress['scan_phase']=='patterns':
                cursor=read_capture_cursor_v2(candidate,stream);source.execute('BEGIN')
                try:
                    found=read_c09_next_row_metadata_v2(source,shape,cursor.last_key)
                    if found is None:progress['scan_phase']='rows';progress['row_complete']=None
                    else:
                        key,metadata=found
                        if _large_memory_source_v3(shape,key,metadata,meter):
                            hit,done,pending,actual=_advance_source_nested_match_v3(
                                build,shape,key,metadata,closure,progress,budget,meter)
                            source_target_pending=pending;source_target_used=True
                            if done:
                                if shape.table=='graph_contact_expression_plan_originals_v3':
                                    removed=closure.contains_operation(pending.proof.producing_operation_id) or hit
                                    progress.update(scan_phase='contact_plan_remove' if removed else 'contact_plan_copy',row_complete=key,nested_hit=hit)
                                elif shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
                                    from .c09_domain_original_source_v3 import _domain_removed_v3
                                    removed=_domain_removed_v3(pending,closure,hit)
                                    progress.update(scan_phase='domain_remove' if removed else 'domain_copy',row_complete=key,nested_hit=hit)
                                else:progress.update(scan_phase='ref_copy',row_complete=key,nested_hit=hit)
                        else:
                            if sum(n or 0 for _,n in metadata)*9>meter.remaining_bytes:raise C09PagedCaptureHold('target pattern row needs registered streaming semantic codec')
                            row=tuple(meter.read_row(source,shape,key))
                            from .c09_b3_managed_metadata_v1 import prepare_b3_managed_source_row_v1
                            if not prepare_b3_managed_source_row_v1(build,shape,key,row,meter):
                                progress['historical_waiting']=False
                            elif _prepare_historical_row_stream_v2(build,shape,row,meter):
                                progress['historical_waiting']=True
                            else:
                                progress['historical_waiting']=False
                                hit,done=_graph_nested_advance_v2(closure,_graph_row_nested_value_v2(shape,row),progress,budget,meter)
                                if done:
                                    progress.update(scan_phase='ref_copy' if shape.table in {'graph_atoms','graph_history'} else 'rows',
                                        row_complete=key,nested_hit=hit)
                finally:source.rollback()
                if shape.table=='graph_world_revision_index_v1' and progress.get('scan_phase')=='rows':
                    progress['scan_phase']='world_producer_metadata'
                if progress.get('historical_waiting'):
                    _advance_historical_row_stream_v2(build,budget,meter)
            else:
                expected=None if progress.get('row_complete') is None else tuple(progress['row_complete'])
                def transform(db,actual_shape,key,row,remaining):
                    row_meter=current_c09_sql_meter_v2()
                    if expected is not None and key!=expected:
                        raise C09PagedCaptureHold('target row pattern continuation does not match actual capture cursor')
                    if expected is None:raise C09PagedCaptureHold('actual target needs its complete same-row pattern sweep')
                    origin=_actual_source_row_origin_v2(build,shape,key,row,row_meter)
                    disposition,target=_classify_graph_target_row_v2(build,shape,key,row,closure,progress.get('nested_hit',False),origin,one,row_meter)
                    if target is not None:row_meter.write_row(db,shape.table,shape.columns,target)
                    if disposition=='derived_removed' and shape.table=='graph_world_revision_index_v1':
                        _generate_world_erasure_barrier_v1(build,db,shape,key,row,origin,row_meter)
                    proof=(build.scope.scope_digest,shape.table,canonical_digest((shape.table,key)),canonical_serialize(key),
                        _row_digest(row),disposition,None if target is None else _row_digest(target),origin['origin_stream_id'],origin['origin_record_ordinal'])
                    row_meter.write_row(db,'c09_graph_dispositions_v2',
                        ('scope_digest','table_name','key_digest','source_primary_key_json','old_commitment','disposition','new_commitment','origin_stream_id','origin_record_ordinal'),proof)
                    return C09RowTransformResultV2(_row_digest(proof),0,0)
                # Capture the one row whose full nested-pattern sweep is complete.
                from dataclasses import replace
                available_local=budget.max_local_ns-(monotonic_ns()-started)
                if available_local<=0:
                    return _graph_step_report_v2(build,'target',meter,started)
                one=replace(budget,max_records=1,max_bytes=meter.remaining_bytes,max_local_ns=available_local)
                engine_meter=require_c09_reserved_meter_v3(one)
                result=advance_c09_rows_v2(source,candidate,stream,shape,one,
                    check_frozen_source=build.pair.check_source,
                    transform_row=transform,meter=engine_meter)
                if result['eof']:
                    with capture_transaction_v2(candidate):
                        complete=seal_capture_stream_v2(candidate,stream);_directory_put_v2(build,'c09_graph_disposition_directory_v2',stream,complete,meter)
                    following=_next_graph_logical_source_table_v3(build,table);progress={'table':following,'scan_phase':'census','pattern_kind':'atom','pattern_after':None}
                    if following is None:
                        with capture_transaction_v2(candidate):_save_graph_progress_v2(build,'owner_outputs',{'after':'','prepared_digest':None,'name_index':0},meter)
                        return _graph_step_report_v2(build,'owner_outputs',meter,started)
                else:progress.update(scan_phase='patterns',pattern_kind='atom',pattern_after=None,nested_hit=False,row_complete=None)
            progress['table']=table if progress.get('table') is None else progress['table']
            with capture_transaction_v2(candidate):_save_graph_progress_v2(build,'target',progress,meter)
    if source_target_used:
        if source_target_pending is not None:source_target_pending.quantum_completed=True
        build.source_row_capture_v3=source_target_pending
    return _graph_step_report_v2(build,'target',meter,started)


def _advance_graph_generated_v2(build,progress):
    from .c09_closure_index_v2 import C09ClosureIndexV2
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    candidate=build.pair.candidate;started=monotonic_ns();namespace=tuple(json.loads(build.scope.graph_namespace))
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter),capture_transaction_v2(candidate):
            closure=C09ClosureIndexV2(candidate,build.scope);count=0;last=progress.get('after_ref')
            while count<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
                members=closure.iter_members('atom',last,1);member=next(members,None)
                if member is None:
                    _save_graph_progress_v2(build,'deferred_schema',{'object_key':None},meter)
                    return _graph_step_report_v2(build,'deferred_schema',meter,started,count)
                ref,origin_stream,ordinal,origin=member;digest=canonical_digest(ref)
                source_exists=build.pair.source.execute('SELECT 1 FROM graph_atoms WHERE token=? UNION ALL SELECT 1 FROM graph_history WHERE token=? LIMIT 1',(ref,ref)).fetchone()
                if source_exists is None:raise C09PagedCaptureHold('actual Source closure names no frozen Graph body')
                existing=meter.read_fixed_row(candidate,'graph_c09_erased_keys_v1',
                    ('bot','persona','key_digest','maintenance_generation','operation_id'),'bot=? AND persona=? AND key_digest=?',(*namespace,digest))
                if existing is None:
                    row=(*namespace,digest,build.scope.maintenance_generation,build.scope.operation_id)
                    meter.write_row(candidate,'graph_c09_erased_keys_v1',('bot','persona','key_digest','maintenance_generation','operation_id'),row)
                    pk=(*namespace,digest);proof=(build.scope.scope_digest,'graph_c09_erased_keys_v1',canonical_digest(('graph_c09_erased_keys_v1',pk)),
                        canonical_serialize(pk),_row_digest(row),'c09_erased_key_v2',ref,origin)
                    meter.write_row(candidate,'c09_graph_generated_rows_v2',
                        ('scope_digest','table_name','key_digest','key_json','row_commitment','producer','origin_ref','origin_digest'),proof)
                last=ref;count+=1
            _save_graph_progress_v2(build,'generated',{'after_ref':last},meter)
    return _graph_step_report_v2(build,'generated',meter,started,count)


def _advance_actual_cold_schema_v2(progress,budget,meter,started):
    """Independently observe every real target schema object through actual EOF."""
    progress.read_db.execute('BEGIN');count=0
    try:
        while count<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
            obj=read_c09_next_schema_object_v2(progress.read_db,progress.schema_key,max_bytes=meter.remaining_bytes)
            if obj is None:
                if progress.schema_count!=progress.candidate.schema_catalogue.complete.record_count:
                    raise C09PagedCaptureHold('actual target SQLite catalogue has an omitted or surplus object')
                progress.target_schema_eof=True;progress.phase='directories';break
            saved=meter.read_fixed_row(progress.read_db,'c09_graph_target_schema_v2',
                ('table_name','target_sql'),'scope_digest=? AND object_type=? AND object_name=?',
                (progress.session.scope.scope_digest,obj.object_type,obj.name))
            if saved!=(obj.table_name,obj.sql):raise C09PagedCaptureHold('actual target schema is outside the sealed catalogue')
            progress.schema_key=obj.primary_key;progress.schema_count+=1;count+=1
    finally:progress.read_db.rollback()
    return {'status':'progress','phase':progress.phase,'completed_records':count,
        'actual_meter_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
        'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def _advance_actual_cold_nested_v2(progress,budget,meter,started):
    """Nested streams get independent census and complete immutable-page verification."""
    field=progress.nested_field;table=_GRAPH_DIRECTORY_TABLES_V2[_GRAPH_DIRECTORY_FIELDS_V2.index(field)]
    with c09_sql_meter_quantum_v2(meter):
        if progress.nested_locator is None:
            after='' if progress.nested_after is None else progress.nested_after
            row=meter.read_fixed_row(progress.read_db,table,('family','identity_json','complete_json'),
                'scope_digest=? AND family COLLATE BINARY>? ORDER BY family COLLATE BINARY',
                (progress.session.scope.scope_digest,after))
            if row is None:
                progress.verified_directories+=1;progress.locator_index+=1;progress.phase='directories'
                progress.nested_field=None;return {'status':'progress','phase':'directories','actual_meter_bytes':meter.consumed_bytes}
            from .c09_paged_capture_contract_v2 import C09CompleteStreamV2
            stream=c09_paged_value_from_wire_v2(json.loads(row[1]),C09StreamIdentityV2)
            complete=c09_paged_value_from_wire_v2(json.loads(row[2]),C09CompleteStreamV2)
            if stream.family!=row[0]:raise C09PagedCaptureHold('nested Graph family differs from its directory key')
            progress.disposition_inventory_version_v3=0;progress.disposition_inventory_after_v3='';progress.disposition_inventory_count_v3=0
            progress.nested_locator=C09SealedStreamLocatorV2('graph',stream,complete)
            progress.nested_verification=begin_c09_stream_verification_v2(progress.read_db,stream)
            if progress.nested_verification.seal_digest!=complete.digest:raise C09PagedCaptureHold('nested complete original differs')
        locator=progress.nested_locator;stream=locator.identity
        source=progress.pair.source if field=='disposition_directory' else progress.census_db
        shape=read_c09_table_shape_v2(source,stream.family)
        census_shape=(_mapped_graph_source_shape_v3(progress.cold_build,shape,meter) or shape) if field=='disposition_directory' else shape
        if not progress.nested_verification.census_complete:
            result=advance_verify_c09_census_v2(source,progress.read_db,stream,census_shape,budget,
                verification=progress.nested_verification,check_frozen_source=progress.pair.require_current,meter=meter)
        else:
            result=advance_verify_c09_stream_v2(progress.read_db,stream,budget,verification=progress.nested_verification,
                verify_record=lambda record:_verify_actual_nested_record_v2(progress,field,shape,record,meter),meter=meter)
            if result['complete']:
                if field=='disposition_directory' and not _advance_graph_disposition_inventory_v3(progress,stream,locator.complete,shape,meter):
                    result['complete']=False
                else:
                    progress.nested_after=stream.family;progress.nested_locator=None;progress.nested_verification=None
    result.update(status='progress',phase=progress.phase,nested_directory=field,actual_meter_bytes=meter.consumed_bytes,
        local_ns=monotonic_ns()-started)
    return result


def _verify_actual_nested_record_v2(progress,field,shape,record,meter):
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    if field=='disposition_directory':
        proof=_read_graph_disposition_original_row_v3(progress.read_db,progress.session.scope.scope_digest,shape.table,record.primary_key,meter)
        if proof is None or proof[3]!=canonical_serialize(record.primary_key) or _row_digest(tuple(proof))!=record.commitment:
            raise C09PagedCaptureHold('nested disposition record differs from its exact nine-field original')
        if shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
            from .c09_domain_original_source_v3 import verify_cold_domain_original_v3
            metadata=_read_frozen_source_row_metadata_v3(progress.cold_build,shape,record.primary_key,meter)
            result=verify_cold_domain_original_v3(progress,shape,record.primary_key,metadata,meter,verify_semantics=False)
            return False if result is None else None
        if shape.table in {'graph_atoms','graph_history'}:
            from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
            actual=meter.read_fixed_row(progress.read_db,'sqlite_master',('sql',),'type=? AND name=?',('table',shape.table))
            if actual==(GRAPH_REF_DDLS_V3[shape.table],):
                metadata=_read_frozen_source_row_metadata_v3(progress.cold_build,shape,record.primary_key,meter)
                result=_verify_cold_graph_ref_source_v3(progress,shape,record.primary_key,metadata,meter,verify_semantics=False)
                return False if result is None else None
        row=meter.read_row(progress.pair.source,shape,record.primary_key)
        if row is None or _row_digest(tuple(row))!=proof[4]:raise C09PagedCaptureHold('nested disposition lost its actual source row')
        result=_verify_cold_source_row_v2(progress,shape,record.primary_key,tuple(row),meter,verify_semantics=False)
        return False if result is None else None
    elif field=='target_directory':
        if shape.table in ('graph_domain_production_originals_v3','graph_contact_expression_plan_originals_v3'):
            from .c09_domain_original_source_v3 import verify_cold_domain_original_v3
            source_shape=read_c09_table_shape_v2(progress.pair.source,shape.table)
            metadata=_read_frozen_source_row_metadata_v3(progress.cold_build,source_shape,record.primary_key,meter)
            result=verify_cold_domain_original_v3(progress,source_shape,record.primary_key,metadata,meter,verify_semantics=False)
            if result is None:return False
            from ..authority_service.c09_authority_storage_rebase import _row_commitment
            row=meter.read_row(progress.read_db,shape,record.primary_key)
            if row is None or c09_row_commitment_v2(tuple(row))!=record.commitment:
                raise C09PagedCaptureHold('actual Domain target directory physical member differs')
            return None
        row=meter.read_row(progress.read_db,shape,record.primary_key)
        if row is None or _row_digest(tuple(row))!=record.commitment:raise C09PagedCaptureHold('nested target row differs from actual target')
        if shape.table in {'graph_atoms','graph_history'} and 'value_cell_id' in shape.columns:
            # An immutable small reference row still requires the independently
            # completed header/segments/original bytes and layout disposition.
            complete=_advance_cold_graph_ref_row_v3(progress,shape,record.primary_key,None,meter)
            return None if complete else False
        return _verify_actual_target_row_v2(progress,shape,record.primary_key,tuple(row),meter)
    elif field=='closure':
        if shape.table not in {'c09_closure_members_v2','c09_closure_edges_v2'}:raise C09PagedCaptureHold('closure nested stream has an unregistered physical family')
        row=meter.read_row(progress.read_db,shape,record.primary_key)
        if row is None or _row_digest(tuple(row))!=record.commitment:raise C09PagedCaptureHold('closure nested row commitment differs')
        values=dict(zip(shape.columns,row,strict=True))
        if values['scope_digest']!=progress.session.scope.scope_digest:raise C09PagedCaptureHold('actual closure row crossed scope')
        return _require_actual_closure_origin_v2(progress,values,meter)
    else:raise C09PagedCaptureHold('unknown nested directory')


def _require_actual_closure_origin_v2(progress,values,meter):
    from .c09_paged_sql_v2 import require_c09_capture_member_v2
    origin=values['origin_stream_id'];ordinal=values['origin_record_ordinal'];commitment=values['origin_commitment']
    if origin==progress.session.scope.barrier_digest:
        # Seed origins are independently checked through actual current Source
        # barrier pages. No freely supplied Source token establishes a seed.
        from .c09_source_plan_barrier_v2 import next_c09_barrier_source_member_v2
        view=progress.cold_build.barrier_view
        if view is None or not view.complete:raise C09PagedCaptureHold('actual cold Source barrier chain has not completed')
        ns=tuple(json.loads(progress.session.scope.graph_namespace))
        if values.get('kind')=='source_id':
            from ..memory_types import source_key
            source_ref=source_key(*ns,values['ref']).token
        elif values.get('kind')=='atom':source_ref=values['ref']
        else:raise C09PagedCaptureHold('actual barrier seed has an unregistered closure member kind')
        previous=meter.read_fixed_row(progress.pair.source,'graph_c09_source_members_v2',('source_ref',),
            'bot=? AND persona=? AND operation_id=? AND affected=1 AND source_ref<? ORDER BY source_ref DESC',
            (*ns,progress.session.scope.operation_id,source_ref))
        actual=next_c09_barrier_source_member_v2(view,'' if previous is None else previous[0],budget=meter.budget)
        if actual is None or (actual['source_ref'],actual['record_ordinal'],actual['record_commitment'])!=(source_ref,ordinal,commitment):
            raise C09PagedCaptureHold('cold closure seed is outside its actual complete Source barrier page')
        return
    raw=meter.read_fixed_row(progress.read_db,'c09_capture_streams_v2',('identity_json','status'),'stream_id=?',(origin,))
    if raw is None or raw[1]!='sealed':raise C09PagedCaptureHold('closure origin has no actual completed source stream')
    stream=c09_paged_value_from_wire_v2(json.loads(raw[0]),C09StreamIdentityV2)
    if stream.scope_digest!=progress.session.scope.scope_digest or stream.stream_kind!='graph_facts':
        raise C09PagedCaptureHold('closure origin belongs to another capture')
    member=meter.read_fixed_row(progress.read_db,'c09_capture_members_v2',('primary_key_json','commitment'),
        'stream_id=? AND record_ordinal=?',(origin,ordinal))
    if member is None or member[1]!=commitment:raise C09PagedCaptureHold('closure origin row commitment differs')
    key=tuple(json.loads(member[0]));require_c09_capture_member_v2(progress.read_db,stream,ordinal,key,commitment,meter=meter)
    shape=read_c09_table_shape_v2(progress.pair.source,stream.family)
    metadata=_read_frozen_source_row_metadata_v3(progress.cold_build,shape,key,meter)
    if _large_memory_source_v3(shape,key,metadata,meter):
        capture=_advance_cold_source_row_capture_v3(progress,shape,key,metadata,meter.budget)
        if capture is None:return False
        if capture.require_complete(progress.cold_build,shape,key,metadata)!=commitment:
            raise C09PagedCaptureHold('closure origin has no identical streamed frozen-source row')
        if 'dependent_ref' in values:
            small=_source_row_small_sql_v3(progress.cold_build,shape,key,meter,capture=capture)
            # The registered typed-edge codec emits no auxiliary memory.source
            # relation. Its only physical edges are exact history dependencies.
            expected=(values['dependent_ref'],values['dependency_ref'])
            if shape.table!='graph_history' or not any(expected==(key[0],dependency)
                    for dependency,_ in small.get('dependencies',())):
                raise C09PagedCaptureHold('closure edge has no exact Source history relation in its original row')
        return
    actual=meter.read_row(progress.pair.source,shape,key)
    from .c09_paged_sql_v2 import c09_row_commitment_v2 as _row_digest
    if actual is None or _row_digest(tuple(actual))!=commitment:raise C09PagedCaptureHold('closure origin has no identical frozen-source row')
    if 'dependent_ref' in values:
        _require_actual_closure_edge_relation_v2(progress,values,shape,tuple(actual))


def _advance_actual_cold_prior_v2(progress,budget,meter,started):
    from .c09_graph_originals_read_v5 import begin_verify_latest_graph_certificate_view_v5
    with c09_sql_meter_quantum_v2(meter):
        build=progress.cold_build
        if build.prior_reader is None:
            build.prior_reader=begin_verify_latest_graph_certificate_view_v5(progress.session,progress.pair)
            if build.prior_reader is None:
                progress.phase='barrier'
                return {'status':'progress','phase':'barrier','actual_meter_bytes':meter.consumed_bytes}
        build.prior_view=build.prior_reader.advance(budget=budget,meter=meter)
        if build.prior_view is not None:progress.phase='barrier'
    return {'status':'progress','phase':progress.phase,'actual_meter_bytes':meter.consumed_bytes,
        'local_ns':monotonic_ns()-started,'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def _advance_actual_cold_barrier_v2(progress,budget,meter,started):
    from .c09_source_plan_barrier_v2 import begin_verify_c09_source_barrier_v2,advance_verify_c09_source_barrier_v2
    with c09_sql_meter_quantum_v2(meter):
        source=progress.pair.source;source.execute('BEGIN')
        try:
            build=progress.cold_build
            if build.barrier_view is None:build.barrier_view=begin_verify_c09_source_barrier_v2(source,session=progress.session)
            if advance_verify_c09_source_barrier_v2(build.barrier_view,budget=budget) is not None:
                progress.phase='source_originals'
        finally:source.rollback()
    return {'status':'progress','phase':progress.phase,'actual_meter_bytes':meter.consumed_bytes,
        'local_ns':monotonic_ns()-started,'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def _managed_graph_metadata_tables_v2():
    from .c09_paged_sql_v2 import CAPTURE_TABLES_V2
    from .c09_graph_originals_read_v5 import PRIOR_GRAPH_VIEW_TABLES_V2
    from .c09_owner_source_output_mappings_v3 import TABLE
    from .c09_contact_plan_prefix_history_v3 import TABLE as CONTACT_PREFIX
    return CAPTURE_TABLES_V2|CLOSURE_TABLES_V2|DOMAIN_INDEX_TABLES_V2|GRAPH_PROOF_TABLES_V2|PRIOR_GRAPH_VIEW_TABLES_V2|{TABLE,CONTACT_PREFIX}




def _next_graph_target_directory_table_v3(build,after):
    following=_next_target_business_table_v2(build,after)
    from .c09_owner_source_output_mappings_v3 import TABLE
    from .c09_contact_plan_prefix_history_v3 import TABLE as CONTACT_PREFIX
    for projection in ('graph_d09_turn_slot_origins_v3',TABLE,CONTACT_PREFIX):
        if (after is None or projection>after) and (following is None or projection<following):following=projection
    return following


def _next_target_business_table_v2(build,after):
    table=_next_graph_logical_source_table_v3(build,after)
    while table is not None and table in _managed_graph_metadata_tables_v2():
        table=_next_graph_logical_source_table_v3(build,table)
    return table


def _metered_graph_row_commitment_v2(row):
    from .c09_paged_sql_v2 import c09_row_commitment_v2
    return c09_row_commitment_v2(tuple(row))


_SOURCE_DISPOSITION_V2=object()


class VerifiedC09SourceDispositionV2:
    """Private full-EOF Source/disposition view; never constructed from a header."""
    __slots__=('_key','verified','scope')

    def __init__(self,key,verified):
        if key is not _SOURCE_DISPOSITION_V2 or type(verified) is not GraphRebaseColdProgressV2:
            raise TypeError('actual independently completed Source disposition stage required')
        if (verified._issuer is not _SWEEP or not verified.source_semantic_eof or verified.verified_directories!=6
                or not verified.target_schema_eof or not verified.closure_semantic_eof or verified.phase!='source_qualified'):
            raise C09PagedCaptureHold('independent Source semantic/structural/origin EOF qualification is incomplete')
        verified.session.require_current();verified.pair.check_source()
        self._key=key;self.verified=verified;self.scope=verified.session.scope

    def require_original_disposition_row_v3(self,table,primary_key,*,meter):
        from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
        from .c09_paged_sql_v2 import require_c09_capture_member_v2,c09_row_commitment_v2
        if self._key is not _SOURCE_DISPOSITION_V2:raise C09PagedCaptureHold('private Source disposition issuer changed')
        self.verified.session.require_current();self.verified.pair.check_source()
        db=self.verified.read_db;key=tuple(primary_key)
        row=_read_graph_disposition_original_row_v3(db,self.scope.scope_digest,table,key,meter)
        if row is None:raise C09PagedCaptureHold('Source disposition original absent')
        directory=meter.read_fixed_row(db,'c09_graph_disposition_directory_v2',('identity_json','complete_json'),
            'scope_digest=? AND family=?',(self.scope.scope_digest,table))
        if directory is None:raise C09PagedCaptureHold('Source disposition family directory absent')
        from .c09_paged_capture_contract_v2 import C09CompleteStreamV2
        stream=c09_paged_value_from_wire_v2(json.loads(directory[0]),C09StreamIdentityV2)
        seal=c09_paged_value_from_wire_v2(json.loads(directory[1]),C09CompleteStreamV2)
        physical=read_c09_table_shape_v2(self.verified.pair.source,table,meter=meter)
        expected=_source_stream_identity_v2(self.verified.cold_build,physical,'row_dispositions')
        if stream!=expected or seal.stream_id!=stream.stream_id:raise C09PagedCaptureHold('disposition stream original identity differs')
        member=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(key)))
        if member is None or member[1]!=c09_row_commitment_v2(row) or not 1<=member[0]<=seal.record_count:
            raise C09PagedCaptureHold('disposition original outside complete member bounds')
        require_c09_capture_member_v2(db,stream,member[0],key,member[1],meter=meter)
        if len(row)==13:
            result=_require_graph_logical_disposition_original_v3(self.verified.cold_build,db,physical,key,row,meter)
        else:result=GraphRowDispositionV1(row[2],row[4],row[5],row[6])
        self.verified.session.require_current();self.verified.pair.check_source();return result

    def require_generated_retained_row(self,table,primary_key,expected_new_commitment,*,meter):
        from .c09_storage_rebase_contract_v1 import GraphRowDispositionV3
        original=self.require_original_disposition_row_v3(table,primary_key,meter=meter)
        if type(original) is GraphRowDispositionV3:
            if original.new_commitment!=expected_new_commitment:
                raise C09PagedCaptureHold('V3 retained target differs from the completed original')
            return original
        from .c09_storage_rebase_contract_v1 import GraphRowDispositionV1
        from .c09_paged_sql_v2 import require_c09_capture_member_v2,c09_row_commitment_v2
        if self._key is not _SOURCE_DISPOSITION_V2:raise C09PagedCaptureHold('private Source disposition issuer changed')
        self.verified.session.require_current();self.verified.pair.check_source()
        if not self.verified.source_semantic_eof or not self.verified.closure_semantic_eof or self.verified.verified_directories!=6:
            raise C09PagedCaptureHold('Source structural qualification changed')
        db=self.verified.read_db
        columns=('scope_digest','table_name','key_digest','source_primary_key_json','old_commitment','disposition','new_commitment','origin_stream_id','origin_record_ordinal')
        row=meter.read_fixed_row(db,'c09_graph_dispositions_v2',columns,
            'scope_digest=? AND table_name=? AND key_digest=?',
            (self.scope.scope_digest,table,canonical_digest((table,primary_key))))
        if row is None or row[3]!=canonical_serialize(primary_key) or row[6]!=expected_new_commitment:
            raise C09PagedCaptureHold('retained target row is outside the actual completed Source disposition')
        member=meter.read_fixed_row(db,'c09_graph_disposition_directory_v2',('identity_json','complete_json'),
            'scope_digest=? AND family=?',(self.scope.scope_digest,table))
        if member is None:raise C09PagedCaptureHold('retained row family has no actual completed disposition original')
        from .c09_paged_capture_contract_v2 import C09CompleteStreamV2
        stream=c09_paged_value_from_wire_v2(json.loads(member[0]),C09StreamIdentityV2)
        seal=c09_paged_value_from_wire_v2(json.loads(member[1]),C09CompleteStreamV2)
        if stream.scope_digest!=self.scope.scope_digest or stream.stream_kind!='row_dispositions' or seal.stream_id!=stream.stream_id:
            raise C09PagedCaptureHold('retained Source disposition belongs to another qualified family')
        located=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
            'stream_id=? AND primary_key_json=?',(stream.stream_id,canonical_serialize(primary_key)))
        if located is None or located[1]!=c09_row_commitment_v2(tuple(row)):
            raise C09PagedCaptureHold('retained Source disposition has no exact original page member')
        require_c09_capture_member_v2(db,stream,located[0],primary_key,located[1],meter=meter)
        shape=read_c09_table_shape_v2(db,table);actual=meter.read_row(db,shape,primary_key)
        if actual is None or c09_row_commitment_v2(tuple(actual))!=expected_new_commitment:
            raise C09PagedCaptureHold('retained target changed after its independent complete sweep')
        self.verified.session.require_current();self.verified.pair.check_source()
        return GraphRowDispositionV1(row[2],row[4],row[5],row[6])


def require_verified_c09_source_disposition_v2(verified):
    """Consume actual pre-target-cold Source stage; never a persisted phase flag."""
    if type(verified) is not GraphRebaseColdProgressV2:
        raise TypeError('private independently completed Source stage required')
    return VerifiedC09SourceDispositionV2(_SOURCE_DISPOSITION_V2,verified)


def _read_frozen_source_row_metadata_v3(build,shape,key,meter):
    from .c09_paged_sql_v2 import _quote,_sql_scalar_size_v2,legacy_cell_read_transaction_v2
    columns=','.join('typeof('+_quote(name)+'),length(CAST('+_quote(name)+' AS BLOB))' for name in shape.columns)
    where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
    with legacy_cell_read_transaction_v2(build.pair.source):
        values=build.pair.source.execute('SELECT '+columns+' FROM '+_quote(shape.table)+' WHERE '+where,key).fetchone()
    if values is None:raise C09PagedCaptureHold('actual frozen Source original row disappeared')
    meter.charge_read(sum(_sql_scalar_size_v2(value) for value in values))
    return tuple((values[index],values[index+1]) for index in range(0,len(values),2))


def _advance_cold_source_row_capture_v3(progress,shape,key,metadata,budget):
    from .c09_graph_row_codec_v2 import C09MemorySourceRowCaptureV3
    build=progress.cold_build;capture=build.source_row_capture_v3
    if (capture is None or capture.shape!=shape or capture.key!=key or capture.metadata!=metadata
            or capture.pattern_kind is not None):
        capture=_begin_graph_source_capture_v3(build,shape,key,metadata)
    if capture.row.complete and capture.value.complete and capture.quantum_completed:
        capture.require_complete(build,shape,key,metadata)
        return capture
    progress.prospective_source_capture_v3=capture.next_quantum(budget)
    return None


def _advance_graph_logical_descriptor_census_v3(progress,locator,shape,meter):
    """Actual complete descriptor inventory, one PK row per reserved quantum."""
    from .c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
    row=meter.read_fixed_row(progress.read_db,'c09_logical_source_rows_v3',
        ('key_digest','primary_key_json','origin_record_ordinal','origin_stream_id'),
        'scope_digest=? AND role=? AND table_name=? AND key_digest>? ORDER BY key_digest',
        (progress.session.scope.scope_digest,'graph',shape.table,progress.logical_descriptor_after_v3))
    if row is None:
        if progress.logical_descriptor_count_v3!=locator.complete.record_count:
            raise C09PagedCaptureHold('complete mapped Source descriptor/member counts differ')
        return True
    key=tuple(json.loads(row[1]))
    if row[0]!=canonical_digest(key) or row[3]!=locator.identity.stream_id:
        raise C09PagedCaptureHold('mapped Source descriptor inventory crossed actual key/stream')
    descriptor=require_c09_logical_source_row_member_v3(progress.read_db,locator.identity,
        role='graph',table_name=shape.table,key=key,record_ordinal=row[2],meter=meter)
    logical=_mapped_graph_source_shape_v3(progress.cold_build,shape,meter)
    if (descriptor['logical_shape_digest']!=logical.logical_shape_digest
            or descriptor['physical_schema_digest']!=shape.schema_digest
            or descriptor['source_role_digest']!=progress.pair.source_original.role_source_digest):
        raise C09PagedCaptureHold('mapped Source descriptor inventory shape/role differs')
    progress.logical_descriptor_after_v3=row[0];progress.logical_descriptor_count_v3+=1
    if progress.logical_descriptor_count_v3>locator.complete.record_count:
        raise C09PagedCaptureHold('mapped Source descriptor inventory has extra rows')
    return False


def _advance_actual_cold_source_originals_v2(progress,budget,meter,started):
    """Every original source family is independently censused and page-verified."""
    with c09_sql_meter_quantum_v2(meter):
        if progress.originals_locator is None:
            following=_next_graph_logical_source_table_v3(progress.cold_build,progress.originals_after)
            if following is None:
                progress.phase='source_semantics'
                return {'status':'progress','phase':'source_semantics','actual_meter_bytes':meter.consumed_bytes}
            saved=meter.read_fixed_row(progress.read_db,'c09_graph_stream_directory_v2',('identity_json','complete_json'),
                'scope_digest=? AND directory_kind=? AND family=?',(progress.session.scope.scope_digest,'source_originals',following))
            if saved is None:raise C09PagedCaptureHold('frozen source family has no complete original stream')
            from .c09_paged_capture_contract_v2 import C09CompleteStreamV2
            identity=c09_paged_value_from_wire_v2(json.loads(saved[0]),C09StreamIdentityV2)
            complete=c09_paged_value_from_wire_v2(json.loads(saved[1]),C09CompleteStreamV2)
            if identity.family!=following or identity.stream_kind!='graph_facts' or identity.scope_digest!=progress.session.scope.scope_digest:
                raise C09PagedCaptureHold('source original stream crossed its actual frozen family')
            progress.logical_descriptor_after_v3="";progress.logical_descriptor_count_v3=0
            progress.originals_locator=C09SealedStreamLocatorV2('graph',identity,complete)
            progress.originals_verification=begin_c09_stream_verification_v2(progress.read_db,identity)
            if progress.originals_verification.seal_digest!=complete.digest:
                raise C09PagedCaptureHold('source original complete commitment differs')
        locator=progress.originals_locator;shape=read_c09_table_shape_v2(progress.pair.source,locator.identity.family)
        logical_shape=_mapped_graph_source_shape_v3(progress.cold_build,shape,meter)
        if not progress.originals_verification.census_complete:
            result=advance_verify_c09_census_v2(progress.pair.source,progress.read_db,locator.identity,logical_shape if logical_shape is not None else shape,budget,
                verification=progress.originals_verification,check_frozen_source=progress.pair.check_source,meter=meter)
        else:
            def verify(record):
                metadata=_read_frozen_source_row_metadata_v3(progress.cold_build,shape,record.primary_key,meter)
                if logical_shape is not None:
                    capture=_advance_cold_source_row_capture_v3(progress,shape,record.primary_key,metadata,budget)
                    if capture is None:return False
                    if capture.row.result.commitment!=record.commitment:
                        raise C09PagedCaptureHold('independent mapped row differs from actual composite source member')
                    from .c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
                    ordinal=meter.read_fixed_row(progress.read_db,'c09_capture_members_v2',('record_ordinal',),
                        'stream_id=? AND key_digest=?',(locator.identity.stream_id,canonical_digest(record.primary_key)))
                    if ordinal is None:raise C09PagedCaptureHold('mapped Source record lost actual member ordinal')
                    descriptor=require_c09_logical_source_row_member_v3(progress.read_db,locator.identity,
                        role='graph',table_name=shape.table,key=record.primary_key,record_ordinal=ordinal[0],meter=meter)
                    if canonical_serialize(descriptor)!=canonical_serialize(capture.row.result.descriptor):
                        raise C09PagedCaptureHold('independent mapped Source differs from actual immutable composite descriptor')
                    return
                # Streamed large Sources were captured in a dedicated one-row
                # page. A small row keeps the original materialized verifier.
                if (shape.table in {'graph_atoms','graph_history'}
                        and sum(size or 0 for _,size in metadata)*9>budget.max_bytes):
                    from ..graph_types import AtomKey
                    if AtomKey.from_token(record.primary_key[0]).type_name=='memory.source':
                        capture=_advance_cold_source_row_capture_v3(progress,shape,record.primary_key,metadata,budget)
                        if capture is None:return False
                        if capture.row.commitment!=record.commitment:
                            raise C09PagedCaptureHold('source original page differs from actual streamed SQL row')
                        return
                actual=meter.read_row(progress.pair.source,shape,record.primary_key)
                if actual is None or _metered_graph_row_commitment_v2(actual)!=record.commitment:
                    raise C09PagedCaptureHold('source original page differs from actual immutable source row')
            result=advance_verify_c09_stream_v2(progress.read_db,locator.identity,budget,
                verification=progress.originals_verification,verify_record=verify,meter=meter)
            if result['complete']:
                if logical_shape is not None and not _advance_graph_logical_descriptor_census_v3(progress,locator,shape,meter):
                    result['complete']=False
                else:
                    progress.originals_after=shape.table;progress.originals_locator=None;progress.originals_verification=None
        progress.pair.check_source();result.update(status='progress',phase=progress.phase,
            original_family=shape.table,actual_meter_bytes=meter.consumed_bytes,local_ns=monotonic_ns()-started)
        return result


def _advance_source_semantic_stage_v2(progress,budget,meter,started):
    """Independently qualify frozen source signatures and actual point joins.

    This stage grants neither target-cold completion nor a Graph certificate.
    Disposition/origin pages are independently swept afterwards before minting
    the private SourceDisposition view used by retained-target cold checks.
    """
    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
    from .c09_graph_row_codec_v2 import read_c09_domain_row_v2
    from .domain_production_erasure_v1 import TABLE_COLUMNS,DERIVED_STORE_TABLES_V6
    from .c09_d04_originals_v3 import TABLE as D04
    from .c09_d07_execution_v1 import TABLE as D07
    from .c09_contact_originals_v1 import TABLE as CONTACT
    from .c09_contact_originals_v2 import TABLE as CONTACT2
    from .c09_foreground_attempt_v1 import TABLE as FOREGROUND_TABLE
    source=progress.pair.source;count=0
    with c09_sql_meter_quantum_v2(meter):
        source.execute('BEGIN')
        try:
            while count<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
                table=progress.semantic_table or _next_graph_logical_source_table_v3(progress.cold_build,None)
                if table is None:raise C09PagedCaptureHold('actual frozen Source semantic inventory absent')
                shape=read_c09_table_shape_v2(source,table)
                found=read_c09_next_row_metadata_v2(source,shape,progress.semantic_key)
                if found is None:
                    next_table=_next_graph_logical_source_table_v3(progress.cold_build,table)
                    if next_table is None:
                        progress.source_semantic_eof=True;progress.phase='closure_replay';break
                    progress.semantic_table=next_table;progress.semantic_key=None;continue
                key,metadata=found
                if _large_memory_source_v3(shape,key,metadata,meter):
                    capture=_advance_cold_source_row_capture_v3(progress,shape,key,metadata,budget)
                    if capture is None:break
                    _source_row_small_sql_v3(progress.cold_build,shape,key,meter,capture=capture)
                    _actual_streamed_source_origin_v3(progress.cold_build,shape,key,metadata,capture,meter)
                    progress.semantic_table=table;progress.semantic_key=key;count+=1
                    continue
                if sum(n or 0 for _,n in metadata)*9>meter.remaining_bytes:
                    if count==0:raise C09PagedCaptureHold('semantic source row requires its registered streaming codec')
                    break
                row=tuple(meter.read_row(source,shape,key));_validate_graph_source_row_v2(progress.session,shape,row)
                from .c09_b3_managed_metadata_v1 import prepare_b3_managed_source_row_v1
                if not prepare_b3_managed_source_row_v1(progress.cold_build,shape,key,row,meter):break
                _require_source_owner_mapping_metadata_v3(progress.cold_build,shape,key,row,meter)
                _require_owner_source_metadata_row_for_graph_v3(progress.cold_build,shape,key,row,meter)
                _require_paid_owner_graph_source_row_v3(progress.cold_build,shape,row,meter)
                if table in TABLE_COLUMNS or table in {D04,D07,CONTACT,CONTACT2,CONTACT_EFFECT_ORIGINAL}:
                    original=read_c09_domain_row_v2(table,shape.columns,row,
                        authority_namespace=progress.session.scope.authority_namespace,
                        issuer=progress.session.get_c09_domain_original_issuer_v2())
                    if table not in DERIVED_STORE_TABLES_V6:
                        _verify_graph_domain_joins_v2(progress.cold_build,shape,row,original,budget,meter)
                if table==FOREGROUND_TABLE:
                    progress.session.read_finished_foreground_graph_original_v2(progress.pair,row,meter=meter)
                # Membership points are not the full source proof: that proof
                # has already completed its independent original-family census
                # and all original pages through genuine EOF in the prior stage.
                _actual_source_row_origin_v2(progress.cold_build,shape,key,row,meter)
                progress.semantic_table=table;progress.semantic_key=key;count+=1
        finally:source.rollback()
    progress.pair.check_source()
    return {'status':'progress','phase':progress.phase,'completed_records':count,
        'actual_meter_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
        'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def _require_actual_closure_edge_relation_v2(progress,edge,shape,row):
    """Origin membership alone cannot authorize an invented physical dependency."""
    from ..graph_types import AtomKey
    from .c09_graph_row_codec_v2 import iter_c09_typed_graph_edges_v2
    expected=(edge['dependent_ref'],edge['dependency_ref'])
    values=dict(zip(shape.columns,row,strict=True))
    if shape.table in {'graph_dependencies','graph_dependency_edges'}:
        if expected!=(values['dependent_token'],values['dependency_token']):
            raise C09PagedCaptureHold('closure edge differs from its actual dependency original')
        return
    if shape.table not in {'graph_atoms','graph_history'}:
        raise C09PagedCaptureHold('closure edge origin is not its registered semantic family')
    key=AtomKey.from_token(values['token']);decoded=json.loads(values['value'])
    if type(decoded) is dict and decoded.get('schema')=='sylanne3.graph.erased_value.v1':
        raise C09PagedCaptureHold('content-free marker cannot create a new semantic dependency')
    source=progress.pair.source;owns_transaction=not source.in_transaction
    if owns_transaction:source.execute('BEGIN')
    try:
        for pair in iter_c09_typed_graph_edges_v2(source,key,decoded):
            if pair==expected:return
        if shape.table=='graph_history':
            for dependency,revision in json.loads(values['dependencies']):
                if expected==(key.token,dependency):return
        raise C09PagedCaptureHold('closure edge has no exact typed/history relation in its original source row')
    finally:
        if owns_transaction:source.rollback()


class _IndependentGraphClosureV2:
    """Work metadata for one private fresh cold run in protected Control DB."""
    __slots__=('db','scope','namespace','progress','meter')
    def __init__(self,db,progress,meter):
        from ..runtime_contracts import NamespaceId
        self.db=db;self.progress=progress;self.scope=progress.session.scope
        self.namespace=NamespaceId(*json.loads(self.scope.graph_namespace));self.meter=meter

    def begin(self):
        run=self.progress.verification_run_id
        pins=(self.scope.scope_digest,self.progress.candidate.candidate_digest,self.progress.pair.source_original.role_source_digest)
        row=self.meter.read_fixed_row(self.db,'c09_graph_closure_verification_runs_v2',
            ('scope_digest','candidate_digest','source_digest'),'verification_run_id=?',(run,))
        if row is None:
            self.meter.write_row(self.db,'c09_graph_closure_verification_runs_v2',
                ('verification_run_id','scope_digest','candidate_digest','source_digest','round','member_generation','round_generation','phase','cursor_json'),
                (run,*pins,0,0,0,'collect','null'))
        elif row!=pins:raise C09PagedCaptureHold('independent closure run crossed actual source/candidate pins')

    def _state(self):
        return self.meter.read_fixed_row(self.db,'c09_graph_closure_verification_runs_v2',
            ('round','member_generation','round_generation','phase','cursor_json'),'verification_run_id=?',(self.progress.verification_run_id,))

    def contains(self,kind,ref):
        if kind not in {'atom','source_id','operation','domain_link','row'}:raise ValueError('closed independent closure kind required')
        return self.meter.read_fixed_row(self.db,'c09_graph_closure_verification_members_v2',('ref',),
            'verification_run_id=? AND kind=? AND ref=?',(self.progress.verification_run_id,kind,ref)) is not None
    def contains_atom(self,ref):return self.contains('atom',ref)
    def contains_source_id(self,ref):return self.contains('source_id',ref)
    def contains_operation(self,ref):return self.contains('operation',ref)
    def contains_domain_link(self,table,ref):return self.contains('domain_link',canonical_serialize((table,ref)))
    def contains_row(self,table,key):return self.contains('row',canonical_serialize((table,key)))
    def add_domain_link(self,table,ref,**origin):return self.add_member('domain_link',canonical_serialize((table,ref)),**origin)
    def add_row(self,table,key,**origin):return self.add_member('row',canonical_serialize((table,key)),**origin)

    def add_member(self,kind,ref,*,origin_stream_id,origin_record_ordinal,origin_commitment):
        from ..graph_types import AtomKey
        from ..runtime_contracts import NamespaceId
        if kind not in {'atom','source_id','operation','domain_link','row'} or type(ref) is not str or not ref:
            raise C09PagedCaptureHold('invalid independent closure structural member')
        if kind=='atom' and NamespaceId.from_key(AtomKey.from_token(ref))!=self.namespace:
            raise C09PagedCaptureHold('independent closure crossed actual namespace')
        if self.contains(kind,ref):return False
        state=self._state()
        if state[3]=='sealed':raise C09PagedCaptureHold('independent sealed closure cannot acquire members')
        self.meter.write_row(self.db,'c09_graph_closure_verification_members_v2',
            ('verification_run_id','kind','ref','added_round','origin_stream_id','origin_record_ordinal','origin_commitment'),
            (self.progress.verification_run_id,kind,ref,state[0],origin_stream_id,origin_record_ordinal,origin_commitment))
        self._update('member_generation=member_generation+1',())
        return True

    def add_atom(self,ref,**origin):
        from ..graph_types import AtomKey
        changed=self.add_member('atom',ref,**origin);key=AtomKey.from_token(ref)
        if key.type_name=='memory.source':self.add_member('source_id',key.owner.subject,**origin)
        return changed

    def add_edge(self,dependent_ref,dependency_ref,*,origin_stream_id,origin_record_ordinal,origin_commitment):
        from ..graph_types import AtomKey
        from ..runtime_contracts import NamespaceId
        for token in (dependent_ref,dependency_ref):
            if NamespaceId.from_key(AtomKey.from_token(token))!=self.namespace:
                raise C09PagedCaptureHold('independent edge crossed actual namespace')
        key=(self.progress.verification_run_id,dependent_ref,dependency_ref,origin_stream_id,origin_record_ordinal)
        existing=self.meter.read_fixed_row(self.db,'c09_graph_closure_verification_edges_v2',('origin_commitment',),
            'verification_run_id=? AND dependent_ref=? AND dependency_ref=? AND origin_stream_id=? AND origin_record_ordinal=?',key)
        if existing is not None:
            if existing!=(origin_commitment,):raise C09PagedCaptureHold('independent edge original changed')
            return False
        if self.progress.closure_replay_phase!='edge_scan':
            raise C09PagedCaptureHold('independent propagation encountered an edge outside its completed verified Source set')
        self.meter.write_row(self.db,'c09_graph_closure_verification_edges_v2',
            ('verification_run_id','dependent_ref','dependency_ref','origin_stream_id','origin_record_ordinal','origin_commitment'),(*key,origin_commitment))
        self._update('member_generation=member_generation+1',())
        return True

    def _update(self,assignments,args):
        self.meter.charge_write(sum(len(str(v).encode('utf-8')) for v in (*args,self.progress.verification_run_id)))
        self.db.execute('UPDATE c09_graph_closure_verification_runs_v2 SET '+assignments+' WHERE verification_run_id=?',(*args,self.progress.verification_run_id))

    def begin_round(self):
        self._update("round=round+1,round_generation=member_generation,phase='expand'",())

    def finish_round(self):
        state=self._state();complete=state[1]==state[2]
        self._update('phase=?',('sealed' if complete else 'collect',))
        return complete

    def iter_members(self,kind,after_ref,limit):
        last='' if after_ref is None else after_ref
        count=0
        while count<limit:
            row=self.meter.read_fixed_row(self.db,'c09_graph_closure_verification_members_v2',
                ('ref','origin_stream_id','origin_record_ordinal','origin_commitment'),
                'verification_run_id=? AND kind=? AND ref COLLATE BINARY>? ORDER BY ref COLLATE BINARY',
                (self.progress.verification_run_id,kind,last))
            if row is None:return
            yield row;last=row[0];count+=1

    def scan_nested_value_page(self,value,*,kind,after_ref,budget):
        from .c09_closure_index_v2 import _nested_pattern_hit
        started=monotonic_ns();last=after_ref;count=0
        for ref,stream,ordinal,commitment in self.iter_members(kind,after_ref,budget.max_records):
            if monotonic_ns()-started>=budget.max_local_ns:break
            last=ref;count+=1
            if _nested_pattern_hit(value,ref,source_id=kind=='source_id'):
                return {'hit':True,'eof':False,'last_ref':last,'completed_records':count,'encoded_bytes':0,'elapsed_ns':monotonic_ns()-started}
        more=self.meter.read_fixed_row(self.db,'c09_graph_closure_verification_members_v2',('ref',),
            'verification_run_id=? AND kind=? AND ref COLLATE BINARY>? ORDER BY ref COLLATE BINARY',
            (self.progress.verification_run_id,kind,'' if last is None else last))
        return {'hit':False,'eof':more is None,'last_ref':last,'completed_records':count,'encoded_bytes':0,'elapsed_ns':monotonic_ns()-started}


def _advance_independent_graph_closure_v2(progress,budget,meter,started):
    """Recompute a fresh closure in existing protected Control work metadata."""
    from .c09_source_plan_barrier_v2 import next_c09_barrier_source_member_v2
    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
    if progress._issuer is not _SWEEP or not progress.source_semantic_eof:
        raise C09PagedCaptureHold('actual independent Source semantic EOF required before closure replay')
    source=progress.pair.source;state=progress.closure_replay_progress
    try:
        with c09_sql_meter_quantum_v2(meter),progress.session.graph_closure_verification_transaction_v2(progress,budget=budget,meter=meter) as db:
            closure=_IndependentGraphClosureV2(db,progress,meter);closure.begin()
            source.execute('BEGIN')
            try:
                if progress.closure_replay_phase=='edge_scan':
                    table=state.get('table') or _next_graph_logical_source_table_v3(progress.cold_build,None)
                    if table is None:raise C09PagedCaptureHold('independent edge source inventory absent')
                    shape=read_c09_table_shape_v2(source,table)
                    found=read_c09_next_row_metadata_v2(source,shape,None if state.get('row_key') is None else tuple(state['row_key']))
                    if found is None:
                        following=_next_graph_logical_source_table_v3(progress.cold_build,table)
                        if following is None:
                            progress.closure_replay_phase='edges_expected';state.clear();state['after']=None
                        else:state.update(table=following,row_key=None)
                    else:
                        key,metadata=found
                        if _large_memory_source_v3(shape,key,metadata,meter):
                            capture=_advance_cold_source_row_capture_v3(progress,shape,key,metadata,budget)
                            if capture is not None:
                                small=_source_row_small_sql_v3(progress.cold_build,shape,key,meter,capture=capture)
                                origin=_actual_streamed_source_origin_v3(progress.cold_build,shape,key,metadata,capture,meter)
                                for dependency,_ in small.get('dependencies',()):
                                    closure.add_edge(key[0],dependency,**origin)
                                state.update(table=table,row_key=key)
                        else:
                            if sum(n or 0 for _,n in metadata)*8>meter.remaining_bytes:
                                raise C09PagedCaptureHold('independent Source edge row needs its registered streaming codec')
                            row=tuple(meter.read_row(source,shape,key))
                            origin=_actual_source_row_origin_v2(progress.cold_build,shape,key,row,meter)
                            _collect_independent_expected_edges_v2(progress,shape,row,closure,origin)
                            state.update(table=table,row_key=key)
                elif progress.closure_replay_phase=='seed':
                    view=progress.cold_build.barrier_view
                    if view is None or not view.complete:raise C09PagedCaptureHold('independent closure seed lacks actual complete barrier')
                    member=next_c09_barrier_source_member_v2(view,state['seed_after'],budget=budget)
                    if member is None:
                        progress.closure_replay_phase='scan';closure.begin_round()
                        state.update(table=None,row_key=None,pattern_kind='atom',pattern_after=None,nested_hit=False)
                    else:
                        closure.add_atom(member['source_ref'],origin_stream_id=member['barrier_digest'],
                            origin_record_ordinal=member['record_ordinal'],origin_commitment=member['record_commitment'])
                        state['seed_after']=member['source_ref']
                elif progress.closure_replay_phase=='scan':
                    table=state.get('table') or _next_graph_logical_source_table_v3(progress.cold_build,None)
                    if table is None:raise C09PagedCaptureHold('actual independent closure Source inventory absent')
                    shape=read_c09_table_shape_v2(source,table)
                    found=read_c09_next_row_metadata_v2(source,shape,None if state.get('row_key') is None else tuple(state['row_key']))
                    if found is None:
                        following=_next_graph_logical_source_table_v3(progress.cold_build,table)
                        if following is None:
                            if closure.finish_round():
                                progress.closure_replay_phase='members_expected'
                                state.clear();state.update(after=None)
                            else:
                                closure.begin_round();state.update(table=None,row_key=None,pattern_kind='atom',pattern_after=None,nested_hit=False)
                        else:state.update(table=following,row_key=None,pattern_kind='atom',pattern_after=None,nested_hit=False)
                    else:
                        key,metadata=found
                        if _large_memory_source_v3(shape,key,metadata,meter):
                            hit,done,pending,actual=_advance_source_nested_match_v3(
                                progress.cold_build,shape,key,metadata,closure,state,budget,meter)
                            progress.prospective_source_capture_v3=pending
                            if done:
                                small,origin=actual
                                _expand_streamed_source_closure_v3(progress.cold_build,shape,key,small,origin,closure,hit,capture=pending)
                                state.update(row_key=key,pattern_kind='atom',pattern_after=None,nested_hit=False)
                                progress.cold_build.source_row_capture_v3=None
                        else:
                            if sum(n or 0 for _,n in metadata)*9>meter.remaining_bytes:
                                raise C09PagedCaptureHold('independent closure Source row requires its registered streaming codec')
                            row=tuple(meter.read_row(source,shape,key))
                            from .c09_b3_managed_metadata_v1 import prepare_b3_managed_source_row_v1
                            qualified=prepare_b3_managed_source_row_v1(progress.cold_build,shape,key,row,meter)
                            hit,done=(_graph_nested_advance_v2(closure,_graph_row_nested_value_v2(shape,row),state,budget,meter)
                                if qualified else(False,False))
                            if done:
                                origin=_actual_source_row_origin_v2(progress.cold_build,shape,key,row,meter)
                                _expand_graph_closure_row_v2(progress.cold_build,shape,key,row,closure,hit,origin,budget,meter)
                                state.update(row_key=key,pattern_kind='atom',pattern_after=None,nested_hit=False)
                        state['table']=table
                else:
                    _advance_bidirectional_closure_comparison_v2(progress,db,budget,meter,started)
                # This state is a work cursor only. A new cold process uses a new
                # nonce and never restores its qualification from this JSON.
                raw=canonical_serialize({'phase':progress.closure_replay_phase,'cursor':state})
                meter.charge_encode(len(raw.encode('utf-8')))
                closure._update('cursor_json=?',(raw,))
            finally:source.rollback()
    except BaseException:
        # A rolled-back generation cannot retain advanced volatile cursors or
        # flags. The caller must reopen an actual new cold verifier from zero.
        progress.closure_semantic_eof=False;progress.verification_run_id=None
        progress.phase='verification_failed'
        raise
    progress.pair.check_source()
    return {'status':'progress','phase':progress.phase,'verification_phase':progress.closure_replay_phase,
        'actual_meter_bytes':meter.consumed_bytes,'local_ns':monotonic_ns()-started,
        'resource_quantum_within_limit':monotonic_ns()-started<=budget.max_local_ns}


def _advance_bidirectional_closure_comparison_v2(progress,control,budget,meter,started):
    """Reject extra and missing edges/members after real independently derived EOF."""
    from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
    phase=progress.closure_replay_phase;state=progress.closure_replay_progress
    edge=phase.startswith('edges_');expected=phase.endswith('_expected')
    actual_table='c09_closure_edges_v2' if edge else 'c09_closure_members_v2'
    expected_table='c09_graph_closure_verification_edges_v2' if edge else 'c09_graph_closure_verification_members_v2'
    source=control if expected else progress.read_db
    table=expected_table if expected else actual_table
    target=progress.read_db if expected else control
    target_table=actual_table if expected else expected_table
    shape=read_c09_table_shape_v2(source,table);done=0
    after=None if state.get('after') is None else tuple(state['after'])
    while done<budget.max_records and monotonic_ns()-started<budget.max_local_ns:
        if expected:
            actual=_read_verification_row_after_v2(control,shape,progress.verification_run_id,after,meter)
            found=None if actual is None else (tuple(actual[shape.columns.index(name)] for name in shape.primary_key_columns),None)
        else:
            actual=None;found=read_c09_next_row_metadata_v2(source,shape,after)
        if found is None:
            if phase=='edges_expected':next_phase='edges_actual'
            elif phase=='edges_actual':next_phase='seed'
            elif phase=='members_expected':next_phase='members_actual'
            elif phase=='members_actual':
                progress.closure_semantic_eof=True;progress.phase='target_schema'
                progress.closure_replay_phase='complete';state.clear();return
            else:raise C09PagedCaptureHold('unknown independent closure comparison phase')
            progress.closure_replay_phase=next_phase;state.clear()
            if next_phase=='seed':state.update(seed_after='',table=None,row_key=None,pattern_kind='atom',pattern_after=None,nested_hit=False)
            else:state['after']=None
            return
        key,metadata=found
        if actual is None:
            size=sum(n or 0 for _,n in metadata)
            if size*5>meter.remaining_bytes:
                if done==0:raise C09PagedCaptureHold('closure comparison descriptor exceeds actual reserved quantum')
                break
            actual=meter.read_row(source,shape,key)
        row=tuple(actual);values=dict(zip(shape.columns,row,strict=True))
        pin_name='verification_run_id' if expected else 'scope_digest'
        pin=progress.verification_run_id if expected else progress.session.scope.scope_digest
        if values[pin_name]!=pin:
            # Candidate only holds this new-scope closure. A copied historical
            # closure belongs to its separately qualified history store.
            if not expected:after=key;done+=1;continue
            raise C09PagedCaptureHold('Control closure generation has a foreign private run')
        if edge:
            keys=(values['dependent_ref'],values['dependency_ref'],values['origin_stream_id'],values['origin_record_ordinal'])
            target_pin=progress.session.scope.scope_digest if expected else progress.verification_run_id
            matched=meter.read_fixed_row(target,target_table,
                ('dependent_ref','dependency_ref','origin_stream_id','origin_record_ordinal','origin_commitment'),
                ('scope_digest' if expected else 'verification_run_id')+'=? AND dependent_ref=? AND dependency_ref=? AND origin_stream_id=? AND origin_record_ordinal=?',
                (target_pin,*keys))
            want=(*keys,values['origin_commitment'])
        else:
            keys=(values['kind'],values['ref'])
            target_pin=progress.session.scope.scope_digest if expected else progress.verification_run_id
            matched=meter.read_fixed_row(target,target_table,
                ('kind','ref','origin_stream_id','origin_record_ordinal','origin_commitment'),
                ('scope_digest' if expected else 'verification_run_id')+'=? AND kind=? AND ref=?',(target_pin,*keys))
            want=(*keys,values['origin_stream_id'],values['origin_record_ordinal'],values['origin_commitment'])
        if matched!=want:
            raise C09PagedCaptureHold('candidate closure has an extra/missing or wrongly derived '+('edge' if edge else 'member'))
        after=key;done+=1
    state['after']=after


def _read_verification_row_after_v2(db,shape,run_id,after,meter):
    """Fixed generation predicate excludes old runs without trusting their cursor."""
    from .c09_paged_sql_v2 import _keyset
    clause,args=_keyset(shape,after)
    predicate='verification_run_id=?'
    if clause:predicate+=' AND ('+clause.strip()[6:]+')'
    order=','.join('"'+name+'" COLLATE BINARY' for name in shape.primary_key_columns)
    return meter.read_fixed_row(db,shape.table,shape.columns,predicate+' ORDER BY '+order,(run_id,*args))


def _collect_independent_expected_edges_v2(progress,shape,row,closure,origin):
    """Expected edge set derives only from all validated actual frozen originals."""
    from ..graph_types import AtomKey
    from ..runtime_contracts import NamespaceId
    from .c09_graph_row_codec_v2 import iter_c09_typed_graph_edges_v2
    values=dict(zip(shape.columns,row,strict=True));namespace=tuple(json.loads(progress.session.scope.graph_namespace))
    if shape.table in {'graph_dependencies','graph_dependency_edges'}:
        dependent=AtomKey.from_token(values['dependent_token']);dependency=AtomKey.from_token(values['dependency_token'])
        if NamespaceId.from_key(dependent).as_tuple!=namespace:return
        closure.add_edge(dependent.token,dependency.token,**origin)
    elif shape.table in {'graph_atoms','graph_history'}:
        key=AtomKey.from_token(values['token'])
        if NamespaceId.from_key(key).as_tuple!=namespace or key.type_name=='memory.access':return
        decoded=json.loads(values['value'])
        if type(decoded) is dict and decoded.get('schema')=='sylanne3.graph.erased_value.v1':return
        for dependent,dependency in iter_c09_typed_graph_edges_v2(progress.pair.source,key,decoded):
            closure.add_edge(dependent,dependency,**origin)
        if shape.table=='graph_history':
            for dependency,revision in json.loads(values['dependencies']):closure.add_edge(key.token,dependency,**origin)


def _prepare_historical_row_stream_v2(build,shape,row,meter):
    """Locate one actual signed historical stream; never trust stored status."""
    if shape.table not in _managed_graph_metadata_tables_v2():return False
    from .c09_historical_proof_row_codec_v2 import (
        read_historical_graph_proof_row_locator_v2,begin_historical_graph_stream_verification_v2)
    locator=read_historical_graph_proof_row_locator_v2(build.session,build.pair,shape,tuple(row),meter=meter)
    if locator is None:return False
    current=build.historical_verification
    if current is None or current.locator!=locator:
        build.historical_verification=begin_historical_graph_stream_verification_v2(build.session,build.pair,locator,meter=meter)
        current=build.historical_verification
    return not current.complete


def _advance_historical_row_stream_v2(build,budget,meter):
    from .c09_historical_proof_row_codec_v2 import advance_historical_graph_stream_verification_v2
    current=build.historical_verification
    if current is None:raise C09PagedCaptureHold('actual historical stream continuation absent')
    return advance_historical_graph_stream_verification_v2(current,budget=budget,meter=meter)


def _require_historical_complete_stream_v2(build,locator):
    current=build.historical_verification
    if current is None:raise C09PagedCaptureHold('historical row lacks its private fresh EOF verifier')
    return current.require_complete(locator)

def _advance_graph_owner_outputs_v3(build,progress):
    from .c09_owner_source_output_publication_v3 import PreparedOwnerOutputPublicationV3
    from .c09_owner_source_output_mappings_v3 import NAMES
    # The Source/name is read before creating a new writer; restart replays the same durable name.
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            table=meter.read_fixed_row(build.pair.source,'sqlite_master',('name',),
                'type=? AND name=?',('table','graph_owner_source_prepared_v3'))
            prepared=progress.get('prepared_digest')
            if table is not None and prepared is None:
                prepared=meter.read_fixed_row(build.pair.source,'graph_owner_source_prepared_v3',
                    ('prepared_digest',),'prepared_digest>? ORDER BY prepared_digest COLLATE BINARY',
                    (progress.get('after',''),))
                prepared=None if prepared is None else prepared[0]
            if prepared is None:
                if table is None:
                    _require_graph_owner_zero_family_v3(build,meter,record=True)
                    extra=meter.read_fixed_row(build.pair.candidate,'c09_owner_source_output_mappings_v3',
                        ('prepared_digest',),'capture_scope_digest=? ORDER BY prepared_digest,cell_name',(build.scope.scope_digest,))
                    if extra is not None:raise C09PagedCaptureHold('zero Source family has an extra target output mapping')
                with capture_transaction_v2(build.pair.candidate):
                    _save_graph_progress_v2(build,'contact_prefix_history',{'after_cell':''},meter)
                return _graph_step_report_v2(build,'contact_prefix_history',meter,monotonic_ns())
            name=NAMES[progress.get('name_index',0)]
    publisher=build.owner_output_publisher_v3
    if publisher is None:publisher=PreparedOwnerOutputPublicationV3(build,prepared,name)
    elif (publisher.prepared_digest,publisher.cell_name)!=(prepared,name):
        raise C09PagedCaptureHold('actual durable prepared/name crossed its private pending publisher')
    prospective=publisher.advance()
    # advance() has already left its actual target reservation successfully.
    build.owner_output_publisher_v3=prospective
    if not prospective.complete:return {'status':'progress','phase':'owner_outputs','prepared_digest':prepared,'cell_name':name}
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter),capture_transaction_v2(build.pair.candidate):
            row=meter.read_fixed_row(build.pair.candidate,
                'c09_owner_source_output_mappings_v3',('original_digest',),
                'capture_scope_digest=? AND prepared_digest=? AND cell_name=?',
                (build.scope.scope_digest,prepared,name))
            if row!=(prospective.row[12],):
                raise C09PagedCaptureHold('completed output publication lost its actual same-transaction mapping')
            index=progress.get('name_index',0)+1
            next_state={'after':progress.get('after',''),'prepared_digest':prepared,'name_index':index}
            if index==len(NAMES):next_state={'after':prepared,'prepared_digest':None,'name_index':0}
            _save_graph_progress_v2(build,'owner_outputs',next_state,meter)
    build.owner_output_publisher_v3=None
    return {'status':'progress','phase':'owner_outputs','prepared_digest':prepared,'cell_name':name}

def _advance_graph_owner_outputs_cold_v3(progress,budget,meter,started):
    from .c09_owner_source_outputs_cold_v3 import PreparedOwnerOutputsColdReadV3
    reader=progress.owner_outputs_cold_reader_v3
    if reader is None:
        progress.prospective_owner_outputs_cold_v3=PreparedOwnerOutputsColdReadV3(progress,meter=meter)
    elif not reader.complete:
        progress.prospective_owner_outputs_cold_v3=reader.advance(meter)
    else:
        progress.owner_outputs_cold_proof_v3=reader.require_complete(meter=meter)
        progress.phase='source_qualified'
    return {'status':'progress','phase':progress.phase,'actual_meter_bytes':meter.consumed_bytes,
            'local_ns':monotonic_ns()-started}

def _require_source_owner_mapping_metadata_v3(build,shape,key,row,meter):
    from .c09_owner_source_output_mappings_v3 import (
        TABLE,DDL,COLUMNS,require_selected_owner_output_mapping_row_v3)
    if shape.table!=TABLE:return False
    if shape.columns!=COLUMNS:
        raise C09PagedCaptureHold('source Owner output mapping physical15-column shape differs')
    scope=build.mapped_source_scope_v3
    if scope is None:scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
    scope.require_current(meter=meter)
    if scope.previous_selected_basis is None:
        raise C09PagedCaptureHold('previous mapped outputs require their actual previous selected issuer')
    with scope.read_database_v3(meter=meter) as db:
        proof=require_selected_owner_output_mapping_row_v3(db,scope.previous_selected_basis,key[1],key[2],meter)
        if proof is None or proof.row!=tuple(row):
            raise C09PagedCaptureHold('prior mapping is not the actual retained signed source member')
        proof.require_current(db=db,meter=meter)
    build.mapped_source_scope_v3=scope
    return True

def _next_graph_logical_source_table_v3(build,after):
    from ..segmented_sql_cell_v1 import DDLS
    from ..authority_service.c09_source_physical_read_v3 import VerifiedSourcePhysicalContainerCensusV3
    build.require_current()
    table=_next_source_table_v2(build.pair.source,after)
    while table in DDLS:
        proof=build.source_container_proof_v3
        if type(proof) is not VerifiedSourcePhysicalContainerCensusV3:
            raise C09PagedCaptureHold('old physical container lacks its actual complete Source census')
        proof.require_source_identity_v3(build.mapped_source_scope_v3)
        table=_next_source_table_v2(build.pair.source,table)
    return table

def _advance_graph_owner_family_qualification_v3(build):
    from ..authority_service.c09_source_physical_read_v3 import (
        source_owner_storage_catalogue_v3,begin_source_owner_metadata_absence_v3)
    mode,reader,proof=build.owner_family_mode_v3,build.owner_family_reader_v3,build.owner_family_proof_v3
    scope=build.mapped_source_scope_v3
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            if mode=='positive':return False
            if proof is not None:proof.require_current(meter=meter);return False
            if scope is None:scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
            if mode is None:
                table_ddls={name:ddl for kind,name,ddl in source_owner_storage_catalogue_v3() if kind=='table'}
                absent=0
                with scope.read_database_v3(meter=meter) as db:
                    for name,ddl in table_ddls.items():
                        row=meter.read_fixed_row(db,'sqlite_master',('type','sql'),'name=?',(name,))
                        if row is None:absent+=1
                        elif row!=('table',ddl):
                            raise C09PagedCaptureHold('Owner Source family actual fixed schema differs')
                if absent==0:mode='positive'
                elif absent==len(table_ddls):
                    mode='absent';reader=begin_source_owner_metadata_absence_v3(scope,meter=meter)
                else:raise C09PagedCaptureHold('Owner Source family is partial; no positive or zero-family authority')
            else:
                reader=reader.advance(meter)
                if reader.complete:proof=reader.proof
    build.mapped_source_scope_v3=scope
    build.owner_family_mode_v3,build.owner_family_reader_v3,build.owner_family_proof_v3=mode,reader,proof
    return mode!='positive'

def _require_graph_owner_zero_family_v3(build,meter,*,record):
    from ..authority_service.c09_source_physical_read_v3 import VerifiedSourceOwnerMetadataAbsenceV3
    proof=build.owner_family_proof_v3
    if type(proof) is not VerifiedSourceOwnerMetadataAbsenceV3 or proof.scope is not build.mapped_source_scope_v3:
        raise C09PagedCaptureHold('actual signed Source Owner3 schema EOF is required for zero outputs')
    proof.require_current(meter=meter)
    details=dict(schema='sylanne3.c09.owner-output-zero-family.v3',scope_digest=build.scope.scope_digest,
        source_role_digest=build.pair.source_original.role_source_digest,record_count=proof.record_count,
        source_absence_original_digest=proof.original['original_digest'],
        family_names=proof.family_names,source_schema_eof_digest=proof.eof_digest,source_absence_root=proof.root)
    control=build.session._control.maintenance.control
    if record:
        return control.record_build_original_v1(operation_id=build.scope.operation_id,
            kind='capture_owner_outputs_zero_family_v3',details=details)
    original=control.read_build_original_v1(operation_id=build.scope.operation_id,kind='capture_owner_outputs_zero_family_v3')
    if original is None or original['details']!=json.loads(canonical_serialize(details)):
        raise C09PagedCaptureHold('zero output family lacks its real producer/source absence original')
    return original


def _advance_graph_contact_prefix_cold_v3(progress,budget,meter,started):
    from .c09_contact_plan_prefix_history_v3 import ContactPlanPrefixesColdReadV3
    reader=progress.contact_prefix_cold_v3
    if reader is None:
        progress.prospective_contact_prefix_cold_v3=ContactPlanPrefixesColdReadV3(progress,meter)
    elif not reader.complete:
        progress.prospective_contact_prefix_cold_v3=reader.advance(meter)
    else:
        progress.contact_prefix_cold_proof_v3=reader.require_complete(meter)
        progress.phase='source_qualified'
    return {'status':'progress','phase':progress.phase,'actual_meter_bytes':meter.consumed_bytes,
        'local_ns':monotonic_ns()-started}


def _authenticated_world_revision_index_v1(build,shape,row,meter):
    """Authenticate only this fixed signed locator and its actual frozen W01 metadata."""
    from .d03_world_history_v1 import (TABLE,COLUMNS,SIGN_KIND,
        decode_world_revision_index_row_v1,world_assertion_commitment_v1)
    from ..runtime_contracts import NamespaceId
    if shape.table!=TABLE or shape.columns!=COLUMNS or len(row[5].encode('utf-8'))>16384:
        raise C09PagedCaptureHold('World C09 signed index exceeds its registered exact shape/bound')
    namespace=NamespaceId(row[0],row[1])
    if namespace.as_tuple!=tuple(json.loads(build.scope.graph_namespace)):
        raise C09PagedCaptureHold('World C09 index lacks its actual namespace maintenance scope')
    issuer=build.session.get_c09_domain_original_issuer_v2()
    index=decode_world_revision_index_row_v1(shape.columns,row,namespace=namespace)
    issuer._signer.verify(SIGN_KIND,row[5],row[7])
    if index.assertion_commitment!=world_assertion_commitment_v1(namespace,index.assertion_id,issuer):
        raise C09PagedCaptureHold('World C09 index assertion commitment differs from its actual signer')
    receipt=meter.read_fixed_row(build.pair.source,'graph_bundle_operations',('receipt_json','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,index.adoption_operation_id))
    history=meter.read_fixed_row(build.pair.source,'graph_history',('event_bot','event_persona','event_id','valid'),
        'token=? AND revision=?',(index.input_version.key.token,index.input_version.revision))
    if receipt is None or history!=(*namespace.as_tuple,index.adoption_operation_id,1):
        raise C09PagedCaptureHold('World C09 index has no actual frozen immutable adoption')
    from .domain_production_originals_v1 import _receipt
    original=_receipt(json.loads(receipt[0]))
    if (receipt[1]!=index.known_from_sequence or original.commit_seq!=receipt[1]
            or canonical_digest(original)!=index.adoption_receipt_digest
            or index.input_version not in original.write_versions):
        raise C09PagedCaptureHold('World C09 index knowledge sequence differs from its actual W01 receipt')
    from .c09_world_producer_metadata_v1 import require_world_producer_metadata_v1
    require_world_producer_metadata_v1(build,index)
    return namespace,index,issuer


def _world_erasure_barrier_row_v1(build,shape,row,meter):
    from .d03_world_history_v1 import (world_revision_commitment_v1,
        world_erasure_barrier_payload_v1,ERASURE_SIGN_KIND)
    namespace,index,issuer=_authenticated_world_revision_index_v1(build,shape,row,meter)
    barrier=world_erasure_barrier_payload_v1(index,namespace=namespace,
        revision_commitment=world_revision_commitment_v1(index,issuer),
        deletion_generation=build.scope.maintenance_generation,
        deletion_knowledge_sequence=_world_deletion_knowledge_sequence_v1(build,namespace,meter),
        delete_original_commitment=build.scope.accepted_receipt_digest)
    from ..domains.d01.production_operations_v1 import plain_v1
    plain=plain_v1(barrier)
    payload=canonical_serialize(plain)
    meter.charge_encode(len(payload.encode('utf-8'))*3)
    return (*namespace.as_tuple,barrier.assertion_commitment,barrier.known_from_sequence,
        barrier.revision_commitment,barrier.deletion_generation,barrier.deletion_knowledge_sequence,barrier.delete_original_commitment,
        payload,canonical_digest(plain),issuer._signer.sign(ERASURE_SIGN_KIND,payload))


def _require_prior_world_erasure_barrier_v1(build,shape,key,row,meter):
    from .d03_world_history_v1 import ERASURE_TABLE,ERASURE_SIGN_KIND,decode_world_erasure_barrier_row_v1
    from .c09_paged_sql_v2 import c09_row_commitment_v2
    if shape.table!=ERASURE_TABLE:
        raise C09PagedCaptureHold('World barrier retention requires its exact metadata family')
    value=decode_world_erasure_barrier_row_v1(shape.columns,row)
    namespace=tuple(json.loads(build.scope.graph_namespace))
    if value.namespace.as_tuple!=namespace:
        raise C09PagedCaptureHold('World foreign barrier lacks its namespace-specific prior certificate view')
    issuer=build.session.get_c09_domain_original_issuer_v2()
    issuer._signer.verify(ERASURE_SIGN_KIND,row[8],row[10])
    if value.deletion_knowledge_sequence>_world_deletion_knowledge_sequence_v1(build,value.namespace,meter):
        raise C09PagedCaptureHold('World retained barrier knowledge watermark moved backwards')
    if value.deletion_generation>=build.scope.maintenance_generation or build.prior_view is None:
        raise C09PagedCaptureHold('World barrier lacks a preceding actual deletion generation/certificate')
    from .c09_graph_originals_read_v5 import VerifiedPagedPriorGraphCertificateViewV2
    if type(build.prior_view)is not VerifiedPagedPriorGraphCertificateViewV2:
        raise C09PagedCaptureHold('World barrier requires its actual complete V2 prior certificate view')
    prior_scope=build.prior_view.reader.certificate.candidate.scope
    if prior_scope.graph_namespace!=build.scope.graph_namespace:
        raise C09PagedCaptureHold('World barrier prior certificate belongs to another namespace')
    if value.deletion_generation==prior_scope.maintenance_generation:
        build.prior_view.require_generated_world_erasure_barrier_v1(key,row,meter=meter)
    else:
        proof=build.prior_view.require_target_row_disposition(shape.table,key,c09_row_commitment_v2(row),meter=meter)
        if (value.deletion_generation>prior_scope.maintenance_generation
                or proof.disposition!='preserved_exact' or proof.old_commitment!=proof.new_commitment):
            raise C09PagedCaptureHold('World barrier is not an identical actual prior target output')


def _generate_world_erasure_barrier_v1(build,db,shape,key,row,origin,meter):
    from .d03_world_history_v1 import ERASURE_TABLE,ERASURE_COLUMNS,ERASURE_DDL
    from .c09_paged_sql_v2 import c09_row_commitment_v2
    actual=meter.read_fixed_row(db,'sqlite_master',('sql',),'type=? AND name=?',('table',ERASURE_TABLE))
    if actual!=(ERASURE_DDL.replace(' IF NOT EXISTS',''),):
        raise C09PagedCaptureHold('World generated erasure barrier lacks its exact installed target schema')
    barrier=_world_erasure_barrier_row_v1(build,shape,row,meter);barrier_key=tuple(barrier[:4])
    present=meter.read_fixed_row(db,ERASURE_TABLE,ERASURE_COLUMNS,
        'bot=? AND persona=? AND assertion_commitment=? AND known_sequence=?',barrier_key)
    if present is not None:
        raise C09PagedCaptureHold('World generated barrier would replace an existing deletion original')
    meter.write_row(db,ERASURE_TABLE,ERASURE_COLUMNS,barrier)
    locator=canonical_serialize(dict(schema='sylanne3.c09.world-erasure-origin.v1',
        stream_id=origin['origin_stream_id'],ordinal=origin['origin_record_ordinal']))
    proof=(build.scope.scope_digest,ERASURE_TABLE,canonical_digest((ERASURE_TABLE,barrier_key)),
        canonical_serialize(barrier_key),c09_row_commitment_v2(barrier),'world_erasure_barrier_v1',
        locator,origin['origin_commitment'])
    meter.write_row(db,'c09_graph_generated_rows_v2',
        ('scope_digest','table_name','key_digest','key_json','row_commitment','producer','origin_ref','origin_digest'),proof)


def _verify_generated_world_erasure_barrier_v1(progress,shape,key,row,origin_ref,origin_digest,meter):
    from .d03_world_history_v1 import TABLE,COLUMNS,ERASURE_TABLE,ERASURE_COLUMNS
    from .c09_paged_sql_v2 import require_c09_capture_member_v2,c09_row_commitment_v2
    if shape.table!=ERASURE_TABLE or shape.columns!=ERASURE_COLUMNS or not progress.source_semantic_eof:
        raise C09PagedCaptureHold('World generated barrier lacks its actual completed source semantic sweep')
    locator=json.loads(origin_ref)
    if (type(locator)is not dict or set(locator)!={'schema','stream_id','ordinal'}
            or locator['schema']!='sylanne3.c09.world-erasure-origin.v1'
            or type(locator['stream_id'])is not str or type(locator['ordinal'])is not int or locator['ordinal']<0
            or canonical_serialize(locator)!=origin_ref):
        raise C09PagedCaptureHold('World generated barrier origin is not its closed opaque capture locator')
    raw=meter.read_fixed_row(progress.read_db,'c09_capture_streams_v2',('identity_json','status'),
        'stream_id=?',(locator['stream_id'],))
    if raw is None or raw[1]!='sealed':
        raise C09PagedCaptureHold('World generated barrier origin source stream is not sealed')
    stream=c09_paged_value_from_wire_v2(json.loads(raw[0]),C09StreamIdentityV2)
    if (stream.stream_id!=locator['stream_id'] or stream.scope_digest!=progress.session.scope.scope_digest
            or stream.stream_kind!='graph_facts' or stream.family!=TABLE):
        raise C09PagedCaptureHold('World generated barrier origin has another actual scope/family')
    member=meter.read_fixed_row(progress.read_db,'c09_capture_members_v2',('primary_key_json','commitment'),
        'stream_id=? AND record_ordinal=?',(stream.stream_id,locator['ordinal']))
    if member is None or member[1]!=origin_digest:
        raise C09PagedCaptureHold('World generated barrier lost its exact actual source member commitment')
    source_key=tuple(json.loads(member[0]))
    require_c09_capture_member_v2(progress.read_db,stream,locator['ordinal'],source_key,origin_digest,meter=meter)
    source_shape=read_c09_table_shape_v2(progress.pair.source,TABLE)
    if source_shape.columns!=COLUMNS:
        raise C09PagedCaptureHold('World generated barrier source index physical shape differs')
    original=meter.read_row(progress.pair.source,source_shape,source_key)
    if original is None or c09_row_commitment_v2(tuple(original))!=origin_digest:
        raise C09PagedCaptureHold('World generated barrier source is not the identical frozen captured row')
    disposition=_read_graph_disposition_original_row_v3(progress.read_db,
        progress.session.scope.scope_digest,TABLE,source_key,meter)
    if disposition is None or disposition[4:7]!=(origin_digest,'derived_removed',None):
        raise C09PagedCaptureHold('World generated barrier has no independently verified removed index original')
    from .d03_world_history_v1 import decode_world_revision_index_row_v1
    from .c09_world_producer_metadata_v1 import prepare_cold_world_producer_v1
    index=decode_world_revision_index_row_v1(source_shape.columns,tuple(original))
    if prepare_cold_world_producer_v1(progress,index,meter.budget) is None:return False
    expected=_world_erasure_barrier_row_v1(progress.cold_build,source_shape,tuple(original),meter)
    target_sequence=meter.read_fixed_row(progress.read_db,'graph_bundle_sequence',('last_seq',),
        'bot=? AND persona=?',tuple(row[:2]))
    if target_sequence!=(expected[6],):
        raise C09PagedCaptureHold('World deletion watermark is not monotonically preserved in actual target sequence')
    if tuple(row)!=expected or key!=tuple(expected[:4]):
        raise C09PagedCaptureHold('World generated barrier differs from its actual signed deletion conversion')

def _world_deletion_knowledge_sequence_v1(build,namespace,meter):
    shape=read_c09_table_shape_v2(build.pair.source,'graph_bundle_sequence')
    if shape.columns!=('bot','persona','last_seq') or shape.primary_key_columns!=('bot','persona'):
        raise C09PagedCaptureHold('World deletion watermark source sequence physical shape differs')
    key=namespace.as_tuple;row=meter.read_row(build.pair.source,shape,key)
    if row is None or tuple(row[:2])!=key or type(row[2])is not int or row[2]<1:
        raise C09PagedCaptureHold('World deletion watermark has no actual namespace sequence original')
    _actual_source_row_origin_v2(build,shape,key,tuple(row),meter)
    return row[2]
