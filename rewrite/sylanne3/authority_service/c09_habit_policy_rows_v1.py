"""Installed Habit Core inventory, source-dependent retirement and independent cold replay."""
from copy import copy
from dataclasses import asdict
import hashlib,hmac,json
from .contract import AuthorityUnavailable
from .d10_habit_ledger_v1 import (POLICY_TABLE,OCCURRENCE_TABLE,POLICY_DDL,OCCURRENCE_DDL,
    POLICY_COLUMNS,OCCURRENCE_COLUMNS,HabitRetirementV1,habit_ledger_triggers_v1,
    habit_ledger_decode_v1,habit_signing_key_v1)
from .d10_habit_contract_v1 import HabitStandingPolicyOriginalV1,HabitOccurrenceQualificationOriginalV1
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize

TABLES={POLICY_TABLE:(POLICY_DDL,POLICY_COLUMNS),OCCURRENCE_TABLE:(OCCURRENCE_DDL,OCCURRENCE_COLUMNS)}

def _read_v1(db,table,columns,where,key,meter):
    if meter is not None:return meter.read_one(db,table,columns,where,key)
    return db.execute('SELECT '+','.join(columns)+' FROM '+table+' WHERE '+where,key).fetchone()

def require_habit_core_schema_v1(db,*,meter=None):
    present=tuple(_read_v1(db,'sqlite_master',('sql',),'type=? AND name=?',('table',table),meter)for table in TABLES)
    if all(value is None for value in present):return False
    for (table,(ddl,_)),row in zip(TABLES.items(),present):
        if row!=(ddl,):raise AuthorityUnavailable('Habit Core needs both exact immutable installed ledgers')
        for name,sql in habit_ledger_triggers_v1(table):
            if _read_v1(db,'sqlite_master',('sql',),'type=? AND name=?',('trigger',name),meter)!=(sql,):
                raise AuthorityUnavailable('Habit Core immutable trigger differs')
    return True

def _bundle_v1(config,namespace,installation_id):
    from .deployment_config import AuthorityDeploymentConfig,InstalledNaturalModelAuthorityV2
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.habit_runtime_policy_v1 import HabitRuntimePolicyV1
    if type(config)is not AuthorityDeploymentConfig:raise AuthorityUnavailable('actual installed Habit deployment required')
    installation=(config.natural_model_authorities_v2 or {}).get(namespace)
    if type(installation)is not InstalledNaturalModelAuthorityV2:raise AuthorityUnavailable('Habit ledger has no actual installed namespace')
    bundle=installation.installation_bundle
    if(type(bundle)is not AdminInstallationBundle or type(bundle.habit_runtime_policy)is not HabitRuntimePolicyV1
            or bundle.installation_policy.authority_namespace!=namespace or bundle.installation_policy.installation_id!=installation_id):
        raise AuthorityUnavailable('Habit ledger installation tuple differs')
    bundle.habit_runtime_policy.require_installation_v1(bundle.installation_policy)
    return bundle

def validate_habit_core_row_v1(table,columns,row,*,config,control):
    if table not in TABLES:raise AuthorityUnavailable('fixed Habit ledger required')
    bundle=_bundle_v1(config,row[0],row[1])
    return habit_ledger_decode_v1(table,columns,row,key=habit_signing_key_v1(bundle),
        authority_namespace=row[0],authority_id=control.authority_id,installation_id=row[1])

def validate_habit_schema_object_v1(transform,original,meter):
    table=original.table_name
    if table not in TABLES:raise AuthorityUnavailable('fixed Habit schema object required')
    expected=TABLES[table][0]if original.object_type=='table'else dict(habit_ledger_triggers_v1(table)).get(original.name)
    if expected is None or original.sql!=expected:raise AuthorityUnavailable('Habit C09 actual immutable schema differs')
    require_habit_core_schema_v1(transform.pair.source,meter=meter)

def _installed_v1(transform):
    maintenance=transform.basis.session._control.maintenance
    return maintenance._installed_deployment_config_v2,maintenance.control

def _source_versions_v1(original):
    versions=original.source_closure_versions if type(original)is HabitStandingPolicyOriginalV1 else tuple(
        v for v in original.read_versions if v.key.type_name=='memory.source')
    namespace=original.namespace if type(original)is HabitStandingPolicyOriginalV1 or type(original)is HabitOccurrenceQualificationOriginalV1 else original.selector.namespace
    if(not versions or any(type(v)is not GraphVersion or v.revision<1 or v.key.type_name!='memory.source'
            or NamespaceId.from_key(v.key)!=namespace for v in versions)):
        raise AuthorityUnavailable('Habit original lacks actual signed same-namespace Source closure')
    return versions

class _HabitCoreDispositionReadV1:
    def __init__(self,builder,shape,key,row,meter):
        builder.require_current()
        if builder.transform.role!='core' or shape.table not in TABLES or shape.columns!=TABLES[shape.table][1]:
            raise AuthorityUnavailable('Habit actual Core shape differs')
        self.builder,self.shape,self.key,self.row=builder,shape,key,tuple(row)
        self.index=0;self.affected=False;self.complete=False;self.quantum_completed=False
        config,control=_installed_v1(builder.transform)
        self.original=validate_habit_core_row_v1(shape.table,shape.columns,self.row,config=config,control=control)
        self.tasks=()
        self.prior_phase="header";self.prior_directory=None;self.prior_target=None;self.prior_target_locator=None
        self.prior_origin=None;self.prior_origin_locator=None;self.prior_origin_proof=None
        self.prior_found=False;self.prior_origin_found=False;self.prior_scope=None
        if type(self.original)is not HabitRetirementV1 and row[0]==builder.scope.authority_namespace:
            policy=self.original
            if type(policy)is not HabitStandingPolicyOriginalV1:
                stored=meter.read_one(builder.pair.source,POLICY_TABLE,POLICY_COLUMNS,
                    'authority_namespace=? AND installation_id=? AND policy_commitment=? AND policy_revision=? AND payload_digest=?',
                    (row[0],row[1],row[2],row[3],self.original.standing_original_digest if type(self.original)is HabitOccurrenceQualificationOriginalV1 else self.original.selector.standing_authorization_original_digest))
                if stored is None:raise AuthorityUnavailable('Habit dependent Core original lost its actual standing issuer')
                policy=validate_habit_core_row_v1(POLICY_TABLE,POLICY_COLUMNS,stored,config=config,control=control)
                if type(policy)is not HabitStandingPolicyOriginalV1:raise AuthorityUnavailable('Habit live dependent original borrowed a retired standing issuer')
                expected=self.original.standing_original_ref if type(self.original)is HabitOccurrenceQualificationOriginalV1 else self.original.selector.standing_authorization_original_ref
                if policy.original_ref!=expected:raise AuthorityUnavailable('Habit dependent original changed actual standing identity')
            from ..domains.d10.habit_policy_v1 import habit_policy_dependency_refs_v1
            dependencies=set(habit_policy_dependency_refs_v1(policy.definition))
            versions=set((*_source_versions_v1(policy),*_source_versions_v1(self.original)))
            pinned={(v.key.token,v.revision)for v in versions}
            pinned.add((policy.definition.recipe_ref,policy.definition.recipe_revision))
            if policy.definition.executor_kind=='source_note':
                source=policy.definition.source_note_input
                pinned.update(((source.source_ref,source.source_revision),(source.role_binding_ref,source.role_binding_revision)))
            if type(self.original)is HabitOccurrenceQualificationOriginalV1:
                version=self.original.occurrence_head;pinned.add((version.key.token,version.revision))
                dependencies.update((version.key.token,self.original.selector.policy_ref))
            elif type(self.original)is not HabitStandingPolicyOriginalV1:
                pinned.add((self.original.selector.subscription_job_ref,self.original.selector.subscription_job_revision))
                dependencies.update((self.original.selector.subscription_job_ref,self.original.selector.policy_ref))
            tasks=[('graph_history',ref,revision)for ref,revision in sorted(pinned)]
            dependencies.update(v.key.token for v in versions)
            self.tasks=tuple(tasks+[('graph_atoms',ref,None)for ref in sorted(dependencies)])
        self._register_v1()
    def _source_heap_bytes(self):
        from ..runtime.source_correction_read_v3 import _heap
        payload=self.row[POLICY_COLUMNS.index("payload_json")]if self.shape.table==POLICY_TABLE else self.row[OCCURRENCE_COLUMNS.index("payload_json")]
        readers=(self.prior_directory,self.prior_origin,self.prior_target)
        pages=sum(reader.page.encoded_bytes*16+65536 for reader in readers if reader is not None and reader.page is not None)
        return _heap((self.row,self.tasks,self.prior_origin_proof))+32*len(payload)+pages+4096
    def _register_v1(self):
        self.builder.session._source_parser_arena_v3.add(self)
        self.builder.session.require_current()
    def advance_v1(self,meter):
        from ..runtime.c09_paged_sql_v2 import (read_c09_table_shape_v2,c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2)
        self.builder.require_current();out=copy(self);out.quantum_completed=False
        if type(self.original)is HabitRetirementV1:
            return _advance_prior_habit_retirement_v1(out,meter)
        if self.index==len(self.tasks):out.complete=True;out._register_v1();return out
        table,ref,revision=self.tasks[self.index];facts=self.builder.transform.facts
        verified=self.builder.session.require_actual_post_mirror_graph_v3();verified.require_current()
        point=meter.parent
        with c09_sql_meter_quantum_v2(meter.parent),legacy_cell_read_transaction_v2(verified.pair.source),legacy_cell_read_transaction_v2(verified._read_db):
            shape=read_c09_table_shape_v2(verified.pair.source,table,meter=point)
            key=(ref,)if table=='graph_atoms'else(ref,revision)
            if shape.primary_key_columns!=(('token',)if table=='graph_atoms'else('token','revision')):
                raise AuthorityUnavailable('Habit C09 Source version key differs')
            metadata=point.read_fixed_row(verified.pair.source,table,('revision','valid'),'token=?'+(' AND revision=?'if revision is not None else''),key)
            if metadata is None:
                if table=='graph_history':raise AuthorityUnavailable('Habit signed Source version has no reconstructible original or prior-erasure proof')
                out.affected=True
            else:
                result=facts._graph_disposition_key_v3(verified,shape,key,point)
                if result.disposition not in {'preserved_exact','logical_preserved_v3','rebuilt_from_surviving_sources',
                        'derived_removed','payload_erased_retained_facts'}:
                    raise AuthorityUnavailable('Habit C09 encountered an unregistered Graph disposition')
                if metadata[1]!=1 or result.disposition in {'derived_removed','payload_erased_retained_facts'}:out.affected=True
        verified.require_current();facts.require_current();out.index+=1;out._register_v1();return out
    def require_v1(self,transform,shape,row):
        self.builder.require_current()
        if(not self.complete or not self.quantum_completed or self.builder.transform is not transform
                or self.shape!=shape or self.row!=tuple(row)or transform.habit_current_v1 is not self):
            raise AuthorityUnavailable('Habit row transform needs actual same-source complete dependency EOF')
        return self

def transform_habit_core_row_v1(transform,shape,row,meter):
    state=transform.habit_current_v1
    if type(state)is not _HabitCoreDispositionReadV1:raise AuthorityUnavailable('Habit Core original has no actual dependency qualification')
    state.require_v1(transform,shape,row)
    if not state.affected:return tuple(row),'preserved_exact'
    config,control=_installed_v1(transform);bundle=_bundle_v1(config,row[0],row[1]);key=habit_signing_key_v1(bundle)
    disposition='policy_retired'if shape.table==POLICY_TABLE else 'qualification_retired'if type(state.original)is HabitOccurrenceQualificationOriginalV1 else 'cue_retired'
    material=dict(authority_namespace=row[0],installation_id=row[1],policy_commitment=row[2],policy_revision=row[3],
        cancellation_generation=row[4],operation_commitment=row[5],original_commitment=None if shape.table==POLICY_TABLE else row[7],
        target_commitment=state.original.target_commitment,project_commitment=state.original.project_commitment,
        effect_commitment=getattr(state.original,"effect_commitment",None),
        accepted_receipt_digest=transform.scope.accepted_receipt_digest,maintenance_generation=transform.scope.maintenance_generation,
        disposition=disposition,schema='d10.habit-retirement.v1')
    value=HabitRetirementV1(**material,signature=hmac.new(key,canonical_serialize(material).encode('utf8'),hashlib.sha256).hexdigest())
    output=(*row[:6],'retirement',*( ()if shape.table==POLICY_TABLE else(row[7],)),canonical_serialize(asdict(value)),value.digest,value.signature,value.target_commitment,value.project_commitment,
        *((value.effect_commitment,)if shape.table==OCCURRENCE_TABLE else()))
    validate_habit_core_row_v1(shape.table,shape.columns,output,config=config,control=control)
    return output,'rebuilt_from_surviving_sources'


def prepare_habit_core_row_v1(builder,shape,key,meter):
    state=builder.transform.habit_current_v1
    if type(state)is _HabitCoreDispositionReadV1 and state.shape==shape and state.key==key:
        return state
    row=meter.read_one(builder.pair.source,shape.table,shape.columns,
        ' AND '.join(name+'=?'for name in shape.primary_key_columns),key)
    if row is None:raise AuthorityUnavailable('actual Habit Core Source row disappeared')
    return _HabitCoreDispositionReadV1(builder,shape,key,row,meter)

def advance_habit_core_source_row_v1(builder,budget,position,meter):
    from .c09_authority_storage_rebase_v2 import _table_shape,_stream
    from ..runtime.c09_paged_sql_v2 import (read_capture_cursor_v2,read_c09_next_row_metadata_v2,
        c09_sql_meter_quantum_v2,legacy_cell_read_transaction_v2)
    builder.require_current();shape=_table_shape(builder.pair.source,position['table'])
    stream=_stream(builder.pair,builder.scope,shape,'row_dispositions')
    with c09_sql_meter_quantum_v2(meter.parent):
        cursor=read_capture_cursor_v2(builder.pair.candidate,stream)
        with legacy_cell_read_transaction_v2(builder.pair.source):
            found=read_c09_next_row_metadata_v2(builder.pair.source,shape,cursor.last_key)
        if found is None:return None
        state=prepare_habit_core_row_v1(builder,shape,found[0],meter)
        if state.complete and state.quantum_completed:return None
        builder._pending_habit_read_v1=state.advance_v1(meter)
        return {'status':'progress','role':'core','phase':'habit_original_dependency_eof'if builder._pending_habit_read_v1.complete else 'habit_original_dependency',
            'completed_records':builder._pending_habit_read_v1.index,'actual_io_bytes':meter.related_read_bytes}

def verify_habit_core_cold_record_v1(builder,reader,stream,record,meter):
    from .c09_authority_storage_rebase_v2 import _table_shape,_json
    from .c09_authority_storage_rebase import _row_commitment
    shape=_table_shape(builder.pair.source,stream.family)
    state=prepare_habit_core_row_v1(builder,shape,record.primary_key,meter)
    if not(state.complete and state.quantum_completed):
        builder._pending_habit_read_v1=state.advance_v1(meter);return False
    expected,disposition=transform_habit_core_row_v1(builder.transform,shape,state.row,meter)
    old_digest=_row_commitment(shape.table,shape.columns,state.row)
    new_digest=_row_commitment(shape.table,shape.columns,expected)
    proof=meter.read_one(reader,'authority_c09_role_rows_v2',('old_commitment','disposition','new_commitment'),
        'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
        (builder.scope.scope_digest,'core',shape.table,canonical_digest(record.primary_key)))
    if proof!=(old_digest,disposition,new_digest):raise AuthorityUnavailable('Habit cold disposition differs from independently repeated actual Source closure')
    target=meter.read_one(reader,shape.table,shape.columns,
        ' AND '.join(name+'=?'for name in shape.primary_key_columns),record.primary_key)
    if target!=expected:raise AuthorityUnavailable('Habit cold target differs from actual source-derived retirement or exact preservation')
    values=(builder.scope.scope_digest,'core',shape.table,canonical_digest(record.primary_key),_json(record.primary_key),old_digest,disposition,new_digest)
    if canonical_digest(('sylanne3.c09.authority-row-disposition.v2',values))!=record.commitment:
        raise AuthorityUnavailable('Habit cold source record lost exact complete stream membership')
    builder.transform.habit_current_v1=None
    return True


def _advance_prior_habit_retirement_v1(state,meter):
    from .c09_authority_storage_rebase import _row_commitment
    from .c09_authority_storage_rebase_v2 import _json
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2,C09HistoricalSealedStreamReaderV2
    from .c09_prepared_storage_v2 import _build_original,PREPARED_FIELDS_V2
    from .c09_prepared_storage_v3 import PREPARED_FIELDS_V3
    from ..runtime.c09_paged_capture_contract_v2 import (C09CaptureScopeV2,C09StreamIdentityV2,C09CompleteStreamV2,
        C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
    builder=state.builder;facts=builder.transform.facts;db=builder.pair.source;root=meter.parent
    original=state.original
    if state.prior_phase=='header':
        lineage=meter.read_one(facts._db,'c09_recovery_history_scopes_v2',
            ('historical_scope_digest','operation_id','prepared_digest'),'scope_digest=? AND generation=?',
            (builder.scope.scope_digest,original.maintenance_generation))
        if lineage is None:raise AuthorityUnavailable('prior Habit retirement has no actual selected historical Core certificate')
        historic,operation,prepared_digest=lineage
        columns=('scope_digest','role','table_name','key_digest','key_json','old_commitment','disposition','new_commitment')
        proof=meter.read_one(db,'authority_c09_role_rows_v2',columns,
            'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
            (historic,'core',state.shape.table,canonical_digest(state.key)))
        if(proof is None or proof[4]!=_json(state.key)or proof[6]!='rebuilt_from_surviving_sources'
                or proof[7]!=_row_commitment(state.shape.table,state.shape.columns,state.row)):
            raise AuthorityUnavailable('prior Habit retirement has no exact authenticated Core transformation origin')
        state.prior_origin_proof=proof
        config,control=_installed_v1(builder.transform)
        with control._db()as selected:
            bounded=_BoundedReadConnectionV2(selected,root)
            prepared_rows=[]
            for table in ('c09_storage_operations_v2','c09_storage_operations_v3'):
                if bounded.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()is None:continue
                found=bounded.execute('SELECT prepared_original_json,prepared_digest FROM '+table+' WHERE installation_id=? AND operation_id=?',
                    (original.installation_id,operation)).fetchone()
                if found is not None:prepared_rows.append(found)
            if len(prepared_rows)!=1 or prepared_rows[0][1]!=prepared_digest:
                raise AuthorityUnavailable('prior Habit retirement lost its unique actual signed PREPARED lineage')
            row=prepared_rows[0]
            prepared=json.loads(row[0]);control.verify_original_v1(prepared,'prepared_digest')
            expected_fields=PREPARED_FIELDS_V2 if prepared.get('schema')=='sylanne3.c09.storage_prepared_original.v2'else PREPARED_FIELDS_V3 if prepared.get('schema')=='sylanne3.c09.storage_prepared_original.v3'else None
            if(expected_fields is None or set(prepared)!=expected_fields or prepared['prepared_digest']!=prepared_digest
                    or prepared['authority_id']!=control.authority_id or prepared['installation_id']!=original.installation_id
                    or prepared['namespace']!=original.authority_namespace or prepared['capture_scope_digest']!=historic
                    or prepared['maintenance_generation']!=original.maintenance_generation
                    or prepared['accepted_receipt_digest']!=original.accepted_receipt_digest):
                raise AuthorityUnavailable('prior Habit retirement differs from its own namespace, accepted receipt and certified generation')
            scope=c09_paged_value_from_wire_v2(_build_original(control,bounded,operation,'capture_scope_v2'),C09CaptureScopeV2)
            header=_build_original(control,bounded,operation,'capture_role_complete_v2_core',prepared['four_role_complete_original_digests']['core'])
        if(scope.scope_digest!=historic or scope.authority_namespace!=original.authority_namespace
                or scope.installation_id!=original.installation_id or scope.accepted_receipt_digest!=original.accepted_receipt_digest
                or header['scope_digest']!=historic or header['role']!='core'):
            raise AuthorityUnavailable('prior Habit retirement has no actual own Core role completion')
        state.prior_scope=historic
        state.prior_directory=C09HistoricalSealedStreamReaderV2(c09_paged_value_from_wire_v2(header['stream_directory'],C09SealedStreamLocatorV2))
        state.prior_phase='directory'
    elif state.prior_phase=='directory':
        state.prior_directory=copy(state.prior_directory)
        def observe(record):
            table='authority_c09_role_streams_v2';columns=('scope_digest','role','table_name','stream_kind','stream_json','seal_json')
            row=meter.read_one(db,table,columns,'scope_digest=? AND role=? AND table_name=? AND stream_kind=?',record.primary_key)
            if row is None or canonical_digest(('sylanne3.c09.authority-directory-row.v2','control_metadata',table,record.primary_key,row))!=record.commitment:
                raise AuthorityUnavailable('prior Habit Core signed directory member differs')
            if row[:3]==(state.prior_scope,'core',state.shape.table)and row[3]in{'target_rows','row_dispositions'}:
                previous=state.prior_target_locator if row[3]=='target_rows'else state.prior_origin_locator
                if previous is not None:raise AuthorityUnavailable('prior Habit target or source-disposition stream is duplicated')
                identity=c09_paged_value_from_wire_v2(json.loads(row[4]),C09StreamIdentityV2)
                complete=c09_paged_value_from_wire_v2(json.loads(row[5]),C09CompleteStreamV2)
                if(identity.scope_digest!=state.prior_scope or identity.stream_kind!=row[3]
                        or identity.family!=state.shape.table or identity.primary_key_columns!=state.shape.primary_key_columns):
                    raise AuthorityUnavailable('prior Habit target stream crossed its exact table/scope/key contract')
                locator=C09SealedStreamLocatorV2('core',identity,complete)
                if row[3]=='target_rows':state.prior_target_locator=locator
                else:state.prior_origin_locator=locator
        if state.prior_directory.advance(db,root,observe):
            if state.prior_target_locator is None or state.prior_origin_locator is None:
                raise AuthorityUnavailable('prior signed Core directory omits Habit target or source-disposition inventory')
            state.prior_target=C09HistoricalSealedStreamReaderV2(state.prior_target_locator)
            state.prior_origin=C09HistoricalSealedStreamReaderV2(state.prior_origin_locator);state.prior_phase='origin'
    elif state.prior_phase=='origin':
        state.prior_origin=copy(state.prior_origin)
        def observe(record):
            if record.primary_key==state.key:
                if state.prior_origin_found:raise AuthorityUnavailable('prior Habit Source disposition appears twice')
                expected=canonical_digest(('sylanne3.c09.authority-row-disposition.v2',state.prior_origin_proof))
                if record.commitment!=expected:raise AuthorityUnavailable('prior Habit old-to-new transformation is outside signed Core Source inventory')
                state.prior_origin_found=True
        if state.prior_origin.advance(db,root,observe):
            if not state.prior_origin_found:raise AuthorityUnavailable('complete signed Core Source inventory omits Habit retirement producer')
            state.prior_phase='target'
    elif state.prior_phase=='target':
        state.prior_target=copy(state.prior_target)
        def observe(record):
            if record.primary_key==state.key:
                if state.prior_found:raise AuthorityUnavailable('prior Habit retirement appears twice in signed target stream')
                commitment=_row_commitment(state.shape.table,state.shape.columns,state.row)
                expected=canonical_digest(('sylanne3.c09.authority-target-row.v2',state.shape.table,state.key,commitment))
                if record.commitment!=expected:raise AuthorityUnavailable('prior Habit target certificate does not contain this exact bodyless row')
                state.prior_found=True
        if state.prior_target.advance(db,root,observe):
            if not state.prior_found:raise AuthorityUnavailable('complete historical Core target inventory omits actual Habit retirement')
            state.prior_phase='complete';state.complete=True
    else:raise AuthorityUnavailable('unknown fixed Habit historical verification phase')
    state._register_v1();return state
