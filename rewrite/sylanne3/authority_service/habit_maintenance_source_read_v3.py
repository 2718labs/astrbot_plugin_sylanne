"""Independent Habit maintenance metadata, Owner and Source preparation on its fresh control permit."""
from .contract import AuthorityUnavailable
from .habit_authority_source_read_v3 import (HabitAuthorityInputsV3,_KEY,_HabitMetadataColumnV3,_HabitSelectionV3,
    _run_column_v3,_fixed_row_v3,_source_refs_v3,require_habit_authority_work_v3,_HabitMetadataStreamV3)
from ..graph_types import AtomKey,GraphAtom,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

# These registered lifecycle families contain references, commitments and statuses, never Source text.
MAINTENANCE_METADATA_TYPES_V1=frozenset(('d10.life_progress.v1','d10.life_progress_provenance.v1',
    'd10.life_progress_eligibility.v1','d11.life_fact_provenance.v1','d11.life_fact_eligibility.v1',
    'runtime.cost_settlement'))

def habit_maintenance_selected_keys_v1(request):
    from .current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    if type(request)is not HabitOriginalMaintenanceSelectorV1:raise TypeError('exact maintenance selector required')
    keys={AtomKey.from_token(request.policy_ref),AtomKey.from_token(request.occurrence_ref)}
    if request.operation_kind=='adopt_habit_outcome_v1':
        from ..runtime.d10_life_progress_provenance_v1 import life_progress_auxiliary_key_v1,PROVENANCE_TYPE,ELIGIBILITY_TYPE
        progress=AtomKey.from_token(request.command.life_progress_ref)
        if progress.type_name!='d10.life_progress.v1'or NamespaceId.from_key(progress)!=request.namespace:
            raise AuthorityUnavailable('Habit maintenance progress locator crossed namespace/type')
        keys.update((progress,life_progress_auxiliary_key_v1(progress,PROVENANCE_TYPE),life_progress_auxiliary_key_v1(progress,ELIGIBILITY_TYPE)))
    return frozenset(keys)

class _MaintenancePreparedMetadataV3(DispatchOriginalJSONReadV3):
    def __init__(self,work,table,ref):
        super().__init__(work,table=table,column='payload_json',key_columns=('bot','persona','kind','original_ref'),
            key=(*work.namespace.as_tuple,'prepared',ref))
        self.metadata_stream=_HabitMetadataStreamV3(self,self.cell.header[0]=='canonical-json.ascii.v1');self.parser=self.metadata_stream
    def _emit(self,event):
        p=event.path
        keep=not p or p[0]in{'binding','plan','prepare_operation_id','schema'}or p[0]=='read_rows'and(
            len(p)<=2 or len(p)>2 and p[2]in{'ref','revision','valid','value_digest'})
        if keep:super()._emit(event)

def _signed_metadata_v1(service,state,ref):
    from ..runtime.d11_life_preparation_v1 import TABLE,SIGN_KIND
    w=state.work
    row=_fixed_row_v3(w,TABLE,('producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND kind=? AND original_ref=?',(*w.namespace.as_tuple,'prepared',ref))
    if row is None:raise AuthorityUnavailable('Habit maintenance actual signed Life preparation absent')
    column=_MaintenancePreparedMetadataV3(w,TABLE,ref);raw=_run_column_v3(w,column)
    if column.metadata_stream.semantic.hexdigest()!=row[1]:raise AuthorityUnavailable('Habit maintenance Life metadata differs from complete signed original EOF')
    service.issuer._signer.verify(SIGN_KIND,canonical_serialize((w.namespace,'prepared',ref,row[1])),row[2])
    return raw,row[1]

def _metadata_v1(state,key):
    w=state.work;head=w.heads.get(key.token)
    if head is None or head[1]!=1:raise AuthorityUnavailable('Habit maintenance actual current metadata member absent')
    state.extra_keys.add(key)
    column=_HabitMetadataColumnV3(state,key,*head,locator=False,selected=True)
    _run_column_v3(w,column);column.finish_metadata_v3()
    return state.metadata[key][3]

def prepare_habit_maintenance_inputs_v3(service,*,credential,subject,permit,request,definition,current_self,current_policy):
    from .current_authority_graph_read_v3 import (AuthorityGraphReadWorkV3,_AuthorityCatalogueReadV3,require_authority_graph_read_controller_v3,_AuthorityNamespaceReadV3,
        AuthorityGraphProjectionV3,_AuthoritySourceMaterialReadV3,_ISSUER)
    from .owner_location_read_v3 import prepare_owner_location_for_habit_graph_work_v3
    reading=service.clock();now=reading.utc_seconds+reading.utc_error_seconds
    controller=require_authority_graph_read_controller_v3(service)
    work=AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=subject,permit=permit,
        namespace=definition.namespace,request=request,deadline_utc=None)
    work.parent_original_id=definition.parent_root_grant_ref;work.now_utc=now
    work.catalogue_reader=_AuthorityCatalogueReadV3(work);work.phase='catalogue'
    state=HabitAuthorityInputsV3(_KEY,work,service,definition,current_self)
    state.read_now_utc=now;state.maintenance=True;state.maintenance_prepared=None
    try:
        state.owner_entry=prepare_owner_location_for_habit_graph_work_v3(work)
        grant=state.owner_entry.grant
        if('workbench.create'not in grant['capabilities']or not set(definition.audience)<=set(grant['audiences'])):
            raise AuthorityUnavailable('Habit maintenance current Owner capability or actual original audiences absent')
        while not work.catalogue_reader.complete:
            with work.quantum_v3()as meter:work.catalogue_reader.advance_v3(meter)
        work.namespace_reader=_AuthorityNamespaceReadV3(work,catalogue=work.catalogue_reader.rows,catalogue_hash=work.catalogue_reader.catalogue_hash)
        while not work.namespace_reader.graph_eof:
            with work.quantum_v3()as meter:work.namespace_reader.advance_v3(meter)
        from ..domains.d10.habit_policy_v1 import habit_policy_dependency_refs_v1
        roots={ref for value in(definition,current_policy.definition)for ref in habit_policy_dependency_refs_v1(value)if AtomKey.from_token(ref).type_name=='memory.source'}
        for _,_,_,raw in state.metadata.values():roots.update(_source_refs_v3(raw))
        if request.operation_kind=='adopt_habit_outcome_v1':
            from ..runtime.d10_life_progress_provenance_v1 import life_progress_auxiliary_key_v1,PROVENANCE_TYPE
            from ..runtime.d11_life_fact_provenance_v1 import life_fact_auxiliary_key_v1,ELIGIBILITY_TYPE
            proof=state.metadata[life_progress_auxiliary_key_v1(AtomKey.from_token(request.command.life_progress_ref),PROVENANCE_TYPE)][3]
            terminal_proof=proof['terminal_provenance'];binding=terminal_proof['binding']
            roots.update(terminal_proof['source_family_refs'])
            if binding['namespace']!={'bot_id':request.namespace.bot_id,'persona_id':request.namespace.persona_id}:
                raise AuthorityUnavailable('Habit maintenance Life proof crossed actual namespace')
            state.maintenance_prepared=_signed_metadata_v1(service,state,binding['prepared_original_ref'])
            prepared=state.maintenance_prepared[0]
            if prepared['binding']!=binding:raise AuthorityUnavailable('Habit maintenance signed Life preparation differs from actual current terminal proof')
            extra={AtomKey.from_token(terminal_proof['fact_ref']),AtomKey.from_token(proof['terminal_provenance_ref']),life_fact_auxiliary_key_v1(AtomKey.from_token(terminal_proof['fact_ref']),ELIGIBILITY_TYPE)}
            for row in terminal_proof['reads']:
                key=AtomKey.from_token(row['ref'])
                if NamespaceId.from_key(key)!=work.namespace:raise AuthorityUnavailable('Habit maintenance actual Life read crossed namespace')
                if key.type_name=='memory.source':roots.add(key.token)
                elif row['revision']!=0 or key.token in work.heads:extra.add(key)
            plan=prepared['plan'];roots.add(plan['input_source']['ref'])
            roots.update(plan.get('content',{}).get('source_refs',()))
            for ref in request.command.accounting_original_refs:
                key=AtomKey.from_token(ref)
                if key.type_name!='runtime.cost_settlement'or NamespaceId.from_key(key)!=work.namespace:
                    raise AuthorityUnavailable('Habit maintenance accounting locator is not its actual same-namespace settlement')
                extra.add(key)
            for key in sorted(extra,key=lambda key:key.token):roots.update(_source_refs_v3(_metadata_v1(state,key)))
            roots.add(request.command.encoding_trigger_ref)
        state.roots=tuple(sorted(roots))
        for ref in state.roots:
            key=AtomKey.from_token(ref)
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=work.namespace:raise AuthorityUnavailable('Habit maintenance Source locator crossed namespace/type')
        work.projection=AuthorityGraphProjectionV3(_ISSUER,work)
        for audience in definition.audience:
            for roots,purpose in habit_maintenance_source_groups_v1(state):
                if purpose not in grant['purposes']:raise AuthorityUnavailable('Habit maintenance lacks current Owner Source purpose')
                material=_AuthoritySourceMaterialReadV3(work,_HabitSelectionV3(_KEY,work,roots,audience,purpose));state.materials.append(material)
                while material.phase=='rights':
                    with work.quantum_v3()as meter:material.advance_v3(meter)
                if material.phase!='cell'or material.pending:raise AuthorityUnavailable('Habit maintenance complete actual ancestor rights absent')
        keys=set(habit_maintenance_selected_keys_v1(request))|state.extra_keys
        for key in sorted(keys,key=lambda key:key.token):
            revision,valid,cell=work.heads[key.token]
            if valid!=1:raise AuthorityUnavailable('Habit maintenance required actual current member was invalidated')
            column=DispatchOriginalJSONReadV3(work,table='graph_atoms',column='value',key_columns=('token',),key=(key.token,),cell_id=cell)
            raw=_run_column_v3(work,column)
            if not _source_refs_v3(raw)<=set(state.roots):raise AuthorityUnavailable('Habit maintenance selected body introduced an unqualified Source')
            state.bodies[key]=GraphAtom(key,revision,raw,True)
        versions={v.key:v.revision for material in state.materials for v in material.versions}
        versions.update((key,atom.revision)for key,atom in state.bodies.items())
        state.read_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda item:item[0].token))
        state.complete=True
        return state.require_for_v3(service=service,permit=permit)
    except BaseException:state.release_v3();raise

def habit_maintenance_source_groups_v1(state):
    purposes=('context','consolidation')if state.work.request.operation_kind=='adopt_habit_outcome_v1'else('context',)
    return tuple((state.roots,purpose)for purpose in purposes)if state.roots else()


def _signed_original_v1(service,state,kind,ref):
    from ..runtime.d11_life_preparation_v1 import TABLE,SIGN_KIND
    w=state.work
    row=_fixed_row_v3(w,TABLE,('producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND kind=? AND original_ref=?',(*w.namespace.as_tuple,kind,ref))
    if row is None:raise AuthorityUnavailable('Habit maintenance actual signed terminal/outcome original absent')
    column=DispatchOriginalJSONReadV3(w,table=TABLE,column='payload_json',key_columns=('bot','persona','kind','original_ref'),
        key=(*w.namespace.as_tuple,kind,ref))
    raw=_run_column_v3(w,column)
    if canonical_digest(raw)!=row[1]:raise AuthorityUnavailable('Habit maintenance signed original canonical digest differs')
    service.issuer._signer.verify(SIGN_KIND,canonical_serialize((w.namespace,kind,ref,row[1])),row[2])
    return raw,row[0]

def _history_member_v1(state,atom,operation):
    w=state.work
    header=_fixed_row_v3(w,'graph_history',('event_id','valid','value_cell_id'),'token=? AND revision=?',(atom.key.token,atom.revision))
    if header is None or header[:2]!=(operation,1):raise AuthorityUnavailable('Habit maintenance current lifecycle member lacks its actual historical producer')
    column=DispatchOriginalJSONReadV3(w,table='graph_history',column='value',key_columns=('token','revision'),
        key=(atom.key.token,atom.revision),cell_id=header[2])
    if _run_column_v3(w,column)!=atom.value:raise AuthorityUnavailable('Habit maintenance current lifecycle member differs from actual history EOF')

def _dependencies_v1(state,key):
    w=state.work;cursor='';values=[]
    while True:
        row=_fixed_row_v3(w,'graph_dependencies',('dependency_token','dependency_revision'),
            'dependent_token=? AND dependency_token>? ORDER BY dependency_token LIMIT 1',(key.token,cursor))
        if row is None:return tuple(values)
        values.append(row);cursor=row[0]
        w.operation.retain(4096)

def require_habit_maintenance_life_v1(service,state,occurrence,command):
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime.d10_life_progress_provenance_v1 import (life_progress_auxiliary_key_v1,PROVENANCE_TYPE,
        life_progress_qualified_writes_v1)
    from ..runtime.d11_life_preparation_v1 import life_prepared_from_wire_v1
    from ..runtime.d11_life_contract_v1 import RegisteredLifeOutcomeV2,life_from_wire_v1,life_adoption_operation_id_v1
    from ..runtime.d11_life_contract_v1 import D11LifeTerminalV1
    from .habit_authority_source_read_v3 import _read_habit_committed_original_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime.d11_life_fact_provenance_v1 import life_current_fact_reads_v1
    w=state.work;progress_atom=state.bodies[AtomKey.from_token(command.life_progress_ref)]
    progress=decode_typed_production_value_v1(progress_atom.value,LifeProgressHeadV1)
    proof_atom=state.bodies[life_progress_auxiliary_key_v1(progress_atom.key,PROVENANCE_TYPE)]
    proof=proof_atom.value['terminal_provenance'];binding=proof['binding']
    prepared_raw,prepared_operation=_signed_original_v1(service,state,'prepared',binding['prepared_original_ref'])
    prepared=life_prepared_from_wire_v1(prepared_raw)
    if prepared.digest!=state.maintenance_prepared[1]or prepared.prepare_operation_id!=prepared_operation:raise AuthorityUnavailable('Habit maintenance actual signed preparation changed after metadata EOF')
    adopted,adoption_operation=_signed_original_v1(service,state,'adopted_life',progress.artifact_ref)
    terminal=life_from_wire_v1(adopted['terminal'],D11LifeTerminalV1)
    b=terminal.binding
    if(progress_atom.revision!=command.life_progress_revision or terminal.status!='completed'
            or terminal.original_ref!=command.actual_terminal_original_ref or terminal.payload.prepared_digest!=prepared.digest
            or b!=prepared.binding or adopted['prepared_digest']!=prepared.digest
            or adoption_operation!=life_adoption_operation_id_v1(b)
            or(progress.reality,progress.actuality,progress.activity_id,progress.effect_id,progress.recipe_ref)!=(
                'real_execution','completed',occurrence.activity_id,occurrence.effect_id,occurrence.recipe_ref)
            or(b.activity_id,b.effect_id,b.attempt_id,b.parent_budget_lease_ref,b.plan_original_ref)!=(
                occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,occurrence.parent_root_grant_ref,occurrence.life_plan_original_ref)
            or prepared.plan.recipe.revision!=occurrence.recipe_revision):
        raise AuthorityUnavailable('Habit maintenance terminal is not this actual original completed Life effect')
    original_digest,production=_read_habit_committed_original_v3(state,operation_id=proof_atom.value['producing_operation_id'],
        expected_kind='advance_life',member=progress_atom)
    if(production['provenance']['actual_progress']!=plain_v1(progress)
            or production['request']['activity_outcome_ref']!=command.life_outcome_original_ref):
        raise AuthorityUnavailable('Habit maintenance actual progress positive COMMIT names another Life outcome')
    # Rebuild the three fixed progress/proof/eligibility members from actual immutable prepared and terminal originals.
    writes=life_progress_qualified_writes_v1(prepared,terminal,progress,proof_atom.value['producing_operation_id'])
    reads=life_current_fact_reads_v1(prepared)
    from ..runtime.d11_life_fact_provenance_v1 import life_fact_qualified_writes_v1
    from ..graph_types import GraphWrite
    end_key=AtomKey.from_token(proof['fact_ref'])
    end=GraphWrite(end_key,{'schema':end_key.type_name,'binding':plain_v1(b),'payload':plain_v1(terminal.payload),
        'journal_ref':terminal.original_ref,'journal_digest':terminal.terminal_digest})
    end_writes=life_fact_qualified_writes_v1(prepared,terminal.claim,terminal,(end,))
    for write in end_writes:
        atom=state.bodies.get(write.key)
        if atom is None or atom.revision!=1 or atom.value!=write.value:raise AuthorityUnavailable('Habit maintenance actual terminal fact/proof/eligibility changed')
        _history_member_v1(state,atom,adoption_operation)
        if _dependencies_v1(state,write.key)!=tuple(sorted((key.token,1 if key in{end_writes[0].key,end_writes[1].key}else next(row.revision for row in reads if row.ref==key.token))for key in write.dependencies)):
            raise AuthorityUnavailable('Habit maintenance terminal current invalidation edges differ')
    fields={'schema','namespace','result_ref','producing_operation_id','prepared_digest','terminal','source_refs','graph_receipt_json','write_commitments'}
    current=adopted['schema']in{'d11.adopted-life-original.v2','d11.adopted-life-original.v3','d11.adopted-life-original.v4'}
    if(set(adopted)!=fields|({'job_result_binding'}if current else set())
            or adopted['schema']not in{'d11.adopted-life-original.v1','d11.adopted-life-original.v2','d11.adopted-life-original.v3','d11.adopted-life-original.v4'}
            or adopted['namespace']!=plain_v1(w.namespace)or adopted['result_ref']!=progress.artifact_ref
            or adopted['producing_operation_id']!=adoption_operation or b.artifact_ref!=progress.artifact_ref):
        raise AuthorityUnavailable('Habit maintenance signed terminal adoption closed identity differs')
    bundle=_fixed_row_v3(w,'graph_bundle_operations',('digest','commit_seq'),'bot=? AND persona=? AND operation_id=?',(*w.namespace.as_tuple,adoption_operation))
    if bundle is None or bundle[1]<1:raise AuthorityUnavailable('Habit maintenance signed terminal adoption has no actual positive Graph COMMIT')
    column=DispatchOriginalJSONReadV3(w,table='graph_bundle_operations',column='receipt_json',key_columns=('bot','persona','operation_id'),key=(*w.namespace.as_tuple,adoption_operation))
    import json
    actual_receipt=_run_column_v3(w,column)
    if actual_receipt!=json.loads(adopted['graph_receipt_json']):raise AuthorityUnavailable('Habit maintenance signed terminal receipt differs from actual adoption COMMIT')
    from ..runtime.domain_production_originals_v1 import _receipt
    receipt=_receipt(actual_receipt)
    if(receipt.status!='committed'or receipt.operation_id!=adoption_operation
            or(receipt.operation_digest,receipt.commit_seq)!=bundle):raise AuthorityUnavailable('Habit maintenance terminal receipt/bundle identity differs')
    versions={v.key.token:v.revision for v in receipt.write_versions};members={}
    if(len(adopted['write_commitments'])!=len(versions)
            or any(type(row)is not dict or set(row)!={'ref','revision','digest'}for row in adopted['write_commitments'])
            or versions!={row['ref']:row['revision']for row in adopted['write_commitments']}):
        raise AuthorityUnavailable('Habit maintenance terminal receipt full immutable member inventory differs')
    for row in adopted['write_commitments']:
        key=AtomKey.from_token(row['ref'])
        if NamespaceId.from_key(key)!=w.namespace:raise AuthorityUnavailable('Habit maintenance terminal history crossed namespace')
        header=_fixed_row_v3(w,'graph_history',('event_id','valid','value_cell_id'),'token=? AND revision=?',(key.token,row['revision']))
        if header is None or header[:2]!=(adoption_operation,1):raise AuthorityUnavailable('Habit maintenance actual signed terminal member history absent')
        column=DispatchOriginalJSONReadV3(w,table='graph_history',column='value',key_columns=('token','revision'),key=(key.token,row['revision']),cell_id=header[2])
        value=_run_column_v3(w,column)
        if canonical_digest(value)!=row['digest']or not _source_refs_v3(value)<=set(state.roots):
            raise AuthorityUnavailable('Habit maintenance actual terminal member changed or introduced unqualified Source')
        members[key.token]=value
    if current:
        from ..graph_types import Owner
        from ..runtime.d11_life_terminal_v1 import validate_life_job_result_members_v1
        job_key=AtomKey(Owner('activity',*w.namespace.as_tuple,b.activity_id),'runtime.job',b.job_id)
        if b.artifact_ref not in members or job_key.token not in members:raise AuthorityUnavailable('Habit maintenance completed terminal lacks actual artifact/job members')
        validate_life_job_result_members_v1(adopted['job_result_binding'],terminal=terminal,artifact_value=members[b.artifact_ref],
            artifact_revision=versions[b.artifact_ref],job_value=members[job_key.token])
    produced={writes[0].key,writes[1].key,AtomKey.from_token(writes[2].value['terminal_eligibility_ref'])}
    for write in writes:
        atom=state.bodies.get(write.key)
        if atom is None or atom.revision!=1 or atom.value!=write.value:raise AuthorityUnavailable('Habit maintenance current progress proof or eligibility changed')
        _history_member_v1(state,atom,proof_atom.value['producing_operation_id'])
        expected=tuple(sorted((key.token,1 if key in produced else next(row.revision for row in reads if row.ref==key.token))for key in write.dependencies))
        if _dependencies_v1(state,write.key)!=expected:raise AuthorityUnavailable('Habit maintenance actual lifecycle invalidation edges differ')
    for row in reads:
        key=AtomKey.from_token(row.ref)
        if key.type_name=='memory.source':
            source=w.sources.get(row.ref)
            if source is None:raise AuthorityUnavailable('Habit maintenance Source current witness absent')
            source.require_current_v3()
            if(source.revision,source.canonical_semantic_digest,row.valid)!=(row.revision,row.value_digest,True):
                raise AuthorityUnavailable('Habit maintenance original Life Source current version changed')
        else:
            atom=state.bodies.get(key)
            if row.revision==0 and key.token not in w.heads:continue
            if atom is None or(atom.revision,canonical_digest(atom.value),atom.valid)!=(row.revision,row.value_digest,row.valid):
                raise AuthorityUnavailable('Habit maintenance actual Life current read changed')
    if adopted['schema']in{'d11.adopted-life-original.v3','d11.adopted-life-original.v4'}:
        from ..runtime.d11_life_graph_types_v1 import life_role_segment_key_v1
        facts=tuple(GraphWrite(key,members[key.token])for key in(life_role_segment_key_v1(b,'start'),life_role_segment_key_v1(b,'end'),AtomKey.from_token(b.artifact_ref)))
        expected_members=life_fact_qualified_writes_v1(prepared,terminal.claim,terminal,facts)
        actual_reads={v.key.token:v.revision for v in receipt.read_versions}
        for write in expected_members:
            if members.get(write.key.token)!=write.value:raise AuthorityUnavailable('Habit maintenance signed terminal complete fact/provenance/eligibility membership differs')
            if write.key.type_name=='d11.life_fact_provenance.v1'and any(actual_reads.get(row['ref'])!=row['revision']for row in write.value['reads']):
                raise AuthorityUnavailable('Habit maintenance terminal receipt lost actual original read set')
        for frozen in prepared.read_rows:
            header=_fixed_row_v3(w,'graph_history',('valid','value_cell_id'),'token=? AND revision=?',(frozen.ref,frozen.revision))
            if frozen.revision==0 and header is None:continue
            if header is None or header[0]!=int(frozen.valid):raise AuthorityUnavailable('Habit maintenance actual signed preparation history member absent')
            column=_MaintenanceHistoryCommitmentV3(w,frozen.ref,frozen.revision,header[1]);_run_column_v3(w,column)
            from ..runtime.d11_life_preparation_v1 import life_read_digest_v1
            if column.metadata_stream.semantic.hexdigest()!=life_read_digest_v1(frozen):raise AuthorityUnavailable('Habit maintenance actual signed preparation history commitment differs')
    outcome_raw,_=_signed_original_v1(service,state,'outcome',command.life_outcome_original_ref)
    outcome=life_from_wire_v1(outcome_raw,RegisteredLifeOutcomeV2)
    if(outcome.plan_original_ref!=b.plan_original_ref or outcome.terminal_original_ref!=terminal.original_ref
            or outcome.start_original_ref!=terminal.claim.original_ref or outcome.artifact_digest!=terminal.payload.artifact_digest
            or tuple(outcome.paid_cost_refs)!=command.accounting_original_refs or len(command.accounting_original_refs)!=1):
        raise AuthorityUnavailable('Habit maintenance actual signed outcome/accounting/terminal lineage differs')
    from ..runtime.d10_life_outcome_v2 import life_experience_source_id_v1
    from ..memory_types import source_key
    if(command.encoding_trigger_ref!=source_key(*w.namespace.as_tuple,life_experience_source_id_v1(b)).token
            or command.growth_trigger_ref!='d10-current:'+original_digest[:48]):
        raise AuthorityUnavailable('Habit maintenance references only actual existing Life encoding and growth originals')
    # Current Graph settlement is a fixed effect locator; actual immutable reservation and receipt are checked independently.
    for ref in command.accounting_original_refs:
        atom=state.bodies[AtomKey.from_token(ref)];value=atom.value
        if(value['status']not in{'settled','overrun'}or value['unconfirmed']
                or(value['activity_id'],value['effect_id'],value['cost_operation_id'])!=(b.activity_id,b.effect_id,b.reservation_operation_id)):
            raise AuthorityUnavailable('Habit maintenance actual effect has pending or unrelated accounting')
        reservation=_fixed_row_v3(w,'runtime_budget_reservations',('state',),'lease_id=? AND operation_id=?',
            (value['lease_id'],value['cost_operation_id']))
        if reservation is None or reservation[0]not in{'settled','overrun'}:raise AuthorityUnavailable('Habit maintenance actual budget reservation is not finally settled')
        receipt=_fixed_row_v3(w,'runtime_budget_operations',('lease_id',),
            'bot_id=? AND persona_id=? AND operation_id=? AND phase=?',(*w.namespace.as_tuple,value['budget_operation_id'],value['budget_phase']))
        if receipt!=(value['lease_id'],):raise AuthorityUnavailable('Habit maintenance actual terminal component receipt absent')
        column=DispatchOriginalJSONReadV3(w,table='runtime_budget_operations',column='receipt_json',
            key_columns=('bot_id','persona_id','operation_id','phase'),key=(*w.namespace.as_tuple,value['budget_operation_id'],value['budget_phase']))
        receipt_raw=_run_column_v3(w,column)
        if column.sha256!=value['budget_receipt_digest']or receipt_raw['status']!=value['status']:
            raise AuthorityUnavailable('Habit maintenance actual immutable component receipt differs from current settlement')
        for name,expected in(('actual_json',value['actual']),('ceiling_json',value['ceiling'])):
            column=DispatchOriginalJSONReadV3(w,table='runtime_budget_reservations',column=name,
                key_columns=('lease_id','operation_id'),key=(value['lease_id'],value['cost_operation_id']))
            if _run_column_v3(w,column)!=expected:raise AuthorityUnavailable('Habit maintenance actual settled component dimensions differ')
        from .habit_authority_source_read_v3 import require_habit_current_adoption_v3
        require_habit_current_adoption_v3(state,atom)
    return terminal


class _MaintenanceHistoryCommitmentV3(DispatchOriginalJSONReadV3):
    def __init__(self,work,ref,revision,cell):
        super().__init__(work,table='graph_history',column='value',key_columns=('token','revision'),key=(ref,revision),cell_id=cell)
        self.metadata_stream=_HabitMetadataStreamV3(self,self.cell.header[0]=='canonical-json.ascii.v1');self.parser=self.metadata_stream
    def _emit(self,event):
        if not event.path:super()._emit(event)
