"""Independent fixed Source-qualified Contact Plan original for named Joint.

This adapter verifies the original signed physical descriptor, full column EOF,
actual positive producer, complete historical query and exact current members.
It does not mint or borrow Contact Host/Domain Source permission.
"""
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import canonical_digest,canonical_serialize
from .contract import AuthorityUnavailable
from .named_joint_binding_source_read_v3 import _fixed,_column,_positive,_run,_MetadataStreamV3
from .named_joint_binding_body_v1 import _bound,_Needed,_SourceLocatorColumn,_precheck_column


def read_bound_named_joint_contact_plan_v1(db,*,namespace,contact_id):
    state=_bound(db)
    if state is None:return None
    binding=state.request.command.binding
    if namespace!=state.work.namespace or contact_id!=binding.contact_id:
        raise AuthorityUnavailable('Named Joint Contact Plan crossed its exact prospective command')
    if state.contact_plan is None:raise _Needed(('contact_plan',contact_id))
    return state.contact_plan


def _row(state,table,columns,key_columns,key):
    return _fixed(state.work,table,columns,' AND '.join(name+'=?'for name in key_columns),key)


def _commitment(state,read,*,historical):
    if read.revision==0:
        if not historical and read.ref in state.work.heads:
            raise AuthorityUnavailable('Named Contact original negative dependency appeared')
        return
    key=AtomKey.from_token(read.ref)
    if key.type_name=='memory.source'and read.ref not in state.closure_refs:
        raise AuthorityUnavailable('Named Contact historical Source lacks current independent ALL')
    table='graph_history'if historical else'graph_atoms'
    columns=('token','revision')if historical else('token',)
    selected=(read.ref,read.revision)if historical else(read.ref,)
    row=_row(state,table,('revision','valid','value_cell_id'),columns,selected)
    if row is None or(row[0],bool(row[1]))!=(read.revision,read.valid):
        raise AuthorityUnavailable('Named Contact actual original dependency revision/currentness changed')
    column=_SourceLocatorColumn(state.work,table=table,column='value',key_columns=columns,key=selected,cell_id=row[2])
    stream=_MetadataStreamV3(column,column.cell.header[0]=='canonical-json.ascii.v1');column.parser=stream
    _run(state.work,column)
    if (column.cell.header[0],column.byte_count,column.sha256,stream.semantic.hexdigest())!=(
            read.codec,read.byte_count,read.payload_sha256,read.semantic_sha256):
        raise AuthorityUnavailable('Named Contact original dependency complete physical/semantic EOF changed')


def _historical_inventory(state,proof):
    epochs={query.epoch.revision for query in proof.query_coverage}
    if len(epochs)!=1:raise AuthorityUnavailable('Named Contact original query epochs differ')
    epoch=next(iter(epochs));refs={read.ref for read in proof.historical_reads}
    kinds={query.type_id for query in proof.query_coverage};after='';rows=[]
    while True:
        with state.work.quantum_v3()as meter:
            sql=(' FROM graph_history h JOIN graph_events e ON '
                '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
                'WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token>?')
            token=state.work.db.execute('SELECT MIN(h.token)'+sql,(*state.work.namespace.as_tuple,epoch,after)).fetchone()[0]
            meter.charge_read(8 if token is None else len(token.encode())+8)
        if token is None:break
        after=token
        if token not in refs and AtomKey.from_token(token).type_name not in kinds:continue
        if len(rows)>=1024:raise AuthorityUnavailable('Named Contact actual historical inventory exceeds its original bound')
        with state.work.quantum_v3()as meter:
            revision=state.work.db.execute('SELECT MAX(h.revision) FROM graph_history h JOIN graph_events e ON '
                '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
                'WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token=?',
                (*state.work.namespace.as_tuple,epoch,token)).fetchone()[0]
            meter.charge_read(8)
        row=_row(state,'graph_history',('token','revision','valid'),('token','revision'),(token,revision))
        if row is None:raise AuthorityUnavailable('Named Contact historical metadata changed during EOF')
        state.work.operation.retain(len(token.encode())*4+256);rows.append(row)
    heads={ref:(revision,bool(valid))for ref,revision,valid in rows}
    for read in proof.historical_reads:
        if heads.get(read.ref)!=((read.revision,read.valid)if read.revision else None):
            raise AuthorityUnavailable('Named Contact original historical metadata omitted or changed a member')
        _commitment(state,read,historical=True)
    for query in proof.query_coverage:
        actual=tuple((ref,revision)for ref,(revision,_)in sorted(heads.items())if AtomKey.from_token(ref).type_name==query.type_id)
        if actual!=tuple((version.key.token,version.revision)for version in query.row_versions):
            raise AuthorityUnavailable('Named Contact complete original historical negative coverage changed')


def _dependencies(state,token):
    after='';rows=[]
    while True:
        row=_fixed(state.work,'graph_dependencies',('dependency_token','dependency_revision'),
            'dependent_token=? AND dependency_token>? ORDER BY dependency_token',(token,after))
        if row is None:return tuple(rows)
        if len(rows)>=1024:raise AuthorityUnavailable('Named Contact actual dependency set exceeds original bound')
        state.work.operation.retain(len(row[0])*4+128);rows.append(row);after=row[0]


def prepare_named_joint_contact_plan_v1(state):
    from ..runtime.contact_plan_adoption_v3 import (TABLE,COLUMNS,SIGN_KIND,contact_plan_logical_descriptor_v3,
        validate_contact_plan_original_payload_v3,contact_plan_writes_v3,OPERATION)
    binding=state.request.command.binding;key=(*state.work.namespace.as_tuple,binding.contact_id)
    row=_row(state,TABLE,COLUMNS,('bot','persona','contact_id'),key)
    if row is None:
        # V2 remains an actual signed formal original, never a cached fallback.
        return _plan2(state,key)
    state.service.issuer._signer.verify(SIGN_KIND,canonical_serialize(contact_plan_logical_descriptor_v3(row)),row[13])
    _precheck_column(state,TABLE,'payload_cell_id',('bot','persona','contact_id'),key,row[4])
    raw=_column(state,TABLE,'payload_cell_id',('bot','persona','contact_id'),key,row[4])
    if canonical_digest(raw)!=row[8]:raise AuthorityUnavailable('Named Contact actual physical Plan logical digest differs')
    plan,expression,proof=validate_contact_plan_original_payload_v3(raw)
    if(plan.namespace,plan.contact_id,proof.producing_operation_id)!=(state.work.namespace,binding.contact_id,row[3]):
        raise AuthorityUnavailable('Named Contact actual Plan/provenance producer differs')
    state.producer_ids.add(row[3]);actual=_positive(state,row[3],kind=OPERATION)
    receipt=actual['receipt'];writes=contact_plan_writes_v3(proof)
    if(canonical_digest(receipt)!=row[12]or row[12]!=raw['receipt_digest']
            or receipt.operation_id!=proof.producing_operation_id
            or {(v.key,v.revision)for v in receipt.write_versions}!={(w.key,1)for w in writes}
            or {(read.ref,read.revision)for read in proof.historical_reads}!={(v.key.token,v.revision)for v in receipt.read_versions}
            or actual['payload']['provenance']['proof']!=raw['proof']
            or(proof.activation_generation,proof.graph_incarnation)!=(state.current_self.activation_generation,state.current_self.graph_incarnation)):
        raise AuthorityUnavailable('Named Contact actual Plan COMMIT/Owner/generation/membership differs')
    _historical_inventory(state,proof)
    revisions={read.ref:read.revision for read in proof.current_reads};revisions.update((w.key.token,1)for w in writes)
    for write in writes:
        current=state.work.heads.get(write.key.token)
        if current is None or current[:2]!=(1,1):raise AuthorityUnavailable('Named Contact current Plan member is no longer actual')
        body=_column(state,'graph_atoms','value',('token',),(write.key.token,),current[2])
        historical=_row(state,'graph_history',('event_id','valid','value_cell_id'),('token','revision'),(write.key.token,1))
        old=None if historical is None else _column(state,'graph_history','value',('token','revision'),(write.key.token,1),historical[2])
        if body!=write.value or historical is None or historical[:2]!=(receipt.operation_id,1)or old!=write.value:
            raise AuthorityUnavailable('Named Contact actual Plan current/historical write changed')
        wanted={(dep.token,revisions[dep.token])for dep in write.dependencies}
        edges=_dependencies(state,write.key.token)
        old_edges=_column(state,'graph_history','dependencies',('token','revision'),(write.key.token,1))
        if len(edges)!=len(wanted)or set(edges)!=wanted or len(old_edges)!=len(wanted)or{tuple(edge)for edge in old_edges}!=wanted:
            raise AuthorityUnavailable('Named Contact actual Plan dependency lineage changed')
    for read in proof.current_reads:_commitment(state,read,historical=False)
    for kind,inventory in raw['current_inventories'].items():
        actual=tuple((ref,head[0],bool(head[1]))for ref,head in sorted(state.work.heads.items())if AtomKey.from_token(ref).type_name==kind)
        if actual!=tuple((r['ref'],r['revision'],r['valid'])for r in inventory):
            raise AuthorityUnavailable('Named Contact actual current negative inventory changed')
    return plan,expression,raw,row[8]


def _plan2(state,key):
    from ..runtime.contact_plan_adoption_v2 import (TABLE,SIGN_KIND,validate_contact_plan_original_payload_v2,
        validate_contact_plan_history_v2,require_current_contact_plan_members_v2,OPERATION)
    row=_row(state,TABLE,('payload_digest','signature'),('bot','persona','contact_id'),key)
    if row is None:raise AuthorityUnavailable('Named Contact actual adopted Plan original is absent')
    _precheck_column(state,TABLE,'payload_json',('bot','persona','contact_id'),key)
    raw=_column(state,TABLE,'payload_json',('bot','persona','contact_id'),key)
    if canonical_digest(raw)!=row[0]:raise AuthorityUnavailable('Named Contact signed Plan2 canonical digest differs')
    state.service.issuer._signer.verify(SIGN_KIND,canonical_serialize((state.work.namespace,key[2],row[0])),row[1])
    plan,expression,proof=validate_contact_plan_original_payload_v2(raw)
    state.producer_ids.add(proof.producing_operation_id);actual=_positive(state,proof.producing_operation_id,kind=OPERATION)
    from .named_joint_binding_body_v1 import _pump
    _pump(state,lambda frame:validate_contact_plan_history_v2(state.work.db,proof=proof,actual=actual))
    _pump(state,lambda frame:require_current_contact_plan_members_v2(state.work.db,proof=proof,receipt=actual['receipt']))
    return plan,expression,raw,row[0]
