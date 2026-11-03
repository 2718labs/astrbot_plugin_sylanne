"""Exact recorded Artifact receipt fact; Source ALL precedes historical originals."""
from contextlib import contextmanager
from contextvars import ContextVar
from types import SimpleNamespace
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.observation_refinement_contract_v3 import observation_platform_observation_v3
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import canonical_digest,NamespaceEpoch
from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3,runtime_storage_quantum_v3
from ..graph_worker import GraphStorageStepV3,create_graph_storage_work_v3
from .natural_outbound_receipt_adoption_read_v3 import (
    NaturalOutboundReceiptAdoptionReadV3,_AdoptionJSONColumnV3,_READERS,
    finish_natural_outbound_receipt_adoption_read_v3)
from .artifact_receipt_original_read_v1 import _NeedPoint,_ReceiptPointV1,_bind_v1,artifact_receipt_sql_v1
KIND='artifact_outbound_receipt_adoption_read_v3'
_ISSUER=object()
_CAPS=WeakKeyDictionary()
_PROOFS=WeakKeyDictionary()
_FACTS=WeakKeyDictionary()
_REPLAYS=WeakKeyDictionary()
_BOUND=ContextVar('actual_artifact_outbound_receipt_fact_v3',default=None)
_FACT_BOUND=ContextVar('actual_artifact_outbound_receipt_fact_originals_v3',default=None)

def _source_cap_v3(reader,meter):
    current=(reader.work,reader.operation,reader.scope,tuple(sorted(
        (ref,task,task.result)for ref,task in reader.source_inspection_tasks.items())))
    if _CAPS.get(reader)!=current or not reader.qualified:
        raise AuthorityUnavailable('Artifact recorded fact lacks its actual complete Source ALL')
    reader.require_current_v3(meter)
    for task in reader.source_inspection_tasks.values():task.require_current_v3(meter)
    return current

class _ArtifactRecordedFactTaskV3:
    def __init__(self,reader):
        self.owner,self.db,self.graph=reader,reader.db,reader.graph
        self.graph_stamp=reader.graph_stamp;self.assembly=False
        self.points={};self.pending=None;self.complete=False
        self.source_roots_qualified=True;self.source_family=frozenset(reader.sources)
        self.receipt=self.original=self.settlement=self.recovered=None
        _FACTS[self]=(reader,reader.work,reader.operation,reader.scope,reader.observation_digest)
    def require_actual_v1(self):
        r=self.owner
        if (_FACTS.get(self)!=(r,r.work,r.operation,r.scope,r.observation_digest)
                or type(r)is not ArtifactOutboundReceiptAdoptionReadV3 or not self.db.in_transaction):
            raise AuthorityUnavailable('Artifact historical point lost its exact Source-qualified Work')
        with runtime_storage_quantum_v3(self.db)as meter:_source_cap_v3(r,meter)
        return self
    def advance_v3(self,meter):
        self.require_actual_v1()
        if self.pending is not None:
            self.pending.advance(meter)
            if self.pending.complete:self.pending=None
            return False
        r=self.owner
        try:
            token=_FACT_BOUND.set(self)
            try:
                with _bind_v1(self):
                    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                    from .artifact_completion_receipt_v1 import require_artifact_completion_receipt_history_v1,receipt_ids_v1
                    op='artifact-completion-source:'+r.final_operation_id.removeprefix('artifact-receipt-message:')
                    original=read_adopted_domain_operation_v1(self.db,r.namespace,op)
                    if original is None:raise AuthorityUnavailable('actual D06 completion producer absent')
                    value=require_artifact_completion_receipt_history_v1(self.db,namespace=r.namespace,original=original)
                    if (value.message_operation_id!=r.final_operation_id or (value.source_ref,)!=r.expression_roots
                            or receipt_ids_v1(value.selector)['activity']!=r.selected_activity_id):
                        raise AuthorityUnavailable('Artifact fact changed its actual D06/final/Core message identity')
                    guard=value.owner_guard
                    owner=artifact_receipt_sql_v1(self.db,
                        'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
                        (*r.namespace.as_tuple,guard.grant_ref)).fetchone()
                    from .domain_background_read_v3 import background_json_loads_v3
                    if (owner is None or owner[2]!=1 or owner[0]!=guard.grant_revision
                            or canonical_digest(background_json_loads_v3(owner[1]))!=guard.grant_digest):
                        raise AuthorityUnavailable('Artifact recorded fact lost its current actual Owner')
                    settlement=read_adopted_domain_operation_v1(self.db,r.namespace,value.completion_operation_id)
                    if settlement is None or (settlement['domain'],settlement['operation_kind'])!=('d08','settle_personal_goal'):
                        raise AuthorityUnavailable('Artifact fact lacks its actual completed Goal producer')
                    from .d11_artifact_draft_content_v1 import ArtifactDraftMethodSettlementHistoryV2
                    from .domain_production_erasure_v1 import decode_typed_production_value_v1
                    history=decode_typed_production_value_v1(
                        settlement['payload']['provenance']['artifact_method_completion'],ArtifactDraftMethodSettlementHistoryV2)
                    if (history.state!='satisfied' or history.selector!=value.selector or history.digest!=value.completion_digest
                            or canonical_digest(settlement['receipt'])!=value.completion_receipt_digest
                            or history.settlement_operation_id!=value.completion_operation_id
                            or history.owner_guard!=guard or history.actor_ref!=original['payload']['authority']['actor']
                            or set(settlement['receipt'].write_versions)!={member.after for member in history.members}
                            or len(settlement['receipt'].write_versions)!=len(history.members)
                            or settlement['payload']['now_utc']!=history.completed_at_utc):
                        raise AuthorityUnavailable('Artifact historical completion receipt/selector/Owner/CAS differs')
                    for member in history.members:
                        if member.before not in settlement['read_versions']:
                            raise AuthorityUnavailable('Artifact completed member lost its before CAS')
                        row=meter.read_fixed_row(self.db,'graph_history',('event_id','valid','value_cell_id'),
                            'token=? AND revision=?',(member.after.key.token,member.after.revision))
                        if row is None or row[:2]!=(history.settlement_operation_id,1):
                            raise AuthorityUnavailable('Artifact completed member lacks its actual producer history')
                        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
                        header=begin_runtime_cell_read_v3(self.db,row[2],erasure_owner_ref=member.after.key.token).header
                        if header[0]!='canonical-json.ascii.v1'or header[5]!=member.after_value_digest:
                            raise AuthorityUnavailable('Artifact completed member metadata commitment differs')
                    for head,digest in value.parent_source_heads:
                        task=r.source_inspection_tasks.get(head.key.token)
                        if task is None or task.result.revision!=head.revision or task.result.semantic_digest!=digest:
                            raise AuthorityUnavailable('Artifact fact parent is outside current exact Source ALL')
                    self.receipt,self.original,self.settlement=value,original,settlement
                    from .artifact_receipt_dispatch_v1 import recover_artifact_receipt_dispatch_candidate_in_transaction_v1
                    recovered=recover_artifact_receipt_dispatch_candidate_in_transaction_v1(self.db,r.namespace,r.final_operation_id)
                    if recovered is None:raise AuthorityUnavailable('Artifact emitted candidate absent')
                    from ..domains.d08 import GoalExecutionProvider
                    spec=next(spec for spec in GoalExecutionProvider().register_types()if spec.name=='d08.action_intent.v1')
                    action=spec.validator(self.history_value_v3(*recovered.write_versions[0]))
                    actual_binding=observation_platform_observation_v3(r.observed).binding
                    if (actual_binding.action_intent_digest.removeprefix('sha256:')!=canonical_digest(action)
                            or recovered.evidence.payload_digest!=actual_binding.origin.payload_digest.removeprefix('sha256:')):
                        raise AuthorityUnavailable('Artifact historical action/payload differs from actual Core execution binding')
                    self.recovered=recovered
            finally:_FACT_BOUND.reset(token)
        except _NeedPoint as needed:
            identity=(needed.query,needed.key)
            if len(self.points)>=256:raise AuthorityUnavailable('Artifact fact exceeded original finite point bound')
            self.pending=_ReceiptPointV1(self,*identity);self.points[identity]=self.pending
            return False
        self.complete=True;return True
    def history_value_v3(self,ref,revision):
        r=self.owner
        if (ref,revision)not in r.history_rows:raise AuthorityUnavailable('Artifact historical member was not actually streamed')
        return r._value('history:'+ref)
    def require_source_column_v3(self,column,value,meter):
        if column.table not in('graph_atoms','graph_history')or column.column!='value':return
        key=AtomKey.from_token(column.key[0])
        if key.type_name!='memory.source':return
        original=self.owner.source_inspection_tasks[key.token].result
        original.require_v3(self.owner,meter)
        from ..memory_types import SourceRecord
        from ..domains.d06.inspection_metadata_v1 import SOURCE_FIELDS
        data=SourceRecord.from_dict(value).to_dict()
        metadata={name:tuple(data[name])if type(data[name])is list else data[name]for name in SOURCE_FIELDS}
        if (tuple(column.cell.header)!=original.header or column.sha256!=original.payload_sha256
                or canonical_digest(data)!=original.semantic_digest or metadata!=dict(original.metadata)):
            raise AuthorityUnavailable('Artifact qualified Source original differs from its inspection commitment')
    def release_v3(self):
        _FACTS.pop(self,None)
        from .dispatch_initial_source_read_v3 import _COLUMNS
        for point in self.points.values():
            for _,_,column in point.columns:_COLUMNS.pop(column,None)
        self.points.clear();self.pending=None
        self.receipt=self.original=self.settlement=self.recovered=None

def current_artifact_recorded_fact_task_v3(db,namespace,operation_id=None):
    task=_FACT_BOUND.get()
    if task is None:return None
    task.require_actual_v1()
    if db is not task.db or namespace!=task.owner.namespace or operation_id is not None and operation_id!=task.owner.final_operation_id:
        raise AuthorityUnavailable('Artifact historical fact lookup changed its actual binding')
    return task

class ArtifactOutboundReceiptAdoptionReadV3(NaturalOutboundReceiptAdoptionReadV3):
    def __init__(self,graph,bootstrap,namespace,final_operation_id,observed=None):
        prefix='artifact-receipt-message:'
        if (not final_operation_id.startswith(prefix)or len(final_operation_id)!=len(prefix)+48
                or any(c not in '0123456789abcdef'for c in final_operation_id[len(prefix):])):
            raise AuthorityUnavailable('exact actual Artifact receipt message locator required')
        super().__init__(graph,bootstrap,namespace,final_operation_id,observed)
        self.family='artifact_receipt';self.fact_task=None
    def _metadata(self,meter):
        raw=self.receipt_column.require_v3(self);candidate=raw.get('dispatch_candidate')
        if (type(candidate)is not dict or candidate.get('schema')!='sylanne.d11.dispatch_candidate.v1'
                or candidate.get('status')!='source_qualified'or len(candidate.get('refs',()))!=4
                or type(candidate.get('source_refs'))is not list or len(candidate['source_refs'])!=1):
            raise AuthorityUnavailable('Artifact actual committed generic candidate metadata absent')
        root=AtomKey.from_token(candidate['source_refs'][0])
        if root.type_name!='memory.source'or root.owner.bot!=self.namespace.bot_id or root.owner.persona!=self.namespace.persona_id:
            raise AuthorityUnavailable('Artifact receipt candidate selected another namespace Source')
        self.receipt_metadata,self.candidate_metadata=raw,candidate
        origin=observation_platform_observation_v3(self.observed).binding.origin
        self.admission_ref=origin.admission_ref;self.authority=SimpleNamespace(audience=(origin.destination_ref,))
        row=meter.read_fixed_row(self.db,'graph_events',('epoch_revision',),
            'bot=? AND persona=? AND session=? AND event_id=?',
            (*self.namespace.as_tuple,self.selected_activity_id,self.final_operation_id))
        if row is None or row[0]!=candidate['graph_epoch']:
            raise AuthorityUnavailable('Artifact candidate lost actual final producer event')
        key=(*self.namespace.as_tuple,self.selected_activity_id,self.final_operation_id)
        for tag,column in(('artifact_reads','reads'),('artifact_writes','revisions')):
            self._enqueue(tag,'graph_events',column,('bot','persona','session','event_id'),key)
        self.phase='artifact_event_columns'
    def _access(self,meter):
        # Acquire metadata/ACL under a real declared group, then independently
        # visit all expression and retained-outbound context groups at ALL EOF.
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        from ..graph_types import GraphAtom
        from ..memory_types import source_key
        self.column.advance(meter)
        if not self.column.complete:return
        token=self.column.key[0];head=self.source_heads[token]
        access=GraphAtom(AtomKey.from_token(token),head[0],self.column.value,bool(head[1]))
        ref=self.pending_sources[-1];source=self.sources[ref]
        purpose='context'if ref==self.authored_source_key.token else'expression'
        record=_qualify_source_rights_values_v3(self.namespace,ref,source,access,None,
            audience=self.authority.audience[0],purpose=purpose,metadata_only=True)
        if record is None:raise AuthorityUnavailable('Artifact fact Source/ancestor current rights denied')
        self.access_atoms[token]=access;self.pending_sources.pop();self.column=None;self.phase='sources'
        self.pending_sources.extend(source_key(*self.namespace.as_tuple,parent).token for parent in record.parent_source_ids
            if source_key(*self.namespace.as_tuple,parent).token not in self.sources)
    def _finish_source_all(self):
        from ..memory_types import source_key,access_key
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        visited,active=set(),set()
        def visit(ref,purpose):
            identity=(ref,purpose)
            if identity in active:raise AuthorityUnavailable('Artifact recorded Source ancestry cyclic')
            if identity in visited:return
            source=self.sources[ref];access=self.access_atoms[access_key(*self.namespace.as_tuple,source.metadata['source_id']).token]
            if _qualify_source_rights_values_v3(self.namespace,ref,source,access,None,
                    audience=self.authority.audience[0],purpose=purpose,metadata_only=True)is None:
                raise AuthorityUnavailable('Artifact recorded Source ALL purpose/audience denied')
            active.add(identity)
            for parent in source.metadata['parent_source_ids']:visit(source_key(*self.namespace.as_tuple,parent).token,purpose)
            active.remove(identity);visited.add(identity)
        for ref in self.expression_roots:visit(ref,'expression')
        if self.authored_source_head is not None:visit(self.authored_source_key.token,'context')
        self.qualified=True
        _CAPS[self]=(self.work,self.operation,self.scope,tuple(sorted(
            (ref,task,task.result)for ref,task in self.source_inspection_tasks.items())))
        for atom in self.access_atoms.values():self.atoms[atom.key.token]=atom
        self.proof=PreparedArtifactOutboundReceiptAdoptionV3(_ISSUER,self);self.phase='admission'
    def advance(self,meter):
        self.require_current_v3(meter)
        if self.phase=='artifact_event_columns':
            if not self._advance_queue(meter):return
            self.event_reads=tuple(GraphVersion(AtomKey.from_token(row[0]),row[1])for row in self._value('artifact_reads'))
            self.event_revisions=tuple(GraphVersion(AtomKey.from_token(row[0]),row[1])for row in self._value('artifact_writes'))
            self.expression_roots=tuple(self.candidate_metadata['source_refs']);self.pending_sources=list(self.expression_roots)
            for version in self.event_reads:
                if version.key.type_name in('memory.source','memory.access','d06.source_correction_head.v1'):
                    self.frozen_versions[version.key.token]=version.revision
            from ..memory_types import source_key
            sid='outbound:'+canonical_digest((self.namespace,self.final_operation_id))[:48]
            self.authored_source_key=source_key(*self.namespace.as_tuple,sid);self.phase='authored_metadata';return
        if self.phase=='access':self._access(meter);return
        if self.phase=='artifact_history':
            types=('d08.action_intent.v1','d08.action_schema.v1','d08.communication_intent_grant.v1','d09.verified_segment_batch.v1')
            revisions={(row.key.token,row.revision)for row in self.event_revisions}
            for (token,revision),kind in zip(self.candidate_metadata['refs'],types):
                key=AtomKey.from_token(token)
                if key.type_name!=kind or (token,revision)not in revisions:
                    raise AuthorityUnavailable('Artifact exact four committed member metadata differs')
                row=meter.read_fixed_row(self.db,'graph_history',('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),
                    'token=? AND revision=?',(token,revision))
                if row is None or row[1:]!=(1,*self.namespace.as_tuple,self.selected_activity_id,self.final_operation_id):
                    raise AuthorityUnavailable('Artifact emitted member lost actual final history')
                self.history_rows[token,revision]=row
                self._enqueue('history:'+token,'graph_history','value',('token','revision'),(token,revision),row[0])
            self.phase='artifact_history_columns';return
        if self.phase=='artifact_history_columns':
            if self._advance_queue(meter):
                self.fact_task=_ArtifactRecordedFactTaskV3(self);self.phase='artifact_facts'
            return
        if self.phase=='artifact_facts':
            if self.fact_task.advance_v3(meter):
                self.recovered=self.fact_task.recovered
                self.receipt_fact=self.fact_task.receipt
                self.receipt_actor=self.fact_task.original['payload']['authority']['actor']
                guard=self.receipt_fact.owner_guard
                head=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,guard.grant_ref))
                if head is None or head[:2]!=(guard.grant_revision,1):
                    raise AuthorityUnavailable('Artifact recorded-fact Owner head changed')
                self.heads[guard.grant_ref]=head
                self.phase='writer_atoms'
            return
        if self.phase=='final_atoms':
            if not self._advance_queue(meter):return
            if self.slot_ref is not None:
                from ..domains.d09.turn_order import turn_outbound_observation_key
                slot=self.atoms[self.slot_ref]
                self._atom(turn_outbound_observation_key(self.namespace,self.scene_ref,self.conversation_ref,slot.value['sequence']),meter,optional=True)
            for version in self.event_reads:
                if version.key.type_name not in('memory.source','memory.access','d06.source_correction_head.v1'):continue
                actual=meter.read_fixed_row(self.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND token=?',(*self.namespace.as_tuple,version.key.token))
                if (0 if actual is None else actual[0])!=version.revision:
                    raise AuthorityUnavailable('Artifact actual original Source readset changed')
                self.heads[version.key.token]=actual
            self.phase='complete_columns';return
        super().advance(meter)
        if self.phase=='named_original':self.phase='artifact_history'
    def release_payload_v3(self):
        _CAPS.pop(self,None)
        if self.proof is not None:_PROOFS.pop(self.proof,None);_REPLAYS.pop(self.proof,None)
        if self.fact_task is not None:self.fact_task.release_v3();self.fact_task=None
        from .dispatch_initial_source_read_v3 import _COLUMNS
        for column,entry in tuple(_COLUMNS.items()):
            if entry[0]is self:_COLUMNS.pop(column,None)
        super().release_payload_v3()

class PreparedArtifactOutboundReceiptAdoptionV3:
    family='artifact_receipt'
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or type(reader)is not ArtifactOutboundReceiptAdoptionReadV3 or _CAPS.get(reader)is None:
            raise AuthorityUnavailable('actual complete Artifact fact Source ALL required')
        self.reader,self.operation,self.query=reader,reader.operation,reader.query
        _PROOFS[self]=(reader,reader.operation,reader.scope,reader.observation_digest)
    def require_current(self,db,namespace,query):
        r=self.reader
        if (_PROOFS.get(self)!=(r,r.operation,r.scope,r.observation_digest)
                or db is not r.db or namespace!=r.namespace or query!=r.query):
            raise AuthorityUnavailable('actual private Artifact fact proof/binding required')
        with runtime_storage_quantum_v3(db)as meter:_source_cap_v3(r,meter)
        return self
    @property
    def recovered(self):return self.reader.recovered
    @property
    def receipt_fact(self):return self.reader.receipt_fact
    @property
    def receipt_actor(self):return self.reader.receipt_actor
    @property
    def receipt_reads(self):return self.read_versions
    @property
    def read_versions(self):
        values={**self.reader.source_heads,**self.reader.heads}
        return tuple(GraphVersion(AtomKey.from_token(ref),0 if head is None else head[0])for ref,head in sorted(values.items()))
    def saved_observation_v3(self):return self.reader.saved_header
    def atom_v3(self,key):
        self.require_current(self.reader.db,self.reader.namespace,self.query)
        atom=self.reader.atoms.get(key.token)
        if atom is None or not atom.valid:raise AuthorityUnavailable('Artifact Body outside actual selected fact projection')
        return atom
    def optional_atom_v3(self,key):
        self.require_current(self.reader.db,self.reader.namespace,self.query)
        if key.token not in self.reader.heads:raise AuthorityUnavailable('Artifact optional head/absence was not read')
        return self.reader.atoms.get(key.token)
    def outbound_slots_v3(self,outbox_ref):
        if outbox_ref!=self.reader.outbox_ref:raise AuthorityUnavailable('Artifact slot belongs to another outbox')
        return()if self.reader.slot_ref is None else(self.atom_v3(AtomKey.from_token(self.reader.slot_ref)),)
    def release_payload_v3(self):self.reader.release_payload_v3()

def begin_artifact_outbound_receipt_adoption_read_v3(graph,bootstrap,namespace,final_operation_id,observed=None):
    r=ArtifactOutboundReceiptAdoptionReadV3(graph,bootstrap,namespace,final_operation_id,observed)
    try:
        work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=r.operation.operation_id,
            selection_digest=r.operation.selection_digest,deadline_utc=None,state=r,operation=r.operation)
        r.work=work;return work
    except BaseException:
        try:r.port.finish_fence(r.scope,request_id='finish:'+r.scope.operation_id,
            request_digest='sha256:'+canonical_digest((r.scope.operation_id,'outbound-fact-read-closed')))
        finally:r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation)
        raise

def advance_artifact_outbound_receipt_adoption_read_v3(graph,work):
    r=work.state
    if type(r)is not ArtifactOutboundReceiptAdoptionReadV3:raise AuthorityUnavailable('actual Artifact fact Work required')
    if canonical_digest(r._current_observation_v3())!=r.observation_digest:
        raise AuthorityUnavailable('actual Core observation changed during Artifact fact READ')
    if r.port.validate_fence(r.scope)!=r.scope.permit:raise AuthorityUnavailable('Artifact fact READ permit changed')
    if r.phase=='replay_fence':
        permit,state=r.port.get_fence_operation(namespace=r.namespace,authority_namespace=r.scope.authority_namespace,
            operation_id=r.saved_original['operation_id'])
        if permit!=r.saved_permit or state not in('active','finished'):
            raise AuthorityUnavailable('Artifact metadata replay original fence unknown')
        r.proof=PreparedArtifactOutboundReceiptReplayV3(_ISSUER,r,state);r.complete=True;r.phase='complete_replay'
        return GraphStorageStepV3('complete',r.proof)
    with bind_runtime_storage_operation_v3(r.operation,r.db),r.store._lock:
        r.db.execute('BEGIN');r._advance_head_memo_v2=(r.db.total_changes,{})
        try:
            with runtime_storage_quantum_v3(r.db)as meter:r.advance(meter)
        finally:r._advance_head_memo_v2=None;r.db.rollback()
    return GraphStorageStepV3('complete',r.proof)if r.complete else GraphStorageStepV3('progress')

def finish_artifact_outbound_receipt_adoption_read_v3(graph,work,error):
    if type(work.state)is not ArtifactOutboundReceiptAdoptionReadV3:
        raise AuthorityUnavailable('actual Artifact fact final retention required')
    return finish_natural_outbound_receipt_adoption_read_v3(graph,work,error)

def observe_artifact_outbound_receipt_adoption_write_v3(proof):
    if type(proof)is not PreparedArtifactOutboundReceiptAdoptionV3:raise AuthorityUnavailable('actual Artifact receipt fact proof required')
    r=proof.reader
    if r.db.in_transaction:raise AuthorityUnavailable('Core observation RPC must precede Artifact WRITE SQL')
    if canonical_digest(r._current_observation_v3())!=r.observation_digest:
        raise AuthorityUnavailable('actual Core observation changed before Artifact fact WRITE')
    r.write_observation=(r.observation_digest,r.graph_stamp)

@contextmanager
def bind_artifact_outbound_receipt_adoption_v3(proof,graph,db,namespace,final_operation_id,observed):
    if type(proof)is not PreparedArtifactOutboundReceiptAdoptionV3:raise AuthorityUnavailable('actual Artifact writer proof required')
    r=proof.reader;proof.require_current(db,namespace,r.query)
    if (not r.complete or graph is not r.graph or final_operation_id!=r.final_operation_id
            or canonical_digest(observed)!=r.observation_digest or r.write_observation!=(r.observation_digest,r.graph_stamp)):
        raise AuthorityUnavailable('Artifact WRITE lacks actual complete READ/current Core observation')
    token=_BOUND.set(proof)
    try:yield proof
    finally:_BOUND.reset(token)

def current_bound_artifact_outbound_receipt_adoption_v3(db,namespace,final_operation_id=None):
    proof=_BOUND.get()
    if proof is None:return None
    if type(proof)is not PreparedArtifactOutboundReceiptAdoptionV3:raise AuthorityUnavailable('unregistered Artifact fact binding')
    r=proof.reader;proof.require_current(db,namespace,r.query)
    if final_operation_id is not None and final_operation_id!=r.final_operation_id:
        raise AuthorityUnavailable('bound Artifact final operation changed')
    return proof

def require_bound_artifact_outbound_receipt_adoption_v3(graph,db,namespace,final_operation_id,observed):
    proof=current_bound_artifact_outbound_receipt_adoption_v3(db,namespace,final_operation_id)
    if proof is None or proof.reader.graph is not graph or canonical_digest(observed)!=proof.reader.observation_digest:
        raise AuthorityUnavailable('Artifact fact writer requires actual private Source READ')
    return proof

class PreparedArtifactOutboundReceiptReplayV3:
    """Actual metadata-only duplicate; has no Body, Source or projection methods."""
    def __init__(self,issuer,reader,state):
        if issuer is not _ISSUER or type(reader)is not ArtifactOutboundReceiptAdoptionReadV3 or reader.phase!='replay_fence' or state not in('active','finished'):
            raise AuthorityUnavailable('actual Artifact replay metadata/original fence required')
        self.reader=reader
        _REPLAYS[self]=(reader,reader.operation,reader.scope,reader.observation_digest,reader.saved_header,reader.saved_permit,reader.saved_event_header)
    def resume_original_ack_v3(self,graph,namespace,final_operation_id,observed):
        r=self.reader
        if (_REPLAYS.get(self)!=(r,r.operation,r.scope,r.observation_digest,r.saved_header,r.saved_permit,r.saved_event_header)
                or graph is not r.graph or namespace!=r.namespace or final_operation_id!=r.final_operation_id
                or canonical_digest(observed)!=r.observation_digest or r.db.in_transaction):
            raise AuthorityUnavailable('actual Artifact metadata replay binding differs')
        r.require_current_v3()
        if canonical_digest(r._current_observation_v3())!=r.observation_digest:
            raise AuthorityUnavailable('Artifact replay cannot substitute an older accepted Core observation')
        permit,state=r.port.get_fence_operation(namespace=namespace,authority_namespace=r.scope.authority_namespace,
            operation_id=r.saved_original['operation_id'])
        if permit!=r.saved_permit or state not in('active','finished'):
            raise AuthorityUnavailable('Artifact replay original adoption ACK unknown')
        if state=='active':
            from ..runtime_contracts import FenceScope
            r.port.finish_fence(FenceScope(namespace,r.scope.authority_namespace,permit.generation,'write',permit.operation_id,
                permit,permit.pinned_anchor,NamespaceEpoch(*namespace.as_tuple,r.saved_original['pre_epoch']),r.saved_original['pre_revision']),
                request_id='finish:'+permit.operation_id,request_digest=r.saved_original['finish_digest'])
        return {'status':'duplicate','observation_outcome':observation_platform_observation_v3(r.observed).outcome}
    def release_payload_v3(self):self.reader.release_payload_v3()
