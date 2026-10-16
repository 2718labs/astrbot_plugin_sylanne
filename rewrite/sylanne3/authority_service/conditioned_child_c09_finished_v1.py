"""Accepted C09 proof of one exact old conditioned producer's finished Core row.

The current active child Work supplies its actual Graph fence. This reader
accepts only the matching old Core tuple from a signed, EOF-verified accepted
history stream. It creates no Build scope, grant, row or replacement fact.
"""
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize

_READS=WeakKeyDictionary()
_DIRECTORY=('scope_digest','role','table_name','stream_kind','stream_json','seal_json')
_DISPOSITION=('scope_digest','role','table_name','key_digest','key_json','old_commitment','disposition','new_commitment')
_TABLE='authority_v2_fences'



def _require_exact_finished_work_v3(work):
    from .conditioned_child_source_v1 import _ConditionedCoreSourceWorkV1,require_conditioned_core_source_work_v1
    from .habit_finished_producer_v3 import _HabitFinishedProducerWorkV3,require_habit_finished_work_v3
    if type(work)is _ConditionedCoreSourceWorkV1:return require_conditioned_core_source_work_v1(work)
    if type(work)is _HabitFinishedProducerWorkV3:return require_habit_finished_work_v3(work)
    from .artifact_model_finished_producer_v3 import _ArtifactModelFinishedProducerV3,require_artifact_finished_work_v3
    if type(work)is _ArtifactModelFinishedProducerV3:return require_artifact_finished_work_v3(work)
    raise AuthorityUnavailable('accepted C09 finished reader requires an exact independently selected private producer Work')

def _finished_control_v3(work):
    _require_exact_finished_work_v3(work)
    from .artifact_model_finished_producer_v3 import _ArtifactModelFinishedProducerV3
    if type(work)is _ArtifactModelFinishedProducerV3:return work.service.owner_storage.control
    from .habit_finished_producer_v3 import _HabitFinishedProducerWorkV3
    source=(work.service.self_identity._source_location if type(work)is _HabitFinishedProducerWorkV3 else work.service._source_location)
    return source._control

def _finished_core_v3(work):
    _require_exact_finished_work_v3(work)
    from .artifact_model_finished_producer_v3 import _ArtifactModelFinishedProducerV3
    if type(work)is _ArtifactModelFinishedProducerV3:return work.service.owner_storage.core
    from .habit_finished_producer_v3 import _HabitFinishedProducerWorkV3
    return work.service.policy_service.core if type(work)is _HabitFinishedProducerWorkV3 else work.service._core

class _AcceptedConditionedProducerFenceReadV1:
    def __init__(self,work,operation_id,header,permit,bundle):
        from .v2_contract import canonical_bytes
        from .v2_fence_store import _TABLES
        from .c09_authority_storage_rebase import _row_commitment,_canonical
        _require_exact_finished_work_v3(work)
        if work.producer_fence_candidates.get(operation_id)!=(header,permit,bundle):
            raise AuthorityUnavailable('C09 conditioned finished reader requires the actual independently selected Graph producer fence')
        self.work,self.operation_id,self.header,self.permit,self.bundle=work,operation_id,header,permit,bundle
        self.control=_finished_control_v3(work)
        self.expected=(permit.operation_id,permit.namespace,permit.subject,permit.token,permit.fence_epoch,
            permit.revision,'finished',canonical_bytes(permit),header[5],header[6],None)
        self.commitment=_row_commitment(_TABLE,_TABLES[_TABLE],self.expected)
        self.key=(permit.operation_id,);self.key_digest=canonical_digest(self.key);self.key_json=_canonical(self.key).decode('utf-8')
        self.phase='selection';self.failed=False;self.complete=False
        self.view=self.disposition=self.lineage=self.summary=self.scope=self.scan=self.core_header=None
        self.historical_frame=None
        self.directory=self.stream=self.directory_row=None
        self.directory_found=self.member_found=False
        self.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from .c09_selected_history_v3 import _selected_history_payload_heap_v3
        seen=set();size=8192+_selected_history_payload_heap_v3((self.expected,self.disposition,self.lineage,
            self.summary,self.scope,self.core_header,self.directory_row),seen)
        for reader in(self.directory,self.stream):
            if reader is not None:size+=_selected_history_payload_heap_v3((reader.locator,reader.cursor,reader.page,reader.records),seen)
        if self.scan is not None:
            size+=_selected_history_payload_heap_v3((getattr(self.scan,'row',None),getattr(self.scan,'result',None)),seen)
        return size

    def _require_work(self):
        work=_require_exact_finished_work_v3(self.work)
        if(self.failed or self.control is not _finished_control_v3(work)
                or work.producer_fence_candidates.get(self.operation_id)!=(self.header,self.permit,self.bundle)
                or _READS.get(work,{}).get(self.operation_id)is not self):
            raise AuthorityUnavailable('C09 conditioned finished reader lost its actual Work or retained first failure')
        work._observe()
        return work

    def _require_selection(self,meter):
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        from .c09_selected_core_source_v3 import SelectedCoreSourceMetadataV3
        view=getattr(self.control,'_selected_history_read_v3',None)
        if(type(view)is not VerifiedSelectedHistoryReadV3 or view.basis.control is not self.control
                or self.view is not None and self.view is not view
                or type(view.core_source_proof)is not SelectedCoreSourceMetadataV3
                or view.core_source_proof.basis is not view.basis):
            raise AuthorityUnavailable('C09 conditioned producer has no actual complete selected history/Core Source EOF')
        self.view=view;view.require_current(meter=meter);view.core_source_proof.require_current(meter=meter)
        current=view.basis.require_current(meter=meter)
        policy=self.work.service.installed_bundle.installation_policy
        runtime=_finished_core_v3(self.work)._runtime_storage_v3
        if((view.scope.authority_id,view.scope.installation_id,view.scope.authority_namespace,view.scope.graph_namespace)!=(
                self.permit.authority_id,policy.installation_id,self.permit.namespace,canonical_serialize(self.work.namespace.as_tuple))
                or runtime is None or runtime.context._reader is not self.control
                or(runtime.context.manifest_digest,runtime.context.pointer_version)!=(
                    view.basis.manifest['manifest_digest'],current['pointer_version'])):
            raise AuthorityUnavailable('C09 conditioned certificate crossed its actual selected Core/Graph installation or lineage')
        context=self.control.read_verified_current_storage_v3(meter=meter)
        context.require_current('business')
        if(context.manifest_digest,context.pointer_version)!=(runtime.context.manifest_digest,runtime.context.pointer_version):
            raise AuthorityUnavailable('C09 conditioned producer selection changed during its accepted history read')
        self.control.require_c09_retained_arena_v3(meter=meter)
        return view

    def advance(self):
        from .daemon import _bootstrap_control_quantum_v3
        try:
            self._require_work()
            with _bootstrap_control_quantum_v3(self.control)as meter:
                self._require_selection(meter)
                self._advance(meter)
                self._require_selection(meter)
            self._require_work()
            return self.complete
        except BaseException:
            self.failed=True
            raise

    def _advance(self,meter):
        import json
        from .c09_paged_recovery_facts_v2 import (_read_one,C09HistoricalSealedStreamReaderV2,
            begin_next_authenticated_prepared_reader_v2)
        from .c09_prepared_storage_v3 import _read_original
        from .c09_selected_core_source_v3 import _locator
        from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2
        view=self.view;basis=view.basis
        if self.phase=='selection':
            with basis.read_database('core',meter=meter)as db:
                row=_read_one(db,'SELECT '+','.join(_DISPOSITION)+' FROM authority_c09_role_rows_v2 '
                    'WHERE role=? AND table_name=? AND key_digest=? AND old_commitment=? AND disposition=? '
                    'AND new_commitment IS NULL ORDER BY scope_digest LIMIT 1',
                    ('core',_TABLE,self.key_digest,self.commitment,'payload_erased_retained_facts'),meter)
                if(row is None or row[4]!=self.key_json):
                    raise AuthorityUnavailable('C09 selected history has no exact erased finished producer tuple disposition')
                self.disposition=tuple(row)
            scope_digest=self.disposition[0]
            if scope_digest==view.scope.scope_digest:
                self.lineage=(view.scope.maintenance_generation,view.scope.operation_id,basis.prepared['prepared_digest'])
                self.summary=basis.prepared;self.phase='scope'
            else:
                with basis.read_database('graph',meter=meter)as graph:
                    self.lineage=_read_one(graph,'SELECT generation,operation_id,prepared_digest FROM c09_recovery_history_scopes_v2 '
                        'WHERE scope_digest=? AND historical_scope_digest=?',(view.scope.scope_digest,scope_digest),meter)
                    if self.lineage is None or not 1<=self.lineage[0]<view.scope.maintenance_generation:
                        raise AuthorityUnavailable('C09 old finished producer is outside the actual selected accepted history')
                    frame=_read_one(graph,'SELECT prepared_digest,facts_digest,bindings_digest,pin_digest,manifest_digest '
                        'FROM c09_recovery_history_frames_v2 WHERE scope_digest=? AND generation=?',
                        (view.scope.scope_digest,self.lineage[0]),meter)
                    if frame is None or frame[0]!=self.lineage[2]:
                        raise AuthorityUnavailable('C09 old producer has no complete selected historical facts frame')
                    self.historical_frame=frame
                self.phase='prepared'
            return
        if self.phase=='prepared':
            if self.scan is None:
                self.scan=begin_next_authenticated_prepared_reader_v2(self.control,
                    after_generation=self.lineage[0]-1,through_generation=basis.manifest['generation'],meter=meter)
                if self.scan is None:raise AuthorityUnavailable('C09 accepted producer historical signed PREPARED is absent')
                return
            summary=self.scan.advance(meter=meter)
            if summary is None:return
            if(summary['maintenance_generation'],summary['operation_id'],summary['prepared_digest'])!=self.lineage:
                raise AuthorityUnavailable('C09 old producer substituted another actual signed PREPARED generation')
            self.summary=summary;self.phase='scope';return
        if self.phase=='scope':
            summary=self.summary
            if(summary['authority_id'],summary['installation_id'],summary['namespace'])!=(
                    self.permit.authority_id,self.control.installation_id,self.permit.namespace):
                raise AuthorityUnavailable('C09 old producer signed namespace or installation differs')
            with self.control._db()as db:
                raw=_read_original(self.control,db,self.lineage[1],'capture_scope_v2',None,meter)
                facts_raw=_read_original(self.control,db,self.lineage[1],'capture_facts_complete_v2',summary['facts_complete_original_digest'],meter)
                header=_read_original(self.control,db,self.lineage[1],'capture_role_complete_v2_core',
                    summary['four_role_complete_original_digests']['core'],meter)
            scope=c09_paged_value_from_wire_v2(raw,C09CaptureScopeV2)
            if(scope.scope_digest!=self.disposition[0]or scope.scope_digest!=summary['capture_scope_digest']
                    or(scope.authority_id,scope.installation_id,scope.authority_namespace,scope.graph_namespace)!=(
                        self.permit.authority_id,self.control.installation_id,self.permit.namespace,canonical_serialize(self.work.namespace.as_tuple))
                    or scope.maintenance_generation!=self.lineage[0]or scope.operation_id!=self.lineage[1]
                    or scope.accepted_receipt_digest!=summary['accepted_receipt_digest']
                    or header['scope_digest']!=scope.scope_digest or header['role']!='core'):
                raise AuthorityUnavailable('C09 producer proof is not its own accepted signed historical Core certificate')
            from .c09_paged_recovery_facts_v2 import _decode_completion
            facts=_decode_completion(facts_raw)
            if facts.scope_digest!=scope.scope_digest or facts.pin_digest!=summary['facts_pin_digest']:
                raise AuthorityUnavailable('C09 old finished producer facts completion differs from its accepted PREPARED')
            if self.historical_frame is not None and self.historical_frame!=(summary['prepared_digest'],facts.pin_digest,
                    facts.binding_stream.complete.digest,facts.pin_digest,summary['new_manifest_digest']):
                raise AuthorityUnavailable('C09 old producer PREPARED differs from its selected complete historical facts frame')
            self.scope=scope;self.core_header=header
            self.directory=C09HistoricalSealedStreamReaderV2(c09_paged_value_from_wire_v2(header['stream_directory'],C09SealedStreamLocatorV2))
            self.phase='directory';return
        if self.phase=='directory':
            with basis.read_database('core',meter=meter)as db:
                def observe(record):
                    key=(self.scope.scope_digest,'core',_TABLE,'row_dispositions')
                    if record.primary_key!=key:return
                    if self.directory_found:raise AuthorityUnavailable('C09 old producer Core disposition stream appears twice')
                    row=meter.read_fixed_row(db,'authority_c09_role_streams_v2',_DIRECTORY,
                        'scope_digest=? AND role=? AND table_name=? AND stream_kind=?',key)
                    expected=canonical_digest(('sylanne3.c09.authority-directory-row.v2',self.directory.locator.identity.stream_kind,
                        'authority_c09_role_streams_v2',key,tuple(row)))if row is not None else None
                    if expected!=record.commitment:raise AuthorityUnavailable('C09 producer stream is outside its actual signed historical Core directory')
                    locator=_locator(row)
                    if locator.identity.primary_key_columns!=('operation_id',):
                        raise AuthorityUnavailable('C09 historical Core fence stream changed its exact original key')
                    self.directory_row=tuple(row);self.stream=C09HistoricalSealedStreamReaderV2(locator);self.directory_found=True
                if self.directory.advance(db,meter,observe):
                    if not self.directory_found:raise AuthorityUnavailable('C09 complete historical Core directory omitted the producer fence table')
                    self.phase='stream'
            return
        if self.phase=='stream':
            with basis.read_database('core',meter=meter)as db:
                def observe(record):
                    if record.primary_key!=self.key:return
                    if self.member_found:raise AuthorityUnavailable('C09 producer finished tuple appears twice in its actual source stream')
                    actual=meter.read_fixed_row(db,'authority_c09_role_rows_v2',_DISPOSITION,
                        'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
                        (self.scope.scope_digest,'core',_TABLE,self.key_digest))
                    if(actual!=self.disposition or record.commitment!=canonical_digest(('sylanne3.c09.authority-row-disposition.v2',self.disposition))):
                        raise AuthorityUnavailable('C09 signed old-to-new row member is not the exact finished producer tuple')
                    self.member_found=True
                if self.stream.advance(db,meter,observe):
                    if not self.member_found:raise AuthorityUnavailable('C09 complete signed producer stream omitted the actual finished original')
                    self.phase='consumed'
            return
        if self.phase=='consumed':
            with basis.read_database('core',meter=meter)as db:
                consumed=_read_one(db,'SELECT operation_id,original_commitment,facts_pin_digest FROM authority_c09_consumed_execution_v1 '
                    'WHERE namespace=? AND kind=? AND item_id=?',(self.permit.namespace,'fence',self.permit.operation_id),meter)
                origin=_read_one(db,'SELECT origin_kind,origin_table,origin_key_json FROM authority_c09_consumed_origins_v2 '
                    'WHERE scope_digest=? AND kind=? AND item_id=?',(self.scope.scope_digest,'fence',self.permit.operation_id),meter)
                live=_read_one(db,'SELECT 1 FROM authority_v2_fences WHERE operation_id=?',(self.permit.operation_id,),meter)
                if(consumed!=(self.permit.operation_id,self.commitment,self.summary['facts_pin_digest'])
                        or origin!=('source_row',_TABLE,self.key_json)or live is not None):
                    raise AuthorityUnavailable('C09 retired producer lost its exact once-only identity/facts pin or was resurrected')
            self.phase='complete';self.complete=True;return
        if self.phase!='complete':raise AuthorityUnavailable('unknown accepted conditioned producer read phase')

    def require_complete(self):
        from .daemon import _bootstrap_control_quantum_v3
        self._require_work()
        if not self.complete or self.phase!='complete'or not self.member_found or not self.directory_found:
            raise AuthorityUnavailable('C09 conditioned producer certificate has not reached its actual complete EOF')
        with _bootstrap_control_quantum_v3(self.control)as meter:self._require_selection(meter)
        return self.expected


def require_accepted_conditioned_producer_fence_v1(work,*,operation_id,header,permit,bundle):
    _require_exact_finished_work_v3(work)
    reads=_READS.setdefault(work,{})
    reader=reads.get(operation_id)
    if reader is None:
        reader=_AcceptedConditionedProducerFenceReadV1(work,operation_id,header,permit,bundle);reads[operation_id]=reader
    elif(reader.header,reader.permit,reader.bundle)!=(header,permit,bundle):
        raise AuthorityUnavailable('C09 producer reader changed its actual original Graph fence during one Work')
    try:
        while not reader.complete:reader.advance()
        return reader.require_complete()
    except BaseException:
        reader.failed=True
        raise


def release_accepted_conditioned_producer_reads_v1(work):
    _READS.pop(work,None)
