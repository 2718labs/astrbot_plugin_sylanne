"""Private bounded UUID history evidence for the actual Owner rebuild cold Work.

A negative result proves no W01 commit. It never bypasses the original attempt,
pending, consumed-operation or fresh Owner admission checks.
"""
from weakref import WeakKeyDictionary
from uuid import UUID
import json
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize

_TASKS=WeakKeyDictionary()
_PROOFS=WeakKeyDictionary()
_KEY=object()
_BINDING_KIND="character_labor_rebuild_selection_binding_v1"
_FAMILIES=("graph_d11_life_originals_v1","graph_domain_production_originals_v1",
    "graph_bundle_operations","graph_owner_domain_attempts_v3")
_EVENTS="graph_events"


def _actual(owner,operation_id,*,meter=None):
    from .character_labor_rebuild_selector_v1 import require_actual_character_labor_rebuild_cold_owner_v1
    owner=require_actual_character_labor_rebuild_cold_owner_v1(owner,meter=meter)
    value=UUID(operation_id)
    if str(value)!=operation_id or value.version!=4 or operation_id!=owner.mutation_operation_id:
        raise AuthorityUnavailable("UUID history requires the same actual D12 mutation UUID")
    return owner


def _identity(owner):
    return (owner,owner.operation,owner.work,owner.namespace,owner.selection_digest,
        owner.graph_stamp,owner.mutation_operation_id)


class VerifiedCharacterLaborRebuildUuidHistoryV1:
    def __init__(self,key,task,outcome):
        if key is not _KEY or outcome not in {"never_committed","uuid_retired"}:
            raise TypeError("actual completed UUID history producer required")
        self.outcome=outcome
        self.history_digest=task.history_digest
        _PROOFS[self]=(task,_TASKS[task],outcome,self.history_digest)

    def require_current_v1(self,owner,*,mutation_operation_id,meter=None):
        _actual(owner,mutation_operation_id,meter=meter)
        saved=_PROOFS.get(self)
        if saved is None:
            raise AuthorityUnavailable("actual private UUID history evidence required")
        task,identity,outcome,digest=saved
        if (_TASKS.get(task)!=identity or identity!=_identity(owner)or not task.complete
                or task.proof is not self or self.outcome!=outcome or self.history_digest!=digest):
            raise AuthorityUnavailable("UUID history evidence left its original current Work/selection")
        return self


class _CharacterLaborRebuildUuidHistoryTaskV1:
    def __init__(self,key,owner,operation_id):
        if key is not _KEY:raise TypeError("actual named UUID history factory required")
        _actual(owner,operation_id)
        self.owner=owner;self.operation_id=operation_id;self.namespace=owner.namespace
        self.targets={table:(*self.namespace.as_tuple,operation_id)for table in _FAMILIES}
        self.targets[_FAMILIES[0]]=(*self.namespace.as_tuple,_BINDING_KIND,
            "character-labor-rebuild-selection:"+operation_id)
        self.request=None;self.column=None;self.response=None;self.started=False
        self.complete=False;self.proof=None;self.history_digest=None;self.chain=[]
        self.generator=self._run()
        _TASKS[self]=_identity(owner)

    def retained_payload_v1(self):
        def frames(generator):
            if generator is None or generator.gi_frame is None:return ()
            return (tuple(value for name,value in generator.gi_frame.f_locals.items()if name not in {"self","r","p","origin","binding","actual"}),
                frames(generator.gi_yieldfrom)if generator.gi_yieldfrom is not None else ())
        c=self.column
        return (self.targets,self.request,self.response,self.chain,
            ()if c is None else(c.body,c.fragment,c.value,c.parser),frames(self.generator))

    def release_v1(self):
        if self.generator is not None:self.generator.close()
        if self.proof is not None:_PROOFS.pop(self.proof,None)
        _TASKS.pop(self,None)
        self.generator=self.request=self.response=self.column=self.proof=None
        self.targets.clear();self.chain.clear()

    def _require(self,meter=None):
        _actual(self.owner,self.operation_id,meter=meter)
        if _TASKS.get(self)!=_identity(self.owner):
            raise AuthorityUnavailable("UUID history task lost its actual cold Work identity")

    def _row(self,meter,table,columns,where,args):
        from .c09_paged_sql_v2 import _quote
        r=self.owner
        sizes=r.db.execute("SELECT "+",".join("length(CAST("+_quote(c)+" AS BLOB))"for c in columns)
            +" FROM "+_quote(table)+" WHERE "+where+" LIMIT 1",args).fetchone()
        meter.charge_read(len(columns)*8)
        if sizes is None:return None
        r.operation.reserve_retained_state_growth_v3(r,sum(n or 0 for n in sizes)*12+32768)
        try:return meter.read_fixed_row(r.db,table,columns,where,args)
        finally:r.operation.finish_retained_state_growth_v3(r)

    def advance_v1(self,meter):
        self._require(meter)
        if self.complete:return True
        if self.column is not None:
            if not self.column.advance(meter):return False
            self.response=(self.column.value,self.column.digest)
            self.column=None;self.request=None
            return False
        if self.request is None:
            try:
                self.request=next(self.generator)if not self.started else self.generator.send(self.response)
                self.started=True;self.response=None
            except StopIteration as done:
                outcome,root=done.value
                self.history_digest=root;self.complete=True
                self.proof=VerifiedCharacterLaborRebuildUuidHistoryV1(_KEY,self,outcome)
                return True
        request=self.request
        if request[0]=="row":
            self.response=self._row(meter,*request[1:]);self.request=None
        elif request[0]=="column":
            from .current_character_labor_adoption_v1 import _LocatorMetadataColumnV1
            _,table,column,keys,key=request
            self.column=_LocatorMetadataColumnV1(self.owner,table,column,keys,key)
        elif request[0]=="disposition":
            from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
            from .c09_graph_rebase_candidate_v2 import GRAPH_DISPOSITION_COLUMNS_V2,GRAPH_DISPOSITION_COLUMNS_V3
            from .c09_paged_sql_v2 import _quote
            _,scope,table,key=request
            required=0
            for physical,columns in (("c09_graph_dispositions_v2",GRAPH_DISPOSITION_COLUMNS_V2),
                    ("c09_graph_dispositions_v3",GRAPH_DISPOSITION_COLUMNS_V3)):
                exists=self._row(meter,"sqlite_schema",("name",),"type=? AND name=?",("table",physical))
                if exists is None:continue
                sizes=self.owner.db.execute("SELECT "+",".join("length(CAST("+_quote(c)+" AS BLOB))"for c in columns)
                    +" FROM "+_quote(physical)+" WHERE scope_digest=? AND table_name=? AND key_digest=?",
                    (scope,table,canonical_digest((table,key)))).fetchone()
                meter.charge_read(len(columns)*8)
                if sizes is not None:required+=sum(n or 0 for n in sizes)*12+32768
            self.owner.operation.reserve_retained_state_growth_v3(self.owner,required)
            try:self.response=_read_graph_disposition_original_row_v3(self.owner.db,*request[1:],meter)
            finally:self.owner.operation.finish_retained_state_growth_v3(self.owner)
            self.request=None
        elif request[0]=="origin":
            from ..runtime_storage_v3 import runtime_source_identity_v4
            self.response=runtime_source_identity_v4(self.owner.operation.handle,meter=meter)
            self.request=None
        else:raise AuthorityUnavailable("UUID history emitted an unregistered metadata request")
        return False

    def _absent(self):
        r=self.owner
        # Native and registered physical Domain rows share the same business PK.
        for table,key in (*self.targets.items(),("graph_domain_production_originals_v3",
                (*self.namespace.as_tuple,self.operation_id))):
            exists=yield("row","sqlite_schema",("name",),"type=? AND name=?",("table",table))
            if exists is None:continue
            where="bot=? AND persona=? AND "+(
                "kind=? AND original_ref=?"if table==_FAMILIES[0]else"operation_id=?")
            row=yield("row",table,("bot",),where,key)
            if row is not None:
                raise AuthorityUnavailable("UUID history requires all current command originals/attempts to be absent")

        for table,columns,where,args in (
                ("graph_bundle_fences_v2",("digest",),"bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,self.operation_id)),
                ("graph_bundle_intents_v2",("fence_attempt_id",),"bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,self.operation_id)),
                ("graph_events",("session",),"bot=? AND persona=? AND event_id=? ORDER BY session",(*self.namespace.as_tuple,self.operation_id))):
            exists=yield("row","sqlite_schema",("name",),"type=? AND name=?",("table",table))
            if exists is not None:
                row=yield("row",table,columns,where,args)
                if row is not None:raise AuthorityUnavailable("UUID history found a partial current W01 event/intent/fence")

    def _certificate(self,digest):
        from .c09_paged_capture_contract_v2 import GraphErasureRebaseCertificateV2,c09_paged_value_from_wire_v2
        after="";found=None
        while True:
            row=yield("row","graph_c09_rebase_certificates_v2",("operation_id",),
                "bot=? AND persona=? AND operation_id>? ORDER BY operation_id",(*self.namespace.as_tuple,after))
            if row is None:break
            after=row[0]
            raw,_=yield("column","graph_c09_rebase_certificates_v2","certificate_json",
                ("bot","persona","operation_id"),(*self.namespace.as_tuple,after))
            value=c09_paged_value_from_wire_v2(raw,GraphErasureRebaseCertificateV2)
            if value.candidate.scope.operation_id!=after:
                raise AuthorityUnavailable("UUID history certificate mirror operation differs")
            if value.certificate_digest==digest:
                if found is not None:raise AuthorityUnavailable("UUID history certificate digest is ambiguous")
                found=value
        if found is None:
            raise AuthorityUnavailable("UUID history lacks its actual selected certificate mirror")
        return found

    def _stream(self,locator,targets=(),*,preserved_events=False):
        from .c09_paged_capture_contract_v2 import (
            C09CompleteStreamV2,C09CapturePageV2,C09CaptureRecordV2,
            c09_paged_value_from_wire_v2,begin_c09_stream_v2,verify_c09_page_v2)
        identity,seal=locator.identity,locator.complete
        saved=yield("row","c09_capture_streams_v2",("status","seal_json"),"stream_id=?",(identity.stream_id,))
        if saved is None or saved[0]!="sealed"or c09_paged_value_from_wire_v2(json.loads(saved[1]),C09CompleteStreamV2)!=seal:
            raise AuthorityUnavailable("UUID history stream lacks its actual complete signed seal")
        cursor=begin_c09_stream_v2(identity);matches={}
        while cursor.page_index<seal.page_count:
            key=(identity.stream_id,cursor.page_index)
            raw,_=yield("column","c09_capture_pages_v2","descriptor_json",("stream_id","page_index"),key)
            page=c09_paged_value_from_wire_v2(raw,C09CapturePageV2)
            raw,_=yield("column","c09_capture_pages_v2","records_json",("stream_id","page_index"),key)
            if type(raw)is not list or len(raw)>100:
                raise AuthorityUnavailable("UUID history page exceeds its official record bound")
            records=tuple(c09_paged_value_from_wire_v2(v,C09CaptureRecordV2)for v in raw)
            cursor=verify_c09_page_v2(identity,cursor,page,records)
            # Negative evidence is computed directly from the authenticated page,
            # never from a potentially incomplete SQL member index.
            for record in records:
                if preserved_events:
                    from .c09_paged_sql_v2 import c09_row_commitment_v2
                    key=record.primary_key
                    if len(key)!=4:
                        raise AuthorityUnavailable("UUID history event stream has another primary key")
                    if key[:2]==self.namespace.as_tuple and key[3]==self.operation_id:
                        raise AuthorityUnavailable("UUID already has an authenticated historical GraphEvent without its complete current receipt")
                    proof=yield("disposition",identity.scope_digest,_EVENTS,key)
                    if (proof is None or len(proof)!=9 or c09_row_commitment_v2(proof)!=record.commitment
                            or proof[:4]!=(identity.scope_digest,_EVENTS,canonical_digest((_EVENTS,key)),canonical_serialize(key))
                            or proof[5]!="preserved_exact"or proof[4]!=proof[6]):
                        raise AuthorityUnavailable("UUID history event identity has no exact preserved original")
                if record.primary_key in targets:
                    if record.primary_key in matches:
                        raise AuthorityUnavailable("UUID history repeats an exact target PK")
                    matches[record.primary_key]=record.commitment
        if (cursor.record_offset,cursor.encoded_bytes,cursor.page_index,cursor.record_chain,cursor.previous_page_digest)!=(
                seal.record_count,seal.encoded_bytes,seal.page_count,seal.record_root,seal.page_root):
            raise AuthorityUnavailable("UUID history did not reach the complete stream EOF/root")
        extra=yield("row","c09_capture_pages_v2",("page_index",),"stream_id=? AND page_index>=?",
            (identity.stream_id,seal.page_count))
        if extra is not None:raise AuthorityUnavailable("UUID history has extra unsealed pages")
        self.chain.append((identity.stream_id,seal.digest))
        return matches

    def _families(self,certificate):
        from .c09_paged_capture_contract_v2 import (
            C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
        from .c09_paged_sql_v2 import c09_row_commitment_v2
        scope=certificate.candidate.scope;outer=certificate.candidate.disposition_directory
        if outer.identity.family!="c09_graph_disposition_directory_v2":
            raise AuthorityUnavailable("UUID history requires the actual closed disposition directory")
        names=(*_FAMILIES,"graph_domain_production_originals_v3",_EVENTS)
        targets=tuple((scope.scope_digest,table)for table in names)
        directory=yield from self._stream(outer,targets)
        # The Domain physical profile is an explicit alternative. All four
        # logical identity families must otherwise be represented in the seal.
        required=(set(_FAMILIES)-{"graph_domain_production_originals_v1"})|{_EVENTS}
        result={};events_complete=False
        for table in names:
            directory_key=(scope.scope_digest,table)
            if directory_key not in directory:continue
            row=yield("row",outer.identity.family,("scope_digest","family","identity_json","complete_json"),
                "scope_digest=? AND family=?",directory_key)
            if row is None or c09_row_commitment_v2(row)!=directory[directory_key]:
                raise AuthorityUnavailable("UUID history family row is not its authenticated directory member")
            identity=c09_paged_value_from_wire_v2(json.loads(row[2]),C09StreamIdentityV2)
            complete=c09_paged_value_from_wire_v2(json.loads(row[3]),C09CompleteStreamV2)
            key=self.targets.get(table,(*self.namespace.as_tuple,self.operation_id))
            columns=("bot","persona","session","event_id")if table==_EVENTS else (
                ("bot","persona","kind","original_ref")if table==_FAMILIES[0]else("bot","persona","operation_id"))
            if (identity.scope_digest!=scope.scope_digest or identity.family!=table
                    or identity.stream_kind!="row_dispositions"
                    or identity.primary_key_columns!=columns
                    or identity.role_source_digest!=certificate.candidate.source.role_source_digest):
                raise AuthorityUnavailable("UUID history family escaped its authenticated source/PK")
            locator=C09SealedStreamLocatorV2("graph",identity,complete)
            if table==_EVENTS:
                yield from self._stream(locator,preserved_events=True)
                events_complete=True;continue
            found=yield from self._stream(locator,(key,))
            if key not in found:continue
            proof=yield("disposition",scope.scope_digest,table,key)
            if (proof is None or c09_row_commitment_v2(proof)!=found[key]
                    or proof[:4]!=(scope.scope_digest,table,canonical_digest((table,key)),canonical_serialize(key))):
                raise AuthorityUnavailable("UUID history disposition is not the actual page record")
            if proof[5]in {"derived_removed","payload_erased_retained_facts"}and proof[6]is None:
                result[table]="retired"
                return result,events_complete
            else:
                # A preserved/rebuilt identity cannot legitimately have vanished
                # from every current command location.
                raise AuthorityUnavailable("UUID history command is preserved, rebuilt or unknown while current rows are absent")
        if any((scope.scope_digest,table)not in directory for table in required)or not any(
                (scope.scope_digest,table)in directory for table in (
                    "graph_domain_production_originals_v1","graph_domain_production_originals_v3")):
            raise AuthorityUnavailable("UUID history is missing a required complete command family")
        return result,events_complete

    def _event_census(self):
        ns=self.namespace.as_tuple
        shape=yield("row","sqlite_schema",("name",),"type=? AND name=?",("table",_EVENTS))
        if shape is None:raise AuthorityUnavailable("UUID history requires its actual permanent GraphEvent family")
        after=None;count=0;root=canonical_digest(("sylanne3.c09.rebuild-uuid-events.v1",ns))
        while True:
            row=yield("row",_EVENTS,("session","event_id","digest"),
                "bot=? AND persona=?"+(""if after is None else
                " AND (session COLLATE BINARY>? OR (session=? AND event_id COLLATE BINARY>?))")+
                " ORDER BY session COLLATE BINARY,event_id COLLATE BINARY",
                ns if after is None else(*ns,after[0],after[0],after[1]))
            if row is None:break
            if row[1]==self.operation_id:
                raise AuthorityUnavailable("UUID already has its actual GraphEvent without a complete current receipt")
            root=canonical_digest((root,row));after=row[:2];count+=1
        return root,count

    def _bookend(self,source_commit):
        yield from self._absent()
        actual=yield("origin",)
        current=canonical_digest((actual.namespace,actual.selection_digest,actual.member,
            actual.instance,actual.origin_kind,actual.genesis_digest,actual.capture_scope_digest,actual.storage_generation))
        if current!=source_commit:
            raise AuthorityUnavailable("UUID history actual source identity changed before its complete EOF")

    def _run(self):
        yield from self._absent()
        origin=yield("origin",)
        r=self.owner;p=r.bundle.installation_policy
        if (origin.namespace!=r.namespace or origin.role!="graph"or origin.selection_digest!=r.selection_digest
                or origin.authority_id!=p.expected_authority_id or origin.authority_namespace!=p.authority_namespace
                or origin.installation_id!=p.installation_id or origin.host_binding is None):
            raise AuthorityUnavailable("UUID history needs its actual installed Host Graph origin")
        source_commit=canonical_digest((origin.namespace,origin.selection_digest,origin.member,
            origin.instance,origin.origin_kind,origin.genesis_digest,origin.capture_scope_digest,origin.storage_generation))
        if origin.origin_kind=="initial_segmented_v4":
            if origin.genesis_digest is None or origin.capture_scope_digest is not None or origin.storage_generation!=0:
                raise AuthorityUnavailable("UUID history lacks its actual initial genesis/incarnation")
            root,count=yield from self._event_census()
            yield from self._bookend(source_commit)
            return "never_committed",canonical_digest((source_commit,root,count,self.operation_id))
        if origin.origin_kind!="selected_v3"or origin.capture_scope_digest is None:
            raise AuthorityUnavailable("UUID history needs a registered initial or selected origin")
        binding=origin.host_binding
        digest=binding.certificate_digest
        certificate=yield from self._certificate(digest)
        scope=certificate.candidate.scope
        if ((scope.scope_digest,scope.authority_id,scope.authority_namespace,scope.installation_id,scope.graph_namespace)!=(
                origin.capture_scope_digest,origin.authority_id,origin.authority_namespace,origin.installation_id,
                canonical_serialize(self.namespace.as_tuple))
                or certificate.candidate.new_incarnation!=origin.member["incarnation_or_journal_id"]):
            raise AuthorityUnavailable("UUID history current certificate differs from actual Host selection")
        seen=set()
        while True:
            if certificate.certificate_digest in seen:
                raise AuthorityUnavailable("UUID history certificate chain is cyclic")
            seen.add(certificate.certificate_digest)
            matches,events_complete=yield from self._families(certificate)
            if matches:
                yield from self._bookend(source_commit)
                return "uuid_retired",canonical_digest((source_commit,self.chain,certificate.certificate_digest,self.operation_id,"retired"))
            if not events_complete:
                raise AuthorityUnavailable("UUID history lacks its complete preserved GraphEvent family")
            self.chain.append((certificate.certificate_digest,certificate.candidate.source.role_source_digest))
            prior=certificate.prior_certificate_digest_or_none
            if prior is None:break
            if certificate.prior_certificate_schema_or_none!="sylanne3.graph.c09_erasure_rebase.v2":
                raise AuthorityUnavailable("UUID history predecessor is not the registered complete certificate type")
            previous=yield from self._certificate(prior)
            oldscope=previous.candidate.scope
            if ((oldscope.authority_id,oldscope.authority_namespace,oldscope.installation_id,oldscope.graph_namespace)!=(
                    scope.authority_id,scope.authority_namespace,scope.installation_id,scope.graph_namespace)
                    or previous.candidate.new_incarnation!=certificate.candidate.old_incarnation
                    or oldscope.maintenance_generation>=certificate.candidate.scope.maintenance_generation):
                raise AuthorityUnavailable("UUID history continuous authority/installation/incarnation chain is broken")
            certificate=previous
        root,count=yield from self._event_census()
        yield from self._bookend(source_commit)
        return "never_committed",canonical_digest((source_commit,self.chain,root,count,self.operation_id))


def create_character_labor_rebuild_uuid_history_task_v1(owner,*,mutation_operation_id):
    return _CharacterLaborRebuildUuidHistoryTaskV1(_KEY,owner,mutation_operation_id)


def require_character_labor_rebuild_uuid_history_v1(task,owner,*,mutation_operation_id,meter=None):
    if type(task)is not _CharacterLaborRebuildUuidHistoryTaskV1 or task not in _TASKS or not task.complete:
        raise AuthorityUnavailable("complete actual UUID history task required")
    return task.proof.require_current_v1(owner,mutation_operation_id=mutation_operation_id,meter=meter)
