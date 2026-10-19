"""Exact original FG/OwnerTask Source READ under the unchanged WRITE fence.

Profiles are privately bound to the real original selector, installed service,
retained Authority Work and current Owner. Mechanical Source parsing grants no
Mesh qualification, public operation or additional Root route.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,GraphAtom,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
from ..runtime.source_correction_read_v3 import _heap

_WORKS=WeakKeyDictionary()
_SOURCE_PROOFS=WeakKeyDictionary()

def original_source_clock_upper_v3(work):
    reading=work.controller.clock()
    return reading.utc_seconds+reading.utc_error_seconds

def original_foreground_work_v3(work):
    return _WORKS.get(work)

def _request_profile_v3(service,request):
    from .current_foreground_activity_v1 import(InstalledCurrentForegroundActivityV1,ForegroundActivityRequestV1,
        ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2,foreground_fence_operation_id_v1,foreground_fence_operation_id_v2)
    from .current_owner_source_note_task_v1 import(InstalledCurrentOwnerSourceNoteTaskV1,OwnerTaskActivityRequestV1,
        OwnerTaskActivityValuesChildRequestV1,owner_task_fence_operation_id_v1)
    if type(service)is InstalledCurrentForegroundActivityV1 and type(request)in{ForegroundActivityRequestV1,ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2}:
        return 'original-foreground-source.v1',(foreground_fence_operation_id_v1(request)if type(request)is ForegroundActivityRequestV1 else foreground_fence_operation_id_v2(request))
    if type(service)is InstalledCurrentOwnerSourceNoteTaskV1 and type(request)in{OwnerTaskActivityRequestV1,OwnerTaskActivityValuesChildRequestV1}:
        return 'original-owner-task-source.v1',owner_task_fence_operation_id_v1(request)
    raise AuthorityUnavailable('Original Source profile requires one exact installed original request')

def _binding_v3(work):
    return(work.service,work.controller,work.request,type(work.request),canonical_digest(work.request),work.credential,
        work.subject,work.permit,work.scope,work.operation,work.selection_digest,work.db,work.handle,
        work.controller.location,work.controller.control,work.namespace,work.original_profile,work.original_deadline)

def require_original_foreground_work_v3(work):
    from .current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
    require_actual_authority_graph_attachment_owner_v3(work)
    saved=_WORKS.get(work)
    if saved is None or saved!=_binding_v3(work):raise AuthorityUnavailable('Original Source lost its actual selector/Work/retained SQL identity')
    profile,fence_id=_request_profile_v3(work.service,work.request)
    if profile!=work.original_profile or work.permit.operation!='write'or work.permit.operation_id!=fence_id or work.deadline_utc>work.original_deadline:
        raise AuthorityUnavailable('Original Source changed the actual original WRITE fence or absolute deadline')
    return saved

def original_owner_header_kind_v3(work):
    require_original_foreground_work_v3(work)
    return 'authority_original_foreground_header'if work.original_profile=='original-foreground-source.v1'else'authority_original_owner_task_header'

def _reserve(work,value,extra=0):
    metadata=work.original_metadata
    amount=_heap((metadata.rows,metadata.heads,metadata.families,metadata.roots,metadata.pending,metadata.originals,
        metadata.history_heads,metadata.c02_history_heads,metadata.historical_pending,getattr(metadata,'catalogue_history_pending',()),metadata.required_originals,metadata.required_matches,value))+extra+65536
    if amount>work.original_reserved:
        work.operation.retain(amount-work.original_reserved);work.original_reserved=amount

class _OriginalMetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,work,*,table,column,key_columns,key,fields=None,cell_id=None):
        require_original_foreground_work_v3(work)
        self.fields=fields
        super().__init__(work,table=table,column=column,key_columns=key_columns,key=key,cell_id=cell_id)
        if self.cell is not None:self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1')
    def _emit(self,event):
        if self.fields is None or not event.path or event.path[0]in self.fields:super()._emit(event)

@dataclass(frozen=True,slots=True)
class _OriginalSourceLeafV3:
    key:AtomKey
    revision:int
    valid:bool
    metadata:object
    cell_id:str
    sha256:str
    header:tuple

class _OriginalSourceColumnV3:
    def __init__(self, work, key):
        self.work, self.key = work, key
        self.phase = "head"
        self.cell = self.parser = None
        self.fragment = b""
        self.offset = 0
        self.complete = False
    def advance(self, meter):
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        work = self.work
        work.require_current(meter=meter)
        if self.phase == "head":
            row = meter.read_fixed_row(work.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*work.namespace.as_tuple, self.key.token))
            if row is None or row[0] < 1 or row[1] != 1 or row[2] is None:
                raise AuthorityUnavailable("Original foreground/Owner task Source current metadata is absent")
            self.head = row
            self.cell = begin_runtime_cell_read_v3(work.db, row[2], erasure_owner_ref=self.key.token)
            if self.cell.header[0] not in ("canonical-json.ascii.v1", "canonical-json.utf8.v1"):
                raise AuthorityUnavailable("Original foreground/Owner task Source has an unregistered physical codec")
            self.parser = C09MemorySourceJSONStreamV3(ensure_ascii=self.cell.header[0] == "canonical-json.ascii.v1")
            self.phase = "body"
            return False
        if self.offset < len(self.fragment):
            end = min(self.offset+1024, len(self.fragment))
            _reserve(work, (work.original_metadata, self.parser._source_metadata), 65536)
            self.parser.feed(self.fragment[self.offset:end], lambda event: None)
            self.offset = end
            return False
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment, self.offset = fragment, 0
            return False
        parsed = self.parser.finish()
        digest = self.cell.finish(meter=meter)
        if (parsed.sha256, parsed.byte_count) != (digest, self.cell.header[3]):
            raise AuthorityUnavailable("Original foreground/Owner task Source metadata did not reach actual canonical EOF")
        metadata = MappingProxyType({name: tuple(value) if type(value) is list else value
            for name, value in self.parser._source_metadata.items()})
        if metadata["source_id"] != self.key.owner.subject:
            raise AuthorityUnavailable("Original foreground/Owner task Source metadata key differs")
        self.leaf = _OriginalSourceLeafV3(self.key, self.head[0], True, metadata, self.head[2], digest, tuple(self.cell.header))
        self.complete = True
        self.fragment = b""
        self.parser = self.cell = None
        return True


class _OriginalBudgetMetadataV3:
    def __init__(self,work):
        self.work = work
        self.current = work.original_parent_budget
        self.seen = set()
        self.leases = {}
        self.grants = {}
        self.column = None
        self.values = {}
        self.columns = []
        self.complete = False

    def advance(self,meter):
        from ..runtime.budget import BudgetLease
        from ..runtime.issuers import _decode_grant
        work = self.work
        work.require_current(meter=meter)
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            value = self.column.require_v3(work)
            if self.kind == "grant":
                encoded = canonical_serialize(value)
                work.service.issuer._signer.verify("budget-grant.v1",encoded,self.signature)
                grant = _decode_grant(encoded)
                if (grant.lease_id != self.current or (grant.bot_id,grant.persona_id) != work.namespace.as_tuple
                        or grant.version != self.grant_version):
                    raise AuthorityUnavailable("Original foreground/Owner task original signed budget metadata differs")
                deadline = min(work.deadline_utc,grant.valid_until_utc)
                if original_source_clock_upper_v3(work) >= deadline:
                    raise AuthorityUnavailable("Original foreground/Owner task original budget deadline expired before body qualification")
                work.deadline_utc = work.operation.deadline_utc = float(deadline)
                from .current_authority_graph_read_v3 import _DEADLINES
                _DEADLINES[work] = (work.operation,work.deadline_utc,None)
                self.grants[self.current] = grant
            else:
                self.values[self.kind] = value
            self.column = None
            return
        if self.columns:
            name = self.columns.pop()
            self.kind = name
            self.column = _OriginalMetadataColumnV3(work,table="runtime_budget_leases",column=name,
                key_columns=("lease_id",),key=(self.current,))
            return
        if self.values:
            row = self.lease_head
            lease = BudgetLease(self.current,row[0],row[1],row[2],row[3],
                self.values["limits_json"],self.values["used_json"],self.values["reserved_json"],
                self.values["unconfirmed_json"],row[4],row[5])
            self.leases[self.current] = lease
            self.values = {}
            if lease.parent_id is None:
                self.complete = True
            else:
                self.current = lease.parent_id
            return
        if self.current in self.seen:
            raise AuthorityUnavailable("Original foreground/Owner task original budget ancestry contains a cycle")
        self.seen.add(self.current)
        row = meter.read_fixed_row(work.db,"runtime_budget_leases",
            ("parent_id","bot_id","persona_id","currency","version","state"),"lease_id=?",(self.current,))
        debt = meter.read_fixed_row(work.db,"runtime_budget_debt_blocks",("lease_id",),
            "lease_id=?",(self.current,))
        if row is None or row[1:3] != work.namespace.as_tuple or row[5] != "active" or debt is not None:
            raise AuthorityUnavailable("Original foreground/Owner task original budget ancestry is unavailable or has unresolved debt")
        head = meter.read_fixed_row(work.db,"runtime_budget_grants",("version","signature","status"),
            "lease_id=? ORDER BY version DESC",(self.current,))
        if head is None or head[2] != "active":
            raise AuthorityUnavailable("Original foreground/Owner task original signed budget grant is unavailable")
        self.lease_head = row
        self.grant_version,self.signature = head[:2]
        self.columns = ["limits_json","used_json","reserved_json","unconfirmed_json"]
        self.kind = "grant"
        self.column = _OriginalMetadataColumnV3(work,table="runtime_budget_grants",column="grant_json",
            key_columns=("lease_id","version"),key=(self.current,head[0]))


class _OriginalRightsV3:
    def __init__(self, work):
        self.work = work
        self.pending = list(sorted(work.original_metadata.roots))
        self.purposes={ref:set(values)for ref,values in work.original_root_purposes.items()}
        self.sources, self.accesses, self.versions = {}, {}, {}
        self.column = None
        self.source = None
        self.phase = "source"
        self.complete = False
    def advance(self, meter):
        from ..memory_types import source_key, access_key, validate_access
        from ..domains.d06 import source_correction_head_key
        from ..runtime.dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
        work = self.work
        work.require_current(meter=meter)
        if self.source is not None:
            self.source.advance(meter)
            if not self.source.complete:
                return
            self.leaf = self.source.leaf
            self.source = None
            key = access_key(*work.namespace.as_tuple, self.leaf.key.owner.subject)
            head = meter.read_fixed_row(work.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*work.namespace.as_tuple, key.token))
            if head is None or head[1] != 1:
                raise AuthorityUnavailable("Original foreground/Owner task Source current Access metadata is absent")
            self.access_head = head
            self.column = _OriginalMetadataColumnV3(work, table="graph_atoms", column="value",
                key_columns=("token",), key=(key.token,), cell_id=head[2])
            return
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            access = self.column.require_v3(work)
            validate_access(access)
            leaf = self.leaf
            record = _SourceMetadataRecordV3(leaf.metadata)
            key = leaf.key
            correction = source_correction_head_key(work.namespace, key.owner.subject)
            head = meter.read_fixed_row(work.db, "graph_atoms", ("revision", "valid"),
                "bot=? AND persona=? AND token=?", (*work.namespace.as_tuple, correction.token))
            if (head is not None or access["source_id"] != record.source_id or access["status"] != "active"
                    or not self.purposes[key.token] <= set(record.purposes)
                    or not self.purposes[key.token] <= set(access["purposes"])
                    or not set(work.original_audiences) <= set(record.audiences)
                    or not set(work.original_audiences) <= set(access["audiences"])):
                raise AuthorityUnavailable("Original foreground/Owner task Source or ancestor current purpose/access/correction differs")
            self.sources[key.token] = leaf
            self.accesses[key.token] = access
            self.versions[key] = leaf.revision
            self.versions[access_key(*work.namespace.as_tuple, key.owner.subject)] = self.access_head[0]
            self.versions[correction] = 0
            for parent in record.parent_source_ids:
                ref=source_key(*work.namespace.as_tuple,parent).token
                before=self.purposes.setdefault(ref,set());prior=set(before);before.update(self.purposes[key.token])
                if ref in self.sources and before!=prior:self.sources.pop(ref);self.accesses.pop(ref)
                self.pending.append(ref)
            self.column = None
            _reserve(work, (work.original_metadata.rows, self.sources, self.accesses, self.versions, self.pending))
            return
        while self.pending:
            ref = self.pending.pop()
            if ref in self.sources:
                continue
            if len(self.sources) >= 256:
                raise AuthorityUnavailable("Original foreground/Owner task actual Source ancestry exceeds the existing bound")
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != work.namespace or key.type_name != "memory.source":
                raise AuthorityUnavailable("Original foreground/Owner task Source roots crossed the exact namespace")
            self.source = _OriginalSourceColumnV3(work, key)
            return
        active, done = set(), set()
        def visit(ref):
            if ref in active:
                raise AuthorityUnavailable("Original foreground/Owner task actual Source ancestry contains a cycle")
            if ref in done:
                return
            active.add(ref)
            for parent in self.sources[ref].metadata["parent_source_ids"]:
                visit(source_key(*work.namespace.as_tuple, parent).token)
            active.remove(ref)
            done.add(ref)
        for ref in self.sources:
            visit(ref)
        self.complete = True
        _SOURCE_PROOFS[work] = (work.operation, work.scope, work.selection_digest, work.graph_stamp, self)
        from .current_authority_graph_read_v3 import _track_authority_capability_v3
        _track_authority_capability_v3(work,_SOURCE_PROOFS,work)


# Metadata profiles retain fixed locators only. None is reserved for signed
# budget/Access control records; business Original metadata uses explicit paths.
_LOCATOR_FIELDS=frozenset({'schema','namespace','kind','original_ref','original_digest','digest','ref','key','revision',
    'source_refs','source_ref','input_source_ref','body_source_ref','creation_evidence_refs','reason_refs',
    'read_versions','query_coverage','type_id','future_decision_ref','prepared_candidates_operation_id',
    'objective_ref','objective_digest','goal_ref','project_ref','recipe_ref','target_entity_ref','role_binding_ref',
    'plan_ref','plan_revision','plan_digest','decision_ref','decision_revision','decision_digest','method_ref',
    'draft_root_registration_ref','root_registration_ref','c02_operation_id','operation_id','phase',
    'parent_budget_lease_ref','parent_grant_ref','audiences','purpose','original_deadline_utc','valid_until_utc',
    'authorization_original_ref','authorization_original_digest','cause','heads','owner_operation_id',
    'extent_original_ref','postcondition_policy_ref','approval_original_ref','contract_ref','preparation_parent_original_ref','prev_phase_original_ref',
    'quote_ref','quote_digest','quote_id','quote_version','job_id','call_id','effect_id','reservation_operation_id',
    'fact_versions','protocol_ref','gp1_interpretation_ref','deadline_ref','counterparty_ref','subject_ref','entity_id',
    'target_ref','source_head','plan_head','goal_head','body_policy_id','body_policy_version','effect_policy_ref',
    'c1_intent_ref','source_revision','source_digest','c02_bundle_digest','c02_receipt_digest','c02_commit_seq',
    'installation_id','manifest_digest'})
_CONTROL_TYPES=frozenset({'d11.owner_grant.v1','d01.persona_activation.v1','d01.persona_plan.v1','runtime.role_resources.v1'})
_FIXED_FAMILIES=frozenset({'d02.body_state.v1','d02.body_profile.v1','d02.reservation.v1',
    'd03.role_binding','d03.entity_anchor','d03.account_binding','d05.boundary_rule','d05.relationship_projection',
    'd07.current_interpretation.v1','d07.focus.v1','d07.attention_ticket.v1','d07.concern_round.v1',
    'd08.commitment.v1','d08.action_intent.v1','d08.action_schema.v1','d08.action_outcome.v1','d08.action_cancellation.v1',
    'd08.goal.v1','d08.personal_plan.v1','d08.decision_record.v2','d10.life_project.v1','d10.activity_recipe.v1',
    'd10.project_checkpoint.v1','d10.life_progress.v1','d01.method_scoped_trial.v1','d01.method_evaluation_protocol.v1',
    'd12.active_scheme_head.v1','d12.domain_scheme_selection.v1'})
_CONTEXT_TYPES=frozenset({'d03.role_binding','d03.entity_anchor','d03.account_binding','d05.boundary_rule',
    'd05.relationship_projection','d07.current_interpretation.v1','d07.focus.v1','d07.attention_ticket.v1','d07.concern_round.v1'})

class _OriginalLocatorColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,metadata,*,table,column,key_columns,key,cell_id=None):
        self.metadata=metadata
        super().__init__(metadata.work,table=table,column=column,key_columns=key_columns,key=key,cell_id=cell_id)
        from .named_joint_binding_source_read_v3 import _MetadataStreamV3
        self.stream=_MetadataStreamV3(self,self.cell is None or self.cell.header[0]=='canonical-json.ascii.v1');self.parser=self.stream
    def _emit(self,event):
        phase_selector=event.path[:3]==('call_plan','phase_group','selector')
        if event.kind in {'object_start','array_start'}or phase_selector or event.path and event.path[-1]=='price'or any(part in _LOCATOR_FIELDS for part in event.path):super()._emit(event)


def _locator_sources_v3(raw):
    from .habit_authority_source_read_v3 import _source_refs_v3
    result=_source_refs_v3(raw)
    def walk(value):
        if type(value)is dict:
            key=value.get('key')
            if type(key)is str and key.startswith('['):
                atom=AtomKey.from_token(key)
                if atom.type_name=='memory.source':result.add(key)
            for item in value.values():
                if type(item)in(dict,list):walk(item)
        elif type(value)is list:
            for item in value:walk(item)
    walk(raw);return result


class _OriginalMetadataV3:
    def __init__(self,work):
        self.work=work;self.rows={};self.heads={};self.families={};self.roots=set();self.pending=[]
        self.context_roots=set();self.exact=set();self.originals={};self.producers=set();self.signed=set()
        self.quote_keys=set();self.job_ids=set();self.candidate_evidence_plan=None;self.actual_selector=None;self.actual_request=None;self.artifact_recipe=None
        self.family_types=set()if work.original_profile=='original-foreground-source.v1'and work.request.operation_kind in {'prepare_artifact_draft_model','acquire_artifact_draft_model','prepare_artifact_draft_model_v2','acquire_artifact_draft_model_v2'}else set(_FIXED_FAMILIES)
        self.column=None;self.cursor='';self.family_index=0;self.family_eof=set();self.complete=False;self.phase='job'
        self.original_cursor='';self.history_cursor='';self.history_heads={};self.c02_history_heads=set()
        self.history_complete=work.original_profile!='original-foreground-source.v1';self.historical_pending=[]
        self.required_originals=set();self.required_matches={};self.producer_scan_complete=False;self.producer_scan_index=0
        request=work.request
        self.job_key=AtomKey.from_token(request.cycle_job_ref if work.original_profile=='original-foreground-source.v1'else request.task_job_ref)
        self.exact.add(self.job_key.token);self.job_ids.add(self.job_key.name)
        if work.original_profile=='original-foreground-source.v1':
            self.roots.update((request.cue_source_ref,request.plan_source_ref));self.exact.update(self.roots)
            if request.plan_ref is not None:self.exact.add(request.plan_ref)
            if request.draft_root_registration_ref is not None:
                from ..runtime.ingress_artifact_task_scope_v1 import task_scope_ref_v1
                self.signed.update((('draft_root_capability',request.draft_root_registration_ref),('artifact_task_scope',task_scope_ref_v1(request.draft_root_registration_ref))))
        else:
            from ..runtime.owner_source_note_task_v1 import AUTHORIZATION_KIND
            self.signed.add((AUTHORIZATION_KIND,request.authorization_original_ref))
            from .current_owner_source_note_task_v1 import OwnerTaskActivityValuesChildRequestV1
            if type(request)is OwnerTaskActivityValuesChildRequestV1:
                from ..runtime.owner_source_note_values_v1 import KIND
                self.signed.add((KIND,request.values_parent_original_ref))
        self.pending=list(sorted(self.exact))
    def _column(self,table,column,keys,key,identity,header,cell=None):
        self.reading=(identity,header)
        self.column=_OriginalLocatorColumnV3(self,table=table,column=column,key_columns=keys,key=key,cell_id=cell)
    def _consume(self,raw,digest):
        w=self.work;identity,header=self.reading;kind=identity[0]
        if kind=='head':
            ref=identity[1];self.rows[ref]=raw
            roots=_locator_sources_v3(raw);self.roots.update(roots)
            if AtomKey.from_token(ref).type_name in _CONTEXT_TYPES:self.context_roots.update(roots)
            # Fixed typed control edges used by the unchanged original recipes.
            for field in ('goal_ref','project_ref','recipe_ref','target_entity_ref','role_binding_ref','plan_ref','decision_ref','protocol_ref','gp1_interpretation_ref','deadline_ref'):
                value=raw.get(field)
                if type(value)is str and value not in self.exact:
                    key=AtomKey.from_token(value)
                    if NamespaceId.from_key(key)==w.namespace:self.exact.add(value);self.pending.append(value)
        elif kind=='life':
            from ..runtime.d11_life_preparation_v1 import SIGN_KIND
            if digest!=header[1]:raise AuthorityUnavailable('Original signed locator did not reach exact canonical whole EOF')
            w.service.issuer._signer.verify(SIGN_KIND,canonical_serialize((w.namespace,identity[1],identity[2],digest)),header[2])
            if identity[1]=='c1_task_intent':
                from .artifact_task_choice_catalogue_v3 import bind_original_signed_c1_metadata_v3
                bind_original_signed_c1_metadata_v3(self,identity,header,raw)
            else:self.producers.add(header[0])
            self.originals[identity]=raw;self.roots.update(_locator_sources_v3(raw))
            if identity[1]=='owner_source_note_task_authorization_v2':
                cause=raw['cause']
                expected=w.request.authorization_original_digest if w.original_profile=='original-owner-task-source.v1'else self.job_authorization_digest
                if digest!=expected or cause['namespace']!={'bot_id':w.namespace.bot_id,'persona_id':w.namespace.persona_id}:
                    raise AuthorityUnavailable('Original Owner task signed authorization metadata differs')
                if w.original_profile=='original-foreground-source.v1'and(cause['parent_budget_lease_ref']!=w.original_parent_budget or tuple(cause['audiences'])!=w.original_audiences):raise AuthorityUnavailable('Original SourceNote foreground changed its original Root/audience')
                w.original_parent_budget=cause['parent_budget_lease_ref'];w.original_audiences=tuple(cause['audiences'])
                self._deadline(cause['original_deadline_utc'])
                for _,head,expected_digest in raw['heads']:
                    ref=head['key']
                    self.historical_pending.append((ref,head['revision'],expected_digest))
                    if ref not in self.exact:self.exact.add(ref);self.pending.append(ref)
            if identity[1]=='artifact_task_scope'and raw.get('objective_ref')is not None:self.signed.add(('artifact_task_objective',raw['objective_ref']))
        elif kind=='producer':
            if digest!=header[2]:raise AuthorityUnavailable('Original producer locator did not reach its exact canonical whole EOF')
            if raw['identity']['operation_id']!=identity[1]or raw['identity']['phase']!=header[1]:raise AuthorityUnavailable('Original producer locator changed canonical identity phase')
            self.roots.update(_locator_sources_v3(raw));self.originals[identity]=raw
            pointer=raw.get('provenance',{}).get('prepared_candidates_operation_id')
            if pointer is not None:self.producers.add(pointer)
            prepared=raw.get('provenance',{}).get('prepared_candidates')
            if prepared is not None:
                self._all_candidate_plan(prepared,header[2])
                for candidate in prepared['candidates']:
                    if candidate.get('quote_ref')is not None:self.quote_keys.add((candidate['quote_ref'],1))
        elif kind in{'history','catalogue_history'}:
            if len(identity)==4 and digest!=identity[3]:raise AuthorityUnavailable('Original signed historical control changed its exact whole EOF digest')
            self.roots.update(_locator_sources_v3(raw))
        elif kind=='job_continuation':
            if raw.get('authorization_original_ref')is not None:
                from ..runtime.owner_source_note_task_v1 import AUTHORIZATION_KIND
                self.signed.add((AUTHORIZATION_KIND,raw['authorization_original_ref']));self.job_authorization_digest=raw['authorization_original_digest']
            call=raw.get('call_plan',{});group=call.get('phase_group')
            if group is not None:
                selector=group['selector']
                from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
                self.actual_selector=artifact_draft_from_wire_v2(selector,ArtifactDraftPhaseSelectorV2)
                self._fixed_original_edges(selector)
                for field in ('decision_ref','plan_ref'):
                    ref=selector[field]
                    if ref not in self.exact:self.exact.add(ref);self.pending.append(ref)
            if w.original_profile=='original-foreground-source.v1'and w.request.operation_kind in {'prepare_artifact_draft_model','acquire_artifact_draft_model','prepare_artifact_draft_model_v2','acquire_artifact_draft_model_v2'}:
                self._exact_artifact_selector_request()
        self._fixed_original_edges(raw)
        _reserve(w,(self.rows,self.originals,self.roots,self.context_roots,self.pending))
    def _exact_artifact_selector_request(self):
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        from ..runtime.d11_artifact_draft_model_v1 import(PrepareArtifactDraftModelRequestV1,AcquireArtifactDraftModelRequestV1,
            PrepareArtifactDraftModelRequestV2,AcquireArtifactDraftModelRequestV2)
        from ..runtime.domain_production_registry_v1 import installed_operation_v1
        from .current_foreground_activity_v1 import foreground_typed_command_digest_v1
        w=self.work;kind=w.request.operation_kind
        if kind.endswith('_v2'):
            if self.actual_selector is None:raise AuthorityUnavailable('Original Artifact phase requires its actual typed current phase selector')
            selector=self.actual_selector
        else:
            selector=artifact_draft_task_selector_v1(w.namespace,c02_operation_id=w.request.c02_operation_id,root_registration_ref=w.request.draft_root_registration_ref)
        types={'prepare_artifact_draft_model':PrepareArtifactDraftModelRequestV1,'acquire_artifact_draft_model':AcquireArtifactDraftModelRequestV1,
            'prepare_artifact_draft_model_v2':PrepareArtifactDraftModelRequestV2,'acquire_artifact_draft_model_v2':AcquireArtifactDraftModelRequestV2}
        command=types[kind](selector)
        if foreground_typed_command_digest_v1(installed_operation_v1(kind),command)!=w.request.request_digest:
            raise AuthorityUnavailable('Original actual Artifact selector does not reproduce its exact signed command digest')
        self.actual_selector,self.actual_request=selector,command
        from .original_artifact_recipe_metadata_v3 import OriginalArtifactRecipeMetadataV3
        self.artifact_recipe=OriginalArtifactRecipeMetadataV3(self)

    def _fixed_original_edges(self,raw):
        # These are exact fields of installed TaskScope/phase controls, never
        # recursive arbitrary objects or caller-provided table permissions.
        from ..runtime.artifact_phase_postconditions_v1 import APPROVAL_KIND_V2,PREPARATION_PARENT_KIND_V1
        edges={'objective_ref':'artifact_task_objective','extent_original_ref':'artifact_task_text_extent',
            'postcondition_policy_ref':'artifact_phase_postcondition_policy','approval_original_ref':APPROVAL_KIND_V2,
            'contract_ref':'artifact_phase_postcondition_contract','preparation_parent_original_ref':PREPARATION_PARENT_KIND_V1,
            'prev_phase_original_ref':'c4_phase_verified'}
        if raw.get('schema')in{'d11.ingress-artifact-task-scope.v1','d11.ingress-artifact-task-scope.v2','d11.ingress-artifact-task-scope.v3'}:
            from .artifact_task_choice_catalogue_v3 import bind_original_task_scope_c1_v3
            bind_original_task_scope_c1_v3(self,raw)
        for field,kind in edges.items():
            ref=raw.get(field)
            if ref is not None:self.signed.add((kind,ref))

    def _deadline(self,deadline):
        w=self.work
        if original_source_clock_upper_v3(w)>=deadline:raise AuthorityUnavailable('Original request absolute deadline expired during metadata')
        w.deadline_utc=w.operation.deadline_utc=min(w.deadline_utc,float(deadline))
        from .current_authority_graph_read_v3 import _DEADLINES
        _DEADLINES[w]=(w.operation,w.deadline_utc,None)
    def _all_candidate_plan(self,prepared,digest):
        from ..runtime.artifact_recipe_metadata_v3 import artifact_candidate_evidence_plan_from_metadata_v3
        plan=artifact_candidate_evidence_plan_from_metadata_v3(prepared,preparation_original_digest=digest)
        if self.candidate_evidence_plan is not None:
            from ..runtime.d01_production_operations_v1 import production_read_plan_v1
            prior=self.candidate_evidence_plan
            plan=production_read_plan_v1((*prior.fixed_type_ids,*plan.fixed_type_ids),(*prior.exact_keys,*plan.exact_keys),
                (*prior.source_roots,*plan.source_roots),(*prior.required_original_refs,*plan.required_original_refs))
        self.candidate_evidence_plan=plan
        self.roots.update(plan.source_roots)
        for key in plan.exact_keys:
            if key.token not in self.exact:self.exact.add(key.token);self.pending.append(key.token)
        before=set(self.required_originals);self.required_originals.update(plan.required_original_refs)
        if self.required_originals!=before:self.original_cursor='';self.producer_scan_index=0;self.producer_scan_complete=False
    def advance(self,meter):
        w=self.work;w.require_current(meter=meter)
        if self.column is not None:
            if not self.column.advance(meter):return
            self._consume(self.column.require_v3(w),self.column.stream.semantic.hexdigest());self.column=None;return
        if self.phase=='job':
            row=meter.read_fixed_row(w.db,'runtime_jobs',('bot_id','persona_id','deadline_utc','budget_ref'),'job_id=?',(self.job_key.name,))
            if row is not None:
                if row[:2]!=w.namespace.as_tuple:raise AuthorityUnavailable('Original task job crossed actual namespace')
                self._deadline(datetime.fromisoformat(row[2].replace('Z','+00:00')).timestamp());w.original_parent_budget=row[3]
            elif w.original_profile=='original-owner-task-source.v1'and w.request.expected_job_revision>0:raise AuthorityUnavailable('Original current Owner task job is absent')
            self.phase='selected'
            if row is not None:self._column('runtime_jobs','continuation_json',('job_id',),(self.job_key.name,),('job_continuation',self.job_key.name),row)
            return
        if self.artifact_recipe is not None and not self.artifact_recipe.complete:
            self.artifact_recipe.advance(meter);return
        if not self.history_complete:
            row=meter.read_fixed_row(w.db,'graph_history',('token','revision','valid','value_cell_id'),'event_bot=? AND event_persona=? AND event_id=? AND token>? ORDER BY token',(*w.namespace.as_tuple,w.request.c02_operation_id,self.history_cursor))
            if row is None:self.history_complete=True;return
            self.history_cursor=row[0];key=AtomKey.from_token(row[0])
            if NamespaceId.from_key(key)!=w.namespace:raise AuthorityUnavailable('Original C02 historical metadata crossed namespace')
            if row[2]and key.type_name in {'memory.episode.v1','memory.subjective_trace.v2'}:
                self.history_heads[row[0],row[1]]=row[2:];self.c02_history_heads.add((row[0],row[1]));self.exact.add(row[0]);self.pending.append(row[0])
                self._column('graph_history','value',('token','revision'),(row[0],row[1]),('history',row[0]),row,row[3])
            return
        catalogue_history=getattr(self,'catalogue_history_pending',None)
        if catalogue_history:
            ref,revision=catalogue_history.pop()
            row=meter.read_fixed_row(w.db,'graph_history',('valid','value_cell_id','event_bot','event_persona'),'token=? AND revision=?',(ref,revision))
            if row is None or row[0]!=1 or row[2:]!=w.namespace.as_tuple:
                raise AuthorityUnavailable('Task catalogue declared producer version lacks actual namespace history')
            self.history_heads[ref,revision]=row[:2]
            self._column('graph_history','value',('token','revision'),(ref,revision),('catalogue_history',ref,revision),row,row[1]);return
        if self.historical_pending:
            ref,revision,digest=self.historical_pending.pop()
            row=meter.read_fixed_row(w.db,'graph_history',('valid','value_cell_id','event_bot','event_persona'),'token=? AND revision=?',(ref,revision))
            if row is None or row[0]!=1 or row[2:]!=w.namespace.as_tuple:raise AuthorityUnavailable('Original signed historical control has no exact real history')
            self.history_heads[ref,revision]=row[:2]
            self._column('graph_history','value',('token','revision'),(ref,revision),('history',ref,revision,digest),row,row[1]);return
        if self.pending:
            ref=self.pending.pop();key=AtomKey.from_token(ref)
            if NamespaceId.from_key(key)!=w.namespace:raise AuthorityUnavailable('Original exact control locator crossed namespace')
            row=meter.read_fixed_row(w.db,'graph_atoms',('revision','valid','value_cell_id'),'token=?',(ref,))
            self.heads[ref]=(0,0,None)if row is None else row
            if row is not None and key.type_name!='memory.source':
                self._column('graph_atoms','value',('token',),(ref,),('head',ref),row,row[2])
                if key.type_name in {'d08.decision_record.v2','d08.personal_plan.v1'}:
                    history=meter.read_fixed_row(w.db,'graph_history',('event_id',),'token=? AND revision=?',(ref,row[0]))
                    if history is not None:self.producers.add(history[0])
            return
        if self.family_index<len(self.family_types):
            kind=sorted(self.family_types)[self.family_index]
            if kind in self.family_eof:self.family_index+=1;return
            row=meter.read_fixed_row(w.db,'graph_atoms',('token','revision','valid','value_cell_id'),'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',(*w.namespace.as_tuple,kind,self.cursor))
            if row is None:self.families.setdefault(kind,[]);self.family_eof.add(kind);self.family_index+=1;self.cursor='';return
            self.cursor=row[0];members=self.families.setdefault(kind,[])
            if len(members)>=128:raise AuthorityUnavailable('Original exact recipe fixed-family census exceeds its unchanged bound')
            members.append(GraphVersion(AtomKey.from_token(row[0]),row[1]));self.heads[row[0]]=row[1:]
            self._column('graph_atoms','value',('token',),(row[0],),('head',row[0]),row[1:],row[3])
            return
        pending=sorted(identity for identity in self.signed if('life',*identity)not in self.originals)
        if pending:
            kind,ref=pending[0];key=(*w.namespace.as_tuple,kind,ref)
            row=meter.read_fixed_row(w.db,'graph_d11_life_originals_v1',('producing_operation_id','payload_digest','signature'),'bot=? AND persona=? AND kind=? AND original_ref=?',key)
            if row is None:
                if kind=='artifact_task_scope':self.originals['life',kind,ref]={};return
                raise AuthorityUnavailable('Original fixed signed metadata locator is absent')
            self._column('graph_d11_life_originals_v1','payload_json',('bot','persona','kind','original_ref'),key,('life',kind,ref),row);return
        if not self.producer_scan_complete and self.required_originals:
            from ..runtime.domain_production_originals_v1 import PHYSICAL_TABLE
            table=('graph_domain_production_originals_v1',PHYSICAL_TABLE)[self.producer_scan_index]
            row=meter.read_fixed_row(w.db,table,('operation_id','domain','original_digest'),'bot=? AND persona=? AND operation_id>? ORDER BY operation_id',(*w.namespace.as_tuple,self.original_cursor))
            if row is None:
                if self.producer_scan_index==0:self.producer_scan_index=1;self.original_cursor='';return
                missing={ref for ref in self.required_originals if '-current:'in ref and ref not in self.required_matches}
                if missing:raise AuthorityUnavailable('Original ALL candidate evidence has no exact positive producer metadata')
                self.producer_scan_complete=True;return
            self.original_cursor=row[0];ref=row[1]+'-current:'+row[2][:48]
            if ref in self.required_originals:
                prior=self.required_matches.setdefault(ref,row[0])
                if prior!=row[0]:raise AuthorityUnavailable('Original ALL candidate producer locator is ambiguous')
                self.producers.add(row[0])
            return
        pending=sorted(operation for operation in self.producers if('producer',operation)not in self.originals)
        if pending:
            operation=pending[0];key=(*w.namespace.as_tuple,operation)
            table='graph_domain_production_originals_v1';name='original_payload_json';cell=None
            row=meter.read_fixed_row(w.db,table,('domain','operation_kind','original_digest','bundle_digest'),'bot=? AND persona=? AND operation_id=?',key)
            if row is None:
                from ..runtime.domain_production_originals_v1 import PHYSICAL_TABLE
                table=PHYSICAL_TABLE;name='original_payload_cell_id'
                row=meter.read_fixed_row(w.db,table,('domain','operation_kind','original_digest','bundle_digest','original_payload_cell_id'),'bot=? AND persona=? AND operation_id=?',key)
                if row is not None:cell=row[4]
            if row is None:raise AuthorityUnavailable('Original selected producer has no actual W01 metadata')
            bundle=meter.read_fixed_row(w.db,'graph_bundle_operations',('digest','commit_seq'),'bot=? AND persona=? AND operation_id=?',key)
            if bundle is None or bundle[0]!=row[3]or type(bundle[1])is not int or bundle[1]<1:raise AuthorityUnavailable('Original selected producer metadata has no actual positive COMMIT')
            self._column(table,name,('bot','persona','operation_id'),key,('producer',operation),row,cell);return
        if self.phase!='budget':w.original_budget=_OriginalBudgetMetadataV3(w);self.phase='budget';return
        w.original_budget.advance(meter)
        if not w.original_budget.complete:return
        w.original_root_purposes={ref:({'context'}if ref in self.context_roots else set(w.original_purposes))for ref in self.roots}
        selected=set()
        if w.original_profile=='original-foreground-source.v1':selected.update((w.request.cue_source_ref,w.request.plan_source_ref))
        else:selected.update(self.originals['life','owner_source_note_task_authorization_v2',w.request.authorization_original_ref]['source_refs'])
        for identity,value in self.originals.items():
            if identity[0]=='life'and identity[1]=='owner_source_note_task_authorization_v2':
                for ref in value['source_refs']:w.original_root_purposes.setdefault(ref,set()).update(('context','consolidation'))
        for ref in selected:w.original_root_purposes.setdefault(ref,set()).update(w.original_purposes)
        self.complete=True


def begin_original_foreground_source_v3(service,*,credential,subject,permit,request,location):
    from .current_authority_graph_read_v3 import(AuthorityGraphReadWorkV3,require_authority_graph_read_controller_v3,_ISSUER,_track_authority_capability_v3)
    profile,fence_id=_request_profile_v3(service,request)
    identity=service.self_identity
    if request.namespace!=identity._namespace_id or request.installation_id!=identity._installation_id or subject!=identity._read_subject or permit.holder!=identity._holder or permit.operation!='write'or permit.operation_id!=fence_id:
        raise AuthorityUnavailable('Original Source requires unchanged exact installed WRITE identity')
    root=service.installed_bundle.installation_policy.root_grant
    deadline=min(root.valid_until_utc,request.requested_deadline_utc)if profile=='original-foreground-source.v1'else root.valid_until_utc
    controller=require_authority_graph_read_controller_v3(service)
    w=AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=subject,permit=permit,namespace=request.namespace,request=request,deadline_utc=deadline)
    w.original_profile=profile;w.original_deadline=float(deadline);w.original_location=location;w.original_reserved=0
    w.now_utc=original_source_clock_upper_v3(w)
    w.parent_original_id=request.c02_operation_id if profile=='original-foreground-source.v1'else request.authorization_original_ref
    w.original_audiences=request.audiences if profile=='original-foreground-source.v1'else()
    w.original_purposes=(request.purpose,)if profile=='original-foreground-source.v1'else('context','consolidation')
    w.original_parent_budget=request.parent_budget_lease_ref if profile=='original-foreground-source.v1'else root.lease_id
    w.original_metadata=None;w.original_rights=None;w.original_self_phase=False
    _WORKS[w]=_binding_v3(w);_track_authority_capability_v3(w,_WORKS,w)
    try:w.original_metadata=_OriginalMetadataV3(w);w.phase='original_metadata';return w
    except BaseException:w.release_v3();raise


def prepare_original_foreground_owner_quantum_v3(work):
    require_original_foreground_work_v3(work)
    if work.phase=='original_metadata':return
    from .original_foreground_owner_location_v3 import prepare_original_foreground_owner_v3
    return prepare_original_foreground_owner_v3(work.service.self_identity._owner_storage,work)

@contextmanager
def bind_original_foreground_owner_quantum_v3(work):
    require_original_foreground_work_v3(work)
    if work.phase=='original_metadata':yield;return
    from .original_foreground_owner_location_v3 import bind_original_foreground_owner_v3
    with bind_original_foreground_owner_v3(work):yield


def require_original_foreground_body_v3(work):
    require_original_foreground_work_v3(work)
    from .original_foreground_owner_location_v3 import _OWNERS
    owner=_OWNERS.get(work)
    if owner is None or owner.observed is None:raise AuthorityUnavailable('Original business Body requires actual independent Owner17 EOF')
    owner._actual()
    proof=_SOURCE_PROOFS.get(work)
    if proof is None or proof[:4]!=(work.operation,work.scope,work.selection_digest,work.graph_stamp)or not proof[4].complete or work.phase!='validate':
        raise AuthorityUnavailable('Original business Body requires its exact completed Source ALL profile')
    return proof[4]

class _OriginalProjectionV3:
    def __init__(self,work):self.work=work
    def get(self,key):
        from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
        work=self.work;require_original_foreground_work_v3(work)
        if NamespaceId.from_key(key)!=work.namespace:raise AuthorityUnavailable('Original current projection crossed namespace')
        if work.original_self_phase:
            if key.type_name not in _CONTROL_TYPES:raise AuthorityUnavailable('Original Self phase requested business Body')
        else:proof=require_original_foreground_body_v3(work)
        if key in work.members:return work.members[key]
        head=work.heads.get(key.token)
        if (work.original_self_phase or key in proof.versions)and head is None:
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            with runtime_storage_quantum_v3(work.db)as meter:head=meter.read_fixed_row(work.db,'graph_atoms',('revision','valid','value_cell_id'),'token=?',(key.token,))
            if not work.original_self_phase and(0 if head is None else head[0])!=proof.versions[key]:raise AuthorityUnavailable('Original Source control head changed from its qualified ALL proof')
            if head is not None:work.heads[key.token]=head
        if head is None or head[0]==0:return GraphAtom(key,0,{},False)
        request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*work.namespace.as_tuple))
        require_original_foreground_attachment_v3(work,request)
        if work.complete:raise AuthorityUnavailable('Original final predicate requested a Body absent from its own prepared EOF')
        raise AuthorityGraphAttachmentRequiredV3(request)


def advance_original_foreground_materials_v3(work,meter):
    require_original_foreground_work_v3(work)
    if work.phase=='original_metadata':
        work.original_metadata.advance(meter)
        if work.original_metadata.complete:work.phase='original_owner'
        return
    if work.phase=='original_owner':
        from .original_foreground_owner_location_v3 import _OWNERS
        owner=_OWNERS.get(work)
        if owner is None or owner.observed is None:raise AuthorityUnavailable('Original Source phase requires completed independent Owner EOF')
        grant=owner.grant
        purposes={purpose for values in work.original_root_purposes.values()for purpose in values}
        if 'workbench.create'not in grant['capabilities']or not purposes<=set(grant['purposes'])or not set(work.original_audiences)<=set(grant['audiences']):raise AuthorityUnavailable('Original current Owner does not cover exact Source purpose/audience groups')
        from .artifact_task_choice_catalogue_v3 import begin_original_task_choice_catalogue_v3
        if begin_original_task_choice_catalogue_v3(work):
            work.phase='original_catalogue';return
        work.original_rights=_OriginalRightsV3(work);work.phase='original_rights';return
    if work.phase in{'original_catalogue','original_catalogue_metadata'}:
        from .artifact_task_choice_catalogue_v3 import advance_original_task_choice_catalogue_v3
        advance_original_task_choice_catalogue_v3(work,meter);return
    if work.phase=='original_rights':
        work.original_rights.advance(meter)
        if work.original_rights.complete:
            work.heads=dict(work.original_metadata.heads)
            for ref,leaf in work.original_rights.sources.items():work.heads[ref]=(leaf.revision,1,leaf.cell_id)
            from ..domains.d03.self_perspective import self_mapping_key
            for key in(owner_grant_key(*work.namespace.as_tuple),self_mapping_key(work.namespace)):
                row=meter.read_fixed_row(work.db,'graph_atoms',('revision','valid','value_cell_id'),'token=?',(key.token,))
                if row is None:raise AuthorityUnavailable('Original Source phase lost its current Owner/Self mapping')
                work.heads[key.token]=row
            work.projection=_OriginalProjectionV3(work);work.phase='validate'
        return
    if work.phase=='validate':return
    raise AuthorityUnavailable('Original Source has no registered material phase')


def require_original_foreground_attachment_v3(work,request):
    require_original_foreground_work_v3(work)
    table,columns,keys,key=request
    if work.original_self_phase:
        if table in {'graph_atoms','graph_history'}:
            if AtomKey.from_token(key[0]).type_name not in _CONTROL_TYPES:raise AuthorityUnavailable('Original Self Body is outside actual D01/Owner control')
        elif request[:3]not in _ORIGINAL_SELF_POINTS:raise AuthorityUnavailable('Original Self point has no fixed installed shape')
        return True
    proof=require_original_foreground_body_v3(work);metadata=work.original_metadata
    from .artifact_task_choice_catalogue_v3 import require_original_task_c1_point_v3
    if require_original_task_c1_point_v3(work,request):return True
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom)!=work.namespace:raise AuthorityUnavailable('Original Body crossed actual namespace')
        if atom.type_name=='memory.source':
            if atom.token not in proof.sources:raise AuthorityUnavailable('Original Source Body was not qualified by exact current ALL')
        elif atom.token not in metadata.exact and atom.type_name not in metadata.families and atom.type_name not in _CONTROL_TYPES and atom not in proof.versions:
            raise AuthorityUnavailable('Original Body was not selected by its fixed recipe metadata')
        locator=metadata.rows.get(atom.token)
        if locator is not None and not _locator_sources_v3(locator)<=set(proof.sources):raise AuthorityUnavailable('Original body Source locators were not wholly qualified before materialization')
        if table=='graph_history'and (key[0],key[1])not in metadata.history_heads and metadata.heads.get(key[0],(0,))[0]!=key[1]:
            raise AuthorityUnavailable('Original historical Body is outside exact current recipe producer history')
    elif table in {'graph_domain_production_originals_v1','graph_domain_production_originals_v3'}:
        if tuple(key[:2])!=work.namespace.as_tuple or ('producer',key[2])not in metadata.originals:raise AuthorityUnavailable('Original W01 Body is outside complete selected producer EOF')
    elif table=='graph_d11_life_originals_v1':
        if tuple(key[:2])!=work.namespace.as_tuple or ('life',key[2],key[3])not in metadata.originals:raise AuthorityUnavailable('Original Life Body is outside exact authenticated signed locator')
    elif table in {'runtime_budget_grants','runtime_budget_leases','runtime_budget_reservations','runtime_budget_operations'}:
        if key[0]not in work.original_budget.leases:raise AuthorityUnavailable('Original budget read escaped actual signed original family')
    elif table=='runtime_jobs':
        if key[0]not in metadata.job_ids:raise AuthorityUnavailable('Original job Body is outside exact current selector')
    elif table=='runtime_resource_quotes':
        if tuple(key)not in metadata.quote_keys:raise AuthorityUnavailable('Original quote Body is outside exact actual selected signed price')
    elif table in {'graph_bundle_operations','graph_events'}:
        operation=key[-1]
        c02=getattr(work.request,'c02_operation_id',None)
        if operation!=c02 and operation not in metadata.producers:raise AuthorityUnavailable('Original event Body has no actual selected producing lineage')
    elif table not in {'graph_ingress_observations','runtime_job_operations','runtime_resource_quotes','graph_owner_domain_attempts_v3','graph_d02_production_policies_v1','d02_fixed_body_policies_v1','graph_dependencies'}:
        raise AuthorityUnavailable('Original exact recipe has no fixed table authority')
    return True


def prepare_original_foreground_attachment_v3(work,request):
    from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3,_HOST_ATTACHMENT_SHAPES_V3
    require_original_foreground_attachment_v3(work,request)
    if request[:3]==('runtime_resource_quotes',('quote_json','signature'),('quote_id','version')):
        from .current_authority_graph_read_v3 import _AuthoritySignedQuoteReadV3
        return _AuthoritySignedQuoteReadV3(work,request)
    c02_shape=request[:3]==('graph_bundle_operations',('digest','receipt_json'),('bot','persona','operation_id'))
    from .artifact_task_choice_catalogue_v3 import original_task_c1_attachment_shape_v3
    task_c1=original_task_c1_attachment_shape_v3(request)
    if not task_c1 and request[:3]not in _HOST_ATTACHMENT_SHAPES_V3 and request[:3]not in _ORIGINAL_SELF_POINTS and not c02_shape and not(request[0]=='graph_history'and set(request[1])<={'token','revision','event_id','value','valid','event_bot','event_persona'}):
        raise AuthorityUnavailable('Original point has no installed fixed full-key materialization shape')
    return _HostProducerAttachmentV3(work,request)


def read_original_foreground_point_v3(work,*,table,columns,key_columns,key,required_valid=False):
    from .current_authority_graph_read_v3 import(AuthorityGraphAttachmentRequiredV3,_authority_json_column_cap_v3,_AuthorityAtomJSONV3,_ISSUER)
    require_original_foreground_work_v3(work)
    columns,key_columns,key=tuple(columns),tuple(key_columns),tuple(key)
    if table=='graph_atoms':
        atom=work.projection.get(AtomKey.from_token(dict(zip(key_columns,key))['token']))
        if atom.revision==0 or required_valid and not atom.valid:return None
        values={'revision':atom.revision,'value':_AuthorityAtomJSONV3(_ISSUER,work,atom),'valid':int(atom.valid),'token':atom.key.token}
        return tuple(values[name]for name in columns)
    request=(table,columns,key_columns,key);require_original_foreground_attachment_v3(work,request)
    attachment=work.attachments.get(request)
    if attachment is None:
        if work.complete:raise AuthorityUnavailable('Original final point was not retained by the same Work')
        raise AuthorityGraphAttachmentRequiredV3(request)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(work.db)as meter:row=attachment.require_row_v3(work,meter)
    if row is None:return None
    result=list(row)
    for index,column in enumerate(columns):
        if column in attachment.json_columns:result[index]=_authority_json_column_cap_v3(work,attachment,attachment.json_columns[column])
    return tuple(result)


def original_foreground_source_family_v3(work,*,namespace,roots,purpose,audiences):
    proof=require_original_foreground_body_v3(work)
    if namespace!=work.namespace or tuple(audiences)!=tuple(work.original_audiences)or not set(roots)<=work.original_metadata.roots or any(purpose not in proof.purposes.get(ref,())for ref in roots):
        raise AuthorityUnavailable('Original predicate changed its exact qualified Source purpose/audience/readset')
    return tuple(GraphVersion(key,revision)for key,revision in sorted(proof.versions.items(),key=lambda item:item[0].token))


def require_original_foreground_source_anchor_in_tx_v3(work,db,location):
    require_original_foreground_work_v3(work)
    identity=work.service.self_identity;qualifier=work.controller.location
    value=qualifier._require_issued(location,purpose='business')
    if db is not identity._core._db or not db.in_transaction or value is not work.original_location or value.permit!=work.permit or value.subject!=work.subject or value.core_anchor!=work.permit.pinned_anchor or value.context._reader is not work.controller.control:
        raise AuthorityUnavailable('Original Self observation changed actual Source/fence/storage identity')
    from .current_source_location_v1 import require_current_source_anchor_in_tx_v1
    row,anchor=require_current_source_anchor_in_tx_v1(db,namespace=qualifier.namespace,expected_anchor=value.core_anchor,holder=value.holder)
    if row[9]!='clear':raise AuthorityUnavailable('Original Source cannot read during actual erasure')
    from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
    require_lifecycle_admission_in_tx_v1(db,qualifier.namespace,action='graph_read')
    qualifier._fences.fences.validate_fence_locked(db,value.permit,subject=value.subject,current_anchor=anchor)


@contextmanager
def original_foreground_self_phase_v3(work):
    require_original_foreground_work_v3(work)
    from .original_foreground_owner_location_v3 import _OWNERS
    owner=_OWNERS[work];owner._check_permission_v3()
    old_phase=work.phase;work.original_self_phase=True;work.phase='validate'
    work.projection=_OriginalProjectionV3(work);work.heads=dict(work.original_metadata.heads)
    with work.quantum_v3()as meter:
        from ..graph_types import Owner
        for key in(owner_grant_key(*work.namespace.as_tuple),AtomKey(Owner('persona',*work.namespace.as_tuple),'d01.persona_activation.v1','current')):
            row=meter.read_fixed_row(work.db,'graph_atoms',('revision','valid','value_cell_id'),'token=?',(key.token,))
            if row is None:raise AuthorityUnavailable('Original Self actual current head is absent')
            work.heads[key.token]=row
    try:yield owner
    finally:
        from .current_authority_graph_read_v3 import _PREPARED
        if work.prepared is not None:_PREPARED.pop(work.prepared,None)
        work.complete=False;work.prepared=None;work.original_self_phase=False;work.phase=old_phase


def read_original_foreground_self_v3(work):
    from .v2_self_identity_contract import SelfIdentityCurrentRequestV1
    from .original_foreground_owner_location_v3 import _OWNERS
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3
    identity=work.service.self_identity;owner=_OWNERS[work];owner._check_permission_v3()
    request=SelfIdentityCurrentRequestV1(work.permit.authority_id,identity._fences.namespace,work.namespace,
        identity._installation_id,identity._manifest_digest,work.request.operation_id,work.permit)
    identity._core._require(work.credential,'self_identity_read',request.authority_namespace,identity._holder)
    with identity._fences._frozen()as(db,deletion,execution,history):
        before=identity._read_locked(db,deletion,execution,history,work.credential,work.subject,request,work.original_location,_original_work=work)
    if before is None or before[1]!=owner.observed.guard:raise AuthorityUnavailable('Original independent Self/Owner comparison is unavailable')
    head,guard,anchor,_=before
    with original_foreground_self_phase_v3(work):
        graph=read_authority_graph_current_v3(work,lambda db:identity._graph._check(db,work.namespace,anchor,
            identity._installation_id,guard,location_observation=work.original_location,storage_admission=owner.observed.storage_admission,holder=identity._holder))
    if graph is None:raise AuthorityUnavailable('Original actual D01 Self role is unavailable')
    with identity._fences._frozen()as(db,deletion,execution,history):
        after=identity._read_locked(db,deletion,execution,history,work.credential,work.subject,request,work.original_location,_original_work=work)
    if before!=after:raise AuthorityUnavailable('Original independent Self changed during same-Work current observation')
    return identity._current_value(request,head,guard,anchor,graph,owner.observed.storage_admission)


def release_original_foreground_source_v3(work):
    from .artifact_task_choice_catalogue_v3 import release_original_task_choice_catalogue_v3
    release_original_task_choice_catalogue_v3(work)
    _SOURCE_PROOFS.pop(work,None)
    from .original_artifact_recipe_metadata_v3 import release_original_artifact_recipe_metadata_v3
    release_original_artifact_recipe_metadata_v3(work)
    # The Work registry is tracked by the actual Authority retained operation;
    # release_v3 removes it after releasing Owner and material capabilities.

_ORIGINAL_SELF_POINTS = frozenset((
    ("graph_owner_issue_operations_v1",
        ("operation_id","request_digest","grant_id","grant_digest","graph_incarnation","graph_access_epoch","graph_epoch","graph_receipt_digest","proof_json"),
        ("bot","persona","operation_id")),
    ("graph_role_init_intents_v1",
        ("operation_id","input_digest","fence_attempt_id","requirements_json","anchor_json","graph_revision","graph_epoch"),("bot","persona")),
    ("graph_role_init_request_proofs_v1",("operation_id","request_digest","input_digest"),("bot","persona")),
    ("graph_role_init_receipts_v1",
        ("operation_id","input_digest","permit_json","receipt_json","pre_graph_revision","pre_graph_epoch","post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest"),
        ("bot","persona")),
))


def observe_original_activity_current_v3(service,*,credential,subject,permit,request):
    from .current_authority_graph_read_v3 import(advance_authority_graph_read_work_v3,read_authority_graph_current_v3,finish_authority_graph_read_work_v3)
    from .original_foreground_owner_location_v3 import prepare_original_foreground_owner_v3,_OWNERS
    location=service.self_identity._source_location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
    work=begin_original_foreground_source_v3(service,credential=credential,subject=subject,permit=permit,request=request,location=location)
    try:
        while work.phase=='original_metadata':advance_authority_graph_read_work_v3(work)
        prepare_original_foreground_owner_v3(service.self_identity._owner_storage,work)
        current_self=read_original_foreground_self_v3(work)
        while work.phase!='validate':advance_authority_graph_read_work_v3(work)
        def current(db):
            result=service._read_current_graph_v3(db,credential=credential,subject=subject,permit=permit,request=request,
                current_self=current_self,current_owner=_OWNERS[work].observed,location=location,now=original_source_clock_upper_v3(work))
            if work.original_profile=='original-foreground-source.v1':
                evidence,job=result
                return complete_original_current_readset_v3(work,evidence),job
            return complete_original_current_readset_v3(work,result)
        result=read_authority_graph_current_v3(work,current)
        if read_original_foreground_self_v3(work)!=current_self:raise AuthorityUnavailable('Original independent Self/Owner/C09/Graph changed before issuance')
        service.self_identity._fences.validate_fence(credential=credential,subject=subject,permit=permit)
        return result
    finally:finish_authority_graph_read_work_v3(work)


def read_original_foreground_budget_v3(work,lease_id,*,issuer=None):
    require_original_foreground_body_v3(work)
    if lease_id not in work.original_budget.leases or issuer is not None and issuer is not work.service.issuer:
        raise AuthorityUnavailable('Original budget read escaped its original authenticated grant family')
    return True,(work.original_budget.grants[lease_id]if issuer is not None else work.original_budget.leases[lease_id])


def read_original_foreground_self_header_v3(work,*,namespace):
    require_original_foreground_work_v3(work)
    from .original_foreground_owner_location_v3 import _OWNERS
    owner=_OWNERS[work];owner._actual()
    if not work.original_self_phase or namespace!=work.namespace:raise AuthorityUnavailable('Original Self metadata requires actual private same-Work Self phase')
    facts=owner.facts;metadata=facts.metadata
    return(('sylanne3.authority.v2',canonical_serialize(metadata.requirements),metadata.graph_revision),(facts.graph_epoch.revision,),tuple(facts.epochs))


def read_original_foreground_c02_history_v3(work,*,namespace,operation_id):
    require_original_foreground_body_v3(work)
    if namespace!=work.namespace or work.original_profile!='original-foreground-source.v1'or operation_id!=work.request.c02_operation_id:
        raise AuthorityUnavailable('Original C02 history changed its exact original selector')
    result=[]
    for token,revision in sorted(work.original_metadata.c02_history_heads):
        row=read_original_foreground_point_v3(work,table='graph_history',columns=('event_id','value','valid'),key_columns=('token','revision'),key=(token,revision))
        if row is None or row[0]!=operation_id or row[2]!=1:raise AuthorityUnavailable('Original C02 history lost its current actual producer')
        result.append((token,revision,row[1]))
    return tuple(result)


def read_bound_original_foreground_inventory_v3(db,namespace,type_id,*,valid_only):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    if work is None or original_foreground_work_v3(work)is None:return False,None
    require_original_foreground_body_v3(work)
    if namespace!=work.namespace or type_id not in work.original_metadata.families:raise AuthorityUnavailable('Original inventory is outside its actual complete recipe metadata EOF')
    rows=tuple(work.projection.get(version.key)for version in work.original_metadata.families[type_id]if not valid_only or work.original_metadata.heads[version.key.token][1])
    return True,tuple(atom for atom in rows if not valid_only or atom.valid)


def complete_original_current_readset_v3(work,evidence):
    """Retain actual ALL evidence locators in the original issuer's signed readset."""
    from dataclasses import replace
    require_original_foreground_body_v3(work)
    plan=work.original_metadata.candidate_evidence_plan
    versions={version.key:version.revision for version in evidence.read_versions}
    proof=require_original_foreground_body_v3(work)
    for key,revision in proof.versions.items():
        if versions.get(key,revision)!=revision:raise AuthorityUnavailable('Original Source ALL head differs from unchanged current predicate')
        versions[key]=revision
    if plan is not None:
        for key in plan.exact_keys:
            head=work.original_metadata.heads.get(key.token)
            if head is None:raise AuthorityUnavailable('Original ALL evidence exact locator has no completed current metadata head')
            revision=head[0]
            prior=versions.get(key,revision)
            if prior!=revision:raise AuthorityUnavailable('Original ALL evidence current head differs from unchanged predicate')
            versions[key]=revision
        for kind in plan.fixed_type_ids:
            rows=work.original_metadata.families.get(kind)
            if rows is None:raise AuthorityUnavailable('Original ALL evidence requested an unclosed exact recipe family')
            for version in rows:
                prior=versions.get(version.key,version.revision)
                if prior!=version.revision:raise AuthorityUnavailable('Original ALL evidence family changed its actual current head')
                versions[version.key]=version.revision
    if len(versions)>128:raise AuthorityUnavailable('Original ALL evidence exceeds the existing original evidence 128-version bound')
    return replace(evidence,read_versions=tuple(GraphVersion(key,revision)for key,revision in sorted(versions.items(),key=lambda item:item[0].token)))


def read_bound_original_foreground_graph_atom_v3(db,namespace,key):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    if work is None or original_foreground_work_v3(work)is None:return False,None
    require_original_foreground_body_v3(work)
    if namespace!=work.namespace:raise AuthorityUnavailable('Original exact current head crossed namespace')
    return True,work.projection.get(key)
