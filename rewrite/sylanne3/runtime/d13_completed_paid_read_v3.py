"""Exact completed D13 job material inside its actual paid Source READ Work."""
from dataclasses import asdict,dataclass,fields,replace
from hashlib import sha256
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,Owner
from ..runtime_contracts import canonical_digest,canonical_serialize
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
from .dispatch_current_inventory_v3 import _heap

COMPLETED_READ_V3="read_current_d13_completed_paid_block_v3"
_JOB_FULL_COLUMNS=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref",
    "phase","work_kind","continuation_json","wake_condition_json","deadline_utc","budget_ref","resource_ref",
    "operator_versions_json","lease_holder","lease_expires_utc","fence","cancel_epoch","usage_json","result_ref")
_JOB_JSON=("continuation_json","operator_versions_json","usage_json")

@dataclass(frozen=True,slots=True)
class CurrentD13CompletedPaidBlockV3:
    saved:object
    costs:tuple
    block:object
    window:object
    metadata:object
    verified:bool

class _CompletedMetadataStreamV3(C09CanonicalJSONStreamV2):
    def __init__(self,derived):
        super().__init__(ensure_ascii=True)
        self.derived=derived;self.nodes={};self.value=None;self.buffers={};self.root_fields=set()
        from ..domains.d13.derived_block_metadata_v2 import DerivedBlockMetadataV2
        from ..runtime_contracts import CompressedTurnBlockV2
        cls=DerivedBlockMetadataV2 if derived else CompressedTurnBlockV2
        self.allowed={f.name for f in fields(cls)}|{"$type"}
    def selected(self,path):
        return not path or self.derived or path[0] not in {"timeline","detail_slots","omitted_ranges"}
    def put(self,path,value):
        if not path:self.value=value;return
        parent=self.nodes[path[:-1]]
        if type(parent)is list:parent.append(value)
        else:parent[path[-1]]=value
    def emit(self,event):
        path=event.path
        if event.kind=="key" and len(path)==1:
            if event.key not in self.allowed:raise AuthorityUnavailable("D13 completed metadata root schema differs")
            self.root_fields.add(event.key)
        if not self.selected(path):return
        if len(path)>=2 and path[0] in {"source_dependencies","turn_expiries","turns"} and type(path[1])is int:
            bound=192 if path[0]=="source_dependencies" else 64
            if path[1]>=bound:raise AuthorityUnavailable("D13 completed metadata exceeds exact installed turn closure")
        if event.kind in {"object_start","array_start"}:
            value={} if event.kind=="object_start" else []
            self.nodes[path]=value;self.put(path,value)
        elif event.kind=="scalar_start":self.buffers[path]=bytearray()
        elif event.kind=="scalar_chunk":
            target=self.buffers[path]
            if len(target)+len(event.raw)>8192:raise AuthorityUnavailable("D13 completed metadata scalar exceeds original bound")
            target.extend(event.raw)
        elif event.kind=="scalar_end":self.put(path,json.loads(self.buffers.pop(path)))
    def finish(self):
        result=super().finish()
        if self.root_fields-{"$type"}!=self.allowed-{"$type"}:
            raise AuthorityUnavailable("D13 completed metadata requires complete exact schema EOF")
        return result

class _DerivedPayloadReadV3:
    def __init__(self,reader,metadata):
        reader.require_current_v3()
        if not reader.qualified:raise AuthorityUnavailable("D13 derived body requires ALL Source ancestors")
        self.reader,self.metadata=reader,metadata
        self.offset=0;self.body=bytearray();self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.complete=False;self.value=None
    def advance_v3(self,meter):
        r=self.reader
        raw,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table="graph_d11_derived_cache_payloads_v1",
            column="payload_bytes",where="bot=? AND persona=? AND block_ref=?",
            parameters=(*r.namespace.as_tuple,self.metadata.block_ref),start=self.offset,length=min(1024,self.metadata.payload_length_bytes-self.offset),meter=meter)
        if kind!="blob" or total!=self.metadata.payload_length_bytes:
            raise AuthorityUnavailable("D13 actual derived payload length/type differs")
        r.reserve_v3(_heap(self.body)*2+len(raw)*16+65536)
        if raw:
            self.body.extend(raw);self.parser.feed(raw,lambda event:None);self.offset+=len(raw);return
        eof=self.parser.finish()
        if eof.sha256!=self.metadata.payload_digest or eof.byte_count!=total:
            raise AuthorityUnavailable("D13 actual derived payload SHA/EOF differs")
        r.reserve_v3(len(self.body)*10+65536)
        from .d11_derived_cache_payload_v1 import _qualify_derived_payload_value_v1
        self.value=_qualify_derived_payload_value_v1(self.metadata,json.loads(self.body.decode("utf8")),
            payload_digest=eof.sha256,payload_length=total)
        self.body.clear();self.complete=True

class CompletedD13PaidReadV3:
    def __init__(self,reader):
        if reader.method!=COMPLETED_READ_V3:raise AuthorityUnavailable("D13 completed material requires its named exact-job recipe")
        self.reader=reader;self.phase="head";self.column=None;self.projection=None
        self.block_head=self.job_head=self.ledger=self.block_key=self.job_key=None
        self.dependencies={};self.cursor=""
        self.metadata=self.block=self.saved=self.value=None
        self.derived=self.metadata_complete=False
        self.scalar_job=None;self.job_json={};self.job=None;self.job_index=0
        self.quote_head=self.grant_head=self.reservation_head=None
        self.reservation=None
        self.quote_row=self.grant_row=None
        self.cost_heads={};self.cost_rows={};self.cost_cursor=0
        self.body_index=0;self.payload_head=None;self.terminal_fact=None
    def heap_v3(self):
        parts=(self.dependencies,self.metadata,self.block,self.saved,self.value,self.scalar_job,self.job_json,
            self.job,self.quote_row,self.grant_row,self.reservation,self.cost_heads,self.cost_rows,self.terminal_fact)
        size=_heap(parts)
        if self.projection is not None:size+=_heap(vars(self.projection))
        if self.column is not None:size+=_heap(vars(self.column))
        if self.block is not None:size+=_heap(asdict(self.block))
        if self.saved is not None:size+=_heap(asdict(self.saved))
        return size
    def column_v3(self,table,column,keycols,key,cell=None,metadata=False):
        from .d13_paid_original_read_v3 import _ColumnV3
        return _ColumnV3(self.reader,table=table,column=column,key_columns=keycols,key=key,cell_id=cell,metadata=metadata)
    def metadata_advance_v3(self,meter):
        r=self.reader;r.require_current_v3(meter=meter)
        if self.phase=="head":
            if r.job[5]!="completed" or not r.job[13]:
                raise AuthorityUnavailable("D13 completed body requires its actual successful job/result_ref")
            from ..host.model_workflows_v6 import AdminModelWorkflowsV6
            from ..host.model_workflows_v7 import AdminModelWorkflowsV7
            from ..host.model_workflows_v8 import AdminModelWorkflowsV8
            from ..model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as V6
            from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as V7
            bundle=r.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
            wf=bundle.model_workflows
            self.derived=(type(wf)is AdminModelWorkflowsV6 and wf.natural_generation is not None and wf.natural_generation.template_version==V6
                or type(wf)in {AdminModelWorkflowsV7,AdminModelWorkflowsV8} and wf.natural_generation is not None and wf.natural_generation.template_version==V7)
            typename="d13.derived_block_metadata.v2" if self.derived else "d13.compressed_turn_block.v2"
            self.block_key=AtomKey(Owner("persona",*r.namespace.as_tuple),typename,r.job[13])
            from .d11_types import runtime_job_key
            self.job_key=runtime_job_key(*r.namespace.as_tuple,r.job[2],r.job_id)
            self.block_head=meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),"token=?",(self.block_key.token,))
            self.job_head=meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),"token=?",(self.job_key.token,))
            self.ledger=meter.read_fixed_row(r.db,"graph_d13_paid_scene_jobs_v1",
                ("input_digest","state","expires_at_utc"),"bot=? AND persona=? AND scene_ref=? AND job_ref=?",
                (*r.namespace.as_tuple,r.frozen_metadata[("window","scene_ref","ref")],r.job_id))
            if (self.block_head is None or self.block_head[1]!=1 or self.job_head is None or self.job_head[1]!=1
                    or self.ledger is None or self.ledger[1]not in {"standby","active"}):
                raise AuthorityUnavailable("D13 completed exact scene/job/result current heads unavailable")
            prefix="d13-paid-derived-complete:" if self.derived else "d13-paid-complete:"
            completion=prefix+r.intent_metadata[("binding","binding_digest")][:48]
            committed=meter.read_fixed_row(r.db,"graph_bundle_operations",("commit_seq",),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,completion))
            for key,head in ((self.block_key,self.block_head),(self.job_key,self.job_head)):
                history=meter.read_fixed_row(r.db,"graph_history",("event_id","valid"),
                    "token=? AND revision=?",(key.token,1 if key==self.block_key else head[0]))
                if history!=(completion,1)or committed is None or committed[0]<1:
                    raise AuthorityUnavailable("D13 completed job/block lack actual producing history/commit")
            if not self.derived and meter.read_fixed_row(r.db,"graph_d13_retirements_v1",("block_token",),
                    "bot=? AND persona=? AND block_token=?",(*r.namespace.as_tuple,self.block_key.token)) is not None:
                raise AuthorityUnavailable("D13 completed ordinary block has its actual retirement original")
            self.column=self.column_v3("graph_atoms","value",("token",),(self.block_key.token,),self.block_head[2],True)
            self.projection=_CompletedMetadataStreamV3(self.derived);self.column.parser=self.projection
            self.phase="projection";return
        if self.phase=="projection":
            self.column.advance(meter)
            if not self.column.complete:return
            raw=self.projection.value
            if (raw["block_ref"]!=r.job[13]or raw["job_ref"]!=r.job_id
                    or raw["conversation_ref"]!=r.authority.audience[0]or raw["status"]not in {"standby","active"}
                    or r.now_utc>=raw["expires_at_utc"]):
                raise AuthorityUnavailable("D13 completed metadata exact result/job/audience/expiry differs")
            from ..runtime_contracts import VersionedRef
            def ref(v):return VersionedRef(v["ref"],v["version"])
            source_deps=tuple(ref(x) for x in raw["source_dependencies"])
            expected=tuple(VersionedRef(value,r.frozen_metadata[(*path[:-1],"version")])
                for path,value in sorted(r.frozen_metadata.items(),key=lambda x:str(x[0]))
                if path[:2]==("plan","source_dependencies")and path[-1:]==("ref",))
            if set(source_deps)!=set(expected):
                raise AuthorityUnavailable("D13 completed block Sources differ from actual frozen plan")
            for version in source_deps:
                if version.ref in r.frozen_versions and r.frozen_versions[version.ref]!=version.version:
                    raise AuthorityUnavailable("D13 completed original/window dependency version differs")
                r.frozen_versions[version.ref]=version.version
                if AtomKey.from_token(version.ref).type_name=="memory.source":r.pending_sources.append(version.ref)
            if self.derived:
                from ..domains.d13.derived_block_metadata_v2 import decode_derived_block_metadata_v2
                self.metadata=decode_derived_block_metadata_v2(raw)
                if (self.metadata.namespace!=r.namespace or self.metadata.scene_ref.ref!=r.frozen_metadata[("window","scene_ref","ref")]
                        or self.metadata.paid_original_digest!=r.intent_head[1]
                        or self.metadata.paid_original_operation_id!=r.job[1]):
                    raise AuthorityUnavailable("D13 derived metadata actual immutable paid binding differs")
                self.payload_head=meter.read_fixed_row(r.db,"graph_d11_derived_cache_payloads_v1",("payload_digest",),
                    "bot=? AND persona=? AND block_ref=?",(*r.namespace.as_tuple,r.job[13]))
                if self.payload_head!=(self.metadata.payload_digest,):
                    raise AuthorityUnavailable("D13 derived payload row lost its metadata SHA commitment")
            else:self.metadata=raw
            self.column=None;self.phase="dependencies";return
        row=meter.read_fixed_row(r.db,"graph_dependencies",("dependency_token","dependency_revision"),
            "dependent_token=? AND dependency_token>? ORDER BY dependency_token",(self.block_key.token,self.cursor))
        if row is not None:
            self.dependencies[row[0]]=row[1];self.cursor=row[0];return
        raw=self.projection.value
        expected={x["ref"]:x["version"] for x in raw["source_dependencies"]}
        if self.dependencies!=expected:raise AuthorityUnavailable("D13 completed block exact dependency coverage differs")
        self.metadata_complete=True;self.phase="body"
    def body_advance_v3(self,meter):
        r=self.reader
        if not r.qualified:raise AuthorityUnavailable("D13 completed body has no ALL Source EOF permission")
        if self.scalar_job is None:
            self.scalar_job=meter.read_fixed_row(r.db,"runtime_jobs",tuple(x for x in _JOB_FULL_COLUMNS if x not in _JOB_JSON),
                "job_id=?",(r.job_id,))
            self.quote_head=meter.read_fixed_row(r.db,"runtime_resource_quotes",("signature",),"quote_id=? AND version=?",
                (r.intent_metadata[("quote_id",)],r.intent_metadata[("quote_version",)]))
            self.grant_head=meter.read_fixed_row(r.db,"runtime_budget_grants",("signature",),"lease_id=? AND version=?",
                (r.job[8],r.intent_metadata[("grant_version",)]))
            self.reservation_head=meter.read_fixed_row(r.db,"runtime_budget_reservations",("digest","state"),
                "lease_id=? AND operation_id=?",(r.job[8],r.intent_metadata[("budget_operation_id",)]))
            if self.scalar_job is None or self.quote_head is None or self.grant_head is None or self.reservation_head is None:
                raise AuthorityUnavailable("D13 completed original accounting/job headers missing")
            return
        if self.job_index<len(_JOB_JSON):
            name=_JOB_JSON[self.job_index]
            if self.column is None:self.column=self.column_v3("runtime_jobs",name,("job_id",),(r.job_id,))
            self.column.advance(meter)
            if self.column.complete:self.job_json[name]=self.column.value;self.column=None;self.job_index+=1
            return
        if self.job is None:
            scalars=dict(zip((x for x in _JOB_FULL_COLUMNS if x not in _JOB_JSON),self.scalar_job))
            from .jobs import _job_from_row
            self.job=_job_from_row(tuple(self.job_json[x]if x in _JOB_JSON else scalars[x] for x in _JOB_FULL_COLUMNS))
            if (self.job.phase,self.job.operation_id,self.job.bot_id,self.job.persona_id,self.job.result_ref,self.job.cancel_epoch)!=(
                    "completed",r.job[1],*r.namespace.as_tuple,r.job[13],0):
                raise AuthorityUnavailable("D13 completed actual job changed during EOF")
            return
        columns=(("runtime_resource_quotes","quote_json",("quote_id","version"),(r.intent_metadata[("quote_id",)],r.intent_metadata[("quote_version",)])),
            ("runtime_budget_grants","grant_json",("lease_id","version"),(r.job[8],r.intent_metadata[("grant_version",)])),
            ("runtime_budget_reservations","ceiling_json",("lease_id","operation_id"),(r.job[8],r.intent_metadata[("budget_operation_id",)])),
            ("graph_atoms","value",("token",),(self.job_key.token,)))
        if self.body_index<len(columns):
            table,col,keycols,key=columns[self.body_index]
            cell=self.job_head[2]if self.body_index==3 else None
            if self.column is None:self.column=self.column_v3(table,col,keycols,key,cell)
            self.column.advance(meter)
            if not self.column.complete:return
            value=self.column.value
            if self.body_index==0:self.quote_row=(value,self.quote_head[0])
            elif self.body_index==1:self.grant_row=(value,self.grant_head[0])
            elif self.body_index==2:self.reservation=(self.reservation_head[0],value,self.reservation_head[1])
            else:
                from .d11_types import job_graph_write
                if json.loads(value)!=job_graph_write(self.job).value:
                    raise AuthorityUnavailable("D13 completed Graph job differs from actual persisted job")
            self.column=None;self.body_index+=1;return
        if self.cost_cursor<2:
            phase=("reserve","settle")[self.cost_cursor]
            if phase not in self.cost_heads:
                self.cost_heads[phase]=meter.read_fixed_row(r.db,"runtime_budget_operations",("digest",),
                    "bot_id=? AND persona_id=? AND operation_id=? AND phase=?",
                    (*r.namespace.as_tuple,r.intent_metadata[("budget_operation_id",)],phase))
                if self.cost_heads[phase]is None:raise AuthorityUnavailable("D13 completed reserve/settle original absent")
            if self.column is None:self.column=self.column_v3("runtime_budget_operations","receipt_json",
                ("bot_id","persona_id","operation_id","phase"),(*r.namespace.as_tuple,r.intent_metadata[("budget_operation_id",)],phase))
            self.column.advance(meter)
            if self.column.complete:
                self.cost_rows[phase]=(phase,self.cost_heads[phase][0],self.column.value)
                self.column=None;self.cost_cursor+=1
            return
        if self.block is None:
            if self.column is None:
                self.column=(_DerivedPayloadReadV3(r,self.metadata)if self.derived else
                    self.column_v3("graph_atoms","value",("token",),(self.block_key.token,),self.block_head[2]))
            if self.derived:self.column.advance_v3(meter)
            else:self.column.advance(meter)
            if not self.column.complete:return
            if self.derived:self.block=self.column.value
            else:
                from ..domains.d13.provider import _block_from_graph_value
                self.block=_block_from_graph_value(json.loads(self.column.value))
            self.column=None;return
        from .d13_paid_coordinator_v1 import recover_paid_d13_in_transaction_v1
        self.saved=recover_paid_d13_in_transaction_v1(r.db,r.namespace,r.job_id)
        if (self.saved is None or self.saved.evidence is None or self.saved.settlement is None
                or self.saved.settlement.receipt.status!="settled"or self.saved.job!=self.job
                or self.saved.frozen.plan.job_ref!=self.block.job_ref
                or self.block.block_ref!=self.job.result_ref
                or r.now_utc>=min(self.block.expires_at_utc,self.saved.original.binding.expires_at_utc)):
            raise AuthorityUnavailable("D13 completed actual paid original/result/body lifetime differs")
        if self.derived and (self.metadata.scene_ref!=r.current_window.scene_ref
                or self.metadata.audience_ref!=r.current_window.audience_ref
                or self.metadata.expires_at_utc!=min(self.block.expires_at_utc,self.saved.original.binding.expires_at_utc,
                    *(turn.trusted_utc+72*3600 for turn in self.block.turns))
                or self.metadata.paid_evidence_digest!=self.saved.evidence.evidence_digest
                or self.metadata.paid_settlement_digest!=canonical_digest(self.saved.settlement)):
            raise AuthorityUnavailable("D13 derived paid evidence/settlement originals differ")
        r.phase="completed_fact"
    def observe_terminal_v3(self):
        r=self.reader
        if r.db.in_transaction:raise AuthorityUnavailable("D13 paired original terminal observation precedes Graph transaction")
        self.terminal_fact=r.graph._GraphCoordinator__content_fence_v2.read_d13_paid_terminal_fact_v3(
            scope=r.fence.scope,intent=self.saved.evidence.fact.intent)
        self.require_terminal_v3(self.saved.evidence.fact,self.saved.evidence.read)
        r.phase="completed_verify"
    def require_terminal_v3(self,fact,read):
        r=self.reader;r.require_current_v3()
        if self.saved is None or (fact,read)!=(self.saved.evidence.fact,self.saved.evidence.read) or self.terminal_fact is None:
            raise AuthorityUnavailable("D13 verifier terminal fact crossed exact paid original Work")
        record,permit,admission,receipt=self.terminal_fact;intent=fact.intent
        if (record!=fact.recovery or record.intent!=intent or record.state!="observed"or record.content_erased
                or record.observation_digest!=read.observation.digest
                or admission!=fact.admission or receipt!=fact.receipt or receipt!=read.terminal_receipt
                or permit.operation!="model_egress"
                or (permit.authority_id,permit.namespace,permit.subject,permit.operation_id,permit.token,permit.fence_epoch,
                    permit.revision,permit.generation,canonical_digest(asdict(permit.pinned_anchor)))!=
                (intent.authority_id,intent.namespace,intent.subject,intent.operation_id,intent.fence_token,intent.fence_epoch,
                    intent.fence_revision,intent.authority_activation_generation,intent.anchor_digest)):
            raise AuthorityUnavailable("D13 same-Work paired terminal original facts differ")
        return True
    def accounting_v3(self,verifier):
        r=self.reader;r.require_current_v3()
        if verifier._db is not r.db or (verifier._resource,verifier._budget)!=(
                r.graph._GraphCoordinator__d02_issuer,r.graph._GraphCoordinator__d11_issuer):
            raise AuthorityUnavailable("D13 verifier accounting authorities crossed actual installed Work")
        from .issuers import _decode_quote,_decode_grant
        verifier._resource._signer.verify("resource-quote.v1",*self.quote_row)
        verifier._budget._signer.verify("budget-grant.v1",*self.grant_row)
        return _decode_quote(self.quote_row[0]),_decode_grant(self.grant_row[0]),self.reservation,(self.cost_rows["settle"][2],)
    def verify_v3(self):
        r=self.reader
        from ..authority_service.d13_paid_block_verifier_v1 import build_installed_d13_paid_block_verifier_v1
        verifier=build_installed_d13_paid_block_verifier_v1(r.db,installation=self.saved.frozen.installation,
            resource_issuer=r.graph._GraphCoordinator__d02_issuer,budget_issuer=r.graph._GraphCoordinator__d11_issuer,
            max_slots=r.window_policy.max_slots)
        if verifier.verify_current_paid_model_block_v2(replace(self.block,status="candidate"),
                plan=self.saved.frozen.plan,window=r.current_window)is not True:
            raise AuthorityUnavailable("D13 actual installed paid verifier rejected current completed body")
        self.value=CurrentD13CompletedPaidBlockV3(self.saved,tuple(self.cost_rows[p] for p in ("reserve","settle")),
            self.block,r.current_window,self.metadata,True)
        r.complete=True
        from .d13_paid_original_read_v3 import PreparedD13PaidOriginalReadV3,_ISSUER
        r.proof=PreparedD13PaidOriginalReadV3(_ISSUER,r)

def current_completed_d13_reader_v3(db):
    from .d13_paid_original_read_v3 import d13_paid_current_reader_v3
    r=d13_paid_current_reader_v3(db)
    if r is None or r.method!=COMPLETED_READ_V3:return None
    if r.completed_read is None or not r.qualified:
        raise AuthorityUnavailable("D13 completed verifier requires its actual named Source READ Work")
    r.require_current_v3()
    return r.completed_read

def read_bound_d13_completed_job_v3(db,job_id):
    from .d13_paid_original_read_v3 import d13_paid_current_reader_v3
    r=d13_paid_current_reader_v3(db)
    if r is None or r.method!=COMPLETED_READ_V3:return False,None
    if r.completed_read.job is None or job_id!=r.job_id:
        raise AuthorityUnavailable("D13 completed job consumer crossed exact qualified actual job")
    return True,r.completed_read.job
