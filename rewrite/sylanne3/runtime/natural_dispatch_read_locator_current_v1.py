"""Exact Natural P2 locator consumer; no initial-reader or Source grant issuer."""
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime
from enum import Enum
import sys
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphReceipt, NamespaceEpoch
from ..memory_types import source_key, access_key
from .natural_dispatch_read_locator_v1 import (
    RECIPE_SCHEMA_V1, project_natural_dispatch_frozen_metadata_v1,
    project_natural_dispatch_admitted_sources_v1,
)
from .owner_material_source_storage_v3 import CanonicalValueStreamV3

_SCHEMA="sylanne.natural_dispatch_read_locator.v1"
_AUTH_SCHEMA="sylanne.natural_final_authorization_original.v4"
_ISSUER=object()
_ISSUED=WeakKeyDictionary()
_WRAPPER=frozenset({"schema","profile_version","metadata","metadata_byte_count","metadata_sha256"})
_METADATA=frozenset({"schema","profile_version","namespace","operation_id","activity_id","effect_id",
    "admission_ref","original_utc_deadline","bundle_digest","admission_digest","admission_receipt_digest",
    "candidate_digest","request_digest","graph_receipt_commitment","graph_incarnation","graph_revision",
    "graph_epoch","generation_seal_digest","review_seal_digest","scoped_proof_digest",
    "authorization_original_digest","source_originals","final_job","recipe"})
_AUTH_PAYLOAD=frozenset({"schema","namespace","identity","candidate_digest","bundle_digest","graph_receipt",
    "graph_receipt_commitment","admission_ref","admission_digest","admission_receipt_digest","request_digest",
    "scope","owner_guard","clock_reading","clock_policy","now_utc","current_effect","effect_snapshot","route",
    "snapshot_versions","snapshot_epochs","snapshot_commitment","query","projection","checks_digest","owner_issue_original",
    "clock_validation","clock_uses","effect_observation","budget_observation","context_catalogue","graph_barrier"})
_FINAL_JOB=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref",
    "phase","work_kind","deadline_utc","budget_ref","resource_ref","fence","cancel_epoch")
_PAID_FIELDS=("generation_original_operation_id","generation_call_id","generation_model_call_request_digest",
    "generation_terminal_receipt_digest","generation_output_digest","generation_reservation_operation_id",
    "review_original_operation_id","review_call_id","review_model_call_request_digest",
    "review_terminal_receipt_digest","review_output_digest","review_reservation_operation_id",
    "parent_budget_lease_id","review_policy_version","current_graph_guard_digest","receipt_digest")
_RECIPE=frozenset({"schema","kind","namespace","variant","generation_parent_original_id",
    "generation_original_operation_id","generation_job_id","generation_c02_operation_id",
    "generation_original_header","commitments","committed_selection","admission","action","batch",
    "semantic_child","plan","frozen_at_utc","expires_at_utc","question","stable_history","history_selection",
    "recent_history","detail_history","stable_turns","source_groups","expected_scoped_d06_projection",
    "required_producer_joins"})
_PROFILES={"dispatch_context_32":("context",32),"dispatch_expression_32":("expression",32),
    "producer_expression_256":("expression",256),"material_expression_256":("expression",256)}


def _exact(value,keys,label):
    if type(value)is not dict or set(value)!=set(keys):
        raise AuthorityUnavailable("Natural locator "+label+" complete keyset differs")


class _PlainDataclassCanonicalStreamV1(CanonicalValueStreamV3):
    """Original plain/typed canonical forms with a reusable live-frame arena."""
    def __init__(self,value,operation,*,plain=True):
        self.operation,self.plain=operation,plain
        self.live_bytes=self.peak_bytes=0
        super().__init__(value)

    def _enter_frame(self,size):
        wanted=self.live_bytes+size
        if wanted>self.peak_bytes:
            self.operation.retain(wanted-self.peak_bytes)
            self.peak_bytes=wanted
        self.live_bytes=wanted

    def _value(self,value,meter_getter=None):
        typed=is_dataclass(value)and not isinstance(value,type)
        frame=0
        try:
            if not self.plain and isinstance(value,AtomKey):
                size=4096+sum(len(part)for part in (value.owner.kind,value.owner.bot,
                    value.owner.persona,value.type_name,value.name,value.owner.subject or ""))*24
                self._enter_frame(size);frame+=size
                value={"$type":"AtomKey","token":value.token}
            elif typed:
                type_name=type(value).__module__+"."+type(value).__qualname__
                names=fields(value)
                size=2048+len(names)*192
                self._enter_frame(size);frame+=size
                value={field.name:getattr(value,field.name)for field in names}
                if not self.plain:value={"$type":type_name,**value}
            elif isinstance(value,Enum):
                value=value.value
            if type(value)is dict:
                extra=512+len(value)*32
                self._enter_frame(extra);frame+=extra
                if any(type(key)is not str for key in value):
                    raise TypeError("actual canonical object requires string keys")
                names=sorted(value)
                yield b"{"
                for index,name in enumerate(names):
                    if index:yield b","
                    yield from self._quoted(name,meter_getter);yield b":"
                    yield from self._value(value[name],meter_getter)
                yield b"}"
            elif type(value)in(list,tuple):
                self._enter_frame(256);frame+=256
                yield b"["
                for index,item in enumerate(value):
                    if index:yield b","
                    yield from self._value(item,meter_getter)
                yield b"]"
            else:
                yield from CanonicalValueStreamV3._value(value,meter_getter)
        finally:
            self.live_bytes-=frame


class _NaturalDispatchLocatorOriginalJoinsV1:
    """Shared read-only joins; each owner keeps its separate private issuer."""
    def _joins(self,meter):
        from .d11_types import runtime_job_key
        owner=self.owner;inventory=self.inventory;db=owner.db;ns=owner.namespace
        history=inventory.natural_history;m=self.metadata
        generation=owner.auxiliary.natural
        inventory.natural_originals.require_for_v3(db,ns,generation.parent_original_id,"generation")
        review_original=inventory.natural_review_originals
        review_original.require_for_v3(db,ns,generation.parent_original_id,"review")
        review=review_original.saved
        if review is None:raise AuthorityUnavailable("actual fully typed terminal review original absent")
        self.evidence=owner.auxiliary.natural_evidence
        refs=tuple((item[0],item[1])for item in owner.auxiliary.natural_candidate["refs"])
        values=[]
        for ref,revision in refs:
            value,valid=history.read_history_json_v3(db,ns,ref,revision,owner.request.activity_id,owner.request.operation_id)
            if valid!=1:raise AuthorityUnavailable("Natural locator actual producing member is invalid")
            values.append(value)
        action,schema,grant,batch=values
        admission_original=inventory.admission_originals
        admission=admission_original.receipt_v3();request=admission_original.request_v3();a=admission.admission
        reads,revisions,epoch=history.event_v3(db,ns,request.activity_id,request.operation_id)
        invalidated=history.event_versions["invalidated"]
        graph_receipt=GraphReceipt("committed",revisions,invalidated,NamespaceEpoch(*ns.as_tuple,epoch))
        scope=inventory.natural_scope_original.read_v3(db,generation)
        self.auth=self.receipt.get("natural_final_authorization_original")
        _exact(self.auth,{"schema","payload","original_digest"},"authorization wrapper")
        p=self.auth["payload"]
        _exact(p,_AUTH_PAYLOAD,"authorization payload")
        if(self.auth["schema"]!=_AUTH_SCHEMA or type(p)is not dict or p.get("schema")!=_AUTH_SCHEMA
                or self.auth["original_digest"]!=m["authorization_original_digest"]):
            raise AuthorityUnavailable("actual Natural auth V4 original absent or differs")
        identity={"activity_id":request.activity_id,"operation_id":request.operation_id,"effect_id":request.effect_id}
        if(any(m[name]!=value for name,value in identity.items())
                or m["namespace"]!=asdict(ns) or m["admission_ref"]!=a.admission_ref
                or m["original_utc_deadline"]!=a.utc_deadline
                or m["graph_incarnation"]!=inventory.graph_stamp[0].requirements.graph_incarnation
                or m["graph_revision"]!=admission.graph_revision or m["graph_epoch"]!=epoch
                or m["graph_epoch"]!=admission.graph_epoch
                or (m["bundle_digest"],m["activity_id"],m["effect_id"])!=history.bundle[:3]
                or m["admission_digest"]!=admission_original.header[2]
                or m["admission_receipt_digest"]!=admission.receipt_digest
                or m["request_digest"]!=a.request_digest):
            raise AuthorityUnavailable("Natural locator actual graph/admission/identity differs")
        if(any(p.get(name)!=m[name]for name in ("bundle_digest","admission_digest","admission_receipt_digest",
                    "candidate_digest","request_digest","graph_receipt_commitment"))
                or p.get("namespace")!=asdict(ns) or p.get("identity")!=action["identity"]
                or p.get("graph_receipt")!=asdict(graph_receipt)
                or p.get("admission_ref")!=a.admission_ref
                or p["scope"]["graph_revision"]+1!=admission.graph_revision
                or p["scope"]["graph_epoch"]["revision"]+1!=epoch
                or p["graph_barrier"]!={"graph_incarnation":m["graph_incarnation"],
                    "access_epoch":self.evidence.access_epoch,"delete_epoch":self.evidence.delete_epoch,
                    "graph_revision":admission.graph_revision-1,"graph_epoch":epoch}):
            raise AuthorityUnavailable("Natural locator differs from its actual authorization originals")
        final_job=m["final_job"];_exact(final_job,{"job_ref",*_FINAL_JOB},"final job")
        job_ref=final_job["job_ref"]
        if(runtime_job_key(ns.bot_id,ns.persona_id,request.activity_id,final_job["job_id"]).token!=job_ref
                or any(final_job[name]!=value for name,value in identity.items())
                or (final_job["bot_id"],final_job["persona_id"])!=ns.as_tuple
                or final_job["work_kind"]!="message" or final_job["phase"]!="waiting"
                or final_job["fence"]!=0 or final_job["cancel_epoch"]!=0
                or final_job["budget_ref"]!=a.budget_parent_lease_ref
                or datetime.fromisoformat(a.utc_deadline.replace("Z","+00:00")).timestamp()
                    >datetime.fromisoformat(final_job["deadline_utc"].replace("Z","+00:00")).timestamp()
                or owner.now_utc>=datetime.fromisoformat(final_job["deadline_utc"].replace("Z","+00:00")).timestamp()):
            raise AuthorityUnavailable("actual final message job identity/deadline/phase differs")
        current=meter.read_fixed_row(db,"runtime_jobs",_FINAL_JOB,"job_id=?",(final_job["job_id"],))
        if current is None or tuple(current)!=tuple(final_job[name]for name in _FINAL_JOB):
            raise AuthorityUnavailable("Natural locator final job current fixed scalar head differs")
        job_key=AtomKey.from_token(job_ref)
        if not any(v.key==job_key and v.revision>0 for v in revisions):
            raise AuthorityUnavailable("Natural locator final job is not in its actual producing event")
        paid=batch["paid_review"]
        paid_actual={"generation_original_operation_id":generation.seal.original_operation_id,
            "generation_call_id":generation.seal.call_id,
            "generation_terminal_receipt_digest":generation.terminal_receipt_digest,
            "generation_output_digest":generation.terminal_output_digest,
            "generation_reservation_operation_id":generation.seal.reservation_operation_id,
            "review_original_operation_id":review.seal.original_operation_id,
            "review_call_id":review.seal.call_id,
            "review_terminal_receipt_digest":review.terminal_receipt_digest,
            "review_output_digest":review.terminal_output_digest,
            "review_reservation_operation_id":review.seal.reservation_operation_id,
            "parent_budget_lease_id":generation.seal.parent_budget_lease_id}
        if any(paid.get(name)!=value for name,value in paid_actual.items()):
            raise AuthorityUnavailable("Natural locator actual generation/review paid originals differ")
        self.final_job_key,self.final_job_values=final_job["job_id"],tuple(current)
        recipe=m["recipe"];_exact(recipe,_RECIPE,"recipe")
        frozen=project_natural_dispatch_frozen_metadata_v1(generation,admission=admission)
        groups=list(frozen["source_groups"])
        groups.insert(1,project_natural_dispatch_admitted_sources_v1(self.evidence,admission=admission,
            original_graph_reads=reads))
        joins=list(frozen["required_producer_joins"])
        semantic=None
        if batch["schema"]=="d09.natural_verified_segment_batch.v3":
            manifest=batch["semantic_manifest"]
            semantic={"selected_index":manifest["selected_index"],"root_operation_id":manifest["root_operation_id"],
                "root_effect_id":manifest["root_effect_id"],"plan_ref":dict(manifest["plan_ref"]),
                "generation_output_digest":batch["paid_review"]["generation_output_digest"],
                "roster":[{name:part[name]for name in ("operation_id","effect_id","segment_id","position","payload_digest")}
                    for part in manifest["segments"]]}
            joins.insert(4,"actual_paid_whole_output_and_roster_child_original")
        for name,value in frozen.items():
            if name not in {"source_groups","commitments","required_producer_joins"}and recipe[name]!=value:
                raise AuthorityUnavailable("Natural locator saved frozen metadata differs: "+name)
        commitments={**frozen["commitments"],"candidate_digest":m["candidate_digest"],
            "admission_receipt_digest":admission.receipt_digest,"request_digest":a.request_digest}
        expected={
            "schema":RECIPE_SCHEMA_V1,"kind":"unsealed_producer_metadata_recipe","namespace":asdict(ns),
            "commitments":commitments,"source_groups":groups,"required_producer_joins":joins,
            "semantic_child":semantic,
            "committed_selection":{"operation_id":request.operation_id,"activity_id":request.activity_id,
                "effect_id":request.effect_id,"attempt_id":request.attempt_id,"admission_ref":a.admission_ref,
                "candidate_writes":[{"ref":ref,"version":rev}for ref,rev in refs],
                "admission_graph_revision":admission.graph_revision,"graph_epoch":epoch,
                "graph_incarnation":a.graph_incarnation,"original_utc_deadline":a.utc_deadline,
                "clock_policy_ref":a.clock_policy_ref,"clock_policy_digest":a.clock_policy_digest,
                "bundle_source_refs":list(self.evidence.source_refs),"access_epoch":self.evidence.access_epoch,
                "delete_epoch":self.evidence.delete_epoch,"query_epoch":self.evidence.query_epoch},
            "admission":{name:getattr(a,name)for name in ("schema","purpose","account_ref","destination_ref",
                "scene_ref","action_ref","segment_index")} | {"audience":list(a.audience)},
            "action":{"identity":{name:action["identity"][name]for name in
                ("activity_id","effect_id","attempt_id","phase","operation_id","canonical_input_digest")},
                **{name:action[name]for name in ("action_id","action_kind","target_ref","purpose")},
                "source_refs":list(action["source_refs"])},
            "batch":{"schema":batch["schema"],"scene_id":batch["scene_id"],"audience_id":batch["audience_id"],
                "source_ref":dict(batch["source_ref"]),"valid_until":batch["valid_until"],
                "cancellation_epoch":batch["cancellation_epoch"],"batch_digest":batch["batch_digest"],
                "segment_id":batch["segment"]["segment_id"],"payload_digest":batch["segment"]["payload_digest"],
                "segment_position":batch["segment"]["position"],"segment_count":len(grant["segment_grants"]),
                "paid_review":{name:batch["paid_review"][name]for name in _PAID_FIELDS}}}
        for name,value in expected.items():
            if recipe[name]!=value:raise AuthorityUnavailable("Natural locator actual committed metadata differs: "+name)
        self.recipe=recipe
        # Type-tagged graph/candidate/scope and asdict seals use their original
        # public canonical forms. Each stream advances under the same real meter.
        self.digests=[
            ("generation_seal_digest",asdict(generation.seal),False),
            ("review_seal_digest",asdict(review.seal),False),
            ("scoped_proof_digest",scope,True),
            ("graph_receipt_commitment",graph_receipt,True),
            ("candidate_digest",self.evidence,"asdict"),
            ("authorization_original_digest",p,False)]
        self.phase="original_digests"
        rows=m["source_originals"]
        if type(rows)is not list:raise AuthorityUnavailable("Natural locator Source EOF identity inventory differs")
        for row in rows:
            _exact(row,{"ref","version","cell_id","byte_count","sha256","producer_operation_id"},"Source original")
            if row["ref"]in self.source_rows:raise AuthorityUnavailable("Natural locator repeats Source identity")
            self.source_rows[row["ref"]]=row
        if [row["ref"]for row in rows]!=sorted(self.source_rows):
            raise AuthorityUnavailable("Natural locator Source inventory order differs")
        owner.operation.retain(65536+len(self.source_rows)*1024)


class NaturalDispatchReadLocatorCurrentV1(_NaturalDispatchLocatorOriginalJoinsV1):
    """All digest work and each Source qualification advance in the same real Work."""
    def __init__(self,owner):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3,PreparedCurrentDispatchInventoryV3
        if(type(owner)is not _DispatchInventoryReadV3 or owner.family!="natural_reply"
                or type(owner.result)is not PreparedCurrentDispatchInventoryV3 or not owner.auxiliary.complete):
            raise AuthorityUnavailable("actual completed Natural P2 inventory owner required")
        self.owner,self.inventory=owner,owner.result
        from .natural_dispatch_p2_read_v1 import require_natural_p2_source_all_v1
        self.source_all = require_natural_p2_source_all_v1(owner,owner.db)
        self.phase="original";self.stream=None;self.result=None
        self.source_rows={};self.seen_sources=set();self.group_members=[]
        self.group_index=0;self.active=set();self.done=set()
        self.walk_frames=[];self.next_ref=None;self.roots=();self.root_index=0
        self.expected={};self.group_started=False;self.walk_peak_bytes=0
        self.metadata=self.wrapper=self.recipe=self.original=self.auth=self.receipt=None
        self.digest_index=0;self.digests=[]

    def _original(self,meter):
        owner=self.owner;inventory=self.inventory;db=owner.db;ns=owner.namespace
        inventory.require_current(db,ns,inventory.query)
        history=inventory.natural_history
        receipt=history.receipt_v3(db,ns,owner.binding.operation_id)
        self.original=history.original
        self.source_all.require_current_v1(owner,db)
        original_metadata = self.source_all.metadata
        if (self.original.sha256,self.original.byte_count) != (
                original_metadata.original_sha,original_metadata.original_bytes):
            raise AuthorityUnavailable("Natural P2 complete receipt differs from its pre-Body metadata EOF")
        self.receipt=receipt
        if(not self.original.complete or self.original.byte_count<1
                or type(self.original.sha256)is not str or len(self.original.sha256)!=64):
            raise AuthorityUnavailable("Natural locator lacks actual complete receipt EOF/SHA")
        wrapper=receipt.get("natural_dispatch_read_locator")
        _exact(wrapper,_WRAPPER,"wrapper")
        if(wrapper["schema"]!=_SCHEMA or type(wrapper["profile_version"])is not int
                or wrapper["profile_version"]!=1 or type(wrapper["metadata_byte_count"])is not int
                or wrapper["metadata_byte_count"]<1 or type(wrapper["metadata_sha256"])is not str
                or len(wrapper["metadata_sha256"])!=64
                or any(ch not in "0123456789abcdef"for ch in wrapper["metadata_sha256"])):
            raise AuthorityUnavailable("Natural locator exact schema/profile/hash differs; legacy HOLD")
        metadata=wrapper["metadata"];_exact(metadata,_METADATA,"metadata")
        if metadata != self.source_all.metadata.metadata:
            raise AuthorityUnavailable("Natural P2 full original metadata differs from its Source barrier")
        if metadata["schema"]!=_SCHEMA or type(metadata["profile_version"])is not int or metadata["profile_version"]!=1:
            raise AuthorityUnavailable("Natural locator metadata profile differs")
        self.wrapper,self.metadata=wrapper,metadata
        self.stream=CanonicalValueStreamV3(metadata);self.phase="metadata_digest"


    def _reserve_walk(self,extra=0):
        """Reserve reusable workspace capacity, never cumulative edge allocations."""
        current=(sys.getsizeof(self.expected)+sys.getsizeof(self.active)+sys.getsizeof(self.done)
            +sys.getsizeof(self.walk_frames)+sum(sys.getsizeof(frame)for frame in self.walk_frames)
            +sys.getsizeof(self.roots)+4096)
        if self.next_ref is not None:current+=sys.getsizeof(self.next_ref)
        wanted=current+extra
        if wanted>self.walk_peak_bytes:
            self.owner.operation.retain(wanted-self.walk_peak_bytes)
            self.walk_peak_bytes=wanted

    def _source(self,meter):
        from ..domains.d06 import source_correction_head_key
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        owner=self.owner;inventory=self.inventory
        groups=self.recipe["source_groups"]
        if self.group_index==len(groups):
            if self.seen_sources!=set(self.source_rows):
                raise AuthorityUnavailable("Natural locator complete Source union differs")
            self.result=_PreparedNaturalReadLocatorV1(_ISSUER,self);self.phase="complete";return
        group=groups[self.group_index]
        if not self.group_started:
            profile=_PROFILES.get(group["source_walk_profile"])
            if profile is None or group["purpose"]!=profile[0]:
                raise AuthorityUnavailable("Natural locator exact Source profile differs")
            self.limit=profile[1]
            if len(group["source_versions"])>self.limit:
                raise AuthorityUnavailable("Natural locator original Source root limit differs")
            self._reserve_walk(1024+len(group["source_versions"])*160)
            self.expected={row["ref"]:row["version"]for row in group["source_versions"]}
            if len(self.expected)!=len(group["source_versions"]):
                raise AuthorityUnavailable("Natural locator repeats original Source roots")
            self.roots=tuple(self.expected);self.root_index=0;self.group_started=True
            self._reserve_walk()
            return
        # One frame retains the original parent tuple and a cursor. Only the
        # next edge token exists outside the already retained metadata.
        if self.next_ref is None:
            if self.walk_frames:
                frame=self.walk_frames[-1]
                if frame[2]==len(frame[1]):
                    self.walk_frames.pop();self.active.remove(frame[0]);self.done.add(frame[0])
                    self._reserve_walk()
                    return
                parent=frame[1][frame[2]]
                self._reserve_walk(2048+(len(parent)+len(owner.namespace.bot_id)+len(owner.namespace.persona_id))*24)
                self.next_ref=source_key(*owner.namespace.as_tuple,parent).token
                frame[2]+=1
                self._reserve_walk()
                return
            if self.root_index<len(self.roots):
                self.next_ref=self.roots[self.root_index];self.root_index+=1
                self._reserve_walk()
                return
            owner.operation.retain(256+len(self.done)*64)
            self.group_members.append((group["purpose"],tuple(group["audience"]),frozenset(self.done)))
            self.group_index+=1;self.group_started=False
            self.active=set();self.done=set();self.expected={};self.roots=()
            self._reserve_walk()
            return
        ref=self.next_ref;self.next_ref=None
        if ref in self.active:raise AuthorityUnavailable("Natural locator Source ancestry cycle")
        if ref in self.done:return
        if len(self.active)+len(self.done)>=self.limit:
            raise AuthorityUnavailable("Natural locator Source closure exceeds original profile")
        key=AtomKey.from_token(ref)
        source=inventory.source_metadata(owner.db,owner.namespace,inventory.query,key,require_grant=False)
        expected=self.source_rows.get(ref)
        actual={"ref":ref,"version":source.revision,"cell_id":source.cell_id,
            "byte_count":source.header[3],"sha256":source.payload_sha256,"producer_operation_id":source.header[2]}
        if expected!=actual or ref in self.expected and source.revision!=self.expected[ref]:
            raise AuthorityUnavailable("Natural locator actual Source cell/version/SHA/count/producer differs")
        if key!=source_key(*owner.namespace.as_tuple,key.owner.subject or ""):
            raise AuthorityUnavailable("Natural locator Source namespace differs")
        access=inventory.projection.get(access_key(*owner.namespace.as_tuple,key.owner.subject))
        correction=inventory.projection.get(source_correction_head_key(owner.namespace,key.owner.subject))
        record=None
        for audience in group["audience"]:
            record=_qualify_source_rights_values_v3(owner.namespace,ref,source,access,correction,
                audience=audience,purpose=group["purpose"],metadata_only=True)
            if record is None:raise AuthorityUnavailable("Natural locator Source purpose/current access/correction differs")
        if record is None:raise AuthorityUnavailable("Natural locator Source audience is absent")
        if len(record.parent_source_ids)>self.limit:
            raise AuthorityUnavailable("Natural locator Source ancestors exceed original family bound")
        meter.charge_encode(512)
        # active/done refer to the canonical string already owned by the
        # actual receipt, rather than keeping a duplicate token for every edge.
        canonical_ref=expected["ref"]
        self._reserve_walk(2048)
        self.seen_sources.add(canonical_ref);self.active.add(canonical_ref)
        self.walk_frames.append([canonical_ref,record.parent_source_ids,0])
        self._reserve_walk()

    def advance(self,meter):
        self.inventory.require_current(self.owner.db,self.owner.namespace,self.inventory.query)
        if self.phase=="original":self._original(meter)
        elif self.phase=="metadata_digest":
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if(self.stream.hash.hexdigest(),self.stream.offset)!=(self.wrapper["metadata_sha256"],self.wrapper["metadata_byte_count"]):
                    raise AuthorityUnavailable("Natural locator canonical metadata SHA/count differs")
                self.stream=None;self.phase="joins"
        elif self.phase=="joins":self._joins(meter)
        elif self.phase=="original_digests":
            if self.digest_index==len(self.digests):self.phase="sources";return False
            name,value,typed=self.digests[self.digest_index]
            if self.stream is None:
                if typed=="asdict":
                    self.stream=_PlainDataclassCanonicalStreamV1(value,self.owner.operation)
                elif typed:
                    self.stream=_PlainDataclassCanonicalStreamV1(value,self.owner.operation,plain=False)
                else:self.stream=CanonicalValueStreamV3(value)
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if self.stream.hash.hexdigest()!=self.metadata[name]:
                    raise AuthorityUnavailable("Natural locator actual original canonical digest differs: "+name)
                self.stream=None;self.digest_index+=1
        elif self.phase=="sources":self._source(meter)
        elif self.phase!="complete":raise AuthorityUnavailable("Natural locator phase differs")
        return self.phase=="complete"


class _PreparedNaturalReadLocatorV1:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or reader.phase!="sources"or reader.group_index!=len(reader.recipe["source_groups"]):
            raise AuthorityUnavailable("actual complete Natural locator issuer required")
        self.inventory=reader.inventory;self.owner=reader.owner
        self.original=reader.original
        self.receipt_sha,self.receipt_bytes=reader.original.sha256,reader.original.byte_count
        self.metadata_sha,self.metadata_bytes=reader.wrapper["metadata_sha256"],reader.wrapper["metadata_byte_count"]
        self.groups=tuple(reader.group_members);self.sources=frozenset(reader.seen_sources)
        self.job_key,self.job_values=reader.final_job_key,reader.final_job_values
        _ISSUED[self]=(self.inventory,self.owner,self.original,self.receipt_sha,self.receipt_bytes,
            self.metadata_sha,self.metadata_bytes,self.groups,self.sources,self.job_key,self.job_values)

    def require_v1(self,inventory,db):
        if(_ISSUED.get(self)!=(self.inventory,self.owner,self.original,self.receipt_sha,self.receipt_bytes,
                self.metadata_sha,self.metadata_bytes,self.groups,self.sources,self.job_key,self.job_values)
                or inventory is not self.inventory or db is not self.owner.db or self.owner.operation.closed):
            raise AuthorityUnavailable("actual retained Natural locator proof changed")
        inventory.require_current(db,inventory.namespace,inventory.query)
        from .dispatch_initial_source_read_v3 import _COLUMNS
        original=self.original
        if _COLUMNS.get(original)!=(self.owner,original.table,original.column,original.key,
                self.receipt_sha,self.receipt_bytes,original._frozen_value):
            raise AuthorityUnavailable("Natural locator original full receipt EOF changed")
        row=db.execute("SELECT "+",".join(_FINAL_JOB)+" FROM runtime_jobs WHERE job_id=?",(self.job_key,)).fetchone()
        if row is None or tuple(row)!=self.job_values:
            raise AuthorityUnavailable("Natural locator actual final job scalar changed")
        return self

    def release_payload_v1(self):
        _ISSUED.pop(self,None)
        self.inventory=self.owner=self.original=self.groups=self.sources=self.job_values=None


def require_natural_dispatch_read_locator_v1(inventory,db):
    from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
    if type(inventory)is not PreparedCurrentDispatchInventoryV3 or inventory.family!="natural_reply":
        raise AuthorityUnavailable("exact Natural P2 inventory required for locator")
    proof=inventory.natural_read_locator
    if type(proof)is not _PreparedNaturalReadLocatorV1:
        raise AuthorityUnavailable("actual Natural locator consumer proof absent; legacy HOLD")
    return proof.require_v1(inventory,db)


def require_natural_locator_source_metadata_v1(inventory,db,key,*,purpose,audiences,revision=None):
    """Source-only lookup for this exact P2 owner; cannot bind an initial reader."""
    proof=require_natural_dispatch_read_locator_v1(inventory,db)
    if not any(purpose==p and tuple(audiences)==a and key.token in members for p,a,members in proof.groups):
        raise AuthorityUnavailable("Natural Source is outside its exact consumed purpose group")
    return inventory.source_metadata(db,inventory.namespace,inventory.query,key,revision=revision,require_grant=False)
