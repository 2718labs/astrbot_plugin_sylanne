"""Fixed Beta1 receipt metadata EOF on the actual installed worker and READ permit.

This reader releases digests and finite state fields only. It grants no Source
or model-body access; those stay with the original production result readers.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from weakref import WeakKeyDictionary
import codecs
import json
import math
import secrets
import sys

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.graph_types import AtomKey, GraphVersion
from sylanne3.graph_worker import (GraphStorageStepV3, GraphStorageWorkV3,
    create_graph_storage_work_v3, require_graph_storage_work_admission_v3)
from sylanne3.runtime_storage_v3 import (begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, begin_runtime_cell_read_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, runtime_storage_v3)
from sylanne3.runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from sylanne3.runtime.first_ingress_v2 import trusted_upper
from sylanne3.runtime.d11_types import RuntimeJobValue
from sylanne3.runtime_contracts import CompressedTurnBlockV2
from sylanne3.domains.d13.derived_block_metadata_v2 import DerivedBlockMetadataV2

KIND = "host_beta1_fixture_evidence_read"
_ISSUER = object()
_READERS = WeakKeyDictionary()
_ALLOWED_TYPES = frozenset({"runtime.job", "d13.compressed_turn_block.v2",
    "d13.derived_block_metadata.v2"})
_ROOT_FIELDS = {"runtime.job": frozenset(RuntimeJobValue.__dataclass_fields__),
    "d13.compressed_turn_block.v2": frozenset(CompressedTurnBlockV2.__dataclass_fields__),
    "d13.derived_block_metadata.v2": frozenset(DerivedBlockMetadataV2.__dataclass_fields__)}
_RETAINED = frozenset({"phase", "status", "expires_at_utc", "job_id", "job_ref",
    "fence", "cancel_epoch", "result_ref", "deadline_utc", "lease_holder",
    "lease_expires_utc", "schema", "payload_digest", "paid_original_digest",
    "paid_evidence_digest", "paid_settlement_digest", "block_ref", "conversation_ref",
    "paid_original_operation_id", "candidate_ref", "compiler_version", "payload_length_bytes"}) | frozenset(RuntimeJobValue.__dataclass_fields__)


@dataclass(frozen=True, slots=True)
class Beta1FixtureEvidenceRequestV3:
    versions: tuple[GraphVersion, ...]
    producing_operation_ids: tuple[str, ...]
    event_scopes: tuple[tuple[str, str, str, str], ...]
    original_deadline_utc: float

    def __post_init__(self):
        if (type(self.versions) is not tuple or not 1 <= len(self.versions) <= 128
                or any(type(v) is not GraphVersion or v.revision < 1
                    or v.key.type_name not in _ALLOWED_TYPES for v in self.versions)
                or len({(v.key.token,v.revision) for v in self.versions}) != len(self.versions)
                or type(self.producing_operation_ids) is not tuple
                or not 1 <= len(self.producing_operation_ids) <= 128
                or any(type(v) is not str or not v for v in self.producing_operation_ids)
                or len(set(self.producing_operation_ids)) != len(self.producing_operation_ids)
                or type(self.event_scopes) is not tuple
                or len(self.event_scopes) != len(self.versions)
                or any(type(scope) is not tuple or len(scope) != 4
                    or any(type(item) is not str or not item for item in scope)
                    or scope[3] not in self.producing_operation_ids for scope in self.event_scopes)
                or {scope[3] for scope in self.event_scopes} != set(self.producing_operation_ids)
                or type(self.original_deadline_utc) not in (int,float)
                or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("exact finite Beta1 receipt metadata request required")


@dataclass(frozen=True, slots=True)
class Beta1ExactNumericJobMetadataRequestV3:
    job_id: str
    original_deadline_utc: float
    versions: tuple = ()
    producing_operation_ids: tuple = ()
    event_scopes: tuple = ()
    reservation_donor_selector: tuple | None = None

    def __post_init__(self):
        if (self.reservation_donor_selector is not None and
                (type(self.reservation_donor_selector)is not tuple or len(self.reservation_donor_selector)!=5
                or any(type(v)is not str or not v for v in self.reservation_donor_selector[:2])
                or type(self.reservation_donor_selector[2])is not int or self.reservation_donor_selector[2]!=1
                or type(self.reservation_donor_selector[3])is not str or not self.reservation_donor_selector[3]
                or type(self.reservation_donor_selector[4])is not int or self.reservation_donor_selector[4]<1)):
            raise ValueError("fixed actual normal Content quote selector required")
        if (type(self.job_id)is not str or not self.job_id or len(self.job_id.encode("utf8"))>4096
                or self.versions or self.producing_operation_ids or self.event_scopes
                or type(self.original_deadline_utc) not in (int,float)
                or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("exact Numeric job metadata selector required")


@dataclass(frozen=True,slots=True)
class Beta1ExactD13JobMetadataRequestV3(Beta1ExactNumericJobMetadataRequestV3):
    """Exact job metadata only; frozen paid request/body is never loaded here."""


@dataclass(frozen=True,slots=True)
class Beta1NumericJobAbsenceMetadataRequestV3:
    identity_result_reference: object
    identity_value: object
    original_deadline_utc: float
    versions: tuple = ()
    producing_operation_ids: tuple = ()
    event_scopes: tuple = ()
    reservation_donor_selector: None = None

    def __post_init__(self):
        from sylanne3.model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1
        if (type(self.identity_result_reference)is not GraphStorageWorkV3
                or type(self.identity_value)is not InternalLifeNumericIdentityV1
                or self.versions or self.producing_operation_ids or self.event_scopes
                or self.reservation_donor_selector is not None
                or type(self.original_deadline_utc)not in(int,float)or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("retained actual Numeric identity result reference required")

    @property
    def job_id(self):
        from sylanne3.model_broker.internal_life_numeric_v1 import internal_life_numeric_ids_v1
        return internal_life_numeric_ids_v1(self.identity_value)["job"]


@dataclass(frozen=True,slots=True)
class Beta1NumericAcceptedMetadataRequestV3:
    job_id: str
    adopt_receipt: object
    expected_before_digest: str
    original_deadline_utc: float
    versions: tuple = ()
    producing_operation_ids: tuple = ()
    event_scopes: tuple = ()
    reservation_donor_selector: None = None

    def __post_init__(self):
        from sylanne3.runtime_contracts import CommitReceipt,NamespaceId
        receipt=self.adopt_receipt
        if(type(receipt)is not CommitReceipt or receipt.status!="committed"
                or self.job_id!="life-numeric-job:"+receipt.operation_id.removeprefix("life-numeric-adopt:")
                or not receipt.operation_id.startswith("life-numeric-adopt:")or len(receipt.write_versions)!=2
                or self.versions or self.producing_operation_ids or self.event_scopes or self.reservation_donor_selector is not None
                or type(self.expected_before_digest)is not str or len(self.expected_before_digest)!=64
                or any(c not in "0123456789abcdef"for c in self.expected_before_digest)
                or type(self.original_deadline_utc)not in(int,float)or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("exact real Numeric adopt receipt metadata selectors required")
        appraisal=tuple(v for v in receipt.write_versions if v.key.type_name=="d04.appraisal_bundle.v1"and v.revision==1)
        jobs=tuple(v for v in receipt.write_versions if v.key.type_name=="runtime.job"and v.revision==3)
        if len(appraisal)!=1 or len(jobs)!=1 or NamespaceId.from_key(appraisal[0].key)!=NamespaceId.from_key(jobs[0].key):
            raise ValueError("Numeric adopt metadata requires its exact two typed receipt members")

    @property
    def appraisal_ref(self):
        return next(v.key.token for v in self.adopt_receipt.write_versions if v.key.type_name=="d04.appraisal_bundle.v1")


def _require_numeric_absence_identity_result_v3(graph,authority,bundle,request,now):
    from sylanne3.runtime.current_life_numeric_read_v3 import IDENTITY_READ_V3,NUMERIC_READ_WORK_KIND_V3,_NumericReadResultV3
    from sylanne3.runtime.current_method_learning_read_v3 import _READERS
    from sylanne3.runtime.d06_life_numeric_context_v1 import life_numeric_context_ids_v1
    work=request.identity_result_reference;r=work.state
    if (work.coordinator is not graph or work.kind!=NUMERIC_READ_WORK_KIND_V3
            or r not in _READERS or r.work is not work or r.graph is not graph
            or r.operation_kind!=IDENTITY_READ_V3 or not r.complete or not r.read_finished
            or r.operation.closed or type(r.result)is not _NumericReadResultV3
            or r.result.require_result_v3(work)is not request.identity_value
            or r.numeric_read_value is not request.identity_value
            or request.identity_value.namespace!=authority.namespace or r.namespace!=authority.namespace
            or r.request.episode_ref!=request.identity_value.episode_ref
            or r.graph_stamp!=graph._v2_graph_stamp(authority.namespace)
            or r.operation.handle is not runtime_storage_v3(graph._GraphCoordinator__store._db)
            or r.operation.selection_digest!=work.selection_digest or now>=r.operation.deadline_utc
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
        raise AuthorityUnavailable("Numeric absence selector lost its actual retained identity result")
    return r.activity_id,life_numeric_context_ids_v1(authority.namespace,r.request.episode_ref)["original"]


class _Beta1ExactNumericJobMetadataV3:
    # These are fixed metadata recipes. No Source, Life payload, model body,
    # budget receipt JSON or arbitrary SQL selector is returned by this reader.
    _JOB_COLUMNS=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref",
        "phase","work_kind","continuation_json","wake_condition_json","deadline_utc","budget_ref","resource_ref",
        "operator_versions_json","lease_holder","lease_expires_utc","fence","cancel_epoch","usage_json","result_ref")

    def __init__(self,reader):
        self.reader=reader;self.phase="job";self.job=None;self.job_metadata=None;self.operation_id=None
        self.token=None;self.head=None;self.versions=[];self.scopes=[]
        self.block_token=None;self.block_head=None;self.payload_presence=None
        self.rows={};self.scan_index=0;self.cursor=None;self.count=0;self.root="0"*64
        self.inventory={};self.balances=[];self.grants={};self.namespace_reservations=[];self.reservation_donor=None;self.reservation_donors=[];self.donor_index=0;self.paid_metadata={};self.paid_index=0;self.namespace_settlements=0;self.complete=False

    def _next_row_v3(self,meter,table,columns,where,args,keys):
        if self.cursor is not None:
            where+=" AND ("+",".join(keys)+")>("+",".join("?"for _ in keys)+")"
            args=(*args,*self.cursor)
        where+=" ORDER BY "+",".join(keys)
        row=meter.read_fixed_row(self.reader.db,table,columns,where,args)
        if row is not None:self.cursor=tuple(row[columns.index(key)]for key in keys)
        return row

    def _numeric_job_v3(self,row):
        from sylanne3.runtime.jobs import _job_from_row
        from sylanne3.model_broker.internal_life_numeric_v1 import WORK_KIND
        job=_job_from_row(row)
        d13=type(self.reader.request)is Beta1ExactD13JobMetadataRequestV3
        if d13:
            from sylanne3.runtime.d13_precompression_job import PAID_WORK_KIND
            fields={"schema","input_digest","conversation_ref","first_sequence","last_sequence","candidate_ref",
                "plan","plan_digest","job_ref","original_operation_id","call_id","binding_digest","frozen_input_digest",
                "wire_digest","read_closure_digest","installation_id","provider_id","model_id","provider_config_digest","max_output_tokens"}
            allowed=job.work_kind==PAID_WORK_KIND and set(job.continuation)==fields
        else:
            allowed=(job.work_kind==WORK_KIND and set(job.continuation)=={"episode_ref","causal_operation_id","numeric_input_digest"}
                and all(type(value)is str and value for value in job.continuation.values()))
        if (job.job_id!=self.reader.request.job_id or (job.bot_id,job.persona_id)!=self.reader.authority.namespace.as_tuple or not allowed):
            raise AuthorityUnavailable("fixed exact installed job metadata identity differs")
        return job

    def advance_v3(self,meter):
        from sylanne3.runtime_contracts import canonical_digest
        from sylanne3.runtime.d11_types import runtime_job_key
        from sylanne3.runtime.jobs import _job_dict
        from sylanne3.runtime.d06_life_numeric_context_v1 import life_numeric_context_ids_v1
        r=self.reader;db=r.db;ns=r.authority.namespace.as_tuple
        if self.phase=="job":
            row=meter.read_fixed_row(db,"runtime_jobs",self._JOB_COLUMNS,
                "job_id=? AND bot_id=? AND persona_id=?",(r.request.job_id,*ns))
            if row is None:raise AuthorityUnavailable("exact current Numeric job is absent")
            self.job=self._numeric_job_v3(row);self.operation_id=self.job.operation_id
            scalar_names=("job_id","operation_id","activity_id","bot_id","persona_id","work_kind","budget_ref",
                "resource_ref","deadline_utc","lease_holder","lease_expires_utc","fence","cancel_epoch","phase","result_ref")
            self.job_metadata=tuple((name,getattr(self.job,name))for name in scalar_names)
            self.job_digest=canonical_digest(_job_dict(self.job))
            self.token=runtime_job_key(*ns,self.job.activity_id,self.job.job_id).token
            self.head=meter.read_fixed_row(db,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(self.token,*ns))
            if self.head is None or self.head[1]!=1:raise AuthorityUnavailable("exact Numeric job projection is absent")
            self.phase="paid" if type(r.request)is Beta1ExactD13JobMetadataRequestV3 else "history";return
        if self.phase=="paid":
            points=(("intent","graph_d13_paid_intent_originals_v1",("operation_id","original_digest")),
                ("call","graph_d13_paid_call_originals_v1",("call_id","original_digest")),
                ("schedule","graph_d13_paid_schedule_inputs_v1",("payload_digest","pending")))
            name,table,columns=points[self.paid_index]
            row=meter.read_fixed_row(db,table,columns,"bot=? AND persona=? AND job_ref=?",(*ns,self.job.job_id))
            self.paid_metadata[name]=None if row is None else tuple(row)
            self.paid_index+=1
            if self.paid_index==len(points):self.phase="history"
            return
        if self.phase=="history":
            row=self._next_row_v3(meter,"graph_history",("revision","valid","event_bot","event_persona","event_session","event_id"),
                "token=?",(self.token,),("revision",))
            if row is not None:
                if tuple(row[2:4])!=ns or row[0]>self.head[0] or row[1]not in(0,1):
                    raise AuthorityUnavailable("exact Numeric job history metadata differs")
                self.versions.append(GraphVersion(AtomKey.from_token(self.token),row[0]));self.scopes.append(tuple(row[2:]));return
            if not self.versions or self.versions[-1].revision!=self.head[0]:
                raise AuthorityUnavailable("exact Numeric job lacks complete current history")
            self.cursor=None;self.phase=("block_head" if type(r.request)is Beta1ExactD13JobMetadataRequestV3
                and self.job.phase=="completed" and self.job.result_ref else "rows");return
        if self.phase=="block_head":
            from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
            from sylanne3.host.model_workflows_v7 import AdminModelWorkflowsV7
            from sylanne3.host.model_workflows_v8 import AdminModelWorkflowsV8
            from sylanne3.model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as V6
            from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as V7
            from sylanne3.graph_types import Owner
            wf=r.bundle.model_workflows
            derived=(type(wf)is AdminModelWorkflowsV6 and wf.natural_generation is not None
                and wf.natural_generation.template_version==V6 or type(wf)in{AdminModelWorkflowsV7,AdminModelWorkflowsV8}
                and wf.natural_generation is not None and wf.natural_generation.template_version==V7)
            kind="d13.derived_block_metadata.v2"if derived else "d13.compressed_turn_block.v2"
            self.block_token=AtomKey(Owner("persona",*ns),kind,self.job.result_ref).token
            self.block_head=meter.read_fixed_row(db,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(self.block_token,*ns))
            if self.block_head is None or self.block_head[1]!=1:
                raise AuthorityUnavailable("exact completed job result metadata head unavailable")
            self.phase="payload_presence"if derived else "block_history";return
        if self.phase=="payload_presence":
            self.payload_presence=meter.read_fixed_row(db,"graph_d11_derived_cache_payloads_v1",("payload_digest",),
                "bot=? AND persona=? AND block_ref=?",(*ns,self.job.result_ref))
            self.phase="block_history";return
        if self.phase=="block_history":
            row=self._next_row_v3(meter,"graph_history",("revision","valid","event_bot","event_persona","event_session","event_id"),
                "token=?",(self.block_token,),("revision",))
            if row is not None:
                if tuple(row[2:4])!=ns or row[0]>self.block_head[0]or row[1]not in(0,1):
                    raise AuthorityUnavailable("exact completed result metadata history crossed namespace/header")
                self.versions.append(GraphVersion(AtomKey.from_token(self.block_token),row[0]));self.scopes.append(tuple(row[2:]));return
            if self.versions[-1].key.token!=self.block_token or self.versions[-1].revision!=self.block_head[0]:
                raise AuthorityUnavailable("exact completed result metadata lacks full head history EOF")
            self.cursor=None;self.phase="rows";return
        accounting=(("runtime_budget_leases",("lease_id","parent_id","currency","limits_json","used_json","reserved_json",
                "unconfirmed_json","version","state"),"bot_id=? AND persona_id=?",ns,("lease_id",)),
            ("runtime_budget_grants",("lease_id","version","grant_json","signature","status"),
                "lease_id IN(SELECT lease_id FROM runtime_budget_leases WHERE bot_id=? AND persona_id=?)",ns,("lease_id","version")),
            ("runtime_budget_operations",("operation_id","phase","digest","lease_id"),
                "bot_id=? AND persona_id=?",ns,("operation_id","phase")),
            ("runtime_budget_reservations",("lease_id","operation_id","digest","ceiling_json","state","actual_json"),
                "lease_id IN(SELECT lease_id FROM runtime_budget_leases WHERE bot_id=? AND persona_id=?)",ns,("lease_id","operation_id")))
        if self.phase=="rows":
            recipes=(("job_operations","runtime_job_operations",("phase","operation_id","digest","job_id","job_json"),
                    "bot_id=? AND persona_id=? AND job_id=?",(*ns,self.job.job_id),("operation_id","phase")),
                ("registrations","graph_bundle_refs",("bot","persona","operation_id","ref_kind","ref"),
                    "bot=? AND persona=? AND ref=?",(*ns,self.token),("operation_id","ref_kind","ref")),
                ("originals","graph_d11_life_originals_v1",("kind","original_ref","producing_operation_id","payload_digest","signature"),
                    "bot=? AND persona=? AND original_ref=?",(*ns,self.job.job_id),("kind","original_ref")),
                ("budget","runtime_budget_operations",("phase","digest","lease_id","operation_id"),
                    "bot_id=? AND persona_id=? AND operation_id=?",(*ns,self.job.operation_id),("phase",)),
                ("reservation","runtime_budget_reservations",("lease_id","operation_id","digest","ceiling_json","state","actual_json"),
                    "operation_id=? AND lease_id IN(SELECT lease_id FROM runtime_budget_leases WHERE bot_id=? AND persona_id=?)",
                    (self.job.operation_id,*ns),("lease_id","operation_id")),
                ("context_original","graph_d11_life_originals_v1",("kind","original_ref","producing_operation_id","payload_digest","signature"),
                    "bot=? AND persona=? AND kind='numeric_context_v1' AND original_ref=?",
                    (*ns,life_numeric_context_ids_v1(
                        r.authority.namespace,self.job.continuation["episode_ref"])["original"]if type(r.request)is not Beta1ExactD13JobMetadataRequestV3 else ""), ("kind","original_ref")))
            if type(r.request)is Beta1ExactD13JobMetadataRequestV3:recipes=recipes[:-1]
            name,table,columns,where,args,keys=recipes[self.scan_index]
            row=self._next_row_v3(meter,table,columns,where,args,keys)
            if row is not None:
                row=list(row)
                if name=="job_operations":
                    saved=json.loads(row[4])
                    from sylanne3.runtime.jobs import PersistentJob
                    original=PersistentJob(**saved)
                    from sylanne3.runtime_contracts import canonical_serialize
                    if row[4]!=canonical_serialize(saved):
                        raise AuthorityUnavailable("Numeric job-operation metadata lacks canonical full JSON EOF")
                    if (original.job_id!=self.job.job_id or (original.bot_id,original.persona_id)!=ns
                            or original.work_kind!=self.job.work_kind):
                        raise AuthorityUnavailable("Numeric job-operation original crossed exact job")
                    row[4]=(len(row[4].encode("utf8")),sha256(row[4].encode("utf8")).hexdigest(),canonical_digest(saved))
                elif name in {"originals","context_original"}:
                    from sylanne3.runtime.d11_life_preparation_v1 import SIGN_KIND
                    from sylanne3.runtime_contracts import canonical_serialize
                    r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                        canonical_serialize((r.authority.namespace,row[0],row[1],row[3])),row[4])
                    row[4]=sha256(row[4].encode("utf8")).hexdigest()
                self.rows.setdefault(name,[]).append(tuple(row));return
            self.rows.setdefault(name,[]);self.scan_index+=1;self.cursor=None
            if self.scan_index==len(recipes):self.phase="accounting";self.scan_index=0
            return
        if self.phase=="accounting":
            table,columns,where,args,keys=accounting[self.scan_index]
            row=self._next_row_v3(meter,table,columns,where,args,keys)
            if row is not None:
                self.count+=1;self.root=canonical_digest((self.root,tuple(row)))
                if table=="runtime_budget_leases":
                    self.balances.append((row[0],row[2],*(json.loads(value)for value in row[3:7]),row[7],row[8]))
                elif table=="runtime_budget_grants" and row[4]=="active":
                    from sylanne3.runtime.issuers import _decode_grant
                    issuer=r.graph._GraphCoordinator__d11_issuer
                    issuer._signer.verify("budget-grant.v1",row[2],row[3])
                    grant=_decode_grant(row[2])
                    if (grant.bot_id,grant.persona_id)!=ns or (grant.lease_id,grant.version)!=(row[0],row[1]):
                        raise AuthorityUnavailable("namespace budget grant metadata differs from actual signer/lease")
                    self.grants[row[0]]=dict(lease_id=grant.lease_id,version=grant.version,grant_id=grant.grant_id,
                        allowed_work_kinds=grant.allowed_work_kinds,valid_until_utc=grant.valid_until_utc,
                        grant_digest=canonical_digest(grant))
                elif table=="runtime_budget_operations" and row[1]=="settle" and row[0]!=self.operation_id:
                    self.namespace_settlements+=1
                elif table=="runtime_budget_reservations" and row[4]=="reserved" and row[1]!=self.operation_id:
                    self.namespace_reservations.append(tuple(row))
                return
            self.inventory[table]=(self.count,self.root,tuple(self.balances))
            self.count=0;self.root="0"*64;self.balances=[];self.cursor=None;self.scan_index+=1
            if self.scan_index==len(accounting):self.phase="donor"
            return
        if self.phase=="donor":
            selector=r.request.reservation_donor_selector
            if selector is not None and self.donor_index==0:
                self.donor_index=1;operation,quote_id,version,operation_digest,commit_seq=selector
                root=r.bundle.installation_policy.root_grant.lease_id
                reservations=[row for row in self.namespace_reservations if(row[0],row[1])==(root,operation)]
                if len(reservations)!=1:raise AuthorityUnavailable("actual normal Content once reservation donor unavailable; HOLD")
                reservation=reservations[0]
                row=meter.read_fixed_row(db,"runtime_resource_quotes",("quote_id","version","quote_json","signature","status"),
                    "quote_id=? AND version=? AND status='active' AND json_type(quote_json,'$.job_continuation')='null'",
                    (quote_id,version))
                if row is None:raise AuthorityUnavailable("actual normal Content quote metadata selector unavailable or nonempty continuation; HOLD")
                from sylanne3.runtime.issuers import _decode_quote
                from sylanne3.model_broker.internal_life_content_v1 import WORK_KIND
                resource=r.graph._GraphCoordinator__d02_issuer
                resource._signer.verify("resource-quote.v1",row[2],row[3]);quote=_decode_quote(row[2])
                if ((quote.quote_id,quote.version,quote.operation_id,quote.parent_budget_lease_ref,quote.bot_id,quote.persona_id,quote.work_kind)
                        !=(quote_id,version,operation,root,*ns,WORK_KIND)or quote.job_continuation is not None):
                    raise AuthorityUnavailable("normal Content receipt/quote/namespace/Root linkage changed")
                from sylanne3.runtime_contracts import canonical_serialize,PERSISTENT_JOB_REF_KIND
                from sylanne3.runtime.d11_types import runtime_job_key
                committed=meter.read_fixed_row(db,"graph_bundle_operations",("digest","commit_seq","activity_id","effect_id"),
                    "bot=? AND persona=? AND operation_id=?",(*ns,operation))
                budget=meter.read_fixed_row(db,"runtime_budget_operations",("digest","lease_id"),
                    "bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",(*ns,operation))
                registered=meter.read_fixed_row(db,"graph_bundle_refs",("operation_id",),
                    "bot=? AND persona=? AND ref_kind=? AND ref=?",(*ns,PERSISTENT_JOB_REF_KIND,quote.graph_job_ref))
                if(committed!=(operation_digest,commit_seq,quote.activity_id,quote.effect_id)
                        or budget!=(reservation[2],root)or registered!=(operation,)
                        or row[2]!=canonical_serialize(quote)or dict(quote.ceiling)!=json.loads(reservation[3])
                        or quote.graph_job_ref is None or AtomKey.from_token(quote.graph_job_ref).type_name!="runtime.job"):
                    raise AuthorityUnavailable("normal Content receipt/registered job/quote/once reserve linkage changed")
                if quote.valid_until_utc<=trusted_upper(r.initial_clock)or quote.deadline_utc<=trusted_upper(r.initial_clock):
                    raise AuthorityUnavailable("actual normal Content quote donor expired; HOLD")
                self.reservation_donor=dict(signed_quote_id=quote.quote_id,quote_version=quote.version,lease_id=reservation[0],
                    reservation_operation_id=reservation[1],reservation_digest=reservation[2],state=reservation[4],
                    ceiling=json.loads(reservation[3]),deadline_utc=quote.deadline_utc,valid_until_utc=quote.valid_until_utc,
                    quote_digest=canonical_digest(quote))
                self.reservation_donors.append(self.reservation_donor);return
            r.versions=tuple(self.versions);r.evidence_scopes=tuple(self.scopes)
            r.metadata_allowset=tuple((v.key.token,v.revision,v.key.type_name)for v in r.versions)
            _READERS[r]=r.identity_v3();self.complete=True

    def result_v3(self,eof_rows):
        from sylanne3.runtime.d11_types import job_value
        from sylanne3.runtime_contracts import canonical_digest
        job_rows=tuple(row for row in eof_rows if row.token==self.token)
        block_rows=tuple(row for row in eof_rows if row.token==self.block_token)
        if (not self.complete or len(eof_rows)!=len(self.versions)or not job_rows
                or job_rows[-1].revision!=self.head[0] or not job_rows[-1].valid
                or job_rows[-1].canonical_semantic_digest!=canonical_digest(job_value(self.job))):
            raise AuthorityUnavailable("actual exact Numeric job metadata and full projection EOF disagree")
        return dict(job=self.job_metadata,job_digest=self.job_digest,accounting_inventory=dict(self.inventory),
            signed_budget_metadata=tuple(self.grants[key]for key in sorted(self.grants)),reservation_donor=self.reservation_donor,
            reservation_donors=tuple(self.reservation_donors),
            paid_metadata=dict(self.paid_metadata),namespace_preceding_settlement_count=self.namespace_settlements,
            **{name:tuple(rows)for name,rows in self.rows.items()},
            block_metadata=None if not block_rows else dict(token=self.block_token,
                revision=self.block_head[0],valid=bool(self.block_head[1]),payload_presence=self.payload_presence,
                current_fields=block_rows[-1].metadata,histories=tuple((row.revision,row.valid,row.event_scope,
                    row.payload_sha256,row.canonical_semantic_digest,row.byte_count,tuple(sorted(row.fields_seen)))for row in block_rows)),
            projection=((job_rows[-1].revision,job_rows[-1].canonical_semantic_digest,job_rows[-1].valid),),
            history=tuple((row.revision,row.valid,row.event_scope,row.payload_sha256,row.canonical_semantic_digest,
                row.byte_count)for row in job_rows))


class _Beta1NumericJobAbsenceMetadataV3(_Beta1ExactNumericJobMetadataV3):
    def __init__(self,reader):
        super().__init__(reader)
        from sylanne3.model_broker.internal_life_numeric_v1 import internal_life_numeric_ids_v1
        from sylanne3.runtime.d11_types import runtime_job_key
        ids=internal_life_numeric_ids_v1(reader.request.identity_value)
        self.operation_id=ids["prepare"];self.phase="absence_job"
        activity,context=reader.absence_identity_selector
        self.token=runtime_job_key(*reader.authority.namespace.as_tuple,activity,ids["job"]).token
        self.context_ref=context;self.context_metadata=None

    def advance_v3(self,meter):
        r=self.reader;ns=r.authority.namespace.as_tuple
        if self.phase=="absence_job":
            if meter.read_fixed_row(r.db,"runtime_jobs",("job_id",),"job_id=? AND bot_id=? AND persona_id=?",(r.request.job_id,*ns))is not None:
                raise AuthorityUnavailable("Numeric prepare absence target already has an actual job")
            self.phase="absence_head";return
        if self.phase=="absence_head":
            if meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),"token=?",(self.token,))is not None:
                raise AuthorityUnavailable("Numeric prepare absence target already has a projection header")
            self.phase="absence_context";return
        if self.phase=="absence_context":
            row=meter.read_fixed_row(r.db,"graph_d11_life_originals_v1",("kind","original_ref","producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind='numeric_context_v1' AND original_ref=?",(*ns,self.context_ref))
            if row is None or row[3]!=r.request.identity_value.context_digest:
                raise AuthorityUnavailable("Numeric absence target signed context header changed")
            self.context_metadata=(*row[:4],sha256(row[4].encode("utf8")).hexdigest())
            self.phase="accounting";return
        return super().advance_v3(meter)

    def result_v3(self,eof_rows):
        if not self.complete or eof_rows:raise AuthorityUnavailable("fixed Numeric target absence metadata incomplete")
        return dict(schema="sylanne.beta1.numeric-job-absence-metadata.v3",namespace=self.reader.authority.namespace.as_tuple,
            expected_job_id=self.reader.request.job_id,expected_prepare_operation_id=self.operation_id,
            identity_digest=self.reader.request.identity_value.digest,job_absent=True,projection_absent=True,
            context_original=(self.context_metadata,),accounting_inventory=dict(self.inventory))


class _Beta1NumericAcceptedMetadataV3(_Beta1ExactNumericJobMetadataV3):
    """One signed accepted original, with its body skipped across actual quanta."""
    _SUMMARY=frozenset({"operation_id","job_id","before_digest","appraisal_ref","appraisal_revision",
        "context_digest","prepared_digest","result_original_ref","result_original_digest","cost_original_ref","cost_original_digest","schema"})

    def __init__(self,reader):
        super().__init__(reader)
        self.acceptance_phase="header";self.acceptance_fields=set();self.acceptance_values={};self.acceptance_scalar=bytearray()
        self.acceptance_header=None;self.acceptance_total=None;self.acceptance_offset=0;self.acceptance_fragment=b""
        self.acceptance_parser=None;self.appraisal_cell=None;self.appraisal_parser=None;self.appraisal_digest=None
        self.appraisal_semantic_decoder=None;self.appraisal_semantic_hash=None
        from sylanne3.authority_service.c09_authority_storage_rebase_v2 import _D13PaidEncodedStringStreamV3
        self.inner_decoder=_D13PaidEncodedStringStreamV3(ensure_ascii=True)
        self.inner_parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.inner_digest=None;self.appraisal_header=None

    def _emit_acceptance_v3(self,event):
        if event.kind=="key"and len(event.path)==1:self.acceptance_fields.add(event.key)
        if event.path==("appraisal_value_json",):
            if event.kind=="scalar_chunk":
                self.inner_decoder.feed(event.raw,lambda child:None)
                if self.inner_decoder.pending:
                    self.inner_parser.feed(bytes(self.inner_decoder.pending),lambda child:None);self.inner_decoder.pending.clear()
            elif event.kind=="scalar_end":
                self.inner_decoder.finish();self.inner_digest=self.inner_parser.finish().sha256
            return
        if event.path in{("namespace","bot_id"),("namespace","persona_id")}:
            name="namespace_"+event.path[-1]
        elif len(event.path)==1 and event.path[0]in self._SUMMARY:name=event.path[0]
        else:return
        if event.kind=="scalar_start":self.acceptance_scalar=bytearray()
        elif event.kind=="scalar_chunk":self.acceptance_scalar.extend(event.raw)
        elif event.kind=="scalar_end":
            self.acceptance_values[name]=json.loads(self.acceptance_scalar);self.acceptance_scalar=bytearray()

    def _appraisal_semantic_v3(self,chunk,*,final=False):
        if self.appraisal_semantic_decoder is None:return
        text=self.appraisal_semantic_decoder.decode(chunk,final=final)
        encoded=[]
        for char in text:
            point=ord(char)
            if point<127:encoded.append(char)
            elif point<=65535:encoded.append(chr(92)+"u"+format(point,"04x"))
            else:
                point-=65536;encoded.append(chr(92)+"u"+format(55296+(point>>10),"04x")+chr(92)+"u"+format(56320+(point&1023),"04x"))
        raw="".join(encoded).encode("ascii")
        from sylanne3.runtime_contracts import current_canonical_output_meter
        meter=current_canonical_output_meter()
        if meter is not None:meter.charge_encode(len(raw))
        self.appraisal_semantic_hash.update(raw)

    def advance_v3(self,meter):
        r=self.reader;req=r.request;ns=r.authority.namespace.as_tuple
        if self.phase!="rows"or self.acceptance_phase=="done":return super().advance_v3(meter)
        from sylanne3.runtime_contracts import canonical_serialize
        receipt=req.adopt_receipt
        if self.acceptance_phase=="header":
            if self.job.phase!="completed"or self.head[0]!=3 or not any(v.key.token==self.token and v.revision==3 for v in receipt.write_versions):
                raise AuthorityUnavailable("Numeric accepted metadata lacks its exact completed job receipt")
            committed=meter.read_fixed_row(r.db,"graph_bundle_operations",("digest","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*ns,receipt.operation_id))
            if committed!=(receipt.operation_digest,receipt.commit_seq):raise AuthorityUnavailable("Numeric adopt metadata producer/commit header changed")
            row=meter.read_fixed_row(r.db,"graph_d11_life_originals_v1",("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1' AND original_ref=?",(*ns,req.appraisal_ref))
            if row is None or row[0]!=receipt.operation_id:raise AuthorityUnavailable("Numeric accepted signed original header absent")
            from sylanne3.runtime.d11_life_preparation_v1 import SIGN_KIND
            r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((r.authority.namespace,"numeric_appraisal_acceptance_v1",req.appraisal_ref,row[1])),row[2])
            self.acceptance_header=row;self.acceptance_parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
            self.acceptance_phase="length";return
        if self.acceptance_phase=="length":
            meter.require_available(1024)
            row=r.db.execute("SELECT typeof(payload_json),length(CAST(payload_json AS BLOB)) FROM graph_d11_life_originals_v1 "
                "WHERE bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1' AND original_ref=?",(*ns,req.appraisal_ref)).fetchone()
            meter.charge_read(16)
            if row is None or row[0]!="text":raise AuthorityUnavailable("fixed accepted metadata JSON column disappeared")
            self.acceptance_total=row[1];self.acceptance_phase="original";return
        if self.acceptance_phase=="original":
            if self.acceptance_fragment:
                part=self.acceptance_fragment[:1024];self.acceptance_parser.feed(part,self._emit_acceptance_v3)
                self.acceptance_fragment=self.acceptance_fragment[len(part):];return
            if self.acceptance_offset<self.acceptance_total:
                from sylanne3.runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table="graph_d11_life_originals_v1",column="payload_json",
                    where="bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1' AND original_ref=?",parameters=(*ns,req.appraisal_ref),
                    start=self.acceptance_offset,length=min(16384,self.acceptance_total-self.acceptance_offset),meter=meter)
                if(total,kind)!=(self.acceptance_total,"text"):raise AuthorityUnavailable("accepted metadata original byte identity changed")
                self.acceptance_offset+=len(chunk);self.acceptance_fragment=chunk;return
            actual=self.acceptance_parser.finish()
            from sylanne3.runtime.d06_life_numeric_task_v1 import LifeNumericAppraisalAcceptanceV1
            summary=self.acceptance_values
            if(actual.sha256!=self.acceptance_header[1]or actual.byte_count!=self.acceptance_total
                    or self.acceptance_fields!=set(LifeNumericAppraisalAcceptanceV1.__dataclass_fields__)
                    or self.inner_digest is None or set(summary)!=self._SUMMARY|{"namespace_bot_id","namespace_persona_id"}
                    or (summary["namespace_bot_id"],summary["namespace_persona_id"])!=ns
                    or type(summary["appraisal_revision"])is not int
                    or any(type(summary[name])is not str for name in self._SUMMARY-{"appraisal_revision"})
                    or summary["schema"]!="d04.life-numeric-appraisal-acceptance.v1"
                    or (summary["operation_id"],summary["job_id"],summary["before_digest"],summary["appraisal_ref"],summary["appraisal_revision"])
                        !=(receipt.operation_id,req.job_id,req.expected_before_digest,req.appraisal_ref,1)
                    or (summary["cost_original_ref"],summary["result_original_ref"])!=(req.job_id,req.job_id)):
                raise AuthorityUnavailable("accepted metadata full signed canonical EOF/closed summary changed")
            self.acceptance_phase="appraisal_header";return
        if self.acceptance_phase=="appraisal_header":
            head=meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),"token=?",(req.appraisal_ref,))
            history=meter.read_fixed_row(r.db,"graph_history",("value_cell_id","valid","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=1",(req.appraisal_ref,))
            if head is None or head[:2]!=(1,1)or history is None or history[0]!=head[2]or history[1]!=1 or tuple(history[2:4])!=ns or history[5]!=receipt.operation_id:
                raise AuthorityUnavailable("accepted appraisal metadata head/history lacks its real producer")
            self.appraisal_header=(head,history);self.appraisal_cell=begin_runtime_cell_read_v3(r.db,head[2],erasure_owner_ref=req.appraisal_ref)
            header=self.appraisal_cell.header
            if header[1]!=req.appraisal_ref or header[2]!=receipt.operation_id or header[0]not in{"canonical-json.ascii.v1","canonical-json.utf8.v1"}:
                raise AuthorityUnavailable("accepted appraisal metadata cell header crossed its receipt")
            utf8=header[0]=="canonical-json.utf8.v1";self.appraisal_parser=C09CanonicalJSONStreamV2(ensure_ascii=not utf8)
            if utf8:self.appraisal_semantic_decoder=codecs.getincrementaldecoder("utf8")("strict");self.appraisal_semantic_hash=sha256()
            self.acceptance_phase="appraisal";return
        if self.acceptance_fragment:
            part=self.acceptance_fragment[:1024];self.appraisal_parser.feed(part,lambda event:None);self._appraisal_semantic_v3(part)
            self.acceptance_fragment=self.acceptance_fragment[len(part):];return
        chunk=self.appraisal_cell.read_fragment(meter=meter)
        if chunk is not None:self.acceptance_fragment=chunk;return
        parsed=self.appraisal_parser.finish();physical=self.appraisal_cell.finish(meter=meter)
        self._appraisal_semantic_v3(b"",final=True)
        semantic=physical if self.appraisal_semantic_hash is None else self.appraisal_semantic_hash.hexdigest()
        if(parsed.sha256,parsed.byte_count)!=(physical,self.appraisal_cell.header[3])or semantic!=self.inner_digest:
            raise AuthorityUnavailable("accepted appraisal current cell full EOF differs from signed accepted commitment")
        self.appraisal_digest=(physical,semantic,parsed.byte_count);self.acceptance_phase="done"

    def extra_heap_v3(self):
        from sylanne3.runtime.source_correction_read_v3 import _heap
        size=_heap((self.acceptance_values,self.acceptance_fields,self.acceptance_scalar,self.acceptance_fragment,
            self.acceptance_header,self.appraisal_header,self.appraisal_digest,self.inner_decoder.__dict__))
        for parser in(self.acceptance_parser,self.appraisal_parser,self.inner_parser,self.inner_decoder):
            if parser is None:continue
            size+=sys.getsizeof(parser)+_heap((parser._string,parser._literal,parser._number,parser._active_scalar))
            for f in parser._stack:size+=sys.getsizeof(f)+_heap((f.kind,f.path,f.state,f.previous_key,f.current_key,f.index))
        return size

    def result_v3(self,eof_rows):
        if self.acceptance_phase!="done":raise AuthorityUnavailable("accepted Numeric metadata EOF incomplete")
        value=super().result_v3(eof_rows)
        value["acceptance_metadata"]=dict(self.acceptance_values)
        value["acceptance_original_metadata"]=("numeric_appraisal_acceptance_v1",self.reader.request.appraisal_ref,
            self.acceptance_header[0],self.acceptance_header[1],sha256(self.acceptance_header[2].encode("utf8")).hexdigest())
        value["appraisal_metadata_eof"]=self.appraisal_digest
        if tuple(row[0]for row in value["budget"])!=("reserve","settle"):
            raise AuthorityUnavailable("accepted metadata requires actual original reserve/settle phases")
        if not any(row[0]=="numeric_paid_v1"for row in value["originals"]):
            raise AuthorityUnavailable("accepted metadata lacks its actual signed paid original header")
        return value


@dataclass(frozen=True, slots=True)
class Beta1FixtureMetadataEOFV3:
    token: str
    revision: int
    valid: bool
    event_scope: tuple[str,str,str,str]
    payload_sha256: str
    canonical_semantic_digest: str
    byte_count: int
    fields_seen: frozenset[str]
    metadata: tuple[tuple[str,object], ...]


class _Beta1EvidenceParserHeapV3:
    def __init__(self, reader):self.reader=reader
    def _runtime_retained_heap_bytes_v3(self):
        from sylanne3.runtime.source_correction_read_v3 import _heap
        parser=self.reader.parser
        size=sys.getsizeof(self)
        if parser is not None:
            size+=sys.getsizeof(parser)+_heap((parser._string,parser._literal,
                parser._number,parser._active_scalar))+sys.getsizeof(parser._stack)
            for frame in parser._stack:
                size+=sys.getsizeof(frame)+_heap((frame.kind,frame.path,frame.state,
                    frame.previous_key,frame.current_key,frame.index))
        return size


class _Beta1FixtureEvidenceReadV3:
    def __init__(self, issuer, graph, authority, lease, bundle, request,
                 operation, fence, initial_clock, verified_manifest, package_root):
        if issuer is not _ISSUER:
            raise TypeError("actual fixed Beta1 evidence reader factory required")
        self.graph = graph
        self.runtime = graph._GraphCoordinator__domain_production_runtime_v1
        self.store = graph._GraphCoordinator__store
        self.db = self.store._db
        self.authority, self.lease, self.bundle = authority, lease, bundle
        self.request, self.operation, self.fence = request, operation, fence
        self.read_scope = fence.scope
        self.graph_stamp = (fence.metadata,fence.epoch)
        self.initial_clock = initial_clock
        self.original_deadline_utc = request.original_deadline_utc
        self.expected_owner_binding = graph._GraphCoordinator__owner_leases[lease]
        self.owner_principal = self.expected_owner_binding.principal
        self.owner_session_proof = graph._GraphCoordinator__owner_session_proofs[lease]
        self.package_root = package_root
        self.manifest_digest = bundle.installation_policy.manifest_digest
        self.verified_manifest = verified_manifest
        self.versions=request.versions;self.evidence_scopes=request.event_scopes
        self.absence_identity_selector=(_require_numeric_absence_identity_result_v3(graph,authority,bundle,request,
            trusted_upper(initial_clock))if type(request)is Beta1NumericJobAbsenceMetadataRequestV3 else None)
        self.snapshot=(_Beta1NumericJobAbsenceMetadataV3(self)if self.absence_identity_selector is not None else
            _Beta1NumericAcceptedMetadataV3(self)if type(request)is Beta1NumericAcceptedMetadataRequestV3 else
            _Beta1ExactNumericJobMetadataV3(self)if type(request)in(Beta1ExactNumericJobMetadataRequestV3,Beta1ExactD13JobMetadataRequestV3)else None)
        self.metadata_allowset=tuple((v.key.token,v.revision,v.key.type_name)for v in self.versions)
        self.work = self.owner_entry = None
        self.index = 0
        self.row = self.cell = self.parser = None
        self.scalar = bytearray()
        self.values = {}
        self.fields_seen = set()
        self.semantic_decoder = self.semantic_hash = None
        self.fragment = b""
        self.offset = 0
        self.rows = []
        self.complete = False
        self.registered = False
        self.parser_heap = _Beta1EvidenceParserHeapV3(self)
        self.parser_registered = False

    def identity_v3(self):
        return (self.graph,self.runtime,self.store,self.db,self.authority,self.lease,
            self.bundle,self.request,self.operation,self.fence,self.read_scope,self.graph_stamp,
            self.initial_clock,self.original_deadline_utc,self.expected_owner_binding,
            self.owner_principal,self.owner_session_proof,self.package_root,
            self.manifest_digest,self.verified_manifest,self.metadata_allowset,self.work)

    def _runtime_retained_heap_bytes_v3(self):
        from sylanne3.runtime.source_correction_read_v3 import _heap
        values=(self.request,self.metadata_allowset,self.row,self.scalar,self.values,
            self.fields_seen,self.fragment,self.rows,
            None if self.snapshot is None else (self.snapshot.phase,self.snapshot.rows,self.snapshot.versions,
                self.snapshot.scopes,self.snapshot.cursor,self.snapshot.inventory,self.snapshot.balances,
                self.snapshot.grants,self.snapshot.namespace_reservations,self.snapshot.reservation_donor,self.snapshot.reservation_donors,self.snapshot.paid_metadata,
                self.snapshot.block_token,self.snapshot.block_head,self.snapshot.payload_presence,
                getattr(self.snapshot,"context_metadata",None),self.absence_identity_selector,
                self.snapshot.job_metadata,None if self.snapshot.job is None else tuple(
                    getattr(self.snapshot.job,name)for name in self.snapshot.job.__dataclass_fields__)))
        size=_heap(values)+sys.getsizeof(self)
        if type(self.snapshot)is _Beta1NumericAcceptedMetadataV3:size+=self.snapshot.extra_heap_v3()
        size+=sys.getsizeof(self.request)+_heap((self.request.producing_operation_ids,self.request.event_scopes,
            self.request.original_deadline_utc))
        for version in self.versions:
            size+=sys.getsizeof(version)+_heap((version.key.token,version.revision))
        for row in self.rows:
            size+=sys.getsizeof(row)+_heap((row.token,row.revision,row.valid,row.event_scope,
                row.payload_sha256,row.canonical_semantic_digest,row.byte_count,
                row.fields_seen,row.metadata))
        if self.cell is not None:
            size+=sys.getsizeof(self.cell)+_heap((self.cell.cell_id,self.cell.header,
                self.cell.root,self.cell.ordinal,self.cell.offset))+sys.getsizeof(self.cell.hash)
        if self.semantic_decoder is not None:
            size+=sys.getsizeof(self.semantic_decoder)+_heap(self.semantic_decoder.getstate())
        return size

    def require_permission_v3(self):
        require_current_beta1_fixture_evidence_reader_v3(self)
        self.graph._authorize(self.lease,self.authority,frozenset({"d11"}),owner_read=True)
        self.graph._validate_read_fence_v3(self.fence)
        if self.owner_entry is None:
            raise AuthorityUnavailable("actual Beta1 fixed Owner EOF is not complete")
        binding=self.owner_entry.require_permission_v3(self)
        if binding != self.expected_owner_binding:
            raise AuthorityUnavailable("Beta1 evidence Owner lease changed")
        clock=self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(self.bundle.ingress_clock)
        if (clock.sample.epoch != self.initial_clock.sample.epoch
                or trusted_upper(clock) >= self.operation.deadline_utc):
            raise AuthorityUnavailable("Beta1 evidence original clock/deadline changed or expired")

    def _emit_v3(self,event):
        if event.kind=="key" and len(event.path)==1:
            type_name=self.versions[self.index].key.type_name
            if event.key not in _ROOT_FIELDS[type_name]:
                raise AuthorityUnavailable("Beta1 metadata root is not the exact registered type")
            growth=len(event.key.encode("utf8"))*4+sys.getsizeof(event.key)+256
            self.operation.reserve_retained_state_growth_v3(self,growth)
            try:self.fields_seen.add(event.key)
            finally:self.operation.finish_retained_state_growth_v3(self)
        if len(event.path)!=1 or event.path[0] not in _RETAINED:
            return
        if event.kind=="scalar_start":self.scalar=bytearray()
        elif event.kind=="scalar_chunk":
            self.operation.reserve_retained_state_growth_v3(self,len(event.raw)*4+1024)
            try:self.scalar.extend(event.raw)
            finally:self.operation.finish_retained_state_growth_v3(self)
        elif event.kind=="scalar_end":
            self.operation.reserve_retained_state_growth_v3(self,len(self.scalar)*4+1024)
            try:self.values[event.path[0]]=json.loads(self.scalar);self.scalar=bytearray()
            finally:self.operation.finish_retained_state_growth_v3(self)

    def _semantic_v3(self,chunk,meter,final=False):
        text=self.semantic_decoder.decode(chunk,final=final)
        self.operation.reserve_retained_state_growth_v3(self,len(text)*12+1024)
        try:
            encoded=[]
            for char in text:
                point=ord(char)
                if point<127:encoded.append(char)
                elif point<=65535:encoded.append(chr(92)+"u"+format(point,"04x"))
                else:
                    point-=65536
                    encoded.append(chr(92)+"u"+format(55296+(point>>10),"04x")
                        +chr(92)+"u"+format(56320+(point&1023),"04x"))
            raw="".join(encoded).encode("ascii")
            meter.charge_encode(len(raw));self.semantic_hash.update(raw)
        finally:self.operation.finish_retained_state_growth_v3(self)

    def release_payload_v3(self):
        if self.owner_entry is not None:
            self.owner_entry.release_v3();self.owner_entry=None
        _READERS.pop(self,None)
        self.rows.clear();self.row=self.cell=self.parser=None
        self.values.clear();self.fields_seen.clear();self.scalar=bytearray();self.fragment=b""
        self.semantic_decoder=self.semantic_hash=None
        if self.parser_registered:
            self.operation.unregister_retained_state_v3(self.parser_heap);self.parser_registered=False
        if self.registered:
            self.operation.unregister_retained_state_v3(self);self.registered=False


def require_current_beta1_fixture_evidence_reader_v3(reader):
    from sylanne3.graph_worker import _require_beta1_engineering_metadata_provider_v3
    import sys
    if _require_beta1_engineering_metadata_provider_v3(reader.graph)is not sys.modules[__name__]:
        raise AuthorityUnavailable("exact registered engineering metadata reader required")
    if (type(reader) is not _Beta1FixtureEvidenceReadV3
            or _READERS.get(reader) != reader.identity_v3()
            or type(reader.work) is not GraphStorageWorkV3 or reader.work.kind != KIND
            or reader.work.state is not reader or reader.work.coordinator is not reader.graph
            or reader.work.operation is not reader.operation or reader.operation.closed
            or reader.read_scope is not reader.fence.scope
            or reader.operation.deadline_utc > reader.original_deadline_utc
            or runtime_storage_v3(reader.db) is not reader.operation.handle
            or reader.work.selection_digest != reader.operation.selection_digest
            or reader.graph._GraphCoordinator__owner_leases.get(reader.lease) is not reader.expected_owner_binding
            or reader.graph._GraphCoordinator__owner_session_proofs.get(reader.lease) is not reader.owner_session_proof):
        raise AuthorityUnavailable("actual same-Work Beta1 receipt metadata reader required")
    require_graph_storage_work_admission_v3(reader.graph)
    return reader


def prepare_current_beta1_fixture_evidence_read_v3(graph,authority,lease,bundle,request):
    from sylanne3.graph_worker import _require_beta1_engineering_metadata_provider_v3
    import sys
    if _require_beta1_engineering_metadata_provider_v3(graph)is not sys.modules[__name__]:
        raise AuthorityUnavailable("exact registered engineering metadata factory required")
    from sylanne3.host.authority_profile import require_current_owner_metadata_installation_v3
    from sylanne3.host.installed_package import verify_installed_backend_runtime_v1
    if type(request) not in (Beta1FixtureEvidenceRequestV3,Beta1ExactNumericJobMetadataRequestV3,Beta1ExactD13JobMetadataRequestV3,Beta1NumericJobAbsenceMetadataRequestV3,Beta1NumericAcceptedMetadataRequestV3):
        raise TypeError("exact Beta1 receipt metadata request required")
    require_graph_storage_work_admission_v3(graph)
    graph._authorize(lease,authority,frozenset({"d11"}),owner_read=True)
    _,package_root,verified=require_current_owner_metadata_installation_v3(
        graph,expected_bundle=bundle)
    root=Path(package_root).resolve(strict=True)
    if verified is None:
        verified=verify_installed_backend_runtime_v1(root,bundle.installation_policy.manifest_digest)
    if not verified.verified or (verified.package_version,verified.build_mode,verified.runtime_scope)!=(
            "3.0.0-beta1","beta1-candidate","backend-beta1-server-test"):
        raise AuthorityUnavailable("Beta1 evidence requires its exact verified protected manifest")
    ns=authority.namespace
    if (any((v.key.owner.bot,v.key.owner.persona)!=ns.as_tuple for v in request.versions)
            or any(scope[:2]!=ns.as_tuple for scope in request.event_scopes)
            or request.original_deadline_utc > bundle.installation_policy.root_grant.valid_until_utc):
        raise AuthorityUnavailable("Beta1 evidence changed its namespace or original root deadline")
    store=graph._GraphCoordinator__store
    clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(bundle.ingress_clock)
    now=trusted_upper(clock)
    deadline=min(request.original_deadline_utc,now+60.0)
    if deadline<=now:raise AuthorityUnavailable("Beta1 evidence original deadline expired")
    operation_id="beta1-evidence-read:"+secrets.token_hex(24)
    operation=begin_runtime_storage_operation_v3(store._db,operation_id,deadline)
    fence=reader=None
    try:
        with bind_runtime_storage_operation_v3(operation,store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id)
            reader=_Beta1FixtureEvidenceReadV3(_ISSUER,graph,authority,lease,bundle,
                request,operation,fence,clock,verified,root)
        work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
        reader.work=work;_READERS[reader]=reader.identity_v3()
        operation.register_retained_state_v3(reader);reader.registered=True
        operation.register_retained_state_v3(reader.parser_heap);reader.parser_registered=True
        return work
    except BaseException:
        if reader is not None:reader.release_payload_v3()
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def advance_current_beta1_fixture_evidence_read_v3(graph,work):
    reader=require_current_beta1_fixture_evidence_reader_v3(work.state)
    if reader.owner_entry is None:
        from sylanne3.authority_service.owner_location_read_v3 import prepare_current_host_beta1_fixture_evidence_owner_entry_v3
        reader.owner_entry=prepare_current_host_beta1_fixture_evidence_owner_entry_v3(reader)
    reader.require_permission_v3()
    with bind_runtime_storage_operation_v3(reader.operation,reader.db),reader.store._lock:
        db=reader.db;db.execute("BEGIN")
        try:
            with runtime_storage_quantum_v3(db) as meter:
                if reader.owner_entry.require_for_v3(reader)!=reader.expected_owner_binding:
                    raise AuthorityUnavailable("Beta1 evidence current Owner changed")
                if graph._v2_graph_stamp(reader.authority.namespace)!=reader.graph_stamp:
                    raise AuthorityUnavailable("Beta1 evidence selected Graph stamp changed")
                if reader.snapshot is not None and not reader.snapshot.complete:
                    reader.operation.reserve_retained_state_growth_v3(reader,262144)
                    try:reader.snapshot.advance_v3(meter)
                    finally:reader.operation.finish_retained_state_growth_v3(reader)
                elif not reader.versions:
                    if type(reader.request)is not Beta1NumericJobAbsenceMetadataRequestV3 or not reader.snapshot.complete:
                        raise AuthorityUnavailable("only the fixed Numeric absence recipe has an empty metadata EOF inventory")
                    reader.complete=True
                elif reader.row is None:
                    version=reader.versions[reader.index]
                    row=meter.read_fixed_row(db,"graph_history",
                        ("value_cell_id","valid","event_bot","event_persona","event_session","event_id"),
                        "token=? AND revision=?",(version.key.token,version.revision))
                    if (row is None or tuple(row[2:4])!=reader.authority.namespace.as_tuple
                            or tuple(row[2:]) != reader.evidence_scopes[reader.index]
                            or type(row[1]) is not int or row[1] not in (0,1)):
                        raise AuthorityUnavailable("Beta1 metadata version has no matching actual receipt producer")
                    reader.row=tuple(row)
                    reader.cell=begin_runtime_cell_read_v3(db,row[0],erasure_owner_ref=version.key.token)
                    if (reader.cell.header[0] not in ("canonical-json.ascii.v1","canonical-json.utf8.v1")
                            or reader.cell.header[1] != version.key.token
                            or reader.cell.header[2] != row[5]):
                        raise AuthorityUnavailable("Beta1 metadata cell has no exact canonical codec")
                    utf8=reader.cell.header[0]=="canonical-json.utf8.v1"
                    reader.parser=C09CanonicalJSONStreamV2(ensure_ascii=not utf8)
                    reader.semantic_decoder=codecs.getincrementaldecoder("utf8")("strict") if utf8 else None
                    reader.semantic_hash=sha256() if utf8 else None
                elif reader.offset<len(reader.fragment):
                    end=min(reader.offset+1024,len(reader.fragment));chunk=reader.fragment[reader.offset:end]
                    parser_growth=(reader.parser.max_depth*(reader.parser.max_key_bytes*8
                        +sys.getsizeof(tuple(range(reader.parser.max_depth)))+512)+len(chunk)*8+1024)
                    reader.operation.reserve_retained_state_growth_v3(reader.parser_heap,parser_growth)
                    try:reader.parser.feed(chunk,reader._emit_v3)
                    finally:reader.operation.finish_retained_state_growth_v3(reader.parser_heap)
                    if reader.semantic_decoder is not None:reader._semantic_v3(chunk,meter)
                    reader.offset=end
                else:
                    chunk=reader.cell.read_fragment(meter=meter)
                    if chunk is not None:
                        reader.operation.reserve_retained_state_growth_v3(reader,len(chunk)+1024)
                        try:reader.fragment=chunk;reader.offset=0
                        finally:reader.operation.finish_retained_state_growth_v3(reader)
                    else:
                        parsed=reader.parser.finish();actual=reader.cell.finish(meter=meter)
                        if (parsed.sha256,parsed.byte_count)!=(actual,reader.cell.header[3]):
                            raise AuthorityUnavailable("Beta1 metadata full cell SHA/byte EOF differs")
                        if reader.semantic_decoder is None:semantic=actual
                        else:
                            reader._semantic_v3(b"",meter,True);semantic=reader.semantic_hash.hexdigest()
                        version=reader.versions[reader.index]
                        if reader.fields_seen!=_ROOT_FIELDS[version.key.type_name]:
                            raise AuthorityUnavailable("Beta1 metadata type field coverage is incomplete")
                        if version.key.type_name=="runtime.job":
                            if reader.values["phase"] not in {"queued","running","waiting","deferred",
                                    "draining","cancelled","completed","failed","pending_confirmation"}:
                                raise AuthorityUnavailable("Beta1 job metadata phase differs")
                        elif reader.values["status"] not in {"standby","active","retired"}:
                            raise AuthorityUnavailable("Beta1 D13 metadata status differs")
                        result=Beta1FixtureMetadataEOFV3(version.key.token,version.revision,bool(reader.row[1]),
                            tuple(reader.row[2:]),actual,semantic,parsed.byte_count,
                            frozenset(reader.fields_seen),tuple(sorted(reader.values.items())))
                        reader.operation.reserve_retained_state_growth_v3(reader,
                            sys.getsizeof(result)+len(reader.fields_seen)*16+len(reader.values)*24+1024)
                        try:reader.rows.append(result)
                        finally:reader.operation.finish_retained_state_growth_v3(reader)
                        reader.index+=1;reader.row=reader.cell=reader.parser=None
                        reader.fragment=b"";reader.offset=0;reader.scalar=bytearray()
                        reader.fields_seen.clear();reader.values.clear()
                        reader.semantic_decoder=reader.semantic_hash=None
                        reader.complete=reader.index==len(reader.versions)
        finally:db.rollback()
    reader.require_permission_v3()
    return GraphStorageStepV3("complete",reader) if reader.complete else GraphStorageStepV3("progress")


def finish_current_beta1_fixture_evidence_read_v3(graph,work,error):
    reader=work.state
    try:graph._finish_read_fence_v3(reader.fence)
    finally:
        if reader.owner_entry is not None:reader.owner_entry.release_v3();reader.owner_entry=None
        if error is None:work.result_lease=work.operation
        else:
            reader.release_payload_v3();finish_runtime_storage_operation_v3(work.operation)
