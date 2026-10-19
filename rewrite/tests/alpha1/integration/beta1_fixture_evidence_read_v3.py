"""Package-external Root snapshot metadata. It creates no Work, permission or Source fact.

Business selectors and results must come from the existing production readers.
Only the fixed Root phase observer may use this module to assert saved originals.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import codecs
import json
import math
import os
import sqlite3
import time
from types import SimpleNamespace
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.graph_types import AtomKey, GraphVersion
from sylanne3.graph_worker import GraphStorageWorkV3
from sylanne3.runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from sylanne3.runtime.d11_types import RuntimeJobValue
from sylanne3.runtime_contracts import CompressedTurnBlockV2
from sylanne3.domains.d13.derived_block_metadata_v2 import DerivedBlockMetadataV2

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


class _ForensicExactJobV4:
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
        if (job.job_id!=self.reader.request.job_id or (job.bot_id,job.persona_id)!=self.reader.namespace.as_tuple or not allowed):
            raise AuthorityUnavailable("fixed exact installed job metadata identity differs")
        return job

    def advance_v3(self,meter):
        from sylanne3.runtime_contracts import canonical_digest
        from sylanne3.runtime.d11_types import runtime_job_key
        from sylanne3.runtime.jobs import _job_dict
        from sylanne3.runtime.d06_life_numeric_context_v1 import life_numeric_context_ids_v1
        r=self.reader;db=r.db;ns=r.namespace.as_tuple
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
            from sylanne3.host.model_workflows_v9 import AdminModelWorkflowsV9
            from sylanne3.model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as V6
            from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as V7
            from sylanne3.graph_types import Owner
            wf=r.bundle.model_workflows
            derived=(type(wf)is AdminModelWorkflowsV6 and wf.natural_generation is not None
                and wf.natural_generation.template_version==V6 or type(wf)in{AdminModelWorkflowsV7,AdminModelWorkflowsV8,AdminModelWorkflowsV9}
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
                        r.namespace,self.job.continuation["episode_ref"])["original"]if type(r.request)is not Beta1ExactD13JobMetadataRequestV3 else ""), ("kind","original_ref")))
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
                    r.d11_issuer._signer.verify(SIGN_KIND,
                        canonical_serialize((r.namespace,row[0],row[1],row[3])),row[4])
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
                    issuer=r.d11_issuer
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
                resource=r.d02_issuer
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
                if quote.valid_until_utc<=(r.observed_at_utc)or quote.deadline_utc<=(r.observed_at_utc):
                    raise AuthorityUnavailable("actual normal Content quote donor expired; HOLD")
                self.reservation_donor=dict(signed_quote_id=quote.quote_id,quote_version=quote.version,lease_id=reservation[0],
                    reservation_operation_id=reservation[1],reservation_digest=reservation[2],state=reservation[4],
                    ceiling=json.loads(reservation[3]),deadline_utc=quote.deadline_utc,valid_until_utc=quote.valid_until_utc,
                    quote_digest=canonical_digest(quote))
                self.reservation_donors.append(self.reservation_donor);return
            r.versions=tuple(self.versions);r.evidence_scopes=tuple(self.scopes)
            r.metadata_allowset=tuple((v.key.token,v.revision,v.key.type_name)for v in r.versions)
            self.complete=True

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



class _ForensicMeterV4:
    """One fixed metadata step is capped at the existing 256 KiB quantum size."""
    def __init__(self):self.used=0
    def charge_read(self,n):
        self.used+=n
        if self.used>262144:raise ValueError("Root forensic metadata step exceeds 256 KiB")
    charge_encode=charge_read
    def require_available(self,n):
        if self.used+n>262144:raise ValueError("Root forensic metadata step exceeds 256 KiB")
    def read_fixed_row(self,db,table,columns,where,args):
        sql="SELECT "+",".join('"'+v+'"'for v in columns)+' FROM "'+table+'" WHERE '+where+' LIMIT 1'
        row=db.execute(sql,args).fetchone()
        if row is not None:self.charge_read(sum(len(v.encode('utf8'))if type(v)is str else len(v)if type(v)is bytes else 8 for v in row))
        return row

def _forensic_cell_metadata_v4(db,cells,version,scope,*,appraisal=False):
    """Validate all actual segments and origins; retain only allowed scalar metadata."""
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.segmented_sql_cell_v1 import MAX_SEGMENT_BYTES
    row=db.execute("SELECT value_cell_id,valid,event_bot,event_persona,event_session,event_id FROM graph_history "
        "WHERE token=? AND revision=?",(version.key.token,version.revision)).fetchone()
    if row is None or tuple(row[2:])!=tuple(scope):raise ValueError("forensic history producer scope differs")
    cell=row[0]
    header=cells.one("segmented_cells_v1",("codec_id","erasure_owner_ref","producer_operation_id","total_bytes",
        "segment_count","payload_sha256","ordered_segment_root","origin_scope_digest"),"cell_id=?",(cell,))
    if (header is None or header[0]not in{"canonical-json.ascii.v1","canonical-json.utf8.v1"}
            or header[1]!=version.key.token or header[2]!=scope[3]):raise ValueError("forensic cell origin/header differs")
    if not cells._runtime_origin(cell,header,"graph_history",version.key.token,version.revision):
        if not cells._owner_source_origin(cell,header,"graph_history",version.key.token,version.revision):
            cells._capture_origin(cell,header,"graph_history",version.key.token,version.revision)
    parser=C09CanonicalJSONStreamV2(ensure_ascii=header[0]=="canonical-json.ascii.v1")
    fields=set();values={};scalar=bytearray();keep=False
    def emit(event):
        nonlocal scalar,keep
        if event.kind=="key"and len(event.path)==1:fields.add(event.key)
        if len(event.path)!=1 or event.path[0]not in _RETAINED:return
        if event.kind=="scalar_start":scalar=bytearray();keep=True
        elif event.kind=="scalar_chunk":
            scalar.extend(event.raw)
            if len(scalar)>65536:raise ValueError("forensic scalar metadata exceeds its fixed limit")
        elif event.kind=="scalar_end"and keep:
            values[event.path[0]]=json.loads(scalar);scalar=bytearray();keep=False
    physical=sha256();semantic=sha256();decoder=codecs.getincrementaldecoder("utf8")("strict")
    root=canonical_digest(("sylanne3.segmented-cell-genesis.v1",cell));offset=0
    for ordinal in range(header[4]):
        item=cells.one("segmented_cell_segments_v1",("byte_offset","payload","payload_sha256"),"cell_id=? AND ordinal=?",(cell,ordinal))
        if item is None or item[0]!=offset or not 0<len(item[1])<=MAX_SEGMENT_BYTES or sha256(item[1]).hexdigest()!=item[2]:
            raise ValueError("forensic segment order/hash differs")
        parser.feed(item[1],emit);physical.update(item[1])
        text=decoder.decode(item[1]);semantic.update(''.join(c if ord(c)<128 else json.dumps(c,ensure_ascii=True)[1:-1]for c in text).encode('ascii'))
        root=canonical_digest(("sylanne3.segmented-cell-link.v1",root,cell,ordinal,offset,len(item[1]),item[2]));offset+=len(item[1])
    decoder.decode(b"",final=True);parsed=parser.finish()
    extra=cells.one("segmented_cell_segments_v1",("ordinal",),"cell_id=? AND ordinal>=? LIMIT 1",(cell,header[4]))
    if extra is not None or(offset,physical.hexdigest(),root,parsed.byte_count,parsed.sha256)!=(header[3],header[5],header[6],header[3],header[5]):
        raise ValueError("forensic canonical cell complete EOF differs")
    if not appraisal and fields!=_ROOT_FIELDS[version.key.type_name]:raise ValueError("forensic metadata schema field EOF differs")
    return Beta1FixtureMetadataEOFV3(version.key.token,version.revision,bool(row[1]),tuple(scope),header[5],
        semantic.hexdigest(),offset,frozenset(fields),tuple(sorted(values.items())))

def _forensic_absence_v4(db,bundle,selector):
    from sylanne3.runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
    from sylanne3.model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1,internal_life_numeric_ids_v1
    from sylanne3.runtime.d06_life_numeric_context_v1 import life_numeric_context_ids_v1
    from sylanne3.runtime.d11_life_preparation_v1 import SIGN_KIND
    identity=InternalLifeNumericIdentityV1(**{**selector['identity'],'namespace':NamespaceId(**selector['identity']['namespace'])})
    ns=bundle.installation_policy.namespace
    if identity.namespace!=ns:raise ValueError("forensic absence namespace differs")
    ids=internal_life_numeric_ids_v1(identity)
    if selector['job_id']!=ids['job']:raise ValueError("forensic absence exact job locator differs")
    if db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=?",(ids['job'],)).fetchone()or db.execute(
            "SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? AND type_name='runtime.job' AND name=?",(*ns.as_tuple,ids['job'])).fetchone():
        raise ValueError("Numeric target is not absent")
    ref=life_numeric_context_ids_v1(ns,identity.episode_ref)['original']
    row=db.execute("SELECT kind,original_ref,producing_operation_id,payload_digest,signature FROM graph_d11_life_originals_v1 "
        "WHERE bot=? AND persona=? AND kind='numeric_context_v1' AND original_ref=?",(*ns.as_tuple,ref)).fetchone()
    if row is None or row[3]!=identity.context_digest:raise ValueError("forensic actual context original differs")
    from sylanne3.runtime.issuers import D02ResourceIssuer,D11BudgetJobIssuer
    issuer=D11BudgetJobIssuer(D02ResourceIssuer(bundle.d02_signing_key),bundle.d11_signing_key)
    issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,row[0],row[1],row[3])),row[4])
    inventory={}
    for table in ('runtime_budget_leases','runtime_budget_grants','runtime_budget_operations','runtime_budget_reservations'):
        records=tuple(db.execute('SELECT * FROM '+table+' ORDER BY 1,2'))
        inventory[table]=(len(records),canonical_digest(records))
    return dict(schema='sylanne.beta1.numeric-job-absence-metadata.v3',namespace=ns.as_tuple,
        expected_job_id=ids['job'],expected_prepare_operation_id=ids['prepare'],identity_digest=identity.digest,
        job_absent=True,projection_absent=True,context_original=((*row[:4],sha256(row[4].encode()).hexdigest()),),accounting_inventory=inventory)

def read_root_snapshot_metadata_v4(*,snapshot,bundle,selector,deadline):
    """Root-only assertion data. Never returns a live Work result or an authority fact."""
    if os.name!='posix'or os.geteuid()!=0:raise PermissionError('isolated Root forensic controller required')
    from sylanne3.runtime.issuers import D02ResourceIssuer,D11BudgetJobIssuer
    from rewrite.tests.alpha1.integration.artifact_forensic_graph_projection_v3 import _ForensicCellsV3
    from sylanne3.runtime_contracts import canonical_digest
    ns=bundle.installation_policy.namespace
    with sqlite3.connect(Path(snapshot).as_uri()+'?mode=ro',uri=True)as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN');cells=_ForensicCellsV3(db,bundle)
        if selector['kind']=='absence':return _forensic_absence_v4(db,bundle,selector)
        if selector['kind']=='versions':
            result=[]
            for item,scope in zip(selector['versions'],selector['event_scopes'],strict=True):
                version=GraphVersion(AtomKey.from_token(item[0]),item[1])
                if version.key.type_name not in _ALLOWED_TYPES or (version.key.owner.bot,version.key.owner.persona)!=ns.as_tuple:raise ValueError('forensic version namespace/type differs')
                result.append(_forensic_cell_metadata_v4(db,cells,version,tuple(scope)))
            return result
        cls=Beta1ExactD13JobMetadataRequestV3 if selector['kind']=='d13'else Beta1ExactNumericJobMetadataRequestV3
        request=cls(selector['job_id'],selector['original_deadline_utc'],reservation_donor_selector=
            None if selector.get('reservation_donor_selector')is None else tuple(selector['reservation_donor_selector']))
        d02=D02ResourceIssuer(bundle.d02_signing_key);d11=D11BudgetJobIssuer(d02,bundle.d11_signing_key)
        reader=SimpleNamespace(db=db,namespace=ns,request=request,bundle=bundle,d11_issuer=d11,d02_issuer=d02,
            observed_at_utc=time.time(),versions=(),evidence_scopes=(),metadata_allowset=())
        state=_ForensicExactJobV4(reader)
        while not state.complete:
            if time.monotonic()>=deadline:raise TimeoutError('original Root forensic phase deadline expired')
            state.advance_v3(_ForensicMeterV4())
        rows=tuple(_forensic_cell_metadata_v4(db,cells,v,s)for v,s in zip(state.versions,state.scopes,strict=True))
        result=state.result_v3(rows)
        if selector['kind']=='accepted':
            from sylanne3.runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
            from sylanne3.runtime_contracts import CommitReceipt,canonical_serialize
            receipt=decode_typed_production_value_v1(selector['adopt_receipt'],CommitReceipt)
            accepted=Beta1NumericAcceptedMetadataRequestV3(selector['job_id'],receipt,selector['expected_before_digest'],selector['original_deadline_utc'])
            committed=db.execute('SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,receipt.operation_id)).fetchone()
            if committed!=(receipt.operation_digest,receipt.commit_seq):raise ValueError('forensic actual adopt W01 differs')
            row=db.execute("SELECT producing_operation_id,payload_digest,signature FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1' AND original_ref=?",(*ns.as_tuple,accepted.appraisal_ref)).fetchone()
            if row is None or row[0]!=receipt.operation_id:raise ValueError('forensic accepted original producer differs')
            from sylanne3.runtime.d11_life_preparation_v1 import SIGN_KIND
            d11._signer.verify(SIGN_KIND,canonical_serialize((ns,'numeric_appraisal_acceptance_v1',accepted.appraisal_ref,row[1])),row[2])
            summary,inner_digest=_forensic_accepted_summary_v4(db,ns,accepted.appraisal_ref,row[1],deadline)
            if summary['before_digest']!=selector['expected_before_digest']:raise ValueError('forensic before-original commitment differs')
            version=next(v for v in receipt.write_versions if v.key.token==accepted.appraisal_ref)
            history=db.execute('SELECT event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?',(version.key.token,version.revision)).fetchone()
            metadata=_forensic_cell_metadata_v4(db,cells,version,history,appraisal=True)
            head=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE token=?',(accepted.appraisal_ref,)).fetchone()
            historical=db.execute('SELECT value_cell_id FROM graph_history WHERE token=? AND revision=?',(accepted.appraisal_ref,version.revision)).fetchone()
            if head!=(version.revision,1,historical[0])or metadata.canonical_semantic_digest!=inner_digest:
                raise ValueError('forensic current appraisal body differs from accepted original EOF')
            result['acceptance_metadata']=summary
            result['acceptance_original_metadata']=('numeric_appraisal_acceptance_v1',accepted.appraisal_ref,*row[:2],sha256(row[2].encode()).hexdigest())
            result['appraisal_metadata_eof']=(metadata.payload_sha256,metadata.canonical_semantic_digest,metadata.byte_count)
        return result


def backup_artifact_v3_fixture_graph_v1(*, graph_path, target):
    """Root-only forensic backup of a newly installed fixture, never an execution capability."""
    import os, sqlite3
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("isolated fixture Root controller required")
    graph_path, target = Path(graph_path), Path(target)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    with sqlite3.connect(graph_path.as_uri() + "?mode=ro", uri=True) as source:
        source.execute("PRAGMA query_only=ON")
        with sqlite3.connect(target) as destination:
            source.backup(destination)
    os.chmod(target, 0o600)
    return sha256(target.read_bytes()).hexdigest()


def verify_artifact_v3_fixture_snapshot_v1(*, snapshot, setup, unknown=False, baseline=False):
    """Authenticate actual signed originals on a read-only captured fixture DB."""
    from collections import Counter
    from sylanne3.host import authority_profile as profile
    from sylanne3.host.model_workflows_v9 import AdminModelWorkflowsV9
    from sylanne3.runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer, _decode_outcome
    from sylanne3.runtime.budget import get_budget_lease, BudgetReceipt
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.artifact_receipt_allocation_v3 import read_actual_artifact_receipt_allocation_v3
    from sylanne3.runtime.artifact_phase_observation_v1 import read_artifact_phase_observation_basis_v1
    from sylanne3.runtime.artifact_phase_observation_result_v1 import _actual_observation_v1
    from sylanne3.runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from sylanne3.runtime.artifact_completion_receipt_v1 import receipt_ids_v1, require_artifact_completion_receipt_history_v1
    from sylanne3.runtime.artifact_receipt_completion_v1 import require_delivered_artifact_receipt_v1, finish_operation_id_v1
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.memory_types import SourceRecord
    from artifact_phase_counter_fixture_v1 import MOCK_V3_PROVIDER, MOCK_V3_MODEL
    bundle = profile._load_installation_bundle_from_root(setup["profile_id"],
        Path("/etc/sylanne/client/profiles"), "Linux")
    policy = bundle.installation_policy
    if (type(bundle.model_workflows) is not AdminModelWorkflowsV9 or bundle.artifact_phase_observer is None
            or bundle.artifact_phase_counter.source_scope != "production"
            or (bundle.artifact_phase_counter.provider_id, bundle.artifact_phase_counter.model_id) !=
               (MOCK_V3_PROVIDER, MOCK_V3_MODEL)
            or (policy.installation_id, policy.manifest_digest, canonical_digest(policy.root_grant)) !=
               (setup["installation_id"], setup["manifest_digest"], setup["root_grant_digest"])
            or policy.root_grant.valid_until_utc != setup["original_deadline_utc"]
            or dict(policy.root_lease.limits) != setup["approved_root_limits"]
            or dict(policy.root_grant.max_ceiling) != setup["approved_root_max_ceiling"]):
        raise ValueError("snapshot did not belong to the exact fresh approved V9 Mock installation")
    issuer = D11BudgetJobIssuer(D02ResourceIssuer(bundle.d02_signing_key), bundle.d11_signing_key)
    ns = policy.namespace
    from rewrite.tests.alpha1.integration.artifact_forensic_graph_projection_v3 import forensic_artifact_snapshot_connection_v3
    with forensic_artifact_snapshot_connection_v3(snapshot=snapshot, bundle=bundle) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        grant = issuer.current_budget_grant(db, policy.root_lease.lease_id)
        root = get_budget_lease(db, policy.root_lease.lease_id)
        if grant != policy.root_grant or root.limits != policy.root_lease.limits or root.used.get("model_microusd", 0) != 0:
            raise ValueError("fresh fixture changed original Root/grant/limits or added a model charge")
        jobs = db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND work_kind='d11.foreground_cycle.v1'",
            ns.as_tuple).fetchall()
        if baseline:
            if jobs:
                raise ValueError("V3 fixture baseline is not a fresh pre-episode Root")
            return {"scope": "signed fresh Root baseline only", "installation_id": policy.installation_id,
                "root_grant_digest": canonical_digest(grant), "model_microusd": 0}
        if len(jobs) != 1:
            raise ValueError("V3 fixture requires one actual foreground episode")
        job = get_job(db, jobs[0][0])
        cycle = foreground_cycle_from_wire_v1(job.continuation)
        _, allocation, child, child_grant = read_actual_artifact_receipt_allocation_v3(db, namespace=ns,
            c02_operation_id=cycle.c02_operation_id, source_ref=cycle.source_ref, issuer=issuer)
        row = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*ns.as_tuple, cycle.source_ref)).fetchone()
        source = SourceRecord.from_dict(json.loads(row[0]))
        if source.text != setup["task_text"] or child_grant.allowed_work_kinds != ("message",) or allocation.message_slots != 1:
            raise ValueError("actual Source or message-only allocation differs")
        plan = cycle.call_plan
        expected = Counter({"C1": 1, "C2": 1, "C4": 1 if unknown else 2, "C3": 1 if unknown else 2})
        if Counter(a.slot for a in plan.attempts) != expected or any(a.state != "completed" for a in plan.attempts):
            return None
        if sum(a.input_ceiling for a in plan.attempts) > 48000 or sum(a.output_ceiling for a in plan.attempts) > 8000:
            raise ValueError("actual episode exceeded the original token caps")
        call_evidence = []
        for attempt in plan.attempts:
            if attempt.budget_lease_ref != root.lease_id:
                raise ValueError("actual model attempt borrowed a grant or message-only lease")
            reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (attempt.budget_lease_ref, attempt.reservation_operation_id)).fetchone()
            if reservation is None or reservation[0] != attempt.reservation_digest or reservation[2] != "settled":
                raise ValueError("actual model lacks its exact settled reservation")
            quotes = db.execute("SELECT quote_id,version FROM runtime_resource_quotes "
                "WHERE json_extract(quote_json,'$.operation_id')=?",
                (attempt.reservation_operation_id,)).fetchall()
            if len(quotes) != 1:
                raise ValueError("model reservation lacks one actual signed D02 quote")
            quote = issuer.resource_issuer.original_signed_quote(db, *quotes[0])
            if quote.parent_budget_lease_ref != root.lease_id or dict(quote.ceiling) != json.loads(reservation[1]):
                raise ValueError("actual quote and reservation ceilings/parent differ")
            outcomes = db.execute("SELECT outcome_json,signature FROM runtime_resource_outcomes WHERE quote_id=? AND operation_id=?",
                (quote.quote_id, quote.operation_id)).fetchall()
            if len(outcomes) != 1:
                raise ValueError("actual signed model cost outcome is missing")
            issuer.resource_issuer._signer.verify("resource-outcome.v1", outcomes[0][0], outcomes[0][1])
            outcome = _decode_outcome(outcomes[0][0])
            if ((outcome.quote_id, outcome.operation_id, outcome.bot_id, outcome.persona_id) !=
                    (quote.quote_id, quote.operation_id, *ns.as_tuple)
                    or outcome.actual is None or outcome.actual.get("model_microusd", 0) != 0):
                raise ValueError("Mock model cost is unknown or nonzero")
            costs = db.execute("SELECT phase,receipt_json FROM runtime_budget_operations "
                "WHERE bot_id=? AND persona_id=? AND operation_id=?", (*ns.as_tuple, attempt.reservation_operation_id)).fetchall()
            receipts = {phase: BudgetReceipt(**json.loads(body)) for phase, body in costs}
            if set(receipts) != {"reserve", "settle"} or receipts["settle"].status != "settled":
                raise ValueError("model actual reserve/settle W01 pair is incomplete")
            call_evidence.append({"call_id": attempt.call_id, "slot": attempt.slot, "quote_id": quote.quote_id,
                "reservation_digest": attempt.reservation_digest, "outcome_digest": canonical_digest(outcome)})
        from sylanne3.runtime.d11_life_preparation_v1 import _read as read_life_original
        signed_c4 = []
        for kind, ref in db.execute("SELECT kind,original_ref FROM graph_d11_life_originals_v1 "
                "WHERE bot=? AND persona=? AND kind LIKE 'c4_phase_%'", ns.as_tuple):
            value = read_life_original(db, issuer=issuer, namespace=ns, kind=kind, ref=ref)
            if value is None:
                raise ValueError("actual C4 signed original disappeared")
            signed_c4.append({"kind": kind, "ref": ref, "digest": canonical_digest(value[0])})
        if not signed_c4:
            raise ValueError("no actual signed C4 model/file history exists")
        observations = []
        for attempt in plan.attempts:
            if attempt.slot != "C3":
                continue
            basis = read_artifact_phase_observation_basis_v1(db, namespace=ns,
                original_ref=attempt.observation_basis_ref, issuer=issuer)
            if basis is None or basis.digest != attempt.observation_basis_digest:
                raise ValueError("D07 call lost its actual signed phase/Source/Owner basis")
            observed = _actual_observation_v1(db, basis=basis, issuer=issuer)
            observations.append({"basis_digest": basis.digest, "prepared_digest": observed.prepared_digest,
                "terminal_ref": observed.terminal_ref, "status": observed.status})
        if unknown:
            if [o["status"] for o in observations] != ["unknown"] or job.phase == "completed":
                raise ValueError("unknown independent observation was fabricated as satisfaction/completion")
            message_count = db.execute("SELECT COUNT(*) FROM runtime_budget_reservations WHERE lease_id=?", (child.lease_id,)).fetchone()[0]
            if message_count:
                raise ValueError("unknown observation dispatched a completion receipt")
            return {"scope": "actual signed unknown observation; no receipt", "calls": call_evidence,
                "observations": observations, "c02_operation_id": cycle.c02_operation_id}
        if [o["status"] for o in observations] != ["satisfied", "satisfied"]:
            raise ValueError("actual independent observations are not both satisfied")
        if job.phase != "completed":
            return None
        ids = receipt_ids_v1(plan.phase_group.selector)
        original = read_adopted_domain_operation_v1(db, ns, ids["producer"])
        if original is None:
            raise ValueError("completed cycle lacks its actual D06 receipt producer W01")
        receipt = require_artifact_completion_receipt_history_v1(db, namespace=ns, original=original)
        delivered = require_delivered_artifact_receipt_v1(db, namespace=ns, receipt=receipt)
        finished = read_adopted_domain_operation_v1(db, ns, finish_operation_id_v1(plan.phase_group.selector))
        if finished is None or finished["operation_kind"] != "finish_artifact_receipt_cycle_v1":
            raise ValueError("cycle completion lacks the actual delivered-receipt finish W01")
        return {"scope": "snapshot actual signed model/cost/Source/Owner/receipt chain; grants no execution authority",
            "calls": call_evidence, "observations": observations, "c02_operation_id": cycle.c02_operation_id,
            "allocation_digest": allocation.digest, "receipt_digest": receipt.digest, "signed_c4_originals": signed_c4,
            "producer_receipt_digest": canonical_digest(original["receipt"]),
            "delivery_digest": canonical_digest(delivered), "finish_receipt_digest": canonical_digest(finished["receipt"]),
            "root_grant_digest": canonical_digest(grant), "model_microusd": 0}


def verify_artifact_v3_queued_cancel_snapshot_v1(*,snapshot,setup,job_id,stop_operation_id=None,before=None):
    """Only the isolated Root's read-only snapshot; this grants no execution right."""
    from sylanne3.host import authority_profile as profile
    from sylanne3.runtime.issuers import D02ResourceIssuer,D11BudgetJobIssuer
    from sylanne3.runtime.budget import get_budget_lease
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.d07_execution_v1 import read_d07_original_v1
    from sylanne3.runtime.artifact_observation_parentage_v3 import artifact_observation_descriptor_from_metadata_v3
    from sylanne3.runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from sylanne3.runtime.artifact_receipt_allocation_v3 import read_actual_artifact_receipt_allocation_v3
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.graph_types import AtomKey
    from rewrite.tests.alpha1.integration.artifact_forensic_graph_projection_v3 import forensic_artifact_snapshot_connection_v3
    bundle=profile._load_installation_bundle_from_root(setup["profile_id"],Path("/etc/sylanne/client/profiles"),"Linux")
    policy=bundle.installation_policy
    if((policy.installation_id,policy.manifest_digest,canonical_digest(policy.root_grant))!=
            (setup["installation_id"],setup["manifest_digest"],setup["root_grant_digest"])
            or policy.root_grant.valid_until_utc!=setup["original_deadline_utc"]
            or dict(policy.root_lease.limits)!=setup["approved_root_limits"]
            or dict(policy.root_grant.max_ceiling)!=setup["approved_root_max_ceiling"]):
        raise ValueError("cancelled fixture changed its actual fresh installed Root/manifest/lifetime")
    issuer=D11BudgetJobIssuer(D02ResourceIssuer(bundle.d02_signing_key),bundle.d11_signing_key)
    ns=policy.namespace
    with forensic_artifact_snapshot_connection_v3(snapshot=snapshot,bundle=bundle)as db:
        db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
        grant=issuer.current_budget_grant(db,policy.root_lease.lease_id)
        root=get_budget_lease(db,policy.root_lease.lease_id)
        job=get_job(db,job_id)
        original=read_d07_original_v1(db,issuer,ns,"prepared",job_id)
        if original is None:raise ValueError("actual signed D07 prepared disappeared")
        descriptor=artifact_observation_descriptor_from_metadata_v3(original[0],namespace=ns,prepared_digest=original[1])
        cycle_job=get_job(db,descriptor.cycle_ref.key.name)
        cycle=foreground_cycle_from_wire_v1(cycle_job.continuation)
        from sylanne3.memory_types import SourceRecord
        source_row=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(cycle.source_ref,)).fetchone()
        if source_row is None or source_row[1]!=1:
            raise ValueError("actual task Source is absent in the isolated fixture snapshot")
        source=SourceRecord.from_dict(json.loads(source_row[0]))
        if source.text!=setup["task_text"]:
            raise ValueError("queued cancellation Source differs from its actual single SDK ingress")
        _,allocation,child,child_grant=read_actual_artifact_receipt_allocation_v3(db,namespace=ns,
            c02_operation_id=cycle.c02_operation_id,source_ref=cycle.source_ref,issuer=issuer)
        if(grant!=policy.root_grant or root.limits!=policy.root_lease.limits
                or root.used.get("model_microusd",0)!=0 or job.budget_ref!=root.lease_id
                or cycle_job.budget_ref!=root.lease_id or descriptor.c02_operation_id!=cycle.c02_operation_id
                or child_grant.allowed_work_kinds!=("message",)or allocation.message_slots!=1
                or read_d07_original_v1(db,issuer,ns,"call",job_id)is not None):
            raise ValueError("cancelled queued child lost its exact Source/Root/allocation/no-Core-call baseline")
        reservation=db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",(root.lease_id,job.operation_id)).fetchone()
        quote=issuer.resource_issuer.original_signed_quote(db,original[0]["quote_id"],original[0]["quote_version"])
        if(reservation is None or reservation[0]!=original[0]["reservation_digest"]
                or json.loads(reservation[1])!=dict(quote.ceiling)
                or quote.operation_id!=job.operation_id or quote.parent_budget_lease_ref!=root.lease_id):
            raise ValueError("queued child lacks its exact signed quote and real reservation")
        costs=tuple(db.execute("SELECT quote_id,operation_id,outcome_json,signature FROM runtime_resource_outcomes "
            "ORDER BY quote_id,operation_id,version"))
        for _,_,encoded,signature in costs:
            issuer.resource_issuer._signer.verify("resource-outcome.v1",encoded,signature)
        financial=canonical_digest((root.used,root.unconfirmed,costs))
        value={"namespace":dict(zip(("bot_id","persona_id"),ns.as_tuple)),
            "job_id":job.job_id,"cycle_job_ref":descriptor.cycle_ref.key.token,
            "c02_operation_id":descriptor.c02_operation_id,"prepared_digest":original[1],
            "job_phase":job.phase,"lease_holder":job.lease_holder,"fence":job.fence,
            "cancel_epoch":job.cancel_epoch,"reservation":reservation,"financial_digest":financial,
            "root_grant_digest":canonical_digest(grant),"deadline_utc":job.deadline_utc}
        if before is None:
            if job.phase!="queued"or job.lease_holder is not None or job.cancel_epoch or job.fence:
                raise ValueError("baseline must be the real never-acquired D07 queued job")
            return value
        if(job.phase!="cancelled"or job.lease_holder is not None or job.cancel_epoch!=before["cancel_epoch"]+1
                or value["prepared_digest"]!=before["prepared_digest"]
                or value["reservation"]!=before["reservation"]or financial!=before["financial_digest"]
                or value["deadline_utc"]!=before["deadline_utc"]):
            raise ValueError("actual queued child cancellation changed original cost, reservation or lifetime")
        stopped=read_adopted_domain_operation_v1(db,ns,stop_operation_id)
        if stopped is None or(stopped["domain"],stopped["operation_kind"])!=("d11","owner_stop_reply_v1"):
            raise ValueError("actual Owner StopReply W01 cancellation is absent")
        provenance=stopped["payload"]["provenance"]
        afters=[item for item in provenance["after_jobs"]if item["job_id"]==job_id]
        refs=[item for item in provenance["child_originals"]if AtomKey.from_token(item[0]).name==job_id]
        operation="owner-stop-job:"+canonical_digest((stop_operation_id,job_id))[:48]
        row=db.execute("SELECT digest,job_id FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
            "AND operation_id=? AND phase='cancel'",(*ns.as_tuple,operation)).fetchone()
        if(len(afters)!=1 or afters[0]["phase"]!="cancelled"or len(refs)!=1
                or list(refs[0][1:])!=[job_id,original[1]]
                or row!=(provenance["stop_original_digest"].removeprefix("sha256:"),job_id)):
            raise ValueError("actual same-child signed carrier/cancel_persistent_job W01 receipt differs")
        value["stop_original_ref"]=provenance["stop_original_ref"]
        value["projection_receipt_digest"]=canonical_digest(stopped["receipt"])
        return value


def _forensic_accepted_summary_v4(db,ns,ref,expected_digest,deadline):
    from sylanne3.authority_service.c09_authority_storage_rebase_v2 import _D13PaidEncodedStringStreamV3
    from sylanne3.runtime.d06_life_numeric_task_v1 import LifeNumericAppraisalAcceptanceV1
    summary_names=frozenset({'context_digest', 'prepared_digest', 'operation_id', 'appraisal_revision', 'result_original_digest', 'before_digest', 'appraisal_ref', 'result_original_ref', 'job_id', 'cost_original_ref', 'schema', 'cost_original_digest'})
    fields=set();values={};scalar=bytearray()
    nested=_D13PaidEncodedStringStreamV3(ensure_ascii=True);inner=C09CanonicalJSONStreamV2(ensure_ascii=True)
    inner_digest=None
    def emit(event):
        nonlocal scalar,inner_digest
        if event.kind=='key'and len(event.path)==1:fields.add(event.key)
        if event.path==('appraisal_value_json',):
            if event.kind=='scalar_chunk':
                nested.feed(event.raw,lambda child:None)
                if nested.pending:inner.feed(bytes(nested.pending),lambda child:None);nested.pending.clear()
            elif event.kind=='scalar_end':nested.finish();inner_digest=inner.finish().sha256
            return
        if event.path in {('namespace','bot_id'),('namespace','persona_id')}:name='namespace_'+event.path[-1]
        elif len(event.path)==1 and event.path[0]in summary_names:name=event.path[0]
        else:return
        if event.kind=='scalar_start':scalar=bytearray()
        elif event.kind=='scalar_chunk':
            scalar.extend(event.raw)
            if len(scalar)>65536:raise ValueError('forensic accepted scalar exceeds bound')
        elif event.kind=='scalar_end':values[name]=json.loads(scalar);scalar=bytearray()
    parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
    parameters=(*ns.as_tuple,ref)
    length=db.execute("SELECT length(CAST(payload_json AS BLOB)) FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1' AND original_ref=?",parameters).fetchone()[0]
    offset=0
    while offset<length:
        if time.monotonic()>=deadline:raise TimeoutError('original Root forensic deadline expired')
        data=db.execute("SELECT substr(CAST(payload_json AS BLOB),?,?) FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1' AND original_ref=?",(offset+1,min(16384,length-offset),*parameters)).fetchone()[0]
        if not data:raise ValueError('forensic accepted original ended early')
        parser.feed(data,emit);offset+=len(data)
    complete=parser.finish()
    if(complete.sha256!=expected_digest or complete.byte_count!=length or fields!=set(LifeNumericAppraisalAcceptanceV1.__dataclass_fields__)
            or inner_digest is None or set(values)!=set(summary_names)|{'namespace_bot_id','namespace_persona_id'}):
        raise ValueError('forensic accepted complete canonical EOF differs')
    return values,inner_digest
