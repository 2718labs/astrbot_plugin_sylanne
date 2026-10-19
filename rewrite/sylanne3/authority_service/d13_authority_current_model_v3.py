"""Pure D13 business equalities over one actual Source Work's completed columns."""
from dataclasses import asdict,replace
from datetime import datetime
import json

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..runtime.dispatch_current_inventory_v3 import _heap


class AuthorityD13CurrentModelReadV3:
    def __init__(self,reader):
        reader.require_registered_v3()
        if not reader.qualified or not reader.eof.complete:
            raise AuthorityUnavailable("D13 business proof requires all Source rights and complete paid EOF")
        self.reader=reader;self.phase="rows";self.complete=False;self.result=None
        self.actions=[];self.schedule=self.job=self.queued=None
        self.raws={};self.checked_leases={}
        self.original=self.frozen=self.call=self.request=None

    def heap_v3(self):
        return _heap((self.raws,self.actions,self.schedule))+sum(_heap(vars(v))for v in self.checked_leases.values())+sum(
            _heap(vars(v))for v in (self.job,self.queued)if v is not None)

    def point(self,meter,table,columns,keys,key):
        r=self.reader;request=(table,tuple(columns),tuple(keys),tuple(key))
        r.allowed_requests.add(request)
        return r.point_v3(request,meter)

    def _rows(self,meter):
        from .current_authority_graph_read_v3 import _AUTHORITY_JOB_FIELDS_V3
        from ..runtime.jobs import get_job,PersistentJob
        from ..runtime.d11_types import runtime_job_key
        r=self.reader;ns=r.namespace.as_tuple;op=r.work.request.operation_id
        p=lambda t,c,k,v:self.point(meter,t,c,k,v)
        p("runtime_jobs",_AUTHORITY_JOB_FIELDS_V3,("job_id",),(r.job_id,))
        self.job=get_job(r.db,r.job_id)
        created=p("runtime_job_operations",("digest","job_id","job_json"),
            ("bot_id","persona_id","operation_id","phase"),(*ns,op,"create"))
        if created is None or created[1]!=r.job_id:raise AuthorityUnavailable("D13 immutable queued job original absent")
        self.queued=PersistentJob(**json.loads(created[2]))
        self.created=created
        self.original,self.frozen,self.call,self.request=r.eof.require_originals_v3(r.verifier,r.plan,r.current_window)
        self.raws["schedule"]=p("graph_d13_paid_schedule_inputs_v1",("payload_json","payload_digest","pending"),
            ("bot","persona","job_ref"),(*ns,r.job_id))
        self.raws["scene"]=p("graph_d13_paid_scene_jobs_v1",("scene_ref","input_digest","state","expires_at_utc"),
            ("bot","persona","job_ref"),(*ns,r.job_id))
        self.raws["bundle"]=p("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq","receipt_json"),
            ("bot","persona","operation_id"),(*ns,op))
        self.raws["worker"]=p("graph_d13_worker_attempts_v2",("request_digest","pre_graph_epoch","receipt_json"),
            ("bot","persona","operation_id"),(*ns,op))
        acquire="d13-paid-acquire:"+canonical_digest({"job":r.job_id,"holder":self.job.lease_holder})[:48]
        self.raws["acquire"]=p("graph_d13_worker_attempts_v2",("request_digest","pre_graph_epoch","receipt_json"),
            ("bot","persona","operation_id"),(*ns,acquire))
        self.raws["acquire_bundle"]=p("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq","receipt_json"),
            ("bot","persona","operation_id"),(*ns,acquire))
        token=runtime_job_key(*ns,self.job.activity_id,r.job_id).token
        self.raws["job_atom"]=p("graph_atoms",("revision","value","valid"),("token","bot","persona"),(token,*ns))
        self.raws["birth"]=p("graph_history",("event_id","value","valid","event_bot","event_persona","event_session","dependencies"),
            ("token","revision"),(token,1))
        self.raws["acquire_history"]=p("graph_history",("event_id","value","valid","event_bot","event_persona","event_session","dependencies"),
            ("token","revision"),(token,r.work.heads[token][0]))
        self.raws["event"]=p("graph_events",("digest","epoch_reads","revisions","epoch_revision"),
            ("bot","persona","session","event_id"),(*ns,"d13-paid",op))
        if any(self.raws[name]is None for name in self.raws):
            raise AuthorityUnavailable("D13 schedule/create/acquire original family is incomplete")
        self.acquire_operation=acquire
        self.schedule=json.loads(self.raws["schedule"][0])
        columns=("schema","requirements_json","graph_revision")
        self.raws["metadata"]=r.window_body.original_point_v3("graph_recovery_metadata_v2",columns,("bot","persona"),ns)
        if self.raws["schedule"][2]!=0 or set(self.schedule)!={"plan","frozen","binding","exact_count","job","ceiling","intent_digest"}:
            raise AuthorityUnavailable("D13 schedule original has another actual shape/state")
        schedule_request=("graph_d13_paid_schedule_inputs_v1",("payload_json","payload_digest","pending"),
            ("bot","persona","job_ref"),(*ns,r.job_id))
        attachment=r.work.attachments[schedule_request]
        column=attachment.json_columns["payload_json"]
        if column.sha256!=self.raws["schedule"][1]:
            raise AuthorityUnavailable("D13 complete schedule payload EOF digest differs")
        from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
        value={"schema":"d13.paid-precompression-intent.v1","plan":self.frozen.plan,
            "frozen":self.frozen,"binding":self.original.binding,"exact_count":self.original.exact_count,
            "job":self.queued,"ceiling":dict(self.original.ceiling)}
        self.actions=[("schedule",_CanonicalComparisonV3(value,operation=r.operation)),
            ("queued",_CanonicalComparisonV3(self.queued,operation=r.operation))]
        self.phase="hashes"

    def advance_v3(self,meter):
        r=self.reader;r.require_current_v3(meter)
        if self.phase=="rows":self._rows(meter);return
        if self.phase=="hashes":
            name,task=self.actions[0]
            if not task.advance(meter):return
            expected=self.schedule["intent_digest"]if name=="schedule"else self.original.job_digest
            if task.digest!=expected:raise AuthorityUnavailable("D13 actual "+name+" complete commitment differs")
            self.actions.pop(0)
            if not self.actions:self.phase="current"
            return
        if self.phase=="current":
            self._check(meter);self.complete=True;self.phase="complete";return
        raise AuthorityUnavailable("D13 current model proof has an unregistered phase")

    def _check(self,meter):
        from .current_d13_paid_model_graph import CurrentD13PaidModelGraph
        from ..runtime.d11_types import job_graph_write,job_value,_strict_payload,RuntimeJobValue
        from ..runtime.issuers import _decode_quote,_decode_grant
        from ..runtime.budget import _lease_from_row
        from .d13_source_identity_v1 import d13_original_source_identity_v1
        from ..model_broker.d13_precompression import _planned_turns_shape_v1
        r=self.reader;intent=r.work.request;ns=r.namespace.as_tuple
        o,f,call,request=self.original,self.frozen,self.call,self.request
        job,queued=self.job,self.queued;window=r.current_window;now=r.now_utc
        p=lambda t,c,k,v:self.point(meter,t,c,k,v)
        meta=self.raws["metadata"];requirements=json.loads(meta[1]);anchor=r.work.permit.pinned_anchor
        if (meta[0]!="sylanne3.authority.v2"or meta[2]<intent.graph_revision
                or r.work.graph_stamp[0]<intent.graph_epoch
                or r.epochs!=(intent.access_epoch,intent.delete_epoch)
                or requirements["namespace"]!=asdict(r.namespace)
                or tuple(requirements[k]for k in ("authority_id","authority_namespace","activation_generation",
                    "revocation_epoch","deletion_seq","execution_seq"))!=(
                    intent.authority_id,intent.namespace,intent.authority_activation_generation,
                    intent.authority_revocation_epoch,intent.authority_deletion_seq,intent.authority_execution_seq)
                or (anchor.authority_id,anchor.namespace,anchor.activation_generation,anchor.revocation_epoch,
                    anchor.deletion_seq,anchor.execution_seq)!=(
                    intent.authority_id,intent.namespace,intent.authority_activation_generation,
                    intent.authority_revocation_epoch,intent.authority_deletion_seq,intent.authority_execution_seq)):
            raise AuthorityUnavailable("D13 Graph, rights or actual Authority anchor changed")
        deadline=lambda s:datetime.fromisoformat(s.replace("Z","+00:00")).timestamp()
        if (job.work_kind!="d13.precompress.paid.v1"or job.phase!="running"or job.effect_id is not None
                or job.cancel_epoch!=0 or job.result_ref is not None or job.fence!=intent.worker_fence
                or job.lease_holder!=intent.subject or job.lease_expires_utc is None
                or now>=min(deadline(job.deadline_utc),deadline(job.lease_expires_utc),o.binding.expires_at_utc)
                or queued.phase!="queued"or queued.fence!=0 or queued.cancel_epoch!=0
                or replace(job,phase="queued",fence=0,lease_holder=None,lease_expires_utc=None)!=queued
                or self.created[0]!=o.budget_reservation_digest
                or json.loads(self.raws["job_atom"][1])!=job_graph_write(job).value or self.raws["job_atom"][2]!=1
                or self.raws["birth"][0]!=job.operation_id or self.raws["birth"][2]!=1
                or self.raws["birth"][3:6]!=(*ns,"d13-paid")
                or self.raws["acquire_history"][0]!=self.acquire_operation or self.raws["acquire_history"][2]!=1
                or self.raws["acquire_history"][3:6]!=(*ns,"d13-paid")
                or json.loads(self.raws["acquire_history"][1])!=job_graph_write(job).value
                or _strict_payload(json.loads(self.raws["birth"][1]),RuntimeJobValue)!=job_value(queued)):
            raise AuthorityUnavailable("D13 current worker/create/acquire W01 job changed")
        sd=self.schedule;bundle=self.raws["bundle"];worker=self.raws["worker"]
        expected=canonical_digest({"phase":"paid_schedule","intent":sd["intent_digest"]})
        receipt=json.loads(bundle[4])
        acquired=json.loads(self.raws["acquire"][2])
        acq_digest=canonical_digest({"job":job.job_id,"original":o.original_digest,
            "timeout_seconds":request.timeout_seconds,"privacy_tier":request.privacy_tier})
        if (sd["frozen"]!=r.eof.frozen_data or sd["plan"]!=r.eof.frozen_data["plan"]
                or sd["binding"]!=asdict(o.binding)or sd["job"]!=asdict(queued)
                or sd["exact_count"]!=(None if o.exact_count is None else asdict(o.exact_count))
                or sd["ceiling"]!=o.ceiling
                or self.raws["scene"]!=(f.plan.scene_ref.ref,f.plan.input_digest,"running",f.plan.expires_at_utc)
                or bundle[:3]!=(expected,job.activity_id,None)or bundle[3]<1 or worker[0]!=expected
                or json.loads(worker[2])!={"job_id":job.job_id}
                or receipt.get("schema")!="d13.paid_schedule.v2"or receipt.get("original_digest")!=o.original_digest
                or receipt.get("pre_graph_epoch")!=worker[1]
                or self.raws["acquire"][0]!=acq_digest or self.raws["acquire_bundle"][0]!=acq_digest
                or self.raws["acquire_bundle"][1:3]!=(job.activity_id,None)or self.raws["acquire_bundle"][3]<=bundle[3]
                or acquired!={"job_id":job.job_id,"call_original_digest":call.original_digest}
                or (o.namespace,o.binding.job_ref,o.binding.original_operation_id)!=(r.namespace,job.job_id,job.operation_id)
                or o.activation_epoch!=requirements["activation_generation"]
                or (f.window.access_epoch,f.window.delete_epoch,f.window.activation_epoch)!=(o.access_epoch,o.delete_epoch,o.activation_epoch)
                or window.namespace!=r.namespace or window.trusted_utc<f.window.trusted_utc or now>=o.binding.expires_at_utc
                or (window.owner_ref,window.conversation_ref,window.scene_ref,window.audience_ref)!=(
                    f.window.owner_ref,f.window.conversation_ref,f.window.scene_ref,f.window.audience_ref)
                or _planned_turns_shape_v1(window,f.plan)!=f.turns
                or any(job.continuation.get(k)!=v for k,v in {
                    "binding_digest":o.binding.binding_digest,"frozen_input_digest":f.digest,
                    "wire_digest":f.wire_digest,"read_closure_digest":f.read_closure_digest}.items())):
            raise AuthorityUnavailable("D13 frozen schedule, Source or immutable request family changed")
        from ..contracts import Event,Scope
        event=self.raws["event"]
        actual_event=Event(Scope(*ns,"d13-paid"),job.operation_id,receipt["occurred_at_utc"],
            "d13.paid_lifecycle",{"operation_id":job.operation_id})
        if (set(receipt)!={"schema","original_digest","occurred_at_utc","pre_graph_epoch"}
                or type(receipt["occurred_at_utc"])is not float
                or receipt["occurred_at_utc"]>=deadline(queued.deadline_utc)
                or event[0]!=actual_event.digest or json.loads(event[1])!=[[*ns,receipt["pre_graph_epoch"]]]
                or event[3]!=receipt["pre_graph_epoch"]+1):
            raise AuthorityUnavailable("D13 actual schedule W01 event/receipt changed")
        from ..runtime.d11_types import runtime_job_key
        if json.loads(event[2])!=[[runtime_job_key(*ns,job.activity_id,job.job_id).token,1]]:
            raise AuthorityUnavailable("D13 schedule original lost its exact W01 birth revision")
        sources,source_revisions,access_revisions=d13_original_source_identity_v1(f)
        if (intent.source_refs,intent.source_revisions,intent.access_revisions)!=(sources,source_revisions,access_revisions):
            raise AuthorityUnavailable("D13 acquired ordered Source ID/revision tuple changed")
        qrow=p("runtime_resource_quotes",("quote_json","signature"),("quote_id","version"),(o.quote_id,o.quote_version))
        issuer=r.installed.issuer
        issuer.resource_issuer._signer.verify("resource-quote.v1",qrow[0],qrow[1]);quote=_decode_quote(qrow[0])
        qstate=meter.read_fixed_row(r.db,"runtime_resource_quotes",("status",),"quote_id=? AND version=?",(o.quote_id,o.quote_version))
        latest=meter.read_fixed_row(r.db,"runtime_budget_grants",("version","status"),
            "lease_id=? ORDER BY version DESC LIMIT 1",(job.budget_ref,))
        if latest is None or latest[1]!="active":raise AuthorityUnavailable("D13 signed current D11 grant absent")
        grow=p("runtime_budget_grants",("grant_json","signature"),("lease_id","version"),(job.budget_ref,latest[0]))
        issuer._signer.verify("budget-grant.v1",grow[0],grow[1]);grant=_decode_grant(grow[0])
        leases={};lease_id=job.budget_ref
        leasecols=("lease_id","parent_id","bot_id","persona_id","currency","limits_json","used_json","reserved_json","unconfirmed_json","version","state")
        while lease_id is not None:
            if lease_id in leases:raise AuthorityUnavailable("D13 budget lease ancestry is cyclic")
            row=p("runtime_budget_leases",leasecols,("lease_id",),(lease_id,))
            lease=_lease_from_row(row);leases[lease_id]=lease
            if (lease.bot_id,lease.persona_id)!=ns:raise AuthorityUnavailable("D13 budget parent crossed namespace")
            if meter.read_fixed_row(r.db,"runtime_budget_debt_blocks",("lease_id",),"lease_id=? LIMIT 1",(lease_id,))is not None:
                raise AuthorityUnavailable("D13 budget ancestry has unresolved overrun debt")
            lease_id=lease.parent_id
        lease=leases[job.budget_ref]
        reservation=p("runtime_budget_reservations",("digest","ceiling_json","state"),("lease_id","operation_id"),
            (job.budget_ref,o.budget_operation_id))
        from ..contracts import canonical_json
        ceiling=dict(intent.budget_ceiling)
        if (canonical_digest(quote)!=o.quote_digest or canonical_digest(grant)!=o.grant_digest
                or (grant.grant_id,grant.version)!=(o.grant_id,o.grant_version)
                or quote.quote_id!=o.quote_id or quote.version!=o.quote_version
                or quote.work_kind!="d13.precompress.paid.v1"or quote.operation_id!=job.operation_id
                or (quote.bot_id,quote.persona_id,quote.activity_id,quote.effect_id)!=(*ns,job.activity_id,None)
                or quote.required_worker_fence is not None or quote.outbox_refs!=()or quote.d02_settlement_refs!=()
                or quote.graph_job_ref!=job_graph_write(job).key.token
                or quote.parent_budget_lease_ref!=job.budget_ref or quote.snapshot_ref!=job.snapshot_ref
                or quote.resource_ref!=job.resource_ref or quote.ceiling!=ceiling or o.ceiling!=ceiling
                or qstate!=("active",)or now>=quote.valid_until_utc or now>=grant.valid_until_utc
                or grant.lease_id!=job.budget_ref or "d13.precompress.paid.v1"not in grant.allowed_work_kinds
                or lease.state!="active"or lease.currency!=grant.currency
                or any(n>grant.max_ceiling.get(k,0)or lease.reserved.get(k,0)<n for k,n in ceiling.items())
                or reservation!=(o.budget_reservation_digest,canonical_json(ceiling),"reserved")
                or (intent.budget_lease_id,intent.budget_reservation_operation_id,intent.budget_reservation_digest)!=(
                    job.budget_ref,o.budget_operation_id,o.budget_reservation_digest)
                or (intent.provider_id,intent.model_id,intent.provider_config_digest,intent.max_output_tokens)!=(
                    f.installation.provider_id,f.installation.model_id,f.installation.provider_config_digest,f.installation.max_output_tokens)
                or f.installation!=r.installed.bundle.d13_paid_precompression.selected_main
                or ceiling.get("output_tokens",0)<intent.max_output_tokens
                or (call.binding_digest,call.intent_original_digest,call.worker_fence,call.request_digest)!=(
                    o.binding.binding_digest,o.original_digest,job.fence,intent.request_digest)
                or request.digest!=intent.request_digest):
            raise AuthorityUnavailable("D13 signed quote/current grant/reservation or original model bounds changed")
        self.checked_leases=leases
        self.result=CurrentD13PaidModelGraph(o,window,job,request)
        self.identity=(r.work,r.operation,r.work.scope,r.work.selection_digest,r.work.request,r.work.permit,r.eof,self.result)

    def require_current_v3(self):
        r=self.reader;r.require_registered_v3()
        if (not self.complete or self.identity!=(r.work,r.operation,r.work.scope,r.work.selection_digest,
                r.work.request,r.work.permit,r.eof,self.result)or r.result is not self.result):
            raise AuthorityUnavailable("D13 current model proof lost its actual completed full EOF seal")
        return self


    def release_v3(self):
        self.raws.clear();self.actions.clear();self.checked_leases.clear()
        self.original=self.frozen=self.call=self.request=self.schedule=self.job=self.queued=self.result=None
