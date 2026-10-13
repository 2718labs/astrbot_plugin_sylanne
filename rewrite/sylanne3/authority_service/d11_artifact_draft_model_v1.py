"""Independent C4 current Graph qualification and exact paired result codec."""
from dataclasses import dataclass,fields
from datetime import datetime
import json

from .contract import AuthorityUnavailable,identifier
from .v2_model_egress_contract import ModelEgressIntentV1,ModelEgressObservationV1,ModelTerminalReceiptV2
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1,artifact_draft_from_wire_v1,artifact_draft_model_ids_v1,_digest


@dataclass(frozen=True,slots=True)
class ArtifactDraftModelResultReadRequestV1:
    authority_id:str
    authority_namespace:str
    namespace:NamespaceId
    installation_id:str
    selector:ArtifactDraftTaskSelectorV1
    job_id:str
    acquire_operation_id:str
    original_operation_id:str
    call_id:str
    binding_digest:str
    model_request_digest:str
    consumer_operation_id:str
    read_attempt_id:str
    purpose:str="artifact_draft_adoption"
    schema:str="d11.artifact-draft-model-result-read.v1"

    def __post_init__(self):
        if (self.schema!="d11.artifact-draft-model-result-read.v1" or self.purpose!="artifact_draft_adoption"
                or type(self.namespace) is not NamespaceId or type(self.selector) is not ArtifactDraftTaskSelectorV1
                or self.selector.namespace!=self.namespace):raise ValueError("exact C4 result-read scope required")
        for name in ("authority_id","authority_namespace","installation_id","job_id","acquire_operation_id",
                "original_operation_id","call_id","consumer_operation_id","read_attempt_id"):identifier(getattr(self,name),name)
        _digest(self.binding_digest);_digest(self.model_request_digest)
        ids=artifact_draft_model_ids_v1(self.selector)
        if (self.job_id,self.acquire_operation_id,self.original_operation_id,self.call_id,self.consumer_operation_id,self.read_attempt_id)!= (
                ids["job"],ids["acquire"],ids["prepare"],ids["call"],ids["adopt"],"artifact-draft-read:"+self.selector.digest[:40]):
            raise ValueError("C4 result read changed the original once identities")

    @property
    def digest(self):return canonical_digest(plain_v1(self))


@dataclass(frozen=True,slots=True)
class ArtifactDraftModelResultReadV1:
    request:ArtifactDraftModelResultReadRequestV1
    observation:ModelEgressObservationV1
    terminal_receipt:ModelTerminalReceiptV2
    schema:str="d11.artifact-draft-model-result-read.v1"

    def __post_init__(self):
        r,o,t=self.request,self.observation,self.terminal_receipt
        if (self.schema!="d11.artifact-draft-model-result-read.v1" or type(r) is not ArtifactDraftModelResultReadRequestV1
                or type(o) is not ModelEgressObservationV1 or type(t) is not ModelTerminalReceiptV2 or o.status!="completed"
                or (o.authority_id,o.namespace,o.call_id,o.request_digest)!=(r.authority_id,r.authority_namespace,r.call_id,r.model_request_digest)
                or (t.call_id,t.request_digest,t.observation_digest,t.installation_id)!=(r.call_id,r.model_request_digest,o.digest,r.installation_id)):
            raise ValueError("C4 paired result differs from its actual terminal/request")


def artifact_draft_model_result_to_wire_v1(value):
    from .v2_model_egress_wire import to_wire
    if type(value) is ArtifactDraftModelResultReadRequestV1:return plain_v1(value)
    if type(value) is ArtifactDraftModelResultReadV1:
        return {"request":plain_v1(value.request),"observation":to_wire(value.observation),
            "terminal_receipt":to_wire(value.terminal_receipt),"schema":value.schema}
    raise TypeError("closed C4 model result type required")


def artifact_draft_model_result_from_wire_v1(raw,kind):
    from .v2_model_egress_wire import from_wire
    if kind not in {ArtifactDraftModelResultReadRequestV1,ArtifactDraftModelResultReadV1} or type(raw) is not dict or set(raw)!={f.name for f in fields(kind)}:
        raise ValueError("closed C4 result fields differ")
    data=dict(raw)
    if kind is ArtifactDraftModelResultReadRequestV1:
        data["namespace"]=NamespaceId(**data["namespace"])
        data["selector"]=artifact_draft_from_wire_v1(data["selector"],ArtifactDraftTaskSelectorV1)
    else:
        data["request"]=artifact_draft_model_result_from_wire_v1(data["request"],ArtifactDraftModelResultReadRequestV1)
        data["observation"]=from_wire(data["observation"],ModelEgressObservationV1)
        data["terminal_receipt"]=from_wire(data["terminal_receipt"],ModelTerminalReceiptV2)
    result=kind(**data)
    if artifact_draft_model_result_to_wire_v1(result)!=raw:raise ValueError("noncanonical C4 result wire")
    return result


def _read_current_artifact_draft_model_graph(db,intent,issuer,now,*,installed_bundle,phase,
        allow_unsealed_prepare=False,allow_accounted_result=False):
    """Read actual current originals; used by the existing Core model verifier."""
    from ..runtime.d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v1,
        read_artifact_draft_frozen_v1,read_artifact_draft_model_request_v1,installed_artifact_draft_workflow_v1)
    from ..runtime.d11_life_preparation_v1 import _read
    from ..runtime.jobs import get_job
    from ..runtime.d11_types import job_graph_write
    from ..runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from ..runtime.budget import require_budget_family_admissible
    from ..graph_types import AtomKey
    from ..domains.d03.self_perspective import self_mapping_key
    from .current_foreground_activity_v1 import _source_family_current_sql_v1
    from .v2_model_egress_wire import to_wire
    if not db.in_transaction or type(intent) is not ModelEgressIntentV1:raise AuthorityUnavailable("C4 requires real pinned Core verifier input")
    from ..runtime.d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v2,
        read_artifact_draft_frozen_v2, read_artifact_draft_model_request_v2, installed_artifact_draft_workflow_v2,
        require_current_artifact_phase_group_v2, _require_artifact_phase_candidate_current_sql_v2,
        _current_artifact_phase_parameters_v2)
    from ..runtime.foreground_call_plan_v1 import ForegroundCallPlanV2
    read_prepared = read_artifact_draft_prepared_v2 if phase else read_artifact_draft_prepared_v1
    read_frozen = read_artifact_draft_frozen_v2 if phase else read_artifact_draft_frozen_v1
    read_request = read_artifact_draft_model_request_v2 if phase else read_artifact_draft_model_request_v1
    read_workflow = installed_artifact_draft_workflow_v2 if phase else installed_artifact_draft_workflow_v1
    job=get_job(db,intent.job_id)
    if job is None or job.continuation.get("schema") != ("d11.artifact-draft-phase-model-job.v2" if phase else "d11.artifact-draft-model-job.v1") or job.work_kind!="artifact_draft_v1" or set(job.continuation)!={"schema","selector","prepared_digest"}:
        raise AuthorityUnavailable("C4 actual job is not the closed prepared variant")
    selector = (artifact_draft_from_wire_v2(job.continuation['selector'], ArtifactDraftPhaseSelectorV2)
        if phase else artifact_draft_from_wire_v1(job.continuation['selector'], ArtifactDraftTaskSelectorV1))
    task = selector.task if phase else selector
    p=read_prepared(db,namespace=task.namespace,issuer=issuer,selector=selector)
    if p is None:raise AuthorityUnavailable("C4 actual prepared original absent")
    frozen=read_frozen(db,prepared=p,issuer=issuer)
    request=read_request(db,prepared=p,issuer=issuer)
    if phase:
        from ..runtime.d11_artifact_draft_model_v1 import require_saved_artifact_phase_count_original_v2
        require_saved_artifact_phase_count_original_v2(db, prepared=p, issuer=issuer, now_utc=now, installed_bundle=installed_bundle)
    workflow=read_workflow(installed_bundle)
    from ..model_broker.artifact_draft_v1 import TEMPLATE_DIGEST,WORK_KIND
    if (dict(request.payload)!=frozen.wire or request.prompt_template_digest!=(TEMPLATE_DIGEST_V2 if phase else TEMPLATE_DIGEST)
            or request.identity.phase!=WORK_KIND or request.envelope.authority.purpose!="consolidation"
            or request.envelope.authority.actor!=p.worker_subject or request.envelope.authority.namespace!=p.namespace
            or request.envelope.authority.worker_fence!=intent.worker_fence
            or request.envelope.authority.audience!=p.audiences
            or request.envelope.parent_budget_lease_ref!=p.parent_budget_lease_ref):
        raise AuthorityUnavailable("C4 actual acquired request differs from complete frozen server input")
    from ..runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    from ..runtime.artifact_continuation_originals_v1 import require_selected_artifact_target_sql_v1
    root_original = _read(db, issuer=issuer, namespace=p.namespace, kind="draft_root_capability",
        ref=task.root_registration_ref)
    if root_original is None:
        raise AuthorityUnavailable("C4 actual registered Root absent")
    root = draft_from_wire_v1(root_original[0], DraftRootCapabilityV1)
    from ..runtime.d11_offline_originals_v1 import _utc
    if ((root.installation_id, root.manifest_digest, root.source_ref) !=
            (p.installation_id, p.manifest_digest, frozen.task_source_ref)
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
                (p.owner_guard.grant_ref, p.owner_guard.grant_revision, p.owner_guard.grant_digest)
            or now >= _utc(root.valid_until_utc).timestamp()):
        raise AuthorityUnavailable("C4 actual current Root installation/Owner/Source/deadline changed")
    if phase:
        from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV3
        from ..runtime.artifact_phase_postconditions_v1 import readonly_current_artifact_phase_postcondition_contract_v1
        contract = readonly_current_artifact_phase_postcondition_contract_v1(db, namespace=p.namespace,
            selector=selector, issuer=issuer, now_utc=now, owner_guard=p.owner_guard, installed_bundle=installed_bundle)
        if (type(frozen) is not ArtifactDraftInputV3 or
                (frozen.postcondition_contract_ref, frozen.postcondition_contract_digest) != (contract.original_ref, contract.digest)):
            raise AuthorityUnavailable('phase frozen material lost its actual preregistered postcondition contract')
        chosen = _require_artifact_phase_candidate_current_sql_v2(db, selector=selector, issuer=issuer, now=now,
            owner_guard=p.owner_guard, audiences=p.audiences, installed_bundle=installed_bundle)
        if _current_artifact_phase_parameters_v2(db, selector=selector, chosen=chosen, issuer=issuer) != (
                frozen.extent, frozen.target, frozen.prior_content):
            raise AuthorityUnavailable('phase frozen parameters differ from actual chosen candidate')
        if frozen.prior_content is not None:
            from ..runtime.d11_artifact_draft_content_v1 import require_current_artifact_prior_content_v2
            require_current_artifact_prior_content_v2(db, namespace=p.namespace, selector=selector,
                prior=frozen.prior_content, issuer=issuer)
    else:
        require_selected_artifact_target_sql_v1(db, namespace=p.namespace, selector=selector,
            root=root, target=frozen.target, issuer=issuer)
    from ..host.authority_profile import require_installed_artifact_target_v2
    require_installed_artifact_target_v2(installed_bundle.artifact_draft, root, frozen.target)
    call=_read(db,issuer=issuer,namespace=p.namespace,kind="c4_phase_call" if phase else "c4_call",ref=p.call_id)
    if (call is None and not allow_unsealed_prepare or call is not None and call[0]!=to_wire(intent)
            or (intent.job_id,intent.call_id,intent.binding_digest,intent.request_digest,intent.acquire_operation_id,
                intent.budget_reservation_operation_id,intent.budget_reservation_digest)!=(p.job_id,p.call_id,p.digest,request.digest,
                p.acquire_operation_id,p.operation_id,p.reservation_digest)
            or (job.phase,job.fence,job.cancel_epoch,job.lease_holder,job.result_ref)!=("running",1,0,intent.subject,None)
            or intent.worker_fence!=job.fence or p.worker_subject!=intent.subject or p.actor_ref!=frozen.current_self_ref
            or job.lease_expires_utc is None or now>=min(frozen.deadline_utc,
                datetime.fromisoformat(job.lease_expires_utc.replace("Z","+00:00")).timestamp())
            or canonical_digest(plain_v1(workflow))!=p.workflow_digest
            or (intent.provider_id,intent.model_id,intent.provider_config_digest,intent.max_output_tokens)!=
                (workflow.provider_id,workflow.model_id,workflow.provider_config_digest,
                    min(workflow.max_output_tokens, artifact_draft_phase_token_limits_v2(selector)["output_tokens"]) if phase else workflow.max_output_tokens)):
        raise AuthorityUnavailable("C4 exact seal/current worker/config/deadline changed")
    cycle=get_job(db,AtomKey.from_token(task.cycle_job_ref).name)
    cont=foreground_cycle_from_wire_v1(cycle.continuation)
    if (cycle.cancel_epoch or cycle.phase in {"completed","failed","cancelled","draining","pending_confirmation"}
            or cont.c02_operation_id!=task.c02_operation_id or cont.source_ref!=frozen.task_source_ref
            or cont.call_plan.parent_budget_lease_ref!=p.parent_budget_lease_ref):
        raise AuthorityUnavailable("C4 parent cycle/task/budget is no longer current")
    if phase:
        if type(cont.call_plan) is not ForegroundCallPlanV2 or cont.call_plan.phase_group.selector != selector:
            raise AuthorityUnavailable('phase current group changed original call selector')
        require_current_artifact_phase_group_v2(db, namespace=p.namespace, group=cont.call_plan.phase_group, issuer=issuer)
        from ..runtime.d11_artifact_draft_model_v1 import read_current_artifact_draft_attempt_v2
        attempts = tuple(row for row in cont.call_plan.attempts if row.call_id == p.call_id)
        if len(attempts) != 1:
            raise AuthorityUnavailable('phase call lost unique actual physical call plan member')
        actual = read_current_artifact_draft_attempt_v2(db, namespace=p.namespace, continuation=cont,
            attempt=attempts[0], issuer=issuer)
        if actual != attempts[0] and not allow_accounted_result:
            raise AuthorityUnavailable('phase original physical reservation state changed')
    _source_family_current_sql_v1(db,namespace=p.namespace,roots=(frozen.task_source_ref,),purpose="consolidation",audiences=p.audiences)
    for version in frozen.source_read_versions:
        row=db.execute("SELECT revision FROM graph_atoms WHERE bot=? AND persona=? AND token=?",(*p.namespace.as_tuple,version.key.token)).fetchone()
        if (0 if row is None else row[0])!=version.revision:raise AuthorityUnavailable("C4 exact input/negative read changed")
    for source in frozen.sources:
        row=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(source.ref,)).fetchone()
        if row is None or row[1]!=1 or canonical_digest(json.loads(row[0]))!=source.value_digest:
            raise AuthorityUnavailable("C4 actual Source bytes changed")
    mapping=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(self_mapping_key(p.namespace).token,)).fetchone()
    if mapping is None or mapping[1]!=1 or canonical_digest(json.loads(mapping[0]))!=frozen.current_self_digest:
        raise AuthorityUnavailable("C4 actual registered self mapping changed")
    rights=db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",p.namespace.as_tuple).fetchone()
    if rights!=(intent.access_epoch,intent.delete_epoch):raise AuthorityUnavailable("C4 current Source rights barrier differs")
    meta=db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",p.namespace.as_tuple).fetchone()
    epoch=db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",p.namespace.as_tuple).fetchone()
    if meta is None or epoch is None:raise AuthorityUnavailable("C4 actual current Authority Graph stamp absent")
    anchor=json.loads(meta[0])
    expected={"authority_id":intent.authority_id,"authority_namespace":intent.namespace,
        "activation_generation":intent.authority_activation_generation,"revocation_epoch":intent.authority_revocation_epoch,
        "deletion_seq":intent.authority_deletion_seq,"execution_seq":intent.authority_execution_seq}
    if any(anchor.get(name)!=value for name,value in expected.items()) or p.activation_generation!=intent.authority_activation_generation:
        raise AuthorityUnavailable("C4 actual restoration/generation anchor changed")
    if not allow_accounted_result and (meta[1],epoch[0])!=(intent.graph_revision,intent.graph_epoch):
        raise AuthorityUnavailable("C4 actual acquired Graph revision/negative epoch changed before admission")
    _require_current_model_project_capacity_v1(db,prepared=p,request=request,issuer=issuer,
        installed_bundle=installed_bundle,now=now,epoch=epoch[0],rights=rights)
    atom=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(job_graph_write(job).key.token,)).fetchone()
    if atom is None or atom[1]!=1 or json.loads(atom[0])!=job_graph_write(job).value:raise AuthorityUnavailable("C4 acquired SQL/Graph job differs")
    quote=issuer.resource_issuer.original_signed_quote(db,p.quote_id,1)
    if (canonical_digest(quote)!=p.quote_digest or tuple(sorted(quote.ceiling.items()))!=intent.budget_ceiling
            or phase and any(amount > workflow.quote_ceiling.get(dimension,0) for dimension,amount in quote.ceiling.items())):
        raise AuthorityUnavailable("C4 actual signed quote differs")
    reserved=db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (p.parent_budget_lease_ref,p.operation_id)).fetchone()
    allowed={"reserved","settled","overrun","unknown","partial_unknown","partial_overrun"} if allow_accounted_result else {"reserved"}
    if reserved is None or reserved[:2]!=(p.reservation_digest,canonical_serialize(dict(quote.ceiling))) or reserved[2] not in allowed:
        raise AuthorityUnavailable("C4 exact original budget state differs")
    if not allow_accounted_result:require_budget_family_admissible(db,p.parent_budget_lease_ref)
    return p,job,frozen


def read_current_artifact_draft_model_graph_v1(db, intent, issuer, now, *, installed_bundle,
        allow_unsealed_prepare=False, allow_accounted_result=False):
    return _read_current_artifact_draft_model_graph(db, intent, issuer, now, installed_bundle=installed_bundle,
        phase=False, allow_unsealed_prepare=allow_unsealed_prepare, allow_accounted_result=allow_accounted_result)


def read_current_artifact_draft_prepared_v2(db, intent, issuer, now, *, installed_bundle,
        allow_unsealed_prepare=False, allow_accounted_result=False):
    return _read_current_artifact_draft_model_graph(db, intent, issuer, now, installed_bundle=installed_bundle,
        phase=True, allow_unsealed_prepare=allow_unsealed_prepare, allow_accounted_result=allow_accounted_result)


def _require_current_model_project_capacity_v1(db,*,prepared,request,issuer,installed_bundle,now,epoch,rights):
    """Actual current namespace read, with full coverage and authenticated rows.

    This server-only frame is a read view for the same D10 invariant. It is
    never exported, committed, used as a private issuance, or a permit.
    """
    from dataclasses import replace
    from ..runtime.d10_project_checkpoint_v1 import read_plan_current_project_capacity_v1,require_current_artifact_project_capacity_v1
    from ..runtime.d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from ..runtime.d11_life_product_adapter_v1 import read_current_life_original_ref_v1
    from ..runtime.domain_production_contracts_v1 import CurrentOperationFrameV1,ProductionQueryCoverageV1
    from ..graph_types import GraphAtom,GraphSnapshot,GraphVersion,NamespaceEpoch,AtomKey
    from ..runtime_contracts import QueryEpoch
    ns=prepared.namespace;plan=read_plan_current_project_capacity_v1(db,namespace=ns,selector=prepared.selector.task if type(prepared.selector) is ArtifactDraftPhaseSelectorV2 else prepared.selector)
    keys=set(plan.exact_keys);keys.add(AtomKey.from_token(prepared.owner_guard.grant_ref))
    pages=[]
    for kind in plan.fixed_type_ids:
        rows=db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*ns.as_tuple,kind)).fetchall()
        if len(rows)>128:raise AuthorityUnavailable("complete current C4 project capacity inventory exceeds bound")
        versions=tuple(GraphVersion(AtomKey.from_token(token),revision) for token,revision in rows)
        keys.update(version.key for version in versions)
        pages.append(ProductionQueryCoverageV1(QueryEpoch(ns,"namespace",epoch),kind,versions,True,None))
    atoms=[]
    for key in sorted(keys,key=lambda value:value.token):
        row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",(*ns.as_tuple,key.token)).fetchone()
        atoms.append(GraphAtom(key,row[0],json.loads(row[1]),bool(row[2])) if row else GraphAtom(key,0,{},False))
    snapshot=GraphSnapshot(tuple(atoms),(NamespaceEpoch(*ns.as_tuple,epoch),))
    originals=[]
    for ref in plan.required_original_refs:
        original=read_current_life_original_ref_v1(db,namespace=ns,original_ref=ref,issuer=issuer)
        if original is not None:originals.append(original)
    envelope=replace(request.envelope,authority=replace(request.envelope.authority,actor=prepared.actor_ref),
        version_guard=replace(request.envelope.version_guard,read_versions=snapshot.versions,
            query_epochs=(QueryEpoch(ns,"namespace",epoch),),access_epoch=rights[0],delete_epoch=rights[1]))
    frame=CurrentOperationFrameV1(envelope,snapshot,now,prepared.owner_guard,prepared.activation_generation,
        tuple(pages),(),tuple(originals))
    readers=InstalledArtifactDraftModelReadersV1(issuer,installed_bundle)
    require_current_artifact_project_capacity_v1(db,frame=frame,selector=prepared.selector.task if type(prepared.selector) is ArtifactDraftPhaseSelectorV2 else prepared.selector,installed_readers=readers)


@dataclass(frozen=True,slots=True)
class ArtifactDraftModelResultDeliveryV1:
    result:ArtifactDraftModelResultReadV1
    permit:object


from .v2_natural_generation_output_service import AuthorityV2NaturalGenerationOutputService


class AuthorityArtifactDraftModelResultServiceV1(AuthorityV2NaturalGenerationOutputService):
    """Existing same-Core terminal reader plus the shared once read-attempt row."""
    def __init__(self,*,store,fences,graph_db_path,d11_issuer,installed_bundle,
            installation_id,read_subject,holder,trusted_now_utc,read_attempts,
            owner_stop_reply_service=None):
        from .v2_model_egress_store import AuthorityV2ModelEgressStore
        from .v2_fence_service import AuthorityV2FenceService
        from .v2_worker_model_result_attempts import AuthorityV2WorkerModelResultAttempts
        from ..runtime.issuers import D11BudgetJobIssuer
        from ..host.authority_profile import AdminInstallationBundle
        from pathlib import Path
        import threading
        if (type(store) is not AuthorityV2ModelEgressStore or type(fences) is not AuthorityV2FenceService
                or type(d11_issuer) is not D11BudgetJobIssuer or type(installed_bundle) is not AdminInstallationBundle
                or type(read_attempts) is not AuthorityV2WorkerModelResultAttempts
                or store._db is not fences.core._db or read_attempts._db is not store._db
                or store._lock is not fences.core._lock or read_attempts._lock is not store._lock):
            raise AuthorityUnavailable("C4 result service requires the actual same Core/model/read-attempt handles")
        self._store,self._fences,self._issuer=store,fences,d11_issuer
        self._bundle,self._attempts=installed_bundle,read_attempts
        self._path=Path(graph_db_path).resolve(strict=True)
        self._installation_id,self._read_subject,self._holder=installation_id,read_subject,holder
        self._clock=trusted_now_utc;self._delivery_lock=threading.RLock();self._inflight_deliveries={}
        self._owner_stop_reply_service_v1=None
        if owner_stop_reply_service is not None:
            self.install_owner_stop_reply_service_v1(owner_stop_reply_service)

    def install_owner_stop_reply_service_v1(self, service):
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        if (type(service) is not InstalledOwnerStopReplyServiceV1
                or service.core is not self._fences.core or service.issuer is not self._issuer
                or service.installation_id != self._installation_id
                or service.namespace_id != self._bundle.installation_policy.namespace
                or service.status_service._source_graphs[self._installation_id] != self._path
                or self._owner_stop_reply_service_v1 is not None):
            raise AuthorityUnavailable("C4 result barrier requires the actual same installed Core/Graph service")
        self._owner_stop_reply_service_v1=service

    def _require_reply_scope_in_tx_v1(self, db, scope, anchor):
        from .owner_stop_reply_v1 import require_reply_scope_not_stopped_in_tx_v1
        require_reply_scope_not_stopped_in_tx_v1(db,
            authority_namespace=self._fences.namespace, installation_id=self._installation_id,
            activation_generation=anchor.activation_generation, actual_cycle_identity=scope,
            action="model_result")

    def _read_original(self, request, anchor, *, content, reply_scope=None):
        with self._fences._frozen() as (db, deletion_head, execution_head, history):
            current=self._fences._current_locked(db,deletion_head,execution_head,
                holder=self._holder,generation=anchor.activation_generation)
            if current != anchor:
                raise AuthorityUnavailable("C4 result read anchor changed")
            if content:
                self._require_reply_scope_in_tx_v1(db,reply_scope,anchor)
            return self._terminal_locked(db,request,anchor,content=content)

    def _scope(self,request):
        if (type(request) not in {ArtifactDraftModelResultReadRequestV1, ArtifactDraftModelResultReadRequestV2}
                or request.installation_id!=self._installation_id or request.authority_namespace!=self._fences.namespace):
            raise AuthorityUnavailable("C4 result read crossed installed scope")

    def _graph_read(self,request,intent):
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(self._path.as_uri()+"?mode=ro",uri=True,isolation_level=None)) as db:
            db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
            reader = (read_current_artifact_draft_prepared_v2 if type(request) is ArtifactDraftModelResultReadRequestV2
                else read_current_artifact_draft_model_graph_v1)
            p,job,frozen=reader(db,intent,self._issuer,self._clock(),
                installed_bundle=self._bundle,allow_accounted_result=True)
            if (request.selector,request.binding_digest,request.model_request_digest,request.original_operation_id)!=(
                    p.selector,p.digest,intent.request_digest,p.operation_id):raise AuthorityUnavailable("C4 result selector differs from actual original")
            return p,job,frozen

    def prepare(self,*,credential,request,now_utc=None):
        self._scope(request)
        with self._delivery_lock:
            if request.read_attempt_id in self._inflight_deliveries:raise AuthorityUnavailable("C4 result delivery already active")
            self._inflight_deliveries[request.read_attempt_id]=None
        try:
            self._fences.core._require(credential,"read",request.authority_namespace,self._holder)
            if self._attempts.read(request) is not None:raise AuthorityUnavailable("C4 result read was attempted; never reread its body")
            anchor=self._fences.current_anchor(credential=credential,subject=self._read_subject)
            if anchor.authority_id!=request.authority_id:raise AuthorityUnavailable("C4 result Authority identity differs")
            intent,terminal,_=self._read_original(request,anchor,content=False)
            before=self._graph_read(request,intent)
            service=self._owner_stop_reply_service_v1
            if service is None:
                raise AuthorityUnavailable("C4 new result read lacks its actual installed reply barrier")
            selector = before[0].selector
            task = selector.task if type(selector) is ArtifactDraftPhaseSelectorV2 else selector
            reply_scope=service.observe_actual_reply_scope_v1(c02_operation_id=task.c02_operation_id)
            permit=self._fences.begin_fence(credential=credential,subject=self._read_subject,holder=self._holder,
                operation="read",operation_id=request.read_attempt_id,expected_anchor=anchor)
            with self._fences.core._tx() as db:
                self._fences.fences.validate_fence_locked(db,permit,subject=self._read_subject,current_anchor=anchor)
                if self._attempts._read_locked(db,request.read_attempt_id) is not None:
                    raise AuthorityUnavailable("C4 result read already attempted")
                self._require_reply_scope_in_tx_v1(db,reply_scope,anchor)
                self._attempts.begin_locked(db,request,permit=permit)
            current,receipt,observation=self._read_original(request,anchor,content=True,reply_scope=reply_scope)
            if current!=intent or receipt!=terminal or self._graph_read(request,intent)!=before:
                raise AuthorityUnavailable("C4 current input/terminal changed during result copy")
            if observation.result_json is None or len(observation.result_json.encode())>65536:
                raise AuthorityUnavailable("C4 actual result exceeds encoded64KiB")
            phase = type(request) is ArtifactDraftModelResultReadRequestV2
            result=(ArtifactDraftModelResultReadV2 if phase else ArtifactDraftModelResultReadV1)(request,observation,terminal)
            with self._fences.core._tx() as db:
                self._fences.fences.validate_fence_locked(db,permit,subject=self._read_subject,current_anchor=anchor)
                self._require_reply_scope_in_tx_v1(db,reply_scope,anchor)
            delivery=(ArtifactDraftModelResultDeliveryV2 if phase else ArtifactDraftModelResultDeliveryV1)(result,permit)
            with self._delivery_lock:self._inflight_deliveries[request.read_attempt_id]=delivery
            return delivery
        except BaseException:
            with self._delivery_lock:self._inflight_deliveries.pop(request.read_attempt_id,None)
            # An attempted read remains UNKNOWN. No exception authorizes fresh
            # content I/O or reconstructs an acknowledgement/result body.
            raise

    def finish_delivery(self,*,credential,delivery):
        if type(delivery) not in {ArtifactDraftModelResultDeliveryV1, ArtifactDraftModelResultDeliveryV2}:raise AuthorityUnavailable("actual C4 delivery required")
        key=delivery.result.request.read_attempt_id
        with self._delivery_lock:
            if self._inflight_deliveries.get(key) is not delivery:raise AuthorityUnavailable("C4 delivery is not the actual inflight original")
            with self._fences.core._tx() as db:
                self._fences.fences.validate_fence_locked(db,delivery.permit,subject=self._read_subject,current_anchor=delivery.permit.pinned_anchor)
                wire = artifact_draft_model_result_to_wire_v2 if type(delivery) is ArtifactDraftModelResultDeliveryV2 else artifact_draft_model_result_to_wire_v1
                digest=canonical_digest(wire(delivery.result))
                self._attempts.finish_locked(db,delivery.result.request,permit=delivery.permit,result_digest=digest)
                self._fences.fences.finish_fence_locked(db,delivery.permit,subject=self._read_subject,
                    current_anchor=delivery.permit.pinned_anchor,request_id=key+":delivered",request_digest="sha256:"+digest)
            self._inflight_deliveries.pop(key,None)

    def abandon_delivery(self,*,delivery):
        if type(delivery) not in {ArtifactDraftModelResultDeliveryV1, ArtifactDraftModelResultDeliveryV2}:raise AuthorityUnavailable("actual C4 delivery required")
        with self._delivery_lock:
            self._inflight_deliveries.pop(delivery.result.request.read_attempt_id,None)


from ..model_broker.artifact_draft_v1 import (ArtifactDraftPhaseSelectorV2, artifact_draft_from_wire_v2,
    artifact_draft_model_ids_v2, artifact_draft_phase_token_limits_v2, TEMPLATE_DIGEST_V2)

@dataclass(frozen=True,slots=True)
class ArtifactDraftModelResultReadRequestV2:
    authority_id:str
    authority_namespace:str
    namespace:NamespaceId
    installation_id:str
    selector:ArtifactDraftPhaseSelectorV2
    job_id:str
    acquire_operation_id:str
    original_operation_id:str
    call_id:str
    binding_digest:str
    model_request_digest:str
    consumer_operation_id:str
    read_attempt_id:str
    purpose:str="artifact_draft_phase_adoption"
    schema:str="d11.artifact-draft-phase-model-result-read.v2"

    def __post_init__(self):
        if (self.schema!="d11.artifact-draft-phase-model-result-read.v2" or self.purpose!="artifact_draft_phase_adoption"
                or type(self.namespace) is not NamespaceId or type(self.selector) is not ArtifactDraftPhaseSelectorV2
                or self.selector.task.namespace!=self.namespace):raise ValueError("exact C4 result-read scope required")
        for name in ("authority_id","authority_namespace","installation_id","job_id","acquire_operation_id",
                "original_operation_id","call_id","consumer_operation_id","read_attempt_id"):identifier(getattr(self,name),name)
        _digest(self.binding_digest);_digest(self.model_request_digest)
        ids=artifact_draft_model_ids_v2(self.selector)
        if (self.job_id,self.acquire_operation_id,self.original_operation_id,self.call_id,self.consumer_operation_id,self.read_attempt_id)!= (
                ids["job"],ids["acquire"],ids["prepare"],ids["call"],ids["adopt"],"artifact-draft-phase-read:"+self.selector.identity_digest[:40]):
            raise ValueError("C4 result read changed the original once identities")

    @property
    def digest(self):return canonical_digest(plain_v1(self))


@dataclass(frozen=True,slots=True)
class ArtifactDraftModelResultReadV2:
    request:ArtifactDraftModelResultReadRequestV2
    observation:ModelEgressObservationV1
    terminal_receipt:ModelTerminalReceiptV2
    schema:str="d11.artifact-draft-phase-model-result-read.v2"

    def __post_init__(self):
        r,o,t=self.request,self.observation,self.terminal_receipt
        if (self.schema!="d11.artifact-draft-phase-model-result-read.v2" or type(r) is not ArtifactDraftModelResultReadRequestV2
                or type(o) is not ModelEgressObservationV1 or type(t) is not ModelTerminalReceiptV2 or o.status!="completed"
                or (o.authority_id,o.namespace,o.call_id,o.request_digest)!=(r.authority_id,r.authority_namespace,r.call_id,r.model_request_digest)
                or (t.call_id,t.request_digest,t.observation_digest,t.installation_id)!=(r.call_id,r.model_request_digest,o.digest,r.installation_id)):
            raise ValueError("C4 paired result differs from its actual terminal/request")


def artifact_draft_model_result_to_wire_v2(value):
    from .v2_model_egress_wire import to_wire
    if type(value) is ArtifactDraftModelResultReadRequestV2:return plain_v1(value)
    if type(value) is ArtifactDraftModelResultReadV2:
        return {"request":plain_v1(value.request),"observation":to_wire(value.observation),
            "terminal_receipt":to_wire(value.terminal_receipt),"schema":value.schema}
    raise TypeError("closed C4 model result type required")


def artifact_draft_model_result_from_wire_v2(raw,kind):
    from .v2_model_egress_wire import from_wire
    if kind not in {ArtifactDraftModelResultReadRequestV2,ArtifactDraftModelResultReadV2} or type(raw) is not dict or set(raw)!={f.name for f in fields(kind)}:
        raise ValueError("closed C4 result fields differ")
    data=dict(raw)
    if kind is ArtifactDraftModelResultReadRequestV2:
        data["namespace"]=NamespaceId(**data["namespace"])
        data["selector"]=artifact_draft_from_wire_v2(data["selector"],ArtifactDraftPhaseSelectorV2)
    else:
        data["request"]=artifact_draft_model_result_from_wire_v2(data["request"],ArtifactDraftModelResultReadRequestV2)
        data["observation"]=from_wire(data["observation"],ModelEgressObservationV1)
        data["terminal_receipt"]=from_wire(data["terminal_receipt"],ModelTerminalReceiptV2)
    result=kind(**data)
    if artifact_draft_model_result_to_wire_v2(result)!=raw:raise ValueError("noncanonical C4 result wire")
    return result



@dataclass(frozen=True, slots=True)
class ArtifactDraftModelResultDeliveryV2:
    result: ArtifactDraftModelResultReadV2
    permit: object
