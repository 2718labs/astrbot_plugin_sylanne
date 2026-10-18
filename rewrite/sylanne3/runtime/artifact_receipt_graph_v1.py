"""Installed fixed completion message assembly through the ordinary FULL Work and generic D08/D09 seal."""
from __future__ import annotations
from dataclasses import replace
from contextlib import contextmanager
from contextvars import ContextVar
import json,math,secrets,time,sqlite3

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_contract import AuthorityCurrentEffectSnapshotV2,FencePermitV2,canonical_digest as authority_canonical_digest
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..graph_types import AtomKey,Owner,GraphAtom,GraphVersion,GraphSnapshot,GraphCandidate,NamespaceEpoch
from ..graph_store import GraphStore,ProductionGraphStore
from ..runtime_contracts import (NamespaceId,AuthorityContext,CommandEnvelope,OperationIdentity,VersionGuard,SourceQualification,
    QueryEpoch,VersionedRef,FenceScope,CommitReceipt,canonical_digest,canonical_serialize,RUNTIME_SCHEMA,namespace_ref)
from ..contracts import StaleRead,Scope,Event,canonical_json
from ..graph_coordinator import UnavailableGuard
from ..memory_types import SourceRecord,access_key,source_key
from ..domains.d03.context import AccountBinding,ContextProvider,EntityAnchor,RoleBindingRequest,WorldEvent
from ..domains.d03.prebatch_social import PrebatchSocialCandidateV1,PrebatchPrivateManifestV1,match_prebatch_batch_v1,_private_route
from ..domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
from ..domains.d06 import source_correction_head_key
from ..domains.d08 import ActionIntent,ActionSchema,ActionSchemaRecord,GoalExecutionProvider
from ..domains.d09 import ClaimKind,segment_payload_digest
from .artifact_receipt_dispatch_v1 import (ArtifactReceiptExpressionV1,ArtifactReceiptActionCandidateV1,
    ArtifactReceiptDispatchBundleCandidateV1,artifact_receipt_expression_v1,artifact_receipt_action_ids_v1,
    artifact_receipt_dispatch_runtime_refs_v1,prepare_artifact_receipt_action_candidate_v1,
    prepare_artifact_receipt_dispatch_bundle_candidate_v1,recover_artifact_receipt_dispatch_candidate_in_transaction_v1)
from .artifact_completion_receipt_v1 import ArtifactCompletionReceiptOriginalV1,receipt_ids_v1
from .artifact_receipt_original_read_v1 import (require_artifact_receipt_assembly_original_v1,
    bind_artifact_receipt_assembly_points_v1,reserve_artifact_receipt_assembly_budget_v1)
from .current_graph_full_read_v3 import (ARTIFACT_RECEIPT_FULL_READ_V1,CURRENT_DISPATCH_FAMILY_V3,
    prepare_current_graph_full_read_v3,bind_prepared_graph_full_read_v3,require_bound_graph_full_read_proof_v3)
from .dispatch_current_projection import derive_current_domain_reads,read_current_dispatch_projection
from .dispatch_source_correction_barrier import read_source_correction_barrier
from .reply_model_job import CurrentReplyRouteManifestV2
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2,read_current_reply_entity_route_binding_v2
from .first_ingress_v2 import trusted_upper
from .jobs import create_job


_RECEIPT_BASE=ContextVar("artifact-receipt-assembly-base.v1",default=None)


def prepare_artifact_receipt_full_read_then_call_v1(graph,authority,lease,*,operation_id,now_utc,deadline_utc,callback,on_release=None):
    """A locator selects a real producer; only the actual Work may issue its seal."""
    work=prepare_current_graph_full_read_v3(graph,authority,lease,read_contract=ARTIFACT_RECEIPT_FULL_READ_V1,
        operation_id="artifact-receipt-read:"+secrets.token_hex(24),deadline_utc=deadline_utc,
        artifact_receipt_operation_id=operation_id,receipt_now_utc=now_utc)
    def completed(proof):
        token=_RECEIPT_BASE.set(proof)
        try:
            with bind_prepared_graph_full_read_v3(proof,graph,graph._GraphCoordinator__store._db):
                return callback(proof)
        finally:
            _RECEIPT_BASE.reset(token);proof.release_payload_v3()
            if on_release is not None:on_release()
    def failed(error):
        if on_release is not None:on_release()
        raise error
    return work.map_terminal_v3("issuer",completed,failed)


def _receipt_base_v1(graph,now_utc):
    proof=_RECEIPT_BASE.get()
    if proof is None or proof.graph is not graph:
        raise AuthorityUnavailable("receipt assembly has no actual originating FULL Work")
    value=require_artifact_receipt_assembly_original_v1(proof,graph,graph._GraphCoordinator__store._db,now_utc=now_utc)
    current=require_bound_graph_full_read_proof_v3(graph,graph._GraphCoordinator__store._db,proof.namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
    return proof,current,value


def _receipt_snapshot_v1(graph,namespace,now_utc):
    proof,current,value=_receipt_base_v1(graph,now_utc)
    if namespace!=value.namespace:raise AuthorityUnavailable("receipt snapshot crossed namespace")
    atoms={atom.key.token:atom for atom in current.projection.atoms}
    task=proof.artifact_receipt_originals.task
    for point in task.points.values():
        if point.table!="graph_atoms"or"value"not in point.selection:continue
        position=point.selection.index("value")
        for row,metadata in zip(point.rows,point.metadata):
            key=dict(zip(point.keys,metadata[point.key_offset:point.key_offset+len(point.keys)]))
            token=key.get("token")
            if token not in task.source_family or row[position]is None:continue
            head=proof.heads.get(token)
            if head is None or head[1]!=1:raise AuthorityUnavailable("receipt Source material lost its actual census head")
            body=json.loads(row[position]);SourceRecord.from_dict(body)
            atoms[token]=GraphAtom(AtomKey.from_token(token),head[0],body,True)
    if not task.source_family<=set(atoms):
        raise AuthorityUnavailable("complete receipt Source family bodies were not actually prepared")
    return GraphSnapshot(tuple(atoms[key]for key in sorted(atoms)),(current.graph_stamp[1],)),current.query


def _receipt_current_atom_v1(db,snapshot,namespace,key):
    graph=_RECEIPT_BASE.get().graph
    proof,current,_=_receipt_base_v1(graph,_RECEIPT_BASE.get().artifact_receipt_originals.task.now_utc)
    atom=snapshot.get(key)
    head=db.execute("SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
        (*namespace.as_tuple,key.token)).fetchone()
    if (atom is None or not atom.valid or head is None or head[:2]!=(atom.revision,1)
            or tuple(head)!=current.heads.get(key.token)):
        raise ValueError("receipt current member differs from its actual full census/delta")
    return atom


def _receipt_route_binding_v1(graph,namespace,route,query,now_utc):
    proof,_,value=_receipt_base_v1(graph,now_utc)
    with bind_artifact_receipt_assembly_points_v1(proof,graph,graph._GraphCoordinator__store._db,now_utc=now_utc):
        return read_current_reply_entity_route_binding_v2(graph._GraphCoordinator__store._db,namespace,route,query,now_utc=now_utc)


def _receipt_all_coverage_v1(graph,namespace,query,now_utc):
    proof,current,_=_receipt_base_v1(graph,now_utc)
    return(proof.coverage.full_eof and proof.coverage.namespace==namespace and current.query==query
        and current.authority_epochs==proof.authority_epochs and current.owner_head==proof.owner_head)


def _receipt_stage_prebatch_v1(self,*,receipt,envelope,route,budget_grant,resource_quote,anchor,scope,
        current_effect,effect_snapshot,now_utc):
    namespace=envelope.authority.namespace
    snapshot,query=_receipt_snapshot_v1(self,namespace,now_utc)
    original=_receipt_route_binding_v1(self,namespace,route,query,now_utc)
    projected_query=QueryEpoch(namespace,"all",query.revision+1)
    projected=_receipt_read_check_versions_v1(self,receipt,namespace,route,original,receipt.source_ref,
        receipt.selector.task.c02_operation_id,budget_grant,resource_quote,anchor,
        expected_query=projected_query,now_utc=now_utc,projected=True)
    common=dict(receipt=receipt,envelope=envelope,route=route,route_binding=original,
        quote=resource_quote,budget_grant=budget_grant,anchor=anchor,now_utc=now_utc)
    provisional=prepare_artifact_receipt_action_candidate_v1(**common,snapshot=snapshot,query=projected_query,
        check_inputs=projected,provisional=True)
    staged_envelope,domain_action,candidate=_receipt_action_stage_v1(self,envelope,provisional,snapshot,now_utc=now_utc)
    with self._full_graph_write_capture_locked(namespace,scope,candidate,phase="provisional")as capture:
        with self._GraphCoordinator__store._provisional_graph_stage_in_transaction(candidate,
                _capability=self._GraphCoordinator__graph_capability,_full_read_capture=capture):
            staged_snapshot,staged_query=_receipt_snapshot_v1(self,namespace,now_utc)
            binding=_receipt_route_binding_v1(self,namespace,route,staged_query,now_utc)
            actual=_receipt_read_check_versions_v1(self,receipt,namespace,route,binding,receipt.source_ref,
                receipt.selector.task.c02_operation_id,budget_grant,resource_quote,anchor,
                expected_query=staged_query,now_utc=now_utc,projected=False)
            issued=prepare_artifact_receipt_action_candidate_v1(**common,snapshot=staged_snapshot,query=staged_query,check_inputs=actual)
            if issued!=replace(provisional,status="candidate"):
                raise UnavailableGuard("actual Artifact receipt E+1 action differs from its provisional read")
            d08,social,source,budget=_receipt_prebatch_checks_v1(self,namespace,scope,current_effect,effect_snapshot,
                issued.intent,issued.schema,issued.expression,route,original,binding,receipt=receipt,
                resource_quote=resource_quote,now_utc=now_utc,valid_until_utc=envelope.deadline_utc)
            checks=(social.role_receipt,social.boundary_receipt,source,d08.receipt,budget)
            if(any(item is None or(item.result,item.coverage)!=("pass","full")for item in checks)
                    or tuple(item.check_kind for item in checks)!=tuple(spec.check_kind for spec in issued.intent.required_checks)):
                raise UnavailableGuard("Artifact receipt E+1 lacks all five actual checks")
            grant=self._freeze_post_c02_reply_route_grant_locked(issued,checks,binding,scope,staged_snapshot,now_utc)
            check_candidate=self._post_c02_check_candidate_from_reads(envelope,staged_query,anchor,scope,d08,social,binding,checks)
    return staged_envelope,domain_action,issued,social,check_candidate,original,binding,grant


def _receipt_final_reissue_v1(self,db,graph_receipt,scope,now_utc,*,receipt,envelope,route,budget_grant,
        resource_quote,anchor,current_effect,effect_snapshot,expected_action,expected_social,
        expected_original_binding,expected_staged_binding,expected_grant,batch_ref):
    if(db is not self._GraphCoordinator__store._db or not db.in_transaction
            or not self._GraphCoordinator__store._lock._is_owned()or graph_receipt.status!="committed"):
        raise UnavailableGuard("Artifact final check lacks its actual Store seal transaction")
    namespace=receipt.namespace
    snapshot,query=_receipt_snapshot_v1(self,namespace,now_utc)
    binding=_receipt_route_binding_v1(self,namespace,route,query,now_utc)
    if(binding!=expected_staged_binding or binding.query.revision!=expected_original_binding.query.revision+1
            or binding.binding_scan_versions!=expected_original_binding.binding_scan_versions
            or tuple((getattr(binding,n).key,getattr(binding,n).revision)for n in("anchor_version","binding_version",
                "arrival_event_version","binding_evidence_event_version","source_version","access_version"))!=
                tuple((getattr(expected_original_binding,n).key,getattr(expected_original_binding,n).revision)
                for n in("anchor_version","binding_version","arrival_event_version","binding_evidence_event_version","source_version","access_version"))):
        raise UnavailableGuard("Artifact receipt original ingress account route changed at seal")
    actual=_receipt_read_check_versions_v1(self,receipt,namespace,route,binding,receipt.source_ref,
        receipt.selector.task.c02_operation_id,budget_grant,resource_quote,anchor,expected_query=query,now_utc=now_utc,projected=False)
    issued=prepare_artifact_receipt_action_candidate_v1(receipt=receipt,envelope=envelope,route=route,
        route_binding=expected_original_binding,snapshot=snapshot,query=query,check_inputs=actual,
        quote=resource_quote,budget_grant=budget_grant,anchor=anchor,now_utc=now_utc)
    if issued!=expected_action:raise UnavailableGuard("Artifact receipt actual final action differs from E+1")
    d08,social,source,budget=_receipt_prebatch_checks_v1(self,namespace,scope,current_effect,effect_snapshot,
        issued.intent,issued.schema,issued.expression,route,expected_original_binding,binding,receipt=receipt,
        resource_quote=resource_quote,now_utc=now_utc,valid_until_utc=envelope.deadline_utc)
    batch=snapshot.get(AtomKey.from_token(batch_ref))
    if social!=expected_social or batch is None or not batch.valid or not match_prebatch_batch_v1(social,batch.value):
        raise UnavailableGuard("Artifact receipt final D03/D09 batch lineage differs")
    checks=(social.role_receipt,social.boundary_receipt,source,d08.receipt,budget)
    if(any(item is None or(item.result,item.coverage)!=("pass","full")for item in checks)
            or tuple(item.check_kind for item in checks)!=tuple(spec.check_kind for spec in issued.intent.required_checks)):
        raise UnavailableGuard("Artifact receipt final check set is incomplete")
    final_grant=self._freeze_post_c02_reply_route_grant_locked(issued,checks,binding,scope,snapshot,now_utc)
    if final_grant!=expected_grant:raise UnavailableGuard("Artifact receipt route-bound grant changed at seal")
    return ArtifactReceiptFinalReissueV1(self._post_c02_check_candidate_from_reads(envelope,query,anchor,scope,d08,social,binding,checks),
        binding,social,d08,final_grant,issued,graph_receipt,receipt)


@contextmanager
def _receipt_prepare_bundle_v1(self,*,authority,scope,installed_bundle,receipt,clock_reading,current_effect,effect_snapshot,
        now_utc,deadline_utc):
    from .artifact_receipt_allocation_v3 import read_actual_artifact_receipt_allocation_v3,require_protected_artifact_receipt_budget_v3
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    store=self._GraphCoordinator__store;db=store._db
    proof,_,actual=_receipt_base_v1(self,now_utc)
    if(receipt!=actual or not store._lock._is_owned()or not db.in_transaction
            or authority.namespace!=receipt.namespace or authority.purpose!="expression"
            or authority.actor!=proof.artifact_receipt_originals.task.actor_ref):
        raise UnavailableGuard("Artifact receipt assembly crossed its actual current Self/Source/receipt")
    task=proof.artifact_receipt_originals.task
    with bind_artifact_receipt_assembly_points_v1(proof,self,db,now_utc=now_utc):
        job0,allocation,_,grant=read_actual_artifact_receipt_allocation_v3(db,namespace=receipt.namespace,
            c02_operation_id=receipt.selector.task.c02_operation_id,source_ref=task.route.source_ref,issuer=self._GraphCoordinator__d11_issuer)
    if allocation.digest!=receipt.allocation_digest:raise UnavailableGuard("Artifact receipt message child allocation changed")
    snapshot,query=_receipt_snapshot_v1(self,receipt.namespace,now_utc)
    ids=receipt_ids_v1(receipt.selector)
    identity=OperationIdentity(ids["activity"],receipt.effect_id,"artifact-receipt-attempt:"+receipt.digest[:40],
        "artifact_receipt_dispatch_v1",receipt.message_operation_id,canonical_digest({"input_refs":[receipt.source_ref]}))
    guard=VersionGuard(snapshot.versions,(query,),*proof.authority_epochs,store._registry.catalogue_hash,
        self._version(db,receipt.namespace,"scheme","current"),self._version(db,receipt.namespace,"operator","current"),
        self._version(db,receipt.namespace,"policy","current"),(),(),())
    envelope=CommandEnvelope(RUNTIME_SCHEMA,identity,authority,guard,
        SourceQualification((receipt.source_ref,),"derived",None,receipt.recorded_at_utc,"inference","ineligible",None,"not_applicable"),
        (receipt.source_ref,),grant.lease_id,deadline_utc,
        clock_reading.monotonic_after_seconds+deadline_utc-clock_reading.utc_upper_bound_seconds,
        "artifact-completion:"+receipt.receipt_id,(receipt.selector.task.c02_operation_id,receipt.producer_operation_id))
    job_ref,outbox_ref,_=artifact_receipt_dispatch_runtime_refs_v1(receipt)
    quote=self._GraphCoordinator__d11_issuer.issue_private_reply_dispatch_quote_v2(db,
        policy=installed_bundle.private_reply_dispatch,namespace=receipt.namespace,identity=identity,parent_grant=grant,
        deadline_utc=deadline_utc,graph_job_ref=job_ref,outbox_refs=(outbox_ref,),now_utc=now_utc)
    if dict(quote.ceiling)!=dict(allocation.message_ceiling):
        raise UnavailableGuard("Artifact receipt cannot change its one installed message price")
    db.execute("INSERT OR IGNORE INTO graph_guard_versions(bot,persona,kind,ref,version)VALUES(?,?,?,?,?)",
        (*receipt.namespace.as_tuple,"resource_lease",quote.quote_id,str(quote.version)))
    if self._version(db,receipt.namespace,"resource_lease",quote.quote_id)!=str(quote.version):
        raise UnavailableGuard("Artifact receipt signed quote graph guard differs")
    envelope=replace(envelope,version_guard=replace(guard,resource_lease_versions=(VersionedRef(quote.quote_id,quote.version),)))
    with reserve_artifact_receipt_assembly_budget_v1(proof,self,scope,envelope,quote,now_utc=now_utc):
        require_protected_artifact_receipt_budget_v3(db,namespace=receipt.namespace,plan=foreground_cycle_from_wire_v1(job0.continuation).call_plan,
            issuer=self._GraphCoordinator__d11_issuer,now_utc=now_utc,installed_bundle=installed_bundle,owner_guard=receipt.owner_guard)
        job=replace(self._GraphCoordinator__d11_issuer.job_for(envelope,db,now_utc=now_utc),phase="waiting",
            wake_condition={"kind":"artifact_receipt_host_takeover","operation_id":receipt.message_operation_id})
        if AtomKey.from_token(job_ref).name!=job.job_id:
            raise UnavailableGuard("Artifact receipt actual reserved job differs from its deterministic ref")
        create_job(db,job,"artifact-receipt-job:"+canonical_digest((receipt.digest,job_ref))[:48],canonical_digest(job))
        staged=_receipt_stage_prebatch_v1(self,receipt=receipt,envelope=envelope,route=task.route,budget_grant=grant,
            resource_quote=quote,anchor=scope.pinned_anchor,scope=scope,current_effect=current_effect,effect_snapshot=effect_snapshot,now_utc=now_utc)
        staged_envelope,domain_action,action,social,checks,original,binding,route_grant=staged
        candidate=prepare_artifact_receipt_dispatch_bundle_candidate_v1(receipt=receipt,envelope=staged_envelope,
            action=action,staged_d08=domain_action,checks=checks.checks,route=task.route,route_binding=binding,
            pre_frozen_grant=route_grant,quote=quote,budget_grant=grant,pre_reserved_job=job,now_utc=now_utc,
            conversation_epoch=checks.graph_epoch)
        if(candidate.status!="candidate"or candidate.job!=job or candidate.job_ref!=job_ref or candidate.outbox_ref!=outbox_ref):
            raise UnavailableGuard("Artifact receipt generic D08/D09 bundle changed its actual job/outbox")
        yield (receipt,task.route,envelope,action.expression,grant,quote,job,staged,candidate)


def prepare_current_artifact_receipt_dispatch_v1(graph,bootstrap,installed_bundle,*,c02_operation_id,source_ref):
    """Produce no model work: admit the fixed Source only after full current pre-read."""
    graph._admin(bootstrap)
    if installed_bundle is not graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle:
        raise UnavailableGuard("Artifact receipt dispatch requires its actual installed Admin bundle")
    produced=graph.prepare_current_artifact_completion_source_v1(bootstrap,installed_bundle,
        c02_operation_id=c02_operation_id,source_ref=source_ref)
    if produced.get("status")!="artifact_completion_source_current":return produced
    locator=produced["receipt_original"]
    port=graph._GraphCoordinator__content_fence_v2
    clock=port.read_ingress_clock(graph._GraphCoordinator__dispatch_clock_policy);now=trusted_upper(clock)
    namespace=installed_bundle.installation_policy.namespace
    if(type(locator)is not ArtifactCompletionReceiptOriginalV1 or locator.namespace!=namespace):
        raise UnavailableGuard("Artifact message lacks its actual D06 completion Source locator")
    # This read grant authorizes preparation only. The actual completed Self is
    # derived from the authenticated D06 original before the writer grant exists.
    with graph._GraphCoordinator__store._lock:
        generation=graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    lease,cap=graph.grant(bootstrap,actor="artifact-receipt-reader",issuer_domain="d11",namespace=namespace,
        domains=("d08","d09","d11"),activation_generation=generation,
        operation_id=locator.message_operation_id)
    handed_off=False
    try:
        authority=AuthorityContext("artifact-receipt-reader","d11",cap,namespace,("persona","activity"),"expression",
            (produced["receipt_original"].selector.task.namespace.persona_id,), "policy:artifact-receipt-read.v1",
            generation)
        # Audience is read from the current original ingress by the installed caller,
        # never from the receipt Source. The preliminary completion-source producer
        # already used its actual current private route.
        route=read_artifact_receipt_locator_route_v1(graph,bootstrap,installed_bundle,
            c02_operation_id=c02_operation_id,source_ref=source_ref)
        authority=replace(authority,audience=(route.conversation_ref,))
        deadline=min(locator.original_deadline_utc,now+installed_bundle.private_reply_dispatch.deadline_after_seconds)
        def assembled(proof):
            fresh=port.read_ingress_clock(graph._GraphCoordinator__dispatch_clock_policy)
            fresh_now=trusted_upper(fresh)
            if fresh_now>=deadline:raise UnavailableGuard("Artifact receipt original frozen dispatch deadline elapsed during FULL preparation")
            return _receipt_assemble_from_full_v1(graph,bootstrap,installed_bundle,proof,fresh,fresh_now,deadline)
        work=prepare_artifact_receipt_full_read_then_call_v1(graph,authority,lease,operation_id=locator.message_operation_id,
            now_utc=now,deadline_utc=deadline,callback=assembled,on_release=lambda:graph.release_authority_lease(bootstrap,lease))
        handed_off=True
        return work
    finally:
        if not handed_off:graph.release_authority_lease(bootstrap,lease)


def _receipt_assemble_from_full_v1(self,bootstrap,installed_bundle,proof,clock,now,deadline):
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..authority_service.v2_contract import to_wire
    store=self._GraphCoordinator__store;port=self._GraphCoordinator__content_fence_v2;namespace=proof.namespace
    with store._lock:
        db=store._db;db.execute("BEGIN")
        try:
            receipt=require_artifact_receipt_assembly_original_v1(proof,self,db,now_utc=now)
            if proof.artifact_receipt_originals.task.candidate_recovery is not None:
                return {"status":"artifact_receipt_dispatch_committed","operation_id":receipt.message_operation_id,
                    "receipt_original":receipt,"commit_receipt":_receipt_committed_operation_v1(self,proof,receipt,now)}
            metadata,epoch=self._v2_graph_stamp(namespace)
            located=_receipt_fence_locator_v1(self,installed_bundle,receipt.selector.task.c02_operation_id,
                proof.artifact_receipt_originals.task.route.source_ref)
            if located is None or located[1:4]!=(receipt.message_operation_id,receipt.effect_id,receipt_ids_v1(receipt.selector)["activity"]):
                raise UnavailableGuard("receipt writer lost its actual stable D06 input locator")
        finally:db.rollback()
    actor=proof.artifact_receipt_originals.task.actor_ref
    lease,cap=self.grant(bootstrap,actor=actor,issuer_domain="d11",namespace=namespace,domains=("d08","d09","d11"),
        activation_generation=metadata.requirements.activation_generation,operation_id=receipt.message_operation_id)
    from ..host.v2_fence_port import V2FenceOutcomeUnknown
    scope=None
    local_boundary=False
    sql_started=False
    rollback_confirmed=False
    commit_started=False
    try:
        authority=AuthorityContext(actor,"d11",cap,namespace,("persona","activity"),"expression",
            proof.artifact_receipt_originals.task.audiences,"policy:artifact-receipt-dispatch.v1",metadata.requirements.activation_generation)
        self._authorize(lease,authority,frozenset({"d08","d09","d11"}))
        target=metadata.requirements
        local_boundary=False
        anchor=port.current_anchor(namespace=namespace,authority_namespace=target.authority_namespace)
        local_boundary=True
        if not self._anchor_matches(target,anchor):raise UnavailableGuard("Artifact receipt Authority anchor changed")
        attempt=_receipt_fence_attempt_id_v1(located)
        local_boundary=False
        permit=port.begin_fence(namespace=namespace,authority_namespace=target.authority_namespace,holder=self._GraphCoordinator__holder,
            generation=target.activation_generation,operation="write",operation_id=attempt,expected_anchor=anchor,retain_on_unknown=True)
        local_boundary=True
        scope=FenceScope(namespace,target.authority_namespace,target.activation_generation,"write",attempt,permit,anchor,epoch,metadata.graph_revision)
        local_boundary=False
        checked=port.validate_fence(scope)
        local_boundary=True
        if type(permit)is not FencePermitV2 or checked!=permit:
            raise UnavailableGuard("Artifact receipt writer lacks its actual current permit")
        local_boundary=False
        guarded=port.get_current_owner_guard_for_fence(namespace=namespace,authority_namespace=target.authority_namespace,permit=permit)
        local_boundary=True
        local_boundary=False
        effect=port.read_current_effect(namespace=namespace,authority_namespace=target.authority_namespace,effect_id=receipt.effect_id)
        local_boundary=True
        local_boundary=False
        effects=port.read_current_effect_snapshot_for_write_fence(namespace=namespace,authority_namespace=target.authority_namespace,permit=permit)
        local_boundary=True
        local_boundary=False
        checked=port.validate_fence(scope)
        local_boundary=True
        if(type(guarded)is not tuple or len(guarded)!=2 or guarded[1]!=permit or type(guarded[0])is not OwnerAuthorizationGuardV1
                or type(effect)is not CurrentEffectReadV2 or effect.state!="absent"or effect.effect_id!=receipt.effect_id
                or type(effects)is not AuthorityCurrentEffectSnapshotV2 or effects.coverage!="complete"
                or effects.anchor!=anchor or effects.permit_digest!=authority_canonical_digest(permit)
                or effects.authority_id!=permit.authority_id or effects.namespace!=permit.namespace
                or checked!=permit):
            raise UnavailableGuard("Artifact receipt paired Owner/effect/snapshot differs")
        with store._lock:
            db.execute("BEGIN IMMEDIATE")
            sql_started=True
            try:
                require_artifact_receipt_assembly_original_v1(proof,self,db,now_utc=now)
                if self._v2_graph_stamp(namespace)!=(metadata,epoch):raise StaleRead("Artifact receipt graph changed before assembly")
                with _receipt_prepare_bundle_v1(self,authority=authority,scope=scope,installed_bundle=installed_bundle,
                        receipt=receipt,clock_reading=clock,current_effect=effect,effect_snapshot=effects,now_utc=now,deadline_utc=deadline)as prepared:
                    finish_id="finish:"+attempt
                    finish_digest="sha256:"+canonical_digest({"action":"finish_artifact_receipt_dispatch_v1",
                        "attempt":attempt,"permit":permit.token,"bundle":prepared[8].bundle.digest})
                    committed=_receipt_seal_v1(self,lease=lease,scope=scope,metadata=metadata,clock_reading=clock,
                        owner_guard=guarded[0],current_effect=effect,effect_snapshot=effects,now_utc=now,prepared=prepared,
                        finish_id=finish_id,finish_digest=finish_digest,prepared_full_read=proof)
                commit_started=True
                db.commit()
            except BaseException:
                if db.in_transaction:
                    db.rollback()
                    rollback_confirmed=True
                raise
        if port.validate_fence(scope)!=permit:raise UnavailableGuard("Artifact receipt permit changed after actual commit")
        with store._lock:
            current,current_epoch=self._v2_graph_stamp(namespace)
            if(current.requirements!=metadata.requirements or current.graph_revision!=metadata.graph_revision+1
                    or current_epoch.revision!=epoch.revision+1):
                raise UnavailableGuard("Artifact receipt committed graph stamp differs")
        port.finish_fence(scope,request_id=finish_id,request_digest=finish_digest)
        return {"status":"artifact_receipt_dispatch_committed","operation_id":receipt.message_operation_id,
            "receipt_original":receipt,"commit_receipt":committed}
    except BaseException as failure:
        if (scope is not None and local_boundary and not commit_started
                and (not sql_started or rollback_confirmed)and isinstance(failure,Exception)
                and not isinstance(failure,(sqlite3.Error,OSError,V2FenceOutcomeUnknown))):
            try:
                _finish_artifact_receipt_known_no_commit_v1(self,installed_bundle,receipt,metadata,epoch,scope)
            except Exception as finish_failure:
                uncertain=V2FenceOutcomeUnknown("Artifact receipt no-commit closure finish remains unknown; original local refusal: "
                    +type(failure).__name__+": "+str(failure))
                uncertain.add_note("Original scope retained; closure cleanup: "+type(finish_failure).__name__+": "+str(finish_failure))
                raise uncertain from failure
        raise
    finally:self.release_authority_lease(bootstrap,lease)


def _receipt_committed_operation_v1(graph,proof,receipt,now):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1
    with bind_artifact_receipt_assembly_points_v1(proof,graph,graph._GraphCoordinator__store._db,now_utc=now):
        row=artifact_receipt_sql_v1(graph._GraphCoordinator__store._db,
            "SELECT digest,activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*receipt.namespace.as_tuple,receipt.message_operation_id)).fetchone()
        event=artifact_receipt_sql_v1(graph._GraphCoordinator__store._db,
            "SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*receipt.namespace.as_tuple,row[1],receipt.message_operation_id)).fetchone()
    detail=json.loads(row[4])
    if event is None or row[2]!=receipt.effect_id:raise UnavailableGuard("Artifact existing dispatch lost its actual event/effect")
    return CommitReceipt("committed",receipt.message_operation_id,row[0],row[1],row[2],row[3],GraphStore._version_rows(event[0]),
        GraphStore._version_rows(event[1]),(NamespaceEpoch(*receipt.namespace.as_tuple,event[2]),),
        tuple(detail["ledger_refs"]),tuple(detail["outbox_refs"]))


def _receipt_current_account_route_v1(
    db, snapshot: GraphSnapshot, namespace: NamespaceId, query: QueryEpoch,
    route: CurrentReplyRouteManifestV2,
    binding: CurrentReplyEntityRouteBindingV2, *,
    account_ref: str, destination_ref: str, sender_ref: str, message_id: str,
    scene_ref: str, now_utc: float,
) -> tuple[GraphVersion, ...]:
    """Recheck W01's account endpoint against the E+1 graph and full scan."""
    identity = {
        "namespace": namespace.as_tuple,
        "platform_ref": account_ref,
        "sender_ref": sender_ref,
    }
    suffix = canonical_digest(identity)
    entity_id = "entity:account-v1:" + suffix
    account_id = "account:v1:" + suffix
    arrival_id = "world:message-arrival-v1:" + canonical_digest({
        "namespace": namespace.as_tuple,
        "platform_ref": account_ref,
        "conversation_ref": destination_ref,
        "message_id": message_id,
        "source_id": AtomKey.from_token(route.source_ref).owner.subject,
    })
    if ((binding.namespace, binding.c02_operation_id, binding.source_ref,
         binding.platform_ref, binding.sender_ref, binding.conversation_ref,
         binding.scene_ref, binding.target_entity_ref, binding.account_id) != (
         namespace, route.c02_operation_id, route.source_ref, account_ref,
         sender_ref, destination_ref, scene_ref, entity_id, account_id)
            or binding.query != QueryEpoch(namespace, "all", query.revision - 1)
            or not binding.binding_digest
            or (binding.valid_until_utc is not None
                and now_utc >= binding.valid_until_utc)):
        raise ValueError("current reply account route differs from original ingress")
    versions = (
        binding.anchor_version, binding.binding_version,
        binding.arrival_event_version, binding.binding_evidence_event_version,
        binding.source_version, binding.access_version,
    )
    if (type(binding.binding_scan_versions) is not tuple
            or any(type(item) is not GraphVersion or item.revision < 1
                   for item in (*versions, *binding.binding_scan_versions))
            or binding.anchor_version.key != AtomKey(
                Owner("persona", *namespace.as_tuple), "d03.entity_anchor", entity_id)
            or binding.binding_version.key != AtomKey(
                Owner("persona", *namespace.as_tuple), "d03.account_binding", account_id)
            or binding.arrival_event_version.key != AtomKey(
                Owner("event", *namespace.as_tuple, arrival_id),
                "d03.world_event", "current")
            or binding.source_version.key != AtomKey.from_token(route.source_ref)
            or binding.access_version.key != access_key(
                *namespace.as_tuple, binding.source_version.key.owner.subject or "")):
        raise ValueError("current reply account version closure differs")
    atoms = tuple(_receipt_current_atom_v1(db, snapshot, namespace, item.key)
                  for item in versions)
    if any(atom.revision != item.revision for atom, item in zip(atoms, versions)):
        raise ValueError("current reply account version changed")
    anchor = EntityAnchor(**{
        **atoms[0].value,
        "creation_evidence_refs": tuple(atoms[0].value["creation_evidence_refs"]),
    })
    account = AccountBinding(**atoms[1].value)
    arrival = WorldEvent(**{
        **atoms[2].value,
        "participant_roles": tuple(tuple(pair) for pair in atoms[2].value["participant_roles"]),
        "source_refs": tuple(atoms[2].value["source_refs"]),
    })
    evidence = WorldEvent(**{
        **atoms[3].value,
        "participant_roles": tuple(tuple(pair) for pair in atoms[3].value["participant_roles"]),
        "source_refs": tuple(atoms[3].value["source_refs"]),
    })
    if (anchor.entity_id != entity_id or anchor.kind != "account"
            or anchor.status != "active"
            or anchor.owner_scope != f"persona:{namespace.persona_id}"
            or account.account_id != account_id
            or account.entity_id != entity_id
            or account.platform_namespace != account_ref
            or account.platform_identifier != sender_ref
            or account.verification_ref != binding.binding_evidence_event_version.key.token
            or account.valid_until != binding.valid_until_utc
            or account.valid_from > now_utc
            or arrival.kind != "message_received" or arrival.reality != "host_observed"
            or arrival.participant_roles != ((entity_id, "sender_account"),)
            or arrival.source_refs != (route.source_ref,)
            or arrival.scene_ref != scene_ref
            or evidence.kind != "message_received" or evidence.reality != "host_observed"
            or evidence.participant_roles != ((entity_id, "sender_account"),)
            or evidence.learned_at != account.valid_from):
        raise ValueError("current reply account endpoint differs")
    graph=_RECEIPT_BASE.get().graph
    _,current,_=_receipt_base_v1(graph,now_utc)
    if current.query!=query:
        raise ValueError("receipt account scan lost its actual complete FULL query epoch")
    rows=tuple((atom.key.token,atom.revision,atom.value)
        for atom in sorted(current.projection.atoms_for_types_v3(frozenset({'d03.account_binding'})),key=lambda item:item.key.token)
        if atom.key.type_name=='d03.account_binding' and atom.valid
        and (atom.key.owner.bot,atom.key.owner.persona)==namespace.as_tuple)
    scan = tuple(GraphVersion(AtomKey.from_token(token), revision)
                 for token, revision, _ in rows)
    if scan != binding.binding_scan_versions:
        raise ValueError("current account binding scan changed")
    matches = []
    for token, _, value in rows:
        row = AccountBinding(**value)
        key = AtomKey.from_token(token)
        _receipt_current_atom_v1(db, snapshot, namespace, key)
        if (row.platform_namespace == account_ref
                and row.platform_identifier == sender_ref
                and row.valid_from <= now_utc
                and (row.valid_until is None or now_utc < row.valid_until)):
            matches.append(key)
    if matches != [binding.binding_version.key]:
        raise ValueError("current reply account binding is ambiguous")
    return tuple(dict.fromkeys((*versions, *scan)))


def _receipt_social_v1(
    db, snapshot: GraphSnapshot, query: QueryEpoch,
    intent: ActionIntent, schema_record: ActionSchemaRecord,
    expression: ArtifactReceiptExpressionV1, *,
    route: CurrentReplyRouteManifestV2,
    route_binding: CurrentReplyEntityRouteBindingV2,
    context: ContextProvider, scope: FenceScope, now_utc: float, receipt: ArtifactCompletionReceiptOriginalV1,
    valid_until_utc: float | None = None,
) -> PrebatchSocialCandidateV1:
    """Issue D03/D05 check candidates from a provisional E+1 graph view.

    W01 must validate ``scope`` with Authority before this call and again at
    seal. A Python FenceScope object alone is not a live permit. Reinvoke this
    function in the final receipt hook and compare the entire result before
    matching the actual D09 batch with ``match_prebatch_batch_v1``.
    """
    def hold(reason: str, *, manifest=None, role=None, boundary=None):
        return PrebatchSocialCandidateV1(
            "hold", (reason,), manifest, role, boundary, None, (), None)

    if (not getattr(db, "in_transaction", False)
            or type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(intent) is not ActionIntent
            or type(schema_record) is not ActionSchemaRecord
            or type(expression) is not ArtifactReceiptExpressionV1
            or type(receipt)is not ArtifactCompletionReceiptOriginalV1
            or type(route) is not CurrentReplyRouteManifestV2
            or type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or type(context) is not ContextProvider
            or type(scope) is not FenceScope
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return hold("social.current_staged_transaction_or_typed_inputs")
    expiry = now_utc + 1.0 if valid_until_utc is None else valid_until_utc
    if (type(expiry) not in (int, float) or not math.isfinite(expiry)
            or expiry <= now_utc):
        return hold("social.current_check_deadline_unavailable")
    namespace = scope.namespace
    if (scope.operation != "write"
            or scope.operation_id != scope.permit.operation_id
            or scope.graph_epoch.revision + 1 != query.revision
            or query != QueryEpoch(namespace, "all", query.revision)
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona,
                snapshot.epochs[0].revision) != (*namespace.as_tuple, query.revision)
            or intent.action_kind != "message" or intent.purpose != "expression"
            or len(intent.source_refs) != 1
            or len(expression.segments) != 1
            or not expression.claims
            or route.namespace != namespace
            or route.source_ref == intent.source_refs[0]
            or intent.source_refs!=(receipt.source_ref,)
            or intent.identity.operation_id!=receipt.message_operation_id
            or expression!=artifact_receipt_expression_v1(receipt,(route.conversation_ref,))
            or type(route.c02_operation_id) is not str
            or not route.c02_operation_id):
        return hold("social.staged_write_scope_or_single_reply")
    segment = expression.segments[0]
    if (segment.media_refs or segment.delay_seconds != 0.0
            or segment.segment_id != receipt_ids_v1(receipt.selector)["batch"]+":segment"
            or segment_payload_digest(segment.body,segment.media_refs,segment.claim_uses)!=expression.payload_digest
            or segment.body!=receipt.text or segment.effect_id!=receipt.effect_id
            or any(claim.source_refs != intent.source_refs
                   or claim.kind is not ClaimKind.REPORTED_CLAIM
                   for claim in expression.claims)):
        return hold("social.source_reply_manifest_differs")
    try:
        frozen = ActionSchema(
            schema_record.schema_id, schema_record.action_kind,
            schema_record.proactive, schema_record.required_checks)
        bound_schema = ActionSchemaRecord.bind(intent, frozen)
    except (TypeError, ValueError):
        return hold("social.staged_action_schema_identity")
    if (schema_record != bound_schema or frozen.proactive
            or schema_record.required_checks != intent.required_checks):
        return hold("social.staged_action_schema_identity")
    owner = Owner("activity", *namespace.as_tuple, intent.identity.activity_id)
    action_key = AtomKey(owner, "d08.action_intent.v1", intent.action_id)
    schema_key = AtomKey(owner, "d08.action_schema.v1", schema_record.schema_ref)
    try:
        action_atom = _receipt_current_atom_v1(db, snapshot, namespace, action_key)
        schema_atom = _receipt_current_atom_v1(db, snapshot, namespace, schema_key)
        source_ref = intent.source_refs[0]
        source_atom = _receipt_current_atom_v1(
            db, snapshot, namespace, AtomKey.from_token(source_ref))
        access_atom = _receipt_current_atom_v1(
            db, snapshot, namespace,
            access_key(*namespace.as_tuple,
                       AtomKey.from_token(source_ref).owner.subject or ""))
        d08 = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
        if (d08[action_key.type_name].validator(action_atom.value) != intent
                or d08[schema_key.type_name].validator(schema_atom.value)
                   != schema_record):
            raise ValueError("staged D08 values differ")
        account_ref, destination_ref, sender_ref, message_id, scene_ref = _private_route(
            db, namespace, route.source_ref)
        if ((route.platform_ref, route.conversation_ref, route.scene_ref)
                != (account_ref, destination_ref, scene_ref)
                or route.route_digest != canonical_digest({
                    "account_ref": account_ref,
                    "destination_ref": destination_ref,
                    "scene_ref": scene_ref,
                })):
            raise ValueError("sealed ingress route differs from current route")
        account_versions = _receipt_current_account_route_v1(
            db, snapshot, namespace, query, route, route_binding,
            account_ref=account_ref, destination_ref=destination_ref,
            sender_ref=sender_ref, message_id=message_id,
            scene_ref=scene_ref, now_utc=now_utc)
        if intent.target_ref != route_binding.target_entity_ref:
            raise ValueError("staged action targets a different account entity")
        if any(claim.allowed_audiences != (destination_ref,)
               or claim.disclosure_ref != source_ref
               for claim in expression.claims):
            raise ValueError("quoted claims differ from private route audience")
        manifest = PrebatchPrivateManifestV1(
            intent.identity.operation_id, route.c02_operation_id,
            intent.action_id, intent.target_ref,
            intent.source_refs[0], account_ref, destination_ref, scene_ref,
            (destination_ref,), segment.segment_id, segment.effect_id,
            expression.payload_digest, expression.provenance_digest,
            route.route_digest,
        )
        projection = read_current_dispatch_projection(
            db, namespace, snapshot, query)
        request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", intent.target_ref, None,
            scene_ref, intent.action_kind, intent.purpose, now_utc, True,
        )
        role_read, boundary_read = derive_current_domain_reads(
            db, projection, request, context)
        specs = {item.check_kind: item for item in intent.required_checks
                 if item.check_kind in {"role_binding", "boundary"}}
        if (len(specs) != 2
                or specs["role_binding"].provider_id != "d03.role_binding"
                or specs["boundary"].provider_id != "d05.boundary"):
            raise ValueError("frozen social check specs differ")
        criteria_atoms = []
        for spec in specs.values():
            criteria = tuple(item for item in spec.required_input_versions
                             if item.ref == spec.criteria_version)
            if len(criteria) != 1:
                raise ValueError("current social criterion missing")
            key = AtomKey.from_token(criteria[0].ref)
            criterion = _receipt_current_atom_v1(db, snapshot, namespace, key)
            if criterion.revision != criteria[0].version:
                raise ValueError("social criterion revision changed")
            criteria_atoms.append(criterion)
        role = context.provide_required_check(
            intent, role_read, valid_until=expiry)
        boundary = issue_prebatch_boundary_check_v1(
            intent, frozen, boundary_read, audience_scope=destination_ref,
            scene_ref=scene_ref, now_utc=now_utc,
            valid_until_utc=expiry)
        correction_refs = {source_ref}
        for atom in (*projection.role_bindings, *projection.boundary_rules):
            refs = atom.value.get("source_refs")
            if type(refs) is not list or not refs:
                raise ValueError("social row lacks source closure")
            correction_refs.update(refs)
        correction_missing = []
        for ref in sorted(correction_refs):
            correction_missing.extend(read_source_correction_barrier(
                db, namespace, query, (ref,), dependent_ref=intent.action_id,
            ).missing_sources)
        predicate_refs = tuple(sorted({
            source_correction_head_key(
                namespace, AtomKey.from_token(ref).owner.subject or "").token
            for ref in correction_refs
        }))
        closure = {
            atom.key: GraphVersion(atom.key, atom.revision)
            for atom in (action_atom, schema_atom, source_atom, access_atom,
                         *criteria_atoms, *projection.role_bindings,
                         *projection.boundary_rules)
        }
        closure.update({item.key: item for item in account_versions})
    except (sqlite3.Error, TypeError, ValueError, KeyError, StopIteration):
        return hold("social.current_graph_provider_read_unavailable")
    missing = []
    if projection.coverage != "full":
        missing.extend(projection.missing_sources)
    missing.extend(correction_missing)
    if (role.result, role.coverage) != ("pass", "full"):
        missing.append("d03.current_role_binding_not_pass")
    if boundary.status != "check_pass":
        missing.extend(boundary.missing)
    return PrebatchSocialCandidateV1(
        "hold" if missing else "checks_candidate",
        tuple(dict.fromkeys(missing)), manifest, role, boundary.receipt,
        query.revision, tuple(sorted(closure.values(),
                                     key=lambda item: item.key.token)), query,
        ("d03.role_binding:all_valid", "d05.boundary_rule:all_valid")
        + (f"graph_first_ingress_identity_v1:source:{source_ref}:unique_private",)
        + ("d03.account_binding:all_valid:unique_current_sender",)
        + predicate_refs,
    )


def _receipt_read_check_versions_v1(
        self, receipt, namespace: NamespaceId, route, route_binding, source_ref: str,
        c02_operation_id: str, budget_grant, resource_quote, anchor, *,
        expected_query, now_utc: float, projected: bool,
        action_kind: str = "message"):
    """Freeze raw provider input versions from this SQL head, never PASS.

    ``projected`` predicts only E+1 query versions from the current E
    rows so D08's immutable action can be staged. The same reader must be
    called again on actual E+1 rows and the resulting action compared.
    """
    from ..domains.d03 import ContextProvider, RoleBindingRequest
    from ..memory_types import SourceRecord, access_key, source_key
    from .budget import get_budget_lease
    from .dispatch_budget_check import _observed_versions
    from .dispatch_current_projection import (
        derive_current_domain_reads, read_current_dispatch_projection,
    )
    from .dispatch_source_correction_barrier import (
        read_source_correction_barrier,
    )
    from .installed_dispatch_admission_issuer import (
        InstalledDispatchAdmissionIssuer,
    )
    from .post_c02_reply_action_v2 import (
        CurrentReplyCheckVersionV2, CurrentReplyCheckVersionsV2,
    )
    from ..runtime_contracts import VersionedRef
    from .restore_anchor import RestoreAnchor

    store = self._GraphCoordinator__store
    db = store._db
    if (not store._lock._is_owned() or not db.in_transaction
            or route.namespace != namespace or source_ref != receipt.source_ref
            or receipt.namespace!=namespace or receipt.selector.task.c02_operation_id!=c02_operation_id
            or route_binding.namespace != namespace
            or route_binding.source_ref != route.source_ref
            or route.c02_operation_id != c02_operation_id
            or type(anchor) is not RestoreAnchor
            or anchor.namespace != namespace_ref(namespace)):
        raise UnavailableGuard("current reply check versions lack graph transaction; HOLD")
    snapshot, query = _receipt_snapshot_v1(self,namespace,now_utc)
    if (route_binding.query != query
            or expected_query.namespace != namespace
            or expected_query.scope_ref != "all"
            or expected_query.revision != query.revision + int(projected)
            or action_kind not in {"message", "communication"}):
        raise UnavailableGuard("reply check query epoch differs; HOLD")
    issuer = self._GraphCoordinator__dispatch_admission_issuer
    context = (issuer._context
               if type(issuer) is InstalledDispatchAdmissionIssuer else None)
    if type(context) is not ContextProvider:
        raise UnavailableGuard("installed D03 context provider unavailable; HOLD")
    projection = read_current_dispatch_projection(
        db, namespace, snapshot, query)
    request = RoleBindingRequest(
        f"persona:{namespace.persona_id}",
        route_binding.target_entity_ref,
        None, route.scene_ref, action_kind, "expression", now_utc, True)
    role_read, boundary_read = derive_current_domain_reads(
        db, projection, request, context)
    if (projection.coverage != "full" or role_read.status != "complete"
            or boundary_read.coverage != "full"):
        raise UnavailableGuard("current D03/D05 reply versions unavailable; HOLD")
    graph = {atom.key: atom for atom in snapshot.atoms}
    source = AtomKey.from_token(source_ref)
    if source != source_key(
            *namespace.as_tuple, source.owner.subject or ""):
        raise UnavailableGuard("reply source is not canonical; HOLD")
    pending = [source.owner.subject or ""]
    source_versions = {}
    while pending:
        source_id = pending.pop()
        key = source_key(*namespace.as_tuple, source_id)
        access = access_key(*namespace.as_tuple, source_id)
        source_atom, access_atom = graph.get(key), graph.get(access)
        if (source_atom is None or access_atom is None
                or not source_atom.valid or not access_atom.valid):
            raise UnavailableGuard("reply source ancestor or access absent; HOLD")
        if key.token in source_versions:
            continue
        record = SourceRecord.from_dict(source_atom.value)
        if record.source_id != source_id:
            raise UnavailableGuard("reply source ancestor identity differs; HOLD")
        source_versions[key.token] = source_atom.revision
        source_versions[access.token] = access_atom.revision
        pending.extend(record.parent_source_ids)
    barrier = read_source_correction_barrier(
        db, namespace, query, tuple(sorted(
            ref for ref in source_versions if AtomKey.from_token(ref).type_name
            == "memory.source")), dependent_ref=source_ref)
    if barrier.missing_sources:
        raise UnavailableGuard("reply source correction barrier changed; HOLD")
    source_revision = source_versions[source_ref]
    role_versions = (
        VersionedRef(source_ref, source_revision),
        VersionedRef("d03.role_binding", expected_query.revision),
    ) + tuple(sorted((
        VersionedRef(item.key.name, item.revision)
        for item in role_read.read_versions
        if item.key.name in set(role_read.matched_bindings)),
        key=lambda item: item.ref))
    boundary_versions = (
        VersionedRef(source_ref, source_revision),
        VersionedRef("d05.boundary", expected_query.revision),
    ) + tuple(VersionedRef(rule.rule_id, rule.scope_version)
              for rule in boundary_read.rules)
    goal_id,action_id,_=artifact_receipt_action_ids_v1(receipt)
    d08_versions = (
        VersionedRef("d08.commitment_conflict.criteria.v1", 1),
        VersionedRef(goal_id, 1),
        VersionedRef(f"commitments-query:persona:{namespace.persona_id}",
                     expected_query.revision),
        VersionedRef(f"execution-epoch:{action_id}", anchor.execution_seq),
        VersionedRef(f"cancellation-epoch:{action_id}", 1),
    )
    if (self._GraphCoordinator__d11_issuer.current_budget_grant(
            db, budget_grant.lease_id) != budget_grant
            or self._GraphCoordinator__d02_issuer._load_quote(
                db, resource_quote.quote_id,
                resource_quote.version) != resource_quote):
        raise UnavailableGuard("reply signed D02/D11 issuer state differs; HOLD")
    reservation = db.execute(
        "SELECT digest,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (budget_grant.lease_id, resource_quote.operation_id)).fetchone()
    if reservation is None or reservation[1] != "reserved":
        raise UnavailableGuard("reply dispatch reservation unavailable; HOLD")
    lease = get_budget_lease(db, budget_grant.lease_id)
    observed_budget = _observed_versions(
        db, lease, resource_quote.operation_id, reservation[0])
    budget_versions = (
        VersionedRef(f"d02.resource_quote:{resource_quote.quote_id}",
                     resource_quote.version),
    ) + observed_budget + (
        VersionedRef(f"d11.budget.grant:{budget_grant.lease_id}",
                     budget_grant.version),)
    return CurrentReplyCheckVersionsV2(
        namespace, expected_query, source_ref, resource_quote.quote_id,
        resource_quote.version, budget_grant.grant_id,
        budget_grant.version, reservation[0], (
            CurrentReplyCheckVersionV2(
                "role_binding", source_ref, role_versions),
            CurrentReplyCheckVersionV2(
                "boundary", source_ref, boundary_versions),
            CurrentReplyCheckVersionV2(
                "source_grant", source_ref,
                tuple(VersionedRef(ref, version)
                      for ref, version in sorted(source_versions.items()))),
            CurrentReplyCheckVersionV2(
                "commitment_conflict",
                "d08.commitment_conflict.criteria.v1", d08_versions),
            CurrentReplyCheckVersionV2(
                "dispatch_budget",
                f"d02.resource_quote:{resource_quote.quote_id}",
                budget_versions),
        ))


def _receipt_prebatch_checks_v1(
        self, namespace: NamespaceId, scope, current_effect,
        effect_snapshot, intent, schema, expression, route,
        original_route_binding, current_route_binding, *,
        resource_quote, now_utc: float, valid_until_utc: float,receipt):
    """Issue only check candidates from one staged E+1 SQL projection.

    This private reader is called before a communication grant or batch
    exists. The final receipt hook must run the same readers again against
    the actual sealed rows and compare their entire relevant closures.
    """
    from ..domains.d03.context import ContextProvider
    from ..domains.d08 import ActionSchemaRecord
    from ..domains.d06 import SourceGrantRead, provide_source_grant_check
    from ..authority_service.v2_contract import (
        AuthorityCurrentEffectSnapshotV2,
        canonical_digest as authority_canonical_digest,
    )
    from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
    from .installed_dispatch_admission_issuer import (
        InstalledDispatchAdmissionIssuer, inspect_current_d11_dispatch_budget,
    )

    issuer = self._GraphCoordinator__dispatch_admission_issuer
    context = (issuer._context
               if type(issuer) is InstalledDispatchAdmissionIssuer else None)
    if type(context) is not ContextProvider:
        raise UnavailableGuard("installed social check provider unavailable; HOLD")
    if (resource_quote.deadline_utc != valid_until_utc
            or resource_quote.valid_until_utc < valid_until_utc
            or not now_utc < valid_until_utc):
        raise UnavailableGuard("signed reply dispatch deadline differs; HOLD")
    snapshot, query = _receipt_snapshot_v1(self,namespace,now_utc)
    d08 = self._read_dispatch_d08_scope_locked(
        namespace, scope, current_effect, effect_snapshot, intent, schema,
        current_route_binding,
        audience=(route.conversation_ref,), purpose=intent.purpose,
        now_utc=now_utc, valid_until_utc=valid_until_utc)
    social = _receipt_social_v1(
        self._GraphCoordinator__store._db, snapshot, query, intent,
        ActionSchemaRecord.bind(intent, schema), expression, route=route,
        route_binding=original_route_binding,
        context=context, scope=scope,receipt=receipt,
        now_utc=now_utc, valid_until_utc=valid_until_utc)
    if (social.status != "checks_candidate" or social.role_receipt is None
            or social.boundary_receipt is None
            or social.manifest is None
            or social.manifest.audience != (route.conversation_ref,)):
        raise UnavailableGuard("current D03/D05 prebatch checks unavailable; HOLD")
    metadata = self._GraphCoordinator__store.graph_recovery_metadata(
        namespace, _capability=self._GraphCoordinator__graph_capability)
    epoch_row = self._GraphCoordinator__store._db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple).fetchone()
    access_delete_row = self._GraphCoordinator__store._db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    coverage=_receipt_all_coverage_v1(self,namespace,query,now_utc)
    barrier = (
        metadata is not None
        and self._anchor_matches(metadata.requirements, scope.pinned_anchor)
        and metadata.graph_revision == scope.graph_revision
        and scope.graph_epoch.revision + 1 == query.revision
        and access_delete_row is not None
        and all(type(value) is int and value >= 0
                for value in access_delete_row)
        and scope.operation_id == scope.permit.operation_id
        and scope.permit.pinned_anchor == scope.pinned_anchor
        and type(effect_snapshot) is AuthorityCurrentEffectSnapshotV2
        and effect_snapshot.anchor == scope.pinned_anchor
        and effect_snapshot.permit_digest
            == authority_canonical_digest(scope.permit)
        and effect_snapshot.coverage == "complete"
        and not effect_snapshot.unresolved_effects
        and type(current_effect) is CurrentEffectReadV2
        and current_effect.state == "absent"
        and (current_effect.execution_head_seq,
             current_effect.execution_head_digest) == (
             scope.pinned_anchor.execution_seq,
             scope.pinned_anchor.execution_digest)
    )
    if not coverage or not barrier:
        raise UnavailableGuard("current D06 source coverage or Authority barrier unavailable; HOLD")
    source_check = provide_source_grant_check(
        intent, SourceGrantRead(
            snapshot, (route.conversation_ref,), "expression",
            coverage, barrier),
        valid_until=valid_until_utc)
    budget = inspect_current_d11_dispatch_budget(
        self._GraphCoordinator__store._db, intent, d11_issuer=self._GraphCoordinator__d11_issuer,
        d02_issuer=self._GraphCoordinator__d02_issuer, now_utc=now_utc)
    if ((source_check.result, source_check.coverage) != ("pass", "full")
            or budget.status != "check_pass" or budget.receipt is None
            or (budget.receipt.result, budget.receipt.coverage)
            != ("pass", "full")
            or budget.receipt.valid_until < valid_until_utc):
        raise UnavailableGuard("current D06/D11 prebatch checks unavailable; HOLD")
    return d08, social, source_check, budget.receipt


def _receipt_action_stage_v1(
        self, envelope, action_candidate, snapshot: GraphSnapshot,
        *, now_utc: float):
    """Build only the four D08 rows needed by the E+1 check readers.

    The returned graph candidate is suitable for the provisional savepoint.
    It carries no checks, communication grant, batch, or dispatch authority.
    """
    from ..domains.d08 import GoalExecutionProvider
    from ..runtime_contracts import DependencySet, DomainProposal, QueryEpoch

    store = self._GraphCoordinator__store
    if (not store._lock._is_owned() or not store._db.in_transaction
            or type(action_candidate) is not ArtifactReceiptActionCandidateV1
            or action_candidate.status != "provisional"
            or action_candidate.goal is None
            or action_candidate.intent is None
            or action_candidate.schema is None
            or type(snapshot) is not GraphSnapshot
            or len(snapshot.epochs) != 1
            or type(now_utc) not in (int, float)
            or not math.isfinite(now_utc)):
        raise UnavailableGuard("provisional reply action stage is unavailable; HOLD")
    namespace = envelope.authority.namespace
    epoch = snapshot.epochs[0]
    if ((epoch.bot, epoch.persona) != namespace.as_tuple
            or envelope.identity != action_candidate.intent.identity
            or envelope.source_qualification.source_refs !=
               action_candidate.intent.source_refs
            or envelope.version_guard.query_epochs !=
               (QueryEpoch(namespace, "all", epoch.revision),)
            or set(snapshot.versions) -
               set(envelope.version_guard.read_versions)):
        raise UnavailableGuard("provisional reply action read set differs; HOLD")
    provider = GoalExecutionProvider()
    empty = DomainProposal(
        "d08", "d08.proposal.v1", provider.descriptor.request_schema_hash,
        envelope, (), DependencySet(), (), ())
    goal = provider.prepare_goal_candidate(
        empty, action_candidate.goal,
        source_ref=envelope.source_qualification.source_refs[0])
    action = provider.prepare_action_candidate(
        goal, action_candidate.intent, action_candidate.schema)
    if (len(action.typed_writes) != 4
            or {item.key.type_name for item in action.typed_writes} != {
                "d08.goal.v1", "d08.action_intent.v1",
                "d08.action_schema.v1", "d08.action_cancellation.v1"
            } or any(item.key in {atom.key for atom in snapshot.atoms}
                     for item in action.typed_writes)):
        raise UnavailableGuard("provisional reply action writes differ; HOLD")
    graph_candidate = GraphCandidate(
        Event(Scope(*namespace.as_tuple, envelope.identity.activity_id),
              envelope.identity.operation_id, float(now_utc),
              "domain_bundle", {"provisional_action_digest":
                                canonical_digest(action_candidate)}),
        action.envelope.version_guard.read_versions,
        action.typed_writes, (epoch,))
    return action.envelope, action, graph_candidate


def _receipt_seal_v1(
        self, *, lease, scope: FenceScope, metadata, clock_reading,
        owner_guard, current_effect, effect_snapshot, now_utc: float,
        prepared, finish_id: str, finish_digest: str,
        prepared_full_read=None) -> CommitReceipt:
    """Seal only a locally assembled reply under the caller's write tx.

    The provisional check tuple is never an admission.  The normal graph
    receipt hook reissues all five checks against final E+1 rows and lets
    the installed dispatch issuer independently validate the command.
    """
    from ..authority_service.v2_contract import to_wire

    store = self._GraphCoordinator__store
    if (not store._lock._is_owned() or not store._db.in_transaction
            or type(scope) is not FenceScope or scope.operation != "write"
            or type(prepared) is not tuple or len(prepared) != 9
            or type(finish_id) is not str or not finish_id
            or type(finish_digest) is not str or not finish_digest
            or self._v2_graph_stamp(scope.namespace) != (
                metadata, scope.graph_epoch)):
        raise UnavailableGuard("reply final seal lost its write transaction; HOLD")
    (receipt_original, route, envelope, expression, grant, quote,
     job, staged, bundle_candidate) = prepared
    if (type(bundle_candidate) is not ArtifactReceiptDispatchBundleCandidateV1
            or bundle_candidate.status != "candidate"
            or bundle_candidate.bundle.envelope.authority.namespace
               != scope.namespace
            or bundle_candidate.bundle.envelope.identity.operation_id
               != envelope.identity.operation_id
            or bundle_candidate.job != job):
        raise UnavailableGuard("reply final bundle is not locally assembled; HOLD")
    (staged_envelope, staged_d08, action, social, candidate,
     original_binding, staged_binding, route_grant) = staged
    if (replace(bundle_candidate.bundle.envelope,
                version_guard=staged_envelope.version_guard)
            != staged_envelope
            or not set(staged_envelope.version_guard.read_versions)
               .issubset(bundle_candidate.bundle.envelope.version_guard.read_versions)):
        raise UnavailableGuard("reply final envelope differs from staged checks; HOLD")
    batch_refs = tuple(
        write.key.token for proposal in bundle_candidate.bundle.proposals
        for write in proposal.typed_writes
        if write.key.type_name == "d09.verified_segment_batch.v1")
    if len(batch_refs) != 1:
        raise UnavailableGuard("reply final batch identity differs; HOLD")

    def reissue(db, graph_receipt, read_scope, final_now):
        return _receipt_final_reissue_v1(self,
            db, graph_receipt, read_scope, final_now,
            envelope=envelope,receipt=receipt_original,route=route,
            budget_grant=grant, resource_quote=quote,
            anchor=scope.pinned_anchor,
            current_effect=current_effect, effect_snapshot=effect_snapshot,
            expected_action=action, expected_social=social,
            expected_original_binding=original_binding,
            expected_staged_binding=staged_binding,
            expected_grant=route_grant, batch_ref=batch_refs[0])

    return self._commit_domain_bundle_fenced(
        bundle_candidate.bundle, lease,
        v2_write=(metadata, scope.graph_epoch, finish_id, finish_digest,
                  canonical_json(to_wire(scope.permit))),
        in_transaction=True, now_utc=now_utc,
        dispatch_clock_reading=clock_reading,
        dispatch_clock_frozen_now_utc=now_utc,
        dispatch_admission_scope=scope,
        dispatch_admission_owner_guard=owner_guard,
        dispatch_admission_current_effect=current_effect,
        dispatch_admission_effect_snapshot=effect_snapshot,
        provisional_check_candidate=candidate,
        installed_final_check_reissuer=reissue,
        _prepared_full_read=prepared_full_read,
        _full_read_write_scope=scope)

def read_artifact_receipt_locator_route_v1(graph,bootstrap,installed_bundle,*,c02_operation_id,source_ref):
    from .ingress_observation import read_committed_ingress_identity
    from .first_ingress_v2 import scene_ref_for_conversation
    graph._admin(bootstrap);namespace=installed_bundle.installation_policy.namespace
    key=AtomKey.from_token(source_ref)
    if key!=source_key(*namespace.as_tuple,key.owner.subject or ""):
        raise UnavailableGuard("receipt locator is not its original canonical ingress Source")
    with graph._GraphCoordinator__store._lock:
        db=graph._GraphCoordinator__store._db;db.execute("BEGIN")
        try:
            original=read_committed_ingress_identity(db,namespace,key.owner.subject)
            if original is None:raise UnavailableGuard("receipt locator has no actual original ingress seal")
            value=json.loads(original.identity_json)
            if value["visibility"]!="private":raise UnavailableGuard("receipt locator has no original private route")
            scene=scene_ref_for_conversation(namespace,value["platform_ref"],value["conversation_ref"])
            digest=canonical_digest({"account_ref":value["platform_ref"],"destination_ref":value["conversation_ref"],"scene_ref":scene})
            return CurrentReplyRouteManifestV2(namespace,c02_operation_id,source_ref,value["platform_ref"],value["conversation_ref"],scene,digest)
        finally:db.rollback()

from dataclasses import dataclass

@dataclass(frozen=True,slots=True)
class ArtifactReceiptFinalReissueV1:
    candidate:object
    route_binding:object
    social:object
    d08_scope:object
    grant:object
    action:object
    graph_receipt:object
    receipt:ArtifactCompletionReceiptOriginalV1

def is_actual_artifact_receipt_final_reissue_v1(value,db,*,now_utc,scope=None):
    if type(value)is not ArtifactReceiptFinalReissueV1:return False
    from .dispatch_check_reissue import ProvisionalCheckCandidateV1
    from ..domains.d08 import CommunicationIntentGrant,DispatchCheckScopeV2
    from ..graph_types import GraphReceipt
    proof=_RECEIPT_BASE.get()
    if proof is None or proof.db is not db:
        raise AuthorityUnavailable("receipt final detail cannot exist without its actual originating full Work")
    _,_,actual=_receipt_base_v1(proof.graph,now_utc)
    if (value.receipt!=actual or type(value.candidate)is not ProvisionalCheckCandidateV1
            or type(value.route_binding)is not CurrentReplyEntityRouteBindingV2
            or type(value.social)is not PrebatchSocialCandidateV1 or type(value.d08_scope)is not DispatchCheckScopeV2
            or type(value.grant)is not CommunicationIntentGrant or type(value.action)is not ArtifactReceiptActionCandidateV1
            or type(value.graph_receipt)is not GraphReceipt or value.graph_receipt.status!="committed"
            or value.graph_receipt.epoch.revision!=value.candidate.graph_epoch
            or value.route_binding.query.revision!=value.candidate.graph_epoch
            or value.social.status!="checks_candidate"or value.action.status!="candidate"
            or value.action.expression!=artifact_receipt_expression_v1(actual,value.grant.audiences)
            or value.action.intent.identity.operation_id!=actual.message_operation_id
            or value.action.intent.identity.effect_id!=actual.effect_id
            or value.action.intent.source_refs!=(actual.source_ref,)
            or value.grant.route_binding_digest!=canonical_digest(value.route_binding)
            or value.action.intent.action_id!=value.d08_scope.action_id
            or value.action.intent.target_ref!=value.route_binding.target_entity_ref
            or value.grant.target_ref!=value.route_binding.target_entity_ref
            or value.grant.audiences!=(value.route_binding.conversation_ref,)
            or len(value.candidate.checks)!=5 or value.candidate.checks!=(value.social.role_receipt,
                value.social.boundary_receipt,value.candidate.checks[2],value.d08_scope.receipt,value.candidate.checks[4])
            or scope is not None and (value.candidate.permit_token!=scope.permit.token
                or value.candidate.authority_head!=scope.pinned_anchor or scope.namespace!=actual.namespace)):
        raise AuthorityUnavailable("receipt final detail changed its actual current seal/Source/fixed expression/five checks")
    return True

def read_current_artifact_receipt_guard_atom_v1(graph,bundle,read):
    proof=_RECEIPT_BASE.get()
    if proof is None:return False,None
    _,current,receipt=_receipt_base_v1(graph,proof.artifact_receipt_originals.task.now_utc)
    envelope=bundle.envelope
    if (envelope.identity.operation_id!=receipt.message_operation_id or envelope.identity.effect_id!=receipt.effect_id
            or envelope.source_qualification.source_refs!=(receipt.source_ref,)
            or envelope.authority.actor!=proof.artifact_receipt_originals.task.actor_ref):
        raise AuthorityUnavailable("receipt guard bundle changed its actual completed Self/Source/message")
    snapshot,_=_receipt_snapshot_v1(graph,receipt.namespace,proof.artifact_receipt_originals.task.now_utc)
    atom=snapshot.get(read.key)
    head=graph._GraphCoordinator__store._db.execute("SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
        (*receipt.namespace.as_tuple,read.key.token)).fetchone()
    if read.revision==0 and atom is None and head is None and read.key.token not in current.heads:
        return True,GraphAtom(read.key,0,{},False)
    if(atom is None or atom.revision!=read.revision or head is None
            or tuple(head)!=current.heads.get(read.key.token)or head[:2]!=(read.revision,int(atom.valid))):
        raise AuthorityUnavailable("receipt guard differs from actual typed FULL census/Store delta")
    return True,atom


def _receipt_fence_locator_v1(graph,installed_bundle,c02_operation_id,source_ref):
    """Read only existing indexed Source/producer/fence metadata; never issue content work."""
    from .foreground_cycle_v1 import foreground_cycle_ids_v1
    namespace=installed_bundle.installation_policy.namespace
    cue=AtomKey.from_token(source_ref)
    if cue!=source_key(*namespace.as_tuple,cue.owner.subject or ""):
        raise UnavailableGuard("receipt fence recovery cue is not its canonical original Source")
    store=graph._GraphCoordinator__store;db=store._db
    if not store._lock._is_owned()or not db.in_transaction:
        raise UnavailableGuard("receipt original fence lookup requires its local metadata transaction")
    rows=db.execute("SELECT a.token,a.subject,a.revision,a.valid FROM graph_dependencies d "
        "JOIN graph_atoms a ON a.token=d.dependent_token WHERE d.dependency_token=? AND a.bot=? AND a.persona=? "
        "AND a.type_name='memory.source' AND a.subject>=? AND a.subject<? ORDER BY a.token LIMIT 2",
        (source_ref,*namespace.as_tuple,"artifact-completion:","artifact-completion;")).fetchall()
    if not rows:return None
    if len(rows)!=1:raise UnavailableGuard("receipt original cue has ambiguous completion Source metadata")
    token,source_id,revision,valid=rows[0]
    marker=source_id.removeprefix("artifact-completion:")
    if(len(marker)!=48 or any(c not in"0123456789abcdef"for c in marker)or revision!=1 or valid!=1
            or token!=source_key(*namespace.as_tuple,"artifact-completion:"+marker).token):
        raise UnavailableGuard("receipt recovery Source identity or immutable head differs")
    producer="artifact-completion-source:"+marker;operation="artifact-receipt-message:"+marker
    effect="artifact-receipt-effect:"+marker
    activity=foreground_cycle_ids_v1(namespace,c02_operation_id)[0]
    original=db.execute("SELECT domain,operation_kind,original_digest,bundle_digest,receipt_digest FROM "
        "graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple,producer)).fetchone()
    produced=db.execute("SELECT digest,activity_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,producer)).fetchone()
    if(original is None or produced is None or original[:2]!=("d06","derive_artifact_completion_receipt_v1")
            or original[3]!=produced[0]or produced[1]!=activity or type(produced[2])is not int or produced[2]<1):
        raise UnavailableGuard("receipt original fence locator has no actual same-task D06 producer")
    for ref in(token,access_key(*namespace.as_tuple,source_id).token):
        born=db.execute("SELECT valid,event_bot,event_persona,event_session,event_id,value_cell_id FROM "
            "graph_history WHERE token=? AND revision=1",(ref,)).fetchone()
        head=db.execute("SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*namespace.as_tuple,ref)).fetchone()
        if(born is None or born[:5]!=(1,*namespace.as_tuple,activity,producer)
                or head!=(1,1,born[5])):
            raise UnavailableGuard("receipt Source/Access birth lost its actual same-producer history")
    input_digest=canonical_digest(("artifact-receipt-fence-input.v1",namespace,c02_operation_id,source_ref,
        token,producer,original,installed_bundle.installation_policy.installation_id,
        installed_bundle.installation_policy.manifest_digest))
    return namespace,operation,effect,activity,input_digest


def _receipt_fence_attempt_id_v1(located):
    return "artifact-receipt-assembly:"+canonical_digest((
        "artifact-receipt-dispatch-attempt.v1",located[1],located[4]))[:48]


def _receipt_no_commit_finish_identity_v1(located,scope):
    return("abort:"+scope.operation_id,"sha256:"+canonical_digest({
        "action":"close_artifact_receipt_assembly_without_commit_v1",
        "namespace":located[0],"operation_id":located[1],"input_digest":located[4],
        "permit_digest":canonical_digest(scope.permit),"anchor":scope.pinned_anchor,
        "graph_revision":scope.graph_revision,"graph_epoch":scope.graph_epoch.revision}))


def _receipt_require_business_absence_v1(graph,located,c02_operation_id):
    """Metadata absence is necessary, never sufficient to abort an unknown active attempt."""
    from .artifact_receipt_allocation_v3 import foreground_artifact_receipt_budget_ids_v3
    from .issuers import private_reply_dispatch_quote_id
    namespace,operation,effect,activity,_=located
    marker=canonical_digest(("d11.artifact-receipt-dispatch.v1",operation))[:48]
    db=graph._GraphCoordinator__store._db
    for table,predicate,args in(
            ("graph_bundle_operations","bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,operation)),
            ("graph_bundle_fences_v2","bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,operation)),
            ("graph_dispatch_admissions","bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,operation)),
            ("graph_events","bot=? AND persona=? AND session=? AND event_id=?",(*namespace.as_tuple,activity,operation)),
            ("runtime_resource_quotes","quote_id=?",(private_reply_dispatch_quote_id(namespace,operation),)),
            ("runtime_budget_reservations","lease_id=? AND operation_id=?",
                (foreground_artifact_receipt_budget_ids_v3(namespace,c02_operation_id)[0],operation)),
            ("runtime_jobs","job_id=?",("artifact-receipt-dispatch:"+marker,))):
        if db.execute("SELECT 1 FROM "+table+" WHERE "+predicate+" LIMIT 1",args).fetchone()is not None:
            raise UnavailableGuard("receipt original "+table+" row prevents proven no-commit closure; HOLD")


def _finish_artifact_receipt_known_no_commit_v1(graph,installed_bundle,receipt,metadata,epoch,scope):
    """Called only from this live attempt's confirmed local refusal/rollback branch."""
    c02=receipt.selector.task.c02_operation_id
    cue=_RECEIPT_BASE.get().artifact_receipt_originals.task.route.source_ref
    store=graph._GraphCoordinator__store;port=graph._GraphCoordinator__content_fence_v2
    with store._lock:
        db=store._db;db.execute("BEGIN")
        try:
            located=_receipt_fence_locator_v1(graph,installed_bundle,c02,cue)
            if(located is None or located[1:4]!=(receipt.message_operation_id,receipt.effect_id,
                    receipt_ids_v1(receipt.selector)["activity"])
                    or _receipt_fence_attempt_id_v1(located)!=scope.operation_id
                    or graph._v2_graph_stamp(receipt.namespace)!=(metadata,epoch)
                    or(scope.graph_revision,scope.graph_epoch)!=(metadata.graph_revision,epoch)):
                raise UnavailableGuard("receipt confirmed refusal lost its exact input/attempt/pre-stamp")
            _receipt_require_business_absence_v1(graph,located,c02)
        finally:db.rollback()
    original,state=port.get_fence_operation(namespace=receipt.namespace,authority_namespace=scope.authority_namespace,
        operation_id=scope.operation_id)
    if original!=scope.permit or state not in{"active","finished"}:
        raise UnavailableGuard("receipt no-commit closure lost its actual original permit")
    if state=="active":
        if port.validate_fence(scope)!=scope.permit:raise UnavailableGuard("receipt no-commit closure scope changed")
        finish_id,finish_digest=_receipt_no_commit_finish_identity_v1(located,scope)
        # V2FencePort records the actual pending finish if this exact request loses
        # its ACK. That private local original may replay it; absence alone may not.
        port.finish_fence(scope,request_id=finish_id,request_digest=finish_digest)


def _recover_artifact_receipt_original_finish_v1(graph,installed_bundle,*,c02_operation_id,source_ref):
    """Inspect the stable attempt before any new Content/FULL call; never rename it."""
    from ..authority_service.v2_contract import from_wire
    from ..host.v2_fence_port import _PendingFinish
    store=graph._GraphCoordinator__store;port=graph._GraphCoordinator__content_fence_v2
    with store._lock:
        db=store._db;db.execute("BEGIN")
        try:
            located=_receipt_fence_locator_v1(graph,installed_bundle,c02_operation_id,source_ref)
            if located is None:return
            namespace,operation,effect,activity,_=located
            attempt=_receipt_fence_attempt_id_v1(located)
            committed=db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
                "WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,operation)).fetchone()
            saved=db.execute("SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,"
                "post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,operation)).fetchone()
            rejected=db.execute("SELECT 1 FROM graph_bundle_rejections_v2 WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple,operation)).fetchone()
            if rejected is not None:raise UnavailableGuard("receipt has an existing formal bundle rejection; HOLD")
            metadata,epoch=graph._v2_graph_stamp(namespace)
            if committed is not None or saved is not None:
                admission=db.execute("SELECT admission_ref,admission_digest,receipt_digest,graph_epoch FROM "
                    "graph_dispatch_admissions WHERE bot=? AND persona=? AND operation_id=? AND effect_id=?",
                    (*namespace.as_tuple,operation,effect)).fetchone()
                event=db.execute("SELECT epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                    (*namespace.as_tuple,activity,operation)).fetchone()
                if(committed is None or saved is None or committed[0]!=saved[0]
                        or committed[1:3]!=(activity,effect)or type(committed[3])is not int or committed[3]<1
                        or saved[4:6]!=(saved[2]+1,saved[3]+1)or admission is None
                        or not all(type(v)is str and v for v in admission[:3])or admission[3]!=saved[5]
                        or event!=(saved[5],)):
                    raise UnavailableGuard("receipt actual committed fence/admission/event metadata differs")
                permit=from_wire(json.loads(saved[1]))
            else:
                # Merely finding no business row is not a deterministic rollback proof.
                _receipt_require_business_absence_v1(graph,located,c02_operation_id)
                permit=None
        finally:db.rollback()
    target=metadata.requirements;grant=port.installation_grant
    if permit is not None:
        original,state=port.get_fence_operation(namespace=namespace,authority_namespace=target.authority_namespace,
            operation_id=attempt)
        if original!=permit:raise UnavailableGuard("receipt actual committed permit differs")
    else:
        try:
            anchor=port.current_anchor(namespace=namespace,authority_namespace=target.authority_namespace)
            observed=port.observe_content_write_attempt_v1(namespace=namespace,authority_namespace=target.authority_namespace,
                operation_id=attempt,expected_anchor=anchor)
        except Exception as observation_failure:
            # Historical get can read an existing permit after its original anchor
            # changed. Neither failure is ever interpreted as an absent attempt.
            try:
                permit,state=port.get_fence_operation(namespace=namespace,authority_namespace=target.authority_namespace,
                    operation_id=attempt)
            except Exception as historical_failure:
                observation_failure.add_note("Historical exact-attempt lookup also failed: "
                    +type(historical_failure).__name__+": "+str(historical_failure))
                raise observation_failure
        else:
            if observed.state=="absent":return
            permit,state=observed.permit,observed.state
    if(type(permit)is not FencePermitV2 or permit.operation!="write"or permit.operation_id!=attempt
            or permit.subject!=grant.subject
            or permit.authority_id!=grant.authority_id or permit.namespace!=target.authority_namespace
            or state not in{"active","finished"}
            or grant.installation_id!=installed_bundle.installation_policy.installation_id
            or grant.manifest_digest!=installed_bundle.installation_policy.manifest_digest):
        raise UnavailableGuard("receipt original attempt changed its actual installation/Authority/namespace")
    if state=="active" and (permit.holder!=graph._GraphCoordinator__holder or permit.generation!=target.activation_generation):
        raise UnavailableGuard("receipt active original attempt changed current holder/generation; HOLD")
    if saved is not None:
        pre,post=saved[2:4],saved[4:6]
        finish_id,finish_digest=saved[6:]
        expected="sha256:"+canonical_digest({"action":"finish_artifact_receipt_dispatch_v1",
            "attempt":attempt,"permit":permit.token,"bundle":saved[0]})
        if(finish_id,finish_digest)!=("finish:"+attempt,expected):
            raise UnavailableGuard("receipt original committed finish request differs")
        if metadata.graph_revision<post[0]or epoch.revision<post[1]:
            raise UnavailableGuard("receipt original committed graph regressed")
        if state=="active":
            if(metadata.graph_revision,epoch.revision)!=post:
                raise UnavailableGuard("receipt active committed finish lost its exact post-stamp")
            scope=FenceScope(namespace,target.authority_namespace,target.activation_generation,"write",attempt,permit,
                permit.pinned_anchor,NamespaceEpoch(*namespace.as_tuple,pre[1]),pre[0])
            if port.validate_fence(scope)!=permit:raise UnavailableGuard("receipt original committed scope changed")
            port.finish_fence(scope,request_id=finish_id,request_digest=finish_digest)
        return
    if state=="finished":
        raise UnavailableGuard("receipt original attempt is finished without an actual committed message; terminal HOLD")
    # Only V2FencePort's actual local pending finish can witness a previously
    # proven local refusal. A cold process or an unknown begin/commit has no such
    # matching abort original and must retain the active scope.
    with port._lock:
        pending=port._pending_finish
        if(type(pending)is not _PendingFinish or pending.scope.permit!=permit
                or pending.scope.operation_id!=attempt or pending.scope.namespace!=namespace
                or(pending.request_id,pending.request_digest)!=_receipt_no_commit_finish_identity_v1(located,pending.scope)):
            raise UnavailableGuard("receipt original active attempt has no local confirmed no-commit finish original; HOLD")
        scope=pending.scope
    with store._lock:
        db.execute("BEGIN")
        try:
            current=graph._v2_graph_stamp(namespace)
            if(current!=(metadata,epoch)or(metadata.graph_revision,epoch.revision)!=(scope.graph_revision,scope.graph_epoch.revision)
                    or _receipt_fence_locator_v1(graph,installed_bundle,c02_operation_id,source_ref)!=located):
                raise UnavailableGuard("receipt pending no-commit finish lost its original pre-stamp/input")
            _receipt_require_business_absence_v1(graph,located,c02_operation_id)
        finally:db.rollback()
    if port.validate_fence(scope)!=permit:raise UnavailableGuard("receipt pending no-commit original scope changed")
    with port._lock:
        if port._pending_finish is not pending:
            raise UnavailableGuard("receipt pending no-commit original changed before replay")
        port.recover_pending_finish()
    raise UnavailableGuard("receipt original attempt is closed without an actual committed message; terminal HOLD")
