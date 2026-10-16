"""Actual installed Core issuer for one original Artifact call's financial metadata."""
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
import json
from .contract import AuthorityUnavailable
from .artifact_no_dispatch_metadata_contract_v1 import (
    SIGN_KIND, FINANCIAL_KINDS, ModelNoDispatchMetadataRequestV1,
    ModelNoDispatchMetadataGrantV1, to_wire_v1, from_wire_v1)
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (runtime_storage_v3, begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3, runtime_storage_quantum_v3)


class InstalledArtifactNoDispatchMetadataServiceV1:
    def __init__(self, *, model_service, owner_service, bundle):
        from .v2_model_egress_service import AuthorityV2ModelEgressService
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        from ..host.authority_profile import AdminInstallationBundle
        if (type(model_service) is not AuthorityV2ModelEgressService
                or type(owner_service) is not InstalledOwnerStopReplyServiceV1
                or type(bundle) is not AdminInstallationBundle
                or model_service._fences is not owner_service.fences
                or model_service._store._db is not owner_service.core._db
                or model_service._graph_verifier._artifact_draft_bundle is not bundle
                or model_service._graph_verifier._issuer is not owner_service.issuer
                or owner_service.namespace_id!=bundle.installation_policy.namespace
                or owner_service.installation_id!=bundle.installation_policy.installation_id):
            raise AuthorityUnavailable("actual same installed Artifact/Core/Owner/C09 composition required")
        self.model_service,self.owner_service,self.bundle=model_service,owner_service,bundle
        self.core,self.fences,self.control,self.issuer=owner_service.core,owner_service.fences,owner_service.control,owner_service.issuer
        self.namespace,self.namespace_id,self.installation_id=owner_service.namespace,owner_service.namespace_id,owner_service.installation_id
        self.holder=bundle.installation_policy.administrator_holder

    def _require_peer_v1(self, credential, subject):
        from .mtls_server import MtlsPeerCredential
        if type(credential) is not MtlsPeerCredential or subject!="mtls:sha256:"+credential.certificate_sha256:
            raise AuthorityUnavailable("original installed financial mTLS controller required")
        self.core._require(credential,"model_egress",self.namespace,self.holder)
        self.core._require(credential,"accounting",self.namespace,self.holder)

    @contextmanager
    def _metadata_operation_v1(self, operation_id):
        db=self.core._db;handle=runtime_storage_v3(db)
        if handle is None or handle.role!="core":
            raise AuthorityUnavailable("actual selected installed Core metadata role required")
        # This new RPC has no execution deadline. Its actual registered metadata
        # operation is checked per quantum; it never edits the original C4 TTL.
        operation=begin_runtime_storage_operation_v3(db,operation_id,None)
        try:
            with bind_runtime_storage_operation_v3(operation,db):
                with runtime_storage_quantum_v3(db):
                    yield operation
        finally:finish_runtime_storage_operation_v3(operation)

    def _original_v1(self, db, request, subject):
        where="namespace=? AND installation_id=?";values=(self.namespace,self.installation_id)
        if request.job_id is not None:
            where+=" AND job_id=?";values+= (request.job_id,)
        else:
            where+=" AND call_id COLLATE BINARY>?";values+=(request.after_call_id,)
        # Only the closed two existing Artifact identity families are candidates.
        where+=" AND (job_id GLOB 'artifact-draft-job:*' OR job_id GLOB 'artifact-draft-v2-job:*')"
        row=db.execute("SELECT call_id,authority_id,installation_id,namespace,job_id,acquire_operation_id,"
            "operation_id,request_digest,binding_digest FROM authority_model_original_identity_v2 WHERE "+where+
            " ORDER BY call_id COLLATE BINARY LIMIT 1",values).fetchone()
        if row is None:return None
        record=self.model_service._store.lookup_original_locked(db,authority_id=row[1],installation_id=row[2],
            namespace=row[3],job_id=row[4],acquire_operation_id=row[5],operation_id=row[6],call_id=row[0],
            request_digest=row[7],binding_digest=row[8])
        if record is None or record.intent.subject!=subject:
            raise AuthorityUnavailable("financial metadata cannot retarget another original model controller")
        return record.intent,canonical_digest(row)

    def issue_v1(self, *, credential, subject, request):
        self._require_peer_v1(credential,subject)
        if type(request) is not ModelNoDispatchMetadataRequestV1 or (
                request.namespace,request.authority_namespace,request.installation_id)!=(
                self.namespace_id,self.namespace,self.installation_id):
            raise AuthorityUnavailable("actual installed financial metadata selector required")
        context,storage,member=self.owner_service._storage()
        context.require_current("business");self.control.verify_member_v1(member,prepared=False)
        with self._metadata_operation_v1(request.read_operation_id) as operation:
            with self.fences._frozen() as (db,deletion,execution,_):
                anchor=self.fences._current_locked(db,deletion,execution,holder=self.holder,
                    require_clear=False,require_no_pending=False)
                original=self._original_v1(db,request,subject)
                if original is None:return None
                head=self.owner_service.status_service.tickets.current_migration_head_in_tx(db,authority_namespace=self.namespace)
                if head is None or head.guard.namespace!=request.namespace:
                    raise AuthorityUnavailable("actual current Owner lineage metadata is absent")
            context.require_current("business");self.control.verify_member_v1(member,prepared=False)
            from .v2_model_egress_wire import to_wire as model_to_wire
            from .v2_owner_contract import to_wire as owner_to_wire
            unsigned=dict(request=asdict(request),intent=model_to_wire(original[0]),subject=subject,holder=self.holder,
                original_identity_digest=original[1],current_anchor=asdict(anchor),current_owner_head=owner_to_wire(head),
                selection_digest=runtime_storage_v3(self.core._db).selection_digest,
                storage_manifest_digest=context.manifest_digest,storage_pointer_version=context.pointer_version,
                storage_generation=context.storage_generation,graph_incarnation=member["incarnation_or_journal_id"],
                core_registered_deadline_utc=operation.deadline_utc,allowed_kinds=list(FINANCIAL_KINDS),
                schema="d11.artifact-no-dispatch-metadata-grant.v1")
            signature=self.issuer._signer.sign(SIGN_KIND,canonical_serialize(unsigned))
            return from_wire_v1({**unsigned,"signature":signature},ModelNoDispatchMetadataGrantV1)

    def validate_v1(self, *, credential, subject, grant):
        self._require_peer_v1(credential,subject)
        if type(grant) is not ModelNoDispatchMetadataGrantV1:raise AuthorityUnavailable("actual typed financial grant required")
        grant.require_signature_v1(self.issuer._signer)
        context,storage,member=self.owner_service._storage()
        context.require_current("business");self.control.verify_member_v1(member,prepared=False)
        with self._metadata_operation_v1(grant.request.read_operation_id) as operation:
            with self.fences._frozen() as (db,deletion,execution,_):
                anchor=self.fences._current_locked(db,deletion,execution,holder=self.holder,
                    require_clear=False,require_no_pending=False)
                original=self._original_v1(db,grant.request,subject)
                head=self.owner_service.status_service.tickets.current_migration_head_in_tx(db,authority_namespace=self.namespace)
                if (original!=(grant.intent,grant.original_identity_digest) or anchor!=grant.current_anchor
                        or head!=grant.current_owner_head or subject!=grant.subject or grant.holder!=self.holder
                        or operation.deadline_utc!=grant.core_registered_deadline_utc):
                    raise AuthorityUnavailable("current original financial metadata permission/pins changed")
        if (context.manifest_digest,context.pointer_version,context.storage_generation,
                member["incarnation_or_journal_id"],runtime_storage_v3(self.core._db).selection_digest)!=(
                grant.storage_manifest_digest,grant.storage_pointer_version,grant.storage_generation,
                grant.graph_incarnation,grant.selection_digest):
            raise AuthorityUnavailable("current financial metadata selected Core/Graph changed")
        context.require_current("business");self.control.verify_member_v1(member,prepared=False)
        return grant

    def read_cancellation_v1(self, *, credential, subject, grant, prepared_wire, prepared_signature):
        self.validate_v1(credential=credential,subject=subject,grant=grant)
        from ..runtime.d11_artifact_draft_model_v1 import (
            ArtifactDraftModelPreparedV1,ArtifactDraftModelPreparedV2,
            artifact_draft_model_from_wire_v1,artifact_draft_model_from_wire_v2)
        from ..runtime.d11_life_preparation_v1 import SIGN_KIND as C4_SIGN_KIND
        from ..runtime.d08_personal_plan_v1 import artifact_goal_plan_keys_v1
        from .owner_goal_cancellation_contract_v1 import GOAL_CANCEL_TABLE_V1,GOAL_CANCEL_COLUMNS_V1,validate_goal_cancellation_core_row_v1
        phase=prepared_wire.get("schema")=="d11.artifact-draft-phase-model-prepared.v2"
        prepared=(artifact_draft_model_from_wire_v2(prepared_wire,ArtifactDraftModelPreparedV2)
            if phase else artifact_draft_model_from_wire_v1(prepared_wire,ArtifactDraftModelPreparedV1))
        kind="c4_phase_prepared" if phase else "c4_prepared"
        self.issuer._signer.verify(C4_SIGN_KIND,canonical_serialize((prepared.namespace,kind,
            prepared.job_id,prepared.digest)),prepared_signature)
        if (prepared.namespace,prepared.digest,prepared.job_id,prepared.call_id,prepared.parent_budget_lease_ref,
                prepared.reservation_digest)!=(grant.request.namespace,grant.intent.binding_digest,
                grant.intent.job_id,grant.intent.call_id,grant.intent.budget_lease_id,grant.intent.budget_reservation_digest):
            raise AuthorityUnavailable("Goal cancel lookup lost its actual signed original financial selector")
        task=prepared.selector.task if phase else prepared.selector
        goal=artifact_goal_plan_keys_v1(task.namespace,c02_operation_id=task.c02_operation_id,
            root_registration_ref=task.root_registration_ref)[0]
        with self._metadata_operation_v1(grant.request.read_operation_id):
            with self.core._tx() as db:
                row=db.execute("SELECT "+",".join(GOAL_CANCEL_COLUMNS_V1)+" FROM "+GOAL_CANCEL_TABLE_V1+
                    " WHERE authority_namespace=? AND installation_id=? AND goal_ref=? AND root_registration_ref=? "
                    "ORDER BY cancel_operation_id LIMIT 1",(self.namespace,self.installation_id,goal.token,task.root_registration_ref)).fetchone()
                if row is None:return None
                original=validate_goal_cancellation_core_row_v1(GOAL_CANCEL_COLUMNS_V1,row,issuer=self.issuer)
                if original.request.c02_operation_id!=task.c02_operation_id:
                    raise AuthorityUnavailable("Goal cancellation changed the actual original Artifact C02")
        self.validate_v1(credential=credential,subject=subject,grant=grant)
        return original
