"""Dedicated metadata and parentage for independently observed Artifact phases."""
from dataclasses import fields
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1
from ..authority_service.contract import AuthorityUnavailable


def artifact_observation_descriptor_from_metadata_v3(raw,*,namespace,prepared_digest):
    from .foreground_call_plan_v1 import NamedC3ParentageDescriptorV3
    from .d07_execution_v1 import d07_execution_ids_v1
    marker=raw["operation_id"].removeprefix("artifact-phase-observe:")
    if (raw["schema"]!="d07.artifact-observation-prepared.v3" or raw["work_kind"]!="concern"
            or raw["operation_id"]!="artifact-phase-observe:"+marker or len(marker)!=48
            or any(c not in "0123456789abcdef"for c in marker)
            or raw["observation_basis_ref"]!="artifact-phase-observation-basis:"+marker
            or raw["semantic_question_ref"]!="artifact-phase-observation-question:"+marker
            or type(raw["cancel_generation"])is not int or raw["cancel_generation"]!=0):
        raise AuthorityUnavailable("Artifact parentage requires its dedicated original identities")
    ids=d07_execution_ids_v1(namespace,raw["operation_id"],"concern")
    if any(raw[name]!=ids[name.removesuffix("_id")]for name in("job_id","call_id","execution_id")):
        raise AuthorityUnavailable("Artifact parentage changed its exact D07 once identities")
    for name in("observation_basis_digest","semantic_question_digest","cycle_digest","call_plan_digest"):
        value=raw[name]
        if type(value)is not str or len(value)!=64 or any(c not in "0123456789abcdef"for c in value):
            raise AuthorityUnavailable("Artifact parentage lost an exact signed commitment")
    head=raw["cycle_ref"]
    if type(head)is not dict or set(head)!={"key","revision"} or type(head["key"])is not str:
        raise AuthorityUnavailable("Artifact parentage requires canonical GraphVersion token wire")
    version=GraphVersion(AtomKey.from_token(head["key"]),head["revision"])
    if version.key.type_name!="runtime.job"or NamespaceId.from_key(version.key)!=namespace or version.revision<1:
        raise AuthorityUnavailable("Artifact parentage crossed its actual cycle namespace")
    return NamedC3ParentageDescriptorV3(namespace=namespace,kind="artifact_observation_self",
        operation_id=raw["operation_id"],job_id=raw["job_id"],call_id=raw["call_id"],
        semantic_question_ref=raw["semantic_question_ref"],semantic_question_digest=raw["semantic_question_digest"],
        observation_basis_ref=raw["observation_basis_ref"],observation_basis_digest=raw["observation_basis_digest"],
        cycle_ref=version,cycle_digest=raw["cycle_digest"],call_plan_digest=raw["call_plan_digest"],
        c02_operation_id=raw["c02_operation_id"],cancel_generation=raw["cancel_generation"],prepared_digest=prepared_digest)


class ArtifactObservationParentMetadataReadV3:
    """One bounded leaf per quantum, retaining no task or authored Source body."""
    def __init__(self,parent):
        from ..authority_service.d07_authority_model_source_read_v3 import _D07SpecialParentMetadataReadV3
        from .d07_stage_content_scope_v3 import _HostSpecialParentMetadataReadV3
        if type(parent)not in{_D07SpecialParentMetadataReadV3,_HostSpecialParentMetadataReadV3}:
            raise AuthorityUnavailable("Artifact metadata requires its exact originating Core or Host parent task")
        self.host=type(parent)is _HostSpecialParentMetadataReadV3
        self.parent,self.reader,self.work=parent,parent.reader,parent.work
        self.phase="basis";self.complete=False;self.basis=None

    def leaf(self,name,leaf):
        return self.parent._leaf_v3(("artifact-observation",self.parent.header.job_id,name),leaf)

    def advance_v3(self,meter):
        if self.host:
            from .d07_stage_content_scope_v3 import (
                _HostSignedParentMetadataReadV3 as _Signed,_HostAdoptedParentMetadataReadV3 as _Adopted,
                _HostHistoryParentMetadataReadV3 as _History,_HostParentJobMetadataReadV3 as _Job,
                _host_parent_head_v3 as _head)
        else:
            from ..authority_service.d07_authority_model_source_read_v3 import (
                _D07SignedParentMetadataReadV3 as _Signed,_D07AdoptedParentMetadataReadV3 as _Adopted,
                _D07HistoryParentMetadataReadV3 as _History,_D07ParentJobMetadataReadV3 as _Job,
                _d07_parent_head_v3 as _head)
        from .artifact_phase_observation_v1 import (KIND,OPERATION,ArtifactPhaseObservationBasisV1,
            ArtifactPhaseObservationQuestionV1,observation_basis_from_wire_v1)
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
        p=self.parent;r=self.reader;w=self.work;raw=p.raw;header=p.header
        r.require_current_v3(meter)
        if self.phase=="basis":
            leaf=self.leaf("basis",_Signed(r,family="life",kind=KIND,
                ref=raw["observation_basis_ref"],expected_digest=raw["observation_basis_digest"]))
            if leaf is None:return
            if leaf.column.fields_seen!={f.name for f in fields(ArtifactPhaseObservationBasisV1)}:
                raise AuthorityUnavailable("Artifact basis changed its exact declared fields")
            basis=observation_basis_from_wire_v1(leaf.value)
            descriptor=artifact_observation_descriptor_from_metadata_v3(raw,namespace=w.namespace,prepared_digest=header.metadata[0])
            if (basis.namespace!=w.namespace or basis.original_ref!=raw["observation_basis_ref"]
                    or basis.digest!=raw["observation_basis_digest"] or basis.owner_guard!=p.owner
                    or basis.registration_operation_id!=leaf.producing_operation_id
                    or basis.ids["question"]!=raw["semantic_question_ref"]
                    or basis.request.selector.task.cycle_job_ref!=descriptor.cycle_ref.key.token
                    or basis.request.selector.task.c02_operation_id!=raw["c02_operation_id"]
                    or (raw["operation_id"],raw["job_id"],raw["call_id"])!=
                        (basis.ids["operation"],basis.ids["job"],basis.ids["call"])):
                raise AuthorityUnavailable("Artifact prepared original crossed its actual basis/task/ticket/Owner")
            declared={(row["ref"],row["revision"])for row in header.source_rows}
            if not {(head.key.token,head.revision)for head,_ in basis.source_heads}<=declared:
                raise AuthorityUnavailable("Artifact prepared metadata omitted its actual task/content Sources")
            for head,digest in basis.source_heads:
                _head(r,head.key.token,revision=head.revision,digest=digest)
            observer=require_current_artifact_phase_observer_v2(r.bundle)
            installed=header.column.frozen_metadata.value["installation"]
            workflow=r.bundle.model_workflows.artifact_observation_cognition
            if ((observer.asset_ref,observer.asset_digest,observer.workflow_digest,observer.observer_id,observer.observer_version)!=
                        (basis.observer_asset_ref,basis.observer_asset_digest,basis.workflow_digest,basis.observer_id,basis.observer_version)
                    or (basis.installation_id,basis.manifest_digest)!=(r.bundle.installation_policy.installation_id,
                        r.bundle.installation_policy.manifest_digest)
                    or workflow is None or canonical_digest(workflow)!=basis.workflow_digest
                    or raw["purpose"]!=workflow.purpose or workflow.work_kind!="d07.cognition"
                    or any(installed[name]!=getattr(workflow,name)for name in(
                        "provider_id","model_id","provider_config_ref","provider_config_digest","max_output_tokens"))):
                raise AuthorityUnavailable("Artifact metadata lost its protected independent observer/workflow pins")
            self.basis=basis;self.basis_leaf=leaf
            p.originals.append(("d11.life_"+KIND,basis.original_ref,leaf.metadata[0]))
            p.deadlines.append(basis.original_deadline_utc)
            self.phase="question";return
        basis=self.basis
        if self.phase=="question":
            leaf=self.leaf("question",_Signed(r,family="d07",kind="semantic_question",
                ref=raw["semantic_question_ref"],expected_digest=raw["semantic_question_digest"]))
            if leaf is None:return
            expected=plain_v1(basis.question);expected.pop("question")
            frozen=header.column.frozen_metadata.value["input"]
            if (leaf.column.fields_seen!={f.name for f in fields(ArtifactPhaseObservationQuestionV1)}
                    or leaf.value!=expected or frozen["question_key"]!=basis.question.question_key
                    or frozen["target_ref"]!=basis.question.target_ref.ref):
                raise AuthorityUnavailable("Artifact signed question changed its actual producer/frozen target")
            p.originals.append(("d07.semantic_question",raw["semantic_question_ref"],leaf.metadata[0]))
            self.phase="registration";return
        if self.phase=="registration":
            leaf=self.leaf("registration",_Adopted(r,basis.registration_operation_id,"artifact_observation_registration"))
            if leaf is None:return
            provenance=leaf.payload["provenance"]
            authority=decode_typed_production_value_v1(leaf.payload["authority"],type(header.authority))
            require_artifact_observation_source_derivation_v3(authority,header.authority)
            from ..domains.d07 import attention_ticket_key
            key=attention_ticket_key(w.namespace,basis.ids["ticket"])
            if (leaf.metadata[:2]!=("d07",OPERATION) or leaf.payload["request"]!=plain_v1(basis.request)
                    or provenance["artifact_observation_basis"]!=plain_v1(basis)
                    or canonical_digest({"schema":key.type_name,**provenance["artifact_observation_ticket"]})!=basis.ticket_digest
                    or tuple(v for v in leaf.receipt.write_versions if v.key==key)!=(GraphVersion(key,1),)
                    or not set(head for head,_ in basis.source_heads)<=set(leaf.receipt.read_versions)):
                raise AuthorityUnavailable("Artifact basis lacks its exact actual W01 birth and Source authority")
            self.registration=leaf;self.phase="ticket";return
        if self.phase=="ticket":
            from ..domains.d07 import attention_ticket_key
            key=attention_ticket_key(w.namespace,basis.ids["ticket"])
            leaf=self.leaf("ticket",_History(r,key.token,1,
                expected_operation=basis.registration_operation_id,expected_digest=basis.ticket_digest))
            if leaf is None:return
            ticket=leaf.value
            if (ticket["ticket_id"]!=basis.ids["ticket"]or ticket["question_key"]!=basis.question.question_key
                    or tuple(ticket["source_refs"])!=basis.source_refs or ticket["valid_until"]!=basis.original_deadline_utc
                    or ticket["category"]!="background"):
                raise AuthorityUnavailable("Artifact observation ticket birth changed its dedicated scope")
            self.phase="contract";return
        if self.phase=="contract":
            from .artifact_phase_postconditions_v1 import CONTRACT_KIND,ArtifactPhasePostconditionContractV1
            leaf=self.leaf("contract",_Signed(r,family="life",kind=CONTRACT_KIND,
                ref=basis.request.contract_ref,expected_digest=basis.contract_digest))
            if leaf is None:return
            contract=decode_typed_production_value_v1(leaf.value,ArtifactPhasePostconditionContractV1)
            from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2 as group
            conditions=[c for c in contract.conditions if(c.condition_id,c.phase_kind)==
                (basis.request.condition_id,basis.request.selector.phase_kind)]
            if (leaf.column.fields_seen!={f.name for f in fields(ArtifactPhasePostconditionContractV1)}
                    or plain_v1(contract)!=leaf.value or contract.original_ref!=basis.request.contract_ref
                    or contract.registration_operation_id!=leaf.producing_operation_id
                    or group(contract.selector)!=group(basis.request.selector)or contract.owner_guard!=basis.owner_guard
                    or (contract.policy_ref,contract.policy_digest)!=(basis.policy_ref,basis.policy_digest)
                    or len(conditions)!=1 or canonical_digest(conditions[0])!=basis.condition_digest
                    or (conditions[0].observer_id,conditions[0].observer_version,conditions[0].observer_asset_digest)!=
                        (basis.observer_id,basis.observer_version,basis.observer_asset_digest)
                    or basis.original_deadline_utc>contract.original_deadline_utc):
                raise AuthorityUnavailable("Artifact observer changed its preregistered same-task contract/condition")
            self.contract=contract;self.phase="policy";return
        if self.phase=="policy":
            from .artifact_phase_postconditions_v1 import (POLICY_KIND,ArtifactPhasePostconditionPolicyOriginalV1,
                ArtifactPhasePostconditionPolicyOriginalV2)
            leaf=self.leaf("policy",_Signed(r,family="life",kind=POLICY_KIND,
                ref=basis.policy_ref,expected_digest=basis.policy_digest))
            if leaf is None:return
            cls={"d11.artifact-phase-postcondition-policy.v1":ArtifactPhasePostconditionPolicyOriginalV1,
                "d11.artifact-phase-postcondition-policy.v2":ArtifactPhasePostconditionPolicyOriginalV2}.get(leaf.value.get("schema"))
            if cls is None or leaf.column.fields_seen!={f.name for f in fields(cls)}:
                raise AuthorityUnavailable("Artifact policy lost exact canonical declared fields")
            policy=decode_typed_production_value_v1(leaf.value,cls)
            if (plain_v1(policy)!=leaf.value or policy.original_ref!=basis.policy_ref
                    or policy.registration_operation_id!=leaf.producing_operation_id
                    or policy.request.task!=basis.request.selector.task or policy.owner_guard!=basis.owner_guard
                    or (policy.source_head,policy.source_value_digest)!=(basis.task_source_head,basis.task_source_digest)
                    or (policy.installation_id,policy.manifest_digest)!=(basis.installation_id,basis.manifest_digest)
                    or basis.original_deadline_utc>policy.original_deadline_utc):
                raise AuthorityUnavailable("Artifact policy changed its actual current task Source/Root/Owner")
            self.policy=policy;self.phase="goal";return
        if self.phase in {"goal","plan"}:
            kind=self.phase;head=getattr(self.policy,kind+"_head");digest=getattr(self.policy,kind+"_digest")
            leaf=self.leaf(kind,ArtifactObservationTaskHeadMetadataReadV3(r,head,digest,kind,host=self.host))
            if leaf is None:return
            if leaf.value["state"]!="active"or kind=="plan"and(
                    leaf.value["goal_ref"],leaf.value["goal_revision"])!=(
                        self.policy.goal_head.key.token,self.policy.goal_head.revision):
                raise AuthorityUnavailable("Artifact observation task Goal/Plan is no longer current and active")
            self.phase="plan"if kind=="goal"else"generation";return
        if self.phase=="generation":
            from .d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerifiedOriginalV2,artifact_draft_phase_verification_from_wire_v2
            selector=basis.request.selector
            leaf=self.leaf("generation",_Signed(r,family="life",kind="c4_phase_verified",
                ref=selector.prev_phase_original_ref,expected_digest=selector.prev_phase_original_digest))
            if leaf is None:return
            previous=artifact_draft_phase_verification_from_wire_v2(leaf.value,ArtifactDraftPhaseVerifiedOriginalV2)
            if (leaf.column.fields_seen!={f.name for f in fields(ArtifactDraftPhaseVerifiedOriginalV2)}
                    or previous.selector!=basis.content_selector or previous.content_selector!=basis.content_selector
                    or previous.producing_operation_id!=leaf.producing_operation_id
                    or (previous.source_head,previous.source_value_digest)!=(basis.content_source_head,basis.content_source_digest)
                    or (previous.readback_original_ref,previous.readback_original_digest)!=(basis.request.file_result_ref,basis.file_result_digest)
                    or previous.readback.content_digest!=basis.file_content_digest or previous.owner_guard!=basis.owner_guard):
                raise AuthorityUnavailable("Artifact observation lost its actual preceding completed generation/file")
            self.generation=previous;self.phase="adoption";return
        if self.phase=="adoption":
            from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV2,artifact_draft_content_from_wire_v2
            leaf=self.leaf("adoption",_Signed(r,family="life",kind="c4_phase_adopted",
                ref=self.generation.content_adoption_ref,expected_digest=self.generation.content_adoption_digest))
            if leaf is None:return
            adoption=artifact_draft_content_from_wire_v2(leaf.value,ArtifactDraftContentAdoptionV2)
            if (leaf.column.fields_seen!={f.name for f in fields(ArtifactDraftContentAdoptionV2)}
                    or adoption.selector!=basis.content_selector or adoption.adoption_operation_id!=leaf.producing_operation_id
                    or (adoption.content.content.ref,adoption.content.content.revision,adoption.content.content.digest)!=
                        (basis.content_source_head.key.token,basis.content_source_head.revision,basis.content_source_digest)
                    or adoption.content.content_digest!=basis.file_content_digest):
                raise AuthorityUnavailable("Artifact authored content changed its actual adopted Source identity")
            self.phase="file";return
        if self.phase=="file":
            leaf=self.leaf("file",_Signed(r,family="life",kind="adopted_life",
                ref=basis.request.file_result_ref,expected_digest=basis.file_result_digest))
            if leaf is None:return
            file=leaf.value
            declared={"schema","namespace","result_ref","producing_operation_id","prepared_digest","terminal",
                "source_refs","graph_receipt_json","write_commitments"}
            if (leaf.column.fields_seen not in(declared,declared|{"job_result_binding"})
                    or file["schema"]not in{"d11.adopted-life-original.v1","d11.adopted-life-original.v2","d11.adopted-life-original.v3","d11.adopted-life-original.v4"}
                    or file["namespace"]!=plain_v1(w.namespace)or file["result_ref"]!=basis.request.file_result_ref
                    or file["producing_operation_id"]!=leaf.producing_operation_id
                    or file["terminal"]["payload"]["status"]!="completed"
                    or file["terminal"]["payload"]["readback"]!=plain_v1(self.generation.readback)):
                raise AuthorityUnavailable("Artifact observation lost its real completed signed file original")
            self.phase="observer_job";return
        if self.phase=="observer_job":
            leaf=self.leaf("observer_job",_Job(r,header.job_id))
            if leaf is None:return
            job=leaf.value
            if ((job["operation_id"],job["activity_id"],job["effect_id"],job["work_kind"],job["budget_ref"])!=
                    (raw["operation_id"],raw["activity_id"],raw["effect_id"],"d07.concern",basis.parent_budget_lease_ref)
                    or job["cancel_epoch"]):
                raise AuthorityUnavailable("Artifact observer changed its actual original job/root lease")
            from ..authority_service.d07_authority_model_source_read_v3 import _d07_parent_utc_v3
            if self.host:
                if job!=r.stage_job.value:
                    raise AuthorityUnavailable("Artifact Host observer crossed its actual stage accounting job")
            elif (job["phase"],job["fence"],job["lease_holder"])!=("running",w.request.worker_fence,w.request.subject):
                raise AuthorityUnavailable("Artifact Core observer changed its actual acquired worker")
            p.deadlines.append(_d07_parent_utc_v3(job["deadline_utc"]))
            if job["phase"]=="running":
                if job["lease_expires_utc"]is None:
                    raise AuthorityUnavailable("Artifact running observer lost its actual worker expiry")
                p.deadlines.append(_d07_parent_utc_v3(job["lease_expires_utc"]))
            self.complete=True;return
        raise AuthorityUnavailable("Artifact observation metadata phase is unregistered")


class ArtifactObservationTaskHeadMetadataReadV3:
    def __init__(self,reader,head,digest,kind,*,host=False):
        from .d07_stage_content_scope_v3 import _HostMetadataReaderV3
        from ..authority_service.d07_authority_model_source_read_v3 import D07AuthorityModelSourceReadV3
        if type(reader)not in{_HostMetadataReaderV3,D07AuthorityModelSourceReadV3}or host!=(type(reader)is _HostMetadataReaderV3):
            raise AuthorityUnavailable("Artifact task head requires its exact originating metadata reader")
        self.host=host
        self.reader,self.work,self.head,self.expected_digest,self.kind=reader,reader.work,head,digest,kind
        self.complete=False;self.column=None
    def advance_v3(self,meter):
        if self.host:
            from .d07_stage_content_scope_v3 import _HostParentColumnV3 as _Column
        else:
            from ..authority_service.d07_authority_model_source_read_v3 import _D07ParentMetadataColumnV3 as _Column
        from ..domains.d08.execution import Goal
        from ..domains.d08.personal_plan_v1 import PersonalPlanV1
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.column is None:
            if self.host:
                from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
                actual=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                    "token=? AND bot=? AND persona=?",(self.head.key.token,*w.namespace.as_tuple))
            else:actual=w.heads.get(self.head.key.token)
            if (NamespaceId.from_key(self.head.key)!=w.namespace or actual is None or
                    actual[:2]!=(self.head.revision,True)or actual[2]is None):
                raise AuthorityUnavailable("Artifact current task metadata version/cell changed")
            self.column=_Column(r if self.host else w,table="graph_atoms",column="value",
                key_columns=("token",),key=(self.head.key.token,),mode="artifact_"+self.kind,
                cell_id=actual[2],erasure_owner_ref=self.head.key.token)
            return
        if not self.column.advance(meter):return
        expected={f.name for f in fields(Goal if self.kind=="goal"else PersonalPlanV1)}
        if self.column.fields_seen!=expected or self.column.canonical_semantic_digest!=self.expected_digest:
            raise AuthorityUnavailable("Artifact current task metadata canonical schema/commitment changed")
        self.value=self.column.require_v3(w);self.complete=True


def require_qualified_artifact_observation_basis_v3(reader,prepared):
    from .artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
    reader.require_body_qualification_v3()
    task=reader.metadata_qualified.require_for_v3(reader).task
    leaf=task.leaves.get(("artifact-observation-parent",prepared.job_id))
    if (type(prepared)is not D07ArtifactObservationPreparedV3 or type(leaf)is not ArtifactObservationParentMetadataReadV3
            or not leaf.complete or leaf.reader is not reader or leaf.basis.digest!=prepared.observation_basis_digest
            or leaf.basis.original_ref!=prepared.observation_basis_ref):
        raise AuthorityUnavailable("Artifact Source body requires its actual completed private parent metadata")
    return leaf.basis


def require_current_artifact_observation_descriptor_v3(db,*,namespace,descriptor,issuer):
    """Same-observation fixed originals; Source rights remain the dedicated Work's gate."""
    from .foreground_call_plan_v1 import NamedC3ParentageDescriptorV3
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..authority_service.d07_authority_model_source_read_v3 import require_current_d07_authority_namespace_recipe_v3
    from ..authority_service.model_reply_scope_observation_v3 import _active_observation_v3,model_reply_scope_point_v3
    from .artifact_phase_observation_v1 import KIND,OPERATION,observation_basis_from_wire_v1
    from .domain_background_read_v3 import background_json_loads_v3,background_verify_signature_v3
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    from ..runtime_contracts import canonical_serialize
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    if (type(descriptor)is not NamedC3ParentageDescriptorV3 or descriptor.kind!="artifact_observation_self"
            or descriptor.namespace!=namespace or descriptor.cancel_generation!=0):
        raise AuthorityUnavailable("dedicated current Artifact parentage descriptor required")
    work=_authority_attachment_owner_v3(db)
    reader=None if work is None else require_current_d07_authority_namespace_recipe_v3(work)
    if reader is not None:
        proof=reader.metadata_qualified.require_for_v3(reader)
        leaf=proof.task.leaves.get(("artifact-observation-parent",descriptor.job_id))
        if (type(leaf)is not ArtifactObservationParentMetadataReadV3 or not leaf.complete
                or leaf.reader is not reader or work.namespace!=namespace):
            raise AuthorityUnavailable("Artifact parentage lost its actual completed Source metadata Work")
        basis=leaf.basis
    else:
        observer=_active_observation_v3(db)
        def point(table,columns,key_columns,key):
            if observer is not None and not observer.legacy:
                return model_reply_scope_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
                    legacy_reader=lambda:None)
            from .natural_producer_qualification_v1 import _producer_original_point_v3
            names=",".join(columns);where=" AND ".join(name+"=?"for name in key_columns)
            return _producer_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
                legacy_reader=lambda:db.execute("SELECT "+names+" FROM "+table+" WHERE "+where,key).fetchone())
        row=point(TABLE,("payload_json","payload_digest","signature","producing_operation_id"),
            ("bot","persona","kind","original_ref"),(*namespace.as_tuple,KIND,descriptor.observation_basis_ref))
        if row is None or row[1]!=descriptor.observation_basis_digest:
            raise AuthorityUnavailable("Artifact parentage lost its exact signed fixed basis")
        if observer is not None and not observer.legacy:
            if not row[0].complete or row[0].sha256!=row[1]:
                raise AuthorityUnavailable("Artifact parentage basis has no actual canonical EOF")
        raw=background_json_loads_v3(row[0])
        background_verify_signature_v3(issuer._signer,SIGN_KIND,
            canonical_serialize((namespace,KIND,descriptor.observation_basis_ref,row[1])),row[2])
        basis=observation_basis_from_wire_v1(raw)
        if basis.registration_operation_id!=row[3]:
            raise AuthorityUnavailable("Artifact parentage changed its actual basis producer")
        from .domain_production_originals_v1 import _receipt,_receipt_wire
        original=point("graph_domain_production_originals_v1",
            ("domain","operation_kind","request_digest","original_digest","original_payload_json",
                "read_versions_json","bundle_digest","receipt_json","receipt_digest"),
            ("bot","persona","operation_id"),(*namespace.as_tuple,basis.registration_operation_id))
        if original is None:
            raise AuthorityUnavailable("Artifact parentage lost its actual basis W01 adoption")
        payload=background_json_loads_v3(original[4]);reads=background_json_loads_v3(original[5])
        receipt_raw=background_json_loads_v3(original[7]);receipt=_receipt(receipt_raw)
        if observer is not None and not observer.legacy:
            if any(not column.complete for column in(original[4],original[5],original[7]))or original[4].sha256!=original[3]:
                raise AuthorityUnavailable("Artifact parentage basis registration has no complete canonical EOF")
        if (canonical_digest(payload)!=original[3]or canonical_digest(receipt)!=original[8]
                or _receipt_wire(receipt)!=receipt_raw or receipt.status!="committed"
                or receipt.operation_id!=basis.registration_operation_id or receipt.operation_digest!=original[6]
                or payload["namespace"]!=plain_v1(namespace)
                or payload["identity"]["operation_id"]!=basis.registration_operation_id
                or len(reads)>1024 or any(NamespaceId.from_key(AtomKey.from_token(ref))!=namespace for ref,revision in reads)):
            raise AuthorityUnavailable("Artifact parentage changed its actual basis adoption receipt/read membership")
        committed=point("graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
            ("bot","persona","operation_id"),(*namespace.as_tuple,basis.registration_operation_id))
        if committed!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
            raise AuthorityUnavailable("Artifact parentage basis has no exact current W01 occurrence")
        adoption={"domain":original[0],"operation_kind":original[1],"payload":payload,"receipt":receipt}
        if ((adoption["domain"],adoption["operation_kind"])!=("d07",OPERATION)
                or adoption["payload"]["request"]!=plain_v1(basis.request)
                or adoption["payload"]["provenance"]["artifact_observation_basis"]!=raw):
            raise AuthorityUnavailable("Artifact parentage basis has no actual W01 registered producer")
        for head,_ in basis.source_heads:
            current=point("graph_atoms",("revision","valid"),("token",),(head.key.token,))
            if current!=(head.revision,1):
                raise AuthorityUnavailable("Artifact parentage original task/content Source version is no longer current")
    if (basis.namespace!=namespace or (basis.original_ref,basis.digest)!=(descriptor.observation_basis_ref,descriptor.observation_basis_digest)
            or (basis.ids["operation"],basis.ids["job"],basis.ids["call"],basis.ids["question"])!=
                (descriptor.operation_id,descriptor.job_id,descriptor.call_id,descriptor.semantic_question_ref)
            or basis.request.selector.task.cycle_job_ref!=descriptor.cycle_ref.key.token
            or basis.request.selector.task.c02_operation_id!=descriptor.c02_operation_id):
        raise AuthorityUnavailable("Artifact parentage crossed its exact basis/task/question/once identities")
    if reader is not None:
        from .d07_execution_v1 import read_d07_original_v1
        question=read_d07_original_v1(db,issuer,namespace,"semantic_question",descriptor.semantic_question_ref)
    else:
        from .d07_execution_v1 import TABLE as QUESTION_TABLE,SIGN_KIND as QUESTION_SIGN_KIND
        question_row=point(QUESTION_TABLE,("payload_json","payload_digest","signature"),
            ("bot","persona","kind","original_ref"),(*namespace.as_tuple,"semantic_question",descriptor.semantic_question_ref))
        if question_row is None or question_row[1]!=descriptor.semantic_question_digest:
            raise AuthorityUnavailable("Artifact parentage lost its exact signed semantic question")
        if observer is not None and not observer.legacy and(
                not question_row[0].complete or question_row[0].sha256!=question_row[1]):
            raise AuthorityUnavailable("Artifact parentage semantic question has no actual canonical EOF")
        semantic=background_json_loads_v3(question_row[0])
        if canonical_digest(semantic)!=question_row[1]:
            raise AuthorityUnavailable("Artifact parentage semantic question canonical commitment changed")
        issuer._signer.verify(QUESTION_SIGN_KIND,canonical_serialize((
            namespace,"semantic_question",descriptor.semantic_question_ref,question_row[1])),question_row[2])
        question=(semantic,question_row[1])
    if (question is None or question[1]!=descriptor.semantic_question_digest or question[0]!=plain_v1(basis.question)):
        raise AuthorityUnavailable("Artifact parentage lost its exact producer-issued signed semantic question")
    job=get_job(db,descriptor.cycle_ref.key.name)
    cycle=foreground_cycle_from_wire_v1(job.continuation)
    plan=cycle.call_plan
    if (type(plan)is not ForegroundCallPlanV3 or cycle.cancel_generation or job.cancel_epoch
            or job.phase in {"completed","failed","cancelled","draining","pending_confirmation"}
            or plan.phase_group is None
            or foreground_artifact_phase_group_identity_v2(plan.phase_group.selector)!=foreground_artifact_phase_group_identity_v2(basis.request.selector)
            or plan.phase_group.selector.phase_index<basis.request.selector.phase_index
            or job.budget_ref!=basis.parent_budget_lease_ref
            or cycle.source_ref!=basis.task_root_source_head.key.token
            or (plan.observer_policy_ref,plan.observer_policy_digest)!=(basis.observer_asset_ref,basis.observer_asset_digest)):
        raise AuthorityUnavailable("Artifact parentage changed its actual live V3 task/cycle/Root/policy")
    from .budget import get_budget_lease,require_budget_family_admissible
    from datetime import datetime,timezone
    lease=get_budget_lease(db,basis.parent_budget_lease_ref)
    require_budget_family_admissible(db,lease.lease_id)
    grant=issuer.current_budget_grant(db,lease.lease_id)
    now=work.controller.clock()if work is not None else datetime.now(timezone.utc).timestamp()
    if ((lease.bot_id,lease.persona_id)!=namespace.as_tuple or lease.state!="active"
            or canonical_digest(grant)!=basis.parent_grant_digest
            or not now<min(basis.original_deadline_utc,grant.valid_until_utc)):
        raise AuthorityUnavailable("Artifact parentage lost its original current grant/lease/deadline")
    return basis


def require_artifact_observation_source_derivation_v3(registration,execution):
    """Two actual signed operations retain one Self actor and their declared scopes."""
    from ..runtime_contracts import AuthorityContext
    from ..authority_service.current_foreground_activity_v1 import foreground_allowed_write_domains_v1
    from .artifact_phase_observation_v1 import OPERATION
    if type(registration)is not AuthorityContext or type(execution)is not AuthorityContext:
        raise AuthorityUnavailable("Artifact observation requires its two actual typed Source authorities")
    shared=("actor","issuer_domain","namespace","audience","provider_policy_ref","activation_generation")
    if (any(getattr(registration,name)!=getattr(execution,name)for name in shared)
            or registration.issuer_domain!="d07"or registration.purpose!="consolidation"or execution.purpose!="proposal"
            or registration.owner_scope!=tuple(sorted(foreground_allowed_write_domains_v1(OPERATION)))
            or execution.owner_scope!=tuple(sorted(foreground_allowed_write_domains_v1("serve_concern")))
            or registration.worker_fence is not None or execution.worker_fence is not None):
        raise AuthorityUnavailable("Artifact observation changed the declared Self/Owner Source derivation")
    return execution
