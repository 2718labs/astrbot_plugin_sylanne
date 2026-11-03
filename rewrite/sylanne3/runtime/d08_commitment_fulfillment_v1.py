"""Actual Source-qualified producers of immutable objective commitment terms."""
from dataclasses import replace
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..runtime_contracts import canonical_digest
from ..memory_types import access_key
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.commitment_fulfillment_v1 import (
    CommitmentFulfillmentTermsV1, terms_key_v1, semantic_scope_v1)
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1
from .persona_growth_birth_v1 import current_persona_birth_control_v1


def commitment_terms_birth_write_v1(db, *, frame, request, commitment, commitment_key):
    ns = frame.envelope.authority.namespace
    read = CurrentDomainReadV1(frame); read.check(db)
    control = current_persona_birth_control_v1(db, namespace=ns)
    family = read.source_family(db, request.source_refs)
    guards = {v.key:v for v in frame.envelope.version_guard.read_versions}
    versions = []
    for token in sorted(family):
        from ..graph_types import AtomKey
        source = AtomKey.from_token(token)
        for key in (source, access_key(*ns.as_tuple,source.owner.subject)):
            version = guards.get(key)
            if version is None or version.revision < 1:
                raise ValueError("terms birth requires every actual Source/Access version in the complete CAS")
            versions.append(version)
    key = terms_key_v1(ns, request.commitment_id)
    if read.head(db,key).revision != 0:
        raise ValueError("terms can only be created with their actual absent commitment birth")
    expected_deadline = key.token if request.deadline_utc is not None else None
    if (commitment.revision != 1 or commitment.deadline_ref != expected_deadline
            or commitment.semantic_scope != semantic_scope_v1(request.fulfillment_kind,request.counterparty_ref,request.deliverable_literal,request.deadline_utc)):
        raise ValueError("actual commitment birth changed the explicitly authorized immutable terms")
    terms = CommitmentFulfillmentTermsV1(ns,GraphVersion(commitment_key,1),canonical_digest(commitment.semantic_scope),
        request.fulfillment_kind,request.deliverable_literal,request.counterparty_ref,request.deadline_utc,request.source_refs,tuple(versions),
        frame.envelope.identity.operation_id,frame.owner_guard,control.activation_version,control.persona_head_version,
        control.graph_incarnation,control.activation_value['activation_generation'])
    return GraphWrite(key,plain_v1(terms),tuple(AtomKey.from_token(ref)for ref in request.source_refs))


def _current_terms_v1(db,frame,request):
    from ..domains.d08.execution import _decode
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d08.commitment_fulfillment_v1 import CommitmentFulfillmentTermsV1,terms_key_v1,semantic_scope_v1
    read=CurrentDomainReadV1(frame);read.check(db);ns=frame.envelope.authority.namespace
    current=read.head(db,request.current_commitment.ref,required=True)
    original=read.head(db,request.terms.ref,required=True)
    commitment=_decode("d08.commitment.v1",current.value)
    terms=decode_typed_production_value_v1(original.value,CommitmentFulfillmentTermsV1)
    if (current.revision!=request.current_commitment.version or current.revision!=commitment.revision
            or original.revision!=1 or request.terms.version!=1 or original.key!=terms_key_v1(ns,commitment.commitment_id)
            or terms.namespace!=ns or terms.commitment.key!=current.key or terms.counterparty_ref!=commitment.counterparty_ref
            or commitment.subject_ref!="persona:"+ns.persona_id
            or commitment.semantic_scope!=semantic_scope_v1(terms.fulfillment_kind,terms.counterparty_ref,terms.deliverable_literal,terms.deadline_utc)
            or canonical_digest(commitment.semantic_scope)!=terms.semantic_scope_digest
            or commitment.deadline_ref!=(original.key.token if terms.deadline_utc is not None else None)
            or commitment.establishment_kind not in {"unilateral","bilateral"}):
        raise ValueError("current commitment changed its exact immutable birth terms, subject, counterparty or deadline")
    read.original(original.key.token);read.original(current.key.token)
    return read,current,commitment,original,terms


def derive_commitment_terms_communication_input_v1(db,*,frame,request):
    from ..domains.d08.commitment_fulfillment_v1 import RegisterCurrentCommitmentTermsCommunicationInputRequestV1,acceptance_key_v1,CommitmentTermsAcceptanceV1
    from ..domains.d08.commitment_communication_v1 import CommitmentTermsCommunicationIntentV2,communication_scope_id_v1,commitment_communication_effect_id_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d08_commitment_communication_v1 import read_current_commitment_communication_route_v1
    if type(request) is not RegisterCurrentCommitmentTermsCommunicationInputRequestV1:
        raise TypeError("exact structured terms communication request required")
    read,current,commitment,original,terms=_current_terms_v1(db,frame,request)
    ns=frame.envelope.authority.namespace
    if (commitment.fulfillment_state!="pending" or commitment.establishment_state not in {"private_intention","offered","communicated","acknowledged"}
            or not frame.now_utc<request.valid_until_utc<=frame.envelope.deadline_utc
            or request.role=="performance" and terms.deadline_utc is not None and request.valid_until_utc>terms.deadline_utc):
        raise ValueError("terms communication requires an active pending commitment and original bounded deadline")
    control=current_persona_birth_control_v1(db,namespace=ns)
    if not {control.activation_version,control.persona_head_version}<=set(frame.envelope.version_guard.read_versions):
        raise ValueError("terms communication lost current persona control CAS")
    accepted=read.head(db,acceptance_key_v1(ns,commitment.commitment_id))
    acceptance_version=None;roots=set(terms.source_refs);roots.add(request.source_ref)
    if accepted.revision:
        if not accepted.valid or accepted.revision!=1:raise ValueError("immutable terms acceptance current head differs")
        value=decode_typed_production_value_v1(accepted.value,CommitmentTermsAcceptanceV1)
        if value.terms!=GraphVersion(original.key,1) or value.terms_digest!=terms.digest or value.actor_ref!=commitment.counterparty_ref:
            raise ValueError("terms acceptance belongs to different immutable terms or recipient")
        read.original(accepted.key.token);roots.add(value.inbound_source_ref)
        acceptance_version=GraphVersion(accepted.key,accepted.revision)
    if request.role=="performance" and commitment.establishment_kind=="bilateral":
        if acceptance_version is None or commitment.establishment_state!="acknowledged":
            raise ValueError("bilateral performance requires prior actual exact-terms acceptance")
    if not set(commitment.source_refs)<=roots or not 1<=len(roots)<=32:
        raise ValueError("V2 terms scope cannot discard current commitment Source dependencies")
    roots=tuple(sorted(roots))
    platform,audience,scene=read_current_commitment_communication_route_v1(db,frame=frame,read=read,
        commitment=commitment,source_ref=request.source_ref,roots=roots)
    scope_id=communication_scope_id_v1(ns,request)
    body=terms.render(request.role,effect_id=commitment_communication_effect_id_v1(scope_id))
    if len(body)>2048:raise ValueError("complete actual performance renderer exceeds the existing route bound")
    from .current_commitment_input_source_v3 import current_commitment_policy_binding_v3
    policy_refs,policy_audiences,policy_versions=current_commitment_policy_binding_v3(db,frame)
    return CommitmentTermsCommunicationIntentV2(ns,scope_id,GraphVersion(current.key,current.revision),
        canonical_digest(commitment),terms.digest,commitment.subject_ref,commitment.counterparty_ref,roots,platform,audience,scene,
        body,request.valid_until_utc,frame.now_utc,frame.envelope.identity.operation_id,
        frame.envelope.authority.actor,frame.owner_guard,control.graph_incarnation,control.activation_value["activation_generation"],control.head_id,
        fulfillment_terms=GraphVersion(original.key,1),fulfillment_terms_digest=terms.digest,role=request.role,
        route_source_ref=request.source_ref,terms_acceptance=acceptance_version,policy_source_refs=policy_refs,
        policy_audiences=policy_audiences,policy_read_versions=policy_versions)


_STAGES = {}


def register_actual_commitment_terms_stage_v1(db,*,frame,request,stage):
    from .current_method_learning_read_v3 import _method_active
    from .current_commitment_input_source_v3 import require_commitment_input_source_v3,require_commitment_input_write_v3
    from ..domains.d08.commitment_fulfillment_v1 import OPERATIONS
    reader=_method_active(db)
    if (reader is None or reader.operation_kind not in OPERATIONS or reader.request!=request
            or stage.operation_kind!=reader.operation_kind or stage.operation_id!=reader.operation_id
            or stage.namespace!=reader.namespace or frame.envelope.identity.operation_id!=reader.operation_id):
        raise ValueError("terms stage requires its actual typed same-Work Owner command")
    state=require_commitment_input_source_v3(reader)
    if state.permission is None:raise ValueError("terms compilation requires actual Source ALL before content")
    state.permission.require_for_v3(reader)
    if not reader.inputs_sealed:
        # The existing READ compiler materializes inputs before the actual WRITE.
        # That candidate is never registered as an authorized commit stage.
        return stage
    binding=require_commitment_input_write_v3(reader)
    if frame.envelope.authority.actor!=binding[2].actor:
        raise ValueError("terms stage changed its actual fresh Owner actor")
    record=(stage,reader,frame,request,binding,state.permission)
    _STAGES[id(stage)]=record
    if not hasattr(state,"terms_stage_ids"):state.terms_stage_ids=[]
    state.terms_stage_ids.append(id(stage))
    return stage


def require_actual_commitment_terms_stage_v1(stage,db,*,scope,owner_guard):
    from .current_method_learning_read_v3 import _method_active
    from .current_commitment_input_source_v3 import require_commitment_input_write_v3
    record=_STAGES.get(id(stage))
    if record is None or record[0] is not stage:
        raise ValueError("terms writes require the actual private SourceWork stage issuance")
    _,reader,frame,request,binding,permission=record
    if (_method_active(db)is not reader or db is not reader.db or scope is not binding[1]
            or owner_guard!=frame.owner_guard or request!=reader.request or reader.operation.closed
            or require_commitment_input_write_v3(reader)!=binding):
        raise ValueError("terms stage changed actual WRITE/Owner/retained Source Work")
    permission.require_for_v3(reader)
    return stage


def release_actual_commitment_terms_stages_v1(state):
    for identity in getattr(state,"terms_stage_ids",()):_STAGES.pop(identity,None)
    if hasattr(state,"terms_stage_ids"):state.terms_stage_ids.clear()


def reject_legacy_terms_ack_v1(db,*,frame,commitment_key):
    from ..domains.d08.commitment_fulfillment_v1 import terms_key_v1
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    key=terms_key_v1(frame.envelope.authority.namespace,commitment_key.name)
    with runtime_storage_quantum_v3(db)as meter:
        row=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid"),
            "token=? AND bot=? AND persona=?",(key.token,*frame.envelope.authority.namespace.as_tuple))
    guards={v.key:v.revision for v in frame.envelope.version_guard.read_versions}
    if guards.get(key)!=(0 if row is None else row[0]):
        raise ValueError("legacy ACK lost its exact terms absence/head CAS")
    if row is not None:
        raise ValueError("terms-bearing commitment requires its exact registered terms transition")


def _terms_outbound_v1(db,frame,read,request,terms,role):
    from .current_commitment_fulfillment_source_v3 import _active_terms_v3,_need_terms_v3
    from ..domains.d08.commitment_communication_v1 import CommitmentTermsCommunicationIntentV2
    from ..authority_service.observation_refinement_contract_v3 import observation_platform_observation_v3
    reader=_active_terms_v3(db);task=_need_terms_v3(reader,("lifecycle_originals",))
    recovered=task.result
    if recovered is None or task.named_original is None:
        raise MissingProductionOriginalV1("actual_named_terms_communication_original")
    scope=recovered.evidence.scope;use=recovered.evidence.promise_use
    if (type(scope)is not CommitmentTermsCommunicationIntentV2 or scope.role!=role or use.role!=role
            or scope.fulfillment_terms.key.token!=request.terms.ref or scope.fulfillment_terms.revision!=request.terms.version
            or scope.fulfillment_terms_digest!=terms.digest or scope.commitment.key.token!=request.current_commitment.ref
            or scope.target_ref!=terms.counterparty_ref or scope.approved_literal!=terms.render(role,effect_id=use.effect_id)
            or use.fulfillment_terms!=scope.fulfillment_terms or use.terms_digest!=terms.digest
            or use.payload_digest!=recovered.evidence.payload_digest):
        raise ValueError("terms outbound observation belongs to another terms, role, actual recipient or rendered payload")
    from .current_beta1_source_read_v3 import require_beta1_source_member_v3
    locator=_need_terms_v3(reader,("lifecycle_locator",))
    outbound_ref=locator.outbound[2]
    outbound=read.source_family(db,(outbound_ref,),purpose="context")[outbound_ref]
    if (set(outbound.parent_source_ids)!={AtomKey.from_token(ref).owner.subject for ref in scope.source_refs}
            or outbound.text!=scope.approved_literal):
        raise ValueError("actual authored outbound Source parents/text differ from its exact adopted V2 scope")
    for ref in scope.source_refs:
        require_beta1_source_member_v3(reader,ref,"context",(scope.conversation_ref,))
    platform=observation_platform_observation_v3(task.observed)
    if (platform.binding.origin.effect_id!=use.effect_id
            or platform.binding.origin.payload_digest.removeprefix("sha256:")!=use.payload_digest
            or platform.destination_ref!=scope.conversation_ref):
        raise ValueError("terms outbound observation changed its actual admitted effect/payload/destination")
    return task,recovered,scope,use,platform


def _inbound_terms_command_v1(db,frame,read,*,source_ref,commitment,terms,scope,verb,effect_id=None):
    from ..domains.d08.commitment_fulfillment_v1 import exact_terms_command_v1
    from ..domains.d03.prebatch_social import _private_route
    from .ingress_observation import read_committed_ingress_identity
    family=read.source_family(db,(source_ref,),purpose="context")
    record=family[source_ref]
    from .current_commitment_input_source_v3 import read_current_commitment_actor_entity_v3
    read_current_commitment_actor_entity_v3(db,frame,source_ref,expected_entity=commitment.counterparty_ref)
    route=_private_route(db,frame.envelope.authority.namespace,source_ref)
    if (route[0],route[1],route[4])!=(scope.platform_ref,scope.conversation_ref,scope.scene_ref):
        raise ValueError("terms command belongs to another actual private conversation")
    if not exact_terms_command_v1(record.text,verb=verb,commitment_id=commitment.commitment_id,terms_digest=terms.digest,effect_id=effect_id):
        raise MissingProductionOriginalV1("exact_actual_inbound_terms_"+verb.lower()+"_command")
    original=read_committed_ingress_identity(db,frame.envelope.authority.namespace,record.source_id)
    if original is None or original.learned_at!=record.recorded_at:
        raise MissingProductionOriginalV1("actual_trusted_inbound_terms_arrival")
    from ..graph_types import AtomKey
    ns=frame.envelope.authority.namespace;key=AtomKey.from_token(source_ref)
    versions=tuple(v for v in frame.envelope.version_guard.read_versions if v.key in {key,access_key(*ns.as_tuple,key.owner.subject)})
    if len(versions)!=2 or any(v.revision<1 for v in versions):
        raise ValueError("terms inbound command lacks its actual Source/Access CAS")
    return versions,float(original.learned_at)


def _terms_stage_v1(db,frame,request,*,operation,writes,provenance,receiver_events):
    from ..domains.d01.production_operations_v1 import stage_result_v1
    from ..domains.d08.execution import GoalExecutionProvider
    from ..domains.d08.production_operations_v1 import verify_d08_production_stage_v1
    provider=GoalExecutionProvider()
    stage=stage_result_v1(frame,"d08",operation,request,writes=writes,provenance=provenance,
        receiver_events=receiver_events,proposal_schema="d08.proposal.v1",proposal_hash=provider.descriptor.request_schema_hash)
    verify_d08_production_stage_v1(stage)
    return register_actual_commitment_terms_stage_v1(db,frame=frame,request=request,stage=stage)


def stage_acknowledge_current_commitment_terms_v1(db,*,frame,request,installed_readers):
    from ..domains.d08.commitment_fulfillment_v1 import AcknowledgeCurrentCommitmentTermsRequestV1,CommitmentTermsAcceptanceV1,acceptance_key_v1,ACK_OPERATION
    if type(request)is not AcknowledgeCurrentCommitmentTermsRequestV1:raise TypeError("exact terms acceptance request required")
    read,current,commitment,terms_atom,terms=_current_terms_v1(db,frame,request)
    if commitment.establishment_kind!="bilateral" or commitment.establishment_state not in {"private_intention","offered","communicated"} or commitment.fulfillment_state!="pending":
        raise ValueError("terms acceptance requires a pending bilateral offer")
    task,recovered,scope,use,platform=_terms_outbound_v1(db,frame,read,request,terms,"offer")
    if platform.outcome not in {"accepted","delivered","read"}:
        raise MissingProductionOriginalV1("actual_accepted_terms_offer_outbound")
    versions,_=_inbound_terms_command_v1(db,frame,read,source_ref=request.inbound_source_ref,
        commitment=commitment,terms=terms,scope=scope,verb="ACCEPT")
    key=acceptance_key_v1(frame.envelope.authority.namespace,commitment.commitment_id)
    if read.head(db,key).revision!=0:raise ValueError("terms acceptance requires its absent immutable target")
    after=replace(commitment,revision=commitment.revision+1,establishment_state="acknowledged",
        communicated_refs=tuple(dict.fromkeys((*commitment.communicated_refs,request.outbound_offer_receipt_ref))),
        acknowledged_refs=tuple(dict.fromkeys((*commitment.acknowledged_refs,request.inbound_source_ref))),
        parent_revision_ref=f"{commitment.commitment_id}@{commitment.revision}",
        source_refs=tuple(dict.fromkeys((*commitment.source_refs,request.inbound_source_ref))))
    accepted=CommitmentTermsAcceptanceV1(frame.envelope.authority.namespace,GraphVersion(terms_atom.key,1),terms.digest,
        GraphVersion(current.key,current.revision),GraphVersion(current.key,current.revision+1),request.inbound_source_ref,versions,
        commitment.counterparty_ref,scope.conversation_ref,request.outbound_offer_receipt_ref,use.effect_id,use.payload_digest,
        frame.envelope.identity.operation_id)
    source_dependencies=tuple(AtomKey.from_token(ref)for ref in frame.envelope.source_qualification.source_refs)
    writes=(GraphWrite(current.key,plain_v1(after),(terms_atom.key,*(v.key for v in versions))),
        GraphWrite(key,plain_v1(accepted),source_dependencies))
    return _terms_stage_v1(db,frame,request,operation=ACK_OPERATION,writes=writes,
        provenance={"commitment_before":commitment,"commitment_after":after,"terms":terms,"acceptance":accepted,
            "actual_observation_digest":canonical_digest(task.observed)},
        receiver_events=(("d08","commitment_terms_accepted_requires_current_performance_qualification"),))


def stage_settle_current_commitment_fulfillment_v1(db,*,frame,request,installed_readers):
    from ..domains.d08.commitment_fulfillment_v1 import SettleCurrentCommitmentFulfillmentRequestV1,CommitmentFulfillmentEvidenceV1,evidence_key_v1,acceptance_key_v1,CommitmentTermsAcceptanceV1,SETTLE_OPERATION
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_production_operations_v1 import waiting_stage_v1
    if type(request)is not SettleCurrentCommitmentFulfillmentRequestV1:raise TypeError("exact objective commitment fulfillment request required")
    read,current,commitment,terms_atom,terms=_current_terms_v1(db,frame,request)
    if commitment.fulfillment_state=="fulfilled":
        return waiting_stage_v1(frame,"d08",SETTLE_OPERATION,request,MissingProductionOriginalV1("commitment_already_settled"))
    if commitment.fulfillment_state!="pending" or commitment.establishment_state not in {"private_intention","offered","communicated","acknowledged"}:
        raise ValueError("cancelled/withdrawn/changed commitment cannot be fulfilled")
    task,recovered,scope,use,platform=_terms_outbound_v1(db,frame,read,request,terms,"performance")
    if platform.outcome!="delivered":
        return waiting_stage_v1(frame,"d08",SETTLE_OPERATION,request,MissingProductionOriginalV1("actual_delivered_performance_observation"))
    accepted_version=None
    if commitment.establishment_kind=="bilateral":
        atom=read.head(db,acceptance_key_v1(frame.envelope.authority.namespace,commitment.commitment_id),required=True)
        accepted=decode_typed_production_value_v1(atom.value,CommitmentTermsAcceptanceV1)
        accepted_version=GraphVersion(atom.key,atom.revision)
        if (commitment.establishment_state!="acknowledged" or accepted.terms!=GraphVersion(terms_atom.key,1)
                or accepted.terms_digest!=terms.digest or scope.terms_acceptance!=accepted_version
                or accepted_version not in recovered.evidence.current_read_versions):
            raise ValueError("bilateral performance did not causally read the actual exact-terms acceptance")
    versions=();actor=None
    latest=task.value("adoption").get("trusted_latest_utc")
    if latest is not None:
        import math
        clock_digest=task.value("adoption").get("trusted_clock_digest")
        if (type(latest)not in (int,float)or not math.isfinite(latest)or latest<0
                or type(clock_digest)is not str or len(clock_digest)!=64 or any(c not in "0123456789abcdef"for c in clock_digest)):
            raise ValueError("delivery latest bound lacks its actual trusted adoption clock commitment")
    predicate=terms.predicate
    if predicate.observation_provider!="d08.commitment_fulfillment.v1"or predicate.kind not in {"communicated","recipient_acknowledged"}:
        raise ValueError("unregistered objective commitment evidence provider")
    if predicate.kind=="recipient_acknowledged":
        if request.recipient_ack_source_ref is None:
            return waiting_stage_v1(frame,"d08",SETTLE_OPERATION,request,MissingProductionOriginalV1("actual_exact_recipient_received_command"))
        versions,latest=_inbound_terms_command_v1(db,frame,read,source_ref=request.recipient_ack_source_ref,
            commitment=commitment,terms=terms,scope=scope,verb="RECEIVED",effect_id=use.effect_id)
        actor=commitment.counterparty_ref
    if latest is None:
        # A deadline-free delivered fact needs no historical punctuality claim.
        if terms.deadline_utc is not None:
            return waiting_stage_v1(frame,"d08",SETTLE_OPERATION,request,MissingProductionOriginalV1("actual_trusted_delivery_latest_bound"))
        latest=frame.now_utc
    if terms.deadline_utc is not None and latest>terms.deadline_utc:
        return waiting_stage_v1(frame,"d08",SETTLE_OPERATION,request,MissingProductionOriginalV1("performance_time_interval_not_proven_within_original_deadline"))
    key=evidence_key_v1(frame.envelope.authority.namespace,commitment.commitment_id)
    if read.head(db,key).revision!=0:raise ValueError("fulfillment requires its absent immutable evidence target")
    after=replace(commitment,revision=commitment.revision+1,fulfillment_state="fulfilled",
        establishment_state="acknowledged"if commitment.establishment_kind=="bilateral"else"communicated",
        communicated_refs=tuple(dict.fromkeys((*commitment.communicated_refs,request.performance_outbound_receipt_ref))),
        parent_revision_ref=f"{commitment.commitment_id}@{commitment.revision}",
        acknowledged_refs=tuple(dict.fromkeys((*commitment.acknowledged_refs,*(()if request.recipient_ack_source_ref is None else(request.recipient_ack_source_ref,))))),
        source_refs=tuple(dict.fromkeys((*commitment.source_refs,*(()if request.recipient_ack_source_ref is None else(request.recipient_ack_source_ref,))))))
    actions=tuple(GraphVersion(AtomKey.from_token(ref),revision)
        for ref,revision in recovered.write_versions if AtomKey.from_token(ref).type_name=="d08.action_intent.v1")
    if len(actions)!=1:raise ValueError("performance requires its unique actual action origin")
    evidence=CommitmentFulfillmentEvidenceV1(frame.envelope.authority.namespace,GraphVersion(terms_atom.key,1),terms.digest,
        GraphVersion(current.key,current.revision),GraphVersion(current.key,current.revision+1),request.performance_outbound_receipt_ref,
        canonical_digest(task.observed),platform.binding.admission_graph_version,platform.binding.admission_receipt_digest.removeprefix("sha256:"),
        actions[0],use.effect_id,use.payload_digest,accepted_version,request.recipient_ack_source_ref,versions,actor,float(latest),frame.envelope.identity.operation_id)
    dependencies=(current.key,terms_atom.key,actions[0].key,*(()if accepted_version is None else(accepted_version.key,)),*(v.key for v in versions))
    source_dependencies=tuple(AtomKey.from_token(ref)for ref in frame.envelope.source_qualification.source_refs)
    writes=(GraphWrite(current.key,plain_v1(after),tuple(k for k in dependencies if k!=current.key)),
        GraphWrite(key,plain_v1(evidence),source_dependencies))
    return _terms_stage_v1(db,frame,request,operation=SETTLE_OPERATION,writes=writes,
        provenance={"commitment_before":commitment,"commitment_after":after,"terms":terms,"fulfillment_evidence":evidence,
            "actual_observation_digest":canonical_digest(task.observed)},
        receiver_events=(("d08","commitment_fulfilled_requires_current_plan_reevaluation"),))


def committed_commitment_fulfillment_view_v1(staged,receipt):
    """Actual same-commit metadata only; no deliverable or rendered literal."""
    from .domain_production_inputs_v1 import StagedDomainInputV1
    from .domain_production_contracts_v1 import StagedDomainOperationV1
    from ..domains.d08.commitment_fulfillment_v1 import CREATE_OPERATION,ACK_OPERATION,SETTLE_OPERATION,TERMS_TYPE,ACCEPTANCE_TYPE,EVIDENCE_TYPE,CommitmentFulfillmentTermsV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    stage=staged.stage if type(staged)is StagedDomainInputV1 else staged
    if type(stage)is not StagedDomainOperationV1 or stage.operation_kind not in {CREATE_OPERATION,ACK_OPERATION,SETTLE_OPERATION}:return None
    if receipt.status!="committed" or receipt.operation_id!=stage.operation_id:return None
    writes=tuple(w for proposal in stage.proposals for w in proposal.typed_writes)
    commitments=tuple(w for w in writes if w.key.type_name=="d08.commitment.v1")
    if not commitments:return None
    if len(commitments)!=1:raise ValueError("terms view requires its actual sole commitment transition")
    write=commitments[0];version=next((v for v in receipt.write_versions if v.key==write.key),None)
    if version is None:raise ValueError("terms view is not in its actual same-commit receipt")
    companions=tuple(w for w in writes if w.key.type_name in {TERMS_TYPE,ACCEPTANCE_TYPE,EVIDENCE_TYPE})
    if len(companions)!=1:raise ValueError("terms view lost its actual immutable companion write")
    companion=companions[0]
    if GraphVersion(companion.key,1)not in receipt.write_versions:
        raise ValueError("terms view companion is absent from its actual same-commit receipt")
    view={"schema":"d08.commitment-transition-view.v1","operation_kind":stage.operation_kind,"operation_id":stage.operation_id,
        "commitment_ref":write.key.token,"commitment_revision":version.revision,
        "establishment_state":write.value["establishment_state"],"fulfillment_state":write.value["fulfillment_state"],
        "evidence_ref":companion.key.token,"evidence_revision":1}
    if companion.key.type_name==TERMS_TYPE:
        terms=decode_typed_production_value_v1(companion.value,CommitmentFulfillmentTermsV1)
        view.update(terms_ref=companion.key.token,terms_revision=1,terms_digest=terms.digest,
            fulfillment_kind=terms.fulfillment_kind,counterparty_ref=terms.counterparty_ref,deadline_utc=terms.deadline_utc)
    else:
        view.update(terms_ref=companion.value["terms"]["key"],terms_revision=companion.value["terms"]["revision"],terms_digest=companion.value["terms_digest"])
    return view
