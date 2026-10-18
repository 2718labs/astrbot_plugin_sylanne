"""Deterministic D08/D09 consumption of a formally committed completion Source."""
from dataclasses import dataclass,asdict,replace
from datetime import datetime,timezone
import json
import math

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,GraphWrite,Owner,GraphSnapshot
from ..memory_types import source_key,access_key,SourceRecord
from ..runtime_contracts import (NamespaceId,OperationIdentity,CommandEnvelope,CheckReceipt,DomainProposal,
    DomainBundle,DependencySet,VersionedRef,canonical_digest,canonical_serialize)
from ..domains.d08 import (ActionIntent,ActionSchema,CommunicationGrantRequest,CommunicationSegmentSpec,
    CommunicationIntentGrant,Goal,GoalPredicate,RequiredCheckSpec,RequiredCheckRegistry,GoalExecutionProvider)
from ..domains.d08.communication_route_binding import verify_route_bound_grant_v2
from ..domains.d09 import (ClaimKind,ExpressionClaim,ClaimUse,SegmentCandidate,D09ExpressionProvider,segment_payload_digest)
from .artifact_completion_receipt_v1 import (ArtifactCompletionReceiptOriginalV1,receipt_ids_v1,
    read_current_artifact_completion_receipt_v1,read_current_artifact_completion_receipt_by_operation_v1)
from .post_c02_reply_action_v2 import CurrentReplyCheckVersionsV2,CurrentReplyCheckVersionV2
from .reply_model_job import CurrentReplyRouteManifestV2
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2,read_current_reply_entity_route_binding_v2
from .issuers import BudgetLeaseGrant,ResourceQuote
from .jobs import PersistentJob
from .dispatch_candidate import dispatch_segment_payload_ref
from .d11_types import (D11_PROPOSAL_SCHEMA,D11_PROPOSAL_SCHEMA_HASH,RuntimeOutboxValue,
    job_graph_write,outbox_graph_write,runtime_job_key,runtime_outbox_key)
from .domain_production_contracts_v1 import ProductionOwnerGuardV1

CHECKS=(("role_binding","d03.role_binding"),("boundary","d05.boundary"),
    ("source_grant","d06.source_grant"),("commitment_conflict","d08.commitment_conflict"),
    ("dispatch_budget","d11.dispatch_budget"))


@dataclass(frozen=True,slots=True)
class ArtifactReceiptExpressionV1:
    receipt_digest:str
    claims:tuple
    segments:tuple
    payload_digest:str
    provenance_digest:str


@dataclass(frozen=True,slots=True)
class ArtifactReceiptActionCandidateV1:
    status:str
    missing:tuple
    goal:Goal
    intent:ActionIntent
    schema:ActionSchema
    communication:CommunicationGrantRequest
    required_input_versions:tuple
    graph_reads:tuple
    expression:ArtifactReceiptExpressionV1


@dataclass(frozen=True,slots=True)
class ArtifactReceiptDispatchBundleCandidateV1:
    status:str
    bundle:DomainBundle
    grant:CommunicationIntentGrant
    batch:dict
    job:PersistentJob
    job_ref:str
    outbox_ref:str


def artifact_receipt_dispatch_runtime_refs_v1(receipt):
    if type(receipt)is not ArtifactCompletionReceiptOriginalV1:
        raise TypeError("actual typed completion receipt required")
    ids=receipt_ids_v1(receipt.selector)
    marker=canonical_digest(("d11.artifact-receipt-dispatch.v1",receipt.message_operation_id))[:48]
    activity=ids["activity"]
    return (runtime_job_key(*receipt.namespace.as_tuple,activity,"artifact-receipt-dispatch:"+marker).token,
        runtime_outbox_key(*receipt.namespace.as_tuple,activity,"artifact-receipt-outbox:"+marker).token,
        "artifact-receipt-once:"+marker)


def artifact_receipt_action_ids_v1(receipt):
    ids=receipt_ids_v1(receipt.selector)
    marker=canonical_digest(("d08.artifact-receipt.v1",ids["operation"],receipt.digest))[:48]
    return tuple(prefix+marker for prefix in("goal:artifact-receipt:","action:artifact-receipt:","schema:artifact-receipt:"))


def artifact_receipt_expression_v1(receipt,audiences):
    if (type(receipt)is not ArtifactCompletionReceiptOriginalV1 or type(audiences)is not tuple
            or not audiences or len(set(audiences))!=len(audiences)):
        raise TypeError("actual completion receipt and exact audiences required")
    ids=receipt_ids_v1(receipt.selector)
    claim=ExpressionClaim(receipt.receipt_id,receipt.text,ClaimKind.REPORTED_CLAIM,
        (receipt.source_ref,),audiences,("expression",),receipt.source_ref)
    use=ClaimUse(claim.claim_id,0,len(receipt.text),ClaimKind.REPORTED_CLAIM)
    segment=SegmentCandidate(ids["batch"]+":segment",receipt.effect_id,receipt.text,(use,),
        ("artifact_completion_receipt",),(),0.)
    payload=segment_payload_digest(segment.body,segment.media_refs,segment.claim_uses)
    return ArtifactReceiptExpressionV1(receipt.digest,(claim,),(segment,),payload,
        canonical_digest(("artifact-completion-expression.v1",receipt.digest,audiences,payload)))


def prepare_artifact_receipt_action_candidate_v1(*,receipt,envelope,route,route_binding,snapshot,query,
        check_inputs,quote,budget_grant,anchor,now_utc,provisional=False):
    from ..runtime_contracts import QueryEpoch
    if (type(receipt)is not ArtifactCompletionReceiptOriginalV1 or type(envelope)is not CommandEnvelope
            or type(route)is not CurrentReplyRouteManifestV2 or type(route_binding)is not CurrentReplyEntityRouteBindingV2
            or type(snapshot)is not GraphSnapshot or type(query)is not QueryEpoch
            or type(check_inputs)is not CurrentReplyCheckVersionsV2 or type(quote)is not ResourceQuote
            or type(budget_grant)is not BudgetLeaseGrant or type(provisional)is not bool):
        raise TypeError("Artifact receipt assembly requires actual typed staged inputs")
    ns=receipt.namespace;ids=receipt_ids_v1(receipt.selector);identity=envelope.identity
    if ((identity.operation_id,identity.effect_id,identity.activity_id)!=(ids["operation"],ids["effect"],ids["activity"])
            or envelope.authority.namespace!=ns or envelope.authority.purpose!="expression"
            or envelope.authority.audience!=(route.conversation_ref,)
            or envelope.source_qualification.source_refs!=(receipt.source_ref,)
            or receipt.source_ref not in envelope.input_refs or route.source_ref==receipt.source_ref
            or (route.namespace,route.c02_operation_id)!=(ns,receipt.selector.task.c02_operation_id)
            or route.c02_operation_id not in envelope.causation
            or (route_binding.namespace,route_binding.c02_operation_id,route_binding.source_ref,
                route_binding.platform_ref,route_binding.conversation_ref,route_binding.scene_ref)!=
                    (ns,route.c02_operation_id,route.source_ref,route.platform_ref,route.conversation_ref,route.scene_ref)
            or not now_utc<envelope.deadline_utc<=receipt.original_deadline_utc
            or query.namespace!=ns or query.scope_ref!="all"or len(snapshot.epochs)!=1
            or snapshot.epochs[0].revision!=(query.revision-1 if provisional else query.revision)
            or route.route_digest!=canonical_digest({"account_ref":route.platform_ref,
                "destination_ref":route.conversation_ref,"scene_ref":route.scene_ref})):
        raise AuthorityUnavailable("Artifact receipt changed its original task/ingress route or disclosed completion Source")
    expression=artifact_receipt_expression_v1(receipt,envelope.authority.audience)
    goal_id,action_id,schema_id=artifact_receipt_action_ids_v1(receipt)
    if ((check_inputs.namespace,check_inputs.query,check_inputs.source_ref,check_inputs.quote_id,
            check_inputs.quote_version,check_inputs.grant_id,check_inputs.grant_version)!=
            (ns,query,receipt.source_ref,quote.quote_id,quote.version,budget_grant.grant_id,budget_grant.version)
            or len(check_inputs.sets)!=len(CHECKS)
            or any(type(item)is not CurrentReplyCheckVersionV2 for item in check_inputs.sets)
            or len(check_inputs.reservation_digest)!=64):
        raise AuthorityUnavailable("Artifact receipt lost its actual five staged check-version sets")
    sets={item.check_kind:item for item in check_inputs.sets}
    if set(sets)!={kind for kind,_ in CHECKS}:raise AuthorityUnavailable("Artifact receipt actual check kinds differ")
    graph={atom.key.token:atom for atom in snapshot.atoms};specs=[];reads={}
    for kind,provider in CHECKS:
        item=sets[kind];versions={v.ref:v.version for v in item.versions}
        if (len(versions)!=len(item.versions)or item.criteria_ref not in versions
                or any(type(v)is not VersionedRef for v in item.versions)):
            raise AuthorityUnavailable("Artifact receipt check set lost its exact current versions")
        for version in item.versions:
            if version.ref in graph:
                atom=graph[version.ref]
                if not atom.valid or atom.revision!=version.version:
                    raise AuthorityUnavailable("Artifact receipt check references a stale Graph member")
                reads[atom.key]=GraphVersion(atom.key,atom.revision)
        if kind=="source_grant":
            required=(receipt.source_ref,access_key(*ns.as_tuple,AtomKey.from_token(receipt.source_ref).owner.subject).token,
                *(head.key.token for head,_ in receipt.parent_source_heads))
            if any(versions.get(ref,0)<1 for ref in required):
                raise AuthorityUnavailable("Artifact receipt SourceGrant omitted its actual derived Source and parents")
        if kind=="commitment_conflict"and versions!={"d08.commitment_conflict.criteria.v1":1,goal_id:1,
                "commitments-query:persona:"+ns.persona_id:query.revision,
                "execution-epoch:"+action_id:anchor.execution_seq,"cancellation-epoch:"+action_id:1}:
            raise AuthorityUnavailable("Artifact receipt commitment check lost its fixed current action closure")
        if kind=="dispatch_budget"and(
                item.criteria_ref!="d02.resource_quote:"+quote.quote_id
                or versions.get(item.criteria_ref)!=quote.version
                or versions.get("d11.budget.grant:"+budget_grant.lease_id)!=budget_grant.version
                or versions.get("d11.budget.reservation:"+budget_grant.lease_id+":"+ids["operation"]+":"+check_inputs.reservation_digest)!=1
                or "d11.budget.lease:"+budget_grant.lease_id not in versions):
            raise AuthorityUnavailable("Artifact receipt budget check lacks its actual signed one-message reservation")
        specs.append(RequiredCheckSpec(kind,provider,"persona:"+ns.persona_id,action_id,"expression",
            item.criteria_ref,item.versions))
    if ((quote.bot_id,quote.persona_id,quote.activity_id,quote.operation_id,quote.effect_id,quote.parent_budget_lease_ref)!=
            (*ns.as_tuple,ids["activity"],ids["operation"],ids["effect"],budget_grant.lease_id)
            or budget_grant.allowed_work_kinds!=("message",)or quote.work_kind!="message"
            or envelope.parent_budget_lease_ref!=budget_grant.lease_id
            or any(v>budget_grant.max_ceiling.get(k,0)for k,v in quote.ceiling.items())):
        raise AuthorityUnavailable("Artifact completion receipt cannot borrow another message/root budget")
    predicate=GoalPredicate("communicated","d11.delivery",(),float(receipt.recorded_at_utc),float(envelope.deadline_utc))
    goal=Goal(goal_id,1,"active",predicate,(receipt.source_ref,),(),None,(),())
    parameters=canonical_digest({"schema":"d08.artifact-receipt-action.v1","receipt":receipt.digest,
        "completion":receipt.completion_digest,"completion_receipt":receipt.completion_receipt_digest,
        "route_digest":route.route_digest,"route_binding_digest":route_binding.binding_digest,
        "quote":canonical_digest(quote),"grant":canonical_digest(budget_grant),"anchor":anchor.proof,
        "payload_digest":expression.payload_digest})
    intent=ActionIntent(action_id,1,goal_id,(),route_binding.target_entity_ref,"message","expression","limited",
        parameters,identity,schema_id,tuple(specs),predicate,(receipt.effect_id,),None,(receipt.source_ref,))
    schema=ActionSchema(schema_id,"message",False,tuple(specs))
    segment=expression.segments[0]
    communication=CommunicationGrantRequest("communication:"+canonical_digest((receipt.receipt_id,action_id)),
        "contact:"+canonical_digest({"route":route.route_digest}),1,(route.conversation_ref,),segment.covered_slots,
        (ClaimKind.REPORTED_CLAIM.value,),(),(CommunicationSegmentSpec(segment.segment_id,segment.effect_id,0,
            expression.payload_digest,len(segment.body),(),None),),0)
    return ArtifactReceiptActionCandidateV1("provisional"if provisional else"candidate",(),goal,intent,schema,communication,
        tuple(v for item in check_inputs.sets for v in item.versions),
        tuple(sorted(reads.values(),key=lambda v:v.key.token)),expression)


def prepare_artifact_receipt_dispatch_bundle_candidate_v1(
    *, envelope: CommandEnvelope,
    action: ArtifactReceiptActionCandidateV1,
    staged_d08: DomainProposal,
    checks: tuple[CheckReceipt, ...],
    receipt: ArtifactCompletionReceiptOriginalV1,
    route: CurrentReplyRouteManifestV2,
    route_binding: CurrentReplyEntityRouteBindingV2,
    pre_frozen_grant: CommunicationIntentGrant,
    quote: ResourceQuote,
    budget_grant: BudgetLeaseGrant,
    pre_reserved_job: PersistentJob,
    now_utc: float,
    conversation_epoch: int,
) -> ArtifactReceiptDispatchBundleCandidateV1:
    """Assemble exact candidate writes from staged action and five receipts.

    ``checks`` must be supplied by W01 from real staged E+1 provider reads.
    This function cannot establish that provenance and intentionally exposes no
    send or admission capability.
    """
    expression=action.expression
    if (type(receipt)is not ArtifactCompletionReceiptOriginalV1 or type(envelope) is not CommandEnvelope
            or type(action) is not ArtifactReceiptActionCandidateV1
            or type(staged_d08) is not DomainProposal
            or type(checks) is not tuple
            or any(type(check) is not CheckReceipt for check in checks)
            or type(expression) is not ArtifactReceiptExpressionV1
            or type(route) is not CurrentReplyRouteManifestV2
            or type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or type(pre_frozen_grant) is not CommunicationIntentGrant
            or type(quote) is not ResourceQuote
            or type(budget_grant) is not BudgetLeaseGrant
            or type(pre_reserved_job) is not PersistentJob
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or type(conversation_epoch) is not int or conversation_epoch < 0):
        raise TypeError("typed staged reply inputs required")
    namespace, identity = envelope.authority.namespace, envelope.identity
    if (action.status != "candidate" or action.missing
            or action.goal is None or action.intent is None
            or action.schema is None or action.communication is None
            or staged_d08.domain != "d08" or staged_d08.envelope != envelope
            or identity.effect_id is None or not now_utc < envelope.deadline_utc
            or route.namespace != namespace
            or route.c02_operation_id not in envelope.causation
            or envelope.source_qualification.source_refs != (receipt.source_ref,)
            or receipt.source_ref not in envelope.input_refs
            or route.source_ref==receipt.source_ref
            or expression.receipt_digest!=receipt.digest
            or (identity.operation_id,identity.effect_id,identity.activity_id)!=(receipt.message_operation_id,receipt.effect_id,receipt_ids_v1(receipt.selector)["activity"])
            or envelope.authority.audience != (route.conversation_ref,)
            or envelope.authority.purpose != "expression"
            or route.route_digest != canonical_digest({
                "account_ref": route.platform_ref,
                "destination_ref": route.conversation_ref,
                "scene_ref": route.scene_ref,
            })
            or action.intent.identity != identity
            or action.intent.goal_ref != action.goal.goal_id
            or action.intent.schema_id != action.schema.schema_id
            or action.intent.source_refs != (receipt.source_ref,)
            or (route_binding.namespace, route_binding.c02_operation_id,
                route_binding.source_ref, route_binding.platform_ref,
                route_binding.conversation_ref, route_binding.scene_ref) != (
                    namespace, route.c02_operation_id, route.source_ref,
                    route.platform_ref, route.conversation_ref, route.scene_ref)
            or action.intent.target_ref != route_binding.target_entity_ref
            or not action.intent.target_ref.startswith("entity:account-v1:")
            or action.intent.action_kind != action.schema.action_kind
            or action.schema.action_kind != "message" or action.schema.proactive
            or action.communication.audiences != (route.conversation_ref,)
            or action.communication.cancellation_epoch != 0):
        raise ValueError("staged passive reply identity or route differs")
    staged_types = [write.key.type_name for write in staged_d08.typed_writes]
    if (len(staged_types) != 4 or set(staged_types) != {
            "d08.goal.v1", "d08.action_intent.v1",
            "d08.action_schema.v1", "d08.action_cancellation.v1"}):
        raise ValueError("staged D08 goal/action/schema/cancellation must be complete")
    if (type(expression.segments) is not tuple or len(expression.segments) != 1
            or not expression.claims):
        raise ValueError("one quoted source-bound segment required")
    segment = expression.segments[0]
    if (not segment.body or segment.media_refs or segment.delay_seconds != 0
            or not segment.covered_slots or not segment.claim_uses
            or segment_payload_digest(segment.body, segment.media_refs,
                                      segment.claim_uses) != expression.payload_digest
            or len(action.communication.segment_specs) != 1
            or action.communication.segment_specs[0].segment_id != segment.segment_id
            or action.communication.segment_specs[0].effect_id != segment.effect_id
            or action.communication.segment_specs[0].payload_digest != expression.payload_digest
            or any(claim.kind is not ClaimKind.REPORTED_CLAIM
                   or claim.source_refs != (receipt.source_ref,)
                   or claim.allowed_audiences != (route.conversation_ref,)
                   or claim.disclosure_ref != receipt.source_ref
                   for claim in expression.claims)):
        raise ValueError("expression exceeds private source manifest")
    job_ref, outbox_ref, idempotency_key = artifact_receipt_dispatch_runtime_refs_v1(receipt)
    if ((quote.bot_id, quote.persona_id, quote.activity_id,
         quote.operation_id, quote.effect_id) !=
            (*namespace.as_tuple, identity.activity_id,
             identity.operation_id, identity.effect_id)
            or quote.parent_budget_lease_ref != budget_grant.lease_id
            or envelope.parent_budget_lease_ref != budget_grant.lease_id
            or (budget_grant.bot_id, budget_grant.persona_id) != namespace.as_tuple
            or quote.graph_job_ref != job_ref
            or quote.outbox_refs != (outbox_ref,)
            or quote.work_kind != "message"
            or quote.required_worker_fence is not None
            or quote.work_kind not in budget_grant.allowed_work_kinds
            or quote.valid_until_utc <= now_utc
            or budget_grant.valid_until_utc <= now_utc
            or quote.deadline_utc != envelope.deadline_utc
            or envelope.version_guard.resource_lease_versions != (
                VersionedRef(quote.quote_id, quote.version),)
            or any(amount > budget_grant.max_ceiling.get(name, 0)
                   for name, amount in quote.ceiling.items())):
        raise ValueError("signed quote or budget lease differs from exact D11 refs")
    if ((pre_reserved_job.job_id, pre_reserved_job.operation_id,
         pre_reserved_job.activity_id, pre_reserved_job.effect_id,
         pre_reserved_job.bot_id, pre_reserved_job.persona_id,
         pre_reserved_job.snapshot_ref, pre_reserved_job.work_kind,
         pre_reserved_job.budget_ref, pre_reserved_job.resource_ref) != (
            AtomKey.from_token(job_ref).name, identity.operation_id,
            identity.activity_id, identity.effect_id, *namespace.as_tuple,
            quote.snapshot_ref, quote.work_kind,
            budget_grant.lease_id, quote.resource_ref)
            or pre_reserved_job.phase != "waiting"
            or pre_reserved_job.fence != 0
            or pre_reserved_job.cancel_epoch != 0
            or pre_reserved_job.lease_holder is not None
            or pre_reserved_job.lease_expires_utc is not None
            or pre_reserved_job.result_ref is not None
            or pre_reserved_job.wake_condition != {
                "kind": "artifact_receipt_host_takeover",
                "operation_id": identity.operation_id}
            or pre_reserved_job.continuation != {}
            or pre_reserved_job.operator_versions != {
                "resource_quote": f"{quote.quote_id}:{quote.version}"}
            or pre_reserved_job.deadline_utc != datetime.fromtimestamp(
                envelope.deadline_utc, timezone.utc).isoformat().replace(
                    "+00:00", "Z")
            or pre_reserved_job.usage):
        raise ValueError("pre-reserved D11 job differs from signed reply quote")
    registry = RequiredCheckRegistry()
    registry.register(action.schema)
    decision = registry.qualify(action.intent, checks, now=now_utc)
    if (decision.status != "qualified"
            or len(checks) != len(action.intent.required_checks)
            or {check.check_kind for check in checks}
               != {spec.check_kind for spec in action.intent.required_checks}):
        raise ValueError("five staged action checks are not fully qualified")
    grant = pre_frozen_grant
    verify_route_bound_grant_v2(
        grant, action.intent, action.communication, route_binding)
    if (grant.qualification_receipt_digest != decision.receipt_digest
            or grant.valid_until != decision.valid_until
            or grant.valid_until <= now_utc):
        raise ValueError("staged route grant differs from five current checks")
    d09 = D09ExpressionProvider()
    prepared = d09.prepare_blueprint(
        grant, route.scene_ref, conversation_epoch,
        expression.claims, now=now_utc)
    if prepared.status != "complete" or prepared.blueprint is None:
        raise ValueError("D09 source reply blueprint is incomplete")
    batch = d09.build_verified_batch_v1(
        grant, prepared.blueprint, expression.segments, now=now_utc)
    if expression!=artifact_receipt_expression_v1(receipt,envelope.authority.audience):
        raise ValueError("Artifact receipt expression changed its fixed complete text")
    if (batch["target_ref"] != route_binding.target_entity_ref
            or batch["audiences"] != [route.conversation_ref]
            or batch["scene_ref"] != route.scene_ref
            or batch["grant_digest"] != canonical_digest(grant)
            or batch["segments"][0]["audiences"] != [route.conversation_ref]):
        raise ValueError("D09 batch lost entity or private delivery route")
    owner = Owner("activity", *namespace.as_tuple, identity.activity_id)
    grant_key = AtomKey(owner, "d08.communication_intent_grant.v1", grant.grant_id)
    batch_key = AtomKey(owner, "d09.verified_segment_batch.v1", batch["batch_id"])
    job_key, outbox_key = AtomKey.from_token(job_ref), AtomKey.from_token(outbox_ref)
    reads = {item.key: item.revision for item in envelope.version_guard.read_versions}
    if len(reads) != len(envelope.version_guard.read_versions):
        raise ValueError("duplicate graph read guard")
    for key in (grant_key, batch_key, job_key, outbox_key):
        if reads.get(key, 0) != 0:
            raise ValueError("candidate graph head is already present")
    extra = tuple(GraphVersion(key, 0) for key in
                  (grant_key, batch_key, job_key, outbox_key) if key not in reads)
    bundle_envelope = replace(envelope, version_guard=replace(
        envelope.version_guard,
        read_versions=envelope.version_guard.read_versions + extra))
    d08 = GoalExecutionProvider()
    d08_proposal = d08.validate(replace(
        staged_d08, envelope=bundle_envelope,
        typed_writes=staged_d08.typed_writes + (GraphWrite(
            grant_key, json.loads(canonical_serialize(asdict(grant))),),)))
    d09_proposal = d09.validate(DomainProposal(
        "d09", "d09.proposal.v1", d09.descriptor.request_schema_hash,
        bundle_envelope, (GraphWrite(batch_key, batch),),
        DependencySet(), (), (),
    ))
    outbox = RuntimeOutboxValue(
        *namespace.as_tuple, identity.activity_id, identity.operation_id,
        identity.effect_id, outbox_key.name, job_key.name, job_ref,
        dispatch_segment_payload_ref(batch_key.token, 0),
        idempotency_key, "pending", envelope.authority.activation_generation,
    )
    if (outbox.payload_ref != dispatch_segment_payload_ref(batch_key.token, 0)
            or outbox.dispatch_generation != envelope.authority.activation_generation):
        raise ValueError("D11 outbox lost the verified delivery segment")
    d11_proposal = DomainProposal(
        "d11", D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
        bundle_envelope, (job_graph_write(pre_reserved_job),
                          outbox_graph_write(outbox, job_key)),
        DependencySet(current_invalidation=(GraphVersion(job_key, 0),)),
        ("artifact-receipt:" + receipt.receipt_id,), (),
    )
    bundle = DomainBundle(
        bundle_envelope, (d08_proposal, d09_proposal, d11_proposal),
        (), (), (), (), (idempotency_key,), (job_ref,), (outbox_ref,),
    )
    return ArtifactReceiptDispatchBundleCandidateV1(
        "candidate", bundle, grant, batch, pre_reserved_job, job_ref, outbox_ref)



@dataclass(frozen=True,slots=True)
class ArtifactReceiptDispatchEvidenceV1:
    namespace:NamespaceId
    operation_id:str
    effect_id:str
    receipt_digest:str
    receipt_source_ref:str
    completion_digest:str
    completion_receipt_digest:str
    action_ref:str
    schema_ref:str
    grant_ref:str
    batch_ref:str
    batch_digest:str
    segment_id:str
    payload_digest:str
    source_refs:tuple
    candidate_digest:str
    status:str="source_qualified"

    @property
    def digest(self):return self.candidate_digest


@dataclass(frozen=True,slots=True)
class ArtifactReceiptDispatchRecoveryV1:
    evidence:ArtifactReceiptDispatchEvidenceV1
    write_versions:tuple
    graph_epoch:int
    graph_incarnation:str|None
    graph_revision:int|None


@dataclass(frozen=True,slots=True)
class ArtifactReceiptCurrentLineageV1:
    receipt:ArtifactCompletionReceiptOriginalV1
    route:CurrentReplyRouteManifestV2
    route_binding:CurrentReplyEntityRouteBindingV2
    source_closure:tuple
    candidate:ArtifactReceiptDispatchRecoveryV1
    digest:str


def _actual_receipt_original_for_operation_v1(db,namespace,operation_id):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .artifact_completion_receipt_v1 import require_artifact_completion_receipt_history_v1
    prefix="artifact-receipt-message:"
    if (type(operation_id)is not str or not operation_id.startswith(prefix)
            or len(operation_id)!=len(prefix)+48 or any(c not in "0123456789abcdef"for c in operation_id[len(prefix):])):
        raise AuthorityUnavailable("exact original Artifact receipt message operation required")
    original=read_adopted_domain_operation_v1(db,namespace,"artifact-completion-source:"+operation_id[len(prefix):])
    if original is None:raise AuthorityUnavailable("Artifact message has no actual D06 receipt producer")
    value=require_artifact_completion_receipt_history_v1(db,namespace=namespace,original=original)
    if value.message_operation_id!=operation_id:
        raise AuthorityUnavailable("Artifact message recovered another receipt producer")
    return value


def recover_artifact_receipt_dispatch_candidate_in_transaction_v1(db,namespace,operation_id,*,prepared_inventory=None):
    from ..runtime_storage_v3 import read_graph_row_v3
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as sql
    if not db.in_transaction or type(namespace)is not NamespaceId:
        raise AuthorityUnavailable("Artifact candidate recovery requires its actual current Graph transaction")
    row=sql(db,"SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple,operation_id)).fetchone()
    if row is None:return None
    raw=background_json_loads_v3(row[2]);candidate=raw.get("dispatch_candidate")
    if (type(candidate)is not dict or candidate.get("schema")!="sylanne.d11.dispatch_candidate.v1"
            or candidate.get("status")!="source_qualified"or len(candidate.get("refs",()))!=4):
        raise AuthorityUnavailable("Artifact completion dispatch has no actual qualified generic candidate")
    if prepared_inventory is None:
        from .artifact_receipt_original_read_v1 import actual_bound_artifact_dispatch_inventory_v1
        prepared_inventory=actual_bound_artifact_dispatch_inventory_v1(db,namespace,operation_id)
    if prepared_inventory is not None:
        value=prepared_inventory.artifact_receipt_originals.require_for_v1(prepared_inventory,db,
            now_utc=prepared_inventory.artifact_receipt_originals.task.now_utc)
    else:value=_actual_receipt_original_for_operation_v1(db,namespace,operation_id)
    ids=receipt_ids_v1(value.selector)
    if (row[:2]!=(ids["activity"],value.effect_id)or operation_id!=value.message_operation_id
            or tuple(candidate["source_refs"])!=(value.source_ref,)):
        raise AuthorityUnavailable("Artifact candidate borrowed another actual message/effect/receipt Source")
    event=sql(db,"SELECT revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple,row[0],operation_id)).fetchone()
    if event is None or event[1]!=candidate["graph_epoch"]:
        raise AuthorityUnavailable("Artifact candidate lost its actual committed event")
    writes=background_json_loads_v3(event[0]);values=[]
    types=("d08.action_intent.v1","d08.action_schema.v1","d08.communication_intent_grant.v1","d09.verified_segment_batch.v1")
    for (ref,revision),kind in zip(candidate["refs"],types):
        key=AtomKey.from_token(ref)
        if key.type_name!=kind or [ref,revision]not in writes or NamespaceId.from_key(key)!=namespace:
            raise AuthorityUnavailable("Artifact candidate write is not its actual generic D08/D09 member")
        history=read_graph_row_v3(db,("value","valid"),where="token=? AND revision=? AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            parameters=(ref,revision,*namespace.as_tuple,row[0],operation_id),history=True)
        if history is None or history[1]!=1:
            raise AuthorityUnavailable("Artifact candidate historical D08/D09 body was removed")
        values.append(background_json_loads_v3(history[0]))
    d08={spec.name:spec for spec in GoalExecutionProvider().register_types()}
    action=d08[types[0]].validator(values[0]);schema=d08[types[1]].validator(values[1]);grant=d08[types[2]].validator(values[2]);batch=values[3]
    next(spec for spec in D09ExpressionProvider.register_types()if spec.name==types[3]).validator(batch)
    expression=artifact_receipt_expression_v1(value,tuple(batch["audiences"]));segment=expression.segments[0]
    actual=batch["segments"]
    if (action.identity.operation_id!=operation_id or action.identity.effect_id!=value.effect_id
            or action.source_refs!=(value.source_ref,)or schema.required_checks!=action.required_checks
            or grant.action_id!=action.action_id or grant.intent_revision!=action.revision
            or batch["grant_digest"]!=canonical_digest(grant)or batch["batch_digest"]!=candidate["batch_digest"]
            or len(actual)!=1 or actual[0]["body"]!=value.text or actual[0]["media_refs"]
            or actual[0]["segment_id"]!=segment.segment_id or actual[0]["effect_id"]!=value.effect_id
            or actual[0]["payload_digest"]!=expression.payload_digest
            or actual[0]["source_refs"]!=[value.source_ref]
            or actual[0]["claim_uses"]!=[{"claim_ref":u.claim_ref,"start":u.start,"end":u.end,"asserted_as":u.asserted_as.value}for u in segment.claim_uses]):
        raise AuthorityUnavailable("Artifact D09 completion text or generic D08/grant lineage differs")
    evidence=ArtifactReceiptDispatchEvidenceV1(namespace,operation_id,value.effect_id,value.digest,value.source_ref,
        value.completion_digest,value.completion_receipt_digest,*tuple(ref for ref,_ in candidate["refs"]),
        batch["batch_digest"],segment.segment_id,expression.payload_digest,(value.source_ref,),candidate["digest"])
    return ArtifactReceiptDispatchRecoveryV1(evidence,tuple(tuple(row)for row in candidate["refs"]),
        candidate["graph_epoch"],candidate["graph_incarnation"],candidate["graph_revision"])


def _original_ingress_route_for_receipt_v1(db,value,query,now_utc,*,prepared_inventory=None):
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .ingress_observation import read_committed_ingress_identity
    from .first_ingress_v2 import scene_ref_for_conversation
    job=get_job(db,AtomKey.from_token(value.selector.task.cycle_job_ref).name)
    cycle=foreground_cycle_from_wire_v1(job.continuation)
    original=read_committed_ingress_identity(db,value.namespace,AtomKey.from_token(cycle.source_ref).owner.subject)
    if original is None:raise AuthorityUnavailable("Artifact receipt lost its actual original ingress route")
    identity=json.loads(original.identity_json)
    account=identity["platform_ref"];destination=identity["conversation_ref"]
    scene=scene_ref_for_conversation(value.namespace,account,destination)
    if identity["visibility"]!="private":
        raise AuthorityUnavailable("Artifact receipt cannot invent a private route for another ingress visibility")
    route=CurrentReplyRouteManifestV2(value.namespace,value.selector.task.c02_operation_id,cycle.source_ref,
        account,destination,scene,canonical_digest({"account_ref":account,"destination_ref":destination,"scene_ref":scene}))
    binding=read_current_reply_entity_route_binding_v2(db,value.namespace,route,query,now_utc=now_utc,
        prepared_inventory=prepared_inventory)
    return route,binding


def read_current_artifact_receipt_dispatch_lineage_v1(graph,*,namespace,admission,action,segment,snapshot,query,
        now_utc,prepared_inventory=None):
    db=graph._GraphCoordinator__store._db
    bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    issuer=graph._GraphCoordinator__d11_issuer
    if prepared_inventory is not None:
        prepared_inventory.require_current(db,namespace,query)
        sealed=prepared_inventory.artifact_receipt_originals
        value=sealed.require_for_v1(prepared_inventory,db,now_utc=now_utc)
        from .artifact_receipt_original_read_v1 import bind_prepared_artifact_receipt_points_v1
        with bind_prepared_artifact_receipt_points_v1(sealed,prepared_inventory,db,now_utc=now_utc):
            route,route_binding=_original_ingress_route_for_receipt_v1(db,value,query,now_utc,prepared_inventory=prepared_inventory)
    else:
        original=_actual_receipt_original_for_operation_v1(db,namespace,admission.operation_id)
        value=read_current_artifact_completion_receipt_by_operation_v1(db,namespace=namespace,
            operation_id=admission.operation_id,issuer=issuer,installed_bundle=bundle,owner_guard=original.owner_guard,
            now_utc=now_utc,audiences=admission.audience)
        route,route_binding=_original_ingress_route_for_receipt_v1(db,value,query,now_utc)
    candidate=recover_artifact_receipt_dispatch_candidate_in_transaction_v1(db,namespace,value.message_operation_id,
        prepared_inventory=prepared_inventory)
    if (candidate is None or action.identity.operation_id!=value.message_operation_id or action.identity.effect_id!=value.effect_id
            or action.source_refs!=(value.source_ref,)or admission.candidate_digest!=candidate.evidence.digest
            or admission.payload_digest!=candidate.evidence.payload_digest
            or (admission.account_ref,admission.destination_ref,admission.scene_ref,admission.object_ref,admission.audience)!=
                (route.platform_ref,route.conversation_ref,route.scene_ref,route_binding.target_entity_ref,(route.conversation_ref,))
            or action.target_ref!=route_binding.target_entity_ref or segment.route_digest!=route.route_digest):
        raise AuthorityUnavailable("Artifact completion lineage differs from its actual admission/op/effect/original ingress")
    if prepared_inventory is not None:
        closure=tuple(sorted(prepared_inventory.source_family(db,(value.source_ref,route.source_ref),
            purpose="expression",audiences=admission.audience)))
    else:
        from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
        closure=tuple(sorted(v.key.token for v in _source_family_current_sql_v1(db,namespace=namespace,
            roots=(value.source_ref,route.source_ref),purpose="expression",audiences=admission.audience)
            if v.key.type_name=="memory.source"))
    from .dispatch_source_correction_barrier import read_source_correction_barrier
    barrier=read_source_correction_barrier(db,namespace,query,closure,dependent_ref=value.source_ref,
        prepared_inventory=prepared_inventory)
    if not barrier.clear:raise AuthorityUnavailable("Artifact completion receipt Source was corrected or removed")
    digest=canonical_digest(("artifact-receipt-current-lineage.v1",value.digest,value.completion_digest,
        value.completion_receipt_digest,route,route_binding,closure,candidate.evidence,query,
        None if prepared_inventory is None else prepared_inventory.artifact_receipt_originals.digest))
    return ArtifactReceiptCurrentLineageV1(value,route,route_binding,closure,candidate,digest)
