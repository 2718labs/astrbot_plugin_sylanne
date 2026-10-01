"""Pure post-C02 private reply bundle candidate for W01's atomic seal.

The supplied receipts are observations from W01's staged E+1 transaction.
Neither this value nor a locally qualified D08 decision authorizes dispatch:
W01 must reissue all five checks at seal and independently admit the bundle.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import math

from ..domains.d08 import (
    CommunicationIntentGrant, GoalExecutionProvider, RequiredCheckRegistry,
)
from ..domains.d08.communication_route_binding import verify_route_bound_grant_v2
from ..domains.d09 import ClaimKind, D09ExpressionProvider, segment_payload_digest
from ..domains.d09.source_reply import SourceReplyExpressionV1
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import (
    CheckReceipt, CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    NamespaceId, OperationIdentity, VersionedRef, canonical_digest,
    canonical_serialize,
)
from .d11_types import (
    D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, RuntimeOutboxValue,
    job_graph_write, outbox_graph_write, runtime_job_key, runtime_outbox_key,
)
from .dispatch_candidate import dispatch_segment_payload_ref
from .issuers import BudgetLeaseGrant, ResourceQuote
from .jobs import PersistentJob
from .post_c02_reply_action_v2 import PostC02ReplyActionCandidateV2
from .reply_model_job import CurrentReplyRouteManifestV2
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2


@dataclass(frozen=True, slots=True)
class PostC02DispatchBundleCandidateV2:
    """Inspectable write candidate only; it carries no send/admission permit."""

    status: str
    bundle: DomainBundle
    grant: object
    batch: dict
    job: PersistentJob
    job_ref: str
    outbox_ref: str


def post_c02_dispatch_runtime_refs_v2(
    namespace: NamespaceId, identity: OperationIdentity,
) -> tuple[str, str, str]:
    """Fix D11 refs before quoting and before reading the model's text."""
    if type(namespace) is not NamespaceId or type(identity) is not OperationIdentity:
        raise TypeError("typed namespace and operation identity required")
    if identity.effect_id is None:
        raise ValueError("one reply effect is required")
    stem = canonical_digest({
        "schema": "sylanne.post-c02-dispatch-runtime-refs.v2",
        "namespace": namespace, "identity": identity,
    })
    job_id = "reply-dispatch-" + stem[:32]
    outbox_id = "reply-outbox-" + stem[:32]
    job_ref = runtime_job_key(*namespace.as_tuple, identity.activity_id, job_id).token
    outbox_ref = runtime_outbox_key(*namespace.as_tuple, identity.activity_id, outbox_id).token
    return job_ref, outbox_ref, "reply-dispatch:" + stem


def prepare_post_c02_reply_bundle_candidate_v2(
    *, envelope: CommandEnvelope,
    action: PostC02ReplyActionCandidateV2,
    staged_d08: DomainProposal,
    checks: tuple[CheckReceipt, ...],
    expression: SourceReplyExpressionV1,
    route: CurrentReplyRouteManifestV2,
    route_binding: CurrentReplyEntityRouteBindingV2,
    pre_frozen_grant: CommunicationIntentGrant,
    quote: ResourceQuote,
    budget_grant: BudgetLeaseGrant,
    pre_reserved_job: PersistentJob,
    now_utc: float,
    conversation_epoch: int,
) -> PostC02DispatchBundleCandidateV2:
    """Assemble exact candidate writes from staged action and five receipts.

    ``checks`` must be supplied by W01 from real staged E+1 provider reads.
    This function cannot establish that provenance and intentionally exposes no
    send or admission capability.
    """
    if (type(envelope) is not CommandEnvelope
            or type(action) is not PostC02ReplyActionCandidateV2
            or type(staged_d08) is not DomainProposal
            or type(checks) is not tuple
            or any(type(check) is not CheckReceipt for check in checks)
            or type(expression) is not SourceReplyExpressionV1
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
            or envelope.source_qualification.source_refs != (route.source_ref,)
            or route.source_ref not in envelope.input_refs
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
            or action.intent.source_refs != (route.source_ref,)
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
                   or claim.source_refs != (route.source_ref,)
                   or claim.allowed_audiences != (route.conversation_ref,)
                   or claim.disclosure_ref != route.source_ref
                   for claim in expression.claims)):
        raise ValueError("expression exceeds private source manifest")
    job_ref, outbox_ref, idempotency_key = post_c02_dispatch_runtime_refs_v2(
        namespace, identity)
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
                "kind": "post_c02_reply_host_takeover",
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
        ("post-c02-reply:" + identity.operation_id,), (),
    )
    bundle = DomainBundle(
        bundle_envelope, (d08_proposal, d09_proposal, d11_proposal),
        (), (), (), (), (idempotency_key,), (job_ref,), (outbox_ref,),
    )
    return PostC02DispatchBundleCandidateV2(
        "candidate", bundle, grant, batch, pre_reserved_job, job_ref, outbox_ref)


__all__ = (
    "PostC02DispatchBundleCandidateV2",
    "post_c02_dispatch_runtime_refs_v2",
    "prepare_post_c02_reply_bundle_candidate_v2",
)
