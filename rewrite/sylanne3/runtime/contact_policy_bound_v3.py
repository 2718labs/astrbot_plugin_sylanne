"""Contact3 operation-bounded qualification; the native D10 check is retained.

Public codecs are evidence shapes, never issuance. Only the active installed
Contact3 projection can issue this narrowing from a fresh complete D10 read.
"""
from dataclasses import dataclass, replace
import math

from ..domains.d10 import ContactContinuation, ContactPolicyCheck
from ..graph_types import GraphVersion
from ..runtime_contracts import CheckReceipt, canonical_serialize


@dataclass(frozen=True, slots=True)
class ContactPolicyQualificationBoundV3:
    provider_receipt: CheckReceipt
    local_check: ContactPolicyCheck
    policy_version: GraphVersion
    opportunity_version: GraphVersion
    continuation: ContactContinuation
    operation_deadline_utc: float
    bounded_receipt: CheckReceipt
    schema: str = 'd10.contact-policy-qualification-bound.v3'

    def __post_init__(self):
        raw, local, bounded = self.provider_receipt, self.local_check, self.bounded_receipt
        deadline = self.operation_deadline_utc
        if (self.schema != 'd10.contact-policy-qualification-bound.v3'
                or type(raw) is not CheckReceipt or type(bounded) is not CheckReceipt
                or type(local) is not ContactPolicyCheck
                or type(self.policy_version) is not GraphVersion
                or type(self.opportunity_version) is not GraphVersion
                or type(self.continuation) is not ContactContinuation
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or self.policy_version.key.type_name != 'd10.contact_policy.v1'
                or self.opportunity_version.key.type_name != 'd10.proactive_opportunity.v1'
                or self.policy_version.revision < 1 or self.opportunity_version.revision < 1
                or raw.check_kind != 'contact_policy' or raw.issuer != 'd10.contact_policy'
                or raw.result != 'pass' or raw.coverage != 'full' or raw.purpose != 'expression'
                or local.result != 'pass' or local.reasons or local.dispatch_authorized is not False
                or type(local.policy_version) is not int or local.policy_version < 1
                or type(local.valid_until) not in (int, float) or not math.isfinite(local.valid_until)
                or raw.valid_until != local.valid_until
                or bounded.valid_until != min(raw.valid_until, deadline)
                or canonical_serialize(bounded) != canonical_serialize(replace(raw,
                    valid_until=min(raw.valid_until, deadline)))):
            raise ValueError('Contact3 policy qualification is not its exact native/min-deadline proof')


def issue_installed_contact_policy_bound_v3(db, read, *, scope, intent,
        policy_id, opportunity_id, current_policy):
    """No supplied receipt, clock or deadline can issue a qualification."""
    from .contact_final_projection_v3 import require_contact_projection_read_v3
    require_contact_projection_read_v3(read, db,
        phases=('provisional_e_plus_1', 'post_cas_e_plus_1'))
    material = read._witness.material
    frame = read.frame
    if (scope is not material.scope or current_policy is not material.current_policy
            or intent.identity != frame.envelope.identity):
        raise ValueError('Contact3 policy bound lost its actual installed command/policy')
    from ..domains.d08.execution import ActionIntent, GoalExecutionProvider
    from ..graph_types import AtomKey, Owner
    if type(intent) is not ActionIntent:
        raise ValueError('Contact3 policy bound requires its exact actual action')
    action_key = AtomKey(Owner('activity', *scope.namespace.as_tuple,
        frame.envelope.identity.activity_id), 'd08.action_intent.v1', intent.action_id)
    action_row = read.head(db, action_key, required=True)
    validator = next(spec.validator for spec in GoalExecutionProvider().register_types()
        if spec.name == 'd08.action_intent.v1')
    if canonical_serialize(validator(action_row.value)) != canonical_serialize(intent):
        raise ValueError('Contact3 policy bound supplied action differs from actual staged SQL')
    from .contact_qualification_v3 import _plan_policy
    _, _, actual_policy, _, actual_opportunity = _plan_policy(db, read, material.content,
        material.current_policy, material.scope, material.frame.now_utc)
    if (policy_id, opportunity_id) != (actual_policy.policy_id, actual_opportunity.opportunity_id):
        raise ValueError('Contact3 policy bound policy/opportunity differ from its actual paid plan')
    from .contact_claim_adoption_v3 import read_current_own_contact_continuation_v3
    continuation = read_current_own_contact_continuation_v3(db, read,
        content=material.content, segment_index=material.request.segment_index,
        current_policy=material.current_policy, scope=material.scope,
        now_utc=material.frame.now_utc)
    from .dispatch_current_contact import read_current_contact
    actual = read_current_contact(db, scope.namespace, frame.snapshot,
        frame.envelope.version_guard.query_epochs[0], intent, policy_id, opportunity_id,
        now=material.frame.now_utc, current_policy=current_policy, scope=scope,
        continuation=continuation)
    if actual.status != 'check_pass' or actual.missing_sources:
        raise ValueError('Contact3 policy bound lacks its freshly verified complete D10 read')
    policy = read.head(db, actual.policy_key, required=True)
    opportunity = read.head(db, actual.opportunity_key, required=True)
    deadline = material.frame.envelope.deadline_utc
    if not material.frame.now_utc < min(actual.receipt.valid_until, deadline):
        raise ValueError('Contact3 policy bound is already expired')
    return ContactPolicyQualificationBoundV3(actual.receipt, actual.local_check,
        GraphVersion(policy.key, policy.revision), GraphVersion(opportunity.key, opportunity.revision),
        continuation, deadline, replace(actual.receipt,
            valid_until=min(actual.receipt.valid_until, deadline)))


def validate_contact_policy_bound_members_v3(bound, *, members, namespace,
        owner_policy, action, now_utc, deadline_utc):
    """Recompute the native D10 rule from the complete recorded SQL inventory.

    Current and historical evidence callers separately authenticate these
    members against actual SQL/history. This function issues no permission.
    """
    import json
    from ..domains.d10 import (ContactClaim, LifeDomain, decode_contact_policy,
        decode_proactive_opportunity, contact_policy_key, opportunity_key)
    from ..domains.d10.contact_claim_v2 import (decode_contact_claim_v2,
        contact_claim_key_v2, contact_window_id_v2)
    from ..domains.d08.execution import ActionIntent
    from ..graph_types import AtomKey
    from ..runtime_contracts import NamespaceId
    if type(bound) is not ContactPolicyQualificationBoundV3 or type(action) is not ActionIntent:
        raise ValueError('Contact3 lacks its typed native policy bound')
    bound.__post_init__()
    if (bound.operation_deadline_utc != deadline_utc
            or not now_utc < bound.bounded_receipt.valid_until
            or bound.provider_receipt.subject_ref != 'persona:' + namespace.persona_id
            or bound.provider_receipt.action_ref != action.action_id):
        raise ValueError('Contact3 policy bound actual operation deadline/identity differs')
    rows = {row.ref: row for row in members}
    def value(version):
        row = rows.get(version.key.token)
        if (NamespaceId.from_key(version.key) != namespace or row is None
                or not row.valid or row.revision != version.revision):
            raise ValueError('Contact3 native policy bound lacks its exact SQL member')
        return json.loads(row.value_json)
    policy_raw, opportunity_raw = value(bound.policy_version), value(bound.opportunity_version)
    policy = decode_contact_policy(policy_raw, namespace)
    opportunity = decode_proactive_opportunity(opportunity_raw, namespace)
    if (bound.policy_version.key != contact_policy_key(namespace, policy.policy_id)
            or bound.opportunity_version.key != opportunity_key(namespace, opportunity.opportunity_id)
            or policy != owner_policy.policy
            or policy_raw['approval_ref'] != owner_policy.original_ref
            or action.target_ref != opportunity.subject_ref):
        raise ValueError('Contact3 native policy bound differs from its Owner/action originals')
    claims = []
    for row in members:
        key = AtomKey.from_token(row.ref)
        if not row.valid or key.type_name not in {'d10.contact_claim.v1','d10.contact_claim.v2'}:
            continue
        raw = json.loads(row.value_json)
        if key.type_name == 'd10.contact_claim.v2':
            claim = decode_contact_claim_v2(raw)
            if key != contact_claim_key_v2(namespace, claim.contact_id):
                raise ValueError('Contact3 native quota claim key differs')
        else:
            spec = next(s for s in LifeDomain.type_specs() if s.name == key.type_name)
            spec.validator(raw)
            claim = ContactClaim(**{**raw, 'segment_effects':tuple(raw['segment_effects']),
                'observations':tuple(tuple(pair) for pair in raw['observations'])})
            if key.name != claim.contact_id:
                raise ValueError('Contact3 native legacy quota claim key differs')
        claims.append(claim)
    own = [claim for claim in claims if claim.contact_id == bound.continuation.contact_id]
    if (len(own) != 1 or own[0].status in {'released','pending_confirmation'}
            or own[0].communication_action_id != bound.continuation.communication_action_id
            or bound.continuation.segment_effect_id != action.identity.effect_id
            or bound.continuation.segment_effect_id not in own[0].segment_effects
            or getattr(own[0], 'approval_ref', None) != owner_policy.original_ref
            or getattr(own[0], 'approval_digest', None) != owner_policy.digest
            or getattr(own[0], 'window_id', None) != contact_window_id_v2(policy)):
        raise ValueError('Contact3 native qualification does not own its exact unconsumed quota')
    position=own[0].segment_effects.index(bound.continuation.segment_effect_id)
    if dict(own[0].observations)!={effect:'accepted'for effect in own[0].segment_effects[:position]}:
        raise ValueError('Contact native bound has no exact earlier accepted own-claim rule input')
    actual = LifeDomain.contact_policy_check(policy, opportunity, tuple(claims),
        now=now_utc, continuation=bound.continuation)
    if canonical_serialize(actual) != canonical_serialize(bound.local_check):
        raise ValueError('Contact3 native policy result/TTL differs from complete SQL quota inventory')
    specs = tuple(spec for spec in action.required_checks
        if spec.check_kind == 'contact_policy' and spec.provider_id == 'd10.contact_policy')
    if len(specs) != 1:
        raise ValueError('Contact3 native policy lacks its unique actual action criterion')
    spec = specs[0]
    expected = CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref,
        spec.purpose, spec.required_input_versions, 'full', actual.result,
        actual.valid_until, spec.provider_id)
    if canonical_serialize(expected) != canonical_serialize(bound.provider_receipt):
        raise ValueError('Contact3 original native receipt differs from its actual action/full rule')
    return bound
