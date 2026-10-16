"""Whole contact occupancy from the live Owner approval and actual paid plan."""
from ..domains.d01.production_operations_v1 import plain_v1
from dataclasses import replace

from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
from ..domains.d10 import ContactContinuation, decode_contact_policy
from ..domains.d10.contact_claim_v2 import (
    ContactClaimV2, contact_claim_key_v2,
    contact_window_id_v2, decode_contact_claim_v2,
)
from ..graph_types import AtomKey, GraphWrite
from ..runtime_contracts import canonical_digest
from .contact_final_action_v1 import contact_whole_grant_request_v1, require_contact_segment_index_v1
from .d10_contact_policy_authority_v1 import require_current_contact_policy_v1


def _expected_claim_v3(db, read, content, current_policy, scope, now):
    plan_atom = read.head(db, content.plan_version.key, required=True)
    plan = decode_contact_plan_v2(plan_atom.value)
    if (plan_atom.revision != content.plan_version.revision
            or canonical_digest(plain_v1(plan)) != content.plan_digest):
        raise ValueError('contact occupancy plan changed')
    policies = tuple(atom for atom in read.complete_inventory(db, 'd10.contact_policy.v1')
        if atom.valid and atom.value['approval_ref'] == plan.policy_original_ref)
    if len(policies) != 1:
        raise ValueError('contact occupancy has no unique adopted current policy')
    original = require_current_contact_policy_v1(current_policy, scope, policies[0].value, now=now)
    if original.digest != plan.policy_original_digest:
        raise ValueError('contact occupancy Owner approval differs from the paid plan')
    policy = decode_contact_policy(policies[0].value, content.namespace)
    parent = contact_whole_grant_request_v1(content)
    claim = ContactClaimV2(content.contact_id, parent.communication_action_id, plan.target_entity_ref,
        policy.channel, policy.category, tuple(item.segment.effect_id for item in content.segments),
        (), 'claimed', policy.policy_id, policy.version, contact_window_id_v2(policy),
        policy.window_start, policy.window_end, original.original_ref, original.digest)
    return claim, policies[0].key, AtomKey.from_token(plan.opportunity_ref.ref)


def prepare_whole_contact_claim_v3(db, read, *, content, current_policy, scope, now_utc):
    """Stage the same initial occupancy in provisional and final transactions."""
    read.check(db)
    claim, policy_key, opportunity = _expected_claim_v3(db, read, content, current_policy, scope, now_utc)
    if read.head(db, contact_claim_key_v2(content.namespace, content.contact_id)).revision != 0:
        raise ValueError('contact occupancy is already present; use its adopted lineage')
    return _contact_claim_write_v3(content.namespace, claim,
        policy_key=policy_key, opportunity_key=opportunity)


def _contact_claim_write_v3(namespace, claim, *, policy_key, opportunity_key):
    """Encode this typed current claim as JSON without changing its V2 wire.

    A candidate is not permission: the installed private reader produced the
    claim/window/approval above and GCP rechecks it under the original fence.
    """
    if type(claim) is not ContactClaimV2:
        raise TypeError('Contact3 requires its actual typed approved-window claim')
    return GraphWrite(contact_claim_key_v2(namespace, claim.contact_id), plain_v1(claim),
        (policy_key, opportunity_key))


def read_current_own_contact_continuation_v3(db, read, *, content, segment_index,
        current_policy, scope, now_utc):
    """Derive continuation from the actual row; no caller continuation is accepted."""
    require_contact_segment_index_v1(content, segment_index)
    expected, _, _ = _expected_claim_v3(db, read, content, current_policy, scope, now_utc)
    atom = read.head(db, contact_claim_key_v2(content.namespace, content.contact_id), required=True)
    current = decode_contact_claim_v2(atom.value)
    if replace(current,observations=(),status='claimed')!=expected or current.status in {'released','pending_confirmation'}:
        raise ValueError('contact occupancy scope or approval changed')
    effect = content.segments[segment_index].segment.effect_id
    if current.status in {'released', 'pending_confirmation'} or effect in dict(current.observations):
        raise ValueError('contact continuation is released, unknown or already observed')
    if segment_index == 0:
        if atom.revision != 1 or current.observations:
            raise ValueError('initial contact claim must be its unconsumed staged original')
    else:
        from .contact_final_stage_v3 import require_installed_contact_material_v3
        from .contact_continuation_stage_v1 import _require_current_continuation_v1
        material=require_installed_contact_material_v3(read._witness.material)
        if material.request.segment_index!=segment_index:
            raise ValueError('Contact continuation current provider has another segment')
        _require_current_continuation_v1(material,db)
        expected_prefix={part.segment.effect_id:'accepted'for part in content.segments[:segment_index]}
        if dict(current.observations)!=expected_prefix:
            raise ValueError('Contact continuation actual own-claim prefix is incomplete')
    return ContactContinuation(content.contact_id, current.communication_action_id, effect)
