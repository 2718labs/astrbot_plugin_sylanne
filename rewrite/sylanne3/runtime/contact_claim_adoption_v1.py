"""Whole contact occupancy from the live Owner approval and actual paid plan."""
from dataclasses import replace

from ..domains.d08.contact_plan_v1 import decode_contact_plan_v1
from ..domains.d09.contact_batch_v1 import contact_batch_key_v1, validate_contact_verified_batch_v1
from ..domains.d10 import ContactContinuation, decode_contact_policy
from ..domains.d10.contact_claim_v2 import (
    ContactClaimV2, contact_claim_key_v2, contact_claim_graph_write_v2,
    contact_window_id_v2, decode_contact_claim_v2,
)
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from .contact_final_action_v1 import contact_final_action_ids_v1
from .d10_contact_policy_authority_v1 import require_current_contact_policy_v1


def _expected_claim(db, read, content, current_policy, scope, now):
    plan_atom = read.head(db, content.plan_version.key, required=True)
    plan = decode_contact_plan_v1(plan_atom.value)
    if (plan_atom.revision != content.plan_version.revision
            or canonical_digest(plan) != content.plan_digest):
        raise ValueError('contact occupancy plan changed')
    policies = tuple(atom for atom in read.complete_inventory(db, 'd10.contact_policy.v1')
        if atom.valid and atom.value['approval_ref'] == plan.policy_original_ref)
    if len(policies) != 1:
        raise ValueError('contact occupancy has no unique adopted current policy')
    original = require_current_contact_policy_v1(current_policy, scope, policies[0].value, now=now)
    if original.original_digest != plan.policy_original_digest:
        raise ValueError('contact occupancy Owner approval differs from the paid plan')
    policy = decode_contact_policy(policies[0].value, content.namespace)
    ids = contact_final_action_ids_v1(content.contact_id, 0)
    claim = ContactClaimV2(content.contact_id, ids['action'], plan.target_entity_ref,
        policy.channel, policy.category, tuple(item.segment.effect_id for item in content.segments),
        (), 'claimed', policy.policy_id, policy.version, contact_window_id_v2(policy),
        policy.window_start, policy.window_end, original.original_ref, original.original_digest)
    return claim, policies[0].key, AtomKey.from_token(plan.opportunity_ref.ref)


def prepare_whole_contact_claim_v1(db, read, *, content, current_policy, scope, now_utc):
    """Stage the same initial occupancy in provisional and final transactions."""
    read.check(db)
    claim, policy_key, opportunity = _expected_claim(db, read, content, current_policy, scope, now_utc)
    if read.head(db, contact_claim_key_v2(content.namespace, content.contact_id)).revision != 0:
        raise ValueError('contact occupancy is already present; use its adopted lineage')
    return contact_claim_graph_write_v2(content.namespace, claim,
        policy_key=policy_key, opportunity_key=opportunity)


def read_current_own_contact_continuation_v1(db, read, *, content, segment_index,
        current_policy, scope, now_utc):
    """Derive continuation from the actual row; no caller continuation is accepted."""
    expected, _, _ = _expected_claim(db, read, content, current_policy, scope, now_utc)
    atom = read.head(db, contact_claim_key_v2(content.namespace, content.contact_id), required=True)
    current = decode_contact_claim_v2(atom.value)
    if replace(current, observations=(), status='claimed') != expected:
        raise ValueError('contact occupancy scope or approval changed')
    effect = content.segments[segment_index].segment.effect_id
    if current.status in {'released', 'pending_confirmation'} or effect in dict(current.observations):
        raise ValueError('contact continuation is released, unknown or already observed')
    if segment_index == 0:
        if atom.revision != 1 or current.observations:
            raise ValueError('initial contact claim must be its unconsumed staged original')
    else:
        batch_atom = read.head(db, contact_batch_key_v1(content.namespace, content.activity_id,
            content.contact_id), required=True)
        batch = validate_contact_verified_batch_v1(batch_atom.value)
        if batch.content != content or batch_atom.revision != 1:
            raise ValueError('contact continuation whole batch changed')
        read.committed_operation(db, batch.producing_operation_id)
        from .d04_root_original_store_v1 import _receipt
        commit = _receipt(db, content.namespace, batch.producing_operation_id)
        if commit.status != 'committed':
            raise ValueError('contact continuation lacks actual whole-batch adoption')
        prior = tuple(item.segment.effect_id for item in content.segments[:segment_index])
        if any(dict(current.observations).get(item) not in {'accepted', 'delivered'} for item in prior):
            raise ValueError('contact continuation predecessor lacks its actual handoff observation')
    return ContactContinuation(content.contact_id, current.communication_action_id, effect)
