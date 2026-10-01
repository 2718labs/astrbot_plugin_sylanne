"""Natural paid dispatch material has a separate graph-candidate identity."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.domains.d08.execution import ActionSchema, ActionSchemaRecord
from sylanne3.domains.d09.natural_batch import NATURAL_BATCH_SCHEMA_V2
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.dispatch_candidate import (
    NaturalDispatchCandidateEvidenceV2, dispatch_segment_payload_ref,
    natural_dispatch_segment_payload_ref_v2, validate_dispatch_candidate_writes,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

from test_dispatch_admission_preflight import _candidates


def _case():
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "one")
    access = access_key(*namespace.as_tuple, "one")
    schema, action, _, _, _, grant = _candidates(
        source_ref=source.token, include_grant=True)
    action = replace(action, action_kind="communication",
                     effect_scope=(action.identity.effect_id,))
    schema = ActionSchemaRecord.bind(action, ActionSchema(
        schema.schema_id, "communication", False, schema.required_checks))
    grant = replace(grant, route_binding_digest="a" * 64)
    paid = {
        "generation_original_operation_id": "original:g",
        "generation_call_id": "call:g",
        "generation_model_call_request_digest": "1" * 64,
        "generation_terminal_receipt_digest": "2" * 64,
        "generation_output_digest": "3" * 64,
        "generation_reservation_operation_id": "reserve:g",
        "review_original_operation_id": "original:r",
        "review_call_id": "call:r",
        "review_model_call_request_digest": "4" * 64,
        "review_terminal_receipt_digest": "5" * 64,
        "review_output_digest": "6" * 64,
        "review_reservation_operation_id": "reserve:r",
        "parent_budget_lease_id": "budget:parent",
        "review_policy_version": "review:v1",
        "current_graph_guard_digest": "7" * 64,
        "receipt_digest": "8" * 64,
    }
    segment = grant.segment_grants[0]
    batch = {
        "schema": NATURAL_BATCH_SCHEMA_V2, "version": 2,
        "qualification": "paid_reviewed_current_source_hold",
        "activity_id": action.identity.activity_id,
        "operation_id": action.identity.operation_id,
        "effect_id": action.identity.effect_id,
        "scene_id": "scene:one", "audience_id": grant.audiences[0],
        "scene_ref": {"ref": source.token, "version": 1},
        "audience_ref": {"ref": source.token, "version": 1},
        "route_binding_digest": grant.route_binding_digest,
        "source_ref": {"ref": source.token, "version": 1},
        "grant_id": grant.grant_id, "grant_digest": canonical_digest(grant),
        "action_id": action.action_id, "intent_ref": grant.intent_ref,
        "segment_authorization_ref": grant.segment_authorization_ref(
            segment.segment_id),
        "required_check_refs": list(grant.required_check_refs),
        "valid_until": grant.valid_until,
        "cancellation_epoch": grant.cancellation_epoch,
        "required_slots": list(grant.required_slots),
        "qualified_units_digest": "9" * 64,
        "current_reads": [
            {"ref": source.token, "version": 1},
            {"ref": access.token, "version": 1},
        ],
        "paid_review": paid,
        "claims": [{"claim_id": "claim:one", "text": "Hello",
                    "kind": "external_fact", "source_refs": [source.token],
                    "allowed_audiences": list(grant.audiences),
                    "eligibility": ["expression"],
                    "disclosure_ref": "disclosure:one"}],
        "segment": {"segment_id": segment.segment_id,
                    "effect_id": action.identity.effect_id, "body": "Hello",
                    "payload_digest": segment.payload_digest,
                    "claim_uses": [{"claim_ref": "claim:one", "start": 0,
                                    "end": 5, "asserted_as": "external_fact"}],
                    "covered_slots": ["answer"], "media_refs": [],
                    "position": 0},
    }
    batch["batch_id"] = "natural-batch:one"
    batch["batch_digest"] = canonical_digest({
        key: value for key, value in batch.items() if key != "batch_digest"})
    owner = Owner("activity", *namespace.as_tuple, action.identity.activity_id)
    writes = tuple(("d08", GraphWrite(
        AtomKey(owner, type_name, name),
        json.loads(canonical_serialize(asdict(value)))))
        for type_name, name, value in (
            ("d08.action_intent.v1", action.action_id, action),
            ("d08.action_schema.v1", schema.schema_ref, schema),
            ("d08.communication_intent_grant.v1", grant.grant_id, grant),
        )) + (("d09", GraphWrite(AtomKey(owner, NATURAL_BATCH_SCHEMA_V2,
                                           batch["batch_id"]), batch)),)
    reads = (GraphVersion(source, 1), GraphVersion(access, 1))
    return namespace, action, writes, reads, source


def test_natural_batch_has_distinct_paid_dispatch_evidence():
    namespace, action, writes, reads, source = _case()
    result = validate_dispatch_candidate_writes(
        writes, namespace=namespace, identity=action.identity,
        read_versions=reads, source_refs=(source.token,),
        access_epoch=0, delete_epoch=0, query_epoch=1)
    assert type(result) is NaturalDispatchCandidateEvidenceV2
    assert result.status == "natural_paid_review_current_hold"
    assert result.generation_original_operation_id != result.review_original_operation_id
    assert result.current_read_versions == reads


def test_natural_batch_rejects_changed_paid_read_and_missing_d08_grant():
    namespace, action, writes, reads, source = _case()
    kwargs = dict(namespace=namespace, identity=action.identity,
                  source_refs=(source.token,), access_epoch=0,
                  delete_epoch=0, query_epoch=1)
    with pytest.raises(ValueError, match="current source or paid read closure"):
        validate_dispatch_candidate_writes(
            writes, read_versions=reads[:1], **kwargs)
    with pytest.raises(ValueError, match="paired D08"):
        validate_dispatch_candidate_writes(
            tuple(item for item in writes if item[1].key.type_name
                  != "d08.communication_intent_grant.v1"),
            read_versions=reads, **kwargs)


def test_natural_payload_ref_uses_independent_v2_identity():
    _, _, writes, _, _ = _case()
    batch_ref = writes[-1][1].key.token
    ref = natural_dispatch_segment_payload_ref_v2(batch_ref, 0)
    assert ref.startswith("d09-natural:")
    with pytest.raises(ValueError, match="verified batch"):
        dispatch_segment_payload_ref(batch_ref, 0)
