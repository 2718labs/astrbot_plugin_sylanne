"""The first reactive candidate is one graph bundle and remains HOLD."""

from dataclasses import replace

import pytest

from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim,
    SegmentCandidate,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.initial_reactive_issuer import (
    assemble_initial_reactive_candidate,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, canonical_digest,
)

from test_dispatch_admission_preflight import _candidates


def _inputs():
    source = source_key("bot", "persona", "source-1").token
    access = access_key("bot", "persona", "source-1").token
    _, intent, _, _, _, grant = _candidates(source_ref=source, include_grant=True)
    identity = replace(intent.identity, canonical_input_digest=canonical_digest({
        "input_refs": [],
    }))
    intent = replace(intent, identity=identity)
    namespace = NamespaceId("bot", "persona")
    authority = AuthorityContext(
        "host", "d06", "capability", namespace, ("event", "activity"),
        "expression", ("entity:user",), "policy-1", 1,
    )
    owner = Owner("activity", "bot", "persona", identity.activity_id)
    writes = (
        AtomKey(owner, "d08.action_intent.v1", intent.action_id),
        AtomKey(owner, "d08.action_schema.v1", "schema-ref:one"),
        AtomKey(owner, "d08.communication_intent_grant.v1", grant.grant_id),
        AtomKey(owner, "d09.verified_segment_batch.v1", "verified-batch:one"),
    )
    guard = VersionGuard(
        (GraphVersion(AtomKey.from_token(source), 1),
         GraphVersion(AtomKey.from_token(access), 1))
        + tuple(GraphVersion(key, 0) for key in writes),
        (QueryEpoch(namespace, "all", 0),), 0, 0,
        "catalogue-1", "scheme-1", "operator-1", "policy-1", (), (), (),
    )
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((source,), "observed", 1.0, 2.0,
                            "external_observation", "eligible", 0.8,
                            "not_applicable"),
        (), "parent", 100.0, 100.0, "character-1", (),
    )
    schema = ActionSchemaRecord.bind(intent, ActionSchema(
        intent.schema_id, intent.action_kind, False, intent.required_checks,
    ))
    use = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    claim = ExpressionClaim(
        "claim:one", "Hello", ClaimKind.EXTERNAL_FACT, (source,),
        ("entity:user",), ("expression",), "disclosure:one",
    )
    blueprint = D09ExpressionProvider.prepare_blueprint(
        grant, "scene:one", 1, (claim,), now=1.0,
    ).blueprint
    assert blueprint is not None
    segments = (SegmentCandidate(
        "segment:one", "effect:one", "Hello", (use,), ("answer",), (), 0.0,
    ),)
    return envelope, intent, schema, grant, blueprint, segments


def test_candidate_assembles_one_atomic_bundle_without_admission():
    envelope, intent, schema, grant, blueprint, segments = _inputs()
    candidate = assemble_initial_reactive_candidate(
        envelope, intent, schema, grant, blueprint, segments, now_utc=1.0,
    )
    assert candidate.evidence.status == "source_hold"
    assert tuple(item.domain for item in candidate.bundle.proposals) == ("d08", "d09")
    assert "d08.current_execution_and_cancellation" in candidate.missing_for_admission
    assert len(candidate.bundle.proposals[0].typed_writes) == 4
    assert len(candidate.bundle.proposals[1].typed_writes) == 1
    current = candidate.bundle.envelope
    assert candidate.bundle.proposals[0].envelope is current
    assert candidate.bundle.proposals[1].envelope is current
    state = candidate.bundle.proposals[0].typed_writes[2]
    assert state.key.type_name == "d08.action_cancellation.v1"
    assert (state.value["state"], state.value["cancel_epoch"]) == ("active", 0)
    assert GraphVersion(state.key, 0) in current.version_guard.read_versions


def test_reactive_assembly_rejects_missing_source_and_changed_segment():
    envelope, intent, schema, grant, blueprint, segments = _inputs()
    with pytest.raises(ValueError, match="source or grant"):
        assemble_initial_reactive_candidate(
            envelope, replace(intent, source_refs=("source:other",)), schema,
            grant, blueprint, segments, now_utc=1.0,
        )
    with pytest.raises(ValueError):
        assemble_initial_reactive_candidate(
            envelope, intent, schema, grant, blueprint,
            (replace(segments[0], body="Changed"),), now_utc=1.0,
        )
