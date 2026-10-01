"""DomainBundle accepts the existing D04 joint evidence without changing old digests."""

from dataclasses import fields, replace
import json

import pytest

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime.d04_joint_advance_v2 import (
    ProductAdvanceEvidenceV2,
    ProductAdvanceMemberV2,
)
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    DomainBundle,
    NamespaceId,
    OperationIdentity,
    ProductAdvanceEvidenceV1,
    QueryEpoch,
    SourceQualification,
    VersionGuard,
    canonical_digest,
    canonical_serialize,
)


SHA = "a" * 64
NAMESPACE = NamespaceId("bot", "persona")
OWNER = Owner("persona", "bot", "persona")


def _envelope() -> CommandEnvelope:
    return CommandEnvelope(
        schema="sylanne.runtime.v1",
        identity=OperationIdentity(
            "activity", None, "attempt", "prepare", "operation",
            canonical_digest({"input_refs": ["input"]}),
        ),
        authority=AuthorityContext(
            "actor", "d11", "capability", NAMESPACE, ("persona",),
            "respond", ("audience",), "policy", 1,
        ),
        version_guard=VersionGuard(
            (GraphVersion(AtomKey(OWNER, "state", "read"), 0),),
            (QueryEpoch(NAMESPACE, "query", 0),),
            0, 0, "catalogue", "scheme", "operator", "policy", (), (), (),
        ),
        source_qualification=SourceQualification(
            ("source",), "observed", 0.0, 0.0,
            "external_observation", "eligible", 0.5, "not_applicable",
        ),
        input_refs=("input",),
        parent_budget_lease_ref="budget",
        deadline_utc=1.0,
        monotonic_deadline=1.0,
        character_interval_ref="interval",
        causation=(),
    )


def _bundle(product_advance=None) -> DomainBundle:
    return DomainBundle(
        _envelope(), (), (), (), (), (), (), (), (), product_advance,
    )


def _joint_evidence(namespace: NamespaceId = NAMESPACE) -> ProductAdvanceEvidenceV2:
    owner = Owner("persona", namespace.bot_id, namespace.persona_id)
    members = []
    for name in ("a", "b"):
        checkpoint = AtomKey(owner, "d04.numeric_checkpoint.v1", name).token
        state = AtomKey(owner, "d04.feeling_state.v1", name).token
        members.append(ProductAdvanceMemberV2(
            checkpoint, "root", 1, SHA, state, 1, SHA, SHA, 0.0,
            2, SHA, 0.0, state, 2, SHA,
        ))
    return ProductAdvanceEvidenceV2(
        "d11.product_advance_evidence.v2", namespace, "operation", SHA,
        "process", "replay", 0.0, 1.0, tuple(members), SHA,
        "incarnation", 0, 0, 0, 0, SHA, SHA, SHA, SHA, SHA,
        SHA, SHA, SHA, SHA, SHA, SHA, (("family", SHA),), SHA, SHA,
    )


def test_joint_evidence_is_typed_and_bound_to_bundle_identity() -> None:
    provisional = _joint_evidence()
    base = _bundle()
    operation_digest = base.v2_digest_with(provisional)
    evidence = replace(provisional, bundle_digest=operation_digest)
    bundle = _bundle(evidence)
    assert bundle.product_advance is evidence
    assert bundle.digest == operation_digest
    wire = json.loads(canonical_serialize(bundle))
    del wire["product_advance"]["bundle_digest"]
    del wire["root_adoption"]
    assert bundle.digest == canonical_digest(wire)
    assert base.v2_digest_with(replace(provisional, bundle_digest="b" * 64)) == operation_digest
    assert base.v2_digest_with(replace(provisional, process_id="other-process")) != operation_digest
    assert base.v2_digest_with(replace(provisional, members=tuple(
        replace(member, next_value_digest="b" * 64) if index == 0 else member
        for index, member in enumerate(provisional.members)
    ))) != operation_digest
    with pytest.raises(ValueError, match="bundle digest differs"):
        _bundle(provisional)
    with pytest.raises(ValueError, match="bundle digest differs"):
        _bundle(replace(evidence, process_id="other-process"))
    with pytest.raises(TypeError, match="typed product evidence"):
        _bundle(object())
    with pytest.raises(ValueError, match="scope and operation"):
        _bundle(_joint_evidence(NamespaceId("other", "persona")))
    with pytest.raises(ValueError, match="scope and operation"):
        _bundle(replace(evidence, operation_id="other-operation"))


def test_legacy_bundle_digest_rules_are_unchanged() -> None:
    empty = _bundle()
    legacy = {
        "$type": f"{type(empty).__module__}.{type(empty).__qualname__}",
        **{field.name: getattr(empty, field.name) for field in fields(empty)
           if field.name not in {"product_advance", "root_adoption"}},
    }
    assert empty.digest == canonical_digest(legacy)

    feeling = AtomKey(OWNER, "d04.feeling_state.v1", "a").token
    mood = AtomKey(OWNER, "d04.mood_field.v1", "a").token
    old_evidence = ProductAdvanceEvidenceV1(
        "d11.product_advance_candidate.v1", feeling, mood, "parent", "replay",
        0.0, 1.0, SHA, SHA, SHA, SHA, SHA, 0.0, 0.0,
    )
    old_bundle = _bundle(old_evidence)
    old_wire = {
        "$type": f"{type(old_bundle).__module__}.{type(old_bundle).__qualname__}",
        **{field.name: getattr(old_bundle, field.name) for field in fields(old_bundle)
           if field.name != "root_adoption"},
    }
    assert old_bundle.digest == canonical_digest(old_wire)
