"""Bilateral acceptance stays separate from offered or unknown communication."""

from dataclasses import replace

import pytest

from sylanne3.domains.d08 import (
    BilateralAcknowledgementReadV1, Commitment, GoalExecutionProvider,
    prepare_coordinator_bilateral_acknowledgement_write_v1,
    propose_bilateral_acknowledgement_v1,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime_contracts import NamespaceId, VersionedRef

from rewrite.tests.alpha1.d08.test_goal_execution_domain import _proposal


def _read():
    namespace = NamespaceId("bot", "persona")
    commitment = Commitment(
        "commitment:art", 2, "persona:persona", "entity:alice",
        "send artifact:sketch", "bilateral", "offered", "pending", None,
        (), (), "commitment:art@1", ("source:offer",),
    )
    head = GraphVersion(AtomKey(Owner("persona", "bot", "persona"),
                                "d08.commitment.v1", commitment.commitment_id), 2)
    return BilateralAcknowledgementReadV1(
        namespace, commitment, head, VersionedRef("receipt:outbound", 4),
        "accepted", GraphVersion(source_key("bot", "persona", "inbound-1"), 3),
        GraphVersion(access_key("bot", "persona", "inbound-1"), 2),
        "entity:alice", commitment.commitment_id, commitment.semantic_scope,
        "accepted", "full",
    )


def test_confirmed_acceptance_produces_versioned_candidate_without_fulfilling_work():
    read = _read()
    candidate = propose_bilateral_acknowledgement_v1(
        read, read_verifier=lambda observed: observed is read,
    )
    assert candidate.status == "candidate"
    assert candidate.commitment is not None
    assert candidate.commitment.establishment_state == "acknowledged"
    assert candidate.commitment.fulfillment_state == "pending"
    assert candidate.commitment.revision == 3
    assert candidate.commitment.communicated_refs == ("receipt:outbound",)
    assert candidate.commitment.acknowledged_refs == (read.inbound_source.key.token,)
    assert candidate.commitment.source_refs == ("source:offer", read.inbound_source.key.token)
    assert candidate.required_versions == (
        read.commitment_head, read.inbound_source, read.inbound_access,
    )
    assert read.commitment.establishment_state == "offered"


@pytest.mark.parametrize("change, reason", [
    ({"outbound_status": "unknown"}, "outbound_unknown"),
    ({"outbound_status": "known_not_accepted"}, "outbound_not_accepted"),
    ({"acceptance_result": "unknown"}, "inbound_not_confirmed"),
    ({"acceptance_result": "disputed"}, "inbound_not_confirmed"),
    ({"inbound_actor_ref": "entity:bob"}, "commitment_scope"),
    ({"accepted_scope": "send artifact:other"}, "commitment_scope"),
    ({"coverage": "partial"}, "current_read_unavailable"),
])
def test_unknown_or_wrong_scope_never_becomes_agreement(change, reason):
    read = replace(_read(), **change)
    result = propose_bilateral_acknowledgement_v1(
        read, read_verifier=lambda _: True,
    )
    assert result.status == "hold"
    assert result.commitment is None
    assert result.reasons == (reason,)


def test_unverified_source_and_unilateral_offer_cannot_upgrade():
    read = _read()
    assert propose_bilateral_acknowledgement_v1(
        read, read_verifier=None,
    ).reasons == ("current_read_unavailable",)
    assert propose_bilateral_acknowledgement_v1(
        read, read_verifier=lambda _: False,
    ).reasons == ("current_read_unverified",)
    unilateral = replace(read, commitment=replace(
        read.commitment, establishment_kind="unilateral"))
    assert propose_bilateral_acknowledgement_v1(
        unilateral, read_verifier=lambda _: True,
    ).reasons == ("commitment_scope",)
    with pytest.raises(ValueError, match="inbound source heads"):
        replace(read, inbound_access=GraphVersion(
            access_key("bot", "persona", "another-source"), 2,
        ))


def test_ordinary_proposal_cannot_write_acknowledged_and_coordinator_path_is_explicit():
    read = _read()
    candidate, write = prepare_coordinator_bilateral_acknowledgement_write_v1(
        read, read_verifier=lambda observed: observed is read,
    )
    assert candidate.required_versions[0] == read.commitment_head
    assert write.key == read.commitment_head.key
    assert write.dependencies == (read.inbound_source.key, read.inbound_access.key)
    with pytest.raises(ValueError, match="privileged bilateral evidence"):
        GoalExecutionProvider().validate(_proposal(writes=(write,)))
    with pytest.raises(ValueError, match="not current"):
        prepare_coordinator_bilateral_acknowledgement_write_v1(
            read, read_verifier=lambda _: False,
        )
