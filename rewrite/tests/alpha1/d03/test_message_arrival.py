"""A committed D06 source, rather than the host clock, anchors D03 arrival."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.domains.d03.message_arrival import build_message_arrival_candidate
from sylanne3.domains.d06 import D06DomainAdapter, SourceAdmission
from sylanne3.graph_types import GraphVersion
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import NamespaceId


def _inputs(occurred_at=10.0):
    namespace = NamespaceId("bot", "persona")
    ingress = HostIngressEnvelope(
        namespace, "platform", "conversation", "sender", "message", "hello",
        occurred_at, 11.0, "private",
        SourceLineage("a" * 64, "reported", "platform-source", "external_report",
                      "reported_claim"),
    )
    # The v2 ingress replaces the host's proposed learned_at with the paired
    # Authority sample before D06 writes the source.
    admitted = D06DomainAdapter(namespace).admit_source(SourceAdmission(
        "a" * 64, "hello", "sender", "reported", "reported",
        "reported_claim", "not_applicable", occurred_at, 20.0,
        "platform-source", ("conversation",), ("context", "consolidation"),
    ))
    scene = SimpleNamespace(
        namespace=namespace, platform_ref="platform",
        conversation_ref="conversation", visibility="private",
        scene_ref=scene_ref_for_conversation(namespace, "platform", "conversation"),
    )
    source_version = GraphVersion(source_key("bot", "persona", "a" * 64), 1)
    access_version = GraphVersion(access_key("bot", "persona", "a" * 64), 1)
    access = {
        "source_id": admitted.source.source_id,
        "audiences": ["conversation"], "purposes": ["context", "consolidation"],
        "status": "active", "recorded_at": 20.0,
    }
    return ingress, scene, admitted, access, source_version, access_version


@pytest.mark.parametrize("occurred_at", [10.0, None])
def test_arrival_uses_authority_receipt_time_not_host_receive_candidate(occurred_at):
    ingress, scene, admitted, access, source_version, access_version = _inputs(occurred_at)
    candidate = build_message_arrival_candidate(
        ingress, scene, admitted.source, access, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    assert candidate.event.occurred_from == 20.0
    assert candidate.event.occurred_until == 20.0
    assert candidate.event.learned_at == 20.0
    assert admitted.source.occurred_at == occurred_at
    assert candidate.event.reality == "host_observed"
    assert candidate.event.participant_roles == ((candidate.sender_anchor.entity_id,
                                                  "sender_account"),)


def test_arrival_rejects_source_and_qualification_time_disagreement():
    ingress, scene, admitted, access, source_version, access_version = _inputs()
    wrong = replace(admitted.qualification, learned_at=21.0)
    with pytest.raises(ValueError, match="qualified source differs"):
        build_message_arrival_candidate(
            ingress, scene, admitted.source, access, wrong,
            source_version=source_version, access_version=access_version,
        )


def test_arrival_rejects_currently_withdrawn_access():
    ingress, scene, admitted, access, source_version, access_version = _inputs()
    access["status"] = "withdrawn"
    with pytest.raises(ValueError, match="qualified source differs"):
        build_message_arrival_candidate(
            ingress, scene, admitted.source, access, admitted.qualification,
            source_version=source_version, access_version=access_version,
        )
