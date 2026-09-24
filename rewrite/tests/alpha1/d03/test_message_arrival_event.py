"""A received message is a host fact; its content remains a report."""

from dataclasses import replace

import pytest

from sylanne3.domains.d03 import build_message_arrival_candidate
from sylanne3.domains.d06 import D06DomainAdapter
from sylanne3.graph_types import GraphVersion
from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.host.d06_ingress import source_admission_from_host
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import NamespaceId


def _case():
    namespace = NamespaceId("bot-1", "persona-1")
    ingress = HostIngressEnvelope(
        namespace, '["platform","aiocqhttp","self"]', '["umo","conversation"]',
        '["platform","sender"]', "message-1", "我昨天去了火星", 10.0, 11.0,
        "private", SourceLineage("a" * 64, "reported", "platform-family",
                                 "external_report", "reported_claim"),
    )
    scene = CurrentHostScene(
        namespace, ingress.platform_ref, ingress.conversation_ref, ingress.visibility,
        scene_ref_for_conversation(namespace, ingress.platform_ref, ingress.conversation_ref),
    )
    admitted = D06DomainAdapter(namespace).admit_source(source_admission_from_host(ingress))
    source_version = GraphVersion(source_key(*namespace.as_tuple, admitted.source.source_id), 1)
    access_version = GraphVersion(access_key(*namespace.as_tuple, admitted.source.source_id), 1)
    return ingress, scene, admitted, source_version, access_version


def test_arrival_is_deterministic_host_fact_with_account_anchor_only():
    ingress, scene, admitted, source_version, access_version = _case()
    candidate = build_message_arrival_candidate(
        ingress, scene, admitted.source, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    repeated = build_message_arrival_candidate(
        ingress, scene, admitted.source, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    assert candidate == repeated
    assert candidate.sender_anchor.kind == "account"
    assert candidate.event.kind == "message_received"
    assert candidate.event.reality == "host_observed"
    assert candidate.event.participant_roles == ((candidate.sender_anchor.entity_id, "sender_account"),)
    assert admitted.source.occurred_at == 10.0
    assert candidate.event.occurred_from == candidate.event.occurred_until == 11.0
    assert candidate.event.learned_at == 11.0
    assert candidate.event.scene_ref == scene.scene_ref
    assert candidate.event.source_refs == (source_version.key.token,)
    assert admitted.source.assertion_status == "reported"
    assert candidate.source_version == source_version
    assert candidate.access_version == access_version


def test_arrival_rejects_a_mismatched_sender_scene_or_source_revision():
    ingress, scene, admitted, source_version, access_version = _case()
    kwargs = {"source_version": source_version, "access_version": access_version}
    for changed_ingress, changed_scene, changed_source, changed_qualification, changed_kwargs in (
        (replace(ingress, sender_ref='["platform","other"]'), scene,
         admitted.source, admitted.qualification, kwargs),
        (ingress, replace(scene, scene_ref="scene:other"),
         admitted.source, admitted.qualification, kwargs),
        (ingress, scene, replace(admitted.source, assertion_status="confirmed"),
         admitted.qualification, kwargs),
        (ingress, scene, admitted.source, admitted.qualification,
         {**kwargs, "access_version": GraphVersion(access_version.key, 0)}),
    ):
        with pytest.raises(ValueError):
            build_message_arrival_candidate(
                changed_ingress, changed_scene, changed_source, changed_qualification,
                **changed_kwargs,
            )


def test_unknown_platform_occurrence_does_not_invent_time():
    ingress, scene, admitted, source_version, access_version = _case()
    ingress = replace(ingress, occurred_at=None)
    admitted = D06DomainAdapter(ingress.namespace).admit_source(source_admission_from_host(ingress))
    candidate = build_message_arrival_candidate(
        ingress, scene, admitted.source, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    assert admitted.source.occurred_at is None
    assert candidate.event.occurred_from == ingress.learned_at
    assert candidate.event.occurred_until == ingress.learned_at
    assert candidate.event.learned_at == ingress.learned_at
