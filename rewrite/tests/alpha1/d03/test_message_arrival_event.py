"""A received message is a host fact; its content remains a report."""

from dataclasses import dataclass, replace

import pytest

from sylanne3.domains.d03 import build_message_arrival_candidate
from sylanne3.domains.d06 import D06DomainAdapter
from sylanne3.graph_types import GraphVersion
from sylanne3.host.d06_ingress import source_admission_from_host
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import NamespaceId


@dataclass(frozen=True)
class _Scene:
    namespace: NamespaceId
    platform_ref: str
    conversation_ref: str
    visibility: str
    scene_ref: str


def _case():
    namespace = NamespaceId("bot-1", "persona-1")
    ingress = HostIngressEnvelope(
        namespace, '["platform","aiocqhttp","self"]', '["umo","conversation"]',
        '["platform","sender"]', "message-1", "我昨天去了火星", 10.0, 11.0,
        "private", SourceLineage("a" * 64, "reported", "platform-family",
                                 "external_report", "reported_claim"),
    )
    scene = _Scene(
        namespace, ingress.platform_ref, ingress.conversation_ref,
        ingress.visibility,
        scene_ref_for_conversation(namespace, ingress.platform_ref, ingress.conversation_ref),
    )
    admission = source_admission_from_host(ingress)
    admitted = D06DomainAdapter(namespace).admit_source(admission)
    access = {
        "source_id": admission.source_id,
        "audiences": list(admission.audiences),
        "purposes": list(admission.purposes),
        "status": "active",
        "recorded_at": admission.learned_at,
    }
    source_version = GraphVersion(source_key(*namespace.as_tuple, admitted.source.source_id), 1)
    access_version = GraphVersion(access_key(*namespace.as_tuple, admitted.source.source_id), 1)
    return ingress, scene, admitted, access, source_version, access_version


def test_arrival_is_deterministic_host_fact_with_account_anchor_only():
    ingress, scene, admitted, access, source_version, access_version = _case()
    candidate = build_message_arrival_candidate(
        ingress, scene, admitted.source, access, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    repeated = build_message_arrival_candidate(
        ingress, scene, admitted.source, access, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    assert candidate == repeated
    assert candidate.sender_anchor.kind == "account"
    assert candidate.account_binding.account_id.startswith("account:")
    assert candidate.account_binding_key.name == candidate.account_binding.account_id
    assert candidate.account_binding.entity_id == candidate.sender_anchor.entity_id
    assert candidate.account_binding.platform_namespace == ingress.platform_ref
    assert candidate.account_binding.platform_identifier == ingress.sender_ref
    assert candidate.account_binding.verification_ref == candidate.event_key.token
    assert candidate.account_binding.valid_from == candidate.event.learned_at
    assert candidate.account_binding.valid_until is None
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


def test_account_identity_is_stable_across_messages_and_distinct_by_platform_or_sender():
    ingress, scene, admitted, access, source_version, access_version = _case()

    def arrival(current_ingress):
        current_scene = replace(
            scene, platform_ref=current_ingress.platform_ref,
            scene_ref=scene_ref_for_conversation(
                current_ingress.namespace, current_ingress.platform_ref,
                current_ingress.conversation_ref,
            ),
        )
        current_admission = D06DomainAdapter(current_ingress.namespace).admit_source(
            source_admission_from_host(current_ingress)
        )
        current_source_version = GraphVersion(
            source_key(*current_ingress.namespace.as_tuple, current_admission.source.source_id), 1,
        )
        current_access_version = GraphVersion(
            access_key(*current_ingress.namespace.as_tuple, current_admission.source.source_id), 1,
        )
        return build_message_arrival_candidate(
            current_ingress, current_scene, current_admission.source,
            {**access, "source_id": current_admission.source.source_id},
            current_admission.qualification,
            source_version=current_source_version,
            access_version=current_access_version,
        )

    first = arrival(ingress)
    another_message = arrival(replace(ingress, message_id="message-2"))
    another_sender = arrival(replace(ingress, sender_ref='["platform","other"]'))
    another_platform = arrival(replace(ingress, platform_ref='["platform","other"]'))
    assert another_message.account_binding.account_id == first.account_binding.account_id
    assert another_message.account_binding_key == first.account_binding_key
    assert another_message.event_key != first.event_key
    assert another_message.account_binding.verification_ref == another_message.event_key.token
    assert another_sender.account_binding.account_id != first.account_binding.account_id
    assert another_platform.account_binding.account_id != first.account_binding.account_id


def test_arrival_rejects_a_mismatched_sender_scene_or_source_revision():
    ingress, scene, admitted, access, source_version, access_version = _case()
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
                changed_ingress, changed_scene, changed_source, access,
                changed_qualification,
                **changed_kwargs,
            )


def test_unknown_platform_occurrence_does_not_invent_time():
    ingress, scene, admitted, access, source_version, access_version = _case()
    ingress = replace(ingress, occurred_at=None)
    admitted = D06DomainAdapter(ingress.namespace).admit_source(source_admission_from_host(ingress))
    candidate = build_message_arrival_candidate(
        ingress, scene, admitted.source, access, admitted.qualification,
        source_version=source_version, access_version=access_version,
    )
    assert admitted.source.occurred_at is None
    assert candidate.event.occurred_from == ingress.learned_at
    assert candidate.event.occurred_until == ingress.learned_at
    assert candidate.event.learned_at == ingress.learned_at


def test_arrival_rejects_a_removed_current_access_record():
    ingress, scene, admitted, access, source_version, access_version = _case()
    access["status"] = "withdrawn"
    with pytest.raises(ValueError, match="current qualified source differs"):
        build_message_arrival_candidate(
            ingress, scene, admitted.source, access, admitted.qualification,
            source_version=source_version, access_version=access_version,
        )
