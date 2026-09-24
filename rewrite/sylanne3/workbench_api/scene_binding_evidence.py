"""Pure D06 source proposals for one Owner scene-binding operation.

These values are inputs to a later graph transaction, not binding authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re

from ..domains.d06 import D06DomainAdapter, SourceAdmission, SourceAdmissionProposal
from ..graph_types import AtomKey
from ..host.current_scene import CurrentHostScene
from ..memory_types import access_key, source_key, validate_access
from ..runtime.first_ingress_v2 import scene_ref_for_conversation
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEAD = re.compile(r"(?:genesis|sha256:[0-9a-f]{64})\Z")


@dataclass(frozen=True, slots=True)
class SceneBindingSource:
    admission: SourceAdmission
    proposal: SourceAdmissionProposal
    source_key: AtomKey
    access_key: AtomKey

    @property
    def source_value(self) -> dict:
        return self.proposal.source.to_dict()

    @property
    def access_value(self) -> dict:
        source = self.proposal.source
        return {
            "source_id": source.source_id,
            "audiences": list(source.audiences),
            "purposes": list(source.purposes),
            "status": "active",
            "recorded_at": source.recorded_at,
        }


@dataclass(frozen=True, slots=True)
class SceneBindingEvidence:
    namespace: NamespaceId
    scene: CurrentHostScene
    owner_actor: str
    operation_id: str
    request_digest: str
    authorization_head: str
    observed_at: float
    owner_config: SceneBindingSource
    host_identity: SceneBindingSource


def _source(
    domain: D06DomainAdapter, *, source_id: str, text: str, speaker_id: str,
    source_kind: str, content_reality: str, evidence_eligibility: str,
    provenance_family: str, observed_at: float,
) -> SceneBindingSource:
    admission = SourceAdmission(
        source_id=source_id, text=text, speaker_id=speaker_id,
        source_kind=source_kind, content_reality=content_reality,
        evidence_eligibility=evidence_eligibility,
        internal_activity_actuality="not_applicable",
        occurred_at=observed_at, learned_at=observed_at,
        provenance_family=provenance_family, audiences=("owner",),
        purposes=("context", "audit"),
    )
    proposal = domain.admit_source(admission)
    namespace = domain.namespace
    result = SceneBindingSource(
        admission, proposal,
        source_key(*namespace.as_tuple, source_id),
        access_key(*namespace.as_tuple, source_id),
    )
    validate_access(result.access_value)
    return result


def build_scene_binding_evidence(
    *, namespace: NamespaceId, scene: CurrentHostScene, owner_actor: str,
    operation_id: str, request_digest: str, authorization_head: str,
    observed_at: float,
) -> SceneBindingEvidence:
    """Build two same-namespace source proposals from a trusted host observation."""
    if type(namespace) is not NamespaceId or type(scene) is not CurrentHostScene:
        raise TypeError("namespace and current host scene are required")
    if scene.namespace != namespace:
        raise ValueError("host scene would cross namespace")
    if scene.scene_ref != scene_ref_for_conversation(
        namespace, scene.platform_ref, scene.conversation_ref,
    ):
        raise ValueError("host scene identity mismatch")
    if scene.visibility not in {"private", "group"}:
        raise ValueError("invalid host scene visibility")
    if any(type(value) is not str or not value.strip()
           for value in (owner_actor, operation_id)):
        raise ValueError("Owner actor and operation are required")
    if type(request_digest) is not str or not _DIGEST.fullmatch(request_digest):
        raise ValueError("invalid request digest")
    if type(authorization_head) is not str or not _HEAD.fullmatch(authorization_head):
        raise ValueError("invalid authorization head")
    if type(observed_at) not in (int, float) or not math.isfinite(observed_at) or observed_at < 0:
        raise ValueError("observed_at must be a finite nonnegative time")
    observed_at = float(observed_at)
    common = {
        "namespace": list(namespace.as_tuple),
        "scene_ref": scene.scene_ref,
        "visibility": scene.visibility,
    }
    config = {
        "schema": "sylanne.scene-binding.owner-config.v1", **common,
        "owner_actor": owner_actor, "operation_id": operation_id,
        "request_digest": request_digest, "authorization_head": authorization_head,
    }
    identity = {
        "schema": "sylanne.scene-binding.host-identity.v1", **common,
        "platform_ref": scene.platform_ref,
        "conversation_ref": scene.conversation_ref,
    }
    domain = D06DomainAdapter(namespace)
    owner_config = _source(
        domain, source_id="scene-owner-config:" + canonical_digest({**config, "observed_at": observed_at}),
        text=canonical_serialize(config), speaker_id=owner_actor,
        source_kind="authored", content_reality="authored",
        evidence_eligibility="none", provenance_family="owner.scene-binding.config.v1",
        observed_at=observed_at,
    )
    host_identity = _source(
        domain, source_id="scene-host-identity:" + canonical_digest({
            **identity, "operation_id": operation_id, "observed_at": observed_at,
        }),
        text=canonical_serialize(identity), speaker_id="astrbot.host",
        source_kind="observed", content_reality="observed",
        evidence_eligibility="external_fact",
        provenance_family="astrbot.host.scene-identity.v1", observed_at=observed_at,
    )
    return SceneBindingEvidence(
        namespace, scene, owner_actor, operation_id, request_digest,
        authorization_head, observed_at, owner_config, host_identity,
    )
