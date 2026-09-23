"""Current-message D03 scene binding applicability checks.

This module evaluates a current scene binding against one host ingress and a
fresh paired D01/D03 graph read.  It is evidence for D11; it is not send
authority.  The caller must supply worker-backed readers and host-owned scope
mapping.  A RoleBinding stored in the graph by itself is never sufficient.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from ...domains.d01 import ActiveRoleQualification
from ...graph_types import GraphVersion
from ...host.ingress import HostIngressEnvelope
from ...runtime_contracts import NamespaceId, VersionedRef
from .context import RoleBinding


def _identifier(value: object, name: str, prefix: str | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError(f"{name} must be a bounded nonempty string")
    if prefix is not None and not value.startswith(prefix):
        raise ValueError(f"{name} must start with {prefix!r}")
    return value


def _positive_version(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive exact integer")
    return value


@dataclass(frozen=True)
class SceneIngressScopeV1:
    """Host-owned mapping and action scope for one ingress message.

    This value must come from the trusted host ingress/scene mapper.  It must
    never be decoded from message text, a model result, or a dashboard request.
    """

    namespace: NamespaceId
    platform_ref: str
    conversation_ref: str
    scene_ref: str
    scope_ref: str
    scope_selector: str
    subject_persona_ref: str
    target_entity_ref: str | None
    group_ref: str | None
    action_kind: str
    purpose: str
    at_time: float | None
    identity_mapping_version: int
    time_mapping_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        for name in ("platform_ref", "conversation_ref", "scope_ref", "scope_selector", "action_kind", "purpose"):
            _identifier(getattr(self, name), name)
        _identifier(self.scene_ref, "scene_ref", "scene:")
        _identifier(self.subject_persona_ref, "subject_persona_ref", "persona:")
        if self.target_entity_ref is not None:
            _identifier(self.target_entity_ref, "target_entity_ref", "entity:")
        if self.group_ref is not None:
            _identifier(self.group_ref, "group_ref")
        if self.at_time is not None and (
            type(self.at_time) not in (int, float) or not math.isfinite(self.at_time) or self.at_time <= 0
        ):
            raise ValueError("at_time must be finite and positive when known")
        _positive_version(self.identity_mapping_version, "identity_mapping_version")
        _positive_version(self.time_mapping_version, "time_mapping_version")


@dataclass(frozen=True)
class NormApplicabilityEvidenceV1:
    """Current D03 norm-policy resolution for the requested action."""

    namespace: NamespaceId
    scene_ref: str
    binding_id: str
    binding_version: int
    graph_epoch: int
    status: str
    norm_refs: tuple[str, ...]
    action_kinds: tuple[str, ...]
    purposes: tuple[str, ...]
    platform_refs: tuple[str, ...]
    scope_selectors: tuple[str, ...]
    visibility_scopes: tuple[str, ...]
    policy_version: int
    valid_until: float

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        _identifier(self.scene_ref, "scene_ref", "scene:")
        _identifier(self.binding_id, "binding_id", "binding:")
        _positive_version(self.binding_version, "binding_version")
        _positive_version(self.graph_epoch, "graph_epoch")
        if self.status not in {"complete", "partial", "unavailable", "stale"}:
            raise ValueError("unsupported norm applicability status")
        for name in ("norm_refs", "action_kinds", "purposes", "platform_refs", "scope_selectors", "visibility_scopes"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or any(not isinstance(item, str) or not item for item in values):
                raise ValueError(f"{name} must be a tuple of nonempty strings")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicates")
        _positive_version(self.policy_version, "policy_version")
        if type(self.valid_until) not in (int, float) or not math.isfinite(self.valid_until) or self.valid_until <= 0:
            raise ValueError("valid_until must be finite and positive")


@dataclass(frozen=True)
class SceneBindingApplicabilityV1:
    status: str
    reasons: tuple[str, ...]
    scene_ref: str | None
    role_head_id: str | None
    binding_id: str | None
    binding_version: int | None
    graph_epoch: int | None
    input_versions: tuple[VersionedRef, ...]
    valid_until: float | None

    def __post_init__(self) -> None:
        if self.status not in {"applicable", "unknown", "inapplicable"}:
            raise ValueError("unsupported scene applicability status")
        if not isinstance(self.reasons, tuple) or any(not isinstance(item, str) or not item for item in self.reasons):
            raise ValueError("reasons must be a tuple of nonempty strings")
        if not isinstance(self.input_versions, tuple) or any(
            not isinstance(item, VersionedRef) for item in self.input_versions
        ):
            raise TypeError("input_versions must contain VersionedRef values")
        if self.status == "applicable" and (
            not self.scene_ref
            or not self.role_head_id
            or not self.binding_id
            or self.binding_version is None
            or self.graph_epoch is None
            or self.valid_until is None
        ):
            raise ValueError("applicable result requires the current binding and role versions")


CurrentSceneReader = Callable[[], tuple[ActiveRoleQualification, RoleBinding | None]]


def check_current_scene_applicability(
    envelope: HostIngressEnvelope,
    scope: SceneIngressScopeV1 | None,
    *,
    current_scene_reader: CurrentSceneReader | None,
    norm_evidence: NormApplicabilityEvidenceV1 | None,
) -> SceneBindingApplicabilityV1:
    """Check applicability for this message using a fresh worker-backed read.

    ``current_scene_reader`` must invoke ``read_active_scene_v2`` through the
    authorized GraphWorker for the exact namespace/scene captured in ``scope``.
    Its result is discarded on every invocation so a cached RoleBinding cannot
    satisfy this check.  The graph API currently does not return its own read
    receipt; the worker integration remains responsible for preserving that
    trusted call boundary.
    """
    if not isinstance(envelope, HostIngressEnvelope):
        raise TypeError("host ingress envelope is required")
    if scope is None:
        return _unknown("host_scene_scope_missing")
    if not isinstance(scope, SceneIngressScopeV1):
        raise TypeError("scope must be a host-owned SceneIngressScopeV1")

    missing = []
    if scope.namespace != envelope.namespace:
        return _inapplicable("namespace_mismatch", scope.scene_ref)
    if scope.platform_ref != envelope.platform_ref:
        return _inapplicable("platform_mismatch", scope.scene_ref)
    if scope.conversation_ref != envelope.conversation_ref or scope.scope_ref != envelope.conversation_ref:
        return _inapplicable("conversation_scope_mismatch", scope.scene_ref)
    if scope.subject_persona_ref != f"persona:{envelope.namespace.persona_id}":
        return _inapplicable("persona_mismatch", scope.scene_ref)
    if envelope.occurred_at is None or scope.at_time is None:
        missing.append("message_occurrence_time_unknown")
    elif scope.at_time != envelope.occurred_at:
        return _inapplicable("message_time_mismatch", scope.scene_ref)
    if scope.action_kind.strip() == "" or scope.purpose.strip() == "":
        missing.append("action_scope_missing")
    if missing:
        return _unknown(*missing, scene_ref=scope.scene_ref)
    if current_scene_reader is None:
        return _unknown("current_fenced_scene_read_missing", scene_ref=scope.scene_ref)

    try:
        read = current_scene_reader()
    except Exception:
        return _unknown("current_fenced_scene_read_unavailable", scene_ref=scope.scene_ref)
    if (
        type(read) is not tuple
        or len(read) != 2
        or type(read[0]) is not ActiveRoleQualification
        or (read[1] is not None and type(read[1]) is not RoleBinding)
    ):
        return _unknown("current_fenced_scene_read_invalid", scene_ref=scope.scene_ref)
    role, binding = read
    if role.namespace != scope.namespace or role.plan.namespace != scope.namespace:
        return _unknown("current_role_namespace_mismatch", scene_ref=scope.scene_ref)
    if role.graph_epoch < 1 or not role.head_id:
        return _unknown("current_role_version_missing", scene_ref=scope.scene_ref)
    if binding is None:
        return _inapplicable("no_current_scene_binding", scope.scene_ref, role=role)
    if binding.scene_ref != scope.scene_ref or binding.subject_persona_ref != scope.subject_persona_ref:
        return _inapplicable("binding_scope_mismatch", scope.scene_ref, role=role, binding=binding)
    if binding.status != "active":
        return _inapplicable("binding_not_active", scope.scene_ref, role=role, binding=binding)
    if binding.scope_selector != scope.scope_selector:
        return _inapplicable("scope_selector_mismatch", scope.scene_ref, role=role, binding=binding)
    if binding.visibility_scope != envelope.visibility:
        return _inapplicable("visibility_scope_mismatch", scope.scene_ref, role=role, binding=binding)
    if binding.target_entity_ref is not None and binding.target_entity_ref != scope.target_entity_ref:
        return _inapplicable("target_scope_mismatch", scope.scene_ref, role=role, binding=binding)
    if binding.group_ref is not None and binding.group_ref != scope.group_ref:
        return _inapplicable("group_scope_mismatch", scope.scene_ref, role=role, binding=binding)
    if (
        scope.at_time < binding.effective_from
        or envelope.learned_at < binding.effective_from
        or (
            binding.effective_until is not None
            and (scope.at_time > binding.effective_until or envelope.learned_at > binding.effective_until)
        )
    ):
        return _inapplicable("binding_outside_effective_interval", scope.scene_ref, role=role, binding=binding)
    if norm_evidence is None:
        return _unknown("current_norm_applicability_missing", scene_ref=scope.scene_ref, role=role, binding=binding)
    if type(norm_evidence) is not NormApplicabilityEvidenceV1:
        raise TypeError("norm_evidence must be current D03 norm-policy evidence")
    if (
        norm_evidence.namespace != scope.namespace
        or norm_evidence.scene_ref != scope.scene_ref
        or norm_evidence.binding_id != binding.role_binding_id
        or norm_evidence.binding_version != binding.binding_version
        or norm_evidence.graph_epoch != role.graph_epoch
    ):
        return _unknown("current_norm_read_version_mismatch", scene_ref=scope.scene_ref, role=role, binding=binding)
    if norm_evidence.status != "complete":
        return _unknown("current_norm_applicability_incomplete", scene_ref=scope.scene_ref, role=role, binding=binding)
    if (
        set(norm_evidence.norm_refs) != set(binding.norm_refs)
        or scope.action_kind not in norm_evidence.action_kinds
        or scope.purpose not in norm_evidence.purposes
        or scope.platform_ref not in norm_evidence.platform_refs
        or scope.scope_selector not in norm_evidence.scope_selectors
        or envelope.visibility not in norm_evidence.visibility_scopes
    ):
        return _inapplicable("norm_does_not_cover_current_action", scope.scene_ref, role=role, binding=binding)

    read_versions = tuple(
        sorted(
            (VersionedRef(f"graph:{item.key.token}", item.revision) for item in role.read_versions),
            key=lambda item: item.ref,
        )
    )
    versions = read_versions + (
        VersionedRef(binding.role_binding_id, binding.binding_version),
        VersionedRef("d03.norm_policy", norm_evidence.policy_version),
        VersionedRef("d03.identity_mapping", scope.identity_mapping_version),
        VersionedRef("d03.time_mapping", scope.time_mapping_version),
        VersionedRef("d03.scene_query_epoch", role.graph_epoch),
    )
    if len({item.ref for item in versions}) != len(versions):
        return _unknown("current_version_set_conflict", scene_ref=scope.scene_ref, role=role, binding=binding)
    expiry = min(
        norm_evidence.valid_until,
        binding.effective_until if binding.effective_until is not None else norm_evidence.valid_until,
    )
    if expiry < envelope.learned_at:
        return _unknown("applicability_evidence_expired", scene_ref=scope.scene_ref, role=role, binding=binding)
    return SceneBindingApplicabilityV1(
        "applicable",
        (),
        scope.scene_ref,
        role.head_id,
        binding.role_binding_id,
        binding.binding_version,
        role.graph_epoch,
        versions,
        expiry,
    )


def _unknown(
    *reasons: str,
    scene_ref: str | None = None,
    role: ActiveRoleQualification | None = None,
    binding: RoleBinding | None = None,
) -> SceneBindingApplicabilityV1:
    return _result("unknown", reasons, scene_ref, role, binding)


def _inapplicable(
    reason: str,
    scene_ref: str | None,
    *,
    role: ActiveRoleQualification | None = None,
    binding: RoleBinding | None = None,
) -> SceneBindingApplicabilityV1:
    return _result("inapplicable", (reason,), scene_ref, role, binding)


def _result(status, reasons, scene_ref, role, binding):
    versions: tuple[VersionedRef, ...] = ()
    if role is not None:
        versions = tuple(VersionedRef(f"graph:{item.key.token}", item.revision) for item in role.read_versions)
    if binding is not None:
        versions += (VersionedRef(binding.role_binding_id, binding.binding_version),)
    return SceneBindingApplicabilityV1(
        status,
        tuple(reasons),
        scene_ref,
        role.head_id if role is not None else None,
        binding.role_binding_id if binding is not None else None,
        binding.binding_version if binding is not None else None,
        role.graph_epoch if role is not None else None,
        versions,
        None,
    )


__all__ = (
    "NormApplicabilityEvidenceV1",
    "SceneBindingApplicabilityV1",
    "SceneIngressScopeV1",
    "check_current_scene_applicability",
)
