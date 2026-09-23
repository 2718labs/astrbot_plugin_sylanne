"""Fail-closed D11 final-admission inspection for a current graph read.

This is intentionally a non-authorizing component. The graph coordinator does
not yet expose a dispatch-only write transaction that can read these facts and
atomically insert the final claim. A caller cannot turn this assessment into a
send permit. The eventual coordinator callback must rerun it inside that same
write transaction, alongside all other RequiredCheckSpec and budget checks.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ...domains.d01 import PersonaDomain
from ...domains.d03.context import RoleBindingResolution
from ...domains.d06 import SourceGrantRead, provide_source_grant_check
from ...domains.d08 import ActionIntent
from ...graph_types import GraphSnapshot
from ...runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from ...runtime_contracts import NamespaceId, canonical_digest


@dataclass(frozen=True)
class FinalAdmissionAssessment:
    """Diagnostic only. ``status`` is always HOLD until an atomic graph port exists."""

    status: str
    missing: tuple[str, ...]
    current_source_proof_digest: str | None


def assess_final_admission(
    candidate: DispatchCandidateEvidenceV1,
    intent: ActionIntent,
    snapshot: GraphSnapshot,
    *,
    namespace: NamespaceId,
    audience: tuple[str, ...],
    batch_audience: tuple[str, ...],
    current_barrier_confirmed: bool,
    owner_guard: OwnerAuthorizationGuardV1 | None,
    role_binding: RoleBindingResolution | None,
    now_utc: float,
) -> FinalAdmissionAssessment:
    """Recheck source ancestry, access and role against one supplied graph read.

    The snapshot, barrier and Owner guard must come from the future trusted
    dispatch write transaction. This function never commits or issues authority.
    It returns HOLD even when the local checks pass, because the shared graph
    transaction and other domain checks have not been wired here.
    """
    if (not isinstance(candidate, DispatchCandidateEvidenceV1)
            or not isinstance(intent, ActionIntent)
            or not isinstance(snapshot, GraphSnapshot)
            or not isinstance(namespace, NamespaceId)):
        raise TypeError("typed candidate, intent, snapshot and namespace required")
    if (type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise ValueError("now_utc must be finite")
    if (type(audience) is not tuple or not audience
            or any(type(item) is not str or not item for item in audience)
            or type(batch_audience) is not tuple):
        raise ValueError("complete audience tuples required")
    if type(current_barrier_confirmed) is not bool:
        raise TypeError("current_barrier_confirmed must be bool")

    missing: list[str] = []
    if (candidate.status != "source_qualified"
            or candidate.operation_id != intent.identity.operation_id
            or candidate.action_digest != canonical_digest(intent)
            or candidate.source_refs != intent.source_refs):
        missing.append("candidate.identity_or_qualification")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or snapshot.epochs[0].revision < candidate.query_epoch):
        missing.append("graph.current_epoch")
    if audience != batch_audience or audience != candidate.source_audience:
        missing.append("source.audience")
    if not current_barrier_confirmed:
        missing.append("source.current_barrier")

    atoms = {atom.key.token: atom for atom in snapshot.atoms}
    proof = []
    pinned = dict(candidate.source_proof_versions)
    if (len(atoms) != len(snapshot.atoms)
            or len(pinned) != len(candidate.source_proof_versions)
            or not pinned
            or any(ref not in atoms or not atoms[ref].valid
                   or atoms[ref].revision != version
                   for ref, version in pinned.items())):
        missing.append("source.current_versions")
    else:
        proof = [(ref, version, canonical_digest(atoms[ref].value))
                 for ref, version in candidate.source_proof_versions]
        if canonical_digest(proof) != candidate.source_proof_digest:
            missing.append("source.current_content")

    if not any(item.startswith("candidate.") or item.startswith("graph.")
               or item.startswith("source.") for item in missing):
        try:
            receipt = provide_source_grant_check(
                intent,
                SourceGrantRead(snapshot, audience, "expression", True,
                                current_barrier_confirmed),
                valid_until=now_utc,
            )
        except (TypeError, ValueError):
            receipt = None
        if receipt is None or (receipt.result, receipt.coverage) != ("pass", "full"):
            missing.append("source.current_ancestry_access")

    if owner_guard is None:
        missing.append("owner.current_guard")
    else:
        try:
            role = PersonaDomain.resolve_active_role(
                snapshot, namespace=namespace, current_guard=owner_guard,
            )
            if role.namespace != namespace:
                missing.append("role.current_head")
        except (TypeError, ValueError):
            missing.append("role.current_head")

    if (not isinstance(role_binding, RoleBindingResolution)
            or role_binding.status != "complete"
            or not role_binding.matched_bindings
            or role_binding.missing_items
            or role_binding.request is None
            or not role_binding.request.scope_complete
            or role_binding.request.subject_persona_ref != f"persona:{namespace.persona_id}"
            or role_binding.request.requested_action_kind != intent.action_kind
            or role_binding.request.purpose != intent.purpose
            or intent.target_ref not in (
                role_binding.request.target_entity_ref,
                role_binding.request.group_ref,
                role_binding.request.scene_ref,
            )
            or (role_binding.valid_until is not None
                and role_binding.valid_until < now_utc)
            or role_binding.query_epoch is None
            or role_binding.query_epoch.namespace != namespace
            or len(snapshot.epochs) != 1
            or role_binding.query_epoch.revision != snapshot.epochs[0].revision
            or not role_binding.read_versions
            or any((atom := snapshot.get(version.key)) is None
                   or not atom.valid or atom.revision != version.revision
                   for version in role_binding.read_versions)):
        missing.append("d03.current_binding")

    # No shared graph final-claim transaction exists yet. Never return READY.
    missing.append("graph.atomic_final_claim_port")
    return FinalAdmissionAssessment(
        "hold", tuple(dict.fromkeys(missing)),
        canonical_digest(proof) if proof else None,
    )
