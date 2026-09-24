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
from ...domains.d08 import ActionIntent, ActionSchema, ActionSchemaRecord, GoalExecutionProvider
from ...domains.d09 import D09ExpressionProvider
from ...graph_types import AtomKey, GraphSnapshot
from ...runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from ...runtime_contracts import NamespaceId, canonical_digest


@dataclass(frozen=True)
class FinalAdmissionAssessment:
    """Diagnostic only. ``status`` is always HOLD until an atomic graph port exists."""

    status: str
    missing: tuple[str, ...]
    current_source_proof_digest: str | None


def _current_candidate_bundle(
    candidate: DispatchCandidateEvidenceV1,
    intent: ActionIntent,
    snapshot: GraphSnapshot,
    namespace: NamespaceId,
    now_utc: float,
) -> bool:
    """Re-read the four committed candidate atoms; a digest in a receipt is not an atom."""
    expected_types = (
        "d08.action_intent.v1", "d08.action_schema.v1",
        "d08.communication_intent_grant.v1", "d09.verified_segment_batch.v1",
    )
    refs = (candidate.action_ref, candidate.schema_ref, candidate.grant_ref, candidate.batch_ref)
    try:
        keys = tuple(AtomKey.from_token(ref) for ref in refs)
        if any(
            key.type_name != type_name
            or (key.owner.bot, key.owner.persona) != namespace.as_tuple
            or key.owner.kind != "activity"
            or key.owner.subject != intent.identity.activity_id
            for key, type_name in zip(keys, expected_types)
        ):
            return False
        if any(sum(atom.key == key for atom in snapshot.atoms) != 1 for key in keys):
            return False
        atoms = tuple(snapshot.get(key) for key in keys)
        if any(atom is None or not atom.valid for atom in atoms):
            return False
        action_atom, schema_atom, grant_atom, batch_atom = atoms
        d08_specs = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
        action = d08_specs[expected_types[0]].validator(action_atom.value)
        schema = d08_specs[expected_types[1]].validator(schema_atom.value)
        grant = d08_specs[expected_types[2]].validator(grant_atom.value)
        batch = batch_atom.value
        next(spec for spec in D09ExpressionProvider.register_types()
             if spec.name == expected_types[3]).validator(batch)
        frozen = ActionSchema(
            schema.schema_id, schema.action_kind, schema.proactive, schema.required_checks,
        )
        check_refs = tuple("check:" + canonical_digest({
            "kind": item.check_kind, "provider": item.provider_id,
            "subject": item.subject_ref, "action": item.action_ref,
            "purpose": item.purpose, "criteria_version": item.criteria_version,
            "input_versions": item.required_input_versions,
        }) for item in schema.required_checks)
        if (
            action != intent
            or ActionSchemaRecord.bind(action, frozen) != schema
            or action_atom.key.name != action.action_id
            or schema_atom.key.name != schema.schema_ref
            or grant_atom.key.name != grant.grant_id
            or batch_atom.key.name != batch["batch_id"]
            or canonical_digest(action) != candidate.action_digest
            or canonical_digest(schema) != candidate.schema_digest
            or canonical_digest(grant) != candidate.grant_digest
            or batch["batch_digest"] != candidate.batch_digest
            or grant.action_id != action.action_id
            or grant.intent_ref != action.action_id
            or grant.intent_revision != action.revision
            or grant.target_ref != action.target_ref
            or grant.purpose != "expression"
            or grant.required_check_refs != check_refs
            or grant.valid_until < now_utc
            or batch["action_id"] != action.action_id
            or batch["intent_ref"] != grant.intent_ref
            or batch["intent_revision"] != grant.intent_revision
            or batch["target_ref"] != grant.target_ref
            or batch["grant_id"] != grant.grant_id
            or batch["grant_digest"] != candidate.grant_digest
            or batch["grant_manifest_digest"] != grant.segment_manifest_digest
            or batch["communication_action_id"] != grant.communication_action_id
            or batch["contact_id"] != grant.contact_id
            or batch["batch_revision"] != grant.batch_revision
            or batch["required_check_refs"] != list(grant.required_check_refs)
            or batch["audiences"] != list(grant.audiences)
            or batch["valid_until"] != grant.valid_until
            or batch["cancellation_epoch"] != grant.cancellation_epoch
            or batch["purpose"] != grant.purpose
            or len(batch["segments"]) != len(grant.segment_grants)
            or any(
                (part["segment_id"], part["effect_id"], part["position"],
                 part["payload_digest"], part["segment_authorization_ref"],
                 part["max_chars"], part["allowed_media"],
                 part["prerequisite_segment_ref"], part["required_check_refs"],
                 part["valid_until"], part["cancellation_epoch"])
                != (segment.segment_id, segment.effect_id, segment.position,
                    segment.payload_digest, grant.segment_authorization_ref(segment.segment_id),
                    segment.max_chars, list(segment.allowed_media),
                    segment.prerequisite_segment_ref, list(segment.required_check_refs),
                    segment.valid_until, segment.cancellation_epoch)
                for part, segment in zip(batch["segments"], grant.segment_grants)
            )
        ):
            return False
        return {ref for part in batch["segments"] for ref in part["source_refs"]} <= set(action.source_refs)
    except (TypeError, ValueError, KeyError, AttributeError):
        return False


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
    if not _current_candidate_bundle(candidate, intent, snapshot, namespace, now_utc):
        missing.append("candidate.current_graph_bundle")
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
