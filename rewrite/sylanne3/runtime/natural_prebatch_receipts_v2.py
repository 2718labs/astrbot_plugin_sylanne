"""Current D03/D05 receipt candidates for a natural V2 final batch.

W01 calls this under its verified Authority write fence, after staging D08 in
the same SQLite transaction.  The result is evidence for final admission, not
a dispatch permit.  Reissue it at the final receipt hook and compare it in
full; W01 still owns the graph commit and D11 admission.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math
import sqlite3

from ..domains.d03.context import ContextProvider, RoleBindingRequest
from ..domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
from ..domains.d08.execution import (
    ActionIntent, ActionSchema, ActionSchemaRecord, GoalExecutionProvider,
)
from ..domains.d08.natural_final import NaturalFinalCommunicationCandidateV2
from ..domains.d08.natural_plan import natural_route_semantic_digest_v2
from ..domains.d09.natural_batch import (
    NATURAL_BATCH_SCHEMA_V2, validate_natural_verified_batch_value_v2,
)
from ..domains.d09.natural_reply import NaturalFinalActionCandidateV2
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import CheckReceipt, FenceScope, QueryEpoch, canonical_digest
from .dispatch_current_projection import (
    derive_current_domain_reads, read_current_dispatch_projection,
)
from .dispatch_source_correction_barrier import read_source_correction_barrier
from .natural_scoped_query_proof_v2 import (
    NaturalScopedQueryHold, NaturalScopedQueryProofV2,
    assert_natural_scoped_query_current_v2,
)
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2


@dataclass(frozen=True, slots=True)
class NaturalPrebatchSocialEvidenceV2:
    status: str
    missing: tuple[str, ...]
    role_receipt: CheckReceipt | None
    boundary_receipt: CheckReceipt | None
    graph_epoch: int | None
    positive_reads: tuple[GraphVersion, ...]
    negative_queries: tuple[QueryEpoch, ...]
    negative_predicates: tuple[str, ...]
    batch_digest: str | None


from .structural_source_closure_v1 import read_current_structural_source_closure_v1 as _current_structural_source_closure


def _current_atom(db, snapshot: GraphSnapshot, key: AtomKey):
    matches = [atom for atom in snapshot.atoms if atom.key == key]
    if len(matches) != 1 or not matches[0].valid or matches[0].revision < 1:
        raise ValueError("staged graph atom missing")
    atom = matches[0]
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (key.token, key.owner.bot, key.owner.persona),
    ).fetchone()
    if row is None or row[0] != atom.revision or row[2] != 1 or json.loads(row[1]) != atom.value:
        raise ValueError("staged graph atom differs from SQLite")
    return atom


def issue_natural_pregrant_social_receipts_v2(
    db, snapshot: GraphSnapshot, query: QueryEpoch,
    final: NaturalFinalActionCandidateV2,
    intent: ActionIntent, schema: ActionSchema,
    route_binding: CurrentReplyEntityRouteBindingV2,
    original_scope_proof: NaturalScopedQueryProofV2,
    context: ContextProvider, scope: FenceScope, *,
    now_utc: float, valid_until_utc: float,
    natural_catalogue_original_receiver=None,
) -> NaturalPrebatchSocialEvidenceV2:
    """Issue current D03/D05 checks before a five-check grant exists.

    The original scoped proof must come from the sealed natural preparation.
    W01 must authenticate that proof and the Authority fence independently.
    """
    def hold(reason: str) -> NaturalPrebatchSocialEvidenceV2:
        return NaturalPrebatchSocialEvidenceV2(
            "hold", (reason,), None, None, None, (), (), (), None)

    if (not getattr(db, "in_transaction", False)
            or type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(final) is not NaturalFinalActionCandidateV2
            or type(intent) is not ActionIntent or type(schema) is not ActionSchema
            or type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or type(original_scope_proof) is not NaturalScopedQueryProofV2
            or type(context) is not ContextProvider or type(scope) is not FenceScope
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or type(valid_until_utc) not in (int, float)
            or not math.isfinite(valid_until_utc) or valid_until_utc <= now_utc):
        return hold("social_v2.typed_current_transaction_required")
    namespace = scope.namespace
    if (scope.operation != "write" or scope.operation_id != scope.permit.operation_id
            or query != QueryEpoch(namespace, "all", scope.graph_epoch.revision + 1)
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona,
                snapshot.epochs[0].revision) != (*namespace.as_tuple, query.revision)):
        return hold("social_v2.staged_write_scope_changed")
    material = final.material
    if (final.status != "candidate_hold_w01_final_admission"
            or material is None
            or intent.action_kind != "communication" or intent.purpose != "expression"
            or intent.required_checks != schema.required_checks
            or schema.action_kind != "communication" or schema.proactive
            or material.final_activity_id != intent.identity.activity_id
            or material.final_operation_id != intent.identity.operation_id
            or material.final_effect_id != intent.identity.effect_id
            or material.route_binding_digest != natural_route_semantic_digest_v2(route_binding)
            or route_binding.namespace != namespace
            or route_binding.target_entity_ref != intent.target_ref
            or route_binding.scene_ref != material.scene_id
            or route_binding.conversation_ref != material.audience_id
            or original_scope_proof.scope.namespace != namespace
            or original_scope_proof.scope.target_entity_ref != intent.target_ref
            or original_scope_proof.scope.scene_ref != material.scene_id
            or original_scope_proof.scope.audience_id != material.audience_id
            or original_scope_proof.scope.account_binding_ref
               != route_binding.binding_version.key.token
            or original_scope_proof.scope.role_binding_ref != material.scene_ref.ref
            or len(original_scope_proof.role_matches) != 1
            or len(original_scope_proof.account_matches) != 1
            or original_scope_proof.role_matches[0].revision != material.scene_ref.version
            or original_scope_proof.account_matches[0].revision != material.audience_ref.version
            or material.audience_ref.ref != route_binding.binding_version.key.token
            or not {ref for claim in material.claims for ref in claim.source_refs}
                   .issubset(set(original_scope_proof.scope.source_roots))):
        return hold("social_v2.paid_route_or_action_changed")
    try:
        proof = assert_natural_scoped_query_current_v2(
            db, original_scope_proof, now_utc=now_utc)
        action_key = AtomKey(Owner("activity", *namespace.as_tuple,
                                   intent.identity.activity_id),
                             "d08.action_intent.v1", intent.action_id)
        schema_record = ActionSchemaRecord.bind(intent, schema)
        schema_key = AtomKey(action_key.owner, "d08.action_schema.v1",
                             schema_record.schema_ref)
        action_atom = _current_atom(db, snapshot, action_key)
        schema_atom = _current_atom(db, snapshot, schema_key)
        validators = {item.name: item.validator for item in GoalExecutionProvider().register_types()}
        if (validators[action_key.type_name](action_atom.value) != intent
                or validators[schema_key.type_name](schema_atom.value) != schema_record):
            raise ValueError("staged D08 action differs")
        projection = read_current_dispatch_projection(db, namespace, snapshot, query)
        request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", intent.target_ref, None,
            material.scene_id, intent.action_kind, intent.purpose, now_utc, True)
        role_read, boundary_read = derive_current_domain_reads(
            db, projection, request, context)
        specs = {(item.check_kind, item.provider_id): item
                 for item in intent.required_checks}
        if len(specs) != len(intent.required_checks):
            raise ValueError("duplicate required check")
        criteria_atoms = []
        for kind in (("role_binding", "d03.role_binding"),
                     ("boundary", "d05.boundary")):
            spec = specs[kind]
            criteria = [item for item in spec.required_input_versions
                        if item.ref == spec.criteria_version]
            if len(criteria) != 1:
                raise ValueError("social criterion missing")
            criteria_key = AtomKey.from_token(criteria[0].ref)
            if (criteria_key.owner.bot, criteria_key.owner.persona) != namespace.as_tuple:
                raise ValueError("social criterion crossed namespace")
            atom = _current_atom(db, snapshot, criteria_key)
            if atom.revision != criteria[0].version:
                raise ValueError("social criterion changed")
            criteria_atoms.append(atom)
        role = context.provide_required_check(
            intent, role_read, valid_until=valid_until_utc,
            natural_catalogue_original_receiver=natural_catalogue_original_receiver)
        boundary = issue_prebatch_boundary_check_v1(
            intent, schema, boundary_read, audience_scope=material.audience_id,
            scene_ref=material.scene_id, now_utc=now_utc,
            valid_until_utc=valid_until_utc)
        structural_refs = set()
        for atom in (*projection.role_bindings, *projection.boundary_rules):
            refs = atom.value.get("source_refs")
            if type(refs) is not list or not refs:
                raise ValueError("social source closure missing")
            structural_refs.update(refs)
        # D09's original roots have already passed their private expression
        # closure. Only additional D03/D05 configuration roots need the Owner
        # structural scope; neither set is substituted for the other.
        structural_refs.difference_update(proof.scope.source_roots)
        structural_versions, structural_heads = _current_structural_source_closure(
            db, snapshot, namespace,
            tuple(sorted(structural_refs)),
        )
        correction_refs = set(original_scope_proof.scope.source_roots) | structural_refs
        correction_missing = []
        for ref in sorted(correction_refs):
            correction_missing.extend(read_source_correction_barrier(
                db, namespace, query, (ref,), dependent_ref=intent.action_id,
            ).missing_sources)
        positive = {atom.key: GraphVersion(atom.key, atom.revision)
                    for atom in (action_atom, schema_atom, *criteria_atoms,
                                 *projection.role_bindings, *projection.boundary_rules)}
        for evidence in (*proof.account_matches, *proof.role_matches,
                         *proof.boundary_matches, *proof.d06_closure):
            if evidence.revision > 0:
                key = AtomKey.from_token(evidence.token)
                if (key.owner.bot, key.owner.persona) != namespace.as_tuple:
                    raise ValueError("scoped read crossed namespace")
                atom = _current_atom(db, snapshot, key)
                if atom.revision != evidence.revision:
                    raise ValueError("scoped graph version changed")
                positive[key] = GraphVersion(key, atom.revision)
        for version in structural_versions:
            positive[version.key] = version
        for version in (
                route_binding.anchor_version, route_binding.binding_version,
                route_binding.arrival_event_version,
                route_binding.binding_evidence_event_version,
                route_binding.source_version, route_binding.access_version,
                *route_binding.binding_scan_versions):
            if (version.key.owner.bot, version.key.owner.persona) != namespace.as_tuple:
                raise ValueError("account route crossed namespace")
            atom = _current_atom(db, snapshot, version.key)
            if atom.revision != version.revision:
                raise ValueError("account route graph version changed")
            positive[version.key] = version
    except (KeyError, TypeError, ValueError, sqlite3.Error, NaturalScopedQueryHold, StopIteration):
        return hold("social_v2.current_graph_provider_read_unavailable")
    missing = list(projection.missing_sources) + correction_missing
    if (role.result, role.coverage) != ("pass", "full"):
        missing.append("d03.current_role_binding_not_pass")
    if boundary.status != "check_pass":
        missing.extend(boundary.missing)
    predicates = (
        "d03.role_binding:all_valid", "d05.boundary_rule:all_valid",
        "d03.account_binding:unique_current_sender",
    ) + tuple(sorted({
        evidence.token for evidence in proof.d06_closure
        if evidence.revision == 0
    } | set(structural_heads) | {
        source_correction_head_key(
            namespace, AtomKey.from_token(ref).owner.subject or "").token
        for ref in correction_refs
    }))
    return NaturalPrebatchSocialEvidenceV2(
        "checks_candidate" if not missing else "hold",
        tuple(dict.fromkeys(missing)), role, boundary.receipt, query.revision,
        tuple(sorted(positive.values(), key=lambda item: item.key.token)),
        (query, QueryEpoch(namespace, "d03.role_binding", query.revision),
         QueryEpoch(namespace, "d05.boundary", query.revision)),
        predicates, None,
    )


def issue_natural_prebatch_social_receipts_v2(
    db, snapshot: GraphSnapshot, query: QueryEpoch,
    final: NaturalFinalActionCandidateV2,
    candidate: NaturalFinalCommunicationCandidateV2,
    schema: ActionSchema, batch: GraphWrite,
    route_binding: CurrentReplyEntityRouteBindingV2,
    original_scope_proof: NaturalScopedQueryProofV2,
    context: ContextProvider, scope: FenceScope, *,
    now_utc: float, valid_until_utc: float,
) -> NaturalPrebatchSocialEvidenceV2:
    """Reissue social checks after grant creation and bind exact V2 batch."""
    def hold(reason: str) -> NaturalPrebatchSocialEvidenceV2:
        return NaturalPrebatchSocialEvidenceV2(
            "hold", (reason,), None, None, None, (), (), (), None)

    if (type(candidate) is not NaturalFinalCommunicationCandidateV2
            or type(final) is not NaturalFinalActionCandidateV2
            or type(batch) is not GraphWrite
            or type(scope) is not FenceScope
            or candidate.status != "candidate_hold_w01_final_admission"
            or type(candidate.action_intent) is not ActionIntent
            or candidate.communication_grant is None):
        return hold("social_v2.typed_final_grant_required")
    intent, grant = candidate.action_intent, candidate.communication_grant
    if (grant.action_id != intent.action_id or grant.target_ref != intent.target_ref
            or final.material is None or grant.audiences != (final.material.audience_id,)
            or grant.route_binding_digest != final.material.route_binding_digest
            or grant.valid_until != valid_until_utc):
        return hold("social_v2.final_grant_changed")
    try:
        validate_natural_verified_batch_value_v2(batch.value)
        value = batch.value
        material = final.material
        if (batch.key.type_name != NATURAL_BATCH_SCHEMA_V2
                or batch.key.name != value["batch_id"]
                or batch.key.owner != Owner("activity", *scope.namespace.as_tuple,
                                            material.final_activity_id)
                or value["operation_id"] != material.final_operation_id
                or value["action_id"] != intent.action_id
                or value["effect_id"] != material.final_effect_id
                or value["source_ref"]["ref"] != material.source_ref.ref
                or value["scene_id"] != material.scene_id
                or value["audience_id"] != material.audience_id
                or value["route_binding_digest"] != material.route_binding_digest
                or value["grant_digest"] != canonical_digest(grant)
                or value["segment"]["segment_id"] != material.segment.segment_id
                or value["segment"]["payload_digest"] != material.payload_digest):
            raise ValueError("V2 batch differs")
    except (AttributeError, KeyError, TypeError, ValueError):
        return hold("social_v2.natural_batch_changed")
    current = issue_natural_pregrant_social_receipts_v2(
        db, snapshot, query, final, intent, schema, route_binding,
        original_scope_proof, context, scope, now_utc=now_utc,
        valid_until_utc=valid_until_utc)
    return replace(current, batch_digest=value["batch_digest"])


__all__ = ["NaturalPrebatchSocialEvidenceV2",
           "issue_natural_pregrant_social_receipts_v2",
           "issue_natural_prebatch_social_receipts_v2"]
