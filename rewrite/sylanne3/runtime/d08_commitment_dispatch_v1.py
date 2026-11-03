"""Named exact-literal communication through actual Source Work and existing W01 seal."""
from __future__ import annotations
from dataclasses import dataclass, replace
import math
import secrets
import sqlite3

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_contract import AuthorityCurrentEffectSnapshotV2, FencePermitV2, canonical_digest as authority_digest
from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import (AuthorityContext, CommandEnvelope, FenceScope, OperationIdentity,
    VersionGuard, VersionedRef, SourceQualification, RUNTIME_SCHEMA, canonical_digest)
from ..domains.d03.prebatch_social import _private_route
from ..domains.d08.commitment_communication_v1 import SCOPE_TYPES, commitment_communication_effect_id_v1, scope_route_source_v1, CommitmentTermsCommunicationIntentV2
from .current_graph_full_read_v3 import (COMMITMENT_COMMUNICATION_FULL_READ_V1,
    prepare_current_graph_full_read_v3, bind_prepared_graph_full_read_v3)
from .d08_commitment_communication_v1 import (bind_named_commitment_full_v1,
    current_named_commitment_scope_v1, prepare_commitment_literal_expression_v1)
from .post_c02_reply_action_v2 import post_c02_reply_action_ids_v2
from .post_c02_reply_bundle_v2 import post_c02_dispatch_runtime_refs_v2, prepare_post_c02_reply_bundle_candidate_v2
from ..host.post_c02_reply_driver import post_c02_reply_operation_id
from .first_ingress_v2 import trusted_upper


@dataclass(frozen=True, slots=True)
class PrepareCurrentCommitmentCommunicationRequestV1:
    scope_ref: str
    c02_operation_id: str
    source_ref: str
    deadline_utc: float

    def __post_init__(self):
        if (AtomKey.from_token(self.scope_ref).type_name not in SCOPE_TYPES
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or type(self.c02_operation_id) is not str or not self.c02_operation_id
                or type(self.deadline_utc) not in (int, float) or not math.isfinite(self.deadline_utc)):
            raise ValueError("named communication requires exact scope/actual C02 Source and finite original deadline")


def prepare_current_commitment_communication_v1(graph, bootstrap, installed_bundle, *,
        scope_ref, c02_operation_id, source_ref, deadline_utc):
    request = PrepareCurrentCommitmentCommunicationRequestV1(scope_ref, c02_operation_id, source_ref, deadline_utc)
    graph._admin(bootstrap)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or installed_bundle is not assembly.admin_bundle:
        raise AuthorityUnavailable("named communication needs its actual installed composition")
    namespace = installed_bundle.installation_policy.namespace
    if any((key.owner.bot, key.owner.persona) != namespace.as_tuple
            for key in (AtomKey.from_token(request.scope_ref), AtomKey.from_token(request.source_ref))):
        raise AuthorityUnavailable("named communication locator crossed namespace")
    store = graph._GraphCoordinator__store; port = graph._GraphCoordinator__content_fence_v2
    clock = port.read_ingress_clock(graph._GraphCoordinator__dispatch_clock_policy); now = trusted_upper(clock)
    send_deadline = min(request.deadline_utc, now + installed_bundle.private_reply_dispatch.deadline_after_seconds)
    # A fresh read-only window can recover an expired original receipt. It
    # never changes the original send deadline or reopens any execution job.
    deadline = send_deadline if now < send_deadline else now + installed_bundle.private_reply_dispatch.deadline_after_seconds
    with store._lock:
        db = store._db; db.execute("BEGIN")
        try:
            _, audience, _, _, _ = _private_route(db, namespace, source_ref)
            metadata, epoch = graph._v2_graph_stamp(namespace)
        finally: db.rollback()
    lease, capability = graph.grant(bootstrap, actor="commitment-literal-reader", issuer_domain="d11",
        namespace=namespace, domains=("d08", "d09", "d11"),
        activation_generation=metadata.requirements.activation_generation,
        operation_id=post_c02_reply_operation_id(c02_operation_id, source_ref))
    authority = AuthorityContext("commitment-literal-reader", "d11", capability, namespace,
        ("persona", "activity"), "expression", (audience,), "policy:commitment-literal-read.v1",
        metadata.requirements.activation_generation)
    try:
        work = prepare_current_graph_full_read_v3(graph, authority, lease,
            read_contract=COMMITMENT_COMMUNICATION_FULL_READ_V1,
            operation_id="commitment-source-read:" + secrets.token_hex(24), deadline_utc=deadline,
            c02_operation_id=c02_operation_id, source_ref=source_ref, commitment_scope_ref=scope_ref)
        work.state.commitment_send_deadline=send_deadline
        work.state.commitment_recovery_only=now>=send_deadline
    except BaseException:
        graph.release_authority_lease(bootstrap, lease); raise
    def completed(proof):
        try:
            from .current_graph_full_read_v3 import PreparedCurrentGraphFullMetadataRecoveryV3
            if type(proof)is PreparedCurrentGraphFullMetadataRecoveryV3:
                proof.require_current_v3(graph,work)
                with store._lock:
                    db.execute("BEGIN")
                    try:result=proof.recovery_task.require_current_v1(proof,graph,db)
                    finally:db.rollback()
                proof.recovery_task.finish_original_v1(graph)
                return result
            with bind_prepared_graph_full_read_v3(proof, graph, db):
                with bind_named_commitment_full_v1(proof, graph, db):
                    reading = port.read_ingress_clock(graph._GraphCoordinator__dispatch_clock_policy)
                    return _assemble_named_commitment_v1(graph, bootstrap, installed_bundle, request,
                        proof, reading, trusted_upper(reading), send_deadline)
        finally:
            proof.release_payload_v3()
            graph.release_authority_lease(bootstrap, lease)
    def failed(error):
        graph.release_authority_lease(bootstrap, lease); raise error
    return work.map_terminal_v3("issuer", completed, failed)


def _prepare_named_commitment_bundle_v1(graph, installed_bundle, proof, approval, *,
        authority, scope, reading, current_effect, effects, now, deadline):
    from .budget import reserve_budget
    from ..graph_coordinator import budget_operation_digest
    from .jobs import create_job
    from .natural_reply_budget_v3 import resolve_natural_reply_budget_for_new_admission_v3
    store = graph._GraphCoordinator__store; db = store._db
    current_named_commitment_scope_v1(db, authority.namespace)
    material = proof.source_material; c02 = material.inputs.c02_receipt.operation_id
    inputs, route = graph._current_post_c02_reply_route_locked(authority.namespace, c02,
        scope_route_source_v1(approval), now, scope.graph_epoch)
    if (inputs.c02_receipt != material.inputs.c02_receipt
            or inputs.attention.ticket != material.inputs.attention.ticket
            or (inputs.source.source_ref, inputs.source.source_revision, inputs.source.access_revision) !=
               (material.inputs.source.source_ref, material.inputs.source.source_revision, material.inputs.source.access_revision)):
        raise AuthorityUnavailable("named communication actual C02 input changed")
    if (route.conversation_ref, route.scene_ref, route.platform_ref) != (
            approval.conversation_ref, approval.scene_ref, approval.platform_ref):
        raise AuthorityUnavailable("named communication live ingress route changed")
    child, grant = resolve_natural_reply_budget_for_new_admission_v3(db, namespace=authority.namespace,
        c02_operation_id=c02, source_ref=scope_route_source_v1(approval), issuer=graph._GraphCoordinator__d11_issuer,
        installed_bundle=installed_bundle, now_utc=now)
    if child.parent_id != installed_bundle.installation_policy.root_lease.lease_id:
        raise AuthorityUnavailable("named communication requires its actual existing foreground child; no root fallback")
    operation = post_c02_reply_operation_id(c02, scope_route_source_v1(approval))
    identity = OperationIdentity(inputs.c02_receipt.activity_id,
        commitment_communication_effect_id_v1(approval.scope_id),
        "attempt:commitment-literal:" + canonical_digest((approval.scope_id, operation))[:40],
        "commitment_literal_v1", operation, canonical_digest({"scope": proof.commitment_scope_original.key.token,
            "source": scope_route_source_v1(approval), "c02": c02}))
    action_id = post_c02_reply_action_ids_v2(c02, scope_route_source_v1(approval))[1]
    expression = prepare_commitment_literal_expression_v1(approval,
        GraphVersion(proof.commitment_scope_original.key, 1), identity=identity, action_id=action_id)
    snapshot, query = graph._dispatch_full_graph_snapshot_locked(authority.namespace)
    reads = tuple(dict.fromkeys((*snapshot.versions, *material.rights_versions,
        GraphVersion(proof.commitment_scope_original.key, 1), approval.commitment,
        *((approval.fulfillment_terms,*approval.policy_read_versions,*(()if approval.terms_acceptance is None else(approval.terms_acceptance,)))
            if type(approval) is CommitmentTermsCommunicationIntentV2 else ()))))
    guard = VersionGuard(reads, (query,), *proof.authority_epochs, store._registry.catalogue_hash,
        graph._version(db, authority.namespace, "scheme", "current"),
        graph._version(db, authority.namespace, "operator", "current"),
        graph._version(db, authority.namespace, "policy", "current"), (), (), ())
    source = material.source_record
    envelope = CommandEnvelope(RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification(approval.source_refs, "reported", source.occurred_at, source.recorded_at,
            "external_report", "ineligible", None, "not_applicable"),
        approval.source_refs, grant.lease_id, deadline,
        reading.monotonic_after_seconds + deadline - reading.utc_upper_bound_seconds,
        "commitment-literal:" + approval.scope_id, (c02, approval.approval_operation_id))
    job_ref, outbox_ref, _ = post_c02_dispatch_runtime_refs_v2(authority.namespace, identity)
    issuer = graph._GraphCoordinator__d11_issuer
    quote = issuer.issue_private_reply_dispatch_quote_v2(db, policy=installed_bundle.private_reply_dispatch,
        namespace=authority.namespace, identity=identity, parent_grant=grant, deadline_utc=deadline,
        graph_job_ref=job_ref, outbox_refs=(outbox_ref,), now_utc=now)
    db.execute("INSERT OR IGNORE INTO graph_guard_versions(bot,persona,kind,ref,version)VALUES(?,?,?,?,?)",
        (*authority.namespace.as_tuple, "resource_lease", quote.quote_id, str(quote.version)))
    envelope = replace(envelope, version_guard=replace(guard,
        resource_lease_versions=(VersionedRef(quote.quote_id, quote.version),)))
    reserve_budget(db, grant.lease_id, operation, budget_operation_digest(envelope, grant.lease_id, dict(quote.ceiling)), quote.ceiling)
    job = replace(issuer.job_for(envelope, db, now_utc=now), phase="waiting",
        wake_condition={"kind": "post_c02_reply_host_takeover", "operation_id": operation})
    create_job(db, job, "commitment-literal-job:" + canonical_digest((approval.scope_id, job_ref))[:48], canonical_digest(job))
    staged = graph._stage_post_c02_reply_prebatch_locked(envelope=envelope, c02_receipt=inputs.c02_receipt,
        route=route, source_ref=scope_route_source_v1(approval), attention=inputs.attention.ticket, focus=inputs.attention.focus,
        budget_grant=grant, resource_quote=quote, expression=expression, anchor=scope.pinned_anchor,
        scope=scope, current_effect=current_effect, effect_snapshot=effects, now_utc=now)
    candidate = prepare_post_c02_reply_bundle_candidate_v2(envelope=staged[0], action=staged[2], staged_d08=staged[1],
        checks=staged[4].checks, expression=expression, route=route, route_binding=staged[6], pre_frozen_grant=staged[7],
        quote=quote, budget_grant=grant, pre_reserved_job=job, now_utc=now, conversation_epoch=staged[4].graph_epoch)
    return (inputs, route, envelope, expression, grant, quote, job, staged, candidate)


def _assemble_named_commitment_v1(graph, bootstrap, installed_bundle, request, proof, reading, now, deadline):
    from ..host.v2_fence_port import V2FenceOutcomeUnknown
    store = graph._GraphCoordinator__store; db = store._db
    port = graph._GraphCoordinator__content_fence_v2
    with store._lock:
        db.execute("BEGIN")
        try:
            approval = current_named_commitment_scope_v1(db, proof.namespace)
            metadata, epoch = graph._v2_graph_stamp(proof.namespace)
            if not now < deadline <= approval.valid_until_utc:
                raise AuthorityUnavailable("named communication original deadline expired during actual Source preparation")
        finally: db.rollback()
    actor = proof.commitment_scope_original.current_self.self_entity_ref
    operation = post_c02_reply_operation_id(request.c02_operation_id, request.source_ref)
    lease, capability = graph.grant(bootstrap, actor=actor, issuer_domain="d11", namespace=proof.namespace,
        domains=("d08", "d09", "d11"), activation_generation=approval.activation_generation, operation_id=operation)
    authority = AuthorityContext(actor, "d11", capability, proof.namespace, ("persona", "activity"), "expression",
        (approval.conversation_ref,), "policy:commitment-literal-dispatch.v1", approval.activation_generation)
    attempt = "commitment-literal-assembly:" + canonical_digest((approval.scope_id, operation))[:48]
    write_scope = None; committed = False; rollback_confirmed = False; sql_started = False
    try:
        anchor = port.current_anchor(namespace=proof.namespace, authority_namespace=metadata.requirements.authority_namespace)
        if not graph._anchor_matches(metadata.requirements, anchor):
            raise AuthorityUnavailable("named communication current Authority root changed")
        permit = port.begin_fence(namespace=proof.namespace, authority_namespace=metadata.requirements.authority_namespace,
            holder=graph._GraphCoordinator__holder, generation=approval.activation_generation, operation="write",
            operation_id=attempt, expected_anchor=anchor, retain_on_unknown=True)
        write_scope = FenceScope(proof.namespace, metadata.requirements.authority_namespace, approval.activation_generation,
            "write", attempt, permit, anchor, epoch, metadata.graph_revision)
        if type(permit) is not FencePermitV2 or port.validate_fence(write_scope) != permit:
            raise AuthorityUnavailable("named communication actual writer permit changed")
        owner_guard = port.get_current_owner_guard_for_fence(namespace=proof.namespace,
            authority_namespace=write_scope.authority_namespace, permit=permit)
        current_self = graph._GraphCoordinator__self_identity_port.current_self_identity(namespace=proof.namespace,
            authority_namespace=write_scope.authority_namespace, request_operation_id=attempt, permit=permit)
        effect_id = commitment_communication_effect_id_v1(approval.scope_id)
        effect = port.read_current_effect(namespace=proof.namespace, authority_namespace=write_scope.authority_namespace,
            effect_id=effect_id)
        effects = port.read_current_effect_snapshot_for_write_fence(namespace=proof.namespace,
            authority_namespace=write_scope.authority_namespace, permit=permit)
        if (type(owner_guard) is not tuple or len(owner_guard) != 2 or type(owner_guard[0]) is not OwnerAuthorizationGuardV1
                or owner_guard[1] != permit
                or owner_guard[0].authorization_head.removeprefix("sha256:") != approval.owner_guard.owner_head_digest
                or type(current_self) is not AuthorityCurrentSelfIdentityV1 or current_self.permit != permit
                or current_self.self_entity_ref != actor or current_self.role_head_id != approval.persona_head_id
                or current_self.graph_incarnation != approval.graph_incarnation
                or current_self.activation_generation != approval.activation_generation
                or type(effect) is not CurrentEffectReadV2 or effect.state != "absent"
                or type(effects) is not AuthorityCurrentEffectSnapshotV2 or effects.coverage != "complete"
                or effects.anchor != anchor or effects.permit_digest != authority_digest(permit)
                or port.validate_fence(write_scope) != permit):
            raise AuthorityUnavailable("named communication fresh Self/Owner/effect/Authority root qualification changed")
        with store._lock:
            db.execute("BEGIN IMMEDIATE"); sql_started = True
            try:
                if graph._v2_graph_stamp(proof.namespace) != (metadata, epoch):
                    raise AuthorityUnavailable("named communication Source Work graph changed before its actual writer")
                prepared = _prepare_named_commitment_bundle_v1(graph, installed_bundle, proof, approval,
                    authority=authority, scope=write_scope, reading=reading, current_effect=effect,
                    effects=effects, now=now, deadline=deadline)
                finish_id = "finish:" + attempt
                finish_digest = "sha256:" + canonical_digest({"action": "finish_commitment_literal_v1",
                    "scope": approval.digest, "permit": permit.token, "bundle": prepared[8].bundle.digest})
                receipt = graph._seal_post_c02_reply_dispatch_locked(lease=lease, scope=write_scope,
                    metadata=metadata, clock_reading=reading, owner_guard=owner_guard[0], current_effect=effect,
                    effect_snapshot=effects, now_utc=now, prepared=prepared, finish_id=finish_id,
                    finish_digest=finish_digest, prepared_full_read=proof)
                committed = True; db.commit()
            except BaseException:
                if db.in_transaction: db.rollback(); rollback_confirmed = True
                raise
        if port.validate_fence(write_scope) != permit:
            raise V2FenceOutcomeUnknown("named communication committed but final permit acknowledgement changed")
        port.finish_fence(write_scope, request_id=finish_id, request_digest=finish_digest)
        return {"status": "commitment_communication_dispatch_committed", "operation_id": operation,
            "scope_ref": request.scope_ref, "commit_receipt": receipt,
            "job_ref": prepared[8].job_ref, "outbox_ref": prepared[8].outbox_ref}
    except BaseException as failure:
        # An unknown result keeps its original permit/operation. Confirmed local
        # no-commit closure is limited to this exact attempt and actual absence.
        if (write_scope is not None and not committed and (not sql_started or rollback_confirmed)
                and isinstance(failure, Exception) and not isinstance(failure, (sqlite3.Error, OSError, V2FenceOutcomeUnknown))):
            with store._lock:
                if graph._v2_graph_stamp(proof.namespace) != (metadata, epoch):
                    raise V2FenceOutcomeUnknown("named no-commit closure original graph stamp changed") from failure
                for table in ("graph_bundle_operations", "graph_dispatch_admissions"):
                    if db.execute("SELECT 1 FROM " + table + " WHERE bot=? AND persona=? AND operation_id=? LIMIT 1",
                            (*proof.namespace.as_tuple, operation)).fetchone() is not None:
                        raise V2FenceOutcomeUnknown("named no-commit closure found durable original state") from failure
            original, state = port.get_fence_operation(namespace=proof.namespace,
                authority_namespace=write_scope.authority_namespace, operation_id=attempt)
            if original != write_scope.permit or state not in {"active", "finished"}:
                raise V2FenceOutcomeUnknown("named no-commit closure actual permit is unresolved") from failure
            if state == "active":
                port.finish_fence(write_scope, request_id="abort:" + attempt,
                    request_digest="sha256:" + canonical_digest(("close_named_commitment_without_commit_v1", approval.digest, write_scope.permit)))
        raise
    finally:
        graph.release_authority_lease(bootstrap, lease)
