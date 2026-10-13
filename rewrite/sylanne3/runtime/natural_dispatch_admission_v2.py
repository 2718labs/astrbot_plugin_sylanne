"""Issue one natural V2 dispatch command from a current, signed graph transaction.

The coordinator owns the Authority write fence and commits this receipt with
``insert_admission``.  This helper never accepts a V1 verified batch.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
import math

from ..dispatch_runtime import DispatchRequest
from ..domains.d03 import RoleBinding, RoleBindingRequest
from ..domains.d08.execution import (
    ActionSchema, ActionSchemaRecord, GoalExecutionProvider,
    RequiredCheckRegistry,
)
from ..domains.d08.natural_plan import natural_route_semantic_digest_v2
from ..domains.d09.natural_batch import (
    NATURAL_BATCH_SCHEMA_V2, NATURAL_BATCH_SCHEMA_V3, rebind_natural_verified_batch_proposal, natural_batch_segment_count,
    validate_natural_verified_batch_value,
)
from ..domains.d09.natural_reply import NaturalFinalActionCandidateV2
from ..graph_types import AtomKey, GraphReceipt, GraphSnapshot
from ..runtime_contracts import (
    CheckReceipt, DomainBundle, FenceScope, QueryEpoch, canonical_digest,
)
from ..runtime_journal import BudgetConstraint, RecoveryConstraintFootprint
from .budget import get_budget_lease
from .d11_types import RuntimeOutboxValue, job_graph_write, outbox_graph_write
from .dispatch_admission import (
    DispatchAdmissionReceiptV1, DispatchAdmissionV1,
    check_receipts_against_specs,
)
from .dispatch_candidate import (
    NaturalDispatchCandidateEvidenceV2, natural_dispatch_segment_payload_ref_v2,
)
from .dispatch_current_projection import (
    CurrentDispatchProjectionV1, read_current_dispatch_projection,
)
from .installed_dispatch_admission_issuer import (
    TrustedDispatchAdmissionContextV1, _message_reservation_dimension_limit,
    inspect_current_owner_grant,
)
from .jobs import get_job
from .natural_final_issuer_v2 import NaturalFinalD11RuntimeV2
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2


class NaturalDispatchAdmissionHold(RuntimeError):
    """A required current original or signed admission is unavailable."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NaturalDispatchAdmissionHold(reason)


def _atom(db, namespace, ref: str, type_name: str) -> dict:
    key = AtomKey.from_token(ref)
    _require(key.type_name == type_name
             and (key.owner.bot, key.owner.persona) == namespace.as_tuple,
             "natural dispatch atom scope differs")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (ref, *namespace.as_tuple),
    ).fetchone()
    _require(row is not None and row[0] > 0 and row[2] == 1,
             "natural dispatch graph original absent")
    return json.loads(row[1])


def _current_natural_role_binding(
    db, projection: CurrentDispatchProjectionV1, namespace,
    action, route: CurrentReplyEntityRouteBindingV2,
    expected_ref: str, expected_revision: int, now_utc: float,
) -> RoleBinding:
    """Select the same concrete scene role that D03's final check matched."""
    request = RoleBindingRequest(
        f"persona:{namespace.persona_id}", action.target_ref, None,
        route.scene_ref, action.action_kind, action.purpose, now_utc, True,
    )
    matches = []
    for atom in projection.role_bindings:
        _require(_atom(db, namespace, atom.key.token, "d03.role_binding")
                 == atom.value, "natural current D03 role row changed")
        value = atom.value
        binding = RoleBinding(**{
            **value, "norm_refs": tuple(value["norm_refs"]),
            "source_refs": tuple(value["source_refs"]),
        })
        _require(atom.key.name == binding.role_binding_id
                 and atom.revision == binding.binding_version
                 and binding.subject_persona_ref == request.subject_persona_ref
                 and (atom.key.owner.kind != "scene"
                      or atom.key.owner.subject == binding.scene_ref),
                 "natural current D03 role identity changed")
        if binding.scene_ref == route.scene_ref and binding.applies_to(request):
            matches.append((atom, binding))
    _require(len(matches) == 1
             and matches[0][0].key.token == expected_ref
             and matches[0][0].revision == expected_revision,
             "natural current D03 role binding ambiguous")
    return matches[0][1]


def issue_natural_dispatch_admission_v2(
    *, db, bundle: DomainBundle, evidence: NaturalDispatchCandidateEvidenceV2,
    final: NaturalFinalActionCandidateV2, runtime: NaturalFinalD11RuntimeV2,
    checks: tuple[CheckReceipt, ...],
    graph_receipt: GraphReceipt, scope: FenceScope, clock_reading,
    clock_policy, owner_guard, current_effect, effect_snapshot,
    route: CurrentReplyEntityRouteBindingV2, snapshot: GraphSnapshot,
    query: QueryEpoch, projection: CurrentDispatchProjectionV1,
    now_utc: float,
) -> tuple[DispatchAdmissionReceiptV1, DispatchRequest]:
    """Construct a command/receipt from W01's held E+1 read and D11 admission.

    W01 must obtain ``scope`` and the Authority observations from its installed
    write fence, and re-read ``route`` and ``snapshot`` from the current SQL
    head in the same BEGIN IMMEDIATE transaction.  This function rechecks the
    graph, Owner and D11 originals before returning persistence inputs.
    """
    _require(getattr(db, "in_transaction", False), "graph write transaction required")
    _require(type(bundle) is DomainBundle
             and type(evidence) is NaturalDispatchCandidateEvidenceV2
             and type(final) is NaturalFinalActionCandidateV2
             and type(runtime) is NaturalFinalD11RuntimeV2
             and type(checks) is tuple
             and all(type(check) is CheckReceipt for check in checks)
             and type(graph_receipt) is GraphReceipt
             and type(scope) is FenceScope
             and type(route) is CurrentReplyEntityRouteBindingV2
             and type(snapshot) is GraphSnapshot
             and type(query) is QueryEpoch
             and type(projection) is CurrentDispatchProjectionV1
             and type(now_utc) in (int, float) and math.isfinite(now_utc),
             "typed natural dispatch transaction material required")
    from ..authority_service.v2_contract import AuthorityCurrentEffectSnapshotV2
    from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..host.authority_profile import AdminIngressClockPolicy
    from ..host.v2_fence_port import VerifiedIngressClockV2
    _require(type(clock_reading) is VerifiedIngressClockV2
             and type(clock_policy) is AdminIngressClockPolicy
             and type(owner_guard) is OwnerAuthorizationGuardV1
             and type(current_effect) is CurrentEffectReadV2
             and type(effect_snapshot) is AuthorityCurrentEffectSnapshotV2
             and len(bundle.persistent_job_refs) == 1
             and len(bundle.outbox_refs) == 1
             and len(bundle.idempotency_keys) == 1,
             "current installed Authority and D11 material required")
    namespace = bundle.envelope.authority.namespace
    identity = bundle.envelope.identity
    _require(scope.namespace == namespace and scope.operation == "write"
             and scope.permit.operation == "write"
             and scope.generation == bundle.envelope.authority.activation_generation
             and graph_receipt.status == "committed"
             and graph_receipt.epoch.revision == query.revision
             and query.namespace == namespace and query.scope_ref == "all"
             and snapshot.epochs == (graph_receipt.epoch,)
             and projection.namespace == namespace
             and projection.graph_epoch == query.revision
             and projection.coverage == "full"
             and route.namespace == namespace and route.query == query
             and runtime.status == "admitted_runtime_hold_graph_final_claim"
             and runtime.candidate_digest == evidence.digest
             and runtime.payload_digest == evidence.payload_digest
             and runtime.job_ref == bundle.persistent_job_refs[0]
             and runtime.outbox_ref == bundle.outbox_refs[0]
             and evidence.operation_id == identity.operation_id
             and evidence.effect_id == identity.effect_id,
             "natural dispatch current fence or identity differs")
    _require(db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone() == (query.revision,), "natural dispatch graph head changed")
    _require(read_current_dispatch_projection(db, namespace, snapshot, query)
             == projection, "natural dispatch D03/D05 projection changed")

    types = {spec.name: spec.validator for spec in GoalExecutionProvider().register_types()}
    action = types["d08.action_intent.v1"](_atom(
        db, namespace, evidence.action_ref, "d08.action_intent.v1"))
    schema = types["d08.action_schema.v1"](_atom(
        db, namespace, evidence.schema_ref, "d08.action_schema.v1"))
    grant = types["d08.communication_intent_grant.v1"](_atom(
        db, namespace, evidence.grant_ref, "d08.communication_intent_grant.v1"))
    batch = _atom(db, namespace, evidence.batch_ref, AtomKey.from_token(evidence.batch_ref).type_name)
    validate_natural_verified_batch_value(batch)
    rebuilt = rebind_natural_verified_batch_proposal(final, grant, batch)
    _require(type(schema) is ActionSchemaRecord
             and rebuilt.write is not None
             and rebuilt.write.key.token == evidence.batch_ref
             and rebuilt.write.value == batch
             and canonical_digest(action) == evidence.action_digest
             and canonical_digest(schema) == evidence.schema_digest
             and canonical_digest(grant) == evidence.grant_digest
             and batch["batch_digest"] == evidence.batch_digest
             and batch["segment"]["payload_digest"] == evidence.payload_digest
             and batch["scene_id"] == route.scene_ref
             and batch["audience_id"] == route.conversation_ref
             and batch["route_binding_digest"] == natural_route_semantic_digest_v2(route)
             and action.identity == identity
             and action.target_ref == route.target_entity_ref
             and grant.audiences == (route.conversation_ref,)
             and grant.required_check_refs == tuple(batch["required_check_refs"])
             and grant.route_binding_digest == batch["route_binding_digest"],
             "natural V2 batch, route or action differs")
    _require(canonical_digest(checks) == runtime.checks_digest,
             "natural D11 check digest differs")
    frozen_schema = ActionSchema(
        schema.schema_id, schema.action_kind, schema.proactive,
        schema.required_checks,
    )
    _require(ActionSchemaRecord.bind(action, frozen_schema) == schema
             and not frozen_schema.proactive
             and len(action.required_checks) == 5,
             "natural frozen five-check schema differs")
    # W01 has reissued these receipts from the current E+1 graph in this fence.
    _require(len(checks) == 5,
             "natural final check receipts missing")
    decision = RequiredCheckRegistry()
    decision.register(frozen_schema)
    qualified = decision.qualify(action, checks, now=now_utc)
    _require(qualified.status == "qualified"
             and qualified.receipt_digest == grant.qualification_receipt_digest
             and tuple(check.check_kind for check in checks)
             == tuple(spec.check_kind for spec in action.required_checks),
             "natural final checks differ from adopted grant")

    owner_row = db.execute(
        "SELECT graph_incarnation FROM graph_owner_issue_operations_v1 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    _require(owner_row is not None and owner_row[0], "current Owner proof missing")
    trusted = TrustedDispatchAdmissionContextV1(
        scope, clock_reading, clock_policy, projection, graph_receipt,
        owner_guard, current_effect, effect_snapshot,
    )
    owner = inspect_current_owner_grant(
        db, namespace, (route.conversation_ref,), "expression",
        trusted_context=trusted, graph_incarnation=owner_row[0],
    )
    _require(owner.status == "owner_verified" and owner.grant_id is not None
             and current_effect.state == "absent"
             and (current_effect.execution_head_seq,
                  current_effect.execution_head_digest) == (
                      scope.pinned_anchor.execution_seq,
                      scope.pinned_anchor.execution_digest),
             "current Owner or Authority journal changed")

    role = _current_natural_role_binding(
        db, projection, namespace, action, route,
        final.material.scene_ref.ref, final.material.scene_ref.version, now_utc,
    )

    runtime_admission = runtime.runtime_admission
    _require(runtime_admission.budget.pre_reserved
             and not runtime_admission.budget.settle_now
             and runtime_admission.budget.lease_id == bundle.envelope.parent_budget_lease_ref
             and len(runtime_admission.jobs) == 1,
             "natural signed D11 admission changed")
    job = get_job(db, AtomKey.from_token(runtime.job_ref).name)
    job_value = _atom(db, namespace, runtime.job_ref, "runtime.job")
    outbox_value = _atom(db, namespace, runtime.outbox_ref, "runtime.outbox")
    outbox = RuntimeOutboxValue(**outbox_value)
    lease = get_budget_lease(db, runtime_admission.budget.lease_id)
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (lease.lease_id, identity.operation_id),
    ).fetchone()
    _require(reservation is not None and reservation[2] == "reserved",
             "natural D11 reservation missing")
    ceiling = json.loads(reservation[1])
    from ..graph_coordinator import budget_operation_digest
    budget_digest = budget_operation_digest(bundle.envelope, lease.lease_id, ceiling)
    selected = _message_reservation_dimension_limit(lease, ceiling)
    _require(reservation[0] == budget_digest and selected is not None
             and lease.version == runtime_admission.budget.expected_version
             and job == runtime_admission.jobs[0].job
             and job_graph_write(job).value == job_value
             and outbox_graph_write(outbox, AtomKey.from_token(runtime.job_ref)).value
             == outbox_value
             and job.phase == "waiting" and job.fence == 0
             and job.wake_condition == {
                 "kind": "post_c02_reply_host_takeover",
                 "operation_id": identity.operation_id,
             }
             and outbox.phase == "pending"
             and outbox.payload_ref == natural_dispatch_segment_payload_ref_v2(
                 evidence.batch_ref, batch["segment"]["position"])
             and outbox.dispatch_generation == scope.generation
             and outbox.idempotency_key == bundle.idempotency_keys[0],
             "natural current D11 command originals changed")
    dimension, limit = selected
    footprint = RecoveryConstraintFootprint(
        "/".join(namespace.as_tuple), identity.activity_id, identity.effect_id,
        external_idempotency_ref=outbox.idempotency_key,
        conflict_keys=(f"target:{grant.target_ref}",),
        communication_action=grant.communication_action_id,
        contact_id=grant.contact_id, segment_id=evidence.segment_id,
        budgets=(BudgetConstraint(
            lease.lease_id, str(lease.used.get(dimension, 0)),
            str(lease.reserved.get(dimension, 0)
                + lease.unconfirmed.get(dimension, 0)), str(limit),
        ),),
    )
    command_digest = canonical_digest({
        "operation_id": identity.operation_id,
        "outbox_ref": runtime.outbox_ref,
        "idempotency_key": outbox.idempotency_key,
        "batch_ref": evidence.batch_ref,
        "segment_index": batch["segment"]["position"],
        "payload_digest": evidence.payload_digest,
        "fence_token": scope.permit.token,
    })
    request = DispatchRequest(
        "/".join(namespace.as_tuple), identity.operation_id,
        identity.activity_id, identity.effect_id, identity.attempt_id,
        command_digest, outbox.payload_ref, evidence.payload_digest,
        "platform:astrbot-private-v1", grant.required_check_refs,
        outbox.dispatch_generation, scope.generation, job.fence,
        scope.permit.token, batch["cancellation_epoch"], footprint,
        False, batch["segment_authorization_ref"],
        grant.segment_manifest_digest, batch["segment"]["position"], natural_batch_segment_count(batch),
    )
    deadline = int(min(
        batch["valid_until"],
        datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
        *(receipt.valid_until for receipt in checks),
    ))
    _require(deadline > now_utc, "natural dispatch deadline expired")
    admission = DispatchAdmissionV1(
        namespace=request.namespace, graph_incarnation=owner_row[0],
        activity_id=identity.activity_id, effect_id=identity.effect_id,
        attempt_id=identity.attempt_id, operation_id=identity.operation_id,
        dispatch_generation=request.dispatch_generation,
        admission_ref="admission:" + canonical_digest({
            "operation_id": identity.operation_id,
            "effect_id": identity.effect_id,
            "candidate": evidence.digest,
        })[:40],
        candidate_digest=evidence.digest, request_digest=canonical_digest(request),
        action_intent_digest=evidence.action_digest,
        action_intent_schema_version="d08.action_intent.v1",
        action_schema_digest=evidence.schema_digest,
        action_schema_version="d08.action_schema.v1",
        required_checks_digest=canonical_digest(action.required_checks),
        required_checks_schema_version="d08.required_check_spec.v1",
        grant_digest=evidence.grant_digest, batch_digest=evidence.batch_digest,
        segment_index=batch["segment"]["position"], payload_digest=evidence.payload_digest,
        account_ref=route.platform_ref,
        destination_ref=route.conversation_ref, scene_ref=route.scene_ref,
        owner_head_ref=owner.grant_id, role_ref=role.social_role,
        binding_ref=role.role_binding_id, object_ref=action.target_ref,
        action_ref=action.action_id, purpose=action.purpose,
        audience=(route.conversation_ref,),
        graph_reads=tuple((version.key.token, version.revision)
                          for version in snapshot.versions),
        query_epoch=query.revision, access_epoch=evidence.access_epoch,
        delete_epoch=evidence.delete_epoch, check_receipts=checks,
        budget_parent_lease_ref=lease.lease_id, budget_lease_ref=lease.lease_id,
        budget_reservation_operation_id=identity.operation_id,
        budget_reservation_digest=budget_digest, budget_ceiling=ceiling,
        budget_currency=lease.currency, budget_version=lease.version,
        contact_reservation_ref=None,
        utc_deadline=datetime.fromtimestamp(deadline, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        clock_policy_ref=clock_policy.source_id,
        clock_policy_digest=canonical_digest(asdict(clock_policy)),
    )
    check_receipts_against_specs(admission, action.required_checks, now_utc)
    receipt = DispatchAdmissionReceiptV1(
        admission, scope.graph_revision + 1, graph_receipt.epoch.revision,
        canonical_digest({
            "admission_digest": admission.digest,
            "graph_revision": scope.graph_revision + 1,
            "graph_epoch": graph_receipt.epoch.revision,
        }),
    )
    return receipt, request


__all__ = ["NaturalDispatchAdmissionHold", "issue_natural_dispatch_admission_v2"]
