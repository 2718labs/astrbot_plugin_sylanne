"""Installed outbound admission from current graph and authenticated V2 reads."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
import sqlite3
from typing import TYPE_CHECKING

from ..domains.d06 import SourceGrantRead, provide_source_grant_check
from ..domains.d03 import ContextProvider, RoleBindingRequest
from ..domains.d03 import RoleBinding
from ..domains.d05 import RelationshipProvider
from ..domains.d08 import (
    ActionIntent, ActionSchema, ActionSchemaRecord, CommitmentConflictSnapshot,
    GoalExecutionProvider, RequiredCheckSpec,
)
from ..domains.d09 import D09ExpressionProvider
from ..graph_types import AtomKey, GraphAtom, GraphReceipt, GraphSnapshot, NamespaceEpoch
from ..runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from ..runtime.dispatch_candidate import dispatch_segment_payload_ref
from ..dispatch_runtime import DispatchRequest
from ..runtime_journal import BudgetConstraint, RecoveryConstraintFootprint
from ..runtime_contracts import (
    CheckReceipt, FenceScope, NamespaceId, QueryEpoch, VersionedRef,
    canonical_digest,
)
from .budget import BudgetError, get_budget_lease, require_budget_family_admissible
from .dispatch_admission import DispatchAdmissionV1
from .dispatch_budget_check import provide_dispatch_budget_check
from .dispatch_current_projection import (
    CurrentDispatchProjectionV1, derive_current_domain_reads,
    read_current_dispatch_projection,
)
from .dispatch_current_commitments import read_current_d08_conflict_facts
from .dispatch_current_commitment_check import CRITERIA_REF, CRITERIA_VERSION
from .d11_types import RuntimeOutboxValue, job_graph_write
from .jobs import JobConflict, get_job
from .issuers import D02ResourceIssuer, D11BudgetGrantIssuer, IssuerAuthorityDenied

if TYPE_CHECKING:
    from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from ..host.authority_profile import AdminIngressClockPolicy
    from ..host.v2_fence_port import VerifiedIngressClockV2


@dataclass(frozen=True, slots=True)
class TrustedDispatchAdmissionContextV1:
    """Coordinator-held service observations paired with one graph write.

    Construction alone is not Authority proof. The coordinator validates the
    installed V2 write fence before this transaction and finishes it after.
    """

    scope: FenceScope
    clock_reading: VerifiedIngressClockV2
    clock_policy: AdminIngressClockPolicy
    projection: CurrentDispatchProjectionV1
    graph_receipt: GraphReceipt
    owner_guard: OwnerAuthorizationGuardV1 | None
    current_effect: CurrentEffectReadV2 | None


@dataclass(frozen=True)
class DispatchSourceInspectionV1:
    status: str
    missing: tuple[str, ...]
    observed_versions: tuple[tuple[str, int], ...]
    provider_result: str | None
    receipt: CheckReceipt | None = None


@dataclass(frozen=True)
class DispatchSocialInspectionV1:
    status: str
    missing: tuple[str, ...]
    role_receipt: CheckReceipt | None
    boundary_receipt: CheckReceipt | None
    graph_epoch: int | None


@dataclass(frozen=True)
class DispatchBudgetInspectionV1:
    status: str
    missing: tuple[str, ...]
    receipt: CheckReceipt | None
    lease_id: str | None
    quote_id: str | None


@dataclass(frozen=True)
class DispatchCommitmentInspectionV1:
    status: str
    missing: tuple[str, ...]
    graph_epoch: int | None
    commitment_refs: tuple[str, ...]
    action_refs: tuple[str, ...]
    receipt: CheckReceipt | None = None


@dataclass(frozen=True)
class DispatchPrivateRouteInspectionV1:
    status: str
    missing: tuple[str, ...]
    account_ref: str | None = None
    destination_ref: str | None = None
    scene_ref: str | None = None


@dataclass(frozen=True)
class DispatchOwnerInspectionV1:
    status: str
    missing: tuple[str, ...]
    grant_id: str | None = None


@dataclass(frozen=True)
class DispatchCommandInspectionV1:
    status: str
    missing: tuple[str, ...]
    request: DispatchRequest | None = None
    budget_ceiling: dict[str, int] | None = None
    budget_reservation_digest: str | None = None


def inspect_current_private_command(
    db, bundle, candidate: DispatchCandidateEvidenceV1,
    budget: DispatchBudgetInspectionV1,
    route: DispatchPrivateRouteInspectionV1, *,
    trusted_context: TrustedDispatchAdmissionContextV1 | None,
    now_utc: float,
) -> DispatchCommandInspectionV1:
    """Construct a private text command from current D09/D11 graph and ledger."""
    def hold(reason: str) -> DispatchCommandInspectionV1:
        return DispatchCommandInspectionV1("hold", (reason,))

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if (type(trusted_context) is not TrustedDispatchAdmissionContextV1
            or budget.status != "check_pass" or route.status != "route_verified"
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return hold("dispatch.current_authority_budget_route_inputs")
    if (len(bundle.persistent_job_refs) != 1 or len(bundle.outbox_refs) != 1):
        return hold("dispatch.unique_d11_job_outbox")
    try:
        namespace = trusted_context.scope.namespace
        identity = bundle.envelope.identity
        batch = _current_atom(db, namespace, candidate.batch_ref,
                              "d09.verified_segment_batch.v1").value
        grant = _current_atom(db, namespace, candidate.grant_ref,
                              "d08.communication_intent_grant.v1").value
        next(item for item in D09ExpressionProvider.register_types()
             if item.name == "d09.verified_segment_batch.v1").validator(batch)
        grant_type = next(item for item in GoalExecutionProvider().register_types()
                          if item.name == "d08.communication_intent_grant.v1")
        frozen_grant = grant_type.validator(grant)
        job_ref = bundle.persistent_job_refs[0]
        outbox_ref = bundle.outbox_refs[0]
        job_atom = _current_atom(db, namespace, job_ref, "runtime.job")
        outbox_atom = _current_atom(db, namespace, outbox_ref, "runtime.outbox")
        outbox = RuntimeOutboxValue(**outbox_atom.value)
        job = get_job(db, outbox.job_id)
        lease = get_budget_lease(db, budget.lease_id)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (budget.lease_id, identity.operation_id),
        ).fetchone()
        if reservation is None:
            return hold("dispatch.current_budget_reservation_missing")
        ceiling = json.loads(reservation[1])
        if (job_atom.value != job_graph_write(job).value
                or outbox.job_ref != job_ref or outbox.job_id != job.job_id
                or outbox.phase != "pending" or job.phase != "queued"
                or (job.bot_id, job.persona_id) != namespace.as_tuple
                or (job.activity_id, job.operation_id, job.effect_id) != (
                    identity.activity_id, identity.operation_id, identity.effect_id)
                or (outbox.activity_id, outbox.operation_id, outbox.effect_id) != (
                    identity.activity_id, identity.operation_id, identity.effect_id)
                or outbox.dispatch_generation != trusted_context.scope.generation
                or outbox.payload_ref != dispatch_segment_payload_ref(
                    candidate.batch_ref, 0)
                or reservation[2] != "reserved" or not ceiling
                or len(ceiling) != 1 or len(lease.limits) != 1
                or budget.receipt is None
                or frozen_grant.required_check_refs
                != tuple(batch["required_check_refs"])
                or frozen_grant.contact_id != batch["contact_id"]
                or frozen_grant.segment_manifest_digest
                != batch["grant_manifest_digest"]):
            return hold("dispatch.current_job_outbox_budget_batch_differs")
        dimension, limit = next(iter(lease.limits.items()))
        if (set(ceiling) != {dimension} or ceiling[dimension] <= 0
                or lease.state != "active"):
            return hold("dispatch.narrow_single_dimension_budget")
        segment = batch["segments"][0]
        deadline = min(
            float(batch["valid_until"]),
            datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
        )
        deadline = int(deadline)
        if deadline <= now_utc:
            return hold("dispatch.current_job_or_batch_expired")
        footprint = RecoveryConstraintFootprint(
            "/".join(namespace.as_tuple), identity.activity_id,
            identity.effect_id,
            external_idempotency_ref=outbox.idempotency_key,
            conflict_keys=(f"target:{frozen_grant.target_ref}",),
            communication_action=frozen_grant.communication_action_id,
            contact_id=frozen_grant.contact_id,
            segment_id=segment["segment_id"],
            budgets=(BudgetConstraint(
                lease.lease_id, str(lease.used.get(dimension, 0)),
                str(lease.reserved.get(dimension, 0)
                    + lease.unconfirmed.get(dimension, 0)), str(limit),
            ),),
        )
        command_digest = canonical_digest({
            "operation_id": identity.operation_id,
            "outbox_ref": outbox_ref,
            "idempotency_key": outbox.idempotency_key,
            "batch_ref": candidate.batch_ref,
            "segment_index": 0,
            "payload_digest": segment["payload_digest"],
            "fence_token": trusted_context.scope.permit.token,
        })
        request = DispatchRequest(
            "/".join(namespace.as_tuple), identity.operation_id,
            identity.activity_id, identity.effect_id, identity.attempt_id,
            command_digest, outbox.payload_ref, segment["payload_digest"],
            "platform:astrbot-private-v1", frozen_grant.required_check_refs,
            outbox.dispatch_generation, trusted_context.scope.generation,
            job.fence, trusted_context.scope.permit.token,
            batch["cancellation_epoch"],
            footprint, False, segment["segment_authorization_ref"],
            frozen_grant.segment_manifest_digest, 0, 1,
        )
    except (sqlite3.OperationalError, JobConflict, BudgetError, KeyError,
            TypeError, ValueError, StopIteration, json.JSONDecodeError):
        return hold("dispatch.current_command_journal_read_unavailable")
    return DispatchCommandInspectionV1(
        "command_verified", (), request, ceiling, reservation[0],
    )


def inspect_current_owner_grant(
    db, namespace: NamespaceId, audience: tuple[str, ...], purpose: str,
    *, trusted_context: TrustedDispatchAdmissionContextV1 | None,
    graph_incarnation: str,
) -> DispatchOwnerInspectionV1:
    """Join current graph Owner grant/proof to the V2 current guard."""
    def hold(reason: str) -> DispatchOwnerInspectionV1:
        return DispatchOwnerInspectionV1("hold", (reason,))

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if (type(namespace) is not NamespaceId
            or type(trusted_context) is not TrustedDispatchAdmissionContextV1
            or trusted_context.owner_guard is None):
        return hold("d01.current_authority_owner_guard")
    try:
        from dataclasses import asdict
        from ..authority_service.v2_owner_contract import (
            OwnerGraphCommitProofV1, canonical_digest as owner_digest,
        )
        from ..contracts import canonical_json
        from ..graph_coordinator import owner_grant_key
        from ..graph_types import validate_owner_grant_v1

        guard = trusted_context.owner_guard
        anchor = trusted_context.scope.pinned_anchor
        grant_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*namespace.as_tuple).token,),
        ).fetchone()
        proof_row = db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json FROM "
            "graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        if grant_row is None or proof_row is None:
            return hold("d01.current_owner_graph_grant_or_proof_missing")
        grant = json.loads(grant_row[1])
        validate_owner_grant_v1(grant)
        proof = OwnerGraphCommitProofV1(
            namespace, proof_row[0], proof_row[1], proof_row[2],
            proof_row[3], proof_row[4], grant["grant_revision"],
            proof_row[5], proof_row[6], proof_row[7],
        )
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        if (grant_row != (1, canonical_json(grant), 1)
                or proof_row[8] != canonical_json(asdict(proof))
                or "sha256:" + canonical_digest(grant) != proof.grant_digest
                or grant["grant_id"] != proof.grant_id
                or grant["issue_operation_id"] != proof.operation_id
                or grant["graph_incarnation"] != graph_incarnation
                or proof.graph_incarnation != graph_incarnation
                or epochs is None
                or proof.graph_access_epoch > epochs[0]
                or proof.graph_epoch > trusted_context.scope.graph_epoch.revision
                or purpose not in grant["purposes"]
                or not set(audience).issubset(grant["audiences"])
                or guard.namespace != namespace
                or guard.authority_id != anchor.authority_id
                or guard.authority_id != grant["authority_id"]
                or guard.installation_id != grant["installation_id"]
                or guard.authorization_revision != grant["grant_revision"]
                or guard.authorization_head != owner_digest(proof)
                or guard.minimum_revocation_revision != 0
                or guard.minimum_revocation_epoch != 0
                or guard.pending_revoke_operation_id is not None
                or anchor.revocation_epoch != 0):
            return hold("d01.current_owner_authorization_differs")
    except (ImportError, sqlite3.OperationalError, TypeError, ValueError,
            KeyError, json.JSONDecodeError):
        return hold("d01.current_owner_graph_proof_unavailable")
    return DispatchOwnerInspectionV1("owner_verified", (), grant["grant_id"])


def inspect_current_private_route(
    db, candidate: DispatchCandidateEvidenceV1, *, now_utc: float,
) -> DispatchPrivateRouteInspectionV1:
    """Bind one D09 text segment to a durable host ingress route in this tx."""
    def hold(*missing: str) -> DispatchPrivateRouteInspectionV1:
        return DispatchPrivateRouteInspectionV1(
            "hold", tuple(dict.fromkeys(missing)),
        )

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if (type(candidate) is not DispatchCandidateEvidenceV1
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or len(candidate.source_refs) != 1
            or len(candidate.source_audience) != 1):
        return hold("d09.narrow_single_source_private_route")
    try:
        from ..runtime.first_ingress_v2 import scene_ref_for_conversation
        from ..host.identity import astrbot_namespace

        key = AtomKey.from_token(candidate.batch_ref)
        namespace = NamespaceId(key.owner.bot, key.owner.persona)
        batch = _current_atom(db, namespace, candidate.batch_ref,
                              "d09.verified_segment_batch.v1").value
        next(item for item in D09ExpressionProvider.register_types()
             if item.name == "d09.verified_segment_batch.v1").validator(batch)
        source_key = AtomKey.from_token(candidate.source_refs[0])
        if (source_key.type_name != "memory.source"
                or source_key.name != "record"
                or (source_key.owner.bot, source_key.owner.persona)
                != namespace.as_tuple):
            return hold("d09.canonical_host_ingress_source")
        rows = db.execute(
            "SELECT platform_ref,conversation_ref,visibility FROM "
            "graph_first_ingress_identity_v1 WHERE bot=? AND persona=? "
            "AND source_ref=?",
            (*namespace.as_tuple, source_key.owner.subject),
        ).fetchall()
        if len(rows) != 1:
            return hold("d09.unique_committed_host_ingress_route")
        account_ref, destination_ref, visibility = rows[0]
        account = json.loads(account_ref)
        destination = json.loads(destination_ref)
        if (visibility != "private" or type(account) is not list
                or len(account) != 3 or type(destination) is not list
                or len(destination) != 2
                or any(type(item) is not str or not item
                       for item in (*account, *destination))
                or json.dumps(account, ensure_ascii=True, separators=(",", ":"))
                != account_ref
                or json.dumps(destination, ensure_ascii=True, separators=(",", ":"))
                != destination_ref
                or astrbot_namespace(account[0], account[2], "route-check").bot_id
                != namespace.bot_id):
            return hold("d09.private_astrbot_ingress_identity")
        expected_scene = scene_ref_for_conversation(
            namespace, account_ref, destination_ref,
        )
        if (tuple(batch["audiences"]) != (destination_ref,)
                or candidate.source_audience != (destination_ref,)
                or batch["scene_ref"] != expected_scene
                or len(batch["segments"]) != 1
                or batch["segments"][0]["media_refs"]
                or float(batch["valid_until"]) <= now_utc):
            return hold("d09.current_private_batch_route_or_segment_differs")
    except (sqlite3.OperationalError, TypeError, ValueError, KeyError,
            StopIteration, json.JSONDecodeError):
        return hold("d09.current_host_ingress_route_unavailable")
    return DispatchPrivateRouteInspectionV1(
        "route_verified", (), account_ref, destination_ref, expected_scene,
    )


class DispatchAdmissionHold(RuntimeError):
    def __init__(self, missing: tuple[str, ...]):
        self.missing = tuple(dict.fromkeys(missing))
        super().__init__("dispatch admission HOLD: " + ", ".join(self.missing))


def inspect_current_d06_source_grant(
    db, intent: ActionIntent, spec: RequiredCheckSpec,
    candidate: DispatchCandidateEvidenceV1, *, audience: tuple[str, ...],
    trusted_context: TrustedDispatchAdmissionContextV1 | None = None,
    now_utc: float | None = None,
) -> DispatchSourceInspectionV1:
    """Read D06 inputs from the caller-held graph transaction.

    A scoped PASS requires the coordinator's prevalidated V2 write fence. Its
    Authority validation rejects historical deletion closures and pins the
    independent deletion/execution heads. SQLite rows alone cannot prove it.
    """
    if not getattr(db, "in_transaction", False):
        raise DispatchAdmissionHold(("graph.current_write_transaction",))
    if (type(intent) is not ActionIntent or type(spec) is not RequiredCheckSpec
            or type(candidate) is not DispatchCandidateEvidenceV1
            or type(audience) is not tuple):
        raise DispatchAdmissionHold(("d06.typed_action_spec_candidate_audience",))
    if (spec.check_kind, spec.provider_id) != ("source_grant", "d06.source_grant"):
        raise DispatchAdmissionHold(("d06.source_grant_spec",))
    if (candidate.status != "source_qualified"
            or candidate.action_digest != canonical_digest(intent)
            or candidate.source_refs != intent.source_refs
            or candidate.source_audience != audience
            or spec not in intent.required_checks):
        raise DispatchAdmissionHold(("d06.qualified_candidate_identity",))
    try:
        source_key = AtomKey.from_token(intent.source_refs[0])
        namespace = NamespaceId(source_key.owner.bot, source_key.owner.persona)
    except (IndexError, TypeError, ValueError) as exc:
        raise DispatchAdmissionHold(("d06.canonical_source_namespace",)) from exc
    if (spec.subject_ref != f"persona:{namespace.persona_id}"
            or spec.action_ref != intent.action_id
            or spec.purpose != "expression"):
        raise DispatchAdmissionHold(("d06.source_grant_scope",))
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    expected_epoch = (trusted_context.graph_receipt.epoch.revision
                      if type(trusted_context) is TrustedDispatchAdmissionContextV1
                      else candidate.query_epoch)
    if (epoch_row is None or epoch_row[0] != expected_epoch
            or (trusted_context is not None
                and (expected_epoch != candidate.query_epoch + 1
                     or trusted_context.scope.graph_epoch.revision
                     != candidate.query_epoch
                     or trusted_context.scope.namespace != namespace))):
        raise DispatchAdmissionHold(("d06.current_graph_epoch",))
    guard_row = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if guard_row != (candidate.access_epoch, candidate.delete_epoch):
        raise DispatchAdmissionHold(("d06.current_access_delete_epochs",))
    required = candidate.source_proof_versions
    if (not required or len(required) != len(set(ref for ref, _ in required))
            or set(required) != set(candidate.source_read_versions +
                                    candidate.access_read_versions)):
        raise DispatchAdmissionHold(("d06.complete_source_access_read_set",))
    atoms = []
    proof = []
    for ref, revision in required:
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError) as exc:
            raise DispatchAdmissionHold(("d06.canonical_graph_ref",)) from exc
        if ((key.owner.bot, key.owner.persona) != namespace.as_tuple
                or key.type_name not in {"memory.source", "memory.access"}):
            raise DispatchAdmissionHold(("d06.source_access_namespace",))
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (ref, *namespace.as_tuple),
        ).fetchone()
        if row is None or row[0] != revision or row[2] != 1:
            raise DispatchAdmissionHold(("d06.current_source_access_versions",))
        try:
            value = json.loads(row[1])
            atom = GraphAtom(key, revision, value, True)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DispatchAdmissionHold(("d06.current_source_access_values",)) from exc
        atoms.append(atom)
        proof.append((ref, revision, canonical_digest(atom.value)))
    if canonical_digest(proof) != candidate.source_proof_digest:
        raise DispatchAdmissionHold(("d06.current_source_access_content",))
    snapshot = GraphSnapshot(tuple(atoms), (
        NamespaceEpoch(*namespace.as_tuple, expected_epoch),
    ))
    barrier = False
    if trusted_context is not None:
        if type(trusted_context) is not TrustedDispatchAdmissionContextV1:
            raise DispatchAdmissionHold(("d06.trusted_admission_context",))
        scope = trusted_context.scope
        if (type(scope) is not FenceScope or scope.operation != "write"
                or scope.namespace != namespace
                or scope.graph_epoch.revision != candidate.query_epoch
                or scope.pinned_anchor != scope.permit.pinned_anchor):
            raise DispatchAdmissionHold(("d06.current_authority_write_scope",))
        barrier = True
    if barrier and (type(now_utc) not in (int, float)
                    or not math.isfinite(now_utc)):
        raise DispatchAdmissionHold(("d06.trusted_admission_time",))
    try:
        receipt = provide_source_grant_check(
            intent, SourceGrantRead(snapshot, audience, "expression", True, barrier),
            valid_until=now_utc + 1.0 if barrier else 0.0,
        )
    except (TypeError, ValueError) as exc:
        raise DispatchAdmissionHold(("d06.provider_recomputation",)) from exc
    if barrier and receipt.result == "pass" and receipt.coverage == "full":
        return DispatchSourceInspectionV1(
            "check_pass", (), required, receipt.result, receipt,
        )
    return DispatchSourceInspectionV1(
        "hold", (("d06.current_source_grant_not_pass",) if barrier else
                 ("d06.independent_deletion_authority_barrier",)),
        required, receipt.result,
    )


def _current_atom(db, namespace: NamespaceId, ref: str, expected_type: str,
                  expected_digest: str | None = None) -> GraphAtom:
    key = AtomKey.from_token(ref)
    if (key.type_name != expected_type
            or (key.owner.bot, key.owner.persona) != namespace.as_tuple):
        raise ValueError("graph atom scope differs")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?", (ref, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[2] != 1:
        raise ValueError("current graph atom unavailable")
    value = json.loads(row[1])
    atom = GraphAtom(key, row[0], value, True)
    if expected_digest is not None and canonical_digest(atom.value) != expected_digest:
        raise ValueError("current graph atom content differs")
    return atom


def inspect_current_d03_d05(
    db, candidate: DispatchCandidateEvidenceV1, *,
    context: ContextProvider, now_utc: float,
    trusted_context: TrustedDispatchAdmissionContextV1 | None = None,
) -> DispatchSocialInspectionV1:
    """Issue scoped D03/D05 candidates from a complete current namespace read.

    The installed ContextProvider must carry the trusted active D03 catalogue.
    The D09 audience is read from the graph; an ambiguous audience mapping
    stays HOLD rather than selecting a convenient D05 boundary scope.
    """
    def hold(*missing: str, role=None, boundary=None, epoch=None):
        return DispatchSocialInspectionV1("hold", tuple(dict.fromkeys(missing)),
                                          role, boundary, epoch)

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if (type(candidate) is not DispatchCandidateEvidenceV1
            or type(context) is not ContextProvider
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return hold("social.typed_installed_context_and_time")
    try:
        key = AtomKey.from_token(candidate.action_ref)
        namespace = NamespaceId(key.owner.bot, key.owner.persona)
        epoch_row = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        expected_epoch = (trusted_context.graph_receipt.epoch.revision
                          if type(trusted_context) is TrustedDispatchAdmissionContextV1
                          else candidate.query_epoch)
        if (epoch_row is None or epoch_row[0] != expected_epoch
                or (trusted_context is not None
                    and (expected_epoch != candidate.query_epoch + 1
                         or trusted_context.scope.graph_epoch.revision
                         != candidate.query_epoch
                         or trusted_context.scope.namespace != namespace))):
            return hold("social.current_graph_epoch")
        epoch = epoch_row[0]
        action_atom = _current_atom(db, namespace, candidate.action_ref,
                                    "d08.action_intent.v1")
        schema_atom = _current_atom(db, namespace, candidate.schema_ref,
                                    "d08.action_schema.v1")
        batch_atom = _current_atom(db, namespace, candidate.batch_ref,
                                   "d09.verified_segment_batch.v1")
        d08 = {item.name: item for item in GoalExecutionProvider().register_types()}
        intent = d08["d08.action_intent.v1"].validator(action_atom.value)
        record = d08["d08.action_schema.v1"].validator(schema_atom.value)
        next(item for item in D09ExpressionProvider.register_types()
             if item.name == "d09.verified_segment_batch.v1").validator(batch_atom.value)
        batch = batch_atom.value
        frozen = ActionSchema(record.schema_id, record.action_kind,
                              record.proactive, record.required_checks)
        expected_activity = intent.identity.activity_id
        if (candidate.action_digest != canonical_digest(intent)
                or candidate.schema_digest != canonical_digest(record)
                or candidate.batch_digest != batch["batch_digest"]
                or record != ActionSchemaRecord.bind(intent, frozen)
                or intent.identity.operation_id != candidate.operation_id
                or any(atom.key.owner.kind != "activity"
                       or atom.key.owner.subject != expected_activity
                       for atom in (action_atom, schema_atom, batch_atom))
                or action_atom.key.name != intent.action_id
                or schema_atom.key.name != record.schema_ref
                or batch_atom.key.name != batch["batch_id"]
                or batch["action_id"] != intent.action_id
                or batch["target_ref"] != intent.target_ref
                or batch["scene_ref"][:6] != "scene:"):
            return hold("social.current_action_schema_batch_identity")
        audience = tuple(batch["audiences"])
        if len(audience) != 1 or audience != candidate.source_audience:
            return hold("social.current_d09_audience_scope")
        scene = batch["scene_ref"]
        rows = db.execute(
            "SELECT token,revision,value,type_name FROM graph_atoms "
            "WHERE bot=? AND persona=? AND type_name IN "
            "('d03.role_binding','d05.boundary_rule') AND valid=1 ORDER BY token",
            namespace.as_tuple,
        ).fetchall()
        atoms = tuple(GraphAtom(AtomKey.from_token(token), revision,
                                json.loads(raw), True)
                      for token, revision, raw, _ in rows)
        snapshot = GraphSnapshot(atoms, (NamespaceEpoch(*namespace.as_tuple, epoch),))
        projection = read_current_dispatch_projection(
            db, namespace, snapshot, QueryEpoch(namespace, "all", epoch),
        )
        request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", intent.target_ref, None,
            scene, intent.action_kind, intent.purpose, now_utc, True,
        )
        role_read, boundary_read = derive_current_domain_reads(
            db, projection, request, context,
        )
        specs = {item.check_kind: item for item in intent.required_checks
                 if item.check_kind in {"role_binding", "boundary"}}
        if (len(specs) != 2 or specs["role_binding"].provider_id != "d03.role_binding"
                or specs["boundary"].provider_id != "d05.boundary"):
            return hold("social.frozen_required_check_specs", epoch=epoch)
        for spec in specs.values():
            criteria = next(item for item in spec.required_input_versions
                            if item.ref == spec.criteria_version)
            criterion = _current_atom(
                db, namespace, criteria.ref,
                AtomKey.from_token(criteria.ref).type_name,
            )
            if criterion.revision != criteria.version:
                return hold("social.current_criteria_version", epoch=epoch)
        role = context.provide_required_check(
            intent, role_read, valid_until=now_utc + 1.0,
        )
        boundary_criteria = next(item for item in specs["boundary"].required_input_versions
                                 if item.ref == specs["boundary"].criteria_version)
        from dataclasses import replace
        boundary_read = replace(
            boundary_read, input_versions=boundary_read.input_versions +
            (boundary_criteria,),
        )
        boundary = RelationshipProvider(
            boundary_read_verifier=lambda read: read == boundary_read,
        ).boundary_required_check(
            intent, frozen, boundary_read, audience_scope=audience[0],
            scene_ref=scene, at_time=now_utc, valid_until=now_utc + 1.0,
        )
    except (TypeError, ValueError, KeyError, StopIteration, json.JSONDecodeError):
        return hold("social.current_graph_provider_read_unavailable")
    missing = []
    if any(rule.subject_persona_ref == f"persona:{namespace.persona_id}"
           and rule.target_entity_ref == intent.target_ref
           and rule.action_kind == intent.action_kind
           and (rule.scene_ref is None or rule.scene_ref == scene)
           and rule.audience_scope != audience[0]
           for rule in boundary_read.rules):
        missing.append("d05.audience_scope_mapping_unavailable")
    if role.result != "pass" or role.coverage != "full":
        missing.append("d03.current_role_binding_not_pass")
    if boundary.result != "pass" or boundary.coverage != "full":
        missing.append("d05.current_boundary_not_pass")
    if projection.coverage != "full":
        missing.extend(projection.missing_sources)
    return DispatchSocialInspectionV1(
        "hold" if missing else "checks_pass", tuple(dict.fromkeys(missing)),
        role, boundary, epoch,
    )


def inspect_current_d11_dispatch_budget(
    db, intent: ActionIntent, *, d11_issuer: D11BudgetGrantIssuer | None,
    d02_issuer: D02ResourceIssuer | None, now_utc: float,
) -> DispatchBudgetInspectionV1:
    """Recompute one scoped D11 budget check from signed and durable state.

    The frozen RequiredCheckSpec uses the signed D02 quote VersionedRef as its
    criteria_version. The existing D11 provider excludes only that criteria
    ref while recomputing the exact lease/grant/reservation read set. This
    seam verifies that the excluded ref really names the active signed quote
    bound to the action and held reservation.
    The independent execution journal is a separate, still required gate.
    """
    def hold(*missing: str, lease_id=None, quote_id=None):
        return DispatchBudgetInspectionV1(
            "hold", tuple(dict.fromkeys(missing)), None, lease_id, quote_id,
        )

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if type(intent) is not ActionIntent or type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        return hold("d11.typed_current_action_and_time")
    if not isinstance(d11_issuer, D11BudgetGrantIssuer):
        return hold("d11.installed_signed_budget_grant_issuer")
    if not isinstance(d02_issuer, D02ResourceIssuer):
        return hold("d11.installed_signed_d02_quote_issuer")
    specs = tuple(spec for spec in intent.required_checks
                  if spec.check_kind == "dispatch_budget")
    if len(specs) != 1 or specs[0].provider_id != "d11.dispatch_budget":
        return hold("d11.unique_frozen_dispatch_budget_spec")
    spec = specs[0]
    if (spec.subject_ref != "persona:" + spec.subject_ref.removeprefix("persona:")
            or spec.action_ref != intent.action_id or spec.purpose != intent.purpose):
        return hold("d11.frozen_budget_scope")
    versions = spec.required_input_versions
    by_ref = {item.ref: item.version for item in versions}
    if len(by_ref) != len(versions):
        return hold("d11.duplicate_frozen_budget_refs")
    lease_refs = tuple(ref for ref in by_ref if ref.startswith("d11.budget.grant:"))
    if len(lease_refs) != 1:
        return hold("d11.frozen_spec_missing_signed_grant_version")
    lease_id = lease_refs[0].removeprefix("d11.budget.grant:")
    quote_refs = tuple(ref for ref in by_ref if ref.startswith("d02.resource_quote:"))
    if len(quote_refs) != 1:
        return hold("d11.frozen_spec_missing_signed_d02_quote_version", lease_id=lease_id)
    quote_id = quote_refs[0].removeprefix("d02.resource_quote:")
    if spec.criteria_version != quote_refs[0]:
        return hold("d11.criteria_not_signed_d02_quote_ref", lease_id=lease_id,
                    quote_id=quote_id)
    try:
        quote = d02_issuer._load_quote(db, quote_id, by_ref[quote_refs[0]])
        grant = d11_issuer.current_budget_grant(db, lease_id)
        lease = get_budget_lease(db, lease_id)
        require_budget_family_admissible(db, lease_id)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (lease_id, intent.identity.operation_id),
        ).fetchone()
    except (IssuerAuthorityDenied, BudgetError, ValueError, TypeError):
        return hold("d11.current_signed_quote_grant_or_lease_unavailable",
                    lease_id=lease_id, quote_id=quote_id)
    if (reservation is None or reservation[2] != "reserved"):
        return hold("d11.current_operation_reservation_unavailable",
                    lease_id=lease_id, quote_id=quote_id)
    try:
        ceiling = json.loads(reservation[1])
    except (TypeError, ValueError, json.JSONDecodeError):
        return hold("d11.current_reservation_ceiling_invalid",
                    lease_id=lease_id, quote_id=quote_id)
    if (quote.quote_id != quote_id or quote.version != by_ref[quote_refs[0]]
            or quote.persona_id != spec.subject_ref.removeprefix("persona:")
            or (quote.activity_id, quote.effect_id, quote.operation_id) != (
                intent.identity.activity_id, intent.identity.effect_id,
                intent.identity.operation_id)
            or quote.work_kind != intent.action_kind
            or quote.parent_budget_lease_ref != lease_id
            or quote.valid_until_utc <= now_utc
            or quote.deadline_utc <= now_utc
            or dict(quote.ceiling) != ceiling
            or (lease.bot_id, lease.persona_id, lease.currency) != (
                quote.bot_id, quote.persona_id, grant.currency)
            or grant.valid_until_utc <= now_utc):
        return hold("d11.signed_quote_reservation_scope_or_ceiling_differs",
                    lease_id=lease_id, quote_id=quote_id)
    reservation_ref = (
        f"d11.budget.reservation:{lease_id}:{intent.identity.operation_id}:"
        f"{reservation[0]}"
    )
    if by_ref.get(reservation_ref) != 1:
        return hold("d11.frozen_spec_reservation_digest_differs",
                    lease_id=lease_id, quote_id=quote_id)
    try:
        ledger = provide_dispatch_budget_check(
            intent, db, d11_issuer,
            namespace=NamespaceId(quote.bot_id, quote.persona_id),
            lease_id=lease_id,
            reservation_operation_id=intent.identity.operation_id,
            reservation_digest=reservation[0], required_ceiling=quote.ceiling,
            work_kind=quote.work_kind, policy_ref=grant.policy_ref,
            now_utc=now_utc,
            valid_until=min(quote.valid_until_utc, grant.valid_until_utc),
        )
    except (TypeError, ValueError, BudgetError, IssuerAuthorityDenied):
        return hold("d11.current_budget_provider_unavailable",
                    lease_id=lease_id, quote_id=quote_id)
    if ledger.result != "pass" or ledger.coverage != "full":
        return hold("d11.current_budget_provider_not_pass",
                    lease_id=lease_id, quote_id=quote_id)
    return DispatchBudgetInspectionV1("check_pass", (), ledger, lease_id, quote_id)


def inspect_current_d08_commitments(
    db, candidate: DispatchCandidateEvidenceV1,
    *, trusted_context: TrustedDispatchAdmissionContextV1 | None = None,
    now_utc: float | None = None,
) -> DispatchCommitmentInspectionV1:
    """Inventory all current D08 conflict rows under the graph transaction.

    The narrow v1 PASS covers a current active goal with no own commitments,
    no other unfinished commitment or same-target action, an active same-commit
    cancellation head, and an authenticated *pre-P2* absent effect read. The
    final P2/effect and revocation recheck remains at handoff.
    """
    def hold(*missing: str, epoch=None, commitments=(), actions=()):
        return DispatchCommitmentInspectionV1(
            "hold", tuple(dict.fromkeys(missing)), epoch,
            tuple(commitments), tuple(actions),
        )

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if type(candidate) is not DispatchCandidateEvidenceV1:
        return hold("d08.typed_dispatch_candidate")
    try:
        action_key = AtomKey.from_token(candidate.action_ref)
        namespace = NamespaceId(action_key.owner.bot, action_key.owner.persona)
        epoch_row = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        expected_epoch = (trusted_context.graph_receipt.epoch.revision
                          if type(trusted_context) is TrustedDispatchAdmissionContextV1
                          else candidate.query_epoch)
        if (epoch_row is None or epoch_row[0] != expected_epoch
                or (trusted_context is not None
                    and (expected_epoch != candidate.query_epoch + 1
                         or trusted_context.scope.graph_epoch.revision
                         != candidate.query_epoch
                         or trusted_context.scope.namespace != namespace))):
            return hold("d08.current_graph_epoch_differs")
        epoch = epoch_row[0]
        rows = db.execute(
            "SELECT token,revision,value,type_name FROM graph_atoms "
            "WHERE bot=? AND persona=? AND type_name IN "
            "('d08.commitment.v1','d08.action_intent.v1',"
            "'d08.action_outcome.v1') AND valid=1 ORDER BY token",
            namespace.as_tuple,
        ).fetchall()
        atoms = tuple(GraphAtom(
            AtomKey.from_token(token), revision, json.loads(raw), True,
        ) for token, revision, raw, _ in rows)
        snapshot = GraphSnapshot(
            atoms, (NamespaceEpoch(*namespace.as_tuple, epoch),),
        )
        facts = read_current_d08_conflict_facts(
            db, namespace, snapshot, QueryEpoch(namespace, "all", epoch),
        )
    except sqlite3.OperationalError:
        return hold("d08.current_graph_schema_unavailable")
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return hold("d08.current_complete_graph_inventory_unavailable")
    actions = tuple(item.action_id for item in facts.action_intents)
    commitments = tuple(item.commitment_id for item in facts.commitments)
    current = tuple(item for item in facts.action_intents
                    if item.action_id == action_key.name
                    and item.identity.operation_id == candidate.operation_id)
    missing = [source for source in facts.missing_sources
               if trusted_context is None or source not in {
                   "atomic_execution_effect_read", "current_action_cancellation_read",
               }]
    if (len(current) != 1 or action_key.type_name != "d08.action_intent.v1"
            or candidate.action_digest != canonical_digest(current[0])):
        missing.append("d08.current_action_identity_differs")
    else:
        intent = current[0]
        specs = tuple(item for item in intent.required_checks
                      if item.check_kind == "commitment_conflict")
        if len(specs) != 1 or specs[0].provider_id != "d08.commitment_conflict":
            missing.append("d08.frozen_commitment_check_missing")
        elif specs[0].criteria_version.startswith("criteria:"):
            missing.append("d08.criteria_ref_has_no_authoritative_issuer")
        if any(other.action_id != intent.action_id
               and other.identity.effect_id == intent.identity.effect_id
               for other in facts.action_intents):
            missing.append("d08.current_effect_shared_by_actions")
    if missing or trusted_context is None:
        missing.append("d08.current_pre_p2_authority_effect")
        return DispatchCommitmentInspectionV1(
            "hold", tuple(dict.fromkeys(missing)), epoch, commitments, actions,
        )
    if (type(trusted_context) is not TrustedDispatchAdmissionContextV1
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        missing.append("d08.typed_trusted_context_and_time")
        return DispatchCommitmentInspectionV1(
            "hold", tuple(dict.fromkeys(missing)), epoch, commitments, actions,
        )
    effect = trusted_context.current_effect
    anchor = trusted_context.scope.pinned_anchor
    intent = current[0]
    spec = tuple(item for item in intent.required_checks
                 if item.check_kind == "commitment_conflict")[0]
    if (effect is None or effect.effect_id != intent.identity.effect_id
            or effect.state != "absent"
            or (effect.authority_id, effect.namespace,
                effect.activation_generation, effect.execution_head_seq,
                effect.execution_head_digest) != (
                anchor.authority_id, anchor.namespace,
                anchor.activation_generation, anchor.execution_seq,
                anchor.execution_digest)):
        missing.append("d08.current_effect_not_absent_at_pinned_execution_head")
    if intent.commitment_refs:
        missing.append("d08.narrow_zero_commitment_policy")
    if any(item.fulfillment_state not in {"fulfilled", "withdrawn"}
           for item in facts.commitments):
        missing.append("d08.other_unfinished_commitment")
    for other in facts.action_intents:
        if other.action_id == intent.action_id:
            continue
        if other.identity.effect_id == intent.identity.effect_id:
            missing.append("d08.current_effect_shared_by_actions")
        if other.target_ref == intent.target_ref and not any(
            outcome.action_id == other.action_id
            and outcome.effect_id == other.identity.effect_id
            and outcome.attempt_id == other.identity.attempt_id
            and outcome.result_level == "completed_verified"
            and not outcome.unknown_effects
            for outcome in facts.action_outcomes
        ):
            missing.append("d08.other_same_target_action_unfinished")
    try:
        if spec.criteria_version != CRITERIA_REF:
            missing.append("d08.fixed_criteria_ref_required")
        schema_atom = _current_atom(
            db, namespace, candidate.schema_ref, "d08.action_schema.v1",
        )
        d08 = {item.name: item for item in GoalExecutionProvider().register_types()}
        schema_record = d08["d08.action_schema.v1"].validator(schema_atom.value)
        frozen_schema = ActionSchema(
            schema_record.schema_id, schema_record.action_kind,
            schema_record.proactive, schema_record.required_checks,
        )
        if (schema_record.proactive
                or schema_record != ActionSchemaRecord.bind(intent, frozen_schema)):
            missing.append("d08.narrow_passive_schema_required")
        goal_rows = db.execute(
            "SELECT revision,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d08.goal.v1' AND name=? AND valid=1",
            (*namespace.as_tuple, intent.goal_ref),
        ).fetchall()
        cancel_rows = db.execute(
            "SELECT revision,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d08.action_cancellation.v1' AND name=? AND valid=1",
            (*namespace.as_tuple, intent.action_id),
        ).fetchall()
        if len(goal_rows) != 1 or len(cancel_rows) != 1:
            missing.append("d08.current_goal_or_cancellation_head_missing")
        else:
            goal = d08["d08.goal.v1"].validator(json.loads(goal_rows[0][1]))
            cancellation = d08["d08.action_cancellation.v1"].validator(
                json.loads(cancel_rows[0][1]))
            if goal.goal_id != intent.goal_ref or goal.state != "active":
                missing.append("d08.current_goal_not_active")
            if (cancellation.action_id != intent.action_id
                    or cancellation.action_revision != intent.revision
                    or cancellation.action_digest != canonical_digest(intent)
                    or cancellation.effect_id != intent.identity.effect_id
                    or cancellation.attempt_id != intent.identity.attempt_id
                    or cancellation.state != "active"
                    or cancellation.cancel_epoch != 0):
                missing.append("d08.current_action_cancelled_or_identity_differs")
            expected = {
                CRITERIA_REF: CRITERIA_VERSION,
                intent.goal_ref: goal_rows[0][0],
                f"commitments-query:persona:{namespace.persona_id}": epoch,
                f"execution-epoch:{intent.action_id}": anchor.execution_seq,
                f"cancellation-epoch:{intent.action_id}": cancel_rows[0][0],
            }
            frozen = {item.ref: item.version for item in spec.required_input_versions}
            if len(frozen) != len(spec.required_input_versions) or frozen != expected:
                missing.append("d08.current_fixed_criteria_read_set_differs")
    except (sqlite3.OperationalError, KeyError, TypeError, ValueError,
            json.JSONDecodeError):
        missing.append("d08.current_goal_cancellation_provider_unavailable")
    if missing:
        return DispatchCommitmentInspectionV1(
            "hold", tuple(dict.fromkeys(missing)), epoch, commitments, actions,
        )
    read = CommitmentConflictSnapshot(
        spec.required_input_versions, "full", (), (), (),
        action_ref=intent.action_id, action_revision=intent.revision,
        intent_digest=canonical_digest(intent), schema_id=intent.schema_id,
        goal_ref=intent.goal_ref, target_ref=intent.target_ref,
        action_kind=intent.action_kind, purpose=intent.purpose,
        commitment_query_epoch_ref=f"commitments-query:persona:{namespace.persona_id}",
        commitment_query_epoch=epoch,
        execution_epoch_ref=f"execution-epoch:{intent.action_id}",
        execution_epoch=anchor.execution_seq,
        cancellation_epoch_ref=f"cancellation-epoch:{intent.action_id}",
        cancellation_epoch=cancel_rows[0][0], current_read_confirmed=True,
    )
    receipt = GoalExecutionProvider().provide_required_check(
        intent, frozen_schema, read, valid_until=now_utc + 1.0,
    )
    if receipt.result != "pass" or receipt.coverage != "full":
        return DispatchCommitmentInspectionV1(
            "hold", ("d08.current_provider_not_pass",), epoch, commitments, actions,
        )
    return DispatchCommitmentInspectionV1(
        "check_pass", (), epoch, commitments, actions, receipt,
    )


class InstalledDispatchAdmissionIssuer:
    """Narrow private admission from installed Authority and current graph reads."""

    def __init__(self, *, context: ContextProvider | None = None,
                 d11_issuer: D11BudgetGrantIssuer | None = None,
                 d02_issuer: D02ResourceIssuer | None = None):
        self._context = context
        self._d11 = d11_issuer
        self._d02 = d02_issuer
        self._issued = None

    def issue_dispatch_admission(self, bundle, snapshot, candidate, db, *,
                                 graph_incarnation: str, now_utc: float,
                                 trusted_context: TrustedDispatchAdmissionContextV1 | None = None):
        self._issued = None
        if not getattr(db, "in_transaction", False):
            raise DispatchAdmissionHold(("graph.current_write_transaction",))
        if type(candidate) is not DispatchCandidateEvidenceV1:
            raise DispatchAdmissionHold(("d08.typed_dispatch_candidate",))
        try:
            action_key = AtomKey.from_token(candidate.action_ref)
        except (TypeError, ValueError) as exc:
            raise DispatchAdmissionHold(("d08.canonical_action_ref",)) from exc
        if action_key.type_name != "d08.action_intent.v1":
            raise DispatchAdmissionHold(("d08.action_intent_ref",))
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (candidate.action_ref,
                                        action_key.owner.bot, action_key.owner.persona),
        ).fetchone()
        if row is None or row[2] != 1:
            raise DispatchAdmissionHold(("d08.current_action_intent",))
        try:
            action = next(item for item in GoalExecutionProvider().register_types()
                          if item.name == "d08.action_intent.v1").validator(
                              json.loads(row[1]))
        except (StopIteration, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DispatchAdmissionHold(("d08.valid_current_action_intent",)) from exc
        if (candidate.action_digest != canonical_digest(action)
                or candidate.operation_id != action.identity.operation_id):
            raise DispatchAdmissionHold(("d08.current_action_identity",))
        specs = tuple(item for item in action.required_checks
                      if item.check_kind == "source_grant")
        if len(specs) != 1:
            raise DispatchAdmissionHold(("d06.unique_source_grant_spec",))
        inspection = inspect_current_d06_source_grant(
            db, action, specs[0], candidate, audience=candidate.source_audience,
            trusted_context=trusted_context, now_utc=now_utc,
        )
        social_missing = ("d03.d05.installed_context_provider",)
        if self._context is not None:
            social = inspect_current_d03_d05(
                db, candidate, context=self._context, now_utc=now_utc,
                trusted_context=trusted_context,
            )
            social_missing = social.missing
        budget = inspect_current_d11_dispatch_budget(
            db, action, d11_issuer=self._d11, d02_issuer=self._d02,
            now_utc=now_utc,
        )
        commitments = inspect_current_d08_commitments(
            db, candidate, trusted_context=trusted_context, now_utc=now_utc,
        )
        route = inspect_current_private_route(db, candidate, now_utc=now_utc)
        owner = inspect_current_owner_grant(
            db, NamespaceId(action_key.owner.bot, action_key.owner.persona),
            candidate.source_audience, action.purpose,
            trusted_context=trusted_context,
            graph_incarnation=graph_incarnation,
        )
        command = inspect_current_private_command(
            db, bundle, candidate, budget, route,
            trusted_context=trusted_context, now_utc=now_utc,
        )
        missing = (
            *inspection.missing, *social_missing, *budget.missing,
            *commitments.missing, *route.missing, *owner.missing,
            *command.missing,
        )
        if missing:
            raise DispatchAdmissionHold(missing)
        if (type(trusted_context) is not TrustedDispatchAdmissionContextV1
                or type(snapshot) is not GraphSnapshot
                or len(snapshot.epochs) != 1
                or trusted_context.scope.namespace != NamespaceId(
                    action_key.owner.bot, action_key.owner.persona)
                or trusted_context.projection.coverage != "full"
                or trusted_context.current_effect.state != "absent"
                or bundle.envelope.parent_budget_lease_ref != budget.lease_id):
            raise DispatchAdmissionHold(("dispatch.current_trusted_context_scope",))
        receipts = (
            social.role_receipt, social.boundary_receipt,
            inspection.receipt, commitments.receipt, budget.receipt,
        )
        if (any(item is None or item.result != "pass" or item.coverage != "full"
                for item in receipts)
                or {item.check_kind for item in action.required_checks}
                != {"role_binding", "boundary", "source_grant",
                    "commitment_conflict", "dispatch_budget"}):
            raise DispatchAdmissionHold(("dispatch.narrow_passive_check_set",))
        by_kind = {receipt.check_kind: receipt for receipt in receipts}
        if any(by_kind[spec.check_kind].issuer != spec.provider_id
               for spec in action.required_checks):
            raise DispatchAdmissionHold(("dispatch.frozen_check_provider_differs",))
        receipts = tuple(by_kind[spec.check_kind] for spec in action.required_checks)
        projection = trusted_context.projection
        bindings = []
        for atom in projection.role_bindings:
            try:
                binding = RoleBinding(**{
                    **atom.value, "norm_refs": tuple(atom.value["norm_refs"]),
                    "source_refs": tuple(atom.value["source_refs"]),
                })
            except (KeyError, TypeError, ValueError):
                continue
            if (binding.role_binding_id == atom.key.name
                    and binding.binding_version == atom.revision
                    and binding.status == "active"
                    and binding.scene_ref == route.scene_ref
                    and binding.target_entity_ref == action.target_ref
                    and binding.effective_from <= now_utc
                    and (binding.effective_until is None
                         or now_utc <= binding.effective_until)):
                bindings.append(binding)
        if len(bindings) != 1:
            raise DispatchAdmissionHold(("d03.unique_current_private_binding",))
        request = command.request
        lease = get_budget_lease(db, budget.lease_id)
        from ..graph_coordinator import budget_operation_digest
        if command.budget_reservation_digest != budget_operation_digest(
                bundle.envelope, budget.lease_id, command.budget_ceiling):
            raise DispatchAdmissionHold(("d11.current_reservation_operation_digest",))
        deadline = int(min(
            *(receipt.valid_until for receipt in receipts),
            float(_current_atom(db, trusted_context.scope.namespace,
                                candidate.batch_ref,
                                "d09.verified_segment_batch.v1").value["valid_until"]),
        ))
        if deadline <= now_utc:
            raise DispatchAdmissionHold(("dispatch.current_deadline",))
        admission = DispatchAdmissionV1(
            namespace="/".join(trusted_context.scope.namespace.as_tuple),
            graph_incarnation=graph_incarnation,
            activity_id=action.identity.activity_id,
            effect_id=action.identity.effect_id,
            attempt_id=action.identity.attempt_id,
            operation_id=action.identity.operation_id,
            dispatch_generation=request.dispatch_generation,
            admission_ref="admission:" + canonical_digest({
                "operation_id": request.operation_id,
                "effect_id": request.effect_id,
                "candidate": candidate.digest,
            })[:40],
            candidate_digest=candidate.digest,
            request_digest=canonical_digest(request),
            action_intent_digest=candidate.action_digest,
            action_intent_schema_version="d08.action_intent.v1",
            action_schema_digest=candidate.schema_digest,
            action_schema_version="d08.action_schema.v1",
            required_checks_digest=canonical_digest(action.required_checks),
            required_checks_schema_version="d08.required_check_spec.v1",
            grant_digest=candidate.grant_digest,
            batch_digest=candidate.batch_digest,
            segment_index=0,
            payload_digest=request.payload_digest,
            account_ref=route.account_ref,
            destination_ref=route.destination_ref,
            scene_ref=route.scene_ref,
            owner_head_ref=owner.grant_id,
            role_ref=bindings[0].social_role,
            binding_ref=bindings[0].role_binding_id,
            object_ref=action.target_ref,
            action_ref=action.action_id,
            purpose=action.purpose,
            audience=(route.destination_ref,),
            graph_reads=tuple((item.key.token, item.revision)
                              for item in snapshot.versions),
            query_epoch=snapshot.epochs[0].revision,
            access_epoch=candidate.access_epoch,
            delete_epoch=candidate.delete_epoch,
            check_receipts=receipts,
            budget_parent_lease_ref=budget.lease_id,
            budget_lease_ref=budget.lease_id,
            budget_reservation_operation_id=request.operation_id,
            budget_reservation_digest=command.budget_reservation_digest,
            budget_ceiling=command.budget_ceiling,
            budget_currency=lease.currency,
            budget_version=lease.version,
            contact_reservation_ref=None,
            utc_deadline=datetime.fromtimestamp(
                deadline, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            clock_policy_ref=trusted_context.clock_policy.source_id,
            clock_policy_digest=canonical_digest(asdict(trusted_context.clock_policy)),
        )
        self._issued = (db, trusted_context, bundle, snapshot, candidate,
                        action, budget, route, command, request, admission,
                        now_utc)
        return request, admission

    def verify_required_check(self, spec, receipt, snapshot, db, *,
                              trusted_context=None) -> bool:
        state = self._issued
        return bool(state is not None and state[0] is db
                    and state[1] is trusted_context and state[3] == snapshot
                    and receipt in state[10].check_receipts
                    and spec in state[5].required_checks
                    and receipt == state[10].check_receipts[
                        next(i for i, item in enumerate(state[5].required_checks)
                             if item == spec)])

    def verify_domain_context(self, admission, snapshot, db, *,
                              trusted_context=None) -> bool:
        state = self._issued
        return bool(state is not None and state[0] is db
                    and state[1] is trusted_context and state[3] == snapshot
                    and state[10] == admission
                    and trusted_context.projection.coverage == "full")

    def verify_command_provenance(self, request, admission, db, *,
                                  trusted_context=None) -> bool:
        state = self._issued
        if (state is None or state[0] is not db or state[1] is not trusted_context
                or state[9] != request or state[10] != admission):
            return False
        current = inspect_current_private_command(
            db, state[2], state[4], state[6], state[7],
            trusted_context=trusted_context, now_utc=state[11],
        )
        return current.status == "command_verified" and current.request == request

    def verify_journal_constraints(self, request, admission, *,
                                   trusted_context=None) -> bool:
        state = self._issued
        if (state is None or state[1] is not trusted_context
                or state[9] != request or state[10] != admission):
            return False
        effect = trusted_context.current_effect
        anchor = trusted_context.scope.pinned_anchor
        verified = (effect.state == "absent"
                    and (effect.execution_head_seq, effect.execution_head_digest)
                    == (anchor.execution_seq, anchor.execution_digest)
                    and request.footprint.effect_id == admission.effect_id
                    and any(item.parent_budget_ref == admission.budget_lease_ref
                            and item.upper_bound is not None
                            for item in request.footprint.budgets))
        self._issued = None
        return verified


__all__ = [
    "DispatchAdmissionHold", "DispatchSourceInspectionV1",
    "InstalledDispatchAdmissionIssuer", "inspect_current_d06_source_grant",
    "DispatchSocialInspectionV1", "inspect_current_d03_d05",
    "DispatchBudgetInspectionV1",
    "inspect_current_d11_dispatch_budget",
    "DispatchCommitmentInspectionV1", "inspect_current_d08_commitments",
    "DispatchPrivateRouteInspectionV1", "inspect_current_private_route",
    "DispatchOwnerInspectionV1", "inspect_current_owner_grant",
    "TrustedDispatchAdmissionContextV1",
]
