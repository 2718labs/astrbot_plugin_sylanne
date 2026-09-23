"""Strict, transport-neutral audit DTOs for ``sylanne3.authority.v2``.

Parsing these objects does not authenticate a caller, validate a live fence, or
prove that a journal append was durable. Only the independent authority service
can make those decisions against its current state and service-owned journal.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import json
import re
from typing import Any

from .contract import CONTENT_OPERATIONS, identifier
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_journal import RecoveryConstraintFootprint


SCHEMA = "sylanne3.authority.v2"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEAD_DIGEST = re.compile(r"^(?:genesis|sha256:[0-9a-f]{64})$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_OPERATIONS = CONTENT_OPERATIONS | frozenset({
    "delete", "migrate", "journal_maintenance", "recovery",
})
_PHASES = frozenset({"prepared", "claimed", "observed", "settled"})
_PLATFORM_OUTCOMES = frozenset({
    "handed_off", "accepted", "delivered", "read",
    "failed_before_acceptance", "unknown",
})
_DELETION_TRANSITIONS = {
    ("absent", "pending"): "request_authorized",
    ("pending", "accepted"): "barrier_installed",
    ("accepted", "closed"): "cleanup_complete",
}
_ANCHOR_FIELDS = frozenset({
    "authority_id", "namespace", "activation_generation",
    "deletion_journal_id", "deletion_seq", "deletion_digest",
    "execution_journal_id", "execution_seq", "execution_digest",
    "revocation_epoch", "proof",
})
_FOOTPRINT_FIELDS = frozenset({
    "namespace", "activity_id", "effect_id", "external_idempotency_ref",
    "external_query_ref", "conflict_keys", "communication_action",
    "contact_id", "segment_id", "object_gate_keys", "quota_occupancies",
    "reservations", "budgets",
})


def _exact_int(value: object, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an exact integer >= {minimum}")
    return value


def _digest(value: object, name: str, *, head: bool = False) -> str:
    pattern = _HEAD_DIGEST if head else _SHA256
    if type(value) is not str or not pattern.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _fields(value: object, expected: frozenset[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"invalid {name} fields")
    return value


def _schema(value: str) -> None:
    if value != SCHEMA or type(value) is not str:
        raise ValueError("unknown authority schema")


def _anchor(value: RestoreAnchor, authority_id: str, namespace: str,
            generation: int) -> None:
    if type(value) is not RestoreAnchor:
        raise ValueError("anchor must be RestoreAnchor")
    if (value.authority_id != authority_id or value.namespace != namespace
            or value.activation_generation != generation):
        raise ValueError("anchor authority, namespace or generation mismatch")
    for field in ("authority_id", "namespace", "deletion_journal_id",
                  "execution_journal_id"):
        identifier(getattr(value, field), field)
    for name in ("activation_generation", "deletion_seq", "execution_seq",
                 "revocation_epoch"):
        _exact_int(getattr(value, name), name)
    for prefix in ("deletion", "execution"):
        seq = getattr(value, f"{prefix}_seq")
        digest = _digest(getattr(value, f"{prefix}_digest"),
                         f"{prefix}_digest", head=True)
        if (seq == 0) != (digest == "genesis"):
            raise ValueError(f"{prefix} genesis does not match sequence")
    if (type(value.proof) is not str or not 1 <= len(value.proof) <= 4096
            or any(ord(char) < 33 or ord(char) == 127 for char in value.proof)):
        raise ValueError("invalid opaque anchor proof")


def _unique_ids(**items: str | None) -> None:
    present = [value for value in items.values() if value is not None]
    if len(present) != len(set(present)):
        raise ValueError("duplicate protocol IDs")


@dataclass(frozen=True, slots=True)
class FencePermitV2:
    authority_id: str
    namespace: str
    subject: str
    holder: str
    generation: int
    operation: str
    operation_id: str
    token: str
    fence_epoch: int
    revision: int
    pinned_anchor: RestoreAnchor
    effect_id: str | None = None
    command_digest: str | None = None
    footprint_digest: str | None = None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _schema(self.schema)
        for field in ("authority_id", "namespace", "subject", "holder",
                      "operation_id"):
            identifier(getattr(self, field), field)
        _exact_int(self.generation, "generation")
        _exact_int(self.fence_epoch, "fence_epoch")
        _exact_int(self.revision, "revision")
        if type(self.operation) is not str or self.operation not in _OPERATIONS:
            raise ValueError("unknown fence operation")
        if type(self.token) is not str or not _TOKEN.fullmatch(self.token):
            raise ValueError("invalid opaque fence token")
        if self.operation == "dispatch":
            identifier(self.effect_id, "effect_id")
            _digest(self.command_digest, "command_digest")
            _digest(self.footprint_digest, "footprint_digest")
        elif any(value is not None for value in (
                self.effect_id, self.command_digest, self.footprint_digest)):
            raise ValueError("effect binding requires dispatch operation")
        _unique_ids(operation_id=self.operation_id, effect_id=self.effect_id)
        _anchor(self.pinned_anchor, self.authority_id, self.namespace,
                self.generation)


@dataclass(frozen=True, slots=True)
class PendingMutationV2:
    """One durable phase transition for one service-owned execution append."""

    permit: FencePermitV2
    mutation_id: str
    request_digest: str
    phase: str
    before_anchor: RestoreAnchor
    expected_append_id: str
    expected_append_digest: str
    schema: str = SCHEMA
    prepared_receipt: MutationReceiptV2 | None = None
    binding: ExecutionBindingV1 | None = None

    def __post_init__(self) -> None:
        _schema(self.schema)
        if type(self.permit) is not FencePermitV2 or self.permit.operation != "dispatch":
            raise ValueError("execution mutation requires a dispatch fence")
        identifier(self.mutation_id, "mutation_id")
        identifier(self.expected_append_id, "expected_append_id")
        _digest(self.request_digest, "request_digest")
        _digest(self.expected_append_digest, "expected_append_digest")
        if type(self.phase) is not str or self.phase not in _PHASES:
            raise ValueError("unknown execution phase")
        _unique_ids(operation_id=self.permit.operation_id,
                    effect_id=self.permit.effect_id, mutation_id=self.mutation_id,
                    expected_append_id=self.expected_append_id)
        _anchor(self.before_anchor, self.permit.authority_id,
                self.permit.namespace, self.permit.generation)
        if self.before_anchor != self.permit.pinned_anchor:
            raise ValueError("pending before-head differs from pinned fence head")
        if self.phase == "claimed":
            receipt, binding = self.prepared_receipt, self.binding
            if (type(receipt) is not MutationReceiptV2
                    or receipt.pending.phase != "prepared"
                    or receipt.durable_state != "committed"
                    or type(binding) is not ExecutionBindingV1
                    or binding.permit != receipt.pending.permit):
                raise ValueError("claim requires original committed prepare and binding")
            if (self.permit != replace(receipt.pending.permit,
                                       revision=receipt.updated_revision,
                                       pinned_anchor=receipt.after_anchor)
                    or self.before_anchor != receipt.after_anchor
                    or binding.operation_id != self.permit.operation_id):
                raise ValueError("claim differs from original prepared operation or fence")
        elif self.prepared_receipt is not None or self.binding is not None:
            raise ValueError("only claimed phase may carry prepared receipt and binding")

    @property
    def expected_execution_seq(self) -> int:
        return self.before_anchor.execution_seq + 1

    @property
    def expected_execution_journal_id(self) -> str:
        return self.before_anchor.execution_journal_id


@dataclass(frozen=True, slots=True)
class ExecutionBindingV1:
    """Immutable dispatch identity and recovery constraints; never a send permit.

    The service must verify the original fence, claim and domain-owned footprint
    against current state before any handoff. Parsing this DTO proves none of them.
    """

    permit: FencePermitV2
    namespace: str
    activity_id: str
    effect_id: str
    attempt_id: str
    operation_id: str
    dispatch_generation: int
    activation_generation: int
    admission_ref: str
    verified_check_refs: tuple[str, ...]
    payload_digest: str
    platform_capability_ref: str
    adapter_ref: str
    account_ref: str
    destination_ref: str
    worker_fence: int
    content_fence: str
    cancel_epoch: int
    footprint: RecoveryConstraintFootprint
    proactive_contact: bool = False
    segment_authorization_ref: str | None = None
    segment_manifest_digest: str | None = None
    segment_index: int | None = None
    segment_count: int | None = None
    contact_policy_check_ref: str | None = None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _schema(self.schema)
        if type(self.permit) is not FencePermitV2 or self.permit.operation != "dispatch":
            raise ValueError("execution binding requires original dispatch fence")
        if type(self.footprint) is not RecoveryConstraintFootprint:
            raise ValueError("execution binding requires recovery footprint")
        for name in ("namespace", "activity_id", "effect_id", "attempt_id",
                     "operation_id", "admission_ref", "platform_capability_ref",
                     "adapter_ref", "account_ref", "destination_ref", "content_fence"):
            identifier(getattr(self, name), name)
        for name in ("dispatch_generation", "activation_generation", "worker_fence",
                     "cancel_epoch"):
            _exact_int(getattr(self, name), name)
        _digest(self.payload_digest, "payload_digest")
        if (type(self.verified_check_refs) is not tuple or not self.verified_check_refs
                or len(set(self.verified_check_refs)) != len(self.verified_check_refs)):
            raise ValueError("verified checks must be a nonempty unique tuple")
        for check_ref in self.verified_check_refs:
            identifier(check_ref, "verified_check_ref")
        if type(self.proactive_contact) is not bool:
            raise ValueError("proactive_contact must be an exact boolean")
        if (self.namespace != self.permit.namespace
                or self.activation_generation != self.permit.generation
                or self.effect_id != self.permit.effect_id
                or self.operation_id != self.permit.operation_id
                or self.footprint.namespace != self.namespace
                or self.footprint.activity_id != self.activity_id
                or self.footprint.effect_id != self.effect_id):
            raise ValueError("execution binding identity differs from fence or footprint")
        footprint_digest = "sha256:" + hashlib.sha256(self.footprint._json().encode()).hexdigest()
        if self.permit.footprint_digest != footprint_digest:
            raise ValueError("execution binding footprint differs from original fence")
        contact = self.footprint.contact_id is not None
        segment = (self.segment_authorization_ref, self.segment_manifest_digest,
                   self.segment_index, self.segment_count)
        if contact:
            if any(value is None for value in segment):
                raise ValueError("contact requires complete finite segment summary")
            identifier(self.segment_authorization_ref, "segment_authorization_ref")
            _digest(self.segment_manifest_digest, "segment_manifest_digest")
            count = _exact_int(self.segment_count, "segment_count", minimum=1)
            if count > 3 or type(self.segment_index) is not int or not 0 <= self.segment_index < count:
                raise ValueError("segment position outside finite three-segment manifest")
            if self.proactive_contact:
                identifier(self.contact_policy_check_ref, "contact_policy_check_ref")
                if self.contact_policy_check_ref not in self.verified_check_refs:
                    raise ValueError("proactive contact policy check is not among verified checks")
                if not self.footprint.quota_occupancies:
                    raise ValueError("proactive contact requires quota footprint")
            elif self.contact_policy_check_ref is not None:
                raise ValueError("responsive contact cannot carry proactive policy check")
            elif self.footprint.quota_occupancies or self.footprint.object_gate_keys:
                raise ValueError("responsive contact cannot occupy proactive contact constraints")
        elif (any(value is not None for value in segment)
              or self.contact_policy_check_ref is not None or self.proactive_contact):
            raise ValueError("non-contact binding cannot carry segment or policy summary")


@dataclass(frozen=True, slots=True)
class PlatformObservationV1:
    """Reported platform evidence; only an installed verifier may trust its source."""

    binding: ExecutionBindingV1
    handoff_start_ref: str
    adapter_ref: str
    account_ref: str
    destination_ref: str
    observation_id: str
    platform_request_id: str | None
    platform_message_id: str | None
    evidence_source_ref: str
    outcome: str
    status_code_summary: str | None
    observed_at_utc: str
    time_source_ref: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _schema(self.schema)
        if type(self.binding) is not ExecutionBindingV1:
            raise ValueError("platform observation requires execution binding")
        for name in ("handoff_start_ref", "adapter_ref", "account_ref",
                     "destination_ref", "observation_id", "evidence_source_ref",
                     "observed_at_utc", "time_source_ref"):
            identifier(getattr(self, name), name)
        for name in ("platform_request_id", "platform_message_id", "status_code_summary"):
            value = getattr(self, name)
            if value is not None:
                identifier(value, name)
        if type(self.outcome) is not str or self.outcome not in _PLATFORM_OUTCOMES:
            raise ValueError("unknown platform observation outcome")
        if not _UTC_TIMESTAMP.fullmatch(self.observed_at_utc):
            raise ValueError("observed_at_utc must be a UTC second timestamp")
        try:
            datetime.fromisoformat(self.observed_at_utc.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid observed_at_utc") from exc
        if (self.adapter_ref != self.binding.adapter_ref
                or self.account_ref != self.binding.account_ref
                or self.destination_ref != self.binding.destination_ref):
            raise ValueError("platform observation destination differs from binding")
        _unique_ids(handoff_start_ref=self.handoff_start_ref,
                    observation_id=self.observation_id)


@dataclass(frozen=True, slots=True)
class MutationReceiptV2:
    pending: PendingMutationV2
    after_anchor: RestoreAnchor
    updated_revision: int
    durable_state: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _schema(self.schema)
        if type(self.pending) is not PendingMutationV2:
            raise ValueError("receipt requires original pending mutation")
        _exact_int(self.updated_revision, "updated_revision", minimum=1)
        if self.updated_revision != self.pending.permit.revision + 1:
            raise ValueError("receipt revision must advance exactly once")
        if self.durable_state not in ("committed", "cancelled_unappended") or type(self.durable_state) is not str:
            raise ValueError("unknown durable mutation state")
        before = self.pending.before_anchor
        after = self.after_anchor
        _anchor(after, self.pending.permit.authority_id,
                self.pending.permit.namespace, self.pending.permit.generation)
        if (after.deletion_journal_id != before.deletion_journal_id
                or after.execution_journal_id != before.execution_journal_id
                or after.deletion_seq != before.deletion_seq
                or after.deletion_digest != before.deletion_digest
                or after.revocation_epoch != before.revocation_epoch):
            raise ValueError("execution mutation changed an unrelated anchor field")
        if self.durable_state == "committed":
            if (after.execution_seq != self.pending.expected_execution_seq
                    or after.execution_digest != self.pending.expected_append_digest):
                raise ValueError("receipt does not match the unique expected append")
        elif after != before:
            raise ValueError("cancelled mutation must preserve exact before-head")


def deletion_scope_digest(roots: tuple[str, ...], epoch: int,
                          policy_ref: str) -> str:
    """Canonical binding for content-free roots, epoch and policy identity."""
    if (type(roots) is not tuple or not roots or len(roots) > 256
            or len(set(roots)) != len(roots)):
        raise ValueError("deletion roots must be a bounded unique tuple")
    for root in roots:
        identifier(root, "closure_root")
    _exact_int(epoch, "deletion_epoch", minimum=1)
    identifier(policy_ref, "policy_ref")
    material = json.dumps({"roots": list(roots), "epoch": epoch,
                           "policy_ref": policy_ref}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True, slots=True)
class DeletionEvidenceV1:
    """Typed evidence record, never proof of service verification by itself."""

    authority_id: str
    namespace: str
    deletion_operation_id: str
    kind: str
    issuer_id: str
    evidence_id: str
    bound_anchor: RestoreAnchor
    request_digest: str
    scope_digest: str
    proof_digest: str
    graph_version: str | None = None
    incarnation: str | None = None
    access_epoch: int | None = None
    deletion_epoch: int | None = None
    barrier_scope_digest: str | None = None
    cleanup_digest: str | None = None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _schema(self.schema)
        for name in ("authority_id", "namespace", "deletion_operation_id",
                     "issuer_id", "evidence_id"):
            identifier(getattr(self, name), name)
        if self.kind not in _DELETION_TRANSITIONS.values() or type(self.kind) is not str:
            raise ValueError("unknown deletion evidence kind")
        if type(self.bound_anchor) is not RestoreAnchor:
            raise ValueError("deletion evidence requires full bound anchor")
        _anchor(self.bound_anchor, self.authority_id, self.namespace,
                self.bound_anchor.activation_generation)
        for name in ("request_digest", "scope_digest", "proof_digest"):
            _digest(getattr(self, name), name)
        graph_fields = (self.graph_version, self.incarnation, self.access_epoch,
                        self.deletion_epoch, self.barrier_scope_digest)
        if self.kind == "request_authorized":
            if any(value is not None for value in (*graph_fields, self.cleanup_digest)):
                raise ValueError("request authorization cannot assert graph or cleanup evidence")
        else:
            identifier(self.graph_version, "graph_version")
            identifier(self.incarnation, "incarnation")
            _exact_int(self.access_epoch, "access_epoch")
            _exact_int(self.deletion_epoch, "deletion_epoch")
            _digest(self.barrier_scope_digest, "barrier_scope_digest")
            if self.kind == "cleanup_complete":
                _digest(self.cleanup_digest, "cleanup_digest")
            elif self.cleanup_digest is not None:
                raise ValueError("barrier evidence cannot assert cleanup completion")


@dataclass(frozen=True, slots=True)
class DeletionPendingV1:
    """One exact deletion transition; this shape does not authorize append."""

    permit: FencePermitV2
    mutation_id: str
    request_digest: str
    deletion_operation_id: str
    source_phase: str
    target_phase: str
    closure_roots: tuple[str, ...]
    deletion_epoch: int
    policy_ref: str
    before_anchor: RestoreAnchor
    evidence: DeletionEvidenceV1
    expected_append_id: str
    expected_append_digest: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _schema(self.schema)
        if type(self.permit) is not FencePermitV2 or self.permit.operation != "delete":
            raise ValueError("deletion pending requires delete fence")
        for name in ("mutation_id", "deletion_operation_id", "expected_append_id"):
            identifier(getattr(self, name), name)
        _unique_ids(operation_id=self.permit.operation_id,
                    deletion_operation_id=self.deletion_operation_id,
                    mutation_id=self.mutation_id,
                    expected_append_id=self.expected_append_id)
        _digest(self.request_digest, "request_digest")
        _digest(self.expected_append_digest, "expected_append_digest")
        expected_kind = _DELETION_TRANSITIONS.get((self.source_phase, self.target_phase))
        if expected_kind is None:
            raise ValueError("invalid deletion phase transition")
        scope_digest = deletion_scope_digest(self.closure_roots,
                                             self.deletion_epoch, self.policy_ref)
        _anchor(self.before_anchor, self.permit.authority_id,
                self.permit.namespace, self.permit.generation)
        if self.before_anchor != self.permit.pinned_anchor:
            raise ValueError("deletion before anchor differs from fence")
        evidence = self.evidence
        if (type(evidence) is not DeletionEvidenceV1
                or evidence.kind != expected_kind
                or evidence.authority_id != self.permit.authority_id
                or evidence.namespace != self.permit.namespace
                or evidence.deletion_operation_id != self.deletion_operation_id
                or evidence.bound_anchor != self.before_anchor
                or evidence.request_digest != self.request_digest
                or evidence.scope_digest != scope_digest):
            raise ValueError("deletion evidence binding differs")

    @property
    def expected_deletion_seq(self) -> int:
        return self.before_anchor.deletion_seq + 1


@dataclass(frozen=True, slots=True)
class DeletionMutationReceiptV1:
    pending: DeletionPendingV1
    after_anchor: RestoreAnchor
    updated_revision: int
    durable_state: str = "committed"
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        _schema(self.schema)
        if type(self.pending) is not DeletionPendingV1 or self.durable_state != "committed":
            raise ValueError("deletion receipt requires committed deletion pending")
        before = self.pending.before_anchor
        after = self.after_anchor
        _exact_int(self.updated_revision, "updated_revision", minimum=1)
        if self.updated_revision != self.pending.permit.revision + 1:
            raise ValueError("deletion receipt revision must advance exactly once")
        _anchor(after, before.authority_id, before.namespace,
                before.activation_generation)
        if (after.deletion_journal_id != before.deletion_journal_id
                or after.execution_journal_id != before.execution_journal_id
                or after.execution_seq != before.execution_seq
                or after.execution_digest != before.execution_digest
                or after.deletion_seq != before.deletion_seq + 1
                or after.deletion_digest != self.pending.expected_append_digest
                or after.revocation_epoch != before.revocation_epoch + 1):
            raise ValueError("deletion receipt does not match unique append and revocation")


def _anchor_wire(anchor: RestoreAnchor) -> dict[str, Any]:
    return {name: getattr(anchor, name) for name in _ANCHOR_FIELDS}


def _anchor_from_wire(value: object) -> RestoreAnchor:
    fields = _fields(value, _ANCHOR_FIELDS, "anchor")
    return RestoreAnchor(**fields)


def _footprint_wire(footprint: RecoveryConstraintFootprint) -> dict[str, Any]:
    return json.loads(footprint._json())


def _footprint_from_wire(value: object) -> RecoveryConstraintFootprint:
    _fields(value, _FOOTPRINT_FIELDS, "recovery footprint")
    try:
        encoded = json.dumps(value, allow_nan=False)
        footprint = RecoveryConstraintFootprint._from_json(encoded)
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("invalid recovery footprint") from exc
    if _footprint_wire(footprint) != value:
        raise ValueError("noncanonical recovery footprint")
    return footprint


def to_wire(value: FencePermitV2 | PendingMutationV2 | MutationReceiptV2 |
            DeletionEvidenceV1 | DeletionPendingV1 | DeletionMutationReceiptV1 |
            ExecutionBindingV1 | PlatformObservationV1) -> dict[str, Any]:
    """Produce a fresh, JSON-shaped dict with an explicit object kind."""
    if type(value) is FencePermitV2:
        return {
            "schema": value.schema, "kind": "fence_permit", "authority_id": value.authority_id,
            "namespace": value.namespace, "subject": value.subject, "holder": value.holder,
            "generation": value.generation, "operation": value.operation,
            "operation_id": value.operation_id, "token": value.token,
            "fence_epoch": value.fence_epoch, "revision": value.revision,
            "pinned_anchor": _anchor_wire(value.pinned_anchor),
            "effect_id": value.effect_id, "command_digest": value.command_digest,
            "footprint_digest": value.footprint_digest,
        }
    if type(value) is PendingMutationV2:
        wire = {
            "schema": value.schema, "kind": "pending_mutation", "permit": to_wire(value.permit),
            "mutation_id": value.mutation_id, "request_digest": value.request_digest,
            "phase": value.phase, "before_anchor": _anchor_wire(value.before_anchor),
            "expected_append_id": value.expected_append_id,
            "expected_append_digest": value.expected_append_digest,
        }
        if value.phase == "claimed":
            wire["prepared_receipt"] = to_wire(value.prepared_receipt)
            wire["binding"] = to_wire(value.binding)
        return wire
    if type(value) is ExecutionBindingV1:
        return {
            "schema": value.schema, "kind": "execution_binding_v1",
            "permit": to_wire(value.permit), "namespace": value.namespace,
            "activity_id": value.activity_id, "effect_id": value.effect_id,
            "attempt_id": value.attempt_id, "operation_id": value.operation_id,
            "dispatch_generation": value.dispatch_generation,
            "activation_generation": value.activation_generation,
            "admission_ref": value.admission_ref,
            "verified_check_refs": list(value.verified_check_refs),
            "payload_digest": value.payload_digest,
            "platform_capability_ref": value.platform_capability_ref,
            "adapter_ref": value.adapter_ref, "account_ref": value.account_ref,
            "destination_ref": value.destination_ref, "worker_fence": value.worker_fence,
            "content_fence": value.content_fence, "cancel_epoch": value.cancel_epoch,
            "footprint": _footprint_wire(value.footprint),
            "proactive_contact": value.proactive_contact,
            "segment_authorization_ref": value.segment_authorization_ref,
            "segment_manifest_digest": value.segment_manifest_digest,
            "segment_index": value.segment_index, "segment_count": value.segment_count,
            "contact_policy_check_ref": value.contact_policy_check_ref,
        }
    if type(value) is PlatformObservationV1:
        return {
            "schema": value.schema, "kind": "platform_observation_v1",
            "binding": to_wire(value.binding),
            "handoff_start_ref": value.handoff_start_ref,
            "adapter_ref": value.adapter_ref, "account_ref": value.account_ref,
            "destination_ref": value.destination_ref,
            "observation_id": value.observation_id,
            "platform_request_id": value.platform_request_id,
            "platform_message_id": value.platform_message_id,
            "evidence_source_ref": value.evidence_source_ref,
            "outcome": value.outcome,
            "status_code_summary": value.status_code_summary,
            "observed_at_utc": value.observed_at_utc,
            "time_source_ref": value.time_source_ref,
        }
    if type(value) is MutationReceiptV2:
        return {
            "schema": value.schema, "kind": "mutation_receipt", "pending": to_wire(value.pending),
            "after_anchor": _anchor_wire(value.after_anchor),
            "updated_revision": value.updated_revision, "durable_state": value.durable_state,
        }
    if type(value) is DeletionEvidenceV1:
        return {
            "schema": value.schema, "kind": "deletion_evidence_v1",
            "authority_id": value.authority_id, "namespace": value.namespace,
            "deletion_operation_id": value.deletion_operation_id,
            "evidence_kind": value.kind, "issuer_id": value.issuer_id,
            "evidence_id": value.evidence_id,
            "bound_anchor": _anchor_wire(value.bound_anchor),
            "request_digest": value.request_digest,
            "scope_digest": value.scope_digest, "proof_digest": value.proof_digest,
            "graph_version": value.graph_version,
            "incarnation": value.incarnation, "access_epoch": value.access_epoch,
            "deletion_epoch": value.deletion_epoch,
            "barrier_scope_digest": value.barrier_scope_digest,
            "cleanup_digest": value.cleanup_digest,
        }
    if type(value) is DeletionPendingV1:
        return {
            "schema": value.schema, "kind": "deletion_pending_v1",
            "permit": to_wire(value.permit), "mutation_id": value.mutation_id,
            "request_digest": value.request_digest,
            "deletion_operation_id": value.deletion_operation_id,
            "source_phase": value.source_phase, "target_phase": value.target_phase,
            "closure_roots": list(value.closure_roots),
            "deletion_epoch": value.deletion_epoch, "policy_ref": value.policy_ref,
            "before_anchor": _anchor_wire(value.before_anchor),
            "evidence": to_wire(value.evidence),
            "expected_append_id": value.expected_append_id,
            "expected_append_digest": value.expected_append_digest,
        }
    if type(value) is DeletionMutationReceiptV1:
        return {
            "schema": value.schema, "kind": "deletion_receipt_v1",
            "pending": to_wire(value.pending),
            "after_anchor": _anchor_wire(value.after_anchor),
            "updated_revision": value.updated_revision,
            "durable_state": value.durable_state,
        }
    raise TypeError("unsupported authority v2 DTO")


def from_wire(value: object) -> (FencePermitV2 | PendingMutationV2 | MutationReceiptV2 |
                                 DeletionEvidenceV1 | DeletionPendingV1 |
                                 DeletionMutationReceiptV1 | ExecutionBindingV1 |
                                 PlatformObservationV1):
    """Reject unknown schemas, fields, kinds and nested shapes before use."""
    if type(value) is not dict or value.get("schema") != SCHEMA:
        raise ValueError("unknown authority schema")
    kind = value.get("kind")
    if kind == "fence_permit":
        _fields(value, frozenset({
            "schema", "kind", "authority_id", "namespace", "subject", "holder",
            "generation", "operation", "operation_id", "token", "fence_epoch",
            "revision", "pinned_anchor", "effect_id", "command_digest",
            "footprint_digest",
        }), "fence permit")
        return FencePermitV2(**{key: (_anchor_from_wire(item) if key == "pinned_anchor" else item)
                                for key, item in value.items() if key != "kind"})
    if kind == "pending_mutation":
        fields = frozenset({
            "schema", "kind", "permit", "mutation_id", "request_digest", "phase",
            "before_anchor", "expected_append_id", "expected_append_digest",
        })
        if value.get("phase") == "claimed":
            fields |= frozenset({"prepared_receipt", "binding"})
        _fields(value, fields, "pending mutation")
        permit = from_wire(value["permit"])
        if type(permit) is not FencePermitV2:
            raise ValueError("pending permit kind mismatch")
        receipt = from_wire(value["prepared_receipt"]) if value["phase"] == "claimed" else None
        binding = from_wire(value["binding"]) if value["phase"] == "claimed" else None
        return PendingMutationV2(
            permit=permit, mutation_id=value["mutation_id"],
            request_digest=value["request_digest"], phase=value["phase"],
            before_anchor=_anchor_from_wire(value["before_anchor"]),
            expected_append_id=value["expected_append_id"],
            expected_append_digest=value["expected_append_digest"],
            schema=value["schema"], prepared_receipt=receipt, binding=binding,
        )
    if kind == "execution_binding_v1":
        _fields(value, frozenset({
            "schema", "kind", "permit", "namespace", "activity_id", "effect_id",
            "attempt_id", "operation_id", "dispatch_generation",
            "activation_generation", "admission_ref", "verified_check_refs",
            "payload_digest",
            "platform_capability_ref", "adapter_ref", "account_ref", "destination_ref",
            "worker_fence", "content_fence", "cancel_epoch", "footprint",
            "proactive_contact", "segment_authorization_ref", "segment_manifest_digest",
            "segment_index", "segment_count", "contact_policy_check_ref",
        }), "execution binding")
        permit = from_wire(value["permit"])
        if type(permit) is not FencePermitV2 or type(value["verified_check_refs"]) is not list:
            raise ValueError("execution binding fence kind mismatch")
        return ExecutionBindingV1(
            **{key: (permit if key == "permit" else
                     _footprint_from_wire(item) if key == "footprint" else
                     tuple(item) if key == "verified_check_refs" else item)
               for key, item in value.items() if key != "kind"})
    if kind == "platform_observation_v1":
        _fields(value, frozenset({
            "schema", "kind", "binding", "handoff_start_ref", "adapter_ref",
            "account_ref", "destination_ref", "observation_id",
            "platform_request_id", "platform_message_id", "evidence_source_ref",
            "outcome", "status_code_summary", "observed_at_utc", "time_source_ref",
        }), "platform observation")
        binding = from_wire(value["binding"])
        if type(binding) is not ExecutionBindingV1:
            raise ValueError("platform observation binding kind mismatch")
        return PlatformObservationV1(
            **{key: (binding if key == "binding" else item)
               for key, item in value.items() if key != "kind"})
    if kind == "mutation_receipt":
        _fields(value, frozenset({
            "schema", "kind", "pending", "after_anchor", "updated_revision",
            "durable_state",
        }), "mutation receipt")
        pending = from_wire(value["pending"])
        if type(pending) is not PendingMutationV2:
            raise ValueError("receipt pending kind mismatch")
        return MutationReceiptV2(
            pending=pending, after_anchor=_anchor_from_wire(value["after_anchor"]),
            updated_revision=value["updated_revision"],
            durable_state=value["durable_state"], schema=value["schema"],
        )
    if kind == "deletion_evidence_v1":
        _fields(value, frozenset({
            "schema", "kind", "authority_id", "namespace",
            "deletion_operation_id", "evidence_kind", "issuer_id",
            "evidence_id", "bound_anchor", "request_digest", "scope_digest",
            "proof_digest", "graph_version", "incarnation", "access_epoch",
            "deletion_epoch", "barrier_scope_digest", "cleanup_digest",
        }), "deletion evidence")
        return DeletionEvidenceV1(
            **{("kind" if key == "evidence_kind" else key):
               (_anchor_from_wire(item) if key == "bound_anchor" else item)
               for key, item in value.items() if key != "kind"})
    if kind == "deletion_pending_v1":
        _fields(value, frozenset({
            "schema", "kind", "permit", "mutation_id", "request_digest",
            "deletion_operation_id", "source_phase", "target_phase",
            "closure_roots", "deletion_epoch", "policy_ref", "before_anchor",
            "evidence", "expected_append_id", "expected_append_digest",
        }), "deletion pending")
        permit, evidence = from_wire(value["permit"]), from_wire(value["evidence"])
        if (type(permit) is not FencePermitV2 or type(evidence) is not DeletionEvidenceV1
                or type(value["closure_roots"]) is not list):
            raise ValueError("deletion pending nested kind or roots mismatch")
        return DeletionPendingV1(
            permit=permit, evidence=evidence,
            closure_roots=tuple(value["closure_roots"]),
            before_anchor=_anchor_from_wire(value["before_anchor"]),
            **{key: item for key, item in value.items() if key not in {
                "kind", "permit", "evidence", "closure_roots", "before_anchor"}},
        )
    if kind == "deletion_receipt_v1":
        _fields(value, frozenset({
            "schema", "kind", "pending", "after_anchor", "updated_revision",
            "durable_state",
        }), "deletion receipt")
        pending = from_wire(value["pending"])
        if type(pending) is not DeletionPendingV1:
            raise ValueError("deletion receipt pending kind mismatch")
        return DeletionMutationReceiptV1(
            pending=pending, after_anchor=_anchor_from_wire(value["after_anchor"]),
            updated_revision=value["updated_revision"],
            durable_state=value["durable_state"], schema=value["schema"],
        )
    raise ValueError("unknown authority v2 DTO kind")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON number: {value}")


def canonical_bytes(value: FencePermitV2 | PendingMutationV2 | MutationReceiptV2 |
                    DeletionEvidenceV1 | DeletionPendingV1 |
                    DeletionMutationReceiptV1 | ExecutionBindingV1 |
                    PlatformObservationV1) -> bytes:
    return json.dumps(to_wire(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_digest(value: FencePermitV2 | PendingMutationV2 | MutationReceiptV2 |
                     DeletionEvidenceV1 | DeletionPendingV1 |
                     DeletionMutationReceiptV1 | ExecutionBindingV1 |
                     PlatformObservationV1) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def decode_bytes(data: bytes) -> (FencePermitV2 | PendingMutationV2 | MutationReceiptV2 |
                                  DeletionEvidenceV1 | DeletionPendingV1 |
                                  DeletionMutationReceiptV1 | ExecutionBindingV1 |
                                  PlatformObservationV1):
    if type(data) is not bytes:
        raise TypeError("authority wire data must be bytes")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs,
                       parse_constant=_reject_constant)
    return from_wire(value)


__all__ = ["SCHEMA", "FencePermitV2", "PendingMutationV2", "MutationReceiptV2",
           "ExecutionBindingV1", "PlatformObservationV1",
           "DeletionEvidenceV1", "DeletionPendingV1", "DeletionMutationReceiptV1",
           "deletion_scope_digest", "to_wire", "from_wire", "canonical_bytes",
           "canonical_digest", "decode_bytes"]
