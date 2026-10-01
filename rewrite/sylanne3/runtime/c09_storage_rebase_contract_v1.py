"""Typed, content-free C09 storage-rebase and recovery contracts.

These records are commitments for an installer verifier. Constructing one does
not authenticate an Authority signature, perform cleanup, or reopen content.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import math
import re

from ..runtime_contracts import canonical_digest
from ..runtime_journal import RecoveryConstraintFootprint


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@#=+-]{0,255}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_DISPOSITIONS = frozenset({
    "preserved_exact", "payload_erased_retained_facts", "derived_removed",
    "rebuilt_from_surviving_sources",
})


def _id(value: str, name: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _digest(value: str, name: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _number(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"invalid {name}")


def _ordered(values: tuple, item_type: type, name: str, key) -> None:
    if (type(values) is not tuple or any(type(v) is not item_type for v in values)
            or tuple(sorted(values, key=key)) != values
            or len({key(v) for v in values}) != len(values)):
        raise ValueError(f"invalid {name}")


def _committed(value, name: str = "digest") -> None:
    _digest(getattr(value, name), name)
    body = tuple(getattr(value, field.name) for field in fields(value)
                 if field.name != name)
    if getattr(value, name) != canonical_digest(body):
        raise ValueError(f"{name} differs")


@dataclass(frozen=True, slots=True)
class GraphRowDispositionV1:
    row_key_digest: str
    old_commitment: str
    disposition: str
    new_commitment: str | None

    def __post_init__(self) -> None:
        _digest(self.row_key_digest, "row_key_digest")
        _digest(self.old_commitment, "old_commitment")
        if self.disposition not in _DISPOSITIONS:
            raise ValueError("unknown row disposition")
        if self.disposition in {"derived_removed", "payload_erased_retained_facts"}:
            if self.disposition == "derived_removed" and self.new_commitment is not None:
                raise ValueError("removed row has a new commitment")
            if self.disposition == "payload_erased_retained_facts" and self.new_commitment is None:
                raise ValueError("retained facts need a new commitment")
        elif self.new_commitment is None:
            raise ValueError("preserved or rebuilt row needs a new commitment")
        if self.new_commitment is not None:
            _digest(self.new_commitment, "new_commitment")
        if self.disposition == "preserved_exact" and self.new_commitment != self.old_commitment:
            raise ValueError("preserved row commitment changed")


@dataclass(frozen=True, slots=True)
class GraphTableDispositionManifestV1:
    table_name: str
    rows: tuple[GraphRowDispositionV1, ...]
    manifest_digest: str
    schema: str = "sylanne3.graph.c09_table_disposition.v1"

    def __post_init__(self) -> None:
        _id(self.table_name, "table_name")
        if self.schema != "sylanne3.graph.c09_table_disposition.v1":
            raise ValueError("table disposition schema differs")
        _ordered(self.rows, GraphRowDispositionV1, "rows", lambda row: row.row_key_digest)
        _committed(self, "manifest_digest")


@dataclass(frozen=True, slots=True)
class GraphErasureRebaseCertificateV1:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    accepted_receipt_digest: str
    barrier_receipt_digest: str
    frozen_inventory_digest: str
    old_incarnation: str
    old_revision: int
    old_graph_epoch: int
    old_access_epoch: int
    old_delete_epoch: int
    new_incarnation: str
    maintenance_generation: int
    table_manifests: tuple[GraphTableDispositionManifestV1, ...]
    source_closure_digest: str
    derived_closure_digest: str
    prior_certificate_digest: str | None
    prior_erased_key_digests: tuple[str, ...]
    newly_erased_key_digests: tuple[str, ...]
    cumulative_erased_key_digests: tuple[str, ...]
    tombstone_root: str
    new_data_root: str
    component_hashes: tuple[tuple[str, str], ...]
    cold_read_digest: str
    certificate_digest: str
    schema: str = "sylanne3.graph.c09_erasure_rebase.v1"

    def __post_init__(self) -> None:
        for name in ("authority_id", "installation_id", "namespace", "operation_id",
                     "old_incarnation", "new_incarnation"):
            _id(getattr(self, name), name)
        if self.schema != "sylanne3.graph.c09_erasure_rebase.v1":
            raise ValueError("graph rebase schema differs")
        for name in ("accepted_receipt_digest", "barrier_receipt_digest",
                     "frozen_inventory_digest", "source_closure_digest",
                     "derived_closure_digest", "tombstone_root", "new_data_root",
                     "cold_read_digest"):
            _digest(getattr(self, name), name)
        for name in ("old_revision", "old_graph_epoch", "old_access_epoch",
                     "old_delete_epoch", "maintenance_generation"):
            _number(getattr(self, name), name)
        if self.maintenance_generation < 1 or self.new_incarnation == self.old_incarnation:
            raise ValueError("new storage generation is not distinct")
        _ordered(self.table_manifests, GraphTableDispositionManifestV1,
                 "table_manifests", lambda item: item.table_name)
        if not self.table_manifests:
            raise ValueError("graph rebase has no table manifest")
        for name in ("prior_erased_key_digests", "newly_erased_key_digests",
                     "cumulative_erased_key_digests"):
            values = getattr(self, name)
            if type(values) is not tuple or values != tuple(sorted(set(values))):
                raise ValueError(f"invalid {name}")
            for value in values:
                _digest(value, name)
        if (not self.newly_erased_key_digests
                or set(self.prior_erased_key_digests).intersection(
                    self.newly_erased_key_digests)
                or self.cumulative_erased_key_digests != tuple(sorted(
                    set(self.prior_erased_key_digests) | set(self.newly_erased_key_digests)))
                or (self.prior_certificate_digest is None) !=
                   (not self.prior_erased_key_digests)):
            raise ValueError("cumulative erased keys differ")
        if self.prior_certificate_digest is not None:
            _digest(self.prior_certificate_digest, "prior_certificate_digest")
        if self.tombstone_root != canonical_digest(self.cumulative_erased_key_digests):
            raise ValueError("tombstone root differs")
        if (type(self.component_hashes) is not tuple or not self.component_hashes
                or self.component_hashes != tuple(sorted(self.component_hashes))
                or len({name for name, _ in self.component_hashes}) != len(self.component_hashes)):
            raise ValueError("component hashes differ")
        for name, value in self.component_hashes:
            _id(name, "component_name")
            _digest(value, "component_hash")
        _committed(self, "certificate_digest")


@dataclass(frozen=True, slots=True)
class SanitizedExecutionFactV4:
    execution_id: str
    input_commitment: str
    result_commitment: str | None
    terminal_commitment: str | None
    signature_commitment: str | None
    status: str
    consumed: bool

    def __post_init__(self) -> None:
        _id(self.execution_id, "execution_id")
        _digest(self.input_commitment, "input_commitment")
        for name in ("result_commitment", "terminal_commitment", "signature_commitment"):
            value = getattr(self, name)
            if value is not None:
                _digest(value, name)
        if (self.status not in {"pending", "completed", "failed", "unknown"}
                or type(self.consumed) is not bool
                or (self.status != "pending" and not self.consumed)
                or (self.status in {"completed", "failed"} and (
                    self.terminal_commitment is None
                    or self.signature_commitment is None))
                or (self.status == "unknown"
                    and self.signature_commitment is None)):
            raise ValueError("execution state or consumed right differs")


@dataclass(frozen=True, slots=True)
class SanitizedD02FactV4:
    quote_id: str
    component_id: str
    outcome_id: str
    settlement_id: str
    quote_commitment: str
    completed_commitment: str
    outcome_commitment: str
    settlement_commitment: str
    fixed_cost_hex: str
    fixed_cost_unit: str = "body_energy"

    def __post_init__(self) -> None:
        for name in ("quote_id", "component_id", "outcome_id", "settlement_id"):
            _id(getattr(self, name), name)
        for name in ("quote_commitment", "completed_commitment",
                     "outcome_commitment", "settlement_commitment"):
            _digest(getattr(self, name), name)
        if (type(self.fixed_cost_hex) is not str
                or self.fixed_cost_unit != "body_energy"):
            raise ValueError("D02 fixed cost unit or representation differs")
        try:
            value = float.fromhex(self.fixed_cost_hex)
        except ValueError as exc:
            raise ValueError("invalid D02 fixed cost") from exc
        if (not math.isfinite(value) or value <= 0
                or value.hex() != self.fixed_cost_hex):
            raise ValueError("D02 fixed cost must preserve one finite float")


@dataclass(frozen=True, slots=True)
class SanitizedD11FactV4:
    settlement_id: str
    parent_budget_id: str
    idempotency_id: str
    upper_bound: int
    actual_cost: int
    settled: int
    pending: int
    debt: int
    cost_unit: str = "cpu_ms"

    def __post_init__(self) -> None:
        for name in ("settlement_id", "parent_budget_id", "idempotency_id"):
            _id(getattr(self, name), name)
        for name in ("upper_bound", "actual_cost", "settled", "pending", "debt"):
            _number(getattr(self, name), name)
        if (self.cost_unit not in {"cpu_ms", "thread_cpu_ms", "input_tokens", "output_tokens", "model_tokens", "model_microusd"}
                or self.settled + self.pending != self.actual_cost
                or self.debt != max(0, self.actual_cost - self.upper_bound)):
            raise ValueError("D11 actual cost, pending, or overrun differs")


@dataclass(frozen=True, slots=True)
class SanitizedUnknownFactV4:
    execution_id: str
    dispatch_generation: int
    platform_query_ref: str | None
    quota_held: int
    cost_pending: tuple[tuple[str, str | None, str | None], ...]
    footprint: RecoveryConstraintFootprint

    def __post_init__(self) -> None:
        _id(self.execution_id, "execution_id")
        _number(self.dispatch_generation, "dispatch_generation")
        if self.dispatch_generation < 1:
            raise ValueError("unknown dispatch generation is absent")
        if self.platform_query_ref is not None:
            _id(self.platform_query_ref, "platform_query_ref")
        _number(self.quota_held, "quota_held")
        if (type(self.footprint) is not RecoveryConstraintFootprint
                or not self.footprint.conflict_keys
                or self.footprint.external_query_ref != self.platform_query_ref
                or self.quota_held != sum(
                    item.occupied for item in self.footprint.quota_occupancies)
                or self.cost_pending != tuple(sorted(
                    [(item.parent_budget_ref, item.pending_amount,
                      item.upper_bound) for item in self.footprint.budgets],
                    key=lambda item: item[0]))):
            raise ValueError("unknown recovery constraint footprint is absent")


@dataclass(frozen=True, slots=True)
class SanitizedGraphFactV4:
    operation_id: str
    receipt_commitment: str
    write_set_commitment: str
    unresolved_obligation_commitment: str | None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        _digest(self.receipt_commitment, "receipt_commitment")
        _digest(self.write_set_commitment, "write_set_commitment")
        if self.unresolved_obligation_commitment is not None:
            _digest(self.unresolved_obligation_commitment,
                    "unresolved_obligation_commitment")


@dataclass(frozen=True, slots=True)
class SanitizedRecoveryFactsV4:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    old_chain_head_digest: str
    verifier_commitment: str
    executions: tuple[SanitizedExecutionFactV4, ...]
    d02_facts: tuple[SanitizedD02FactV4, ...]
    d11_facts: tuple[SanitizedD11FactV4, ...]
    unknown_facts: tuple[SanitizedUnknownFactV4, ...]
    graph_facts: tuple[SanitizedGraphFactV4, ...]
    facts_digest: str
    schema: str = "sylanne3.authority.sanitized_recovery_facts.v4"

    def __post_init__(self) -> None:
        for name in ("authority_id", "installation_id", "namespace", "operation_id"):
            _id(getattr(self, name), name)
        if (type(self.old_chain_head_digest) is not str
                or not self.old_chain_head_digest.startswith("sha256:")):
            raise ValueError("old chain head must preserve journal digest syntax")
        _digest(self.old_chain_head_digest.removeprefix("sha256:"),
                "old_chain_head_digest")
        _digest(self.verifier_commitment, "verifier_commitment")
        if self.schema != "sylanne3.authority.sanitized_recovery_facts.v4":
            raise ValueError("recovery facts schema differs")
        for name, kind, key in (
            ("executions", SanitizedExecutionFactV4, lambda v: v.execution_id),
            ("d02_facts", SanitizedD02FactV4, lambda v: v.quote_id),
            ("d11_facts", SanitizedD11FactV4, lambda v: v.settlement_id),
            ("unknown_facts", SanitizedUnknownFactV4, lambda v: v.execution_id),
            ("graph_facts", SanitizedGraphFactV4, lambda v: v.operation_id),
        ):
            _ordered(getattr(self, name), kind, name, key)
        states = {fact.execution_id: fact.status for fact in self.executions}
        if (any(states.get(fact.execution_id) != "unknown" for fact in self.unknown_facts)
                or {key for key, status in states.items() if status == "unknown"}
                   != {fact.execution_id for fact in self.unknown_facts}):
            raise ValueError("unknown execution constraints differ")
        _committed(self, "facts_digest")


@dataclass(frozen=True, slots=True)
class SanitizedGraphReadV1:
    key_digest: str
    status: str
    original_commitment: str | None
    certificate_digest: str | None

    def __post_init__(self) -> None:
        _digest(self.key_digest, "key_digest")
        if self.status == "original":
            if self.original_commitment is None or self.certificate_digest is not None:
                raise ValueError("original read commitment differs")
            _digest(self.original_commitment, "original_commitment")
        elif self.status == "erased":
            if self.original_commitment is not None or self.certificate_digest is None:
                raise ValueError("erased read must name its rebase certificate")
            _digest(self.certificate_digest, "certificate_digest")
        else:
            raise ValueError("read status must be original or erased")


def require_same_operation_replay_v1(prior, candidate) -> None:
    """A store can use this before returning an existing C09 original."""
    if type(prior) is not type(candidate) or type(prior) not in {
            GraphErasureRebaseCertificateV1, SanitizedRecoveryFactsV4}:
        raise TypeError("matching C09 originals required")
    identity = ("authority_id", "installation_id", "namespace", "operation_id")
    if any(getattr(prior, name) != getattr(candidate, name) for name in identity):
        raise ValueError("C09 operation identity differs")
    if prior != candidate:
        raise ValueError("C09 same operation has a different commitment")


__all__ = [
    "GraphRowDispositionV1", "GraphTableDispositionManifestV1",
    "GraphErasureRebaseCertificateV1", "SanitizedExecutionFactV4",
    "SanitizedD02FactV4", "SanitizedD11FactV4", "SanitizedUnknownFactV4",
    "SanitizedGraphFactV4", "SanitizedRecoveryFactsV4", "SanitizedGraphReadV1",
    "require_same_operation_replay_v1",
]
