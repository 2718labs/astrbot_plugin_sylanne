"""Dedicated Authority D04 ABI2 execution contract; no role BodyQuote.

Binding, claim and terminal are distinct durable originals. Only the installed
Authority service can issue claim/terminal; these DTOs grant no execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor

SCHEMA = "d04.numeric_authority_original.v3"
WORK_KIND = "d04.joint_numeric_cpu.v3"


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("D04 numeric digest must be SHA256")


@dataclass(frozen=True, slots=True)
class D04NumericBindingV3:
    namespace: NamespaceId
    authority_id: str
    authority_namespace: str
    installation_id: str
    activation_generation: int
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    operation_id: str
    execution_id: str
    job_id: str
    activity_id: str
    input_original_ref: str
    input_digest: str
    algorithm_id: str
    algorithm_build_digest: str
    native_manifest_sha256: str
    native_sha256: str
    output_policy_digest: str
    quote_id: str
    quote_version: int
    quote_digest: str
    parent_budget_lease_ref: str
    reservation_operation_id: str
    reservation_digest: str
    cpu_ceiling_ms: int
    family_roots: tuple[str, ...]
    deadline_utc: str
    schema: str = SCHEMA

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId or self.schema != SCHEMA:
            raise ValueError("typed D04 numeric namespace/schema required")
        for name in ("owner_grant_digest", "input_digest", "algorithm_build_digest",
                     "native_manifest_sha256", "native_sha256", "output_policy_digest",
                     "quote_digest", "reservation_digest"):
            _digest(getattr(self, name))
        for name in ("activation_generation", "owner_grant_revision", "quote_version", "cpu_ceiling_ms"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError("D04 numeric version/ceiling must be positive")
        if (type(self.family_roots) is not tuple or not self.family_roots
                or tuple(sorted(set(self.family_roots))) != self.family_roots):
            raise ValueError("D04 numeric families require complete sorted unique roots")
        for name in ("authority_id", "authority_namespace", "installation_id", "owner_grant_ref",
                     "operation_id", "execution_id", "job_id", "activity_id", "input_original_ref",
                     "algorithm_id", "quote_id", "parent_budget_lease_ref", "reservation_operation_id",
                     "deadline_utc"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError("D04 numeric identity incomplete")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04NumericClaimV3:
    binding_digest: str
    execution_id: str
    claim_id: str
    claim_sequence: int
    executor_installation_id: str
    executor_incarnation: str
    signature: str
    schema: str = SCHEMA

    def __post_init__(self):
        _digest(self.binding_digest)
        if (self.schema != SCHEMA or type(self.claim_sequence) is not int or self.claim_sequence < 1
                or not all((self.execution_id, self.claim_id, self.executor_installation_id,
                            self.executor_incarnation, self.signature))):
            raise ValueError("D04 numeric claim identity incomplete")


@dataclass(frozen=True, slots=True)
class D04NumericMeasurementV3:
    binding_digest: str
    claim_id: str
    status: str
    actual_cpu_ns: int
    full_transcript_digest: str | None
    family_loo_transcripts: tuple[tuple[str, str], ...]
    output_original_digest: str | None
    failure_code: str | None
    measurement_clock: str = "thread_time_ns"
    schema: str = SCHEMA

    def __post_init__(self):
        _digest(self.binding_digest)
        if (self.schema != SCHEMA or self.status not in {"completed", "failed"}
                or self.measurement_clock != "thread_time_ns"
                or type(self.actual_cpu_ns) is not int or self.actual_cpu_ns < 0):
            raise ValueError("D04 numeric measured terminal invalid")
        if tuple(sorted(self.family_loo_transcripts)) != self.family_loo_transcripts:
            raise ValueError("D04 LOO transcripts must be sorted")
        if len({f for f, _ in self.family_loo_transcripts}) != len(self.family_loo_transcripts):
            raise ValueError("D04 LOO transcript family duplicate")
        for _family, digest in self.family_loo_transcripts:
            _digest(digest)
        if self.status == "completed":
            _digest(self.full_transcript_digest)
            _digest(self.output_original_digest)
            if self.failure_code is not None:
                raise ValueError("completed D04 numeric terminal has failure")
        elif not self.failure_code:
            raise ValueError("failed D04 numeric terminal needs failure code")

    @property
    def actual_cpu_ms(self):
        return (self.actual_cpu_ns + 999_999) // 1_000_000


@dataclass(frozen=True, slots=True)
class D04NumericTerminalV3:
    binding: D04NumericBindingV3
    claim: D04NumericClaimV3
    measurement: D04NumericMeasurementV3
    terminal_ref: str
    terminal_sequence: int
    journal_head_digest: str
    signature: str
    schema: str = SCHEMA

    def __post_init__(self):
        if (type(self.binding) is not D04NumericBindingV3 or type(self.claim) is not D04NumericClaimV3
                or type(self.measurement) is not D04NumericMeasurementV3 or self.schema != SCHEMA
                or self.claim.binding_digest != self.binding.digest
                or self.measurement.binding_digest != self.binding.digest
                or self.measurement.claim_id != self.claim.claim_id
                or self.claim.execution_id != self.binding.execution_id
                or self.claim.executor_installation_id != self.binding.installation_id
                or type(self.terminal_sequence) is not int
                or self.terminal_sequence <= self.claim.claim_sequence
                or not self.signature or not self.terminal_ref):
            raise ValueError("D04 numeric durable terminal identity differs")
        _digest(self.journal_head_digest)
        if (self.measurement.status == "completed" and
                tuple(f for f, _ in self.measurement.family_loo_transcripts) != self.binding.family_roots):
            raise ValueError("D04 terminal does not cover all removal transcripts")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04NumericMeasuredCostClosureV3:
    """Measured execution cost only; never a restored/adoptable numeric result."""
    binding: D04NumericBindingV3
    claim: D04NumericClaimV3
    measurement: D04NumericMeasurementV3
    artifact_disposition: str
    barrier_basis_digest: str
    current_anchor: RestoreAnchor
    closure_ref: str
    terminal_sequence: int
    journal_head_digest: str
    signature: str
    adoption_allowed: bool = False
    schema: str = "d04.numeric-measured-cost-closure.v3"

    def __post_init__(self):
        if (type(self.binding) is not D04NumericBindingV3 or type(self.claim) is not D04NumericClaimV3
                or type(self.measurement) is not D04NumericMeasurementV3 or type(self.current_anchor) is not RestoreAnchor
                or self.claim.binding_digest!=self.binding.digest or self.measurement.binding_digest!=self.binding.digest
                or self.measurement.claim_id!=self.claim.claim_id or self.measurement.status!="completed"
                or self.artifact_disposition not in {"withheld_by_current_barrier","missing_after_crash"}
                or self.adoption_allowed is not False or self.schema!="d04.numeric-measured-cost-closure.v3"
                or type(self.terminal_sequence) is not int or self.terminal_sequence<=self.claim.claim_sequence
                or not self.closure_ref or not self.signature):
            raise ValueError("numeric measured-cost closure identity differs")
        _digest(self.barrier_basis_digest);_digest(self.journal_head_digest)

    @property
    def digest(self):
        return canonical_digest(asdict(self))

    @property
    def terminal_ref(self):
        return self.closure_ref


def to_wire(value):
    if type(value) not in {D04NumericBindingV3, D04NumericClaimV3, D04NumericMeasurementV3, D04NumericTerminalV3, D04NumericMeasuredCostClosureV3}:
        raise TypeError("typed D04 numeric Authority original required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw, kind):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("D04 numeric Authority wire shape differs")
    values = dict(raw)
    if kind is D04NumericBindingV3:
        values["namespace"] = NamespaceId(**values["namespace"])
        values["family_roots"] = tuple(values["family_roots"])
    elif kind is D04NumericMeasurementV3:
        values["family_loo_transcripts"] = tuple(tuple(pair) for pair in values["family_loo_transcripts"])
    elif kind in {D04NumericTerminalV3,D04NumericMeasuredCostClosureV3}:
        values["binding"] = from_wire(values["binding"], D04NumericBindingV3)
        values["claim"] = from_wire(values["claim"], D04NumericClaimV3)
        values["measurement"] = from_wire(values["measurement"], D04NumericMeasurementV3)
        if kind is D04NumericMeasuredCostClosureV3:values["current_anchor"]=RestoreAnchor(**values["current_anchor"])
    elif kind is not D04NumericClaimV3:
        raise ValueError("unsupported D04 numeric wire type")
    result = kind(**values)
    if to_wire(result) != raw:
        raise ValueError("noncanonical D04 numeric Authority wire")
    return result
