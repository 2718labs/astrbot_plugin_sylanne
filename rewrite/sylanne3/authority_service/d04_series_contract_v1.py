"""Independent chunk protocol; old numeric-v3 completed means final only."""
from dataclasses import asdict, dataclass, fields
import json

from .d04_numeric_contract_v3 import D04NumericBindingV3, from_wire as numeric_from_wire
from ..runtime_contracts import canonical_digest, canonical_serialize


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("series commitment must be SHA256")


@dataclass(frozen=True, slots=True)
class D04SeriesChunkBindingV1:
    numeric: D04NumericBindingV3
    root_ref: str
    root_digest: str
    plan_digest: str
    start_step_index: int
    end_step_index: int
    predecessor_ref: str | None
    predecessor_digest: str | None
    schema: str = "d04.series-chunk-binding.v1"

    def __post_init__(self):
        _digest(self.root_digest)
        _digest(self.plan_digest)
        if (type(self.numeric) is not D04NumericBindingV3 or not self.root_ref
                or type(self.start_step_index) is not int or type(self.end_step_index) is not int
                or not 0 <= self.start_step_index < self.end_step_index
                or self.end_step_index - self.start_step_index > 512
                or self.schema != "d04.series-chunk-binding.v1"):
            raise ValueError("series chunk identity/absolute bounds differ")
        if self.start_step_index == 0:
            if self.predecessor_ref is not None or self.predecessor_digest is not None:
                raise ValueError("initial series chunk has no predecessor")
        else:
            if not self.predecessor_ref:
                raise ValueError("continuation requires actual predecessor original")
            _digest(self.predecessor_digest)

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04SeriesClaimV1:
    binding_digest: str
    execution_id: str
    claim_id: str
    claim_sequence: int
    executor_installation_id: str
    executor_incarnation: str
    signature: str
    schema: str = "d04.series-claim.v1"

    def __post_init__(self):
        _digest(self.binding_digest)
        if (self.schema != "d04.series-claim.v1" or type(self.claim_sequence) is not int
                or self.claim_sequence < 1 or not all((self.execution_id, self.claim_id,
                    self.executor_installation_id, self.executor_incarnation, self.signature))):
            raise ValueError("series claim identity differs")


@dataclass(frozen=True, slots=True)
class D04SeriesMeasurementV1:
    binding_digest: str
    claim_id: str
    status: str
    actual_cpu_ns: int
    chunk_math_digest: str | None
    endpoint_digest: str | None
    failure_code: str | None
    schema: str = "d04.series-measurement.v1"

    def __post_init__(self):
        _digest(self.binding_digest)
        if (self.schema != "d04.series-measurement.v1" or self.status not in {"chunk_completed", "failed"}
                or type(self.actual_cpu_ns) is not int or self.actual_cpu_ns < 0 or not self.claim_id):
            raise ValueError("series actual measurement differs")
        if self.status == "chunk_completed":
            _digest(self.chunk_math_digest)
            _digest(self.endpoint_digest)
            if self.failure_code is not None:
                raise ValueError("completed chunk has no failure")
        elif not self.failure_code:
            raise ValueError("failed chunk needs actual failure code")

    @property
    def actual_cpu_ms(self):
        return (self.actual_cpu_ns + 999_999) // 1_000_000


@dataclass(frozen=True, slots=True)
class D04SeriesTerminalV1:
    binding: D04SeriesChunkBindingV1
    claim: D04SeriesClaimV1
    measurement: D04SeriesMeasurementV1
    terminal_ref: str
    terminal_sequence: int
    journal_head_digest: str
    signature: str
    schema: str = "d04.series-terminal.v1"

    def __post_init__(self):
        _digest(self.journal_head_digest)
        if (self.schema != "d04.series-terminal.v1" or type(self.binding) is not D04SeriesChunkBindingV1
                or type(self.claim) is not D04SeriesClaimV1 or type(self.measurement) is not D04SeriesMeasurementV1
                or self.claim.binding_digest != self.binding.digest
                or self.measurement.binding_digest != self.binding.digest
                or self.measurement.claim_id != self.claim.claim_id
                or self.claim.execution_id != self.binding.numeric.execution_id
                or self.claim.executor_installation_id != self.binding.numeric.installation_id
                or type(self.terminal_sequence) is not int or self.terminal_sequence != self.claim.claim_sequence + 1
                or not self.signature or not self.terminal_ref):
            raise ValueError("series durable terminal/claim differs")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04SeriesGateV1:
    binding: D04SeriesChunkBindingV1
    phase: str
    permit: object
    before_requirements_json: str
    before_graph_revision: int
    root_digest: str
    retain_math: bool
    signature: str
    schema: str = "d04.series-gate.v1"

    def __post_init__(self):
        from .v2_contract import FencePermitV2
        if (type(self.binding) is not D04SeriesChunkBindingV1 or type(self.permit) is not FencePermitV2
                or self.phase not in {"measurement", "settlement", "restore"}
                or self.permit.operation != ("write" if self.phase == "restore" else "accounting")
                or self.permit.operation_id != gate_id(self.binding, self.phase)
                or self.root_digest != self.binding.root_digest
                or type(self.retain_math) is not bool or not self.signature
                or self.schema != "d04.series-gate.v1"):
            raise ValueError("series exact gate differs")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def to_wire(value):
    if type(value) not in {D04SeriesChunkBindingV1, D04SeriesClaimV1, D04SeriesMeasurementV1, D04SeriesTerminalV1, D04SeriesGateV1}:
        raise TypeError("typed series Authority original required")
    raw = json.loads(canonical_serialize(asdict(value)))
    if type(value) is D04SeriesGateV1:
        from .v2_contract import to_wire as fence_to_wire
        raw["permit"] = fence_to_wire(value.permit)
    return raw


def from_wire(raw, kind):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("series Authority wire fields differ")
    values = dict(raw)
    if kind is D04SeriesChunkBindingV1:
        values["numeric"] = numeric_from_wire(values["numeric"], D04NumericBindingV3)
    elif kind is D04SeriesTerminalV1:
        for name, child in (("binding", D04SeriesChunkBindingV1), ("claim", D04SeriesClaimV1),
                ("measurement", D04SeriesMeasurementV1)):
            values[name] = from_wire(values[name], child)
    elif kind is D04SeriesGateV1:
        from .v2_contract import from_wire as fence_from_wire
        values["binding"] = from_wire(values["binding"], D04SeriesChunkBindingV1)
        values["permit"] = fence_from_wire(values["permit"])
    elif kind not in {D04SeriesClaimV1, D04SeriesMeasurementV1}:
        raise ValueError("unsupported series Authority wire type")
    result = kind(**values)
    if to_wire(result) != raw:
        raise ValueError("noncanonical series Authority wire")
    return result


def mutation_id(binding, phase):
    if phase not in {"claim", "terminal"}:
        raise ValueError("unknown series mutation phase")
    return "d04-series:" + phase + ":" + canonical_digest((binding.numeric.authority_namespace,
        binding.numeric.installation_id, binding.numeric.execution_id))


def gate_id(binding, phase):
    if phase not in {"claim", "measurement", "settlement", "restore"}:
        raise ValueError("unknown series gate phase")
    return "d04-series-gate:" + phase + ":" + binding.digest
