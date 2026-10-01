"""Authored-root CPU execution identities, separate from joint family/job work.

These values are audit contracts only. A root claim must come from the installed
Authority after an actual reserved, current Owner root preparation is reread.
"""
from dataclasses import asdict, dataclass
from uuid import UUID

from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime.restore_anchor import RestoreAnchor

ROOT_ALGORITHM_ID_V3 = "d04.authored_root_initial_box_readout.v3"
ROOT_EXECUTION_SCHEMA_V3 = "d04.authored-root-execution-binding.v3"


@dataclass(frozen=True, slots=True)
class D04RootExecutionBindingV3:
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
    input_original_ref: str
    input_digest: str
    algorithm_id: str
    algorithm_build_digest: str
    native_manifest_sha256: str
    native_sha256: str
    output_policy_digest: str
    preset_id: str
    preset_digest: str
    candidate_digest: str
    parent_budget_lease_ref: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_operation_id: str
    reservation_digest: str
    cpu_ceiling_ms: int
    deadline_utc: str
    schema: str = ROOT_EXECUTION_SCHEMA_V3

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.schema!=ROOT_EXECUTION_SCHEMA_V3
                or self.algorithm_id!=ROOT_ALGORITHM_ID_V3):
            raise ValueError("dedicated authored-root execution identity required")
        if str(UUID(self.operation_id))!=self.operation_id or UUID(self.operation_id).version!=4:
            raise ValueError("authored-root operation must be its original UUID4")
        for name in ("activation_generation","owner_grant_revision","quote_version","cpu_ceiling_ms"):
            if type(getattr(self,name)) is not int or getattr(self,name)<1:
                raise ValueError("authored-root version/CPU ceiling must be positive")
        for name in ("owner_grant_digest","input_digest","algorithm_build_digest","native_manifest_sha256","native_sha256",
                     "output_policy_digest","preset_digest","candidate_digest","quote_digest","reservation_digest"):
            value=getattr(self,name)
            if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("authored-root digest must be exact SHA256")
        for name in ("authority_id","authority_namespace","installation_id","owner_grant_ref","execution_id",
                     "input_original_ref","preset_id","parent_budget_lease_ref","quote_id","reservation_operation_id","deadline_utc"):
            if type(getattr(self,name)) is not str or not getattr(self,name):
                raise ValueError("authored-root original identity incomplete")

    @property
    def digest(self):
        return canonical_digest(asdict(self))

    @property
    def cpu_dimension(self):
        return "thread_cpu_ms"


def _hex(value):
    if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("authored-root original digest must be SHA256")


@dataclass(frozen=True, slots=True)
class D04RootExecutionClaimV3:
    binding_digest: str
    execution_id: str
    claim_id: str
    claim_sequence: int
    executor_installation_id: str
    executor_incarnation: str
    signature: str
    schema: str = "d04.authored-root-execution-claim.v3"

    def __post_init__(self):
        _hex(self.binding_digest)
        if (self.schema!="d04.authored-root-execution-claim.v3" or type(self.claim_sequence) is not int or self.claim_sequence<1
                or any(type(value) is not str or not value for value in (self.execution_id,self.claim_id,
                    self.executor_installation_id,self.executor_incarnation,self.signature))):
            raise ValueError("authored-root claim identity differs")


@dataclass(frozen=True, slots=True)
class D04RootExecutionMeasurementV3:
    binding_digest: str
    claim_id: str
    status: str
    actual_cpu_ns: int
    artifact_digest: str | None
    initial_box_proof_digest: str | None
    output_issuance_digest: str | None
    output_write_set_digest: str | None
    failure_code: str | None
    measurement_clock: str = "thread_time_ns"
    schema: str = "d04.authored-root-execution-measurement.v3"

    def __post_init__(self):
        _hex(self.binding_digest)
        if (self.schema!="d04.authored-root-execution-measurement.v3" or self.status not in {"completed","failed"}
                or type(self.actual_cpu_ns) is not int or self.actual_cpu_ns<0 or self.measurement_clock!="thread_time_ns"
                or type(self.claim_id) is not str or not self.claim_id):
            raise ValueError("authored-root measured CPU differs")
        if self.status=="completed":
            for value in (self.artifact_digest,self.initial_box_proof_digest,self.output_issuance_digest,self.output_write_set_digest):_hex(value)
            if self.failure_code is not None:raise ValueError("completed root math cannot claim failure")
        elif not self.failure_code:
            raise ValueError("failed root math requires an actual bounded failure code")

    @property
    def actual_cpu_ms(self):return (self.actual_cpu_ns+999_999)//1_000_000


@dataclass(frozen=True, slots=True)
class D04RootExecutionTerminalV3:
    binding: D04RootExecutionBindingV3
    claim: D04RootExecutionClaimV3
    measurement: D04RootExecutionMeasurementV3
    terminal_ref: str
    terminal_sequence: int
    journal_head_digest: str
    signature: str
    schema: str = "d04.authored-root-execution-terminal.v3"

    def __post_init__(self):
        if (type(self.binding) is not D04RootExecutionBindingV3 or type(self.claim) is not D04RootExecutionClaimV3
                or type(self.measurement) is not D04RootExecutionMeasurementV3
                or self.schema!="d04.authored-root-execution-terminal.v3"
                or self.claim.binding_digest!=self.binding.digest or self.measurement.binding_digest!=self.binding.digest
                or self.claim.execution_id!=self.binding.execution_id or self.claim.executor_installation_id!=self.binding.installation_id
                or self.measurement.claim_id!=self.claim.claim_id or type(self.terminal_sequence) is not int
                or self.terminal_sequence<=self.claim.claim_sequence or not self.terminal_ref or not self.signature):
            raise ValueError("authored-root terminal identities differ")
        _hex(self.journal_head_digest)

    @property
    def digest(self):return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04RootMeasuredCostClosureV3:
    """Measured execution cost only; never a restored/adoptable root result."""
    binding: D04RootExecutionBindingV3
    claim: D04RootExecutionClaimV3
    measurement: D04RootExecutionMeasurementV3
    artifact_disposition: str
    barrier_basis_digest: str
    current_anchor: RestoreAnchor
    closure_ref: str
    terminal_sequence: int
    journal_head_digest: str
    signature: str
    adoption_allowed: bool = False
    schema: str = "d04.authored-root-measured-cost-closure.v3"

    def __post_init__(self):
        if (type(self.binding) is not D04RootExecutionBindingV3 or type(self.claim) is not D04RootExecutionClaimV3
                or type(self.measurement) is not D04RootExecutionMeasurementV3 or type(self.current_anchor) is not RestoreAnchor
                or self.claim.binding_digest!=self.binding.digest or self.measurement.binding_digest!=self.binding.digest
                or self.measurement.claim_id!=self.claim.claim_id or self.measurement.status!="completed"
                or self.artifact_disposition not in {"withheld_by_current_barrier","missing_after_crash"}
                or self.adoption_allowed is not False or self.schema!="d04.authored-root-measured-cost-closure.v3"
                or type(self.terminal_sequence) is not int or self.terminal_sequence<=self.claim.claim_sequence
                or not self.closure_ref or not self.signature):
            raise ValueError("root measured-cost closure identity differs")
        _hex(self.barrier_basis_digest);_hex(self.journal_head_digest)

    @property
    def digest(self):
        return canonical_digest(asdict(self))

    @property
    def terminal_ref(self):
        return self.closure_ref


def root_execution_to_wire_v3(value):
    from ..runtime_contracts import canonical_serialize
    import json
    if type(value) not in {D04RootExecutionBindingV3,D04RootExecutionClaimV3,D04RootExecutionMeasurementV3,D04RootExecutionTerminalV3,D04RootMeasuredCostClosureV3}:
        raise TypeError("typed authored-root execution original required")
    return json.loads(canonical_serialize(asdict(value)))


def root_execution_from_wire_v3(raw,kind):
    if kind not in {D04RootExecutionBindingV3,D04RootExecutionClaimV3,D04RootExecutionMeasurementV3,D04RootExecutionTerminalV3,D04RootMeasuredCostClosureV3} or type(raw) is not dict or set(raw)!=set(kind.__dataclass_fields__):
        raise ValueError("authored-root original wire fields differ")
    value=dict(raw)
    if kind is D04RootExecutionBindingV3:value["namespace"]=NamespaceId(**value["namespace"])
    if kind in {D04RootExecutionTerminalV3,D04RootMeasuredCostClosureV3}:
        value["binding"]=root_execution_from_wire_v3(value["binding"],D04RootExecutionBindingV3)
        value["claim"]=root_execution_from_wire_v3(value["claim"],D04RootExecutionClaimV3)
        value["measurement"]=root_execution_from_wire_v3(value["measurement"],D04RootExecutionMeasurementV3)
    if kind is D04RootMeasuredCostClosureV3:value["current_anchor"]=RestoreAnchor(**value["current_anchor"])
    result=kind(**value)
    if root_execution_to_wire_v3(result)!=raw:raise ValueError("noncanonical authored-root original")
    return result
