"""Independent D04 numeric CPU originals and accounting transaction helpers.

W01 freezes quote/job before Authority claim. The installed runner measures the
same synchronous thread across full ABI2, every LOO and output certification.
An Authority durable terminal is mandatory before importing actual CPU. A
claim without terminal is unknown, and this module never reissues execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import threading
from time import thread_time_ns

from ..authority_service.d04_numeric_contract_v3 import (
    D04NumericBindingV3, D04NumericClaimV3, D04NumericMeasurementV3,
    D04NumericTerminalV3, WORK_KIND, to_wire, from_wire,
)
from ..graph_types import GraphWrite
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .budget import reserve_budget, settle_budget, get_budget_lease
from .d11_types import job_graph_write, cost_settlement_from_runtime, cost_settlement_graph_write
from .jobs import create_job, get_job, checkpoint_job, transition_job
from .d04_appraisal_driver_v3 import record_d04_original_in_transaction_v3, read_d04_original_v3
from .d04_semantic_mapping_v3 import evidence_payload_v3


@dataclass(frozen=True, slots=True)
class D04NumericPreparedV3:
    binding: D04NumericBindingV3
    input_payload_json: str
    quote_payload_json: str
    reserve_receipt_json: str
    job_payload_json: str
    original_ref: str
    schema: str = "d04.numeric_prepared_original.v3"

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04NumericStageV3:
    prepared: D04NumericPreparedV3
    writes: tuple[GraphWrite, ...]


@dataclass(frozen=True, slots=True)
class D04NumericCostOriginalV3:
    namespace: NamespaceId
    operation_id: str
    prepared_digest: str
    binding_digest: str
    terminal_ref: str
    terminal_digest: str
    status: str
    actual_cpu_ns: int
    actual_cpu_ms: int
    budget_receipt_json: str
    cost_write_json: str
    schema: str = "d04.numeric_paid_original.v3"

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def stage_d04_numeric_in_transaction_v3(
    db, *, binding: D04NumericBindingV3, input_payload, quote, job, resource_issuer,
) -> D04NumericStageV3:
    """Freeze a current W01 request/ABI2 input, sign quote, reserve and create job."""
    if not db.in_transaction or type(binding) is not D04NumericBindingV3:
        raise ValueError("D04 numeric preparation requires caller-owned Owner fence")
    wire = canonical_serialize(evidence_payload_v3(input_payload))
    frozen_data = json.loads(wire)
    if (not {"read_rows", "installed_identity", "mapping_original_refs", "numeric_request", "evidence_inputs"} <= frozen_data.keys()
            or not frozen_data["read_rows"] or not frozen_data["mapping_original_refs"]):
        raise ValueError("D04 numeric frozen current/semantic/installed/ABI recipe incomplete")
    if (canonical_digest(json.loads(wire)) != binding.input_digest
            or quote.work_kind != WORK_KIND or job.work_kind != WORK_KIND
            or quote.quote_id != binding.quote_id or quote.version != binding.quote_version
            or canonical_digest(quote) != binding.quote_digest
            or dict(quote.ceiling) != {"cpu_ms": binding.cpu_ceiling_ms}
            or quote.operation_id != binding.operation_id or job.operation_id != binding.operation_id
            or job.job_id != binding.job_id or job.activity_id != binding.activity_id
            or (quote.bot_id, quote.persona_id) != binding.namespace.as_tuple
            or (job.bot_id, job.persona_id) != binding.namespace.as_tuple
            or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref
            or job.budget_ref != binding.parent_budget_lease_ref
            or quote.graph_job_ref != job_graph_write(job).key.token
            or job.phase != "queued" or job.fence != 0 or job.cancel_epoch
            or job.effect_id is not None or quote.effect_id is not None
            or quote.required_worker_fence is not None):
        raise ValueError("D04 numeric signed quote/job/input differs from binding")
    prior = read_d04_numeric_prepared_v3(db, binding.namespace, binding.operation_id)
    if prior is not None:
        if prior.binding != binding or prior.input_payload_json != wire:
            raise ValueError("D04 numeric operation conflicts with original")
        return D04NumericStageV3(prior, ())
    resource_issuer.issue_quote(db, quote)
    original_quote = resource_issuer.original_signed_quote(db, quote.quote_id, quote.version)
    if original_quote != quote:
        raise ValueError("D04 signed numeric quote differs")
    reservation = reserve_budget(db, binding.parent_budget_lease_ref,
        binding.reservation_operation_id, binding.reservation_digest, quote.ceiling)
    persisted = create_job(db, job, binding.operation_id, binding.digest)
    receipt_row = db.execute("SELECT receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if receipt_row is None or reservation.status != "reserved":
        raise ValueError("D04 numeric reserve receipt missing")
    prepared = D04NumericPreparedV3(binding, wire, canonical_serialize(quote),
        receipt_row[0], canonical_serialize(asdict(persisted)), binding.input_original_ref)
    record_d04_original_in_transaction_v3(db, binding.namespace, "numeric_prepared",
        binding.operation_id, asdict(prepared))
    return D04NumericStageV3(prepared, (job_graph_write(persisted),))


def read_d04_numeric_prepared_v3(db, namespace, operation_id):
    row = read_d04_original_v3(db, namespace, "numeric_prepared", operation_id)
    if row is None:
        return None
    raw = row[0]
    value = D04NumericPreparedV3(**{**raw, "binding": from_wire(raw["binding"], D04NumericBindingV3)})
    if (value.binding.namespace != namespace or value.binding.operation_id != operation_id
            or value.digest != row[1]
            or canonical_digest(json.loads(value.input_payload_json)) != value.binding.input_digest):
        raise ValueError("D04 immutable numeric preparation changed")
    return value


def record_d04_numeric_claim_in_transaction_v3(db, prepared, claim):
    if (not db.in_transaction or type(claim) is not D04NumericClaimV3
            or claim.binding_digest != prepared.binding.digest
            or claim.execution_id != prepared.binding.execution_id):
        raise ValueError("D04 Authority claim differs from original preparation")
    return record_d04_original_in_transaction_v3(db, prepared.binding.namespace,
        "numeric_claim", prepared.binding.operation_id, to_wire(claim))


def measure_installed_d04_numeric_v3(prepared, claim, execute_installed):
    """Invoke the fixed installed full+all LOO+output synchronously exactly once.

    This is invoked only after the installed Authority grants a *new* claim;
    a returned historical claim never authorizes this function again. The
    credential-owning caller must durably record its returned measurement with
    Authority before W01 is asked to settle it. Exceptions still incur CPU.
    """
    if (type(prepared) is not D04NumericPreparedV3 or type(claim) is not D04NumericClaimV3
            or claim.binding_digest != prepared.binding.digest or not callable(execute_installed)):
        raise ValueError("installed D04 execution and original Authority claim required")
    owner_thread = threading.get_ident()
    start = thread_time_ns()
    result = None
    error = None
    try:
        from ..native_runtime.d04_fixed_trajectory_v2 import bounded_d04_native_cpu_v2
        with bounded_d04_native_cpu_v2(prepared.binding.cpu_ceiling_ms):
            result = execute_installed(prepared)
        # An awaitable/thread pool return would attribute another thread's CPU
        # to this execution, so the installed contract is strictly synchronous.
        from .d04_joint_product_assembly_v3 import D04InstalledJointProductV3
        if type(result) is not D04InstalledJointProductV3 or threading.get_ident() != owner_thread:
            raise ValueError("installed D04 execution did not return synchronous product")
        candidate, output = result.replay.candidate, result.output
        binding = prepared.binding
        if ((candidate.native_manifest_sha256, candidate.native_sha256) !=
                (binding.native_manifest_sha256, binding.native_sha256)
                or output.policy_digest != binding.output_policy_digest
                or tuple(f for f, _ in candidate.family_transcripts) != binding.family_roots
                or output.full_transcript_sha256 != candidate.full_transcript_sha256
                or output.family_transcripts != candidate.family_transcripts):
            raise ValueError("D04 actual installed output/native/families differ")
    except Exception as exc:
        error = exc
    elapsed = thread_time_ns() - start
    measurement = D04NumericMeasurementV3(prepared.binding.digest, claim.claim_id,
        "completed" if error is None else "failed", elapsed,
        result.replay.candidate.full_transcript_sha256 if error is None else None,
        result.replay.candidate.family_transcripts if error is None else (),
        result.output.original_digest if error is None else None,
        None if error is None else type(error).__name__)
    return result if error is None else None, measurement, error


def numeric_cost_operation_v3(namespace, operation_id):
    return "d04-numeric-cost:" + canonical_digest((namespace, operation_id))[:48]


def settle_d04_numeric_terminal_in_transaction_v3(
    db, prepared, *, terminal: D04NumericTerminalV3,
    authority_original: D04NumericTerminalV3, resource_issuer,
    holder: str, fence: int,
):
    """Import paired Authority reread and D11 CPU settlement in the W01 fence.

    authority_original must be fetched from the installation-owned Authority
    port outside this transaction. No candidate signature is verified locally
    as a substitute. W01 commits the returned cost/job writes in this txn.
    """
    if (not db.in_transaction or type(terminal) is not D04NumericTerminalV3
            or type(authority_original) is not D04NumericTerminalV3 or authority_original != terminal
            or terminal.binding != prepared.binding):
        raise ValueError("D04 paired Authority numeric terminal original differs")
    binding = prepared.binding
    current = read_d04_numeric_prepared_v3(db, binding.namespace, binding.operation_id)
    if current != prepared:
        raise ValueError("D04 numeric preparation original changed")
    quote = resource_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    if (canonical_digest(quote) != binding.quote_digest or quote.work_kind != WORK_KIND
            or dict(quote.ceiling) != {"cpu_ms": binding.cpu_ceiling_ms}
            or quote.operation_id != binding.operation_id
            or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref):
        raise ValueError("D04 signed numeric accounting quote changed")
    prior = read_d04_original_v3(db, binding.namespace, "numeric_cost", binding.operation_id)
    if prior is not None:
        if prior[0]["terminal_digest"] != terminal.digest:
            raise ValueError("D04 numeric terminal conflicts with paid original")
        return prior[0], ()
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    if (lease.bot_id, lease.persona_id) != binding.namespace.as_tuple:
        raise ValueError("D04 numeric budget namespace differs")
    reserve = db.execute("SELECT receipt_json,digest FROM runtime_budget_operations WHERE bot_id=? "
        "AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if reserve != (prepared.reserve_receipt_json, binding.reservation_digest):
        raise ValueError("D04 numeric original reserve receipt changed")
    job = get_job(db, binding.job_id)
    if (job.phase != "running" or job.fence != fence or job.lease_holder != holder
            or job.operation_id != binding.operation_id or job.work_kind != WORK_KIND):
        raise ValueError("D04 numeric worker changed")
    record_d04_original_in_transaction_v3(db, binding.namespace, "numeric_terminal",
        binding.operation_id, to_wire(terminal))
    receipt = settle_budget(db, binding.parent_budget_lease_ref, binding.reservation_operation_id,
        binding.reservation_digest, {"cpu_ms": terminal.measurement.actual_cpu_ms}, execution_revoked=True)
    if receipt.status not in {"settled", "overrun"}:
        raise ValueError("D04 numeric terminal is not fully accounted")
    cost_operation = numeric_cost_operation_v3(binding.namespace, binding.operation_id)
    cost_value = cost_settlement_from_runtime(db, bot_id=binding.namespace.bot_id,
        persona_id=binding.namespace.persona_id, activity_id=binding.activity_id,
        bundle_operation_id=binding.operation_id, effect_id=None, settlement_id=cost_operation,
        lease_id=binding.parent_budget_lease_ref, cost_operation_id=binding.reservation_operation_id,
        budget_operation_id=binding.reservation_operation_id, budget_phase="settle",
        prior_unknown_ref=None, execution_revoked=True)
    cost_write = cost_settlement_graph_write(cost_value)
    checkpoint_job(db, binding.job_id, holder, fence, continuation=job.continuation,
                   usage={"cpu_ms": terminal.measurement.actual_cpu_ms})
    finished = transition_job(db, binding.job_id, holder, fence,
        target_phase="completed" if terminal.measurement.status == "completed" else "failed",
        result_ref="d04-numeric-terminal:" + binding.digest[:48])
    original = D04NumericCostOriginalV3(binding.namespace, binding.operation_id,
        prepared.digest, binding.digest, terminal.terminal_ref, terminal.digest,
        terminal.measurement.status, terminal.measurement.actual_cpu_ns, terminal.measurement.actual_cpu_ms,
        canonical_serialize(asdict(receipt)), canonical_serialize(asdict(cost_write)))
    record_d04_original_in_transaction_v3(db, binding.namespace, "numeric_cost",
        binding.operation_id, asdict(original))
    return original, (cost_write, job_graph_write(finished))


def read_d04_numeric_cost_original_v3(db, namespace, operation_id):
    row = read_d04_original_v3(db, namespace, "numeric_cost", operation_id)
    if row is None:
        return None
    from ..runtime_contracts import NamespaceId
    value = D04NumericCostOriginalV3(**{**row[0], "namespace": NamespaceId(**row[0]["namespace"])})
    if value.digest != row[1] or value.namespace != namespace or value.operation_id != operation_id:
        raise ValueError("D04 numeric paid original changed")
    return value


def build_d04_numeric_input_payload_v3(preparation, evidence_inputs, *,
    installation_id, owner_grant_ref, owner_grant_revision, owner_grant_digest,
    algorithm_id, algorithm_build_digest, native_manifest_sha256, native_sha256,
    output_policy_digest, max_iterations, tolerance,
):
    """Build the actual frozen installed recipe, with current source rows.

    Actual loaded ABI2 matrices/quantized drives are deterministically produced
    by the pinned algorithm and recorded by the evidence builder after its
    paid run. No numerical integration occurs during prepare.
    """
    current = preparation.current
    if (evidence_inputs.component_digest != current.component.candidate_digest
            or evidence_inputs.member_refs != current.component.checkpoint_refs
            or type(max_iterations) is not int or max_iterations < 1
            or type(tolerance) is not float or tolerance <= 0):
        raise ValueError("D04 numeric request/current evidence differs")
    mappings = tuple(sorted({drive.mapping_compiler_ref for drive in current.drives}))
    payload = {"schema": "d04.numeric-frozen-work-input.v3",
        "read_rows": [asdict(row) for row in evidence_inputs.read_rows],
        "installed_identity": {"installation_id": installation_id,
            "owner_grant_ref": owner_grant_ref, "owner_grant_revision": owner_grant_revision,
            "owner_grant_digest": owner_grant_digest, "algorithm_id": algorithm_id,
            "algorithm_build_digest": algorithm_build_digest,
            "native_manifest_sha256": native_manifest_sha256, "native_sha256": native_sha256,
            "output_policy_digest": output_policy_digest},
        "mapping_original_refs": mappings,
        "numeric_request": {"component": current.component,
            "checkpoints": current.checkpoints, "drives": current.drives, "families": current.families,
            "predecessors": preparation.predecessors, "max_iterations": max_iterations,
            "tolerance": tolerance, "clock": evidence_inputs.clock},
        "evidence_inputs": asdict(evidence_inputs)}
    canonical = evidence_payload_v3(payload)
    return canonical, canonical_digest(canonical)


def record_installed_d04_numeric_measurement_in_transaction_v3(db, prepared, claim, measurement):
    """Installed executor's durable observer receipt, independent of CPU settlement."""
    if (not db.in_transaction or type(measurement) is not D04NumericMeasurementV3
            or measurement.binding_digest != prepared.binding.digest
            or measurement.claim_id != claim.claim_id or claim.binding_digest != prepared.binding.digest):
        raise ValueError("D04 installed numeric measurement identity differs")
    saved = read_d04_original_v3(db, prepared.binding.namespace, "numeric_claim", prepared.binding.operation_id)
    if saved is None or saved[0] != to_wire(claim):
        raise ValueError("D04 installed measurement has no durable original Authority claim")
    return record_d04_original_in_transaction_v3(db, prepared.binding.namespace,
        "numeric_measurement", prepared.binding.operation_id, {"binding": to_wire(prepared.binding),
            "claim": to_wire(claim), "measurement": to_wire(measurement)})


def read_installed_d04_numeric_measurement_original_v3(db, binding, claim):
    """Concrete trusted measurement reader for the installed Authority service."""
    if not db.in_transaction:
        raise ValueError("D04 executor measurement requires pinned current read")
    saved = read_d04_original_v3(db, binding.namespace, "numeric_measurement", binding.operation_id)
    if saved is None:
        return None
    raw, _digest = saved
    if raw["binding"] != to_wire(binding) or raw["claim"] != to_wire(claim):
        raise ValueError("D04 installed measured execution identity differs")
    return from_wire(raw["measurement"], D04NumericMeasurementV3)
