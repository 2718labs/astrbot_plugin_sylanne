"""Installed, content-free accounting of the original C04 execution.

The accounting grant serializes an existing bill. It cannot authorize content
reads, another execution, a body reservation, or experience adoption.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, JournalHead, identifier
from .internal_work_contract import InternalWorkBindingV1, InternalWorkTerminalProofV1
from .internal_work_rpc_wire import from_wire as work_from_wire, to_wire as work_to_wire
from .internal_work_service import AuthorityInternalWorkService
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire


@dataclass(frozen=True, slots=True)
class HistoricalInternalCostRequestV1:
    operation_id: str
    binding: InternalWorkBindingV1
    expected_anchor: RestoreAnchor
    schema: str = "sylanne3.authority.internal-accounting-request.v1"

    def __post_init__(self):
        identifier(self.operation_id, "operation_id")
        if (type(self.binding) is not InternalWorkBindingV1
                or type(self.expected_anchor) is not RestoreAnchor
                or self.binding.namespace != self.expected_anchor.namespace
                or self.operation_id == self.binding.operation_id
                or self.schema != "sylanne3.authority.internal-accounting-request.v1"):
            raise ValueError("original internal accounting identity differs")


@dataclass(frozen=True, slots=True)
class HistoricalInternalCostEvidenceV1:
    installation_id: str
    binding: InternalWorkBindingV1
    proof_digest: str
    claim_receipt_ref: str
    claim_receipt_digest: str
    terminal_receipt_ref: str
    terminal_receipt_digest: str
    terminal_sequence: int
    original_journal_head: JournalHead
    status: str
    actual_cpu_ms: int
    component_completed: bool
    component_receipt_ref: str | None
    component_receipt_digest: str | None
    projection_digest: str
    schema: str = "sylanne3.authority.internal-cost-evidence.v1"

    def __post_init__(self):
        identifier(self.installation_id, "installation_id")
        if (type(self.binding) is not InternalWorkBindingV1
                or self.status not in {"completed", "failed"}
                or type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0
                or type(self.component_completed) is not bool
                or self.component_completed != (self.status == "completed")
                or type(self.terminal_sequence) is not int or self.terminal_sequence < 2
                or type(self.original_journal_head) is not JournalHead
                or self.original_journal_head.seq < self.terminal_sequence
                or self.schema != "sylanne3.authority.internal-cost-evidence.v1"):
            raise ValueError("historical measured execution evidence differs")
        for name in ("proof_digest", "claim_receipt_digest", "terminal_receipt_digest", "projection_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("historical execution digest differs")
        for name in ("claim_receipt_ref", "terminal_receipt_ref"):
            identifier(getattr(self, name), name)
        if self.component_completed:
            if (self.component_receipt_ref != "internal-work:component:" + self.binding.binding_digest
                    or type(self.component_receipt_digest) is not str or len(self.component_receipt_digest) != 64):
                raise ValueError("historical completed component identity differs")
        elif self.component_receipt_ref is not None or self.component_receipt_digest is not None:
            raise ValueError("failed execution cannot claim a completed body component")

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class HistoricalInternalCostGrantV1:
    permit: FencePermitV2
    evidence: HistoricalInternalCostEvidenceV1
    schema: str = "sylanne3.authority.internal-accounting-grant.v1"

    def __post_init__(self):
        if (type(self.permit) is not FencePermitV2 or self.permit.operation != "accounting"
                or type(self.evidence) is not HistoricalInternalCostEvidenceV1
                or self.permit.namespace != self.evidence.binding.namespace
                or self.schema != "sylanne3.authority.internal-accounting-grant.v1"):
            raise ValueError("historical accounting permit differs")


def _shape(value, kind):
    if type(value) is not dict or set(value) != {f.name for f in fields(kind)}:
        raise ValueError("internal accounting wire shape differs")
    return dict(value)


def to_wire(value):
    if type(value) is HistoricalInternalCostRequestV1:
        return {**asdict(value), "binding": work_to_wire(value.binding)}
    if type(value) is HistoricalInternalCostEvidenceV1:
        return {**asdict(value), "binding": work_to_wire(value.binding)}
    if type(value) is HistoricalInternalCostGrantV1:
        return {"permit": fence_to_wire(value.permit), "evidence": to_wire(value.evidence), "schema": value.schema}
    raise ValueError("unsupported internal accounting wire")


def from_wire(value, kind):
    raw = _shape(value, kind)
    if kind is HistoricalInternalCostRequestV1:
        raw["binding"] = work_from_wire(raw["binding"], InternalWorkBindingV1)
        raw["expected_anchor"] = RestoreAnchor(**_shape(raw["expected_anchor"], RestoreAnchor))
    elif kind is HistoricalInternalCostEvidenceV1:
        raw["binding"] = work_from_wire(raw["binding"], InternalWorkBindingV1)
        raw["original_journal_head"] = JournalHead(**_shape(raw["original_journal_head"], JournalHead))
    elif kind is HistoricalInternalCostGrantV1:
        raw["permit"] = fence_from_wire(raw["permit"])
        raw["evidence"] = from_wire(raw["evidence"], HistoricalInternalCostEvidenceV1)
    else:
        raise ValueError("unsupported internal accounting kind")
    return kind(**raw)


class InstalledHistoricalInternalAccountingServiceV1:
    def __init__(self, *, accounting, internal_work, installation_id):
        from .v2_accounting_service import AuthorityV2AccountingMaintenanceService
        if (type(accounting) is not AuthorityV2AccountingMaintenanceService
                or type(internal_work) is not AuthorityInternalWorkService
                or not internal_work.installed_runtime_verified
                or internal_work.journal is not accounting._fences.execution):
            raise AuthorityUnavailable("one installed internal accounting Authority required")
        identifier(installation_id, "installation_id")
        self.accounting, self.internal_work, self.installation_id = accounting, internal_work, installation_id

    def _evidence(self, binding):
        observed = self.internal_work.inspect(binding)
        if (observed.claim_append is None or observed.terminal_append is None
                or observed.terminal is None or observed.terminal.status not in {"completed", "failed"}):
            raise AuthorityUnavailable("claim-only internal execution remains unknown and occupied")
        proof = InternalWorkTerminalProofV1(binding, observed.claim, observed.terminal,
            observed.claim_append.receipt_ref, observed.claim_append.content_digest,
            observed.terminal_append.receipt_ref, observed.terminal_append.content_digest,
            JournalHead(self.internal_work.journal.journal_id, observed.terminal_append.sequence,
                        observed.terminal_append.chain_digest))
        verified = self.internal_work.verify_original_internal_work_terminal(proof)
        if (not self.internal_work.verify_installed_terminal(binding, proof.claim, proof.terminal)
                or verified.component_completed != (verified.status == "completed")):
            raise AuthorityUnavailable("original measured terminal is not installed-authenticated")
        projection = canonical_digest({"schema": "internal-cost-projection.v1",
            "original_proof_digest": verified.proof_digest, "installation_id": self.installation_id,
            "binding_digest": binding.binding_digest, "terminal_digest": proof.terminal_receipt_digest,
            "actual_cpu_ms": verified.actual_cpu_ms, "component_completed": verified.component_completed})
        return HistoricalInternalCostEvidenceV1(self.installation_id, binding, verified.proof_digest,
            proof.claim_receipt_ref, proof.claim_receipt_digest, proof.terminal_receipt_ref,
            proof.terminal_receipt_digest, verified.terminal_sequence, proof.journal_head,
            verified.status, verified.actual_cpu_ms, verified.component_completed,
            proof.terminal.component_receipt_ref if verified.component_completed else None,
            proof.terminal.component_receipt_digest if verified.component_completed else None, projection)

    def operate(self, *, credential, request, action, grant=None):
        if type(request) is not HistoricalInternalCostRequestV1 or action not in {"begin", "validate", "finish", "recover_finish"}:
            raise AuthorityUnavailable("typed installed internal accounting request required")
        a, f = self.accounting, self.accounting._fences
        f.core._require(credential, "accounting", f.namespace, a._holder)
        if request.binding.namespace != f.namespace:
            raise AuthorityUnavailable("historical execution namespace differs")
        if action in {"finish", "recover_finish"}:
            # A lost finish ACK is queryable after later journal appends. No
            # current content or accounting grant is issued on this branch.
            with f.core._tx() as db:
                f.core.require_current_storage_generation_locked(db, namespace=f.namespace, action="accounting")
                row = f.fences._row(db, request.operation_id)
                if row is not None and row[6] == "finished":
                    permit = f.fences._permit(row)
                    finish_id = "internal-accounting-finish:" + request.operation_id
                    finish_digest = "sha256:" + canonical_digest({"request": to_wire(request), "token": permit.token})
                    if (permit.subject != a._subject or permit.operation != "accounting"
                            or permit.pinned_anchor != request.expected_anchor
                            or row[8:10] != (finish_id, finish_digest)):
                        raise AuthorityUnavailable("historical accounting finish recovery differs")
                    return True
        # Independent execution rereads occur before the final Authority txn.
        evidence = self._evidence(request.binding)
        command_digest = "sha256:" + canonical_digest({"request": to_wire(request), "evidence": to_wire(evidence)})
        with f._frozen() as (db, deletion_head, execution_head, _history):
            a._require_closed_deletion_history()
            anchor = f._current_locked(db, deletion_head, execution_head, holder=a._holder,
                                       generation=request.expected_anchor.activation_generation)
            f.core.require_current_storage_generation_locked(db, namespace=f.namespace, action="accounting")
            if (anchor != request.expected_anchor
                    or execution_head.journal_id != evidence.original_journal_head.journal_id
                    or execution_head.seq < evidence.original_journal_head.seq):
                raise AuthorityUnavailable("internal accounting head changed before fence")
            if action == "begin":
                permit = f.fences.begin_fence_locked(db, subject=a._subject, holder=a._holder,
                    operation="accounting", current_anchor=anchor, operation_id=request.operation_id,
                    command_digest=command_digest)
                return HistoricalInternalCostGrantV1(permit, evidence)
            row = f.fences._row(db, request.operation_id)
            if row is None:
                raise AuthorityUnavailable("original internal accounting fence absent")
            permit = f.fences._permit(row)
            expected_grant = HistoricalInternalCostGrantV1(permit, evidence)
            if (permit.operation != "accounting" or permit.command_digest != command_digest
                    or permit.pinned_anchor != anchor or permit.subject != a._subject
                    or (action != "recover_finish" and grant != expected_grant)):
                raise AuthorityUnavailable("original internal accounting grant changed")
            finish_id = "internal-accounting-finish:" + request.operation_id
            finish_digest = "sha256:" + canonical_digest({"request": to_wire(request), "token": permit.token})
            if row[6] == "finished":
                if action not in {"finish", "recover_finish"} or row[8:10] != (finish_id, finish_digest):
                    raise AuthorityUnavailable("historical accounting finish replay differs")
                return True
            f.fences.validate_fence_locked(db, permit, subject=a._subject, current_anchor=anchor)
            if action in {"finish", "recover_finish"}:
                f.fences.finish_fence_locked(db, permit, subject=a._subject, current_anchor=anchor,
                    request_id=finish_id, request_digest=finish_digest)
            return True
