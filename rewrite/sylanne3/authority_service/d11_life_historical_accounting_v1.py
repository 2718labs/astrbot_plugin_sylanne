"""Installed D11 historical cost permission over independently retained originals."""
from dataclasses import dataclass, fields
import json
import sqlite3

from .contract import AuthorityUnavailable
from ..runtime.d11_life_contract_v1 import (
    D11LifeExecutionBindingV1,
    life_from_wire_v1, life_to_wire_v1, life_mutation_id_v1,
)
from .d11_offline_tick_contract_v1 import _hex, _chain, _positive, _text
from .d11_life_journal_v1 import read_life_rows_locked_v1
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire
from ..runtime_contracts import canonical_digest, canonical_serialize


@dataclass(frozen=True, slots=True)
class D11LifeHistoricalCostGrantV1:
    binding: D11LifeExecutionBindingV1
    accounting_original_ref: str
    accounting_original_digest: str
    prepared_digest: str
    claim_ref: str
    claim_digest: str
    claim_sequence: int
    terminal_ref: str
    terminal_digest: str
    terminal_sequence: int
    execution_journal_id: str
    status: str
    actual_cpu_ms: int | None
    durable_closure_digest: str
    permit: FencePermitV2
    schema: str = "d11.life-historical-cost-grant.v1"

    def __post_init__(self):
        if (self.schema != "d11.life-historical-cost-grant.v1"
                or type(self.binding) is not D11LifeExecutionBindingV1
                or type(self.permit) is not FencePermitV2 or self.permit.operation != "accounting"
                or self.permit.namespace != self.binding.authority_namespace
                or self.permit.authority_id != self.binding.authority_id
                or self.permit.subject != "d11-life:" + self.binding.installation_id
                or self.permit.operation_id != historical_accounting_operation_id_v1(self.binding)
                or self.claim_ref != life_mutation_id_v1(self.binding, "claim")
                or self.terminal_ref != life_mutation_id_v1(self.binding, "terminal")
                or self.execution_journal_id != self.permit.pinned_anchor.execution_journal_id
                or self.terminal_sequence <= self.claim_sequence
                or self.terminal_sequence > self.permit.pinned_anchor.execution_seq
                or self.status not in {"completed", "failed", "unknown"}
                or (self.status == "unknown" and self.actual_cpu_ms is not None)
                or (self.status != "unknown" and (type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0))):
            raise ValueError("exact independent life historical cost grant required")
        for value in (self.accounting_original_digest, self.prepared_digest, self.durable_closure_digest):
            _hex(value)
        for value in (self.claim_digest, self.terminal_digest):
            _chain(value)
        for value in (self.accounting_original_ref, self.claim_ref, self.terminal_ref, self.execution_journal_id):
            _text(value)
        for value in (self.claim_sequence, self.terminal_sequence):
            _positive(value)
        if self.permit.command_digest != "sha256:" + historical_accounting_command_digest_v1(self):
            raise ValueError("life accounting command does not bind its retained original")

    @property
    def digest(self):
        return canonical_digest(historical_accounting_to_wire_v1(self))


def historical_accounting_operation_id_v1(binding):
    return "d11-life-historical:" + canonical_digest(
        (binding.authority_namespace, binding.installation_id, binding.execution_id))


def historical_accounting_command_digest_v1(value):
    raw = historical_accounting_to_wire_v1(value) if type(value) is D11LifeHistoricalCostGrantV1 else dict(value)
    raw.pop("permit", None)
    raw.pop("schema", None)
    return canonical_digest(raw)


def historical_accounting_to_wire_v1(value):
    if type(value) is not D11LifeHistoricalCostGrantV1:
        raise TypeError("exact D11 historical accounting grant required")
    raw = {field.name: getattr(value, field.name) for field in fields(value)}
    raw["binding"] = life_to_wire_v1(value.binding)
    raw["permit"] = fence_to_wire(value.permit)
    return raw


def historical_accounting_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(D11LifeHistoricalCostGrantV1)}:
        raise ValueError("D11 historical accounting fields differ")
    values = dict(raw)
    values["binding"] = life_from_wire_v1(values["binding"], D11LifeExecutionBindingV1)
    values["permit"] = fence_from_wire(values["permit"])
    value = D11LifeHistoricalCostGrantV1(**values)
    if historical_accounting_to_wire_v1(value) != raw:
        raise ValueError("D11 historical accounting wire is noncanonical")
    return value


def _scope(service, binding):
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    if (type(service) is not AuthorityD11LifeServiceV1 or type(binding) is not D11LifeExecutionBindingV1
            or binding.namespace != service.namespace or binding.authority_namespace != service.bridge.namespace
            or binding.installation_id != service.installation_id):
        raise AuthorityUnavailable("life historical original crossed its installed service")
    service.bridge.core._require(service.credential, "accounting", service.bridge.namespace)


def _retained_originals(service, binding):
    """Full original authentication occurs outside the Core SQL transaction."""
    from .c09_process_identity_v1 import require_process_retired_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    with service.bridge.journal.freeze_writes():
        _, claim, terminal, _, _ = read_life_rows_locked_v1(service.bridge.journal, binding)
        if claim is None or terminal is None:
            raise AuthorityUnavailable("life claim-only work remains occupied HOLD")
        service._verify_payload(claim.payload)
        service._verify_payload(terminal.payload)
    if terminal.status == "unknown":
        process = json.loads(claim.payload.executor_incarnation)
        if canonical_serialize(process) != claim.payload.executor_incarnation:
            raise AuthorityUnavailable("life original OS birth identity bytes differ")
        require_process_retired_v1(process)
    prepared = service.read_d11_life_accounting_prepared_v1(binding)
    if prepared is None or prepared.prepared_digest != claim.payload.prepared_digest:
        raise AuthorityUnavailable("life signed content-free prepared original differs")
    return prepared, claim, terminal, canonical_digest(plain_v1(prepared))


def _storage_observation(service):
    """Observe selected physical handles before Graph/Core SQL or journal guards."""
    from .c09_storage_control_v1 import InstalledC09StorageReaderV1
    reader = getattr(service.bridge.core, "_c09_storage_reader_v1", None)
    if not isinstance(reader, InstalledC09StorageReaderV1):
        raise AuthorityUnavailable("installed life accounting storage reader unavailable")
    context = reader.read_verified_current_storage_v1()
    context.require_current("accounting")
    expected = {"core": service.bridge.core.path.resolve(), "graph": service.graph_path,
        "deletion": service.bridge.deletion.path.resolve(), "execution": service.bridge.journal.path.resolve()}
    if (context.manifest["installation_id"] != service.installation_id
            or context.manifest["authority_id"] != reader.authority_id
            or any(member["namespace"] != service.bridge.namespace
                or member["resolved_path"] != str(expected[member["role"]]) for member in context.manifest["members"])):
        raise AuthorityUnavailable("life accounting selected installed handles differ")
    return reader, context


def _storage_recheck_locked(service, db, observation, anchor):
    reader, context = observation
    if getattr(service.bridge.core, "_c09_storage_reader_v1", None) is not reader:
        raise AuthorityUnavailable("life accounting installed storage reader changed")
    with reader._db() as control:
        current = reader._current(control)
    if (current["pointer_version"], current["current_manifest_digest"], current["stage"]) != (
            context.pointer_version, context.manifest_digest, context.stage):
        raise AuthorityUnavailable("life accounting selected storage pointer changed")
    members = {member["role"]: member for member in context.manifest["members"]}
    if (context.manifest["authority_id"] != service.bridge.core._id(db)
            or members["execution"]["incarnation_or_journal_id"] != anchor.execution_journal_id
            or members["deletion"]["incarnation_or_journal_id"] != anchor.deletion_journal_id):
        raise AuthorityUnavailable("life accounting actual selected Authority/journals differ")


def _material_locked(service, db, binding, prepared, claim, terminal, prepared_digest, execution):
    head, actual_claim, actual_terminal, _, _ = read_life_rows_locked_v1(service.bridge.journal, binding)
    if head != execution or (actual_claim, actual_terminal) != (claim, terminal):
        raise AuthorityUnavailable("life retained original changed during accounting")
    claim_gate, claim_row = service._gate(db, binding, "claim")
    terminal_gate, terminal_row = service._gate(db, binding, "terminal")
    expected_claim = (claim_gate.operation_id + ":consumed", "sha256:" + canonical_digest(
        (binding.digest, claim.original_ref, claim.claim_digest)))
    expected_terminal = (terminal_gate.operation_id + ":consumed", "sha256:" + canonical_digest(
        (binding.digest, terminal.original_ref, terminal.terminal_digest)))
    if (binding.authority_id != service.bridge.core._id(db)
            or claim_row[6] != "finished" or terminal_row[6] != "finished"
            or claim_row[8:10] != expected_claim or terminal_row[8:10] != expected_terminal
            or terminal_gate.command_digest != "sha256:" + canonical_digest((binding.digest, claim.claim_digest))
            or terminal.journal_id != execution.journal_id or terminal.terminal_sequence > execution.seq):
        raise AuthorityUnavailable("life durable claim/terminal closure is not authenticated")
    return dict(binding=life_to_wire_v1(binding), accounting_original_ref=prepared.accounting_original_ref,
        accounting_original_digest=prepared_digest, prepared_digest=prepared.prepared_digest,
        claim_ref=claim.original_ref, claim_digest=claim.claim_digest, claim_sequence=claim.claim_sequence,
        terminal_ref=terminal.original_ref, terminal_digest=terminal.terminal_digest,
        terminal_sequence=terminal.terminal_sequence, execution_journal_id=terminal.journal_id,
        status=terminal.status, actual_cpu_ms=terminal.actual_cpu_ms,
        durable_closure_digest=canonical_digest((binding.digest, expected_claim, expected_terminal,
            canonical_digest(claim_gate), canonical_digest(terminal_gate))))


def operate_life_historical_accounting_v1(service, binding, action, gate=None):
    _scope(service, binding)
    if action not in {"begin", "validate", "finish", "status"}:
        raise AuthorityUnavailable("closed life historical accounting action required")
    operation_id = historical_accounting_operation_id_v1(binding)
    if action != "begin" and (type(gate) is not D11LifeHistoricalCostGrantV1 or gate.binding != binding):
        raise AuthorityUnavailable("exact life historical accounting gate required")
    # Exact finished ACK precedes new heads, worker, source and process checks.
    if action in {"finish", "status"}:
        with service.bridge.core._tx() as db:
            row = service.bridge.fences._row(db, operation_id)
            if row is None or service.bridge.fences._permit(row) != gate.permit:
                raise AuthorityUnavailable("life historical accounting original permit differs")
            if action == "status":
                if row[6] not in {"active", "finished"}:
                    raise AuthorityUnavailable("life historical accounting state differs")
                return row[6]
            if row[6] == "finished":
                if row[8:10] != (operation_id + ":finished", "sha256:" + gate.digest):
                    raise AuthorityUnavailable("life historical finish replay changed")
                return True
    storage = _storage_observation(service)
    prepared, claim, terminal, prepared_digest = _retained_originals(service, binding)
    if action == "finish":
        from ..runtime.d11_life_historical_accounting_v1 import verify_life_historical_accounting_commit_v1
        db = sqlite3.connect(service.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            verify_life_historical_accounting_commit_v1(db, gate=gate, issuer=service.issuer,
                resource_issuer=service.resource_issuer, require_current_anchor=True)
        finally:
            db.close()
    with service._frozen() as (db, deletion, execution, _):
        anchor = service.fences._current_locked(db, deletion, execution, require_clear=False)
        _storage_recheck_locked(service, db, storage, anchor)
        material = _material_locked(service, db, binding, prepared, claim, terminal, prepared_digest, execution)
        command = "sha256:" + historical_accounting_command_digest_v1(material)
        if action == "begin":
            permit = service.bridge.fences.begin_fence_locked(db, subject=service._subject,
                holder=service.bridge.core._row(db, service.bridge.namespace)[0], operation="accounting",
                current_anchor=anchor, operation_id=operation_id, command_digest=command)
            material["binding"] = binding
            return D11LifeHistoricalCostGrantV1(**material, permit=permit)
        actual = {key: value for key, value in historical_accounting_to_wire_v1(gate).items() if key not in {"permit", "schema"}}
        if actual != material or gate.permit.command_digest != command:
            raise AuthorityUnavailable("life independently authenticated accounting original changed")
        service.bridge.fences.validate_fence_locked(db, gate.permit, subject=service._subject, current_anchor=anchor)
        if action == "finish":
            service.bridge.fences.finish_fence_locked(db, gate.permit, subject=service._subject,
                current_anchor=anchor, request_id=operation_id + ":finished", request_digest="sha256:" + gate.digest)
            return True
        return gate
