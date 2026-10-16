"""Exact own-execution continuation for an independently completed clock tick.

The wire value is evidence, not an admission. Only the concrete installed
service can reread its journal, current Owner, and frozen Graph to issue it.
"""
from dataclasses import asdict, dataclass, fields
import json
import sqlite3

from .contract import AuthorityUnavailable
from .d11_offline_tick_contract_v1 import (
    D11OfflineTickBindingV1, D11OfflineTickTerminalV1,
    offline_tick_from_wire_v1, offline_tick_to_wire_v1,
)
from .d11_offline_tick_journal_v1 import read_offline_tick_rows_locked_v1
from .d12_target_owner_admission_v1 import (
    D12CurrentOwnerAuthorityV1, current_owner_authority_from_wire_v1,
    current_owner_authority_to_wire_v1,
)
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest, canonical_serialize, SnapshotRequirementsV2


_LOCATION_FIELDS = ("authority_id", "namespace", "activation_generation", "revocation_epoch",
    "deletion_journal_id", "deletion_seq", "deletion_digest", "execution_journal_id")
_ANCHOR_FIELDS = (*_LOCATION_FIELDS, "execution_seq", "execution_digest")


def _same_location(before, after):
    return all(getattr(before, name) == getattr(after, name) for name in _LOCATION_FIELDS)


def _requirements_match(requirements, anchor):
    return (requirements.authority_namespace == anchor.namespace
        and all(getattr(requirements, name) == getattr(anchor, name)
            for name in _ANCHOR_FIELDS if name != "namespace"))


@dataclass(frozen=True, slots=True)
class D11OfflineTickAdoptionBridgeV1:
    binding: D11OfflineTickBindingV1
    terminal: D11OfflineTickTerminalV1
    owner_authority: D12CurrentOwnerAuthorityV1
    owner_actor_id: str
    prepared_digest: str
    before_requirements_json: str
    before_graph_revision: int
    before_graph_epoch: int
    before_anchor: RestoreAnchor
    after_anchor: RestoreAnchor
    permit: FencePermitV2
    qualification_digest: str
    schema: str = "d11.offline-tick-adoption-bridge.v1"

    def __post_init__(self):
        from ..runtime.d10_offline_tick_execution_v1 import _decode_json
        if (self.schema != "d11.offline-tick-adoption-bridge.v1"
                or type(self.binding) is not D11OfflineTickBindingV1
                or type(self.terminal) is not D11OfflineTickTerminalV1
                or self.terminal.binding != self.binding
                or type(self.owner_authority) is not D12CurrentOwnerAuthorityV1
                or type(self.owner_actor_id) is not str or not self.owner_actor_id
                or type(self.before_anchor) is not RestoreAnchor or type(self.after_anchor) is not RestoreAnchor
                or type(self.permit) is not FencePermitV2 or self.permit.operation != "write"
                or self.permit.pinned_anchor != self.after_anchor
                or self.permit.namespace != self.binding.authority_namespace
                or self.permit.authority_id != self.binding.authority_id
                or self.permit.generation != self.binding.activation_generation
                or self.owner_authority.guard.namespace != self.binding.namespace
                or not _same_location(self.before_anchor, self.after_anchor)
                or self.terminal.claim.claim_sequence != self.before_anchor.execution_seq + 1
                or self.terminal.terminal_sequence != self.terminal.claim.claim_sequence + 1
                or self.after_anchor.execution_seq != self.terminal.terminal_sequence
                or self.after_anchor.execution_digest != self.terminal.terminal_digest
                or self.terminal.journal_id != self.after_anchor.execution_journal_id
                or self.prepared_digest != self.terminal.payload.prepared_digest
                or any(type(value) is not int or value < 0 for value in
                    (self.before_graph_revision, self.before_graph_epoch))):
            raise ValueError("offline bridge is not its exact own claim/terminal transition")
        requirements = _decode_json(self.before_requirements_json, SnapshotRequirementsV2)
        if requirements.namespace != self.binding.namespace or not _requirements_match(requirements, self.before_anchor):
            raise ValueError("offline bridge frozen requirements differ from original claim anchor")
        if self.qualification_digest != bridge_digest_v1(self):
            raise ValueError("offline bridge qualification commitment differs")


def offline_bridge_to_wire_v1(value):
    if type(value) is not D11OfflineTickAdoptionBridgeV1:
        raise TypeError("exact offline bridge required")
    raw = asdict(value)
    raw["binding"] = offline_tick_to_wire_v1(value.binding)
    raw["terminal"] = offline_tick_to_wire_v1(value.terminal)
    raw["owner_authority"] = current_owner_authority_to_wire_v1(value.owner_authority)
    raw["permit"] = fence_to_wire(value.permit)
    return raw


def bridge_digest_v1(value):
    raw = offline_bridge_to_wire_v1(value)
    del raw["qualification_digest"]
    return canonical_digest(raw)


def offline_bridge_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(D11OfflineTickAdoptionBridgeV1)}:
        raise ValueError("offline bridge wire fields differ")
    values = dict(raw)
    values["binding"] = offline_tick_from_wire_v1(values["binding"], D11OfflineTickBindingV1)
    values["terminal"] = offline_tick_from_wire_v1(values["terminal"], D11OfflineTickTerminalV1)
    values["owner_authority"] = current_owner_authority_from_wire_v1(values["owner_authority"])
    values["permit"] = fence_from_wire(values["permit"])
    for name in ("before_anchor", "after_anchor"):
        values[name] = RestoreAnchor(**values[name])
    value = D11OfflineTickAdoptionBridgeV1(**values)
    if offline_bridge_to_wire_v1(value) != raw:
        raise ValueError("offline bridge wire is noncanonical")
    return value


def _make_bridge(**values):
    # Compute the commitment over the same closed wire before constructing the
    # strict DTO. No object identity here confers permission.
    raw = dict(values, schema="d11.offline-tick-adoption-bridge.v1")
    raw["binding"] = offline_tick_to_wire_v1(values["binding"])
    raw["terminal"] = offline_tick_to_wire_v1(values["terminal"])
    raw["owner_authority"] = current_owner_authority_to_wire_v1(values["owner_authority"])
    raw["permit"] = fence_to_wire(values["permit"])
    raw["before_anchor"] = asdict(values["before_anchor"])
    raw["after_anchor"] = asdict(values["after_anchor"])
    return D11OfflineTickAdoptionBridgeV1(**values, qualification_digest=canonical_digest(raw))


def _originals_locked(service, db, binding, execution):
    head, claim, terminal, claim_row, terminal_row = read_offline_tick_rows_locked_v1(service.bridge.journal, binding)
    if claim is None or terminal is None:
        raise AuthorityUnavailable("offline adoption needs an actual durable terminal")
    service._verify_payload(claim.payload)
    service._verify_payload(terminal.payload)
    source, source_row = service._gate(db, binding, "claim")
    before = source.pinned_anchor
    if (head != execution or source_row[6] != "finished"
            or claim_row[0] != before.execution_seq + 1 or claim_row[5] != before.execution_digest
            or terminal_row[0] != claim_row[0] + 1 or terminal_row[5] != claim_row[6]
            or (execution.seq, execution.digest) != (terminal_row[0], terminal_row[6])):
        raise AuthorityUnavailable("offline adoption cannot skip interleaved or later execution rows")
    return before, source, terminal


def _owner_observation(service,binding,permit,before):
    from .owner_location_read_v3 import _owner_location_service_invocation_v3
    with _owner_location_service_invocation_v3(service):
        from .owner_location_read_v3 import prepare_owner_location_for_offline_bridge_v3
        return prepare_owner_location_for_offline_bridge_v3(service,binding=binding,permit=permit,before=before)

def _observe_bridge(service, binding, permit):
    with service._frozen() as (db, deletion, execution, _):
        after, holder = service._current(db, deletion, execution)
        before, source, terminal = _originals_locked(service, db, binding, execution)
        if not _same_location(before, after) or source.holder != holder:
            raise AuthorityUnavailable("offline transition crossed deletion, generation or holder")
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=after)
    prepared = service._prepared(binding, for_execution=False)
    service._prepared_anchor(prepared, before)
    if prepared.digest != terminal.payload.prepared_digest:
        raise AuthorityUnavailable("offline terminal preparation commitment changed")
    owner, actor_id = _owner_observation(service, binding, permit, before)
    with service._frozen() as (db, deletion, execution, _):
        current, _ = service._current(db, deletion, execution)
        actual_before, _, actual_terminal = _originals_locked(service, db, binding, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=current)
        if (current, actual_before, actual_terminal) != (after, before, terminal):
            raise AuthorityUnavailable("offline terminal interval changed after outside-SQL read")
        service._owner_current(db, binding, prepared, owner)
    return _make_bridge(binding=binding, terminal=terminal, owner_authority=owner, owner_actor_id=actor_id,
        prepared_digest=prepared.digest, before_requirements_json=prepared.requirements_json,
        before_graph_revision=prepared.graph_revision, before_graph_epoch=prepared.graph_epoch,
        before_anchor=before, after_anchor=after, permit=permit)


def operate_offline_adoption_bridge_v1(service, binding, action, gate=None, outcome=None):
    from .owner_location_read_v3 import _owner_location_service_invocation_v3
    with _owner_location_service_invocation_v3(service):
        from .d11_offline_tick_service_v1 import AuthorityD11OfflineTickServiceV1
        if type(service) is not AuthorityD11OfflineTickServiceV1 or action not in {"begin", "validate", "finish", "status"}:
            raise AuthorityUnavailable("actual installed offline bridge and closed operation required")
        if action in {"finish", "status"}:
            from .d11_offline_historical_accounting_v1 import _scope
            _scope(service, binding)
        else:
            service._binding(binding)
        service.bridge.core._require(service.credential, "current", service.bridge.namespace)
        operation_id = service._gate_id(binding, "adoption")
        if action != "begin" and (type(gate) is not D11OfflineTickAdoptionBridgeV1
                or gate.binding != binding or gate.permit.operation_id != operation_id):
            raise AuthorityUnavailable("offline exact original bridge required")
        if action in {"finish", "status"}:
            with service.bridge.core._tx() as db:
                row = service.bridge.fences._row(db, operation_id)
                if row is None or service.bridge.fences._permit(row) != gate.permit:
                    raise AuthorityUnavailable("offline actual bridge gate differs")
                if action == "status":
                    if row[6] not in {"active", "finished"}:
                        raise AuthorityUnavailable("offline gate has an unsupported state")
                    return row[6]
                if outcome not in {"committed", "abandoned"}:
                    raise AuthorityUnavailable("offline finish requires an exact outcome")
                finish = (operation_id + ":" + outcome, "sha256:" + canonical_digest((gate.qualification_digest, outcome)))
                if row[6] == "finished":
                    if row[8:10] != finish:
                        raise AuthorityUnavailable("offline finished bridge replay changed outcome")
                    return True
            _verify_graph_finish(service, gate, outcome)
            with service._frozen() as (db, deletion, execution, _):
                current = service.fences._current_locked(db, deletion, execution, require_clear=False)
                service.bridge.fences.validate_fence_locked(db, gate.permit, subject=service._subject, current_anchor=current)
                service.bridge.fences.finish_fence_locked(db, gate.permit, subject=service._subject,
                    current_anchor=current, request_id=finish[0], request_digest=finish[1])
            return True
        if action == "begin":
            service._recover_committed_append(binding)
            with service._frozen() as (db, deletion, execution, _):
                from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
                after, holder = service._current(db, deletion, execution)
                before, source, _ = _originals_locked(service, db, binding, execution)
                if not _same_location(before, after) or source.holder != holder:
                    raise AuthorityUnavailable("offline own interval crossed its actual location")
                require_lifecycle_admission_in_tx_v1(db, service.bridge.namespace, action="offline_tick_adoption")
                permit = service.bridge.fences.begin_fence_locked(db, subject=service._subject,
                    holder=holder, operation="write", current_anchor=after, operation_id=operation_id)
            try:
                return _observe_bridge(service, binding, permit)
            except BaseException:
                # No content mutation occurs during observation. Close exactly
                # this still-current unused permit; ambiguity remains recoverable.
                with service._frozen() as (db, deletion, execution, _):
                    current, _ = service._current(db, deletion, execution)
                    service.bridge.fences.finish_fence_locked(db, permit, subject=service._subject,
                        current_anchor=current, request_id=operation_id + ":rejected",
                        request_digest="sha256:" + canonical_digest((binding.digest, "adoption-rejected")))
                raise
        if _observe_bridge(service, binding, gate.permit) != gate:
            raise AuthorityUnavailable("offline independently reread bridge changed")
        return gate


def _verify_graph_finish(service, gate, outcome):
    from ..runtime.d11_offline_adoption_v1 import verify_offline_adoption_commit_v1
    db = sqlite3.connect(service.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        if outcome == "committed":
            verify_offline_adoption_commit_v1(db, gate=gate, issuer=service.issuer,
                resource_issuer=service.resource_issuer)
        else:
            from ..runtime.d10_offline_tick_terminal_v1 import offline_tick_adoption_operation_id_v1
            metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                "WHERE bot=? AND persona=?", gate.binding.namespace.as_tuple).fetchone()
            epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", gate.binding.namespace.as_tuple).fetchone()
            prior = db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*gate.binding.namespace.as_tuple, offline_tick_adoption_operation_id_v1(gate.binding))).fetchone()
            if (prior is not None or metadata != (gate.before_requirements_json, gate.before_graph_revision)
                    or epoch != (gate.before_graph_epoch,)):
                raise AuthorityUnavailable("offline abandon cannot erase an actual or changed commit")
    finally:
        db.close()
