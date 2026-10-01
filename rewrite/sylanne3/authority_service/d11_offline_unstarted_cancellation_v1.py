"""Permanent no-future-claim proof for one genuinely unstarted offline tick."""
from dataclasses import dataclass, fields
import sqlite3

from .contract import AuthorityUnavailable, JournalHead
from .d11_offline_tick_contract_v1 import D11OfflineTickBindingV1, offline_tick_from_wire_v1, offline_tick_to_wire_v1, _hex
from .d11_offline_tick_journal_v1 import read_offline_tick_rows_locked_v1
from .d11_offline_historical_accounting_v1 import _scope, _storage_observation, _storage_recheck_locked
from .v2_contract import (FencePermitV2, FenceNeverBegunReceiptV2, from_wire as fence_from_wire,
    to_wire as fence_to_wire, decode_bytes, canonical_bytes)
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime_contracts import canonical_digest, canonical_serialize


def unstarted_cancellation_operation_id_v1(binding):
    return "d11-offline-cancel:" + canonical_digest((binding.authority_namespace, binding.installation_id, binding.execution_id))


@dataclass(frozen=True, slots=True)
class D11OfflineUnstartedCancellationGrantV1:
    binding: D11OfflineTickBindingV1
    accounting_original_ref: str
    accounting_original_digest: str
    prepared_digest: str
    claim_gate_id: str
    no_future_claim_kind: str
    no_future_claim_original_json: str
    no_future_claim_digest: str
    frozen_journal_head: JournalHead
    permit: FencePermitV2
    schema: str = "d11.offline-unstarted-cancellation-grant.v1"

    def __post_init__(self):
        if (self.schema != "d11.offline-unstarted-cancellation-grant.v1" or type(self.binding) is not D11OfflineTickBindingV1
                or type(self.permit) is not FencePermitV2 or self.permit.operation != "accounting"
                or type(self.frozen_journal_head) is not JournalHead
                or self.permit.operation_id != unstarted_cancellation_operation_id_v1(self.binding)
                or self.permit.namespace != self.binding.authority_namespace or self.permit.authority_id != self.binding.authority_id
                or self.permit.subject != "d11-offline:" + self.binding.installation_id
                or self.claim_gate_id != "d11-offline-gate:claim:" + canonical_digest(
                    (self.binding.authority_namespace, self.binding.installation_id, self.binding.execution_id))
                or (self.frozen_journal_head.journal_id, self.frozen_journal_head.seq, self.frozen_journal_head.digest) !=
                    (self.permit.pinned_anchor.execution_journal_id, self.permit.pinned_anchor.execution_seq, self.permit.pinned_anchor.execution_digest)
                or self.no_future_claim_kind not in {"never_begun", "unappended"}):
            raise ValueError("exact unstarted offline cancellation grant required")
        import json
        raw = json.loads(self.no_future_claim_original_json)
        if canonical_serialize(raw) != self.no_future_claim_original_json or canonical_digest(raw) != self.no_future_claim_digest:
            raise ValueError("offline no-future-claim original bytes differ")
        if self.no_future_claim_kind == "never_begun":
            original = fence_from_wire(raw)
            if (type(original) is not FenceNeverBegunReceiptV2 or original.operation_id != self.claim_gate_id
                    or original.installation_id != self.binding.installation_id or original.namespace != self.binding.authority_namespace
                    or original.subject != self.permit.subject or original.authority_id != self.binding.authority_id
                    or original.request_id != self.claim_gate_id + ":unbegun"
                    or original.request_digest != "sha256:" + canonical_digest((self.binding.digest, "unappended"))):
                raise ValueError("offline permanent never-begun original differs")
        else:
            if type(raw) is not dict or set(raw) != {"permit", "request_id", "request_digest", "state"}:
                raise ValueError("offline unappended closure shape differs")
            original = fence_from_wire(raw["permit"])
            if (type(original) is not FencePermitV2 or original.operation != "write" or original.operation_id != self.claim_gate_id
                    or original.subject != self.permit.subject or original.namespace != self.binding.authority_namespace
                    or original.authority_id != self.binding.authority_id or original.generation != self.binding.activation_generation
                    or raw["state"] != "finished" or raw["request_id"] != self.claim_gate_id + ":unappended"
                    or raw["request_digest"] != "sha256:" + canonical_digest((self.binding.digest, "unappended"))):
                raise ValueError("offline genuine unappended finish differs")
        for value in (self.accounting_original_digest, self.prepared_digest, self.no_future_claim_digest):
            _hex(value)
        if self.permit.command_digest != "sha256:" + _command_digest(self):
            raise ValueError("offline cancellation accounting permit commitment differs")

    @property
    def digest(self):
        return canonical_digest(unstarted_cancellation_to_wire_v1(self))


def unstarted_cancellation_to_wire_v1(value):
    if type(value) is not D11OfflineUnstartedCancellationGrantV1:
        raise TypeError("exact D11 unstarted cancellation grant required")
    raw = plain_v1(value)
    raw["permit"] = fence_to_wire(value.permit)
    return raw


def unstarted_cancellation_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(D11OfflineUnstartedCancellationGrantV1)}:
        raise ValueError("offline cancellation grant fields differ")
    values = dict(raw)
    values["binding"] = offline_tick_from_wire_v1(values["binding"], D11OfflineTickBindingV1)
    values["permit"] = fence_from_wire(values["permit"])
    values["frozen_journal_head"] = JournalHead(**values["frozen_journal_head"])
    value = D11OfflineUnstartedCancellationGrantV1(**values)
    if unstarted_cancellation_to_wire_v1(value) != raw:
        raise ValueError("offline cancellation grant wire is noncanonical")
    return value


def _command_digest(value):
    raw = unstarted_cancellation_to_wire_v1(value) if type(value) is D11OfflineUnstartedCancellationGrantV1 else dict(value)
    raw.pop("permit", None)
    raw.pop("schema", None)
    return canonical_digest(raw)


def _permanent_retirement_locked(service, db, binding, anchor, *, retire):
    gate_id = service._gate_id(binding, "claim")
    row = service.bridge.fences._row(db, gate_id)
    digest = "sha256:" + canonical_digest((binding.digest, "unappended"))
    if row is None:
        prior = db.execute("SELECT request_id,request_digest,receipt FROM authority_v2_never_begun WHERE operation_id=?", (gate_id,)).fetchone()
        if prior is None:
            if not retire:
                raise AuthorityUnavailable("offline claim identity is not permanently retired")
            original = service.bridge.fences.reject_unbegun_content_fence_locked(db, subject=service._subject,
                installation_id=service.installation_id, holder=service.bridge.core._row(db, service.bridge.namespace)[0],
                generation=anchor.activation_generation, operation_id=gate_id, current_anchor=anchor,
                request_id=gate_id + ":unbegun", request_digest=digest)
        else:
            original = decode_bytes(prior[2])
            if (type(original) is not FenceNeverBegunReceiptV2
                    or prior != (original.request_id, original.request_digest, canonical_bytes(original))
                    or (original.request_id, original.request_digest) != (gate_id + ":unbegun", digest)):
                raise AuthorityUnavailable("offline actual permanent rejection original differs")
        return "never_begun", canonical_serialize(fence_to_wire(original))
    permit, row = service._gate(db, binding, "claim")
    if row[6] == "active":
        if not retire:
            raise AuthorityUnavailable("offline active unappended claim gate is not retired")
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=anchor)
        service.bridge.fences.finish_fence_locked(db, permit, subject=service._subject, current_anchor=anchor,
            request_id=gate_id + ":unappended", request_digest=digest)
        row = service.bridge.fences._row(db, gate_id)
    if row[6] != "finished" or row[8:10] != (gate_id + ":unappended", digest):
        raise AuthorityUnavailable("offline claim fence lacks its exact unappended closure; HOLD")
    return "unappended", canonical_serialize({"permit": fence_to_wire(permit), "request_id": row[8], "request_digest": row[9], "state": "finished"})


def operate_offline_unstarted_cancellation_v1(service, binding, action, gate=None):
    _scope(service, binding)
    if action not in {"begin", "validate", "finish", "status"}:
        raise AuthorityUnavailable("closed offline cancellation action required")
    operation = unstarted_cancellation_operation_id_v1(binding)
    if action != "begin" and (type(gate) is not D11OfflineUnstartedCancellationGrantV1 or gate.binding != binding):
        raise AuthorityUnavailable("exact original offline cancellation gate required")
    if action in {"finish", "status"}:
        with service.bridge.core._tx() as db:
            row = service.bridge.fences._row(db, operation)
            if row is None or service.bridge.fences._permit(row) != gate.permit:
                raise AuthorityUnavailable("offline cancellation original permit differs")
            if action == "status":
                if row[6] not in {"active", "finished"}:
                    raise AuthorityUnavailable("offline cancellation state differs")
                return row[6]
            if row[6] == "finished":
                if row[8:10] != (operation + ":finished", "sha256:" + gate.digest):
                    raise AuthorityUnavailable("offline cancellation finished ACK changed")
                return True
    storage = _storage_observation(service)
    prepared = service.read_d11_offline_accounting_prepared_v1(binding)
    if prepared is None:
        raise AuthorityUnavailable("offline cancellation actual signed accounting preparation absent")
    if action == "finish":
        from ..runtime.d11_offline_unstarted_cancellation_v1 import verify_offline_unstarted_cancellation_commit_v1
        db = sqlite3.connect(service.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            verify_offline_unstarted_cancellation_commit_v1(db, gate=gate, issuer=service.issuer,
                resource_issuer=service.resource_issuer, require_current_anchor=True)
        finally:
            db.close()
    with service._frozen() as (db, deletion, execution, _):
        anchor = service.fences._current_locked(db, deletion, execution, require_clear=False)
        _storage_recheck_locked(service, db, storage, anchor)
        head, claim, terminal, _, _ = read_offline_tick_rows_locked_v1(service.bridge.journal, binding)
        if head != execution or claim is not None or terminal is not None:
            raise AuthorityUnavailable("claimed offline work cannot refund its reserved ceiling")
        kind, original_json = _permanent_retirement_locked(service, db, binding, anchor, retire=action == "begin")
        import json
        material = {"binding": offline_tick_to_wire_v1(binding), "accounting_original_ref": prepared.accounting_original_ref,
            "accounting_original_digest": canonical_digest(plain_v1(prepared)), "prepared_digest": prepared.prepared_digest,
            "claim_gate_id": service._gate_id(binding, "claim"), "no_future_claim_kind": kind,
            "no_future_claim_original_json": original_json, "no_future_claim_digest": canonical_digest(json.loads(original_json)),
            "frozen_journal_head": plain_v1(head)}
        command = "sha256:" + _command_digest(material)
        if action == "begin":
            permit = service.bridge.fences.begin_fence_locked(db, subject=service._subject,
                holder=service.bridge.core._row(db, service.bridge.namespace)[0], operation="accounting",
                current_anchor=anchor, operation_id=operation, command_digest=command)
            material["binding"], material["frozen_journal_head"] = binding, head
            return D11OfflineUnstartedCancellationGrantV1(**material, permit=permit)
        actual = {key: value for key, value in unstarted_cancellation_to_wire_v1(gate).items() if key not in {"schema", "permit"}}
        if actual != material:
            raise AuthorityUnavailable("offline cancellation independent no-future-claim proof changed")
        service.bridge.fences.validate_fence_locked(db, gate.permit, subject=service._subject, current_anchor=anchor)
        if action == "finish":
            service.bridge.fences.finish_fence_locked(db, gate.permit, subject=service._subject, current_anchor=anchor,
                request_id=operation + ":finished", request_digest="sha256:" + gate.digest)
            return True
        return gate
