"""Sign a root freeze using its already measured, reserved execution original."""
from __future__ import annotations

from dataclasses import asdict
import json

from ..runtime_contracts import canonical_digest, canonical_serialize
from .d04_root_execution_v3 import read_root_prepared_v3
from .d11_d04_root_freeze_v3 import (
    D11RootFreezeOriginalV3, D11RootFreezeReadV3, ROOT_WORK_KIND_V3,
    _SIGN_KIND, read_d11_root_freeze_v3,
)


def issue_executed_d11_root_freeze_v3(db, graph, witness, read, *, now_utc):
    """No new reservation or native execution may occur at final adoption."""
    from .d04_root_adoption_execution_v3 import require_root_commit_witness_v3
    require_root_commit_witness_v3(graph, db, witness, after_head=True)
    prepared, terminal = witness.prepared, witness.bridge.terminal
    binding, issuer = prepared.binding, graph._GraphCoordinator__d11_issuer
    if (type(read) is not D11RootFreezeReadV3 or read.namespace != binding.namespace
            or read.operation_id != binding.operation_id or read.candidate_digest != binding.candidate_digest
            or read.native_manifest_sha256 != binding.native_manifest_sha256
            or read.native_sha256 != binding.native_sha256
            or read.abi2_initial_box_digest != terminal.measurement.initial_box_proof_digest
            or read.output_projection_digest != terminal.measurement.output_issuance_digest
            or read.authored_write_set_digest != terminal.measurement.output_write_set_digest
            or read_root_prepared_v3(db, binding.namespace, binding.operation_id) != prepared):
        raise ValueError("root final freeze differs from its actual measured execution")
    quote = graph._GraphCoordinator__d02_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    grant, signature = issuer.signed_budget_grant_at_version(db, binding.parent_budget_lease_ref,
        json.loads(prepared.signed_grant_payload_json)["version"])
    grant_row = db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?",
        (grant.lease_id, grant.version)).fetchone()
    reserve = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if (canonical_serialize(quote) != prepared.quote_payload_json or canonical_digest(quote) != binding.quote_digest
            or quote.work_kind != ROOT_WORK_KIND_V3 or dict(quote.ceiling) != {"thread_cpu_ms": binding.cpu_ceiling_ms}
            or quote.operation_id != binding.operation_id or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref
            or grant_row != (prepared.signed_grant_payload_json, prepared.signed_grant_signature)
            or signature != prepared.signed_grant_signature or grant.allowed_work_kinds != (ROOT_WORK_KIND_V3,)
            or tuple(sorted(grant.max_ceiling.items())) != (("thread_cpu_ms", binding.cpu_ceiling_ms),)
            or reserve != (binding.reservation_digest, binding.parent_budget_lease_ref, prepared.reserve_receipt_json)):
        raise ValueError("root final freeze signed quote/grant/original reservation differs")
    read_json = canonical_serialize(asdict(read))
    prior = read_d11_root_freeze_v3(db, issuer, namespace=binding.namespace, operation_id=binding.operation_id)
    if prior is not None:
        if prior.freeze_read_json != read_json or prior.reserve_operation_id != binding.reservation_operation_id:
            raise ValueError("root final freeze conflicts with its prior original")
        return prior
    payload = dict(namespace=binding.namespace, operation_id=binding.operation_id,
        parent_budget_lease_ref=binding.parent_budget_lease_ref,
        parent_budget_original_json=prepared.parent_budget_original_json,
        parent_budget_original_digest=canonical_digest(json.loads(prepared.parent_budget_original_json)),
        grant_version=grant.version, grant_signature=signature, grant_digest=canonical_digest(asdict(grant)),
        grant_signature_digest=canonical_digest(signature), quote_ceiling=tuple(sorted(grant.max_ceiling.items())),
        reserve_operation_id=binding.reservation_operation_id, reserve_digest=binding.reservation_digest,
        reserve_receipt_digest=canonical_digest(json.loads(prepared.reserve_receipt_json)),
        freeze_read_json=read_json, freeze_read_digest=canonical_digest(json.loads(read_json)),
        frozen_at_utc=now_utc, schema="d11.d04_authored_root_freeze_original.v3")
    frozen = D11RootFreezeOriginalV3(**payload, original_digest=canonical_digest(payload))
    encoded = canonical_serialize(asdict(frozen))
    db.execute("INSERT INTO runtime_d11_d04_root_freezes_v3 VALUES(?,?,?,?,?)",
        (*binding.namespace.as_tuple, binding.operation_id, encoded, issuer._signer.sign(_SIGN_KIND, encoded)))
    if read_d11_root_freeze_v3(db, issuer, namespace=binding.namespace, operation_id=binding.operation_id) != frozen:
        raise ValueError("root final executed freeze failed its independent signed reread")
    return frozen
