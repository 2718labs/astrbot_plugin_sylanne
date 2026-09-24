"""Durable, content-complete identity for a first-ingress encoding request.

This module is a storage primitive.  The graph coordinator must qualify the
current job, source, budget, and trusted request issuer before inserting a row.
Nothing here grants permission to call a provider.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from ..memory_types import SourceRecord
    from ..model_broker.broker import ModelCallRequest
    from ..runtime_contracts import NamespaceId


class EncodingCallConflict(RuntimeError):
    """One job or call identity was reused with different content."""


@dataclass(frozen=True)
class EncodingCallBinding:
    namespace: NamespaceId
    job_id: str
    source_id: str
    source_revision: int
    access_revision: int
    budget_lease_id: str
    budget_reservation_operation_id: str
    binding_digest: str
    model_request_digest: str
    call_id: str
    request_json: str

    @property
    def request(self) -> Mapping[str, Any]:
        return json.loads(self.request_json)


def install_schema(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_encoding_call_bindings_v1(
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            job_id TEXT NOT NULL, call_id TEXT NOT NULL,
            source_id TEXT NOT NULL, source_revision INTEGER NOT NULL,
            access_revision INTEGER NOT NULL,
            budget_lease_id TEXT NOT NULL,
            budget_reservation_operation_id TEXT NOT NULL,
            binding_digest TEXT NOT NULL,
            model_request_digest TEXT NOT NULL,
            request_json TEXT NOT NULL,
            PRIMARY KEY(bot,persona,job_id),
            UNIQUE(bot,persona,call_id),
            FOREIGN KEY(job_id) REFERENCES runtime_jobs(job_id)
        )
    """)
    db.execute("""
        CREATE TRIGGER IF NOT EXISTS runtime_encoding_call_bindings_no_update_v1
        BEFORE UPDATE ON runtime_encoding_call_bindings_v1
        BEGIN SELECT RAISE(ABORT, 'encoding call binding is immutable'); END
    """)
    # D12 closure cleanup must eventually be able to purge source-bearing
    # request JSON. Normal write admission has no delete operation.


def prepare_binding(
    namespace: NamespaceId, job_id: str, source: SourceRecord,
    source_revision: int, access_revision: int, budget_lease_id: str,
    budget_reservation_operation_id: str, request: ModelCallRequest,
    *, prompt_template_version: str, provider_config_ref: str,
    provider_config_digest: str,
) -> EncodingCallBinding:
    """Freeze all request inputs. Caller must independently qualify their origin."""
    from ..memory_types import SourceRecord, source_key
    from ..model_broker.broker import ModelCallRequest
    from ..model_broker.first_ingress_encoding import (
        FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
        build_first_ingress_encoding_payload,
    )
    from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

    if (type(request) is not ModelCallRequest or type(namespace) is not NamespaceId
            or type(source) is not SourceRecord):
        raise TypeError("typed namespace, source and model request are required")
    source_id = source.source_id
    source_ref = source_key(*namespace.as_tuple, source_id).token
    if any(type(value) is not str or not value for value in (
            job_id, source_id, budget_lease_id,
            budget_reservation_operation_id, prompt_template_version,
            provider_config_ref)):
        raise ValueError("binding identities and template version must be nonempty")
    if any(type(value) is not int or value < 1
           for value in (source_revision, access_revision)):
        raise ValueError("binding needs committed source and access revisions")
    if (type(provider_config_digest) is not str
            or len(provider_config_digest) != 64
            or any(char not in "0123456789abcdef" for char in provider_config_digest)):
        raise ValueError("provider config digest must be lowercase SHA-256")
    if (request.envelope.authority.namespace != namespace
            or request.envelope.source_qualification.source_refs != (source_ref,)
            or request.envelope.parent_budget_lease_ref != budget_lease_id
            or request.envelope.input_refs != (source_ref,)):
        raise ValueError("model request differs from source or budget identity")
    expected_payload, expected_template_digest = build_first_ingress_encoding_payload(source)
    if (dict(request.payload) != expected_payload
            or request.prompt_template_digest != expected_template_digest
            or prompt_template_version != FIRST_INGRESS_ENCODING_TEMPLATE_VERSION):
        raise ValueError("model request differs from fixed first-ingress template")
    frozen = {
        "schema": "sylanne.first-ingress-encoding-call.v1",
        "namespace": list(namespace.as_tuple),
        "job_id": job_id,
        "source_id": source_id,
        "source_revision": source_revision,
        "access_revision": access_revision,
        "budget_lease_id": budget_lease_id,
        "budget_reservation_operation_id": budget_reservation_operation_id,
        "call_id": request.call_id,
        "model_request_digest": request.digest,
        "envelope": json.loads(canonical_serialize(request.envelope)),
        "provider_id": request.provider_id,
        "model_id": request.model_id,
        "provider_config_ref": provider_config_ref,
        "provider_config_digest": provider_config_digest,
        "required_capabilities": sorted(request.required_capabilities),
        "privacy_tier": request.privacy_tier,
        "prompt_template_digest": request.prompt_template_digest,
        "prompt_template_version": prompt_template_version,
        "payload": dict(request.payload),
        "timeout_seconds": float(request.timeout_seconds),
        "max_output_tokens": request.max_output_tokens,
    }
    request_json = canonical_serialize(frozen)
    if len(request_json.encode("utf-8")) > 131_072:
        raise ValueError("encoding request exceeds durable binding limit")
    return EncodingCallBinding(
        namespace, job_id, source_id, source_revision, access_revision,
        budget_lease_id, budget_reservation_operation_id,
        canonical_digest(frozen), request.digest, request.call_id, request_json,
    )


def load_binding(db, namespace: NamespaceId, job_id: str) -> EncodingCallBinding | None:
    from ..runtime_contracts import canonical_digest

    row = db.execute(
        "SELECT source_id,source_revision,access_revision,budget_lease_id,"
        "budget_reservation_operation_id,binding_digest,model_request_digest,"
        "call_id,request_json "
        "FROM runtime_encoding_call_bindings_v1 WHERE bot=? AND persona=? AND job_id=?",
        namespace.as_tuple + (job_id,),
    ).fetchone()
    if row is None:
        return None
    binding = EncodingCallBinding(namespace, job_id, *row)
    _validate_binding_content(binding)
    return binding


def _validate_binding_content(binding: EncodingCallBinding) -> None:
    from ..runtime_contracts import canonical_digest

    request = binding.request
    try:
        model_digest = canonical_digest({
            "envelope": request["envelope"],
            "call_id": request["call_id"],
            "provider_id": request["provider_id"],
            "model_id": request["model_id"],
            "purpose": request["envelope"]["authority"]["purpose"],
            "required_capabilities": request["required_capabilities"],
            "privacy_tier": request["privacy_tier"],
            "template": request["prompt_template_digest"],
            "payload": request["payload"],
            "timeout_seconds": request["timeout_seconds"],
            "max_output_tokens": request["max_output_tokens"],
        })
    except (KeyError, TypeError, ValueError) as exc:
        raise EncodingCallConflict("encoding model request is incomplete") from exc
    if (canonical_digest(request) != binding.binding_digest
            or request.get("namespace") != list(binding.namespace.as_tuple)
            or request.get("job_id") != binding.job_id
            or request.get("call_id") != binding.call_id
            or request.get("source_id") != binding.source_id
            or request.get("source_revision") != binding.source_revision
            or request.get("access_revision") != binding.access_revision
            or request.get("budget_lease_id") != binding.budget_lease_id
            or request.get("budget_reservation_operation_id")
            != binding.budget_reservation_operation_id
            or request.get("model_request_digest") != binding.model_request_digest
            or model_digest != binding.model_request_digest):
        raise EncodingCallConflict("encoding request binding content is inconsistent")


def insert_binding(db, binding: EncodingCallBinding) -> EncodingCallBinding:
    """Insert inside the coordinator's graph transaction, or replay exactly."""
    if type(binding) is not EncodingCallBinding:
        raise TypeError("typed encoding call binding required")
    _validate_binding_content(binding)
    prior = load_binding(db, binding.namespace, binding.job_id)
    if prior is not None:
        if prior != binding:
            raise EncodingCallConflict("encoding job already has a different request")
        return prior
    other = db.execute(
        "SELECT job_id FROM runtime_encoding_call_bindings_v1 "
        "WHERE bot=? AND persona=? AND call_id=?",
        binding.namespace.as_tuple + (binding.call_id,),
    ).fetchone()
    if other is not None:
        raise EncodingCallConflict("encoding call ID already belongs to another job")
    db.execute(
        "INSERT INTO runtime_encoding_call_bindings_v1"
        "(bot,persona,job_id,call_id,source_id,source_revision,access_revision,"
        "budget_lease_id,budget_reservation_operation_id,binding_digest,"
        "model_request_digest,request_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        binding.namespace.as_tuple + (binding.job_id, binding.call_id,
            binding.source_id, binding.source_revision, binding.access_revision,
            binding.budget_lease_id, binding.budget_reservation_operation_id,
            binding.binding_digest, binding.model_request_digest,
            binding.request_json),
    )
    return binding
