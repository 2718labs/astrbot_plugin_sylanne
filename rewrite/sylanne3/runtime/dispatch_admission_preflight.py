"""Pure D11 admission preflight. Its report is never a dispatch claim."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from ..dispatch_runtime import DispatchRequest
from ..domains.d08.execution import (
    ActionIntent, ActionSchema, ActionSchemaRecord, RequiredCheckSpec,
)
from ..domains.d09 import D09ExpressionProvider
from ..runtime_contracts import CheckReceipt, canonical_digest


CheckVerifier = Callable[[RequiredCheckSpec, CheckReceipt], bool]


@dataclass(frozen=True)
class DispatchAdmissionPreflight:
    """Candidate fingerprint and unsatisfied prerequisites; always HOLD."""

    status: str
    candidate_digest: str
    missing: tuple[str, ...]


def _check_ref(spec: RequiredCheckSpec) -> str:
    return "check:" + canonical_digest({
        "kind": spec.check_kind,
        "provider": spec.provider_id,
        "subject": spec.subject_ref,
        "action": spec.action_ref,
        "purpose": spec.purpose,
        "criteria_version": spec.criteria_version,
        "input_versions": spec.required_input_versions,
    })


def preflight_dispatch_admission(
    schema: ActionSchemaRecord,
    intent: ActionIntent,
    batch: dict,
    request: DispatchRequest,
    receipts: tuple[CheckReceipt, ...],
    *,
    now_utc: float,
    trusted_check_verifier: CheckVerifier | None = None,
) -> DispatchAdmissionPreflight:
    """Compare frozen candidates without granting business or platform authority.

    The verifier is supplied by the future trusted graph writer. A receipt's
    issuer string alone cannot establish provenance or current graph reads.
    """
    if (type(schema) is not ActionSchemaRecord or type(intent) is not ActionIntent
            or type(batch) is not dict or type(request) is not DispatchRequest
            or type(receipts) is not tuple
            or any(type(item) is not CheckReceipt for item in receipts)):
        raise TypeError("typed schema, intent, batch, request and receipts required")
    if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        raise ValueError("now_utc must be finite")
    # D09's registered graph validator checks the full finite payload, body,
    # claim spans, source references and content digest. It does not qualify
    # sources or prove the batch came from trusted graph state.
    batch_spec = next(spec for spec in D09ExpressionProvider.register_types()
                      if spec.name == "d09.verified_segment_batch.v1")
    batch_spec.validator(batch)
    missing: list[str] = []

    def require(condition: bool, code: str) -> None:
        if not condition:
            missing.append(code)

    frozen = ActionSchema(
        schema.schema_id, schema.action_kind, schema.proactive,
        schema.required_checks,
    )
    try:
        frozen_matches = ActionSchemaRecord.bind(intent, frozen) == schema
    except (TypeError, ValueError):
        frozen_matches = False
    require(frozen_matches, "d08.frozen_schema")
    identity = intent.identity
    require((request.activity_id, request.effect_id, request.attempt_id,
             request.operation_id) ==
            (identity.activity_id, identity.effect_id, identity.attempt_id,
             identity.operation_id), "dispatch.identity")
    refs = tuple(_check_ref(spec) for spec in schema.required_checks)
    require(request.required_check_refs == refs, "dispatch.required_check_refs")
    require(batch["required_check_refs"] == list(refs), "d09.required_check_refs")
    require((batch["action_id"], batch["intent_revision"], batch["target_ref"],
             batch["purpose"]) ==
            (intent.action_id, intent.revision, intent.target_ref, "expression"),
            "d09.action_scope")
    require(request.proactive_contact == schema.proactive, "dispatch.contact_mode")
    require(request.cancel_epoch == batch["cancellation_epoch"],
            "dispatch.cancellation_epoch")
    require(request.segment_manifest_digest == batch["grant_manifest_digest"],
            "dispatch.segment_manifest")
    require(request.segment_count == len(batch["segments"]),
            "dispatch.segment_count")
    index = request.segment_index
    if type(index) is int and 0 <= index < len(batch["segments"]):
        segment = batch["segments"][index]
        require((request.effect_id, request.payload_digest,
                 request.segment_authorization_ref) ==
                (segment["effect_id"], segment["payload_digest"],
                 segment["segment_authorization_ref"]), "dispatch.segment_identity")
        require(request.footprint.segment_id == segment["segment_id"],
                "dispatch.segment_footprint")
    else:
        missing.append("dispatch.segment_index")
    require(request.footprint.contact_id == batch["contact_id"],
            "dispatch.contact_identity")
    require(bool(request.footprint.budgets), "dispatch.budget_footprint")
    require({ref for segment in batch["segments"] for ref in segment["source_refs"]}
            <= set(intent.source_refs), "d09.source_refs")
    require(float(batch["valid_until"]) >= now_utc, "d09.expired")

    by_kind: dict[str, list[CheckReceipt]] = {}
    for receipt in receipts:
        by_kind.setdefault(receipt.check_kind, []).append(receipt)
    require(set(by_kind) == {spec.check_kind for spec in schema.required_checks},
            "checks.exact_set")
    if trusted_check_verifier is None:
        missing.append("checks.trusted_verifier")
    for spec in schema.required_checks:
        matched = by_kind.get(spec.check_kind, ())
        if len(matched) != 1:
            missing.append(f"check:{spec.check_kind}:cardinality")
            continue
        receipt = matched[0]
        require((receipt.issuer, receipt.subject_ref, receipt.action_ref,
                 receipt.purpose, receipt.input_versions) ==
                (spec.provider_id, spec.subject_ref, spec.action_ref,
                 spec.purpose, spec.required_input_versions),
                f"check:{spec.check_kind}:scope")
        require(receipt.coverage == "full" and receipt.result == "pass"
                and receipt.valid_until >= now_utc,
                f"check:{spec.check_kind}:result")
        if trusted_check_verifier is not None:
            try:
                current = trusted_check_verifier(spec, receipt) is True
            except Exception:
                current = False
            require(current, f"check:{spec.check_kind}:unverified")

    # D09 expressly freezes only content. Source/access qualification and the
    # final graph/Authority transaction are separate, currently absent gates.
    missing.extend(("d09.source_qualification", "dispatch.command_provenance",
                    "graph.current_admission"))
    digest = canonical_digest({
        "schema": schema, "intent": intent, "batch": batch,
        "request": request, "receipts": receipts,
    })
    return DispatchAdmissionPreflight("hold", digest, tuple(dict.fromkeys(missing)))


__all__ = ["DispatchAdmissionPreflight", "preflight_dispatch_admission"]
