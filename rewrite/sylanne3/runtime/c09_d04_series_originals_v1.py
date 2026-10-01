"""Installed closed C09 inventory for actual series originals."""
import json
from .c09_d04_originals_v3 import _fields, _json, _budget
from ..authority_service.d04_series_contract_v1 import (D04SeriesChunkBindingV1, D04SeriesClaimV1,
    D04SeriesMeasurementV1, D04SeriesTerminalV1, D04SeriesGateV1, from_wire)

SERIES_BODY_KINDS = frozenset({"series_root", "series_chunk_prepared", "series_chunk_math", "series_final_native_prefix"})
SERIES_FACT_KINDS = frozenset({"series_chunk_accounting", "series_chunk_measurement", "series_chunk_terminal",
    "series_chunk_cost_pending", "series_chunk_cost_commit", "series_chunk_cost", "series_chunk_cost_gate", "series_chunk_measurement_gate",
    "series_progress", "series_adoption", "series_adoption_gate", "series_adoption_rejected"})


def validate_d04_series_original_payload_v1(kind, raw):
    if kind == "series_root":
        _fields(raw, ("schema", "root_ref", "numeric_operation_id", "numeric_prepared_digest", "c02_operation_id", "source_ref",
            "deadline_utc", "plan_digest", "frozen_model", "output_policy", "output_policy_sha256", "operator_version", "graph_revision", "graph_epoch", "requirements"),
            "d04.series-root.v1")
        from .d04_series_codec_v1 import decode_series_dto_v1
        from ..native_runtime.d04_joint_product_math import D04JointCompiledInputsV1
        frozen = decode_series_dto_v1(D04JointCompiledInputsV1, raw["frozen_model"])
        if frozen.plan.digest != raw["plan_digest"]:
            raise ValueError("series root plan commitment differs")
    elif kind == "series_chunk_math":
        from .d04_series_codec_v1 import decode_series_dto_v1
        from ..native_runtime.d04_series_math_v1 import D04SeriesChunkMathV1
        decode_series_dto_v1(D04SeriesChunkMathV1, raw)
    elif kind in {"series_chunk_prepared", "series_chunk_accounting"}:
        fields = {"schema", "binding", "quote_payload_json", "reserve_receipt_json"}
        fields.update({"job", "graph_revision", "graph_epoch", "requirements_json"} if kind == "series_chunk_prepared" else {"job_identity_json"})
        _fields(raw, fields, "d04.series-chunk-prepared.v1" if kind == "series_chunk_prepared" else "d04.series-chunk-accounting.v1")
        binding = from_wire(raw["binding"], D04SeriesChunkBindingV1)
        _budget(_json(raw["reserve_receipt_json"]))
        from .issuers import _decode_quote, ResourceQuote
        from dataclasses import fields
        from .d04_numeric_accounting_prepared_v3 import _json as accounting_json
        from ..runtime_contracts import canonical_serialize
        quote = _decode_quote(canonical_serialize(accounting_json(raw["quote_payload_json"],
            (field.name for field in fields(ResourceQuote)), typed=ResourceQuote)))
        from ..runtime_contracts import canonical_digest
        if canonical_digest(quote) != binding.numeric.quote_digest:
            raise ValueError("series accounting quote commitment differs")
        if kind == "series_chunk_accounting":
            from .d04_numeric_accounting_prepared_v3 import JOB_IDENTITY_FIELDS
            _fields(_json(raw["job_identity_json"]), JOB_IDENTITY_FIELDS)
    elif kind == "series_chunk_measurement":
        _fields(raw, {"claim", "measurement", "artifact_payload_digest"})
        claim = from_wire(raw["claim"], D04SeriesClaimV1)
        measured = from_wire(raw["measurement"], D04SeriesMeasurementV1)
        if claim.claim_id != measured.claim_id or claim.binding_digest != measured.binding_digest:
            raise ValueError("series observed CPU claim identity differs")
    elif kind == "series_chunk_terminal":
        from_wire(raw, D04SeriesTerminalV1)
    elif kind in {"series_chunk_cost_gate", "series_adoption_gate", "series_chunk_measurement_gate"}:
        from_wire(raw, D04SeriesGateV1)
    elif kind in {"series_chunk_cost_pending", "series_chunk_cost_commit", "series_chunk_cost"}:
        fields = {"schema", "root_digest", "binding_digest", "terminal_digest", "actual_cpu_ns", "actual_cpu_ms",
            "status", "math_digest", "budget_status", "gate_digest", "authority_ack"}
        if kind == "series_chunk_cost_commit" or {"event_id", "graph_receipt_digest"} <= set(raw):
            fields.update({"event_id", "graph_receipt_digest"})
        _fields(raw, fields, "d04.series-chunk-cost.v1")
        if raw["status"] not in {"chunk_completed", "failed"} or raw["actual_cpu_ms"] != (raw["actual_cpu_ns"] + 999999) // 1000000:
            raise ValueError("series retained measured CPU differs")
    elif kind == "series_progress":
        _fields(raw, {"schema", "root_digest", "graph_revision", "graph_epoch", "event_id", "before_requirements",
            "after_requirements", "write_versions", "write_values"}, "d04.series-own-progress.v1")
    elif kind == "series_adoption":
        _fields(raw, {"schema", "status", "root_ref", "root_digest", "operation_id", "gate_digest", "last_binding_digest",
            "terminal_digest", "complete_prefix_digest", "output_original_digest", "numeric_receipt_digest", "graph_receipt_digest",
            "total_step_count", "chunk_count", "actual_cpu_ns", "actual_cpu_ms"}, "d04.series-adoption.v1")
    elif kind == "series_adoption_rejected":
        _fields(raw, {"schema", "gate_digest", "status"}, "d04.series-adoption-rejected.v1")
        if raw["status"] != "rejected_no_commit":
            raise ValueError("series rejection is not a known no-commit outcome")
    elif kind == "series_final_native_prefix":
        _fields(raw, {"root_ref", "root_digest", "math_digest", "chunks"})
    else:
        raise ValueError("unclassified series original kind")
    return raw
