"""Frozen, independent semantic-review call for natural D09 language.

The parser returns only an untrusted model candidate. In particular, a
syntactically valid ``pass`` is not an Authority receipt or permission to
adopt/send text. W09 must authenticate the original paid call terminal and its
current read fence; W01 must authenticate the current read fence independently.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from ..runtime_contracts import (
    NATURAL_REPLY_REVIEW_WORKFLOW_V1,
    NaturalReplyGenerationOriginalSealV2,
    NaturalReplyReviewOriginalSealV2,
    canonical_digest,
    canonical_serialize,
)
from ..runtime.natural_original_v3 import NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3
from ..runtime.natural_original_v4 import NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4
from ..runtime.natural_original_v6 import NaturalReplyGenerationOriginalSealV6,NaturalReplyReviewOriginalSealV6
from ..runtime.natural_original_v7 import NaturalReplyGenerationOriginalSealV7,NaturalReplyReviewOriginalSealV7
from ..domains.d09.natural_reply import (
    NATURAL_REPLY_OUTPUT_SCHEMA_V2, QualifiedExpressionUnitV2,
    NATURAL_REPLY_OUTPUT_SCHEMA_V3, natural_semantic_ranges_v3,
)


INPUT_SCHEMA = "sylanne.d09.natural_review_input.v1"
OUTPUT_SCHEMA = "sylanne.d09.natural_review_output.v1"
REVIEW_TEMPLATE_VERSION = NATURAL_REPLY_REVIEW_WORKFLOW_V1
MAX_BODY_CHARS = 2048
MAX_UNITS = 16
MAX_ISSUES = 16
_ISSUE_CODES = frozenset({
    "unsupported_claim", "meaning_shift", "negation_shift",
    "speaker_shift", "time_or_quantity_shift", "certainty_shift",
    "commitment_out_of_scope", "audience_or_disclosure_violation",
    "required_slot_missing", "simulation_unmarked", "other_semantic_risk",
})

SYSTEM_MESSAGE = (
    "Independently review the proposed reply against the frozen qualified basis. "
    "Check audience and disclosure, factuality, speaker attribution, negation, "
    "time and quantity, uncertainty, commitments, simulation marking, and required "
    "slots. Promise grant refs below are opaque identifiers, not scope. In this "
    "version any explicit promise speech act must be reported as hold. Return only "
    "JSON with exactly schema, verdict, issues. verdict is "
    "pass, rewrite, or hold. issues is a bounded list of {code, location}; code "
    "must be one of the listed issue codes and location is null or a JSON pointer "
    "into body/units. A pass has no issues. Do not include reasoning, chain of "
    "thought, cost, permissions, receipts, or authority claims. Allowed issue "
    "codes: unsupported_claim, meaning_shift, negation_shift, speaker_shift, "
    "time_or_quantity_shift, certainty_shift, commitment_out_of_scope, "
    "audience_or_disclosure_violation, required_slot_missing, simulation_unmarked, "
    "other_semantic_risk."
)
REVIEW_TEMPLATE_DIGEST = canonical_digest({
    "version": REVIEW_TEMPLATE_VERSION,
    "input_schema": INPUT_SCHEMA,
    "output_schema": OUTPUT_SCHEMA,
    "layout": "system/review_user",
    "system_message": SYSTEM_MESSAGE,
})
INPUT_SCHEMA_V2 = "sylanne.d09.natural_review_input.v2"
OUTPUT_SCHEMA_V2 = "sylanne.d09.natural_review_output.v2"
from ..runtime_contracts import NATURAL_REPLY_REVIEW_WORKFLOW_V2 as REVIEW_TEMPLATE_VERSION_V2
SYSTEM_MESSAGE_V2 = SYSTEM_MESSAGE.replace(
    "exactly schema, verdict, issues.", "exactly schema, verdict, issues, prefix_safe."
) + (
    " The output schema is sylanne.d09.natural_review_output.v2. Review all "
    "semantic_segments in their frozen order and every possible interrupted "
    "prefix. prefix_safe must be a boolean. Return pass only if prefix_safe is "
    "true and each bubble is a complete meaning preserving qualifiers, attribution, "
    "negation, uncertainty, lists and code. An assertion whose restriction arrives "
    "only in a later bubble is unsafe. Use other_semantic_risk for unsafe prefixes."
)
REVIEW_TEMPLATE_DIGEST_V2 = canonical_digest({
    "version": REVIEW_TEMPLATE_VERSION_V2, "input_schema": INPUT_SCHEMA_V2,
    "output_schema": OUTPUT_SCHEMA_V2, "layout": "system/review_user",
    "system_message": SYSTEM_MESSAGE_V2,
})


@dataclass(frozen=True, slots=True)
class NaturalReviewQualifiedUnitV1:
    """Exact generation unit; grant refs remain opaque and never authorize text."""

    source_unit: QualifiedExpressionUnitV2
    promise_grant_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.source_unit) is not QualifiedExpressionUnitV2:
            raise TypeError("review basis must retain the exact generation unit")
        if (type(self.promise_grant_refs) is not tuple
                or any(type(item) is not str or not item.strip() or len(item) > 1024
                       for item in self.promise_grant_refs)
                or len(set(self.promise_grant_refs)) != len(self.promise_grant_refs)):
            raise ValueError("promise grant refs must be unique bounded strings")


@dataclass(frozen=True, slots=True)
class NaturalReviewInstallationV1:
    installation_id: str
    provider_id: str
    provider_config_digest: str
    model_id: str
    max_output_tokens: int = 512

    def __post_init__(self) -> None:
        if any(type(getattr(self, name)) is not str or not getattr(self, name).strip()
               for name in ("installation_id", "provider_id", "model_id")):
            raise ValueError("review installation identity is required")
        digest = self.provider_config_digest
        if (type(digest) is not str or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)):
            raise ValueError("provider config digest must be lowercase SHA-256")
        if type(self.max_output_tokens) is not int or not 1 <= self.max_output_tokens <= 2048:
            raise ValueError("review output token limit is outside bounds")


@dataclass(frozen=True, slots=True)
class NaturalReviewUnitV1:
    start: int
    end: int
    kind: str
    basis_ids: tuple[str, ...]
    speech_act: str
    promise_grant_id: str | None
    slot_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FrozenNaturalReplyReviewV1:
    generation_frozen_input_digest: str
    generation_output_digest: str
    qualified_units_digest: str
    body: str
    units: tuple[NaturalReviewUnitV1, ...]
    qualified_basis: tuple[NaturalReviewQualifiedUnitV1, ...]
    review_policy_version: str
    installation: NaturalReviewInstallationV1
    canonical_input: str
    messages_wire: str
    canonical_wire: str
    digest: str
    wire_digest: str


@dataclass(frozen=True, slots=True)
class UntrustedNaturalReplyReviewOutputV1:
    generation_frozen_input_digest: str
    generation_output_digest: str
    review_frozen_input_digest: str
    output_digest: str
    verdict: str
    issues: tuple[tuple[str, str | None], ...]
    canonical_output: str
    status: str = "untrusted_review_candidate"


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("natural review output repeats a field")
        result[key] = value
    return result


def _generation_output_values_v3(
    output: object,
) -> tuple[str, tuple[NaturalReviewUnitV1, ...], str, dict[str, object]]:
    semantic_batch = type(output) is dict and output.get("schema") == NATURAL_REPLY_OUTPUT_SCHEMA_V3
    fields = {"schema", "body", "units"} | ({"semantic_segments"} if semantic_batch else set())
    if (type(output) is not dict or set(output) != fields
            or output.get("schema") not in {NATURAL_REPLY_OUTPUT_SCHEMA_V2, NATURAL_REPLY_OUTPUT_SCHEMA_V3}
            or type(output.get("body")) is not str
            or not 0 < len(output["body"]) <= MAX_BODY_CHARS
            or type(output.get("units")) is not list
            or not 0 < len(output["units"]) <= MAX_UNITS):
        raise ValueError("generation output shape or bounds differ")
    if semantic_batch:
        natural_semantic_ranges_v3(output)
    body = output["body"]
    units: list[NaturalReviewUnitV1] = []
    cursor = 0
    for item in output["units"]:
        if (type(item) is not dict or set(item) != {
                "start", "end", "kind", "basis_ids", "speech_act",
                "promise_grant_id", "slot_ids"}):
            raise ValueError("generation unit shape differs")
        start, end = item["start"], item["end"]
        basis_ids, slot_ids = item["basis_ids"], item["slot_ids"]
        if (type(start) is not int or type(end) is not int
                or not cursor <= start < end <= len(body)
                or body[cursor:start].strip()
                or type(item["kind"]) is not str or not item["kind"]
                or type(item["speech_act"]) is not str or not item["speech_act"]
                or type(basis_ids) is not list or not basis_ids
                or any(type(value) is not str or not value for value in basis_ids)
                or len(set(basis_ids)) != len(basis_ids)
                or type(slot_ids) is not list
                or any(type(value) is not str or not value for value in slot_ids)
                or len(set(slot_ids)) != len(slot_ids)
                or (item["promise_grant_id"] is not None
                    and (type(item["promise_grant_id"]) is not str
                         or not item["promise_grant_id"]))):
            raise ValueError("generation unit fields or coverage differ")
        units.append(NaturalReviewUnitV1(
            start, end, item["kind"], tuple(basis_ids), item["speech_act"],
            item["promise_grant_id"], tuple(slot_ids)))
        cursor = end
    if body[cursor:].strip():
        raise ValueError("generation output has unmapped body text")
    canonical_output = {
        "schema": output["schema"],
        "body": body,
        "units": [dict(item) for item in output["units"]],
    }
    if semantic_batch:
        canonical_output["semantic_segments"] = [dict(item) for item in output["semantic_segments"]]
    return body, tuple(units), canonical_output


def _generation_output(output):
    body,units,canonical_output=_generation_output_values_v3(output)
    return body,units,canonical_digest(canonical_output),canonical_output

def freeze_natural_reply_review_v1(
    generation: NaturalReplyGenerationOriginalSealV2,
    generation_output: dict[str, object],
    qualified_basis: tuple[QualifiedExpressionUnitV2, ...],
    promise_grant_refs: tuple[str, ...],
    review_policy_version: str,
    installation: NaturalReviewInstallationV1,
) -> FrozenNaturalReplyReviewV1:
    """Freeze the exact same-basis input and provider wire for a review call."""
    body,units,canonical_output,policy,semantic_batch=_natural_review_value_fields_v3(
        generation,generation_output,qualified_basis,promise_grant_refs,review_policy_version,installation)
    basis_digest=canonical_digest(qualified_basis)
    if basis_digest!=generation.qualified_units_digest:
        raise ValueError('review qualified basis differs from generation seal')
    output_digest=canonical_digest(canonical_output)
    if output_digest!=generation_output_digest_from_generation(generation_output):
        raise ValueError('generation output digest is not stable')
    payload = {
        "schema": INPUT_SCHEMA_V2 if semantic_batch else INPUT_SCHEMA,
        "template_version": REVIEW_TEMPLATE_VERSION_V2 if semantic_batch else REVIEW_TEMPLATE_VERSION,
        "generation_frozen_input_digest": generation.frozen_input_digest,
        "generation_output_digest": output_digest,
        "qualified_units_digest": basis_digest,
        "review_policy_version": policy,
        "body": body,
        "units": [asdict(unit) for unit in units],
        "qualified_basis": [
            asdict(NaturalReviewQualifiedUnitV1(unit, promise_grant_refs))
            for unit in qualified_basis
        ],
    }
    if semantic_batch:
        payload["semantic_segments"] = canonical_output["semantic_segments"]
        payload["generation_output_schema"] = canonical_output["schema"]
    canonical_input = canonical_serialize(payload)
    messages = canonical_serialize([
        {"role": "system", "content": SYSTEM_MESSAGE_V2 if semantic_batch else SYSTEM_MESSAGE},
        {"role": "user", "content": canonical_input},
    ])
    wire = canonical_serialize({
        "provider_id": installation.provider_id,
        "model": installation.model_id,
        "messages": json.loads(messages),
        "max_output_tokens": installation.max_output_tokens,
    })
    return FrozenNaturalReplyReviewV1(
        generation.frozen_input_digest, output_digest, basis_digest, body, units,
        qualified_basis, policy, installation, canonical_input, messages,
        wire, canonical_digest(payload), sha256(wire.encode("utf-8")).hexdigest(),
    )


def generation_output_digest_from_generation(output: dict[str, object]) -> str:
    """Return the canonical digest used to bind a review to exact generated text."""
    _, _, digest, _ = _generation_output(output)
    return digest


def parse_natural_reply_review_output_v1(
    text: str,
    frozen: FrozenNaturalReplyReviewV1,
    generation: NaturalReplyGenerationOriginalSealV2,
    review: NaturalReplyReviewOriginalSealV2,
) -> UntrustedNaturalReplyReviewOutputV1:
    """Parse syntax and pre-call seal bindings, not original-call provenance.

    ``review.model_request_digest`` binds the exact frozen provider wire. W09
    separately authenticates its durable typed-call digest and original paid
    terminal; neither is inferred or returned by this pure parser.
    """
    if (type(text) is not str or len(text) > 16_384
            or type(frozen) is not FrozenNaturalReplyReviewV1
            or type(generation) not in (NaturalReplyGenerationOriginalSealV2, NaturalReplyGenerationOriginalSealV3, NaturalReplyGenerationOriginalSealV4,NaturalReplyGenerationOriginalSealV6,NaturalReplyGenerationOriginalSealV7)
            or (type(generation), type(review)) not in (
                (NaturalReplyGenerationOriginalSealV2, NaturalReplyReviewOriginalSealV2),
                (NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3),
                (NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4),
                (NaturalReplyGenerationOriginalSealV6,NaturalReplyReviewOriginalSealV6),
                (NaturalReplyGenerationOriginalSealV7,NaturalReplyReviewOriginalSealV7))):
        raise TypeError("bounded text and typed frozen review identities required")
    if (frozen.generation_frozen_input_digest != generation.frozen_input_digest
            or frozen.qualified_units_digest != generation.qualified_units_digest
            or review.generation_original_operation_id != generation.original_operation_id
            or review.generation_call_id != generation.call_id
            or review.generation_frozen_input_digest != frozen.generation_frozen_input_digest
            or review.generation_output_digest != frozen.generation_output_digest
            or review.qualified_units_digest != frozen.qualified_units_digest
            or review.review_frozen_input_digest != frozen.digest
            or review.review_policy_version != frozen.review_policy_version
            or review.installation_id != frozen.installation.installation_id
            or review.provider_config_digest != frozen.installation.provider_config_digest
            or review.model_request_digest != frozen.wire_digest):
        raise ValueError("review seal is not bound to the frozen generation and model wire")
    return _parse_natural_reply_review_output_payload_v1(text,
        semantic_batch=json.loads(frozen.canonical_input).get("schema")==INPUT_SCHEMA_V2,
        units=frozen.units,generation_frozen_input_digest=frozen.generation_frozen_input_digest,
        generation_output_digest=frozen.generation_output_digest,review_frozen_input_digest=frozen.digest)


def _parse_natural_reply_review_output_payload_v1(text, *, semantic_batch, units,
        generation_frozen_input_digest, generation_output_digest, review_frozen_input_digest):
    """Pure output semantics shared after independent original-input validation."""
    if type(text) is not str or len(text)>16_384:
        raise ValueError("natural review output size differs")
    try:
        data = json.loads(text, object_pairs_hook=_unique_fields)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("natural review output is not valid unique-key JSON") from exc
    return _validate_natural_reply_review_output_payload_v1(data,semantic_batch=semantic_batch,units=units,
        generation_frozen_input_digest=generation_frozen_input_digest,
        generation_output_digest=generation_output_digest,review_frozen_input_digest=review_frozen_input_digest)


def _validate_natural_reply_review_output_payload_v1(data, *, semantic_batch, units,
        generation_frozen_input_digest, generation_output_digest, review_frozen_input_digest):
    """Already uniquely parsed output; same formal semantics and digest domain."""
    fields = {"schema", "verdict", "issues"} | ({"prefix_safe"} if semantic_batch else set())
    if (type(data) is not dict or set(data) != fields
            or data["schema"] != (OUTPUT_SCHEMA_V2 if semantic_batch else OUTPUT_SCHEMA)
            or semantic_batch and type(data["prefix_safe"]) is not bool
            or data["verdict"] not in {"pass", "rewrite", "hold"}
            or type(data["issues"]) is not list or len(data["issues"]) > MAX_ISSUES):
        raise ValueError("natural review output shape differs")
    issues: list[tuple[str, str | None]] = []
    for item in data["issues"]:
        if type(item) is not dict or set(item) != {"code", "location"}:
            raise ValueError("natural review issue shape differs")
        code, location = item["code"], item["location"]
        if (type(code) is not str or code not in _ISSUE_CODES
                or (location is not None and (
                    type(location) is not str or len(location) > 128
                    or not (location == "/body" or location.startswith("/body/")
                            or location == "/units" or location.startswith("/units/")
                            or semantic_batch and (location == "/semantic_segments"
                                                   or location.startswith("/semantic_segments/")))))):
            raise ValueError("natural review issue is outside bounded vocabulary")
        issues.append((code, location))
    if ((data["verdict"] == "pass" and issues)
            or (data["verdict"] != "pass" and not issues)):
        raise ValueError("review verdict and issue list disagree")
    verdict = data["verdict"]
    if semantic_batch and data["prefix_safe"] is not True:
        verdict = "hold"
        if len(issues) < MAX_ISSUES:
            issues.append(("other_semantic_risk", "/semantic_segments"))
    if any(unit.speech_act == "promise" for unit in units):
        verdict = "hold"
        if len(issues) < MAX_ISSUES:
            issues.append(("commitment_out_of_scope", "/units"))
    canonical_output = canonical_serialize(data)
    return UntrustedNaturalReplyReviewOutputV1(
        generation_frozen_input_digest,
        generation_output_digest,
        review_frozen_input_digest,
        canonical_digest(data),
        verdict,
        tuple(issues),
        canonical_output,
    )


__all__ = [
    "INPUT_SCHEMA", "OUTPUT_SCHEMA", "REVIEW_TEMPLATE_VERSION",
    "REVIEW_TEMPLATE_DIGEST",
    "NaturalReviewQualifiedUnitV1", "NaturalReviewInstallationV1",
    "NaturalReviewUnitV1", "FrozenNaturalReplyReviewV1",
    "UntrustedNaturalReplyReviewOutputV1",
    "freeze_natural_reply_review_v1", "generation_output_digest_from_generation",
    "parse_natural_reply_review_output_v1",
]
__all__ += ["INPUT_SCHEMA_V2", "OUTPUT_SCHEMA_V2", "REVIEW_TEMPLATE_VERSION_V2",
            "REVIEW_TEMPLATE_DIGEST_V2"]



def _natural_review_value_fields_v3(generation,generation_output,qualified_basis,
        promise_grant_refs,review_policy_version,installation):
    """Original review value rules before an owned canonical comparison."""
    if (type(generation) not in (NaturalReplyGenerationOriginalSealV2, NaturalReplyGenerationOriginalSealV3,
            NaturalReplyGenerationOriginalSealV4,NaturalReplyGenerationOriginalSealV6,NaturalReplyGenerationOriginalSealV7)
            or type(qualified_basis)is not tuple or not qualified_basis
            or any(type(unit)is not QualifiedExpressionUnitV2 for unit in qualified_basis)
            or type(promise_grant_refs)is not tuple
            or any(type(item)is not str or not item.strip()for item in promise_grant_refs)
            or len(set(promise_grant_refs))!=len(promise_grant_refs)
            or type(review_policy_version)is not str or not review_policy_version.strip()
            or type(installation)is not NaturalReviewInstallationV1):
        raise TypeError('typed generation, qualified basis, policy and installation required')
    if len({unit.basis_id for unit in qualified_basis})!=len(qualified_basis):
        raise ValueError('qualified basis IDs must be unique')
    body,units,canonical_output=_generation_output_values_v3(generation_output)
    basis_ids={item.basis_id for item in qualified_basis}
    if any(not set(unit.basis_ids).issubset(basis_ids)for unit in units):
        raise ValueError('generation unit cites a basis outside the frozen review basis')
    return body,units,canonical_output,review_policy_version.strip(),canonical_output['schema']==NATURAL_REPLY_OUTPUT_SCHEMA_V3
