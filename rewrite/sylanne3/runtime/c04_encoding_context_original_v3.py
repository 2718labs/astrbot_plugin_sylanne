"""D11 C04 encoding context read from W01's Owner-fenced graph transaction.

Meaning facets are nested in committed D04 AppraisalBundle graph originals.
Their exact appraisal version and issuer operation are checked from history;
caller-provided facet IDs and times have no authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re
import sqlite3

from ..domains.d04.affect import _decode_appraisal
from ..domains.d04.joint_state_output_v1 import joint_state_payload_v1
from ..contracts import canonical_json
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import SourceRecord
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_encoding_baseline_store_v3 import _joint_numeric, _receipt
from .c04_v3_contracts import ExactRefV3
from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PERSPECTIVE = frozenset({
    "d03.entity_anchor", "d03.role_binding", "d03.self_perspective.v1",
})
_INTERPRETATION = frozenset({
    "d07.current_interpretation.v1", "d07.belief_revision.v1",
})


class D11EncodingContextHold(ValueError):
    """The encoding-time Owner read or a real facet issuer is unavailable."""


def _sha(value: object, name: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name} needs a lowercase SHA-256 digest")


def _ref(value: object, namespace: NamespaceId, types: frozenset[str],
         name: str) -> AtomKey:
    if type(value) is not ExactRefV3:
        raise TypeError(f"{name} must be an exact graph version")
    key = AtomKey.from_token(value.ref)
    if NamespaceId.from_key(key) != namespace or key.type_name not in types:
        raise ValueError(f"{name} graph scope or type differs")
    return key


@dataclass(frozen=True, slots=True)
class MeaningFacetIssuerBindingV3:
    """Facet ID inside an exact D04 appraisal; issuer proof is still required."""

    facet_id: str
    appraisal: ExactRefV3
    facet_digest: str
    appraisal_issuer_digest: str

    def __post_init__(self) -> None:
        if type(self.facet_id) is not str or not self.facet_id.strip():
            raise ValueError("facet ID is required")
        if (type(self.appraisal) is not ExactRefV3
                or AtomKey.from_token(self.appraisal.ref).type_name
                   != "d04.appraisal_bundle.v1"):
            raise ValueError("MeaningFacet needs an exact D04 appraisal original")
        _sha(self.facet_digest, "facet")
        _sha(self.appraisal_issuer_digest, "appraisal issuer")


@dataclass(frozen=True, slots=True)
class D11EncodingContextOriginalV3:
    """Frozen shape only; constructing it is never an issuance or commit."""

    namespace: NamespaceId
    encoding_operation_id: str
    joint_operation_id: str
    source: ExactRefV3
    perspective: ExactRefV3
    interpretations: tuple[ExactRefV3, ...]
    feelings: tuple[ExactRefV3, ...]
    meaning_facets: tuple[MeaningFacetIssuerBindingV3, ...]
    as_known_at: float
    owner_fence_digest: str
    joint_receipt_digest: str
    joint_numeric_original_digest: str
    joint_output_original_digest: str
    read_versions: tuple[GraphVersion, ...]
    read_set_digest: str
    schema: str = "d11.c04_encoding_context_original.v3"
    status: str = "w01_owner_fenced_encoding_context"

    def __post_init__(self) -> None:
        if (self.schema not in {"d11.c04_encoding_context_original.v3",
                               "d11.c04_encoding_context_original.authored.v3"}
                or self.status != "w01_owner_fenced_encoding_context"):
            raise ValueError("encoding context cannot claim issuance")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("encoding namespace must be typed")
        for name in ("encoding_operation_id", "joint_operation_id"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"{name} is required")
        _ref(self.source, self.namespace, frozenset({"memory.source"}), "source")
        _ref(self.perspective, self.namespace, _PERSPECTIVE, "perspective")
        for name, values, types in (
            ("interpretations", self.interpretations, _INTERPRETATION),
            ("feelings", self.feelings, frozenset({
                "d04.authored_feeling_state.v1" if self.schema.endswith(".authored.v3")
                else "d04.feeling_state.v1"})),
        ):
            if (type(values) is not tuple or not values
                    or tuple(item.ref for item in values)
                       != tuple(sorted({item.ref for item in values}))):
                raise ValueError(f"{name} must be complete, unique and ordered")
            for item in values:
                _ref(item, self.namespace, types, name)
        if (type(self.meaning_facets) is not tuple or not self.meaning_facets
                or any(type(item) is not MeaningFacetIssuerBindingV3
                       for item in self.meaning_facets)
                or tuple(item.facet_id for item in self.meaning_facets)
                   != tuple(sorted({item.facet_id for item in self.meaning_facets}))):
            raise ValueError("MeaningFacet issuer bindings must be unique and ordered")
        if any(NamespaceId.from_key(AtomKey.from_token(item.appraisal.ref))
               != self.namespace for item in self.meaning_facets):
            raise ValueError("MeaningFacet appraisal crosses namespace")
        if type(self.as_known_at) not in (int, float) or not math.isfinite(self.as_known_at):
            raise ValueError("as_known_at must be finite")
        for name in ("owner_fence_digest", "joint_receipt_digest",
                     "joint_numeric_original_digest", "joint_output_original_digest",
                     "read_set_digest"):
            _sha(getattr(self, name), name)
        if (type(self.read_versions) is not tuple
                or any(type(item) is not GraphVersion for item in self.read_versions)
                or len({item.key for item in self.read_versions}) != len(self.read_versions)
                or self.read_set_digest != canonical_digest(self.read_versions)):
            raise ValueError("encoding read set differs")
        required = (self.source, self.perspective, *self.interpretations,
                    *self.feelings, *(item.appraisal for item in self.meaning_facets))
        reads = set(self.read_versions)
        if any(GraphVersion(AtomKey.from_token(item.ref), item.revision) not in reads
               for item in required):
            raise ValueError("encoding context original is absent from exact reads")


@dataclass(frozen=True, slots=True)
class W01EncodingGraphReadV3:
    """Internal W01 read request; the graph connection remains authoritative."""

    db: sqlite3.Connection
    namespace: NamespaceId
    encoding_operation_id: str
    joint_operation_id: str
    source_ref: str
    perspective_ref: str
    owner_fence_digest: str
    as_known_at: float


def _historical(db: sqlite3.Connection, namespace: NamespaceId,
                version: GraphVersion) -> tuple[dict, str]:
    row = db.execute(
        "SELECT value,valid,event_id FROM graph_history WHERE token=? "
        "AND revision=? AND event_bot=? AND event_persona=?",
        (version.key.token, version.revision, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[1] != 1:
        raise D11EncodingContextHold("encoding historical graph value is absent")
    try:
        value = json.loads(row[0])
        if type(value) is not dict or canonical_json(value) != row[0]:
            raise ValueError("historical value is not an object")
    except (TypeError, ValueError) as exc:
        raise D11EncodingContextHold("encoding historical graph value differs") from exc
    return value, row[2]


def issue_d11_encoding_context_original_v3(*, trusted_w01_read: object,
                                            facet_issuer_evidence: object,
                                            ) -> D11EncodingContextOriginalV3:
    """Issue from one authenticated W01 graph read, never caller facet bytes."""
    if (type(trusted_w01_read) is not W01EncodingGraphReadV3
            or facet_issuer_evidence is not None):
        raise D11EncodingContextHold("trusted W01 graph read is required")
    read = trusted_w01_read
    db, namespace = read.db, read.namespace
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId):
        raise D11EncodingContextHold("trusted W01 Owner graph transaction is required")
    _sha(read.owner_fence_digest, "Owner fence")
    if type(read.as_known_at) is not float or not math.isfinite(read.as_known_at):
        raise D11EncodingContextHold("trusted W01 encoding clock is absent")
    receipt = _receipt(db, namespace, read.encoding_operation_id)
    joint_receipt = _receipt(db, namespace, read.joint_operation_id)
    versions = receipt.read_versions
    by_ref = {item.key.token: item for item in versions}
    source = by_ref.get(read.source_ref)
    if source is None or source.revision < 1 or source.key.type_name != "memory.source":
        raise D11EncodingContextHold("encoding source was not an exact W01 read")
    source_value, _ = _historical(db, namespace, source)
    source_record = SourceRecord.from_dict(source_value)
    perspective = by_ref.get(read.perspective_ref)
    if (perspective is None or perspective.revision < 1
            or perspective.key.type_name not in _PERSPECTIVE):
        raise D11EncodingContextHold("encoding perspective was not an exact W01 read")
    _historical(db, namespace, perspective)
    appraisals = tuple(item for item in versions
                       if item.key.type_name == "d04.appraisal_bundle.v1"
                       and item.revision > 0)
    facets: list[MeaningFacetIssuerBindingV3] = []
    interpretations: set[str] = set()
    known_times = [source_record.recorded_at]
    for appraisal_version in appraisals:
        value, issuer_operation = _historical(db, namespace, appraisal_version)
        appraisal = _decode_appraisal(value)
        selected = tuple(facet for facet in appraisal.meaning_facets
                         if read.source_ref in facet.source_refs)
        if not selected:
            continue
        issuer_digest = canonical_digest(asdict(_receipt(
            db, namespace, issuer_operation)))
        known_times.append(appraisal.learned_at)
        for facet in selected:
            interpretations.add(facet.interpretation_ref)
            facets.append(MeaningFacetIssuerBindingV3(
                facet.facet_id,
                ExactRefV3(appraisal_version.key.token,
                           appraisal_version.revision),
                canonical_digest(asdict(facet)), issuer_digest,
            ))
    if not facets:
        raise D11EncodingContextHold("D04 MeaningFacet original is absent")
    if read.as_known_at < max(known_times):
        raise D11EncodingContextHold("encoding clock predates its graph sources")
    interpretation_versions = tuple(by_ref.get(ref) for ref in sorted(interpretations))
    if (any(item is None or item.revision < 1
            or item.key.type_name not in _INTERPRETATION
            for item in interpretation_versions)):
        raise D11EncodingContextHold("MeaningFacet interpretation was not read")
    for item in interpretation_versions:
        _historical(db, namespace, item)
    output = read_d04_joint_output_original_v1(
        db, namespace, read.joint_operation_id)
    if output is None:
        raise D11EncodingContextHold("adopted encoding joint output is absent")
    numeric = db.execute(
        "SELECT numeric_receipt_json,numeric_receipt_digest,verification_json,"
        "verification_digest FROM graph_d04_joint_numeric_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.joint_operation_id,),
    ).fetchone()
    if numeric is None:
        raise D11EncodingContextHold("encoding joint numeric original is absent")
    from ..domains.d04.encoding_baseline_v2 import ProjectionNumericErrorV2
    from .d04_joint_advance_v2 import (
        JointNumericOriginalV1, JointNumericOriginalVerificationV1,
        _decode_numeric_candidate,
    )
    candidate = _decode_numeric_candidate(numeric[0])
    raw_verification = json.loads(numeric[2])
    raw_verification["numeric_error"] = ProjectionNumericErrorV2(
        **raw_verification["numeric_error"])
    verification = JointNumericOriginalVerificationV1(**raw_verification)
    if (candidate.receipt_digest != numeric[1]
            or canonical_digest(asdict(verification)) != numeric[3]):
        raise D11EncodingContextHold("encoding numeric original digest differs")
    source_families = {row[6] for row in candidate.source_versions
                       if row[2] == read.source_ref}
    source_checkpoints = {
        member.checkpoint_ref for member in candidate.members
        if any(family.family_id in source_families
               and read.source_ref in family.source_refs
               for family in member.families)
    }
    source_members = tuple(member for member in output.members
                           if member.kind == "feeling"
                           and member.checkpoint_ref in source_checkpoints)
    feeling_refs = {member.predecessor_state_ref for member in source_members}
    feelings = tuple(item for item in versions
                     if item.key.token in feeling_refs and item.revision > 0)
    if not feelings or {item.key.token for item in feelings} != feeling_refs:
        raise D11EncodingContextHold("encoding Feeling joint members are incomplete")
    for item in feelings:
        value, event_id = _historical(db, namespace, item)
        member = next(member for member in source_members
                      if member.predecessor_state_ref == item.key.token)
        if (event_id != read.joint_operation_id
                or item.revision != member.predecessor_state_revision + 1
                or canonical_digest(value) != canonical_digest(
                    joint_state_payload_v1(member.next_state))):
            raise D11EncodingContextHold("Feeling is not the adopted joint output")
    selected_member = next((member for member in source_members
                            if member.predecessor_state_ref == feelings[0].key.token),
                           None)
    if selected_member is None:
        raise D11EncodingContextHold("encoding numeric member is absent")
    numeric_original = JointNumericOriginalV1(
        selected_member.checkpoint_ref,
        selected_member.predecessor_checkpoint_revision + 1,
        read.joint_operation_id, canonical_digest(asdict(joint_receipt)),
        candidate, verification,
    )
    if _joint_numeric(
            db, namespace, read.joint_operation_id,
            numeric_original.original_ref, numeric_original.original_revision,
            numeric_original.adoption_receipt_digest,
            canonical_digest(asdict(numeric_original))) != numeric_original:
        raise D11EncodingContextHold("encoding numeric original differs")
    return D11EncodingContextOriginalV3(
        namespace, read.encoding_operation_id, read.joint_operation_id,
        ExactRefV3(source.key.token, source.revision),
        ExactRefV3(perspective.key.token, perspective.revision),
        tuple(ExactRefV3(item.key.token, item.revision)
              for item in interpretation_versions),
        tuple(ExactRefV3(item.key.token, item.revision) for item in feelings),
        tuple(sorted(facets, key=lambda item: item.facet_id)),
        read.as_known_at, read.owner_fence_digest,
        canonical_digest(asdict(joint_receipt)),
        canonical_digest(asdict(numeric_original)), output.original_digest,
        versions, canonical_digest(versions),
        schema=("d11.c04_encoding_context_original.authored.v3"
                if output.schema == "d04.joint-state-output.v2"
                else "d11.c04_encoding_context_original.v3"),
    )


__all__ = [
    "D11EncodingContextHold", "D11EncodingContextOriginalV3",
    "MeaningFacetIssuerBindingV3", "W01EncodingGraphReadV3",
    "issue_d11_encoding_context_original_v3",
]
