"""Source-qualified expression units for D09's natural-language v2 path.

This is a content and permission candidate over a W01-supplied snapshot. It
does not authenticate the snapshot, approve a paraphrase, issue an Authority
grant, or admit delivery. D09's independent semantic review must check that
the eventual wording preserves speaker, time, polarity, uncertainty and scope.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId, canonical_digest
from . import source_correction_head_key


@dataclass(frozen=True, slots=True)
class SourceTextSpan:
    start: int
    end: int

    def __post_init__(self) -> None:
        if (type(self.start) is not int or type(self.end) is not int
                or self.start < 0 or self.end <= self.start):
            raise ValueError("source text span must be a nonempty half-open range")


@dataclass(frozen=True, slots=True)
class QualifiedExpressionRequest:
    source_ref: str
    claim_kind: str
    evidence_span: SourceTextSpan
    direct_quote_span: SourceTextSpan | None = None
    direct_quote_text: str | None = None
    negation_cue_span: SourceTextSpan | None = None

    def __post_init__(self) -> None:
        if self.claim_kind not in {"attributed_report", "confirmed_external_fact"}:
            raise ValueError("D06 expression claim kind is unsupported")
        AtomKey.from_token(self.source_ref)
        if type(self.evidence_span) is not SourceTextSpan:
            raise TypeError("D06 expression needs an evidence span")
        if (self.direct_quote_span is None) != (self.direct_quote_text is None):
            raise ValueError("direct quote text and span must be paired")
        if (self.direct_quote_span is not None
                and type(self.direct_quote_span) is not SourceTextSpan):
            raise TypeError("direct quote span must be typed")
        if (self.direct_quote_text is not None
                and (type(self.direct_quote_text) is not str or not self.direct_quote_text)):
            raise ValueError("direct quote text must be nonempty")
        if (self.negation_cue_span is not None
                and type(self.negation_cue_span) is not SourceTextSpan):
            raise TypeError("negation cue span must be typed")


@dataclass(frozen=True, slots=True)
class QualifiedExpressionUnitCandidate:
    unit_id: str
    claim_kind: str
    source_ref: str
    source_excerpt: str
    evidence_span: SourceTextSpan
    direct_quote_span: SourceTextSpan | None
    direct_quote_text: str | None
    negation_cue_span: SourceTextSpan | None
    polarity_status: str
    speaker_id: str
    occurred_at: float | None
    learned_at: float
    source_kind: str
    assertion_status: str
    attribution_required: bool
    allowed_audiences: tuple[str, ...]
    purpose: str
    lineage_source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: NamespaceEpoch
    access_epoch: int
    deletion_epoch: int
    valid_until: float
    status: str = "candidate_hold_semantic_review_and_authority"

    @property
    def qualification_digest(self) -> str:
        """Source-closure identity, independent of unrelated graph writes."""
        return self.unit_id.removeprefix("d06-qualified:")

    def assert_current(
        self, snapshot: GraphSnapshot, *, access_epoch: int,
        deletion_epoch: int, now: float,
    ) -> None:
        """Reject a changed source, permission, correction or expiry.

        W01 must repeat this under its current Authority read/admission fence.
        """
        if (type(snapshot) is not GraphSnapshot
                or snapshot.epochs != (self.graph_epoch,)
                or access_epoch != self.access_epoch
                or deletion_epoch != self.deletion_epoch
                or type(now) not in (int, float) or not math.isfinite(now)
                or now >= self.valid_until):
            raise ValueError("D06 expression qualification is stale or expired")
        for version in self.read_versions:
            atom = snapshot.get(version.key)
            if (atom is None or atom.revision != version.revision
                    or (version.revision > 0 and not atom.valid)
                    or (version.revision == 0 and atom.valid)):
                raise ValueError("D06 expression source closure changed")


def prepare_qualified_expression_unit(
    snapshot: GraphSnapshot, *, namespace: NamespaceId,
    request: QualifiedExpressionRequest, audiences: tuple[str, ...],
    access_epoch: int, deletion_epoch: int, valid_until: float,
) -> QualifiedExpressionUnitCandidate:
    """Qualify a bounded source slice without promoting reports into facts."""
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(request) is not QualifiedExpressionRequest
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any(NamespaceId.from_key(atom.key) != namespace for atom in snapshot.atoms)):
        raise ValueError("D06 expression requires one coherent namespace snapshot")
    if (type(audiences) is not tuple or not audiences
            or any(type(item) is not str or not item or item == "*" for item in audiences)
            or len(set(audiences)) != len(audiences)
            or type(access_epoch) is not int or access_epoch < 0
            or type(deletion_epoch) is not int or deletion_epoch < 0
            or type(valid_until) not in (int, float)
            or not math.isfinite(valid_until) or valid_until < 0):
        raise ValueError("D06 expression audience, barrier or expiry is invalid")
    key = AtomKey.from_token(request.source_ref)
    if key != source_key(*namespace.as_tuple, key.owner.subject):
        raise ValueError("D06 expression source is not canonical")
    proofs: dict[AtomKey, GraphVersion] = {}
    lineage: list[str] = []
    pending = [key.owner.subject]
    visited: set[str] = set()
    root_record = None
    while pending:
        source_id = pending.pop()
        if source_id in visited:
            continue
        visited.add(source_id)
        if len(visited) > 256:
            raise ValueError("D06 expression source ancestry exceeds bound")
        source = source_key(*namespace.as_tuple, source_id)
        access = access_key(*namespace.as_tuple, source_id)
        correction = source_correction_head_key(namespace, source_id)
        source_atom, access_atom, correction_atom = (
            snapshot.get(item) for item in (source, access, correction)
        )
        if (source_atom is None or access_atom is None or correction_atom is None
                or source_atom.revision < 1 or access_atom.revision < 1
                or not source_atom.valid or not access_atom.valid):
            raise ValueError("D06 expression source/access closure is incomplete")
        if correction_atom.revision != 0 or correction_atom.valid:
            raise ValueError("D06 expression source or ancestor was corrected")
        record = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        if (record.source_id != source_id or access_atom.value["source_id"] != source_id
                or access_atom.value["status"] != "active"
                or not set(audiences).issubset(record.audiences)
                or not set(audiences).issubset(access_atom.value["audiences"])
                or "expression" not in record.purposes
                or "expression" not in access_atom.value["purposes"]):
            raise PermissionError("D06 expression source or ancestor unavailable")
        proofs[source] = GraphVersion(source, source_atom.revision)
        proofs[access] = GraphVersion(access, access_atom.revision)
        proofs[correction] = GraphVersion(correction, 0)
        lineage.append(source.token)
        if source == key:
            root_record = record
        pending.extend(record.parent_source_ids)
    if root_record is None:
        raise ValueError("D06 expression source missing")
    if (request.claim_kind == "confirmed_external_fact"
            and (root_record.source_kind != "observed"
                 or root_record.assertion_status != "confirmed")):
        raise ValueError("reported or unconfirmed source cannot qualify external fact")
    if (request.claim_kind == "attributed_report"
            and root_record.source_kind not in {"reported", "observed"}):
        raise ValueError("source cannot qualify an attributed external report")
    text = root_record.text
    evidence = request.evidence_span
    if evidence.end > len(text):
        raise ValueError("D06 expression evidence span exceeds original source")
    for label, span in (("quote", request.direct_quote_span),
                        ("negation", request.negation_cue_span)):
        if span is not None and (span.start < evidence.start or span.end > evidence.end):
            raise ValueError(f"D06 expression {label} span exceeds evidence")
    if (request.direct_quote_span is not None
            and text[request.direct_quote_span.start:request.direct_quote_span.end]
            != request.direct_quote_text):
        raise ValueError("direct quote must match original source exactly")
    # A source slice proves bytes, not the meaning or scope of a negation cue.
    # D09's independent review must adjudicate the final paraphrase.
    unit_id = "d06-qualified:" + canonical_digest({
        "source_ref": key.token, "source_revision": proofs[key].revision,
        "access_revision": proofs[access_key(*namespace.as_tuple, key.owner.subject)].revision,
        "claim_kind": request.claim_kind,
        "source_excerpt": text[evidence.start:evidence.end],
        "evidence_span": (evidence.start, evidence.end),
        "quote_span": ((request.direct_quote_span.start, request.direct_quote_span.end)
                       if request.direct_quote_span is not None else None),
        "quote_text": request.direct_quote_text,
        "negation_cue_span": ((request.negation_cue_span.start,
                                request.negation_cue_span.end)
                               if request.negation_cue_span is not None else None),
        "polarity_status": ("source_cue_unreviewed" if request.negation_cue_span
                            else "unspecified_unreviewed"),
        "speaker_id": root_record.speaker_id,
        "occurred_at": root_record.occurred_at,
        "learned_at": root_record.recorded_at,
        "source_kind": root_record.source_kind,
        "assertion_status": root_record.assertion_status,
        "attribution_required": request.claim_kind == "attributed_report",
        "audiences": audiences, "purpose": "expression",
        "lineage_source_refs": lineage,
        "access_epoch": access_epoch,
        "deletion_epoch": deletion_epoch, "valid_until": float(valid_until),
        "read_versions": [(item.key.token, item.revision)
                          for item in sorted(proofs.values(),
                                             key=lambda item: item.key.token)],
    })
    return QualifiedExpressionUnitCandidate(
        unit_id, request.claim_kind, key.token, text[evidence.start:evidence.end],
        evidence, request.direct_quote_span, request.direct_quote_text,
        request.negation_cue_span,
        "source_cue_unreviewed" if request.negation_cue_span else "unspecified_unreviewed",
        root_record.speaker_id, root_record.occurred_at, root_record.recorded_at,
        root_record.source_kind, root_record.assertion_status,
        request.claim_kind == "attributed_report", audiences, "expression",
        tuple(lineage),
        tuple(proofs[item] for item in sorted(proofs, key=lambda item: item.token)),
        snapshot.epochs[0], access_epoch, deletion_epoch, float(valid_until),
    )


def recompute_qualified_expression_unit(
    snapshot: GraphSnapshot, *, namespace: NamespaceId,
    candidate: QualifiedExpressionUnitCandidate, audiences: tuple[str, ...],
    access_epoch: int, deletion_epoch: int, now: float,
) -> QualifiedExpressionUnitCandidate:
    """Rebuild the D06 qualification at W01's current authenticated read fence.

    A matching digest alone is insufficient: every typed field must still match
    the current source projection, including speaker, times and assertion scope.
    This remains a candidate, never an admission or semantic-review receipt.
    """
    if type(candidate) is not QualifiedExpressionUnitCandidate:
        raise TypeError("typed D06 expression candidate is required")
    if (type(now) not in (int, float) or not math.isfinite(now)
            or now >= candidate.valid_until):
        raise ValueError("D06 expression qualification expired")
    if audiences != candidate.allowed_audiences:
        raise PermissionError("D06 expression audience changed")
    rebuilt = prepare_qualified_expression_unit(
        snapshot, namespace=namespace,
        request=QualifiedExpressionRequest(
            candidate.source_ref, candidate.claim_kind, candidate.evidence_span,
            candidate.direct_quote_span, candidate.direct_quote_text,
            candidate.negation_cue_span,
        ),
        audiences=audiences, access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, valid_until=candidate.valid_until,
    )
    # The namespace epoch fences this read, but it is not part of the
    # source-closure identity. A plan/job write may advance it harmlessly.
    if rebuilt != replace(candidate, graph_epoch=rebuilt.graph_epoch):
        raise ValueError("D06 expression qualification changed")
    return rebuilt


__all__ = ["SourceTextSpan", "QualifiedExpressionRequest",
           "QualifiedExpressionUnitCandidate", "prepare_qualified_expression_unit",
           "recompute_qualified_expression_unit"]
