"""Pure D04 semantic-to-24D drive candidate with contribution evidence.

The caller supplies appraisal meaning and bounded doses. This compiler checks
their structure and replay against sourced drive rows; it cannot establish
that the supplied appraisals, source heads, or compiler invocation are current.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction
import math

from ..domains.d04.affect import AppraisalBundle
from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from ..domains.d04.numeric_drive import SourcedNumericDrive
from ..graph_types import AtomKey
from ..memory_types import SourceRecord, access_key
from ..runtime_contracts import canonical_digest


MAPPING_VERSION = "candidate:d04-semantic-drive:1"
MECHANISMS = tuple(axis.split(":", 1)[0] for axis in REGISTERED_AXIS_IDS[::3])


class D04SemanticDriveHold(ValueError):
    """The supplied semantic shares cannot support this numeric candidate."""


@dataclass(frozen=True, slots=True)
class D04SemanticMechanismShare:
    appraisal_ref: str
    appraisal_revision: int
    appraisal: AppraisalBundle
    facet_id: str
    source_ref: str
    source_revision: int
    access_revision: int
    source: SourceRecord
    mechanism: str
    layer_doses: tuple[float, float, float]
    family_share: float


@dataclass(frozen=True, slots=True)
class D04SemanticSourceVector:
    source_ref: str
    source_revision: int
    access_revision: int
    provenance_root: str
    drive: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class D04SemanticDriveCandidate:
    checkpoint_ref: str
    checkpoint_revision: int
    role_start: float
    role_end: float
    source_vectors: tuple[D04SemanticSourceVector, ...]
    drive: tuple[float, ...]
    contribution_evidence: tuple[tuple[str, ...], ...]
    collapsed_retries: int
    transcript_sha256: str
    mapping_version: str = MAPPING_VERSION
    status: str = "candidate_hold"
    missing_authorities: tuple[str, ...] = (
        "w01_fenced_current_appraisal_source_access_and_dedup_inventory",
        "d04_authorized_semantic_dose_and_mapping_policy",
        "w01_atomic_sourced_drive_and_contribution_adoption",
    )


def _finite_unit(value: object, label: str, *, positive: bool = False) -> float:
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not (-1.0 <= value <= 1.0)
            or (positive and not 0.0 < value <= 1.0)):
        raise D04SemanticDriveHold(f"{label} must be a finite normalized value")
    return float(value)


def _validate_share(share: D04SemanticMechanismShare, checkpoint: AtomKey) -> None:
    if type(share) is not D04SemanticMechanismShare:
        raise D04SemanticDriveHold("semantic drive requires typed mechanism shares")
    if type(share.appraisal) is not AppraisalBundle or type(share.source) is not SourceRecord:
        raise D04SemanticDriveHold("semantic drive needs typed appraisal and source")
    if (type(share.appraisal_revision) is not int or share.appraisal_revision < 1
            or type(share.source_revision) is not int or share.source_revision < 1
            or type(share.access_revision) is not int or share.access_revision < 1):
        raise D04SemanticDriveHold("semantic input revisions must be positive")
    try:
        appraisal_key = AtomKey.from_token(share.appraisal_ref)
        source_key = AtomKey.from_token(share.source_ref)
    except (TypeError, ValueError) as exc:
        raise D04SemanticDriveHold("semantic input refs are invalid") from exc
    if (appraisal_key.type_name != "d04.appraisal_bundle.v1"
            or appraisal_key.owner.kind != "event"
            or appraisal_key.name != share.appraisal.appraisal_id
            or source_key.type_name != "memory.source"
            or source_key.owner.kind != "event" or source_key.name != "record"
            or source_key.owner.subject != share.source.source_id
            or any((key.owner.bot, key.owner.persona) !=
                   (checkpoint.owner.bot, checkpoint.owner.persona)
                   for key in (appraisal_key, source_key))
            or share.source_ref not in share.appraisal.source_refs
            or share.source.parent_source_ids):
        raise D04SemanticDriveHold("appraisal and independent root source do not bind")
    facets = [facet for facet in share.appraisal.meaning_facets
              if facet.facet_id == share.facet_id]
    if len(facets) != 1 or share.source_ref not in facets[0].source_refs:
        raise D04SemanticDriveHold("mechanism facet does not bind source")
    if share.mechanism not in MECHANISMS:
        raise D04SemanticDriveHold("mechanism is absent from registered 24D basis")
    if type(share.layer_doses) is not tuple or len(share.layer_doses) != 3:
        raise D04SemanticDriveHold("mechanism needs fast, residual and slow doses")
    for dose in share.layer_doses:
        _finite_unit(dose, "layer dose")
    _finite_unit(share.family_share, "family share", positive=True)


def compile_d04_semantic_drive_candidate(
    *, checkpoint_ref: str, checkpoint_revision: int,
    role_start: float, role_end: float,
    shares: tuple[D04SemanticMechanismShare, ...],
) -> D04SemanticDriveCandidate:
    """Map declared mechanisms to axes, folding retries and bounding root shares.

    One provenance root may fund several facets for one event/target/meaning
    contribution, but their shares must sum to at most one. A different root
    with the same contribution identity is ambiguous and rejected. Independent
    contributions are not merged by vector similarity or mechanism name.
    """
    try:
        checkpoint = AtomKey.from_token(checkpoint_ref)
    except (TypeError, ValueError) as exc:
        raise D04SemanticDriveHold("checkpoint ref is invalid") from exc
    if checkpoint.type_name != "d04.numeric_checkpoint.v1" or checkpoint.owner.kind != "persona":
        raise D04SemanticDriveHold("semantic drive needs a persona checkpoint")
    if (type(checkpoint_revision) is not int or checkpoint_revision < 1
            or type(role_start) not in (int, float) or not math.isfinite(role_start)
            or type(role_end) not in (int, float) or not math.isfinite(role_end)
            or role_end <= role_start or type(shares) is not tuple or not shares):
        raise D04SemanticDriveHold("semantic drive needs a bounded interval and inputs")

    unique: dict[tuple[str, str, str, str, str], D04SemanticMechanismShare] = {}
    family_roots: dict[tuple[str, str, str], str] = {}
    source_heads: dict[str, tuple[int, int, str]] = {}
    collapsed = 0
    for share in shares:
        _validate_share(share, checkpoint)
        appraisal = share.appraisal
        family = (appraisal.event_ref, appraisal.target_ref, appraisal.contribution_key)
        root = share.source.provenance_root
        if family in family_roots and family_roots[family] != root:
            raise D04SemanticDriveHold("contribution identity aliases distinct source roots")
        family_roots[family] = root
        source_head = (share.source_revision, share.access_revision, root)
        if share.source_ref in source_heads and source_heads[share.source_ref] != source_head:
            raise D04SemanticDriveHold("source head changes within one candidate")
        source_heads[share.source_ref] = source_head
        identity = (*family, share.facet_id, share.mechanism)
        prior = unique.get(identity)
        if prior is not None:
            if prior != share:
                raise D04SemanticDriveHold("same contribution has conflicting doses or provenance")
            collapsed += 1
        else:
            unique[identity] = share

    allocations: dict[tuple[str, str, str], Fraction] = {}
    per_source: dict[str, list[Fraction]] = {}
    evidence = []
    for identity, share in sorted(unique.items()):
        # Different contribution keys from one root still share one event/target dose.
        family_scope = (share.source.provenance_root, share.appraisal.event_ref,
                        share.appraisal.target_ref)
        allocations[family_scope] = (allocations.get(family_scope, Fraction(0))
                                     + Fraction(str(share.family_share)))
        if allocations[family_scope] > 1:
            raise D04SemanticDriveHold("source family contribution share exceeds one")
        vector = per_source.setdefault(share.source_ref, [Fraction(0)] * 24)
        offset = MECHANISMS.index(share.mechanism) * 3
        for layer, dose in enumerate(share.layer_doses):
            vector[offset + layer] += Fraction(str(share.family_share)) * Fraction(str(dose))
        evidence.append((*identity, share.source_ref, share.appraisal_ref,
                         canonical_digest((share.appraisal_revision, asdict(share.appraisal),
                                           share.source_revision, asdict(share.source),
                                           share.access_revision, share.layer_doses,
                                           share.family_share))))
    vectors = tuple(D04SemanticSourceVector(
        ref, *source_heads[ref], tuple(float(value) for value in per_source[ref]),
    ) for ref in sorted(per_source))
    totals = tuple(float(sum((Fraction.from_float(row.drive[index]) for row in vectors),
                             Fraction(0)))
                   for index in range(24))
    if any(not math.isfinite(value) or abs(value) > 1.0e6 for value in totals):
        raise D04SemanticDriveHold("compiled drive exceeds fixed-chain domain")
    transcript = canonical_digest({
        "schema": "d04.semantic-drive-candidate.v1", "mapping_version": MAPPING_VERSION,
        "checkpoint": (checkpoint_ref, checkpoint_revision),
        "interval": (role_start, role_end), "source_vectors": tuple(asdict(row) for row in vectors),
        "contribution_evidence": evidence,
    })
    return D04SemanticDriveCandidate(
        checkpoint_ref, checkpoint_revision, float(role_start), float(role_end),
        vectors, totals, tuple(evidence), collapsed, transcript,
    )


def verify_d04_semantic_drive_rows(
    candidate: D04SemanticDriveCandidate, drives: tuple[SourcedNumericDrive, ...],
) -> None:
    """Compare supplied graph-shaped rows to a replayable semantic candidate."""
    if type(candidate) is not D04SemanticDriveCandidate or type(drives) is not tuple:
        raise D04SemanticDriveHold("semantic replay needs typed candidate and rows")
    expected = {row.source_ref: row for row in candidate.source_vectors}
    if len(drives) != len(expected):
        raise D04SemanticDriveHold("sourced drive inventory is incomplete or repeated")
    seen = set()
    for drive in drives:
        if type(drive) is not SourcedNumericDrive or drive.source_ref not in expected:
            raise D04SemanticDriveHold("unexpected sourced drive")
        if drive.source_ref in seen:
            raise D04SemanticDriveHold("repeated sourced drive")
        seen.add(drive.source_ref)
        row = expected[drive.source_ref]
        source = AtomKey.from_token(row.source_ref)
        observed = (drive.source_revision, drive.access_ref, drive.access_revision,
                    drive.checkpoint_ref, drive.checkpoint_revision,
                    drive.role_start, drive.role_end, drive.mapping_version,
                    drive.mapping_compiler_ref, drive.drive)
        required = (row.source_revision,
                    access_key(source.owner.bot, source.owner.persona,
                               source.owner.subject).token,
                    row.access_revision, candidate.checkpoint_ref,
                    candidate.checkpoint_revision, candidate.role_start,
                    candidate.role_end, candidate.mapping_version,
                    candidate.transcript_sha256, row.drive)
        if observed != required:
            raise D04SemanticDriveHold("sourced drive differs from semantic candidate")
