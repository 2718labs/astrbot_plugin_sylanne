"""Uncommitted semantic dose allocation for the provisional 24D D04 operator.

This module does not infer psychology from prose, qualify source evidence, or
authorize graph writes. A trusted policy compiler must supply every mechanism
signal and its versioned role-conditioned mapping before a source can produce
a numerical drive candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from .affect import AppraisalBundle
from ...native_runtime.d04_block_instances import D04BlockIdentity, D04DriveSegment
from ...native_runtime.d04_engineering_scheme import DIMENSION, LAYERS, MECHANISMS
from ...runtime_contracts import canonical_digest


KNOWN_FIELDS = frozenset({
    "responsibility_hypothesis", "controllability", "anticipated_impact",
    "relation_meaning", "self_meaning", "confidence",
})


@dataclass(frozen=True, slots=True)
class RoleCondition:
    role_ref: str
    persona_version: str
    condition_version: str
    policy_version: str

    def __post_init__(self) -> None:
        if not all((self.role_ref, self.persona_version, self.condition_version, self.policy_version)):
            raise ValueError("role condition requires explicit identity and versions")


@dataclass(frozen=True, slots=True)
class CompiledMechanismRule:
    mechanism_id: str
    layer_gains: tuple[float, float, float]
    required_known_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mechanism_id not in MECHANISMS:
            raise ValueError("rule mechanism is outside the 24D engineering scheme")
        if (len(self.layer_gains) != len(LAYERS)
                or any(not math.isfinite(gain) or gain < 0 for gain in self.layer_gains)):
            raise ValueError("layer gains must be three finite nonnegative values")
        if len(set(self.required_known_fields)) != len(self.required_known_fields):
            raise ValueError("duplicate required semantic field")
        if not set(self.required_known_fields) <= KNOWN_FIELDS:
            raise ValueError("unknown required semantic field")


@dataclass(frozen=True, slots=True)
class CompiledDrivePolicy:
    mapping_version: str
    compiler_ref: str
    condition_version: str
    policy_version: str
    max_source_dose: float
    rules: tuple[CompiledMechanismRule, ...]

    def __post_init__(self) -> None:
        if not all((self.mapping_version, self.compiler_ref, self.condition_version, self.policy_version)):
            raise ValueError("compiled mapping needs explicit provenance and versions")
        if not math.isfinite(self.max_source_dose) or self.max_source_dose <= 0:
            raise ValueError("source dose cap must be positive and finite")
        if {rule.mechanism_id for rule in self.rules} != set(MECHANISMS) or len(self.rules) != len(MECHANISMS):
            raise ValueError("compiled mapping must cover each of the eight mechanisms once")


@dataclass(frozen=True, slots=True)
class CompiledMeaningSignal:
    appraisal_id: str
    facet_id: str
    canonical_meaning_ref: str
    source_ref: str
    mechanism_id: str
    magnitude: float | None

    def __post_init__(self) -> None:
        if self.mechanism_id not in MECHANISMS:
            raise ValueError("signal mechanism is outside the 24D engineering scheme")
        if self.magnitude is not None and (
            not math.isfinite(self.magnitude) or not 0 <= self.magnitude <= 1
        ):
            raise ValueError("compiled magnitude must be in [0, 1] or explicitly unknown")


@dataclass(frozen=True, slots=True)
class HeldDrive:
    source_ref: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class SourcedDrive:
    identity: D04BlockIdentity
    segment: D04DriveSegment
    source_family: str
    content_reality: str
    appraisal_refs: tuple[str, ...]
    contribution_keys: tuple[str, ...]
    unknown_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SemanticDriveAllocation:
    drives: tuple[SourcedDrive, ...]
    held: tuple[HeldDrive, ...]
    mapping_version: str | None
    condition_version: str | None
    schema: str = "d04.semantic-drive.engineering-candidate.v1"


def allocate_semantic_drives(
    appraisals: tuple[AppraisalBundle, ...],
    signals: tuple[CompiledMeaningSignal, ...],
    *,
    role_condition: RoleCondition | None,
    policy: CompiledDrivePolicy | None,
    role_start: float,
    role_end: float,
) -> SemanticDriveAllocation:
    """Allocate a finite total dose per causal source, across all paraphrases.

    Every facet/source needs eight explicit compiled signals. Repeated signals
    for the same stable meaning and mechanism collapse to one contribution;
    conflicting repeats hold that source. Unknown inputs hold their source,
    rather than becoming a numerical zero or certain external fact. Returned
    segments are conditional inputs for D04BlockInstance, not certified states.
    """
    if (not math.isfinite(role_start) or not math.isfinite(role_end)
            or role_end <= role_start):
        raise ValueError("a finite positive role interval is required")
    if any(not isinstance(item, AppraisalBundle) for item in appraisals):
        raise TypeError("appraisals must contain AppraisalBundle values")
    if any(not isinstance(item, CompiledMeaningSignal) for item in signals):
        raise TypeError("signals must contain CompiledMeaningSignal values")
    if role_condition is None or policy is None:
        return SemanticDriveAllocation((), (HeldDrive(None, "role_condition_or_mapping_missing"),), None, None)
    if (policy.condition_version != role_condition.condition_version
            or policy.policy_version != role_condition.policy_version):
        return SemanticDriveAllocation(
            (), (HeldDrive(None, "role_condition_mapping_version_mismatch"),),
            policy.mapping_version, role_condition.condition_version,
        )

    appraisal_by_id = {item.appraisal_id: item for item in appraisals}
    if len(appraisal_by_id) != len(appraisals):
        raise ValueError("appraisal IDs must be unique within one allocation")
    rules = {rule.mechanism_id: rule for rule in policy.rules}
    rows: dict[tuple[str, str, str, str], CompiledMeaningSignal] = {}
    source_errors: dict[str, str] = {}
    for signal in signals:
        appraisal = appraisal_by_id.get(signal.appraisal_id)
        if appraisal is None:
            raise ValueError("signal references an absent appraisal")
        facet = next((item for item in appraisal.meaning_facets if item.facet_id == signal.facet_id), None)
        if facet is None:
            raise ValueError("signal references an absent facet")
        if not signal.source_ref or signal.source_ref not in facet.source_refs:
            source_errors[signal.source_ref] = "source_unresolved"
            continue
        if not signal.canonical_meaning_ref:
            source_errors[signal.source_ref] = "canonical_meaning_missing"
            continue
        key = (signal.appraisal_id, signal.facet_id, signal.source_ref, signal.mechanism_id)
        if key in rows:
            source_errors[signal.source_ref] = "duplicate_compiled_signal"
        rows[key] = signal

    # A source owns one finite dose pool even when several appraisals, objects,
    # or meanings cite it. Structural identity stays per object/meaning/source.
    by_source: dict[str, dict[tuple[str, str, str], float]] = {}
    metadata: dict[str, dict[tuple[str, str], list[AppraisalBundle]]] = {}
    unknowns: dict[str, dict[tuple[str, str], set[str]]] = {}
    realities: dict[str, set[tuple[str, str]]] = {}
    for appraisal in appraisals:
        for facet in appraisal.meaning_facets:
            for source_ref in facet.source_refs:
                realities.setdefault(source_ref, set()).add((appraisal.source_family, appraisal.content_reality))
                facet_rows = [rows.get((appraisal.appraisal_id, facet.facet_id, source_ref, name))
                              for name in MECHANISMS]
                if any(row is None for row in facet_rows):
                    source_errors.setdefault(source_ref, "compiled_signal_missing")
                    continue
                assert all(row is not None for row in facet_rows)
                meaning_refs = {row.canonical_meaning_ref for row in facet_rows}
                if len(meaning_refs) != 1:
                    source_errors.setdefault(source_ref, "canonical_meaning_inconsistent")
                    continue
                meaning_ref = next(iter(meaning_refs))
                block = (appraisal.target_ref, meaning_ref)
                metadata.setdefault(source_ref, {}).setdefault(block, []).append(appraisal)
                unknowns.setdefault(source_ref, {}).setdefault(block, set()).update(facet.unknown_fields)
                for row in facet_rows:
                    assert row is not None
                    if row.magnitude is None:
                        source_errors.setdefault(source_ref, "compiled_magnitude_unknown")
                        continue
                    rule = rules[row.mechanism_id]
                    if any(field in facet.unknown_fields for field in rule.required_known_fields):
                        source_errors.setdefault(source_ref, "required_semantic_field_unknown")
                        continue
                    # Repeated wording shares its stable causal and meaning key.
                    key = (appraisal.target_ref, meaning_ref, row.mechanism_id)
                    previous = by_source.setdefault(source_ref, {}).get(key)
                    if previous is not None and previous != row.magnitude:
                        source_errors.setdefault(source_ref, "conflicting_paraphrase")
                    by_source[source_ref][key] = row.magnitude

    drives: list[SourcedDrive] = []
    held: list[HeldDrive] = []
    duration = role_end - role_start
    for source_ref in sorted(set(by_source) | set(realities) | set(source_errors)):
        if len(realities.get(source_ref, ())) != 1:
            source_errors.setdefault(source_ref, "source_reality_inconsistent")
        if source_ref in source_errors:
            held.append(HeldDrive(source_ref, source_errors[source_ref]))
            continue
        vectors: dict[tuple[str, str], list[float]] = {}
        for (target_ref, meaning_ref, mechanism_id), magnitude in by_source[source_ref].items():
            vector = vectors.setdefault((target_ref, meaning_ref), [0.0] * DIMENSION)
            start = MECHANISMS.index(mechanism_id) * len(LAYERS)
            for layer, gain in enumerate(rules[mechanism_id].layer_gains):
                vector[start + layer] = gain * magnitude
        total = sum(abs(value) for vector in vectors.values() for value in vector)
        scale = min(1.0, policy.max_source_dose / total) if total else 1.0
        family, reality = next(iter(realities[source_ref]))
        for (target_ref, meaning_ref), vector in sorted(vectors.items()):
            identity = D04BlockIdentity(role_condition.role_ref, target_ref, meaning_ref, source_ref)
            appraisals_for_block = metadata[source_ref][(target_ref, meaning_ref)]
            drive = tuple(value * scale / duration for value in vector)
            drive_ref = "d04:drive:" + canonical_digest({
                "role": role_condition.role_ref,
                "persona_version": role_condition.persona_version,
                "condition_version": role_condition.condition_version,
                "policy_version": policy.policy_version,
                "mapping_version": policy.mapping_version,
                "source": source_ref,
                "object": target_ref,
                "meaning": meaning_ref,
                "interval": (role_start, role_end),
                "drive": drive,
            })
            segment = D04DriveSegment(
                drive_ref, role_start, role_end, drive,
            )
            drives.append(SourcedDrive(
                identity, segment, family, reality,
                tuple(sorted({item.appraisal_id for item in appraisals_for_block})),
                tuple(sorted({item.contribution_key for item in appraisals_for_block})),
                tuple(sorted(unknowns[source_ref][(target_ref, meaning_ref)])),
            ))
    return SemanticDriveAllocation(
        tuple(drives), tuple(held), policy.mapping_version, role_condition.condition_version,
    )
