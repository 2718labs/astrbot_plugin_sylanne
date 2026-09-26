"""D06 memory-domain proposals for the alpha1 runtime.

The adapter in this package is deliberately side-effect free.  It qualifies
inputs and prepares typed candidates for the shared runtime; it never treats a
candidate as a committed memory, performs deletion itself, or creates a second
memory database.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import math
from typing import Mapping

from ...memory_types import (
    SourceRecord, association_key, episode_key, interpretation_key,
    register_memory_types, source_key,
    subjective_trace_key, subjective_trace_v2_key, validate_episode,
    validate_subjective_trace, validate_subjective_trace_v2,
)
from ...memory_types import access_key, validate_access, validate_association
from ...memory_types import InterpretationRecord, SourceRecord
from ...memory_retrieval import MemoryBatch
from ...graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from ...runtime_contracts import (
    CommandEnvelope,
    DependencySet,
    DomainBundle,
    DomainProposal,
    NamespaceId,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    SourceQualification,
    schema_hash,
)
from .source_grant import SourceGrantRead, provide_source_grant_check


_PURPOSES = frozenset({"context", "expression", "consolidation", "audit"})
_SOURCE_KINDS = frozenset({"observed", "reported", "authored", "internal", "simulated"})
_REALITIES = frozenset({"observed", "reported", "authored", "simulated", "inferred", "unknown"})
_EVIDENCE_ELIGIBILITY = frozenset({"external_fact", "reported_claim", "subjective_only", "none"})
_ACTUALITIES = frozenset({"committed", "candidate", "not_applicable"})
_D06_PROPOSAL_SCHEMA = "d06.contract.v1"
_D06_PROPOSAL_SCHEMA_HASH = schema_hash({
    "schema": _D06_PROPOSAL_SCHEMA,
    "proposal": "memory-domain-writes",
    "runtime": "sylanne.runtime.v1",
})
_RECOLLECTION_TYPE = "d06.recollection.v1"
_RECOLLECTION_FIELDS = frozenset({
    "recollection_id", "activity_id", "selection_ref", "candidate_set_id",
    "content_refs", "activity_basis_refs", "now_interpretation_refs",
    "feeling_experience_refs", "self_understanding_refs",
    "provenance_eligibility", "focus_epoch", "access_epoch", "delete_epoch",
})
_RECOLLECTION_SCHEMA_HASH = schema_hash({
    "type": _RECOLLECTION_TYPE,
    "version": 1,
    "owner_kinds": ("activity",),
    "storage_role": "source",
    "fields": sorted(_RECOLLECTION_FIELDS),
})
_RECOLLECTION_PROJECTION_TYPE = "d06.recollection_projection.v1"
_RECOLLECTION_PROJECTION_FIELDS = frozenset({
    "projection_id", "activity_id", "recollection_ref", "experience_ref",
    "source_ref", "source_revision", "mood_ref", "mood_revision",
    "coupling_version", "projection_version", "state",
    "evidence_eligibility", "details", "subjective_weight",
    "subjective_tone", "duration_interval", "encoding_trace_ref",
    "baseline_status",
})
_RECOLLECTION_PROJECTION_SCHEMA_HASH = schema_hash({
    "type": _RECOLLECTION_PROJECTION_TYPE,
    "version": 1,
    "owner_kinds": ("activity",),
    "storage_role": "source",
    "fields": sorted(_RECOLLECTION_PROJECTION_FIELDS),
})
_WORKBENCH_VIEW = "d06.memory_sources.v1"
_WORKBENCH_FIELDS = frozenset({"sources", "coverage"})
_WORKBENCH_TYPES = ("memory.source", "memory.access", "memory.interpretation")


def _nonempty(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _names(value: object, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{label} must not be empty")
    for item in value:
        _nonempty(item, f"{label} item")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must contain unique values")
    return value


def _finite(value: object, label: str, *, minimum: float = 0.0) -> float:
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    if value < minimum:
        raise ValueError(f"{label} must be at least {minimum}")
    return float(value)


def _optional_time(value: object, label: str) -> None:
    if value is not None:
        _finite(value, label)


def _stable_id(prefix: str, value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]}"


def _json_names(value: object, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not list:
        raise TypeError(f"{label} must be a JSON array")
    result = tuple(value)
    return _names(result, label, allow_empty=allow_empty)


def _validate_recollection(value: object) -> None:
    if type(value) is not dict:
        raise TypeError("recollection must be a JSON object")
    if frozenset(value) != _RECOLLECTION_FIELDS:
        raise ValueError("recollection fields must match the registered schema exactly")
    for name in ("recollection_id", "activity_id", "selection_ref", "candidate_set_id"):
        _nonempty(value[name], name)
    for name in (
        "content_refs", "activity_basis_refs", "now_interpretation_refs",
        "feeling_experience_refs", "self_understanding_refs", "provenance_eligibility",
    ):
        _json_names(
            value[name], name,
            allow_empty=name not in {"content_refs", "activity_basis_refs", "now_interpretation_refs", "feeling_experience_refs"},
        )
    for name in ("focus_epoch", "access_epoch", "delete_epoch"):
        if type(value[name]) is not int or isinstance(value[name], bool) or value[name] < 0:
            raise ValueError(f"{name} must be a nonnegative integer")


def _validate_recollection_projection(value: object) -> None:
    if type(value) is not dict or frozenset(value) != _RECOLLECTION_PROJECTION_FIELDS:
        raise ValueError("recollection projection fields must match the registered schema exactly")
    for name in ("projection_id", "activity_id", "coupling_version", "projection_version"):
        _nonempty(value[name], name)
    for name in ("recollection_ref", "experience_ref", "source_ref", "mood_ref"):
        token = _nonempty(value[name], name)
        AtomKey.from_token(token)
    for name in ("source_revision", "mood_revision"):
        if type(value[name]) is not int or isinstance(value[name], bool) or value[name] <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if value["state"] != "committed_subjective_projection":
        raise ValueError("projection state must reflect C04 adoption")
    if value["evidence_eligibility"] != "subjective_only":
        raise ValueError("projection cannot qualify external evidence")
    if type(value["details"]) is not list:
        raise TypeError("details must be a JSON array")
    seen = set()
    detail_fields = {"detail_id", "state", "source_ref", "source_span",
                     "interpretation_ref", "subjective_salience", "subjective_accessibility"}
    for detail in value["details"]:
        if type(detail) is not dict or set(detail) != detail_fields:
            raise ValueError("projection detail fields must match the registered schema exactly")
        detail_id = _nonempty(detail["detail_id"], "detail_id")
        if detail_id in seen:
            raise ValueError("projection detail IDs must be unique")
        seen.add(detail_id)
        _nonempty(detail["state"], "detail state")
        for name in ("source_ref", "interpretation_ref"):
            ref = detail[name]
            if ref is not None:
                AtomKey.from_token(_nonempty(ref, name))
        span = detail["source_span"]
        if span is not None and (type(span) is not list or len(span) != 2
                                 or any(type(x) is not int or x < 0 for x in span)
                                 or span[1] <= span[0]):
            raise ValueError("source_span must be a nonempty half-open range or null")
        for name in ("subjective_salience", "subjective_accessibility"):
            interval = detail[name]
            if interval is not None and (type(interval) is not list or len(interval) != 2
                                         or any(type(x) not in (int, float) or isinstance(x, bool)
                                                or not math.isfinite(x) or not 0 <= x <= 1 for x in interval)
                                         or interval[1] < interval[0]):
                raise ValueError(f"{name} must be a bounded interval or null")
    for name in ("subjective_weight", "subjective_tone", "duration_interval"):
        interval = value[name]
        if interval is not None and (type(interval) is not list or len(interval) != 2
                                     or any(type(x) not in (int, float) or isinstance(x, bool)
                                            or not math.isfinite(x) for x in interval)
                                     or interval[1] < interval[0]):
            raise ValueError(f"{name} must be a finite ordered interval or null")
    for name in ("encoding_trace_ref", "baseline_status"):
        if value[name] is not None:
            _nonempty(value[name], name)


def _canonical_graph_refs(
    value: object, label: str, namespace: NamespaceId, *, allow_empty: bool = True,
) -> tuple[str, ...]:
    refs = _names(value, label, allow_empty=allow_empty)
    keys = []
    for ref in refs:
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} item must be a canonical graph atom token") from exc
        if NamespaceId.from_key(key) != namespace:
            raise ValueError(f"{label} item would cross namespace")
        keys.append(key.token)
    return tuple(sorted(keys))


class TriggerKind(Enum):
    EXPLICIT_PAST_REQUEST = "explicit_past_request"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    CORRECTION_OR_CONFLICT = "correction_or_conflict"
    COMMITMENT_EXECUTION = "commitment_execution"
    REPAIR_BASIS = "repair_basis"
    TIME_OR_ACTIVITY_STATUS = "time_or_activity_status"
    OPTIONAL_ASSOCIATION = "optional_association"


_MANDATORY_TRIGGERS = frozenset({
    TriggerKind.EXPLICIT_PAST_REQUEST,
    TriggerKind.UNRESOLVED_REFERENCE,
    TriggerKind.CORRECTION_OR_CONFLICT,
    TriggerKind.COMMITMENT_EXECUTION,
    TriggerKind.REPAIR_BASIS,
    TriggerKind.TIME_OR_ACTIVITY_STATUS,
})


@dataclass(frozen=True)
class RecallIntent:
    request_id: str
    trigger: TriggerKind | None = None
    rationale: str | None = None
    greeting_only: bool = False
    working_set_refs: tuple[str, ...] = ()
    trigger_policy_version: str = "d06.trigger.v1"

    def __post_init__(self) -> None:
        _nonempty(self.request_id, "request_id")
        if self.trigger is not None and type(self.trigger) is not TriggerKind:
            raise TypeError("trigger must be TriggerKind or None")
        if self.trigger is not None:
            _nonempty(self.rationale, "rationale")
        elif self.rationale is not None:
            raise ValueError("rationale requires a trigger")
        if type(self.greeting_only) is not bool:
            raise TypeError("greeting_only must be bool")
        _names(self.working_set_refs, "working_set_refs")
        _nonempty(self.trigger_policy_version, "trigger_policy_version")


@dataclass(frozen=True)
class RecallQualification:
    request_id: str
    mode: str
    trigger: TriggerKind | None
    rationale: str | None
    trigger_policy_version: str
    working_set_refs: tuple[str, ...]


@dataclass(frozen=True)
class SourceAdmission:
    source_id: str
    text: str
    speaker_id: str
    source_kind: str
    content_reality: str
    evidence_eligibility: str
    internal_activity_actuality: str
    occurred_at: float | None
    learned_at: float
    provenance_family: str
    audiences: tuple[str, ...]
    purposes: tuple[str, ...]
    parent_source_ids: tuple[str, ...] = ()
    subjective_confidence: float | None = None

    def __post_init__(self) -> None:
        _nonempty(self.source_id, "source_id")
        _nonempty(self.text, "text")
        _nonempty(self.speaker_id, "speaker_id")
        if self.source_kind not in _SOURCE_KINDS:
            raise ValueError("unknown source_kind")
        if self.content_reality not in _REALITIES:
            raise ValueError("unknown content_reality")
        if self.evidence_eligibility not in _EVIDENCE_ELIGIBILITY:
            raise ValueError("unknown evidence_eligibility")
        if (self.source_kind in {"authored", "simulated", "internal"}
                and self.evidence_eligibility in {"external_fact", "reported_claim"}):
            raise ValueError("authored/simulated/internal sources cannot qualify as external evidence")
        if self.internal_activity_actuality not in _ACTUALITIES:
            raise ValueError("unknown internal_activity_actuality")
        _optional_time(self.occurred_at, "occurred_at")
        _finite(self.learned_at, "learned_at")
        _nonempty(self.provenance_family, "provenance_family")
        _names(self.audiences, "audiences", allow_empty=False)
        if "*" in self.audiences:
            raise ValueError("audiences must not contain a wildcard")
        _names(self.purposes, "purposes", allow_empty=False)
        if not set(self.purposes).issubset(_PURPOSES):
            raise ValueError("unknown purpose")
        _names(self.parent_source_ids, "parent_source_ids")
        if self.subjective_confidence is not None:
            confidence = _finite(self.subjective_confidence, "subjective_confidence")
            if confidence > 1:
                raise ValueError("subjective_confidence must be at most 1")
        if self.content_reality in {"authored", "simulated", "inferred", "unknown"} and self.evidence_eligibility == "external_fact":
            raise ValueError("non-observed content cannot qualify as external fact")


@dataclass(frozen=True)
class SourceAdmissionProposal:
    source: SourceRecord
    qualification: SourceQualification
    encoding_pending: bool = True
    status: str = "proposal"


@dataclass(frozen=True)
class EncodingContext:
    event_ref: str
    perspective_ref: str
    then_feeling_refs: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    detail_weights: tuple[tuple[str, float], ...]
    read_versions: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        _nonempty(self.event_ref, "event_ref")
        _nonempty(self.perspective_ref, "perspective_ref")
        _names(self.then_feeling_refs, "then_feeling_refs")
        _names(self.interpretation_refs, "interpretation_refs")
        seen = set()
        for detail, weight in self.detail_weights:
            _nonempty(detail, "detail")
            if detail in seen:
                raise ValueError("detail_weights must have unique details")
            seen.add(detail)
            value = _finite(weight, "detail weight")
            if value > 1:
                raise ValueError("detail weight must be at most 1")
        for ref, version in self.read_versions:
            _nonempty(ref, "read version ref")
            if type(version) is not int or isinstance(version, bool) or version < 0:
                raise ValueError("read version must be a nonnegative integer")


@dataclass(frozen=True)
class MemoryEpisodeCandidate:
    episode_id: str
    source_refs: tuple[str, ...]
    event_ref: str


@dataclass(frozen=True)
class SubjectiveTraceCandidate:
    trace_id: str
    episode_ref: str
    perspective_ref: str
    then_feeling_refs: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    detail_weights: tuple[tuple[str, float], ...]


@dataclass(frozen=True)
class EncodingProposal:
    episode: MemoryEpisodeCandidate
    trace: SubjectiveTraceCandidate
    read_versions: tuple[tuple[str, int], ...]
    status: str = "proposal"


@dataclass(frozen=True)
class CandidateItem:
    candidate_id: str
    content_ref: str
    provenance_family: str
    trigger_reason: str
    allowed_purposes: tuple[str, ...]
    activation: float
    provenance_eligibility: str

    def __post_init__(self) -> None:
        for field in ("candidate_id", "content_ref", "provenance_family", "trigger_reason", "provenance_eligibility"):
            _nonempty(getattr(self, field), field)
        _names(self.allowed_purposes, "allowed_purposes", allow_empty=False)
        if not set(self.allowed_purposes).issubset(_PURPOSES):
            raise ValueError("unknown candidate purpose")
        activation = _finite(self.activation, "activation")
        if activation > 1:
            raise ValueError("activation must be at most 1")


@dataclass(frozen=True)
class CandidateSet:
    candidate_set_id: str
    items: tuple[CandidateItem, ...]
    coverage: str
    continuation: str | None = None
    access_epoch: int | None = None
    delete_epoch: int | None = None

    def __post_init__(self) -> None:
        _nonempty(self.candidate_set_id, "candidate_set_id")
        if type(self.items) is not tuple or any(not isinstance(item, CandidateItem) for item in self.items):
            raise TypeError("items must be a tuple of CandidateItem")
        ids = tuple(item.candidate_id for item in self.items)
        if len(set(ids)) != len(ids):
            raise ValueError("candidate IDs must be unique")
        if self.coverage not in {"complete", "partial", "unavailable"}:
            raise ValueError("unknown coverage")
        if self.continuation is not None:
            _nonempty(self.continuation, "continuation")
        if self.coverage == "complete" and self.continuation is not None:
            raise ValueError("complete candidate set cannot have a continuation")
        for value, label in ((self.access_epoch, "access_epoch"), (self.delete_epoch, "delete_epoch")):
            if value is not None and (type(value) is not int or isinstance(value, bool) or value < 0):
                raise ValueError(f"{label} must be a nonnegative integer or None")


@dataclass(frozen=True)
class RetrievalChannel:
    name: str
    batch: MemoryBatch
    activation: float

    def __post_init__(self) -> None:
        _nonempty(self.name, "name")
        if not isinstance(self.batch, MemoryBatch):
            raise TypeError("batch must be MemoryBatch")
        activation = _finite(self.activation, "activation")
        if activation > 1:
            raise ValueError("activation must be at most 1")


@dataclass(frozen=True)
class SelectionTicket:
    ticket_id: str
    activity_id: str
    candidate_set_id: str
    selected_candidate_ids: tuple[str, ...]
    focus_epoch: int

    def __post_init__(self) -> None:
        _nonempty(self.ticket_id, "ticket_id")
        _nonempty(self.activity_id, "activity_id")
        _nonempty(self.candidate_set_id, "candidate_set_id")
        _names(self.selected_candidate_ids, "selected_candidate_ids", allow_empty=False)
        if type(self.focus_epoch) is not int or isinstance(self.focus_epoch, bool) or self.focus_epoch < 0:
            raise ValueError("focus_epoch must be a nonnegative integer")


@dataclass(frozen=True)
class RecollectionContext:
    now_interpretation_refs: tuple[str, ...]
    feeling_experience_refs: tuple[str, ...]
    self_understanding_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _names(self.now_interpretation_refs, "now_interpretation_refs")
        _names(self.feeling_experience_refs, "feeling_experience_refs")
        _names(self.self_understanding_refs, "self_understanding_refs")


@dataclass(frozen=True)
class RecollectionProposal:
    recollection_id: str
    activity_id: str
    selection_ref: str
    content_refs: tuple[str, ...]
    activity_basis_refs: tuple[str, ...]
    now_interpretation_refs: tuple[str, ...]
    feeling_experience_refs: tuple[str, ...]
    self_understanding_refs: tuple[str, ...]
    provenance_eligibility: tuple[str, ...]
    status: str = "proposal"


@dataclass(frozen=True)
class CorrectionRequest:
    request_id: str
    target_refs: tuple[str, ...]
    basis_source_refs: tuple[str, ...]
    replacement_claim: str
    access_epoch: int
    deletion_epoch: int


@dataclass(frozen=True)
class SourceCorrectionReadSetV1:
    """Values from W01's fenced graph read; this DTO is not a read proof."""

    sources: tuple[SourceRecord, ...]
    accesses: tuple[Mapping[str, object], ...]
    interpretations: tuple[InterpretationRecord, ...]
    d07_belief_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (type(self.sources) is not tuple or not self.sources
                or any(type(item) is not SourceRecord for item in self.sources)):
            raise ValueError("correction requires typed source reads")
        if (type(self.accesses) is not tuple or len(self.accesses) != len(self.sources)
                or any(not isinstance(item, Mapping) for item in self.accesses)):
            raise ValueError("correction requires paired source access reads")
        for item in self.accesses:
            validate_access(dict(item))
        if (type(self.interpretations) is not tuple or not self.interpretations
                or any(type(item) is not InterpretationRecord for item in self.interpretations)):
            raise ValueError("correction requires typed interpretation reads")
        _names(self.d07_belief_refs, "d07_belief_refs")


@dataclass(frozen=True)
class SourceCorrectionCandidateV1:
    """D06 writes and cross-domain obligations, pending W01 atomic adoption."""

    proposal: DomainProposal
    correction_source_ref: str
    invalidated_target_refs: tuple[str, ...]
    d07_invalidation_refs: tuple[str, ...]
    required_reevaluation_domains: tuple[str, ...] = ("d07", "d04", "d05")
    status: str = "proposal_requires_w01_atomic_bundle"

    def __post_init__(self) -> None:
        if (type(self.proposal) is not DomainProposal or self.proposal.domain != "d06"
                or self.status != "proposal_requires_w01_atomic_bundle"):
            raise ValueError("source correction cannot claim a commit")
        AtomKey.from_token(self.correction_source_ref)
        _names(self.invalidated_target_refs, "invalidated_target_refs", allow_empty=False)
        _names(self.d07_invalidation_refs, "d07_invalidation_refs")
        if self.required_reevaluation_domains != ("d07", "d04", "d05"):
            raise ValueError("source correction requires domain reevaluation")


@dataclass(frozen=True)
class ErasureRequest:
    request_id: str
    target_refs: tuple[str, ...]
    scope: str
    access_epoch: int
    deletion_epoch: int


@dataclass(frozen=True)
class DeletionClosureCandidate:
    """D06's version-bound semantic closure proposal for a C07 deletion.

    ``closure_id`` identifies these exact inputs for a trusted Authority issuer;
    it is never proof that a barrier was installed or that deletion was accepted.
    """

    closure_id: str
    request_id: str
    namespace: NamespaceId
    root_refs: tuple[str, ...]
    scope: str
    access_epoch_before: int
    delete_epoch_before: int
    current_dependency_refs: tuple[str, ...]
    historical_source_refs: tuple[str, ...]
    association_refs: tuple[str, ...]
    graph_cache_refs: tuple[str, ...]
    status: str = "proposal_requires_authority_v2"

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if self.status != "proposal_requires_authority_v2":
            raise ValueError("deletion closure cannot claim an Authority phase")


@dataclass(frozen=True)
class TransferRequest:
    transfer_id: str
    source_refs: tuple[str, ...]
    destination_namespace: str
    transfer_grant_ref: str
    source_access_epoch: int
    source_deletion_epoch: int


@dataclass(frozen=True)
class RuntimeMutationPlan:
    operation_id: str
    operation: str
    target_refs: tuple[str, ...]
    required_bundle_parts: tuple[str, ...]
    guards: tuple[tuple[str, int | str], ...]
    status: str = "pending_runtime_authority"


class D06DomainProvider:
    """Catalogue-level D06 provider used by production registry discovery.

    The provider validates D06-owned graph writes. Namespace-bound preparation
    remains on :class:`D06DomainAdapter`; neither object grants commit authority.
    """

    @staticmethod
    def provide_required_check(intent, read: SourceGrantRead, *, valid_until: float):
        return provide_source_grant_check(intent, read, valid_until=valid_until)

    @property
    def workbench_view_contract(self):
        # A v2 context carries coordinator-issued proof that all internal
        # pages were read under one Owner lease, fence, and graph epoch.
        return {
            _WORKBENCH_VIEW: {
                "types": _WORKBENCH_TYPES,
                "fields": _WORKBENCH_FIELDS,
                "projection_context": "d12.projection_context.v2",
            },
        }

    @staticmethod
    def project_workbench(view_type, atoms, *, context):
        from ...workbench_api.domain_registry import PROJECTION_CONTEXT_V2, ProjectionContextV2
        from ...graph_coordinator import verify_complete_projection_snapshot_v1

        if view_type != _WORKBENCH_VIEW or not isinstance(context, ProjectionContextV2):
            raise ValueError("unsupported D06 workbench projection context")
        if (context.schema_version != PROJECTION_CONTEXT_V2
                or not verify_complete_projection_snapshot_v1(
                    context.snapshot_proof, authority=context.authority,
                    view_type=view_type, type_names=_WORKBENCH_TYPES,
                    owner_kind="event", audience=context.audience,
                    purpose=context.purpose)):
            raise ValueError("complete fenced snapshot proof is unavailable")

        sources = {}
        accesses = {}
        interpretations = {}
        for atom in atoms:
            key_token = atom.get("key")
            if not isinstance(key_token, str):
                raise ValueError("D06 projection requires canonical atom identity")
            key = AtomKey.from_token(key_token)
            if ((key.owner.bot, key.owner.persona) != context.authority.namespace.as_tuple
                    or key.owner.kind != "event"):
                raise ValueError("D06 projection atom identity crosses authority scope")
            atom_type = atom.get("type")
            value = atom.get("value")
            if key.type_name != atom_type:
                raise ValueError("D06 projection atom identity/type mismatch")
            if atom_type == "memory.source":
                record = SourceRecord.from_dict(value)
                if key.owner.subject != record.source_id or key.name != "record":
                    raise ValueError("D06 source identity does not match graph key")
                sources[record.source_id] = record
            elif atom_type == "memory.access":
                validate_access(value)
                source_id = value["source_id"]
                if key.owner.subject != source_id or key.name != "access":
                    raise ValueError("D06 access identity does not match graph key")
                if source_id in accesses:
                    raise ValueError("duplicate D06 source access state")
                accesses[source_id] = value
            elif atom_type == "memory.interpretation":
                record = InterpretationRecord.from_dict(value)
                if key.owner.subject != record.interpretation_id or key.name != "current":
                    raise ValueError("D06 interpretation identity does not match graph key")
                interpretations[record.interpretation_id] = record
            else:
                raise ValueError("D06 projection input contains an undeclared type")
        retracted_sources = {
            source_id
            for interpretation in interpretations.values()
            if interpretation.status == "retracted"
            for source_id in interpretation.source_ids
            if source_id in sources
        }

        projected = []
        for source_id, source in sorted(sources.items()):
            access = accesses.get(source_id)
            if (access is None or access["status"] != "active"
                    or source_id in retracted_sources):
                continue
            if (context.audience not in source.audiences
                    or context.purpose not in source.purposes
                    or context.audience not in access["audiences"]
                    or context.purpose not in access["purposes"]):
                continue
            # SourceRecord has no evidence-eligibility field. Expose only
            # source metadata; do not infer a qualification from its status.
            projected.append({
                "source_id": source.source_id,
                "source_kind": source.source_kind,
                "assertion_status": source.assertion_status,
                "recorded_at": source.recorded_at,
                "qualification": "not_recorded",
            })
        return {"sources": projected, "coverage": "complete"}

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d06.memory",
            contract_version=RUNTIME_SCHEMA,
            request_schema_hash=_D06_PROPOSAL_SCHEMA_HASH,
            response_schema_hash=schema_hash({"domain": "d06", "memory": 1}),
            owner_capabilities=("event", "activity"),
            supported_modalities=("structured", "text"),
            supported_purposes=tuple(sorted(_PURPOSES)),
            supported_platforms=("runtime",),
            timeout_mode="bounded",
            cancellation_mode="cooperative",
            idempotency_mode="operation_id_and_activity_id",
            cost_reporting_mode="d11_receipt",
            health_capabilities=("validate", "qualify_source", "assemble_recollection"),
            recovery_capabilities=("invalidate", "resume_retrieval"),
        )

    @staticmethod
    def type_specs() -> tuple[TypeSpec, ...]:
        registry = TypeRegistry()
        register_memory_types(registry)
        specs = list(registry.specs)
        specs.append(TypeSpec(
            _RECOLLECTION_TYPE,
            ("activity",),
            "source",
            _validate_recollection,
            immutable=True,
            writer_domain="d06",
            schema_hash=_RECOLLECTION_SCHEMA_HASH,
        ))
        specs.append(TypeSpec(
            _RECOLLECTION_PROJECTION_TYPE,
            ("activity",),
            "source",
            _validate_recollection_projection,
            immutable=True,
            writer_domain="d06",
            schema_hash=_RECOLLECTION_PROJECTION_SCHEMA_HASH,
        ))
        return tuple(sorted(specs, key=lambda item: item.name))

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d06" or proposal.proposal_schema != _D06_PROPOSAL_SCHEMA:
            raise ValueError("proposal is not a D06 memory proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("D06 proposal schema hash is not recognized")
        registry = TypeRegistry()
        for spec in self.type_specs():
            registry.register(spec)
        for write in proposal.typed_writes:
            spec = registry.spec(write.key.type_name)
            if spec.writer_domain != "d06":
                raise ValueError("D06 proposal contains a non-D06 graph write")
            registry.validate(write.key, write.value)
        projections = [write for write in proposal.typed_writes
                       if write.key.type_name == _RECOLLECTION_PROJECTION_TYPE]
        if projections:
            recollections = [write for write in proposal.typed_writes
                             if write.key.type_name == _RECOLLECTION_TYPE]
            if len(projections) != 1 or len(recollections) != 1:
                raise ValueError("C04 projection must accompany exactly one recollection")
            projection, recollection = projections[0], recollections[0]
            projection_source = AtomKey.from_token(projection.value["source_ref"])
            if (projection.value["recollection_ref"] != recollection.key.token
                    or projection.value["activity_id"] != recollection.value["activity_id"]
                    or projection_source.owner.subject not in recollection.value["content_refs"]
                    or projection_source.type_name != "memory.source"
                    or NamespaceId.from_key(projection_source)
                    != proposal.envelope.authority.namespace
                    or projection.key.owner != recollection.key.owner):
                raise ValueError("C04 projection differs from its persisted recollection")
        trace_types = {"memory.subjective_trace.v1", "memory.subjective_trace.v2"}
        encoding = {write.key.type_name: write for write in proposal.typed_writes
                    if write.key.type_name in {"memory.episode.v1", *trace_types}}
        if encoding:
            traces = trace_types.intersection(encoding)
            if (len(proposal.typed_writes) != 2
                    or "memory.episode.v1" not in encoding or len(traces) != 1):
                raise ValueError("C02 must include exactly one episode and one trace")
            episode = encoding["memory.episode.v1"]
            trace = encoding[next(iter(traces))]
            self_mapping = ()
            if trace.key.type_name == "memory.subjective_trace.v2":
                from ..d03.self_perspective import self_mapping_key
                perspective = AtomKey.from_token(trace.value["perspective_ref"])
                if (perspective.type_name != "d03.self_perspective.v1"
                        or perspective.owner.kind != "persona"):
                    raise ValueError("C02 v2 requires the D03 self perspective")
                self_mapping = (self_mapping_key(proposal.envelope.authority.namespace),)
            source_refs = tuple(AtomKey.from_token(token) for token in episode.value["source_refs"])
            if (len(source_refs) != 1
                    or proposal.envelope.source_qualification.source_refs != (source_refs[0].token,)
                    or trace.value["episode_ref"] != episode.key.token):
                raise ValueError("C02 episode, trace and qualified source do not agree")
            source = source_refs[0]
            access = access_key(source.owner.bot, source.owner.persona, source.owner.subject)
            required = (source, access, *self_mapping, *(AtomKey.from_token(token) for token in (
                episode.value["event_ref"], trace.value["perspective_ref"],
                *trace.value["then_feeling_refs"], *trace.value["interpretation_refs"],
                *((trace.value["encoding_baseline_ref"],)
                  if trace.key.type_name == "memory.subjective_trace.v2" else ()),
            )))
            reads = {ref.key: ref for ref in proposal.envelope.version_guard.read_versions}
            historical = set(proposal.dependencies.historical_provenance)
            if (len(reads) != len(proposal.envelope.version_guard.read_versions)
                    or any(reads.get(key) is None or reads[key].revision <= 0
                           or reads[key] not in historical for key in required)
                    or any(reads.get(write.key) != GraphVersion(write.key, 0)
                           or write.dependencies for write in (episode, trace))):
                raise ValueError("C02 lacks complete committed provenance or absence proofs")
        associations = tuple(write for write in proposal.typed_writes
                             if write.key.type_name == "memory.association.v1")
        if associations:
            if len(proposal.typed_writes) != 1:
                raise ValueError("association proposal must contain exactly one association")
            write = associations[0]
            source = AtomKey.from_token(write.value["source_ref"])
            refs = (source, AtomKey.from_token(write.value["target_ref"]),
                    *(AtomKey.from_token(ref) for ref in write.value["basis_source_refs"]))
            if write.key != association_key(source.owner.bot, source.owner.persona,
                                            source.owner.subject, write.value["association_id"]):
                raise ValueError("association key does not match its directed source")
            reads = {ref.key: ref for ref in proposal.envelope.version_guard.read_versions}
            historical = set(proposal.dependencies.historical_provenance)
            required = tuple(dict.fromkeys((key for ref in refs for key in (
                ref, access_key(ref.owner.bot, ref.owner.persona, ref.owner.subject),
            ))))
            if (len(reads) != len(proposal.envelope.version_guard.read_versions)
                    or reads.get(write.key) != GraphVersion(write.key, 0)
                    or write.dependencies
                    or any(reads.get(key) is None or reads[key].revision <= 0
                           or reads[key] not in historical for key in required)
                    or not set(ref.token for ref in refs).issubset(
                        proposal.envelope.source_qualification.source_refs)):
                raise ValueError("association lacks qualified source, access, or absence proofs")
        return proposal


class D06DomainAdapter:
    """Prepare D06 proposals without bypassing the shared runtime authority."""

    def __init__(self, namespace: NamespaceId):
        if not isinstance(namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        self.namespace = namespace

    def association_identity(
        self,
        source_id: str,
        target_id: str,
        basis_source_ids: tuple[str, ...],
        *,
        kind: str,
        context_tags: tuple[str, ...] = (),
        content_reality: str = "subjective",
    ) -> AtomKey:
        """Provide the stable key needed for a graph absence read before compile."""
        source = source_key(*self.namespace.as_tuple, source_id)
        target = source_key(*self.namespace.as_tuple, target_id)
        basis = tuple(source_key(*self.namespace.as_tuple, item) for item in basis_source_ids)
        association_id = _stable_id("association", {
            "source": source.token, "target": target.token,
            "basis": tuple(key.token for key in basis), "kind": kind,
            "context_tags": context_tags, "content_reality": content_reality,
        })
        key = association_key(*self.namespace.as_tuple, source_id, association_id)
        validate_association({
            "association_id": association_id, "source_ref": source.token,
            "target_ref": target.token, "kind": kind, "weight": 0.0,
            "context_tags": list(context_tags),
            "basis_source_refs": [item.token for item in basis],
            "content_reality": content_reality,
        })
        return key

    def compile_association(
        self,
        envelope: CommandEnvelope,
        prepared: object,
        *,
        kind: str,
        weight: float,
        context_tags: tuple[str, ...] = (),
        content_reality: str = "subjective",
    ) -> DomainProposal:
        """Build one source-traceable directed edge for the shared graph."""
        from .pipeline import PreparedAssociation

        if not isinstance(envelope, CommandEnvelope) or not isinstance(prepared, PreparedAssociation):
            raise TypeError("association needs an envelope and prepared source reads")
        if envelope.authority.namespace != self.namespace or envelope.authority.issuer_domain != "d06":
            raise ValueError("association authority differs from D06 namespace")
        if prepared.status != "candidate" or (prepared.epoch.bot, prepared.epoch.persona) != self.namespace.as_tuple:
            raise ValueError("association preparation is invalid for this namespace")
        guarded = {version.key: version for version in envelope.version_guard.read_versions}
        if any(guarded.get(version.key) != version for version in prepared.proof_versions):
            raise ValueError("association source reads differ from envelope guard")
        source = source_key(*self.namespace.as_tuple, prepared.source_ref)
        target = source_key(*self.namespace.as_tuple, prepared.target_ref)
        basis = tuple(source_key(*self.namespace.as_tuple, source_id)
                      for source_id in prepared.basis_source_refs)
        source_refs = tuple(dict.fromkeys((source, target, *basis)))
        if not set(key.token for key in source_refs).issubset(envelope.source_qualification.source_refs):
            raise ValueError("association sources are absent from qualification")
        key = self.association_identity(
            prepared.source_ref, prepared.target_ref, prepared.basis_source_refs,
            kind=kind, context_tags=context_tags, content_reality=content_reality,
        )
        association_id = key.name
        if guarded.get(key) != GraphVersion(key, 0):
            raise ValueError("association requires a revision-0 graph absence proof")
        value = {
            "association_id": association_id,
            "source_ref": source.token,
            "target_ref": target.token,
            "kind": kind,
            "weight": weight,
            "context_tags": list(context_tags),
            "basis_source_refs": [key.token for key in basis],
            "content_reality": content_reality,
        }
        validate_association(value)
        return self.wrap_runtime_proposal(
            envelope,
            typed_writes=(GraphWrite(key, value),),
            dependencies=DependencySet(historical_provenance=prepared.proof_versions),
            contribution_keys=(f"association:{key.token}",),
            required_bundle_parts=(),
        )

    def qualify_recall(self, intent: RecallIntent) -> RecallQualification:
        if not isinstance(intent, RecallIntent):
            raise TypeError("intent must be RecallIntent")
        if intent.trigger in _MANDATORY_TRIGGERS:
            mode = "mandatory"
        elif intent.trigger is TriggerKind.OPTIONAL_ASSOCIATION:
            mode = "optional_association"
        elif intent.working_set_refs:
            mode = "working_set_only"
        else:
            mode = "no_history_search"
        return RecallQualification(
            intent.request_id,
            mode,
            intent.trigger,
            intent.rationale,
            intent.trigger_policy_version,
            intent.working_set_refs,
        )

    def admit_source(self, request: SourceAdmission) -> SourceAdmissionProposal:
        if not isinstance(request, SourceAdmission):
            raise TypeError("request must be SourceAdmission")
        assertion_status = {
            "external_fact": "confirmed",
            "reported_claim": "reported",
            "subjective_only": "unknown",
            "none": "unknown",
        }[request.evidence_eligibility]
        source = SourceRecord(
            source_id=request.source_id,
            text=request.text,
            speaker_id=request.speaker_id,
            source_kind=request.source_kind,
            assertion_status=assertion_status,
            occurred_at=request.occurred_at,
            recorded_at=request.learned_at,
            provenance_root=request.provenance_family,
            audiences=request.audiences,
            purposes=request.purposes,
            parent_source_ids=request.parent_source_ids,
            independence="unknown",
        )
        source_family = {
            "observed": "observed",
            "reported": "reported",
            "authored": "authored",
            "simulated": "simulated",
            "internal": "derived",
        }[request.source_kind]
        content_reality = {
            "observed": "external_observation",
            "reported": "external_report",
            "authored": "authored_content",
            "simulated": "simulation",
            "inferred": "inference",
            "unknown": "unknown",
        }[request.content_reality]
        evidence_eligibility = {
            "external_fact": "eligible",
            "reported_claim": "qualified",
            "subjective_only": "ineligible",
            "none": "ineligible",
        }[request.evidence_eligibility]
        actuality = {
            "committed": "actual",
            "candidate": "unknown",
            "not_applicable": "not_applicable",
        }[request.internal_activity_actuality]
        qualification = SourceQualification(
            source_refs=(source_key(
                self.namespace.bot_id,
                self.namespace.persona_id,
                request.source_id,
            ).token,),
            source_family=source_family,
            occurred_at=request.occurred_at,
            learned_at=request.learned_at,
            content_reality=content_reality,
            evidence_eligibility=evidence_eligibility,
            subjective_confidence=request.subjective_confidence,
            internal_activity_actuality=actuality,
        )
        return SourceAdmissionProposal(source, qualification)

    def assemble_candidates(
        self,
        candidate_set_id: str,
        channels: tuple[RetrievalChannel, ...],
        *,
        purpose: str,
        max_candidates: int = 64,
        access_epoch: int | None = None,
        delete_epoch: int | None = None,
    ) -> CandidateSet:
        _nonempty(candidate_set_id, "candidate_set_id")
        if purpose not in _PURPOSES:
            raise ValueError("unknown purpose")
        if type(channels) is not tuple or any(not isinstance(channel, RetrievalChannel) for channel in channels):
            raise TypeError("channels must be a tuple of RetrievalChannel")
        if type(max_candidates) is not int or isinstance(max_candidates, bool) or not 1 <= max_candidates <= 64:
            raise ValueError("max_candidates must be an integer from 1 to 64")
        for value, label in ((access_epoch, "access_epoch"), (delete_epoch, "delete_epoch")):
            if value is not None and (type(value) is not int or isinstance(value, bool) or value < 0):
                raise ValueError(f"{label} must be a nonnegative integer or None")
        if (access_epoch is None) != (delete_epoch is None):
            raise ValueError("access and deletion epochs must be captured together")
        if channels:
            epochs = {channel.batch.epoch for channel in channels}
            if len(epochs) != 1:
                raise ValueError("retrieval channels must share one namespace epoch")
            epoch = next(iter(epochs))
            if (epoch.bot, epoch.persona) != self.namespace.as_tuple:
                raise ValueError("retrieval channel namespace differs from D06 adapter")

        by_content: dict[str, CandidateItem] = {}
        continuation_tokens: list[str] = []
        partial = False
        truncated = False
        for channel in channels:
            batch = channel.batch
            if not batch.complete:
                partial = True
            if batch.continuation is not None:
                continuation_tokens.append(batch.continuation.token)
            for hit in batch.hits:
                for source in hit.sources:
                    if purpose not in source.purposes:
                        continue
                    eligibility = {
                        "observed": "observed",
                        "reported": "reported",
                        "authored": "authored",
                        "simulated": "simulated",
                        "internal": "internal",
                    }[source.source_kind]
                    item = CandidateItem(
                        _stable_id("candidate", {
                            "content_ref": source.source_id,
                            "family": source.provenance_root,
                        }),
                        source.source_id,
                        source.provenance_root,
                        channel.name,
                        (purpose,),
                        channel.activation,
                        eligibility,
                    )
                    previous = by_content.get(source.source_id)
                    if previous is None:
                        if len(by_content) >= max_candidates:
                            truncated = True
                            continue
                        by_content[source.source_id] = item
                    elif previous.provenance_family != item.provenance_family:
                        raise ValueError("same content_ref has conflicting provenance families")
                    elif item.activation > previous.activation:
                        by_content[source.source_id] = CandidateItem(
                            previous.candidate_id,
                            previous.content_ref,
                            previous.provenance_family,
                            previous.trigger_reason,
                            previous.allowed_purposes,
                            item.activation,
                            previous.provenance_eligibility,
                        )
        coverage = "partial" if partial or truncated else "complete"
        continuation = None
        if coverage == "partial":
            continuation = _stable_id("frontier", {
                "set": candidate_set_id,
                "tokens": continuation_tokens,
                "truncated": truncated,
            })
        return CandidateSet(
            candidate_set_id, tuple(by_content.values()), coverage, continuation,
            access_epoch, delete_epoch,
        )

    def prepare_encoding(self, source_ref: str, context: EncodingContext) -> EncodingProposal:
        _nonempty(source_ref, "source_ref")
        if not isinstance(context, EncodingContext):
            raise TypeError("context must be EncodingContext")
        episode_id = _stable_id("episode", {
            "source_ref": source_ref, "event_ref": context.event_ref,
            "read_versions": context.read_versions,
        })
        trace_id = _stable_id("trace", {
            "episode_id": episode_id,
            "perspective_ref": context.perspective_ref,
            "then_feeling_refs": context.then_feeling_refs,
            "interpretation_refs": context.interpretation_refs,
            "details": context.detail_weights,
        })
        return EncodingProposal(
            MemoryEpisodeCandidate(episode_id, (source_ref,), context.event_ref),
            SubjectiveTraceCandidate(
                trace_id,
                episode_id,
                context.perspective_ref,
                context.then_feeling_refs,
                context.interpretation_refs,
                context.detail_weights,
            ),
            context.read_versions,
        )

    def compile_encoding(self, envelope: CommandEnvelope, prepared: object) -> DomainProposal:
        return self._compile_encoding(envelope, prepared, encoding_baseline_ref=None)

    def compile_encoding_v2(
        self, envelope: CommandEnvelope, prepared: object, *, encoding_baseline_ref: str,
    ) -> DomainProposal:
        """Compile C02 with D04 baseline and a committed D03 self perspective.

        A sender entity or scene binding cannot stand in for the role's self.
        The legacy unversioned compiler remains for historical fixture data.
        """
        return self._compile_encoding(
            envelope, prepared, encoding_baseline_ref=encoding_baseline_ref,
        )

    def _compile_encoding(
        self, envelope: CommandEnvelope, prepared: object, *,
        encoding_baseline_ref: str | None,
    ) -> DomainProposal:
        """Compile a proof-bound C02 candidate; only GraphCoordinator may admit it."""
        from .pipeline import PreparedEncoding

        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if not isinstance(prepared, PreparedEncoding) or prepared.status != "candidate":
            raise TypeError("prepared must be a D06 candidate encoding")
        if envelope.authority.issuer_domain != "d06" or envelope.authority.namespace != self.namespace:
            raise ValueError("C02 requires D06 authority in the encoding namespace")
        if (prepared.epoch.bot, prepared.epoch.persona) != self.namespace.as_tuple:
            raise ValueError("prepared encoding crosses namespace")
        proposal = prepared.proposal
        if proposal.status != "proposal" or proposal.episode.source_refs != (prepared.source_ref,):
            raise ValueError("encoding proposal does not match the authorized source")
        if proposal.trace.episode_ref != proposal.episode.episode_id:
            raise ValueError("subjective trace does not name the proposed episode")
        source = source_key(*self.namespace.as_tuple, prepared.source_ref)
        access = access_key(*self.namespace.as_tuple, prepared.source_ref)
        if (envelope.source_qualification.source_refs != (source.token,)
                or source.token not in envelope.input_refs):
            raise ValueError("C02 envelope does not qualify the source")
        guarded = {version.key: version for version in envelope.version_guard.read_versions}
        proof = {version.key: version for version in prepared.proof_versions}
        if (len(guarded) != len(envelope.version_guard.read_versions)
                or len(proof) != len(prepared.proof_versions)):
            raise ValueError("C02 read proofs must not repeat keys")
        if source not in proof or access not in proof:
            raise ValueError("C02 requires committed source and access proofs")
        if any(version.revision <= 0 or guarded.get(key) != version
               for key, version in proof.items()):
            raise ValueError("C02 source proof differs from guarded committed versions")

        def graph_ref(token: str, label: str, allowed_types: frozenset[str]) -> AtomKey:
            key = AtomKey.from_token(token)
            if (NamespaceId.from_key(key) != self.namespace
                    or key.type_name not in allowed_types):
                raise ValueError(f"{label} is not an allowed same-namespace graph reference")
            if key not in guarded or guarded[key].revision <= 0:
                raise ValueError(f"{label} lacks a committed read proof")
            return key

        event = graph_ref(proposal.episode.event_ref, "event_ref", frozenset({"d03.world_event"}))
        perspective_types = (frozenset({"d03.self_perspective.v1"})
                             if encoding_baseline_ref is not None else
                             frozenset({"d03.role_binding", "d03.entity_anchor"}))
        perspective = graph_ref(proposal.trace.perspective_ref,
                                "perspective_ref", perspective_types)
        if encoding_baseline_ref is not None and perspective.owner.kind != "persona":
            raise ValueError("C02 self perspective must be persona-owned")
        mapping = None
        if encoding_baseline_ref is not None:
            from ..d03.self_perspective import self_mapping_key
            mapping = graph_ref(self_mapping_key(self.namespace).token,
                                "self_mapping_ref",
                                frozenset({"d03.self_identity_mapping.v1"}))
        feelings = tuple(graph_ref(
            ref, "then_feeling_ref", frozenset({"d04.feeling_state.v1", "d04.appraisal_bundle.v1"})
        )
                         for ref in proposal.trace.then_feeling_refs)
        interpretations = tuple(graph_ref(
            ref, "interpretation_ref",
            frozenset({"d07.current_interpretation.v1", "d07.belief_revision.v1"}),
        )
                                for ref in proposal.trace.interpretation_refs)
        baseline = (graph_ref(
            encoding_baseline_ref, "encoding_baseline_ref",
            frozenset({"d04.encoding_baseline.v1"}),
        ) if encoding_baseline_ref is not None else None)
        required = (source, event, perspective,
                    *((mapping,) if mapping is not None else ()),
                    *feelings, *interpretations,
                    *((baseline,) if baseline is not None else ()))
        context_versions: dict[AtomKey, int] = {}
        for ref, revision in proposal.read_versions:
            key = source if ref in {prepared.source_ref, source.token} else AtomKey.from_token(ref)
            if key in context_versions or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("encoding read_versions repeat or cross namespace")
            context_versions[key] = revision
            if guarded.get(key) != GraphVersion(key, revision) or revision <= 0:
                raise ValueError("encoding read_versions differ from committed guard")
        if not set(required).issubset(context_versions):
            raise ValueError("encoding context lacks required read_versions")

        episode = episode_key(*self.namespace.as_tuple, proposal.episode.episode_id)
        trace = (subjective_trace_v2_key if baseline is not None else subjective_trace_key)(
            *self.namespace.as_tuple, proposal.trace.trace_id,
        )
        if (guarded.get(episode) != GraphVersion(episode, 0)
                or guarded.get(trace) != GraphVersion(trace, 0)):
            raise ValueError("C02 requires revision-0 episode and trace proofs")
        episode_value = {
            "episode_id": proposal.episode.episode_id,
            "source_refs": [source.token],
            "event_ref": event.token,
        }
        trace_value = {
            "trace_id": proposal.trace.trace_id,
            "episode_ref": episode.token,
            "perspective_ref": perspective.token,
            "then_feeling_refs": [key.token for key in feelings],
            "interpretation_refs": [key.token for key in interpretations],
            "detail_weights": [[detail, float(weight)] for detail, weight in proposal.trace.detail_weights],
        }
        if baseline is not None:
            trace_value["encoding_baseline_ref"] = baseline.token
        validate_episode(episode_value)
        (validate_subjective_trace_v2 if baseline is not None else validate_subjective_trace)(trace_value)
        writes = (
            GraphWrite(episode, episode_value),
            GraphWrite(trace, trace_value),
        )
        historical = tuple(dict.fromkeys((
            *prepared.proof_versions,
            *(guarded[key] for key in (event, perspective,
                                      *((mapping,) if mapping is not None else ()),
                                      *feelings, *interpretations,
                                      *((baseline,) if baseline is not None else ()))),
        )))
        return self.wrap_runtime_proposal(
            envelope,
            typed_writes=writes,
            dependencies=DependencySet(
                historical_provenance=historical,
            ),
            contribution_keys=(f"encoding:{trace.token}",),
            required_bundle_parts=(),
        )

    def wrap_runtime_proposal(
        self,
        envelope: CommandEnvelope,
        *,
        typed_writes: tuple,
        dependencies: DependencySet,
        contribution_keys: tuple[str, ...],
        required_bundle_parts: tuple[str, ...],
    ) -> DomainProposal:
        """Wrap already-compiled D06 graph writes in the common P0 contract.

        Constructing this value does not authenticate the opaque capability or
        confer commit authority; W01 must validate it at the bundle boundary.
        """
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if envelope.authority.issuer_domain != "d06":
            raise ValueError("D06 proposal requires a d06 issuer_domain")
        if envelope.authority.namespace != self.namespace:
            raise ValueError("proposal namespace differs from D06 adapter")
        if not isinstance(dependencies, DependencySet):
            raise TypeError("dependencies must be DependencySet")
        return DomainProposal(
            "d06",
            _D06_PROPOSAL_SCHEMA,
            _D06_PROPOSAL_SCHEMA_HASH,
            envelope,
            typed_writes,
            dependencies,
            contribution_keys,
            required_bundle_parts,
        )

    def compile_source_ingress(
        self,
        envelope: CommandEnvelope,
        request: SourceAdmission,
    ) -> DomainProposal:
        """Compile the D06 half of C01 for W01's atomic bundle coordinator.

        W01/D11 must still add the referenced persistent job, outbox and
        idempotency receipt to the same bundle before it can commit.
        """
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        admitted = self.admit_source(request)
        if envelope.source_qualification != admitted.qualification:
            raise ValueError("envelope source qualification differs from admission")
        if envelope.authority.namespace != self.namespace:
            raise ValueError("source ingress namespace differs from D06 adapter")
        if envelope.authority.purpose not in request.purposes:
            raise ValueError("source access does not cover command purpose")
        if not set(envelope.authority.audience).issubset(request.audiences):
            raise ValueError("source access does not cover command audience")

        source = source_key(
            self.namespace.bot_id, self.namespace.persona_id, request.source_id
        )
        access = access_key(
            self.namespace.bot_id, self.namespace.persona_id, request.source_id
        )
        read_versions = {item.key: item.revision for item in envelope.version_guard.read_versions}
        if read_versions.get(source) != 0 or read_versions.get(access) != 0:
            raise ValueError("first source ingress requires source and access revision-0 proofs")
        if source.token not in envelope.input_refs:
            raise ValueError("source token must be an envelope input_ref")

        historical = []
        for parent_id in request.parent_source_ids:
            parent_source = source_key(
                self.namespace.bot_id, self.namespace.persona_id, parent_id
            )
            parent_access = access_key(
                self.namespace.bot_id, self.namespace.persona_id, parent_id
            )
            for key in (parent_source, parent_access):
                revision = read_versions.get(key)
                if revision is None or revision <= 0:
                    raise ValueError("parent source and access require positive read proofs")
                historical.append(next(
                    version for version in envelope.version_guard.read_versions
                    if version.key == key
                ))

        access_value = {
            "source_id": request.source_id,
            "audiences": list(request.audiences),
            "purposes": list(request.purposes),
            "status": "active",
            "recorded_at": request.learned_at,
        }
        validate_access(access_value)
        writes = (
            GraphWrite(source, admitted.source.to_dict()),
            GraphWrite(access, access_value, (source,)),
        )
        source_absence_proof = next(
            version for version in envelope.version_guard.read_versions
            if version.key == source
        )
        return self.wrap_runtime_proposal(
            envelope,
            typed_writes=writes,
            dependencies=DependencySet(
                current_invalidation=(source_absence_proof,),
                historical_provenance=tuple(historical),
            ),
            contribution_keys=(f"source-ingress:{source.token}",),
            required_bundle_parts=("persistent_job", "outbox"),
        )

    def prepare_recollection(
        self,
        ticket: SelectionTicket,
        candidates: CandidateSet,
        context: RecollectionContext,
    ) -> RecollectionProposal:
        if not isinstance(ticket, SelectionTicket):
            raise TypeError("ticket must be SelectionTicket")
        if not isinstance(candidates, CandidateSet):
            raise TypeError("candidates must be CandidateSet")
        if not isinstance(context, RecollectionContext):
            raise TypeError("context must be RecollectionContext")
        if ticket.candidate_set_id != candidates.candidate_set_id:
            raise ValueError("selection ticket does not name the candidate set")
        by_id = {item.candidate_id: item for item in candidates.items}
        missing = [item for item in ticket.selected_candidate_ids if item not in by_id]
        if missing:
            raise ValueError(f"selection contains unknown candidates: {missing!r}")
        selected = tuple(by_id[item] for item in ticket.selected_candidate_ids)
        content_refs = tuple(dict.fromkeys(item.content_ref for item in selected))
        eligibility = tuple(dict.fromkeys(item.provenance_eligibility for item in selected))
        recollection_id = _stable_id("recollection", {
            "activity_id": ticket.activity_id,
            "selection_ref": ticket.ticket_id,
            "content_refs": content_refs,
            "focus_epoch": ticket.focus_epoch,
        })
        return RecollectionProposal(
            recollection_id,
            ticket.activity_id,
            ticket.ticket_id,
            content_refs,
            (ticket.ticket_id, candidates.candidate_set_id),
            context.now_interpretation_refs,
            context.feeling_experience_refs,
            context.self_understanding_refs,
            eligibility,
        )

    def recollection_write(
        self,
        proposal: RecollectionProposal,
        *,
        candidate_set_id: str,
        focus_epoch: int,
        access_epoch: int,
        delete_epoch: int,
    ) -> GraphWrite:
        if not isinstance(proposal, RecollectionProposal):
            raise TypeError("proposal must be RecollectionProposal")
        _nonempty(candidate_set_id, "candidate_set_id")
        self._epochs(access_epoch, delete_epoch)
        if type(focus_epoch) is not int or isinstance(focus_epoch, bool) or focus_epoch < 0:
            raise ValueError("focus_epoch must be a nonnegative integer")
        owner = Owner(
            "activity", self.namespace.bot_id, self.namespace.persona_id,
            proposal.activity_id,
        )
        value = {
            "recollection_id": proposal.recollection_id,
            "activity_id": proposal.activity_id,
            "selection_ref": proposal.selection_ref,
            "candidate_set_id": candidate_set_id,
            "content_refs": list(proposal.content_refs),
            "activity_basis_refs": list(proposal.activity_basis_refs),
            "now_interpretation_refs": list(proposal.now_interpretation_refs),
            "feeling_experience_refs": list(proposal.feeling_experience_refs),
            "self_understanding_refs": list(proposal.self_understanding_refs),
            "provenance_eligibility": list(proposal.provenance_eligibility),
            "focus_epoch": focus_epoch,
            "access_epoch": access_epoch,
            "delete_epoch": delete_epoch,
        }
        _validate_recollection(value)
        return GraphWrite(
            AtomKey(owner, _RECOLLECTION_TYPE, proposal.recollection_id),
            value,
        )

    def recollection_projection_write(self, reconstruction, experience_write: GraphWrite) -> GraphWrite:
        """Persist a source-bounded subjective projection adopted by this C04 bundle."""
        if experience_write.key.type_name != "d04.recollection_experience.v1":
            raise ValueError("projection requires its D04 recollection experience write")
        experience = experience_write.value
        if (experience.get("recollection_ref") != AtomKey(
                Owner("activity", *self.namespace.as_tuple, reconstruction.activity_id),
                _RECOLLECTION_TYPE, reconstruction.recollection_id).token
                or experience.get("memory_ref") != reconstruction.source_ref
                or tuple(experience.get("salience_interval", ())) != reconstruction.subjective_weight
                or tuple(experience.get("tone_interval", ())) != reconstruction.subjective_tone
                or experience.get("evidence_weight_delta") != 0.0):
            raise ValueError("D04 official experience does not certify this subjective projection")
        versions = {version.key: version for version in reconstruction.read_versions}
        source_key_value = AtomKey.from_token(reconstruction.source_ref)
        mood_key_value = AtomKey.from_token(reconstruction.mood_ref)
        source_version, mood_version = versions.get(source_key_value), versions.get(mood_key_value)
        if source_version is None or mood_version is None:
            raise ValueError("projection requires guarded source and mood versions")
        details = []
        for detail in reconstruction.subjective_details:
            details.append({
                "detail_id": detail.detail_id,
                "state": detail.state,
                "source_ref": detail.source_ref,
                "source_span": list(detail.source_span) if detail.source_span is not None else None,
                "interpretation_ref": detail.interpretation_ref,
                "subjective_salience": list(detail.subjective_salience),
                "subjective_accessibility": (list(detail.subjective_accessibility)
                                             if detail.subjective_accessibility is not None else None),
            })
        projection_id = _stable_id("projection", (
            reconstruction.recollection_id, experience_write.key.token,
            source_version.revision, mood_version.revision, reconstruction.coupling_version,
        ))
        value = {
            "projection_id": projection_id,
            "activity_id": reconstruction.activity_id,
            "recollection_ref": experience["recollection_ref"],
            "experience_ref": experience_write.key.token,
            "source_ref": reconstruction.source_ref,
            "source_revision": source_version.revision,
            "mood_ref": reconstruction.mood_ref,
            "mood_revision": mood_version.revision,
            "coupling_version": reconstruction.coupling_version,
            "projection_version": "d06.affective_projection.v1",
            "state": "committed_subjective_projection",
            "evidence_eligibility": "subjective_only",
            "details": details,
            "subjective_weight": list(experience["salience_interval"]),
            "subjective_tone": list(experience["tone_interval"]),
            "duration_interval": (list(reconstruction.subjective_duration_interval_v1)
                                  if reconstruction.subjective_duration_interval_v1 is not None else None),
            "encoding_trace_ref": reconstruction.encoding_trace_ref,
            "baseline_status": reconstruction.then_feeling_status,
        }
        _validate_recollection_projection(value)
        return GraphWrite(
            AtomKey(Owner("activity", *self.namespace.as_tuple, reconstruction.activity_id),
                    _RECOLLECTION_PROJECTION_TYPE, projection_id),
            value,
        )

    def assemble_recollection_bundle(
        self,
        envelope: CommandEnvelope,
        ticket: SelectionTicket,
        candidates: CandidateSet,
        context: RecollectionContext,
        *,
        supporting_proposals: tuple[DomainProposal, ...],
        choice_ref: str,
        d02_settlement_ref: str,
        d11_cost_settlement_ref: str,
        persistent_job_ref: str,
        outbox_ref: str,
    ) -> DomainBundle:
        """Build the complete C04 candidate without committing or claiming recall.

        The coordinator remains responsible for provider validation, capability
        checks, locked epoch revalidation and commit receipt creation.
        """
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if envelope.authority.namespace != self.namespace:
            raise ValueError("recollection namespace differs from D06 adapter")
        if envelope.identity.activity_id != getattr(ticket, "activity_id", None):
            raise ValueError("selection ticket activity differs from operation activity")
        proposal = self.prepare_recollection(ticket, candidates, context)
        if candidates.access_epoch is None or candidates.delete_epoch is None:
            raise ValueError("candidate set lacks access/deletion epoch capture")
        if (
            candidates.access_epoch != envelope.version_guard.access_epoch
            or candidates.delete_epoch != envelope.version_guard.delete_epoch
        ):
            raise ValueError("candidate set authorization epochs are stale")
        if ticket.ticket_id not in envelope.input_refs or candidates.candidate_set_id not in envelope.input_refs:
            raise ValueError("ticket and candidate set must be bound into envelope input_refs")
        if not any(
            item.version == ticket.focus_epoch
            for item in envelope.version_guard.focus_lease_versions
        ):
            raise ValueError("selection ticket focus epoch is not guarded")
        if not context.now_interpretation_refs:
            raise ValueError("C04 requires the current D07 interpretation candidate")
        if not context.feeling_experience_refs:
            raise ValueError("C04 requires the current D04 feeling candidate")

        selected = {
            item.candidate_id: item for item in candidates.items
            if item.candidate_id in ticket.selected_candidate_ids
        }
        source_keys = tuple(
            source_key(self.namespace.bot_id, self.namespace.persona_id, selected[item].content_ref)
            for item in ticket.selected_candidate_ids
        )
        access_keys = tuple(
            access_key(self.namespace.bot_id, self.namespace.persona_id, selected[item].content_ref)
            for item in ticket.selected_candidate_ids
        )
        read_map = {item.key: item for item in envelope.version_guard.read_versions}
        dependencies = []
        for source, access in zip(source_keys, access_keys):
            if source.token not in envelope.source_qualification.source_refs:
                raise ValueError("selected candidate source is absent from source qualification")
            for key in (source, access):
                version = read_map.get(key)
                if version is None or version.revision <= 0:
                    raise ValueError("selected source and access require positive read proofs")
                dependencies.append(version)

        if type(supporting_proposals) is not tuple or any(
            not isinstance(item, DomainProposal) for item in supporting_proposals
        ):
            raise TypeError("supporting_proposals must be a tuple of DomainProposal")
        if any(item.envelope != envelope for item in supporting_proposals):
            raise ValueError("C04 supporting proposals must share the exact envelope")
        by_domain = {item.domain: item for item in supporting_proposals}
        if len(by_domain) != len(supporting_proposals):
            raise ValueError("C04 accepts exactly one proposal from each supporting domain")
        required_domains = {"d07", "d04", "d02", "d11"}
        if set(by_domain) != required_domains:
            missing = sorted(required_domains - set(by_domain))
            extra = sorted(set(by_domain) - required_domains)
            raise ValueError(f"C04 supporting domains are incomplete (missing={missing!r}, extra={extra!r})")

        for ref, label in (
            (choice_ref, "choice_ref"),
            (d02_settlement_ref, "d02_settlement_ref"),
            (d11_cost_settlement_ref, "d11_cost_settlement_ref"),
            (persistent_job_ref, "persistent_job_ref"),
            (outbox_ref, "outbox_ref"),
        ):
            _nonempty(ref, label)
            AtomKey.from_token(ref)
        if AtomKey.from_token(persistent_job_ref).type_name != "runtime.job":
            raise ValueError("persistent_job_ref must reference runtime.job")

        tokens_by_domain = {
            domain: {write.key.token for write in domain_proposal.typed_writes}
            for domain, domain_proposal in by_domain.items()
        }
        required_tokens = {
            "d07": {choice_ref, *context.now_interpretation_refs},
            "d04": {*context.feeling_experience_refs, *context.self_understanding_refs},
            "d02": {d02_settlement_ref},
            "d11": {d11_cost_settlement_ref, persistent_job_ref, outbox_ref},
        }
        for domain, refs in required_tokens.items():
            absent = refs - tokens_by_domain[domain]
            if absent:
                raise ValueError(f"{domain} proposal does not materialize required C04 refs: {sorted(absent)!r}")

        choice_write = next(
            write for write in by_domain["d07"].typed_writes if write.key.token == choice_ref
        )
        choice = choice_write.value
        expected_choice = {
            "ticket_id": ticket.ticket_id,
            "activity_id": ticket.activity_id,
            "candidate_set_id": ticket.candidate_set_id,
            "selected_candidate_ids": list(ticket.selected_candidate_ids),
            "focus_epoch": ticket.focus_epoch,
        }
        if any(choice.get(name) != value for name, value in expected_choice.items()):
            raise ValueError("D07 choice write does not encode this SelectionTicket")

        recollection_write = self.recollection_write(
            proposal,
            candidate_set_id=candidates.candidate_set_id,
            focus_epoch=ticket.focus_epoch,
            access_epoch=candidates.access_epoch,
            delete_epoch=candidates.delete_epoch,
        )
        feeling_writes = {
            write.key.token: write
            for write in by_domain["d04"].typed_writes
            if write.key.type_name == "d04.recollection_experience.v1"
        }
        for ref in context.feeling_experience_refs:
            feeling_write = feeling_writes.get(ref)
            if (
                feeling_write is not None
                and feeling_write.value.get("recollection_ref") != recollection_write.key.token
            ):
                raise ValueError("D04 feeling write does not reference this recollection")
        d06_proposal = self.wrap_runtime_proposal(
            envelope,
            typed_writes=(recollection_write,),
            dependencies=DependencySet(historical_provenance=tuple(dependencies)),
            contribution_keys=(f"recollection-activity:{ticket.activity_id}",),
            required_bundle_parts=(
                "experience", "choice", "d02_settlement", "cost_settlement",
                "persistent_job", "outbox",
            ),
        )
        return DomainBundle(
            envelope,
            (d06_proposal, *supporting_proposals),
            (recollection_write.key.token,),
            (choice_ref,),
            (d02_settlement_ref,),
            (d11_cost_settlement_ref,),
            (f"d06:c04:{ticket.activity_id}",),
            (persistent_job_ref,),
            (outbox_ref,),
        )

    def plan_correction(self, request: CorrectionRequest) -> RuntimeMutationPlan:
        self._validate_correction(request)
        return RuntimeMutationPlan(
            request.request_id,
            "revise_or_consolidate",
            request.target_refs,
            ("invalidate_current_interpretation", "replacement_proposal", "domain_reevaluation_outbox"),
            (("access_epoch", request.access_epoch), ("deletion_epoch", request.deletion_epoch)),
        )

    def correction_source_key(self, request: CorrectionRequest) -> AtomKey:
        """Stable absence-read target for one correction operation."""
        self._validate_correction(request)
        source_id = _stable_id("source-correction", {
            "namespace": self.namespace.as_tuple, "operation_id": request.request_id,
        })
        return source_key(*self.namespace.as_tuple, source_id)

    def compile_source_correction(
        self, envelope: CommandEnvelope, request: CorrectionRequest,
        reads: SourceCorrectionReadSetV1, *, recorded_at: float,
    ) -> SourceCorrectionCandidateV1:
        """Prepare one reported correction and D06 interpretation retractions.

        W01 must independently bind these values to a current fenced read,
        verify D07's own invalidation proposal, and commit a persistent job and
        reevaluation outbox with the D06 proposal. No write occurs here.
        """
        self._validate_correction(request)
        if type(envelope) is not CommandEnvelope or type(reads) is not SourceCorrectionReadSetV1:
            raise TypeError("correction requires an envelope and typed graph reads")
        if (envelope.authority.namespace != self.namespace
                or envelope.authority.issuer_domain != "d06"
                or envelope.identity.operation_id != request.request_id
                or envelope.identity.phase != "source-correction"
                or envelope.version_guard.access_epoch != request.access_epoch
                or envelope.version_guard.delete_epoch != request.deletion_epoch):
            raise ValueError("correction envelope does not match the operation and epochs")
        recorded_at = _finite(recorded_at, "recorded_at")
        basis = _canonical_graph_refs(request.basis_source_refs, "basis_source_refs",
                                      self.namespace, allow_empty=False)
        targets = _canonical_graph_refs(request.target_refs, "target_refs",
                                        self.namespace, allow_empty=False)
        basis_keys = tuple(AtomKey.from_token(ref) for ref in basis)
        target_keys = tuple(AtomKey.from_token(ref) for ref in targets)
        if (any(key.type_name != "memory.source" or key.name != "record"
                or key.owner.kind != "event" for key in basis_keys)
                or any(key.type_name != "memory.interpretation" or key.name != "current"
                       or key.owner.kind != "event" for key in target_keys)):
            raise ValueError("correction requires D06 source and interpretation refs")
        if (tuple(source_key(*self.namespace.as_tuple, item.source_id).token
                  for item in reads.sources) != basis
                or tuple(interpretation_key(*self.namespace.as_tuple, item.interpretation_id).token
                         for item in reads.interpretations) != targets):
            raise ValueError("correction read values differ from selected graph refs")
        for source, access in zip(reads.sources, reads.accesses):
            access = dict(access)
            if (access["source_id"] != source.source_id or access["status"] != "active"
                    or not set(envelope.authority.audience).issubset(source.audiences)
                    or not set(envelope.authority.audience).issubset(access["audiences"])
                    or envelope.authority.purpose not in source.purposes
                    or envelope.authority.purpose not in access["purposes"]):
                raise ValueError("correction basis lacks current source access")
        source_ids = {source.source_id for source in reads.sources}
        for interpretation in reads.interpretations:
            if (interpretation.status == "retracted"
                    or not source_ids.intersection(interpretation.source_ids)
                    or recorded_at < max(interpretation.valid_from,
                                         interpretation.recorded_at)):
                raise ValueError("correction target is not a current dependent interpretation")
        if recorded_at < max(source.recorded_at for source in reads.sources):
            raise ValueError("correction cannot predate its selected sources")
        d07_keys = tuple(AtomKey.from_token(ref) for ref in reads.d07_belief_refs)
        if any(key.type_name != "d07.belief_revision.v1"
               or NamespaceId.from_key(key) != self.namespace for key in d07_keys):
            raise ValueError("D07 invalidation refs must use the shared graph contract")

        correction_key = self.correction_source_key(request)
        correction_access = access_key(*self.namespace.as_tuple,
                                       correction_key.owner.subject)
        expected_inputs = (correction_key.token, *basis, *targets,
                           *(key.token for key in d07_keys))
        if envelope.input_refs != expected_inputs:
            raise ValueError("correction input refs do not bind the selected closure")
        guarded = {item.key: item for item in envelope.version_guard.read_versions}
        if len(guarded) != len(envelope.version_guard.read_versions):
            raise ValueError("correction read versions must be unique")
        positive = tuple(dict.fromkeys((
            *(key for source in reads.sources for key in (
                source_key(*self.namespace.as_tuple, source.source_id),
                access_key(*self.namespace.as_tuple, source.source_id),
            )), *target_keys, *d07_keys,
        )))
        if (guarded.get(correction_key) != GraphVersion(correction_key, 0)
                or guarded.get(correction_access) != GraphVersion(correction_access, 0)
                or any(guarded.get(key) is None or guarded[key].revision <= 0
                       for key in positive)):
            raise ValueError("correction lacks complete CAS reads and absence proofs")
        if not set(basis).issubset(envelope.source_qualification.source_refs):
            raise ValueError("correction basis lacks source qualification")
        audiences = set.intersection(*(
            set(source.audiences).intersection(access["audiences"])
            for source, access in zip(reads.sources, reads.accesses)
        ))
        purposes = set.intersection(*(
            set(source.purposes).intersection(access["purposes"])
            for source, access in zip(reads.sources, reads.accesses)
        ))
        if (not audiences or not purposes
                or not set(envelope.authority.audience).issubset(audiences)
                or envelope.authority.purpose not in purposes):
            raise ValueError("correction cannot widen source access")
        admitted = self.admit_source(SourceAdmission(
            correction_key.owner.subject, request.replacement_claim,
            envelope.authority.actor, "reported", "reported", "reported_claim",
            "not_applicable", None, recorded_at, "owner.correction.v1",
            tuple(sorted(audiences)), tuple(sorted(purposes)),
            tuple(source.source_id for source in reads.sources),
        ))
        # The envelope qualifies the existing basis. The new claim is always
        # admitted as a reported statement, never as an external fact.
        access_value = {
            "source_id": admitted.source.source_id,
            "audiences": list(admitted.source.audiences),
            "purposes": list(admitted.source.purposes),
            "status": "active", "recorded_at": recorded_at,
        }
        validate_access(access_value)
        writes = [
            GraphWrite(correction_key, admitted.source.to_dict()),
            GraphWrite(correction_access, access_value, (correction_key,)),
        ]
        for key, old in zip(target_keys, reads.interpretations):
            retracted = replace(old, status="retracted", valid_to=recorded_at)
            writes.append(GraphWrite(key, retracted.to_dict(), (correction_key,)))
        current_edges = tuple(dict.fromkeys(
            dependency for write in writes for dependency in write.dependencies
        ))
        proposal = self.wrap_runtime_proposal(
            envelope, typed_writes=tuple(writes),
            dependencies=DependencySet(
                current_invalidation=tuple(guarded[key] for key in current_edges),
                historical_provenance=tuple(guarded[key] for key in positive),
            ),
            contribution_keys=(f"source-correction:{correction_key.token}",),
            required_bundle_parts=("persistent_job", "outbox"),
        )
        D06DomainProvider().validate(proposal)
        return SourceCorrectionCandidateV1(
            proposal, correction_key.token, targets,
            tuple(key.token for key in d07_keys),
        )

    def prepare_deletion_closure(
        self,
        request: ErasureRequest,
        *,
        current_dependency_refs: tuple[str, ...] = (),
        historical_source_refs: tuple[str, ...] = (),
        association_refs: tuple[str, ...] = (),
        graph_cache_refs: tuple[str, ...] = (),
    ) -> DeletionClosureCandidate:
        """Prepare D06 closure semantics without producing Authority evidence.

        The shared Authority/D11 path must independently verify the graph read,
        issue the fence-bound evidence, install the barrier, and return receipts.
        """
        if not isinstance(request, ErasureRequest):
            raise TypeError("request must be ErasureRequest")
        _nonempty(request.request_id, "request_id")
        _nonempty(request.scope, "scope")
        self._epochs(request.access_epoch, request.deletion_epoch)
        roots = _canonical_graph_refs(
            request.target_refs, "target_refs", self.namespace, allow_empty=False,
        )
        current = _canonical_graph_refs(
            current_dependency_refs, "current_dependency_refs", self.namespace,
        )
        historical = _canonical_graph_refs(
            historical_source_refs, "historical_source_refs", self.namespace,
        )
        associations = _canonical_graph_refs(
            association_refs, "association_refs", self.namespace,
        )
        caches = _canonical_graph_refs(
            graph_cache_refs, "graph_cache_refs", self.namespace,
        )
        identity = {
            "contract": "d06.deletion-closure.v1",
            "request_id": request.request_id,
            "namespace": list(self.namespace.as_tuple),
            "root_refs": roots,
            "scope": request.scope,
            "access_epoch_before": request.access_epoch,
            "delete_epoch_before": request.deletion_epoch,
            "current_dependency_refs": current,
            "historical_source_refs": historical,
            "association_refs": associations,
            "graph_cache_refs": caches,
        }
        return DeletionClosureCandidate(
            _stable_id("deletion-closure", identity),
            request.request_id,
            self.namespace,
            roots,
            request.scope,
            request.access_epoch,
            request.deletion_epoch,
            current,
            historical,
            associations,
            caches,
        )

    def plan_erasure(self, request: ErasureRequest) -> RuntimeMutationPlan:
        if not isinstance(request, ErasureRequest):
            raise TypeError("request must be ErasureRequest")
        _nonempty(request.request_id, "request_id")
        _names(request.target_refs, "target_refs", allow_empty=False)
        _nonempty(request.scope, "scope")
        self._epochs(request.access_epoch, request.deletion_epoch)
        return RuntimeMutationPlan(
            request.request_id,
            "erase_memory",
            request.target_refs,
            ("independent_deletion_intent", "authority_barrier", "cleanup_job", "facet_receipts"),
            (("access_epoch", request.access_epoch), ("deletion_epoch", request.deletion_epoch), ("scope", request.scope)),
        )

    def plan_transfer(self, request: TransferRequest) -> RuntimeMutationPlan:
        if not isinstance(request, TransferRequest):
            raise TypeError("request must be TransferRequest")
        _nonempty(request.transfer_id, "transfer_id")
        _names(request.source_refs, "source_refs", allow_empty=False)
        _nonempty(request.destination_namespace, "destination_namespace")
        _nonempty(request.transfer_grant_ref, "transfer_grant_ref")
        self._epochs(request.source_access_epoch, request.source_deletion_epoch)
        return RuntimeMutationPlan(
            request.transfer_id,
            "inspect_or_transfer",
            request.source_refs,
            ("synchronous_origin_authorization", "isolated_import_batch", "transfer_receipt"),
            (
                ("source_access_epoch", request.source_access_epoch),
                ("source_deletion_epoch", request.source_deletion_epoch),
                ("destination_namespace", request.destination_namespace),
                ("transfer_grant_ref", request.transfer_grant_ref),
            ),
        )

    @staticmethod
    def _epochs(access_epoch: int, deletion_epoch: int) -> None:
        for value, label in ((access_epoch, "access_epoch"), (deletion_epoch, "deletion_epoch")):
            if type(value) is not int or isinstance(value, bool) or value < 0:
                raise ValueError(f"{label} must be a nonnegative integer")

    @classmethod
    def _validate_correction(cls, request: CorrectionRequest) -> None:
        if not isinstance(request, CorrectionRequest):
            raise TypeError("request must be CorrectionRequest")
        _nonempty(request.request_id, "request_id")
        _names(request.target_refs, "target_refs", allow_empty=False)
        _names(request.basis_source_refs, "basis_source_refs", allow_empty=False)
        _nonempty(request.replacement_claim, "replacement_claim")
        cls._epochs(request.access_epoch, request.deletion_epoch)


__all__ = [
    "CandidateItem",
    "CandidateSet",
    "CorrectionRequest",
    "D06DomainAdapter",
    "D06DomainProvider",
    "DeletionClosureCandidate",
    "EncodingContext",
    "EncodingProposal",
    "ErasureRequest",
    "MemoryEpisodeCandidate",
    "RecallIntent",
    "RecallQualification",
    "RecollectionContext",
    "RecollectionProposal",
    "RetrievalChannel",
    "RuntimeMutationPlan",
    "SelectionTicket",
    "SourceAdmission",
    "SourceAdmissionProposal",
    "SourceCorrectionCandidateV1",
    "SourceCorrectionReadSetV1",
    "SourceGrantRead",
    "SubjectiveTraceCandidate",
    "TransferRequest",
    "TriggerKind",
    "provide_source_grant_check",
]
