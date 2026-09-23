"""D06 memory-domain proposals for the alpha1 runtime.

The adapter in this package is deliberately side-effect free.  It qualifies
inputs and prepares typed candidates for the shared runtime; it never treats a
candidate as a committed memory, performs deletion itself, or creates a second
memory database.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math

from ...memory_types import SourceRecord, register_memory_types, source_key
from ...memory_types import access_key, validate_access
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
        return proposal


class D06DomainAdapter:
    """Prepare D06 proposals without bypassing the shared runtime authority."""

    def __init__(self, namespace: NamespaceId):
        if not isinstance(namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        self.namespace = namespace

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
        identity = {
            "source_ref": source_ref,
            "event_ref": context.event_ref,
            "perspective_ref": context.perspective_ref,
            "read_versions": context.read_versions,
        }
        episode_id = _stable_id("episode", identity)
        trace_id = _stable_id("trace", {**identity, "details": context.detail_weights})
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
    "SubjectiveTraceCandidate",
    "TransferRequest",
    "TriggerKind",
]
