"""Unsigned C04 V3 evidence contracts and a strict canonical wire codec.

Construction and decoding validate linkage only. D04, D07, Authority, and W01
must independently authenticate their own originals before any adoption.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields, is_dataclass
import hashlib
import json
import math
import re
from typing import get_args, get_origin, get_type_hints
from types import UnionType

from ..contracts import canonical_json
from ..graph_types import AtomKey
from ..memory_association import ActivationPolicy
from ..domains.d06 import SelectionTicket
from ..runtime_contracts import NamespaceId


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMA = "c04.current_association.v3"
AUTHORED_INPUT_SCHEMA_V3 = "c04.current_association.authored.v3.input"
ALGORITHM_ID_V3 = "d06.association_activation.v3"


def _text(value: object, name: str) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be nonempty")


def _digest(value: object, name: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical SHA-256 digest")


def _sha(value: object, name: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 hash")


def _ref(value: object, namespace: NamespaceId, name: str,
         type_name: str | None = None) -> AtomKey:
    if type(value) is not str:
        raise ValueError(f"{name} must be a graph ref")
    key = AtomKey.from_token(value)
    if ((key.owner.bot, key.owner.persona) != namespace.as_tuple
            or (type_name is not None and key.type_name != type_name)):
        raise ValueError(f"{name} namespace or graph type differs")
    return key


def _interval(value: object, name: str, *, signed: bool = False) -> None:
    lower = -1.0 if signed else 0.0
    if (type(value) is not tuple or len(value) != 2
            or any(type(x) not in (float, int) or not math.isfinite(x) for x in value)
            or not lower <= value[0] <= value[1] <= 1.0):
        raise ValueError(f"{name} must be an ordered certified interval")


def _sorted_unique(values: object, name: str, *, required: bool = False) -> None:
    if (type(values) is not tuple or (required and not values)
            or tuple(sorted(set(values))) != values):
        raise ValueError(f"{name} must be sorted and unique")


def _semantic_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(_encode(value)).encode()).hexdigest()


def canonical_v3_digest(value: object) -> str:
    """Digest one V3 DTO or its ordered tuple using the canonical wire values."""
    return _semantic_digest(value)


def _canonical_head_original_v3(row):
    from .c04_direct_seed_v4 import canonical_original_for_c04_head_v4
    return canonical_original_for_c04_head_v4(row)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class GraphHeadV3:
    ref: str
    revision: int
    valid: bool
    value_json: str | None
    _canonical_original: InitVar[object] = None

    def __post_init__(self, _canonical_original) -> None:
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 0 or type(self.valid) is not bool:
            raise ValueError("graph head needs exact revision and validity")
        if self.revision == 0:
            if self.valid or self.value_json is not None:
                raise ValueError("absent graph head has no value")
        elif _canonical_original is not None:
            if type(self.value_json)is not str:raise ValueError('present graph head needs its exact canonical wire')
        elif (type(self.value_json) is not str
              or type(json.loads(self.value_json)) is not dict
              or canonical_json(json.loads(self.value_json)) != self.value_json):
            raise ValueError("graph head value must be a canonical complete object")
        if _canonical_original is not None:
            from .c04_direct_seed_v4 import retain_c04_canonical_head_v4
            retain_c04_canonical_head_v4(self,_canonical_original,ref_value=self.ref,
                revision=self.revision,valid=self.valid,wire=self.value_json)

    @property
    def value(self) -> dict | None:
        from .c04_direct_seed_v4 import canonical_original_for_c04_head_v4
        original=canonical_original_for_c04_head_v4(self)
        return original.value_v4()if original is not None else None if self.value_json is None else json.loads(self.value_json)

    @property
    def value_digest(self):
        from .c04_direct_seed_v4 import canonical_original_for_c04_head_v4
        original=canonical_original_for_c04_head_v4(self)
        if original is not None:return original.sha256
        from ..runtime_contracts import canonical_digest
        return None if self.value_json is None else canonical_digest(self.value)


@dataclass(frozen=True, slots=True)
class ExactRefV3:
    ref: str
    revision: int

    def __post_init__(self) -> None:
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("original needs a positive exact graph revision")


@dataclass(frozen=True, slots=True)
class ProjectionNumericErrorV3:
    inherited_state_error_2norm: float
    solve_state_error_2norm: float
    salience_readout_error: float
    tone_readout_error: float
    numeric_proof_digest: str

    def __post_init__(self) -> None:
        for name in ("inherited_state_error_2norm", "solve_state_error_2norm",
                     "salience_readout_error", "tone_readout_error"):
            value = getattr(self, name)
            if type(value) not in (float, int) or not 0 <= value < math.inf:
                raise ValueError(f"{name} must be finite and nonnegative")
        _digest(self.numeric_proof_digest, "numeric proof digest")


@dataclass(frozen=True, slots=True)
class ProjectionMemberV3:
    feeling: ExactRefV3
    checkpoint: ExactRefV3

    def __post_init__(self) -> None:
        if type(self.feeling) is not ExactRefV3 or type(self.checkpoint) is not ExactRefV3:
            raise TypeError("projection member needs exact Feeling and checkpoint refs")
        feeling = AtomKey.from_token(self.feeling.ref)
        checkpoint = AtomKey.from_token(self.checkpoint.ref)
        authored = type(self) is ProjectionMemberAuthoredV3
        if (feeling.type_name != ("d04.authored_feeling_state.v1" if authored else "d04.feeling_state.v1")
                or checkpoint.type_name != ("d04.numeric_checkpoint.v2" if authored else "d04.numeric_checkpoint.v1")
                or feeling.owner != checkpoint.owner):
            raise ValueError("projection member Feeling and checkpoint differ")


@dataclass(frozen=True, slots=True)
class ProjectionMemberAuthoredV3(ProjectionMemberV3):
    """Authored wire discriminator; the legacy member keeps its old refs."""


@dataclass(frozen=True, slots=True)
class D04EncodingBaselineOriginalV3:
    namespace: NamespaceId
    encoding_operation_id: str
    source: ExactRefV3
    perspective: ExactRefV3
    interpretations: tuple[ExactRefV3, ...]
    members: tuple[ProjectionMemberV3 | ProjectionMemberAuthoredV3, ...]
    member_set_digest: str
    joint_adoption_receipt_digest: str
    joint_numeric_original_digest: str
    joint_output_original_digest: str
    policy_digest: str
    readout_sha256: str
    native_manifest_sha256: str
    native_sha256: str
    owner_epoch: int
    access_epoch: int
    delete_epoch: int
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    numeric_error: ProjectionNumericErrorV3
    proof_digest: str
    semantic_calibration: str = "unvalidated"
    evidence_weight_delta: int = 0

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("baseline namespace must be typed")
        _text(self.encoding_operation_id, "encoding operation")
        for name, type_name in (("source", "memory.source"),):
            item = getattr(self, name)
            if type(item) is not ExactRefV3:
                raise TypeError(f"{name} must be an exact original")
            _ref(item.ref, self.namespace, name, type_name)
        if type(self.perspective) is not ExactRefV3:
            raise TypeError("perspective must be an exact original")
        _ref(self.perspective.ref, self.namespace, "perspective")
        if (type(self.interpretations) is not tuple or not self.interpretations
                or any(type(item) is not ExactRefV3 for item in self.interpretations)
                or tuple(sorted({item.ref for item in self.interpretations}))
                   != tuple(item.ref for item in self.interpretations)):
            raise ValueError("baseline needs complete sorted interpretations")
        for item in self.interpretations:
            _ref(item.ref, self.namespace, "interpretation")
        authored = type(self) is D04EncodingBaselineAuthoredOriginalV3
        member_type = ProjectionMemberAuthoredV3 if authored else ProjectionMemberV3
        if (type(self.members) is not tuple or not self.members
                or any(type(item) is not member_type for item in self.members)
                or tuple(sorted({item.feeling.ref for item in self.members}))
                   != tuple(item.feeling.ref for item in self.members)):
            raise ValueError("baseline needs complete sorted Feeling members")
        for member in self.members:
            _ref(member.feeling.ref, self.namespace, "Feeling",
                 "d04.authored_feeling_state.v1" if authored else "d04.feeling_state.v1")
            _ref(member.checkpoint.ref, self.namespace, "checkpoint",
                 "d04.numeric_checkpoint.v2" if authored else "d04.numeric_checkpoint.v1")
        if self.member_set_digest != _semantic_digest(self.members):
            raise ValueError("baseline member set digest differs")
        for name in ("joint_adoption_receipt_digest", "joint_numeric_original_digest",
                     "joint_output_original_digest", "policy_digest", "proof_digest"):
            _digest(getattr(self, name), name)
        for name in ("readout_sha256", "native_manifest_sha256", "native_sha256"):
            _sha(getattr(self, name), name)
        for name in ("owner_epoch", "access_epoch", "delete_epoch"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"{name} must be nonnegative")
        _interval(self.salience_interval, "baseline salience")
        _interval(self.tone_interval, "baseline tone", signed=True)
        if type(self.numeric_error) is not ProjectionNumericErrorV3:
            raise TypeError("baseline needs joint numeric error breakdown")
        if self.semantic_calibration != "unvalidated" or self.evidence_weight_delta != 0:
            raise ValueError("D04 projection has no semantic calibration or evidence gain")

    @property
    def digest(self) -> str:
        return _semantic_digest(self)


@dataclass(frozen=True, slots=True)
class D04CurrentConditionedSalienceOriginalV3:
    namespace: NamespaceId
    operation_id: str
    source_ref: str
    baseline_digest: str
    current_mood: ExactRefV3
    current_checkpoint: ExactRefV3
    current_joint_adoption_receipt_digest: str
    current_joint_numeric_original_digest: str
    current_joint_output_original_digest: str
    source_closure_digest: str
    audience: str
    purpose: str
    owner_epoch: int
    access_epoch: int
    delete_epoch: int
    policy_digest: str
    readout_sha256: str
    native_sha256: str
    base_salience_interval: tuple[float, float]
    conditioned_salience_interval: tuple[float, float]
    base_tone_interval: tuple[float, float]
    conditioned_tone_interval: tuple[float, float]
    numeric_error: ProjectionNumericErrorV3
    baseline_proof_digest: str
    conditioning_proof_digest: str
    semantic_calibration: str = "unvalidated"
    evidence_weight_delta: int = 0

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("condition namespace must be typed")
        _text(self.operation_id, "operation")
        _ref(self.source_ref, self.namespace, "source", "memory.source")
        authored = type(self) is D04CurrentSalienceConditionAuthoredV3
        for name, type_name in (("current_mood", "d04.authored_mood_state.v1" if authored else "d04.mood_field.v1"),
                                ("current_checkpoint", "d04.numeric_checkpoint.v2" if authored else "d04.numeric_checkpoint.v1")):
            item = getattr(self, name)
            if type(item) is not ExactRefV3:
                raise TypeError(f"{name} must be an exact original")
            _ref(item.ref, self.namespace, name, type_name)
        if (AtomKey.from_token(self.current_mood.ref).owner
                != AtomKey.from_token(self.current_checkpoint.ref).owner):
            raise ValueError("Mood and checkpoint member differ")
        for name in ("baseline_digest", "current_joint_adoption_receipt_digest",
                     "current_joint_numeric_original_digest", "current_joint_output_original_digest",
                     "source_closure_digest", "policy_digest", "baseline_proof_digest",
                     "conditioning_proof_digest"):
            _digest(getattr(self, name), name)
        for name in ("readout_sha256", "native_sha256"):
            _sha(getattr(self, name), name)
        for name in ("audience", "purpose"):
            _text(getattr(self, name), name)
        for name in ("owner_epoch", "access_epoch", "delete_epoch"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"{name} must be nonnegative")
        for name in ("base_salience_interval", "conditioned_salience_interval"):
            _interval(getattr(self, name), name)
        for name in ("base_tone_interval", "conditioned_tone_interval"):
            _interval(getattr(self, name), name, signed=True)
        if type(self.numeric_error) is not ProjectionNumericErrorV3:
            raise TypeError("condition needs joint numeric error breakdown")
        if self.semantic_calibration != "unvalidated" or self.evidence_weight_delta != 0:
            raise ValueError("condition has no semantic calibration or evidence gain")

    @property
    def digest(self) -> str:
        return _semantic_digest(self)


@dataclass(frozen=True, slots=True)
class D04EncodingBaselineAuthoredOriginalV3(D04EncodingBaselineOriginalV3):
    """Exact authored Feeling/checkpoint wire variant."""


@dataclass(frozen=True, slots=True)
class D04CurrentSalienceConditionAuthoredV3(D04CurrentConditionedSalienceOriginalV3):
    """Exact authored current Mood/checkpoint wire variant."""


@dataclass(frozen=True, slots=True)
class AssociationTargetV3:
    source_ref: str
    baseline: D04EncodingBaselineOriginalV3 | D04EncodingBaselineAuthoredOriginalV3
    condition: D04CurrentConditionedSalienceOriginalV3 | D04CurrentSalienceConditionAuthoredV3

    def __post_init__(self) -> None:
        authored = type(self) is AssociationTargetAuthoredV3
        if (type(self.baseline) is not (D04EncodingBaselineAuthoredOriginalV3 if authored else D04EncodingBaselineOriginalV3)
                or type(self.condition) is not (D04CurrentSalienceConditionAuthoredV3 if authored else D04CurrentConditionedSalienceOriginalV3)
                or self.source_ref != self.baseline.source.ref
                or self.source_ref != self.condition.source_ref
                or self.baseline.namespace != self.condition.namespace
                or self.condition.baseline_digest != self.baseline.digest
                or self.condition.base_salience_interval != self.baseline.salience_interval
                or self.condition.base_tone_interval != self.baseline.tone_interval):
            raise ValueError("candidate source, baseline and current condition differ")


@dataclass(frozen=True, slots=True)
class AssociationTargetAuthoredV3(AssociationTargetV3):
    """Authored target only; a mixed lineage batch is rejected."""


@dataclass(frozen=True, slots=True)
class AssociationPageV3:
    source_ref: str
    hop: int
    edge_refs: tuple[str, ...]
    next_after: str | None

    def __post_init__(self) -> None:
        AtomKey.from_token(self.source_ref)
        if type(self.hop) is not int or self.hop not in (0, 1):
            raise ValueError("page hop exceeds installed bound")
        _sorted_unique(self.edge_refs, "edge refs")
        for ref in self.edge_refs:
            AtomKey.from_token(ref)
        if self.next_after is not None and (not self.edge_refs or self.next_after != self.edge_refs[-1]):
            raise ValueError("continuation must be the last included edge")


@dataclass(frozen=True, slots=True)
class AssociationBudgetV3:
    max_hops: int
    max_edges: int
    max_nodes: int
    max_iterations: int
    max_candidates: int

    def __post_init__(self) -> None:
        for name, floor, ceiling in (("max_hops", 0, 2), ("max_edges", 1, 128),
                                     ("max_nodes", 1, 128), ("max_iterations", 1, 64),
                                     ("max_candidates", 1, 32)):
            value = getattr(self, name)
            if type(value) is not int or not floor <= value <= ceiling:
                raise ValueError(f"{name} exceeds bounded C04 work")


def _validate_c04_common_input_fields_v3(work, *, authored):
    _ref(work.cue_source_ref, work.namespace, "cue", "memory.source")
    _ref(work.focus_ref, work.namespace, "focus", "d07.focus.v1")
    _ref(work.attention_ticket_ref, work.namespace, "attention ticket", "d07.attention_ticket.v1")
    _ref(work.mood_ref, work.namespace, "mood",
         "d04.authored_mood_state.v1" if authored else "d04.mood_field.v1")
    if (type(work.selection_ticket) is not SelectionTicket
            or work.selection_ticket.activity_id != work.activity_id
            or work.selection_ticket_digest != _semantic_digest(work.selection_ticket)):
        raise ValueError("selection ticket identity or digest differs")
    for name in ("selection_ticket_digest", "algorithm_build_digest"):
        _digest(getattr(work, name), name)
    if (type(work.budget) is not AssociationBudgetV3
            or type(work.policy) is not ActivationPolicy
            or type(work.truncated) is not bool):
        raise TypeError("budget, policy and truncation must be typed")
    if (work.policy.leak, work.policy.spread, work.policy.max_iterations,
            work.policy.max_nodes, work.policy.min_activation) != (
            0.5, 0.25, work.budget.max_iterations, work.budget.max_nodes, 1e-6):
        raise ValueError("activation policy differs from installed V3 numeric policy")
    for name in ("graph_epoch", "owner_epoch", "access_epoch", "delete_epoch"):
        if type(getattr(work, name)) is not int or getattr(work, name) < 0:
            raise ValueError(f"{name} must be nonnegative")
    if (type(work.context_tags) is not tuple or len(work.context_tags) > 8
            or tuple(sorted(set(work.context_tags))) != work.context_tags):
        raise ValueError("context tags must be bounded, sorted and unique")
    if (type(work.reads) is not tuple or len(work.reads) > 1024
            or any(type(item) is not GraphHeadV3 for item in work.reads)
            or tuple(sorted({item.ref for item in work.reads})) != tuple(item.ref for item in work.reads)):
        raise ValueError("graph reads must be bounded, sorted and unique")
    for item in work.reads:
        _ref(item.ref, work.namespace, "read")
    if (type(work.edge_pages) is not tuple or len(work.edge_pages) > work.budget.max_nodes
            or any(type(item) is not AssociationPageV3 for item in work.edge_pages)
            or tuple(sorted({item.source_ref for item in work.edge_pages}))
               != tuple(item.source_ref for item in work.edge_pages)):
        raise ValueError("edge pages must be bounded, sorted and unique")
    for page in work.edge_pages:
        _ref(page.source_ref, work.namespace, "page source", "memory.source")
        for edge_ref in page.edge_refs:
            _ref(edge_ref, work.namespace, "page edge", "memory.association.v1")
    if (type(work.targets) is not tuple or not work.targets
            or len(work.targets) > work.budget.max_nodes
            or any(type(item) is not (AssociationTargetAuthoredV3 if authored else AssociationTargetV3)
                   for item in work.targets)
            or tuple(sorted({item.source_ref for item in work.targets}))
               != tuple(item.source_ref for item in work.targets)):
        raise ValueError("targets must be bounded, sorted and unique")
    for target in work.targets:
        condition = target.condition
        if (condition.namespace != work.namespace or condition.operation_id != work.operation_id
                or (condition.audience, condition.purpose) != (work.audience, work.purpose)
                or condition.current_mood.ref != work.mood_ref
                or (condition.owner_epoch, condition.access_epoch, condition.delete_epoch)
                   != (work.owner_epoch, work.access_epoch, work.delete_epoch)):
            raise ValueError("target condition differs from frozen operation or rights")
    if work.cue_source_ref not in {target.source_ref for target in work.targets}:
        raise ValueError("cue needs its own qualified condition")


@dataclass(frozen=True, slots=True)
class AssociationWorkInputV3:
    namespace: NamespaceId
    activity_id: str
    operation_id: str
    cue_source_ref: str
    focus_ref: str
    attention_ticket_ref: str
    mood_ref: str
    selection_ticket: SelectionTicket
    selection_ticket_digest: str
    audience: str
    purpose: str
    context_tags: tuple[str, ...]
    reads: tuple[GraphHeadV3, ...]
    edge_pages: tuple[AssociationPageV3, ...]
    budget: AssociationBudgetV3
    policy: ActivationPolicy
    graph_epoch: int
    owner_epoch: int
    access_epoch: int
    delete_epoch: int
    truncated: bool
    algorithm_id: str
    algorithm_build_digest: str
    targets: tuple[AssociationTargetV3 | AssociationTargetAuthoredV3, ...]
    schema: str = _SCHEMA + ".input"

    def __post_init__(self) -> None:
        if self.schema not in {_SCHEMA + ".input", AUTHORED_INPUT_SCHEMA_V3} or type(self.namespace) is not NamespaceId:
            raise ValueError("unknown C04 V3 input schema or namespace")
        for name in ("activity_id", "operation_id", "audience", "purpose"):
            _text(getattr(self, name), name)
        if self.algorithm_id != ALGORITHM_ID_V3:
            raise ValueError("C04 V3 algorithm identity differs")
        _validate_c04_common_input_fields_v3(self, authored=self.schema == AUTHORED_INPUT_SCHEMA_V3)
        self._validate_closure()

    def _validate_closure(self) -> None:
        by_ref = {item.ref: item for item in self.reads}
        for ref in (self.cue_source_ref, self.focus_ref, self.attention_ticket_ref,
                    self.mood_ref):
            row = by_ref.get(ref)
            if row is None or row.revision < 1 or not row.valid:
                raise ValueError("cue, focus and attention ticket need present graph originals")
        for target in self.targets:
            row = by_ref.get(target.source_ref)
            if row is None or row.revision < 1 or not row.valid:
                raise ValueError("each target needs a present source original")
            if (target.baseline.source.revision != row.revision
                    or target.condition.current_mood.ref != self.mood_ref
                    or target.condition.current_mood.revision
                       != by_ref[self.mood_ref].revision):
                raise ValueError("target baseline or current Mood version differs from frozen reads")
        if self.budget.max_hops and self.cue_source_ref not in {
                page.source_ref for page in self.edge_pages}:
            raise ValueError("cue edge page is missing")
        if self.budget.max_hops == 0 and self.edge_pages:
            raise ValueError("zero-hop input cannot query edges")
        included_edges = {edge for page in self.edge_pages for edge in page.edge_refs}
        graph_edges = {row.ref for row in self.reads
                       if AtomKey.from_token(row.ref).type_name == "memory.association.v1"}
        if included_edges != graph_edges or len(included_edges) > self.budget.max_edges:
            raise ValueError("edge pages differ from complete edge originals")
        for edge in included_edges:
            row = by_ref[edge]
            if row.revision < 1 or not row.valid:
                raise ValueError("association edge must be a present original")
        if any(page.next_after is not None for page in self.edge_pages) and not self.truncated:
            raise ValueError("page continuation needs explicit truncation")
        reachable = {self.cue_source_ref}
        for hop in range(self.budget.max_hops):
            for page in self.edge_pages:
                if page.hop != hop or page.source_ref not in reachable:
                    continue
                for edge in page.edge_refs:
                    value = by_ref[edge].value
                    if value["context_tags"] and not set(value["context_tags"]) & set(self.context_tags):
                        continue
                    reachable.add(value["target_ref"])
        if any(target.source_ref not in reachable for target in self.targets):
            raise ValueError("target is outside the qualified association closure")
        # Reuse the established complete graph/source/access/correction validator.
        # Its cue salience object is a local validation adapter, never V3 evidence.
        from ..domains.d06.c04_work_input_v2 import (
            AssociationQueryCoverageV2, AssociationWorkInputV2,
            D04SalienceOriginalV2, FrozenGraphReadV2,
        )
        from ..domains.d06.current_association_candidates import CurrentAssociationBudgetV1
        from ..graph_types import NamespaceEpoch

        cue = next(target for target in self.targets
                   if target.source_ref == self.cue_source_ref)
        if self.schema == AUTHORED_INPUT_SCHEMA_V3:
            from types import SimpleNamespace
            from ..domains.d06.c04_work_input_v2 import _validate_complete_graph_closure_v1
            # This local validation view is never serialized or admitted as a
            # V2 original. All V3 fields/targets were strictly checked above.
            closure = SimpleNamespace(namespace=self.namespace, cue_source_ref=self.cue_source_ref,
                focus_ref=self.focus_ref, attention_ticket_ref=self.attention_ticket_ref, mood_ref=self.mood_ref,
                selection_ticket=self.selection_ticket, audience=self.audience, purpose=self.purpose,
                context_tags=self.context_tags, budget=self.budget, truncated=self.truncated,
                reads=tuple(FrozenGraphReadV2(AtomKey.from_token(row.ref), row.revision,
                    row.valid, row.value_json, _canonical_original=_canonical_head_original_v3(row)) for row in self.reads),
                edge_queries=tuple(AssociationQueryCoverageV2(page.source_ref,page.hop,page.edge_refs,page.next_after)
                    for page in self.edge_pages))
            _validate_complete_graph_closure_v1(closure,mood_type="d04.authored_mood_state.v1")
            return
        AssociationWorkInputV2(
            self.namespace, self.activity_id, self.operation_id,
            self.cue_source_ref, self.focus_ref, self.attention_ticket_ref,
            self.mood_ref, self.selection_ticket,
            D04SalienceOriginalV2(self.cue_source_ref, self.mood_ref,
                                  cue.baseline.salience_interval,
                                  cue.condition.conditioned_salience_interval,
                                  "v3-closure-validation"),
            self.audience, self.purpose, self.context_tags, self.policy,
            CurrentAssociationBudgetV1(
                self.budget.max_hops, self.budget.max_edges, self.budget.max_nodes,
                self.budget.max_iterations, self.budget.max_candidates),
            tuple(FrozenGraphReadV2(AtomKey.from_token(row.ref), row.revision,
                                    row.valid, row.value_json, _canonical_original=_canonical_head_original_v3(row)) for row in self.reads),
            tuple(AssociationQueryCoverageV2(page.source_ref, page.hop,
                                             page.edge_refs, page.next_after)
                  for page in self.edge_pages),
            NamespaceEpoch(*self.namespace.as_tuple, self.graph_epoch),
            self.truncated,
        )

    def validate_closure(self) -> None:
        """Recheck the frozen, typed graph envelope before CPU work."""
        self._validate_closure()

    @property
    def input_digest(self) -> str:
        return _semantic_digest(self)

    def to_json(self) -> str:
        return encode_v3(self)

    @classmethod
    def from_json(cls, wire: str) -> AssociationWorkInputV3:
        return decode_v3(wire, cls)


@dataclass(frozen=True, slots=True)
class AssociationScoreV3:
    source_ref: str
    activation: float
    conditioned_salience: float
    score: float
    condition_digest: str
    evidence_eligibility: str = "subjective_association_only"

    def __post_init__(self) -> None:
        AtomKey.from_token(self.source_ref)
        for name in ("activation", "conditioned_salience", "score"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and nonnegative")
        _digest(self.condition_digest, "condition digest")
        if self.evidence_eligibility != "subjective_association_only":
            raise ValueError("association cannot upgrade evidence")


def _validate_c04_common_result_fields_v3(work):
    for name in ("operation_id", "algorithm_id", "stop_reason"):
        _text(getattr(work, name), name)
    for name in ("input_digest", "algorithm_build_digest"):
        _digest(getattr(work, name), name)
    if (type(work.candidates) is not tuple
            or any(type(item) is not AssociationScoreV3 for item in work.candidates)
            or len({item.source_ref for item in work.candidates}) != len(work.candidates)):
        raise ValueError("result candidates must be unique")
    for item in work.candidates:
        _ref(item.source_ref, work.namespace, "result source", "memory.source")
    for name in ("visited_nodes", "visited_edges", "iterations"):
        if type(getattr(work, name)) is not int or getattr(work, name) < 0:
            raise ValueError(f"{name} must be nonnegative")
    if type(work.truncated) is not bool:
        raise TypeError("result truncation must be explicit")


def _validate_c04_result_against_input_v3(result, work):
    if ((result.namespace, result.operation_id, result.input_digest,
                result.algorithm_id, result.algorithm_build_digest)
               != (work.namespace, work.operation_id, work.input_digest,
                   work.algorithm_id, work.algorithm_build_digest)
            or len(result.candidates) > work.budget.max_candidates
            or any(item.source_ref not in {target.source_ref for target in work.targets}
                   or item.condition_digest != next(target.condition.digest
                       for target in work.targets if target.source_ref == item.source_ref)
                   or item.conditioned_salience != sum(next(
                       target.condition.conditioned_salience_interval
                       for target in work.targets if target.source_ref == item.source_ref)) / 2
                   or not math.isclose(item.score,
                       item.activation * item.conditioned_salience,
                       rel_tol=0, abs_tol=1e-12)
                   for item in result.candidates)):
        raise ValueError("C04 result differs from frozen input or target originals")


@dataclass(frozen=True, slots=True)
class AssociationWorkResultV3:
    namespace: NamespaceId
    operation_id: str
    input_digest: str
    algorithm_id: str
    algorithm_build_digest: str
    candidates: tuple[AssociationScoreV3, ...]
    visited_nodes: int
    visited_edges: int
    iterations: int
    truncated: bool
    stop_reason: str
    schema: str = _SCHEMA + ".result"

    def __post_init__(self) -> None:
        if self.schema != _SCHEMA + ".result" or type(self.namespace) is not NamespaceId:
            raise ValueError("unknown C04 V3 result schema")
        _validate_c04_common_result_fields_v3(self)

    @property
    def result_digest(self) -> str:
        return _semantic_digest(self)

    def validate_input(self, work: AssociationWorkInputV3) -> None:
        if type(work) is not AssociationWorkInputV3:
            raise ValueError("C04 result differs from frozen input or target originals")
        _validate_c04_result_against_input_v3(self, work)

    def to_json(self) -> str:
        return encode_v3(self)

    @classmethod
    def from_json(cls, wire: str) -> AssociationWorkResultV3:
        return decode_v3(wire, cls)


@dataclass(frozen=True, slots=True)
class PlannedWriteV3:
    ref: str
    value_digest: str
    expected_revision: int = 0

    def __post_init__(self) -> None:
        AtomKey.from_token(self.ref)
        _digest(self.value_digest, "planned write value digest")
        if type(self.expected_revision) is not int or self.expected_revision != 0:
            raise ValueError("new C04 writes need revision-zero absence")


@dataclass(frozen=True, slots=True)
class C04AdoptionPlanV3:
    namespace: NamespaceId
    operation_id: str
    input_digest: str
    result_digest: str
    algorithm_build_digest: str
    terminal_receipt_digest: str
    d02_settlement_digest: str
    d11_settlement_digest: str
    d07_selection_digest: str
    d07_interpretation_digest: str
    owner_epoch: int
    access_epoch: int
    delete_epoch: int
    content_read_set_digest: str
    writes: tuple[PlannedWriteV3, ...]
    write_set_digest: str
    schema: str = _SCHEMA + ".adoption_plan"

    def __post_init__(self) -> None:
        if self.schema != _SCHEMA + ".adoption_plan" or type(self.namespace) is not NamespaceId:
            raise ValueError("unknown C04 V3 adoption plan schema")
        _text(self.operation_id, "operation")
        for name in ("input_digest", "result_digest", "algorithm_build_digest",
                     "terminal_receipt_digest", "d02_settlement_digest", "d11_settlement_digest",
                     "d07_selection_digest", "d07_interpretation_digest",
                     "content_read_set_digest", "write_set_digest"):
            _digest(getattr(self, name), name)
        for name in ("owner_epoch", "access_epoch", "delete_epoch"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"{name} must be nonnegative")
        if (type(self.writes) is not tuple or not self.writes
                or any(type(item) is not PlannedWriteV3 for item in self.writes)
                or tuple(sorted({item.ref for item in self.writes}))
                   != tuple(item.ref for item in self.writes)):
            raise ValueError("complete planned writes must be sorted and unique")
        for item in self.writes:
            _ref(item.ref, self.namespace, "write")
        if self.write_set_digest != _semantic_digest(self.writes):
            raise ValueError("complete write set digest differs")

    @property
    def plan_digest(self) -> str:
        return _semantic_digest(self)

    def to_json(self) -> str:
        return encode_v3(self)

    @classmethod
    def from_json(cls, wire: str) -> C04AdoptionPlanV3:
        return decode_v3(wire, cls)


@dataclass(frozen=True, slots=True)
class C04AdoptionReceiptV3:
    namespace: NamespaceId
    operation_id: str
    plan_digest: str
    input_digest: str
    result_digest: str
    write_set_digest: str
    graph_epoch_after: int
    schema: str = _SCHEMA + ".adoption_receipt"

    def __post_init__(self) -> None:
        if self.schema != _SCHEMA + ".adoption_receipt" or type(self.namespace) is not NamespaceId:
            raise ValueError("unknown C04 V3 adoption receipt schema")
        _text(self.operation_id, "operation")
        for name in ("plan_digest", "input_digest", "result_digest", "write_set_digest"):
            _digest(getattr(self, name), name)
        if type(self.graph_epoch_after) is not int or self.graph_epoch_after < 0:
            raise ValueError("receipt graph epoch must be nonnegative")

    def validate_plan(self, plan: C04AdoptionPlanV3) -> None:
        if (type(plan) is not C04AdoptionPlanV3
                or (self.namespace, self.operation_id, self.plan_digest, self.input_digest,
                    self.result_digest, self.write_set_digest)
                   != (plan.namespace, plan.operation_id, plan.plan_digest, plan.input_digest,
                       plan.result_digest, plan.write_set_digest)):
            raise ValueError("adoption receipt differs from plan")

    def to_json(self) -> str:
        return encode_v3(self)

    @classmethod
    def from_json(cls, wire: str) -> C04AdoptionReceiptV3:
        return decode_v3(wire, cls)


_TYPES = {cls.__name__: cls for cls in (
    GraphHeadV3, ExactRefV3, ProjectionNumericErrorV3, ProjectionMemberV3, ProjectionMemberAuthoredV3,
    D04EncodingBaselineOriginalV3,
    D04CurrentConditionedSalienceOriginalV3, AssociationTargetV3,
    D04EncodingBaselineAuthoredOriginalV3, D04CurrentSalienceConditionAuthoredV3, AssociationTargetAuthoredV3,
    AssociationPageV3, AssociationBudgetV3, AssociationWorkInputV3,
    AssociationScoreV3, AssociationWorkResultV3, PlannedWriteV3,
    C04AdoptionPlanV3,
    C04AdoptionReceiptV3,
)}


def _encode(value: object) -> object:
    if type(value) is NamespaceId:
        return {"$type": "NamespaceId", "bot_id": value.bot_id,
                "persona_id": value.persona_id}
    if type(value) is ActivationPolicy:
        return {"$type": "ActivationPolicy", **{
            field.name: getattr(value, field.name) for field in fields(value)}}
    if type(value) is SelectionTicket:
        return {"$type": "SelectionTicket", **{
            field.name: _encode(getattr(value, field.name)) for field in fields(value)}}
    if is_dataclass(value) and type(value).__name__ in _TYPES:
        return {"$type": type(value).__name__,
                **{field.name: _encode(getattr(value, field.name)) for field in fields(value)}}
    if type(value) is tuple:
        return [_encode(item) for item in value]
    return value


def _decode(expected: object, value: object, *, _canonical_original=None) -> object:
    if _canonical_original is not None and expected is not GraphHeadV3:
        raise TypeError('canonical C04 head proof belongs only to its exact GraphHead constructor')
    origin = get_origin(expected)
    if origin is tuple:
        args = get_args(expected)
        if type(value) is not list or (len(args) == 2 and args[1] is not Ellipsis
                                       and len(value) != len(args)):
            raise ValueError("wire tuple shape differs")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(args[0], item) for item in value)
        return tuple(_decode(item_type, item) for item_type, item in zip(args, value))
    if origin is UnionType:
        for option in get_args(expected):
            try:
                return _decode(option, value)
            except (TypeError, ValueError):
                pass
        raise ValueError("wire union type differs")
    if expected is type(None):
        if value is not None:
            raise ValueError("wire value must be null")
        return None
    if expected in (str, int, bool, float):
        if type(value) is not expected and not (expected is float and type(value) is int):
            raise ValueError("wire scalar type differs")
        return value
    if expected is NamespaceId:
        if (type(value) is not dict
                or set(value) != {"$type", "bot_id", "persona_id"}
                or value["$type"] != "NamespaceId"):
            raise ValueError("wire namespace differs")
        return NamespaceId(value["bot_id"], value["persona_id"])
    if expected is ActivationPolicy:
        if (type(value) is not dict or value.get("$type") != "ActivationPolicy"
                or set(value) != {"$type", *(field.name for field in fields(ActivationPolicy))}):
            raise ValueError("wire activation policy differs")
        return ActivationPolicy(**{field.name: value[field.name]
                                   for field in fields(ActivationPolicy)})
    if expected is SelectionTicket:
        if (type(value) is not dict or value.get("$type") != "SelectionTicket"
                or set(value) != {"$type", *(field.name for field in fields(SelectionTicket))}):
            raise ValueError("wire selection ticket differs")
        hints = get_type_hints(SelectionTicket)
        return SelectionTicket(**{field.name: _decode(hints[field.name], value[field.name])
                                  for field in fields(SelectionTicket)})
    if expected in _TYPES.values():
        if type(value) is not dict or value.get("$type") != expected.__name__:
            raise ValueError("wire V3 type differs")
        hints = get_type_hints(expected)
        if set(value) != {"$type", *(field.name for field in fields(expected))}:
            raise ValueError("wire V3 fields differ")
        decoded={field.name:_decode(hints[field.name],value[field.name])for field in fields(expected)}
        if expected is GraphHeadV3 and _canonical_original is not None:
            decoded['_canonical_original']=_canonical_original
        return expected(**decoded)
    raise TypeError("unsupported C04 V3 wire type")


def encode_v3(value: object) -> str:
    if type(value) not in _TYPES.values():
        raise TypeError("typed C04 V3 contract required")
    return canonical_json(_encode(value))


def decode_v3(wire: str, expected: type) -> object:
    if expected not in _TYPES.values() or type(wire) is not str:
        raise TypeError("typed C04 V3 decoder required")

    def exact_pairs(pairs: list[tuple[str, object]]) -> dict:
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate wire field")
        return result

    payload = json.loads(wire, object_pairs_hook=exact_pairs)
    if canonical_json(payload) != wire:
        raise ValueError("C04 V3 wire is not canonical")
    return _decode(expected, payload)


__all__ = [*_TYPES, "ALGORITHM_ID_V3", "canonical_v3_digest", "encode_v3", "decode_v3"]
