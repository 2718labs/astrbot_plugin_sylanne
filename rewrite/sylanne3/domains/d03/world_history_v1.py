"""D03 bitemporal assertions over immutable Graph originals and actual W01 receipts."""
from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphVersion, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash

INPUT_TYPE = "d03.world_assertion_input.v1"
VIEW_TYPE = "d03.world_view.v1"
EXPRESSION_TYPE = "d09.world_perspective_input.v1"
WORLD_OPERATIONS = ("adopt_world_assertion_v1", "relearn_world_assertion_v1", "query_world_view_v1", "project_world_perspective_v1")
WORLD_OBSERVER_KIND_V3 = "observe_committed_world_v1"


def _text(value, name, maximum=256):
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ValueError("bounded World " + name + " required")


def _sequence(value, name, minimum=1):
    if type(value) is not int or value < minimum:
        raise ValueError("actual integer World " + name + " required")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("World original digest differs")


def _version(value, type_name):
    if type(value) is not GraphVersion or value.revision < 1 or value.key.type_name != type_name:
        raise ValueError("World version must name its actual typed Graph original")


@dataclass(frozen=True, slots=True)
class WorldIntervalV1:
    lower: float | None
    upper: float | None
    precision: str

    def __post_init__(self):
        if self.precision not in {"exact", "bounded", "open", "unknown"}:
            raise ValueError("World time precision is closed")
        for value in (self.lower, self.upper):
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise ValueError("World time bound must be finite or explicitly unknown")
        if self.lower is not None and self.upper is not None and self.upper < self.lower:
            raise ValueError("World interval is reversed")
        if (self.precision == "exact" and (self.lower is None or self.upper is None)
                or self.precision == "unknown" and (self.lower is not None or self.upper is not None)
                or self.precision == "bounded" and (self.lower is None or self.upper is None)
                or self.precision == "open" and self.lower is not None and self.upper is not None):
            raise ValueError("World interval precision does not match its bounds")

    def at(self, point):
        if self.lower is not None and point < self.lower or self.upper is not None and point > self.upper:
            return "outside"
        return "inside" if self.precision == "exact" else "unknown"


@dataclass(frozen=True, slots=True)
class WorldAssertionInputV1:
    assertion_id: str
    revision_id: str
    event_version: GraphVersion
    perspective_version: GraphVersion
    interpretation_version: GraphVersion | None
    valid_interval: WorldIntervalV1
    occurred_interval: WorldIntervalV1
    learned_at: float
    received_at: float | None
    source_refs: tuple[str, ...]
    origin_kind: str
    reality: str
    assertion_status: str
    scope: str
    supersedes_ref: str | None
    correction_ref: str | None
    dispute_refs: tuple[str, ...]
    prior_erasure_digest: str | None = None
    schema: str = "d03.world-assertion-input.v1"

    def __post_init__(self):
        if self.schema != "d03.world-assertion-input.v1":
            raise ValueError("World assertion input schema differs")
        for name in ("assertion_id", "revision_id", "scope"):
            _text(getattr(self, name), name, 1024 if name == "scope" else 256)
        _version(self.event_version, "d03.world_event")
        _version(self.perspective_version, "d03.self_perspective.v1")
        if self.interpretation_version is not None:
            _version(self.interpretation_version, "d07.current_interpretation.v1")
        if type(self.valid_interval) is not WorldIntervalV1 or type(self.occurred_interval) is not WorldIntervalV1:
            raise TypeError("World assertion needs explicit interval precision")
        for value in (self.learned_at, self.received_at):
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise ValueError("World material time differs")
        if (self.origin_kind not in {"reported", "observed", "derived", "simulated"}
                or self.reality not in {"host_observed", "reported", "candidate", "simulated"}
                or self.assertion_status not in {"asserted", "confirmed", "disputed", "retracted", "unknown"}):
            raise ValueError("World assertion evidence qualification differs")
        if (type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 16
                or len(set(self.source_refs)) != len(self.source_refs)
                or any(AtomKey.from_token(ref).type_name != "memory.source" for ref in self.source_refs)):
            raise ValueError("World assertion requires bounded independent Source refs")
        if type(self.dispute_refs) is not tuple or len(self.dispute_refs) > 16 or len(set(self.dispute_refs)) != len(self.dispute_refs):
            raise ValueError("World dispute set differs")
        if self.prior_erasure_digest is not None:
            _digest(self.prior_erasure_digest)
            if self.supersedes_ref is not None:
                raise ValueError("World relearning predecessor is its opaque erasure barrier")
        namespace=NamespaceId.from_key(self.event_version.key)
        for ref in (self.supersedes_ref, self.correction_ref, *self.dispute_refs):
            if ref is not None:
                key=AtomKey.from_token(ref)
                if key.type_name!=INPUT_TYPE or NamespaceId.from_key(key)!=namespace:
                    raise ValueError("World correction/dispute/predecessor must be an actual same-namespace World revision")


@dataclass(frozen=True, slots=True)
class AdoptWorldAssertionRequestV1:
    assertion: WorldAssertionInputV1

    def __post_init__(self):
        if type(self.assertion) is not WorldAssertionInputV1 or self.assertion.prior_erasure_digest is not None:
            raise TypeError("World adoption accepts its exact immutable input; relearning is a separate explicit producer")


@dataclass(frozen=True, slots=True)
class WorldViewCursorV1:
    query_digest: str
    knowledge_watermark: int
    after_assertion_commitment: str

    def __post_init__(self):
        _digest(self.query_digest)
        _sequence(self.knowledge_watermark, "watermark", 0)
        _digest(self.after_assertion_commitment)


@dataclass(frozen=True, slots=True)
class WorldViewRequestV1:
    event_time_as_of: float
    knowledge_as_of: int
    perspective_version: GraphVersion
    purpose: str
    audience: str
    coverage_bound: int = 16
    cursor: WorldViewCursorV1 | None = None

    def __post_init__(self):
        if type(self.event_time_as_of) not in (int, float) or not math.isfinite(self.event_time_as_of) or self.event_time_as_of < 0:
            raise ValueError("World event-time point must be explicit and finite")
        _sequence(self.knowledge_as_of, "knowledge point", 0)
        _version(self.perspective_version, "d03.self_perspective.v1")
        if self.purpose not in {"context", "consolidation", "expression"}:
            raise ValueError("World purpose is closed")
        _text(self.audience, "audience")
        if self.audience == "*" or type(self.coverage_bound) is not int or not 1 <= self.coverage_bound <= 64:
            raise ValueError("World audience or page bound differs")
        if self.cursor is not None and type(self.cursor) is not WorldViewCursorV1:
            raise TypeError("World continuation must be typed")

    @property
    def query_digest(self):
        return canonical_digest((self.event_time_as_of, self.knowledge_as_of,
            self.perspective_version, self.purpose, self.audience, self.coverage_bound))


@dataclass(frozen=True, slots=True)
class WorldPerspectiveProjectionV1:
    version: GraphVersion
    original_digest: str
    persona_ref: str
    self_entity_ref: str
    scene_ref: str
    role_head_id: str
    identity_mapping_ref: str
    arrival_event_ref: str

    def __post_init__(self):
        _version(self.version,"d03.self_perspective.v1")
        _digest(self.original_digest)
        for name in ("persona_ref","self_entity_ref","scene_ref","role_head_id"):
            _text(getattr(self,name),name)
        AtomKey.from_token(self.identity_mapping_ref);AtomKey.from_token(self.arrival_event_ref)


@dataclass(frozen=True, slots=True)
class WorldInterpretationProjectionV1:
    version: GraphVersion
    original_digest: str
    question_key: str
    proposition: str
    stance: str
    subjective_conviction: float
    evidence_status: str
    meaningful_unknowns: tuple[str,...]

    def __post_init__(self):
        from ..d07 import Stance,EvidenceStatus
        _version(self.version,"d07.current_interpretation.v1")
        _digest(self.original_digest)
        _text(self.question_key,"question",1024);_text(self.proposition,"historical proposition",2048)
        if (self.stance not in {s.value for s in Stance} or self.evidence_status not in {s.value for s in EvidenceStatus}
                or type(self.subjective_conviction) not in (int,float) or not 0<=self.subjective_conviction<=1
                or type(self.meaningful_unknowns)is not tuple or len(self.meaningful_unknowns)>16):
            raise ValueError("World historical cognition projection differs")


@dataclass(frozen=True, slots=True)
class WorldAssertionRevisionV1:
    input_version: GraphVersion
    input_digest: str
    adoption_operation_id: str
    adoption_receipt_digest: str
    known_from_sequence: int
    recorded_sequence: int
    superseded_at_sequence: int | None
    assertion: WorldAssertionInputV1
    temporal_match: str
    perspective: WorldPerspectiveProjectionV1
    interpretation: WorldInterpretationProjectionV1 | None

    def __post_init__(self):
        _version(self.input_version, INPUT_TYPE)
        _digest(self.input_digest)
        _digest(self.adoption_receipt_digest)
        _text(self.adoption_operation_id, "actual adoption operation")
        _sequence(self.known_from_sequence, "known-from")
        if self.recorded_sequence!=self.known_from_sequence:
            raise ValueError("World recorded sequence must be its real input adoption")
        if self.superseded_at_sequence is not None:
            _sequence(self.superseded_at_sequence, "successor sequence")
            if self.superseded_at_sequence <= self.known_from_sequence:
                raise ValueError("World successor must be a later actual adoption")
        if (type(self.assertion) is not WorldAssertionInputV1
                or self.temporal_match not in {"inside", "unknown"}
                or type(self.perspective)is not WorldPerspectiveProjectionV1
                or self.interpretation is not None and type(self.interpretation)is not WorldInterpretationProjectionV1):
            raise ValueError("World historical revision body differs")


@dataclass(frozen=True, slots=True)
class WorldViewResultV1:
    request: WorldViewRequestV1
    revisions: tuple[WorldAssertionRevisionV1, ...]
    coverage: str
    eof: bool
    next_cursor: WorldViewCursorV1 | None
    knowledge_watermark: int
    scanned: int
    unknowns: tuple[str, ...]
    source_refs: tuple[str, ...]
    source_versions: tuple[GraphVersion, ...]
    access_epoch: int
    delete_epoch: int
    schema: str = "d03.world-view.v1"

    def __post_init__(self):
        if (self.schema != "d03.world-view.v1" or type(self.request) is not WorldViewRequestV1
                or type(self.revisions) is not tuple or len(self.revisions) > self.request.coverage_bound
                or any(type(item) is not WorldAssertionRevisionV1 for item in self.revisions)
                or self.coverage not in {"complete", "partial", "unknown"} or type(self.eof) is not bool
                or self.eof != (self.next_cursor is None) or self.coverage == "complete" and (not self.eof or self.unknowns or self.request.cursor is not None)
                or type(self.scanned) is not int or not 0 <= self.scanned <= self.request.coverage_bound):
            raise ValueError("World page coverage or bounded EOF differs")
        for value in (self.knowledge_watermark, self.access_epoch, self.delete_epoch):
            _sequence(value, "current barrier", 0)
        if self.request.knowledge_as_of > self.knowledge_watermark:
            raise ValueError("World query cannot know a future commit sequence")
        if type(self.source_refs) is not tuple or len(self.source_refs) > 16 or type(self.source_versions) is not tuple:
            raise ValueError("World Source closure exceeds its original semantic target bound")
        if type(self.unknowns) is not tuple or any(type(item) is not str or not item for item in self.unknowns):
            raise ValueError("World unknowns must remain explicit")

    @property
    def digest(self):
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class ProjectWorldPerspectiveRequestV1:
    view_version: GraphVersion
    communication_grant_version: GraphVersion
    scene_ref: str
    conversation_epoch: int

    def __post_init__(self):
        _version(self.view_version, VIEW_TYPE)
        _version(self.communication_grant_version, "d08.communication_intent_grant.v1")
        _text(self.scene_ref, "scene")
        _sequence(self.conversation_epoch, "conversation epoch", 0)


@dataclass(frozen=True, slots=True)
class WorldPerspectiveExpressionInputV1:
    view_version: GraphVersion
    view_digest: str
    perspective_version: GraphVersion
    historical_interpretation_versions: tuple[GraphVersion, ...]
    blueprint_json: str
    source_refs: tuple[str, ...]
    qualification: str = "content_verified_source_hold"
    schema: str = "d09.world-perspective-input.v1"

    def __post_init__(self):
        _version(self.view_version, VIEW_TYPE)
        _version(self.perspective_version, "d03.self_perspective.v1")
        _digest(self.view_digest)
        if (self.schema != "d09.world-perspective-input.v1" or self.qualification != "content_verified_source_hold"
                or type(self.blueprint_json) is not str or len(self.blueprint_json.encode()) > 8192
                or type(self.source_refs) is not tuple or not self.source_refs
                or type(self.historical_interpretation_versions) is not tuple or not self.historical_interpretation_versions):
            raise ValueError("World expression requires actual historical perspective and cognition, under existing final admission")
        for value in self.historical_interpretation_versions:
            _version(value, "d07.current_interpretation.v1")


def world_assertion_key_v1(namespace, revision_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), INPUT_TYPE, revision_id)


def world_view_key_v1(namespace, operation_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), VIEW_TYPE,
        "view:" + canonical_digest((namespace, operation_id))[:48])


def world_expression_key_v1(namespace, activity_id, operation_id):
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id), EXPRESSION_TYPE,
        "world:" + canonical_digest((namespace, operation_id))[:48])


def decode_world_value_v1(raw, value_type):
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, value_type)


def world_type_specs_v1(domain):
    definitions = ((INPUT_TYPE, WorldAssertionInputV1), (VIEW_TYPE, WorldViewResultV1)) if domain == "d03" else (
        (EXPRESSION_TYPE, WorldPerspectiveExpressionInputV1),)
    return tuple(TypeSpec(name, ("persona",) if domain == "d03" else ("activity",), "state",
        lambda raw, cls=cls: decode_world_value_v1(raw, cls), immutable=name == INPUT_TYPE, writer_domain=domain,
        schema_hash=schema_hash({"type": name, "fields": tuple(cls.__dataclass_fields__), "version": 1}))
        for name, cls in definitions)

@dataclass(frozen=True, slots=True)
class ObserveCommittedWorldRequestV1:
    producing_operation_id: str
    expected_request_digest: str
    result_version: GraphVersion
    result_digest: str
    purpose: str
    audience: str

    def __post_init__(self):
        _text(self.producing_operation_id,"saved operation")
        _digest(self.expected_request_digest);_digest(self.result_digest)
        if (type(self.result_version)is not GraphVersion or self.result_version.revision<1
                or self.result_version.key.type_name not in {INPUT_TYPE,VIEW_TYPE,EXPRESSION_TYPE}
                or self.purpose not in {"context","consolidation","expression"}):
            raise ValueError("World cold observer requires an existing typed adopted original")
        _text(self.audience,"observer audience")

@dataclass(frozen=True, slots=True)
class WorldErasureBarrierV1:
    namespace: NamespaceId
    assertion_commitment: str
    known_from_sequence: int
    revision_commitment: str
    deletion_generation: int
    deletion_knowledge_sequence: int
    delete_original_commitment: str
    schema: str = "d03.world-erasure-barrier.v1"

    def __post_init__(self):
        if self.schema!="d03.world-erasure-barrier.v1" or type(self.namespace)is not NamespaceId:
            raise ValueError("World erasure coverage barrier schema differs")
        for value in (self.assertion_commitment,self.revision_commitment,self.delete_original_commitment):
            _digest(value)
        _sequence(self.known_from_sequence,"erased revision adoption")
        _sequence(self.deletion_generation,"actual deletion generation")
        _sequence(self.deletion_knowledge_sequence,"actual deletion knowledge watermark",0)
        if self.deletion_knowledge_sequence<self.known_from_sequence:
            raise ValueError("World deletion watermark precedes the erased actual adoption")

@dataclass(frozen=True, slots=True)
class WorldErasureBarrierRefV1:
    assertion_commitment: str
    known_from_sequence: int
    payload_digest: str

    def __post_init__(self):
        _digest(self.assertion_commitment);_digest(self.payload_digest)
        _sequence(self.known_from_sequence,"prior erased adoption")


@dataclass(frozen=True, slots=True)
class RelearnWorldAssertionRequestV1:
    assertion: WorldAssertionInputV1
    prior_erasure_ref: WorldErasureBarrierRefV1

    def __post_init__(self):
        if (type(self.assertion)is not WorldAssertionInputV1 or type(self.prior_erasure_ref)is not WorldErasureBarrierRefV1
                or self.assertion.supersedes_ref is not None
                or self.assertion.prior_erasure_digest!=self.prior_erasure_ref.payload_digest):
            raise ValueError("World relearning needs explicit actual erasure lineage and new material")
