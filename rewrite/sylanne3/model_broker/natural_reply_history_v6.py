"""Distinct v6 natural wire for bounded same-snapshot multi-block D13 history."""
from dataclasses import InitVar, asdict, dataclass, fields
from hashlib import sha256
import math

from ..domains.d09.natural_reply import NaturalExpressionPlanV2, QualifiedExpressionUnitV2
from ..graph_types import AtomKey
from ..runtime_contracts import CompletedTurnV1, VersionedRef, canonical_digest, canonical_serialize
from .context_reply import ContextReplyPartV1
from .natural_reply import NaturalReplyInstallationV2, NaturalReplyMessageV2
from .natural_reply_history_v3 import D13NaturalRawTurnV1
from .natural_reply_history_v4 import D13NaturalDetailPartV1, SYSTEM_MESSAGE_V5, OUTPUT_SCHEMA_V3

TEMPLATE_VERSION = 'sylanne.d09.context_reply_input.v6'
INPUT_SCHEMA = TEMPLATE_VERSION
OUTPUT_SCHEMA = OUTPUT_SCHEMA_V3
SYSTEM_MESSAGE = SYSTEM_MESSAGE_V5 + ' Ordered stable_history may contain multiple independently qualified derived blocks. Never infer a missing turn from block adjacency or promote cache metadata to authority.'
TEMPLATE_DIGEST = canonical_digest({'version': TEMPLATE_VERSION, 'input_schema': INPUT_SCHEMA,
    'output_schema': OUTPUT_SCHEMA, 'layout': 'system/stable_user/dynamic_user', 'system_message': SYSTEM_MESSAGE})


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

@dataclass(frozen=True, slots=True)
class D13NaturalHistorySelectionV2:
    window_digest: str
    order_watermark: int
    coverage: tuple[tuple[int, int], ...]
    gaps: tuple[tuple[int, int], ...]
    source_dependencies: tuple[VersionedRef, ...]
    read_set: tuple[VersionedRef, ...]
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    conversation_ref: str
    expires_at_utc: float
    access_epoch: int
    deletion_epoch: int
    activation_generation: int
    block_refs: tuple[VersionedRef, ...]
    raw_turn_refs: tuple[VersionedRef, ...]
    selected_slice_digest: str
    policy_ref: str
    policy_digest: str
    page_cursors: tuple[tuple[int | None, int, int, int], ...]
    collection_snapshot_commitment: str
    schema: str = 'd13.natural_history_selection.v2'
    def __post_init__(self):
        if (self.schema != 'd13.natural_history_selection.v2'
                or not all(_digest(value) for value in (self.window_digest,self.selected_slice_digest,self.policy_digest,self.collection_snapshot_commitment))
                or any(type(value) is not int or value < 0 for value in (self.order_watermark,self.access_epoch,self.deletion_epoch,self.activation_generation))
                or self.activation_generation < 1 or type(self.scene_ref) is not VersionedRef or type(self.audience_ref) is not VersionedRef
                or type(self.conversation_ref) is not str or not self.conversation_ref or type(self.policy_ref) is not str or not self.policy_ref
                or type(self.expires_at_utc) not in (int,float) or not math.isfinite(self.expires_at_utc)):
            raise ValueError('v6 history requires its exact current source/collection/policy identity')
        for refs in (self.source_dependencies,self.read_set,self.raw_turn_refs,self.block_refs):
            if type(refs) is not tuple or any(type(ref) is not VersionedRef for ref in refs) or len({ref.ref for ref in refs}) != len(refs):
                raise ValueError('v6 history references must be distinct actual versions')
        if (len(self.block_refs)>4 or len(self.raw_turn_refs)>256
                or any(ref.version<1 or AtomKey.from_token(ref.ref).type_name not in('d13.derived_block_metadata.v1','d13.derived_block_metadata.v2') for ref in self.block_refs)
                or not {self.scene_ref,self.audience_ref,*self.source_dependencies,*self.block_refs} <= set(self.read_set)):
            raise ValueError('v6 history actual metadata/source read closure is incomplete')
        for ranges in (self.coverage,self.gaps):
            if (type(ranges) is not tuple or any(type(row) is not tuple or len(row)!=2 or any(type(n) is not int or n<0 for n in row)
                    or row[0]>row[1] for row in ranges) or any(a[1]>=b[0] for a,b in zip(ranges,ranges[1:]))):
                raise ValueError('v6 history ranges must retain actual ordered coverage and gaps')
        if any(a<=d and c<=b for a,b in self.coverage for c,d in self.gaps):
            raise ValueError('v6 history coverage cannot overlap gaps')
        if (type(self.page_cursors) is not tuple or not 1<=len(self.page_cursors)<=4
                or any(type(row) is not tuple or len(row)!=4 or (row[0] is not None and (type(row[0]) is not int or row[0]<1))
                    or any(type(n) is not int for n in row[1:]) or not 1<=row[1]<=64 or row[2]<0 or row[3]<row[2]
                    or row[3]-row[2]+1>row[1] for row in self.page_cursors)
                or self.page_cursors[0][0] is not None
                or any(b[0]!=a[2] or b[3]!=a[2]-1 for a,b in zip(self.page_cursors,self.page_cursors[1:]))
                or sum(row[3]-row[2]+1 for row in self.page_cursors)>256):
            raise ValueError('v6 history pages require their exact strict cursors and bounded original scan')

@dataclass(frozen=True, slots=True)
class NaturalReplyInputV6:
    question: ContextReplyPartV1
    plan: NaturalExpressionPlanV2
    stable_history: tuple[ContextReplyPartV1, ...]
    recent_history: tuple[D13NaturalRawTurnV1, ...]
    history_selection: D13NaturalHistorySelectionV2
    detail_history: tuple[D13NaturalDetailPartV1, ...]
    frozen_at_utc: float
    expires_at_utc: float
    schema: str = INPUT_SCHEMA

    _prepared_history_eof_v3: InitVar[object] = None

    def __post_init__(self,_prepared_history_eof_v3=None):
        if _prepared_history_eof_v3 is not None:
            from ..runtime.natural_frozen_original_read_v3 import require_prepared_history_slice_v3
        selection = self.history_selection
        if (self.schema != INPUT_SCHEMA or type(self.plan) is not NaturalExpressionPlanV2 or
                type(self.question) is not ContextReplyPartV1 or self.question.kind != "question" or
                type(selection) is not D13NaturalHistorySelectionV2 or
                selection.scene_ref != self.plan.scene_ref or selection.audience_ref != self.plan.audience_ref or
                selection.conversation_ref != self.plan.audience_id or self.question.audience_ref != self.plan.audience_ref or
                type(self.stable_history) is not tuple or len(self.stable_history) > 4 or
                any(type(p) is not ContextReplyPartV1 or p.kind != "d13_history" or
                    p.ref not in selection.block_refs or p.audience_ref != self.plan.audience_ref for p in self.stable_history) or
                {p.ref for p in self.stable_history} != set(selection.block_refs) or
                type(self.recent_history) is not tuple or
                any(type(t) is not D13NaturalRawTurnV1 for t in self.recent_history)
                or type(self.detail_history) is not tuple or len(self.detail_history) > 256
                or any(type(d) is not D13NaturalDetailPartV1 for d in self.detail_history)
                or self.detail_history and not selection.block_refs):
            raise ValueError("natural V6 requires precise current D03 scope and actual history")
        if (any(type(v) not in (int,float) or not math.isfinite(v)
                for v in (self.frozen_at_utc,self.expires_at_utc)) or
                not self.frozen_at_utc < self.expires_at_utc <= min(self.plan.valid_until_utc,
                    self.question.expires_at_utc, selection.expires_at_utc) or
                any(p.expires_at_utc < self.expires_at_utc for p in self.stable_history)):
            raise ValueError("natural V6 current input lifetime differs")
        if (any(d.expires_at_utc < self.expires_at_utc
                or d.source_ref not in selection.source_dependencies for d in self.detail_history)
                or any(a.sequence > b.sequence for a, b in zip(self.detail_history, self.detail_history[1:]))
                or len({(d.sequence, d.source_ref, d.text) for d in self.detail_history}) != len(self.detail_history)
                or any(d.source_ref == t.turn.source_ref for d in self.detail_history for t in self.recent_history)):
            raise ValueError("natural V6 detail provenance, ordering or TTL differs")
        turns = tuple(t.turn for t in self.recent_history)
        if (tuple(t.raw_ref for t in turns) != selection.raw_turn_refs or
                any(t.conversation_ref != selection.conversation_ref or t.audience_ref != selection.audience_ref or
                    not 0 <= self.frozen_at_utc-t.trusted_utc < 72*3600 or
                    t.trusted_utc+72*3600 < self.expires_at_utc or
                    not {t.raw_ref,t.source_ref,t.access_ref}.issubset(selection.source_dependencies)
                    for t in turns) or any(a.sequence >= b.sequence for a,b in zip(turns,turns[1:])) or
                selection.selected_slice_digest != (canonical_digest({
                    "stable_history": self.stable_history, "recent_history": self.recent_history,
                    "detail_history": self.detail_history,
                    "coverage": selection.coverage, "gaps": selection.gaps}) if _prepared_history_eof_v3 is None else require_prepared_history_slice_v3(_prepared_history_eof_v3,self))):
            raise ValueError("natural V6 history original, order, TTL or slice differs")
        if (not self.plan.units or len({u.basis_id for u in self.plan.units}) != len(self.plan.units) or
                any(type(u) is not QualifiedExpressionUnitV2 or u.audience_ref != self.plan.audience_id or
                    u.purpose != "expression" or u.expires_at_utc < self.expires_at_utc for u in self.plan.units)):
            raise ValueError("natural V6 qualified expression basis differs")


@dataclass(frozen=True, slots=True)
class FrozenNaturalReplyRequestV6:
    input: NaturalReplyInputV6
    installation: NaturalReplyInstallationV2
    messages: tuple[NaturalReplyMessageV2, ...]
    canonical_wire: str
    stable_prefix_wire: str
    stable_prefix_digest: str
    frozen_input_digest: str
    qualified_units_digest: str
    model_request_digest: str
    schema: str = "sylanne.d09.frozen_natural_request.v6"


def freeze_natural_reply_request_v6(input, installation):
    if type(input) is not NaturalReplyInputV6 or type(installation) is not NaturalReplyInstallationV2:
        raise TypeError("typed natural V6 input and installed model required")
    input_schema = INPUT_SCHEMA
    scope = {"namespace": asdict(input.plan.namespace), "scene_id": input.plan.scene_id,
        "audience_id": input.plan.audience_id, "scene_ref": asdict(input.plan.scene_ref),
        "audience_ref": asdict(input.plan.audience_ref)}
    plan = asdict(input.plan)
    plan.pop("units")
    stable = canonical_serialize({"schema": input_schema, "scope": scope,
        "stable_history": [asdict(p) for p in input.stable_history]})
    dynamic = canonical_serialize({"schema": input_schema, "scope": scope,
        "frozen_at_utc": input.frozen_at_utc, "expires_at_utc": input.expires_at_utc,
        "question": asdict(input.question), "expression_plan": plan,
        "qualified_units": [asdict(u) for u in input.plan.units],
        "recent_history": [asdict(t) for t in input.recent_history],
        "detail_history": [asdict(d) for d in input.detail_history],
        "history_selection": asdict(input.history_selection)})
    messages = (NaturalReplyMessageV2("system",SYSTEM_MESSAGE),
        NaturalReplyMessageV2("user",stable), NaturalReplyMessageV2("user",dynamic))
    wire = canonical_serialize({"provider_id": installation.provider_id,
        "model": installation.model_id,"messages": [asdict(m) for m in messages],
        "max_output_tokens": installation.max_output_tokens})
    prefix = ('{"max_output_tokens":'+str(installation.max_output_tokens)+',"messages":['+
        canonical_serialize(asdict(messages[0]))+','+canonical_serialize(asdict(messages[1]))+',{"content":')
    if not wire.startswith(prefix):
        raise ValueError("natural V6 stable prefix differs from actual wire")
    return FrozenNaturalReplyRequestV6(input, installation, messages, wire, prefix,
        canonical_digest({"template_digest":TEMPLATE_DIGEST,"installation":installation,
            "stable_prefix_sha256":sha256(prefix.encode()).hexdigest()}),canonical_digest(input),
        canonical_digest(input.plan.units),sha256(wire.encode()).hexdigest(),
        "sylanne.d09.frozen_natural_request.v6")



def thaw_natural_reply_request_v6(raw,*,prepared_eof=None):
    """Strict canonical V6 decoder; it does not reinterpret a V2 original."""
    if prepared_eof is not None:
        from ..runtime.natural_frozen_original_read_v3 import require_prepared_natural_frozen_v3
        return require_prepared_natural_frozen_v3(prepared_eof,raw,version=6)
    from ..runtime.natural_reply_job_v2 import _part, _unit
    from ..runtime_contracts import NamespaceId
    if type(raw) is not dict or set(raw) != {f.name for f in fields(FrozenNaturalReplyRequestV6)}:
        raise ValueError("natural V6 frozen fields differ")
    data = raw["input"]
    if type(data) is not dict or set(data) != {f.name for f in fields(NaturalReplyInputV6)}:
        raise ValueError("natural V6 input fields differ")
    p = dict(data["plan"])
    p["namespace"] = NamespaceId(**p["namespace"])
    for k in ("plan_ref","scene_ref","audience_ref"):
        p[k] = VersionedRef(**p[k])
    for k in ("required_slots","allowed_speech_acts"):
        p[k] = tuple(p[k])
    p["promise_grants"] = tuple(VersionedRef(**v) for v in p["promise_grants"])
    p["units"] = tuple(_unit(v) for v in p["units"])
    sel = dict(data["history_selection"])
    for k in ("scene_ref","audience_ref"):
        sel[k] = None if sel[k] is None else VersionedRef(**sel[k])
    for k in ("source_dependencies","read_set","raw_turn_refs","block_refs"):
        sel[k] = tuple(VersionedRef(**v) for v in sel[k])
    for k in ("coverage","gaps","page_cursors"):
        sel[k] = tuple(tuple(v) for v in sel[k])
    recent = []
    for item in data["recent_history"]:
        if type(item) is not dict or set(item) != {"turn","completion_ref"}:
            raise ValueError("natural V6 raw turn fields differ")
        turn = dict(item["turn"])
        for k in ("audience_ref","raw_ref","source_ref","access_ref"):
            turn[k] = VersionedRef(**turn[k])
        recent.append(D13NaturalRawTurnV1(CompletedTurnV1(**turn),VersionedRef(**item["completion_ref"])))
    expected = freeze_natural_reply_request_v6(NaturalReplyInputV6(
        _part(data["question"]),NaturalExpressionPlanV2(**p),tuple(_part(v) for v in data["stable_history"]),
        tuple(recent),D13NaturalHistorySelectionV2(**sel),
        tuple(D13NaturalDetailPartV1(d["sequence"], VersionedRef(**d["source_ref"]),
            d["speaker_ref"], d["text"], d["expires_at_utc"]) for d in data["detail_history"]),
        data["frozen_at_utc"],data["expires_at_utc"],data["schema"]),
        NaturalReplyInstallationV2(**raw["installation"]))
    if canonical_serialize(asdict(expected)) != canonical_serialize(raw):
        raise ValueError("natural V6 canonical frozen original changed")
    return expected


def parse_natural_reply_output_v6(text, frozen):
    from .natural_reply import _parse_natural_reply_output_payload
    if (type(frozen) is not FrozenNaturalReplyRequestV6 or
            freeze_natural_reply_request_v6(frozen.input,frozen.installation) != frozen):
        raise ValueError("natural V6 frozen original differs")
    return _parse_natural_reply_output_payload(text, frozen)
