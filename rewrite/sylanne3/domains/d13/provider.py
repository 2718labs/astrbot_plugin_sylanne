"""D13 provider over D11-issued windows; no local source or job repository."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from typing import Mapping

from ...graph_types import TypeSpec
from ...runtime_contracts import (
    CompressedTurnBlockV2, ConversationWindowProjectionV1, DomainProposal,
    ProviderDescriptor, RUNTIME_SCHEMA, ShortContextRequestV1,
    ShortContextSliceV1, TurnAnchorV1, TurnDetailSlotV1,
    TurnTimelineItemV1, VersionedRef, schema_hash,
)
from .precompression import (
    D13CurrentPaidModelVerifierV2, EXTRACTIVE_MODEL_VERSION,
    PrecompressionPlan, _fingerprint, _model_candidate_current,
    compile_deterministic_candidate, render_detail_slot,
    select_detail_slots,
)
from .prefix import stable_segment_digest
from .raw_slice import (
    _MAX_AGE_SECONDS, _implicit_missing_ranges, _merge_ranges,
    assemble_raw_slice,
)


PROPOSAL_SCHEMA = "d13.proposal.v1"
_PROPOSAL_HASH = schema_hash({"domain": "d13", "proposal": 1, "mode": "derived_cache"})
_BLOCK_TYPE = "d13.compressed_turn_block.v2"


@dataclass(frozen=True, slots=True)
class ShortContextProjectionQueryV1:
    """D11 supplies a current, authorized window and optional active cache."""

    window: ConversationWindowProjectionV1
    request: ShortContextRequestV1
    active_block: CompressedTurnBlockV2 | None = None
    active_plan: PrecompressionPlan | None = None
    query_keys: tuple[str, ...] = ()
    query_text: str = ""
    rementioned_sources: tuple[VersionedRef, ...] = ()
    evidence_sources: tuple[VersionedRef, ...] = ()

    def __post_init__(self) -> None:
        if type(self.window) is not ConversationWindowProjectionV1:
            raise TypeError("window must be a D11 projection")
        if type(self.request) is not ShortContextRequestV1:
            raise TypeError("request must be ShortContextRequestV1")
        if (self.active_block is None) != (self.active_plan is None):
            raise ValueError("active block and plan must be supplied together")
        if self.active_block is not None and type(self.active_block) is not CompressedTurnBlockV2:
            raise TypeError("active_block must be CompressedTurnBlockV2")
        if self.active_plan is not None and type(self.active_plan) is not PrecompressionPlan:
            raise TypeError("active_plan must be PrecompressionPlan")
        if type(self.query_keys) is not tuple or any(
                type(key) is not str or not key for key in self.query_keys):
            raise ValueError("query_keys must be a tuple of trusted nonempty strings")
        if len(set(self.query_keys)) != len(self.query_keys):
            raise ValueError("query_keys must be unique")
        if type(self.query_text) is not str or len(self.query_text.encode("utf-8")) > 4096:
            raise ValueError("query_text must be bounded text")
        for name in ("rementioned_sources", "evidence_sources"):
            refs = getattr(self, name)
            if type(refs) is not tuple or any(type(ref) is not VersionedRef for ref in refs):
                raise TypeError(f"{name} must contain versioned source references")


def block_graph_value(block: CompressedTurnBlockV2) -> dict:
    """JSON-shaped value for the shared graph cache, pending D11 store wiring."""
    if type(block) is not CompressedTurnBlockV2:
        raise TypeError("block must be CompressedTurnBlockV2")
    return json.loads(json.dumps(asdict(block), allow_nan=False))


def _ref(value: object) -> VersionedRef:
    if type(value) is not dict or set(value) != {"ref", "version"}:
        raise ValueError("invalid versioned reference")
    return VersionedRef(**value)


def _block_from_graph_value(value: object) -> CompressedTurnBlockV2:
    if type(value) is not dict or set(value) != {
        "block_ref", "conversation_ref", "audience_ref", "turns", "source_dependencies",
        "timeline", "detail_slots", "omitted_ranges", "compiler_version", "job_ref",
        "candidate_ref", "expires_at_utc", "status", "schema",
    }:
        raise ValueError("invalid D13 block graph fields")
    if any(type(value[name]) is not list for name in (
            "turns", "source_dependencies", "timeline", "detail_slots", "omitted_ranges")):
        raise ValueError("invalid D13 block graph collection")
    turns = tuple(TurnAnchorV1(
        item["conversation_ref"], _ref(item["audience_ref"]), item["sequence"],
        _ref(item["raw_ref"]), _ref(item["source_ref"]), _ref(item["access_ref"]),
        item["speaker_ref"], item["trusted_utc"],
    ) for item in value["turns"])
    timeline = tuple(TurnTimelineItemV1(
        item["sequence"], _ref(item["source_ref"]), item["speaker_ref"], item["text"]
    ) for item in value["timeline"])
    details = tuple(TurnDetailSlotV1(
        item["key"], item["sequence"], _ref(item["source_ref"]), item["text"]
    ) for item in value["detail_slots"])
    return CompressedTurnBlockV2(
        value["block_ref"], value["conversation_ref"], _ref(value["audience_ref"]),
        turns, tuple(_ref(item) for item in value["source_dependencies"]),
        timeline, details, tuple(tuple(item) for item in value["omitted_ranges"]),
        value["compiler_version"], value["job_ref"], value["candidate_ref"],
        value["expires_at_utc"], value["status"], value["schema"],
    )


def validate_block_graph_value(value: object) -> None:
    try:
        block = _block_from_graph_value(value)
        if block_graph_value(block) != value:
            raise ValueError("D13 block graph value is not canonical")
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("invalid D13 block graph value") from exc


def retirement_reason(
    block: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1,
) -> str | None:
    """Classify a stored block against D11's current authorized window.

    None means the source closure is current; it does not authorize a model
    call or prove that a model-assisted block's text is faithful.
    """
    if block.status not in {"standby", "active"}:
        raise ValueError("stored standby or active D13 block required")
    if window.trusted_utc >= block.expires_at_utc:
        return "72h_expired"
    covered = tuple(t for t in window.turns
                    if plan.first_sequence <= t.sequence <= plan.last_sequence)
    if (
        block.conversation_ref != window.conversation_ref or
        block.audience_ref != window.audience_ref or
        block.block_ref != f"d13:block:{plan.input_digest}" or
        block.job_ref != plan.job_ref or block.candidate_ref != plan.candidate_ref or
        block.expires_at_utc != plan.expires_at_utc or
        window.scene_ref != plan.scene_ref or window.audience_ref != plan.audience_ref or
        (window.access_epoch, window.delete_epoch, window.activation_epoch) !=
        (plan.access_epoch, plan.delete_epoch, plan.activation_epoch) or
        len(covered) != plan.last_sequence - plan.first_sequence + 1 or
        not covered or covered[0].sequence != plan.first_sequence or
        covered[-1].sequence != plan.last_sequence or
        _fingerprint(window, covered) != plan.input_digest or
        block.turns != tuple(TurnAnchorV1.from_turn(t) for t in covered) or
        block.source_dependencies != plan.source_dependencies or
        not set(block.source_dependencies).issubset(window.source_dependencies)
    ):
        return "source_invalidated"
    return None


def prepare_retirement(
    block: CompressedTurnBlockV2, plan: PrecompressionPlan,
    window: ConversationWindowProjectionV1, *, cache_revision: int,
) -> object:
    """Build D11's CAS intent from a verified expiry/invalidation reason."""
    reason = retirement_reason(block, plan, window)
    if reason is None:
        raise ValueError("current D13 block is not due for retirement")
    from ...runtime.d13_precompression_job import prepare_retirement_intent_v1

    return prepare_retirement_intent_v1(
        block, window, cache_revision=cache_revision,
        source_invalidated=reason == "source_invalidated",
    )


def _active_slice(
    query: ShortContextProjectionQueryV1,
    paid_verifier: D13CurrentPaidModelVerifierV2 | None = None,
) -> ShortContextSliceV1:
    window, request, block, plan = (query.window, query.request,
                                    query.active_block, query.active_plan)
    assert block is not None and plan is not None
    if not request.opt_in or (request.conversation_ref, request.scene_ref, request.audience_ref) != (
            window.conversation_ref, window.scene_ref, window.audience_ref):
        raise ValueError("short context requires a matching opt-in")
    if block.status != "active":
        raise ValueError("active block required")
    reason = retirement_reason(block, plan, window)
    if reason is not None:
        raise ValueError(f"active block requires retirement: {reason}")
    # Model output needs both current exact-source validation and the original
    # paid-result port on every read; a stored active bit is never enough.
    if block.compiler_version == EXTRACTIVE_MODEL_VERSION:
        if not _model_candidate_current(block, plan, window, paid_verifier):
            raise ValueError("active model block lacks current paid/source proof")
    else:
        expected = compile_deterministic_candidate(window, plan)
        if block != replace(expected, status="active"):
            raise ValueError("active block differs from current authorized source")
    covered_end = block.turns[-1].sequence
    recent_tail = tuple(t for t in window.turns if t.sequence > covered_end
                        and 0 <= window.trusted_utc - t.trusted_utc < _MAX_AGE_SECONDS)
    stable_lines = [f"[{item.sequence} {item.speaker_ref}] {item.text}"
                    for item in block.timeline]
    block_bytes = len("\n".join(stable_lines).encode("utf-8"))
    include_block = block_bytes <= request.history_token_budget
    used = block_bytes if include_block else 0
    if not include_block:
        stable_lines = []
    chosen = []
    for turn in reversed(recent_tail):
        if chosen and chosen[-1].sequence != turn.sequence + 1:
            break
        size = used + len(f"{turn.speaker_ref}: {turn.text}".encode("utf-8")) + (
            1 if stable_lines or chosen else 0)
        if size > request.history_token_budget:
            break
        chosen.append(turn)
        used = size
    chosen.reverse()
    selected = (block,) if include_block else ()
    detail_slots = select_detail_slots(
        block, query_keys=query.query_keys,
        detail_byte_budget=max(0, request.history_token_budget - used - (1 if used else 0)),
        query_text=query.query_text,
        rementioned_sources=query.rementioned_sources,
        evidence_sources=tuple(dict.fromkeys((
            *query.evidence_sources, *(t.source_ref for t in chosen)))),
    ) if include_block else ()
    if detail_slots:
        used += 1 + len("\n".join(render_detail_slot(block, slot)
                                    for slot in detail_slots).encode("utf-8"))
    represented = {a.sequence for b in selected for a in b.turns} | {t.sequence for t in chosen}
    missing = [*window.missing_ranges, *_implicit_missing_ranges(window)]
    missing.extend((t.sequence, t.sequence) for t in window.turns if t.sequence not in represented)
    missing.extend(r for b in selected for r in b.omitted_ranges)
    deps = tuple(dict.fromkeys(
        (r for b in selected for r in b.source_dependencies),
    ))
    deps = tuple(dict.fromkeys((*deps, *(r for t in chosen
                                  for r in (t.raw_ref, t.source_ref, t.access_ref)))))
    expiry = min((*(b.expires_at_utc for b in selected),
                  *(t.trusted_utc + _MAX_AGE_SECONDS for t in chosen)),
                 default=window.trusted_utc)
    prefix = stable_segment_digest(window, request, "\n".join(stable_lines))
    return ShortContextSliceV1(
        window.conversation_ref, window.audience_ref, selected, tuple(chosen),
        tuple(slot.key for slot in detail_slots),
        deps, _merge_ranges(missing), expiry, prefix, used,
    )


def render_active_slice(context_slice: ShortContextSliceV1) -> str:
    """Stable block spine and raw tail, followed by selected dynamic values."""
    if type(context_slice) is not ShortContextSliceV1 or not context_slice.blocks:
        raise ValueError("active D13 slice required")
    stable = [f"[{item.sequence} {item.speaker_ref}] {item.text}"
              for block in context_slice.blocks for item in block.timeline]
    stable.extend(f"{turn.speaker_ref}: {turn.text}" for turn in context_slice.raw_tail)
    by_key = {slot.key: (block, slot) for block in context_slice.blocks
              for slot in block.detail_slots}
    dynamic = [render_detail_slot(*by_key[key])
               for key in context_slice.selected_detail_slots]
    return "\n".join((*stable, *dynamic))


def validate_slice_for_consumption(
    query: ShortContextProjectionQueryV1,
    context_slice: ShortContextSliceV1,
    current_window: ConversationWindowProjectionV1,
    *, paid_verifier: D13CurrentPaidModelVerifierV2 | None = None,
) -> None:
    """Recheck a frozen slice against D11's trusted window at model egress.

    D11 must obtain ``current_window`` from the current authorized graph inside
    the egress fence. A saved projection or caller-supplied clock is not proof
    of current source access. Any intervening graph or representation change
    requires a newly frozen model request.
    """
    if (type(query) is not ShortContextProjectionQueryV1 or
            type(context_slice) is not ShortContextSliceV1 or
            type(current_window) is not ConversationWindowProjectionV1):
        raise TypeError("typed D13 query, slice and current window required")
    original = query.window
    if current_window.trusted_utc < original.trusted_utc:
        raise ValueError("D13 trusted clock moved backwards")
    if current_window.trusted_utc >= context_slice.expires_at_utc and (
            context_slice.blocks or context_slice.raw_tail):
        raise ValueError("D13 slice crossed its 72-hour deadline")
    if (
        current_window.namespace != original.namespace or
        current_window.owner_ref != original.owner_ref or
        current_window.conversation_ref != original.conversation_ref or
        current_window.scene_ref != original.scene_ref or
        current_window.audience_ref != original.audience_ref or
        current_window.order_watermark != original.order_watermark or
        current_window.read_set != original.read_set or
        current_window.source_dependencies != original.source_dependencies or
        (current_window.access_epoch, current_window.delete_epoch,
         current_window.activation_epoch) !=
        (original.access_epoch, original.delete_epoch, original.activation_epoch)
    ):
        raise ValueError("D13 source or access read set changed")
    refreshed = D13ShortContextProvider().project(
        replace(query, window=current_window), paid_verifier=paid_verifier)
    if refreshed != context_slice:
        raise ValueError("D13 frozen slice differs from current authorized projection")


class D13ShortContextProvider:
    """Read-only domain seam until W01/W09 install the derived-cache write port."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            "d13.short_context", RUNTIME_SCHEMA, _PROPOSAL_HASH,
            schema_hash({"domain": "d13", "response": "short_context_slice.v1"}),
            ("persona",), ("structured_text",), ("recent_context",), ("runtime",),
            "bounded", "cooperative", "operation_id", "d11_receipt",
            ("project_raw", "project_deterministic_active"), ("rebuild_from_raw",),
        )

    @staticmethod
    def register_types() -> tuple[TypeSpec, ...]:
        return (TypeSpec(
            name=_BLOCK_TYPE, owner_kinds=("persona",), storage_role="cache",
            validator=validate_block_graph_value, immutable=False,
            schema_version=2, writer_domain="d13",
            schema_hash=schema_hash({"domain": "d13", "type": _BLOCK_TYPE,
                                     "owner": "persona", "storage": "cache", "version": 2}),
        ),)

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if type(proposal) is not DomainProposal or (
                proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash) != (
                "d13", PROPOSAL_SCHEMA, _PROPOSAL_HASH):
            raise ValueError("unrecognized D13 proposal")
        if proposal.typed_writes:
            raise ValueError("D13 cache writes require the W01/D11 admission port")
        return proposal

    def compile_scheme(self, draft: object, snapshot: object = None) -> object:
        raise LookupError("D13 has no character scheme")

    def project(self, query: ShortContextProjectionQueryV1,
                snapshot: object = None, *,
                paid_verifier: D13CurrentPaidModelVerifierV2 | None = None,
                ) -> ShortContextSliceV1:
        if type(query) is not ShortContextProjectionQueryV1:
            raise TypeError("D13 requires a typed projection query")
        if snapshot is not None and snapshot is not query.window:
            raise ValueError("projection snapshot does not match D11 window")
        return (_active_slice(query, paid_verifier) if query.active_block is not None else
                assemble_raw_slice(query.window, query.request))

    def invalidate(self, refs: tuple[object, ...]) -> tuple[object, ...]:
        if type(refs) is not tuple:
            raise TypeError("refs must be a tuple")
        return refs  # D11 performs synchronous read blocking and physical cleanup.

    def cleanup(self, plan: object) -> object:
        raise LookupError("D13 physical cache cleanup requires the D11 store")


__all__ = (
    "PROPOSAL_SCHEMA", "ShortContextProjectionQueryV1", "D13ShortContextProvider",
    "block_graph_value", "validate_block_graph_value", "render_active_slice",
    "retirement_reason", "prepare_retirement",
    "validate_slice_for_consumption",
)
