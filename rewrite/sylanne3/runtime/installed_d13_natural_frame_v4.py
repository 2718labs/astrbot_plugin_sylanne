"""Actual V4 wire assembly over the transaction's current authorized window.

This module never performs network I/O or mutates a cache. Installed full-wire
policy is a separate authority dependency; absence never becomes token proof.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import math

from ..domains.d13.provider import D13ShortContextProvider, ShortContextProjectionQueryV1
from ..domains.d13.raw_slice import _merge_ranges
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..model_broker.context_reply import ContextReplyPartV1
from ..model_broker.natural_reply_history_v4 import (
    TEMPLATE_VERSION, D13NaturalDetailPartV1, D13NaturalHistorySelectionV1,
    D13NaturalRawTurnV1, FrozenNaturalReplyRequestV4, NaturalReplyInputV4,
    freeze_natural_reply_request_v4,
)
from ..runtime_contracts import ShortContextRequestV1, VersionedRef, canonical_digest
from .d13_current_window import read_current_d13_window_for_authority_v1

POLICY_REF = "d13.natural.current_full_wire.v4"


@dataclass(frozen=True, slots=True)
class D13NaturalWireDecisionV1:
    """An installed policy's verified read, not a caller-supplied fit flag.

    Implementations must verify both full provider wires, exact installation,
    source closure, lifetime and current foreground worst-cost budget. The
    caller cannot supply this result to the public frame function.
    """
    selected: str
    token_evidence: str
    proof_digest: str
    raw_request_digest: str
    compressed_request_digest: str
    current_window_digest: str
    policy_digest: str
    expires_at_utc: float
    budget_state: str = "reserved_original"

    def __post_init__(self):
        if self.budget_state not in {"preparation_only", "reserved_original"}:
            raise ValueError("installed D13 budget state differs")
        if self.selected not in {"raw", "compressed", "hold"}:
            raise ValueError("unknown installed D13 wire decision")
        if self.token_evidence not in {"exact_full_wire", "bounded_full_wire"}:
            raise ValueError("installed full-wire evidence required")
        for value in (self.proof_digest, self.raw_request_digest,
                      self.compressed_request_digest, self.current_window_digest,
                      self.policy_digest):
            if (type(value) is not str or len(value) != 64
                    or any(c not in "0123456789abcdef" for c in value)):
                raise ValueError("full-wire decision needs exact SHA-256 bindings")
        if type(self.expires_at_utc) not in (int, float) or not math.isfinite(self.expires_at_utc):
            raise ValueError("full-wire decision needs finite expiry")


@dataclass(frozen=True, slots=True)
class NaturalHistoryDecisionV4:
    selected: str
    token_evidence: str
    activation: str
    policy_digest: str
    wire_digest: str
    proof_digest: str | None = None
    activation_write: GraphWrite | None = None
    activation_expected: GraphVersion | None = None
    budget_state: str = "unverified"


@dataclass(frozen=True, slots=True)
class D13NaturalWirePreflightV1:
    """Non-authorizing complete pair for an out-of-transaction counter read.

    The cache target may not exist yet. This is never a prior admission or a
    saved model original. Final preparation must regenerate these exact bytes
    from CURRENT source eligibility and the same old cache CAS revision.
    """
    raw: FrozenNaturalReplyRequestV4
    compressed: FrozenNaturalReplyRequestV4
    current_window: object
    standby: object
    precompression_plan: object
    cache_ref: VersionedRef
    cache_status: str
    installed_policy_digest: str
    frame_policy_digest: str
    status: str = "non_authorizing_preflight"

    def __post_init__(self):
        from ..runtime_contracts import ConversationWindowProjectionV1, CompressedTurnBlockV2
        from ..domains.d13.precompression import PrecompressionPlan
        if (type(self.raw) is not FrozenNaturalReplyRequestV4
                or type(self.compressed) is not FrozenNaturalReplyRequestV4
                or type(self.current_window) is not ConversationWindowProjectionV1
                or type(self.standby) is not CompressedTurnBlockV2
                or type(self.precompression_plan) is not PrecompressionPlan
                or type(self.cache_ref) is not VersionedRef or self.cache_ref.version < 1
                or self.cache_status not in {"standby", "active"}
                or self.status != "non_authorizing_preflight"
                or self.standby.status != "standby"
                or self.raw.input.stable_history or not self.compressed.input.stable_history
                or self.raw.input.question != self.compressed.input.question
                or self.raw.input.plan != self.compressed.input.plan
                or self.raw.installation != self.compressed.installation
                or self.raw.input.frozen_at_utc != self.compressed.input.frozen_at_utc
                or self.raw.input.expires_at_utc != self.compressed.input.expires_at_utc
                or self.current_window.trusted_utc != self.raw.input.frozen_at_utc
                or self.current_window.namespace != self.raw.input.plan.namespace
                or canonical_digest(self.current_window) != self.raw.input.history_selection.window_digest
                or canonical_digest(self.current_window) != self.compressed.input.history_selection.window_digest
                or self.standby.job_ref != self.precompression_plan.job_ref
                or AtomKey.from_token(self.cache_ref.ref).name != self.standby.block_ref
                or self.compressed.input.history_selection.block_ref != VersionedRef(
                    self.cache_ref.ref, self.cache_ref.version + (self.cache_status == "standby"))
                or self.raw != freeze_natural_reply_request_v4(self.raw.input, self.raw.installation)
                or self.compressed != freeze_natural_reply_request_v4(self.compressed.input, self.compressed.installation)):
            raise ValueError("D13 preflight must retain the exact non-authorizing original pair")
        for digest in (self.installed_policy_digest, self.frame_policy_digest):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("D13 preflight needs pinned policy identities")
        if (self.raw.input.history_selection.policy_digest != self.frame_policy_digest
                or self.compressed.input.history_selection.policy_digest != self.frame_policy_digest):
            raise ValueError("D13 preflight frame policy differs")

    @property
    def frozen_at_utc(self):
        return self.raw.input.frozen_at_utc

    @property
    def expires_at_utc(self):
        return self.raw.input.expires_at_utc

    @property
    def digest(self):
        return canonical_digest(self)


def prepare_current_natural_wire_preflight_v1(db, **kwargs):
    """Read one eligible pair, without selecting compression or reserving cost."""
    if any(name in kwargs for name in ("original", "preflight", "preflight_out")):
        raise ValueError("first D13 preflight cannot masquerade as original replay")
    pending = []
    freeze_current_natural_frame_v4(db, **kwargs, preflight_out=pending)
    return pending[0] if pending else None


def build_natural_frame_v4(*, window, plan, question, installation,
                           frozen_at_utc, expires_at_utc, policy_digest,
                           context_query=None, block_ref=None, paid_verifier=None):
    """Pure exact wire construction, not permission to consume compression.

    The compressed option validates its real active projection independently.
    Activation selection is performed only by the installed full-wire port.
    """
    if (window.scene_ref != plan.scene_ref or window.audience_ref != plan.audience_ref
            or question.audience_ref != plan.audience_ref
            or window.namespace != plan.namespace
            or window.conversation_ref != plan.audience_id):
        raise ValueError("D13 and natural reply must use the same current D03 scope")
    stable, details, block_version = (), (), None
    read_set = window.read_set
    if context_query is None:
        if block_ref is not None:
            raise ValueError("raw history cannot carry a cache head")
        turns = tuple(t for t in window.turns if t.source_ref != question.ref
                      and 0 <= window.trusted_utc - t.trusted_utc < 72 * 3600)
        gaps = _merge_ranges((*window.missing_ranges,
            *((t.sequence, t.sequence) for t in window.turns
              if t.source_ref != question.ref and t not in turns)))
        represented = {t.sequence for t in turns}
        dependencies = tuple(dict.fromkeys(r for t in turns
                                          for r in (t.raw_ref, t.source_ref, t.access_ref)))
        expiry = min((expires_at_utc, *(t.trusted_utc + 72 * 3600 for t in turns)))
    else:
        if (type(context_query) is not ShortContextProjectionQueryV1
                or context_query.window != window or type(block_ref) is not VersionedRef
                or context_query.active_block is None
                or AtomKey.from_token(block_ref.ref).name != context_query.active_block.block_ref):
            raise ValueError("compressed history requires the actual current cache head")
        projected = D13ShortContextProvider().project(context_query, paid_verifier=paid_verifier)
        if len(projected.blocks) != 1:
            raise ValueError("compressed natural history needs one represented block")
        block = projected.blocks[0]
        # A question is sent once, in the dynamic question field; never hide a
        # duplicate question in a summary or invent a raw historical turn.
        if any(t.source_ref == question.ref for t in block.turns):
            raise ValueError("current question must not be compressed as history")
        turns = tuple(t for t in projected.raw_tail if t.source_ref != question.ref)
        expiry = min(expires_at_utc, projected.expires_at_utc)
        stable_text = "\n".join(f"[{t.sequence} {t.speaker_ref}] {t.text}" for t in block.timeline)
        stable = (ContextReplyPartV1("d13_history", block_ref, window.audience_ref,
                                    expiry, stable_text, block.source_dependencies),)
        selected = set(projected.selected_detail_slots)
        speakers = {(t.sequence, t.source_ref): t.speaker_ref for t in block.turns}
        details = tuple(D13NaturalDetailPartV1(
            slot.sequence, slot.source_ref, speakers[(slot.sequence, slot.source_ref)],
            slot.text, expiry) for slot in sorted(block.detail_slots,
                key=lambda s: (s.sequence, s.key)) if slot.key in selected)
        dependencies = projected.source_dependencies
        gaps = projected.missing_ranges
        represented = {t.sequence for t in block.turns} | {t.sequence for t in turns}
        block_version = block_ref
        read_set = tuple(dict.fromkeys((*read_set, block_ref)))
    coverage = _merge_ranges((n, n) for n in sorted(represented)
                            if not any(a <= n <= b for a, b in gaps))
    raw = tuple(D13NaturalRawTurnV1(t, t.raw_ref) for t in turns)
    selection = D13NaturalHistorySelectionV1(
        canonical_digest(replace(window, trusted_utc=frozen_at_utc)),
        window.order_watermark, coverage, gaps, dependencies, read_set,
        window.scene_ref, window.audience_ref, window.conversation_ref, expiry,
        window.access_epoch, window.delete_epoch, window.activation_epoch,
        block_version, tuple(t.raw_ref for t in turns),
        canonical_digest({"stable_history": stable, "recent_history": raw,
                          "detail_history": details, "coverage": coverage, "gaps": gaps}),
        POLICY_REF, policy_digest)
    return freeze_natural_reply_request_v4(NaturalReplyInputV4(
        question, plan, stable, raw, selection, details, frozen_at_utc, expiry), installation)


def freeze_current_natural_frame_v4(
    db, *, namespace, plan, question, installation, now_utc, expires_at_utc,
    activation_generation, max_slots=64, original=None, installed_wire_port=None,
    paid_verifier=None, history_byte_budget=262144, cache_ref=None,
    preflight=None, preflight_out=None,
):
    """Read current scope, prepare the real pair, then ask installed authority.

    ``installed_wire_port`` is an installation-created authority service, never
    decoded from request input. It supplies a SHA-256 ``policy_digest`` and
    ``evaluate_natural_pair_v4(raw=..., compressed=..., current_window=...,
    standby=..., precompression_plan=..., now_utc=...)`` returning
    D13NaturalWireDecisionV1 after independent source/model/full-wire/budget
    verification. It must not perform network I/O inside this transaction.

    Cache writes are returned, never applied here. The caller must atomically
    apply both the old revision CAS and active target with the first job. An
    original recheck returns no write and cannot choose another candidate.
    """
    import json
    from ..domains.d13.provider import _block_from_graph_value, block_graph_value, retirement_reason
    from .d13_precompression_job import plan_from_precompression_job_v1
    from .jobs import get_job
    if not db.in_transaction:
        raise ValueError("D13 V4 needs the current fenced transaction")
    if type(history_byte_budget) is not int or not 1 <= history_byte_budget <= 4 * 1024 * 1024:
        raise ValueError("D13 history byte safety cap is invalid")
    if preflight_out is not None and (type(preflight_out) is not list or preflight_out
            or original is not None or preflight is not None):
        raise ValueError("D13 first preflight needs a fresh output collector")
    if preflight is not None and (type(preflight) is not D13NaturalWirePreflightV1
            or original is not None or preflight.raw.input.plan != plan
            or preflight.raw.input.question != question or preflight.raw.installation != installation
            or not preflight.frozen_at_utc <= now_utc < preflight.expires_at_utc
            or expires_at_utc < preflight.expires_at_utc):
        raise ValueError("D13 retained preflight scope, model or CURRENT lifetime changed")
    if original is not None and (type(original) is not FrozenNaturalReplyRequestV4
            or original.input.plan != plan or original.input.question != question
            or original.installation != installation or now_utc >= original.input.expires_at_utc
            or now_utc < original.input.frozen_at_utc):
        raise ValueError("D13 original V4 input or lifetime changed")
    window = read_current_d13_window_for_authority_v1(
        db, namespace, plan.scene_id, plan.audience_id, max_slots, now_utc,
        expected_activation_generation=activation_generation)
    installed_policy = getattr(installed_wire_port, "policy_digest", None)
    if installed_wire_port is not None and (type(installed_policy) is not str
            or len(installed_policy) != 64
            or any(c not in "0123456789abcdef" for c in installed_policy)):
        raise ValueError("installed full-wire policy identity absent")
    policy_digest = canonical_digest({"schema": POLICY_REF, "max_slots": max_slots,
        "history_byte_safety_cap": history_byte_budget, "max_age_seconds": 72 * 3600,
        "installation": installation, "installed_full_wire_policy": installed_policy})
    if preflight is not None and (
            installed_policy != preflight.installed_policy_digest
            or policy_digest != preflight.frame_policy_digest
            or replace(window, trusted_utc=preflight.frozen_at_utc) != preflight.current_window):
        raise ValueError("D13 preflight CURRENT source/access/order/generation or installed policy changed")
    at = (preflight.frozen_at_utc if preflight is not None else
          now_utc if original is None else original.input.frozen_at_utc)
    expiry = (preflight.expires_at_utc if preflight is not None else
              expires_at_utc if original is None else original.input.expires_at_utc)
    raw = build_natural_frame_v4(window=window, plan=plan, question=question,
        installation=installation, frozen_at_utc=at, expires_at_utc=expiry,
        policy_digest=policy_digest)

    def finish(frozen, proof=None, write=None, expected=None):
        if original is not None and (frozen != original
                or freeze_natural_reply_request_v4(original.input, original.installation) != original):
            raise ValueError("D13 original V4 wire or selection is no longer current")
        reads = tuple(GraphVersion(AtomKey.from_token(ref.ref), ref.version)
                      for ref in frozen.input.history_selection.read_set)
        if expected is not None:
            reads = tuple(expected if r.key == expected.key else r for r in reads)
        return frozen, reads, NaturalHistoryDecisionV4(
            "compressed" if frozen.input.stable_history else "raw",
            "token_evidence_unverified" if proof is None else proof.token_evidence,
            "activation_not_attempted" if write is None else "activation_prepared",
            policy_digest, frozen.model_request_digest,
            None if proof is None else proof.proof_digest, write, expected,
            "unverified" if proof is None else proof.budget_state)

    if original is not None and original.input.history_selection.block_ref is None:
        return finish(raw)
    if installed_wire_port is None:
        return finish(raw)  # A compressed original fails equality rather than degrading.
    requested_ref = (preflight.cache_ref if preflight is not None else
                     original.input.history_selection.block_ref if original else cache_ref)
    if requested_ref is not None:
        rows = db.execute("SELECT token,revision,value FROM graph_atoms WHERE token=? AND valid=1",
                          (requested_ref.ref,)).fetchall()
        if not rows or rows[0][1] != requested_ref.version:
            if original or preflight is not None:
                raise ValueError("D13 original/preflight cache head changed")
            return finish(raw)
    else:
        rows = db.execute(
            "SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d13.compressed_turn_block.v2' AND owner_kind='persona' "
            "AND valid=1 ORDER BY json_extract(value,'$.turns[#-1].sequence') DESC,token LIMIT 16",
            namespace.as_tuple).fetchall()
    for token, revision, value in rows:
        try:
            key = AtomKey.from_token(token)
            block = _block_from_graph_value(json.loads(value))
            if (key.owner.kind != "persona" or (key.owner.bot, key.owner.persona) != namespace.as_tuple
                    or key.type_name != "d13.compressed_turn_block.v2" or key.name != block.block_ref
                    or block.status not in {"active", "standby"}):
                continue
            if db.execute("SELECT 1 FROM graph_d13_retirements_v1 WHERE bot=? AND persona=? AND block_token=?",
                          namespace.as_tuple + (token,)).fetchone() is not None:
                continue
            job = get_job(db, block.job_ref)
            if (job.bot_id, job.persona_id) != namespace.as_tuple:
                continue
            compression_plan = plan_from_precompression_job_v1(job)
            if retirement_reason(block, compression_plan, window) is not None:
                continue
            if preflight is not None and (block.status != preflight.cache_status
                    or replace(block, status="standby") != preflight.standby):
                raise ValueError("D13 preflight cache original changed")
            if original is not None and block.status != "active":
                raise ValueError("D13 original active block is no longer active")
            target = VersionedRef(token, revision + (block.status == "standby"))
            request = ShortContextRequestV1("d09", "reply", window.conversation_ref,
                window.scene_ref, window.audience_ref, "d13:v4:" + plan.final_operation_id,
                None, history_byte_budget, installation.provider_id, installation.model_id,
                TEMPLATE_VERSION, "no-tools.v1", job.budget_ref, True)
            query = ShortContextProjectionQueryV1(window, request,
                replace(block, status="active"), compression_plan,
                query_text=question.text[:1024],
                evidence_sources=tuple(dict.fromkeys(r for u in plan.units for r in u.source_refs)))
            compressed = build_natural_frame_v4(window=window, plan=plan, question=question,
                installation=installation, frozen_at_utc=at, expires_at_utc=expiry,
                policy_digest=policy_digest, context_query=query, block_ref=target,
                paid_verifier=paid_verifier)
        except (ValueError, TypeError, KeyError):
            if original is not None or preflight is not None:
                raise ValueError("D13 original/preflight compressed source closure changed")
            continue
        pair_expiry = min(raw.input.expires_at_utc, compressed.input.expires_at_utc)
        if raw.input.expires_at_utc != pair_expiry:
            raw = build_natural_frame_v4(window=window, plan=plan, question=question,
                installation=installation, frozen_at_utc=at, expires_at_utc=pair_expiry,
                policy_digest=policy_digest)
        if compressed.input.expires_at_utc != pair_expiry:
            compressed = build_natural_frame_v4(window=window, plan=plan, question=question,
                installation=installation, frozen_at_utc=at, expires_at_utc=pair_expiry,
                policy_digest=policy_digest, context_query=query, block_ref=target,
                paid_verifier=paid_verifier)
        if preflight_out is not None:
            preflight_out.append(D13NaturalWirePreflightV1(raw, compressed, window,
                replace(block, status="standby"), compression_plan, VersionedRef(token, revision),
                block.status, installed_policy, policy_digest))
            return finish(raw)
        if preflight is not None and (raw != preflight.raw or compressed != preflight.compressed
                or compression_plan != preflight.precompression_plan):
            raise ValueError("D13 current regenerated wires differ from counted preflight original")
        try:
            proof = installed_wire_port.evaluate_natural_pair_v4(
                raw=raw, compressed=compressed, current_window=window,
                standby=replace(block, status="standby"),
                precompression_plan=compression_plan, now_utc=now_utc)
        except Exception:
            proof = None
        if (type(proof) is not D13NaturalWireDecisionV1
                or proof.raw_request_digest != raw.model_request_digest
                or proof.compressed_request_digest != compressed.model_request_digest
                or proof.current_window_digest != canonical_digest(window)
                or proof.policy_digest != installed_policy
                or proof.expires_at_utc < compressed.input.expires_at_utc
                or proof.expires_at_utc <= now_utc
                or original is not None and proof.budget_state != "reserved_original"):
            if original is not None or preflight is not None:
                raise ValueError("D13 current installed full-wire proof unavailable")
            continue
        if proof.selected == "hold":
            raise ValueError("D13 full-wire policy requires HOLD")
        if proof.selected == "raw":
            return finish(raw, proof)
        if block.status == "active":
            return finish(compressed, proof)
        write = GraphWrite(key, block_graph_value(replace(block, status="active")),
                           tuple(AtomKey.from_token(r.ref) for r in block.source_dependencies))
        return finish(compressed, proof, write, GraphVersion(key, revision))
    if preflight is not None:
        raise ValueError("D13 preflight candidate is no longer eligible")
    return finish(raw)
