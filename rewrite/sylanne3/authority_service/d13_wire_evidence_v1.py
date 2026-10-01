"""Pinned, signed full-provider-wire evidence for installed D13 selection.

Counting happens before the Graph transaction. This reader only reopens durable
signed originals and independently reconstructs the current Graph closure. It
never calls a provider, estimates tokens from bytes, or predicts cache savings.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, fields, replace
import json
import math
import sqlite3
from types import MappingProxyType
from typing import Mapping

from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v4 import (
    FrozenNaturalReplyRequestV4, TEMPLATE_DIGEST, freeze_natural_reply_request_v4,
)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

EVIDENCE_SCHEMA = "sylanne3.d13.signed-full-wire-evidence.v1"
SIGNING_DOMAIN = (EVIDENCE_SCHEMA + "\0").encode()
WIRE_POLICY = "sylanne.natural.v4.complete-no-tools.v1"


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 9_000_000_000_000_000


@dataclass(frozen=True, slots=True)
class InstalledD13WirePolicyV1:
    """Only load from the administrator-protected installation profile.

    The counter key authenticates complete-wire count/bound responses, including
    provider serialization overhead. An arbitrary integer count is insufficient.
    Pricing is the verified maximum of uncached input or cache-write input, plus
    explicit storage and output bounds. All rates are integer micro-USD/million.
    """
    installation: NaturalReplyInstallationV2
    counter_public_key_hex: str
    counter_policy_id: str
    counter_policy_version: int
    counter_policy_fingerprint: str
    tokenizer_fingerprint: str
    wire_policy_fingerprint: str
    context_limit_tokens: int
    tool_reserve_tokens: int
    uncached_input_microusd_per_million: int
    cache_write_input_microusd_per_million: int
    output_microusd_per_million: int
    storage_microusd_upper: int
    allow_conservative_switch: bool = False
    max_slots: int = 64
    wire_policy_id: str = WIRE_POLICY
    template_digest: str = TEMPLATE_DIGEST
    schema: str = "sylanne3.d13.installed-wire-policy.v1"

    def __post_init__(self):
        if (type(self.installation) is not NaturalReplyInstallationV2
                or self.schema != "sylanne3.d13.installed-wire-policy.v1"
                or self.wire_policy_id != WIRE_POLICY or self.template_digest != TEMPLATE_DIGEST
                or not _digest(self.counter_public_key_hex)
                or not self.counter_policy_id or type(self.counter_policy_id) is not str
                or not _integer(self.counter_policy_version, 1)
                or not _integer(self.context_limit_tokens, 1)
                or self.context_limit_tokens <= self.installation.max_output_tokens + self.tool_reserve_tokens
                or type(self.max_slots) is not int or not 1 <= self.max_slots <= 64
                or type(self.allow_conservative_switch) is not bool):
            raise ValueError("installed D13 full-wire policy identity/capacity differs")
        for name in ("counter_policy_fingerprint", "tokenizer_fingerprint", "wire_policy_fingerprint"):
            if not _digest(getattr(self, name)):
                raise ValueError("installed D13 policy assets require SHA-256 pins")
        for name in ("tool_reserve_tokens", "uncached_input_microusd_per_million",
                     "cache_write_input_microusd_per_million", "output_microusd_per_million",
                     "storage_microusd_upper"):
            if not _integer(getattr(self, name)):
                raise ValueError("installed D13 reserves and prices require integer bounds")

    @property
    def policy_digest(self):
        return canonical_digest(self)


def installed_d13_wire_policy_from_payload_v1(value):
    """Decode an already authenticated administrator profile field, not input."""
    if value is None:
        return None
    if type(value) is not dict or set(value) != {f.name for f in fields(InstalledD13WirePolicyV1)}:
        raise ValueError("installed D13 wire policy fields differ")
    return InstalledD13WirePolicyV1(**{**value,
        "installation": NaturalReplyInstallationV2(**value["installation"])})


@dataclass(frozen=True, slots=True)
class D13ForegroundBudgetBindingV1:
    """W01-selected original foreground reservation, never the background job."""
    quote_id: str
    quote_version: int
    lease_id: str
    reservation_operation_id: str
    reservation_digest: str

    def __post_init__(self):
        if (any(type(v) is not str or not v for v in
                (self.quote_id, self.lease_id, self.reservation_operation_id))
                or not _integer(self.quote_version, 1) or not _digest(self.reservation_digest)):
            raise ValueError("exact original foreground budget binding required")


@dataclass(frozen=True, slots=True)
class D13ForegroundBudgetPreparationV1:
    """Current signed grant/capacity check only; no reservation or egress grant."""
    namespace: NamespaceId
    lease_id: str
    grant_id: str
    grant_version: int
    grant_digest: str
    quote_ceiling: Mapping[str, int]
    activity_id: str
    reservation_operation_id: str

    def __post_init__(self):
        from ..runtime_contracts import NamespaceId
        if (type(self.namespace) is not NamespaceId
                or any(type(v) is not str or not v for v in
                    (self.lease_id, self.grant_id, self.activity_id, self.reservation_operation_id))
                or not _integer(self.grant_version, 1) or not _digest(self.grant_digest)
                or type(self.quote_ceiling) is not dict or not self.quote_ceiling
                or any(type(k) is not str or not _integer(v) for k, v in self.quote_ceiling.items())):
            raise ValueError("installed D13 preparation requires signed foreground grant identity")
        object.__setattr__(self, "quote_ceiling", MappingProxyType(dict(self.quote_ceiling)))


def install_d13_wire_evidence_schema_v1(db):
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d13_wire_evidence_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        evidence_digest TEXT NOT NULL, policy_digest TEXT NOT NULL,
        raw_request_digest TEXT NOT NULL, compressed_request_digest TEXT NOT NULL,
        envelope_json TEXT NOT NULL, PRIMARY KEY(bot,persona,evidence_digest))""")
    db.execute("""CREATE INDEX IF NOT EXISTS graph_d13_wire_evidence_pair_v1 ON
        graph_d13_wire_evidence_v1(bot,persona,policy_digest,raw_request_digest,compressed_request_digest)""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_d13_wire_evidence_no_{action.lower()}_v1
            BEFORE {action} ON graph_d13_wire_evidence_v1
            BEGIN SELECT RAISE(ABORT, 'D13 signed wire evidence is immutable'); END""")


_PAYLOAD_FIELDS = frozenset({"schema", "namespace", "policy_digest", "raw_request_digest",
    "compressed_request_digest", "raw_frozen_digest", "compressed_frozen_digest",
    "original_window_digest", "original_standby_digest", "precompression_plan_digest",
    "frozen_at_utc", "expires_at_utc", "token_evidence", "raw_lower_tokens",
    "raw_upper_tokens", "compressed_lower_tokens", "compressed_upper_tokens"})


def verify_signed_d13_wire_envelope_v1(policy, envelope):
    """Verify original signed bytes without refreshing any signed time or state."""
    if (type(policy) is not InstalledD13WirePolicyV1 or type(envelope) is not dict
            or set(envelope) != {"payload", "signature"}):
        raise ValueError("signed installed D13 full-wire envelope required")
    payload = envelope["payload"]
    if (type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS
            or payload["schema"] != EVIDENCE_SCHEMA
            or payload["policy_digest"] != policy.policy_digest
            or payload["token_evidence"] not in {"exact_full_wire", "bounded_full_wire"}):
        raise ValueError("D13 evidence schema or installed policy differs")
    from ..runtime_contracts import NamespaceId
    if type(payload["namespace"]) is not dict or set(payload["namespace"]) != {"bot_id", "persona_id"}:
        raise ValueError("D13 signed namespace fields differ")
    NamespaceId(**payload["namespace"])
    for name in ("raw_request_digest", "compressed_request_digest", "raw_frozen_digest",
                 "compressed_frozen_digest", "precompression_plan_digest",
                 "original_window_digest", "original_standby_digest"):
        if not _digest(payload[name]):
            raise ValueError("D13 signed exact wire binding invalid")
    for name in ("raw_lower_tokens", "raw_upper_tokens", "compressed_lower_tokens", "compressed_upper_tokens"):
        if not _integer(payload[name], 0 if "lower" in name else 1):
            raise ValueError("D13 full nonempty wire requires valid integer token evidence")
    if (payload["raw_lower_tokens"] > payload["raw_upper_tokens"]
            or payload["compressed_lower_tokens"] > payload["compressed_upper_tokens"]
            or payload["raw_request_digest"] == payload["compressed_request_digest"]
            or payload["token_evidence"] == "exact_full_wire" and (
                payload["raw_lower_tokens"] != payload["raw_upper_tokens"] or
                payload["compressed_lower_tokens"] != payload["compressed_upper_tokens"])):
        raise ValueError("D13 exact count or conservative interval differs")
    for name in ("frozen_at_utc", "expires_at_utc"):
        if type(payload[name]) not in (int, float) or not math.isfinite(payload[name]):
            raise ValueError("D13 evidence trusted lifetime invalid")
    if payload["expires_at_utc"] <= payload["frozen_at_utc"]:
        raise ValueError("D13 evidence lifetime invalid")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    signature = base64.b64decode(envelope["signature"], validate=True)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.counter_public_key_hex)).verify(
        signature, SIGNING_DOMAIN + canonical_serialize(payload).encode())
    return payload


def record_signed_d13_wire_evidence_v1(db, *, policy, envelope):
    """Persist a prior installed-counter response; never mint a count or signature."""
    if not db.in_transaction:
        raise ValueError("D13 wire evidence import requires caller-owned transaction")
    payload = verify_signed_d13_wire_envelope_v1(policy, envelope)
    encoded, digest = canonical_serialize(envelope), canonical_digest(envelope)
    from ..runtime_contracts import NamespaceId
    ns = NamespaceId(**payload["namespace"]).as_tuple
    row = db.execute("SELECT envelope_json FROM graph_d13_wire_evidence_v1 WHERE bot=? AND persona=? AND evidence_digest=?",
                     ns + (digest,)).fetchone()
    if row is not None:
        if row != (encoded,):
            raise ValueError("D13 signed evidence replay changed")
        return digest
    db.execute("INSERT INTO graph_d13_wire_evidence_v1 VALUES(?,?,?,?,?,?,?)", ns + (
        digest, policy.policy_digest, payload["raw_request_digest"],
        payload["compressed_request_digest"], encoded))
    return digest


def _pair_original_fields(policy, raw, compressed, current_window, standby, precompression_plan):
    if (type(raw) is not FrozenNaturalReplyRequestV4 or type(compressed) is not FrozenNaturalReplyRequestV4
            or raw.installation != policy.installation or compressed.installation != policy.installation
            or raw != freeze_natural_reply_request_v4(raw.input, raw.installation)
            or compressed != freeze_natural_reply_request_v4(compressed.input, compressed.installation)
            or raw.input.stable_history or not compressed.input.stable_history
            or raw.input.question != compressed.input.question or raw.input.plan != compressed.input.plan
            or raw.input.frozen_at_utc != compressed.input.frozen_at_utc
            or raw.input.expires_at_utc != compressed.input.expires_at_utc
            or standby.status != "standby"):
        raise ValueError("two original complete same-model natural wires required")
    return {"schema": EVIDENCE_SCHEMA, "namespace": asdict(raw.input.plan.namespace),
        "policy_digest": policy.policy_digest,
        "raw_request_digest": raw.model_request_digest,
        "compressed_request_digest": compressed.model_request_digest,
        "raw_frozen_digest": canonical_digest(raw), "compressed_frozen_digest": canonical_digest(compressed),
        "original_window_digest": canonical_digest(replace(
            current_window, trusted_utc=raw.input.frozen_at_utc)),
        "original_standby_digest": canonical_digest(standby),
        "precompression_plan_digest": canonical_digest(precompression_plan),
        "frozen_at_utc": raw.input.frozen_at_utc, "expires_at_utc": raw.input.expires_at_utc}


def d13_full_wire_count_request_v1(*, policy, raw, compressed, current_window, standby, precompression_plan):
    """Actual complete wires sent to a pinned counter outside a Graph transaction.

    Request contents authorize no model call. The counter must sign its measured
    count or proved interval over these exact originals and installed policy.
    """
    return {"schema": "sylanne3.d13.full-wire-count-request.v1",
        "original": _pair_original_fields(policy, raw, compressed, current_window, standby, precompression_plan),
        "policy": asdict(policy), "raw_wire": raw.canonical_wire,
        "compressed_wire": compressed.canonical_wire}


def _verify_current_window(db, policy, raw, current_window, now):
    from ..runtime.d13_current_window import read_current_d13_window_for_authority_v1
    if (not db.in_transaction or type(now) not in (int, float) or not math.isfinite(now)
            or current_window.trusted_utc != now or not raw.input.frozen_at_utc <= now < raw.input.expires_at_utc):
        raise ValueError("current fenced trusted D13 lifetime required")
    reread = read_current_d13_window_for_authority_v1(db, raw.input.plan.namespace,
        raw.input.plan.scene_id, raw.input.plan.audience_id, policy.max_slots, now,
        expected_activation_generation=current_window.activation_epoch)
    if reread != current_window:
        raise ValueError("D13 independent source/access/deletion/generation read differs")
    return reread


def _worst_cost(policy, input_upper):
    tokens = input_upper + policy.installation.max_output_tokens + policy.tool_reserve_tokens
    rate = max(policy.uncached_input_microusd_per_million, policy.cache_write_input_microusd_per_million)
    amount = ((input_upper + policy.tool_reserve_tokens) * rate + 999999) // 1000000
    amount += (policy.installation.max_output_tokens * policy.output_microusd_per_million + 999999) // 1000000
    return tokens, amount + policy.storage_microusd_upper


def _require_ceiling(policy, ceiling, input_upper):
    tokens, amount = _worst_cost(policy, input_upper)
    # The D11 contract accepts aggregate model_tokens or separate input/output
    # dimensions. If both are present, both must cover their actual bounds.
    separate = (ceiling.get("input_tokens", 0) >= input_upper + policy.tool_reserve_tokens
                and ceiling.get("output_tokens", 0) >= policy.installation.max_output_tokens)
    aggregate = ceiling.get("model_tokens", 0) >= tokens
    if (not (separate or aggregate)
            or "model_tokens" in ceiling and not aggregate
            or "input_tokens" in ceiling and ceiling["input_tokens"] < input_upper + policy.tool_reserve_tokens
            or "output_tokens" in ceiling and ceiling["output_tokens"] < policy.installation.max_output_tokens
            or ceiling.get("model_microusd", 0) < amount):
        raise ValueError("foreground ceiling cannot cover full-wire no-cache worst cost")
    return tokens, amount


def _verify_foreground_budget(db, policy, binding, resource_issuer, budget_issuer,
                              frozen, input_upper, now, *, quote_read_versions=None):
    from ..runtime.budget import get_budget_lease, require_budget_family_admissible
    from ..runtime.issuers import D02ResourceIssuer, D11BudgetGrantIssuer
    if (type(binding) not in {D13ForegroundBudgetBindingV1, D13ForegroundBudgetPreparationV1}
            or type(resource_issuer) is not D02ResourceIssuer
            or not isinstance(budget_issuer, D11BudgetGrantIssuer)):
        raise ValueError("installed original foreground budget authority required")
    grant = budget_issuer.current_budget_grant(db, binding.lease_id)
    lease = get_budget_lease(db, binding.lease_id)
    require_budget_family_admissible(db, binding.lease_id)
    ns = frozen.input.plan.namespace.as_tuple
    if ((grant.bot_id, grant.persona_id) != ns or (lease.bot_id, lease.persona_id) != ns
            or lease.state != "active" or lease.currency != "USD" or grant.currency != "USD"
            or "natural_generation" not in grant.allowed_work_kinds or grant.valid_until_utc <= now):
        raise ValueError("current signed foreground grant is unavailable")
    if type(binding) is D13ForegroundBudgetPreparationV1:
        ceiling = dict(binding.quote_ceiling)
        if (binding.namespace != frozen.input.plan.namespace
                or (grant.grant_id, grant.version, canonical_digest(grant)) !=
                   (binding.grant_id, binding.grant_version, binding.grant_digest)
                or any(v > grant.max_ceiling.get(k, 0) or v > lease.available(k)
                       for k, v in ceiling.items())
                or db.execute("SELECT 1 FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (binding.lease_id, binding.reservation_operation_id)).fetchone() is not None):
            raise ValueError("D13 preparation signed grant or unreserved capacity changed")
        tokens, amount = _require_ceiling(policy, ceiling, input_upper)
        return canonical_digest({"state": "preparation_only", "grant": grant,
            "lease_version": lease.version, "ceiling": ceiling,
            "reservation_operation_id": binding.reservation_operation_id,
            "required_model_tokens": tokens, "required_model_microusd": amount})
    quote = resource_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    from ..host.authority_profile import installed_model_config_ref
    installed_resource = installed_model_config_ref(policy.installation.provider_id,
        policy.installation.model_id, policy.installation.provider_config_digest)
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (binding.lease_id, binding.reservation_operation_id)).fetchone()
    status = db.execute("SELECT status FROM runtime_resource_quotes WHERE quote_id=? AND version=?",
        (binding.quote_id, binding.quote_version)).fetchone()
    ceiling = dict(quote.ceiling)
    tokens, amount = _require_ceiling(policy, ceiling, input_upper)
    if (quote.work_kind != "natural_generation" or quote.resource_ref != installed_resource
            or quote.operation_id != binding.reservation_operation_id
            or quote.parent_budget_lease_ref != binding.lease_id
            or (quote.bot_id, quote.persona_id) != ns
            or min(quote.valid_until_utc, quote.deadline_utc) <= now
            or status != ("active",) or reservation is None
            or reservation[0] != binding.reservation_digest or reservation[2] not in {"reserved", "settled"}
            or json.loads(reservation[1]) != ceiling
            or any(v > grant.max_ceiling.get(k, 0) for k, v in ceiling.items())):
        raise ValueError("current signed foreground worst-cost reservation differs")
    if quote_read_versions is None:
        from ..runtime.natural_reply_job_v2 import read_original_preparation
        rows = db.execute("SELECT parent_original_id FROM graph_natural_generation_preparations_v2 "
            "WHERE bot=? AND persona=? AND json_extract(seal_json,'$.reservation_operation_id')=?",
            ns + (binding.reservation_operation_id,)).fetchall()
        if len(rows) != 1:
            raise ValueError("D13 exact foreground original is absent or ambiguous")
        saved = read_original_preparation(db, frozen.input.plan.namespace, rows[0][0], "generation")
        if (saved is None or saved.frozen != frozen or saved.seal.parent_budget_lease_id != binding.lease_id
                or saved.seal.reservation_operation_id != binding.reservation_operation_id):
            raise ValueError("D13 budget original binds another frozen model wire")
        quote_read_versions = saved.read_versions
    snapshot = "natural-generation-snapshot:" + canonical_digest({
        "frozen_input_digest": frozen.frozen_input_digest,
        "read_versions": [(row.key.token, row.revision) for row in quote_read_versions]})[:48]
    if quote.snapshot_ref != snapshot:
        raise ValueError("D13 foreground signed quote snapshot differs from selected wire")
    return canonical_digest({"state": "reserved_original", "binding": binding,
        "quote": quote, "grant": grant, "wire_digest": frozen.model_request_digest,
        "required_model_tokens": tokens, "required_model_microusd": amount})


class InstalledD13WireEvidencePortV1:
    """A concrete DB-only verifier, constructed separately by W01 and Authority."""
    def __init__(self, db, *, policy, foreground_budget, resource_issuer, budget_issuer,
                 paid_verifier=None):
        if type(db) is not sqlite3.Connection or type(policy) is not InstalledD13WirePolicyV1:
            raise ValueError("installed Graph database and pinned D13 policy required")
        self._db, self._policy = db, policy
        self._budget, self._resource, self._issuer = foreground_budget, resource_issuer, budget_issuer
        self._paid = paid_verifier
        self._last_pair = None
        self.pending_count_request = None
        self._quote_read_versions = None
        self.policy_digest = policy.policy_digest

    def evaluate_natural_pair_v4(self, *, raw, compressed, current_window, standby,
                                 precompression_plan, now_utc):
        from ..domains.d13.precompression import decide_activation
        from ..runtime.installed_d13_natural_frame_v4 import D13NaturalWireDecisionV1
        policy, db = self._policy, self._db
        _verify_current_window(db, policy, raw, current_window, now_utc)
        expected = _pair_original_fields(policy, raw, compressed, current_window, standby, precompression_plan)
        self.pending_count_request = d13_full_wire_count_request_v1(policy=policy, raw=raw,
            compressed=compressed, current_window=current_window, standby=standby,
            precompression_plan=precompression_plan)
        if decide_activation(standby, precompression_plan, current_window,
                raw_window_fits=True, proven_future_saving=False, paid_verifier=self._paid) == "invalid":
            raise ValueError("D13 paid/source original is no longer current")
        try:
            rows = db.execute("SELECT evidence_digest,envelope_json FROM graph_d13_wire_evidence_v1 "
                "WHERE bot=? AND persona=? AND policy_digest=? AND raw_request_digest=? AND compressed_request_digest=? ORDER BY evidence_digest LIMIT 17",
                raw.input.plan.namespace.as_tuple + (policy.policy_digest, raw.model_request_digest, compressed.model_request_digest)).fetchall()
        except sqlite3.OperationalError:
            return None
        if len(rows) > 16:
            return None
        for digest, encoded in rows:
            try:
                envelope = json.loads(encoded)
                if canonical_serialize(envelope) != encoded or canonical_digest(envelope) != digest:
                    continue
                payload = verify_signed_d13_wire_envelope_v1(policy, envelope)
                if any(payload[k] != v for k, v in expected.items()):
                    continue
                capacity = policy.context_limit_tokens - policy.installation.max_output_tokens - policy.tool_reserve_tokens
                raw_fit = payload["raw_upper_tokens"] <= capacity
                compressed_fit = payload["compressed_upper_tokens"] <= capacity
                selected = ("raw" if raw_fit else "compressed" if compressed_fit and (
                    payload["raw_lower_tokens"] > capacity or policy.allow_conservative_switch) else "hold")
                budget_digest = _verify_foreground_budget(db, policy, self._budget, self._resource,
                    self._issuer, raw if selected == "raw" else compressed,
                    payload["raw_upper_tokens"] if selected == "raw" else payload["compressed_upper_tokens"], now_utc,
                    quote_read_versions=self._quote_read_versions)
                result = D13NaturalWireDecisionV1(selected, payload["token_evidence"],
                    canonical_digest({"signed_evidence": digest, "foreground_budget": budget_digest}),
                    raw.model_request_digest, compressed.model_request_digest,
                    canonical_digest(current_window), policy.policy_digest, payload["expires_at_utc"],
                    budget_state=("preparation_only" if type(self._budget) is D13ForegroundBudgetPreparationV1
                                  else "reserved_original"))
                if type(self._budget) is D13ForegroundBudgetBindingV1 and self._quote_read_versions is None:
                    original_rows = db.execute("SELECT j.continuation_json FROM graph_natural_generation_preparations_v2 p "
                        "JOIN runtime_jobs j ON j.job_id=json_extract(p.seal_json,'$.job_id') "
                        "AND j.bot_id=p.bot AND j.persona_id=p.persona "
                        "WHERE p.bot=? AND p.persona=? AND json_extract(p.seal_json,'$.reservation_operation_id')=?",
                        raw.input.plan.namespace.as_tuple + (self._budget.reservation_operation_id,)).fetchall()
                    if len(original_rows) != 1:
                        continue
                    continuation = json.loads(original_rows[0][0])
                    if (continuation.get("history_budget_state") != "reserved_original"
                            or continuation.get("history_proof_digest") != result.proof_digest):
                        continue
                self._last_pair = (raw, compressed, current_window, standby, precompression_plan, result)
                self.pending_count_request = None
                return result
            except Exception:
                continue
        return None

    def validate_reserved_selection_v1(self, *, selected, decision, binding, read_versions, now_utc):
        """Mandatory atomic second gate after reserve, before job/original/CAS.

        Re-verifies the exact original pair and real quote/reservation. The
        first decision remains explicitly preparation-only; returned proof is
        the distinct admitted state to persist in the immutable job original.
        """
        from ..runtime.installed_d13_natural_frame_v4 import NaturalHistoryDecisionV4
        if (not self._db.in_transaction or type(self._budget) is not D13ForegroundBudgetPreparationV1
                or type(binding) is not D13ForegroundBudgetBindingV1 or self._last_pair is None
                or type(decision) is not NaturalHistoryDecisionV4
                or decision.budget_state != "preparation_only"
                or decision.wire_digest != selected.model_request_digest
                or (binding.lease_id, binding.reservation_operation_id) !=
                   (self._budget.lease_id, self._budget.reservation_operation_id)):
            raise ValueError("D13 atomic reserved selection requires its actual preparation")
        raw, compressed, window, standby, plan, first = self._last_pair
        if (decision.proof_digest != first.proof_digest or decision.selected != first.selected
                or selected != (raw if first.selected == "raw" else compressed)):
            raise ValueError("D13 selected wire differs from its prepared evidence")
        quote = self._resource.original_signed_quote(self._db, binding.quote_id, binding.quote_version)
        if quote.activity_id != self._budget.activity_id or dict(quote.ceiling) != dict(self._budget.quote_ceiling):
            raise ValueError("D13 reserved foreground quote differs from installed preparation")
        admitted = InstalledD13WireEvidencePortV1(self._db, policy=self._policy,
            foreground_budget=binding, resource_issuer=self._resource,
            budget_issuer=self._issuer, paid_verifier=self._paid)
        admitted._quote_read_versions = read_versions
        proof = admitted.evaluate_natural_pair_v4(raw=raw, compressed=compressed,
            current_window=replace(window, trusted_utc=now_utc), standby=standby,
            precompression_plan=plan, now_utc=now_utc)
        if proof is None or proof.selected != first.selected or proof.budget_state != "reserved_original":
            raise ValueError("D13 atomic reserved foreground verification failed")
        return D13NaturalReservedSelectionV1(selected.model_request_digest,
            proof.proof_digest, binding.reservation_digest, proof.token_evidence)


@dataclass(frozen=True, slots=True)
class D13NaturalReservedSelectionV1:
    wire_digest: str
    proof_digest: str
    reservation_digest: str
    token_evidence: str
    budget_state: str = "reserved_original"


def validate_reserved_d13_natural_selection_v1(port, *, selected, decision, binding,
                                               read_versions, now_utc):
    if type(port) is not InstalledD13WireEvidencePortV1:
        raise ValueError("installation-created D13 wire port required")
    return port.validate_reserved_selection_v1(selected=selected, decision=decision,
        binding=binding, read_versions=read_versions, now_utc=now_utc)
