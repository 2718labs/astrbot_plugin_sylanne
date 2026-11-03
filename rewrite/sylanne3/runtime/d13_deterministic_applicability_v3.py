"""Same-Source-Work deterministic D13 planning and compiler applicability."""
from __future__ import annotations

from weakref import WeakKeyDictionary
from .runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3
from dataclasses import dataclass, replace

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import (
    CompressedTurnBlockV2, TurnAnchorV1, TurnDetailSlotV1, TurnTimelineItemV1,
)
from ..domains.d13.precompression import (
    COMPILER_VERSION, D13CurrentPressureUnavailableV3, PrecompressionPlan, _fingerprint_value_v1, _omission_ranges,
    _QUALIFIER, _TTL, _SPAN,
)

_CONFIGURED = WeakKeyDictionary()
_PRESSURE_ORIGINALS = WeakKeyDictionary()
_PRESSURE_GRANT_COLUMNS = WeakKeyDictionary()
_PRESSURE_POLICY_READS = WeakKeyDictionary()
_HISTORICAL_PRESSURE = WeakKeyDictionary()
_DECISION_PRESSURE_FACTS = WeakKeyDictionary()
_TECHNICAL_CONFIGURED = WeakKeyDictionary()
_PREPARED = WeakKeyDictionary()
_DECISIONS = WeakKeyDictionary()
_ISSUER = object()
_FALLBACK_BEAT = "已提交发言；详情须回查原文"
_PUNCTUATION = frozenset("。！？.!?")
_SEPARATORS = _PUNCTUATION | {"\n"}
_PAIRS = frozenset(("未知", "失败", "超时", "更正", "改到", "如果", "除非"))


@dataclass(frozen=True, slots=True)
class D13CurrentPressureOriginalsV1:
    """Signed originals only; current pressure requires the actual Source Work."""
    wire_policy: object
    counter_envelope: object
    mapping_envelope: object

    def __post_init__(self):
        from ..authority_service.d13_core_counter_contract_v1 import (
            InstalledD13WirePolicyV7, D13CoreFullWireEnvelopeV1)
        from ..authority_service.d13_current_pressure_mapping_v1 import D13CurrentPressureMappingEnvelopeV1
        if (type(self.wire_policy) is not InstalledD13WirePolicyV7
                or type(self.counter_envelope) is not D13CoreFullWireEnvelopeV1
                or type(self.mapping_envelope) is not D13CurrentPressureMappingEnvelopeV1):
            raise TypeError("exact installed pressure originals required")


def _pressure_grant_head_v1(reader, meter=None):
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    if meter is not None:
        return meter.read_fixed_row(reader.db, "runtime_budget_grants",
            ("lease_id", "version", "signature", "status"),
            "lease_id=? ORDER BY version DESC", (_CONFIGURED[reader].lease_id,))
    with runtime_storage_quantum_v3(reader.db) as current:
        return current.read_fixed_row(reader.db, "runtime_budget_grants",
            ("lease_id", "version", "signature", "status"),
            "lease_id=? ORDER BY version DESC", (_CONFIGURED[reader].lease_id,))


class _D13PressureGrantColumnV1:
    """The existing JSON column parser and signer consume the same fragments."""
    def __init__(self, issuer, task):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable("actual pressure grant column issuer required")
        from .d13_paid_original_read_v3 import _ColumnV3
        self.task = task
        self.reader = task.owner
        self.metadata = task.grant_metadata
        self.signer = self.reader.graph._GraphCoordinator__d11_issuer._signer
        self.column = _ColumnV3(self.reader, table="runtime_budget_grants",
            column="grant_json", key_columns=("lease_id", "version"), key=self.metadata[:2])
        self.complete = False
        self.verifier = None
        task.grant_column = self
        _PRESSURE_GRANT_COLUMNS[self] = (task, self.reader, self.metadata, self.column, self.signer)
        self.verifier = self.signer.begin_original_stream_verification_v3("budget-grant.v1", self)

    def advance(self, meter):
        require_d13_pressure_grant_signature_column_v1(self, signer=self.signer,
            kind="budget-grant.v1", verifier=self.verifier)
        if self.complete:
            return True
        from .dispatch_current_inventory_v3 import _heap
        self.reader.reserve_v3(_heap((self.column.fragment, self.column.body, self.column.value)) + 65536)
        fragment = self.column.fragment[:1024]
        self.column.advance(meter)
        self.reader.reserve_v3(_heap((self.column.fragment, self.column.body, self.column.value)) + 65536)
        if fragment:
            self.verifier.update(fragment)
        if self.column.complete:
            self.signer.finish_original_stream_verification_v3(
                "budget-grant.v1", self.metadata[2], self, self.verifier)
            self.complete = True
        return self.complete

    def release_v1(self):
        _PRESSURE_GRANT_COLUMNS.pop(self, None)
        self.task = self.reader = self.column = self.signer = self.verifier = None


def require_d13_pressure_grant_signature_column_v1(original, *, signer, kind,
        signature=None, verifier=None, complete=False):
    if type(original) is not _D13PressureGrantColumnV1 or original not in _PRESSURE_GRANT_COLUMNS:
        raise AuthorityUnavailable("actual retained pressure grant column required")
    task, reader, metadata, column, actual_signer = _PRESSURE_GRANT_COLUMNS[original]
    if (kind != "budget-grant.v1" or signer is not actual_signer
            or original.signer is not signer or original.reader is not reader or original.task is not task
            or original.column is not column or original.metadata != metadata
            or reader.deterministic_applicability_task is not task or task.grant_column is not original
            or _CONFIGURED.get(reader) is not task.policy or not reader.qualified
            or metadata != _pressure_grant_head_v1(reader) or metadata[3] != "active"
            or signature is not None and signature != metadata[2]
            or verifier is not None and verifier is not original.verifier
            or complete and not column.complete):
        raise AuthorityUnavailable("pressure grant signature lost its actual column/current Source Work")
    reader.require_current_v3()
    return original


class _D13PressurePolicyReadV1:
    def __init__(self, issuer, task, grant):
        if issuer is not _ISSUER or not task.grant_column.complete:
            raise AuthorityUnavailable("complete actual pressure grant signature EOF required")
        self.reader, self.policy, self.grant = task.owner, task.policy, grant
        self.signature = task.grant_metadata[2]
        self.metadata = task.grant_metadata
        self.grant_ceiling = tuple(sorted(grant.max_ceiling.items()))
        self.issuer = task.owner.graph._GraphCoordinator__d11_issuer
        _PRESSURE_POLICY_READS[self] = (
            self.reader, self.policy, self.grant, self.signature, self.metadata, self.issuer, self.grant_ceiling)

    def release_v1(self):
        _PRESSURE_POLICY_READS.pop(self, None)
        self.reader = self.policy = self.grant = self.issuer = None


def require_actual_d13_pressure_policy_read_v1(proof, work):
    if type(proof) is not _D13PressurePolicyReadV1 or proof not in _PRESSURE_POLICY_READS:
        raise AuthorityUnavailable("actual current D13 pressure policy/grant EOF required")
    reader, policy, grant, signature, metadata, issuer, ceiling = _PRESSURE_POLICY_READS[proof]
    if (proof.reader is not reader or proof.policy is not policy or proof.grant is not grant
            or proof.signature != signature or proof.metadata != metadata or proof.issuer is not issuer
            or proof.grant_ceiling != ceiling or tuple(sorted(grant.max_ceiling.items())) != ceiling
            or reader.work is not work or _CONFIGURED.get(reader) is not policy
            or reader.graph._GraphCoordinator__d13_precompression_policy is not policy
            or reader.graph._GraphCoordinator__d11_issuer is not issuer
            or reader.deterministic_applicability_task.policy_read is not proof
            or metadata != _pressure_grant_head_v1(reader) or metadata[3] != "active"
            or reader.now_utc >= grant.valid_until_utc):
        raise AuthorityUnavailable("D13 pressure policy or current signed grant changed")
    reader.require_current_v3()
    return policy, grant, signature, grant.valid_until_utc


def _utf8_size(char):
    value = ord(char)
    if value < 0x80:
        return 1
    if value < 0x800:
        return 2
    if 0xD800 <= value <= 0xDFFF:
        raise UnicodeEncodeError("utf-8", char, 0, 1, "surrogates not allowed")
    return 3 if value < 0x10000 else 4


class _ClauseScanV3:
    """Exact _CLAUSE.finditer(...).strip() results, retaining at most 160 bytes."""
    def __init__(self, text, raw_bytes, consume):
        self.text, self.raw_bytes, self.consume = text, raw_bytes, consume
        self.offset = 0
        self.complete = self.any_clause = False
        self._reset()

    def _reset(self):
        self.run = False
        self.started = False
        self.length = self.trimmed_length = 0
        self.buffer = []
        self.qualified = False
        self.previous = ""
        self.word = ""
        self.word_overflow = False

    def _end_word(self):
        if self.word and not self.word_overflow and _QUALIFIER.fullmatch(self.word):
            self.qualified = True
        self.word = ""
        self.word_overflow = False

    def _append(self, char):
        if char in "不没无未" or self.previous + char in _PAIRS:
            self.qualified = True
        self.previous = char
        if char == "_" or char.isalnum():
            if not self.word_overflow:
                if len(self.word) < 10:
                    self.word += char
                else:
                    self.word = ""
                    self.word_overflow = True
        else:
            self._end_word()
        if not self.started:
            if char.isspace():
                return
            self.started = True
        self.length += _utf8_size(char)
        if self.length <= 160:
            self.buffer.append(char)
        if not char.isspace():
            self.trimmed_length = self.length

    def _emit(self):
        self._end_word()
        if self.trimmed_length:
            value = "".join(self.buffer).strip() if self.trimmed_length <= 160 else None
            self.consume(value, self.trimmed_length, self.qualified)
            self.any_clause = True
        self._reset()

    def advance(self, meter):
        end = min(self.offset + 256, len(self.text))
        if meter is not None:
            meter.require_available(32768)
            meter.charge_encode((end - self.offset) * 4)
        for char in self.text[self.offset:end]:
            if char in _SEPARATORS:
                if self.run:
                    if char in _PUNCTUATION:
                        self._append(char)
                    self._emit()
            else:
                self.run = True
                self._append(char)
        self.offset = end
        if self.offset == len(self.text):
            if self.run:
                self._emit()
            if not self.any_clause:
                # _source_clauses returns the original text, without strip,
                # only when every regex match was empty after strip.
                value = self.text if self.raw_bytes <= 160 else None
                self.consume(value, self.raw_bytes, False)
            self.complete = True
        return self.complete


class _DeterministicApplicabilityReadV3:
    """Pure complete-prefix computation; authority remains with its real owner."""
    def __init__(self, owner):
        self.owner, self.window = owner, owner.current_window
        self.policy = _CONFIGURED[owner]
        self.phase = "recent"
        self.position = self.offset = self.part = 0
        self.recent = []
        self.sizes = {}
        self.body_sizes = {}
        self.pressure_originals = _PRESSURE_ORIGINALS.get(owner)
        self.grant_metadata = self.grant_column = self.policy_read = None
        self.pressure_verified = self.pressure_window_digest = self.pressure_tokens = None
        self.pressure_payload = None
        self.past_pressure = _HISTORICAL_PRESSURE.get(owner)
        self.prefix = []
        self.used = 0
        self.plan = self.stream = self.scan = self.result = None
        self.technical_configuration = _TECHNICAL_CONFIGURED.get(owner)
        if self.technical_configuration is not None:
            if owner.technical_job_header != self.technical_configuration[3]:
                raise AuthorityUnavailable("technical compiler lost its original job metadata header")
            self.plan = self.technical_configuration[1]
            self.phase = "assigned_prefix"
        self.required = []
        self.aggregate_overflow = False
        self.first = None
        self.first_seen = False
        self.beat = self.detail = None
        self.original_bytes = self.rendered_bytes = 0
        self.anchors, self.timeline, self.details, self.omitted = [], [], [], []
        self.render_parts = None
        self.render_part = self.render_offset = 0
        self.complete = False
        # Text and VersionedRefs are borrowed from the already-retained window.
        # The new live state contains <= 64 metadata rows and <= 160-byte fragments.
        owner.operation.retain(65536 + len(self.window.turns) * 8192)


    def _grant_metadata(self, meter):
        originals = self.pressure_originals
        if type(originals) is not D13CurrentPressureOriginalsV1:
            raise D13CurrentPressureUnavailableV3("pressure_missing")
        if self.grant_metadata is None:
            self.grant_metadata = _pressure_grant_head_v1(self.owner, meter)
            if self.grant_metadata is None or self.grant_metadata[3] != "active":
                raise D13CurrentPressureUnavailableV3("pressure_grant_unavailable")
            return
        if self.grant_column is None:
            _D13PressureGrantColumnV1(_ISSUER, self)
            return
        if not self.grant_column.advance(meter):
            return
        from .issuers import _decode_grant
        grant = _decode_grant(self.grant_column.column.value)
        policy = self.policy
        if ((grant.bot_id, grant.persona_id) != self.owner.namespace.as_tuple
                or (grant.grant_id, grant.version, grant.lease_id) !=
                    (policy.grant_id, policy.grant_version, policy.lease_id)
                or policy.work_kind not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(name, 0)
                    for name, amount in policy.quote_ceiling.items())
                or self.owner.now_utc >= grant.valid_until_utc):
            raise D13CurrentPressureUnavailableV3("pressure_grant_changed")
        self.policy_read = _D13PressurePolicyReadV1(_ISSUER, self, grant)
        if self.past_pressure is None:
            from ..authority_service.d13_current_pressure_mapping_v1 import verify_current_d13_pressure_mapping_v1
            self.pressure_verified = verify_current_d13_pressure_mapping_v1(
                originals.wire_policy, originals.mapping_envelope,
                counter_envelope=originals.counter_envelope, policy_read_proof=self.policy_read,
                work=self.owner.work, now_utc=self.owner.now_utc)
            self.pressure_payload = self.pressure_verified.payload
        else:
            facts = self._require_historical_pressure_v1()
            self.pressure_payload = facts[1]
            from ..authority_service.d13_current_pressure_mapping_v1 import pressure_selection_policy_wire_v1
            from ..runtime_contracts import canonical_digest
            if (self.pressure_payload.selection_policy != pressure_selection_policy_wire_v1(policy)
                    or self.pressure_payload.grant_original_digest !=
                        canonical_digest((grant, self.grant_metadata[2]))):
                raise D13CurrentPressureUnavailableV3("pressure_grant_changed")
        self._require_pressure_window_metadata_v1()
        payload = self.pressure_payload
        self.stream = RuntimeCanonicalStreamV3(
            replace(self.window, trusted_utc=payload.frozen_at_utc), self.owner.operation)
        self.phase = "pressure_window"

    def _require_pressure_window_metadata_v1(self):
        p, w = self.pressure_payload, self.window
        metadata = self.owner.window_metadata
        members = tuple((t.sequence, t.raw_ref, t.source_ref, t.access_ref, t.trusted_utc)
            for t in w.turns)
        selected = tuple((t.sequence, t.raw_ref, t.source_ref, t.access_ref, t.trusted_utc)
            for t in p.selected_members)
        unclosed = tuple(sequence for sequence, slot, completion in metadata.records
            if completion is None)
        if (metadata.reader is not self.owner or not metadata.complete
                or self.owner.current_window is not w or not self.owner.qualified
                or (p.namespace, p.installation_id, p.authority_namespace) !=
                    (w.namespace, self.policy.installation_id,
                     self.owner.fence.metadata.requirements.authority_namespace)
                or (p.scene_ref, p.audience_ref, p.conversation_ref, p.owner_ref) !=
                    (w.scene_ref, w.audience_ref, w.conversation_ref, w.owner_ref)
                or (p.order_watermark, p.access_epoch, p.delete_epoch, p.activation_epoch) !=
                    (w.order_watermark, w.access_epoch, w.delete_epoch, w.activation_epoch)
                or (p.first_sequence, p.last_sequence) != (metadata.start, metadata.end)
                or (p.max_slots, p.history_token_budget) !=
                    (self.policy.max_slots, self.policy.history_token_budget)
                or p.missing_ranges != w.missing_ranges
                or p.expired_sequences != tuple(metadata.expired_sequences)
                or p.unclosed_sequences != unclosed or selected != members
                or self.past_pressure is None and self.owner.now_utc >= p.expires_at_utc):
            raise D13CurrentPressureUnavailableV3("pressure_selection_changed")

    def _pressure_window(self, meter):
        self.owner.require_current_v3(meter=meter)
        require_actual_d13_pressure_policy_read_v1(self.policy_read, self.owner.work)
        if self.past_pressure is not None:
            self._require_historical_pressure_v1()
        self._require_pressure_window_metadata_v1()
        self.stream.read_fragment(meter)
        if not self.stream.complete:
            return
        self.pressure_window_digest = self.stream.hash.hexdigest()
        if self.pressure_window_digest != self.pressure_payload.selected_window_digest:
            raise D13CurrentPressureUnavailableV3("pressure_selection_changed")
        from ..authority_service.d13_current_pressure_mapping_v1 import pressure_mapping_exact_tokens_v1
        self.pressure_tokens = (pressure_mapping_exact_tokens_v1(self.pressure_verified)
            if self.past_pressure is None else self._require_historical_pressure_v1()[2])
        if self.pressure_tokens is None:
            raise D13CurrentPressureUnavailableV3("pressure_not_exact")
        self.stream = None
        self.position = 0
        self.phase = ("sizes" if self.pressure_tokens * 10 >= self.policy.history_token_budget * 6
            else "not_needed")

    def _require_historical_pressure_v1(self):
        if _HISTORICAL_PRESSURE.get(self.owner) is not self.past_pressure:
            raise AuthorityUnavailable("D13 historical pressure lost its actual fallback Source Work")
        decision, facts = self.past_pressure
        require_issued_d13_deterministic_no_reduction_v3(decision)
        if (_DECISION_PRESSURE_FACTS.get(decision) is not facts
                or facts[0] is not self.pressure_originals
                or self.owner.now_utc >= decision.original_deadline_utc):
            raise AuthorityUnavailable("D13 original pressure decision is no longer retained")
        return facts

    def require_pressure_v1(self):
        if self.technical_configuration is not None:
            return
        if self.pressure_payload is None:
            if self.plan is not None:
                raise D13CurrentPressureUnavailableV3("pressure_missing")
            return
        if _PRESSURE_ORIGINALS.get(self.owner) is not self.pressure_originals:
            raise AuthorityUnavailable("pressure originals lost their actual scheduler Source Work")
        require_actual_d13_pressure_policy_read_v1(self.policy_read, self.owner.work)
        if self.past_pressure is not None:
            self._require_historical_pressure_v1()
        self._require_pressure_window_metadata_v1()
        from ..authority_service.d13_current_pressure_mapping_v1 import pressure_mapping_exact_tokens_v1
        tokens = (pressure_mapping_exact_tokens_v1(self.pressure_verified)
            if self.past_pressure is None else self._require_historical_pressure_v1()[2])
        if (self.pressure_window_digest != self.pressure_payload.selected_window_digest
                or self.pressure_tokens != tokens):
            raise AuthorityUnavailable("pressure source EOF or exact count changed")

    def _size_part(self, meter):
        turn = self.recent[self.position]
        parts = (turn.speaker_ref, ": ", turn.text)
        value = parts[self.part]
        if self.offset < len(value):
            end = min(self.offset + 1024, len(value))
            raw = value[self.offset:end].encode("utf-8")
            meter.charge_encode(len(raw))
            self.sizes[self.position] = self.sizes.get(self.position, 0) + len(raw)
            if self.part == 2:
                self.body_sizes[self.position] = self.body_sizes.get(self.position, 0) + len(raw)
            self.offset = end
            return
        self.part += 1
        self.offset = 0
        if self.part == len(parts):
            self.position += 1
            self.part = 0

    def _assigned_prefix(self):
        plan = self.plan
        if self.position < len(self.window.turns):
            turn = self.window.turns[self.position]
            if plan.first_sequence <= turn.sequence <= plan.last_sequence:
                self.prefix.append(turn)
            self.position += 1
            return
        turns = self.prefix
        if (len(turns) != plan.last_sequence - plan.first_sequence + 1
                or not turns or turns[0].sequence != plan.first_sequence
                or turns[-1].sequence != plan.last_sequence
                or self.window.scene_ref != plan.scene_ref or self.window.audience_ref != plan.audience_ref
                or (self.window.access_epoch, self.window.delete_epoch, self.window.activation_epoch) !=
                   (plan.access_epoch, plan.delete_epoch, plan.activation_epoch)
                or self.window.trusted_utc >= plan.expires_at_utc
                or len({turn.raw_ref for turn in turns}) != len(turns)):
            raise ValueError("stale or incomplete precompression plan")
        self.position = self.offset = 0
        self.phase = "assigned_bytes"

    def _assigned_bytes(self, meter):
        if self.position == len(self.prefix):
            self.stream = RuntimeCanonicalStreamV3(
                _fingerprint_value_v1(self.window, tuple(self.prefix)), self.owner.operation)
            self.phase = "fingerprint"
            return
        turn = self.prefix[self.position]
        self.body_sizes.setdefault(self.position, 0)
        if self.offset < len(turn.text):
            end = min(self.offset + 1024, len(turn.text))
            raw = turn.text[self.offset:end].encode("utf-8")
            meter.charge_encode(len(raw))
            self.body_sizes[self.position] += len(raw)
            self.original_bytes += len(raw)
            self.offset = end
            return
        self.position += 1
        self.offset = 0

    def _prefix(self):
        if self.position >= len(self.recent) - 1:
            self.phase = "plan"
            return
        turn = self.recent[self.position]
        if self.prefix and (turn.sequence != self.prefix[-1].sequence + 1
                or turn.trusted_utc - self.prefix[0].trusted_utc > _SPAN
                or self.used + self.sizes[self.position] > self.policy.history_token_budget * 0.3):
            self.phase = "plan"
            return
        self.prefix.append(turn)
        self.used += self.sizes[self.position]
        self.original_bytes += self.body_sizes.get(self.position, 0)
        self.position += 1

    def _start_plan(self):
        if len(self.prefix) < 2:
            self._finish(None, None)
            return
        turns = tuple(self.prefix)
        if (len({turn.raw_ref for turn in turns}) != len(turns)
                or any(start <= turns[-1].sequence and end >= turns[0].sequence
                       for start, end in self.window.missing_ranges)):
            self._finish(None, None)
            return
        # This is the existing typed canonical algebra and chunk encoder.
        # It retains only the live frame high-water mark, not each yielded node.
        self.stream = RuntimeCanonicalStreamV3(
            _fingerprint_value_v1(self.window, turns), self.owner.operation)
        self.phase = "fingerprint"

    def _seal_plan(self):
        turns = tuple(self.prefix)
        digest = self.stream.hash.hexdigest()
        if self.technical_configuration is not None:
            if digest != self.plan.input_digest:
                raise ValueError("stale or incomplete precompression plan")
            self.stream = None
            self.position = 0
            self.phase = "fragments"
            return
        deps = tuple(dict.fromkeys(ref for turn in turns
                                   for ref in (turn.raw_ref, turn.source_ref, turn.access_ref)))
        self.plan = PrecompressionPlan(
            job_ref=f"d13:precompress:{digest}", candidate_ref=f"d13:candidate:{digest}",
            input_digest=digest, first_sequence=turns[0].sequence,
            last_sequence=turns[-1].sequence, source_dependencies=deps,
            scene_ref=self.window.scene_ref, audience_ref=self.window.audience_ref,
            access_epoch=self.window.access_epoch, delete_epoch=self.window.delete_epoch,
            activation_epoch=self.window.activation_epoch,
            expires_at_utc=turns[0].trusted_utc + _TTL)
        self.stream = None
        covered = tuple(turn for turn in self.window.turns
            if self.plan.first_sequence <= turn.sequence <= self.plan.last_sequence)
        if (len(covered) != len(turns) or any(a is not b for a, b in zip(covered, turns))
                or self.window.trusted_utc >= self.plan.expires_at_utc):
            raise ValueError("stale or incomplete precompression plan")
        self.position = 0
        self.phase = "fragments"

    def _first_pass(self, value, size, qualified):
        if not self.first_seen:
            self.first, self.first_seen = value, True
        if qualified:
            if size > 160:
                raise ValueError("qualified source clause cannot be folded safely")
            if self.aggregate_overflow: return
            next_size = sum(len(part.encode("utf-8")) for part in self.required)
            next_size += len(value.encode("utf-8")) + len(self.required)
            if next_size > 160:
                self.aggregate_overflow = True
                return
            self.required.append(value)

    def _detail_pass(self, value, size, qualified):
        if (self.detail is None and value is not None and value not in self.required
                and value != self.beat and size <= 160 and len(set(value)) > 2):
            self.detail = value

    def _fragments(self, meter):
        turn = self.prefix[self.position]
        if self.scan is None:
            self.required = []
            self.aggregate_overflow = False
            self.first, self.first_seen = None, False
            self.scan = _ClauseScanV3(turn.text, self.body_sizes[self.position], self._first_pass)
        if not self.scan.advance(meter):
            return
        if self.aggregate_overflow:
            raise ValueError("qualified source clauses cannot fit a stable beat")
        self.beat = " ".join(self.required) if self.required else (
            self.first if self.first is not None else _FALLBACK_BEAT)
        self.detail = None
        self.scan = _ClauseScanV3(turn.text, self.body_sizes[self.position], self._detail_pass)
        self.phase = "details"

    def _details(self, meter):
        if not self.scan.advance(meter):
            return
        turn = self.prefix[self.position]
        details = (self.detail,) if self.detail is not None else (
            (self.required[-1],) if self.required else ())
        represented = self.body_sizes[self.position] <= 160 and (
            self.beat == turn.text or turn.text in details)
        self.anchors.append(TurnAnchorV1.from_turn(turn))
        self.timeline.append(TurnTimelineItemV1(turn.sequence, turn.source_ref, turn.speaker_ref, self.beat))
        if details:
            self.details.append(TurnDetailSlotV1(
                f"turn:{turn.sequence}", turn.sequence, turn.source_ref, details[0]))
        if not represented:
            self.omitted.append(turn.sequence)
        self.scan = None
        self.position += 1
        self.phase = "render" if self.position == len(self.prefix) else "fragments"
        if self.phase == "render":
            self.position = 0

    def _render(self, meter):
        if self.render_parts is None:
            if self.position < len(self.timeline):
                item = self.timeline[self.position]
                self.render_parts = (f"[{item.sequence} ", item.speaker_ref, "] ", item.text)
            else:
                detail_index = self.position - len(self.timeline)
                if detail_index == len(self.details):
                    self.phase = "candidate"
                    return
                item = self.details[detail_index]
                self.render_parts = (f"[{item.sequence} {item.key}] ", item.text)
            if self.position:
                self.rendered_bytes += 1  # exactly rendered_text's newline join
            self.render_part = self.render_offset = 0
        value = self.render_parts[self.render_part]
        if self.render_offset < len(value):
            end = min(self.render_offset + 1024, len(value))
            raw = value[self.render_offset:end].encode("utf-8")
            meter.charge_encode(len(raw))
            self.rendered_bytes += len(raw)
            self.render_offset = end
            return
        self.render_part += 1
        self.render_offset = 0
        if self.render_part == len(self.render_parts):
            self.position += 1
            self.render_parts = None

    def _finish(self, plan, candidate):
        self.result = PreparedD13DeterministicApplicabilityV3(_ISSUER, self, plan, candidate)
        self.complete = True
        self.phase = "complete"

    def advance(self, meter):
        if self.phase == "assigned_prefix":
            self._assigned_prefix()
        elif self.phase == "assigned_bytes":
            self._assigned_bytes(meter)
        elif self.phase == "recent":
            if self.position < len(self.window.turns):
                turn = self.window.turns[self.position]
                if 0 <= self.window.trusted_utc - turn.trusted_utc < _TTL:
                    self.recent.append(turn)
                self.position += 1
            else:
                self.position = 0
                self.phase = "pressure_grant" if len(self.recent) >= 3 else "not_needed"
        elif self.phase == "pressure_grant":
            self._grant_metadata(meter)
        elif self.phase == "pressure_window":
            self._pressure_window(meter)
        elif self.phase == "sizes":
            if self.position < len(self.recent):
                self._size_part(meter)
            else:
                self.position = 0
                self.phase = "prefix"
        elif self.phase == "prefix":
            self._prefix()
        elif self.phase == "plan":
            self._start_plan()
        elif self.phase == "fingerprint":
            self.stream.read_fragment(meter)
            if self.stream.complete:
                self._seal_plan()
        elif self.phase == "fragments":
            self._fragments(meter)
        elif self.phase == "details":
            self._details(meter)
        elif self.phase == "render":
            self._render(meter)
        elif self.phase == "candidate":
            candidate = CompressedTurnBlockV2(
                block_ref=f"d13:block:{self.plan.input_digest}",
                conversation_ref=self.window.conversation_ref, audience_ref=self.window.audience_ref,
                turns=tuple(self.anchors), source_dependencies=self.plan.source_dependencies,
                timeline=tuple(self.timeline), detail_slots=tuple(self.details),
                omitted_ranges=_omission_ranges(self.omitted), compiler_version=COMPILER_VERSION,
                job_ref=self.plan.job_ref, candidate_ref=self.plan.candidate_ref,
                expires_at_utc=self.plan.expires_at_utc, status="candidate")
            self._finish(self.plan, candidate)
        elif self.phase == "not_needed":
            self._finish(None, None)
        elif self.phase != "complete":
            raise ValueError("unknown deterministic applicability phase")
        return self.complete


class PreparedD13DeterministicApplicabilityV3:
    def __init__(self, issuer, task, plan, candidate):
        if issuer is not _ISSUER or _CONFIGURED.get(task.owner) is not task.policy:
            raise AuthorityUnavailable("actual deterministic scheduler Source Work required")
        self.reader, self.window, self.policy = task.owner, task.window, task.policy
        self.technical_configuration = task.technical_configuration
        self.pressure_originals, self.policy_read = task.pressure_originals, task.policy_read
        self.pressure_verified = task.pressure_verified
        self.pressure_payload, self.past_pressure = task.pressure_payload, task.past_pressure
        self.pressure_window_digest, self.pressure_tokens = task.pressure_window_digest, task.pressure_tokens
        self.plan, self.candidate = plan, candidate
        self.original_bytes, self.rendered_bytes = task.original_bytes, task.rendered_bytes
        _PREPARED[self] = self._identity()

    def _identity(self):
        return (self.reader, self.reader.work, self.reader.operation, self.reader.selection_digest,
            self.window, self.policy, self.plan, self.candidate, self.original_bytes, self.rendered_bytes,
            COMPILER_VERSION, self.technical_configuration, self.pressure_originals,
            self.policy_read, self.pressure_verified, self.pressure_payload, self.past_pressure,
            self.pressure_window_digest, self.pressure_tokens)

    def require_v3(self, window, plan=None):
        if (self not in _PREPARED or _PREPARED[self] != self._identity() or self.reader.current_window is not window
                or window is not self.window or _CONFIGURED.get(self.reader) is not self.policy
                or _TECHNICAL_CONFIGURED.get(self.reader) is not self.technical_configuration
                or self.reader.deterministic_applicability_task.result is not self
                or not self.reader.deterministic_applicability_task.complete
                or plan is not None and plan != self.plan):
            raise AuthorityUnavailable("deterministic applicability changed its exact Source Work/prefix")
        self.reader.require_current_v3()
        self.reader.deterministic_applicability_task.require_pressure_v1()
        return self

    def release_payload_v3(self):
        _PREPARED.pop(self, None)
        self.reader = self.window = self.policy = self.plan = self.candidate = None
        self.technical_configuration = None
        self.pressure_originals = self.policy_read = self.pressure_verified = None
        self.pressure_payload = self.past_pressure = None
        self.pressure_window_digest = self.pressure_tokens = None


def configure_d13_deterministic_applicability_v3(work, graph, authority, lease, *, scene_ref, policy,
        pressure_mapping=None):
    from ..graph_worker import GraphStorageWorkV3
    from .d13_paid_original_read_v3 import D13PaidOriginalReadWorkV3
    from .d13_technical_policy import AdminD13PrecompressionPolicyV1
    if (type(work) is not GraphStorageWorkV3 or type(work.state) is not D13PaidOriginalReadWorkV3
            or type(policy) is not AdminD13PrecompressionPolicyV1
            or work.coordinator is not graph or work.state.graph is not graph
            or work.terminal or work._finish_called or work.state.phase != "metadata"
            or work.state.method != "read_current_d13_conversation_window_v1"
            or work.state.technical_job_id is not None
            or work.state.authority != authority or work.state.lease is not lease
            or work.state.scene_ref != scene_ref or work.state.window_policy is not policy
            or work.state.args.get("max_slots") != policy.max_slots
            or work.state.args.get("before_sequence") is not None
            or work.state in _CONFIGURED):
        raise AuthorityUnavailable("only the fresh exact deterministic scheduler may prepare applicability")
    if pressure_mapping is not None and type(pressure_mapping) is not D13CurrentPressureOriginalsV1:
        raise AuthorityUnavailable("actual signed pressure originals required")
    _CONFIGURED[work.state] = policy
    _PRESSURE_ORIGINALS[work.state] = pressure_mapping
    return work


def advance_d13_deterministic_applicability_v3(reader, meter):
    if reader not in _CONFIGURED:
        raise AuthorityUnavailable("deterministic applicability was not configured by its scheduler")
    if reader.deterministic_applicability_task is None:
        reader.deterministic_applicability_task = _DeterministicApplicabilityReadV3(reader)
    if reader.deterministic_applicability_task.advance(meter):
        return reader.deterministic_applicability_task.result
    return None


def has_d13_deterministic_applicability_v3(reader):
    return reader in _CONFIGURED


def prepared_d13_deterministic_applicability_v3(reader, window):
    if reader not in _CONFIGURED:
        return None
    task = reader.deterministic_applicability_task
    if type(task) is not _DeterministicApplicabilityReadV3 or not task.complete:
        raise AuthorityUnavailable("deterministic scheduler did not finish its complete applicability READ")
    return task.result.require_v3(window)


def require_d13_deterministic_compiler_applicability_v3(prepared, window, plan):
    if type(prepared) is not PreparedD13DeterministicApplicabilityV3:
        raise AuthorityUnavailable("actual deterministic applicability EOF proof required")
    return prepared.require_v3(window, plan)


def release_d13_deterministic_applicability_v3(reader):
    configured = reader in _CONFIGURED
    task = reader.deterministic_applicability_task
    decision = reader.deterministic_no_reduction_decision
    if decision is not None:
        _DECISIONS.pop(decision, None)
        _DECISION_PRESSURE_FACTS.pop(decision, None)
        reader.deterministic_no_reduction_decision = None
    if task is not None:
        if task.result is not None:
            task.result.release_payload_v3()
        if task.stream is not None:
            task.stream.iterator.close()
        task.owner = task.window = task.policy = task.scan = task.stream = task.result = None
        if task.pressure_verified is not None:
            task.pressure_verified.release_v1()
        if task.policy_read is not None:
            task.policy_read.release_v1()
        if task.grant_column is not None:
            task.grant_column.release_v1()
        task.technical_configuration = None
        task.pressure_originals = task.pressure_verified = task.policy_read = task.grant_column = None
        task.grant_metadata = task.pressure_window_digest = task.pressure_tokens = None
        task.pressure_payload = task.past_pressure = None
        task.recent.clear()
        task.prefix.clear()
        task.anchors.clear()
        task.timeline.clear()
        task.details.clear()
        task.render_parts = None
    _CONFIGURED.pop(reader, None)
    _PRESSURE_ORIGINALS.pop(reader, None)
    _HISTORICAL_PRESSURE.pop(reader, None)
    _TECHNICAL_CONFIGURED.pop(reader, None)
    reader.deterministic_applicability_task = None
    if configured:
        reader.current_window = reader.window_body = reader.window_metadata = None


@dataclass(frozen=True, eq=False)
class D13DeterministicNoReductionV3:
    """Metadata-only method decision; current paid READ must revalidate it."""
    namespace: object
    scene_ref: str
    conversation_ref: str
    owner_ref: str
    audience_ref: object
    plan: PrecompressionPlan
    compiler_version: str
    policy_identity: tuple
    graph_stamp: tuple
    window_order_watermark: int
    window_trusted_utc: float
    window_source_dependencies: tuple
    window_read_set: tuple
    window_missing_ranges: tuple
    source_operation_id: str
    source_selection_digest: str
    original_deadline_utc: float
    original_bytes: int
    rendered_bytes: int
    status: str = "not_applicable"
    reason: str = "deterministic_no_reduction"


def _decision_identity_v3(value):
    return tuple(getattr(value, name) for name in value.__dataclass_fields__)


def issue_d13_deterministic_no_reduction_v3(prepared, error):
    from ..domains.d13.precompression import DeterministicPrecompressionNoReductionV1
    if (type(prepared) is not PreparedD13DeterministicApplicabilityV3
            or type(error) is not DeterministicPrecompressionNoReductionV1):
        raise AuthorityUnavailable("only the actual complete compiler no-reduction result is admissible")
    actual = prepared.require_v3(prepared.window, prepared.plan)
    reader, window, policy, plan = actual.reader, actual.window, actual.policy, actual.plan
    if (plan is None or actual.candidate is None or not reader.qualified
            or actual.technical_configuration is not None
            or actual.rendered_bytes < actual.original_bytes
            or reader.deterministic_no_reduction_decision is not None):
        raise AuthorityUnavailable("no complete unique deterministic no-reduction decision")
    identity = (policy.namespace, policy.installation_id, policy.grant_id,
        policy.grant_version, policy.lease_id, policy.history_token_budget,
        tuple(sorted(policy.quote_ceiling.items())), policy.deadline_after_seconds,
        policy.max_slots, policy.resource_ref, policy.work_kind, policy.compiler_version)
    value = D13DeterministicNoReductionV3(
        namespace=window.namespace, scene_ref=reader.scene_ref,
        conversation_ref=window.conversation_ref, owner_ref=window.owner_ref,
        audience_ref=window.audience_ref, plan=plan, compiler_version=COMPILER_VERSION,
        policy_identity=identity, graph_stamp=reader.graph_stamp,
        window_order_watermark=window.order_watermark, window_trusted_utc=window.trusted_utc,
        window_source_dependencies=window.source_dependencies, window_read_set=window.read_set,
        window_missing_ranges=window.missing_ranges,
        source_operation_id=reader.operation.operation_id,
        source_selection_digest=reader.selection_digest,
        original_deadline_utc=min(reader.deadline,reader.original_deadline or reader.deadline,plan.expires_at_utc),
        original_bytes=actual.original_bytes, rendered_bytes=actual.rendered_bytes)
    reader.operation.retain(4096 + 256 * (
        len(value.window_source_dependencies) + len(value.window_read_set) + len(plan.source_dependencies)))
    _DECISIONS[value] = _decision_identity_v3(value)
    _DECISION_PRESSURE_FACTS[value] = (actual.pressure_originals, actual.pressure_payload,
        actual.pressure_tokens)
    reader.deterministic_no_reduction_decision = value
    return value


def require_issued_d13_deterministic_no_reduction_v3(value):
    """Issuer/lifetime only: this function grants no current Source access."""
    if (type(value) is not D13DeterministicNoReductionV3
            or value not in _DECISIONS or _DECISIONS[value] != _decision_identity_v3(value)):
        raise AuthorityUnavailable("actual retained deterministic no-reduction metadata decision required")
    return value


def configure_d13_paid_fallback_applicability_v3(reader, decision):
    """Configure a new paid READ's own computation, never import old Source permission."""
    from .d13_paid_original_read_v3 import D13PaidOriginalReadWorkV3
    from .d13_technical_policy import AdminD13PrecompressionPolicyV1
    value = require_issued_d13_deterministic_no_reduction_v3(decision)
    policy = reader.graph._GraphCoordinator__d13_precompression_policy
    paid = reader.graph._GraphCoordinator__d13_paid_precompression_policy
    if (type(reader) is not D13PaidOriginalReadWorkV3 or reader.parent is None
            or reader.parent.expected_decision is not value or reader.parent.expected_pending is not None
            or reader.method != "schedule_d13_paid_precompression_v1" or reader.phase != "metadata"
            or reader.job_id is not None or not reader.work is reader.parent.work
            or type(policy) is not AdminD13PrecompressionPolicyV1
            or policy.namespace != reader.namespace or policy.max_slots > paid.max_slots
            or policy.history_token_budget != paid.history_token_budget
            or reader in _CONFIGURED):
        raise AuthorityUnavailable("D13 new paid applicability requires its own exact installed Source Work")
    reader.args["max_slots"] = policy.max_slots
    _CONFIGURED[reader] = policy
    facts = _DECISION_PRESSURE_FACTS.get(value)
    if facts is None:
        raise D13CurrentPressureUnavailableV3("pressure_original_missing")
    _PRESSURE_ORIGINALS[reader] = facts[0]
    _HISTORICAL_PRESSURE[reader] = (value, facts)


def require_current_d13_paid_fallback_v3(reader, decision):
    """Verify fresh paid Source EOF and the complete exact pre-write method decision."""
    from .d13_paid_original_read_v3 import PreparedD13PaidOriginalReadV3
    value = require_issued_d13_deterministic_no_reduction_v3(decision)
    if (reader.parent is None or reader.parent.expected_decision is not value
            or type(reader.proof) is not PreparedD13PaidOriginalReadV3 or not reader.qualified
            or reader.method != "schedule_d13_paid_precompression_v1" or not reader.complete):
        raise AuthorityUnavailable("D13 paid fallback lacks its own current Source/Owner EOF")
    reader.proof.require_current_v3(reader.db)
    window = reader.current_window
    actual = prepared_d13_deterministic_applicability_v3(reader, window)
    policy = actual.policy
    identity = (policy.namespace, policy.installation_id, policy.grant_id,
        policy.grant_version, policy.lease_id, policy.history_token_budget,
        tuple(sorted(policy.quote_ceiling.items())), policy.deadline_after_seconds,
        policy.max_slots, policy.resource_ref, policy.work_kind, policy.compiler_version)
    if (value.namespace != window.namespace or value.scene_ref != reader.scene_ref
            or value.conversation_ref != window.conversation_ref or value.owner_ref != window.owner_ref
            or value.audience_ref != window.audience_ref or value.graph_stamp != reader.graph_stamp
            or value.window_order_watermark != window.order_watermark
            or value.window_source_dependencies != window.source_dependencies or value.window_read_set != window.read_set
            or value.window_missing_ranges != window.missing_ranges
            or reader.operation.operation_id == value.source_operation_id
            or value.policy_identity != identity or value.compiler_version != COMPILER_VERSION
            or actual.plan != value.plan or actual.original_bytes != value.original_bytes
            or actual.rendered_bytes != value.rendered_bytes or actual.rendered_bytes < actual.original_bytes
            or reader.now_utc < value.window_trusted_utc or reader.now_utc >= value.original_deadline_utc
            or reader.now_utc >= value.plan.expires_at_utc):
        raise AuthorityUnavailable("D13 new paid window/prefix/policy/epochs/deadline changed after deterministic decision")
    return actual


def configure_d13_technical_compiler_v3(work, graph, authority, lease, *, job, plan, method):
    """Compile only the durable original prefix in its actual technical Source Work."""
    from ..graph_worker import GraphStorageWorkV3
    from .jobs import PersistentJob
    from .d13_paid_original_read_v3 import D13PaidOriginalReadWorkV3, _JOB_COLUMNS
    from .d13_precompression_job import plan_from_precompression_job_v1
    from .d13_technical_policy import AdminD13PrecompressionPolicyV1
    policy = graph._GraphCoordinator__d13_precompression_policy
    expected_phase = {
        "acquire_d13_deterministic_precompression_job_v2": "queued",
        "complete_d13_deterministic_precompression_job_v2": "running",
    }.get(method)
    if (type(work) is not GraphStorageWorkV3 or type(work.state) is not D13PaidOriginalReadWorkV3
            or type(job) is not PersistentJob or type(plan) is not PrecompressionPlan
            or type(policy) is not AdminD13PrecompressionPolicyV1 or expected_phase is None
            or work.coordinator is not graph or work.state.graph is not graph
            or work.terminal or work._finish_called or work.state.phase != "metadata"
            or work.state.parent is not None or work.state.job_id is not None
            or work.state.technical_job_id != job.job_id
            or work.state.method != "read_current_d13_conversation_window_v1"
            or work.state.authority != authority or work.state.lease is not lease
            or work.state.window_policy is not policy
            or work.state.args.get("max_slots") != policy.max_slots
            or work.state.args.get("before_sequence") is not None
            or job.work_kind != "d13.precompress" or job.phase != expected_phase
            or (job.bot_id, job.persona_id) != authority.namespace.as_tuple
            or job.budget_ref != policy.lease_id or job.cancel_epoch
            or job.operator_versions.get("d13_compiler") != policy.compiler_version
            or job.operator_versions.get("d11_grant") != f"{policy.grant_id}:{policy.grant_version}"
            or job.operator_versions.get("installation_id") != policy.installation_id
            or expected_phase == "running" and (job.lease_holder != authority.actor or job.fence < 1)
            or plan_from_precompression_job_v1(job) != plan
            or work.state in _CONFIGURED or work.state in _TECHNICAL_CONFIGURED):
        raise AuthorityUnavailable("exact durable technical job/plan Source Work configuration required")
    header = tuple(getattr(job, name) for name in _JOB_COLUMNS)
    _TECHNICAL_CONFIGURED[work.state] = (job, plan, method, header)
    _CONFIGURED[work.state] = policy
    return work


def prepared_d13_technical_compiler_v3(reader, window, *, job, plan, method):
    """Require the same worker's compiled EOF, never a scheduler/fallback decision."""
    from .d13_paid_original_read_v3 import D13PaidOriginalReadWorkV3
    configuration = _TECHNICAL_CONFIGURED.get(reader)
    if (type(reader) is not D13PaidOriginalReadWorkV3 or configuration is None
            or configuration[0] != job or configuration[1] != plan or configuration[2] != method
            or reader.technical_job_id != job.job_id or reader.technical_job_header != configuration[3]
            or not reader.qualified or not reader.complete
            or reader.current_window is not window):
        raise AuthorityUnavailable("actual technical job/plan compiled EOF differs")
    actual = prepared_d13_deterministic_applicability_v3(reader, window)
    if (actual is None or actual.technical_configuration is not configuration
            or actual.plan != plan or actual.candidate is None):
        raise AuthorityUnavailable("technical worker has no complete original-prefix compiler proof")
    return actual
